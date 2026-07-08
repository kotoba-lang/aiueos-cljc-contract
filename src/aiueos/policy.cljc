(ns aiueos.policy
  "The policy reasoner, ported from the retired `aiueos/src/policy.rs` Rust
  module to CLJC per ADR-2607022200 (aiueos's semantic authority moved from a
  Rust crate to CLJC/EDN; this namespace is the executable decision model the
  `:aiueos.policy/*` shape in `resources/aiueos/policy_contract.edn` and
  `aiueos.contract/validate-policy-decision` describe).

  Given a capability graph (`aiueos.graph`, who exports what) and a policy
  (kernel-provided primitives, per-component grants, per-trust
  forbiddances), `verify-component` decides whether a component is allowed
  to run and which capabilities it is actually granted. The output is always
  a policy-decision map (`:aiueos/decision :grant` or `:deny`) — never a
  silent pass."
  (:require [clojure.set :as set]
            [aiueos.graph :as graph]
            [aiueos.surface :as surface]))

(def default-kernel-caps
  "Primitive capabilities the kernel/broker hands out directly (no exporter
  component needed). These are the hardware/runtime seams. Mirrors
  `resources/aiueos/policy_contract.edn` :aiueos.policy/kernel-caps."
  #{:log/write :clock/monotonic :random/bytes
    :topic/publish :topic/subscribe
    :pci/config :dma/map :irq/subscribe :mmio/map})

(def default-forbid-effects
  "Effects forbidden for a given trust level. The AI-generated/untrusted
  lockdown: no network, no secrets, no persistence for :ai-generated; no
  secrets for :untrusted. Mirrors :aiueos.policy/forbid."
  {:ai-generated #{:network :secrets :persistent-write}
   :untrusted #{:secrets}})

(def default-policy
  "The default policy: a conservative set of kernel primitives, and the
  AI-generated/untrusted lockdown."
  {:aiueos.policy/kernel-caps default-kernel-caps
   :aiueos.policy/grants {}
   :aiueos.policy/forbid-effects default-forbid-effects
   :aiueos.policy/signers {}
   :aiueos.policy/require-signed false
   :aiueos.policy/surface nil
   :aiueos.policy/net-allow #{}})

(defn- as-kw-set [x]
  (cond
    (nil? x) #{}
    (set? x) x
    (coll? x) (set x)
    :else #{x}))

;; ───────── signer trust store (ADR-2606290900, informed by ADR-2607022400's
;; EROS/KeyKOS microkernel survey: revocation is "unadopt", never "erase") ─────────

(def signer-statuses
  "ADR-2606290900's signer lifecycle states. `:rotated` and `:revoked` both
  invalidate DIRECT trust in the key -- rotation-chain following (trusting
  whatever `:aiueos.signer/rotated-to` now points at) is ADR-2606290900's K4,
  future work, not implemented here."
  #{:active :rotated :revoked})

(defn signer-entry
  "Normalize a raw `:aiueos.policy/signers` registry value into a full
  trust-store entry map. A plain hex-string value -- the legacy flat
  registry shape every existing policy/manifest in this repo already uses --
  becomes an always-`:active`, unbounded-validity entry. Fully backward
  compatible: policies that never adopted lifecycle fields behave exactly as
  before."
  [raw]
  (cond
    (string? raw) {:aiueos.signer/public-key raw :aiueos.signer/status :active}
    (map? raw) (merge {:aiueos.signer/status :active} raw)
    :else nil))

(defn signer-status-ok?
  "True unless the signer's trust-store status is `:revoked` or `:rotated`."
  [entry]
  (= :active (:aiueos.signer/status entry :active)))

(defn signer-in-window?
  "True if `now` (epoch seconds) falls within the entry's
  `:aiueos.signer/valid-from`/`:aiueos.signer/valid-until` window, or either
  bound is nil (unbounded). `now` itself may be nil -- a caller with no
  clock available (or that doesn't care to enforce expiry) skips only this
  time check; `signer-status-ok?`'s revocation check is unconditional and
  always applies regardless of clock availability."
  [entry now]
  (or (nil? now)
      (let [from (:aiueos.signer/valid-from entry)
            until (:aiueos.signer/valid-until entry)]
        (and (or (nil? from) (>= now from))
             (or (nil? until) (< now until))))))

(defn signer-trusted?
  "The `not_revoked ∧ not_expired` clauses of ADR-2606290900's trust
  formula (`signature_valid ∧ not_expired ∧ not_revoked ∧
  issuer_trusted_for`) -- signature validity itself is
  `aiueos.signing/verify`'s job, not this namespace's. `nil` if `signer-id`
  isn't registered at all (distinct from `false` for a registered-but-
  invalid signer, though callers needing only a yes/no answer can treat
  both as untrusted)."
  [policy signer-id now]
  (when-let [raw (get (:aiueos.policy/signers policy) signer-id)]
    (let [entry (signer-entry raw)]
      (boolean (and entry (signer-status-ok? entry) (signer-in-window? entry now))))))

(defn parse-policy
  "Parse a deployment policy overlay (the `:aiueos/*` EDN validated by
  `aiueos.contract/validate-deployment-policy`) into an effective policy.
  Everything is optional and *extends* the default policy: kernel-caps and
  net-allow are unioned, grants are merged per-component, forbid is
  *replaced* per-trust (an explicit `:aiueos/forbid` entry for a trust level
  overrides — not adds to — the default lockdown for that level, matching
  the retired `Policy::from_edn`), signers are merged.

  Callers should validate the overlay shape with
  `aiueos.contract/validate-deployment-policy` first; this function does not
  re-check unknown keys."
  ([] default-policy)
  ([overlay]
   (let [overlay (or overlay {})]
     (cond-> default-policy
       (:aiueos/kernel-caps overlay)
       (update :aiueos.policy/kernel-caps set/union (as-kw-set (:aiueos/kernel-caps overlay)))

       (:aiueos/grants overlay)
       (update :aiueos.policy/grants
               (fn [grants]
                 (reduce-kv (fn [acc id caps]
                              (update acc id set/union (as-kw-set caps)))
                            grants
                            (:aiueos/grants overlay))))

       (:aiueos/forbid overlay)
       (update :aiueos.policy/forbid-effects merge (:aiueos/forbid overlay))

       (:aiueos/signers overlay)
       (update :aiueos.policy/signers merge (:aiueos/signers overlay))

       (contains? overlay :aiueos/require-signed)
       (assoc :aiueos.policy/require-signed (boolean (:aiueos/require-signed overlay)))

       (:aiueos/surface overlay)
       (assoc :aiueos.policy/surface (name (:aiueos/surface overlay)))

       (:aiueos/net-allow overlay)
       (update :aiueos.policy/net-allow set/union (as-kw-set (:aiueos/net-allow overlay)))))))

(defn granted-to
  "Capabilities available to manifest `m`: kernel primitives ∪ explicit
  grants. With an active surface (ADR-0005), the kernel primitives are
  restricted to those the surface can actually back — an import that maps to
  an unoffered kernel cap becomes :unresolved-capability (the host refuses
  to provide what this surface shouldn't). Explicit grants are never
  surface-gated."
  [policy m]
  (let [active-surface (:aiueos.policy/surface policy)
        kernel-caps (:aiueos.policy/kernel-caps policy)
        base (if-let [offered (and active-surface (surface/offered-by-id active-surface))]
               (set/intersection kernel-caps offered)
               kernel-caps)
        id (:aiueos/component m)
        extra (get (:aiueos.policy/grants policy) id #{})]
    (set/union base extra)))

(defn- violation
  ([component kind message]
   {:aiueos/component component :aiueos/kind kind :aiueos/message message}))

(defn verify-component
  "Verify one component manifest `m` against `graph` (an `aiueos.graph/build`
  result) and `policy` (an effective policy from `parse-policy`). Returns a
  policy-decision map matching `aiueos.contract/validate-policy-decision`:
  `{:aiueos/decision :grant :aiueos/component id :aiueos/capabilities #{...}}`
  on success, or `{:aiueos/decision :deny :aiueos/component id
  :aiueos/violations [...]}` listing every violation (never just the first)."
  [m graph policy]
  (let [id (:aiueos/component m)
        granted (granted-to policy m)
        active-surface (:aiueos.policy/surface policy)
        targets-present? (contains? m :aiueos/surface)
        targets (as-kw-set (:aiueos/surface m))
        surface-violations
        (if (and active-surface targets-present? (not (contains? targets (keyword active-surface))))
          [(violation id :surface-mismatch
                      (str "component targets surfaces " targets
                           " but the active surface is " active-surface))]
          [])
        imports (as-kw-set (:aiueos/imports m))
        {:keys [resolved import-violations]}
        (reduce (fn [acc imp]
                  (let [by-graph (some #(not= % id) (graph/providers graph imp))
                        by-grant (contains? granted imp)]
                    (if (or by-graph by-grant)
                      (update acc :resolved conj imp)
                      (update acc :import-violations conj
                              (violation id :unresolved-capability
                                         (str "import " imp
                                              " has no provider, kernel cap, or grant"))))))
                {:resolved #{} :import-violations []}
                imports)
        effects (as-kw-set (:aiueos/effects m))
        trust (or (:aiueos/trust m) :untrusted)
        forbidden (get (:aiueos.policy/forbid-effects policy) trust #{})
        effect-violations
        (for [eff effects :when (contains? forbidden eff)]
          (violation id :forbidden-effect
                     (str "effect " eff " is forbidden for " (name trust) " components")))
        requires (as-kw-set (:aiueos/requires m))
        dma? (contains? effects :dma)
        requires-iommu? (contains? requires :iommu)
        has-iommu? (or (contains? granted :iommu) (contains? resolved :iommu))
        dma-violations
        (if (and dma? (not (and requires-iommu? has-iommu?)))
          [(violation id :dma-without-iommu
                      "DMA requires `:requires #{:iommu}` and an :iommu grant")]
          [])
        violations (vec (concat surface-violations import-violations effect-violations dma-violations))]
    (if (seq violations)
      {:aiueos/decision :deny :aiueos/component id :aiueos/violations violations}
      (let [caps (cond-> resolved
                   (and requires-iommu? (contains? granted :iommu)) (conj :iommu))]
        {:aiueos/decision :grant :aiueos/component id :aiueos/capabilities caps}))))

(defn verify-system
  "Verify every component in `components` (a vector of manifest maps) against
  a shared capability graph built from all of them. Returns a vector of
  policy-decision maps, one per component, in input order."
  [components policy]
  (let [g (graph/build components)]
    (mapv #(verify-component % g policy) components)))
