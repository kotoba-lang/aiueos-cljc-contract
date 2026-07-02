(ns aiueos.broker
  "The capability broker's decision logic, ported from the retired
  `aiueos/src/broker.rs` Rust module to CLJC per ADR-2607022200.

  This namespace owns the *decisions* the broker makes: whether a component
  is granted capabilities (`verify-one`/`verify-system`), the code-as-data
  admission gate (`verify-admission`, ADR-0004), and pure data assembly for
  `:aiueos/run-plan` / `:aiueos/run-receipt` (matching
  `aiueos.contract/validate-run-plan` / `validate-run-receipt`).

  It deliberately does NOT own execution. The retired Rust broker's
  `launch`/`launch_with_surfaces`/`boot`/`boot_rounds*`/`materialize_and_run`/
  `compile_component_source` all required wasmtime hosting, wasm-byte file
  I/O, and running untrusted code under fuel/memory limits — that is
  `:provider/execute` in `resources/aiueos/broker_contract.edn`'s `:run-receipt`
  flow, and per ADR-2607022200 it is permanently a native/host adapter
  concern (Layer 3), never CLJC authority. `.kotoba` compiles TO Wasm; it
  cannot itself host other Wasm components. A host adapter should: call
  `verify-one`/`verify-admission` here, only proceed to execute on
  `:aiueos/decision :grant`, then call `run-receipt` with the execution
  result to shape the audited receipt.

  Every function here is pure: no file I/O, no wall-clock reads. Where the
  retired Rust broker appended directly to an `AuditLog`, these functions
  instead return `:aiueos.broker/audit-entries` — a vector of pure
  `aiueos.audit/audit-entry` maps — for the caller (a host adapter) to
  append via `aiueos.audit/append!`. This mirrors the pure/impure split
  `aiueos.audit` itself already draws.

  One retired module is deliberately NOT ported here or anywhere:
  `aiueos/src/safe.rs`, the safe-kotoba subset gate (denies eval/require/
  reflection/host construction before compiling `:aiueos/source`). It is
  redundant, not merely out of scope — `kotoba-lang/kotoba`'s own
  `kototama`/`kotoba-clj` compiler layer already owns this exact check
  (`kotoba-lang/kotoba/src/kotoba/runtime.clj`), and `kotoba-lang/kotoba`'s
  `ADR-kotoba-shell-aiueos-safety-clj.md` formalizes the split: kototama
  gates the *language* (is this source safe to compile at all?), aiueos
  gates *capabilities* over the manifest and the resulting artifact (this
  namespace + `aiueos.policy`). A host adapter compiling `:aiueos/source`
  should call kototama's safety gate first, then this namespace's
  `verify-one`/`verify-admission` — porting a second denylist here would
  duplicate, and risk drifting from, kototama's."
  (:require [clojure.string :as str]
            [aiueos.audit :as audit]
            [aiueos.graph :as graph]
            [aiueos.manifest :as manifest]
            [aiueos.policy :as policy]
            [aiueos.signing :as signing]))

(def ^:private trust-rank
  "Lower = more trusted. Mirrors the retired Rust `Trust` enum's derived
  `Ord` (declaration order: Trusted, Verified, Untrusted, AiGenerated)."
  {:trusted 0 :verified 1 :untrusted 2 :ai-generated 3})

(defn- below-verified? [trust]
  (> (get trust-rank trust (:untrusted trust-rank)) (get trust-rank :verified)))

(defn- signature-violation? [x]
  (and (map? x) (contains? x :aiueos/kind)))

(defn authenticate
  "Verify `m`'s signature against `policy` (ADR-0003). Returns one of:
  - `{:aiueos.broker/signer nil}` — unsigned, allowed (policy doesn't
    require signatures).
  - `{:aiueos.broker/signer signer-id}` — a valid signature names a
    registered signer.
  - a violation map `{:aiueos/component id :aiueos/kind :bad-signature
    :aiueos/message \"...\"}` — unsigned under a `:aiueos.policy/require-signed`
    policy, or the signature is missing context / unregistered / forged.
    A bad signature is NEVER downgraded to unsigned."
  [m policy]
  (let [status (signing/verify m policy)]
    (cond
      (signing/violation? status) status

      (and (signing/unsigned? status) (:aiueos.policy/require-signed policy))
      {:aiueos/component (:aiueos/component m)
       :aiueos/kind :bad-signature
       :aiueos/message "unsigned component rejected (require-signed policy)"}

      (signing/unsigned? status) {:aiueos.broker/signer nil}

      (signing/verified? status) {:aiueos.broker/signer (:aiueos.signing/signer status)})))

(defn elevate-for-signature
  "A signature elevates an under-trusted component to `:verified` for the
  capability check (ADR-0003), unlocking that tier's policy. No-op if
  `signer` is nil or `m` is already `:trusted`/`:verified`."
  [m signer]
  (if (and signer (below-verified? (:aiueos/trust m :untrusted)))
    (manifest/with-trust m :verified)
    m))

(defn- grant-audit-entries [decision signer]
  [(audit/audit-entry
    (:aiueos/component decision) :grant
    (let [caps (str/join " " (map name (:aiueos/capabilities decision)))]
      (if signer
        (str "caps: " caps " signer: " (if (keyword? signer) (name signer) signer))
        (str "caps: " caps))))])

(defn- deny-audit-entries [decision]
  (mapv (fn [v]
          (audit/audit-entry (:aiueos/component decision) :deny
                              (str "[" (name (:aiueos/kind v)) "] " (:aiueos/message v))))
        (:aiueos/violations decision)))

(defn verify-one
  "Verify a single component manifest `m` against `graph` and `policy`.
  Runs signature authenticity first (ADR-0003): a bad signature (or an
  unsigned component under a require-signed policy) denies outright without
  reaching the capability check; a valid signature elevates an
  under-trusted component to `:verified` before `aiueos.policy/verify-component`
  runs.

  Returns a policy-decision map (matches
  `aiueos.contract/validate-policy-decision`) with one extra key,
  `:aiueos.broker/audit-entries` — a vector of pure `aiueos.audit/audit-entry`
  maps the caller should append. Every grant and every denial is audited,
  exactly like the retired Rust broker's `verify_one`/`deny`."
  [m graph policy]
  (let [auth (authenticate m policy)]
    (if (signature-violation? auth)
      (let [decision {:aiueos/decision :deny
                       :aiueos/component (:aiueos/component m)
                       :aiueos/violations [auth]}]
        (assoc decision :aiueos.broker/audit-entries (deny-audit-entries decision)))
      (let [signer (:aiueos.broker/signer auth)
            m-eff (elevate-for-signature m signer)
            decision (policy/verify-component m-eff graph policy)
            entries (if (= :grant (:aiueos/decision decision))
                      (grant-audit-entries decision signer)
                      (deny-audit-entries decision))]
        (assoc decision :aiueos.broker/audit-entries entries)))))

(defn verify-system
  "Verify every component in `components` against a shared capability graph
  built from all of them. Mirrors the retired Rust `verify_system`: nothing
  is grantable unless the WHOLE system passes — if any component is denied,
  the aggregate decision is `:deny` with every violation from every denied
  component, and no grants are returned. Per-component audit entries are
  always aggregated, whether the system as a whole is granted or denied
  (matching the Rust behavior that per-component denials are audited even
  when aggregation later fails the boot)."
  [components policy]
  (let [g (graph/build components)
        results (mapv #(verify-one % g policy) components)
        audit-entries (vec (mapcat :aiueos.broker/audit-entries results))
        violations (vec (mapcat :aiueos/violations (filter #(= :deny (:aiueos/decision %)) results)))]
    (if (seq violations)
      {:aiueos/decision :deny
       :aiueos/violations violations
       :aiueos.broker/audit-entries audit-entries}
      {:aiueos/decision :grant
       :aiueos/grants (mapv #(select-keys % [:aiueos/component :aiueos/capabilities]) results)
       :aiueos.broker/audit-entries audit-entries})))

(defn floor-trust-for-admission
  "Code-as-data admission (ADR-0004): floor `m`'s trust to `:ai-generated`
  before verification. An agent-submitted component can never grant itself
  trust — a valid signature can still *elevate* it afterward (ADR-0003);
  `verify-admission` applies that elevation on top of this floor, exactly
  like `verify-one` does for any other manifest."
  [m]
  (manifest/with-trust m :ai-generated))

(defn verify-admission
  "The verification half of the retired Rust `Broker::admit` (ADR-0004) —
  floors `m`'s trust to `:ai-generated`, then runs the same `verify-one`
  capability gate. This is the PURE decision: whether the floored-trust
  component would be granted capabilities to run at all. It does not
  execute the component — actual compilation/execution is a native
  host-adapter concern (ADR-2607022200 Layer 3), not authority. A host
  adapter should call this first and only proceed to execute (and only then
  call `run-receipt`) when `:aiueos/decision` is `:grant`."
  [m graph policy]
  (verify-one (floor-trust-for-admission m) graph policy))

(defn run-plan
  "Assemble a `:aiueos/run-plan` (matches `aiueos.contract/validate-run-plan`)
  for `m` against `graph`/`policy`/`component-boundary`. Pure data assembly
  only — mirrors `broker_contract.edn`'s `:run-plan` flow steps
  (`:policy/evaluate :grant/normalize :component-boundary/attach :audit/plan`)
  but does not execute anything. `:aiueos/grant` is present only when
  `:aiueos/decision` is `:grant`; a host adapter must refuse to execute a
  `:deny` plan."
  [m graph policy component-boundary]
  (let [decision (verify-one m graph policy)
        audit-entries (:aiueos.broker/audit-entries decision)
        pure-decision (dissoc decision :aiueos.broker/audit-entries)
        base {:aiueos/component (:aiueos/component m)
              :aiueos/manifest m
              :aiueos/decision pure-decision
              :aiueos/entry (or (:aiueos/entry m) "main")
              :aiueos/args (or (:aiueos/args m) [])
              :aiueos/component-boundary component-boundary
              :aiueos/audit-events audit-entries}]
    (cond-> base
      (= :grant (:aiueos/decision pure-decision))
      (assoc :aiueos/grant
             {:aiueos/subject (:aiueos/component m)
              :aiueos/audience :aiueos/broker
              :aiueos/component (:aiueos/component m)
              :aiueos/capabilities (:aiueos/capabilities pure-decision)}))))

(defn run-receipt
  "Shape a `:aiueos/run-receipt` (matches `aiueos.contract/validate-run-receipt`)
  from an already-executed result. Pure data assembly only — the actual
  execution (`:provider/execute` in `broker_contract.edn`'s `:run-receipt`
  flow) is a native host-adapter concern (ADR-2607022200 Layer 3). Call this
  AFTER running a `:grant` run-plan, to produce the audited receipt the
  broker_contract's `:audit/receipt` step describes."
  [component status & {:keys [result error started-at finished-at audit-events]
                        :or {audit-events []}}]
  (cond-> {:aiueos/component component
           :aiueos/status status
           :aiueos/audit-events audit-events}
    (some? result) (assoc :aiueos/result result)
    (some? error) (assoc :aiueos/error error)
    (some? started-at) (assoc :aiueos/started-at started-at)
    (some? finished-at) (assoc :aiueos/finished-at finished-at)))
