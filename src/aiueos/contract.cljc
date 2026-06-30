(ns aiueos.contract
  "Pure CLJC authority contract for the first aiueos Rust migration slice.

  The namespace intentionally validates plain EDN maps without depending on a
  runtime host. It is small by design: enough to pin the shared manifest,
  policy-decision, and audit-event shapes before behavior migrates from Rust."
  (:require [clojure.set :as set]))

(def manifest-kinds
  #{:app :service :driver :broker :agent :kernel-extension :compat})

(def trust-levels
  #{:trusted :verified :untrusted :ai-generated})

(def policy-decisions
  #{:grant :deny})

(def violation-kinds
  #{:unresolved-capability
    :forbidden-effect
    :dma-without-iommu
    :bad-signature
    :surface-mismatch})

(def audit-events
  #{:grant :deny :compile :run :reject})

(def manifest-required-keys
  #{:aiueos/component :aiueos/kind})

(def manifest-optional-keys
  #{:aiueos/trust
    :aiueos/source
    :aiueos/wasm
    :aiueos/wasm-sha256
    :aiueos/imports
    :aiueos/exports
    :aiueos/effects
    :aiueos/requires
    :aiueos/limits
    :aiueos/entry
    :aiueos/args
    :aiueos/device
    :aiueos/publishes
    :aiueos/subscribes
    :aiueos/topics
    :aiueos/signer
    :aiueos/signature
    :aiueos/quota
    :aiueos/schedule
    :aiueos/surface})

(def manifest-keys
  (set/union manifest-required-keys manifest-optional-keys))

(def policy-decision-required-keys
  #{:aiueos/decision :aiueos/component})

(def policy-decision-optional-keys
  #{:aiueos/capabilities :aiueos/violations :aiueos/detail})

(def policy-decision-keys
  (set/union policy-decision-required-keys policy-decision-optional-keys))

(def audit-event-required-keys
  #{:aiueos/ts :aiueos/event :aiueos/component :aiueos/detail})

(def audit-event-keys
  audit-event-required-keys)

(def violation-required-keys
  #{:aiueos/kind :aiueos/message})

(defn- aiueos-key? [k]
  (and (keyword? k) (= "aiueos" (namespace k))))

(defn- component-id? [x]
  (or (keyword? x)
      (and (string? x) (not (empty? x)))))

(defn- kw-set? [x]
  (and (set? x) (every? keyword? x)))

(defn- kw-coll? [x]
  (or (nil? x) (kw-set? x) (and (vector? x) (every? keyword? x))))

(defn- int-vector? [x]
  (and (vector? x) (every? int? x)))

(defn- positive-integer? [x]
  (and (int? x) (pos? x)))

(defn- non-negative-integer? [x]
  (and (int? x) (not (neg? x))))

(defn- err [path message]
  {:path path :message message})

(defn- missing-errors [m required]
  (mapv #(err [%] "required key is missing")
        (sort (remove #(contains? m %) required))))

(defn- unknown-aiueos-key-errors [m allowed]
  (mapv #(err [%] "unknown :aiueos/* key")
        (sort (filter #(and (aiueos-key? %) (not (contains? allowed %))) (keys m)))))

(defn- field-error [m k pred message]
  (when (and (contains? m k) (not (pred (get m k))))
    (err [k] message)))

(defn- collect-errors [& xs]
  (vec (remove nil? (mapcat #(if (sequential? %) % [%]) xs))))

(defn- prefix-errors [prefix errors]
  (mapv #(update % :path (fn [path] (into prefix path))) errors))

(defn- valid-result [errors]
  {:valid? (empty? errors)
   :errors errors})

(defn validate-manifest
  "Validate a minimal component manifest EDN map.

  This does not resolve capabilities or read artifacts. It only pins the pure
  authority shape shared by CLJC and host adapters."
  [m]
  (let [errors
        (if-not (map? m)
          [(err [] "manifest must be a map")]
          (collect-errors
           (missing-errors m manifest-required-keys)
           (unknown-aiueos-key-errors m manifest-keys)
           (field-error m :aiueos/component component-id?
                        ":aiueos/component must be a keyword or non-empty string")
           (field-error m :aiueos/kind manifest-kinds
                        ":aiueos/kind must be a known component kind")
           (field-error m :aiueos/trust trust-levels
                        ":aiueos/trust must be a known trust level")
           (field-error m :aiueos/source string?
                        ":aiueos/source must be a string")
           (field-error m :aiueos/wasm string?
                        ":aiueos/wasm must be a string")
           (field-error m :aiueos/wasm-sha256 string?
                        ":aiueos/wasm-sha256 must be a string")
           (field-error m :aiueos/imports kw-coll?
                        ":aiueos/imports must be a keyword set or vector")
           (field-error m :aiueos/exports kw-coll?
                        ":aiueos/exports must be a keyword set or vector")
           (field-error m :aiueos/effects kw-coll?
                        ":aiueos/effects must be a keyword set or vector")
           (field-error m :aiueos/requires kw-coll?
                        ":aiueos/requires must be a keyword set or vector")
           (field-error m :aiueos/entry string?
                        ":aiueos/entry must be a string")
           (field-error m :aiueos/args int-vector?
                        ":aiueos/args must be a vector of integers")
           (field-error m :aiueos/limits map?
                        ":aiueos/limits must be a map")
           (field-error m :aiueos/quota map?
                        ":aiueos/quota must be a map")
           (field-error m :aiueos/schedule map?
                        ":aiueos/schedule must be a map")
           (when-let [limits (:aiueos/limits m)]
             (when (map? limits)
               (prefix-errors
                [:aiueos/limits]
                (collect-errors
                 (field-error limits :memory-pages positive-integer?
                              ":memory-pages must be a positive integer")
                 (field-error limits :fuel positive-integer?
                              ":fuel must be a positive integer")))))
           (when-let [quota (:aiueos/quota m)]
             (when (map? quota)
               (prefix-errors
                [:aiueos/quota]
                (collect-errors
                 (field-error quota :host-calls positive-integer?
                              ":host-calls must be a positive integer")
                 (field-error quota :publishes non-negative-integer?
                              ":publishes must be a non-negative integer")))))
           (when-let [schedule (:aiueos/schedule m)]
             (when (map? schedule)
               (prefix-errors
                [:aiueos/schedule]
                (collect-errors
                 (field-error schedule :period-ms positive-integer?
                              ":period-ms must be a positive integer")
                 (field-error schedule :deadline-ms positive-integer?
                              ":deadline-ms must be a positive integer")
                 (field-error schedule :cycle-ms positive-integer?
                              ":cycle-ms must be a positive integer")
                 (field-error schedule :priority non-negative-integer?
                              ":priority must be a non-negative integer")))))))]
    (valid-result errors)))

(defn manifest? [m]
  (:valid? (validate-manifest m)))

(defn- validate-violation [v index]
  (if-not (map? v)
    [(err [:aiueos/violations index] "violation must be a map")]
    (prefix-errors
     [:aiueos/violations index]
     (collect-errors
      (missing-errors v violation-required-keys)
      (field-error v :aiueos/kind violation-kinds
                   ":aiueos/kind must be a known violation kind")
      (field-error v :aiueos/message string?
                   ":aiueos/message must be a string")))))

(defn validate-policy-decision
  "Validate the pure policy decision shape.

  A grant carries `:aiueos/capabilities`; a deny carries
  `:aiueos/violations`. This is a contract shape, not a reasoner."
  [d]
  (let [errors
        (if-not (map? d)
          [(err [] "policy decision must be a map")]
          (let [decision (:aiueos/decision d)]
            (collect-errors
             (missing-errors d policy-decision-required-keys)
             (unknown-aiueos-key-errors d policy-decision-keys)
             (field-error d :aiueos/decision policy-decisions
                          ":aiueos/decision must be :grant or :deny")
             (field-error d :aiueos/component component-id?
                          ":aiueos/component must be a keyword or non-empty string")
             (field-error d :aiueos/detail string?
                          ":aiueos/detail must be a string")
             (case decision
               :grant
               (collect-errors
                (when-not (contains? d :aiueos/capabilities)
                  (err [:aiueos/capabilities] "grant decision requires capabilities"))
                (field-error d :aiueos/capabilities kw-set?
                             ":aiueos/capabilities must be a keyword set"))

               :deny
               (collect-errors
                (when-not (contains? d :aiueos/violations)
                  (err [:aiueos/violations] "deny decision requires violations"))
                (field-error d :aiueos/violations vector?
                             ":aiueos/violations must be a vector")
                (when (vector? (:aiueos/violations d))
                  (mapcat validate-violation (:aiueos/violations d) (range))))

               nil))))]
    (valid-result errors)))

(defn policy-decision? [d]
  (:valid? (validate-policy-decision d)))

(defn validate-audit-event
  "Validate one append-only audit log event map."
  [e]
  (let [errors
        (if-not (map? e)
          [(err [] "audit event must be a map")]
          (collect-errors
           (missing-errors e audit-event-required-keys)
           (unknown-aiueos-key-errors e audit-event-keys)
           (field-error e :aiueos/ts non-negative-integer?
                        ":aiueos/ts must be a non-negative integer")
           (field-error e :aiueos/event audit-events
                        ":aiueos/event must be a known audit event")
           (field-error e :aiueos/component component-id?
                        ":aiueos/component must be a keyword or non-empty string")
           (field-error e :aiueos/detail string?
                        ":aiueos/detail must be a string")))]
    (valid-result errors)))

(defn audit-event? [e]
  (:valid? (validate-audit-event e)))
