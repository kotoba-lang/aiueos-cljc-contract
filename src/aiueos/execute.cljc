(ns aiueos.execute
  "Execute a compiled `.kotoba` Wasm component, per ADR-2607022900: the
  native adapter's execution layer runs on the JVM via com.dylibso.chicory
  (a pure-JVM Wasm runtime) instead of Rust/wasmtime. This supersedes the
  Rust-tender assumption in ADR-2607022700 for everything except real
  hardware access (the device-access quartet stays a deterministic stub
  here, same as it was in the retired Rust host.rs and in kotoba.wasm-exec).

  This namespace never grants a capability itself -- `execute` always calls
  `aiueos.broker/verify-one` first and refuses to run anything the broker
  denies. Chicory host-import closures back the 7 non-hardware aiueos
  kernel capabilities with real behavior; `aiueos.topic`'s pure bus is
  threaded through an atom so the imperative Chicory boundary can mutate it
  across host calls within one run.

  JVM-only (`#?(:clj ...)` throughout): Chicory is a Java library, and this
  is exactly the kind of host/adapter code the rest of this repo already
  keeps `:clj`-gated (see `aiueos.signing`'s crypto, `aiueos.audit`'s file
  I/O).

  `:aiueos/limits :fuel` (ADR-0001) IS instruction-level metering, unlike
  `:aiueos/quota`'s host-CALL count above -- via
  `Instance.Builder/withUnsafeExecutionListener`, a real Chicory hook that
  fires per Wasm instruction (`fuel-listener`). Chicory's own docs mark
  this API `unsafe`/`experimental`/possibly-removed-later (its
  *documented, supported* execution-limit mechanism is a wall-clock
  thread-interrupt timeout, not this), and it only fires in the
  interpreter path -- Chicory's separate AOT compiler bypasses it
  entirely. Treat fuel enforcement here as a working prototype on an
  unofficial API, not a permanent guarantee (ADR-2607022900 follow-up
  2, 2026-07-02).

  `:aiueos/limits :memory-pages` (ADR-0001) IS enforced, and via a
  STABLE Chicory API (`Instance.Builder/withMemoryLimits`, not marked
  unsafe/experimental like the fuel listener) -- `memory-pages-limits`
  reads the module's own declared initial page count (never overridden;
  a module that needs N pages to even start must still get them) and
  caps only the MAXIMUM a `memory.grow` call can reach to
  `min(manifest-limit, module's-own-declared-max)`. Verified empirically
  (not just per Chicory's docs) that this genuinely blocks growth: a
  module instantiated with a capped `MemoryLimits` sees `Memory/grow`
  return -1 past the cap, its page count unchanged."
  (:require [aiueos.broker :as broker]
            [aiueos.manifest :as manifest]
            [aiueos.topic :as topic]
            #?(:clj [clojure.edn :as edn]))
  #?(:clj
     (:import (com.dylibso.chicory.runtime ExecutionListener HostFunction ImportFunction
                                           ImportValues Instance WasmFunctionHandle)
              (com.dylibso.chicory.wasm Parser)
              (com.dylibso.chicory.wasm.types FunctionType MemoryLimits ValType))))

#?(:clj
   (defn- read-str
     "UTF-8 string at [ptr, ptr+len) in INSTANCE's exported linear memory."
     [instance ptr len]
     (.readString (.memory instance) (int ptr) (int len))))

#?(:clj
   (defn- write-bytes!
     "Write BS into INSTANCE's memory at PTR (capacity CAP bytes); -1 if BS
     would overflow CAP."
     [instance ptr cap bs]
     (let [n (count bs)]
       (if (> n cap)
         -1
         (do (.write (.memory instance) (int ptr) (byte-array bs) 0 n)
             n)))))

#?(:clj
   (def ^:private valtype {:i32 ValType/I32 :i64 ValType/I64}))

#?(:clj
   (defn- host-fn
     "One (module \"kotoba\") host import -- FIELD, param/result keyword
     types (:i32/:i64, matching aiueos.policy's kernel-cap :params/:result
     shapes), and a Clojure fn [instance long-args] -> long."
     [field params result f]
     (HostFunction. "kotoba" field
                    (FunctionType/of (mapv valtype params) [(valtype result)])
                    (reify WasmFunctionHandle
                      (apply [_ instance args]
                        (long-array [(f instance args)]))))))

#?(:clj
   (defn- count-and-check!
     "ADR-0006 quota enforcement: increment COUNT-ATOM, and if it now
     exceeds LIMIT, throw ex-info tagged `:aiueos.execute/quota-exceeded`
     (caught by `run-if-granted`, which aborts the run without letting F
     execute the offending call) instead of running F. This is a call-COUNT
     cap, not instruction-level fuel metering -- see the aiueos.execute
     namespace docstring for why: Chicory has no gas-metering API yet
     (ADR-2607022900), so this is what's actually enforceable today."
     [count-atom limit kind f]
     (let [n (swap! count-atom inc)]
       (if (> n limit)
         (throw (ex-info (str "aiueos quota exceeded: " (name kind))
                          {:aiueos.execute/quota-exceeded {:kind kind :limit limit :count n}}))
         (f)))))

#?(:clj
   (defn- assert-topic-allowed!
     "The topic-id allow-set gate `aiueos.manifest/normalize` derives into
     `:aiueos/publishes`/`:aiueos/subscribes` (`nil` = unrestricted, a set
     = restricted to exactly those numeric topic ids -- see
     `aiueos.manifest/derive-topic-ids`'s docstring) was previously
     validated/derived but never enforced anywhere: a granted component
     could publish to or read from ANY topic id, not just its declared
     ones. Throws ex-info tagged `:aiueos.execute/topic-forbidden` (same
     abort convention as quota/fuel) when ALLOWED-IDS is a set and
     TOPIC-ID isn't in it; a no-op when ALLOWED-IDS is nil (unrestricted)."
     [op topic-id allowed-ids]
     (when (and allowed-ids (not (contains? allowed-ids topic-id)))
       (throw (ex-info (str "aiueos topic " (name op) " forbidden: topic " topic-id)
                        {:aiueos.execute/topic-forbidden {:op op :topic-id topic-id}})))))

#?(:clj
   (defn- fuel-listener
     "`:aiueos/limits :fuel` (ADR-0001) enforcement: an ExecutionListener
     that increments FUEL-ATOM on every Wasm instruction executed and
     throws (same `:aiueos.execute/*-exceeded` ex-data convention as
     `count-and-check!`, tagged `:aiueos.execute/fuel-exceeded`) the
     instant it exceeds LIMIT. See the namespace docstring for why this is
     a prototype on an unofficial Chicory API, not a permanent guarantee."
     [fuel-atom limit]
     (reify ExecutionListener
       (onExecution [_ _instruction _stack]
         (let [n (swap! fuel-atom inc)]
           (when (> n limit)
             (throw (ex-info "aiueos fuel exceeded"
                              {:aiueos.execute/fuel-exceeded {:limit limit :count n}}))))))))

#?(:clj
   (defn- memory-limits-for
     "`:aiueos/limits :memory-pages` (ADR-0001) enforcement, as a Chicory
     `MemoryLimits` for `instantiate` to pass to `withMemoryLimits`. MODULE
     is the already-`Parser/parse`d WasmModule -- every `.kotoba`-compiled
     module declares its own memory section (`kotoba-clj` always emits
     `:kotoba.wasm/memory? true`), so this reads that section's OWN
     `initialPages` and NEVER overrides it (a module that needs N pages to
     even start must still get them -- overriding initial to less than
     what the module declares silently starts it under-provisioned, which
     empirically causes `Instance/builder` to still \"succeed\" but hands
     the guest less memory than it assumes it has). Only the MAXIMUM a
     `memory.grow` call can reach is capped, to
     `min(manifest-limit, module's-own-declared-max)`."
     [module manifest-limit]
     (let [own-limits (.limits (.getMemory (.get (.memorySection module)) 0))]
       (MemoryLimits. (.initialPages own-limits) (min manifest-limit (.maximumPages own-limits))))))

#?(:clj
   (defn- device-access-stub
     "A deterministic always-0 stub for one of the device-access quartet
     (pci-config/dma-map/irq-subscribe/mmio-map). Real hardware access
     stays unimplemented here per ADR-2607022900 -- registering these as
     capabilities makes them nameable/gateable from .kotoba source, it does
     not grant hardware access. Mirrors kotoba.wasm-exec's
     stub-host-function convention. Still counts against HOST-CALLS-ATOM's
     quota -- a component spamming an unimplemented capability is still
     resource abuse."
     [field params result host-calls-atom host-calls-limit]
     (host-fn field params result
              (fn [_instance _args]
                (count-and-check! host-calls-atom host-calls-limit :host-calls
                                   (fn [] 0))))))

#?(:clj
   (defn aiueos-host-functions
     "The 7 non-hardware aiueos kernel-cap host imports, backed by real
     Clojure behavior:
     - log-write: appends the UTF-8 string at (ptr,len) to LOG-ATOM (a
       vector of strings).
     - clock-monotonic: System/nanoTime.
     - random-bytes: fills (ptr,len) with SecureRandom bytes.
     - topic-publish/topic-poll/topic-take/topic-count: delegate to
       aiueos.topic, threading the pure bus value through TOPIC-BUS-ATOM.

     Every call here counts against HOST-CALLS-ATOM/HOST-CALLS-LIMIT
     (ADR-0006 quota, `:aiueos/quota :host-calls`); `topic_publish`
     additionally counts against PUBLISHES-ATOM/PUBLISHES-LIMIT
     (`:aiueos/quota :publishes`) -- exceeding either throws
     (`count-and-check!`), aborting the run.

     Every topic-* call also checks its topic-id argument against
     PUBLISHES-ALLOWED (`topic_publish`) or SUBSCRIBES-ALLOWED
     (`topic_poll`/`topic_take`/`topic_count`) -- the manifest's declared
     `:aiueos/publishes`/`:aiueos/subscribes` allow-set (`nil` =
     unrestricted; see `assert-topic-allowed!`). A component granted
     `:topic/publish` could otherwise publish to or read from ANY topic
     id, not just its declared ones -- this was a real, silent gap
     (`:aiueos/publishes`/`:aiueos/subscribes` were validated/derived by
     `aiueos.manifest` but never enforced anywhere) until this check.

     Returns a seq of HostFunction for `instantiate`. LOG-ATOM and
     TOPIC-BUS-ATOM are supplied by the caller (see `execute`) so a run's
     log/topic state is inspectable afterward and independent across runs."
     [log-atom topic-bus-atom host-calls-atom host-calls-limit publishes-atom publishes-limit
      publishes-allowed subscribes-allowed]
     [(host-fn "log_write" [:i32 :i32] :i32
               (fn [instance args]
                 (count-and-check!
                  host-calls-atom host-calls-limit :host-calls
                  (fn []
                    (swap! log-atom conj (read-str instance (aget args 0) (aget args 1)))
                    0))))
      (host-fn "clock_monotonic" [] :i64
                (fn [_instance _args]
                  (count-and-check!
                   host-calls-atom host-calls-limit :host-calls
                   (fn [] (System/nanoTime)))))
      (host-fn "random_bytes" [:i32 :i32] :i32
               (fn [instance args]
                 (count-and-check!
                  host-calls-atom host-calls-limit :host-calls
                  (fn []
                    (let [len (int (aget args 1))
                          bs (byte-array len)]
                      (.nextBytes (java.security.SecureRandom.) bs)
                      (write-bytes! instance (aget args 0) len bs))))))
      (host-fn "topic_publish" [:i32 :i64] :i32
               (fn [_instance args]
                 (count-and-check!
                  host-calls-atom host-calls-limit :host-calls
                  (fn []
                    (count-and-check!
                     publishes-atom publishes-limit :publishes
                     (fn []
                       (let [topic-id (int (aget args 0))]
                         (assert-topic-allowed! :publish topic-id publishes-allowed)
                         (swap! topic-bus-atom topic/publish topic-id (aget args 1))
                         0)))))))
      (host-fn "topic_poll" [:i32] :i64
               (fn [_instance args]
                 (count-and-check!
                  host-calls-atom host-calls-limit :host-calls
                  (fn []
                    (let [topic-id (int (aget args 0))]
                      (assert-topic-allowed! :subscribe topic-id subscribes-allowed)
                      (or (topic/latest @topic-bus-atom topic-id) 0))))))
      (host-fn "topic_take" [:i32] :i64
               (fn [_instance args]
                 (count-and-check!
                  host-calls-atom host-calls-limit :host-calls
                  (fn []
                    (let [topic-id (int (aget args 0))]
                      (assert-topic-allowed! :subscribe topic-id subscribes-allowed)
                      (let [[bus' v] (topic/take-sample @topic-bus-atom topic-id)]
                        (reset! topic-bus-atom bus')
                        (or v 0)))))))
      (host-fn "topic_count" [:i32] :i64
               (fn [_instance args]
                 (count-and-check!
                  host-calls-atom host-calls-limit :host-calls
                  (fn []
                    (let [topic-id (int (aget args 0))]
                      (assert-topic-allowed! :subscribe topic-id subscribes-allowed)
                      (topic/topic-count @topic-bus-atom topic-id))))))]))

#?(:clj
   (defn device-access-stubs
     "The 4 device-access quartet stubs (pci-config/dma-map/irq-subscribe/
     mmio-map) -- see `device-access-stub`'s docstring."
     [host-calls-atom host-calls-limit]
     [(device-access-stub "pci_config" [:i32 :i32] :i32 host-calls-atom host-calls-limit)
      (device-access-stub "dma_map" [:i32 :i32] :i64 host-calls-atom host-calls-limit)
      (device-access-stub "irq_subscribe" [:i32] :i64 host-calls-atom host-calls-limit)
      (device-access-stub "mmio_map" [:i64 :i32] :i64 host-calls-atom host-calls-limit)]))

#?(:clj
   (defn instantiate
     "Parse WASM-BYTES and build a Chicory Instance with all 11 aiueos
     kernel-cap host imports bound (7 real + 4 device-access stubs) plus a
     permissive `has_capability` stub (the static capability gate already
     ran at compile/broker-decision time; a denied component never reaches
     execution -- see `execute`). LOG-ATOM/TOPIC-BUS-ATOM per
     `aiueos-host-functions`; QUOTA is a normalized `:aiueos/quota` map
     (`{:host-calls N :publishes N}`, ADR-0006) -- `has_capability` itself
     is NOT quota-counted (a link-time permission check, not a resource-
     consuming action). FUEL-LIMIT (`:aiueos/limits :fuel`, ADR-0001) is
     wired via `fuel-listener` (see namespace docstring). MEMORY-PAGES-LIMIT
     (`:aiueos/limits :memory-pages`, ADR-0001) is wired via
     `memory-limits-for`/`withMemoryLimits` (see namespace docstring).
     TOPIC-ALLOWED is `{:publishes <set-or-nil> :subscribes <set-or-nil>}`
     -- the manifest's `:aiueos/publishes`/`:aiueos/subscribes` topic-id
     allow-sets (`nil` = unrestricted), enforced via
     `assert-topic-allowed!`."
     [wasm-bytes log-atom topic-bus-atom quota fuel-limit memory-pages-limit topic-allowed]
     (let [host-calls-atom (atom 0)
           publishes-atom (atom 0)
           fuel-atom (atom 0)
           has-capability (host-fn "has_capability" [:i32] :i32 (fn [_instance _args] 1))
           fns (concat [has-capability]
                       (aiueos-host-functions log-atom topic-bus-atom
                                               host-calls-atom (:host-calls quota)
                                               publishes-atom (:publishes quota)
                                               (:publishes topic-allowed) (:subscribes topic-allowed))
                       (device-access-stubs host-calls-atom (:host-calls quota)))
           imports (-> (ImportValues/builder)
                       (.addFunction (into-array ImportFunction fns))
                       .build)
           module (Parser/parse ^bytes wasm-bytes)]
       (-> (Instance/builder module)
           (.withImportValues imports)
           (.withUnsafeExecutionListener (fuel-listener fuel-atom fuel-limit))
           (.withMemoryLimits (memory-limits-for module memory-pages-limit))
           .build))))

#?(:clj
   (defn call-main
     "Invoke an already-built Instance's 0-arity exported `main`, returning
     its single i32/i64 result as a long."
     [instance]
     (aget ^longs (.apply (.export instance "main") (long-array 0)) 0)))

#?(:clj
   (def default-quota
     "Used when `m` (the manifest passed to `execute`/`execute-admission`)
     wasn't run through `aiueos.manifest/normalize` first, so it has no
     `:aiueos/quota` -- same generous defaults `normalize-quota` applies
     (1024 host-calls / 256 publishes per run)."
     {:host-calls manifest/default-host-calls :publishes manifest/default-quota-publishes}))

#?(:clj
   (def default-fuel
     "Used when `m` has no `:aiueos/limits :fuel` -- same generous default
     `normalize-limits` applies (10,000,000 Wasm instructions per run)."
     manifest/default-fuel))

#?(:clj
   (def default-memory-pages
     "Used when `m` has no `:aiueos/limits :memory-pages` -- same generous
     default `normalize-limits` applies (16 pages = 1 MiB)."
     manifest/default-memory-pages))

#?(:clj
   (defn- exceeded-key [e]
     (let [d (ex-data e)]
       (cond
         (contains? d :aiueos.execute/quota-exceeded) [:aiueos.execute/quota-exceeded (:aiueos.execute/quota-exceeded d)]
         (contains? d :aiueos.execute/fuel-exceeded) [:aiueos.execute/fuel-exceeded (:aiueos.execute/fuel-exceeded d)]
         (contains? d :aiueos.execute/topic-forbidden) [:aiueos.execute/topic-forbidden (:aiueos.execute/topic-forbidden d)]
         :else nil))))

#?(:clj
   (defn- topic-allowed-for
     "`m`'s `:aiueos/publishes`/`:aiueos/subscribes` (see
     `aiueos.manifest/normalize`'s docstring) as `instantiate`'s
     TOPIC-ALLOWED shape. An unnormalized `m` simply has neither key, so
     both come back `nil` -- exactly the correct \"unrestricted\" default,
     unlike quota/fuel which need an explicit generous default."
     [m]
     {:publishes (:aiueos/publishes m) :subscribes (:aiueos/subscribes m)}))

#?(:clj
   (defn- run-if-granted
     "Shared tail of `execute`/`execute-admission`: given an already-computed
     policy DECISION, only instantiate+run WASM-BYTES on Chicory when
     `:aiueos/decision` is `:grant`; a `:deny` decision is returned
     unmodified, unexecuted. QUOTA (`:aiueos/quota`, defaults to
     `default-quota`) caps host-call/publish counts (ADR-0006); FUEL-LIMIT
     (`:aiueos/limits :fuel`, defaults to `default-fuel`) caps Wasm
     instructions executed (ADR-0001, prototype -- see namespace
     docstring); MEMORY-PAGES-LIMIT (`:aiueos/limits :memory-pages`,
     defaults to `default-memory-pages`) caps how far the component's own
     `memory.grow` can reach (a stable Chicory API, unlike fuel -- see
     namespace docstring); TOPIC-ALLOWED (`topic-allowed-for`) restricts
     topic-* calls to the manifest's declared topic ids. Exceeding/
     violating quota/fuel/topic-allowed aborts the run; the result carries
     `:aiueos.execute/quota-exceeded`, `:aiueos.execute/fuel-exceeded`, or
     `:aiueos.execute/topic-forbidden` instead of `:aiueos.execute/result`,
     with whatever log/topic-bus state accumulated before the abort still
     attached. An unrelated exception still propagates uncaught.

     MEMORY-PAGES-LIMIT does NOT abort the run this way -- unlike
     quota/fuel/topic-allowed (host-side policy checks), a `memory.grow`
     beyond the cap is real WebAssembly semantics: Chicory's `Memory/grow`
     returns -1 (the standard \"grow failed\" sentinel) to the GUEST's own
     code, which keeps running and decides what to do with that -1 itself
     -- same as any other Wasm runtime's memory limit, not an aiueos-
     specific abort.

     Every result also carries an ADDITIVE `:aiueos/run-receipt`
     (`broker/run-receipt`, ADR-2607022900 follow-up 8 -- the pre-existing,
     tested `aiueos.broker` contract this namespace previously never
     adopted, now wired in alongside the `:aiueos.execute/*` shape rather
     than replacing it): `:succeeded` on normal completion, `:failed` on a
     quota/fuel/topic-forbidden abort (`:aiueos/error` set to the
     exception's message), or `:denied` when DECISION itself was `:deny`
     (no execution attempted). `:aiueos/started-at`/`:finished-at` are
     epoch milliseconds; `:aiueos/audit-events` mirrors the same
     `:aiueos.broker/audit-entries` DECISION already carried."
     ([decision wasm-bytes]
      (run-if-granted decision wasm-bytes default-quota default-fuel default-memory-pages
                       {:publishes nil :subscribes nil}))
     ([decision wasm-bytes quota fuel-limit memory-pages-limit topic-allowed]
      (let [component (:aiueos/component decision)
            audit-events (:aiueos.broker/audit-entries decision)]
        (if (= :grant (:aiueos/decision decision))
          (let [log-atom (atom [])
                topic-bus-atom (atom topic/empty-bus)
                instance (instantiate wasm-bytes log-atom topic-bus-atom quota fuel-limit
                                       memory-pages-limit topic-allowed)
                started-at (System/currentTimeMillis)]
            (try
              (let [result (call-main instance)
                    finished-at (System/currentTimeMillis)]
                (assoc decision
                       :aiueos.execute/result result
                       :aiueos.execute/log @log-atom
                       :aiueos.execute/topic-bus @topic-bus-atom
                       :aiueos/run-receipt
                       (broker/run-receipt component :succeeded
                                            :result result :started-at started-at
                                            :finished-at finished-at :audit-events audit-events)))
              (catch clojure.lang.ExceptionInfo e
                (let [finished-at (System/currentTimeMillis)]
                  (if-let [[k v] (exceeded-key e)]
                    (assoc decision
                           k v
                           :aiueos.execute/log @log-atom
                           :aiueos.execute/topic-bus @topic-bus-atom
                           :aiueos/run-receipt
                           (broker/run-receipt component :failed
                                                :error (ex-message e) :started-at started-at
                                                :finished-at finished-at :audit-events audit-events))
                    (throw e))))))
          (let [now (System/currentTimeMillis)]
            (assoc decision
                   :aiueos/run-receipt
                   (broker/run-receipt component :denied
                                        :started-at now :finished-at now
                                        :audit-events audit-events))))))))

#?(:clj
   (defn execute
     "The end-to-end path: verify `m` (a normalized manifest) against
     `graph`/`policy` via `aiueos.broker/verify-one`; only if granted,
     instantiate WASM-BYTES on Chicory and call its exported `main`, capped
     by `m`'s `:aiueos/quota` (`default-quota` if unnormalized),
     `:aiueos/limits :fuel`/`:memory-pages` (`default-fuel`/
     `default-memory-pages` if unnormalized), and
     `:aiueos/publishes`/`:aiueos/subscribes` (unrestricted if unnormalized).

     Returns `{:aiueos/decision :deny ...}` (the broker's denial, unexecuted),
     `{:aiueos/decision :grant ... :aiueos.execute/result <long>
     :aiueos.execute/log [<string>...] :aiueos.execute/topic-bus <bus>}` on a
     completed run, or the same shape with `:aiueos.execute/quota-exceeded
     {:kind :host-calls|:publishes :limit N :count N}`,
     `:aiueos.execute/fuel-exceeded {:limit N :count N}`, or
     `:aiueos.execute/topic-forbidden {:op :publish|:subscribe :topic-id N}`
     instead of `:result` when the run aborted mid-execution
     (`:memory-pages` never aborts -- see `run-if-granted`'s docstring)."
     [m graph policy wasm-bytes]
     (run-if-granted (broker/verify-one m graph policy) wasm-bytes
                      (or (:aiueos/quota m) default-quota)
                      (get-in m [:aiueos/limits :fuel] default-fuel)
                      (get-in m [:aiueos/limits :memory-pages] default-memory-pages)
                      (topic-allowed-for m))))

#?(:clj
   (defn execute-admission
     "The execution half of the retired Rust `Broker::admit` (ADR-0004),
     now actually runnable: floors `m`'s trust to `:ai-generated`
     (`broker/floor-trust-for-admission`) before verification -- an
     agent-submitted component can never grant itself trust -- then, only
     if still granted after the floor, instantiates and executes WASM-BYTES
     on Chicory exactly like `execute`. Same return shape as `execute`."
     [m graph policy wasm-bytes]
     (run-if-granted (broker/verify-admission m graph policy) wasm-bytes
                      (or (:aiueos/quota m) default-quota)
                      (get-in m [:aiueos/limits :fuel] default-fuel)
                      (get-in m [:aiueos/limits :memory-pages] default-memory-pages)
                      (topic-allowed-for m))))
