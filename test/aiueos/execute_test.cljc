(ns aiueos.execute-test
  "Real end-to-end proof for ADR-2607022900: a .kotoba component, compiled
  to a genuine Wasm binary via kotoba-clj, verified through
  aiueos.broker/verify-one, and actually EXECUTED on Chicory (no Rust,
  no wasmtime, no subprocess) -- closing the compile -> check -> emit ->
  verify -> RUN loop entirely on the JVM."
  (:require [aiueos.contract :as contract]
            [aiueos.execute :as execute]
            [aiueos.graph :as graph]
            [aiueos.policy :as policy]
            [aiueos.topic :as topic]
            [clojure.test :refer [deftest is testing]]
            #?(:clj [clojure.string :as str])))

;; Compiled Wasm binaries, base64-embedded rather than checked in as binary
;; .wasm files -- this repo's .gitignore excludes *.wasm as a matter of
;; policy (avoid binaries in git), and these fixtures are small enough that
;; inlining is simpler than a build-time compile step. Each is the real
;; output of `bin/kotoba-clj wasm emit ... --binary --policy ...`
;; (kotoba-lang/kotoba) for the source shown in its comment.

#?(:clj
   (defn- b64->bytes [s]
     (.decode (java.util.Base64/getDecoder) (str/replace s "\n" ""))))

;; (ns demo-aiueos-execute-test)
;; (defn main [] (topic-publish 1 (i64 42)))
(def ^:private topic-publish-wasm-b64
  "AGFzbQEAAAABCwJgAn9+AX9gAAF/AhgBBmtvdG9iYQ10b3BpY19wdWJsaXNoAAADAgEBBQMBAAEG\nBwF/AUGAEAsHEQIEbWFpbgABBm1lbW9yeQIACgoBCABBAUIqEAAL")

;; (ns demo-aiueos-irq)
;; (defn main [] (irq-subscribe 33))
(def ^:private irq-subscribe-wasm-b64
  "AGFzbQEAAAABCgJgAX8BfmAAAX4CGAEGa290b2JhDWlycV9zdWJzY3JpYmUAAAMCAQEFAwEAAQYH\nAX8BQYAQCwcRAgRtYWluAAEGbWVtb3J5AgAKCAEGAEEhEAAL")

;; (ns demo-aiueos-mmio)
;; (defn main [] (mmio-map (i64 0) 4096))
(def ^:private mmio-map-wasm-b64
  "AGFzbQEAAAABCwJgAn5/AX5gAAF+AhMBBmtvdG9iYQhtbWlvX21hcAAAAwIBAQUDAQABBgcBfwFB\ngBALBxECBG1haW4AAQZtZW1vcnkCAAoLAQkAQgBBgCAQAAs=")

;; (ns demo-aiueos-dma)
;; (defn main [] (dma-map 0 4096))
(def ^:private dma-map-wasm-b64
  "AGFzbQEAAAABCwJgAn9/AX5gAAF+AhIBBmtvdG9iYQdkbWFfbWFwAAADAgEBBQMBAAEGBwF/AUGA\nEAsHEQIEbWFpbgABBm1lbW9yeQIACgsBCQBBAEGAIBAACw==")

;; (ns demo-aiueos-pci)
;; (defn main [] (pci-config 0 16))
(def ^:private pci-config-wasm-b64
  "AGFzbQEAAAABCwJgAn9/AX9gAAF/AhUBBmtvdG9iYQpwY2lfY29uZmlnAAADAgEBBQMBAAEGBwF/\nAUGAEAsHEQIEbWFpbgABBm1lbW9yeQIACgoBCABBAEEQEAAL")

;; No aiueos host imports at all -- built directly from WAT via wasm-tools,
;; not kotoba-clj (kotoba-clj's `memory-grow` primitive exists but this
;; module doesn't need any kotoba:* import surface, just raw Wasm
;; memory.grow, so hand-authored WAT is the more direct proof source here):
;;   (module
;;     (memory (export "memory") 1)
;;     (func (export "main") (result i32)
;;       i32.const 10
;;       memory.grow))
;; main() returns memory.grow's own result: the previous page count (1) on
;; success, or -1 on failure -- the real WebAssembly "grow failed" sentinel,
;; observable directly in :aiueos.execute/result.
(def ^:private memory-grow-wasm-b64
  "AGFzbQEAAAABBQFgAAF/AwIBAAUDAQABBxECBm1lbW9yeQIABG1haW4AAAoIAQYAQQpAAAs=")

#?(:clj
   (def topic-publish-wasm (b64->bytes topic-publish-wasm-b64)))

#?(:clj
   (def memory-grow-wasm (b64->bytes memory-grow-wasm-b64)))

(def empty-graph (graph/build []))

#?(:clj
   (deftest execute-denies-an-unresolved-import-without-reaching-chicory
     (testing "topic/publish is a default kernel-cap (always granted); an
     UNKNOWN import with no provider or grant is what actually exercises
     deny -- never reaches Chicory"
       (let [m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:custom/nobody-provides-this}}
             result (execute/execute m empty-graph policy/default-policy topic-publish-wasm)]
         (is (= :deny (:aiueos/decision result)))
         (is (= [:unresolved-capability] (mapv :aiueos/kind (:aiueos/violations result))))
         (is (not (contains? result :aiueos.execute/result)))))))

#?(:clj
   (deftest execute-grants-and-actually-runs-on-chicory
     (testing "granted -- the wasm module really executes, topic-publish really mutates the bus"
       (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
             m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:topic/publish}}
             result (execute/execute m empty-graph policy* topic-publish-wasm)]
         (is (= :grant (:aiueos/decision result)))
         (is (= 0 (:aiueos.execute/result result))
             "topic-publish's own host import returns i32 status 0 on success")
         (is (= 42 (topic/latest (:aiueos.execute/topic-bus result) 1))
             "the component's (topic-publish 1 (i64 42)) call really landed in the topic bus")
         (is (= 1 (topic/topic-count (:aiueos.execute/topic-bus result) 1)))))))

#?(:clj
   (deftest execute-log-atom-starts-empty-when-no-log-write-is-called
     (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
           m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
              :aiueos/imports #{:topic/publish}}
           result (execute/execute m empty-graph policy* topic-publish-wasm)]
       (is (= [] (:aiueos.execute/log result))))))

;; ───────── device-access quartet: stubs really execute through the full
;; compile -> decide -> Chicory pipeline, not just link-check ─────────

#?(:clj
   (def device-access-execute-demos
     "pci/config, dma/map, irq/subscribe, mmio/map are all default kernel
     caps (aiueos.policy/default-kernel-caps) -- no explicit grant needed,
     same as topic/publish above. Each stub always returns 0 (see
     aiueos.execute/device-access-stub); this proves that return value
     really comes back through a live Chicory call, not just a static
     assumption."
     [{:component :app/irq :capability :irq/subscribe :wasm (b64->bytes irq-subscribe-wasm-b64)}
      {:component :app/mmio :capability :mmio/map :wasm (b64->bytes mmio-map-wasm-b64)}
      {:component :app/dma :capability :dma/map :wasm (b64->bytes dma-map-wasm-b64)}
      {:component :app/pci :capability :pci/config :wasm (b64->bytes pci-config-wasm-b64)}]))

#?(:clj
   (deftest device-access-quartet-executes-through-chicory-and-stub-returns-zero
     (doseq [{:keys [component capability wasm]} device-access-execute-demos]
       (let [m {:aiueos/component component :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{capability}}
             result (execute/execute m empty-graph policy/default-policy wasm)]
         (is (= :grant (:aiueos/decision result)) component)
         (is (= 0 (:aiueos.execute/result result))
             (str component ": device-access stub must return 0 through a real Chicory call"))))))

;; ───────── ADR-0006 quota enforcement: aborts a real Chicory run, not
;; just a static check ─────────

#?(:clj
   (deftest execute-with-generous-default-quota-runs-normally
     (testing "an unnormalized manifest (no :aiueos/quota key) falls back
     to execute/default-quota and behaves exactly like before quota
     enforcement existed"
       (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
             m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:topic/publish}}
             result (execute/execute m empty-graph policy* topic-publish-wasm)]
         (is (= :grant (:aiueos/decision result)))
         (is (not (contains? result :aiueos.execute/quota-exceeded)))))))

#?(:clj
   (deftest execute-aborts-when-the-publishes-quota-is-exhausted
     (testing "publishes quota 0 -- the component's single topic-publish
     call is the FIRST call and already exceeds it; the run aborts
     through a real Chicory host-function throw, not a static check"
       (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
             m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:topic/publish}
                :aiueos/quota {:host-calls 1024 :publishes 0}}
             result (execute/execute m empty-graph policy* topic-publish-wasm)]
         (is (= :grant (:aiueos/decision result))
             "the CAPABILITY decision is still :grant -- quota is a separate, run-time-only limit")
         (is (not (contains? result :aiueos.execute/result))
             "no :result -- the run aborted before main returned normally")
         (is (= {:kind :publishes :limit 0 :count 1}
                (:aiueos.execute/quota-exceeded result)))
         (is (= (topic/topic-count topic/empty-bus 1) (topic/topic-count (:aiueos.execute/topic-bus result) 1))
             "the offending call's own effect never landed -- checked before the swap!")))))

#?(:clj
   (deftest execute-aborts-when-the-host-calls-quota-is-exhausted
     (testing "host-calls quota 0 -- the component's first host call
     (topic-publish itself) already exceeds it, before the :publishes
     sub-check even runs"
       (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
             m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:topic/publish}
                :aiueos/quota {:host-calls 0 :publishes 256}}
             result (execute/execute m empty-graph policy* topic-publish-wasm)]
         (is (= :grant (:aiueos/decision result)))
         (is (= {:kind :host-calls :limit 0 :count 1}
                (:aiueos.execute/quota-exceeded result)))))))

#?(:clj
   (deftest execute-admission-also-enforces-quota
     (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
           m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :ai-generated
              :aiueos/imports #{:topic/publish}
              :aiueos/quota {:host-calls 1024 :publishes 0}}
           result (execute/execute-admission m empty-graph policy* topic-publish-wasm)]
       (is (= :grant (:aiueos/decision result)))
       (is (= :publishes (:kind (:aiueos.execute/quota-exceeded result)))))))

;; ───────── ADR-0001 fuel enforcement (prototype, ADR-2607022900
;; follow-up 2): real instruction-level metering via Chicory's
;; withUnsafeExecutionListener, not just a call-count proxy ─────────

#?(:clj
   (deftest execute-with-generous-default-fuel-runs-normally
     (testing "an unnormalized manifest (no :aiueos/limits key) falls back
     to execute/default-fuel (10M) and behaves exactly like before fuel
     enforcement existed"
       (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
             m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:topic/publish}}
             result (execute/execute m empty-graph policy* topic-publish-wasm)]
         (is (= :grant (:aiueos/decision result)))
         (is (not (contains? result :aiueos.execute/fuel-exceeded)))))))

#?(:clj
   (deftest execute-aborts-when-fuel-is-exhausted
     (testing "fuel limit 1 -- the component's `main` executes more than
     one Wasm instruction (a constant load + a call, at minimum), so the
     run aborts on real per-instruction metering via Chicory's
     ExecutionListener, not a static analysis"
       (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
             m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:topic/publish}
                :aiueos/limits {:memory-pages 16 :fuel 1}}
             result (execute/execute m empty-graph policy* topic-publish-wasm)]
         (is (= :grant (:aiueos/decision result))
             "the CAPABILITY decision is still :grant -- fuel is a separate, run-time-only limit")
         (is (not (contains? result :aiueos.execute/result))
             "no :result -- the run aborted before main returned normally")
         (is (contains? result :aiueos.execute/fuel-exceeded))
         (is (= 1 (:limit (:aiueos.execute/fuel-exceeded result))))
         (is (pos? (:count (:aiueos.execute/fuel-exceeded result)))
             "the count is whatever the real instruction stream reached before the abort")))))

#?(:clj
   (deftest execute-fuel-and-quota-are-independent-limits
     (testing "a generous fuel limit alongside an exhausted quota still
     reports quota-exceeded, not fuel-exceeded -- confirms the two
     mechanisms don't interfere with each other"
       (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
             m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:topic/publish}
                :aiueos/quota {:host-calls 1024 :publishes 0}
                :aiueos/limits {:memory-pages 16 :fuel 10000000}}
             result (execute/execute m empty-graph policy* topic-publish-wasm)]
         (is (contains? result :aiueos.execute/quota-exceeded))
         (is (not (contains? result :aiueos.execute/fuel-exceeded)))))))

;; ───────── topic-id allow-set enforcement (:aiueos/publishes /
;; :aiueos/subscribes, derived by aiueos.manifest but previously never
;; enforced anywhere -- a real, silent capability-gating gap) ─────────

#?(:clj
   (deftest execute-aborts-when-publishing-to-a-topic-id-outside-the-allow-set
     (testing "the fixture publishes to topic 1; declaring :aiueos/publishes
     #{2} (topic 1 NOT included) proves the check runs against the REAL
     argument the guest passed through Chicory, not a static analysis"
       (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
             m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:topic/publish}
                :aiueos/publishes #{2}}
             result (execute/execute m empty-graph policy* topic-publish-wasm)]
         (is (= :grant (:aiueos/decision result))
             "the CAPABILITY decision is still :grant -- the topic-id allow-set is a separate, run-time-only check")
         (is (not (contains? result :aiueos.execute/result))
             "no :result -- the run aborted before main returned normally")
         (is (= {:op :publish :topic-id 1} (:aiueos.execute/topic-forbidden result)))
         (is (= (topic/topic-count topic/empty-bus 1) (topic/topic-count (:aiueos.execute/topic-bus result) 1))
             "the offending publish's own effect never landed -- checked before the swap!")))))

#?(:clj
   (deftest execute-allows-publishing-when-the-topic-id-is-in-the-allow-set
     (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
           m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
              :aiueos/imports #{:topic/publish}
              :aiueos/publishes #{1}}
           result (execute/execute m empty-graph policy* topic-publish-wasm)]
       (is (= :grant (:aiueos/decision result)))
       (is (not (contains? result :aiueos.execute/topic-forbidden)))
       (is (= 42 (topic/latest (:aiueos.execute/topic-bus result) 1))))))

#?(:clj
   (deftest execute-with-no-declared-publishes-is-unrestricted
     (testing "an unnormalized manifest (no :aiueos/publishes key at all)
     falls back to nil -- unrestricted -- exactly like before this
     enforcement existed; same fixture as
     execute-grants-and-actually-runs-on-chicory above"
       (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
             m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
                :aiueos/imports #{:topic/publish}}
             result (execute/execute m empty-graph policy* topic-publish-wasm)]
         (is (not (contains? result :aiueos.execute/topic-forbidden)))
         (is (= 42 (topic/latest (:aiueos.execute/topic-bus result) 1)))))))

;; ───────── :aiueos/limits :memory-pages (ADR-0001): a stable Chicory API
;; (withMemoryLimits), unlike fuel -- and unlike quota/fuel/topic-allowed,
;; it does NOT abort the run: memory.grow beyond the cap returns -1 to the
;; GUEST's own code (real WebAssembly semantics), observable directly in
;; :aiueos.execute/result rather than a *-exceeded/-forbidden key ─────────

#?(:clj
   (deftest execute-with-generous-default-memory-pages-lets-memory-grow-succeed
     (testing "an unnormalized manifest (no :aiueos/limits key) falls back
     to execute/default-memory-pages (16 pages); growing by 10 stays well
     within that, so memory.grow succeeds and returns the previous page
     count (1)"
       (let [m {:aiueos/component :app/memory-grow :aiueos/kind :app :aiueos/trust :verified}
             result (execute/execute m empty-graph policy/default-policy memory-grow-wasm)]
         (is (= :grant (:aiueos/decision result)))
         (is (= 1 (:aiueos.execute/result result))
             "memory.grow(10) succeeded -- returns the PREVIOUS page count, not the new one")))))

#?(:clj
   (deftest execute-caps-memory-growth-and-the-guest-observes-the-failure
     (testing ":memory-pages 1 -- the module's own declared initial (1
     page) is honored (instantiation succeeds, unlike setting initial
     itself too low), but growing by 10 pages exceeds the cap; the guest's
     own memory.grow call gets Wasm's real -1 failure sentinel -- this is
     NOT an aiueos abort, :aiueos.execute/result is still populated
     normally, just holding the guest's own -1"
       (let [m {:aiueos/component :app/memory-grow :aiueos/kind :app :aiueos/trust :verified
                :aiueos/limits {:memory-pages 1 :fuel 10000000}}
             result (execute/execute m empty-graph policy/default-policy memory-grow-wasm)]
         (is (= :grant (:aiueos/decision result)))
         (is (= -1 (:aiueos.execute/result result))
             "memory.grow(10) FAILED under the cap -- Wasm's own -1 sentinel, not an aiueos exception")
         (is (not (contains? result :aiueos.execute/fuel-exceeded))
             "the memory cap is independent of fuel -- a generous fuel limit alongside it doesn't abort anything")))))

#?(:clj
   (deftest execute-admission-also-caps-memory-growth
     (let [m {:aiueos/component :app/memory-grow :aiueos/kind :app :aiueos/trust :ai-generated
              :aiueos/limits {:memory-pages 1 :fuel 10000000}}
           result (execute/execute-admission m empty-graph policy/default-policy memory-grow-wasm)]
       (is (= :grant (:aiueos/decision result)))
       (is (= -1 (:aiueos.execute/result result))))))

;; ───────── :aiueos/run-receipt (ADR-2607022900 follow-up 8): an ADDITIVE
;; field alongside the pre-existing :aiueos.execute/* shape -- wires
;; aiueos.broker's pre-existing, tested run-receipt contract into the real
;; execution path for the first time ─────────

#?(:clj
   (deftest execute-produces-a-succeeded-run-receipt-on-normal-completion
     (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
           m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
              :aiueos/imports #{:topic/publish}}
           result (execute/execute m empty-graph policy* topic-publish-wasm)
           receipt (:aiueos/run-receipt result)]
       (is (some? receipt) "run-receipt is ADDITIVE -- present alongside :aiueos.execute/result, not replacing it")
       (is (= 42 (topic/latest (:aiueos.execute/topic-bus result) 1))
           "the pre-existing :aiueos.execute/* shape is untouched by this change")
       (is (= :app/topic-publish (:aiueos/component receipt)))
       (is (= :succeeded (:aiueos/status receipt)))
       (is (= 0 (:aiueos/result receipt)))
       (is (nat-int? (:aiueos/started-at receipt)))
       (is (nat-int? (:aiueos/finished-at receipt)))
       (is (>= (:aiueos/finished-at receipt) (:aiueos/started-at receipt)))
       (is (vector? (:aiueos/audit-events receipt))))))

#?(:clj
   (deftest execute-produces-a-denied-run-receipt-without-executing
     (let [m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
              :aiueos/imports #{:custom/nobody-provides-this}}
           result (execute/execute m empty-graph policy/default-policy topic-publish-wasm)
           receipt (:aiueos/run-receipt result)]
       (is (= :deny (:aiueos/decision result)))
       (is (some? receipt))
       (is (= :denied (:aiueos/status receipt)))
       (is (not (contains? receipt :aiueos/result))))))

#?(:clj
   (deftest execute-produces-a-failed-run-receipt-when-quota-aborts-the-run
     (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
           m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
              :aiueos/imports #{:topic/publish}
              :aiueos/quota {:host-calls 1024 :publishes 0}}
           result (execute/execute m empty-graph policy* topic-publish-wasm)
           receipt (:aiueos/run-receipt result)]
       (is (contains? result :aiueos.execute/quota-exceeded))
       (is (some? receipt))
       (is (= :failed (:aiueos/status receipt)))
       (is (string? (:aiueos/error receipt))))))

#?(:clj
   (deftest run-receipt-round-trips-through-aiueos-contract-validate-run-receipt
     (let [policy* (policy/parse-policy {:aiueos/grants {:app/topic-publish #{:topic/publish}}})
           m {:aiueos/component :app/topic-publish :aiueos/kind :app :aiueos/trust :verified
              :aiueos/imports #{:topic/publish}}
           result (execute/execute m empty-graph policy* topic-publish-wasm)
           receipt (:aiueos/run-receipt result)]
       (is (:valid? (contract/validate-run-receipt receipt))
           "the receipt execute produces really satisfies aiueos.contract's own shape validator"))))
