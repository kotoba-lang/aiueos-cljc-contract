(ns aiueos.execute-test
  "Real end-to-end proof for ADR-2607022900: a .kotoba component, compiled
  to a genuine Wasm binary via kotoba-clj, verified through
  aiueos.broker/verify-one, and actually EXECUTED on Chicory (no Rust,
  no wasmtime, no subprocess) -- closing the compile -> check -> emit ->
  verify -> RUN loop entirely on the JVM."
  (:require [aiueos.execute :as execute]
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

#?(:clj
   (def topic-publish-wasm (b64->bytes topic-publish-wasm-b64)))

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
