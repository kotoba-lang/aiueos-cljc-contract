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

;; The compiled Wasm binary for:
;;   (ns demo-aiueos-execute-test)
;;   (defn main [] (topic-publish 1 (i64 42)))
;; built via `bin/kotoba-clj wasm emit ... --binary --policy
;; {:kotoba.policy/capabilities #{:topic/publish}}` (kotoba-lang/kotoba).
;; Base64-embedded (96 bytes) rather than checked in as a binary .wasm file
;; -- this repo's .gitignore excludes *.wasm as a matter of policy (avoid
;; binaries in git), and this fixture is small enough that inlining is the
;; simpler, gitignore-respecting choice over a build-time compile step.
(def ^:private topic-publish-wasm-b64
  "AGFzbQEAAAABCwJgAn9+AX9gAAF/AhgBBmtvdG9iYQ10b3BpY19wdWJsaXNoAAADAgEBBQMBAAEG\nBwF/AUGAEAsHEQIEbWFpbgABBm1lbW9yeQIACgoBCABBAUIqEAAL")

#?(:clj
   (def topic-publish-wasm
     (.decode (java.util.Base64/getDecoder) (str/replace topic-publish-wasm-b64 "\n" ""))))

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
