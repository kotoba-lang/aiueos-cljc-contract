(ns aiueos.contract-test
  (:require [aiueos.contract :as contract]
            #?(:clj [clojure.edn :as edn])
            #?(:clj [clojure.java.io :as io])
            [clojure.test :refer [deftest is testing]]))

#?(:clj
   (defn- example-edn-files []
     (->> (file-seq (io/file "examples"))
          (filter #(.isFile %))
          (filter #(.endsWith (.getName %) ".edn"))
          (sort-by #(.getPath %)))))

#?(:clj
   (defn- read-edn-file [file]
     (edn/read-string (slurp file))))

#?(:clj
   (defn- example-kind [data]
     (cond
       (:aiueos/component data) :manifest
       (:aiueos/system data) :system
       (or (:aiueos/policy data)
           (:aiueos/kernel-caps data)
           (:aiueos/signers data)) :policy
       :else :fixture)))

#?(:clj
   (defn- validate-example [kind data]
     (case kind
       :manifest (contract/validate-manifest data)
       :system (contract/validate-system data)
       :policy (contract/validate-deployment-policy data)
       :fixture {:valid? true :errors []})))

(def minimal-manifest
  {:aiueos/component :service/log
   :aiueos/kind :service
   :aiueos/trust :verified
   :aiueos/source "log-service.clj"
   :aiueos/entry "init"
   :aiueos/args []
   :aiueos/exports #{:log/write}
   :aiueos/effects #{:storage}
   :aiueos/limits {:memory-pages 8 :fuel 1000000}})

(deftest manifest-contract
  (testing "validates the minimal component manifest shape"
    (is (contract/manifest? minimal-manifest))
    (is (= {:valid? true :errors []}
           (contract/validate-manifest minimal-manifest))))
  (testing "rejects missing, unknown, and malformed authority fields"
    (let [result (contract/validate-manifest
                  {:aiueos/component :service/log
                   :aiueos/kind :unknown
                   :aiueos/effcts #{:network}
                   :aiueos/args [:not-an-int]})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/kind] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/effcts] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/args] (:path %)) (:errors result))))))

(deftest policy-decision-contract
  (testing "validates grant decisions"
    (is (contract/policy-decision?
         {:aiueos/decision :grant
          :aiueos/component :service/log
          :aiueos/capabilities #{:log/write}})))
  (testing "validates deny decisions with violation shape"
    (is (contract/policy-decision?
         {:aiueos/decision :deny
          :aiueos/component :agent/generated
          :aiueos/violations
          [{:aiueos/kind :forbidden-effect
            :aiueos/message "effect network is forbidden"}]})))
  (testing "rejects incomplete decisions"
    (let [result (contract/validate-policy-decision
                  {:aiueos/decision :grant
                   :aiueos/component :service/log})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/capabilities] (:path %)) (:errors result))))))

(deftest audit-event-contract
  (testing "validates audit events emitted by authority or host adapters"
    (is (contract/audit-event?
         {:aiueos/ts 1782748800
          :aiueos/event :grant
          :aiueos/component :service/log
          :aiueos/detail "capabilities #{:log/write}"})))
  (testing "rejects malformed events"
    (let [result (contract/validate-audit-event
                  {:aiueos/ts -1
                   :aiueos/event :unknown
                   :aiueos/component ""})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/ts] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/event] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/detail] (:path %)) (:errors result))))))

(def aiueos-component-boundary
  #?(:clj (contract/load-component-boundary)
     :cljs
     {:aiueos/world :aiueos/component
      :aiueos/contract :aiueos/authority
      :aiueos/adapter :wasm-component-model
      :aiueos/wit "generated-or-checked-from-edn"
      :aiueos/imports
      [{:aiueos/name :host/wasm-runner
        :aiueos/direction :import
        :aiueos/capability :host/execute
        :aiueos/request :aiueos/run-plan
        :aiueos/response :aiueos/run-receipt}
       {:aiueos/name :host/filesystem
        :aiueos/direction :import
        :aiueos/capability :fs/read
        :aiueos/request :aiueos/manifest
        :aiueos/response :aiueos/manifest}
       {:aiueos/name :host/process
        :aiueos/direction :import
        :aiueos/capability :process/spawn
        :aiueos/request :aiueos/run-plan
        :aiueos/response :aiueos/run-receipt}
       {:aiueos/name :host/device
        :aiueos/direction :import
        :aiueos/capability :device/io
        :aiueos/request :aiueos/run-plan
        :aiueos/response :aiueos/run-receipt}
       {:aiueos/name :host/audit-sink
        :aiueos/direction :import
        :aiueos/capability :audit/write
        :aiueos/request :aiueos/audit-event
        :aiueos/response :aiueos/audit-receipt}]
      :aiueos/exports
      [{:aiueos/name :aiueos/verify
        :aiueos/direction :export
        :aiueos/request :aiueos/manifest
        :aiueos/response :aiueos/policy-decision}
       {:aiueos/name :aiueos/inspect
        :aiueos/direction :export
        :aiueos/request :aiueos/manifest
        :aiueos/response :aiueos/component-boundary}
       {:aiueos/name :aiueos/admit
        :aiueos/direction :export
        :aiueos/request :aiueos/manifest
        :aiueos/response :aiueos/policy-decision}
       {:aiueos/name :aiueos/run-plan
        :aiueos/direction :export
        :aiueos/request :aiueos/manifest
        :aiueos/response :aiueos/run-plan}]}))

(deftest component-boundary-contract
  (testing "validates kotoba authority for the Wasm Component Model boundary"
    (is (contract/component-boundary? aiueos-component-boundary))
    (is (= {:valid? true :errors []}
           (contract/validate-component-boundary aiueos-component-boundary)))
    (is (= contract/required-component-imports
           (set (map :aiueos/name (:aiueos/imports aiueos-component-boundary)))))
    (is (= contract/required-component-exports
           (set (map :aiueos/name (:aiueos/exports aiueos-component-boundary))))))
  (testing "rejects malformed component ports before WIT or host adapters are considered"
    (let [result (contract/validate-component-boundary
                  {:aiueos/world :aiueos/component
                   :aiueos/wit 42
                   :aiueos/imports
                   [{:aiueos/name :host/wasm-runner
                     :aiueos/direction :export}]
                   :aiueos/exports
                   [{:aiueos/direction :export}]})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/wit] (:path %)) (:errors result)))
      (is (some #(= [:import 0 :aiueos/direction] (:path %)) (:errors result)))
      (is (some #(= [:export 0 :aiueos/name] (:path %)) (:errors result))))))

(deftest component-boundary-completeness-contract
  (testing "rejects boundary data that leaves Rust/provider authority implicit"
    (let [result (contract/validate-component-boundary
                  (update aiueos-component-boundary :aiueos/imports
                          #(vec (remove (comp #{:host/device} :aiueos/name) %))))]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/imports] (:path %)) (:errors result)))))
  (testing "rejects non-Component-Model adapter authority"
    (let [result (contract/validate-component-boundary
                  (assoc aiueos-component-boundary :aiueos/adapter :rust-host))]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/adapter] (:path %)) (:errors result))))))

(def normalized-grant
  {:aiueos/subject "did:key:z6Mkoperator"
   :aiueos/audience :aiueos/component
   :aiueos/component :service/log
   :aiueos/manifest-cid "bafy-manifest"
   :aiueos/wasm-cid "bafy-wasm"
   :aiueos/capabilities #{:log/write}
   :aiueos/limits {:host-calls 2}
   :aiueos/not-before 1782748800
   :aiueos/expires-at 1782752400
   :aiueos/proof {:type :kotoba/grant-signature}})

(def grant-audit-event
  {:aiueos/ts 1782748801
   :aiueos/event :grant
   :aiueos/component :service/log
   :aiueos/detail "effective capabilities #{:log/write}"})

(def run-plan
  {:aiueos/component :service/log
   :aiueos/manifest minimal-manifest
   :aiueos/decision
   {:aiueos/decision :grant
    :aiueos/component :service/log
    :aiueos/capabilities #{:log/write}}
   :aiueos/grant normalized-grant
   :aiueos/component-boundary aiueos-component-boundary
   :aiueos/entry "init"
   :aiueos/args []
   :aiueos/limits {:memory-pages 8 :fuel 1000000}
   :aiueos/imports contract/required-component-imports
   :aiueos/audit-events [grant-audit-event]})

(def run-receipt
  {:aiueos/component :service/log
   :aiueos/status :succeeded
   :aiueos/result {:value 0}
   :aiueos/started-at 1782748802
   :aiueos/finished-at 1782748803
   :aiueos/run-cid "bafy-run"
   :aiueos/input-cid "bafy-input"
   :aiueos/output-cid "bafy-output"
   :aiueos/audit-events
   [{:aiueos/ts 1782748803
     :aiueos/event :run
     :aiueos/component :service/log
     :aiueos/detail "component completed"}]})

(deftest grant-contract
  (testing "validates normalized Kotoba Grant data before local materialization"
    (is (contract/grant? normalized-grant))
    (is (= {:valid? true :errors []}
           (contract/validate-grant normalized-grant))))
  (testing "rejects external-envelope-shaped or untyped grants"
    (let [result (contract/validate-grant
                  {:aiueos/subject "did:key:z6Mkoperator"
                   :aiueos/audience :aiueos/component
                   :aiueos/component :service/log
                   :aiueos/capabilities [:log/write]
                   :aiueos/resources ["https://example.com/*"]})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/capabilities] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/resources] (:path %)) (:errors result))))))

(deftest run-plan-contract
  (testing "validates broker-produced run plans for component providers"
    (is (contract/run-plan? run-plan))
    (is (= {:valid? true :errors []}
           (contract/validate-run-plan run-plan))))
  (testing "rejects plans with malformed nested authority data"
    (let [result (contract/validate-run-plan
                  (assoc-in run-plan
                            [:aiueos/decision :aiueos/decision]
                            :maybe))]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/decision :aiueos/decision] (:path %)) (:errors result))))))

(deftest run-receipt-contract
  (testing "validates provider-produced receipts"
    (is (contract/run-receipt? run-receipt))
    (is (= {:valid? true :errors []}
           (contract/validate-run-receipt run-receipt))))
  (testing "rejects receipts with malformed status or audit events"
    (let [result (contract/validate-run-receipt
                  {:aiueos/component :service/log
                   :aiueos/status :done
                   :aiueos/audit-events
                   [{:aiueos/ts -1
                     :aiueos/event :run
                     :aiueos/component :service/log
                     :aiueos/detail "bad"}]})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/status] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/audit-events 0 :aiueos/ts] (:path %)) (:errors result))))))

(deftest policy-contract-authority
  (testing "validates aiueos policy tables as CLJC/EDN authority"
    (let [policy (contract/load-policy-contract)]
      (is (contract/policy-contract? policy))
      (is (= {:valid? true :errors []}
             (contract/validate-policy-contract policy)))))
  (testing "rejects Rust-owned policy authority"
    (let [result (contract/validate-policy-contract
                  {:aiueos.policy/id :aiueos/default-policy
                   :aiueos.policy/authority [:rust]
                   :aiueos.policy/source-files ["src/policy.rs"]
                   :aiueos.policy/kernel-caps #{:log/write}
                   :aiueos.policy/forbid {:ai-generated #{:network}}
                   :aiueos.policy/decision-shapes #{:grant}
                   :aiueos.policy/violation-kinds #{:forbidden-effect}
                   :aiueos.policy/signer-statuses #{:active}
                   :aiueos.policy/effects #{:network}
                   :aiueos.policy/grant-fields [:aiueos/component]})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos.policy/authority] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.policy/decision-shapes] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.policy/violation-kinds] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.policy/kernel-caps] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.policy/grant-fields] (:path %)) (:errors result))))))

(deftest broker-contract-authority
  (testing "validates aiueos broker flows as CLJC/EDN authority"
    (let [broker (contract/load-broker-contract)]
      (is (contract/broker-contract? broker))
      (is (= {:valid? true :errors []}
             (contract/validate-broker-contract broker)))))
  (testing "rejects runtime-owned broker flow authority"
    (let [result (contract/validate-broker-contract
                  {:aiueos.broker/id :aiueos/capability-broker
                   :aiueos.broker/authority [:rust]
                   :aiueos.broker/source-files ["src/broker.rs"]
                   :aiueos.broker/policy :rust/policy
                   :aiueos.broker/component-boundary :native
                   :aiueos.broker/flows
                   [{:aiueos.broker/name :launch
                     :aiueos.broker/input :aiueos/manifest
                     :aiueos.broker/output :aiueos/run-plan
                     :aiueos.broker/steps ["verify"]}]
                   :aiueos.broker/audit-events #{:grant}
                   :aiueos.broker/run-statuses #{:succeeded}})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos.broker/authority] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.broker/policy] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.broker/component-boundary] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.broker/flows 0 :aiueos.broker/name] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.broker/flows 0 :aiueos.broker/steps] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.broker/flows] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.broker/audit-events] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.broker/run-statuses] (:path %)) (:errors result))))))

(deftest aiueos-provider-filesystem-conformance
  (testing "policy and broker source-files name real CLJC files in this repo, not Rust in ../aiueos"
    (let [contracts [(contract/load-policy-contract)
                     (contract/load-broker-contract)]]
      (is (seq (-> contracts first :aiueos.policy/source-files)))
      (is (seq (-> contracts second :aiueos.broker/source-files))
          "aiueos.broker ports verify-system/verify-one/run-plan/run-receipt-shaping (ADR-2607022200); :provider/execute stays a native adapter concern, not modeled here")
      (is (= {:valid? true :errors []}
             (contract/validate-aiueos-provider-files contracts "."))))))

#?(:clj
   (deftest example-fixtures-follow-authority-contracts
     (testing "examples are checked by CLJC/EDN authority instead of host runtime code"
       (let [classified (map (fn [file]
                               (let [data (read-edn-file file)
                                     kind (example-kind data)
                                     result (validate-example kind data)]
                                 {:path (.getPath file)
                                  :kind kind
                                  :valid? (:valid? result)
                                  :errors (:errors result)}))
                             (example-edn-files))
             by-kind (frequencies (map :kind classified))
             failures (remove :valid? classified)]
         (is (= {:manifest 15 :system 4 :policy 4 :fixture 3} by-kind))
         (is (empty? failures) (pr-str failures))))))
