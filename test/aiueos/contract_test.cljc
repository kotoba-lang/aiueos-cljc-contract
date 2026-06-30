(ns aiueos.contract-test
  (:require [aiueos.contract :as contract]
            [clojure.test :refer [deftest is testing]]))

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
