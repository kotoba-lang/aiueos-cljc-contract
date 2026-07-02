(ns aiueos.policy-test
  (:require [aiueos.policy :as policy]
            [aiueos.graph :as graph]
            [clojure.test :refer [deftest is testing]]))

(def empty-graph (graph/build []))

(deftest grants-a-kernel-capability-import
  (let [m {:aiueos/component :service/log :aiueos/kind :service :aiueos/trust :verified
           :aiueos/imports #{:log/write} :aiueos/exports #{}}
        decision (policy/verify-component m empty-graph policy/default-policy)]
    (is (= :grant (:aiueos/decision decision)))
    (is (contains? (:aiueos/capabilities decision) :log/write))))

(deftest denies-an-unresolved-import
  (let [m {:aiueos/component :app/notes :aiueos/kind :app :aiueos/trust :verified
           :aiueos/imports #{:net/fetch} :aiueos/exports #{}}
        decision (policy/verify-component m empty-graph policy/default-policy)]
    (is (= :deny (:aiueos/decision decision)))
    (is (= [:unresolved-capability]
           (mapv :aiueos/kind (:aiueos/violations decision))))))

(deftest resolves-an-import-via-a-provider-component
  (let [fs-service {:aiueos/component :service/fs :aiueos/kind :service :aiueos/trust :verified
                    :aiueos/exports #{:fs/read} :aiueos/imports #{}}
        notes-app {:aiueos/component :app/notes :aiueos/kind :app :aiueos/trust :verified
                   :aiueos/imports #{:fs/read} :aiueos/exports #{}}
        g (graph/build [fs-service notes-app])
        decision (policy/verify-component notes-app g policy/default-policy)]
    (is (= :grant (:aiueos/decision decision)))
    (is (contains? (:aiueos/capabilities decision) :fs/read))))

(deftest a-component-does-not-resolve-its-own-export
  (let [m {:aiueos/component :app/self :aiueos/kind :app :aiueos/trust :verified
           :aiueos/imports #{:custom/thing} :aiueos/exports #{:custom/thing}}
        g (graph/build [m])
        decision (policy/verify-component m g policy/default-policy)]
    (is (= :deny (:aiueos/decision decision)))
    (is (= [:unresolved-capability] (mapv :aiueos/kind (:aiueos/violations decision))))))

(deftest ai-generated-lockdown-forbids-network-secrets-persistent-write
  (let [m {:aiueos/component :agent/researcher :aiueos/kind :agent :aiueos/trust :ai-generated
           :aiueos/effects #{:network :secrets}}
        decision (policy/verify-component m empty-graph policy/default-policy)]
    (is (= :deny (:aiueos/decision decision)))
    (is (= 2 (count (:aiueos/violations decision))))
    (is (every? #(= :forbidden-effect %) (map :aiueos/kind (:aiueos/violations decision))))))

(deftest untrusted-forbids-secrets-but-not-network
  (let [m {:aiueos/component :app/plain :aiueos/kind :app :aiueos/trust :untrusted
           :aiueos/effects #{:network}}
        decision (policy/verify-component m empty-graph policy/default-policy)]
    (is (= :grant (:aiueos/decision decision)))))

(deftest missing-trust-defaults-to-untrusted
  (let [m {:aiueos/component :app/no-trust :aiueos/kind :app
           :aiueos/effects #{:secrets}}
        decision (policy/verify-component m empty-graph policy/default-policy)]
    (is (= :deny (:aiueos/decision decision)))
    (is (= [:forbidden-effect] (mapv :aiueos/kind (:aiueos/violations decision))))))

(deftest dma-without-iommu-is-denied
  (let [m {:aiueos/component :driver/virtio-blk :aiueos/kind :driver :aiueos/trust :verified
           :aiueos/effects #{:dma}}
        decision (policy/verify-component m empty-graph policy/default-policy)]
    (is (= :deny (:aiueos/decision decision)))
    (is (= [:dma-without-iommu] (mapv :aiueos/kind (:aiueos/violations decision))))))

(deftest dma-with-required-and-granted-iommu-succeeds
  (let [policy* (policy/parse-policy {:aiueos/grants {:driver/virtio-blk #{:iommu}}})
        m {:aiueos/component :driver/virtio-blk :aiueos/kind :driver :aiueos/trust :verified
           :aiueos/effects #{:dma} :aiueos/requires #{:iommu}}
        decision (policy/verify-component m empty-graph policy*)]
    (is (= :grant (:aiueos/decision decision)))
    (is (contains? (:aiueos/capabilities decision) :iommu))))

(deftest dma-requires-iommu-key-even-if-granted
  (let [policy* (policy/parse-policy {:aiueos/grants {:driver/virtio-blk #{:iommu}}})
        m {:aiueos/component :driver/virtio-blk :aiueos/kind :driver :aiueos/trust :verified
           :aiueos/effects #{:dma}}
        decision (policy/verify-component m empty-graph policy*)]
    (is (= :deny (:aiueos/decision decision)))
    (is (= [:dma-without-iommu] (mapv :aiueos/kind (:aiueos/violations decision))))))

(deftest surface-gate-denies-a-component-pinned-elsewhere
  (let [policy* (policy/parse-policy {:aiueos/surface :browser})
        m {:aiueos/component :app/robot-only :aiueos/kind :app :aiueos/trust :verified
           :aiueos/surface #{:robot}}
        decision (policy/verify-component m empty-graph policy*)]
    (is (= :deny (:aiueos/decision decision)))
    (is (= [:surface-mismatch] (mapv :aiueos/kind (:aiueos/violations decision))))))

(deftest surface-gate-allows-a-portable-component
  (let [policy* (policy/parse-policy {:aiueos/surface :browser})
        m {:aiueos/component :app/portable :aiueos/kind :app :aiueos/trust :verified}
        decision (policy/verify-component m empty-graph policy*)]
    (is (= :grant (:aiueos/decision decision)))))

(deftest surface-restricts-kernel-caps-to-the-offered-set
  (let [policy* (policy/parse-policy {:aiueos/surface :browser})
        m {:aiueos/component :app/needs-pci :aiueos/kind :app :aiueos/trust :verified
           :aiueos/imports #{:pci/config}}
        decision (policy/verify-component m empty-graph policy*)]
    (is (= :deny (:aiueos/decision decision)))
    (is (= [:unresolved-capability] (mapv :aiueos/kind (:aiueos/violations decision))))))

(deftest explicit-forbid-overlay-replaces-the-default-for-that-trust
  (let [policy* (policy/parse-policy {:aiueos/forbid {:untrusted #{}}})
        m {:aiueos/component :app/wants-secrets :aiueos/kind :app :aiueos/trust :untrusted
           :aiueos/effects #{:secrets}}
        decision (policy/verify-component m empty-graph policy*)]
    (is (= :grant (:aiueos/decision decision)))))

(deftest verify-system-returns-one-decision-per-component-in-order
  (let [fs-service {:aiueos/component :service/fs :aiueos/kind :service :aiueos/trust :verified
                    :aiueos/exports #{:fs/read} :aiueos/imports #{}}
        notes-app {:aiueos/component :app/notes :aiueos/kind :app :aiueos/trust :verified
                   :aiueos/imports #{:fs/read} :aiueos/exports #{}}
        decisions (policy/verify-system [fs-service notes-app] policy/default-policy)]
    (is (= [:service/fs :app/notes] (mapv :aiueos/component decisions)))
    (is (every? #(= :grant (:aiueos/decision %)) decisions))))
