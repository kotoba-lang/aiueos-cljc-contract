(ns aiueos.graph-test
  (:require [aiueos.graph :as graph]
            [clojure.test :refer [deftest is testing]]))

(def log-service
  {:aiueos/component :service/log :aiueos/kind :service
   :aiueos/exports #{:log/write} :aiueos/imports #{}})

(def notes-app
  {:aiueos/component :app/notes :aiueos/kind :app
   :aiueos/exports #{} :aiueos/imports #{:log/write :fs/read}})

(def fs-service
  {:aiueos/component :service/fs :aiueos/kind :service
   :aiueos/exports #{:fs/read :fs/write} :aiueos/imports #{}})

(deftest build-maps-capability-to-exporters
  (let [g (graph/build [log-service notes-app fs-service])]
    (is (= [:service/log] (graph/providers g :log/write)))
    (is (= [:service/fs] (graph/providers g :fs/read)))
    (is (= [] (graph/providers g :net/fetch)))))

(deftest boot-order-orders-providers-before-consumers
  (let [{:keys [aiueos.graph/order]} (graph/boot-order [notes-app log-service fs-service])
        components [notes-app log-service fs-service]
        pos (into {} (map-indexed (fn [i idx] [idx i])) order)]
    (is (= 3 (count order)))
    ;; log-service (idx 1) and fs-service (idx 2) must boot before notes-app (idx 0).
    (is (< (pos 1) (pos 0)))
    (is (< (pos 2) (pos 0)))))

(deftest boot-order-detects-a-cycle
  (let [a {:aiueos/component :a :aiueos/exports #{:cap/a} :aiueos/imports #{:cap/b}}
        b {:aiueos/component :b :aiueos/exports #{:cap/b} :aiueos/imports #{:cap/a}}
        result (graph/boot-order [a b])]
    (is (contains? result :aiueos.graph/cycle))
    (is (= #{:a :b} (set (:aiueos.graph/cycle result))))))

(deftest depths-tracks-dependency-depth
  (let [components [notes-app log-service fs-service]
        d (graph/depths components)]
    (is (= 0 (nth d 1))) ; log-service: no imports resolved by another component
    (is (= 0 (nth d 2))) ; fs-service: no imports resolved by another component
    (is (= 1 (nth d 0))) ; notes-app: depends on both, depth = 1 + max(0,0)
    ))

(deftest check-unique-ids-rejects-duplicates
  (is (nil? (graph/check-unique-ids [log-service fs-service])))
  (is (= :duplicate-component-id
         (:aiueos/error (graph/check-unique-ids [log-service log-service])))))

(deftest check-unique-devices-rejects-conflicting-bindings
  (let [drv-a {:aiueos/component :driver/a
               :aiueos/device {:bus "pci" :vendor "1af4" :device "1001"}}
        drv-b {:aiueos/component :driver/b
               :aiueos/device {:bus "pci" :vendor "1af4" :device "1001"}}
        drv-c {:aiueos/component :driver/c
               :aiueos/device {:bus "pci" :vendor "1af4" :device "1002"}}]
    (is (nil? (graph/check-unique-devices [drv-a drv-c])))
    (is (= :duplicate-device-binding
           (:aiueos/error (graph/check-unique-devices [drv-a drv-b]))))
    ;; a partial binding is too ambiguous to conflict
    (let [partial-a {:aiueos/component :driver/partial-a :aiueos/device {:bus "pci"}}
          partial-b {:aiueos/component :driver/partial-b :aiueos/device {:bus "pci"}}]
      (is (nil? (graph/check-unique-devices [partial-a partial-b]))))))
