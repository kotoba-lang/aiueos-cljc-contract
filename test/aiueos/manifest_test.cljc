(ns aiueos.manifest-test
  (:require [aiueos.manifest :as manifest]
            [clojure.test :refer [deftest is testing]]))

;; -----------------------------------------------------------------------
;; trust defaulting
;; -----------------------------------------------------------------------

(deftest agent-defaults-to-ai-generated
  (is (= :ai-generated (manifest/default-trust :agent)))
  (is (= :ai-generated
         (manifest/resolve-trust {:aiueos/component :agent/researcher :aiueos/kind :agent}))))

(deftest kernel-extension-defaults-to-trusted
  (is (= :trusted (manifest/default-trust :kernel-extension)))
  (is (= :trusted
         (manifest/resolve-trust {:aiueos/component :kx/net :aiueos/kind :kernel-extension}))))

(deftest other-kinds-default-to-untrusted
  (doseq [kind [:app :service :driver :broker :compat]]
    (is (= :untrusted (manifest/default-trust kind)))
    (is (= :untrusted
           (manifest/resolve-trust {:aiueos/component :c :aiueos/kind kind})))))

(deftest explicit-trust-is-preserved-over-the-kind-default
  (is (= :verified
         (manifest/resolve-trust {:aiueos/component :agent/x :aiueos/kind :agent
                                   :aiueos/trust :verified})))
  (is (= :untrusted
         (manifest/resolve-trust {:aiueos/component :kx/x :aiueos/kind :kernel-extension
                                   :aiueos/trust :untrusted}))))

;; -----------------------------------------------------------------------
;; limits
;; -----------------------------------------------------------------------

(deftest limits-default-when-absent
  (is (= {:memory-pages 16 :fuel 10000000} (manifest/normalize-limits {}))))

(deftest limits-preserve-explicit-in-range-values
  (is (= {:memory-pages 64 :fuel 5000}
         (manifest/normalize-limits {:aiueos/limits {:memory-pages 64 :fuel 5000}}))))

(deftest limits-partial-override-defaults-the-rest
  (is (= {:memory-pages 16 :fuel 42}
         (manifest/normalize-limits {:aiueos/limits {:fuel 42}}))))

(deftest limits-memory-pages-at-the-4gib-ceiling-is-valid
  (is (= 65536 (:memory-pages (manifest/normalize-limits {:aiueos/limits {:memory-pages 65536}})))))

(deftest limits-memory-pages-over-the-4gib-ceiling-errors
  (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs cljs.core.ExceptionInfo)
               (manifest/normalize-limits {:aiueos/limits {:memory-pages 65537}}))))

(deftest limits-zero-memory-pages-errors
  (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs cljs.core.ExceptionInfo)
               (manifest/normalize-limits {:aiueos/limits {:memory-pages 0}}))))

(deftest limits-non-integer-fuel-errors
  (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs cljs.core.ExceptionInfo)
               (manifest/normalize-limits {:aiueos/limits {:fuel 1.5}}))))

(deftest limits-error-carries-the-path-and-message
  (try
    (manifest/normalize-limits {:aiueos/limits {:memory-pages 100000}})
    (is false "expected an ex-info to be thrown")
    (catch #?(:clj clojure.lang.ExceptionInfo :cljs cljs.core.ExceptionInfo) e
      (is (= [:aiueos/limits :memory-pages] (:path (ex-data e))))
      (is (string? (:message (ex-data e)))))))

;; -----------------------------------------------------------------------
;; quota (ADR-0006)
;; -----------------------------------------------------------------------

(deftest quota-defaults-when-absent
  (is (= {:host-calls 1024 :publishes 256} (manifest/normalize-quota {}))))

(deftest quota-preserves-explicit-in-range-values
  (is (= {:host-calls 10 :publishes 0}
         (manifest/normalize-quota {:aiueos/quota {:host-calls 10 :publishes 0}}))))

(deftest quota-host-calls-must-be-at-least-one
  (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs cljs.core.ExceptionInfo)
               (manifest/normalize-quota {:aiueos/quota {:host-calls 0}}))))

(deftest quota-publishes-may-be-zero-but-not-negative
  (is (= 0 (:publishes (manifest/normalize-quota {:aiueos/quota {:publishes 0}}))))
  (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs cljs.core.ExceptionInfo)
               (manifest/normalize-quota {:aiueos/quota {:publishes -1}}))))

;; -----------------------------------------------------------------------
;; schedule (ADR-0006 cycle derivation)
;; -----------------------------------------------------------------------

(deftest schedule-defaults-to-every-cycle-priority-100
  (is (= #:aiueos.manifest{:period-cycles 1 :deadline-cycles 1 :priority 100}
         (manifest/normalize-schedule {}))))

(deftest schedule-period-cycles-divides-evenly
  (is (= 5 (:aiueos.manifest/period-cycles
            (manifest/normalize-schedule
             {:aiueos/schedule {:period-ms 500 :cycle-ms 100}})))))

(deftest schedule-period-cycles-rounds-up-on-a-remainder
  ;; 250 / 100 = 2.5 -> ceil -> 3
  (is (= 3 (:aiueos.manifest/period-cycles
            (manifest/normalize-schedule
             {:aiueos/schedule {:period-ms 250 :cycle-ms 100}})))))

(deftest schedule-deadline-ms-defaults-to-period-ms
  (let [sched (manifest/normalize-schedule {:aiueos/schedule {:period-ms 300 :cycle-ms 100}})]
    (is (= 3 (:aiueos.manifest/period-cycles sched)))
    (is (= 3 (:aiueos.manifest/deadline-cycles sched)))))

(deftest schedule-deadline-ms-independent-of-period-ms-when-given
  (let [sched (manifest/normalize-schedule
               {:aiueos/schedule {:period-ms 500 :deadline-ms 250 :cycle-ms 100}})]
    (is (= 5 (:aiueos.manifest/period-cycles sched)))
    (is (= 3 (:aiueos.manifest/deadline-cycles sched)))))

(deftest schedule-cycle-ms-defaults-to-one-so-ms-equals-cycles
  (let [sched (manifest/normalize-schedule {:aiueos/schedule {:period-ms 7 :deadline-ms 4}})]
    (is (= 7 (:aiueos.manifest/period-cycles sched)))
    (is (= 4 (:aiueos.manifest/deadline-cycles sched)))))

(deftest schedule-priority-explicit-is-preserved
  (is (= 10 (:aiueos.manifest/priority
             (manifest/normalize-schedule {:aiueos/schedule {:priority 10}})))))

;; -----------------------------------------------------------------------
;; topic id derivation
;; -----------------------------------------------------------------------

(def topics {:sensor 1 :actuator 2})

(deftest derive-topic-ids-resolves-named-topic-exports
  (is (= #{1 2}
         (manifest/derive-topic-ids #{:topic/sensor :topic/actuator} topics))))

(deftest derive-topic-ids-excludes-the-coarse-gate-capabilities
  ;; :topic/publish and :topic/subscribe are never data-topic names, even
  ;; when a `:publish`/`:subscribe` entry happens to exist in the topics map.
  (is (= #{1}
         (manifest/derive-topic-ids #{:topic/sensor :topic/publish :topic/subscribe}
                                     (assoc topics :publish 99 :subscribe 98)))))

(deftest derive-topic-ids-ignores-non-topic-capabilities
  (is (= #{1}
         (manifest/derive-topic-ids #{:topic/sensor :log/write :fs/read} topics))))

(deftest derive-topic-ids-ignores-unknown-topic-names
  (is (= #{1}
         (manifest/derive-topic-ids #{:topic/sensor :topic/unknown} topics))))

(deftest derive-topic-ids-returns-nil-not-empty-set-when-nothing-resolves
  (is (nil? (manifest/derive-topic-ids #{:log/write} topics)))
  (is (nil? (manifest/derive-topic-ids #{} topics)))
  (is (nil? (manifest/derive-topic-ids #{:topic/publish :topic/subscribe} topics))))

(deftest normalize-derives-publishes-from-exports-and-subscribes-from-imports
  (let [m {:aiueos/component :driver/sensor :aiueos/kind :driver
           :aiueos/topics topics
           :aiueos/exports #{:topic/sensor}
           :aiueos/imports #{:topic/actuator}}
        n (manifest/normalize m)]
    (is (= #{1} (:aiueos/publishes n)))
    (is (= #{2} (:aiueos/subscribes n)))))

(deftest normalize-leaves-publishes-nil-unrestricted-when-nothing-resolves
  (let [m {:aiueos/component :app/plain :aiueos/kind :app
           :aiueos/exports #{} :aiueos/imports #{}}
        n (manifest/normalize m)]
    (is (nil? (:aiueos/publishes n)))
    (is (nil? (:aiueos/subscribes n)))))

(deftest normalize-explicit-publishes-overrides-derivation
  (let [m {:aiueos/component :driver/sensor :aiueos/kind :driver
           :aiueos/topics topics
           :aiueos/exports #{:topic/sensor}
           :aiueos/publishes #{999}}
        n (manifest/normalize m)]
    (is (= #{999} (:aiueos/publishes n)))))

(deftest normalize-explicit-empty-publishes-stays-empty-rather-than-deriving
  (let [m {:aiueos/component :driver/sensor :aiueos/kind :driver
           :aiueos/topics topics
           :aiueos/exports #{:topic/sensor}
           :aiueos/publishes #{}}
        n (manifest/normalize m)]
    (is (= #{} (:aiueos/publishes n)))))

(deftest normalize-explicit-subscribes-overrides-derivation
  (let [m {:aiueos/component :driver/sensor :aiueos/kind :driver
           :aiueos/topics topics
           :aiueos/imports #{:topic/actuator}
           :aiueos/subscribes #{777}}
        n (manifest/normalize m)]
    (is (= #{777} (:aiueos/subscribes n)))))

(deftest normalize-defaults-topics-to-empty-map-when-absent
  (is (= {} (:aiueos/topics (manifest/normalize {:aiueos/component :a :aiueos/kind :app})))))

;; -----------------------------------------------------------------------
;; signed-message (ADR-0003)
;; -----------------------------------------------------------------------

(deftest signed-message-nil-without-wasm-sha256
  (is (nil? (manifest/signed-message {:aiueos/component :driver/sensor}))))

(deftest signed-message-binds-keyword-id-and-hash-without-a-leading-colon
  (is (= "driver/sensor\n3b1f"
         (manifest/signed-message {:aiueos/component :driver/sensor
                                    :aiueos/wasm-sha256 "3b1f"}))))

(deftest signed-message-binds-a-simple-keyword-id-without-namespace
  (is (= "app\nabc"
         (manifest/signed-message {:aiueos/component :app
                                    :aiueos/wasm-sha256 "abc"}))))

(deftest signed-message-binds-a-string-id-as-is
  (is (= "driver/sensor\n3b1f"
         (manifest/signed-message {:aiueos/component "driver/sensor"
                                    :aiueos/wasm-sha256 "3b1f"}))))

;; -----------------------------------------------------------------------
;; with-trust (ADR-0003 signature elevation)
;; -----------------------------------------------------------------------

(deftest with-trust-replaces-trust-without-mutating-the-original
  (let [m {:aiueos/component :driver/sensor :aiueos/trust :untrusted}
        elevated (manifest/with-trust m :verified)]
    (is (= :verified (:aiueos/trust elevated)))
    (is (= :untrusted (:aiueos/trust m)))
    (is (= :driver/sensor (:aiueos/component elevated)))))

;; -----------------------------------------------------------------------
;; normalize — integration
;; -----------------------------------------------------------------------

(deftest normalize-fills-in-every-default-explicitly
  (let [m {:aiueos/component :agent/researcher :aiueos/kind :agent
           :aiueos/exports #{} :aiueos/imports #{}}
        n (manifest/normalize m)]
    (is (= :ai-generated (:aiueos/trust n)))
    (is (= {:memory-pages 16 :fuel 10000000} (:aiueos/limits n)))
    (is (= {:host-calls 1024 :publishes 256} (:aiueos/quota n)))
    (is (= #:aiueos.manifest{:period-cycles 1 :deadline-cycles 1 :priority 100}
           (:aiueos/schedule n)))
    (is (= {} (:aiueos/topics n)))
    (is (nil? (:aiueos/publishes n)))
    (is (nil? (:aiueos/subscribes n)))
    ;; passthrough fields are untouched
    (is (= :agent/researcher (:aiueos/component n)))
    (is (= :agent (:aiueos/kind n)))))

(deftest normalize-preserves-explicit-values-across-every-block
  (let [m {:aiueos/component :driver/virtio-blk :aiueos/kind :driver
           :aiueos/trust :verified
           :aiueos/limits {:memory-pages 32 :fuel 999}
           :aiueos/quota {:host-calls 5 :publishes 1}
           :aiueos/schedule {:period-ms 20 :deadline-ms 10 :priority 10 :cycle-ms 10}
           :aiueos/device {:bus "pci" :vendor "1af4" :device "1001"}}
        n (manifest/normalize m)]
    (is (= :verified (:aiueos/trust n)))
    (is (= {:memory-pages 32 :fuel 999} (:aiueos/limits n)))
    (is (= {:host-calls 5 :publishes 1} (:aiueos/quota n)))
    (is (= #:aiueos.manifest{:period-cycles 2 :deadline-cycles 1 :priority 10}
           (:aiueos/schedule n)))
    (is (= {:bus "pci" :vendor "1af4" :device "1001"} (:aiueos/device n)))))

(deftest normalize-throws-on-an-out-of-range-limit
  (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs cljs.core.ExceptionInfo)
               (manifest/normalize {:aiueos/component :a :aiueos/kind :app
                                     :aiueos/limits {:memory-pages 999999}}))))
