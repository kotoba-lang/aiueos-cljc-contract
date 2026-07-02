(ns aiueos.decide-test
  (:require [aiueos.cli :as cli]
            [aiueos.decide :as decide]
            [clojure.test :refer [deftest is testing]]))

(def contract (cli/read-contract))

(deftest handle-request-dispatches-verify
  (let [m {:aiueos/component :service/log :aiueos/kind :service :aiueos/trust :verified
           :aiueos/imports #{:log/write} :aiueos/exports #{}}
        response (decide/handle-request contract
                                         {:aiueos.decide/command :verify
                                          :aiueos.decide/request {:aiueos/manifest m}})]
    (is (= :verify (:aiueos.cli/command response)))
    (is (= :grant (:aiueos/decision response)))))

(deftest handle-request-dispatches-a-denial
  (let [m {:aiueos/component :app/notes :aiueos/kind :app :aiueos/trust :verified
           :aiueos/imports #{:net/fetch}}
        response (decide/handle-request contract
                                         {:aiueos.decide/command :verify
                                          :aiueos.decide/request {:aiueos/manifest m}})]
    (is (= :deny (:aiueos/decision response)))))

(deftest handle-request-rejects-a-request-missing-command
  (is (= :malformed-request
         (:aiueos.decide/error (decide/handle-request contract {:aiueos.decide/request {}})))))

(deftest handle-line-round-trips-through-edn-text
  (let [m {:aiueos/component :service/log :aiueos/kind :service :aiueos/trust :verified
           :aiueos/imports #{:log/write}}
        line (pr-str {:aiueos.decide/command :verify :aiueos.decide/request {:aiueos/manifest m}})
        response (read-string (decide/handle-line contract line))]
    (is (= :grant (:aiueos/decision response)))))

(deftest handle-line-never-throws-on-malformed-edn
  (testing "unreadable EDN text becomes an error response, not an exception"
    (let [response (read-string (decide/handle-line contract "not valid edn ("))]
      (is (= :malformed-request (:aiueos.decide/error response))))))

#?(:clj
   (deftest decide-subprocess-smoke-test
     (testing "bb decide, invoked as a real subprocess, round-trips one request over stdio"
       (let [pb (ProcessBuilder. ["bb" "decide"])
             _ (.redirectErrorStream pb false)
             proc (.start pb)
             stdin (java.io.PrintWriter. (.getOutputStream proc) true)
             stdout (java.io.BufferedReader.
                     (java.io.InputStreamReader. (.getInputStream proc)))
             m {:aiueos/component :service/log :aiueos/kind :service :aiueos/trust :verified
                :aiueos/imports #{:log/write}}
             request (pr-str {:aiueos.decide/command :verify
                              :aiueos.decide/request {:aiueos/manifest m}})]
         (.println stdin request)
         (.flush stdin)
         (let [response-line (.readLine stdout)
               response (read-string response-line)]
           (.close stdin)
           (.destroy proc)
           (is (= :grant (:aiueos/decision response)))
           (is (= :verify (:aiueos.cli/command response))))))))
