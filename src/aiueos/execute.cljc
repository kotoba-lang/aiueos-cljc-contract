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
  I/O)."
  (:require [aiueos.broker :as broker]
            [aiueos.topic :as topic]
            #?(:clj [clojure.edn :as edn]))
  #?(:clj
     (:import (com.dylibso.chicory.runtime HostFunction ImportFunction ImportValues
                                           Instance WasmFunctionHandle)
              (com.dylibso.chicory.wasm Parser)
              (com.dylibso.chicory.wasm.types FunctionType ValType))))

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
   (defn- device-access-stub
     "A deterministic always-0 stub for one of the device-access quartet
     (pci-config/dma-map/irq-subscribe/mmio-map). Real hardware access
     stays unimplemented here per ADR-2607022900 -- registering these as
     capabilities makes them nameable/gateable from .kotoba source, it does
     not grant hardware access. Mirrors kotoba.wasm-exec's
     stub-host-function convention."
     [field params result]
     (host-fn field params result (fn [_instance _args] 0))))

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

     Returns a seq of HostFunction for `instantiate`. LOG-ATOM and
     TOPIC-BUS-ATOM are supplied by the caller (see `execute`) so a run's
     log/topic state is inspectable afterward and independent across runs."
     [log-atom topic-bus-atom]
     [(host-fn "log_write" [:i32 :i32] :i32
               (fn [instance args]
                 (swap! log-atom conj (read-str instance (aget args 0) (aget args 1)))
                 0))
      (host-fn "clock_monotonic" [] :i64
                (fn [_instance _args] (System/nanoTime)))
      (host-fn "random_bytes" [:i32 :i32] :i32
               (fn [instance args]
                 (let [len (int (aget args 1))
                       bs (byte-array len)]
                   (.nextBytes (java.security.SecureRandom.) bs)
                   (write-bytes! instance (aget args 0) len bs))))
      (host-fn "topic_publish" [:i32 :i64] :i32
               (fn [_instance args]
                 (swap! topic-bus-atom topic/publish (int (aget args 0)) (aget args 1))
                 0))
      (host-fn "topic_poll" [:i32] :i64
               (fn [_instance args]
                 (or (topic/latest @topic-bus-atom (int (aget args 0))) 0)))
      (host-fn "topic_take" [:i32] :i64
               (fn [_instance args]
                 (let [[bus' v] (topic/take-sample @topic-bus-atom (int (aget args 0)))]
                   (reset! topic-bus-atom bus')
                   (or v 0))))
      (host-fn "topic_count" [:i32] :i64
               (fn [_instance args]
                 (topic/topic-count @topic-bus-atom (int (aget args 0)))))]))

#?(:clj
   (defn device-access-stubs
     "The 4 device-access quartet stubs (pci-config/dma-map/irq-subscribe/
     mmio-map) -- see `device-access-stub`'s docstring."
     []
     [(device-access-stub "pci_config" [:i32 :i32] :i32)
      (device-access-stub "dma_map" [:i32 :i32] :i64)
      (device-access-stub "irq_subscribe" [:i32] :i64)
      (device-access-stub "mmio_map" [:i64 :i32] :i64)]))

#?(:clj
   (defn instantiate
     "Parse WASM-BYTES and build a Chicory Instance with all 11 aiueos
     kernel-cap host imports bound (7 real + 4 device-access stubs) plus a
     permissive `has_capability` stub (the static capability gate already
     ran at compile/broker-decision time; a denied component never reaches
     execution -- see `execute`). LOG-ATOM/TOPIC-BUS-ATOM per
     `aiueos-host-functions`."
     [wasm-bytes log-atom topic-bus-atom]
     (let [has-capability (host-fn "has_capability" [:i32] :i32 (fn [_instance _args] 1))
           fns (concat [has-capability]
                       (aiueos-host-functions log-atom topic-bus-atom)
                       (device-access-stubs))
           imports (-> (ImportValues/builder)
                       (.addFunction (into-array ImportFunction fns))
                       .build)
           module (Parser/parse ^bytes wasm-bytes)]
       (-> (Instance/builder module) (.withImportValues imports) .build))))

#?(:clj
   (defn call-main
     "Invoke an already-built Instance's 0-arity exported `main`, returning
     its single i32/i64 result as a long."
     [instance]
     (aget ^longs (.apply (.export instance "main") (long-array 0)) 0)))

#?(:clj
   (defn- run-if-granted
     "Shared tail of `execute`/`execute-admission`: given an already-computed
     policy DECISION, only instantiate+run WASM-BYTES on Chicory when
     `:aiueos/decision` is `:grant`; a `:deny` decision is returned
     unmodified, unexecuted."
     [decision wasm-bytes]
     (if (= :grant (:aiueos/decision decision))
       (let [log-atom (atom [])
             topic-bus-atom (atom topic/empty-bus)
             instance (instantiate wasm-bytes log-atom topic-bus-atom)
             result (call-main instance)]
         (assoc decision
                :aiueos.execute/result result
                :aiueos.execute/log @log-atom
                :aiueos.execute/topic-bus @topic-bus-atom))
       decision)))

#?(:clj
   (defn execute
     "The end-to-end path: verify `m` (a normalized manifest) against
     `graph`/`policy` via `aiueos.broker/verify-one`; only if granted,
     instantiate WASM-BYTES on Chicory and call its exported `main`.

     Returns `{:aiueos/decision :deny ...}` (the broker's denial, unexecuted)
     or `{:aiueos/decision :grant ... :aiueos.execute/result <long>
     :aiueos.execute/log [<string>...] :aiueos.execute/topic-bus <bus>}` --
     the broker decision plus the execution outcome and the final log/topic
     state (inspectable, e.g. for tests or an audit trail)."
     [m graph policy wasm-bytes]
     (run-if-granted (broker/verify-one m graph policy) wasm-bytes)))

#?(:clj
   (defn execute-admission
     "The execution half of the retired Rust `Broker::admit` (ADR-0004),
     now actually runnable: floors `m`'s trust to `:ai-generated`
     (`broker/floor-trust-for-admission`) before verification -- an
     agent-submitted component can never grant itself trust -- then, only
     if still granted after the floor, instantiates and executes WASM-BYTES
     on Chicory exactly like `execute`. Same return shape as `execute`."
     [m graph policy wasm-bytes]
     (run-if-granted (broker/verify-admission m graph policy) wasm-bytes)))
