(ns aiueos.launcher
  "The aiueos CLI binary itself, per ADR-2607022700/2607022900: the retired
  Rust `bin/aiueos.rs` argv-parsing/file-I/O role, reimplemented as JVM
  Clojure. Ties together `aiueos.cli` (command/request shaping),
  `aiueos.manifest` (normalization), `aiueos.policy`/`aiueos.broker`
  (decisions), and `aiueos.execute` (real Chicory execution) into a single
  runnable entry point.

  This is deliberately NOT the same thing as `aiueos.decide` (the
  bb-runnable, decision-only EDN-over-stdio subprocess for host adapters
  without Chicory available). `aiueos.launcher` is the JVM-specific,
  execution-capable launcher: `run`/`admit` here ACTUALLY EXECUTE a granted
  component via `aiueos.execute`, not just report `:host-action
  :adapter-required` like `aiueos.cli/command-result` does generically for
  a host-neutral caller.

  JVM-only (`#?(:clj ...)` throughout) -- file I/O and `aiueos.execute`'s
  Chicory dependency both require it; not runnable under babashka."
  (:require [aiueos.broker :as broker]
            [aiueos.cli :as cli]
            [aiueos.contract :as contract]
            [aiueos.execute :as execute]
            [aiueos.graph :as graph]
            [aiueos.manifest :as manifest]
            [aiueos.policy :as policy]
            #?(:clj [clojure.edn :as edn])
            #?(:clj [clojure.java.io :as io])
            #?(:clj [clojure.string :as str])))

#?(:clj
   (defn read-edn-file
     "Read and parse one EDN file. Throws ex-info with the path on failure
     (a manifest/policy/system file that doesn't parse should fail loud,
     not silently)."
     [path]
     (try
       (edn/read-string (slurp path))
       (catch Exception e
         (throw (ex-info (str "failed to read EDN file: " path) {:path path} e))))))

#?(:clj
   (defn- resolve-wasm-path
     "The `:aiueos/wasm` a normalized manifest declares, resolved relative
     to the manifest FILE's own directory (not the caller's cwd) -- matches
     the retired Rust `System::load` convention: a component's
     `:aiueos/source`/`:aiueos/wasm` paths resolve against where that
     component's manifest was loaded from."
     [manifest-path m]
     (when-let [wasm-rel (:aiueos/wasm m)]
       (.getPath (io/file (.getParentFile (io/file manifest-path)) wasm-rel)))))

#?(:clj
   (defn- read-wasm-bytes [path]
     (with-open [in (io/input-stream path)
                 out (java.io.ByteArrayOutputStream.)]
       (io/copy in out)
       (.toByteArray out))))

#?(:clj
   (defn load-manifest
     "Read MANIFEST-PATH, validate its shape, and normalize it
     (`aiueos.manifest/normalize`). Throws ex-info on an invalid manifest
     shape (fail loud, matching the rest of this repo's manifest handling)."
     [manifest-path]
     (let [raw (read-edn-file manifest-path)
           validation (contract/validate-manifest raw)]
       (when-not (:valid? validation)
         (throw (ex-info (str manifest-path ": invalid manifest") validation)))
       (manifest/normalize raw))))

#?(:clj
   (defn load-policy
     "POLICY-PATH's deployment-policy overlay, parsed into an effective
     policy via `aiueos.policy/parse-policy`; `aiueos.policy/default-policy`
     when POLICY-PATH is nil (no `--policy` given)."
     [policy-path]
     (if policy-path
       (policy/parse-policy (read-edn-file policy-path))
       policy/default-policy)))

#?(:clj
   (defn run-command
     "The `run`/`admit` command bodies: load MANIFEST-PATH (+ POLICY-PATH),
     resolve+read its declared `:aiueos/wasm` bytes, and actually execute
     via `aiueos.execute/execute` (or `execute-admission` when ADMIT? is
     true). Returns the same shape `aiueos.execute/execute` does. Throws
     ex-info if the manifest declares no `:aiueos/wasm` -- nothing to run."
     [manifest-path policy-path admit?]
     (let [m (load-manifest manifest-path)
           wasm-path (resolve-wasm-path manifest-path m)
           _ (when-not wasm-path
               (throw (ex-info (str manifest-path ": no :aiueos/wasm to run") {:manifest m})))
           wasm-bytes (read-wasm-bytes wasm-path)
           policy* (load-policy policy-path)
           g (graph/build [m])]
       (if admit?
         (execute/execute-admission m g policy* wasm-bytes)
         (execute/execute m g policy* wasm-bytes)))))

#?(:clj
   (defn verify-command
     "The `verify` command body: load MANIFEST-PATH (+ POLICY-PATH) and
     return `aiueos.broker/verify-one`'s decision -- no execution, matching
     `aiueos.cli.edn`'s `:full` coverage for `verify`."
     [manifest-path policy-path]
     (let [m (load-manifest manifest-path)
           policy* (load-policy policy-path)
           g (graph/build [m])]
       (broker/verify-one m g policy*))))

#?(:clj
   (defn- print-result [result edn?]
     (if edn?
       (println (pr-str result))
       (do (println (str (name (:aiueos/decision result)) " " (name (:aiueos/component result))))
           (when (:aiueos/violations result)
             (doseq [v (:aiueos/violations result)]
               (println (str "  [" (name (:aiueos/kind v)) "] " (:aiueos/message v)))))
           (when (contains? result :aiueos.execute/result)
             (println (str "  result: " (:aiueos.execute/result result))))))))

#?(:clj
   (defn dispatch
     "Run one aiueos CLI invocation. ARGV[0] is the command name; the rest
     are positionals/flags, shaped via `aiueos.cli/parse-argv`. Supported
     today: `verify`/`run`/`admit` (all three: `<manifest-path>
     [--policy <path>] [--edn]`) -- the commands `aiueos.execute` makes
     genuinely executable on this JVM launcher. Other `aiueos.cli.edn`
     commands (`inspect`/`surface`/`audit`/`up`/the adapter-only six)
     are not wired here yet."
     [argv]
     (let [command (some-> (first argv) keyword)
           {:keys [positionals options]} (cli/parse-argv (rest argv))
           manifest-path (first positionals)
           policy-path (:policy options)
           edn? (boolean (:edn options))]
       (case command
         :verify (print-result (verify-command manifest-path policy-path) edn?)
         :run (print-result (run-command manifest-path policy-path false) edn?)
         :admit (print-result (run-command manifest-path policy-path true) edn?)
         (do (binding [*out* *err*]
               (println (str "aiueos: unsupported or not-yet-wired command `" (name command) "`"))
               (println "supported: verify, run, admit"))
             #?(:clj (System/exit 2)))))))

#?(:clj
   (defn -main [& argv]
     (dispatch argv)))
