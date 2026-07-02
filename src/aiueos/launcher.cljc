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
  (:require [aiueos.audit :as audit]
            [aiueos.broker :as broker]
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
   (defn- resolve-system-component-paths
     "A system.aiueos.edn's `:aiueos/components` is a vector of manifest
     paths relative to the SYSTEM file itself (matches the retired Rust
     `System::load` convention -- same base-directory rule
     `resolve-wasm-path` applies to a single manifest's `:aiueos/wasm`)."
     [system-path components]
     (let [base (.getParentFile (io/file system-path))]
       (mapv #(.getPath (io/file base %)) components))))

#?(:clj
   (defn load-system-entries
     "Read SYSTEM-PATH (`{:aiueos/system id :aiueos/components [paths...]}`)
     and return `[{:aiueos.launcher/path <manifest-path> :aiueos/manifest
     <normalized-manifest>} ...]`, one per component, in
     `:aiueos/components` declaration order (NOT boot order -- see
     `up-command` for that). Keeping each manifest's own file path
     alongside it (rather than just the normalized manifest, as
     `load-system` returns) is what lets `up-command` resolve each
     component's OWN `:aiueos/wasm` relative to ITS OWN manifest file,
     exactly like `run-command` does for a single manifest."
     [system-path]
     (let [raw (read-edn-file system-path)
           validation (contract/validate-system raw)]
       (when-not (:valid? validation)
         (throw (ex-info (str system-path ": invalid system") validation)))
       (mapv (fn [path] {:aiueos.launcher/path path :aiueos/manifest (load-manifest path)})
             (resolve-system-component-paths system-path (:aiueos/components raw))))))

#?(:clj
   (defn load-system
     "Read SYSTEM-PATH and return just the vector of normalized component
     manifests (see `load-system-entries` for the path-carrying variant)."
     [system-path]
     (mapv :aiueos/manifest (load-system-entries system-path))))

#?(:clj
   (defn inspect-command
     "The `inspect` command body: load SYSTEM-PATH's components and return
     `aiueos.cli`'s `:inspect` result (capability providers, boot order,
     dependency depths) -- no execution, `:full` coverage."
     [system-path]
     (cli/command-result (cli/read-contract) :inspect
                          {:aiueos/components (load-system system-path)})))

#?(:clj
   (defn up-command
     "The `up` command body: boot the components of SYSTEM-PATH that are
     DUE at SCHED-CYCLE (a non-negative ADR-0006 cycle counter, defaulting
     to 0 -- see `aiueos.manifest/due-this-cycle?`; cycle 0 is always due
     for every component, so the default invocation boots everyone, same
     as before scheduling existed). Boot order is
     `aiueos.graph/priority-boot-order` -- dependency order (providers
     before consumers) with same-depth components ordered by
     `:aiueos/schedule`'s `:priority` (lower = more urgent). A component
     not due this cycle is simply skipped (omitted from
     `:aiueos/boot-results`, not treated as stopped/denied).

     Each due component is verified + (if granted and it declares
     `:aiueos/wasm`) actually executed via `aiueos.execute/execute`,
     exactly like `run-command` does for a single manifest; a component
     with no `:aiueos/wasm` (a pure capability provider with nothing to
     run) only gets a decision, matching `verify-command`.

     Stops at the FIRST denied/quota-or-fuel-exceeded DUE component -- a
     system doesn't boot past a component that can't run, since later
     components may depend on it. Returns `{:aiueos.cli/ok? true
     :aiueos/boot-results [...]}` on a clean boot (every due component
     reached) or `{:aiueos.cli/ok? false :aiueos/boot-results [...]
     :aiueos/stopped-at <component-id>}` when boot halted early. A
     dependency CYCLE (no valid boot order exists) is reported as
     `{:aiueos.cli/ok? false :aiueos.cli/code :graph/cycle :aiueos/cycle
     [component-ids...]}` before anything executes.

     NOTE: `:aiueos/schedule`'s `:aiueos.manifest/deadline-cycles` is NOT
     enforced -- see `aiueos.manifest/due-this-cycle?`'s docstring for why
     (Chicory's synchronous, non-preemptible execution has no mechanism
     to check elapsed cycles mid-run)."
     ([system-path policy-path] (up-command system-path policy-path 0))
     ([system-path policy-path sched-cycle]
      (let [entries (load-system-entries system-path)
            manifests (mapv :aiueos/manifest entries)
            priorities (mapv #(get-in % [:aiueos/schedule :aiueos.manifest/priority]) manifests)
            policy* (load-policy policy-path)
            g (graph/build manifests)
            order-result (graph/priority-boot-order manifests priorities)]
        (if-let [cycle (:aiueos.graph/cycle order-result)]
          {:aiueos.cli/command :up :aiueos.cli/ok? false :aiueos.cli/code :graph/cycle
           :aiueos/cycle cycle}
          (loop [indices (get-in order-result [:aiueos.graph/order]) results []]
            (if (empty? indices)
              {:aiueos.cli/command :up :aiueos.cli/ok? true :aiueos/boot-results results}
              (let [i (first indices)
                    {:aiueos.launcher/keys [path] :aiueos/keys [manifest]} (nth entries i)]
                (if-not (manifest/due-this-cycle? (:aiueos/schedule manifest) sched-cycle)
                  (recur (rest indices) results)
                  (let [wasm-path (resolve-wasm-path path manifest)
                        result (if wasm-path
                                 (execute/execute manifest g policy* (read-wasm-bytes wasm-path))
                                 (broker/verify-one manifest g policy*))
                        results' (conj results result)
                        booted? (and (= :grant (:aiueos/decision result))
                                     (not (contains? result :aiueos.execute/quota-exceeded))
                                     (not (contains? result :aiueos.execute/fuel-exceeded)))]
                    (if booted?
                      (recur (rest indices) results')
                      {:aiueos.cli/command :up :aiueos.cli/ok? false :aiueos/boot-results results'
                       :aiueos/stopped-at (:aiueos/component manifest)})))))))))))

#?(:clj
   (defn surface-command
     "The `surface inspect --id <id>` command body: no file I/O needed
     beyond the contract itself."
     [surface-id-str]
     (cli/command-result (cli/read-contract) :surface
                          {:aiueos/surface-id (keyword surface-id-str)})))

#?(:clj
   (defn audit-command
     "The `audit` command body: read the log at LOG-PATH (defaulting to
     `aiueos.audit/log-path` under the current directory when nil, matching
     the retired Rust `AuditLog::under` default) via `aiueos.audit/read-log`,
     then delegate the pure event/component filtering to
     `aiueos.cli`'s `:audit` handler."
     [log-path event-str component-str]
     (let [path (or log-path (.getPath (audit/log-path ".")))
           events (audit/read-log path)]
       (cli/command-result (cli/read-contract) :audit
                            (cond-> {:aiueos/audit-events events}
                              event-str (assoc :aiueos/event (keyword event-str))
                              component-str (assoc :aiueos/component (keyword component-str)))))))

#?(:clj
   (defn- print-result [result edn?]
     (cond
       edn? (println (pr-str result))

       (contains? result :aiueos/decision)
       (do (println (str (name (:aiueos/decision result)) " " (name (:aiueos/component result))))
           (when (:aiueos/violations result)
             (doseq [v (:aiueos/violations result)]
               (println (str "  [" (name (:aiueos/kind v)) "] " (:aiueos/message v)))))
           (when (contains? result :aiueos.execute/result)
             (println (str "  result: " (:aiueos.execute/result result)))))

       (contains? result :aiueos/boot-order)
       (do (println (str "boot order: " (get-in result [:aiueos/boot-order :aiueos.graph/order])))
           (println (str "depths: " (:aiueos/depths result))))

       (contains? result :aiueos/offered)
       (println (str (name (:aiueos/surface-id result)) " offers: " (:aiueos/offered result)))

       (contains? result :aiueos/audit-events)
       (doseq [{:aiueos/keys [ts event component detail]} (:aiueos/audit-events result)]
         (println (str ts " [" (name event) "] " (name component) " -- " detail)))

       (contains? result :aiueos/boot-results)
       (do (doseq [r (:aiueos/boot-results result)]
             (println (str (name (:aiueos/decision r)) " " (name (:aiueos/component r))
                            (when (contains? r :aiueos.execute/quota-exceeded) " (quota exceeded)")
                            (when (contains? r :aiueos.execute/fuel-exceeded) " (fuel exceeded)"))))
           (when (:aiueos/stopped-at result)
             (println (str "boot stopped at " (name (:aiueos/stopped-at result))))))

       (contains? result :aiueos/cycle)
       (println (str "boot order impossible -- dependency cycle: " (:aiueos/cycle result)))

       :else (println (pr-str result)))))

#?(:clj
   (defn dispatch
     "Run one aiueos CLI invocation. ARGV[0] is the command name; the rest
     are positionals/flags, shaped via `aiueos.cli/parse-argv`.

     `verify`/`run`/`admit <manifest-path> [--policy <path>] [--edn]` --
     `run`/`admit` actually execute a granted component via `aiueos.execute`.
     `inspect <system-path> [--edn]` -- capability providers/boot
     order/depths across a system's components.
     `surface <surface-id> [--edn]` -- a deployment surface's offered set.
     `audit [--log <path>] [--event <kw>] [--component <kw>] [--edn]` --
     query the append-only audit log (defaults to `.aiueos/audit.edn`
     under the current directory).
     `up <system-path> [--policy <path>] [--cycle <n>] [--edn]` -- boot the
     components due at cycle N (default 0, ADR-0006; see `up-command`) in
     priority-aware dependency order, executing each as it's reached;
     stops at the first denied/quota-or-fuel-exceeded DUE component.

     The adapter-only six (`sign`/`check`/`compile`/`hash`/`image`/`vm`)
     are not wired here -- `check`/`compile` delegate to
     kototama/kotoba-clj, `sign` is key-custody tooling, `image`/`vm` are
     native provisioning (see `aiueos.cli`'s namespace docstring)."
     [argv]
     (let [command (some-> (first argv) keyword)
           {:keys [positionals options]} (cli/parse-argv (rest argv))
           edn? (boolean (:edn options))]
       (case command
         :verify (print-result (verify-command (first positionals) (:policy options)) edn?)
         :run (print-result (run-command (first positionals) (:policy options) false) edn?)
         :admit (print-result (run-command (first positionals) (:policy options) true) edn?)
         :inspect (print-result (inspect-command (first positionals)) edn?)
         :surface (print-result (surface-command (or (first positionals) (:id options))) edn?)
         :audit (print-result (audit-command (:log options) (:event options) (:component options)) edn?)
         :up (print-result (up-command (first positionals) (:policy options)
                                        (if-let [c (:cycle options)] (Long/parseLong c) 0))
                            edn?)
         (do (binding [*out* *err*]
               (println (str "aiueos: unsupported or not-yet-wired command `" (name command) "`"))
               (println "supported: verify, run, admit, inspect, surface, audit, up"))
             #?(:clj (System/exit 2)))))))

#?(:clj
   (defn -main [& argv]
     (dispatch argv)))
