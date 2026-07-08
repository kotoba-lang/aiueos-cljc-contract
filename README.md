# aiueos-cljc-contract

CLJC/EDN authority contracts for aiueos.

This repository owns the semantic shapes for aiueos manifests, policy
decisions, grants, audit events, run plans, run receipts, and the
`aiueos/component` Wasm Component Model boundary.

Rust, JavaScript, Python, Svelte, or host-specific code may consume these
contracts as adapters/providers elsewhere, but they are not authority here.

## Contract Data

- `src/aiueos/contract.cljc` validates the pure aiueos data contracts.
- `src/aiueos/graph.cljc` derives capability providers, boot order (`boot-order`,
  and `priority-boot-order` — same order with same-depth components sorted by
  `:aiueos/schedule` priority, ADR-0006), and dependency depth.
- `src/aiueos/policy.cljc` resolves grants, surface policy, and component admission.
- `src/aiueos/surface.cljc` owns the known deployment surface/provider registry.
- `src/aiueos/manifest.cljc` normalizes a manifest's trust/limits/quota/schedule/topic defaults.
- `src/aiueos/signing.cljc` verifies ed25519 manifest signatures (JDK-native, no external crypto dep).
- `src/aiueos/audit.cljc` builds and (JVM-)appends/reads append-only audit log entries.
- `src/aiueos/topic.cljc` is the pure, immutable in-process pub/sub topic bus.
- `src/aiueos/broker.cljc` composes the above into grant/deny decisions, the ADR-0004
  admission gate, and `:aiueos/run-plan`/`:aiueos/run-receipt` shaping.
- `src/aiueos/cli.cljc` is the CLJC authority for the aiueos CLI command contract
  (mirrors `kotoba-lang/kotoba-lang`'s `kotoba.cli` pattern).
- `src/aiueos/decide.cljc` is the decision subprocess bridge (ADR-2607022700):
  `bb decide` reads EDN requests on stdin, dispatches through `aiueos.cli`, writes
  EDN policy decisions on stdout — for host adapters that are not JVM processes.
- `src/aiueos/execute.cljc` **actually executes** a compiled `.kotoba` Wasm
  component (ADR-2607022900), via [Chicory](https://github.com/dylibso/chicory)
  (a pure-JVM Wasm runtime — no Rust, no wasmtime, no subprocess). Verifies through
  `aiueos.broker/verify-one` first and refuses to run anything denied; the 7
  non-hardware kernel capabilities (`log-write`/`clock-monotonic`/`random-bytes`/
  `topic-*`) get real Clojure-backed host functions, the device-access quartet
  (`pci-config`/`dma-map`/`irq-subscribe`/`mmio-map`) stays a deterministic stub
  pending real hardware access (native shim or `java.lang.foreign`, unresolved).
  Enforces `:aiueos/quota {:host-calls N :publishes N}` (ADR-0006) — a per-run
  host-function call-count cap; exceeding it aborts the run mid-execution
  (`:aiueos.execute/quota-exceeded`, offending call's own effect never lands).
  Also enforces `:aiueos/limits :fuel` (ADR-0001) — **real instruction-level
  metering**, via Chicory's `Instance.Builder/withUnsafeExecutionListener`
  (fires per Wasm instruction executed). Chicory has no first-class gas-metering
  API, and this hook is explicitly documented `unsafe`/`experimental`/possibly
  removed later (its supported execution-limit mechanism is a wall-clock
  thread-interrupt timeout, not this) — treat fuel enforcement as a working
  prototype on an unofficial API, not a permanent guarantee. It also only fires
  in Chicory's interpreter path; a future switch to Chicory's AOT compiler would
  bypass it entirely. Also enforces `:aiueos/limits :memory-pages` (ADR-0001) —
  via a **stable** Chicory API (`Instance.Builder/withMemoryLimits`, not marked
  unsafe/experimental like the fuel listener). Reads the module's own declared
  initial page count (never overridden — a module that needs N pages to start
  still gets them) and caps only the maximum `memory.grow` can reach. Unlike
  quota/fuel/topic-forbidden, this does NOT abort the run — `memory.grow` past
  the cap returns Wasm's own `-1` failure sentinel to the guest, observable
  directly in `:aiueos.execute/result`, same as any other Wasm runtime's memory
  limit. Also enforces `:aiueos/publishes`/`:aiueos/subscribes`
  (the topic-id allow-set `aiueos.manifest/normalize` derives) — a granted
  component's `topic_publish`/`topic_poll`/`topic_take`/`topic_count` calls are
  restricted to its declared topic ids (`nil` = unrestricted); this was
  previously validated/derived by `aiueos.manifest` but never actually enforced
  anywhere, letting a granted component access any topic id. Every result also
  carries an ADDITIVE `:aiueos/run-receipt` (`aiueos.broker/run-receipt`,
  ADR-2607022900 follow-up 8 — a pre-existing, tested contract `execute`
  previously never adopted, now wired in alongside the `:aiueos.execute/*`
  shape rather than replacing it): `:succeeded`/`:failed`/`:denied` status,
  `:started-at`/`:finished-at` (epoch ms), and the same audit events.
  **JVM-only** — needs `clojure -M:test`, not `bb` (Chicory isn't in babashka's
  class allowlist).
- `src/aiueos/launcher.cljc` is a real, runnable CLI: the retired Rust
  `bin/aiueos.rs`'s argv-parsing/file-I/O role, reimplemented as JVM Clojure.
  Ties `aiueos.cli` + `aiueos.manifest` + `aiueos.policy`/`aiueos.broker` +
  `aiueos.execute`/`aiueos.audit` together. `verify`/`run`/`admit`/`inspect`/
  `surface`/`audit`/`up` are wired today (`run`/`admit` actually execute a
  granted component's declared `:aiueos/wasm`, not just decide; `up` boots
  the components due at a given ADR-0006 cycle (`--cycle N`, default 0 —
  boots everyone, matching the pre-scheduling default) in
  `aiueos.graph/priority-boot-order` — dependency order with same-depth
  components ordered by `:aiueos/schedule`'s `:priority` — stopping at the
  first denied/quota-or-fuel-exceeded DUE component). Try it:
  `clojure -M -m aiueos.launcher up <system>.edn --cycle 3 --edn`.
  **`:aiueos/schedule`'s `:deadline-cycles` is NOT enforced** — see
  `aiueos.manifest/due-this-cycle?`'s docstring for why (Chicory's
  synchronous, non-preemptible execution has no mechanism to check
  elapsed cycles mid-run). **JVM-only**, same reason as `aiueos.execute`.
  Not wired: the adapter-only six (`sign`/`check`/`compile`/`hash`/
  `image`/`vm`).
- `resources/aiueos/component_boundary.edn` owns the component imports/exports.
- `resources/aiueos/policy_contract.edn` / `broker_contract.edn` own the policy/broker decision tables.
- `resources/aiueos/cli.edn` owns the CLI command/option contract.
- `test/aiueos/*_test.cljc` checks every CLJC validator/reasoner/contract above.

Per ADR-2607022900, the native adapter's *execution* layer (what the retired Rust
`host.rs`/`runtime.rs` did) is no longer assumed to require Rust/wasmtime — Chicory
lets it live here, in CLJC, for everything except real hardware access. What's still
genuinely out of scope: the device-access quartet's raw MMIO/DMA/PCI/IRQ handling,
the retired `virtio.rs` driver, and VM/initramfs provisioning. The one exception
worth naming on the language side: the retired `safe.rs` (safe-kotoba subset gate)
was NOT ported because it's redundant — that check already lives in
`kotoba-lang/kotoba`'s `kototama`/`kotoba-clj` layer.

## Verify

```bash
clojure -M:test   # full suite, including aiueos.execute-test (Chicory, JVM-only)
bb test:cljc      # everything except aiueos.execute-test
```

## Maturity

Tracked M0-M6 in `docs/coverage.edn` (template borrowed from
`kotoba-lang/kotoba-lang`'s `docs/lang/coverage.edn`). Currently at M4:
positive and negative fixtures are both extensive (every validator/reasoner
has deny-path tests, not just happy-path), CI runs the full suite on JDK
17 + 21. M5 (external-implementation-suite) is marked `:ambiguous` — see
the note in `docs/coverage.edn` about `kototama`'s dependency pointing at a
stale duplicate of this repo's `src/aiueos/` living in `kotoba-lang/aiueos`
rather than at this repo. M6 (compatibility policy) is not yet written.
