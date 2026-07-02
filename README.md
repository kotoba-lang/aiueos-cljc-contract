# aiueos-cljc-contract

CLJC/EDN authority contracts for aiueos.

This repository owns the semantic shapes for aiueos manifests, policy
decisions, grants, audit events, run plans, run receipts, and the
`aiueos/component` Wasm Component Model boundary.

Rust, JavaScript, Python, Svelte, or host-specific code may consume these
contracts as adapters/providers elsewhere, but they are not authority here.

## Contract Data

- `src/aiueos/contract.cljc` validates the pure aiueos data contracts.
- `src/aiueos/graph.cljc` derives capability providers, boot order, and dependency depth.
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
  **JVM-only** — needs `clojure -M:test`, not `bb` (Chicory isn't in babashka's
  class allowlist).
- `src/aiueos/launcher.cljc` is a real, runnable CLI: the retired Rust
  `bin/aiueos.rs`'s argv-parsing/file-I/O role, reimplemented as JVM Clojure.
  Ties `aiueos.cli` + `aiueos.manifest` + `aiueos.policy`/`aiueos.broker` +
  `aiueos.execute` together. `verify`/`run`/`admit` are wired today (`run`/`admit`
  actually execute a granted component's declared `:aiueos/wasm`, not just decide).
  Try it: `clojure -M -m aiueos.launcher run <manifest>.edn --edn`. **JVM-only**,
  same reason as `aiueos.execute`.
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
