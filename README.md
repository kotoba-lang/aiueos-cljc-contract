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
  admission gate, and `:aiueos/run-plan`/`:aiueos/run-receipt` shaping. Execution itself
  stays a native host-adapter concern (ADR-2607022200 Layer 3) — never ported here.
- `src/aiueos/cli.cljc` is the CLJC authority for the aiueos CLI command contract
  (mirrors `kotoba-lang/kotoba-lang`'s `kotoba.cli` pattern).
- `resources/aiueos/component_boundary.edn` owns the component imports/exports.
- `resources/aiueos/policy_contract.edn` / `broker_contract.edn` own the policy/broker decision tables.
- `resources/aiueos/cli.edn` owns the CLI command/option contract.
- `test/aiueos/*_test.cljc` checks every CLJC validator/reasoner/contract above.

Everything the retired Rust `aiueos` crate did that is NOT here (wasmtime hosting,
the CLI binary's execution path, the virtio driver, VM/initramfs provisioning) is
permanently native/host-adapter territory per ADR-2607022200 — `.kotoba` compiles
TO Wasm and cannot itself host other Wasm components. The one exception worth
naming: the retired `safe.rs` (safe-kotoba subset gate) was NOT ported because it
is redundant — that check already lives in `kotoba-lang/kotoba`'s
`kototama`/`kotoba-clj` layer (see `aiueos.broker`'s namespace docstring).

## Verify

```bash
clojure -M:test
bb test:cljc
```
