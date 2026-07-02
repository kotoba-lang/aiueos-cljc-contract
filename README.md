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
- `resources/aiueos/component_boundary.edn` owns the component imports/exports.
- `test/aiueos/*_test.cljc` checks the CLJC validator, graph, policy, surface, and EDN boundary.

## Verify

```bash
clojure -M:test
bb test:cljc
```
