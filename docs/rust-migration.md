# Rust Migration

`aiueos` is currently a Rust crate that models component manifests, capability
graphs, policy reasoning, safe checks, audit logs, topic buses, and optional wasm
execution. The target architecture is Kotoba/CLJC as the semantic authority with
native execution hidden behind host adapters.

## Current Rust Surface

| module | role | target |
|---|---|---|
| `manifest` | component/system EDN parsing | CLJC schema and parser contract |
| `graph` | capability graph projection | CLJC pure data transform |
| `policy` | grants/effects/DMA/device policy | CLJC policy engine |
| `broker` | verify/compile/run orchestration | CLJC orchestration contract plus host adapter |
| `safe` | safe-kotoba subset gate | Kotoba/CLJC language gate |
| `audit` | append-only EDN audit log | CLJC audit event schema |
| `topic` | in-process topic bus | CLJC protocol contract; host-specific transport adapters |
| `host` / `runtime` | wasm execution and host ABI | native backend adapter only |

## Target Boundary

Authoritative:

- manifest schema
- capability graph semantics
- policy reasoner rules
- safe-kotoba gate contract
- audit event schema
- topic protocol
- broker state machine

Host adapter only:

- `wasmtime`
- artifact hash calculation
- ed25519 verification implementation
- filesystem/CLI execution
- native process lifecycle

## CLJC Authority Seed

`src/aiueos/contract.cljc` now defines the first pure CLJC contract for the
shared authority layer: validators for a minimal component manifest, policy
decision, and audit event. The contract is intentionally data-only so Rust,
Kotoba, and other host adapters can conform to the same EDN shapes while runtime
behavior migrates incrementally.

## Migration Steps

1. Extract manifest, graph, policy, audit, topic, and broker contracts to CLJC.
2. Keep Rust as a compatibility CLI/runtime host that consumes those contracts.
3. Replace Rust-only policy decisions with CLJC pure functions and conformance
   tests.
4. Generate or mechanically mirror host adapter structs from CLJC schemas.
5. Retire the Rust crate once Kotoba-native CLI/runtime can launch the same
   component graph.
