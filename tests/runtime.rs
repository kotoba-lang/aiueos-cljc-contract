//! Integration tests for the execution seam (feature `wasm-runtime`): the
//! broker-conferred fuel + memory limits must actually be enforced, and a real
//! module must run. Uses WAT directly so the tests don't need the (dormant)
//! kototama CLJ compiler — they run in a standalone clone.

#![cfg(feature = "wasm-runtime")]

use aiueos::runtime;

// doubles its i64 arg; exports a 1-page linear memory.
const DOUBLE: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "main") (param $n i64) (result i64)
    (i64.mul (local.get $n) (i64.const 2))))"#;

// spins forever — only a fuel budget can stop it.
const SPIN: &str = r#"(module
  (func (export "go") (result i64)
    (loop $l (br $l))
    (i64.const 0)))"#;

#[test]
fn runs_a_module_under_limits() {
    let r = runtime::run_wasm(DOUBLE.as_bytes(), "main", &[21], 10_000_000, 16).expect("runs");
    assert_eq!(r, 42);
}

#[test]
fn fuel_limit_traps_runaway() {
    // An unbounded loop must be stopped by the fuel budget, not hang the host —
    // capability enforcement, not cooperation.
    let r = runtime::run_wasm(SPIN.as_bytes(), "go", &[], 50_000, 16);
    assert!(r.is_err(), "runaway should exhaust fuel / trap");
}

#[test]
fn memory_cap_is_enforced() {
    // The module exports a 1-page memory. A zero-page cap must reject
    // instantiation rather than let it allocate.
    assert!(
        runtime::run_wasm(DOUBLE.as_bytes(), "main", &[21], 10_000_000, 0).is_err(),
        "0-page memory cap must trap the module's initial memory"
    );
    // A generous cap runs fine — proves it's the limit, not the module, failing.
    assert_eq!(
        runtime::run_wasm(DOUBLE.as_bytes(), "main", &[21], 10_000_000, 16).unwrap(),
        42
    );
}

#[test]
fn missing_entry_function_is_a_run_error() {
    assert!(runtime::run_wasm(DOUBLE.as_bytes(), "nonexistent", &[1], 10_000, 16).is_err());
}
