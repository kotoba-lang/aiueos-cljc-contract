//! The **computer-use** deployment surface (ADR-0007): the `display/frame`,
//! `pointer/move`, `pointer/click`, `keyboard/key`, and `keyboard/type` providers.
//! Phase-0 keeps them in-process and deterministic — synthetic input is recorded
//! to the host audit ledger (`host_events`) and `frame` returns a monotonic handle
//! — a testable provider before the real Xvfb-container / microVM backing. They are
//! gated identically to every other capability: a component that doesn't hold the
//! cap traps, and the host's real HID is unreachable because no `pointer-host` /
//! `keyboard-host` / `display-host` provider is bound at all. WAT components
//! exercise the ABI directly: `wasm-runtime`, no kototama.
#![cfg(feature = "wasm-runtime")]

use aiueos::host;
use aiueos::topic::TopicBus;
use std::collections::BTreeSet;

// Captures a frame, moves the pointer to (10,20), clicks button 0, presses key 13,
// then types the 5-byte string "hello" — the synthetic-input vocabulary of a
// computer-use agent driving a virtual screen.
const DRIVE: &str = r#"(module
  (import "aiueos:host" "frame" (func $frame (result i64)))
  (import "aiueos:host" "pointer-move" (func $move (param i32 i32)))
  (import "aiueos:host" "pointer-click" (func $click (param i32)))
  (import "aiueos:host" "key" (func $key (param i32)))
  (import "aiueos:host" "type" (func $type (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "hello")
  (func (export "run") (result i64)
    (drop (call $frame))
    (call $move (i32.const 10) (i32.const 20))
    (call $click (i32.const 0))
    (call $key (i32.const 13))
    (call $type (i32.const 0) (i32.const 5))
    (i64.const 0)))"#;

// Tries to move the pointer with no capability granted — must trap.
const MOVE_ONLY: &str = r#"(module
  (import "aiueos:host" "pointer-move" (func $move (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "run") (result i64)
    (call $move (i32.const 1) (i32.const 2))
    (i64.const 0)))"#;

fn caps(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn run(wat: &str, caps: &BTreeSet<String>) -> aiueos::Result<host::HostOutcome> {
    host::run_with_host(
        wat.as_bytes(),
        "run",
        &[],
        1_000_000,
        4,
        caps,
        TopicBus::new(),
    )
}

#[test]
fn computer_virtual_records_synthetic_input_when_granted() {
    let granted = caps(&[
        "display/frame",
        "pointer/move",
        "pointer/click",
        "keyboard/key",
        "keyboard/type",
    ]);
    let o = run(DRIVE, &granted).expect("computer-use caps granted");
    // Every synthetic action is in the audit ledger — the record of what the agent
    // did on the virtual surface (ADR-0007 §6).
    let ev = &o.host_events;
    assert!(ev.iter().any(|e| e.starts_with("aiueos:host/frame id=")));
    assert!(ev.iter().any(|e| e == "aiueos:host/pointer-move x=10 y=20"));
    assert!(ev.iter().any(|e| e == "aiueos:host/pointer-click button=0"));
    assert!(ev.iter().any(|e| e == "aiueos:host/key code=13"));
    assert!(ev.iter().any(|e| e == "aiueos:host/type bytes=5"));
}

#[test]
fn pointer_move_traps_without_capability() {
    // The gate denies the call when pointer/move isn't conferred — the providers are
    // bound (resolvable) but never callable without the capability.
    assert!(
        run(MOVE_ONLY, &BTreeSet::new()).is_err(),
        "pointer-move without pointer/move must trap"
    );
}

#[test]
fn the_host_hid_is_unreachable_on_the_virtual_surface() {
    // ADR-0007: the host's real keyboard/mouse/display have NO provider bound on the
    // default (virtual) install, so importing one fails to instantiate even if a
    // (mis-issued) capability were held. Calling pointer-host is unresolvable.
    const GRAB: &str = r#"(module
      (import "aiueos:host" "pointer-host" (func $grab (param i32 i32)))
      (memory (export "memory") 1)
      (func (export "run") (result i64)
        (call $grab (i32.const 0) (i32.const 0))
        (i64.const 0)))"#;
    assert!(
        run(GRAB, &caps(&["pointer/host"])).is_err(),
        "host HID provider must be unbound (unreachable) on the virtual surface"
    );
}
