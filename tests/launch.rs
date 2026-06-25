//! Coverage for `Broker::launch` (the single-component path behind `aiueos run`)
//! with host-importing WAT components and its `:aiueos/wasm` error handling:
//! a missing file, malformed bytes, and a host call the component never imported.
//! Exec-only (WAT) — no kototama.
#![cfg(feature = "wasm-runtime")]

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::error::AiueosError;
use aiueos::graph::CapabilityGraph;
use aiueos::manifest::Manifest;
use aiueos::policy::Policy;
use std::path::{Path, PathBuf};

fn broker() -> Broker {
    Broker::new(
        Policy::default(),
        AuditLog::new(std::env::temp_dir().join("aiueos-launch-test.edn")),
    )
}

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join("aiueos-launch-test");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn launch_in(dir: &Path, manifest: &str) -> aiueos::Result<i64> {
    let m = Manifest::load(&dir.join(manifest)).unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&m));
    broker().launch(&m, dir, &g)
}

#[test]
fn launch_runs_a_host_importing_component_with_a_fresh_bus() {
    // The example sensor imports :topic/publish (a kernel cap) → its grant lets
    // the publish through; launch runs it on a fresh bus and returns the reading.
    let m = Manifest::load(Path::new("examples/robot/sensor.edn")).expect("loads");
    let g = CapabilityGraph::build(std::slice::from_ref(&m));
    let r = broker()
        .launch(&m, Path::new("examples/robot"), &g)
        .expect("sensor launches");
    assert_eq!(r, 21);
}

#[test]
fn launch_traps_host_call_without_the_imported_capability() {
    // Publishes, but the manifest imports nothing → empty grant → publish traps.
    let dir = tmpdir();
    std::fs::write(
        dir.join("rogue.wat"),
        r#"(module
          (import "aiueos:host" "publish" (func $p (param i32 i64)))
          (func (export "tick") (param i64) (result i64)
            (call $p (i32.const 1) (local.get 0))
            (local.get 0)))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("rogue.edn"),
        r#"{:aiueos/component :driver/rogue :aiueos/kind :driver
            :aiueos/wasm "rogue.wat" :aiueos/entry "tick" :aiueos/args [5]}"#,
    )
    .unwrap();
    assert!(matches!(
        launch_in(&dir, "rogue.edn"),
        Err(AiueosError::Run(_))
    ));
}

#[test]
fn malformed_wasm_is_a_clean_run_error() {
    let dir = tmpdir();
    std::fs::write(dir.join("garbage.wat"), "this is not wasm or wat (((").unwrap();
    std::fs::write(
        dir.join("garbage.edn"),
        r#"{:aiueos/component :app/garbage :aiueos/kind :app
            :aiueos/wasm "garbage.wat" :aiueos/entry "main"}"#,
    )
    .unwrap();
    // Parse failure surfaces as a clean Run error, not a panic.
    assert!(matches!(
        launch_in(&dir, "garbage.edn"),
        Err(AiueosError::Run(_))
    ));
}

#[test]
fn missing_wasm_file_is_an_io_error() {
    let dir = tmpdir();
    std::fs::write(
        dir.join("ghost.edn"),
        r#"{:aiueos/component :app/ghost :aiueos/kind :app
            :aiueos/wasm "nope.wat" :aiueos/entry "main"}"#,
    )
    .unwrap();
    assert!(matches!(
        launch_in(&dir, "ghost.edn"),
        Err(AiueosError::Io(_))
    ));
}
