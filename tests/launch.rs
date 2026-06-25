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

// In a build without the CLJ compiler (the default/standalone config), a
// component that needs source compilation must fail with a clear, named error —
// not a panic, and not a silent no-op.
#[cfg(not(feature = "kototama"))]
#[test]
fn source_component_without_kototama_is_a_clear_error() {
    let dir = tmpdir();
    std::fs::write(dir.join("src.clj"), "(defn main [n] n)").unwrap();
    std::fs::write(
        dir.join("srccomp.edn"),
        r#"{:aiueos/component :app/src :aiueos/kind :app
            :aiueos/source "src.clj" :aiueos/entry "main"}"#,
    )
    .unwrap();
    match launch_in(&dir, "srccomp.edn") {
        Err(AiueosError::Run(msg)) => {
            assert!(
                msg.contains("kototama"),
                "error names the missing feature: {msg}"
            )
        }
        other => panic!("expected a Run error, got {other:?}"),
    }
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
fn wasm_sha256_matches_runs_and_mismatch_is_rejected() {
    let dir = tmpdir();
    let wat = br#"(module (func (export "main") (result i64) (i64.const 7)))"#;
    std::fs::write(dir.join("m.wat"), wat).unwrap();
    let good = aiueos::runtime::sha256_hex(wat);

    // correct hash → runs
    std::fs::write(
        dir.join("good.edn"),
        format!(
            r#"{{:aiueos/component :app/g :aiueos/kind :app
                :aiueos/wasm "m.wat" :aiueos/entry "main" :aiueos/wasm-sha256 "{good}"}}"#
        ),
    )
    .unwrap();
    assert_eq!(launch_in(&dir, "good.edn").unwrap(), 7);

    // wrong hash → rejected (tamper detection)
    std::fs::write(
        dir.join("bad.edn"),
        r#"{:aiueos/component :app/b :aiueos/kind :app
            :aiueos/wasm "m.wat" :aiueos/entry "main" :aiueos/wasm-sha256 "deadbeef"}"#,
    )
    .unwrap();
    assert!(matches!(
        launch_in(&dir, "bad.edn"),
        Err(AiueosError::Run(_))
    ));
}

#[test]
fn a_runtime_trap_is_audited_as_reject() {
    let dir = tmpdir();
    let logpath = dir.join("trap-audit.edn");
    let _ = std::fs::remove_file(&logpath);
    std::fs::write(
        dir.join("trap.wat"),
        r#"(module (func (export "tick") (result i64) (unreachable)))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("trap.edn"),
        r#"{:aiueos/component :app/trap :aiueos/kind :app :aiueos/wasm "trap.wat" :aiueos/entry "tick"}"#,
    )
    .unwrap();
    let m = Manifest::load(&dir.join("trap.edn")).unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&m));
    let broker = Broker::new(Policy::default(), AuditLog::new(&logpath));
    assert!(broker.launch(&m, &dir, &g).is_err(), "unreachable traps");

    let entries = AuditLog::new(&logpath).read().unwrap();
    let has_reject = entries.iter().any(|e| {
        aiueos::edn::get(e, "aiueos", "event")
            .and_then(|v| v.as_keyword().map(|k| k.name().to_string()))
            == Some("reject".to_string())
    });
    assert!(
        has_reject,
        "a runtime trap must leave a reject in the audit log"
    );
}

#[test]
fn launch_denies_an_unresolved_import() {
    // The component imports :fs/open — not a kernel cap, and with no provider in
    // its single-component graph it's unresolved → launch denies before running.
    let dir = tmpdir();
    std::fs::write(
        dir.join("needsfs.wat"),
        r#"(module (func (export "tick") (result i64) (i64.const 0)))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("needsfs.edn"),
        r#"{:aiueos/component :app/needsfs :aiueos/kind :app
            :aiueos/wasm "needsfs.wat" :aiueos/entry "tick" :aiueos/imports #{:fs/open}}"#,
    )
    .unwrap();
    assert!(matches!(
        launch_in(&dir, "needsfs.edn"),
        Err(AiueosError::Denied(_))
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
