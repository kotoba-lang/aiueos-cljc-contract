//! Integration test for the boot sequence (`aiueos up`). The resident and
//! IOMMU-deny paths need only the runtime (they don't compile source); the
//! full 4-component success path compiles CLJ examples and so needs `kototama`.
#![cfg(feature = "wasm-runtime")]

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::graph::System;
use aiueos::manifest::Manifest;
use aiueos::policy::Policy;
use std::path::Path;

fn scratch_audit(name: &str) -> AuditLog {
    AuditLog::new(std::env::temp_dir().join(name))
}

// Compiles the CLJ example components → requires the kototama feature (monorepo).
#[cfg(feature = "kototama")]
#[test]
fn boots_the_example_system_in_dependency_order() {
    let sys = System::load(Path::new("examples/system.aiueos.edn")).expect("system loads");
    let policy = Policy::load(Path::new("examples/policy/default.edn")).expect("policy loads");
    let broker = Broker::new(policy, scratch_audit("aiueos-boot-ok.edn"));

    // Providers must precede consumers: driver before fs, fs+log before the app.
    let order = sys.boot_order().expect("acyclic");
    let pos = |id: &str| {
        order
            .iter()
            .position(|&i| sys.components[i].id == id)
            .unwrap()
    };
    assert!(pos("driver/virtio-blk") < pos("service/fs"));
    assert!(pos("service/fs") < pos("app/notes"));
    assert!(pos("service/log") < pos("app/notes"));

    let report = broker.boot(&sys, Path::new("examples")).expect("boots");
    assert_eq!(report.launched.len(), 4);
    let notes = report
        .launched
        .iter()
        .find(|o| o.component == "app/notes")
        .expect("app launched");
    assert_eq!(notes.result, Some(42), "main(21) = 42");
}

#[test]
fn boot_rounds_threads_one_bus_across_rounds() {
    // A producer publishes one sample per round; a consumer returns count(scan).
    // Across 3 rounds on a shared bus the count grows 1 → 2 → 3 — proving the
    // topic bus persists between rounds (a periodic control loop).
    let dir = std::env::temp_dir().join("aiueos-rounds-test");
    std::fs::create_dir_all(&dir).unwrap();
    let prod = dir.join("prod.wat");
    std::fs::write(
        &prod,
        r#"(module (import "aiueos:host" "publish" (func $p (param i32 i64)))
            (func (export "tick") (result i64) (call $p (i32.const 1) (i64.const 5)) (i64.const 0)))"#,
    )
    .unwrap();
    let cons = dir.join("cons.wat");
    std::fs::write(
        &cons,
        r#"(module (import "aiueos:host" "count" (func $c (param i32) (result i64)))
            (func (export "tick") (result i64) (call $c (i32.const 1))))"#,
    )
    .unwrap();

    let producer = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/prod :aiueos/kind :driver :aiueos/wasm "{}"
            :aiueos/entry "tick" :aiueos/imports #{{:topic/publish}} :aiueos/exports #{{:topic/scan}}}}"#,
        prod.display()
    ))
    .unwrap();
    let consumer = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/cons :aiueos/kind :driver :aiueos/wasm "{}"
            :aiueos/entry "tick" :aiueos/imports #{{:topic/subscribe :topic/scan}}}}"#,
        cons.display()
    ))
    .unwrap();

    let sys = System::from_manifests("rounds", vec![producer, consumer]);
    let broker = Broker::new(Policy::default(), scratch_audit("aiueos-rounds.edn"));
    let reports = broker
        .boot_rounds(&sys, Path::new("."), 3)
        .expect("boots 3 rounds");
    assert_eq!(reports.len(), 3);

    let counts: Vec<i64> = reports
        .iter()
        .map(|r| {
            r.launched
                .iter()
                .find(|o| o.component == "driver/cons")
                .unwrap()
                .result
                .unwrap()
        })
        .collect();
    assert_eq!(
        counts,
        vec![1, 2, 3],
        "publish count persists across rounds"
    );
}

#[test]
fn random_differs_across_rounds() {
    // A node returns random() each round; the control-loop cycle advances per
    // round, so the readings differ — random + rounds integrated.
    let dir = std::env::temp_dir().join("aiueos-randrounds-test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("noisy.wat"),
        r#"(module (import "aiueos:host" "random" (func $r (result i64)))
            (func (export "tick") (result i64) (call $r)))"#,
    )
    .unwrap();
    let m = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/noisy :aiueos/kind :driver :aiueos/wasm "{}"
            :aiueos/entry "tick" :aiueos/imports #{{:random/bytes}}}}"#,
        dir.join("noisy.wat").display()
    ))
    .unwrap();
    let sys = System::from_manifests("noisy", vec![m]);
    let broker = Broker::new(Policy::default(), scratch_audit("aiueos-randrounds.edn"));
    let reports = broker
        .boot_rounds(&sys, Path::new("."), 3)
        .expect("3 rounds");
    let vals: Vec<i64> = reports
        .iter()
        .map(|r| r.launched[0].result.unwrap())
        .collect();
    assert_ne!(vals[0], vals[1], "random advances with the cycle");
    assert_ne!(vals[1], vals[2]);
}

#[test]
fn schedule_period_skips_off_cycles() {
    // Two components: one default (every cycle), one with :period-ms 2 (cycle-ms
    // default 1 → period_cycles 2). Over 3 cycles (0,1,2) the period-2 node runs
    // on cycles 0 and 2 only; the default node runs all three.
    let dir = std::env::temp_dir().join("aiueos-sched-test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("c.wat"),
        r#"(module (func (export "tick") (result i64) (i64.const 1)))"#,
    )
    .unwrap();
    let every = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/every :aiueos/kind :driver :aiueos/wasm "{}"
            :aiueos/entry "tick"}}"#,
        dir.join("c.wat").display()
    ))
    .unwrap();
    let half = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/half :aiueos/kind :driver :aiueos/wasm "{}"
            :aiueos/entry "tick" :aiueos/schedule {{:period-ms 2}}}}"#,
        dir.join("c.wat").display()
    ))
    .unwrap();
    let sys = System::from_manifests("sched", vec![every, half]);
    let broker = Broker::new(Policy::default(), scratch_audit("aiueos-sched.edn"));
    let reports = broker
        .boot_rounds(&sys, Path::new("."), 3)
        .expect("3 cycles");

    let ran =
        |r: &aiueos::broker::BootReport, id: &str| r.launched.iter().any(|o| o.component == id);
    // cycle 0: both; cycle 1: only the every-cycle node; cycle 2: both again.
    assert!(ran(&reports[0], "driver/half") && ran(&reports[0], "driver/every"));
    assert!(
        !ran(&reports[1], "driver/half"),
        "period-2 node skips cycle 1"
    );
    assert!(
        ran(&reports[1], "driver/every"),
        "every-cycle node still runs"
    );
    assert!(
        ran(&reports[2], "driver/half"),
        "period-2 node runs cycle 2"
    );
}

#[test]
fn clock_advances_across_rounds() {
    // clock() returns the control-loop cycle, so across 3 rounds it reads 0,1,2.
    let dir = std::env::temp_dir().join("aiueos-clock-test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("clk.wat"),
        r#"(module (import "aiueos:host" "clock" (func $c (result i64)))
            (func (export "tick") (result i64) (call $c)))"#,
    )
    .unwrap();
    let m = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/clk :aiueos/kind :driver :aiueos/wasm "{}"
            :aiueos/entry "tick" :aiueos/imports #{{:clock/monotonic}}}}"#,
        dir.join("clk.wat").display()
    ))
    .unwrap();
    let sys = System::from_manifests("clock", vec![m]);
    let broker = Broker::new(Policy::default(), scratch_audit("aiueos-clock.edn"));
    let reports = broker
        .boot_rounds(&sys, Path::new("."), 3)
        .expect("3 rounds");
    let ticks: Vec<i64> = reports
        .iter()
        .map(|r| r.launched[0].result.unwrap())
        .collect();
    assert_eq!(
        ticks,
        vec![0, 1, 2],
        "clock() reflects the control-loop cycle"
    );
}

#[test]
fn resident_component_with_no_code_launches_as_resident() {
    // A pure manifest (no :aiueos/source / :aiueos/wasm) passes the gate but has
    // nothing to execute — it boots as a resident with no result.
    let svc = Manifest::parse_str(
        "{:aiueos/component :svc/resident :aiueos/kind :service :aiueos/exports #{:x/y}}",
    )
    .unwrap();
    let sys = System::from_manifests("resident-demo", vec![svc]);
    let broker = Broker::new(Policy::default(), scratch_audit("aiueos-boot-resident.edn"));
    let report = broker.boot(&sys, Path::new(".")).expect("boots");
    assert_eq!(report.launched.len(), 1);
    assert_eq!(report.launched[0].component, "svc/resident");
    assert!(
        report.launched[0].result.is_none(),
        "no code → resident (no result)"
    );
}

#[test]
fn boot_enforces_declared_topic_isolation() {
    // The WAT publishes to topic 1, but the manifest declares :aiueos/publishes
    // #{2} — so the broker confines it to topic 2 and the publish to 1 traps.
    let dir = std::env::temp_dir().join("aiueos-topiciso-test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("rogue.wat"),
        r#"(module (import "aiueos:host" "publish" (func $p (param i32 i64)))
            (func (export "tick") (result i64) (call $p (i32.const 1) (i64.const 9)) (i64.const 0)))"#,
    )
    .unwrap();
    let m = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/rogue :aiueos/kind :driver :aiueos/wasm "{}"
            :aiueos/entry "tick" :aiueos/imports #{{:topic/publish}} :aiueos/publishes #{{2}}}}"#,
        dir.join("rogue.wat").display()
    ))
    .unwrap();
    let sys = System::from_manifests("iso", vec![m]);
    let broker = Broker::new(Policy::default(), scratch_audit("aiueos-topiciso.edn"));
    assert!(
        broker.boot(&sys, Path::new(".")).is_err(),
        "publishing to an undeclared topic must trap at boot"
    );
}

#[test]
fn boot_aborts_without_iommu_grant() {
    let sys = System::load(Path::new("examples/system.aiueos.edn")).expect("system loads");
    let broker = Broker::new(Policy::default(), scratch_audit("aiueos-boot-deny.edn"));
    // Default policy grants no IOMMU → the driver's :dma effect is denied → no boot.
    assert!(broker.boot(&sys, Path::new("examples")).is_err());
}
