//! End-to-end coverage of the `aiueos` binary: argument handling, exit codes, and
//! the commands that don't need the wasm runtime (help, unknown, check, audit,
//! verify). Drives the real built binary via `CARGO_BIN_EXE_aiueos`.

use std::path::PathBuf;
use std::process::Command;

/// Run the `aiueos` binary with `args`; return (exit code, stdout, stderr).
fn aiueos(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_aiueos"))
        .args(args)
        .output()
        .expect("spawn aiueos");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("aiueos-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn write(name: &str, contents: &str) -> PathBuf {
    let p = scratch(name);
    std::fs::write(&p, contents).unwrap();
    p
}

// ---------------------------------------------------------------------------
// usage / dispatch
// ---------------------------------------------------------------------------

#[test]
fn no_args_prints_usage_and_exits_zero() {
    let (code, _out, err) = aiueos(&[]);
    assert_eq!(code, 0);
    assert!(err.contains("USAGE"), "usage shown on stderr");
}

#[test]
fn help_exits_zero() {
    for flag in ["help", "-h", "--help"] {
        let (code, _o, _e) = aiueos(&[flag]);
        assert_eq!(code, 0, "`aiueos {flag}` exits 0");
    }
}

#[test]
fn unknown_command_exits_two() {
    let (code, _out, err) = aiueos(&["wibble"]);
    assert_eq!(code, 2, "unknown command → exit 2");
    assert!(err.contains("unknown command"));
}

// ---------------------------------------------------------------------------
// check — safe-kotoba subset gate
// ---------------------------------------------------------------------------

#[test]
fn check_accepts_safe_source() {
    let p = write("ok.clj", "(defn f [n] (+ n 1))");
    let (code, out, _e) = aiueos(&["check", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("safe-kotoba subset"));
}

#[test]
fn check_rejects_unsafe_source() {
    let p = write("bad.clj", r#"(defn f [] (slurp "/etc/passwd"))"#);
    let (code, _out, err) = aiueos(&["check", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("slurp"));
}

#[test]
fn check_without_file_arg_errors() {
    let (code, _out, _err) = aiueos(&["check"]);
    assert_eq!(code, 1);
}

// ---------------------------------------------------------------------------
// audit — replay
// ---------------------------------------------------------------------------

#[test]
fn audit_missing_log_reports_empty_and_exits_zero() {
    let p = scratch("nonexistent-audit.edn");
    let _ = std::fs::remove_file(&p);
    let (code, out, _e) = aiueos(&["audit", "--log", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("no audit entries"));
}

#[test]
fn audit_replays_a_populated_log() {
    // `verify` writes a grant entry to <manifest-dir>/.aiueos/audit.edn; replay it
    // and check the populated-log formatting (header + ts/event/component/detail).
    let manifest = write(
        "auditme.edn",
        "{:aiueos/component :app/auditme :aiueos/kind :app :aiueos/imports #{:log/write}}",
    );
    let log = scratch(".aiueos/audit.edn");
    let _ = std::fs::remove_file(&log);
    let (vc, _o, _e) = aiueos(&["verify", manifest.to_str().unwrap()]);
    assert_eq!(vc, 0, "verify writes an audit entry");

    let (code, out, _e) = aiueos(&["audit", "--log", log.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("entries"), "header with entry count");
    assert!(out.contains("grant"), "the grant event is rendered");
    assert!(out.contains("app/auditme"), "the component id is rendered");
    let _ = std::fs::remove_file(&log);
}

#[test]
fn audit_edn_on_empty_log_is_an_empty_vector() {
    // An agent consuming --edn must get parseable EDN even when there's nothing —
    // an empty vector, not a human "(no audit entries)" line or an error.
    let p = scratch("nonexistent-audit-edn.edn");
    let _ = std::fs::remove_file(&p);
    let (code, out, _e) = aiueos(&["audit", "--log", p.to_str().unwrap(), "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN even when empty");
    assert_eq!(v.as_vector().map(|x| x.len()), Some(0), "empty log → []");
}

#[test]
fn audit_filters_by_event_and_emits_edn() {
    // Use an ISOLATED dir so verify's audit log isn't shared with other tests
    // (the negative filters below rely on the log containing only our entries).
    let dir = std::env::temp_dir().join("aiueos-cli-auditfilter");
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = dir.join("filterme.edn");
    std::fs::write(
        &manifest,
        "{:aiueos/component :app/filterme :aiueos/kind :app :aiueos/imports #{:log/write}}",
    )
    .unwrap();
    let log = dir.join(".aiueos/audit.edn");
    let _ = std::fs::remove_file(&log);
    let (_c, _o, _e) = aiueos(&["verify", manifest.to_str().unwrap()]);

    // --event grant → only grant entries; --edn → an EDN vector.
    let (code, out, _e) = aiueos(&[
        "audit",
        "--log",
        log.to_str().unwrap(),
        "--event",
        "grant",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("filtered log is valid EDN");
    let items = v.as_vector().expect("a vector");
    assert!(!items.is_empty(), "at least one grant");
    assert!(
        items
            .iter()
            .all(|e| aiueos::edn::get_kw(e, "aiueos", "event").as_deref() == Some("grant")),
        "every entry matches the event filter"
    );

    // --event deny → no matches for this clean component.
    let (code, out, _e) = aiueos(&["audit", "--log", log.to_str().unwrap(), "--event", "deny"]);
    assert_eq!(code, 0);
    assert!(out.contains("no audit entries"));

    // --component matches the one we ran; a different id → no matches.
    let (code, out, _e) = aiueos(&[
        "audit",
        "--log",
        log.to_str().unwrap(),
        "--component",
        "app/filterme",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("app/filterme"));
    let (code, out, _e) = aiueos(&[
        "audit",
        "--log",
        log.to_str().unwrap(),
        "--component",
        "app/nobody",
    ]);
    assert_eq!(code, 0);
    assert!(
        out.contains("no audit entries"),
        "unknown component → no matches"
    );
    let _ = std::fs::remove_file(&log);
}

// ---------------------------------------------------------------------------
// verify — capability + policy check on a single manifest (no wasm needed)
// ---------------------------------------------------------------------------

#[test]
fn verify_clean_manifest_passes() {
    // imports only a kernel-provided capability → resolves with the default policy.
    let p = write(
        "ok.edn",
        "{:aiueos/component :app/ok :aiueos/kind :app :aiueos/imports #{:log/write}}",
    );
    let (code, out, _err) = aiueos(&["verify", p.to_str().unwrap()]);
    assert_eq!(code, 0, "clean manifest verifies");
    assert!(out.contains("verified"));
}

#[test]
fn verify_unresolved_import_is_denied() {
    let p = write(
        "lonely.edn",
        "{:aiueos/component :app/lonely :aiueos/kind :app :aiueos/imports #{:gpu/render}}",
    );
    let (code, _out, err) = aiueos(&["verify", p.to_str().unwrap()]);
    assert_eq!(code, 1, "unresolved import → denied");
    assert!(err.contains("unresolved-capability"));
}

#[test]
fn verify_accepts_flags_before_the_path() {
    // `--policy <val>` before the target must not be mistaken for the target.
    let (code, out, _e) = aiueos(&[
        "verify",
        "--policy",
        "examples/policy/default.edn",
        "examples/system.aiueos.edn",
    ]);
    assert_eq!(
        code, 0,
        "policy-before-path applies the policy to the system"
    );
    assert!(out.contains("verified"));
}

#[test]
fn verify_edn_reports_structural_errors_as_edn() {
    // A missing file in --edn mode → EDN error on stdout (not human stderr), exit 1.
    let (code, out, _e) = aiueos(&["verify", "/no/such/system.aiueos.edn", "--edn"]);
    assert_eq!(code, 1);
    let v = kotoba_edn::parse(out.trim()).expect("error is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "kind")
            .and_then(|x| x.as_keyword().map(|k| k.name().to_string())),
        Some("io".to_string())
    );
    assert!(aiueos::edn::get(&v, "aiueos", "error").is_some());
}

#[test]
fn verify_edn_emits_machine_readable_verdict() {
    // pass: with the IOMMU policy → verified true, output is valid EDN.
    let (code, out, _e) = aiueos(&[
        "verify",
        "examples/system.aiueos.edn",
        "--policy",
        "examples/policy/default.edn",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("verdict is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "verified").and_then(|x| x.as_bool()),
        Some(true)
    );
    assert!(aiueos::edn::get(&v, "aiueos", "grants").is_some());

    // deny: no policy → verified false + violations, exit 1, still valid EDN.
    let (code, out, _e) = aiueos(&["verify", "examples/system.aiueos.edn", "--edn"]);
    assert_eq!(code, 1, "denial → exit 1 even in --edn mode");
    let v = kotoba_edn::parse(out.trim()).expect("denial verdict is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "verified").and_then(|x| x.as_bool()),
        Some(false)
    );
    assert!(aiueos::edn::get(&v, "aiueos", "violations").is_some());
}

// ---------------------------------------------------------------------------
// inspect — pure (no wasm), reads the bundled example system
// ---------------------------------------------------------------------------

#[test]
fn inspect_prints_the_capability_graph() {
    // Integration tests run with cwd = crate root, so the examples are present.
    let (code, out, _e) = aiueos(&[
        "inspect",
        "examples/system.aiueos.edn",
        "--policy",
        "examples/policy/default.edn",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("capability graph"));
    assert!(out.contains("driver/virtio-blk"));
    assert!(out.contains("log/write"));
    // the driver's device binding is surfaced
    assert!(out.contains("device: bus=pci"));
    assert!(out.contains("0x1af4:0x1001"));
}

#[test]
fn inspect_empty_graph_reports_no_capabilities() {
    // A system whose components export nothing → the capability graph is empty.
    write(
        "noexports.edn",
        "{:aiueos/component :app/q :aiueos/kind :app}",
    );
    let sys = write(
        "emptysys.aiueos.edn",
        r#"{:aiueos/system :empty :aiueos/components ["noexports.edn"]}"#,
    );
    let (code, out, _e) = aiueos(&["inspect", sys.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("no exported capabilities"));
}

#[test]
fn inspect_edn_emits_structured_snapshot() {
    let (code, out, _e) = aiueos(&["inspect", "examples/system.aiueos.edn", "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("snapshot is valid EDN");
    // top-level shape: system + components + graph + verdicts
    assert!(aiueos::edn::get(&v, "aiueos", "system").is_some());
    assert!(aiueos::edn::get(&v, "aiueos", "components").is_some());
    assert!(aiueos::edn::get(&v, "aiueos", "graph").is_some());
    assert!(aiueos::edn::get(&v, "aiueos", "verdicts").is_some());
}

#[test]
fn inspect_on_a_single_manifest_gives_a_helpful_error() {
    // A single component manifest isn't a system graph — inspect should say so
    // (and point at `verify`), not emit a cryptic ":aiueos/components" error.
    let p = write("single.edn", "{:aiueos/component :app/x :aiueos/kind :app}");
    let (code, _out, err) = aiueos(&["inspect", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("system graph") && err.contains("verify"));
}

#[test]
fn inspect_dot_renders_the_robot_topic_dataflow() {
    // Named topics ARE capability-graph edges, so --dot draws the actual
    // sensor → planner → actuator pipeline (the boot-order dataflow).
    let (code, out, _e) = aiueos(&["inspect", "examples/robot/robot.aiueos.edn", "--dot"]);
    assert_eq!(code, 0);
    assert!(out.contains(r#""driver/sensor" -> "agent/planner""#));
    assert!(out.contains(r#""agent/planner" -> "driver/actuator""#));
    assert!(out.contains("topic/scan") && out.contains("topic/cmd"));
}

#[test]
fn inspect_human_shows_topic_confinement() {
    // The robot nodes derive publishes/subscribes — the human view shows them
    // like it shows device bindings.
    let (code, out, _e) = aiueos(&["inspect", "examples/robot/robot.aiueos.edn"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("topics: pub["),
        "per-component topic confinement shown"
    );
}

#[test]
fn inspect_edn_includes_per_topic_isolation() {
    // The robot components declare/derive publishes/subscribes — inspect --edn
    // should expose them so an agent sees the topic confinement.
    let (code, out, _e) = aiueos(&["inspect", "examples/robot/robot.aiueos.edn", "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    let comps = aiueos::edn::get(&v, "aiueos", "components")
        .and_then(|x| x.as_vector())
        .expect("components vector");
    // component fields are bare keywords (:id, :publishes, …)
    let sensor = comps
        .iter()
        .find(|c| {
            aiueos::edn::get_bare(c, "id").and_then(|x| x.as_string()) == Some("driver/sensor")
        })
        .expect("sensor present");
    // sensor publishes to topic 1 (derived from its :topic/scan export)
    assert!(aiueos::edn::get_bare(sensor, "publishes").is_some());
}

#[test]
fn inspect_dot_emits_a_graphviz_digraph() {
    let (code, out, _e) = aiueos(&["inspect", "examples/system.aiueos.edn", "--dot"]);
    assert_eq!(code, 0);
    assert!(out.contains("digraph aiueos"));
    assert!(out.contains("->"), "has at least one dependency edge");
    // the driver provides block/* to the fs service
    assert!(out.contains(r#""driver/virtio-blk" -> "service/fs""#));
}

#[test]
fn inspect_renders_policy_violations() {
    // No --policy → default policy grants no IOMMU → the driver's DMA is denied.
    // inspect reports (it doesn't gate), so it still exits 0 but shows the ✗ line.
    let (code, out, _e) = aiueos(&["inspect", "examples/system.aiueos.edn"]);
    assert_eq!(code, 0, "inspect reports rather than gating");
    assert!(
        out.contains("dma-without-iommu"),
        "the violation kind is rendered"
    );
    assert!(out.contains("driver/virtio-blk"));
}

// ---------------------------------------------------------------------------
// up / run on the WAT robot system — exercises boot + launch + the host ABI
// through the binary without the CLJ compiler (standalone-capable).
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm-runtime")]
#[test]
fn hash_prints_sha256_matching_the_library() {
    let p = write("hashme.wat", "(module)");
    let want = aiueos::runtime::sha256_hex(b"(module)");
    let (code, out, _e) = aiueos(&["hash", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(
        out.contains(&want),
        "prints the sha256 the broker will check against"
    );
    // --edn form is parseable and carries the same digest
    let (code, out, _e) = aiueos(&["hash", p.to_str().unwrap(), "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "sha256").and_then(|x| x.as_string()),
        Some(want.as_str())
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn hash_missing_file_errors() {
    let (code, _o, _e) = aiueos(&["hash", "/no/such/artifact.wasm"]);
    assert_eq!(code, 1);
}

#[cfg(feature = "signing")]
#[test]
fn verify_edn_surfaces_authenticity_per_component() {
    // An agent verifying a component should see provenance in --edn, not just pass/fail.
    let (code, out, _e) = aiueos(&[
        "verify",
        "examples/signed/demo.edn",
        "--policy",
        "examples/signed/policy.edn",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    let auth = aiueos::edn::get(&v, "aiueos", "authenticity").expect("authenticity present");
    // authenticity is a {component-id-string status-string} map
    let status = match auth {
        kotoba_edn::EdnValue::Map(m) => m
            .iter()
            .find(|(k, _)| k.as_string() == Some("app/signed-demo"))
            .and_then(|(_, val)| val.as_string()),
        _ => None,
    };
    assert_eq!(
        status,
        Some("verified:demo"),
        "names the signer that vouched for the component"
    );
}

#[cfg(feature = "signing")]
#[test]
fn verify_edn_reports_denied_authenticity_for_an_unregistered_signer() {
    // The signed example under the DEFAULT policy (no :aiueos/signers) → the signer
    // is unregistered → the verdict is verified:false with authenticity "denied".
    let (code, out, _e) = aiueos(&["verify", "examples/signed/demo.edn", "--edn"]);
    assert_eq!(code, 1, "an unregistered signer is denied");
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN even on denial");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "verified").and_then(|x| x.as_bool()),
        Some(false)
    );
    let status = match aiueos::edn::get(&v, "aiueos", "authenticity") {
        Some(kotoba_edn::EdnValue::Map(m)) => m
            .iter()
            .find(|(k, _)| k.as_string() == Some("app/signed-demo"))
            .and_then(|(_, val)| val.as_string()),
        _ => None,
    };
    assert_eq!(status, Some("denied"), "authenticity reports the denial");
}

#[cfg(feature = "signing")]
#[test]
fn the_signed_example_verifies_only_with_its_signer_policy() {
    // The bundled signed example verifies under the policy that registers its
    // signer, and is denied without it (unregistered signer). Keeps the example
    // and its committed signature honest.
    let (code, out, _e) = aiueos(&[
        "verify",
        "examples/signed/demo.edn",
        "--policy",
        "examples/signed/policy.edn",
    ]);
    assert_eq!(code, 0, "signed example verifies with its signer policy");
    assert!(out.contains("verified"));

    // default policy has no signers → the signer is unregistered → denied
    let (code, _o, _e) = aiueos(&["verify", "examples/signed/demo.edn"]);
    assert_eq!(code, 1, "denied without the signer registered");
}

#[cfg(feature = "signing")]
#[test]
fn sign_output_is_consumable_by_the_verifier() {
    // sign a manifest via the CLI, then feed the emitted signature + public key
    // back into the library verifier — the full sign → verify cycle.
    let p = write(
        "tosign.edn",
        r#"{:aiueos/component :app/demo :aiueos/kind :app :aiueos/wasm-sha256 "abc123"}"#,
    );
    let seed = "07".repeat(32); // 32-byte hex seed
    let (code, out, _e) = aiueos(&["sign", p.to_str().unwrap(), "--key", &seed, "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    let sig = aiueos::edn::get(&v, "aiueos", "signature")
        .and_then(|x| x.as_string())
        .unwrap()
        .to_string();
    let pk = aiueos::edn::get(&v, "aiueos", "public-key")
        .and_then(|x| x.as_string())
        .unwrap()
        .to_string();

    let signed = aiueos::manifest::Manifest::parse_str(&format!(
        r#"{{:aiueos/component :app/demo :aiueos/kind :app :aiueos/wasm-sha256 "abc123"
            :aiueos/signer "dev" :aiueos/signature "{sig}"}}"#
    ))
    .unwrap();
    let policy = aiueos::policy::Policy::from_edn(
        &kotoba_edn::parse(&format!("{{:aiueos/signers {{:dev \"{pk}\"}}}}")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        aiueos::signing::verify(&signed, &policy).unwrap(),
        aiueos::signing::SigStatus::Verified("dev".into()),
        "the CLI-produced signature verifies"
    );

    // signing a manifest with no artifact hash to bind → error
    let nohash = write("nohash.edn", "{:aiueos/component :app/n :aiueos/kind :app}");
    let (code, _o, _e) = aiueos(&["sign", nohash.to_str().unwrap(), "--key", &seed]);
    assert_eq!(code, 1, "no :aiueos/wasm-sha256 → nothing to sign");
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_on_a_single_manifest_gives_a_helpful_error() {
    let p = write(
        "single-for-up.edn",
        "{:aiueos/component :app/x :aiueos/kind :app}",
    );
    let (code, _out, err) = aiueos(&["up", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("system graph") && err.contains("run"));
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn dry_run_validates_the_clj_system_without_the_compiler() {
    // The CLJ example system can't be *booted* without the kototama feature, but
    // --dry-run stops before compilation — so it validates the system's manifests,
    // wiring, and policy even in the default/standalone build.
    let (code, out, _e) = aiueos(&[
        "up",
        "examples/system.aiueos.edn",
        "--policy",
        "examples/policy/default.edn",
        "--dry-run",
    ]);
    assert_eq!(code, 0, "dry-run validates without compiling CLJ");
    assert!(out.contains("4 component(s) would launch"));
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_dry_run_verifies_without_launching() {
    let (code, out, _e) = aiueos(&["up", "examples/robot/robot.aiueos.edn", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(out.contains("dry-run"));
    // nothing is launched, so no component result lines
    assert!(!out.contains("→ 21"), "no component is actually executed");

    // --edn form
    let (code, out, _e) = aiueos(&[
        "up",
        "examples/robot/robot.aiueos.edn",
        "--dry-run",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "dry-run").and_then(|x| x.as_bool()),
        Some(true)
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_boots_the_robot_system() {
    let (code, out, _e) = aiueos(&["up", "examples/robot/robot.aiueos.edn"]);
    assert_eq!(code, 0, "robot boots with the default policy");
    assert!(out.contains("system up"));
    assert!(out.contains("3/3"));
    assert!(out.contains("driver/actuator"));
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_rounds_runs_n_cycles() {
    let (code, out, _e) = aiueos(&[
        "up",
        "examples/robot/robot.aiueos.edn",
        "--rounds",
        "2",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    // multi-round → :aiueos/rounds is a vector of 2 rounds; :aiueos/launched kept.
    let rounds = aiueos::edn::get(&v, "aiueos", "rounds").expect("rounds present");
    assert_eq!(rounds.as_vector().map(|r| r.len()), Some(2));
    assert!(aiueos::edn::get(&v, "aiueos", "launched").is_some());
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_edn_emits_machine_readable_boot_report() {
    let (code, out, _e) = aiueos(&["up", "examples/robot/robot.aiueos.edn", "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("boot report is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "system").and_then(|x| x.as_string()),
        Some("robot")
    );
    assert!(aiueos::edn::get(&v, "aiueos", "launched").is_some());
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn run_edn_emits_machine_readable_result() {
    let (code, out, _e) = aiueos(&[
        "run",
        "examples/robot/sensor.edn",
        "--system",
        "examples/robot/robot.aiueos.edn",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("run result is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "result").and_then(|x| x.as_integer()),
        Some(21)
    );
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "component").and_then(|x| x.as_string()),
        Some("driver/sensor")
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn run_a_host_importing_component() {
    let (code, out, _e) = aiueos(&[
        "run",
        "examples/robot/sensor.edn",
        "--system",
        "examples/robot/robot.aiueos.edn",
    ]);
    assert_eq!(code, 0);
    assert!(
        out.contains("= 21"),
        "sensor publishes & returns its reading"
    );
}

// ---------------------------------------------------------------------------
// up / run / compile on the CLJ example system — needs the kototama compiler
// (monorepo only); dormant in a standalone build.
// ---------------------------------------------------------------------------

#[cfg(feature = "kototama")]
#[test]
fn up_boots_the_example_system_with_policy() {
    let (code, out, _e) = aiueos(&[
        "up",
        "examples/system.aiueos.edn",
        "--policy",
        "examples/policy/default.edn",
    ]);
    assert_eq!(code, 0, "boots with the iommu policy");
    assert!(out.contains("system up"));
    assert!(out.contains("4/4"));
}

#[cfg(feature = "kototama")]
#[test]
fn up_without_policy_aborts_on_dma_denial() {
    let (code, _out, err) = aiueos(&["up", "examples/system.aiueos.edn"]);
    assert_eq!(code, 1, "no iommu grant → boot aborts");
    assert!(err.contains("dma-without-iommu"));
}

#[cfg(feature = "kototama")]
#[test]
fn run_app_compiles_and_executes_to_42() {
    let (code, out, _e) = aiueos(&[
        "run",
        "examples/apps/notes.edn",
        "--system",
        "examples/system.aiueos.edn",
        "--policy",
        "examples/policy/default.edn",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("= 42"));
}

// ---------------------------------------------------------------------------
// compile — CLJ/manifest → wasm (wasm-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "kototama")]
#[test]
fn compile_clj_writes_wasm_next_to_source() {
    let p = write("comp_src.clj", "(defn main [n] (+ n 1))");
    let wasm = p.with_extension("wasm");
    let _ = std::fs::remove_file(&wasm);
    let (code, out, _e) = aiueos(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("compiled"));
    let bytes = std::fs::read(&wasm).expect("wasm written next to source");
    assert_eq!(&bytes[0..4], b"\0asm", "real wasm magic");
    let _ = std::fs::remove_file(&wasm);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_honors_output_flag() {
    let p = write("comp_src2.clj", "(defn main [n] n)");
    let out_path = scratch("custom_out.wasm");
    let _ = std::fs::remove_file(&out_path);
    let (code, _o, _e) = aiueos(&[
        "compile",
        p.to_str().unwrap(),
        "-o",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(out_path.exists(), "wasm written to the -o path");
    let _ = std::fs::remove_file(&out_path);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_rejects_unsafe_source_before_emitting() {
    let p = write("comp_bad.clj", r#"(defn f [] (slurp "x"))"#);
    let wasm = p.with_extension("wasm");
    let _ = std::fs::remove_file(&wasm);
    let (code, _o, err) = aiueos(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("slurp"));
    assert!(
        !wasm.exists(),
        "no wasm emitted when the source is rejected"
    );
}

#[cfg(feature = "kototama")]
#[test]
fn compile_manifest_reads_its_source() {
    let dir = std::env::temp_dir().join("aiueos-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("m_src.clj"), "(defn main [n] (* n 3))").unwrap();
    let manifest = dir.join("m.edn");
    std::fs::write(
        &manifest,
        r#"{:aiueos/component :app/m :aiueos/kind :app :aiueos/source "m_src.clj"}"#,
    )
    .unwrap();
    let outp = dir.join("m_out.wasm");
    let _ = std::fs::remove_file(&outp);
    let (code, _o, _e) = aiueos(&[
        "compile",
        manifest.to_str().unwrap(),
        "-o",
        outp.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "manifest's :aiueos/source is compiled");
    assert!(outp.exists());
    let _ = std::fs::remove_file(&outp);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_manifest_without_source_errors() {
    let p = write("nosrc.edn", "{:aiueos/component :app/n :aiueos/kind :app}");
    let (code, _o, _e) = aiueos(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 1, "manifest with no :aiueos/source cannot compile");
}
