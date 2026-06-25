//! Coverage for system-graph loading/validation and broker auditing of the
//! deny path. Pure core — no wasm runtime needed. Uses temp files for the
//! on-disk loading paths.

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::error::AiueosError;
use aiueos::graph::{CapabilityGraph, System};
use aiueos::manifest::Manifest;
use aiueos::policy::Policy;
use std::path::PathBuf;

fn m(src: &str) -> Manifest {
    Manifest::parse_str(src).unwrap()
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aiueos-systest-{name}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// System::load — structural errors
// ---------------------------------------------------------------------------

#[test]
fn system_load_missing_components_is_schema_error() {
    let dir = tmp("nocomps");
    let sys = dir.join("system.aiueos.edn");
    std::fs::write(&sys, "{:aiueos/system :x}").unwrap();
    assert!(matches!(System::load(&sys), Err(AiueosError::Schema(_))));
}

#[test]
fn system_load_nonstring_component_path_is_schema_error() {
    let dir = tmp("badpath");
    let sys = dir.join("system.aiueos.edn");
    std::fs::write(
        &sys,
        "{:aiueos/system :x :aiueos/components [:not-a-string]}",
    )
    .unwrap();
    assert!(matches!(System::load(&sys), Err(AiueosError::Schema(_))));
}

#[test]
fn system_load_missing_component_file_is_io_error() {
    let dir = tmp("missingfile");
    let sys = dir.join("system.aiueos.edn");
    std::fs::write(
        &sys,
        r#"{:aiueos/system :x :aiueos/components ["ghost.edn"]}"#,
    )
    .unwrap();
    assert!(matches!(System::load(&sys), Err(AiueosError::Io(_))));
}

#[test]
fn system_load_resolves_component_relative_to_system_file() {
    let dir = tmp("relresolve");
    std::fs::write(
        dir.join("c.edn"),
        "{:aiueos/component :svc/a :aiueos/kind :service :aiueos/exports #{:a/x}}",
    )
    .unwrap();
    let sys = dir.join("system.aiueos.edn");
    std::fs::write(&sys, r#"{:aiueos/system :x :aiueos/components ["c.edn"]}"#).unwrap();
    let loaded = System::load(&sys).expect("loads");
    assert_eq!(loaded.components.len(), 1);
    assert_eq!(loaded.components[0].id, "svc/a");
    // The component's base dir is its own directory, not the cwd.
    assert_eq!(loaded.bases[0], dir);
}

// ---------------------------------------------------------------------------
// duplicate-id detection
// ---------------------------------------------------------------------------

#[test]
fn duplicate_component_ids_are_rejected() {
    let a = m("{:aiueos/component :svc/dup :aiueos/kind :service :aiueos/exports #{:a/x}}");
    let b = m("{:aiueos/component :svc/dup :aiueos/kind :service :aiueos/exports #{:b/y}}");
    assert!(matches!(
        System::try_from_manifests("s", vec![a, b]),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn unique_component_ids_pass_validation() {
    let a = m("{:aiueos/component :svc/a :aiueos/kind :service}");
    let b = m("{:aiueos/component :svc/b :aiueos/kind :service}");
    assert!(System::try_from_manifests("s", vec![a, b]).is_ok());
}

// ---------------------------------------------------------------------------
// capability graph
// ---------------------------------------------------------------------------

#[test]
fn capability_graph_lists_all_providers_of_a_shared_capability() {
    // Two services both exporting log/write → both are providers.
    let a = m("{:aiueos/component :svc/a :aiueos/kind :service :aiueos/exports #{:log/write}}");
    let b = m("{:aiueos/component :svc/b :aiueos/kind :service :aiueos/exports #{:log/write}}");
    let g = CapabilityGraph::build(&[a, b]);
    let mut provs = g.providers("log/write").to_vec();
    provs.sort();
    assert_eq!(provs, vec!["svc/a".to_string(), "svc/b".to_string()]);
    assert!(g.providers("nope/none").is_empty());
}

// ---------------------------------------------------------------------------
// broker: the deny path must be audited
// ---------------------------------------------------------------------------

#[test]
fn broker_audits_grant_and_deny() {
    let path = tmp("audit").join("audit.edn");
    let _ = std::fs::remove_file(&path);
    let broker = Broker::new(Policy::default(), AuditLog::new(&path));

    // A clean component → grant.
    let ok = m("{:aiueos/component :app/ok :aiueos/kind :app :aiueos/imports #{:log/write}}");
    let g = CapabilityGraph::build(std::slice::from_ref(&ok));
    assert!(broker.verify_one(&ok, &g).is_ok());

    // A driver doing DMA with no IOMMU grant → deny.
    let bad = m("{:aiueos/component :driver/bad :aiueos/kind :driver
                  :aiueos/effects #{:dma} :aiueos/requires #{:iommu}}");
    let g2 = CapabilityGraph::build(std::slice::from_ref(&bad));
    assert!(broker.verify_one(&bad, &g2).is_err());

    let entries = broker.audit.read().unwrap();
    let events: Vec<String> = entries
        .iter()
        .filter_map(|e| aiueos::edn::get_kw(e, "aiueos", "event"))
        .collect();
    assert!(events.contains(&"grant".to_string()), "grant audited");
    assert!(events.contains(&"deny".to_string()), "deny audited");
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Policy::load — on-disk policy parsing
// ---------------------------------------------------------------------------

#[test]
fn policy_load_reads_grants_from_file() {
    let p = tmp("policyload").join("pol.edn");
    std::fs::write(&p, "{:aiueos/grants {:driver/x #{:iommu}}}").unwrap();
    let pol = Policy::load(&p).expect("policy loads");
    assert!(pol.grants.get("driver/x").unwrap().contains("iommu"));
}

#[test]
fn policy_load_malformed_is_edn_error() {
    let p = tmp("policybad").join("pol.edn");
    std::fs::write(&p, "{:aiueos/grants #{").unwrap();
    assert!(matches!(Policy::load(&p), Err(AiueosError::Edn(_))));
}

#[test]
fn policy_load_missing_file_is_io_error() {
    let p = tmp("policymissing").join("nope.edn");
    let _ = std::fs::remove_file(&p);
    assert!(matches!(Policy::load(&p), Err(AiueosError::Io(_))));
}

// ---------------------------------------------------------------------------
// audit: a corrupt log line is surfaced, not silently skipped
// ---------------------------------------------------------------------------

#[test]
fn audit_read_rejects_a_garbage_line() {
    let p = tmp("auditgarbage").join("audit.edn");
    std::fs::write(&p, "{:aiueos/event :grant}\nnot valid edn {{{\n").unwrap();
    assert!(
        AuditLog::new(&p).read().is_err(),
        "a corrupt audit line must surface as an error"
    );
}
