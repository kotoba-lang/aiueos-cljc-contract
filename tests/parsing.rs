//! Negative-path & round-trip coverage for the semantic core (no wasm runtime):
//! manifest schema errors, policy `from_edn` merge semantics, the audit log
//! round-trip, and the safe-kotoba subset edge cases.

use aiueos::audit::{AuditLog, Event};
use aiueos::error::AiueosError;
use aiueos::manifest::{Kind, Manifest, Trust};
use aiueos::policy::Policy;
use aiueos::{edn, safe};

// ---------------------------------------------------------------------------
// manifest: schema validation
// ---------------------------------------------------------------------------

#[test]
fn manifest_non_map_is_schema_error() {
    assert!(matches!(
        Manifest::parse_str("[:not :a :map]"),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn manifest_missing_component_id_is_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiueos/kind :app}"),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn manifest_missing_kind_is_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiueos/component :app/x}"),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn manifest_unknown_kind_is_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiueos/component :x/y :aiueos/kind :wizard}"),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn manifest_unknown_trust_is_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiueos/component :x/y :aiueos/kind :app :aiueos/trust :godmode}"),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn manifest_bad_edn_is_parse_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiueos/component"),
        Err(AiueosError::Edn(_))
    ));
}

#[test]
fn manifest_defaults_kernel_extension_to_trusted() {
    let m = Manifest::parse_str("{:aiueos/component :k/x :aiueos/kind :kernel-extension}").unwrap();
    assert_eq!(m.trust, Trust::Trusted);
    assert_eq!(m.kind, Kind::KernelExtension);
}

#[test]
fn manifest_applies_default_limits_and_entry() {
    let m = Manifest::parse_str("{:aiueos/component :app/x :aiueos/kind :app}").unwrap();
    assert_eq!(m.limits.memory_pages, 16);
    assert_eq!(m.limits.fuel, 10_000_000);
    assert_eq!(m.entry, "main");
    assert!(m.args.is_empty());
    assert_eq!(m.trust, Trust::Untrusted);
}

#[test]
fn manifest_rejects_unknown_aiueos_key() {
    // `:aiueos/effcts` is a typo for `:aiueos/effects` — silently dropping it would
    // hide a `:dma` effect from the IOMMU gate. It must be a hard error.
    let r = Manifest::parse_str(
        "{:aiueos/component :driver/x :aiueos/kind :driver :aiueos/effcts #{:dma}}",
    );
    match r {
        Err(AiueosError::Schema(msg)) => {
            assert!(msg.contains("aiueos/effcts"), "names the bad key")
        }
        other => panic!("expected schema error, got {other:?}"),
    }
}

#[test]
fn manifest_accepts_all_known_keys() {
    // Every recognized :aiueos/* key — keep in sync with MANIFEST_KEYS so a new
    // key can't be added without an acceptance test.
    let m = Manifest::parse_str(
        r#"{:aiueos/component :driver/full :aiueos/kind :driver :aiueos/trust :untrusted
            :aiueos/source "x.clj" :aiueos/wasm "x.wasm" :aiueos/wasm-sha256 "abc"
            :aiueos/imports #{:dma/map} :aiueos/exports #{:block/read}
            :aiueos/effects #{:dma} :aiueos/requires #{:iommu}
            :aiueos/limits {:memory-pages 8 :fuel 99} :aiueos/entry "go" :aiueos/args [1 2]
            :aiueos/device {:bus :pci} :aiueos/publishes #{1} :aiueos/subscribes #{2}
            :aiueos/topics {:scan 1}}"#,
    )
    .expect("all recognized keys parse");
    assert_eq!(m.id, "driver/full");
    assert_eq!(m.topics.get("scan"), Some(&1));
    assert_eq!(m.args, vec![1, 2]);
    assert_eq!(m.wasm_sha256.as_deref(), Some("abc"));
    assert!(m.publishes.unwrap().contains(&1));
    assert!(m.subscribes.unwrap().contains(&2));
}

#[test]
fn manifest_ignores_non_aiueos_namespaced_keys() {
    // Keys outside the :aiueos/ namespace (e.g. user annotations) are not policed.
    let m = Manifest::parse_str(
        "{:aiueos/component :app/x :aiueos/kind :app :my/note \"hello\" :doc/owner :jun}",
    )
    .expect("foreign-namespaced keys are allowed");
    assert_eq!(m.id, "app/x");
}

#[test]
fn manifest_rejects_zero_and_negative_limits() {
    // 0 pages would trap at runtime; a negative value would silently wrap to a
    // huge u32 — both must be rejected at parse time.
    for bad in [
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/limits {:memory-pages 0}}",
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/limits {:memory-pages -1}}",
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/limits {:fuel 0}}",
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/limits {:fuel -5}}",
    ] {
        assert!(
            matches!(Manifest::parse_str(bad), Err(AiueosError::Schema(_))),
            "should reject: {bad}"
        );
    }
}

#[test]
fn manifest_rejects_absurd_and_non_integer_memory() {
    // Above the wasm32 4 GiB ceiling (65536 pages).
    assert!(matches!(
        Manifest::parse_str(
            "{:aiueos/component :a/x :aiueos/kind :app :aiueos/limits {:memory-pages 70000}}"
        ),
        Err(AiueosError::Schema(_))
    ));
    // Non-integer limit value.
    assert!(matches!(
        Manifest::parse_str(
            "{:aiueos/component :a/x :aiueos/kind :app :aiueos/limits {:memory-pages \"lots\"}}"
        ),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn manifest_rejects_malformed_args() {
    // Non-integer element, or a non-vector value, must not be silently coerced.
    assert!(matches!(
        Manifest::parse_str(
            r#"{:aiueos/component :a/x :aiueos/kind :app :aiueos/args [1 "two" 3]}"#
        ),
        Err(AiueosError::Schema(_))
    ));
    assert!(matches!(
        Manifest::parse_str("{:aiueos/component :a/x :aiueos/kind :app :aiueos/args 5}"),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn manifest_parses_device_binding() {
    let m = Manifest::parse_str(
        r#"{:aiueos/component :driver/blk :aiueos/kind :driver
            :aiueos/device {:bus :pci :vendor "0x1af4" :device "0x1001"
                            :queues [{:name :request}]}}"#,
    )
    .unwrap();
    let d = m.device.expect("device captured");
    assert_eq!(d.bus.as_deref(), Some("pci"));
    assert_eq!(d.vendor.as_deref(), Some("0x1af4"));
    assert_eq!(d.device.as_deref(), Some("0x1001"));
}

#[test]
fn manifest_rejects_empty_entry() {
    assert!(matches!(
        Manifest::parse_str(r#"{:aiueos/component :a/x :aiueos/kind :app :aiueos/entry ""}"#),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn manifest_parses_topic_id_sets() {
    let m = Manifest::parse_str(
        "{:aiueos/component :d/x :aiueos/kind :driver :aiueos/publishes #{1 2} :aiueos/subscribes #{3}}",
    )
    .unwrap();
    let pubs = m.publishes.expect("publishes set");
    assert!(pubs.contains(&1) && pubs.contains(&2));
    assert_eq!(m.subscribes.expect("subscribes").len(), 1);
    // absent → unrestricted (None)
    let n = Manifest::parse_str("{:aiueos/component :d/y :aiueos/kind :driver}").unwrap();
    assert!(n.publishes.is_none() && n.subscribes.is_none());
}

#[test]
fn publishes_subscribes_derived_from_named_topics() {
    // exports :topic/scan + topics {:scan 1} → publishes {1} (derived);
    // imports :topic/cmd + topics {:cmd 2} → subscribes {2} (derived).
    let m = Manifest::parse_str(
        r#"{:aiueos/component :agent/p :aiueos/kind :agent
            :aiueos/imports #{:topic/subscribe :topic/cmd}
            :aiueos/exports #{:topic/scan}
            :aiueos/topics {:scan 1 :cmd 2}}"#,
    )
    .unwrap();
    assert_eq!(m.publishes.unwrap(), [1].into_iter().collect());
    assert_eq!(m.subscribes.unwrap(), [2].into_iter().collect());
}

#[test]
fn explicit_publishes_override_derivation() {
    let m = Manifest::parse_str(
        r#"{:aiueos/component :d/x :aiueos/kind :driver
            :aiueos/exports #{:topic/scan} :aiueos/topics {:scan 1}
            :aiueos/publishes #{9}}"#,
    )
    .unwrap();
    assert_eq!(
        m.publishes.unwrap(),
        [9].into_iter().collect(),
        "explicit publishes win over derivation"
    );
}

#[test]
fn manifest_rejects_non_integer_topic_ids() {
    assert!(matches!(
        Manifest::parse_str(
            r#"{:aiueos/component :d/x :aiueos/kind :driver :aiueos/publishes #{:scan}}"#
        ),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn manifest_parses_wasm_sha256() {
    let m = Manifest::parse_str(
        r#"{:aiueos/component :app/x :aiueos/kind :app
            :aiueos/wasm "x.wasm" :aiueos/wasm-sha256 "abc123"}"#,
    )
    .unwrap();
    assert_eq!(m.wasm_sha256.as_deref(), Some("abc123"));
}

#[test]
fn manifest_without_device_has_none() {
    let m = Manifest::parse_str("{:aiueos/component :app/x :aiueos/kind :app}").unwrap();
    assert!(m.device.is_none());
}

#[test]
fn manifest_accepts_integer_args_and_empty() {
    let m = Manifest::parse_str("{:aiueos/component :a/x :aiueos/kind :app :aiueos/args [1 2 -3]}")
        .unwrap();
    assert_eq!(m.args, vec![1, 2, -3]);
    let e =
        Manifest::parse_str("{:aiueos/component :a/y :aiueos/kind :app :aiueos/args []}").unwrap();
    assert!(e.args.is_empty());
}

#[test]
fn manifest_accepts_limits_at_the_boundaries() {
    let m = Manifest::parse_str(
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/limits {:memory-pages 1 :fuel 1}}",
    )
    .expect("min limits are valid");
    assert_eq!(m.limits.memory_pages, 1);
    assert_eq!(m.limits.fuel, 1);
}

#[test]
fn manifest_partial_limits_keep_defaults_for_missing_keys() {
    // Only memory-pages given → fuel falls back to the default.
    let m = Manifest::parse_str(
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/limits {:memory-pages 4}}",
    )
    .unwrap();
    assert_eq!(m.limits.memory_pages, 4);
    assert_eq!(m.limits.fuel, 10_000_000);
}

// ---------------------------------------------------------------------------
// policy: from_edn extends the defaults
// ---------------------------------------------------------------------------

fn policy(src: &str) -> Policy {
    Policy::from_edn(&kotoba_edn::parse(src).unwrap()).unwrap()
}

#[test]
fn policy_kernel_caps_extend_defaults() {
    let p = policy("{:aiueos/kernel-caps #{:gpu/render}}");
    assert!(p.kernel_caps.contains("gpu/render"), "added cap present");
    assert!(p.kernel_caps.contains("log/write"), "default cap retained");
}

#[test]
fn policy_grants_are_merged_per_component() {
    let p = policy("{:aiueos/grants {:driver/x #{:iommu :dma/map}}}");
    let g = p.grants.get("driver/x").expect("grant present");
    assert!(g.contains("iommu") && g.contains("dma/map"));
}

#[test]
fn policy_forbid_overrides_a_trust_level() {
    let p = policy("{:aiueos/forbid {:untrusted #{:network :secrets}}}");
    let f = p.forbid_effects.get(&Trust::Untrusted).unwrap();
    assert!(f.contains("network") && f.contains("secrets"));
}

#[test]
fn policy_default_locks_down_ai_generated() {
    let p = Policy::default();
    let f = p.forbid_effects.get(&Trust::AiGenerated).unwrap();
    for eff in ["network", "secrets", "persistent-write"] {
        assert!(f.contains(eff), "ai-generated must forbid {eff}");
    }
}

// ---------------------------------------------------------------------------
// audit: append → read round-trip
// ---------------------------------------------------------------------------

#[test]
fn audit_round_trips_entries() {
    let path = std::env::temp_dir().join("aiueos-audit-roundtrip.edn");
    let _ = std::fs::remove_file(&path);
    let log = AuditLog::new(&path);
    log.append(Event::Grant, "app/x", "caps: log/write")
        .unwrap();
    log.append(Event::Deny, "driver/y", "[dma-without-iommu] no grant")
        .unwrap();

    let entries = log.read().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        edn::get_kw(&entries[0], "aiueos", "event").as_deref(),
        Some("grant")
    );
    assert_eq!(
        edn::get_str(&entries[1], "aiueos", "component").as_deref(),
        Some("driver/y")
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn audit_read_missing_file_is_empty() {
    let path = std::env::temp_dir().join("aiueos-audit-does-not-exist-xyz.edn");
    let _ = std::fs::remove_file(&path);
    assert!(AuditLog::new(&path).read().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// safe-kotoba subset edge cases
// ---------------------------------------------------------------------------

#[test]
fn safe_accepts_a_multi_form_pure_program() {
    let src = "(def x 10)\n(defn f [n] (+ n x))\n(defn g [n] (if (< n 0) 0 (f n)))";
    assert!(safe::check(src).is_ok());
}

#[test]
fn safe_rejects_dotted_host_class() {
    // Bare dotted class symbol (no `/`) — previously slipped through.
    assert!(matches!(
        safe::check("(defn f [] (java.util.ArrayList.))"),
        Err(AiueosError::Unsafe(_))
    ));
}

#[test]
fn safe_rejects_namespaced_host_static() {
    // `System/exit` — namespace `System`.
    assert!(matches!(
        safe::check("(defn f [] (System/exit 1))"),
        Err(AiueosError::Unsafe(_))
    ));
}

#[test]
fn safe_does_not_flag_innocent_lookalikes() {
    // `javascript` and `systemd-thing` are not under any denied root.
    assert!(safe::check("(defn f [javascript systemic] (+ javascript systemic))").is_ok());
}

// ---------------------------------------------------------------------------
// edn helpers
// ---------------------------------------------------------------------------

#[test]
fn edn_kw_collection_sorts_and_dedups_from_vector_or_set() {
    let v = kotoba_edn::parse("[:b/x :a/y :b/x]").unwrap();
    assert_eq!(edn::kw_collection(Some(&v)), vec!["a/y", "b/x"]);
    let s = kotoba_edn::parse("#{:a/y :b/x}").unwrap();
    assert_eq!(edn::kw_collection(Some(&s)), vec!["a/y", "b/x"]);
    assert!(edn::kw_collection(None).is_empty());
}
