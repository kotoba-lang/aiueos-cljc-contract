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
            :aiueos/topics {:scan 1} :aiueos/signer "alice" :aiueos/signature "9c2e"
            :aiueos/quota {:host-calls 32 :publishes 4}
            :aiueos/schedule {:period-ms 20 :priority 5 :cycle-ms 10}
            :aiueos/surface #{:robot}}"#,
    )
    .expect("all recognized keys parse");
    assert_eq!(m.id, "driver/full");
    assert_eq!(m.topics.get("scan"), Some(&1));
    assert_eq!(m.signer.as_deref(), Some("alice"));
    assert_eq!(m.signature.as_deref(), Some("9c2e"));
    assert_eq!(m.quota.host_calls, 32);
    assert_eq!(m.quota.publishes, 4);
    assert_eq!(m.schedule.period_cycles, 2); // ceil(20 / 10)
    assert_eq!(m.schedule.priority, 5);
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
fn signed_message_binds_id_and_artifact_hash() {
    // The signed message is "<id>\n<wasm-sha256>" — present only with a hash.
    let signed = Manifest::parse_str(
        r#"{:aiueos/component :driver/s :aiueos/kind :driver :aiueos/wasm-sha256 "abc123"}"#,
    )
    .unwrap();
    assert_eq!(signed.signed_message().as_deref(), Some("driver/s\nabc123"));

    // No artifact hash → nothing to sign.
    let unhashed =
        Manifest::parse_str("{:aiueos/component :driver/s :aiueos/kind :driver}").unwrap();
    assert_eq!(unhashed.signed_message(), None);
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
fn quota_defaults_when_absent_and_parses_when_present() {
    // absent → generous defaults (existing components unaffected)
    let d = Manifest::parse_str("{:aiueos/component :a/x :aiueos/kind :app}").unwrap();
    assert_eq!(d.quota.host_calls, 1024);
    assert_eq!(d.quota.publishes, 256);
    // present → the declared per-cycle caps
    let m = Manifest::parse_str(
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/quota {:host-calls 8 :publishes 2}}",
    )
    .unwrap();
    assert_eq!(m.quota.host_calls, 8);
    assert_eq!(m.quota.publishes, 2);
}

#[test]
fn schedule_defaults_and_derives_cycles() {
    // absent → run every cycle, priority 100
    let d = Manifest::parse_str("{:aiueos/component :a/x :aiueos/kind :app}").unwrap();
    assert_eq!(d.schedule.period_cycles, 1);
    assert_eq!(d.schedule.deadline_cycles, 1);
    assert_eq!(d.schedule.priority, 100);
    // period-ms/cycle-ms derive to ceil; deadline defaults to the period
    let m = Manifest::parse_str(
        "{:aiueos/component :a/x :aiueos/kind :app
          :aiueos/schedule {:period-ms 25 :cycle-ms 10 :priority 1}}",
    )
    .unwrap();
    assert_eq!(m.schedule.period_cycles, 3, "ceil(25/10)");
    assert_eq!(m.schedule.deadline_cycles, 3, "deadline defaults to period");
    assert_eq!(m.schedule.priority, 1);
}

#[test]
fn manifest_rejects_malformed_schedule() {
    for bad in [
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/schedule 5}",
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/schedule {:periodms 10}}",
        r#"{:aiueos/component :a/x :aiueos/kind :app :aiueos/schedule {:priority "high"}}"#,
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/schedule {:cycle-ms 0}}",
    ] {
        assert!(
            matches!(Manifest::parse_str(bad), Err(AiueosError::Schema(_))),
            "should reject: {bad}"
        );
    }
}

#[test]
fn manifest_rejects_malformed_quota() {
    for bad in [
        // not a map
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/quota 5}",
        // unknown sub-key (typo)
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/quota {:host-cals 8}}",
        // non-integer value
        r#"{:aiueos/component :a/x :aiueos/kind :app :aiueos/quota {:host-calls "lots"}}"#,
        // zero host-calls (a component that can't make one call is nonsense)
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/quota {:host-calls 0}}",
    ] {
        assert!(
            matches!(Manifest::parse_str(bad), Err(AiueosError::Schema(_))),
            "should reject: {bad}"
        );
    }
}

#[test]
fn manifest_rejects_malformed_topics_map() {
    for bad in [
        // not a map
        "{:aiueos/component :a/x :aiueos/kind :app :aiueos/topics 5}",
        // non-integer value
        r#"{:aiueos/component :a/x :aiueos/kind :app :aiueos/topics {:scan "x"}}"#,
        // non-keyword key
        r#"{:aiueos/component :a/x :aiueos/kind :app :aiueos/topics {"scan" 1}}"#,
    ] {
        assert!(
            matches!(Manifest::parse_str(bad), Err(AiueosError::Schema(_))),
            "should reject: {bad}"
        );
    }
}

#[test]
fn coarse_topic_gates_are_not_derived_as_named_topics() {
    // :topic/cmd is a named data topic (→2); :topic/subscribe is the coarse gate
    // cap — even though a topics map names :subscribe, it must NOT be derived.
    let m = Manifest::parse_str(
        r#"{:aiueos/component :d/x :aiueos/kind :driver
            :aiueos/imports #{:topic/subscribe :topic/cmd}
            :aiueos/topics {:subscribe 99 :cmd 2}}"#,
    )
    .unwrap();
    let subs = m.subscribes.unwrap();
    assert!(subs.contains(&2));
    assert!(
        !subs.contains(&99),
        "the coarse topic/subscribe gate is not a data topic"
    );
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
fn surface_gate_denies_a_mismatched_component() {
    use aiueos::graph::CapabilityGraph;
    use aiueos::policy::{self, ViolationKind};
    let robot_policy =
        Policy::from_edn(&kotoba_edn::parse("{:aiueos/surface :robot}").unwrap()).unwrap();
    assert_eq!(robot_policy.surface.as_deref(), Some("robot"));

    // a browser-targeted component on the robot surface → surface-mismatch denial
    let browser = Manifest::parse_str(
        "{:aiueos/component :app/b :aiueos/kind :app :aiueos/surface #{:browser :client}}",
    )
    .unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&browser));
    let vs = policy::verify_component(&browser, &g, &robot_policy).expect_err("mismatch");
    assert!(vs.iter().any(|v| v.kind == ViolationKind::SurfaceMismatch));

    // a component that targets :robot is fine on the robot surface
    let robot_app = Manifest::parse_str(
        "{:aiueos/component :app/r :aiueos/kind :app :aiueos/surface #{:robot}}",
    )
    .unwrap();
    let g2 = CapabilityGraph::build(std::slice::from_ref(&robot_app));
    assert!(policy::verify_component(&robot_app, &g2, &robot_policy).is_ok());

    // a portable component (no :aiueos/surface) runs on any surface
    let portable = Manifest::parse_str("{:aiueos/component :app/p :aiueos/kind :app}").unwrap();
    let g3 = CapabilityGraph::build(std::slice::from_ref(&portable));
    assert!(policy::verify_component(&portable, &g3, &robot_policy).is_ok());
}

#[test]
fn policy_rejects_non_keyword_or_unknown_surface() {
    // non-keyword
    assert!(matches!(
        Policy::from_edn(&kotoba_edn::parse(r#"{:aiueos/surface "robot"}"#).unwrap()),
        Err(AiueosError::Schema(_))
    ));
    // unknown surface id (so its offered set would be undefined)
    assert!(matches!(
        Policy::from_edn(&kotoba_edn::parse("{:aiueos/surface :teapot}").unwrap()),
        Err(AiueosError::Schema(_))
    ));
}

#[test]
fn surface_restricts_kernel_caps_to_the_offered_set() {
    use aiueos::graph::CapabilityGraph;
    use aiueos::policy::{self, ViolationKind};
    // A component importing :topic/publish (a kernel cap). Under :robot it
    // resolves (robot offers topic/publish); under :browser it does NOT (browser
    // offers no topic bus) → unresolved-capability.
    let m = Manifest::parse_str(
        "{:aiueos/component :app/pub :aiueos/kind :app :aiueos/imports #{:topic/publish}}",
    )
    .unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&m));

    let robot = Policy::from_edn(&kotoba_edn::parse("{:aiueos/surface :robot}").unwrap()).unwrap();
    assert!(
        policy::verify_component(&m, &g, &robot).is_ok(),
        "robot offers topic/publish"
    );

    let browser =
        Policy::from_edn(&kotoba_edn::parse("{:aiueos/surface :browser}").unwrap()).unwrap();
    let vs = policy::verify_component(&m, &g, &browser).expect_err("browser offers no topic bus");
    assert!(vs
        .iter()
        .any(|v| v.kind == ViolationKind::UnresolvedCapability));
}

#[test]
fn policy_rejects_unknown_trust_and_non_maps() {
    for bad in [
        // unknown trust in forbid → the lockdown would silently not apply
        "{:aiueos/forbid {:ai-genrated #{:network}}}",
        // non-map forbid / grants
        "{:aiueos/forbid 5}",
        "{:aiueos/grants 5}",
    ] {
        assert!(
            matches!(
                Policy::from_edn(&kotoba_edn::parse(bad).unwrap()),
                Err(AiueosError::Schema(_))
            ),
            "should reject: {bad}"
        );
    }
}

#[test]
fn policy_rejects_unknown_keys() {
    // A typo'd policy key would silently grant nothing / allow everything.
    assert!(matches!(
        Policy::from_edn(&kotoba_edn::parse("{:aiueos/grnts {:driver/x #{:iommu}}}").unwrap()),
        Err(AiueosError::Schema(_))
    ));
    // Foreign-namespaced keys are still allowed (annotations).
    assert!(Policy::from_edn(&kotoba_edn::parse("{:aiueos/policy :p :note/x 1}").unwrap()).is_ok());
}

#[test]
fn policy_accepts_all_known_keys() {
    // Every recognized :aiueos/* policy key together — keep in sync with the
    // strict POLICY_KEYS set so a new key can't be added without an acceptance test.
    let p = Policy::from_edn(
        &kotoba_edn::parse(
            r#"{:aiueos/policy :full
                :aiueos/kernel-caps #{:extra/cap}
                :aiueos/grants {:driver/x #{:iommu}}
                :aiueos/forbid {:untrusted #{:secrets}}
                :aiueos/signers {:alice "abcd"}
                :aiueos/require-signed true
                :aiueos/surface :cloud}"#,
        )
        .unwrap(),
    )
    .expect("all recognized policy keys parse");
    assert!(p.kernel_caps.contains("extra/cap"));
    assert!(p.grants.get("driver/x").unwrap().contains("iommu"));
    assert_eq!(p.signers.get("alice").map(String::as_str), Some("abcd"));
    assert!(p.require_signed);
    assert_eq!(p.surface.as_deref(), Some("cloud"));
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
fn audit_records_every_event_kind() {
    // Each Event variant maps to its keyword — Compile/Reject are otherwise only
    // hit on the dormant compile path / runtime traps.
    let path = std::env::temp_dir().join("aiueos-audit-events.edn");
    let _ = std::fs::remove_file(&path);
    let log = AuditLog::new(&path);
    for ev in [
        Event::Grant,
        Event::Deny,
        Event::Compile,
        Event::Run,
        Event::Reject,
    ] {
        log.append(ev, "c", "d").unwrap();
    }
    let kinds: Vec<String> = log
        .read()
        .unwrap()
        .iter()
        .filter_map(|e| edn::get_kw(e, "aiueos", "event"))
        .collect();
    assert_eq!(kinds, ["grant", "deny", "compile", "run", "reject"]);
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
fn safe_rejects_each_escape_hatch() {
    // A representative span of the DENY list — guards against a token being
    // dropped from the security-critical safe-kotoba gate.
    for src in [
        "(defn f [x] (read-string x))",
        "(defn f [] (spit y 1))",
        "(require evil)",
        "(use evil)",
        "(defmacro m [] 1)",
        "(defn f [] (alter-var-root v))",
        "(defn f [] (intern n s))",
        "(defn f [] (with-redefs [a 1] a))",
        "(defn f [] (Runtime/getRuntime))",
        "(defn f [] (System/getenv))",
        "(defn f [] (java.net.Socket.))",
        "(defn f [] (load-string s))",
    ] {
        assert!(
            matches!(safe::check(src), Err(AiueosError::Unsafe(_))),
            "safe-kotoba must reject: {src}"
        );
    }
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
