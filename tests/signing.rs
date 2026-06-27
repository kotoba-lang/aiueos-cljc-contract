//! ed25519 manifest authenticity (ADR-0003): a valid signature verifies and
//! resolves the signer; a tampered signature, an unregistered signer, a
//! missing-context signature, and an unsigned manifest each get the right
//! verdict. Generates a keypair in-test so it's self-contained.
#![cfg(feature = "signing")]

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::graph::{CapabilityGraph, System};
use aiueos::manifest::Manifest;
use aiueos::policy::Policy;
use aiueos::signing::{verify, SigStatus};
use ed25519_dalek::{Signer, SigningKey};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A deterministic keypair from a fixed seed (test-only).
fn keypair() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn policy_with_signer(name: &str, key_hex: &str) -> Policy {
    let src = format!("{{:aiueos/signers {{:{name} \"{key_hex}\"}}}}");
    Policy::from_edn(&kotoba_edn::parse(&src).unwrap()).unwrap()
}

fn signed_manifest(sig_hex: &str) -> Manifest {
    Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/sensor :aiueos/kind :driver
            :aiueos/wasm-sha256 "abc123"
            :aiueos/signer "alice" :aiueos/signature "{sig_hex}"}}"#,
    ))
    .unwrap()
}

#[test]
fn a_valid_signature_verifies_and_names_the_signer() {
    let key = keypair();
    // sign the canonical message for (id=driver/sensor, hash=abc123)
    let sig = key.sign(b"driver/sensor\nabc123");
    let m = signed_manifest(&hex(&sig.to_bytes()));
    let policy = policy_with_signer("alice", &hex(key.verifying_key().as_bytes()));
    assert_eq!(
        verify(&m, &policy).unwrap(),
        SigStatus::Verified("alice".into())
    );
}

#[test]
fn a_tampered_signature_is_denied() {
    let key = keypair();
    // sign a DIFFERENT message → the signature won't verify the manifest's binding
    let sig = key.sign(b"driver/sensor\nDIFFERENT");
    let m = signed_manifest(&hex(&sig.to_bytes()));
    let policy = policy_with_signer("alice", &hex(key.verifying_key().as_bytes()));
    assert!(
        verify(&m, &policy).is_err(),
        "wrong-message signature must be denied"
    );
}

#[test]
fn an_unregistered_signer_is_denied() {
    let key = keypair();
    let sig = key.sign(b"driver/sensor\nabc123");
    let m = signed_manifest(&hex(&sig.to_bytes()));
    // policy registers a different signer name → "alice" is unknown
    let policy = policy_with_signer("bob", &hex(key.verifying_key().as_bytes()));
    assert!(
        verify(&m, &policy).is_err(),
        "unregistered signer must be denied"
    );
}

#[test]
fn an_unsigned_manifest_is_unsigned() {
    let m = Manifest::parse_str(
        r#"{:aiueos/component :driver/s :aiueos/kind :driver :aiueos/wasm-sha256 "abc123"}"#,
    )
    .unwrap();
    assert_eq!(verify(&m, &Policy::default()).unwrap(), SigStatus::Unsigned);
}

#[test]
fn a_signature_without_artifact_hash_is_denied() {
    // signed but nothing to bind (no :aiueos/wasm-sha256)
    let m = Manifest::parse_str(
        r#"{:aiueos/component :driver/s :aiueos/kind :driver
            :aiueos/signer "alice" :aiueos/signature "deadbeef"}"#,
    )
    .unwrap();
    let policy = policy_with_signer("alice", &hex(keypair().verifying_key().as_bytes()));
    assert!(verify(&m, &policy).is_err(), "no hash to bind → denied");
}

// --- broker integration (ADR-0003 increment 3) ---------------------------------

#[test]
fn valid_signature_elevates_trust_unlocking_a_forbidden_effect() {
    // A :driver defaults to :untrusted, which forbids the :secrets effect. A valid
    // signature elevates it to :verified (no such forbiddance) — so signing is what
    // makes the difference between denied and allowed.
    let key = keypair();
    let sig = key.sign(b"driver/x\nabc");
    let signed = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/x :aiueos/kind :driver :aiueos/wasm-sha256 "abc"
            :aiueos/effects #{{:secrets}} :aiueos/signer "alice" :aiueos/signature "{}"}}"#,
        hex(&sig.to_bytes())
    ))
    .unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&signed));
    let policy = policy_with_signer("alice", &hex(key.verifying_key().as_bytes()));
    let broker = Broker::new(
        policy,
        AuditLog::new(std::env::temp_dir().join("aiueos-sign-elev.edn")),
    );
    assert!(
        broker.verify_one(&signed, &g).is_ok(),
        "signed → :verified → :secrets allowed"
    );

    // Same component, unsigned → stays :untrusted → :secrets is forbidden → denied.
    let unsigned = Manifest::parse_str(
        "{:aiueos/component :driver/x :aiueos/kind :driver :aiueos/effects #{:secrets}}",
    )
    .unwrap();
    let g2 = CapabilityGraph::build(std::slice::from_ref(&unsigned));
    let plain = Broker::new(
        Policy::default(),
        AuditLog::new(std::env::temp_dir().join("aiueos-sign-elev2.edn")),
    );
    assert!(
        plain.verify_one(&unsigned, &g2).is_err(),
        "unsigned :untrusted :secrets denied"
    );
}

#[test]
fn broker_denies_a_bad_signature_and_audits_provenance() {
    let logpath = std::env::temp_dir().join("aiueos-sign-prov.edn");
    let _ = std::fs::remove_file(&logpath);
    let key = keypair();

    // valid signature → grant audited with the signer (provenance)
    let sig = key.sign(b"driver/x\nabc");
    let good = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/x :aiueos/kind :driver :aiueos/wasm-sha256 "abc"
            :aiueos/signer "alice" :aiueos/signature "{}"}}"#,
        hex(&sig.to_bytes())
    ))
    .unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&good));
    let policy = policy_with_signer("alice", &hex(key.verifying_key().as_bytes()));
    let broker = Broker::new(policy, AuditLog::new(&logpath));
    broker.verify_one(&good, &g).expect("verified");
    let entries = AuditLog::new(&logpath).read().unwrap();
    assert!(
        entries
            .iter()
            .any(|e| aiueos::edn::get_str(e, "aiueos", "detail")
                .is_some_and(|d| d.contains("signer: alice"))),
        "grant records the signer"
    );

    // forged signature → Denied at the broker
    let bad = Manifest::parse_str(
        r#"{:aiueos/component :driver/x :aiueos/kind :driver :aiueos/wasm-sha256 "abc"
            :aiueos/signer "alice" :aiueos/signature "00"}"#,
    )
    .unwrap();
    assert!(
        broker.verify_one(&bad, &g).is_err(),
        "forged signature denied"
    );
    let _ = std::fs::remove_file(&logpath);
}

#[test]
fn require_signed_policy_denies_unsigned_but_allows_signed() {
    let key = keypair();
    let signers = format!(
        "{{:aiueos/require-signed true :aiueos/signers {{:alice \"{}\"}}}}",
        hex(key.verifying_key().as_bytes())
    );
    let policy = Policy::from_edn(&kotoba_edn::parse(&signers).unwrap()).unwrap();
    assert!(policy.require_signed);

    // unsigned → denied under require-signed
    let unsigned = Manifest::parse_str("{:aiueos/component :app/u :aiueos/kind :app}").unwrap();
    let gu = CapabilityGraph::build(std::slice::from_ref(&unsigned));
    let broker = Broker::new(
        policy,
        AuditLog::new(std::env::temp_dir().join("aiueos-reqsigned.edn")),
    );
    assert!(
        broker.verify_one(&unsigned, &gu).is_err(),
        "require-signed denies an unsigned component"
    );

    // a validly signed component still passes
    let sig = key.sign(b"app/s\nabc");
    let signed = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :app/s :aiueos/kind :app :aiueos/wasm-sha256 "abc"
            :aiueos/signer "alice" :aiueos/signature "{}"}}"#,
        hex(&sig.to_bytes())
    ))
    .unwrap();
    let gs = CapabilityGraph::build(std::slice::from_ref(&signed));
    assert!(
        broker.verify_one(&signed, &gs).is_ok(),
        "a signed component passes require-signed"
    );
}

#[test]
fn require_signed_must_be_a_boolean() {
    assert!(Policy::from_edn(&kotoba_edn::parse("{:aiueos/require-signed 1}").unwrap()).is_err());
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn a_signature_cannot_rescue_swapped_artifact_bytes() {
    // Signing attests the (id, wasm-sha256) binding; integrity checks the actual
    // bytes against that hash at launch. Together: a signer vouches for *specific*
    // bytes, and swapping them is rejected even with a valid signature.
    use aiueos::runtime::sha256_hex;
    let dir = std::env::temp_dir().join("aiueos-sign-integrity");
    std::fs::create_dir_all(&dir).unwrap();
    let wat = br#"(module (func (export "main") (result i64) (i64.const 7)))"#;
    std::fs::write(dir.join("c.wat"), wat).unwrap();
    let hash = sha256_hex(wat);

    let key = keypair();
    let sig = key.sign(format!("app/c\n{hash}").as_bytes());
    std::fs::write(
        dir.join("c.edn"),
        format!(
            r#"{{:aiueos/component :app/c :aiueos/kind :app :aiueos/wasm "c.wat"
                :aiueos/entry "main" :aiueos/wasm-sha256 "{hash}"
                :aiueos/signer "alice" :aiueos/signature "{}"}}"#,
            hex(&sig.to_bytes())
        ),
    )
    .unwrap();

    let m = Manifest::load(&dir.join("c.edn")).unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&m));
    let policy = policy_with_signer("alice", &hex(key.verifying_key().as_bytes()));
    let broker = Broker::new(policy, AuditLog::new(dir.join("audit.edn")));

    // signed + bytes match the declared hash → launches
    assert_eq!(broker.launch(&m, &dir, &g).unwrap(), 7);

    // swap the artifact for different bytes — the signature is still "valid" for
    // the declared hash, but integrity now fails.
    std::fs::write(
        dir.join("c.wat"),
        br#"(module (func (export "main") (result i64) (i64.const 9)))"#,
    )
    .unwrap();
    assert!(
        broker.launch(&m, &dir, &g).is_err(),
        "swapped bytes rejected despite a valid signature"
    );
}

#[test]
fn malformed_crypto_input_errors_without_panicking() {
    let key = keypair();
    let good_policy = policy_with_signer("alice", &hex(key.verifying_key().as_bytes()));
    // odd-length, non-hex, and valid-hex-but-wrong-length signatures
    for bad_sig in ["abc", "zz", "00"] {
        assert!(
            verify(&signed_manifest(bad_sig), &good_policy).is_err(),
            "malformed signature `{bad_sig}` must error"
        );
    }
    // a registered signer whose key is malformed (not 32 bytes) — still an error,
    // not a panic, even with an otherwise-valid signature.
    let sig = hex(&key.sign(b"driver/sensor\nabc123").to_bytes());
    for bad_key in ["abcd", "zz", &"11".repeat(31)] {
        let policy = policy_with_signer("alice", bad_key);
        assert!(
            verify(&signed_manifest(&sig), &policy).is_err(),
            "malformed signer key `{bad_key}` must error"
        );
    }
}

#[test]
fn require_signed_system_denies_when_any_component_is_unsigned() {
    // A require-signed deployment verifying a whole system: an all-signed system
    // passes; adding one unsigned component makes verify_system deny.
    let key = keypair();
    let sig = key.sign(b"app/signed\nabc");
    let signed = Manifest::parse_str(&format!(
        r#"{{:aiueos/component :app/signed :aiueos/kind :app :aiueos/wasm-sha256 "abc"
            :aiueos/signer "alice" :aiueos/signature "{}"}}"#,
        hex(&sig.to_bytes())
    ))
    .unwrap();
    let policy_src = format!(
        "{{:aiueos/require-signed true :aiueos/signers {{:alice \"{}\"}}}}",
        hex(key.verifying_key().as_bytes())
    );
    let policy = Policy::from_edn(&kotoba_edn::parse(&policy_src).unwrap()).unwrap();

    // all components signed → the system verifies
    let ok_sys = System::from_manifests("signed-sys", vec![signed.clone()]);
    let broker = Broker::new(
        policy,
        AuditLog::new(std::env::temp_dir().join("aiueos-reqsys.edn")),
    );
    assert!(
        broker.verify_system(&ok_sys).is_ok(),
        "all-signed system passes"
    );

    // add an unsigned component → the whole system is denied under require-signed
    let unsigned = Manifest::parse_str("{:aiueos/component :app/plain :aiueos/kind :app}").unwrap();
    let mixed = System::from_manifests("mixed-sys", vec![signed, unsigned]);
    assert!(
        broker.verify_system(&mixed).is_err(),
        "an unsigned component fails the require-signed system"
    );
}
