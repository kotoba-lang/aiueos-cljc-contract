//! Parse-layer hardening: `Kind`/`Trust` parse↔label round-trips (catches future
//! drift between the two), and `edn` helper behavior on shapes that aren't what
//! the caller expected (non-keyword, non-map, non-collection). Pure core.

use aiueos::edn;
use aiueos::manifest::{Kind, Trust};

#[test]
fn kind_parse_label_round_trips_every_variant() {
    for k in [
        Kind::App,
        Kind::Service,
        Kind::Driver,
        Kind::Broker,
        Kind::Agent,
        Kind::KernelExtension,
        Kind::Compat,
    ] {
        assert_eq!(Kind::parse(k.label()), Some(k), "round-trip {}", k.label());
    }
    assert_eq!(Kind::parse("wizard"), None);
}

#[test]
fn trust_parse_label_round_trips_every_variant() {
    for t in [
        Trust::Trusted,
        Trust::Verified,
        Trust::Untrusted,
        Trust::AiGenerated,
    ] {
        assert_eq!(Trust::parse(t.label()), Some(t), "round-trip {}", t.label());
    }
    assert_eq!(Trust::parse("godmode"), None);
}

#[test]
fn kw_string_is_some_only_for_keywords() {
    let kw = kotoba_edn::parse(":a/b").unwrap();
    assert_eq!(edn::kw_string(&kw).as_deref(), Some("a/b"));
    assert_eq!(edn::kw_string(&kotoba_edn::parse("\"x\"").unwrap()), None);
    assert_eq!(edn::kw_string(&kotoba_edn::parse("42").unwrap()), None);
}

#[test]
fn get_on_non_map_is_none() {
    let v = kotoba_edn::parse("[1 2 3]").unwrap();
    assert!(edn::get(&v, "aiueos", "x").is_none());
    assert!(edn::get_bare(&v, "x").is_none());
    assert!(edn::get_str(&v, "aiueos", "x").is_none());
}

#[test]
fn get_missing_key_is_none_but_present_key_reads() {
    let m = kotoba_edn::parse("{:aiueos/a 1 :n \"hi\"}").unwrap();
    assert!(edn::get(&m, "aiueos", "b").is_none());
    assert_eq!(
        edn::get(&m, "aiueos", "a").and_then(|v| v.as_integer()),
        Some(1)
    );
    assert_eq!(
        edn::get_bare(&m, "n").and_then(|v| v.as_string()),
        Some("hi")
    );
}

#[test]
fn kw_collection_on_non_collection_is_empty() {
    assert!(edn::kw_collection(Some(&kotoba_edn::parse("42").unwrap())).is_empty());
    assert!(edn::kw_collection(Some(&kotoba_edn::parse("{:a 1}").unwrap())).is_empty());
    assert!(edn::kw_collection(Some(&kotoba_edn::parse("\"s\"").unwrap())).is_empty());
    assert!(edn::kw_collection(None).is_empty());
}
