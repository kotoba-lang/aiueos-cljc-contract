//! Small ergonomic layer over `kotoba_edn::EdnValue`.
//!
//! Manifests, policies and device schemas are all read as EDN (kotoba is the
//! single source of truth for "words that describe the system"). These helpers
//! turn the generic tree into the few shapes aiueos cares about: keyword keys,
//! keyword sets, strings and integers.

use kotoba_edn::EdnValue;

/// Render an EDN keyword as its canonical `ns/name` (or bare `name`) string,
/// dropping the leading `:`. This is the identity aiueos uses everywhere for
/// capabilities, effects and component ids.
pub fn kw_string(v: &EdnValue) -> Option<String> {
    v.as_keyword().map(|k| k.to_qualified())
}

/// Look up `:ns/name` in a map value. Returns `None` if `m` is not a map or the
/// key is absent.
pub fn get<'a>(m: &'a EdnValue, ns: &str, name: &str) -> Option<&'a EdnValue> {
    m.as_map()?.get(&EdnValue::kw(ns, name))
}

/// Look up a bare `:name` key in a map value.
pub fn get_bare<'a>(m: &'a EdnValue, name: &str) -> Option<&'a EdnValue> {
    m.as_map()?.get(&EdnValue::kw_bare(name))
}

/// Collect a set/vector/list of keywords into canonical strings, sorted &
/// de-duplicated. Accepts a missing value as the empty set.
pub fn kw_collection(v: Option<&EdnValue>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(v) = v else { return out };
    let items: Vec<&EdnValue> = match v {
        EdnValue::Set(s) => s.iter().collect(),
        EdnValue::Vector(xs) | EdnValue::List(xs) => xs.iter().collect(),
        _ => return out,
    };
    for it in items {
        if let Some(s) = kw_string(it) {
            out.push(s);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Like `kw_collection`, but accepts either strings (`"isekai.network"`) or
/// keywords (`:isekai.network`) — for open allow-lists such as `:aiueos/net-allow`.
pub fn str_collection(v: Option<&EdnValue>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(v) = v else { return out };
    let items: Vec<&EdnValue> = match v {
        EdnValue::Set(s) => s.iter().collect(),
        EdnValue::Vector(xs) | EdnValue::List(xs) => xs.iter().collect(),
        _ => return out,
    };
    for it in items {
        if let Some(s) = scalar_string(it) {
            out.push(s);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Read a string-valued map entry.
pub fn get_str(m: &EdnValue, ns: &str, name: &str) -> Option<String> {
    get(m, ns, name).and_then(|v| v.as_string().map(|s| s.to_string()))
}

/// Read a keyword-valued map entry as a canonical string.
pub fn get_kw(m: &EdnValue, ns: &str, name: &str) -> Option<String> {
    get(m, ns, name).and_then(kw_string)
}

/// Render a scalar value as a string whether it's written as a string (`"pci"`)
/// or a keyword (`:pci`). Used for open schemas (e.g. device fields) that accept
/// either form.
pub fn scalar_string(v: &EdnValue) -> Option<String> {
    match v {
        EdnValue::String(s) => Some(s.clone()),
        EdnValue::Keyword(_) => kw_string(v),
        _ => None,
    }
}
