//! The safe-kotoba subset checker.
//!
//! System components (services, drivers) must be written in a subset of
//! CLJ/Kotoba with no escape hatches: no `eval`, no runtime `require`, no
//! reflection, no ambient filesystem/network/process access. The kototama
//! compiler already rejects most of this by *not implementing it*, but the
//! checker is an explicit, earlier gate that returns a security-shaped error
//! (`AiueosError::Unsafe`) instead of an opaque "unknown symbol" compile failure.
//!
//! The check is a conservative denylist over every symbol in the source tree.

use crate::error::{AiueosError, Result};
use kotoba_edn::EdnValue;

/// Symbols (by bare name *or* namespace) that are never allowed in safe-kotoba.
const DENY: &[&str] = &[
    // dynamic code / metaprogramming
    "eval",
    "read-string",
    "read",
    "load",
    "load-file",
    "load-string",
    "defmacro",
    "macroexpand",
    "alter-var-root",
    "intern",
    "resolve",
    "ns-resolve",
    "find-var",
    "with-redefs",
    // module / host loading
    "require",
    "use",
    "import",
    // ambient filesystem / process / network (host escape)
    "slurp",
    "spit",
    "sh",
    // jvm/host reflection roots (namespace match catches `java.*`, `System/*`, …)
    "java",
    "javax",
    "clojure.java.io",
    "System",
    "Runtime",
    "ProcessBuilder",
    "Socket",
    "URL",
];

/// A token matches a denied root if it equals it (`eval`, `System`) or is a
/// dotted member of it (`java.util.ArrayList` under `java`, `clojure.java.io`
/// under `clojure.java`). Checked against both the symbol name and its
/// namespace so `System/exit` (ns=`System`) and a bare dotted class
/// `java.util.ArrayList` (name=`java.util.ArrayList`, no ns) are both caught.
fn token_hit(token: &str, denied: &str) -> bool {
    token == denied || token.starts_with(&format!("{denied}."))
}

fn flag(sym: &kotoba_edn::Symbol, reasons: &mut Vec<String>) {
    let name = &sym.name;
    let ns = sym.namespace.as_deref();
    let hit = DENY
        .iter()
        .any(|d| token_hit(name, d) || ns.map_or(false, |n| token_hit(n, d)));
    if hit {
        let q = sym.to_qualified();
        reasons.push(format!(
            "forbidden symbol `{q}` (not in the safe-kotoba subset)"
        ));
    }
}

fn walk(v: &EdnValue, reasons: &mut Vec<String>) {
    match v {
        EdnValue::Symbol(s) => flag(s, reasons),
        EdnValue::List(xs) | EdnValue::Vector(xs) => {
            for x in xs {
                walk(x, reasons);
            }
        }
        EdnValue::Map(m) => {
            for (k, val) in m {
                walk(k, reasons);
                walk(val, reasons);
            }
        }
        EdnValue::Set(s) => {
            for x in s {
                walk(x, reasons);
            }
        }
        EdnValue::Tagged { value, .. } => walk(value, reasons),
        _ => {}
    }
}

/// Returns `Ok(())` if `src` is within the safe-kotoba subset, else the list of
/// reasons it was rejected.
pub fn check(src: &str) -> Result<()> {
    let forms = kotoba_edn::parse_all(src)?;
    let mut reasons = Vec::new();
    for form in &forms {
        walk(form, &mut reasons);
    }
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(AiueosError::Unsafe(reasons))
    }
}
