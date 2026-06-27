//! Deployment surfaces (ADR-0005). The same component+manifest+capability model
//! runs on edge, robotics, cloud, browser, client — but the *capabilities a
//! surface can back* differ. A surface is, at the policy level, the set of
//! capability names it offers a provider for; `Policy::granted_to` intersects the
//! kernel caps with this set, so an import resolves to a kernel cap **only if the
//! active surface offers it** — a missing provider is a loud `unresolved-capability`
//! denial, never a silent no-op. The actual host-function providers are bound in
//! a later increment; this is the verify-level contract.

use std::collections::BTreeSet;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// The capabilities a known surface can back, or `None` for an unknown surface id.
/// Keep ids in sync with the ADR-0005 table.
pub fn offered(id: &str) -> Option<BTreeSet<String>> {
    Some(match id {
        // The in-process robot — the only surface with real host providers today.
        "robot" => set(&[
            "topic/publish",
            "topic/subscribe",
            "clock/monotonic",
            "log/write",
            "random/bytes",
            "pci/config",
            "dma/map",
            "irq/subscribe",
            "mmio/map",
        ]),
        "browser" => set(&[
            "dom/render",
            "dom/event",
            "net/fetch",
            "log/write",
            "clock/monotonic",
        ]),
        "cloud" => set(&[
            "storage/kv",
            "net/fetch",
            "log/write",
            "clock/monotonic",
            "random/bytes",
        ]),
        _ => return None,
    })
}

/// Whether `id` names a surface aiueos knows (so its offered set is defined).
pub fn is_known(id: &str) -> bool {
    offered(id).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_surfaces_offer_caps_and_unknown_is_none() {
        assert!(offered("robot").unwrap().contains("topic/publish"));
        assert!(offered("browser").unwrap().contains("dom/render"));
        assert!(!offered("browser").unwrap().contains("topic/publish"));
        assert_eq!(offered("teapot"), None);
        assert!(is_known("cloud") && !is_known("teapot"));
    }
}
