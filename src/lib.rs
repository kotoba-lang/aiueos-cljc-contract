//! # aiueos — a Kotoba-defined, Kototama-executed, capability-secure Wasm OS
//!
//! aiueos models an operating system not as "a set of processes" but as a
//! **graph of meaning-annotated capability components**. Everything a component
//! *is* — its kind, trust, imports, exports, effects, limits — is written as
//! **kotoba** (EDN). The broker turns that description into either a running
//! component (compiled CLJ→wasm by **kototama**, executed under fuel + memory
//! limits) or a documented denial. Nothing runs without passing the capability
//! graph and policy reasoner, and every decision is audited.
//!
//! This crate is the **Phase-0 MVP** from the design: it runs on a host OS as
//! `aiueos run`, with mock services and a virtio-blk *logic* stub. The microkernel,
//! real device ABIs (MMIO/DMA/IRQ) and the microVM image are later phases; the
//! seams (`:effects`, `:requires #{:iommu}`, kernel-provided capabilities) are
//! already modeled so those phases slot in without reshaping the core.
//!
//! ## Layers
//! - [`manifest`] — `:aiueos/...` component descriptions.
//! - [`graph`] — system graph → capability graph (who provides what).
//! - [`policy`] — the reasoner: resolve imports, enforce effects & DMA policy.
//! - [`broker`] — the trusted seam: verify → safe-check → compile → run, audited.
//! - [`safe`] — the safe-kotoba subset gate.
//! - [`audit`] — append-only EDN audit log.
//! - [`topic`] — in-process pub/sub bus (the ROS-topic analogue).
//! - [`host`] — broker-mediated `aiueos:host` ABI: capabilities enforced at call
//!   time (feature `wasm-runtime`).
//! - [`runtime`] — kototama compile (`kototama`) + wasm execution (`wasm-runtime`).
//!
//! ## Example: describe a component, then let the broker decide
//!
//! ```
//! use aiueos::graph::CapabilityGraph;
//! use aiueos::policy;
//! use aiueos::{Manifest, Policy};
//!
//! // A component written as kotoba (EDN): a notes app that wants to log.
//! let app = Manifest::parse_str(
//!     "{:aiueos/component :app/notes :aiueos/kind :app :aiueos/imports #{:log/write}}",
//! )
//! .unwrap();
//!
//! // The capability graph + the default policy decide what it may touch.
//! let graph = CapabilityGraph::build(std::slice::from_ref(&app));
//! let grant = policy::verify_component(&app, &graph, &Policy::default()).unwrap();
//! assert!(grant.capabilities.contains("log/write")); // log/write is a kernel cap
//!
//! // An import nobody provides is denied before anything runs.
//! let lonely = Manifest::parse_str(
//!     "{:aiueos/component :app/lonely :aiueos/kind :app :aiueos/imports #{:gpu/render}}",
//! )
//! .unwrap();
//! let g2 = CapabilityGraph::build(std::slice::from_ref(&lonely));
//! assert!(policy::verify_component(&lonely, &g2, &Policy::default()).is_err());
//! ```

pub mod audit;
pub mod broker;
pub mod edn;
pub mod error;
pub mod graph;
pub mod manifest;
pub mod policy;
pub mod safe;
pub mod surface;
pub mod topic;
pub mod virtio;

#[cfg(feature = "computer-backing")]
pub mod backing;
#[cfg(feature = "wasm-runtime")]
pub mod host;
#[cfg(feature = "wasm-runtime")]
pub mod runtime;
#[cfg(feature = "signing")]
pub mod signing;

pub use error::{AiueosError, Result};
pub use manifest::{Kind, Limits, Manifest, Trust};
pub use policy::{Policy, Violation, ViolationKind};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{CapabilityGraph, System};

    fn m(src: &str) -> Manifest {
        Manifest::parse_str(src).expect("manifest parses")
    }

    #[test]
    fn parses_a_driver_manifest() {
        let d = m(r#"
            {:aiueos/component :driver/virtio-blk
             :aiueos/kind :driver
             :aiueos/imports #{:dma/map :irq/subscribe}
             :aiueos/exports #{:block/read :block/write}
             :aiueos/effects #{:device-io :dma :interrupt}
             :aiueos/requires #{:iommu}
             :aiueos/limits {:memory-pages 32 :fuel 5000000}
             :aiueos/entry "read-block"
             :aiueos/args [7]}"#);
        assert_eq!(d.id, "driver/virtio-blk");
        assert_eq!(d.kind, Kind::Driver);
        assert_eq!(d.trust, Trust::Untrusted);
        assert_eq!(d.limits.memory_pages, 32);
        assert_eq!(d.limits.fuel, 5_000_000);
        assert_eq!(d.entry, "read-block");
        assert_eq!(d.args, vec![7]);
        assert!(d.exports.contains(&"block/read".to_string()));
    }

    #[test]
    fn agent_defaults_to_ai_generated_trust() {
        let a = m(r#"{:aiueos/component :agent/summarize :aiueos/kind :agent}"#);
        assert_eq!(a.trust, Trust::AiGenerated);
    }

    #[test]
    fn dma_requires_iommu_grant() {
        // Driver does DMA, requires iommu, but no grant → denied.
        let d = m(r#"
            {:aiueos/component :driver/x :aiueos/kind :driver
             :aiueos/effects #{:dma} :aiueos/requires #{:iommu}}"#);
        let graph = CapabilityGraph::build(std::slice::from_ref(&d));
        let p = Policy::default();
        let r = policy::verify_component(&d, &graph, &p);
        assert!(r.is_err(), "no iommu grant should be denied");

        // Grant iommu → allowed.
        let v = kotoba_edn::parse(r#"{:aiueos/grants {:driver/x #{:iommu}}}"#).unwrap();
        let p2 = Policy::from_edn(&v).unwrap();
        let grant = policy::verify_component(&d, &graph, &p2).expect("granted");
        assert!(grant.capabilities.contains("iommu"));
    }

    #[test]
    fn ai_generated_cannot_use_network() {
        let a = m(r#"
            {:aiueos/component :agent/leaky :aiueos/kind :agent
             :aiueos/effects #{:network}}"#);
        let graph = CapabilityGraph::build(std::slice::from_ref(&a));
        let r = policy::verify_component(&a, &graph, &Policy::default());
        let vs = r.expect_err("network must be forbidden");
        assert!(vs.iter().any(|v| v.kind == ViolationKind::ForbiddenEffect));
    }

    #[test]
    fn untrusted_forbids_secrets_but_not_network() {
        // The :untrusted tier (default for a plain app) forbids :secrets — but,
        // unlike :ai-generated, NOT :network. Tests the tier distinction.
        let secret = m(r#"{:aiueos/component :app/s :aiueos/kind :app
                          :aiueos/effects #{:secrets}}"#);
        let g = CapabilityGraph::build(std::slice::from_ref(&secret));
        assert!(
            policy::verify_component(&secret, &g, &Policy::default()).is_err(),
            "untrusted :secrets is denied"
        );

        let net = m(r#"{:aiueos/component :app/n :aiueos/kind :app
                       :aiueos/effects #{:network}}"#);
        let g2 = CapabilityGraph::build(std::slice::from_ref(&net));
        assert!(
            policy::verify_component(&net, &g2, &Policy::default()).is_ok(),
            "untrusted :network is allowed (only :ai-generated forbids it)"
        );
    }

    #[test]
    fn imports_resolve_across_the_graph() {
        let fs = m(r#"
            {:aiueos/component :service/fs :aiueos/kind :service
             :aiueos/exports #{:fs/open :fs/read}}"#);
        let app = m(r#"
            {:aiueos/component :app/notes :aiueos/kind :app
             :aiueos/imports #{:fs/open :log/write}}"#);
        let sys = System::from_manifests("demo", vec![fs, app]);
        let graph = sys.graph();
        // app imports fs/open (from fs service) and log/write (kernel cap) → ok.
        let app_ref = &sys.components[1];
        assert!(policy::verify_component(app_ref, &graph, &Policy::default()).is_ok());
    }

    #[test]
    fn unresolved_import_is_denied() {
        let app = m(r#"
            {:aiueos/component :app/lonely :aiueos/kind :app
             :aiueos/imports #{:gpu/render}}"#);
        let graph = CapabilityGraph::build(std::slice::from_ref(&app));
        let vs = policy::verify_component(&app, &graph, &Policy::default())
            .expect_err("gpu/render has no provider");
        assert!(vs
            .iter()
            .any(|v| v.kind == ViolationKind::UnresolvedCapability));
    }

    #[test]
    fn boot_order_is_dependency_respecting() {
        // app depends on fs + log; fs depends on the driver. Providers boot first.
        let log = m(
            r#"{:aiueos/component :service/log :aiueos/kind :service :aiueos/exports #{:log/write}}"#,
        );
        let drv = m(
            r#"{:aiueos/component :driver/blk :aiueos/kind :driver :aiueos/exports #{:block/read}}"#,
        );
        let fs = m(r#"{:aiueos/component :service/fs :aiueos/kind :service
                       :aiueos/imports #{:block/read} :aiueos/exports #{:fs/open}}"#);
        let app = m(r#"{:aiueos/component :app/notes :aiueos/kind :app
                        :aiueos/imports #{:fs/open :log/write}}"#);
        // Intentionally unordered to prove the topo sort, not input order, decides.
        let sys = System::from_manifests("demo", vec![app, fs, log, drv]);
        let order = sys.boot_order().expect("acyclic");
        let pos = |id: &str| {
            order
                .iter()
                .position(|&i| sys.components[i].id == id)
                .unwrap()
        };
        assert!(pos("driver/blk") < pos("service/fs"));
        assert!(pos("service/fs") < pos("app/notes"));
        assert!(pos("service/log") < pos("app/notes"));
    }

    #[test]
    fn boot_order_detects_cycle() {
        let a = m(r#"{:aiueos/component :a :aiueos/kind :service
                      :aiueos/imports #{:b/x} :aiueos/exports #{:a/x}}"#);
        let b = m(r#"{:aiueos/component :b :aiueos/kind :service
                      :aiueos/imports #{:a/x} :aiueos/exports #{:b/x}}"#);
        let sys = System::from_manifests("cyclic", vec![a, b]);
        let cycle = sys.boot_order().expect_err("a↔b is a cycle");
        assert_eq!(cycle.len(), 2);
    }

    #[test]
    fn safe_subset_rejects_eval_and_slurp() {
        assert!(safe::check("(defn f [n] (+ n 1))").is_ok());
        assert!(matches!(
            safe::check("(defn f [x] (eval x))"),
            Err(AiueosError::Unsafe(_))
        ));
        assert!(matches!(
            safe::check(r#"(defn f [] (slurp "/etc/passwd"))"#),
            Err(AiueosError::Unsafe(_))
        ));
    }
}
