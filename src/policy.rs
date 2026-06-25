//! The policy reasoner. Given a capability graph (who exports what) and a policy
//! (kernel-provided primitives, per-component grants, per-trust forbiddances),
//! it decides whether each component is allowed to run and *which capabilities
//! it is actually granted*. The output is either a set of [`Grant`]s or a list
//! of [`Violation`]s — never a silent pass.

use crate::edn;
use crate::graph::CapabilityGraph;
use crate::manifest::{Manifest, Trust};
use kotoba_edn::EdnValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// An import is provided by nobody (no exporter, not a kernel cap, not granted).
    UnresolvedCapability,
    /// The component declares an effect forbidden for its trust level.
    ForbiddenEffect,
    /// A component performing DMA without an IOMMU requirement/grant.
    DmaWithoutIommu,
}

impl ViolationKind {
    pub fn label(self) -> &'static str {
        match self {
            ViolationKind::UnresolvedCapability => "unresolved-capability",
            ViolationKind::ForbiddenEffect => "forbidden-effect",
            ViolationKind::DmaWithoutIommu => "dma-without-iommu",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub component: String,
    pub kind: ViolationKind,
    pub message: String,
}

/// The capabilities actually conferred on a component once policy has run.
#[derive(Debug, Clone)]
pub struct Grant {
    pub component: String,
    pub capabilities: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    /// Primitive capabilities the kernel/broker hands out directly (no exporter
    /// component needed). These are the hardware/runtime seams.
    pub kernel_caps: BTreeSet<String>,
    /// Extra capabilities explicitly granted to a specific component id.
    pub grants: BTreeMap<String, BTreeSet<String>>,
    /// Effects forbidden for a given trust level.
    pub forbid_effects: BTreeMap<Trust, BTreeSet<String>>,
}

impl Default for Policy {
    /// The default policy: a conservative set of kernel primitives, and the
    /// AI-generated/untrusted lockdown (no network, no secrets, no persistence).
    fn default() -> Self {
        let kernel_caps = [
            "log/write",
            "clock/monotonic",
            "random/bytes",
            // pub/sub topic bus (the aiueos:host ABI gates publish/poll on these)
            "topic/publish",
            "topic/subscribe",
            // device-broker primitives (only meaningful with a matching grant)
            "pci/config",
            "dma/map",
            "irq/subscribe",
            "mmio/map",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let mut forbid_effects = BTreeMap::new();
        forbid_effects.insert(
            Trust::AiGenerated,
            ["network", "secrets", "persistent-write"]
                .into_iter()
                .map(String::from)
                .collect(),
        );
        forbid_effects.insert(
            Trust::Untrusted,
            ["secrets"].into_iter().map(String::from).collect(),
        );

        Policy {
            kernel_caps,
            grants: BTreeMap::new(),
            forbid_effects,
        }
    }
}

impl Policy {
    /// Parse a policy document. Everything is optional and *extends* the default
    /// policy (kernel-caps are unioned, grants merged, forbiddances overridden
    /// per-trust).
    pub fn from_edn(v: &EdnValue) -> crate::error::Result<Policy> {
        let mut p = Policy::default();
        for c in edn::kw_collection(edn::get(v, "aiueos", "kernel-caps")) {
            p.kernel_caps.insert(c);
        }
        if let Some(EdnValue::Map(g)) = edn::get(v, "aiueos", "grants") {
            for (k, caps) in g {
                if let Some(id) = edn::kw_string(k) {
                    let set: BTreeSet<String> =
                        edn::kw_collection(Some(caps)).into_iter().collect();
                    p.grants.entry(id).or_default().extend(set);
                }
            }
        }
        if let Some(EdnValue::Map(fb)) = edn::get(v, "aiueos", "forbid") {
            for (k, effs) in fb {
                if let Some(trust) = edn::kw_string(k).and_then(|s| Trust::parse(&s)) {
                    let set: BTreeSet<String> =
                        edn::kw_collection(Some(effs)).into_iter().collect();
                    p.forbid_effects.insert(trust, set);
                }
            }
        }
        Ok(p)
    }

    pub fn load(path: &Path) -> crate::error::Result<Policy> {
        let src = std::fs::read_to_string(path)?;
        let v = kotoba_edn::parse(&src)?;
        Policy::from_edn(&v)
    }

    /// Capabilities available to `m`: kernel primitives ∪ explicit grants.
    fn granted_to(&self, m: &Manifest) -> BTreeSet<String> {
        let mut s = self.kernel_caps.clone();
        if let Some(extra) = self.grants.get(&m.id) {
            s.extend(extra.iter().cloned());
        }
        s
    }
}

/// Verify one component against the graph + policy. On success, returns the
/// concrete capability grant the broker should confer.
pub fn verify_component(
    m: &Manifest,
    graph: &CapabilityGraph,
    policy: &Policy,
) -> std::result::Result<Grant, Vec<Violation>> {
    let mut violations = Vec::new();
    let granted = policy.granted_to(m);

    // 1. Every import must resolve: exported by some component, a kernel cap, or
    //    an explicit grant.
    let mut resolved = BTreeSet::new();
    for imp in &m.imports {
        let by_graph = graph.providers(imp).iter().any(|p| p != &m.id);
        if by_graph || granted.contains(imp) {
            resolved.insert(imp.clone());
        } else {
            violations.push(Violation {
                component: m.id.clone(),
                kind: ViolationKind::UnresolvedCapability,
                message: format!("import {imp} has no provider, kernel cap, or grant"),
            });
        }
    }

    // 2. Effects must be allowed for the trust level.
    if let Some(forbidden) = policy.forbid_effects.get(&m.trust) {
        for eff in &m.effects {
            if forbidden.contains(eff) {
                violations.push(Violation {
                    component: m.id.clone(),
                    kind: ViolationKind::ForbiddenEffect,
                    message: format!(
                        "effect {eff} is forbidden for {} components",
                        m.trust.label()
                    ),
                });
            }
        }
    }

    // 3. Driver DMA policy: anything doing DMA must require + be granted an IOMMU.
    if m.effects.iter().any(|e| e == "dma") {
        let requires_iommu = m.requires.iter().any(|r| r == "iommu");
        let has_iommu = granted.contains("iommu") || resolved.contains("iommu");
        if !requires_iommu || !has_iommu {
            violations.push(Violation {
                component: m.id.clone(),
                kind: ViolationKind::DmaWithoutIommu,
                message: "DMA requires `:requires #{:iommu}` and an :iommu grant".into(),
            });
        }
    }

    if violations.is_empty() {
        // The conferred capability set = resolved imports ∪ any iommu requirement.
        let mut caps = resolved;
        if m.requires.iter().any(|r| r == "iommu") && granted.contains("iommu") {
            caps.insert("iommu".into());
        }
        Ok(Grant {
            component: m.id.clone(),
            capabilities: caps,
        })
    } else {
        Err(violations)
    }
}
