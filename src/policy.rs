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
    /// A signed manifest whose signature is missing context, unregistered, or
    /// fails to verify (ADR-0003).
    BadSignature,
    /// A component pinned to surfaces that don't include the active one (ADR-0005).
    SurfaceMismatch,
}

impl ViolationKind {
    pub fn label(self) -> &'static str {
        match self {
            ViolationKind::UnresolvedCapability => "unresolved-capability",
            ViolationKind::ForbiddenEffect => "forbidden-effect",
            ViolationKind::DmaWithoutIommu => "dma-without-iommu",
            ViolationKind::BadSignature => "bad-signature",
            ViolationKind::SurfaceMismatch => "surface-mismatch",
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
    /// Trusted signer id → hex ed25519 public key (`:aiueos/signers`). A signed
    /// manifest is authentic only if its signer resolves here (ADR-0003).
    pub signers: BTreeMap<String, String>,
    /// `:aiueos/require-signed` — when true, an *unsigned* component is denied
    /// (every component must carry a valid signature). Enforced under the
    /// `signing` feature.
    pub require_signed: bool,
    /// `:aiueos/surface` — the active deployment surface (ADR-0005). A component
    /// pinned to other surfaces is denied. `None` = unspecified (no surface gate).
    pub surface: Option<String>,
    /// `:aiueos/net-allow` — origin allow-list scoping `net/fetch` (ADR-0007). The
    /// network capability is attenuated to these origins; the surface's fetch
    /// provider traps any other host. Empty = no extra scoping declared.
    pub net_allow: BTreeSet<String>,
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
            signers: BTreeMap::new(),
            require_signed: false,
            surface: None,
            net_allow: BTreeSet::new(),
        }
    }
}

impl Policy {
    /// Parse a policy document. Everything is optional and *extends* the default
    /// policy (kernel-caps are unioned, grants merged, forbiddances overridden
    /// per-trust).
    pub fn from_edn(v: &EdnValue) -> crate::error::Result<Policy> {
        // Reject unknown `:aiueos/*` keys — a typo like `:aiueos/grnts` would
        // otherwise silently grant nothing (or `:aiueos/forbd` silently allow),
        // a security-relevant silent failure. Fail loud, like manifests.
        const POLICY_KEYS: &[&str] = &[
            "policy",
            "kernel-caps",
            "grants",
            "forbid",
            "signers",
            "require-signed",
            "surface",
            "net-allow",
        ];
        if let Some(map) = v.as_map() {
            let mut unknown: Vec<String> = map
                .keys()
                .filter_map(|k| k.as_keyword())
                .filter(|kw| kw.namespace() == Some("aiueos") && !POLICY_KEYS.contains(&kw.name()))
                .map(|kw| kw.to_qualified())
                .collect();
            if !unknown.is_empty() {
                unknown.sort();
                return Err(crate::error::AiueosError::Schema(format!(
                    "policy: unknown key(s): {}",
                    unknown.join(", ")
                )));
            }
        }

        use crate::error::AiueosError::Schema;
        let mut p = Policy::default();
        for c in edn::kw_collection(edn::get(v, "aiueos", "kernel-caps")) {
            p.kernel_caps.insert(c);
        }
        match edn::get(v, "aiueos", "grants") {
            None => {}
            Some(EdnValue::Map(g)) => {
                for (k, caps) in g {
                    if let Some(id) = edn::kw_string(k) {
                        let set: BTreeSet<String> =
                            edn::kw_collection(Some(caps)).into_iter().collect();
                        p.grants.entry(id).or_default().extend(set);
                    }
                }
            }
            Some(_) => return Err(Schema("policy: :aiueos/grants must be a map".into())),
        }
        match edn::get(v, "aiueos", "forbid") {
            None => {}
            Some(EdnValue::Map(fb)) => {
                for (k, effs) in fb {
                    // forbid keys are a closed set of trust levels — an unknown
                    // trust would silently fail to apply the lockdown.
                    let name = edn::kw_string(k).ok_or_else(|| {
                        Schema("policy: :aiueos/forbid keys must be trust keywords".into())
                    })?;
                    let trust = Trust::parse(&name).ok_or_else(|| {
                        Schema(format!("policy: unknown trust `{name}` in :aiueos/forbid"))
                    })?;
                    let set: BTreeSet<String> =
                        edn::kw_collection(Some(effs)).into_iter().collect();
                    p.forbid_effects.insert(trust, set);
                }
            }
            Some(_) => return Err(Schema("policy: :aiueos/forbid must be a map".into())),
        }
        match edn::get(v, "aiueos", "signers") {
            None => {}
            Some(EdnValue::Map(sg)) => {
                for (k, key) in sg {
                    let name = edn::kw_string(k).ok_or_else(|| {
                        Schema("policy: :aiueos/signers keys must be keywords".into())
                    })?;
                    let hex = key.as_string().ok_or_else(|| {
                        Schema(format!("policy: signer `{name}` key must be a hex string"))
                    })?;
                    p.signers.insert(name, hex.to_string());
                }
            }
            Some(_) => return Err(Schema("policy: :aiueos/signers must be a map".into())),
        }
        match edn::get(v, "aiueos", "require-signed") {
            None => {}
            Some(EdnValue::Bool(b)) => p.require_signed = *b,
            Some(_) => {
                return Err(Schema(
                    "policy: :aiueos/require-signed must be a boolean".into(),
                ))
            }
        }
        match edn::get(v, "aiueos", "surface") {
            None => {}
            Some(k) if k.as_keyword().is_some() => {
                let id = k.as_keyword().unwrap().name().to_string();
                if !crate::surface::is_known(&id) {
                    return Err(Schema(format!(
                        "policy: unknown :aiueos/surface `{id}` (known: robot, browser, cloud, \
                         computer-virtual, computer-vm, computer-host)"
                    )));
                }
                p.surface = Some(id);
            }
            Some(_) => return Err(Schema("policy: :aiueos/surface must be a keyword".into())),
        }
        for o in edn::str_collection(edn::get(v, "aiueos", "net-allow")) {
            p.net_allow.insert(o);
        }
        Ok(p)
    }

    pub fn load(path: &Path) -> crate::error::Result<Policy> {
        let src = std::fs::read_to_string(path)?;
        let v = kotoba_edn::parse(&src)?;
        Policy::from_edn(&v)
    }

    /// Capabilities available to `m`: kernel primitives ∪ explicit grants. With an
    /// active surface (ADR-0005), the kernel primitives are restricted to those the
    /// surface can actually back — an import that maps to an *unoffered* kernel cap
    /// becomes `unresolved-capability` (the host refuses to provide what this
    /// surface shouldn't). Explicit grants are never surface-gated.
    fn granted_to(&self, m: &Manifest) -> BTreeSet<String> {
        let mut s: BTreeSet<String> =
            match self.surface.as_deref().and_then(crate::surface::offered) {
                Some(offered) => self.kernel_caps.intersection(&offered).cloned().collect(),
                None => self.kernel_caps.clone(),
            };
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

    // 0. Surface gate (ADR-0005): a component pinned to specific surfaces may only
    //    run on the active one. Portable components (no :aiueos/surface) and an
    //    unspecified active surface (no policy :aiueos/surface) skip the check.
    if let (Some(active), Some(targets)) = (&policy.surface, &m.surfaces) {
        if !targets.contains(active) {
            violations.push(Violation {
                component: m.id.clone(),
                kind: ViolationKind::SurfaceMismatch,
                message: format!(
                    "component targets surfaces {targets:?} but the active surface is {active:?}"
                ),
            });
        }
    }

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
