//! The system graph and the derived capability graph.
//!
//! A *system graph* (`system.aiueos.edn`) is just a list of component manifests.
//! Loading it produces a [`System`]; from a system we derive a
//! [`CapabilityGraph`] that maps each capability to the components exporting it,
//! which the policy reasoner uses to resolve imports.

use crate::edn;
use crate::error::{AiueosError, Result};
use crate::manifest::Manifest;
use kotoba_edn::EdnValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// A loaded set of component manifests forming one running system.
#[derive(Debug, Clone)]
pub struct System {
    pub name: String,
    pub components: Vec<Manifest>,
    /// The directory each component's manifest was loaded from — its
    /// `:aiueos/source` / `:aiueos/wasm` paths resolve against this, *not* the
    /// system file's directory. Parallel to `components`.
    pub bases: Vec<PathBuf>,
}

impl System {
    /// Load `system.aiueos.edn`. `:aiueos/components` is a vector of paths relative
    /// to the system file. A bare list of manifests (without a wrapper) is also
    /// accepted via [`System::from_manifests`].
    pub fn load(path: &Path) -> Result<System> {
        let src = std::fs::read_to_string(path)?;
        let v = kotoba_edn::parse(&src)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));

        let name = edn::get_kw(&v, "aiueos", "system")
            .or_else(|| edn::get_str(&v, "aiueos", "system"))
            .unwrap_or_else(|| "system".to_string());

        let comp_paths = match edn::get(&v, "aiueos", "components") {
            Some(EdnValue::Vector(xs)) | Some(EdnValue::List(xs)) => xs,
            _ => {
                return Err(AiueosError::Schema(
                    "system graph missing :aiueos/components vector".into(),
                ))
            }
        };

        let mut components = Vec::new();
        let mut bases = Vec::new();
        for p in comp_paths {
            let rel = p
                .as_string()
                .ok_or_else(|| AiueosError::Schema("component path must be a string".into()))?;
            let full: PathBuf = base.join(rel);
            components.push(Manifest::load(&full)?);
            bases.push(
                full.parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf(),
            );
        }
        check_unique_ids(&components)?;
        check_unique_devices(&components)?;
        Ok(System {
            name,
            components,
            bases,
        })
    }

    /// Build a system from already-loaded manifests, rejecting duplicate ids.
    /// Like [`from_manifests`](System::from_manifests) but validated.
    pub fn try_from_manifests(
        name: impl Into<String>,
        components: Vec<Manifest>,
    ) -> crate::error::Result<System> {
        check_unique_ids(&components)?;
        check_unique_devices(&components)?;
        Ok(System::from_manifests(name, components))
    }

    pub fn from_manifests(name: impl Into<String>, components: Vec<Manifest>) -> System {
        let bases = vec![PathBuf::from("."); components.len()];
        System {
            name: name.into(),
            components,
            bases,
        }
    }

    /// Topological launch order: a capability provider boots before any consumer
    /// that imports it. Returns component indices in boot order, or the ids of
    /// components caught in a dependency cycle.
    pub fn boot_order(&self) -> std::result::Result<Vec<usize>, Vec<String>> {
        let graph = self.graph();
        let n = self.components.len();
        let idx: BTreeMap<&str, usize> = self
            .components
            .iter()
            .enumerate()
            .map(|(i, c)| (c.id.as_str(), i))
            .collect();

        // De-duplicated provider→consumer edges (a pair can share many caps).
        let mut edges: BTreeSet<(usize, usize)> = BTreeSet::new();
        for (ci, c) in self.components.iter().enumerate() {
            for imp in &c.imports {
                for prov in graph.providers(imp) {
                    if let Some(&pi) = idx.get(prov.as_str()) {
                        if pi != ci {
                            edges.insert((pi, ci));
                        }
                    }
                }
            }
        }

        let mut indeg = vec![0usize; n];
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &(p, c) in &edges {
            adj[p].push(c);
            indeg[c] += 1;
        }

        // Kahn's algorithm, draining the ready set in index order for a stable,
        // deterministic boot sequence.
        let mut ready: BTreeSet<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
        let mut order = Vec::with_capacity(n);
        while let Some(&u) = ready.iter().next() {
            ready.remove(&u);
            order.push(u);
            for &v in &adj[u] {
                indeg[v] -= 1;
                if indeg[v] == 0 {
                    ready.insert(v);
                }
            }
        }

        if order.len() == n {
            Ok(order)
        } else {
            // Whatever never reached in-degree 0 is part of (or downstream of) a cycle.
            Err((0..n)
                .filter(|i| !order.contains(i))
                .map(|i| self.components[i].id.clone())
                .collect())
        }
    }

    pub fn graph(&self) -> CapabilityGraph {
        CapabilityGraph::build(&self.components)
    }
}

/// Reject a system whose components don't have unique ids. Duplicates would
/// silently collide: both would be credited as providers of the same exports,
/// and the boot-order index would keep only one — a footgun worth a hard error.
fn check_unique_ids(components: &[Manifest]) -> crate::error::Result<()> {
    let mut seen = BTreeSet::new();
    for c in components {
        if !seen.insert(c.id.as_str()) {
            return Err(crate::error::AiueosError::Schema(format!(
                "duplicate component id `{}` in system",
                c.id
            )));
        }
    }
    Ok(())
}

/// Reject a system where two components bind the *same physical device*. A device
/// (a fully-specified `bus:vendor:device` triple) can have exactly one driver —
/// two drivers owning the same hardware is a conflict, not a fallback.
fn check_unique_devices(components: &[Manifest]) -> crate::error::Result<()> {
    let mut seen: BTreeMap<(&str, &str, &str), &str> = BTreeMap::new();
    for c in components {
        if let Some(d) = &c.device {
            // Only fully-specified bindings can conflict; a partial one (e.g. just
            // a bus) is too ambiguous to claim exclusive ownership.
            if let (Some(bus), Some(vendor), Some(dev)) = (&d.bus, &d.vendor, &d.device) {
                let key = (bus.as_str(), vendor.as_str(), dev.as_str());
                if let Some(prev) = seen.insert(key, c.id.as_str()) {
                    return Err(crate::error::AiueosError::Schema(format!(
                        "device {bus}:{vendor}:{dev} is bound by both `{prev}` and `{}`",
                        c.id
                    )));
                }
            }
        }
    }
    Ok(())
}

/// capability → exporting component ids.
#[derive(Debug, Clone, Default)]
pub struct CapabilityGraph {
    providers: BTreeMap<String, Vec<String>>,
}

impl CapabilityGraph {
    pub fn build(components: &[Manifest]) -> CapabilityGraph {
        let mut providers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for c in components {
            for e in &c.exports {
                providers.entry(e.clone()).or_default().push(c.id.clone());
            }
        }
        CapabilityGraph { providers }
    }

    /// Components exporting `cap` (empty slice if none).
    pub fn providers(&self, cap: &str) -> &[String] {
        self.providers.get(cap).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn all(&self) -> &BTreeMap<String, Vec<String>> {
        &self.providers
    }
}
