//! The capability broker — the trusted seam that turns a manifest + policy into
//! either a running component or a documented denial. It is the only thing that
//! confers capabilities, and every decision it makes is audited.

use crate::audit::{AuditLog, Event};
use crate::error::{AiueosError, Result};
use crate::graph::{CapabilityGraph, System};
use crate::manifest::Manifest;
use crate::policy::{self, Grant, Policy};
#[cfg(feature = "wasm-runtime")]
use crate::topic::TopicBus;
#[cfg(feature = "wasm-runtime")]
use std::path::Path;

pub struct Broker {
    pub policy: Policy,
    pub audit: AuditLog,
}

/// One component's result in a boot sequence.
#[derive(Debug, Clone)]
pub struct LaunchOutcome {
    pub component: String,
    pub kind: &'static str,
    /// The i64 the component's entry produced, or `None` for a declaration-only
    /// (resident, no-code) component.
    pub result: Option<i64>,
}

/// The outcome of booting a whole system.
#[derive(Debug, Clone)]
pub struct BootReport {
    pub system: String,
    pub launched: Vec<LaunchOutcome>,
}

impl Broker {
    pub fn new(policy: Policy, audit: AuditLog) -> Broker {
        Broker { policy, audit }
    }

    /// Verify a whole system: link capabilities, run policy per component, and
    /// audit each grant/deny. Returns the grants if *every* component passes,
    /// otherwise the aggregated violations (and nothing is launched).
    pub fn verify_system(&self, system: &System) -> Result<Vec<Grant>> {
        let graph = system.graph();
        let mut grants = Vec::new();
        let mut all_violations = Vec::new();
        for m in &system.components {
            match policy::verify_component(m, &graph, &self.policy) {
                Ok(grant) => {
                    let caps: Vec<&str> = grant.capabilities.iter().map(|s| s.as_str()).collect();
                    self.audit
                        .append(Event::Grant, &m.id, &format!("caps: {}", caps.join(" ")))?;
                    grants.push(grant);
                }
                Err(vs) => {
                    for v in &vs {
                        self.audit.append(
                            Event::Deny,
                            &m.id,
                            &format!("[{}] {}", v.kind.label(), v.message),
                        )?;
                    }
                    all_violations.extend(vs);
                }
            }
        }
        if all_violations.is_empty() {
            Ok(grants)
        } else {
            Err(AiueosError::Denied(all_violations))
        }
    }

    /// Verify a single component against a graph (used by `aiueos run`, where the
    /// graph may be just the component itself or its declared system).
    pub fn verify_one(&self, m: &Manifest, graph: &CapabilityGraph) -> Result<Grant> {
        match policy::verify_component(m, graph, &self.policy) {
            Ok(grant) => {
                let caps: Vec<&str> = grant.capabilities.iter().map(|s| s.as_str()).collect();
                self.audit
                    .append(Event::Grant, &m.id, &format!("caps: {}", caps.join(" ")))?;
                Ok(grant)
            }
            Err(vs) => {
                for v in &vs {
                    self.audit.append(
                        Event::Deny,
                        &m.id,
                        &format!("[{}] {}", v.kind.label(), v.message),
                    )?;
                }
                Err(AiueosError::Denied(vs))
            }
        }
    }

    /// Full launch path: verify, safe-check source, compile, and run under the
    /// manifest's limits. `base` is the directory the manifest's `:aiueos/source` /
    /// `:aiueos/wasm` paths resolve against. Returns the i64 the entry produced.
    #[cfg(feature = "wasm-runtime")]
    pub fn launch(&self, m: &Manifest, base: &Path, graph: &CapabilityGraph) -> Result<i64> {
        // Capability gate (audits grant/deny internally). The conferred capability
        // set is what the host ABI enforces at call time — a fresh bus per run.
        let grant = self.verify_one(m, graph)?;
        let (result, _bus) =
            self.materialize_and_run(m, base, &grant.capabilities, TopicBus::new())?;
        Ok(result)
    }

    /// Boot an entire system: link capabilities into a launch order, verify every
    /// component against the policy, then launch each in dependency order (a
    /// capability provider before any consumer). The whole sequence is audited;
    /// any denial or cycle aborts the boot before anything runs.
    #[cfg(feature = "wasm-runtime")]
    pub fn boot(&self, system: &System, _base: &Path) -> Result<BootReport> {
        // Stage 1–2: capability link → topological boot order.
        let order = system.boot_order().map_err(|cycle| {
            AiueosError::Schema(format!("dependency cycle: {}", cycle.join(" → ")))
        })?;

        // Stage 3: policy verification of the whole system (audits each grant/deny).
        // The grants are the per-component conferred capability sets the host ABI
        // will enforce at run time.
        let grants = self.verify_system(system)?;
        let caps_of: std::collections::BTreeMap<String, _> = grants
            .into_iter()
            .map(|g| (g.component, g.capabilities))
            .collect();

        // Stage 4: launch in order. A single topic bus is threaded through every
        // component so a producer's publish is visible to a later consumer's poll
        // — the running ROS-style dataflow over capability-gated components.
        let empty = std::collections::BTreeSet::new();
        let mut bus = TopicBus::new();
        let mut launched = Vec::new();
        for i in order {
            let m = &system.components[i];
            let base = &system.bases[i];
            if m.source.is_none() && m.wasm.is_none() {
                // A pure manifest with no code is a declaration-only/resident
                // component (e.g. a policy or a not-yet-implemented service): it
                // passes the gate but has nothing to execute.
                launched.push(LaunchOutcome {
                    component: m.id.clone(),
                    kind: m.kind.label(),
                    result: None,
                });
                continue;
            }
            let caps = caps_of.get(&m.id).unwrap_or(&empty);
            let (result, next_bus) = self.materialize_and_run(m, base, caps, bus)?;
            bus = next_bus;
            launched.push(LaunchOutcome {
                component: m.id.clone(),
                kind: m.kind.label(),
                result: Some(result),
            });
        }
        Ok(BootReport {
            system: system.name.clone(),
            launched,
        })
    }

    /// Shared tail of launch/boot: safe-check source, compile (or load wasm), and
    /// run under the manifest's limits with the `aiueos:host` ABI bound and `caps`
    /// gating every host call. Threads `bus` in and back out. Does **not** verify
    /// — callers gate first. Returns the entry result and the (possibly updated)
    /// bus.
    #[cfg(feature = "wasm-runtime")]
    fn materialize_and_run(
        &self,
        m: &Manifest,
        base: &Path,
        caps: &std::collections::BTreeSet<String>,
        bus: TopicBus,
    ) -> Result<(i64, TopicBus)> {
        // Obtain wasm: compile source (safe-checked, needs the kototama feature)
        // or load precompiled bytes / WAT text (`:aiueos/wasm`).
        let wasm: Vec<u8> = match (&m.source, &m.wasm) {
            (Some(src_rel), _) => self.compile_component_source(m, base, src_rel)?,
            (None, Some(wasm_rel)) => std::fs::read(base.join(wasm_rel))?,
            (None, None) => {
                return Err(AiueosError::Schema(format!(
                    "{}: needs :aiueos/source or :aiueos/wasm to run",
                    m.id
                )))
            }
        };

        // Execute under fuel + memory limits, with the host ABI gated by `caps`.
        // A host call to a capability not in `caps` traps → surfaces as a run error.
        let outcome = crate::host::run_with_host(
            &wasm,
            &m.entry,
            &m.args,
            m.limits.fuel,
            m.limits.memory_pages,
            caps,
            bus,
        )?;
        self.audit.append(
            Event::Run,
            &m.id,
            &format!(
                "{}({:?}) = {} [{} host call(s)]",
                m.entry, m.args, outcome.result, outcome.host_calls
            ),
        )?;
        Ok((outcome.result, outcome.bus))
    }

    /// Compile a component's `:aiueos/source` (safe-checked) to wasm. Requires the
    /// `kototama` feature; without it, a source-based component cannot run.
    #[cfg(feature = "kototama")]
    fn compile_component_source(
        &self,
        m: &Manifest,
        base: &Path,
        src_rel: &str,
    ) -> Result<Vec<u8>> {
        let src = std::fs::read_to_string(base.join(src_rel))?;
        if let Err(e) = crate::safe::check(&src) {
            self.audit
                .append(Event::Reject, &m.id, &format!("unsafe source: {src_rel}"))?;
            return Err(e);
        }
        let bytes = crate::runtime::compile_source(&src)?;
        self.audit.append(
            Event::Compile,
            &m.id,
            &format!("{src_rel} → {} wasm bytes", bytes.len()),
        )?;
        Ok(bytes)
    }

    /// Without the `kototama` feature, `:aiueos/source` components can't be built —
    /// use `:aiueos/wasm` (precompiled or WAT) instead.
    #[cfg(all(feature = "wasm-runtime", not(feature = "kototama")))]
    fn compile_component_source(
        &self,
        _m: &Manifest,
        _base: &Path,
        src_rel: &str,
    ) -> Result<Vec<u8>> {
        Err(AiueosError::Run(format!(
            "compiling :aiueos/source ({src_rel}) requires the `kototama` feature; \
             use :aiueos/wasm for precompiled/WAT components"
        )))
    }
}
