//! The capability broker — the trusted seam that turns a manifest + policy into
//! either a running component or a documented denial. It is the only thing that
//! confers capabilities, and every decision it makes is audited.

use crate::audit::{AuditLog, Event};
use crate::error::{AiueosError, Result};
use crate::graph::{CapabilityGraph, System};
use crate::manifest::Manifest;
use crate::policy::{self, Grant, Policy, Violation};
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

/// The verdict of admitting an agent-submitted component (ADR-0004). A structured
/// alternative to a `Result` so an agent loop can branch on *why* it was rejected.
#[derive(Debug, Clone)]
pub struct AdmitOutcome {
    pub component: String,
    /// Whether the component passed the gate and ran.
    pub admitted: bool,
    /// The entry's return value when admitted.
    pub result: Option<i64>,
    /// Human-readable rejection detail, else `None`.
    pub reason: Option<String>,
    /// Stable machine-readable rejection code (`denied` / `unsafe` / `run` / …)
    /// so an agent can branch on *why* without parsing `reason`; `None` if admitted.
    pub reason_code: Option<&'static str>,
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
            match self.verify_one(m, &graph) {
                Ok(grant) => grants.push(grant),
                // Per-component denials are already audited by verify_one; here we
                // just aggregate so the whole system's violations are reported.
                Err(AiueosError::Denied(vs)) => all_violations.extend(vs),
                Err(other) => return Err(other),
            }
        }
        if all_violations.is_empty() {
            Ok(grants)
        } else {
            Err(AiueosError::Denied(all_violations))
        }
    }

    /// Verify a single component against a graph (used by `aiueos run`, where the
    /// graph may be just the component itself or its declared system). Runs
    /// signature authenticity (ADR-0003) first: a bad signature denies; a valid
    /// one elevates the component to `:verified` and is recorded in the audit.
    pub fn verify_one(&self, m: &Manifest, graph: &CapabilityGraph) -> Result<Grant> {
        let signer = match self.authenticate(m) {
            Ok(s) => s,
            Err(AiueosError::Denied(vs)) => return Err(self.deny(m, vs)),
            Err(other) => return Err(other),
        };
        // A signature elevates an under-trusted component to :verified for the
        // capability check (unlocking the verified tier's policy).
        let elevated;
        let m_eff = match &signer {
            Some(_) if m.trust > crate::manifest::Trust::Verified => {
                elevated = m.with_trust(crate::manifest::Trust::Verified);
                &elevated
            }
            _ => m,
        };
        match policy::verify_component(m_eff, graph, &self.policy) {
            Ok(grant) => {
                let caps: Vec<&str> = grant.capabilities.iter().map(|s| s.as_str()).collect();
                let detail = match &signer {
                    Some(s) => format!("caps: {} signer: {s}", caps.join(" ")),
                    None => format!("caps: {}", caps.join(" ")),
                };
                self.audit.append(Event::Grant, &m.id, &detail)?;
                Ok(grant)
            }
            Err(vs) => Err(self.deny(m, vs)),
        }
    }

    /// Audit a list of violations as denials and wrap them as a `Denied` error.
    fn deny(&self, m: &Manifest, vs: Vec<Violation>) -> AiueosError {
        for v in &vs {
            let _ = self.audit.append(
                Event::Deny,
                &m.id,
                &format!("[{}] {}", v.kind.label(), v.message),
            );
        }
        AiueosError::Denied(vs)
    }

    /// Verify a manifest's signature (ADR-0003): `Ok(Some(signer))` if a valid
    /// signature names a registered signer, `Ok(None)` if unsigned, `Err(Denied)`
    /// on a bad/forged signature. Without the `signing` feature, always `None`.
    fn authenticate(&self, m: &Manifest) -> Result<Option<String>> {
        #[cfg(feature = "signing")]
        {
            use crate::signing::{verify, SigStatus};
            return match verify(m, &self.policy)? {
                // A `require-signed` policy rejects unsigned components outright.
                SigStatus::Unsigned if self.policy.require_signed => {
                    Err(AiueosError::Denied(vec![Violation {
                        component: m.id.clone(),
                        kind: crate::policy::ViolationKind::BadSignature,
                        message: "unsigned component rejected (require-signed policy)".into(),
                    }]))
                }
                SigStatus::Unsigned => Ok(None),
                SigStatus::Verified(s) => Ok(Some(s)),
            };
        }
        #[cfg(not(feature = "signing"))]
        {
            let _ = m;
            Ok(None)
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

    /// Code-as-data admission (ADR-0004): the front door for a component an AI
    /// agent emitted at runtime. Identical to [`launch`](Self::launch) except the
    /// submitted manifest's **trust is floored to `:ai-generated`** before
    /// verification — agent code can never grant itself trust (a valid signature
    /// can still *elevate* it, per ADR-0003). Returns a structured verdict rather
    /// than an error, so an agent loop can read *why* a component was rejected and
    /// regenerate.
    #[cfg(feature = "wasm-runtime")]
    pub fn admit(&self, m: &Manifest, base: &Path, graph: &CapabilityGraph) -> AdmitOutcome {
        let floored = m.with_trust(crate::manifest::Trust::AiGenerated);
        match self.launch(&floored, base, graph) {
            Ok(result) => AdmitOutcome {
                component: floored.id,
                admitted: true,
                result: Some(result),
                reason: None,
                reason_code: None,
            },
            Err(e) => AdmitOutcome {
                component: floored.id,
                admitted: false,
                result: None,
                reason_code: Some(e.kind()),
                reason: Some(e.to_string()),
            },
        }
    }

    /// Boot an entire system: link capabilities into a launch order, verify every
    /// component against the policy, then launch each in dependency order (a
    /// capability provider before any consumer). The whole sequence is audited;
    /// any denial or cycle aborts the boot before anything runs.
    #[cfg(feature = "wasm-runtime")]
    pub fn boot(&self, system: &System, base: &Path) -> Result<BootReport> {
        let mut reports = self.boot_rounds(system, base, 1)?;
        Ok(reports.pop().expect("one round → one report"))
    }

    /// Boot the system for `rounds` rounds, threading **one** topic bus across all
    /// of them — a periodic control loop. Capabilities are linked and verified
    /// once; then each round launches every coded component in dependency order,
    /// so a producer's samples in one round are visible (e.g. via `take`) to a
    /// consumer in the same or a later round. Returns one [`BootReport`] per round.
    #[cfg(feature = "wasm-runtime")]
    pub fn boot_rounds(
        &self,
        system: &System,
        _base: &Path,
        rounds: usize,
    ) -> Result<Vec<BootReport>> {
        // Stage 1–2: capability link → topological boot order.
        let order = system.boot_order().map_err(|cycle| {
            AiueosError::Schema(format!("dependency cycle: {}", cycle.join(" → ")))
        })?;

        // Stage 3: policy verification of the whole system (audits each grant/deny).
        let grants = self.verify_system(system)?;
        let caps_of: std::collections::BTreeMap<String, _> = grants
            .into_iter()
            .map(|g| (g.component, g.capabilities))
            .collect();

        // Stage 4: launch in order, once per round, on a shared bus. The scheduler
        // (ADR-0006) refines the topological order by priority *within* dependency
        // depth, so an urgent node runs earlier without ever preceding its provider.
        let empty = std::collections::BTreeSet::new();
        let depths = system.depths();
        let topo_pos: std::collections::BTreeMap<usize, usize> =
            order.iter().enumerate().map(|(p, &i)| (i, p)).collect();
        let mut bus = TopicBus::new();
        let mut reports = Vec::with_capacity(rounds.max(1));
        for cycle in 0..rounds.max(1) {
            let mut launched = Vec::new();
            // Release the components whose period is due this cycle (period_cycles=1,
            // the default, = every cycle), then order them by (depth, priority,
            // topo-position) — dataflow-correct, with priority breaking ties.
            let mut released: Vec<usize> = order
                .iter()
                .copied()
                .filter(|&i| (cycle as u64) % system.components[i].schedule.period_cycles == 0)
                .collect();
            released.sort_by_key(|&i| {
                (
                    depths[i],
                    system.components[i].schedule.priority,
                    topo_pos[&i],
                )
            });
            for &i in &released {
                let m = &system.components[i];
                let base = &system.bases[i];
                if m.source.is_none() && m.wasm.is_none() {
                    // A pure manifest with no code is a declaration-only/resident
                    // component: it passes the gate but has nothing to execute.
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
            reports.push(BootReport {
                system: system.name.clone(),
                launched,
            });
            // Next round is the next control-loop cycle: clock() advances.
            bus.advance();
        }
        Ok(reports)
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
            (None, Some(wasm_rel)) => {
                let bytes = std::fs::read(base.join(wasm_rel))?;
                if let Some(expected) = &m.wasm_sha256 {
                    let actual = crate::runtime::sha256_hex(&bytes);
                    if !actual.eq_ignore_ascii_case(expected) {
                        self.audit.append(
                            Event::Reject,
                            &m.id,
                            &format!("wasm sha256 mismatch: {wasm_rel}"),
                        )?;
                        return Err(AiueosError::Run(format!(
                            "{}: :aiueos/wasm-sha256 mismatch for {wasm_rel} \
                             (expected {expected}, got {actual})",
                            m.id
                        )));
                    }
                }
                bytes
            }
            (None, None) => {
                return Err(AiueosError::Schema(format!(
                    "{}: needs :aiueos/source or :aiueos/wasm to run",
                    m.id
                )))
            }
        };

        // Execute under fuel + memory limits, with the host ABI gated by `caps`
        // and restricted to the topic ids the manifest declared. A host call to an
        // ungranted capability — or an undeclared topic — traps → a run error.
        let topics = crate::host::TopicAccess {
            publish: m.publishes.clone(),
            subscribe: m.subscribes.clone(),
        };
        let outcome = match crate::host::run_with_host_restricted(
            &wasm,
            &m.entry,
            &m.args,
            m.limits.fuel,
            m.limits.memory_pages,
            caps,
            bus,
            &topics,
            m.quota,
        ) {
            Ok(o) => o,
            Err(e) => {
                // A runtime trap (fuel/memory exhaustion, an undeclared-topic or
                // ungranted-capability host call, `unreachable`) is security-relevant
                // — record it before surfacing. Don't let an audit IO error mask the
                // original run error.
                let _ = self
                    .audit
                    .append(Event::Reject, &m.id, &format!("run failed: {e}"));
                return Err(e);
            }
        };
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
