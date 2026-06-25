//! Component manifests — the `:aiueos/...` EDN that describes *what a component is*,
//! *what it may touch* (capabilities/effects) and *how much it may consume*
//! (limits). A manifest is data; the broker and policy reasoner decide whether
//! that data is allowed to run.

use crate::edn;
use crate::error::{AiueosError, Result};
use kotoba_edn::EdnValue;
use std::path::Path;

/// Recognized top-level `:aiueos/*` manifest keys. Any other `:aiueos/`-namespaced
/// key is a typo or an unsupported field and is rejected (see `from_edn`).
const MANIFEST_KEYS: &[&str] = &[
    "component",
    "kind",
    "trust",
    "source",
    "wasm",
    "imports",
    "exports",
    "effects",
    "requires",
    "limits",
    "entry",
    "args",
    "device",
];

/// The kind of a component. This drives default policy and how the runtime
/// treats it (a `:driver` may request device capabilities; an `:agent` is
/// untrusted by default; etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    App,
    Service,
    Driver,
    Broker,
    Agent,
    KernelExtension,
    Compat,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "app" => Kind::App,
            "service" => Kind::Service,
            "driver" => Kind::Driver,
            "broker" => Kind::Broker,
            "agent" => Kind::Agent,
            "kernel-extension" => Kind::KernelExtension,
            "compat" => Kind::Compat,
            _ => return None,
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Kind::App => "app",
            Kind::Service => "service",
            Kind::Driver => "driver",
            Kind::Broker => "broker",
            Kind::Agent => "agent",
            Kind::KernelExtension => "kernel-extension",
            Kind::Compat => "compat",
        }
    }
}

/// Trust level — how the component arrived and how much it is believed. An
/// AI-generated component is the least trusted and the most constrained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// Part of the trusted computing base (kernel-extension, signed brokers).
    Trusted,
    /// Carries a verification proof / signed manifest.
    Verified,
    /// Plain third-party component.
    Untrusted,
    /// Emitted by an AI agent at runtime — ephemeral, no network/secrets/persist.
    AiGenerated,
}

impl Trust {
    pub fn parse(s: &str) -> Option<Trust> {
        Some(match s {
            "trusted" => Trust::Trusted,
            "verified" => Trust::Verified,
            "untrusted" => Trust::Untrusted,
            "ai-generated" => Trust::AiGenerated,
            _ => return None,
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Trust::Trusted => "trusted",
            Trust::Verified => "verified",
            Trust::Untrusted => "untrusted",
            Trust::AiGenerated => "ai-generated",
        }
    }
}

/// Upper bound on declared linear-memory pages: 65536 × 64 KiB = 4 GiB, the
/// wasm32 address-space ceiling.
const MAX_MEMORY_PAGES: i64 = 65_536;

/// Read a `:aiueos/limits` sub-key, validating it's an integer in `[min, max]`.
/// Absent → `default`. A non-integer or out-of-range value is a hard error (this
/// is also what stops a negative value from wrapping when cast to u32/u64).
fn read_limit(l: &EdnValue, key: &str, id: &str, min: i64, max: i64, default: i64) -> Result<i64> {
    match edn::get_bare(l, key) {
        None => Ok(default),
        Some(v) => {
            let n = v.as_integer().ok_or_else(|| {
                AiueosError::Schema(format!("{id}: :aiueos/limits {key} must be an integer"))
            })?;
            if n < min || n > max {
                return Err(AiueosError::Schema(format!(
                    "{id}: :aiueos/limits {key}={n} out of range [{min}, {max}]"
                )));
            }
            Ok(n)
        }
    }
}

/// Resource limits enforced at run time. Defaults are deliberately small.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum linear-memory pages (64 KiB each).
    pub memory_pages: u32,
    /// wasmtime fuel budget — one unit per executed instruction.
    pub fuel: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            memory_pages: 16,
            fuel: 10_000_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Manifest {
    /// Canonical id, e.g. `driver/virtio-blk`.
    pub id: String,
    pub kind: Kind,
    pub trust: Trust,
    /// Path to CLJ/Kotoba source compiled by kototama (relative to the manifest).
    pub source: Option<String>,
    /// Path to a precompiled `.wasm` (alternative to `source`).
    pub wasm: Option<String>,
    /// Capabilities this component needs from others / the kernel.
    pub imports: Vec<String>,
    /// Capabilities this component provides to others.
    pub exports: Vec<String>,
    /// Side effects the component performs (`:device-io`, `:dma`, `:network`…).
    pub effects: Vec<String>,
    /// Hardware/runtime requirements (e.g. `:iommu`).
    pub requires: Vec<String>,
    pub limits: Limits,
    /// Exported wasm function the runtime calls.
    pub entry: String,
    /// i64 arguments passed to `entry`.
    pub args: Vec<i64>,
}

impl Manifest {
    pub fn from_edn(v: &EdnValue) -> Result<Manifest> {
        if v.as_map().is_none() {
            return Err(AiueosError::Schema("manifest must be a map".into()));
        }
        let id = edn::get_kw(v, "aiueos", "component")
            .ok_or_else(|| AiueosError::Schema("manifest missing :aiueos/component".into()))?;

        // Reject unknown `:aiueos/*` keys. A typo like `:aiueos/effcts` would
        // otherwise silently drop an effect — including a `:dma` effect, which
        // would mean the DMA→IOMMU gate never fires. Fail loud instead.
        if let Some(map) = v.as_map() {
            let mut unknown: Vec<String> = map
                .keys()
                .filter_map(|k| k.as_keyword())
                .filter(|kw| {
                    kw.namespace() == Some("aiueos") && !MANIFEST_KEYS.contains(&kw.name())
                })
                .map(|kw| kw.to_qualified())
                .collect();
            if !unknown.is_empty() {
                unknown.sort();
                return Err(AiueosError::Schema(format!(
                    "{id}: unknown manifest key(s): {}",
                    unknown.join(", ")
                )));
            }
        }

        let kind_s = edn::get_kw(v, "aiueos", "kind")
            .ok_or_else(|| AiueosError::Schema(format!("{id}: missing :aiueos/kind")))?;
        let kind = Kind::parse(&kind_s)
            .ok_or_else(|| AiueosError::Schema(format!("{id}: unknown :aiueos/kind {kind_s}")))?;

        // Trust defaults: agents are AI-generated-grade untrusted unless stated.
        let trust = match edn::get_kw(v, "aiueos", "trust") {
            Some(t) => Trust::parse(&t)
                .ok_or_else(|| AiueosError::Schema(format!("{id}: unknown :aiueos/trust {t}")))?,
            None if kind == Kind::Agent => Trust::AiGenerated,
            None if kind == Kind::KernelExtension => Trust::Trusted,
            None => Trust::Untrusted,
        };

        let limits = match edn::get(v, "aiueos", "limits") {
            Some(l) => {
                let d = Limits::default();
                Limits {
                    // ≥1 page (a component needs memory for its own instance) and
                    // ≤4 GiB. Rejecting <1 also prevents a negative value silently
                    // wrapping to a huge u32.
                    memory_pages: read_limit(
                        l,
                        "memory-pages",
                        &id,
                        1,
                        MAX_MEMORY_PAGES,
                        d.memory_pages as i64,
                    )? as u32,
                    // ≥1 fuel unit (0 fuel can't execute anything).
                    fuel: read_limit(l, "fuel", &id, 1, i64::MAX, d.fuel as i64)? as u64,
                }
            }
            None => Limits::default(),
        };

        // `:aiueos/args` must be a vector of integers (the i64 args passed to the
        // entry). Silently dropping a non-integer element or ignoring a non-vector
        // value would pass the entry the wrong arguments — fail loud instead.
        let args = match edn::get(v, "aiueos", "args") {
            None => Vec::new(),
            Some(EdnValue::Vector(xs)) | Some(EdnValue::List(xs)) => {
                let mut out = Vec::with_capacity(xs.len());
                for x in xs {
                    out.push(x.as_integer().ok_or_else(|| {
                        AiueosError::Schema(format!(
                            "{id}: :aiueos/args must be a vector of integers"
                        ))
                    })?);
                }
                out
            }
            Some(_) => {
                return Err(AiueosError::Schema(format!(
                    "{id}: :aiueos/args must be a vector"
                )))
            }
        };

        Ok(Manifest {
            id,
            kind,
            trust,
            source: edn::get_str(v, "aiueos", "source"),
            wasm: edn::get_str(v, "aiueos", "wasm"),
            imports: edn::kw_collection(edn::get(v, "aiueos", "imports")),
            exports: edn::kw_collection(edn::get(v, "aiueos", "exports")),
            effects: edn::kw_collection(edn::get(v, "aiueos", "effects")),
            requires: edn::kw_collection(edn::get(v, "aiueos", "requires")),
            limits,
            entry: edn::get_str(v, "aiueos", "entry").unwrap_or_else(|| "main".to_string()),
            args,
        })
    }

    /// Parse a single component manifest from EDN.
    ///
    /// ```
    /// use aiueos::{Kind, Manifest, Trust};
    /// let d = Manifest::parse_str(
    ///     "{:aiueos/component :driver/blk :aiueos/kind :driver
    ///       :aiueos/exports #{:block/read} :aiueos/entry \"read\" :aiueos/args [7]}",
    /// )
    /// .unwrap();
    /// assert_eq!(d.id, "driver/blk");
    /// assert_eq!(d.kind, Kind::Driver);
    /// assert_eq!(d.trust, Trust::Untrusted); // default for a non-agent
    /// assert_eq!(d.args, vec![7]);
    /// ```
    pub fn parse_str(src: &str) -> Result<Manifest> {
        let v = kotoba_edn::parse(src)?;
        Manifest::from_edn(&v)
    }

    pub fn load(path: &Path) -> Result<Manifest> {
        let src = std::fs::read_to_string(path)?;
        Manifest::parse_str(&src)
    }
}
