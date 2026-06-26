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
    "wasm-sha256",
    "publishes",
    "subscribes",
    "topics",
];

/// Parse `:aiueos/topics {:name id …}` (name→topic-id map). Absent → empty.
fn topic_name_map(v: &EdnValue, id: &str) -> Result<std::collections::BTreeMap<String, i32>> {
    let mut out = std::collections::BTreeMap::new();
    let m = match edn::get(v, "aiueos", "topics") {
        None => return Ok(out),
        Some(EdnValue::Map(m)) => m,
        Some(_) => {
            return Err(AiueosError::Schema(format!(
                "{id}: :aiueos/topics must be a map of name → topic id"
            )))
        }
    };
    for (k, val) in m {
        let name = k
            .as_keyword()
            .map(|kw| kw.name().to_string())
            .ok_or_else(|| {
                AiueosError::Schema(format!("{id}: :aiueos/topics keys must be keywords"))
            })?;
        let n = val
            .as_integer()
            .filter(|n| *n >= i32::MIN as i64 && *n <= i32::MAX as i64);
        let n = n.ok_or_else(|| {
            AiueosError::Schema(format!(
                "{id}: :aiueos/topics values must be topic ids (i32)"
            ))
        })?;
        out.insert(name, n as i32);
    }
    Ok(out)
}

/// Map named topic capabilities (`topic/<name>`) in `caps` to their numeric ids
/// via the `topics` map. `None` if none resolve (so the caller leaves the access
/// unrestricted rather than declaring an empty allow-set).
fn derive_topic_ids(
    caps: &[String],
    topics: &std::collections::BTreeMap<String, i32>,
) -> Option<std::collections::BTreeSet<i32>> {
    let set: std::collections::BTreeSet<i32> = caps
        .iter()
        .filter_map(|c| c.strip_prefix("topic/"))
        // `topic/publish` & `topic/subscribe` are the coarse gate capabilities,
        // not named data topics — never derive an id from them.
        .filter(|name| *name != "publish" && *name != "subscribe")
        .filter_map(|name| topics.get(name).copied())
        .collect();
    (!set.is_empty()).then_some(set)
}

/// Parse an optional `:aiueos/{publishes,subscribes}` set of topic ids. Absent →
/// `None` (unrestricted). A non-set/vector, or a non-integer / out-of-range
/// element, is a hard error.
fn topic_id_set(
    v: &EdnValue,
    key: &str,
    id: &str,
) -> Result<Option<std::collections::BTreeSet<i32>>> {
    let items: &[EdnValue] = match edn::get(v, "aiueos", key) {
        None => return Ok(None),
        Some(EdnValue::Set(s)) => return collect_topic_ids(s.iter(), key, id).map(Some),
        Some(EdnValue::Vector(xs)) | Some(EdnValue::List(xs)) => xs,
        Some(_) => {
            return Err(AiueosError::Schema(format!(
                "{id}: :aiueos/{key} must be a set of topic ids"
            )))
        }
    };
    collect_topic_ids(items.iter(), key, id).map(Some)
}

fn collect_topic_ids<'a>(
    it: impl Iterator<Item = &'a EdnValue>,
    key: &str,
    id: &str,
) -> Result<std::collections::BTreeSet<i32>> {
    let mut out = std::collections::BTreeSet::new();
    for x in it {
        let n = x.as_integer().ok_or_else(|| {
            AiueosError::Schema(format!("{id}: :aiueos/{key} must contain only integers"))
        })?;
        if n < i32::MIN as i64 || n > i32::MAX as i64 {
            return Err(AiueosError::Schema(format!(
                "{id}: :aiueos/{key} topic id {n} out of range"
            )));
        }
        out.insert(n as i32);
    }
    Ok(out)
}

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

/// The device a driver binds to (`:aiueos/device`). Phase-0 captures the binding
/// identity (bus + vendor/device ids); the richer schema (queues, interrupts,
/// dma) stays as data in the manifest for later phases. `bus`/`vendor`/`device`
/// accept either string or keyword form in EDN.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Device {
    pub bus: Option<String>,
    pub vendor: Option<String>,
    pub device: Option<String>,
}

impl Device {
    fn from_edn(d: &EdnValue) -> Device {
        Device {
            bus: edn::get_bare(d, "bus").and_then(edn::scalar_string),
            vendor: edn::get_bare(d, "vendor").and_then(edn::scalar_string),
            device: edn::get_bare(d, "device").and_then(edn::scalar_string),
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
    /// Expected lowercase-hex SHA-256 of the `:aiueos/wasm` artifact. When set,
    /// the broker rejects the component if the loaded bytes don't match.
    pub wasm_sha256: Option<String>,
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
    /// The device this (driver) component binds to, if declared.
    pub device: Option<Device>,
    /// Topic ids this component may publish to. `None` = unrestricted.
    pub publishes: Option<std::collections::BTreeSet<i32>>,
    /// Topic ids this component may read (poll/take/count). `None` = unrestricted.
    pub subscribes: Option<std::collections::BTreeSet<i32>>,
    /// Named topic → numeric id map (`:aiueos/topics`). Links the named topic
    /// capabilities to the runtime ids; `publishes`/`subscribes` are derived from
    /// it when not given explicitly.
    pub topics: std::collections::BTreeMap<String, i32>,
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

        // Entry defaults to "main"; an explicit empty string is rejected (it would
        // silently fail to resolve an exported function at run time).
        let entry = match edn::get_str(v, "aiueos", "entry") {
            None => "main".to_string(),
            Some(e) if e.is_empty() => {
                return Err(AiueosError::Schema(format!(
                    "{id}: :aiueos/entry must not be empty"
                )))
            }
            Some(e) => e,
        };

        let imports = edn::kw_collection(edn::get(v, "aiueos", "imports"));
        let exports = edn::kw_collection(edn::get(v, "aiueos", "exports"));
        let topics = topic_name_map(v, &id)?;

        // Per-topic runtime isolation: use the explicit numeric set if given, else
        // derive it from the named topic exports/imports via the :aiueos/topics
        // name→id map (so the named graph topics and the runtime ids stay linked).
        let publishes = match topic_id_set(v, "publishes", &id)? {
            Some(p) => Some(p),
            None => derive_topic_ids(&exports, &topics),
        };
        let subscribes = match topic_id_set(v, "subscribes", &id)? {
            Some(s) => Some(s),
            None => derive_topic_ids(&imports, &topics),
        };

        Ok(Manifest {
            id,
            kind,
            trust,
            source: edn::get_str(v, "aiueos", "source"),
            wasm: edn::get_str(v, "aiueos", "wasm"),
            wasm_sha256: edn::get_str(v, "aiueos", "wasm-sha256"),
            imports,
            exports,
            effects: edn::kw_collection(edn::get(v, "aiueos", "effects")),
            requires: edn::kw_collection(edn::get(v, "aiueos", "requires")),
            limits,
            entry,
            args,
            device: edn::get(v, "aiueos", "device").map(Device::from_edn),
            publishes,
            subscribes,
            topics,
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
