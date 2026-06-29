//! The broker-mediated host ABI (`aiueos:host`). This is where capabilities stop
//! being a static manifest claim and become **runtime enforcement**: a component
//! can only call a host function if its conferred capability set contains the
//! matching capability. A call without the capability *traps* — it does not
//! cooperate, it cannot proceed.
//!
//! The ABI is intentionally numeric (no linear-memory marshaling) for Phase-0:
//!
//! | import                | capability         | meaning                          |
//! |-----------------------|--------------------|----------------------------------|
//! | `log(i64)`            | `log/write`        | emit an i64 log sample           |
//! | `clock() -> i64`      | `clock/monotonic`  | monotonic cycle (control loop)   |
//! | `random() -> i64`     | `random/bytes`     | deterministic pseudo-random      |
//! | `publish(i32, i64)`   | `topic/publish`    | publish a sample to a topic      |
//! | `poll(i32) -> i64`    | `topic/subscribe`  | latest sample on a topic         |
//! | `count(i32) -> i64`   | `topic/subscribe`  | #samples published to a topic    |
//! | `take(i32) -> i64`    | `topic/subscribe`  | pop oldest unread sample (FIFO)  |
//! | `dom-render(i32,i32)` | `dom/render`       | paint markup (browser surface)   |
//! | `dom-event(i32,i32)->i32` | `dom/event`    | read next injected input (FIFO)  |
//! | `input-event(i32,i32)->i32` | `input/event` | read next low-level input event  |
//! | `fb-present(i32,i32,i32,i32,i32)->i32` | `framebuffer/present` | present a pixel frame |
//! | `kv-set(i32,i32,i32,i32)` | `storage/kv`   | store bytes under a key (cloud)  |
//! | `kv-get(i32,i32,i32,i32)->i32` | `storage/kv` | read a key's bytes (cloud)     |
//! | `fetch(i32,i32,i32,i32)->i32` | `net/fetch` | read a URL's fixture body (cloud) |
//!
//! The `kv-*` / `fetch` trio is the **cloud** deployment surface (ADR-0005), backed
//! by an in-process KV map and a URL→response fixture map — deterministic, no real
//! socket. `kv-get` / `fetch` use the same caller-buffer convention as `dom-event`
//! (byte length, `-1` on miss, `-2` when the buffer is too small).
//!
//! The `dom-*` pair and `fb-present` are the **browser / GUI** deployment surface
//! (ADR-0005, ADR-0009): `dom-render` reads a UTF-8 markup string `(ptr, len)` and
//! appends it to a host-side render log; `dom-event` reads the next injected input
//! event into a caller-provided buffer `(ptr, cap)`, returning the byte length,
//! `-1` when the queue is drained, or `-2` (event retained) when the buffer is too
//! small. `input-event` has the same buffer convention for lower-level HID /
//! virtio-input style events. `fb-present` records a linear framebuffer frame
//! `(ptr, len, width, height, stride)`. Phase-0 keeps all of this in-process and
//! deterministic — fixtures stand in for a real host page, input device, or
//! virtio-gpu scanout.
//!
//! `poll` of an empty topic returns [`EMPTY`]. The topic bus is threaded *by
//! value* through each run so the broker can pass one bus across a whole booted
//! system — producer → consumer dataflow without shared mutable state.

use crate::error::{AiueosError, Result};
use crate::topic::TopicBus;
use kotoba_edn::EdnValue;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Val, ValType,
};

type KqeKey = (String, String, String);

/// In-process KQE graph state threaded by the broker across component launches.
/// Objects are raw CBOR/list<u8> bytes as exposed by the kotoba:kais ABI.
#[derive(Debug, Clone, Default)]
pub struct KqeStore {
    quads: BTreeMap<KqeKey, Vec<Vec<u8>>>,
}

impl KqeStore {
    pub fn load(path: &Path) -> Result<KqeStore> {
        let src = match std::fs::read_to_string(path) {
            Ok(src) => src,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(KqeStore::default()),
            Err(e) => return Err(e.into()),
        };
        let root = kotoba_edn::parse(&src)?;
        let Some(items) = crate::edn::get(&root, "aiueos", "kqe").and_then(|v| v.as_vector())
        else {
            return Err(AiueosError::Schema(
                "kqe store: expected :aiueos/kqe vector".into(),
            ));
        };
        let mut store = KqeStore::default();
        for item in items {
            let graph = kqe_field(item, "graph")?;
            let subject = kqe_field(item, "subject")?;
            let predicate = kqe_field(item, "predicate")?;
            let object_hex = kqe_field(item, "object-hex")?;
            let object = hex_decode(&object_hex)?;
            store
                .quads
                .entry((graph, subject, predicate))
                .or_default()
                .push(object);
        }
        Ok(store)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let quads = self
            .quads
            .iter()
            .flat_map(|((graph, subject, predicate), objects)| {
                objects.iter().map(move |object| {
                    EdnValue::map([
                        (EdnValue::kw_bare("graph"), EdnValue::string(graph.clone())),
                        (
                            EdnValue::kw_bare("subject"),
                            EdnValue::string(subject.clone()),
                        ),
                        (
                            EdnValue::kw_bare("predicate"),
                            EdnValue::string(predicate.clone()),
                        ),
                        (
                            EdnValue::kw_bare("object-hex"),
                            EdnValue::string(hex_encode(object)),
                        ),
                    ])
                })
            });
        let root = EdnValue::map([(EdnValue::kw("aiueos", "kqe"), EdnValue::vector(quads))]);
        std::fs::write(path, kotoba_edn::to_string(&root))?;
        Ok(())
    }

    #[cfg(feature = "kototama")]
    fn datomic_query(
        &self,
        caps: &BTreeSet<String>,
        graph_filter: Option<&str>,
        query: &EdnValue,
    ) -> anyhow::Result<Vec<(String, String, String, Vec<u8>)>> {
        let tx = kotoba_core::cid::KotobaCid::from_bytes(b"aiueos-kqe-datomic-snapshot");
        let mut datoms = Vec::new();
        let mut seen_subjects = BTreeSet::new();
        for ((graph, subject, predicate), objects) in &self.quads {
            if graph_filter.is_some_and(|wanted| wanted != graph) {
                continue;
            }
            if !has_target_cap(caps, "kotoba.graph-read/", graph) {
                continue;
            }
            let entity = kqe_entity_cid(graph, subject);
            if seen_subjects.insert((graph.clone(), subject.clone())) {
                datoms.push(kotoba_datomic::Datom::assert(
                    entity.clone(),
                    "kqe/graph".to_string(),
                    EdnValue::string(graph.clone()),
                    tx.clone(),
                ));
                datoms.push(kotoba_datomic::Datom::assert(
                    entity.clone(),
                    "kqe/subject".to_string(),
                    EdnValue::string(subject.clone()),
                    tx.clone(),
                ));
            }
            for object in objects {
                datoms.push(kotoba_datomic::Datom::assert(
                    entity.clone(),
                    predicate.clone(),
                    kqe_object_to_datomic_value(object),
                    tx.clone(),
                ));
            }
        }
        let db = kotoba_datomic::Db::from_datoms(datoms, Some(tx));
        let rows = kotoba_datomic::q(query.clone(), &db, &[])
            .map_err(|e| anyhow::anyhow!("kqe datomic query failed: {e}"))?;
        let graph = graph_filter.unwrap_or("datomic").to_string();
        Ok(rows
            .into_iter()
            .enumerate()
            .map(|(i, row)| {
                (
                    graph.clone(),
                    format!("row/{i}"),
                    "datomic/row".to_string(),
                    kotoba_edn::to_string(&EdnValue::vector(row)).into_bytes(),
                )
            })
            .collect())
    }
}

/// Deterministic LLM responses for kotoba:kais host calls. This keeps LLM IO
/// explicit and testable: a component still needs `kotoba.infer/<model>`, and
/// aiueos returns only responses the caller supplied as fixtures.
#[derive(Debug, Clone, Default)]
pub struct LlmFixtures {
    responses: BTreeMap<String, Vec<u8>>,
}

impl LlmFixtures {
    pub fn load(path: &Path) -> Result<LlmFixtures> {
        let src = std::fs::read_to_string(path)?;
        let root = kotoba_edn::parse(&src)?;
        let Some(map) = crate::edn::get(&root, "aiueos", "llm").and_then(|v| v.as_map()) else {
            return Err(AiueosError::Schema(
                "llm fixture: expected :aiueos/llm map".into(),
            ));
        };
        let mut fixtures = LlmFixtures::default();
        for (model, response) in map {
            let model = edn_key_string(model).ok_or_else(|| {
                AiueosError::Schema("llm fixture: model keys must be strings or keywords".into())
            })?;
            let response = response.as_string().ok_or_else(|| {
                AiueosError::Schema(format!("llm fixture `{model}` response must be a string"))
            })?;
            fixtures
                .responses
                .insert(model, response.as_bytes().to_vec());
        }
        Ok(fixtures)
    }

    fn response(&self, model: &str) -> Option<&[u8]> {
        self.responses.get(model).map(Vec::as_slice)
    }
}

/// A presented linear framebuffer frame (ADR-0009). Bytes are opaque to the host
/// in Phase 0; callers usually pass RGBA or BGRA rows and describe the row stride.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramebufferFrame {
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

/// The **browser** deployment surface's DOM/GUI state (ADR-0005, ADR-0009). Phase-0 keeps it
/// in-process and deterministic, exactly like [`TopicBus`] and [`KqeStore`]:
/// `dom/render` appends the markup a component paints to an ordered log the broker
/// can inspect, `dom/event` delivers semantic events the caller injected as
/// fixtures (a click / keystroke / navigation) to the guest FIFO, and
/// `input/event` delivers lower-level input device events FIFO. The host page is
/// simulated, never real DOM — so a component can be exercised against `browser`
/// deterministically before a real web host binds the same capabilities. The
/// framebuffer log is the same idea for pixels: a testable provider before
/// virtio-gpu or a native compositor exists.
#[derive(Debug, Clone, Default)]
pub struct DomSurface {
    /// Markup painted via `dom/render`, in call order — "what was rendered."
    rendered: Vec<String>,
    /// Pending input events delivered FIFO via `dom/event` — "the operations."
    events: VecDeque<String>,
    /// Pending low-level input events delivered FIFO via `input-event`.
    input_events: VecDeque<String>,
    /// Linear framebuffer frames presented via `fb-present`, in call order.
    framebuffer: Vec<FramebufferFrame>,
}

impl DomSurface {
    /// A browser surface seeded with the input events to deliver to the guest
    /// (the clicks / keystrokes it will observe), in order. Empty = no input.
    pub fn with_events<I, S>(events: I) -> DomSurface
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        DomSurface {
            rendered: Vec::new(),
            events: events.into_iter().map(Into::into).collect(),
            input_events: VecDeque::new(),
            framebuffer: Vec::new(),
        }
    }

    /// A browser surface seeded with low-level input events (future HID /
    /// virtio-input style events), delivered FIFO via `input-event`.
    pub fn with_input_events<I, S>(events: I) -> DomSurface
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        DomSurface {
            rendered: Vec::new(),
            events: VecDeque::new(),
            input_events: events.into_iter().map(Into::into).collect(),
            framebuffer: Vec::new(),
        }
    }

    /// Load injected DOM input events from an EDN fixture, keeping browser IO
    /// explicit and testable the way [`LlmFixtures`] does for inference:
    ///
    /// ```edn
    /// {:aiueos/dom-events ["click:#submit" "input:hello"]}
    /// ```
    pub fn load(path: &Path) -> Result<DomSurface> {
        let src = std::fs::read_to_string(path)?;
        let root = kotoba_edn::parse(&src)?;
        let Some(items) =
            crate::edn::get(&root, "aiueos", "dom-events").and_then(|v| v.as_vector())
        else {
            return Err(AiueosError::Schema(
                "dom events fixture: expected :aiueos/dom-events vector".into(),
            ));
        };
        let mut events = VecDeque::new();
        for item in items {
            let event = item.as_string().ok_or_else(|| {
                AiueosError::Schema("dom events fixture: each event must be a string".into())
            })?;
            events.push_back(event.to_string());
        }
        Ok(DomSurface {
            rendered: Vec::new(),
            events,
            input_events: VecDeque::new(),
            framebuffer: Vec::new(),
        })
    }

    /// Load injected low-level input events from an EDN fixture:
    ///
    /// ```edn
    /// {:aiueos/input-events ["key:Enter" "pointer:10,20"]}
    /// ```
    pub fn load_input(path: &Path) -> Result<DomSurface> {
        let src = std::fs::read_to_string(path)?;
        let root = kotoba_edn::parse(&src)?;
        let Some(items) =
            crate::edn::get(&root, "aiueos", "input-events").and_then(|v| v.as_vector())
        else {
            return Err(AiueosError::Schema(
                "input events fixture: expected :aiueos/input-events vector".into(),
            ));
        };
        let mut input_events = VecDeque::new();
        for item in items {
            let event = item.as_string().ok_or_else(|| {
                AiueosError::Schema("input events fixture: each event must be a string".into())
            })?;
            input_events.push_back(event.to_string());
        }
        Ok(DomSurface {
            rendered: Vec::new(),
            events: VecDeque::new(),
            input_events,
            framebuffer: Vec::new(),
        })
    }

    /// Merge another fixture surface's pending inputs into this one.
    pub fn merge_inputs(&mut self, other: DomSurface) {
        self.events.extend(other.events);
        self.input_events.extend(other.input_events);
    }

    /// The markup painted via `dom/render` so far, in call order.
    pub fn rendered(&self) -> &[String] {
        &self.rendered
    }

    /// Linear framebuffer frames presented via `fb-present` so far.
    pub fn framebuffer(&self) -> &[FramebufferFrame] {
        &self.framebuffer
    }
}

/// The **cloud** deployment surface's state (ADR-0005). Like every other Phase-0
/// provider it is in-process and deterministic: `storage/kv` is an in-memory map
/// threaded by the broker across launches (like [`KqeStore`]), and `net/fetch` is
/// a fixture map (like [`LlmFixtures`]) so HTTP responses are explicit and testable
/// — aiueos never opens a real socket or reads ambient credentials from inside the
/// host import. A real socket/HTTP broker is future TCB, bound the same way.
#[derive(Debug, Clone, Default)]
pub struct CloudSurface {
    /// `storage/kv` state, surviving across launches in a boot round.
    kv: BTreeMap<String, Vec<u8>>,
    /// `net/fetch` fixture responses, keyed by URL.
    fetch: BTreeMap<String, Vec<u8>>,
}

impl CloudSurface {
    /// A cloud surface seeded with `net/fetch` fixture responses (url → body).
    pub fn with_fetch<I, K, V>(responses: I) -> CloudSurface
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Vec<u8>>,
    {
        CloudSurface {
            kv: BTreeMap::new(),
            fetch: responses
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// Load cloud fixtures from EDN — a KV seed and/or fetch responses:
    ///
    /// ```edn
    /// {:aiueos/kv    {"session/alice" "token"}
    ///  :aiueos/fetch {"https://api/health" "ok"}}
    /// ```
    pub fn load(path: &Path) -> Result<CloudSurface> {
        let src = std::fs::read_to_string(path)?;
        let root = kotoba_edn::parse(&src)?;
        let kv = cloud_string_map(&root, "kv")?;
        let fetch = cloud_string_map(&root, "fetch")?;
        Ok(CloudSurface { kv, fetch })
    }

    /// The value stored under `key` in the KV store, if any.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.kv.get(key).map(Vec::as_slice)
    }

    /// Keys currently present in the KV store, in deterministic order.
    pub fn keys(&self) -> Vec<String> {
        self.kv.keys().cloned().collect()
    }
}

/// Parse `:aiueos/<name>` as a `{string → string}` EDN map into `{String → bytes}`,
/// shared by [`CloudSurface::load`] for the `kv` and `fetch` maps. Absent → empty.
fn cloud_string_map(root: &EdnValue, name: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    let Some(map) = crate::edn::get(root, "aiueos", name).and_then(|v| v.as_map()) else {
        return Ok(BTreeMap::new());
    };
    let mut out = BTreeMap::new();
    for (key, value) in map {
        let key = edn_key_string(key).ok_or_else(|| {
            AiueosError::Schema(format!("cloud fixture :aiueos/{name} keys must be strings"))
        })?;
        let value = value.as_string().ok_or_else(|| {
            AiueosError::Schema(format!(
                "cloud fixture :aiueos/{name} `{key}` must be a string"
            ))
        })?;
        out.insert(key, value.as_bytes().to_vec());
    }
    Ok(out)
}

fn edn_key_string(v: &EdnValue) -> Option<String> {
    v.as_string()
        .map(str::to_string)
        .or_else(|| crate::edn::kw_string(v))
}

fn kqe_field(item: &EdnValue, name: &str) -> Result<String> {
    crate::edn::get_bare(item, name)
        .and_then(|v| v.as_string().map(str::to_string))
        .ok_or_else(|| AiueosError::Schema(format!("kqe store item missing string :{name}")))
}

#[derive(Debug, Clone, Default)]
struct KqeQueryFilter {
    graph: Option<String>,
    subject: Option<String>,
    predicate: Option<String>,
    datomic: Option<EdnValue>,
}

impl KqeQueryFilter {
    fn parse(src: &str) -> anyhow::Result<KqeQueryFilter> {
        let src = src.trim();
        if src.is_empty() {
            return Ok(KqeQueryFilter::default());
        }
        if !src.starts_with('{') {
            return Ok(KqeQueryFilter {
                predicate: Some(src.to_string()),
                ..KqeQueryFilter::default()
            });
        }
        let edn = kotoba_edn::parse(src)
            .map_err(|e| anyhow::anyhow!("kqe query filter EDN parse error: {e}"))?;
        let map = edn
            .as_map()
            .ok_or_else(|| anyhow::anyhow!("kqe query filter must be an EDN map"))?;
        for key in map.keys() {
            let Some(kw) = key.as_keyword() else {
                anyhow::bail!("kqe query filter keys must be keywords");
            };
            if kw.namespace().is_some()
                || !matches!(kw.name(), "graph" | "subject" | "predicate" | "datomic")
            {
                anyhow::bail!("kqe query filter has unknown key `:{}`", kw.to_qualified());
            }
        }
        Ok(KqeQueryFilter {
            graph: query_filter_field(&edn, "graph")?,
            subject: query_filter_field(&edn, "subject")?,
            predicate: query_filter_field(&edn, "predicate")?,
            datomic: crate::edn::get_bare(&edn, "datomic").cloned(),
        })
    }

    fn matches(&self, graph: &str, subject: &str, predicate: &str) -> bool {
        self.graph.as_deref().is_none_or(|g| g == graph)
            && self.subject.as_deref().is_none_or(|s| s == subject)
            && self.predicate.as_deref().is_none_or(|p| p == predicate)
    }

    fn audit_label(&self) -> String {
        if self.datomic.is_some() {
            format!("datomic graph={:?}", self.graph)
        } else {
            format!(
                "graph={:?} subject={:?} predicate={:?}",
                self.graph, self.subject, self.predicate
            )
        }
    }
}

fn query_filter_field(edn: &EdnValue, name: &str) -> anyhow::Result<Option<String>> {
    crate::edn::get_bare(edn, name)
        .map(|v| {
            v.as_string()
                .map(str::to_string)
                .ok_or_else(|| anyhow::anyhow!("kqe query filter `:{name}` must be a string"))
        })
        .transpose()
}

#[cfg(feature = "kototama")]
fn kqe_entity_cid(graph: &str, subject: &str) -> kotoba_core::cid::KotobaCid {
    kotoba_core::cid::KotobaCid::from_bytes(format!("{graph}/{subject}").as_bytes())
}

#[cfg(feature = "kototama")]
fn kqe_object_to_datomic_value(object: &[u8]) -> EdnValue {
    match std::str::from_utf8(object) {
        Ok(s) => EdnValue::string(s.to_string()),
        Err(_) => EdnValue::string(format!("0x{}", hex_encode(object))),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(AiueosError::Schema(
            "kqe store: odd-length hex object".into(),
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| {
                AiueosError::Schema(format!("kqe store: invalid hex byte `{}`", &s[i..i + 2]))
            })
        })
        .collect()
}

/// Returned by `poll` when a topic has never been published to.
pub const EMPTY: i64 = i64::MIN;

/// Per-topic access restriction. `None` means unrestricted (any topic id);
/// `Some(set)` restricts to exactly those topic ids — so a component can only
/// publish to / read the topics it declared, not another node's topics.
#[derive(Debug, Clone, Default)]
pub struct TopicAccess {
    pub publish: Option<BTreeSet<i32>>,
    pub subscribe: Option<BTreeSet<i32>>,
}

impl TopicAccess {
    /// No per-topic restriction (only the coarse capability gate applies).
    pub fn unrestricted() -> Self {
        Self::default()
    }
}

fn topic_ok(set: &Option<BTreeSet<i32>>, topic: i32) -> bool {
    set.as_ref().map_or(true, |s| s.contains(&topic))
}

/// FNV-1a over `bytes`, continuing from `h`.
fn fnv1a(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// A deterministic per-run seed from the run signature (entry + args + caps).
/// Distinct components → distinct seeds → independent `random()` streams; two
/// truly identical runs share a stream (they're indistinguishable). `caps` is a
/// BTreeSet, so iteration order is stable.
fn run_seed(entry: &str, args: &[i64], caps: &BTreeSet<String>) -> u64 {
    let mut h = fnv1a(0xcbf2_9ce4_8422_2325, entry.as_bytes());
    for a in args {
        h = fnv1a(h, &a.to_le_bytes());
    }
    for c in caps {
        h = fnv1a(h, c.as_bytes());
    }
    h
}

/// What a host call costs against the per-cycle quota (ADR-0006).
enum Charge {
    /// An ordinary gated host call.
    Call,
    /// A `publish`, which also draws on the separate publish budget.
    Publish,
}

/// Charge one host call against the component's per-cycle quota, trapping if the
/// budget is exhausted — so an over-quota call fails exactly like an ungranted
/// capability or an undeclared topic. Increments the call counter.
fn charge(ctx: &mut HostCtx, kind: Charge) -> anyhow::Result<()> {
    ctx.calls += 1;
    if ctx.calls as u64 > ctx.quota.host_calls {
        anyhow::bail!(
            "host-call quota exceeded ({} per cycle)",
            ctx.quota.host_calls
        );
    }
    if matches!(kind, Charge::Publish) {
        ctx.publishes += 1;
        if ctx.publishes > ctx.quota.publishes {
            anyhow::bail!("publish quota exceeded ({} per cycle)", ctx.quota.publishes);
        }
    }
    Ok(())
}

/// splitmix64 — a fast, well-distributed mixing function. Used to make `random()`
/// deterministic-yet-varied from a seed (reproducible Phase-0 randomness).
fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The store context every host call sees: the conferred capabilities (the gate),
/// the topic bus, the per-topic restriction, and call/log accounting.
pub struct HostCtx {
    limits: StoreLimits,
    caps: BTreeSet<String>,
    topics: TopicAccess,
    bus: TopicBus,
    logs: Vec<i64>,
    events: Vec<String>,
    calls: usize,
    /// Per-cycle host-call quota (ADR-0006) and the publish sub-counter.
    quota: crate::manifest::Quota,
    publishes: u64,
    /// Per-run base seed for `random()` — derived from the run signature
    /// (entry + args + caps) so distinct components draw *independent* streams
    /// rather than the same value at the same cycle.
    seed: u64,
    /// KQE graph state for kotoba:kais host calls, threaded by the broker across
    /// component launches like TopicBus.
    kqe: KqeStore,
    /// Deterministic LLM response provider for kotoba:kais/infer.
    llm: LlmFixtures,
    /// Browser-surface DOM state for `dom/render` + `dom/event` (ADR-0005).
    dom: DomSurface,
    /// Cloud-surface state for `storage/kv` + `net/fetch` (ADR-0005).
    cloud: CloudSurface,
    /// The `computer-virtual` backing daemon (ADR-0007), lazily spawned on the first
    /// forwarded computer-use action when `AIUEOS_COMPUTER_BACKING` is set. `None`
    /// keeps the in-process audit ledger as the only effect (the default).
    #[cfg(feature = "computer-backing")]
    backing: Option<crate::backing::Backing>,
}

/// What a host-enabled run produced.
pub struct HostOutcome {
    pub result: i64,
    pub logs: Vec<i64>,
    pub host_calls: usize,
    pub host_events: Vec<String>,
    /// The bus after this component ran — pass it to the next component.
    pub bus: TopicBus,
    /// The KQE store after this component ran — pass it to the next component.
    pub kqe: KqeStore,
    /// Markup the component painted via `dom/render`, in call order (browser
    /// surface). Empty on any surface that doesn't confer `dom/render`.
    pub dom_rendered: Vec<String>,
    /// Pixel frames the component presented via `fb-present`, in call order.
    pub framebuffer_presented: Vec<FramebufferFrame>,
    /// The browser surface after this component ran — pass it to the next
    /// component so injected events are consumed FIFO and rendered markup
    /// accumulates across a boot round.
    pub dom: DomSurface,
    /// The cloud surface after this component ran (its `storage/kv` mutations) —
    /// pass it to the next component, like [`HostOutcome::kqe`].
    pub cloud: CloudSurface,
}

fn run_err(e: impl std::fmt::Display) -> AiueosError {
    AiueosError::Run(e.to_string())
}

/// The capability gate. Returns a trap (host error) when `cap` isn't granted.
fn gate(ctx: &HostCtx, cap: &str, what: &str) -> anyhow::Result<()> {
    if ctx.caps.contains(cap) {
        Ok(())
    } else {
        anyhow::bail!("capability `{cap}` not granted — host call `{what}` denied")
    }
}

fn gate_target(ctx: &HostCtx, prefix: &str, target: &str, what: &str) -> anyhow::Result<()> {
    if ctx.caps.contains(&format!("{prefix}{target}")) || ctx.caps.contains(&format!("{prefix}*")) {
        Ok(())
    } else {
        anyhow::bail!("capability `{prefix}{target}` not granted — host call `{what}` denied")
    }
}

fn has_target(ctx: &HostCtx, prefix: &str, target: &str) -> bool {
    has_target_cap(&ctx.caps, prefix, target)
}

fn has_target_cap(caps: &BTreeSet<String>, prefix: &str, target: &str) -> bool {
    caps.contains(&format!("{prefix}{target}")) || caps.contains(&format!("{prefix}*"))
}

fn gate_class(ctx: &HostCtx, prefix: &str, what: &str) -> anyhow::Result<()> {
    if ctx
        .caps
        .iter()
        .any(|cap| cap.strip_prefix(prefix).is_some())
    {
        Ok(())
    } else {
        anyhow::bail!("capability `{prefix}<target>` not granted — host call `{what}` denied")
    }
}

impl crate::surface::Provider {
    /// Bind this provider's host import into the runtime linker. Providers whose
    /// low-level implementation is not available in Phase 0 return `Ok(false)`;
    /// importing them still fails at instantiate time, which is the intended loud
    /// "no provider exists yet" behavior for native device caps.
    fn bind(&self, linker: &mut Linker<HostCtx>) -> Result<bool> {
        match self.name {
            "log" => linker
                .func_wrap(
                    "aiueos:host",
                    "log",
                    |mut c: Caller<'_, HostCtx>, v: i64| -> anyhow::Result<()> {
                        gate(c.data(), "log/write", "log")?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        d.logs.push(v);
                        note(d, format!("aiueos:host/log value={v}"));
                        Ok(())
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "clock" => linker
                .func_wrap(
                    "aiueos:host",
                    "clock",
                    |mut c: Caller<'_, HostCtx>| -> anyhow::Result<i64> {
                        gate(c.data(), "clock/monotonic", "clock")?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        let tick = d.bus.tick();
                        note(d, format!("aiueos:host/clock tick={tick}"));
                        Ok(tick as i64)
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "random" => linker
                .func_wrap(
                    "aiueos:host",
                    "random",
                    |mut c: Caller<'_, HostCtx>| -> anyhow::Result<i64> {
                        gate(c.data(), "random/bytes", "random")?;
                        let d = c.data_mut();
                        let mixed = d
                            .seed
                            .wrapping_add(d.bus.tick().wrapping_mul(0x9E37_79B9_7F4A_7C15))
                            .wrapping_add(d.calls as u64);
                        charge(d, Charge::Call)?;
                        note(d, "aiueos:host/random");
                        Ok(splitmix64(mixed) as i64)
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "publish" => linker
                .func_wrap(
                    "aiueos:host",
                    "publish",
                    |mut c: Caller<'_, HostCtx>, topic: i32, value: i64| -> anyhow::Result<()> {
                        gate(c.data(), "topic/publish", "publish")?;
                        if !topic_ok(&c.data().topics.publish, topic) {
                            anyhow::bail!(
                                "topic {topic} not in this component's :aiueos/publishes set"
                            );
                        }
                        let d = c.data_mut();
                        charge(d, Charge::Publish)?;
                        d.bus.publish(topic, value);
                        note(
                            d,
                            format!("aiueos:host/publish topic={topic} value={value}"),
                        );
                        Ok(())
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "poll" => linker
                .func_wrap(
                    "aiueos:host",
                    "poll",
                    |mut c: Caller<'_, HostCtx>, topic: i32| -> anyhow::Result<i64> {
                        gate(c.data(), "topic/subscribe", "poll")?;
                        if !topic_ok(&c.data().topics.subscribe, topic) {
                            anyhow::bail!(
                                "topic {topic} not in this component's :aiueos/subscribes set"
                            );
                        }
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        let value = d.bus.latest(topic).unwrap_or(EMPTY);
                        note(d, format!("aiueos:host/poll topic={topic} value={value}"));
                        Ok(value)
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "count" => linker
                .func_wrap(
                    "aiueos:host",
                    "count",
                    |mut c: Caller<'_, HostCtx>, topic: i32| -> anyhow::Result<i64> {
                        gate(c.data(), "topic/subscribe", "count")?;
                        if !topic_ok(&c.data().topics.subscribe, topic) {
                            anyhow::bail!(
                                "topic {topic} not in this component's :aiueos/subscribes set"
                            );
                        }
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        let count = d.bus.count(topic);
                        note(d, format!("aiueos:host/count topic={topic} count={count}"));
                        Ok(count as i64)
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "take" => linker
                .func_wrap(
                    "aiueos:host",
                    "take",
                    |mut c: Caller<'_, HostCtx>, topic: i32| -> anyhow::Result<i64> {
                        gate(c.data(), "topic/subscribe", "take")?;
                        if !topic_ok(&c.data().topics.subscribe, topic) {
                            anyhow::bail!(
                                "topic {topic} not in this component's :aiueos/subscribes set"
                            );
                        }
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        let value = d.bus.take(topic).unwrap_or(EMPTY);
                        note(d, format!("aiueos:host/take topic={topic} value={value}"));
                        Ok(value)
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "dom-render" => linker
                .func_wrap(
                    "aiueos:host",
                    "dom-render",
                    |mut c: Caller<'_, HostCtx>, ptr: i32, len: i32| -> anyhow::Result<()> {
                        gate(c.data(), "dom/render", "dom-render")?;
                        let markup = read_guest_string(&mut c, ptr, len)?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        note(d, format!("aiueos:host/dom-render bytes={}", markup.len()));
                        d.dom.rendered.push(markup);
                        Ok(())
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "dom-event" => linker
                .func_wrap(
                    "aiueos:host",
                    "dom-event",
                    |mut c: Caller<'_, HostCtx>,
                     buf_ptr: i32,
                     buf_cap: i32|
                     -> anyhow::Result<i32> {
                        gate(c.data(), "dom/event", "dom-event")?;
                        if buf_cap < 0 {
                            anyhow::bail!("negative dom-event buffer capacity");
                        }
                        let next_len = c.data().dom.events.front().map(String::len);
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        match next_len {
                            None => {
                                note(d, "aiueos:host/dom-event none");
                                Ok(-1)
                            }
                            Some(n) if n > buf_cap as usize => {
                                note(
                                    d,
                                    format!(
                                        "aiueos:host/dom-event buffer-too-small need={n} cap={buf_cap}"
                                    ),
                                );
                                Ok(-2)
                            }
                            Some(_) => {
                                let event =
                                    d.dom.events.pop_front().expect("peeked a present event");
                                note(d, format!("aiueos:host/dom-event bytes={}", event.len()));
                                let bytes = event.into_bytes();
                                write_guest_bytes(&mut c, buf_ptr, &bytes)?;
                                Ok(bytes.len() as i32)
                            }
                        }
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "input-event" => linker
                .func_wrap(
                    "aiueos:host",
                    "input-event",
                    |mut c: Caller<'_, HostCtx>,
                     buf_ptr: i32,
                     buf_cap: i32|
                     -> anyhow::Result<i32> {
                        gate(c.data(), "input/event", "input-event")?;
                        if buf_cap < 0 {
                            anyhow::bail!("negative input-event buffer capacity");
                        }
                        let next_len = c.data().dom.input_events.front().map(String::len);
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        match next_len {
                            None => {
                                note(d, "aiueos:host/input-event none");
                                Ok(-1)
                            }
                            Some(n) if n > buf_cap as usize => {
                                note(
                                    d,
                                    format!(
                                        "aiueos:host/input-event buffer-too-small need={n} cap={buf_cap}"
                                    ),
                                );
                                Ok(-2)
                            }
                            Some(_) => {
                                let event = d
                                    .dom
                                    .input_events
                                    .pop_front()
                                    .expect("peeked a present input event");
                                note(d, format!("aiueos:host/input-event bytes={}", event.len()));
                                let bytes = event.into_bytes();
                                write_guest_bytes(&mut c, buf_ptr, &bytes)?;
                                Ok(bytes.len() as i32)
                            }
                        }
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "fb-present" => linker
                .func_wrap(
                    "aiueos:host",
                    "fb-present",
                    |mut c: Caller<'_, HostCtx>,
                     ptr: i32,
                     len: i32,
                     width: i32,
                     height: i32,
                     stride: i32|
                     -> anyhow::Result<i32> {
                        gate(c.data(), "framebuffer/present", "fb-present")?;
                        if width <= 0 || height <= 0 || stride <= 0 {
                            anyhow::bail!("invalid framebuffer dimensions");
                        }
                        let bytes = read_guest_bytes(&mut c, ptr, len)?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        note(
                            d,
                            format!(
                                "aiueos:host/fb-present bytes={} width={width} height={height} stride={stride}",
                                bytes.len()
                            ),
                        );
                        d.dom.framebuffer.push(FramebufferFrame {
                            bytes,
                            width: width as u32,
                            height: height as u32,
                            stride: stride as u32,
                        });
                        Ok(len)
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "kv-set" => linker
                .func_wrap(
                    "aiueos:host",
                    "kv-set",
                    |mut c: Caller<'_, HostCtx>,
                     k_ptr: i32,
                     k_len: i32,
                     v_ptr: i32,
                     v_len: i32|
                     -> anyhow::Result<()> {
                        gate(c.data(), "storage/kv", "kv-set")?;
                        let key = read_guest_string(&mut c, k_ptr, k_len)?;
                        let value = read_guest_bytes(&mut c, v_ptr, v_len)?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        note(
                            d,
                            format!("aiueos:host/kv-set key={key} bytes={}", value.len()),
                        );
                        d.cloud.kv.insert(key, value);
                        Ok(())
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "kv-get" => linker
                .func_wrap(
                    "aiueos:host",
                    "kv-get",
                    |mut c: Caller<'_, HostCtx>,
                     k_ptr: i32,
                     k_len: i32,
                     buf_ptr: i32,
                     buf_cap: i32|
                     -> anyhow::Result<i32> {
                        gate(c.data(), "storage/kv", "kv-get")?;
                        if buf_cap < 0 {
                            anyhow::bail!("negative kv-get buffer capacity");
                        }
                        let key = read_guest_string(&mut c, k_ptr, k_len)?;
                        let value = c.data().cloud.kv.get(&key).cloned();
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        match value {
                            None => {
                                note(d, format!("aiueos:host/kv-get key={key} miss"));
                                Ok(-1)
                            }
                            Some(bytes) if bytes.len() > buf_cap as usize => {
                                note(
                                    d,
                                    format!(
                                        "aiueos:host/kv-get key={key} buffer-too-small need={} cap={buf_cap}",
                                        bytes.len()
                                    ),
                                );
                                Ok(-2)
                            }
                            Some(bytes) => {
                                note(
                                    d,
                                    format!("aiueos:host/kv-get key={key} bytes={}", bytes.len()),
                                );
                                write_guest_bytes(&mut c, buf_ptr, &bytes)?;
                                Ok(bytes.len() as i32)
                            }
                        }
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "fetch" => linker
                .func_wrap(
                    "aiueos:host",
                    "fetch",
                    |mut c: Caller<'_, HostCtx>,
                     url_ptr: i32,
                     url_len: i32,
                     buf_ptr: i32,
                     buf_cap: i32|
                     -> anyhow::Result<i32> {
                        gate(c.data(), "net/fetch", "fetch")?;
                        if buf_cap < 0 {
                            anyhow::bail!("negative fetch buffer capacity");
                        }
                        let url = read_guest_string(&mut c, url_ptr, url_len)?;
                        let body = c.data().cloud.fetch.get(&url).cloned();
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        match body {
                            None => {
                                note(d, format!("aiueos:host/fetch url={url} no-fixture"));
                                Ok(-1)
                            }
                            Some(bytes) if bytes.len() > buf_cap as usize => {
                                note(
                                    d,
                                    format!(
                                        "aiueos:host/fetch url={url} buffer-too-small need={} cap={buf_cap}",
                                        bytes.len()
                                    ),
                                );
                                Ok(-2)
                            }
                            Some(bytes) => {
                                note(
                                    d,
                                    format!("aiueos:host/fetch url={url} bytes={}", bytes.len()),
                                );
                                write_guest_bytes(&mut c, buf_ptr, &bytes)?;
                                Ok(bytes.len() as i32)
                            }
                        }
                    },
                )
                .map(|_| true)
                .map_err(run_err),

            // ── the computer-use surface providers (ADR-0007) ──────────────────
            // A VIRTUAL screen + synthetic input. Phase-0 keeps them in-process and
            // deterministic (the audit ledger IS the record of what the agent did),
            // exactly like `input-event` / `fb-present` — a testable provider before
            // the real Xvfb-container / microVM backing. Each is gated identically;
            // there is deliberately NO `pointer-host` / `keyboard-host` /
            // `display-host` provider here, so a computer-use component can never
            // reach the operator's real HID (those names hit the `_` arm = unbound).
            "frame" => linker
                .func_wrap(
                    "aiueos:host",
                    "frame",
                    |mut c: Caller<'_, HostCtx>| -> anyhow::Result<i64> {
                        gate(c.data(), "display/frame", "frame")?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        let id = {
                            let base = d.calls as i64; // monotonic in-process handle
                            #[cfg(feature = "computer-backing")]
                            {
                                match backing_mut(d).map(|b| b.frame()) {
                                    Some(fid) if fid != 0 => fid, // the real daemon's frame id
                                    _ => base,
                                }
                            }
                            #[cfg(not(feature = "computer-backing"))]
                            {
                                base
                            }
                        };
                        note(d, format!("aiueos:host/frame id={id}"));
                        Ok(id)
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "pointer-move" => linker
                .func_wrap(
                    "aiueos:host",
                    "pointer-move",
                    |mut c: Caller<'_, HostCtx>, x: i32, y: i32| -> anyhow::Result<()> {
                        gate(c.data(), "pointer/move", "pointer-move")?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        note(d, format!("aiueos:host/pointer-move x={x} y={y}"));
                        #[cfg(feature = "computer-backing")]
                        if let Some(b) = backing_mut(d) {
                            b.pointer_move(x, y);
                        }
                        Ok(())
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "pointer-click" => linker
                .func_wrap(
                    "aiueos:host",
                    "pointer-click",
                    |mut c: Caller<'_, HostCtx>, button: i32| -> anyhow::Result<()> {
                        gate(c.data(), "pointer/click", "pointer-click")?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        note(d, format!("aiueos:host/pointer-click button={button}"));
                        #[cfg(feature = "computer-backing")]
                        if let Some(b) = backing_mut(d) {
                            b.pointer_click(button);
                        }
                        Ok(())
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "key" => linker
                .func_wrap(
                    "aiueos:host",
                    "key",
                    |mut c: Caller<'_, HostCtx>, code: i32| -> anyhow::Result<()> {
                        gate(c.data(), "keyboard/key", "key")?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        note(d, format!("aiueos:host/key code={code}"));
                        #[cfg(feature = "computer-backing")]
                        if let Some(b) = backing_mut(d) {
                            b.key(code);
                        }
                        Ok(())
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            "type" => linker
                .func_wrap(
                    "aiueos:host",
                    "type",
                    |mut c: Caller<'_, HostCtx>, ptr: i32, len: i32| -> anyhow::Result<()> {
                        gate(c.data(), "keyboard/type", "type")?;
                        let bytes = read_guest_bytes(&mut c, ptr, len)?;
                        let d = c.data_mut();
                        charge(d, Charge::Call)?;
                        note(d, format!("aiueos:host/type bytes={}", bytes.len()));
                        #[cfg(feature = "computer-backing")]
                        if let Some(b) = backing_mut(d) {
                            b.type_text(&String::from_utf8_lossy(&bytes));
                        }
                        Ok(())
                    },
                )
                .map(|_| true)
                .map_err(run_err),
            _ => Ok(false),
        }
    }
}

impl crate::surface::Surface {
    fn install(&self, linker: &mut Linker<HostCtx>) -> Result<usize> {
        let mut installed = 0;
        for provider in self.providers() {
            if provider.bind(linker)? {
                installed += 1;
            }
        }
        Ok(installed)
    }
}

fn memory(c: &mut Caller<'_, HostCtx>) -> anyhow::Result<wasmtime::Memory> {
    c.get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| anyhow::anyhow!("guest exports no memory"))
}

fn check_range(ptr: i32, len: i32) -> anyhow::Result<(usize, usize)> {
    if ptr < 0 || len < 0 {
        anyhow::bail!("negative guest pointer/length");
    }
    let start = ptr as usize;
    let len = len as usize;
    let end = start
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("guest pointer range overflow"))?;
    Ok((start, end))
}

fn read_guest_bytes(c: &mut Caller<'_, HostCtx>, ptr: i32, len: i32) -> anyhow::Result<Vec<u8>> {
    let (start, end) = check_range(ptr, len)?;
    let mem = memory(c)?;
    let data = mem.data(&mut *c);
    if end > data.len() {
        anyhow::bail!("guest memory read out of bounds");
    }
    Ok(data[start..end].to_vec())
}

fn read_guest_string(c: &mut Caller<'_, HostCtx>, ptr: i32, len: i32) -> anyhow::Result<String> {
    let bytes = read_guest_bytes(c, ptr, len)?;
    String::from_utf8(bytes).map_err(|e| anyhow::anyhow!("guest string is not utf-8: {e}"))
}

fn write_guest_bytes(c: &mut Caller<'_, HostCtx>, ptr: i32, bytes: &[u8]) -> anyhow::Result<()> {
    let (start, end) = check_range(ptr, bytes.len() as i32)?;
    let mem = memory(c)?;
    let data = mem.data_mut(&mut *c);
    if end > data.len() {
        anyhow::bail!("guest memory write out of bounds");
    }
    data[start..end].copy_from_slice(bytes);
    Ok(())
}

fn write_guest_u8(c: &mut Caller<'_, HostCtx>, ptr: i32, value: u8) -> anyhow::Result<()> {
    write_guest_bytes(c, ptr, &[value])
}

fn write_guest_i32(c: &mut Caller<'_, HostCtx>, ptr: i32, value: i32) -> anyhow::Result<()> {
    write_guest_bytes(c, ptr, &value.to_le_bytes())
}

fn guest_alloc(c: &mut Caller<'_, HostCtx>, len: usize, align: i32) -> anyhow::Result<i32> {
    if len == 0 {
        return Ok(0);
    }
    let realloc = c
        .get_export("cabi_realloc")
        .and_then(|e| e.into_func())
        .ok_or_else(|| anyhow::anyhow!("guest exports no cabi_realloc"))?;
    let mut results = [Val::I32(0)];
    realloc.call(
        &mut *c,
        &[
            Val::I32(0),
            Val::I32(0),
            Val::I32(align),
            Val::I32(len as i32),
        ],
        &mut results,
    )?;
    match results[0] {
        Val::I32(ptr) => Ok(ptr),
        ref other => anyhow::bail!("cabi_realloc returned unexpected value {other:?}"),
    }
}

fn guest_alloc_bytes(c: &mut Caller<'_, HostCtx>, bytes: &[u8]) -> anyhow::Result<i32> {
    let ptr = guest_alloc(c, bytes.len(), 1)?;
    if !bytes.is_empty() {
        write_guest_bytes(c, ptr, bytes)?;
    }
    Ok(ptr)
}

fn note(ctx: &mut HostCtx, event: impl Into<String>) {
    ctx.events.push(event.into());
}

/// The `computer-virtual` backing (ADR-0007), spawned lazily on first use when the
/// operator set `AIUEOS_COMPUTER_BACKING`. `None` keeps the in-process ledger as the
/// only effect. Feature-gated so the default build has no subprocess path at all.
#[cfg(feature = "computer-backing")]
fn backing_mut(ctx: &mut HostCtx) -> Option<&mut crate::backing::Backing> {
    if ctx.backing.is_none() {
        ctx.backing = crate::backing::Backing::from_env();
    }
    ctx.backing.as_mut()
}

/// Instantiate `wasm` (binary or WAT text) with the `aiueos:host` ABI bound, run
/// `entry(args)` under fuel + memory limits with `caps` gating every host call,
/// threading `bus` through. A denied host call traps and surfaces as
/// [`AiueosError::Run`]. No per-topic restriction — see [`run_with_host_restricted`].
pub fn run_with_host(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
) -> Result<HostOutcome> {
    run_with_host_restricted(
        wasm,
        entry,
        args,
        fuel,
        memory_pages,
        caps,
        bus,
        &TopicAccess::unrestricted(),
        crate::manifest::Quota::default(),
    )
}

/// Like [`run_with_host`], but additionally restricts which topic ids the
/// component may publish to / read, per `topics`. A publish/poll/take/count to a
/// topic outside the declared set traps even when the coarse capability is held.
#[allow(clippy::too_many_arguments)]
pub fn run_with_host_restricted(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
    topics: &TopicAccess,
    quota: crate::manifest::Quota,
) -> Result<HostOutcome> {
    run_with_host_restricted_with_kqe(
        wasm,
        entry,
        args,
        fuel,
        memory_pages,
        caps,
        bus,
        KqeStore::default(),
        topics,
        quota,
    )
}

/// Like [`run_with_host_restricted`], but also threads KQE graph state across
/// component launches.
#[allow(clippy::too_many_arguments)]
pub fn run_with_host_restricted_with_kqe(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
    kqe: KqeStore,
    topics: &TopicAccess,
    quota: crate::manifest::Quota,
) -> Result<HostOutcome> {
    run_with_host_restricted_with_kqe_and_llm(
        wasm,
        entry,
        args,
        fuel,
        memory_pages,
        caps,
        bus,
        kqe,
        LlmFixtures::default(),
        topics,
        quota,
    )
}

/// Like [`run_with_host_restricted_with_kqe`], but also wires a deterministic
/// LLM fixture provider for `kotoba:kais/llm.infer`.
#[allow(clippy::too_many_arguments)]
pub fn run_with_host_restricted_with_kqe_and_llm(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
    kqe: KqeStore,
    llm: LlmFixtures,
    topics: &TopicAccess,
    quota: crate::manifest::Quota,
) -> Result<HostOutcome> {
    run_with_host_restricted_with_kqe_llm_dom(
        wasm,
        entry,
        args,
        fuel,
        memory_pages,
        caps,
        bus,
        kqe,
        llm,
        DomSurface::default(),
        topics,
        quota,
    )
}

/// Like [`run_with_host_restricted_with_kqe_and_llm`], but also binds the
/// **browser** surface's `dom/render` + `dom/event` providers (ADR-0005). `dom`
/// seeds the input events delivered to the guest (FIFO) and collects the markup
/// it paints; other surfaces pass [`DomSurface::default`]. The two providers are
/// gated identically to every other host call — a component without `dom/render`
/// / `dom/event` in its conferred set traps, and a surface that doesn't offer
/// them (e.g. `robot`) never confers them in the first place.
#[allow(clippy::too_many_arguments)]
pub fn run_with_host_restricted_with_kqe_llm_dom(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
    kqe: KqeStore,
    llm: LlmFixtures,
    dom: DomSurface,
    topics: &TopicAccess,
    quota: crate::manifest::Quota,
) -> Result<HostOutcome> {
    run_with_host_restricted_with_kqe_llm_dom_cloud(
        wasm,
        entry,
        args,
        fuel,
        memory_pages,
        caps,
        bus,
        kqe,
        llm,
        dom,
        CloudSurface::default(),
        topics,
        quota,
    )
}

/// Like [`run_with_host_restricted_with_kqe_llm_dom`], but also binds the
/// **cloud** surface's `storage/kv` (`kv-set` / `kv-get`) and `net/fetch`
/// (`fetch`) providers (ADR-0005). `cloud` seeds the `net/fetch` fixtures and any
/// initial KV state and collects the KV mutations; other surfaces pass
/// [`CloudSurface::default`]. Every provider is gated identically — a component
/// without `storage/kv` / `net/fetch` traps, and a surface that doesn't offer
/// them never confers them.
#[allow(clippy::too_many_arguments)]
pub fn run_with_host_restricted_with_kqe_llm_dom_cloud(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
    kqe: KqeStore,
    llm: LlmFixtures,
    dom: DomSurface,
    cloud: CloudSurface,
    topics: &TopicAccess,
    quota: crate::manifest::Quota,
) -> Result<HostOutcome> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(run_err)?;
    // Module::new accepts a binary module or WAT text (wasmtime's default `wat`).
    let module = Module::new(&engine, wasm).map_err(run_err)?;

    let mut linker: Linker<HostCtx> = Linker::new(&engine);
    crate::surface::Surface::robot()
        .union(&crate::surface::Surface::browser())
        .union(&crate::surface::Surface::cloud())
        // The computer-use virtual surface (ADR-0007): frame + synthetic pointer/
        // keyboard. Binding only makes the host imports resolvable; the gate still
        // confers them per-component. The host-HID escape hatch (`computer_host`) is
        // deliberately NOT installed here — its providers stay unbound by default.
        .union(&crate::surface::Surface::computer_virtual())
        .install(&mut linker)?;
    linker
        .func_wrap(
            "kotoba:kais/auth@0.1.0",
            "has-capability",
            |mut c: Caller<'_, HostCtx>,
             resource_ptr: i32,
             resource_len: i32,
             ability_ptr: i32,
             ability_len: i32|
             -> anyhow::Result<i32> {
                gate(c.data(), "kotoba.auth/self", "has-capability")?;
                let resource = read_guest_string(&mut c, resource_ptr, resource_len)?;
                let ability = read_guest_string(&mut c, ability_ptr, ability_len)?;
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                let cap = format!("{resource}/{ability}");
                let granted = d.caps.contains(&cap) || d.caps.contains(&format!("{resource}/*"));
                note(
                    d,
                    format!("kotoba:kais/auth.has-capability {resource}/{ability}={granted}"),
                );
                Ok(granted as i32)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/kqe@0.1.0",
            "assert-quad",
            |mut c: Caller<'_, HostCtx>,
             g_ptr: i32,
             g_len: i32,
             s_ptr: i32,
             s_len: i32,
             p_ptr: i32,
             p_len: i32,
             o_ptr: i32,
             o_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let graph = read_guest_string(&mut c, g_ptr, g_len)?;
                let subject = read_guest_string(&mut c, s_ptr, s_len)?;
                let predicate = read_guest_string(&mut c, p_ptr, p_len)?;
                let object = read_guest_bytes(&mut c, o_ptr, o_len)?;
                gate_target(c.data(), "kotoba.graph-write/", &graph, "assert-quad")?;
                let event = format!("kotoba:kais/kqe.assert-quad {graph}/{subject}/{predicate}");
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                d.kqe
                    .quads
                    .entry((graph, subject, predicate))
                    .or_default()
                    .push(object);
                note(d, event);
                write_guest_u8(&mut c, ret, 0)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/kqe@0.1.0",
            "retract-quad",
            |mut c: Caller<'_, HostCtx>,
             g_ptr: i32,
             g_len: i32,
             s_ptr: i32,
             s_len: i32,
             p_ptr: i32,
             p_len: i32,
             o_ptr: i32,
             o_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let graph = read_guest_string(&mut c, g_ptr, g_len)?;
                let subject = read_guest_string(&mut c, s_ptr, s_len)?;
                let predicate = read_guest_string(&mut c, p_ptr, p_len)?;
                let object = read_guest_bytes(&mut c, o_ptr, o_len)?;
                gate_target(c.data(), "kotoba.graph-write/", &graph, "retract-quad")?;
                let event = format!("kotoba:kais/kqe.retract-quad {graph}/{subject}/{predicate}");
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                if let Some(objects) = d.kqe.quads.get_mut(&(graph, subject, predicate)) {
                    objects.retain(|existing| existing != &object);
                }
                note(d, event);
                write_guest_u8(&mut c, ret, 0)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/kqe@0.1.0",
            "get-objects",
            |mut c: Caller<'_, HostCtx>,
             g_ptr: i32,
             g_len: i32,
             s_ptr: i32,
             s_len: i32,
             p_ptr: i32,
             p_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let graph = read_guest_string(&mut c, g_ptr, g_len)?;
                let subject = read_guest_string(&mut c, s_ptr, s_len)?;
                let predicate = read_guest_string(&mut c, p_ptr, p_len)?;
                gate_target(c.data(), "kotoba.graph-read/", &graph, "get-objects")?;
                let event = format!("kotoba:kais/kqe.get-objects {graph}/{subject}/{predicate}");
                {
                    let d = c.data_mut();
                    charge(d, Charge::Call)?;
                }
                let objects = c
                    .data()
                    .kqe
                    .quads
                    .get(&(graph, subject, predicate))
                    .cloned()
                    .unwrap_or_default();
                let count = objects.len();
                let array_ptr = guest_alloc(&mut c, objects.len() * 8, 4)?;
                for (i, object) in objects.iter().enumerate() {
                    let ptr = guest_alloc_bytes(&mut c, object)?;
                    let base = array_ptr + (i * 8) as i32;
                    write_guest_i32(&mut c, base, ptr)?;
                    write_guest_i32(&mut c, base + 4, object.len() as i32)?;
                }
                note(c.data_mut(), format!("{event} count={count}"));
                write_guest_i32(&mut c, ret, array_ptr)?;
                write_guest_i32(&mut c, ret + 4, objects.len() as i32)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/kqe@0.1.0",
            "query",
            |mut c: Caller<'_, HostCtx>,
             filter_ptr: i32,
             filter_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let filter = read_guest_string(&mut c, filter_ptr, filter_len)?;
                let filter = KqeQueryFilter::parse(&filter)?;
                gate_class(c.data(), "kotoba.graph-read/", "query")?;
                if let Some(graph) = &filter.graph {
                    gate_target(c.data(), "kotoba.graph-read/", graph, "query")?;
                }
                {
                    let d = c.data_mut();
                    charge(d, Charge::Call)?;
                }
                let quads: Vec<(String, String, String, Vec<u8>)> =
                    if let Some(query) = &filter.datomic {
                        #[cfg(feature = "kototama")]
                        {
                            c.data().kqe.datomic_query(
                                &c.data().caps,
                                filter.graph.as_deref(),
                                query,
                            )?
                        }
                        #[cfg(not(feature = "kototama"))]
                        {
                            let _ = query;
                            anyhow::bail!("kqe datomic query requires the `kototama` feature");
                        }
                    } else {
                        c.data()
                            .kqe
                            .quads
                            .iter()
                            .filter(|((graph, subject, predicate), _)| {
                                has_target(c.data(), "kotoba.graph-read/", graph)
                                    && filter.matches(graph, subject, predicate)
                            })
                            .flat_map(|((graph, subject, predicate), objects)| {
                                objects.iter().cloned().map(|object| {
                                    (graph.clone(), subject.clone(), predicate.clone(), object)
                                })
                            })
                            .collect()
                    };
                let count = quads.len();
                let array_ptr = guest_alloc(&mut c, quads.len() * 32, 4)?;
                for (i, (graph, subject, predicate, object)) in quads.iter().enumerate() {
                    let graph_ptr = guest_alloc_bytes(&mut c, graph.as_bytes())?;
                    let subject_ptr = guest_alloc_bytes(&mut c, subject.as_bytes())?;
                    let predicate_ptr = guest_alloc_bytes(&mut c, predicate.as_bytes())?;
                    let object_ptr = guest_alloc_bytes(&mut c, object)?;
                    let base = array_ptr + (i * 32) as i32;
                    write_guest_i32(&mut c, base, graph_ptr)?;
                    write_guest_i32(&mut c, base + 4, graph.len() as i32)?;
                    write_guest_i32(&mut c, base + 8, subject_ptr)?;
                    write_guest_i32(&mut c, base + 12, subject.len() as i32)?;
                    write_guest_i32(&mut c, base + 16, predicate_ptr)?;
                    write_guest_i32(&mut c, base + 20, predicate.len() as i32)?;
                    write_guest_i32(&mut c, base + 24, object_ptr)?;
                    write_guest_i32(&mut c, base + 28, object.len() as i32)?;
                }
                note(
                    c.data_mut(),
                    format!(
                        "kotoba:kais/kqe.query {} count={count}",
                        filter.audit_label()
                    ),
                );
                write_guest_u8(&mut c, ret, 0)?;
                write_guest_i32(&mut c, ret + 4, array_ptr)?;
                write_guest_i32(&mut c, ret + 8, quads.len() as i32)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/llm@0.1.0",
            "infer",
            |mut c: Caller<'_, HostCtx>,
             model_ptr: i32,
             model_len: i32,
             prompt_ptr: i32,
             prompt_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let model = read_guest_string(&mut c, model_ptr, model_len)?;
                let prompt = read_guest_bytes(&mut c, prompt_ptr, prompt_len)?;
                gate_target(c.data(), "kotoba.infer/", &model, "infer")?;
                let response = c.data().llm.response(&model).map(Vec::from);
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                note(
                    d,
                    format!(
                        "kotoba:kais/llm.infer model={model} prompt-bytes={}",
                        prompt.len()
                    ),
                );
                if let Some(response) = response {
                    let response_ptr = guest_alloc_bytes(&mut c, &response)?;
                    write_guest_u8(&mut c, ret, 0)?;
                    write_guest_i32(&mut c, ret + 4, response_ptr)?;
                    write_guest_i32(&mut c, ret + 8, response.len() as i32)
                } else {
                    write_guest_u8(&mut c, ret, 1)?;
                    write_guest_i32(&mut c, ret + 4, 0)?;
                    write_guest_i32(&mut c, ret + 8, 0)
                }
            },
        )
        .map_err(run_err)?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(memory_pages as usize * 64 * 1024)
        .build();
    let ctx = HostCtx {
        limits,
        caps: caps.clone(),
        topics: topics.clone(),
        bus,
        logs: Vec::new(),
        events: Vec::new(),
        calls: 0,
        quota,
        publishes: 0,
        seed: run_seed(entry, args, caps),
        kqe,
        llm,
        dom,
        cloud,
        // Lazily spawned on the first forwarded computer-use action (feature only).
        #[cfg(feature = "computer-backing")]
        backing: None,
    };
    let mut store = Store::new(&engine, ctx);
    store.limiter(|c| &mut c.limits);
    store.set_fuel(fuel).map_err(run_err)?;

    let instance = linker.instantiate(&mut store, &module).map_err(run_err)?;
    let f = instance
        .get_func(&mut store, entry)
        .ok_or_else(|| AiueosError::Run(format!("module has no exported function `{entry}`")))?;

    let ty = f.ty(&store);
    let params: Vec<Val> = ty
        .params()
        .enumerate()
        .map(|(i, t)| {
            let a = args.get(i).copied().unwrap_or(0);
            match t {
                ValType::I32 => Val::I32(a as i32),
                _ => Val::I64(a),
            }
        })
        .collect();
    let mut results: Vec<Val> = ty
        .results()
        .map(|t| match t {
            ValType::I32 => Val::I32(0),
            _ => Val::I64(0),
        })
        .collect();

    f.call(&mut store, &params, &mut results).map_err(run_err)?;

    let result = match results.first() {
        Some(Val::I32(v)) => *v as i64,
        Some(Val::I64(v)) => *v,
        None => 0,
        other => {
            return Err(AiueosError::Run(format!(
                "unexpected result kind: {other:?}"
            )))
        }
    };
    let data = store.into_data();
    Ok(HostOutcome {
        result,
        logs: data.logs,
        host_calls: data.calls,
        host_events: data.events,
        bus: data.bus,
        kqe: data.kqe,
        dom_rendered: data.dom.rendered().to_vec(),
        framebuffer_presented: data.dom.framebuffer().to_vec(),
        dom: data.dom,
        cloud: data.cloud,
    })
}
