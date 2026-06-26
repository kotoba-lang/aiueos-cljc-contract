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
//!
//! `poll` of an empty topic returns [`EMPTY`]. The topic bus is threaded *by
//! value* through each run so the broker can pass one bus across a whole booted
//! system — producer → consumer dataflow without shared mutable state.

use crate::error::{AiueosError, Result};
use crate::topic::TopicBus;
use std::collections::BTreeSet;
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Val, ValType,
};

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
    calls: usize,
}

/// What a host-enabled run produced.
pub struct HostOutcome {
    pub result: i64,
    pub logs: Vec<i64>,
    pub host_calls: usize,
    /// The bus after this component ran — pass it to the next component.
    pub bus: TopicBus,
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
) -> Result<HostOutcome> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(run_err)?;
    // Module::new accepts a binary module or WAT text (wasmtime's default `wat`).
    let module = Module::new(&engine, wasm).map_err(run_err)?;

    let mut linker: Linker<HostCtx> = Linker::new(&engine);
    linker
        .func_wrap(
            "aiueos:host",
            "log",
            |mut c: Caller<'_, HostCtx>, v: i64| -> anyhow::Result<()> {
                gate(c.data(), "log/write", "log")?;
                let d = c.data_mut();
                d.logs.push(v);
                d.calls += 1;
                Ok(())
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "clock",
            |mut c: Caller<'_, HostCtx>| -> anyhow::Result<i64> {
                gate(c.data(), "clock/monotonic", "clock")?;
                let tick = c.data().bus.tick() as i64;
                c.data_mut().calls += 1;
                Ok(tick) // monotonic control-loop cycle (Phase-0 clock stand-in)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "random",
            |mut c: Caller<'_, HostCtx>| -> anyhow::Result<i64> {
                gate(c.data(), "random/bytes", "random")?;
                // Deterministic (reproducible) pseudo-random: splitmix64 over the
                // control-loop cycle + this run's call index. Same cycle + same
                // call order → same stream, by design (Phase-0 determinism).
                // NOT a CSPRNG — predictable; never use for keys/nonces/secrets.
                let d = c.data_mut();
                let seed = d
                    .bus
                    .tick()
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(d.calls as u64);
                d.calls += 1;
                Ok(splitmix64(seed) as i64)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "publish",
            |mut c: Caller<'_, HostCtx>, topic: i32, value: i64| -> anyhow::Result<()> {
                gate(c.data(), "topic/publish", "publish")?;
                if !topic_ok(&c.data().topics.publish, topic) {
                    anyhow::bail!("topic {topic} not in this component's :aiueos/publishes set");
                }
                let d = c.data_mut();
                d.bus.publish(topic, value);
                d.calls += 1;
                Ok(())
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "poll",
            |mut c: Caller<'_, HostCtx>, topic: i32| -> anyhow::Result<i64> {
                gate(c.data(), "topic/subscribe", "poll")?;
                if !topic_ok(&c.data().topics.subscribe, topic) {
                    anyhow::bail!("topic {topic} not in this component's :aiueos/subscribes set");
                }
                let v = c.data().bus.latest(topic).unwrap_or(EMPTY);
                c.data_mut().calls += 1;
                Ok(v)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "count",
            |mut c: Caller<'_, HostCtx>, topic: i32| -> anyhow::Result<i64> {
                // how many samples have been published to `topic` — lets a
                // consumer notice missed/extra readings. Same capability as poll.
                gate(c.data(), "topic/subscribe", "count")?;
                if !topic_ok(&c.data().topics.subscribe, topic) {
                    anyhow::bail!("topic {topic} not in this component's :aiueos/subscribes set");
                }
                let n = c.data().bus.count(topic) as i64;
                c.data_mut().calls += 1;
                Ok(n)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "take",
            |mut c: Caller<'_, HostCtx>, topic: i32| -> anyhow::Result<i64> {
                // pop the oldest unread sample (FIFO) so a consumer never misses
                // one; EMPTY when drained. Same capability as poll.
                gate(c.data(), "topic/subscribe", "take")?;
                if !topic_ok(&c.data().topics.subscribe, topic) {
                    anyhow::bail!("topic {topic} not in this component's :aiueos/subscribes set");
                }
                let d = c.data_mut();
                let v = d.bus.take(topic).unwrap_or(EMPTY);
                d.calls += 1;
                Ok(v)
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
        calls: 0,
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
        bus: data.bus,
    })
}
