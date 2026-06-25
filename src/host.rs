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
//! | `clock() -> i64`      | `clock/monotonic`  | monotonic tick (Phase-0: 0)      |
//! | `publish(i32, i64)`   | `topic/publish`    | publish a sample to a topic      |
//! | `poll(i32) -> i64`    | `topic/subscribe`  | latest sample on a topic         |
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

/// The store context every host call sees: the conferred capabilities (the gate),
/// the topic bus, and call/log accounting.
pub struct HostCtx {
    limits: StoreLimits,
    caps: BTreeSet<String>,
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
/// [`AiueosError::Run`].
pub fn run_with_host(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
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
                c.data_mut().calls += 1;
                Ok(0) // Phase-0 deterministic monotonic stub.
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "publish",
            |mut c: Caller<'_, HostCtx>, topic: i32, value: i64| -> anyhow::Result<()> {
                gate(c.data(), "topic/publish", "publish")?;
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
                let v = c.data().bus.latest(topic).unwrap_or(EMPTY);
                c.data_mut().calls += 1;
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
