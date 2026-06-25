//! Direct coverage of the `aiueos:host` ABI surface that the robot pipeline
//! doesn't exercise: the `log` and `clock` host calls, capability attenuation
//! (granted *some* caps but not the needed one), and call accounting
//! (`logs` / `host_calls`). WAT components — `wasm-runtime`, no kototama.
#![cfg(feature = "wasm-runtime")]

use aiueos::host;
use aiueos::topic::TopicBus;
use std::collections::BTreeSet;

const LOGGER: &str = r#"(module
  (import "aiueos:host" "log" (func $log (param i64)))
  (func (export "run") (param $v i64) (result i64)
    (call $log (local.get $v))
    (local.get $v)))"#;

const LOG_TWICE: &str = r#"(module
  (import "aiueos:host" "log" (func $log (param i64)))
  (func (export "run") (param $v i64) (result i64)
    (call $log (local.get $v))
    (call $log (i64.add (local.get $v) (i64.const 1)))
    (local.get $v)))"#;

const CLOCKED: &str = r#"(module
  (import "aiueos:host" "clock" (func $clock (result i64)))
  (func (export "run") (result i64)
    (call $clock)))"#;

// poll (topic 1) then publish (topic 2): needs BOTH subscribe and publish.
const POLL_THEN_PUBLISH: &str = r#"(module
  (import "aiueos:host" "poll"    (func $poll    (param i32) (result i64)))
  (import "aiueos:host" "publish" (func $publish (param i32 i64)))
  (func (export "run") (result i64)
    (local $v i64)
    (local.set $v (call $poll (i32.const 1)))
    (call $publish (i32.const 2) (local.get $v))
    (local.get $v)))"#;

// publishes 10 then 20 to topic 1, returns count(1) → 2.
const PUBLISH_TWICE_COUNT: &str = r#"(module
  (import "aiueos:host" "publish" (func $pub (param i32 i64)))
  (import "aiueos:host" "count"   (func $cnt (param i32) (result i64)))
  (func (export "run") (result i64)
    (call $pub (i32.const 1) (i64.const 10))
    (call $pub (i32.const 1) (i64.const 20))
    (call $cnt (i32.const 1))))"#;

// publishes 10 then 20 to topic 1, returns take(1) → 10 (FIFO oldest, vs poll=20).
const PUBLISH_TWICE_TAKE: &str = r#"(module
  (import "aiueos:host" "publish" (func $pub (param i32 i64)))
  (import "aiueos:host" "take"    (func $take (param i32) (result i64)))
  (func (export "run") (result i64)
    (call $pub (i32.const 1) (i64.const 10))
    (call $pub (i32.const 1) (i64.const 20))
    (call $take (i32.const 1))))"#;

fn caps(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn run(wat: &str, args: &[i64], caps: &BTreeSet<String>) -> aiueos::Result<host::HostOutcome> {
    host::run_with_host(
        wat.as_bytes(),
        "run",
        args,
        1_000_000,
        1,
        caps,
        TopicBus::new(),
    )
}

#[test]
fn log_requires_log_write_and_collects_samples() {
    let o = run(LOGGER, &[7], &caps(&["log/write"])).expect("log granted");
    assert_eq!(o.result, 7);
    assert_eq!(o.logs, vec![7], "logged sample captured");
    assert_eq!(o.host_calls, 1);

    assert!(
        run(LOGGER, &[7], &BTreeSet::new()).is_err(),
        "log without log/write traps"
    );
}

#[test]
fn clock_requires_clock_monotonic() {
    let o = run(CLOCKED, &[], &caps(&["clock/monotonic"])).expect("clock granted");
    assert_eq!(o.result, 0, "Phase-0 monotonic stub");

    assert!(
        run(CLOCKED, &[], &BTreeSet::new()).is_err(),
        "clock without clock/monotonic traps"
    );
}

#[test]
fn host_calls_are_counted() {
    let o = run(LOG_TWICE, &[10], &caps(&["log/write"])).expect("two logs granted");
    assert_eq!(o.logs, vec![10, 11]);
    assert_eq!(o.host_calls, 2, "both host calls counted");
}

#[test]
fn count_reports_publish_count_and_needs_subscribe() {
    // publish twice then count → 2; needs both publish (to publish) and
    // subscribe (to count).
    let o = run(
        PUBLISH_TWICE_COUNT,
        &[],
        &caps(&["topic/publish", "topic/subscribe"]),
    )
    .expect("granted");
    assert_eq!(o.result, 2);

    // count without topic/subscribe traps (only publish granted).
    assert!(
        run(PUBLISH_TWICE_COUNT, &[], &caps(&["topic/publish"])).is_err(),
        "count without topic/subscribe must trap"
    );
}

#[test]
fn take_pops_oldest_fifo_unlike_poll() {
    // take returns the OLDEST unread sample (10), where poll would return the
    // latest (20) — proves FIFO drain semantics.
    let o = run(
        PUBLISH_TWICE_TAKE,
        &[],
        &caps(&["topic/publish", "topic/subscribe"]),
    )
    .expect("granted");
    assert_eq!(o.result, 10);

    // take without topic/subscribe traps.
    assert!(run(PUBLISH_TWICE_TAKE, &[], &caps(&["topic/publish"])).is_err());
}

#[test]
fn capability_attenuation_traps_on_the_missing_one() {
    // Granted subscribe (poll succeeds) but NOT publish → the publish traps even
    // though the component got partway. A capability you weren't given can't be
    // reached, no matter what else you hold.
    let only_sub = caps(&["topic/subscribe"]);
    assert!(
        run(POLL_THEN_PUBLISH, &[], &only_sub).is_err(),
        "publish without topic/publish traps despite holding topic/subscribe"
    );
    // With both, it runs to completion.
    let both = caps(&["topic/subscribe", "topic/publish"]);
    assert!(run(POLL_THEN_PUBLISH, &[], &both).is_ok());
}
