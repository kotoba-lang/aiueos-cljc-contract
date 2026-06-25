//! The topic bus — aiueos's in-process publish/subscribe substrate, the ROS-topic
//! analogue. Components don't share memory or call each other directly: a
//! producer `publish`es an i64 sample to a numeric topic id, a consumer `poll`s
//! the latest value. Both go through the broker-mediated host ABI (see
//! [`crate::host`]), so every publish/poll is capability-gated and audited.
//!
//! Phase-0 keeps it deliberately small: latest-value semantics (last write wins)
//! + a per-topic publish count, numeric topic ids, i64 payloads. Queued history,
//! typed messages and named topics are later phases.

use std::collections::{BTreeMap, VecDeque};

/// A numeric topic identifier. Phase-0 uses integers; named topics with their own
/// per-topic capabilities (`topic/scan`, `topic/cmd`) are a later refinement that
/// would also make topic wiring show up as capability-graph edges.
pub type TopicId = i32;

#[derive(Debug, Default, Clone)]
pub struct TopicBus {
    latest: BTreeMap<TopicId, i64>,
    counts: BTreeMap<TopicId, u64>,
    /// Unread samples per topic, oldest-first — drained by `take` so a consumer
    /// never misses a reading (where `latest` would coalesce to the newest).
    queues: BTreeMap<TopicId, VecDeque<i64>>,
}

impl TopicBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `value` to `topic`: update the latest value, bump the publish
    /// count, and enqueue it for FIFO `take`.
    pub fn publish(&mut self, topic: TopicId, value: i64) {
        self.latest.insert(topic, value);
        *self.counts.entry(topic).or_insert(0) += 1;
        self.queues.entry(topic).or_default().push_back(value);
    }

    /// The most recent value on `topic` (peek, non-destructive), or `None`.
    pub fn latest(&self, topic: TopicId) -> Option<i64> {
        self.latest.get(&topic).copied()
    }

    /// Pop the oldest unread sample on `topic` (FIFO), or `None` if drained.
    pub fn take(&mut self, topic: TopicId) -> Option<i64> {
        self.queues.get_mut(&topic).and_then(|q| q.pop_front())
    }

    /// Unread (not-yet-taken) samples on `topic`.
    pub fn pending(&self, topic: TopicId) -> usize {
        self.queues.get(&topic).map_or(0, |q| q.len())
    }

    /// How many times `topic` has been published to.
    pub fn count(&self, topic: TopicId) -> u64 {
        self.counts.get(&topic).copied().unwrap_or(0)
    }

    /// Topics that currently hold a value.
    pub fn topics(&self) -> impl Iterator<Item = TopicId> + '_ {
        self.latest.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_sets_latest_and_counts() {
        let mut bus = TopicBus::new();
        assert_eq!(bus.latest(1), None);
        assert_eq!(bus.count(1), 0);

        bus.publish(1, 10);
        bus.publish(1, 20);
        assert_eq!(bus.latest(1), Some(20), "last write wins");
        assert_eq!(bus.count(1), 2);
    }

    #[test]
    fn take_drains_fifo_oldest_first() {
        let mut bus = TopicBus::new();
        bus.publish(1, 10);
        bus.publish(1, 20);
        bus.publish(1, 30);
        assert_eq!(bus.pending(1), 3);
        assert_eq!(bus.take(1), Some(10), "oldest first");
        assert_eq!(bus.take(1), Some(20));
        assert_eq!(bus.pending(1), 1);
        assert_eq!(bus.latest(1), Some(30), "latest is unaffected by take");
        assert_eq!(bus.take(1), Some(30));
        assert_eq!(bus.take(1), None, "drained");
        assert_eq!(
            bus.count(1),
            3,
            "count is total published, not affected by take"
        );
    }

    #[test]
    fn topics_are_independent() {
        let mut bus = TopicBus::new();
        bus.publish(1, 100);
        bus.publish(2, 200);
        assert_eq!(bus.latest(1), Some(100));
        assert_eq!(bus.latest(2), Some(200));
        assert_eq!(bus.latest(3), None);
        let mut ts: Vec<_> = bus.topics().collect();
        ts.sort();
        assert_eq!(ts, vec![1, 2]);
    }
}
