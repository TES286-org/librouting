//! Bounded MPMC broadcast bus for [`RouterEvent`].
//!
//! ROADMAP §"Scaling" item #3 (the multi-threaded RIB + lock-free
//! event bus) names this module as the preparation for retiring
//! `Arc<RwLock<DefaultRouter>>`: the daemon's read-side consumers
//! (the ticker, the API socket, the metrics endpoint, the BMP
//! mirror, the kernel mirror) subscribe to the bus instead of taking
//! the router's read lock, and a local view kept in sync by the
//! events replaces the shared lock for those reads. The write side
//! (import, reselect, export) proceeds concurrently once the RIB
//! gains per-shard locks; the bus is what lets the API thread read
//! without waiting for the writer.
//!
//! This module is the data structure: a bounded broadcast channel
//! where each subscriber gets its own [`Receiver`] and [`publish`]
//! writes to every subscriber's channel in one pass. A full
//! subscriber drops the event (the [`try_publish`] path returns a
//! count of how many subscribers accepted it) so a slow consumer
//! cannot block the publisher — the daemon's hot path never waits on
//! a consumer that might be stuck on I/O.
//!
//! The bus is `Clone` (internals behind an `Arc`) so the publisher
//! and every subscriber hold their own handle. Disconnected
//! subscribers (the `Receiver` dropped) are pruned on the next
//! [`publish`] so the sender list does not grow monotonically as
//! subscribers come and go.
//!
//! The implementation uses [`std::sync::mpsc::sync_channel`] per
//! subscriber — bounded, and the standard-library choice the rest of
//! the daemon already makes (the RTR client, the ROA loader, the
//! multi-protocol supervisor all use `sync_channel`). A lock-free
//! SPSC ring buffer per subscriber is the follow-up optimisation the
//! ROADMAP names; the contract this module exposes (bounded
//! broadcast, drop-on-full, subscriber pruning) stays stable across
//! that swap.

use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::event::RouterEvent;

/// The per-subscriber channel capacity the bus creates on
/// [`EventBus::new`]. Each subscriber gets its own bounded channel
/// of this size, so a slow consumer holds at most `capacity` events
/// before the bus drops new ones on that subscriber only.
///
/// The daemon's ticker thread polls every 50 ms; a capacity of 1024
/// absorbs a burst of route updates (the full-table churn a
/// restart generates) without dropping on a subscriber that is
/// keeping up in the aggregate.
const DEFAULT_CAPACITY: usize = 1024;

/// A bounded MPMC broadcast bus carrying [`RouterEvent`] values.
///
/// Created with [`EventBus::new`] (the default per-subscriber
/// capacity) or [`EventBus::with_capacity`]. Each call to
/// [`EventBus::subscribe`] adds a subscriber and returns its
/// [`Receiver`]; [`EventBus::publish`] writes to every active
/// subscriber. The bus is `Clone` — internally an `Arc` — so the
/// publisher and every subscriber hold their own handle without
/// borrowing each other.
///
/// Subscribers whose `Receiver` has been dropped are pruned on the
/// next publish, so the sender list tracks live subscribers only.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<Mutex<BusInner>>,
    capacity: usize,
}

struct BusInner {
    senders: Vec<SyncSender<RouterEvent>>,
    /// Monotonic count of events the publisher has accepted (the
    /// events that reached at least one subscriber). Exposed for
    /// observability — a daemon's metrics endpoint can surface
    /// `lr_event_bus_published_total` and `lr_event_bus_dropped_total`
    /// without holding the bus lock.
    published: u64,
    /// Monotonic count of events dropped on at least one subscriber
    /// (the subscriber's channel was full and `try_send` failed).
    /// A non-zero rate here means a subscriber is not keeping up;
    /// the daemon's metrics can flag it.
    dropped: u64,
}

impl EventBus {
    /// Create a bus with the default per-subscriber capacity
    /// ([`DEFAULT_CAPACITY`]).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a bus with a custom per-subscriber capacity. Each
    /// subscriber gets its own bounded channel of this size.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BusInner {
                senders: Vec::new(),
                published: 0,
                dropped: 0,
            })),
            capacity: capacity.max(1),
        }
    }

    /// Add a subscriber. Returns the [`Receiver`] the subscriber
    /// polls for events. The subscriber stays active until the
    /// `Receiver` is dropped; the next [`publish`] after the drop
    /// prunes the sender from the internal list.
    pub fn subscribe(&self) -> Receiver<RouterEvent> {
        let (tx, rx) = sync_channel(self.capacity);
        let mut inner = self.inner.lock().unwrap();
        inner.senders.push(tx);
        rx
    }

    /// Broadcast an event to every active subscriber. Uses
    /// [`SyncSender::try_send`] so a full subscriber drops the event
    /// rather than blocking the publisher — the daemon's hot path
    /// (route install / withdraw) never waits on a consumer that
    /// might be stuck on I/O.
    ///
    /// Returns the number of subscribers that accepted the event.
    /// Disconnected subscribers (the `Receiver` dropped) are pruned
    /// in the same pass.
    pub fn publish(&self, event: RouterEvent) -> usize {
        let mut inner = self.inner.lock().unwrap();
        inner.published = inner.published.saturating_add(1);
        let mut accepted = 0;
        let mut dropped_any = false;
        // `try_send` is non-blocking: `Ok(())` accepted, `Err(Full)`
        // drops on this subscriber, `Err(Disconnected)` prunes the
        // sender. Retain the live senders in one pass.
        inner.senders.retain(|tx| match tx.try_send(event.clone()) {
            Ok(()) => {
                accepted += 1;
                true
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                dropped_any = true;
                true
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
        });
        if dropped_any {
            inner.dropped = inner.dropped.saturating_add(1);
        }
        accepted
    }

    /// Number of active subscribers (the sender count after the last
    /// pruning pass). A subscriber whose `Receiver` has been dropped
    /// but whose sender has not yet been pruned by a `publish` call
    /// still counts here — the prune happens on the next publish.
    pub fn subscriber_count(&self) -> usize {
        self.inner.lock().unwrap().senders.len()
    }

    /// Monotonic count of events the publisher has accepted (events
    /// that reached the publish path). Exposed so a metrics endpoint
    /// can surface `lr_event_bus_published_total`.
    pub fn published_total(&self) -> u64 {
        self.inner.lock().unwrap().published
    }

    /// Monotonic count of events dropped on at least one subscriber
    /// (the subscriber's channel was full). A non-zero rate means a
    /// subscriber is not keeping up. Exposed so a metrics endpoint
    /// can surface `lr_event_bus_dropped_total` and an alert can
    /// flag a stuck consumer.
    pub fn dropped_total(&self) -> u64 {
        self.inner.lock().unwrap().dropped
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper for a subscriber that wants a blocking wait with a
/// deadline. The standard library's `Receiver::recv_timeout` returns
/// `Err(RecvTimeoutError::Timeout)` when the deadline elapses and
/// `Err(RecvTimeoutError::Disconnected)` when every sender has been
/// dropped (the bus was dropped or all clones were dropped).
///
/// This is a convenience wrapper that converts the disconnected case
/// to `None` (the subscriber treats "bus gone" the same as "no more
/// events") and keeps the timeout case as `None` too, so the caller's
/// poll loop is a plain `while let Some(ev) = bus.recv_or_none(timeout)`.
///
/// Not part of the bus itself — the bus returns a plain `Receiver`
/// from `subscribe`, and the subscriber owns its poll cadence. This
/// helper just shortens the common shape.
pub fn recv_or_none(rx: &Receiver<RouterEvent>, timeout: Duration) -> Option<RouterEvent> {
    match rx.recv_timeout(timeout) {
        Ok(ev) => Some(ev),
        Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => None,
    }
}

#[cfg(test)]
mod tests;
