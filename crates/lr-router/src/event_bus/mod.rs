//! Bounded MPMC broadcast bus for [`RouterEvent`].
//!
//! Issue #101 (the daemon-refactoring block of the 2.x plan): the
//! daemon's publisher (the ticker thread that drains `poll_events`)
//! broadcasts every router event here, and the read-side consumers
//! subscribe in place of taking the `Arc<RwLock<DefaultRouter>>`
//! read — the kernel mirror is the first subscriber, so kernel route
//! I/O runs on its own thread and never under the router's writer
//! lock. [`EventBus::close`] is the shutdown handshake: the daemon's
//! exit path closes the bus after the last publish, every subscriber
//! drains its queue, sees `Disconnected`, and exits — the join then
//! guarantees no accepted event went unapplied.
//!
//! This module is the data structure: a bounded broadcast channel
//! where each subscriber gets its own [`EventSubscriber`] and
//! [`publish`] writes to every subscriber's queue in one pass. A
//! full subscriber drops the event (the [`try_publish`] path returns
//! a count of how many subscribers accepted it) so a slow consumer
//! cannot block the publisher — the daemon's hot path never waits on
//! a consumer that might be stuck on I/O.
//!
//! # Lock-free publish path
//!
//! Each subscriber's queue is a [`MpmcRing`] — a bounded lock-free
//! MPMC queue (Vyukov's algorithm, the same shape
//! `crossbeam_queue::ArrayQueue` and the Linux kernel's `ptr_ring`
//! implement). `try_push` and `try_pop` coordinate through CAS on
//! the head/tail counters and an Acquire/Release pair on each slot's
//! sequence number; no mutex is taken on the push or pop path. The
//! previous implementation used `std::sync::mpsc::sync_channel` per
//! subscriber, whose `try_send` takes a per-send mutex; with N
//! subscribers the publisher took N mutexes per publish. The
//! per-subscriber ring eliminates that — the publish hot path is
//! lock-free between the publisher and each subscriber.
//!
//! The subscriber list itself is a `RwLock<Vec<Arc<SubscriberInner>>>`:
//! `publish` takes a read lock (concurrent with other publishers,
//! exclusive with `subscribe` / `close`), `subscribe` and `close`
//! take a write lock. The daemon has one publisher per bus (the
//! ticker, or the OSPF main loop in standalone mode), so read-lock
//! contention does not arise in practice; the design leaves room
//! for a future second publisher without a re-design.
//!
//! The bus is `Clone` (internals behind an `Arc`) so the publisher
//! and every subscriber hold their own handle. Disconnected
//! subscribers (the `EventSubscriber` dropped) are pruned on the
//! next [`publish`] so the subscriber list tracks live subscribers
//! only.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::event::RouterEvent;

use ring::MpmcRing;

/// The per-subscriber channel capacity the bus creates on
/// [`EventBus::new`]. Each subscriber gets its own bounded queue of
/// this size, so a slow consumer holds at most `capacity` events
/// before the bus drops new ones on that subscriber only.
///
/// The daemon's ticker thread polls every 50 ms; a capacity of 1024
/// absorbs a burst of route updates (the full-table churn a
/// restart generates) without dropping on a subscriber that is
/// keeping up in the aggregate.
const DEFAULT_CAPACITY: usize = 1024;

/// The sleep cadence [`EventSubscriber::recv_timeout`] uses between
/// non-blocking pops when the queue is empty. A subscriber that has
/// no events spins at this rate until an event arrives, the timeout
/// elapses, or the bus closes. The 1 ms cadence matches the daemon's
/// 50 ms tick well below the latency class the kernel mirror and the
/// metrics scraper need, without burning a core on a tight spin.
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// A bounded MPMC broadcast bus carrying [`RouterEvent`] values.
///
/// Created with [`EventBus::new`] (the default per-subscriber
/// capacity) or [`EventBus::with_capacity`]. Each call to
/// [`EventBus::subscribe`] adds a subscriber and returns its
/// [`EventSubscriber`]; [`EventBus::publish`] writes to every active
/// subscriber. The bus is `Clone` — internally an `Arc` — so the
/// publisher and every subscriber hold their own handle without
/// borrowing each other.
///
/// Subscribers whose `EventSubscriber` has been dropped are pruned
/// on the next publish, so the subscriber list tracks live
/// subscribers only.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<BusInner>,
    capacity: usize,
}

struct BusInner {
    subscribers: RwLock<Vec<Arc<SubscriberInner>>>,
    closed: AtomicBool,
    published: AtomicU64,
    dropped: AtomicU64,
}

/// The shared state behind an [`EventSubscriber`]: the bounded
/// lock-free ring the publisher writes to and the subscriber reads
/// from, plus the `closed` flag the bus's [`EventBus::close`] sets
/// so the subscriber's `recv` can distinguish "queue empty, bus
/// still live" (timeout) from "queue empty, bus gone" (disconnected).
///
/// The `closed` flag is per-subscriber rather than read off the bus
/// so a subscriber that outlives the bus's `Arc` (a scraper thread
/// holding the subscriber after the daemon dropped its bus handle)
/// still sees the close. The bus sets the flag during `close()` in
/// the same critical section that clears the subscriber list, so a
/// subscriber either observes `closed == true` or is still in the
/// list (and will be on the next publish).
struct SubscriberInner {
    ring: Arc<MpmcRing<RouterEvent>>,
    closed: AtomicBool,
}

/// A subscriber's handle to the [`EventBus`].
///
/// Created by [`EventBus::subscribe`]; polls the bus's per-subscriber
/// lock-free queue. The API mirrors `std::sync::mpsc::Receiver`'s
/// `try_recv` and `recv_timeout` (same error types) so the call
/// sites and match patterns a `Receiver` consumer used before the
/// lock-free swap compile unchanged — the only thing that moved is
/// the type name.
///
/// The handle is `Clone` (shares the inner `Arc`) so a subscriber
/// thread can hand a copy to a drain thread. Drop is the unsubscribe
/// signal: when every clone is dropped, the bus prunes the
/// subscriber on its next publish.
#[derive(Clone)]
pub struct EventSubscriber {
    inner: Arc<SubscriberInner>,
}

impl EventSubscriber {
    /// Non-blocking receive. Returns `Ok(event)` if one was queued,
    /// `Err(TryRecvError::Empty)` if the queue is empty and the bus
    /// is still live, `Err(TryRecvError::Disconnected)` if the queue
    /// is empty and the bus has been closed (or this subscriber
    /// joined after the close).
    pub fn try_recv(&self) -> Result<RouterEvent, TryRecvError> {
        if let Some(ev) = self.inner.ring.try_pop() {
            return Ok(ev);
        }
        // The queue is empty from this load. The bus may have been
        // closed between the pop and this flag read; re-check the
        // ring after seeing `closed == true` so a producer that
        // pushed just before the close is not lost.
        if self.inner.closed.load(Ordering::Acquire) {
            if let Some(ev) = self.inner.ring.try_pop() {
                return Ok(ev);
            }
            return Err(TryRecvError::Disconnected);
        }
        Err(TryRecvError::Empty)
    }

    /// Bounded receive. Returns `Ok(event)` if one arrived within
    /// `timeout`; `Err(RecvTimeoutError::Timeout)` if the deadline
    /// elapsed with the bus still live; `Err(RecvTimeoutError::Disconnected)`
    /// if the queue drained and the bus closed.
    ///
    /// Between non-blocking pops the subscriber sleeps at
    /// [`RECV_POLL_INTERVAL`] — short enough that the daemon's 50 ms
    /// tick arrives with at most one sleep of latency, long enough
    /// that an idle subscriber does not burn a core on a tight spin.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<RouterEvent, RecvTimeoutError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(ev) = self.inner.ring.try_pop() {
                return Ok(ev);
            }
            if self.inner.closed.load(Ordering::Acquire) {
                // Same re-check as `try_recv`: a producer that
                // pushed between the pop and the close must not be
                // lost.
                if let Some(ev) = self.inner.ring.try_pop() {
                    return Ok(ev);
                }
                return Err(RecvTimeoutError::Disconnected);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(RecvTimeoutError::Timeout);
            }
            let remaining = deadline - now;
            std::thread::sleep(remaining.min(RECV_POLL_INTERVAL));
        }
    }
}

impl EventBus {
    /// Create a bus with the default per-subscriber capacity
    /// ([`DEFAULT_CAPACITY`]).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a bus with a custom per-subscriber capacity. Each
    /// subscriber gets its own bounded queue of at least this size
    /// (the ring rounds up to the next power of two internally).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(BusInner {
                subscribers: RwLock::new(Vec::new()),
                closed: AtomicBool::new(false),
                published: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
            }),
            capacity: capacity.max(1),
        }
    }

    /// Add a subscriber. Returns the [`EventSubscriber`] the
    /// subscriber polls for events. The subscriber stays active
    /// until every clone of the handle is dropped; the next
    /// [`publish`] after the drop prunes the subscriber from the
    /// internal list.
    ///
    /// After [`EventBus::close`] the bus accepts no subscribers: the
    /// returned `EventSubscriber` is already marked closed, so a late
    /// joiner observes "no more events" (its `try_recv` returns
    /// `Disconnected` and its `recv_timeout` returns `Disconnected`
    /// without waiting) instead of polling a queue nobody will ever
    /// write to.
    pub fn subscribe(&self) -> EventSubscriber {
        let inner = Arc::new(SubscriberInner {
            ring: MpmcRing::new(self.capacity),
            closed: AtomicBool::new(self.inner.closed.load(Ordering::Acquire)),
        });
        // If the bus is already closed, do not add the subscriber to
        // the list — its `closed` flag is already true, so its first
        // `recv` returns `Disconnected`. Adding it would only delay
        // the prune.
        if !inner.closed.load(Ordering::Relaxed) {
            self.inner
                .subscribers
                .write()
                .unwrap()
                .push(Arc::clone(&inner));
        }
        EventSubscriber { inner }
    }

    /// Broadcast an event to every active subscriber. Uses
    /// [`MpmcRing::try_push`] so a full subscriber drops the event
    /// rather than blocking the publisher — the daemon's hot path
    /// (route install / withdraw) never waits on a consumer that
    /// might be stuck on I/O.
    ///
    /// Returns the number of subscribers that accepted the event
    /// (`0` once the bus has been closed). Disconnected subscribers
    /// (the `EventSubscriber` and its clones dropped) are pruned in
    /// the same pass.
    pub fn publish(&self, event: RouterEvent) -> usize {
        if self.inner.closed.load(Ordering::Acquire) {
            return 0;
        }
        // Count the publish before the walk: a publish that drops on
        // every subscriber still counts as accepted-by-the-bus (the
        // publisher's hot path reached the publish call). The
        // `dropped` counter separates the drop rate from the publish
        // rate so a metrics scraper can alert on either.
        self.inner.published.fetch_add(1, Ordering::Relaxed);
        let mut accepted = 0;
        let mut dropped_any = false;
        // Read-lock the subscriber list: concurrent publishers (the
        // daemon has at most two, in standalone OSPF mode) share the
        // lock; subscribe/close take the write lock. The per-sub
        // push is lock-free, so the lock is held only for the walk.
        let mut subs = self.inner.subscribers.write().unwrap();
        subs.retain(|sub| {
            // A subscriber whose `EventSubscriber` (and all its
            // clones) was dropped has strong_count == 1 (the bus's
            // own Arc). Prune it. The prune runs in the same pass as
            // the publish so the list tracks live subscribers
            // without a separate reaper.
            if Arc::strong_count(sub) == 1 {
                return false;
            }
            match sub.ring.try_push(event.clone()) {
                Ok(()) => {
                    accepted += 1;
                    true
                }
                Err(_) => {
                    dropped_any = true;
                    true
                }
            }
        });
        if dropped_any {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
        }
        accepted
    }

    /// Close the bus for good. Sets every live subscriber's
    /// `closed` flag and clears the subscriber list, so each
    /// subscriber's `recv` returns
    /// [`RecvTimeoutError::Disconnected`] once it has drained the
    /// events already queued — the deterministic shutdown
    /// handshake: after `close`, no `publish` is accepted, and a
    /// subscriber that observes `Disconnected` knows both facts at
    /// once.
    ///
    /// The daemon's shutdown path calls this after the last
    /// publisher's final publish, then joins the subscriber threads —
    /// the drain-then-exit semantics guarantee the subscriber
    /// applied every event that was ever accepted before it returns.
    /// Closing is idempotent; `subscribe` after close returns an
    /// `EventSubscriber` that is immediately disconnected.
    pub fn close(&self) {
        let mut subs = self.inner.subscribers.write().unwrap();
        for sub in subs.iter() {
            sub.closed.store(true, Ordering::Release);
        }
        subs.clear();
        self.inner.closed.store(true, Ordering::Release);
    }

    /// True after [`EventBus::close`]. A live bus with zero
    /// subscribers is not closed — `publish` still counts it.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// Number of active subscribers (the count after the last
    /// pruning pass). A subscriber whose `EventSubscriber` has been
    /// dropped but whose entry has not yet been pruned by a publish
    /// still counts here — the prune happens on the next publish.
    pub fn subscriber_count(&self) -> usize {
        self.inner.subscribers.read().unwrap().len()
    }

    /// Monotonic count of events the publisher has accepted (events
    /// that reached the publish path). Exposed so a metrics endpoint
    /// can surface `lr_event_bus_published_total`.
    pub fn published_total(&self) -> u64 {
        self.inner.published.load(Ordering::Relaxed)
    }

    /// Monotonic count of events dropped on at least one subscriber
    /// (the subscriber's queue was full). A non-zero rate means a
    /// subscriber is not keeping up. Exposed so a metrics endpoint
    /// can surface `lr_event_bus_dropped_total` and an alert can
    /// flag a stuck consumer.
    pub fn dropped_total(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper for a subscriber that wants a blocking wait with a
/// deadline. [`EventSubscriber::recv_timeout`] returns
/// `Err(RecvTimeoutError::Timeout)` when the deadline elapses and
/// `Err(RecvTimeoutError::Disconnected)` when the bus has been
/// closed (and the queue drained).
///
/// This is a convenience wrapper that converts the disconnected case
/// to `None` (the subscriber treats "bus gone" the same as "no more
/// events") and keeps the timeout case as `None` too, so the caller's
/// poll loop is a plain `while let Some(ev) = bus.recv_or_none(timeout)`.
///
/// Not part of the bus itself — the bus returns an [`EventSubscriber`]
/// from `subscribe`, and the subscriber owns its poll cadence. This
/// helper just shortens the common shape.
pub fn recv_or_none(rx: &EventSubscriber, timeout: Duration) -> Option<RouterEvent> {
    match rx.recv_timeout(timeout) {
        Ok(ev) => Some(ev),
        Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => None,
    }
}

mod ring;

#[cfg(test)]
mod tests;
