//! Tests for the [`EventBus`] — the bounded MPMC broadcast that
//! ROADMAP §"Scaling" item #3 names as the preparation for retiring
//! `Arc<RwLock<DefaultRouter>>`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::{recv_or_none, EventBus};
use crate::event::RouterEvent;
use lr_core::addr::Prefix;

/// A small helper: build a `RouterEvent::PrefixAdvertised` for the
/// test (the cheapest variant to construct — no session handle, no
/// route clone).
fn ev(prefix: [u8; 4], len: u8) -> RouterEvent {
    RouterEvent::PrefixAdvertised(Prefix::new_v4(prefix, len))
}

/// The basic contract: every subscriber gets every event, in order.
#[test]
fn every_subscriber_gets_every_event_in_order() {
    let bus = EventBus::with_capacity(16);
    let rx_a = bus.subscribe();
    let rx_b = bus.subscribe();

    for i in 0..8 {
        bus.publish(ev([10, 0, 0, i], 32));
    }

    let drain = |rx: std::sync::mpsc::Receiver<RouterEvent>| {
        let mut out = Vec::new();
        while let Ok(e) = rx.try_recv() {
            out.push(e);
        }
        out
    };

    let a = drain(rx_a);
    let b = drain(rx_b);
    assert_eq!(a.len(), 8, "subscriber A got every event");
    assert_eq!(b.len(), 8, "subscriber B got every event");
    // Same order on both.
    for (a_e, b_e) in a.iter().zip(b.iter()) {
        assert_eq!(format!("{a_e:?}"), format!("{b_e:?}"));
    }
}

/// `publish` returns the number of subscribers that accepted the
/// event.
#[test]
fn publish_returns_accepted_count() {
    let bus = EventBus::with_capacity(8);
    assert_eq!(bus.publish(ev([10, 0, 0, 1], 32)), 0, "no subscribers");
    let _rx_a = bus.subscribe();
    let _rx_b = bus.subscribe();
    assert_eq!(bus.publish(ev([10, 0, 0, 2], 32)), 2, "both accepted");
}

/// A full subscriber drops the event on that subscriber only; other
/// subscribers still get it. The `dropped_total` counter ticks.
#[test]
fn full_subscriber_drops_other_subscribers_still_get_it() {
    let bus = EventBus::with_capacity(2);
    let rx_slow = bus.subscribe();
    let rx_fast = bus.subscribe();

    // Fill the slow subscriber's channel (capacity 2). The fast
    // subscriber is not yet read from, but its channel also holds 2.
    bus.publish(ev([10, 0, 0, 1], 32));
    bus.publish(ev([10, 0, 0, 2], 32));
    // Both channels are now full (each holds 2).
    assert_eq!(bus.subscriber_count(), 2);

    // One more publish: both channels are full, so both drop. The
    // event is lost on both.
    let accepted = bus.publish(ev([10, 0, 0, 3], 32));
    assert_eq!(accepted, 0, "both channels full → 0 accepted");
    assert_eq!(bus.dropped_total(), 1, "dropped counter ticked once");

    // Drain the fast subscriber; the next publish reaches it.
    let mut fast_got = Vec::new();
    while let Ok(e) = rx_fast.try_recv() {
        fast_got.push(e);
    }
    assert_eq!(fast_got.len(), 2, "fast subscriber drained its 2 events");

    // Now the fast subscriber has room; the slow one is still full.
    let accepted = bus.publish(ev([10, 0, 0, 4], 32));
    assert_eq!(accepted, 1, "fast accepted, slow still full");
    assert_eq!(
        bus.dropped_total(),
        2,
        "dropped counter ticked again (slow)"
    );

    // The fast subscriber got the new event.
    let mut fast_got_2 = Vec::new();
    while let Ok(e) = rx_fast.try_recv() {
        fast_got_2.push(e);
    }
    assert_eq!(fast_got_2.len(), 1, "fast subscriber got the latest event");

    // The slow subscriber never got events 3 or 4.
    let mut slow_got = Vec::new();
    while let Ok(e) = rx_slow.try_recv() {
        slow_got.push(e);
    }
    assert_eq!(slow_got.len(), 2, "slow subscriber only got the first 2");
}

/// A subscriber whose `Receiver` is dropped is pruned on the next
/// publish — the sender list tracks live subscribers only.
#[test]
fn dropped_subscribers_are_pruned_on_publish() {
    let bus = EventBus::with_capacity(8);
    {
        let _rx = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);
    }
    // The receiver is now dropped. subscriber_count still reports 1
    // because the prune happens on the next publish.
    assert_eq!(bus.subscriber_count(), 1, "not yet pruned");
    bus.publish(ev([10, 0, 0, 1], 32));
    assert_eq!(bus.subscriber_count(), 0, "pruned on publish");
    assert_eq!(bus.dropped_total(), 0, "disconnected is not 'dropped'");
}

/// The bus is `Clone` and the clone shares the same internal state —
/// publishing through a clone reaches subscribers on the original.
#[test]
fn clone_shares_state() {
    let bus = EventBus::with_capacity(8);
    let rx = bus.subscribe();
    let bus_clone = bus.clone();

    bus_clone.publish(ev([10, 0, 0, 1], 32));
    let ev_recv = rx.try_recv().expect("clone reached the subscriber");
    assert!(matches!(ev_recv, RouterEvent::PrefixAdvertised(_)));
    assert_eq!(bus.published_total(), 1);
    assert_eq!(
        bus_clone.published_total(),
        1,
        "clone sees the same counters"
    );
}

/// Concurrent publishers and subscribers: many threads publishing
/// and many threads draining, every subscriber gets the total number
/// of events published (no loss when the channel has capacity).
#[test]
fn concurrent_publish_and_drain() {
    const PUBLISHERS: usize = 4;
    const EVENTS_PER_PUBLISHER: usize = 100;
    const SUBSCRIBERS: usize = 3;
    const CAPACITY: usize = PUBLISHERS * EVENTS_PER_PUBLISHER + 64;

    let bus = EventBus::with_capacity(CAPACITY);
    let rxs: Vec<_> = (0..SUBSCRIBERS).map(|_| bus.subscribe()).collect();
    let received: Vec<_> = (0..SUBSCRIBERS)
        .map(|_| Arc::new(AtomicUsize::new(0)))
        .collect();

    // Shutdown signal — the orchestrator sets it after all
    // publishers finish, so subscriber threads know to drain their
    // remaining events and exit. Using a separate AtomicBool avoids
    // the Arc-strong-count race the original design had (each
    // subscriber thread held its own bus clone, so strong_count
    // never dropped to 1).
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bus_arc = Arc::new(bus);
    let mut sub_threads = Vec::new();
    for (rx, count) in rxs.into_iter().zip(received.iter().cloned()) {
        let shutdown = Arc::clone(&shutdown);
        sub_threads.push(thread::spawn(move || {
            loop {
                match recv_or_none(&rx, Duration::from_millis(10)) {
                    Some(_ev) => {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        if shutdown.load(Ordering::Relaxed) {
                            // Publishers are done — drain any
                            // stragglers then exit.
                            while let Ok(_ev) = rx.try_recv() {
                                count.fetch_add(1, Ordering::Relaxed);
                            }
                            break;
                        }
                    }
                }
            }
        }));
    }

    // Spawn publishers.
    let mut pub_threads = Vec::new();
    for i in 0..PUBLISHERS {
        let bus = Arc::clone(&bus_arc);
        pub_threads.push(thread::spawn(move || {
            for j in 0..EVENTS_PER_PUBLISHER {
                bus.publish(ev([10, i as u8, j as u8, 1], 32));
            }
        }));
    }

    // Wait for publishers to finish.
    for t in pub_threads {
        t.join().unwrap();
    }
    // Signal subscribers to drain and exit.
    shutdown.store(true, Ordering::Relaxed);

    for t in sub_threads {
        t.join().unwrap();
    }

    let total_expected = PUBLISHERS * EVENTS_PER_PUBLISHER;
    for (i, count) in received.iter().enumerate() {
        let n = count.load(Ordering::Relaxed);
        assert_eq!(
            n, total_expected,
            "subscriber {i} got {n} events, expected {total_expected}"
        );
    }
}

/// `published_total` and `dropped_total` are monotonic and exposed
/// for observability.
#[test]
fn counters_are_monotonic_and_exposed() {
    let bus = EventBus::with_capacity(2);
    let _rx = bus.subscribe();
    assert_eq!(bus.published_total(), 0);
    assert_eq!(bus.dropped_total(), 0);

    bus.publish(ev([10, 0, 0, 1], 32));
    assert_eq!(bus.published_total(), 1);
    assert_eq!(bus.dropped_total(), 0);

    // Publish without any subscriber — the event reaches the publish
    // path but is not accepted by any subscriber. `published_total`
    // ticks (the publisher accepted the event); `dropped_total` does
    // not (there was no full subscriber to drop on — the list is
    // empty after pruning the disconnected sender from the previous
    // subscriber drop).
    drop(_rx);
    bus.publish(ev([10, 0, 0, 2], 32));
    assert_eq!(
        bus.published_total(),
        2,
        "published ticks on every publish call"
    );
    assert_eq!(bus.dropped_total(), 0, "disconnected is not 'dropped'");
}

/// `with_capacity(0)` is clamped to 1 so the bus always has room for
/// at least one event per subscriber.
#[test]
fn capacity_zero_clamped_to_one() {
    let bus = EventBus::with_capacity(0);
    let rx = bus.subscribe();
    // One event fits.
    assert_eq!(bus.publish(ev([10, 0, 0, 1], 32)), 1);
    // The receiver holds one event; a second publish drops (channel
    // full at capacity 1).
    assert_eq!(bus.publish(ev([10, 0, 0, 2], 32)), 0);
    assert_eq!(bus.dropped_total(), 1);
    // Drain and publish again.
    let _ = rx.try_recv();
    assert_eq!(bus.publish(ev([10, 0, 0, 3], 32)), 1);
}

/// `recv_or_none` returns `None` on timeout and `None` on
/// disconnect (every sender dropped).
#[test]
fn recv_or_none_handles_timeout_and_disconnect() {
    let bus = EventBus::with_capacity(4);
    let rx = bus.subscribe();

    // Timeout — no event within the deadline.
    let start = std::time::Instant::now();
    let result = recv_or_none(&rx, Duration::from_millis(50));
    assert!(result.is_none(), "timeout returns None");
    assert!(
        start.elapsed() >= Duration::from_millis(40),
        "waited at least ~50 ms"
    );

    // Publish and receive.
    bus.publish(ev([10, 0, 0, 1], 32));
    let result = recv_or_none(&rx, Duration::from_millis(50));
    assert!(result.is_some(), "event received");

    // Disconnect — drop the bus (and its clone) so every sender is
    // gone.
    drop(bus);
    let result = recv_or_none(&rx, Duration::from_millis(50));
    assert!(result.is_none(), "disconnect returns None");
}
