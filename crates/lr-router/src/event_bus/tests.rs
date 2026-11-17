//! Tests for the [`EventBus`] — the bounded MPMC broadcast that
//! ROADMAP §"Scaling" item #3 names as the preparation for retiring
//! `Arc<RwLock<DefaultRouter>>`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::{recv_or_none, EventBus, EventSubscriber};
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

    let drain = |rx: EventSubscriber| {
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

/// A publish that sees a mix of live and dead subscribers reaches
/// the live ones, skips the dead one (no drop counted on a consumer
/// nobody reads), and prunes the dead one in the same publish —
/// the lazy-prune path under the write lock runs while a live
/// subscriber stays in the list.
#[test]
fn mixed_live_and_dead_subscribers_publish_and_prune() {
    let bus = EventBus::with_capacity(8);
    let rx_live = bus.subscribe();
    {
        let _rx_dead = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
    }
    // The dead subscriber is still listed; the live one gets the
    // event, the dead one is skipped and pruned.
    assert_eq!(bus.publish(ev([10, 0, 0, 1], 32)), 1, "live accepted");
    assert_eq!(bus.subscriber_count(), 1, "dead subscriber pruned");
    assert_eq!(bus.dropped_total(), 0, "a dead subscriber is not a drop");
    assert!(matches!(
        rx_live.try_recv(),
        Ok(RouterEvent::PrefixAdvertised(_))
    ));

    // Dead subscribers on both sides of a live one (head and tail)
    // are skipped and pruned; the live subscriber in the middle
    // still receives the event — the event moves to it even though
    // it is not the last entry in the list.
    drop(rx_live);
    let rx_mid = bus.subscribe();
    {
        let _rx_tail = bus.subscribe();
    }
    assert_eq!(bus.subscriber_count(), 3, "two dead entries still listed");
    assert_eq!(
        bus.publish(ev([10, 0, 0, 2], 32)),
        1,
        "only the live one accepts"
    );
    assert_eq!(bus.subscriber_count(), 1, "both dead subscribers pruned");
    assert_eq!(
        bus.dropped_total(),
        0,
        "dead subscribers never count as drops"
    );
    assert!(matches!(
        rx_mid.try_recv(),
        Ok(RouterEvent::PrefixAdvertised(_))
    ));
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
    //
    // Ordering contract: the store is Release and the load is
    // Acquire. The chain the drain below relies on is: the
    // publishers' ring pushes happen-before the orchestrator's
    // store (the join synchronizes), and the store happens-before
    // the subscriber's post-load ring reads (Release/Acquire
    // synchronizes). With Relaxed on either side the second edge
    // disappears, and on a weakly ordered machine (the riscv64 CI
    // runner, RVWMO) the drain's try_pop can read a stale slot
    // sequence AND a stale tail — the queue looks empty with one
    // published event still invisible — and the single-pass drain
    // exits a subscriber one event short. x86_64's TSO hides the
    // window in practice; the orderings make it correct by
    // construction, not by hardware.
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
                        if shutdown.load(Ordering::Acquire) {
                            // Publishers are done — drain any
                            // stragglers then exit. The
                            // Release/Acquire pair above guarantees
                            // every completed push is visible to
                            // these reads, so the single pass is
                            // complete.
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
    // Signal subscribers to drain and exit. Release pairs with the
    // subscribers' Acquire load — see the ordering contract above.
    shutdown.store(true, Ordering::Release);

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

/// SPSC stress with in-order verification — a regression guard for
/// the ring's `head` / `tail` CAS ordering. The ring's `try_push`
/// fullness pre-check reads `head` with `Acquire`; `try_pop`'s empty
/// pre-check reads `tail` with `Acquire`. The CAS on both counters
/// uses `AcqRel` on success so the write half publishes the counter
/// advance to the other side's `load(Acquire)`. An earlier revision
/// used `Acquire`-only success (write half `Relaxed`); on weakly
/// ordered memory (RISC-V RVWMO, ARM64) a producer could read a
/// stale `head` and `try_push` would return `Err(v)` even though the
/// consumer had freed the slot — `EventBus::publish` does not retry,
/// so the event was dropped. x86_64's TSO hid the window; the
/// riscv64 and s390x native CI runners do not.
///
/// This test runs a single publisher and a single subscriber
/// concurrently on a bus whose capacity exceeds the total event
/// count (the same shape `concurrent_publish_and_drain` above uses
/// for the multi-publisher case). With capacity > total events, a
/// legitimate full is impossible — the queue can hold every event
/// the publisher emits — so any drop is a false full. The
/// subscriber verifies monotonic in-order delivery: every event's
/// sequence equals the previous sequence plus one (mod 256), so a
/// single dropped event surfaces as a gap assertion.
///
/// The capacity buffer (> total events) keeps the test reliable on
/// slow CI runners where the subscriber might briefly fall behind:
/// the queue absorbs the burst without overflowing, and the
/// subscriber catches up. The false-full bug does not depend on the
/// queue being near-full — it depends on a stale `head` read, which
/// can happen at any queue depth — so the test still exercises the
/// ordering contract the fix establishes.
#[test]
fn spsc_stress_no_drops_and_in_order_delivery() {
    const EVENTS: usize = 4_000;
    // Capacity exceeds the total event count: a legitimate full is
    // impossible, so any drop is a false full.
    const CAPACITY: usize = EVENTS + 64;

    let bus = EventBus::with_capacity(CAPACITY);
    let rx = bus.subscribe();

    let received = Arc::new(AtomicUsize::new(0));
    // Start at 255 so the first event (seq 0) satisfies the
    // monotonic check `seq == prev.wrapping_add(1) % 256` (0 == 255+1
    // mod 256 == 0). The publisher emits seq = i % 256 for i in
    // 0..EVENTS, so this chains correctly through every wrap.
    let last_seen = Arc::new(AtomicUsize::new(255));
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Subscriber: drain as fast as possible. The events are
    // PrefixAdvertised for 10.0.N.1 with N = i % 256, so the prefix's
    // third octet is the sequence number — verify monotonic delivery
    // (no reordering, no gaps). When the publisher signals shutdown
    // (after joining), do a final single-pass drain so any stragglers
    // in the queue are observed before exit — the publisher has
    // joined, so no more events will land.
    let rx_thread = {
        let rx = rx.clone();
        let received = Arc::clone(&received);
        let last_seen = Arc::clone(&last_seen);
        let shutdown = Arc::clone(&shutdown);
        thread::spawn(move || loop {
            match rx.try_recv() {
                Ok(RouterEvent::PrefixAdvertised(p)) => {
                    let seq = p.addr.octets()[2] as usize;
                    let prev = last_seen.load(Ordering::Relaxed);
                    // Monotonic: each event's sequence is the
                    // previous plus one (the publisher emits in
                    // order). A gap means a dropped event; an
                    // out-of-order event means the ring's FIFO
                    // contract is broken.
                    assert_eq!(
                        seq,
                        prev.wrapping_add(1) % 256,
                        "event seq {seq} prev {prev}: out of order or dropped"
                    );
                    last_seen.store(seq, Ordering::Relaxed);
                    received.fetch_add(1, Ordering::Relaxed);
                }
                Ok(_) => unreachable!("publisher only emits PrefixAdvertised"),
                Err(_) => {
                    if shutdown.load(Ordering::Acquire) {
                        // Final drain: the publisher has joined, so
                        // every accepted event is already in the
                        // ring (or was dropped). A single pass
                        // observes every queued event.
                        while let Ok(RouterEvent::PrefixAdvertised(p)) = rx.try_recv() {
                            let seq = p.addr.octets()[2] as usize;
                            let prev = last_seen.load(Ordering::Relaxed);
                            assert_eq!(
                                seq,
                                prev.wrapping_add(1) % 256,
                                "drain: event seq {seq} prev {prev}: out of order or dropped"
                            );
                            last_seen.store(seq, Ordering::Relaxed);
                            received.fetch_add(1, Ordering::Relaxed);
                        }
                        break;
                    }
                    std::thread::yield_now();
                }
            }
        })
    };

    // Publisher: emit EVENTS events as fast as possible. The publish
    // hot path does NOT retry on full — a false full drops the event
    // and the assertion at the end fails. With capacity > total
    // events a legitimate full is impossible; any drop is a false
    // full.
    let pub_bus = bus.clone();
    let pub_thread = thread::spawn(move || {
        for i in 0..EVENTS {
            pub_bus.publish(ev([10, 0, (i % 256) as u8, 1], 32));
        }
    });

    pub_thread.join().unwrap();
    // Signal shutdown. The subscriber's final drain pass observes
    // every queued event; the assertion at the end verifies the
    // count matches EVENTS (no drops).
    shutdown.store(true, Ordering::Release);
    rx_thread.join().unwrap();

    assert_eq!(
        received.load(Ordering::Relaxed),
        EVENTS,
        "every event delivered (no false-full drops)"
    );
    assert_eq!(
        bus.dropped_total(),
        0,
        "dropped_total stayed at zero (capacity exceeded total events)"
    );
    assert_eq!(bus.published_total(), EVENTS as u64);
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

/// `close` is the shutdown handshake: queued events still drain, the
/// subscriber then sees `Disconnected`, and later publishes are
/// refused. A live bus with zero subscribers is NOT closed.
#[test]
fn close_drains_then_disconnects_and_refuses_publishes() {
    use std::sync::mpsc::RecvTimeoutError;
    let bus = EventBus::with_capacity(8);
    let rx = bus.subscribe();
    bus.publish(ev([10, 0, 0, 1], 32));
    bus.publish(ev([10, 0, 0, 2], 32));

    // Close after the last publish.
    bus.close();
    assert!(bus.is_closed(), "bus reports closed");

    // The two queued events still drain, in order.
    let first = rx.recv_timeout(Duration::from_millis(100)).ok();
    let second = rx.recv_timeout(Duration::from_millis(100)).ok();
    assert!(matches!(
        (first, second),
        (Some(RouterEvent::PrefixAdvertised(a)), Some(RouterEvent::PrefixAdvertised(b)))
            if a == Prefix::new_v4([10, 0, 0, 1], 32) && b == Prefix::new_v4([10, 0, 0, 2], 32)
    ));
    // Queue empty + every sender dropped → Disconnected.
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(100)),
        Err(RecvTimeoutError::Disconnected)
    ));

    // Publishes after close are refused.
    assert_eq!(bus.publish(ev([10, 0, 0, 3], 32)), 0);
    assert!(matches!(
        rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Disconnected)
    ));
}

/// `close` is idempotent, and a fresh `subscribe` after close gets a
/// `Receiver` that is immediately disconnected (no events, no
/// blocking).
#[test]
fn close_is_idempotent_and_late_subscribers_see_disconnected() {
    let bus = EventBus::with_capacity(4);
    let rx = bus.subscribe();
    bus.close();
    bus.close();
    assert!(bus.is_closed());
    assert!(matches!(
        rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Disconnected)
    ));
    let rx_late = bus.subscribe();
    assert!(
        matches!(
            rx_late.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        ),
        "a subscriber that joined after close sees no events"
    );
}

/// The counters survive `close`: `published_total` keeps the events
/// accepted before the close, `dropped_total` keeps its count — a
/// metrics endpoint scraping after shutdown still reports the
/// daemon's lifetime totals.
#[test]
fn counters_survive_close() {
    let bus = EventBus::with_capacity(2);
    let _rx = bus.subscribe();
    bus.publish(ev([10, 0, 0, 1], 32));
    bus.publish(ev([10, 0, 0, 2], 32));
    // Capacity 2 full — the third publish drops on the subscriber.
    bus.publish(ev([10, 0, 0, 3], 32));
    bus.close();
    assert_eq!(bus.published_total(), 3);
    assert_eq!(bus.dropped_total(), 1);
}

/// A `subscribe` that races with `close` must never return a
/// subscriber whose `closed` flag stays false while the bus is
/// closed — its `recv_timeout` would return `Timeout` forever
/// instead of `Disconnected`, breaking the late-joiner contract the
/// `close_is_idempotent_and_late_subscribers_see_disconnected` test
/// pins for the close-then-subscribe case. The straightforward
/// read-then-push pattern (read `closed` outside the write lock,
/// then push) has a window where the read sees `false`, `close`
/// runs in between, and the push lands in a list `close` had
/// already cleared — the new subscriber's `closed` flag never
/// flips. The re-check under the write lock closes the window.
///
/// The test runs many iterations with many concurrent subscriber
/// threads against one closer per iteration. A buggy implementation
/// would surface at least one subscriber returning `Empty` (queue
/// empty, flag false) instead of `Disconnected`; the fixed
/// implementation returns `Disconnected` for every subscriber once
/// `close` has completed.
#[test]
fn subscribe_concurrent_with_close_always_disconnects() {
    use std::sync::Barrier;

    const ITERATIONS: usize = 200;
    const SUBSCRIBERS: usize = 8;
    let mut failures = 0;
    for _ in 0..ITERATIONS {
        let bus = EventBus::with_capacity(4);
        let barrier = Arc::new(Barrier::new(SUBSCRIBERS + 1));
        let mut threads = Vec::with_capacity(SUBSCRIBERS);
        for _ in 0..SUBSCRIBERS {
            let b = Arc::clone(&barrier);
            let bus_clone = bus.clone();
            threads.push(thread::spawn(move || {
                b.wait();
                bus_clone.subscribe()
            }));
        }
        // Release every subscriber thread, then close immediately so
        // each subscribe's outer `closed` check races close's write
        // lock acquisition.
        barrier.wait();
        bus.close();
        for t in threads {
            let rx = t.join().unwrap();
            if !matches!(
                rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Disconnected)
            ) {
                failures += 1;
            }
        }
    }
    assert_eq!(
        failures, 0,
        "{failures} subscribers did not see Disconnected after close — \
         the subscribe/close race the re-check under the write lock closes"
    );
}
