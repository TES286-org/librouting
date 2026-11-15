//! `cargo bench -p lr-router --bench event_bus_publish` — measure
//! the publish-path throughput of the event bus (issue #101 — the
//! daemon-refactoring block's lock-free event bus).
//!
//! The benchmark covers the two shapes the daemon's publish hot path
//! takes:
//!
//! * **single subscriber, full drain** — the kernel mirror's shape:
//!   one subscriber keeps up, so every published event is accepted
//!   and popped before the next publish.
//! * **four subscribers, no drain** — the stress shape: every
//!   subscriber's queue fills, so every publish after the first
//!   `capacity` events drops on every subscriber. The benchmark
//!   measures the drop path, which is the worst-case the daemon
//!   faces when a subscriber is stuck on I/O.
//!
//! The Vyukov MPMC ring the bus uses (see
//! `crates/lr-router/src/event_bus/ring.rs`) is lock-free on the
//! push path: the publisher takes a read lock on the subscriber
//! list, walks it, and pushes to each subscriber's ring through a
//! CAS retry loop with no mutex. The previous implementation took
//! a mutex per `sync_channel::try_send`, so the per-subscriber push
//! was N mutex acquisitions per publish; this bench is the
//! before/after evidence the swap was a real improvement.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lr_core::addr::Prefix;
use lr_router::{EventBus, RouterEvent};

/// Build a `RouterEvent::PrefixAdvertised` — the cheapest variant to
/// construct (no session handle, no route clone).
fn ev(i: u8) -> RouterEvent {
    RouterEvent::PrefixAdvertised(Prefix::new_v4([10, 0, 0, i], 32))
}

/// One subscriber that keeps up: the publisher pushes, the
/// subscriber pops. Measures the uncontended push-then-pop round
/// trip — the kernel-mirror shape.
fn single_subscriber_full_drain(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_bus/single_subscriber_full_drain");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("publish_pop", "default_cap"), |b| {
        b.iter_with_setup(
            || {
                let bus = EventBus::new();
                let rx = bus.subscribe();
                (bus, rx)
            },
            |(bus, rx)| {
                bus.publish(ev(1));
                let _ = rx.try_recv();
            },
        )
    });
    group.finish();
}

/// Four subscribers that do not drain: every publish after the
/// capacity-th drops on every subscriber. Measures the drop path,
/// the worst case the daemon faces when a subscriber is stuck.
fn four_subscribers_no_drain(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_bus/four_subscribers_no_drain");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("publish_drop", "default_cap"), |b| {
        b.iter_with_setup(
            || {
                let bus = EventBus::new();
                let _rxs: Vec<_> = (0..4).map(|_| bus.subscribe()).collect();
                // Pre-fill the queues so every measured publish drops.
                // Default capacity is 1024; fill it.
                for i in 0..1024 {
                    bus.publish(ev((i % 255) as u8));
                }
                bus
            },
            |bus| {
                bus.publish(ev(255));
            },
        )
    });
    group.finish();
}

criterion_group!(
    benches,
    single_subscriber_full_drain,
    four_subscribers_no_drain,
);
criterion_main!(benches);
