//! `cargo bench -p lr-rib --bench rib_session_teardown` — measure
//! session-scoped Adj-RIB-In/Out iteration cost on multi-peer tables.
//!
//! Exercises the four session-scoped paths that the previous
//! `keys().filter()` shape made O(N) over the *whole* table:
//!
//! * `AdjRibIn::clear_for(origin)` — session teardown (drop one
//!   peer's slice of Adj-RIB-In).
//! * `AdjRibIn::mutate_origin(origin, …)` — GR / LLGR retention pass
//!   (RFC 4724 §4 / RFC 9494 §4.2) that rewrites one peer's slice.
//! * `AdjRibOut::clear_for(dest)` — outbound session teardown.
//! * `AdjRibOut::advertised_keys(dest, family)` — table-refresh
//!   withdrawal bookkeeping for one destination + family.
//!
//! Each shape runs at three scales — a small enterprise router
//! (100 routes / 5 peers), a medium edge (1 000 / 10) and a large
//! IXP edge (10 000 / 20) — so the absolute numbers stay readable
//! across machines. The number of routes per peer stays comparable
//! across scales (~20 / ~100 / ~500) so the per-peer cost is
//! visible alongside the table-scale cost.
//!
//! After the range-bounding fix, every shape is O(K log N) where K
//! is the *peer's* route count and N is the table size. Before the
//! fix, every shape was O(N) — clearing one peer's 100 routes out
//! of a 10 000-route table iterated all 10 000 keys.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lr_core::addr::Prefix;
use lr_core::attr::Attributes;
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
use lr_rib::{AdjRibIn, AdjRibOut};
use std::hint::black_box;

/// Build one IPv4-unicast route for `peer` at prefix index `i`.
fn v4_route(peer: u64, i: u32) -> Route {
    let a = (i >> 8) as u8;
    let b = (i & 0xff) as u8;
    Route {
        key: RouteKey::new(Prefix::new_v4([10, a, b, 0], 24), NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin { proto: 0, peer },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 100 + (i % 50)),
        next_hop: None,
        attributes: Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

/// Build an IPv6-unicast route for `peer` at prefix index `i`.
fn v6_route(peer: u64, i: u32) -> Route {
    let mut addr = [0u8; 16];
    addr[0] = 0x20;
    addr[1] = 0x01;
    addr[2] = 0x0d;
    addr[3] = 0xb8;
    addr[6] = (i >> 8) as u8;
    addr[7] = (i & 0xff) as u8;
    Route {
        key: RouteKey::new(Prefix::new_v6(addr, 48), NlriFamily::IPV6_UNICAST),
        origin: RouteOrigin { proto: 0, peer },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 100 + (i % 50)),
        next_hop: None,
        attributes: Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

/// Populate an AdjRibIn with `routes_per_peer` v4 + `routes_per_peer`
/// v6 routes per peer, across `peer_count` peers. The total table
/// size is `2 * routes_per_peer * peer_count`.
fn populate_adj_rib_in(routes_per_peer: u32, peer_count: u64) -> AdjRibIn {
    let mut rib = AdjRibIn::new();
    for peer in 0..peer_count {
        for i in 0..routes_per_peer {
            let o = RouteOrigin { proto: 0, peer };
            rib.feed_pre_policy(o, v4_route(peer, i));
            rib.feed_pre_policy(o, v6_route(peer, i));
        }
    }
    assert_eq!(
        rib.len(),
        2 * routes_per_peer as usize * peer_count as usize,
        "populated every route"
    );
    rib
}

/// Populate an AdjRibOut with the same shape — every peer receives
/// the same set of v4 + v6 advertisements.
fn populate_adj_rib_out(routes_per_peer: u32, peer_count: u64) -> AdjRibOut {
    let mut rib = AdjRibOut::new();
    for peer in 0..peer_count {
        let dest = RouteOrigin { proto: 0, peer };
        for i in 0..routes_per_peer {
            rib.advertise(dest, &v4_route(peer, i), 1);
            rib.advertise(dest, &v6_route(peer, i), 1);
        }
    }
    assert_eq!(
        rib.len(),
        2 * routes_per_peer as usize * peer_count as usize,
        "populated every advertisement"
    );
    rib
}

const SCALES: [(u32, u64); 3] = [(20, 5), (100, 10), (500, 20)];

fn bench_clear_for_adj_rib_in(c: &mut Criterion) {
    let mut group = c.benchmark_group("adj_rib_in_clear_for");
    for &(routes_per_peer, peer_count) in SCALES.iter() {
        let total = 2 * routes_per_peer as usize * peer_count as usize;
        group.throughput(Throughput::Elements(total as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{total}_routes_{peer_count}_peers")),
            &(routes_per_peer, peer_count),
            |b, &(routes_per_peer, peer_count)| {
                b.iter_with_setup(
                    || populate_adj_rib_in(routes_per_peer, peer_count),
                    |mut rib| {
                        // Drop peer 0's slice; every other peer stays intact.
                        rib.clear_for(RouteOrigin { proto: 0, peer: 0 });
                        black_box(rib.len());
                    },
                );
            },
        );
    }
    group.finish();
}

fn bench_mutate_origin_adj_rib_in(c: &mut Criterion) {
    let mut group = c.benchmark_group("adj_rib_in_mutate_origin");
    for &(routes_per_peer, peer_count) in SCALES.iter() {
        let total = 2 * routes_per_peer as usize * peer_count as usize;
        group.throughput(Throughput::Elements(total as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{total}_routes_{peer_count}_peers")),
            &(routes_per_peer, peer_count),
            |b, &(routes_per_peer, peer_count)| {
                b.iter_with_setup(
                    || populate_adj_rib_in(routes_per_peer, peer_count),
                    |mut rib| {
                        // GR / LLGR-style pass: keep every route, but
                        // touch every attribute bag — the closure runs
                        // once per route of the named origin.
                        let removed = rib.mutate_origin(RouteOrigin { proto: 0, peer: 0 }, Some);
                        black_box((rib.len(), removed));
                    },
                );
            },
        );
    }
    group.finish();
}

fn bench_clear_for_adj_rib_out(c: &mut Criterion) {
    let mut group = c.benchmark_group("adj_rib_out_clear_for");
    for &(routes_per_peer, peer_count) in SCALES.iter() {
        let total = 2 * routes_per_peer as usize * peer_count as usize;
        group.throughput(Throughput::Elements(total as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{total}_routes_{peer_count}_peers")),
            &(routes_per_peer, peer_count),
            |b, &(routes_per_peer, peer_count)| {
                b.iter_with_setup(
                    || populate_adj_rib_out(routes_per_peer, peer_count),
                    |mut rib| {
                        rib.clear_for(RouteOrigin { proto: 0, peer: 0 });
                        black_box(rib.len());
                    },
                );
            },
        );
    }
    group.finish();
}

fn bench_advertised_keys_adj_rib_out(c: &mut Criterion) {
    let mut group = c.benchmark_group("adj_rib_out_advertised_keys");
    for &(routes_per_peer, peer_count) in SCALES.iter() {
        let total = 2 * routes_per_peer as usize * peer_count as usize;
        group.throughput(Throughput::Elements(total as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{total}_routes_{peer_count}_peers")),
            &(routes_per_peer, peer_count),
            |b, &(routes_per_peer, peer_count)| {
                b.iter_with_setup(
                    || populate_adj_rib_out(routes_per_peer, peer_count),
                    |rib| {
                        let v4 = rib.advertised_keys(
                            RouteOrigin { proto: 0, peer: 0 },
                            NlriFamily::IPV4_UNICAST,
                        );
                        let v6 = rib.advertised_keys(
                            RouteOrigin { proto: 0, peer: 0 },
                            NlriFamily::IPV6_UNICAST,
                        );
                        black_box((v4.len(), v6.len()));
                    },
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_clear_for_adj_rib_in,
    bench_mutate_origin_adj_rib_in,
    bench_clear_for_adj_rib_out,
    bench_advertised_keys_adj_rib_out,
);
criterion_main!(benches);
