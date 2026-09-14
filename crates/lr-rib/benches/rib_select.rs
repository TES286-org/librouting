//! `cargo bench -p lr-rib --bench rib_select` — measure Loc-RIB
//! install + best-path throughput (ROADMAP-v3 D6.2, D15).
//!
//! Three scales:
//!
//! * 100 routes  — small enterprise / lab router.
//! * 1 000 routes — medium edge router.
//! * 10 000 routes — large enterprise / IXP edge.
//!
//! Each iteration installs a fresh batch of routes (one per prefix)
//! into an empty Loc-RIB, then iterates `iter_best()` once to scan
//! the resulting table. The `install` path is O(log n) per call
//! (BTreeMap), but the diff-tracking history is O(1) per install;
//! the `iter_best` path is O(n).
//!
//! The bench is the basis for the D15 sharded-RIB refactor: when
//! per-AFI sharding lands, the same bench should show ~2× throughput
//! on mixed v4/v6 workloads.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use lr_core::addr::Prefix;
use lr_core::attr::Attributes;
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
use lr_rib::LocRib;
use std::hint::black_box;

fn make_route(i: u32) -> Route {
    // Build 10.{i/256}.{i%256}.0/24 prefixes — covers 65k distinct
    // /24s in the 10/8 space, more than enough for the largest bench.
    let a = (i >> 8) as u8;
    let b = (i & 0xff) as u8;
    let prefix = Prefix::new_v4([10, a, b, 0], 24);
    Route {
        key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin {
            proto: 1,
            peer: i as u64,
        },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 100 + i),
        next_hop: None,
        attributes: Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

fn bench_rib_install_and_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("rib_select");

    for size in [100u32, 1_000u32, 10_000u32] {
        let routes: Vec<Route> = (0..size).map(make_route).collect();
        group.throughput(Throughput::Elements(size as u64));
        // Bench: install all routes into a fresh LocRib, then walk
        // iter_best() once. The install is the dominant cost in real
        // operation (every UPDATE triggers one install).
        group.bench_function(format!("install_and_scan/{size}"), |b| {
            b.iter_with_setup(
                || routes.clone(),
                |routes| {
                    let mut rib = LocRib::new();
                    for r in routes {
                        rib.install(r);
                    }
                    // Walk the best paths — black_box forces the
                    // compiler to actually execute the iteration.
                    let count = black_box(rib.iter_best().count());
                    assert_eq!(count, size as usize, "all installs must land in the RIB");
                },
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_rib_install_and_scan);
criterion_main!(benches);
