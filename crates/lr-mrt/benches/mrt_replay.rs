//! `cargo bench -p lr-mrt --bench mrt_replay` — real-data replay
//! throughput: parse a public MRT RIB dump, install every route into
//! a fresh `LocRib`, measure the install rate.
//!
//! The bench is the criterion harness for the issue #101 "Benchmark
//! Based on Real Data" item. The CLI tool `lr bench replay --mrt
//! <file>` runs the same workload outside criterion and also reports
//! memory and path-selection correctness; this bench focuses on the
//! install-throughput axis so criterion's regression-detection bot
//! can track drift on the storage hot path.
//!
//! # Dump selection
//!
//! The bench reads `LR_BENCH_MRT` (an absolute path to a `.mrt`
//! file, typically a RouteViews `bview.` dump gunzipped by
//! `tests/bench/real_data.sh`). When the env var is unset or the
//! path is not readable, the bench falls back to a small synthetic
//! dump built in-process so the bench is never dead code on a
//! runner without network egress.
//!
//! The synthetic dump carries 1 000 prefixes with one path each and
//! empty attribute sets — the same shape the unit tests use, scaled
//! to give criterion a non-trivial sample size. A real RouteViews
//! IPv4 RIB carries ~1M prefixes with non-empty attribute sets; the
//! throughput numbers from a real dump are the ones to track for
//! regression.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use lr_core::addr::{Asn, IpAddr, Prefix};
use lr_core::attr::Attributes;
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
use lr_mrt::{decode_attributes, MrtRecord, PeerEntry, RibEntry};
use lr_rib::LocRib;

/// Build a synthetic `n`-prefix dump so the bench always has
/// something to measure. Each prefix is `10.{i/256}.{i%256}.0/24`,
/// one entry per prefix, empty attribute set.
fn synthetic_routes(n: u32) -> Vec<Route> {
    (0..n)
        .map(|i| {
            let a = (i >> 8) as u8;
            let b = (i & 0xff) as u8;
            let prefix = Prefix::new_v4([10, a, b, 0], 24);
            let entry = RibEntry {
                peer_index: 0,
                originated_time: 1_700_000_000 + i,
                path_id: 0,
                attributes: Vec::new(),
            };
            route_from_entry(prefix, NlriFamily::IPV4_UNICAST, &entry)
        })
        .collect()
}

/// Convert one MRT RIB entry into a `Route`, mirroring the CLI
/// bench's `build_route` so the criterion bench measures the same
/// install path the CLI does.
fn route_from_entry(prefix: Prefix, family: NlriFamily, entry: &RibEntry) -> Route {
    let attrs: Attributes = decode_attributes(&entry.attributes);
    let local_pref = 100;
    Route {
        key: RouteKey::new(prefix, family),
        origin: RouteOrigin {
            proto: 1,
            peer: entry.peer_index as u64,
        },
        protocol: Protocol::Bgp,
        preference: Preference::new(Protocol::Bgp.default_admin_distance(), local_pref),
        next_hop: None,
        attributes: attrs,
        age_ms: (entry.originated_time as u64) * 1000,
        path_id: entry.path_id,
        tag: None,
    }
}

/// Load routes from `LR_BENCH_MRT` if set and readable; otherwise
/// build the synthetic set of `n` routes.
fn load_routes(n: u32) -> (Vec<Route>, &'static str) {
    if let Ok(path) = std::env::var("LR_BENCH_MRT") {
        if let Ok(records) = lr_mrt::parse_file(&path) {
            let mut out = Vec::new();
            for record in &records {
                if let MrtRecord::Rib(table) = record {
                    let family = if table.prefix.is_ipv4() {
                        NlriFamily::IPV4_UNICAST
                    } else {
                        NlriFamily::IPV6_UNICAST
                    };
                    for entry in &table.entries {
                        out.push(route_from_entry(table.prefix, family, entry));
                    }
                }
            }
            if !out.is_empty() {
                return (out, "real");
            }
        }
    }
    (synthetic_routes(n), "synthetic")
}

// Keep the `PeerEntry` import honest — the bench's real-data path
// references the type when a future enrichment surfaces peer
// identity in the Route's origin. The binding never fires today;
// dropping it would let the import lint fire on a clean build.
fn _peer_entry_anchor() -> PeerEntry {
    PeerEntry {
        bgp_id: 0,
        ip: IpAddr::V4([0; 4]),
        asn: Asn(0),
    }
}

fn bench_mrt_replay_install(c: &mut Criterion) {
    // The synthetic fallback is 1 000 routes — small enough to keep
    // the bench under criterion's per-iteration budget on a slow
    // runner, large enough that the install path's per-call overhead
    // is amortised. A real dump carries whatever `LR_BENCH_MRT`
    // points at; the throughput label adapts.
    let (routes, source) = load_routes(1_000);
    let n = routes.len() as u64;
    let _ = _peer_entry_anchor();

    let mut group = c.benchmark_group("mrt_replay");
    group.throughput(Throughput::Elements(n));
    group.sample_size(10);
    group.bench_function(BenchmarkId::new("install", source), |b| {
        b.iter_with_setup(
            || routes.clone(),
            |routes| {
                let rib = LocRib::new();
                let mut installed = 0usize;
                for r in &routes {
                    if rib.install(r.clone()) {
                        installed += 1;
                    }
                }
                let len = black_box(rib.len());
                assert_eq!(len, routes.len(), "every install must land in the RIB");
                assert_eq!(installed, routes.len());
            },
        );
    });
    group.finish();
}

criterion_group!(benches, bench_mrt_replay_install);
criterion_main!(benches);
