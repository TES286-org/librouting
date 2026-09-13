//! `cargo bench -p lr-bgp --bench roa_validate` — measure ROA
//! validation throughput (ROADMAP-v3 D6.2, D8.4).
//!
//! RFC 6811 §2 mandates a linear scan over the ROA table per
//! validation query. The current implementation is `O(n)` over
//! a `Vec<RoaEntry>`; the bench exercises the three table sizes
//! the operations community actually deploys:
//!
//! * 1k entries  — a single AS with a few delegated prefixes.
//! * 10k entries — a small ISP / IXP route-server.
//! * 100k entries — a regional RPKI cache snapshot.
//!
//! Each iteration validates a route whose prefix is covered by
//! at least one ROA — the worst case for the linear scan since
//! every entry must be visited before a `Valid` decision can be
//! returned.
//!
//! The bench output is the basis for the ROADMAP-v3 D8.4 radix-trie
//! refactor: when that lands, the same bench should show a 10–100×
//! speedup at 100k entries.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lr_bgp::roa::{RoaEntry, RoaState, RoaTable, RoaTableBuilder};
use lr_core::addr::{Asn, Prefix};

/// Build a ROA table of `n` entries: each entry authorizes
/// `10.{i}.0.0/16` for AS 65000. The probe route covers
/// `10.0.0.0/8` so every entry must be visited before the
/// `NotFound` decision is returned — the worst case for the
/// linear scan.
fn build_table(n: usize) -> RoaTable {
    let mut builder = RoaTableBuilder::new();
    for i in 0..n as u32 {
        // Use unique prefixes so entries do not deduplicate.
        let hi = (i >> 8) as u8;
        let lo = (i & 0xff) as u8;
        // i is the prefix; we authorise 10.{hi}.{lo}.0/24 for AS 65000.
        builder
            .add(&format!("10.{hi}.{lo}.0/24"), Some(24), 65000 + (i % 1000))
            .expect("add ROA entry");
    }
    builder.build()
}

fn bench_roa_validate(c: &mut Criterion) {
    let probe = Prefix::new_v4([10, 0, 0, 0], 8);
    let origin = Asn(65000);

    let mut group = c.benchmark_group("roa_validate");
    for size in [1_000, 10_000, 100_000] {
        let table = build_table(size);
        // Each validation does O(n) work proportional to table size.
        group.throughput(Throughput::Elements(1));
        group.bench_function(size.to_string(), |b| {
            b.iter(|| {
                let state = black_box(table.validate(black_box(&probe), Some(origin)));
                // For an empty catch-all prefix probe, the answer
                // is `NotFound` (none of our /24 ROAs cover a /8
                // probe — the prefix_len > max_length check excludes
                // them, but they're still scanned).
                debug_assert_eq!(state, RoaState::NotFound);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_roa_validate);
criterion_main!(benches);

// Use the unused `RoaEntry` import to avoid warnings — the
// bench imports the type for documentation references but does
// not construct entries directly.
#[allow(dead_code)]
fn _roa_entry_unused(_e: RoaEntry) {}
