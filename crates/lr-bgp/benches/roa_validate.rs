//! `cargo bench -p lr-bgp --bench roa_validate` — measure ROA
//! validation throughput (ROADMAP-v3 D6.2, D8.4).
//!
//! Since D8.4, `RoaTable::validate` walks a path-compressed prefix
//! trie: the covering ROAs of a route are exactly the trie nodes on
//! the root-to-route path, so a query costs `O(prefix_len)` node
//! visits instead of an `O(n)` scan over the entry list. The bench
//! exercises the two query shapes and the three table sizes the
//! operations community actually deploys:
//!
//! * 1k entries  — a single AS with a few delegated prefixes.
//! * 10k entries — a small ISP / IXP route-server.
//! * 100k entries — a regional RPKI cache snapshot.
//!
//! * `uncovered` validates a route whose prefix no ROA covers — for
//!   the pre-trie linear scan this was the worst case (every entry
//!   visited before the `NotFound` decision); for the trie it is a
//!   shallow walk that terminates at the root.
//! * `covered` validates a route that IS authorized by an exact ROA —
//!   the trie's worst case, walking the full prefix depth to the
//!   matching node.
//!
//! Both query shapes should be flat (roughly constant) across table
//! sizes; if a size shows growth, the trie's path compression has
//! regressed.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use lr_bgp::roa::{RoaEntry, RoaState, RoaTable, RoaTableBuilder};
use lr_core::addr::{Asn, Prefix};
use std::hint::black_box;

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
    let uncovered = Prefix::new_v4([10, 0, 0, 0], 8);
    // An exact /24 from the table: covered and authorized — the
    // deepest possible walk for this shape.
    let covered = Prefix::new_v4([10, 0, 0, 0], 24);
    let origin = Asn(65000);

    let mut group = c.benchmark_group("roa_validate");
    for size in [1_000, 10_000, 100_000] {
        let table = build_table(size);
        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("uncovered-{size}"), |b| {
            b.iter(|| {
                let state = black_box(table.validate(black_box(&uncovered), Some(origin)));
                // No /24 ROA covers a /8 probe: covered stays false.
                debug_assert_eq!(state, RoaState::NotFound);
            });
        });
        group.bench_function(format!("covered-{size}"), |b| {
            b.iter(|| {
                let state = black_box(table.validate(black_box(&covered), Some(origin)));
                // 10.0.0.0/24 with origin AS 65000 + (0 % 1000): the
                // first entry's origin, authorized by max_length 24.
                debug_assert_eq!(state, RoaState::Valid);
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
