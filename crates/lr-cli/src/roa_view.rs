//! `show roa` renderer — the runtime API half of `lrctl roa list`
//! (ROADMAP "lrctl roa list", issue #52 follow-up).
//!
//! The renderer reads the live [`lr_bgp::RoaStore`] snapshot and
//! emits one line per ROA entry, mirroring BIRD's `show roa` output:
//!
//! ```text
//! roa-total 2 static 1 rtr 1
//! 203.0.113.0/24 max-length 24 as 64512 source static
//! 198.51.100.0/24 max-length 24 as 64513 source rtr
//! ```
//!
//! The summary line (`roa-total N static S rtr R`) is always emitted,
//! even when the daemon has no store — `roa-total 0 static 0 rtr 0` —
//! so a script can rely on the line shape regardless of the daemon
//! mode. Per-entry lines follow, sorted by `(prefix, max_length, asn)`
//! (the canonical order the store already enforces).
//!
//! Provenance is rendered per-entry via [`lr_bgp::RoaStore::provenance_of`]:
//! `source static` (config `[[roa]]` table only), `source rtr`
//! (RFC 8210 cache only), or `source both` (present in both layers —
//! the dedup case; the static layer survives an RTR cache reset, so
//! it is the "primary" source for operator purposes). An entry not
//! in either layer should not happen (the merged snapshot is the
//! union of the two); the renderer reports `static` as a defensive
//! fallback in that impossible case.
//!
//! # Performance
//!
//! The store's read path is `Arc<RoaTable>` under a short read-lock —
//! the lock is held only long enough to clone the `Arc`. The actual
//! walk runs lock-free on the snapshot, so a `show roa` request
//! never contends with the validation hot path.

use std::fmt::Write as _;
use std::sync::Arc;

use lr_bgp::{RoaStore, RoaTable};

/// Render the full `show roa` body (without the trailing newline —
/// the caller adds one if needed).
///
/// `None` is the daemon mode without a ROA store (OSPF/Babel/BMP/
/// multi-protocol supervisor). The renderer still emits the summary
/// line so the wire shape is stable across daemon modes.
pub fn render(roa_store: Option<&Arc<RoaStore>>) -> String {
    let Some(store) = roa_store else {
        return render_summary(0, 0, 0);
    };
    let snapshot = store.load();
    let total = snapshot.len();
    let static_count = store.static_len();
    let rtr_count = store.rtr_len();
    let mut out = render_summary(total, static_count, rtr_count);
    render_entries(&mut out, &snapshot, store);
    out
}

/// Build the summary line. Three space-separated counters — total,
/// static layer, RTR layer. `static + rtr` may exceed `total` because
/// the same entry present in both layers deduplicates into one in the
/// merged snapshot; the summary preserves the layer counts so the
/// operator can see the duplication.
fn render_summary(total: usize, static_count: usize, rtr_count: usize) -> String {
    let mut out = String::with_capacity(48);
    let _ = writeln!(
        out,
        "roa-total {total} static {static_count} rtr {rtr_count}"
    );
    out
}

/// Walk the merged snapshot and emit one line per entry. Provenance
/// is recovered per-entry via [`RoaStore::provenance_of`], so each
/// line reports the exact layer membership (`static`, `rtr`, or
/// `both`) rather than a coarse table-wide value.
fn render_entries(out: &mut String, snapshot: &Arc<RoaTable>, store: &RoaStore) {
    for entry in snapshot.entries() {
        let source = store.provenance_of(entry).as_str();
        let _ = writeln!(
            out,
            "{} max-length {} as {} source {}",
            entry.prefix, entry.max_length, entry.asn.0, source
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_bgp::roa::RoaTableBuilder;
    use lr_bgp::rtr::client::RoaDelta;
    use lr_bgp::RoaEntry;
    use lr_core::addr::{Asn, Prefix};

    fn entry(prefix: Prefix, max: u8, asn: u32) -> RoaEntry {
        RoaEntry {
            prefix,
            max_length: max,
            asn: Asn(asn),
        }
    }

    fn p4(o: [u8; 4], len: u8) -> Prefix {
        Prefix::new_v4(o, len)
    }

    fn delta(announce: bool, entry: RoaEntry) -> RoaDelta {
        RoaDelta { announce, entry }
    }

    #[test]
    fn no_store_renders_zero_summary() {
        let body = render(None);
        assert!(body.contains("roa-total 0 static 0 rtr 0"), "body: {body}");
        // No per-entry lines.
        assert!(!body.contains("max-length"), "body: {body}");
    }

    #[test]
    fn empty_store_renders_zero_summary() {
        let store = Arc::new(RoaStore::new());
        let body = render(Some(&store));
        assert!(body.contains("roa-total 0 static 0 rtr 0"), "body: {body}");
    }

    #[test]
    fn static_layer_entries_are_listed() {
        let mut b = RoaTableBuilder::new();
        b.add("203.0.113.0/24", None, 64512).unwrap();
        b.add("198.51.100.0/24", Some(26), 64513).unwrap();
        let store = Arc::new(RoaStore::from_table(b.build()));
        let body = render(Some(&store));
        assert!(body.contains("roa-total 2 static 2 rtr 0"), "body: {body}");
        assert!(
            body.contains("203.0.113.0/24 max-length 24 as 64512 source static"),
            "body: {body}"
        );
        assert!(
            body.contains("198.51.100.0/24 max-length 26 as 64513 source static"),
            "body: {body}"
        );
    }

    #[test]
    fn rtr_layer_entries_are_listed() {
        let store = Arc::new(RoaStore::new());
        store.apply_rtr_deltas(&[delta(true, entry(p4([203, 0, 113, 0], 24), 24, 64512))]);
        let body = render(Some(&store));
        assert!(body.contains("roa-total 1 static 0 rtr 1"), "body: {body}");
        // RTR-only: provenance reported as "rtr" since the static
        // layer is empty.
        assert!(
            body.contains("203.0.113.0/24 max-length 24 as 64512 source rtr"),
            "body: {body}"
        );
    }

    #[test]
    fn merged_layers_dedup_total() {
        let store = Arc::new(RoaStore::new());
        let e = entry(p4([203, 0, 113, 0], 24), 24, 64512);
        store.replace_static([e]);
        store.apply_rtr_deltas(&[delta(true, e)]);
        let body = render(Some(&store));
        // Same entry in both layers: total is 1 (dedup), static 1, rtr 1.
        assert!(body.contains("roa-total 1 static 1 rtr 1"), "body: {body}");
        // The entry is rendered once. Per-entry provenance reports
        // "both" because the entry is in the static layer and the
        // RTR layer.
        assert!(
            body.contains("203.0.113.0/24 max-length 24 as 64512 source both"),
            "body: {body}"
        );
        // Exactly one entry line.
        let entry_lines = body.lines().filter(|l| l.contains("max-length")).count();
        assert_eq!(entry_lines, 1, "body: {body}");
    }

    #[test]
    fn entries_are_sorted_canonically() {
        // Insert in reverse order — the snapshot's `entries()` is
        // sorted, so the renderer output is stable.
        let mut b = RoaTableBuilder::new();
        b.add("198.51.100.0/24", None, 64513).unwrap();
        b.add("203.0.113.0/24", None, 64512).unwrap();
        let store = Arc::new(RoaStore::from_table(b.build()));
        let body = render(Some(&store));
        let lines: Vec<&str> = body.lines().filter(|l| l.contains("max-length")).collect();
        assert_eq!(lines.len(), 2);
        // 198.x comes before 203.x (lexicographic on the prefix).
        assert!(lines[0].starts_with("198.51.100.0/24"), "lines: {lines:?}");
        assert!(lines[1].starts_with("203.0.113.0/24"), "lines: {lines:?}");
    }

    #[test]
    fn ipv6_entries_are_rendered() {
        let mut b = RoaTableBuilder::new();
        b.add("2001:db8::/32", Some(48), 64512).unwrap();
        let store = Arc::new(RoaStore::from_table(b.build()));
        let body = render(Some(&store));
        assert!(body.contains("roa-total 1 static 1 rtr 0"), "body: {body}");
        assert!(
            body.contains("2001:db8::/32 max-length 48 as 64512 source static"),
            "body: {body}"
        );
    }
}
