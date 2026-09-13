//! Thread-safe, incrementally updatable ROA database — the live half
//! of the RPKI-RTR client integration (ROADMAP-v3 D2.3).
//!
//! [`RoaTable`] is an immutable, sorted entry list: cheap to share,
//! but static. The RTR client (RFC 8210) however produces *delta
//! batches* at every completed sync and a config reload replaces the
//! static entries wholesale — both while other threads are mid-way
//! through validating routes against the table. [`RoaStore`] bridges
//! the two worlds:
//!
//! * **Two provenance layers.** `static` entries come from the local
//!   configuration (`[[roa]]` tables, the FFI surface) and are only
//!   ever replaced by an explicit [`RoaStore::replace_static`] (config
//!   reload). `rtr` entries come from the cache and follow the
//!   protocol lifecycle — cleared on data expiry (RFC 8210 §6: "the
//!   client MUST NOT use data beyond the expire interval") and when
//!   the operator points the daemon at a different cache.
//! * **Atomic snapshot swap.** Every mutation rebuilds the merged
//!   entry set and swaps it in as one `Arc<RoaTable>`. A reader either
//!   sees the previous table or the new one, never a half-applied
//!   sync — the read side is a single `Arc` clone under a read lock,
//!   after which validation runs lock-free on the snapshot. The same
//!   snapshot discipline the RTR client applies per sync (never a
//!   half-applied database) carries through to the readers.
//! * **No new dependencies.** The pattern is `arc-swap`'s semantics
//!   built on `std::sync::RwLock<Arc<_>>`; the write path runs once
//!   per sync/reload (a sort + dedup over a low-thousands entry list)
//!   so the extra rebuild cost is noise.
//!
//! # Poison tolerance
//!
//! Every mutation is a plain field assignment behind the lock — the
//! guarded state is never left invalid — so a panic in *another*
//! writer cannot poison the data for the readers: the lock is
//! recovered via `into_inner()` rather than propagated.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use crate::roa::{RoaEntry, RoaTable};
use crate::rtr::client::RoaDelta;

/// The guarded state: both provenance layers plus the merged snapshot
/// readers validate against.
#[derive(Debug, Default)]
struct RoaStoreInner {
    static_entries: HashSet<RoaEntry>,
    rtr_entries: HashSet<RoaEntry>,
    snapshot: Arc<RoaTable>,
}

/// A live, shared ROA database with two provenance layers
/// (configuration + RTR cache) and atomic whole-table snapshot swaps.
///
/// Clone-free reader path:
///
/// ```no_run
/// use lr_bgp::RoaStore;
/// use lr_core::addr::{Asn, Prefix};
///
/// let store = RoaStore::new();
/// // ... RTR syncs apply deltas, reloads replace the static layer ...
/// let snapshot = store.load();          // Arc<RoaTable>, cheap
/// let prefix = Prefix::new_v4([203, 0, 113, 0], 24);
/// let state = snapshot.validate(&prefix, Some(Asn(64512)));
/// ```
#[derive(Debug, Default)]
pub struct RoaStore {
    inner: RwLock<RoaStoreInner>,
}

impl RoaStore {
    /// Empty store — every validation returns `NotFound` until a
    /// sync or `replace_static` lands.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store seeded with an immutable table as its **static** layer
    /// (the startup configuration path).
    pub fn from_table(table: RoaTable) -> Self {
        let store = Self::new();
        store.replace_static(table.entries().iter().copied());
        store
    }

    /// Load the current merged snapshot. The returned `Arc` keeps the
    /// table alive even if a sync swaps it out mid-validation.
    pub fn load(&self) -> Arc<RoaTable> {
        // Read lock: readers (the validation hot path) run in
        // parallel; they only clone an `Arc` and release.
        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Arc::clone(&inner.snapshot)
    }

    /// Replace the **static** layer (config reload path). RTR-learned
    /// entries are preserved — the cache does not stop talking because
    /// the operator edited a `[[roa]]` table.
    pub fn replace_static(&self, entries: impl IntoIterator<Item = RoaEntry>) {
        let mut inner = self.lock();
        inner.static_entries = entries.into_iter().collect();
        inner.rebuild();
    }

    /// Apply one completed sync's delta batch atomically. Per RFC 8210
    /// §5.6 duplicates coalesce and §12 code-6 unknown withdrawals are
    /// no-ops — both are the natural set semantics here, the caller
    /// decides whether to log them.
    pub fn apply_rtr_deltas(&self, deltas: &[RoaDelta]) {
        if deltas.is_empty() {
            return;
        }
        let mut inner = self.lock();
        for delta in deltas {
            if delta.announce {
                inner.rtr_entries.insert(delta.entry);
            } else {
                inner.rtr_entries.remove(&delta.entry);
            }
        }
        inner.rebuild();
    }

    /// Drop every RTR-learned entry — the data-expiry (RFC 8210 §6)
    /// and cache-change responses. Static entries survive; validation
    /// falls back to the configured table immediately.
    pub fn clear_rtr(&self) {
        let mut inner = self.lock();
        if inner.rtr_entries.is_empty() {
            return;
        }
        inner.rtr_entries.clear();
        inner.rebuild();
    }

    /// Number of entries in the current merged snapshot.
    pub fn len(&self) -> usize {
        self.read().snapshot.len()
    }

    /// True when the merged snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Static-layer entry count (for status lines / diagnostics).
    pub fn static_len(&self) -> usize {
        self.read().static_entries.len()
    }

    /// RTR-layer entry count (for status lines / diagnostics).
    pub fn rtr_len(&self) -> usize {
        self.read().rtr_entries.len()
    }

    /// Read-lock helper with the same poison recovery as `load` —
    /// diagnostics counters share the reader path so they never
    /// contend with each other (the write path runs once per sync).
    fn read(&self) -> std::sync::RwLockReadGuard<'_, RoaStoreInner> {
        match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Write-lock helper with poison recovery: the guarded state is
    /// only ever field-assigned (never mutated in place), so a
    /// poisoned lock still holds a consistent value — recover it
    /// instead of failing every writer forever.
    fn lock(&self) -> std::sync::RwLockWriteGuard<'_, RoaStoreInner> {
        match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl RoaStoreInner {
    /// Rebuild the merged snapshot: union of both layers, deduplicated
    /// and sorted (deterministic — the same entry set always produces
    /// the same table, so status output and tests are stable).
    fn rebuild(&mut self) {
        let entries = self
            .static_entries
            .iter()
            .copied()
            .chain(self.rtr_entries.iter().copied());
        self.snapshot = Arc::new(RoaTable::from_entries(entries));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roa::RoaState;
    use lr_core::addr::{Asn, Prefix};

    fn p4(octets: [u8; 4], len: u8) -> Prefix {
        Prefix::new_v4(octets, len)
    }

    fn entry(prefix: Prefix, max: u8, asn: u32) -> RoaEntry {
        RoaEntry {
            prefix,
            max_length: max,
            asn: Asn(asn),
        }
    }

    fn delta(announce: bool, entry: RoaEntry) -> RoaDelta {
        RoaDelta { announce, entry }
    }

    #[test]
    fn empty_store_not_found() {
        let store = RoaStore::new();
        assert!(store.is_empty());
        assert_eq!(
            store
                .load()
                .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
            RoaState::NotFound
        );
    }

    #[test]
    fn from_table_seeds_static_layer() {
        let mut b = crate::roa::RoaTableBuilder::new();
        b.add("203.0.113.0/24", None, 64512).unwrap();
        let store = RoaStore::from_table(b.build());
        assert_eq!(store.len(), 1);
        assert_eq!(store.static_len(), 1);
        assert_eq!(store.rtr_len(), 0);
        assert_eq!(
            store
                .load()
                .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
            RoaState::Valid
        );
    }

    #[test]
    fn rtr_deltas_announce_and_withdraw() {
        let store = RoaStore::new();
        let e = entry(p4([203, 0, 113, 0], 24), 24, 64512);
        store.apply_rtr_deltas(&[delta(true, e)]);
        assert_eq!(store.rtr_len(), 1);
        assert_eq!(
            store
                .load()
                .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
            RoaState::Valid
        );
        // The same sync withdrawing the record removes it again.
        store.apply_rtr_deltas(&[delta(false, e)]);
        assert_eq!(store.rtr_len(), 0);
        assert_eq!(
            store
                .load()
                .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
            RoaState::NotFound
        );
    }

    #[test]
    fn duplicate_announcement_coalesces() {
        // RFC 8210 §5.6: a duplicate announcement inside one sync is
        // not an error — set semantics coalesce it.
        let store = RoaStore::new();
        let e = entry(p4([203, 0, 113, 0], 24), 24, 64512);
        store.apply_rtr_deltas(&[delta(true, e), delta(true, e)]);
        assert_eq!(store.rtr_len(), 1);
    }

    #[test]
    fn unknown_withdrawal_is_noop() {
        // RFC 8210 §12 code 6: withdrawing a record the client does
        // not hold must not corrupt the table.
        let store = RoaStore::new();
        let e = entry(p4([203, 0, 113, 0], 24), 24, 64512);
        store.apply_rtr_deltas(&[delta(true, e)]);
        store.apply_rtr_deltas(&[delta(false, entry(p4([198, 51, 100, 0], 24), 24, 64513))]);
        assert_eq!(store.rtr_len(), 1);
        assert_eq!(
            store
                .load()
                .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
            RoaState::Valid
        );
    }

    #[test]
    fn replace_static_preserves_rtr_layer() {
        let store = RoaStore::new();
        store.apply_rtr_deltas(&[delta(true, entry(p4([203, 0, 113, 0], 24), 24, 64512))]);
        store.replace_static([entry(p4([198, 51, 100, 0], 24), 24, 64513)]);
        assert_eq!(store.static_len(), 1);
        assert_eq!(store.rtr_len(), 1);
        assert_eq!(store.len(), 2);
        // A second reload with the same set is idempotent.
        store.replace_static([entry(p4([198, 51, 100, 0], 24), 24, 64513)]);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn clear_rtr_preserves_static_layer() {
        let mut b = crate::roa::RoaTableBuilder::new();
        b.add("203.0.113.0/24", None, 64512).unwrap();
        let store = RoaStore::from_table(b.build());
        store.apply_rtr_deltas(&[delta(true, entry(p4([198, 51, 100, 0], 24), 24, 64513))]);
        assert_eq!(store.len(), 2);
        // Data expiry (RFC 8210 §6): the cache-sourced records go,
        // the configured ones stay.
        store.clear_rtr();
        assert_eq!(store.rtr_len(), 0);
        assert_eq!(store.static_len(), 1);
        assert_eq!(
            store
                .load()
                .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
            RoaState::Valid
        );
        assert_eq!(
            store
                .load()
                .validate(&p4([198, 51, 100, 0], 24), Some(Asn(64513))),
            RoaState::NotFound
        );
        // Clearing an already-empty RTR layer is a no-op (no rebuild).
        store.clear_rtr();
        assert_eq!(store.static_len(), 1);
    }

    #[test]
    fn layers_merge_and_dedup() {
        // The same record present in both layers must not double-count.
        let store = RoaStore::new();
        let e = entry(p4([203, 0, 113, 0], 24), 24, 64512);
        store.replace_static([e]);
        store.apply_rtr_deltas(&[delta(true, e)]);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn snapshot_is_deterministic() {
        // Same entries in different insertion orders → same table.
        let a = RoaStore::new();
        a.replace_static([
            entry(p4([203, 0, 113, 0], 24), 24, 64512),
            entry(p4([198, 51, 100, 0], 24), 24, 64513),
        ]);
        let b = RoaStore::new();
        b.replace_static([
            entry(p4([198, 51, 100, 0], 24), 24, 64513),
            entry(p4([203, 0, 113, 0], 24), 24, 64512),
        ]);
        assert_eq!(a.load(), b.load());
    }

    #[test]
    fn concurrent_readers_never_see_partial_state() {
        // Smoke test: readers validate against a snapshot while a
        // writer churns delta batches — every observation must be a
        // fully-applied table state (either the record is present on
        // both sides or absent on both sides, never mid-sync).
        let store = Arc::new(RoaStore::new());
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        let table = store.load();
                        let s1 = table.validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512)));
                        let s2 = table.validate(&p4([198, 51, 100, 0], 24), Some(Asn(64513)));
                        // Both records move together, so a snapshot
                        // that has either must have both.
                        assert_eq!(s1 == RoaState::Valid, s2 == RoaState::Valid);
                    }
                })
            })
            .collect();
        for i in 0..200 {
            let e1 = entry(p4([203, 0, 113, 0], 24), 24, 64512);
            let e2 = entry(p4([198, 51, 100, 0], 24), 24, 64513);
            if i % 2 == 0 {
                store.apply_rtr_deltas(&[delta(true, e1), delta(true, e2)]);
            } else {
                store.apply_rtr_deltas(&[delta(false, e1), delta(false, e2)]);
            }
        }
        for r in readers {
            r.join().expect("reader thread");
        }
        assert!(store.is_empty());
    }
}
