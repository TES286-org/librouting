//! Link-state database (per area). Stores LSAs keyed by (type, ls_id, adv).

use core::fmt;
use std::collections::BTreeMap;

use crate::lsa::{Lsa, LsaHeader, LsaKey};

/// RFC 2328 §14: LSAs are refreshed before they reach MaxAge.
pub const MAX_AGE_SECS: u16 = 3_600;
/// RFC 2328 §14.1: default self-originated LSA refresh interval.
pub const LS_REFRESH_TIME_SECS: u16 = 1_800;
/// RFC 2328 §12.1.2: the first sequence number of a newly originated LSA.
const INITIAL_SEQUENCE_NUMBER: u32 = 0x8000_0001;
/// RFC 2328 §12.1.2: the largest sequence number an LSA may carry.
const MAX_SEQUENCE_NUMBER: u32 = 0x7fff_ffff;

/// Whether an LSA sequence number is inside the usable space
/// `0x80000001..=0x7fffffff` (RFC 2328 §12.1.2). `0x80000000` is
/// reserved and must never be used. Values in the low half of the
/// circular space (`0x00000000..=0x7ffffffe`) cannot be produced by
/// legitimate origination — LSAs are started at `0x80000001` and
/// flushed rather than wrapped past `0x7fffffff` — so they are treated
/// as malformed instead of being compared (an instance such as
/// `0x00000001` would otherwise compare "newer" than a stored
/// `0x80000001` and poison the watermark).
fn sequence_in_range(seq: u32) -> bool {
    seq >= INITIAL_SEQUENCE_NUMBER || seq == MAX_SEQUENCE_NUMBER
}

/// Outcome of installing one LSA instance (RFC 2328 §13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// No previous instance existed; the LSA was added.
    New,
    /// The instance was newer and replaced the previous one.
    Replaced,
    /// Duplicate or older instance; the database is unchanged.
    Ignored,
    /// A MaxAge instance purged the previous entry from the database.
    Purged,
}

impl InstallOutcome {
    /// Whether the install changed the database (and thus whether the LSA
    /// should be flooded onward and routes recomputed).
    pub fn changed(self) -> bool {
        !matches!(self, InstallOutcome::Ignored)
    }
}

/// An LSA entry in the LSDB. Carries the LSA itself + an installation age.
#[derive(Debug, Clone)]
pub struct LsaEntry {
    pub lsa: Lsa,
    /// Wallclock time at install, in milliseconds (caller-provided clock).
    pub installed_ms: u64,
}

/// One area's LSDB.
#[derive(Default)]
pub struct Lsdb {
    entries: BTreeMap<LsaKey, LsaEntry>,
    /// Sequence number watermark — used to detect newer instances.
    seq_watermark: BTreeMap<LsaKey, u32>,
    /// Monotonic content revision counter, bumped on every install or
    /// removal that changes the database. Reads of derived projections
    /// (the SRv6 database, the BGP-LS projection, ...) use it as a
    /// cheap invalidation token: instead of re-walking the LSDB on
    /// every SPF run, the caller caches the projection keyed by
    /// `(lsdb_pointer, version)` and recomputes only when the version
    /// moves. The counter is bumped exactly when
    /// [`InstallOutcome::changed`] is true for an [`install`](Self::install)
    /// and when [`remove`](Self::remove) returns `Some` — refresh
    /// re-writes and `Ignored` installs leave it untouched so a pure
    /// refresh tick (RFC 2328 §14.1) does not invalidate caches built
    /// from the previous content.
    version: u64,
}

impl Lsdb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Monotonic content revision counter — bumped on every
    /// [`install`](Self::install) or [`remove`](Self::remove) that
    /// changes the database. A caller that maintains a derived
    /// projection (for example the SRv6 database in
    /// [`crate::srv6db::Srv6Database::from_lsdb`]) reads it before and
    /// after the rebuild and reuses the cached projection whenever the
    /// value has not moved.
    ///
    /// The counter never wraps in practice: at the OSPF maximum LSA
    /// arrival rate of one content-changing install per millisecond it
    /// would take ~584 million years to overflow `u64`.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Install one LSA instance (RFC 2328 §13): newer instances replace
    /// the stored copy, duplicates and older instances are ignored, and an
    /// instance aged to MaxAge purges the LSA from the database.
    ///
    /// The [`version`](Self::version) counter is bumped exactly when the
    /// install changes the database ([`InstallOutcome::changed`] is
    /// true). `Ignored` installs leave the counter — and every cache
    /// keyed on it — untouched.
    pub fn install(&mut self, lsa: Lsa, now_ms: u64) -> InstallOutcome {
        let key = lsa.key();
        if lsa.header.ls_age >= MAX_AGE_SECS {
            // §13: a MaxAge instance flushes the LSA (and its watermark so
            // re-origination may restart at the initial sequence number).
            return if self.entries.remove(&key).is_some() {
                self.seq_watermark.remove(&key);
                self.version = self.version.wrapping_add(1);
                InstallOutcome::Purged
            } else {
                InstallOutcome::Ignored
            };
        }
        // Accept if newer than what we have (signed sequence space,
        // §12.1.2). Out-of-range sequence numbers (the reserved
        // 0x80000000 and the unreachable wrap region) are rejected
        // outright — never compared, so a malformed instance cannot be
        // treated as newer than a valid one or poison the watermark.
        if !sequence_in_range(lsa.header.ls_sequence_number) {
            return InstallOutcome::Ignored;
        }
        let prev_seq = self.seq_watermark.get(&key).copied().unwrap_or(0);
        if (lsa.header.ls_sequence_number as i32) <= (prev_seq as i32) && prev_seq != 0 {
            return InstallOutcome::Ignored;
        }
        self.seq_watermark
            .insert(key, lsa.header.ls_sequence_number);
        let outcome = if self.entries.contains_key(&key) {
            InstallOutcome::Replaced
        } else {
            InstallOutcome::New
        };
        self.entries.insert(
            key,
            LsaEntry {
                lsa,
                installed_ms: now_ms,
            },
        );
        self.version = self.version.wrapping_add(1);
        outcome
    }

    /// Remove one LSA. Bumps [`version`](Self::version) when an entry
    /// was actually removed (the `Some` arm).
    pub fn remove(&mut self, key: &LsaKey) -> Option<LsaEntry> {
        self.seq_watermark.remove(key);
        if let Some(entry) = self.entries.remove(key) {
            self.version = self.version.wrapping_add(1);
            Some(entry)
        } else {
            None
        }
    }

    pub fn get(&self, key: &LsaKey) -> Option<&LsaEntry> {
        self.entries.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&LsaKey, &LsaEntry)> {
        self.entries.iter()
    }

    /// Return self-originated LSAs due for RFC 2328 §14.1 refresh.
    ///
    /// Each returned LSA has its sequence number incremented, age reset to
    /// zero, and checksum cleared for the egress encoder to recompute. The
    /// refreshed instance replaces the installed copy atomically.
    ///
    /// The [`version`](Self::version) counter is **not** bumped: a refresh
    /// rewrites the same LSA body under a new sequence number and reset
    /// age, so derived projections that depend only on the body (the
    /// SRv6 database, the BGP-LS projection, ...) stay valid. Caches
    /// keyed on `version` therefore survive a refresh tick.
    pub fn refresh_due(&mut self, advertising_router: u32, now_ms: u64) -> Vec<Lsa> {
        let due: Vec<LsaKey> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.lsa.header.advertising_router == advertising_router
                    && now_ms.saturating_sub(entry.installed_ms)
                        + u64::from(entry.lsa.header.ls_age) * 1_000
                        >= u64::from(LS_REFRESH_TIME_SECS) * 1_000
            })
            .map(|(key, _)| *key)
            .collect();
        let mut refreshed = Vec::with_capacity(due.len());
        for key in due {
            let Some(entry) = self.entries.get(&key) else {
                continue;
            };
            let mut lsa = entry.lsa.clone();
            let Some(sequence) = lsa.header.ls_sequence_number.checked_add(1) else {
                continue;
            };
            if !sequence_in_range(sequence) {
                // §14.1: at MAX_SEQUENCE_NUMBER the LSA must be flushed
                // rather than refreshed (the next value would be the
                // reserved 0x80000000, §12.1.2).
                continue;
            }
            lsa.header.ls_sequence_number = sequence;
            lsa.header.ls_age = 0;
            lsa.finalize(); // length + §C.4 checksum cover the new instance
            self.seq_watermark.insert(key, sequence);
            self.entries.insert(
                key,
                LsaEntry {
                    lsa: lsa.clone(),
                    installed_ms: now_ms,
                },
            );
            refreshed.push(lsa);
        }
        refreshed
    }

    /// Aging — LSAs whose age exceeds MAX_AGE (3600s) are removed.
    ///
    /// Bumps [`version`](Self::version) once for every LSA actually
    /// removed (the body of the LSDB shrinks, so every projection that
    /// depends on its contents is invalidated).
    pub fn age_out(&mut self, now_ms: u64) -> Vec<Lsa> {
        const MAX_AGE: u64 = MAX_AGE_SECS as u64 * 1000;
        let mut removed = Vec::new();
        let keys: Vec<LsaKey> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                let age = e.lsa.header.ls_age as u64 * 1000;
                now_ms.saturating_sub(e.installed_ms) + age >= MAX_AGE
            })
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            if let Some(e) = self.entries.remove(&k) {
                self.seq_watermark.remove(&k);
                self.version = self.version.wrapping_add(1);
                removed.push(e.lsa);
            }
        }
        removed
    }

    /// Get the headers of all installed LSAs (used in DB-Description exchange).
    pub fn headers(&self) -> Vec<LsaHeader> {
        self.entries.values().map(|e| e.lsa.header).collect()
    }
}

impl fmt::Display for Lsdb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Lsdb({} entries)", self.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lsa(ls_id: u32, adv: u32, seq: u32) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0,
                ls_type: 1,
                link_state_id: ls_id,
                advertising_router: adv,
                ls_sequence_number: seq,
                ls_checksum: 0,
                length: LsaHeader::LEN as u16,
            },
            body: Vec::new(),
        }
    }

    #[test]
    fn install_and_lookup() {
        let mut db = Lsdb::new();
        let lsa = make_lsa(1, 0x01020304, 0x80000001);
        assert_eq!(db.install(lsa.clone(), 0), InstallOutcome::New);
        assert_eq!(db.len(), 1);
        let e = db.get(&lsa.key()).unwrap();
        assert_eq!(e.lsa.header.ls_sequence_number, 0x80000001);
    }

    #[test]
    fn older_ignored() {
        let mut db = Lsdb::new();
        let l1 = make_lsa(1, 2, 0x80000005);
        let l2 = make_lsa(1, 2, 0x80000003);
        assert_eq!(db.install(l1, 0), InstallOutcome::New);
        assert_eq!(db.install(l2, 1), InstallOutcome::Ignored); // older
        assert_eq!(db.len(), 1);
        let e = db.get(&make_lsa(1, 2, 0).key()).unwrap();
        assert_eq!(e.lsa.header.ls_sequence_number, 0x80000005);
    }

    #[test]
    fn newer_replaces() {
        let mut db = Lsdb::new();
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000001), 0),
            InstallOutcome::New
        );
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000002), 5),
            InstallOutcome::Replaced
        );
        let e = db.get(&make_lsa(1, 2, 0).key()).unwrap();
        assert_eq!(e.installed_ms, 5);
        assert_eq!(e.lsa.header.ls_sequence_number, 0x80000002);
    }

    #[test]
    fn max_age_instance_purges() {
        let mut db = Lsdb::new();
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000001), 0),
            InstallOutcome::New
        );
        let mut flush = make_lsa(1, 2, 0x80000002);
        flush.header.ls_age = MAX_AGE_SECS;
        assert_eq!(db.install(flush, 10), InstallOutcome::Purged);
        assert!(db.is_empty());
        // A second MaxAge instance for the purged LSA is a no-op.
        let mut again = make_lsa(1, 2, 0x80000003);
        again.header.ls_age = MAX_AGE_SECS;
        assert_eq!(db.install(again, 11), InstallOutcome::Ignored);
    }

    #[test]
    fn re_origination_after_flush_starts_at_initial_sequence() {
        let mut db = Lsdb::new();
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000009), 0),
            InstallOutcome::New
        );
        let mut flush = make_lsa(1, 2, 0x8000000a);
        flush.header.ls_age = MAX_AGE_SECS;
        assert_eq!(db.install(flush, 10), InstallOutcome::Purged);
        // The watermark was cleared with the entry, so a fresh instance at
        // the initial sequence number is accepted again.
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000001), 12),
            InstallOutcome::New
        );
    }

    #[test]
    fn refresh_due_reoriginates_self_lsa() {
        let mut db = Lsdb::new();
        let lsa = make_lsa(1, 2, 0x80000001);
        db.install(lsa, 0);
        assert!(db.refresh_due(2, 1_799_999).is_empty());
        let refreshed = db.refresh_due(2, 1_800_000);
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].header.ls_age, 0);
        assert_eq!(refreshed[0].header.ls_sequence_number, 0x80000002);
        let entry = db.get(&refreshed[0].key()).unwrap();
        assert_eq!(entry.installed_ms, 1_800_000);
    }

    #[test]
    fn refresh_skips_non_self_lsa() {
        let mut db = Lsdb::new();
        db.install(make_lsa(1, 2, 0x80000001), 0);
        assert!(db.refresh_due(3, 1_800_000).is_empty());
    }

    #[test]
    fn age_out_max_age() {
        let mut db = Lsdb::new();
        // Installed at age 0; after 3600 s of wallclock it ages out.
        // (Instances that *arrive* at MaxAge are purged at install time —
        // see `max_age_instance_purges`.)
        db.install(make_lsa(1, 2, 0x80000001), 0);
        assert_eq!(db.len(), 1);
        assert!(db.age_out(3_599_999).is_empty());
        let removed = db.age_out(3_600_000);
        assert_eq!(removed.len(), 1);
        assert!(db.is_empty());
    }

    #[test]
    fn out_of_range_sequence_rejected() {
        let mut db = Lsdb::new();
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000001), 0),
            InstallOutcome::New
        );
        // The reserved sequence number (RFC 2328 §12.1.2) is rejected.
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000000), 5),
            InstallOutcome::Ignored
        );
        // An instance from the unreachable wrap region must not compare
        // "newer" than a stored 0x80000001 (audit D1) — it is rejected
        // outright so the watermark cannot be poisoned.
        assert_eq!(
            db.install(make_lsa(1, 2, 0x00000001), 6),
            InstallOutcome::Ignored
        );
        // The legitimate instance after the stored one still installs.
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000002), 7),
            InstallOutcome::Replaced
        );
    }

    #[test]
    fn max_sequence_number_is_accepted_but_not_refreshed() {
        let mut db = Lsdb::new();
        // 0x7fffffff is the legitimate maximum (RFC 2328 §12.1.2).
        assert_eq!(
            db.install(make_lsa(1, 2, 0x7fffffff), 0),
            InstallOutcome::New
        );
        // Refreshing it would produce the reserved 0x80000000 — the
        // refresh is skipped instead (the LSA must be flushed, §14.1).
        assert!(db.refresh_due(2, 1_800_000).is_empty());
    }

    #[test]
    fn version_starts_at_zero() {
        let db = Lsdb::new();
        assert_eq!(db.version(), 0);
    }

    #[test]
    fn version_bumps_on_install_replace_and_purge() {
        let mut db = Lsdb::new();
        assert_eq!(db.version(), 0);

        // New install bumps.
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000001), 0),
            InstallOutcome::New
        );
        assert_eq!(db.version(), 1);

        // Replacement bumps again.
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000002), 5),
            InstallOutcome::Replaced
        );
        assert_eq!(db.version(), 2);

        // MaxAge instance purges — bumps.
        let mut flush = make_lsa(1, 2, 0x80000003);
        flush.header.ls_age = MAX_AGE_SECS;
        assert_eq!(db.install(flush, 10), InstallOutcome::Purged);
        assert_eq!(db.version(), 3);
    }

    #[test]
    fn version_ignored_install_leaves_counter_untouched() {
        let mut db = Lsdb::new();
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000005), 0),
            InstallOutcome::New
        );
        assert_eq!(db.version(), 1);

        // Older instance — ignored, version does not move.
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000003), 1),
            InstallOutcome::Ignored
        );
        assert_eq!(db.version(), 1);

        // Reserved sequence number — ignored.
        assert_eq!(
            db.install(make_lsa(1, 2, 0x80000000), 2),
            InstallOutcome::Ignored
        );
        assert_eq!(db.version(), 1);

        // Out-of-range (wrap-region) sequence — ignored.
        assert_eq!(
            db.install(make_lsa(1, 2, 0x00000001), 3),
            InstallOutcome::Ignored
        );
        assert_eq!(db.version(), 1);

        // A MaxAge instance for a non-existent LSA is also ignored.
        let mut flush = make_lsa(7, 2, 0x80000002);
        flush.header.ls_age = MAX_AGE_SECS;
        assert_eq!(db.install(flush, 4), InstallOutcome::Ignored);
        assert_eq!(db.version(), 1);
    }

    #[test]
    fn version_remove_bumps_only_when_something_was_removed() {
        let mut db = Lsdb::new();
        let lsa = make_lsa(1, 2, 0x80000001);
        db.install(lsa.clone(), 0);
        assert_eq!(db.version(), 1);

        // Removing an unknown key leaves the counter untouched.
        let other_key = make_lsa(2, 2, 0x80000001).key();
        assert!(db.remove(&other_key).is_none());
        assert_eq!(db.version(), 1);

        // Removing a real entry bumps.
        assert!(db.remove(&lsa.key()).is_some());
        assert_eq!(db.version(), 2);
    }

    #[test]
    fn version_age_out_bumps_per_removed_lsa() {
        let mut db = Lsdb::new();
        db.install(make_lsa(1, 2, 0x80000001), 0);
        db.install(make_lsa(2, 2, 0x80000001), 0);
        db.install(make_lsa(3, 2, 0x80000001), 0);
        assert_eq!(db.version(), 3);

        // Before MaxAge — nothing removed, version untouched.
        assert!(db.age_out(3_599_999).is_empty());
        assert_eq!(db.version(), 3);

        // At MaxAge — every entry removed, version bumps per LSA.
        let removed = db.age_out(3_600_000);
        assert_eq!(removed.len(), 3);
        assert_eq!(db.version(), 6);
        assert!(db.is_empty());
    }

    #[test]
    fn version_refresh_does_not_bump() {
        let mut db = Lsdb::new();
        let lsa = make_lsa(1, 2, 0x80000001);
        db.install(lsa, 0);
        assert_eq!(db.version(), 1);

        // A refresh re-writes the same body under a new sequence
        // number — the SRv6 / BGP-LS projections that depend on the
        // body stay valid, so the version counter does not move.
        let refreshed = db.refresh_due(2, 1_800_000);
        assert_eq!(refreshed.len(), 1);
        assert_eq!(db.version(), 1);
    }
}
