//! Per-neighbor LSA retransmission list (RFC 2328 §13.5 / §13.6 / §13.7).
//!
//! When an LSA is flooded to a neighbor the same instance is added to
//! that neighbor's *Link State Retransmission List* (§13.5). The list
//! is drained by two events:
//!
//! - **LS-Acknowledgment received (§13.7)** — the neighbor's Link State
//!   Acknowledgment packet carries the LSA headers it has received; the
//!   matching entries are removed from the list.
//! - **Retransmission timer (§13.6 / Appendix C `RxmtInterval`)** — every
//!   `RxmtInterval`, every entry still on the list is re-flooded to the
//!   neighbor as a unicast LS-Update.
//!
//! Without this list the flood path is fire-and-forget: a single dropped
//! LS-Update (or LS-Ack) leaves the two LSDBs permanently out of sync and
//! SPF computes against a stale view of the area. This module gives the
//! exchange driver a small, ownership-friendly container for the list.
//!
//! # Storage shape
//!
//! `BTreeMap<LsaKey, (Lsa, last_sent_ms)>` — keyed by the LSA identity
//! (`(ls_type, link_state_id, advertising_router)`, matching [`LsaKey`]).
//! `BTreeMap` gives ordered iteration so a `poll` walk is deterministic
//! (handy for tests that compare packet streams) and lookups/removals
//! are `O(log n)`.
//!
//! The full LSA instance is cached so a retransmit does not have to
//! re-resolve the LSDB: per RFC 2328 §13.6 the retransmitted instance
//! is the one we most recently flooded, even if the LSDB has since
//! installed a newer instance (the receiver will accept it as a
//! duplicate, re-ack to silence us, and the newer instance arrives
//! through the regular flood path).
//!
//! # Concurrency
//!
//! The list is single-threaded: OSPF sessions are driven by the
//! router's poll loop, which holds an exclusive borrow on
//! `DefaultRouter::sessions` for the duration of one tick. The list
//! owns no locks of its own.

use crate::lsa::{Lsa, LsaHeader, LsaKey};

/// One entry on the retransmission list — the LSA instance we flooded
/// plus the wall-clock `now_ms` of the most recent (re)transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetransmitEntry {
    /// The exact LSA instance placed on the wire.
    pub lsa: Lsa,
    /// `now_ms` of the most recent send (initial flood or retransmit).
    /// Used by the poll loop to wait `RxmtInterval` between repeats.
    pub last_sent_ms: u64,
}

/// Per-neighbor LSA retransmission list (RFC 2328 §13.5). The list
/// tracks every LSA we have flooded to a neighbor and not yet seen
/// acknowledged by an LS-Acknowledgment packet (§13.7).
#[derive(Debug, Default, Clone)]
pub struct LinkStateRetransmissionList {
    entries: std::collections::BTreeMap<LsaKey, RetransmitEntry>,
}

impl LinkStateRetransmissionList {
    /// Create an empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of LSAs currently awaiting acknowledgment.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no LSAs are awaiting acknowledgment.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record `lsa` as just flooded to this neighbor at `now_ms`
    /// (RFC 2328 §13.5 step 5). If the same key is already on the
    /// list (a duplicate flood — same instance re-flooded, or a newer
    /// instance of the same LSA), the entry is overwritten with the
    /// new instance and the send timestamp is reset.
    ///
    /// Performance: `O(log n)` (one `BTreeMap::insert`).
    pub fn record_flood(&mut self, lsa: Lsa, now_ms: u64) {
        let key = lsa.key();
        self.entries.insert(
            key,
            RetransmitEntry {
                lsa,
                last_sent_ms: now_ms,
            },
        );
    }

    /// Apply one LS-Acknowledgment packet (§13.7): for every header in
    /// `ack`, remove the matching entry from the list. Returns the
    /// number of entries actually removed so the caller can emit a
    /// diagnostic when an ack references an LSA we never flooded (a
    /// stray / duplicate ack from a neighbor that re-acked after we
    /// already removed it — harmless per §13.7 step 5, but useful to
    /// observe).
    ///
    /// Matching is by `LsaKey` (type / LS-ID / advertising router):
    /// §13.7 explicitly matches on those three fields, NOT on
    /// sequence number or checksum — an ack for an older instance
    /// still clears the entry because the receiver is signaling "I
    /// have a more recent instance than the one you sent".
    ///
    /// Performance: `O(m log n)` for `m` acked headers, each removal
    /// a `BTreeMap::remove`.
    pub fn apply_acks(&mut self, ack: &[LsaHeader]) -> usize {
        let mut removed = 0usize;
        for h in ack {
            let key = LsaKey::from(h);
            if self.entries.remove(&key).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Walk the list and return the LSAs whose
    /// `now_ms - last_sent_ms >= rxmt_interval` (RFC 2328 §13.6). The
    /// returned LSAs are *not* removed from the list; their
    /// `last_sent_ms` is bumped to `now_ms` so the next retransmit
    /// cycle waits another full `rxmt_interval`. The caller is
    /// responsible for putting the returned LSAs into a unicast
    /// LS-Update packet addressed to this neighbor.
    ///
    /// The walk is `O(n)`; `n` is bounded by the area LSDB size, which
    /// is itself bounded by `MaxAge` eviction — so the worst case is
    /// the area's full LSA count, the same shape BIRD walks every
    /// `RxmtInterval` per neighbor.
    pub fn poll(&mut self, now_ms: u64, rxmt_interval: u64) -> Vec<Lsa> {
        let mut out = Vec::new();
        for entry in self.entries.values_mut() {
            if now_ms.saturating_sub(entry.last_sent_ms) >= rxmt_interval {
                out.push(entry.lsa.clone());
                entry.last_sent_ms = now_ms;
            }
        }
        out
    }

    /// Drop every entry whose LSA identity matches `key`. Used by
    /// the LSDB replacement path: when a newer LSA instance is
    /// installed, the older instance is removed from the
    /// retransmission list (the new instance will be flooded
    /// separately and re-added to the list there).
    ///
    /// Returns `true` if an entry was removed.
    ///
    /// Performance: `O(log n)`.
    pub fn remove(&mut self, key: &LsaKey) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Drop every entry — used on neighbor reset (§10.1 `Kill`,
    /// §10.9 sequence-mismatch restart, §14 LSDB flush).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Read-only iterator over the list entries, ordered by `LsaKey`.
    /// Used by the `show ospf neighbor` renderer to surface "LSAs
    /// pending ack" diagnostics.
    pub fn iter(&self) -> impl Iterator<Item = (&LsaKey, &RetransmitEntry)> {
        self.entries.iter()
    }

    /// True when the list holds `lsa`'s identity (type / LS-ID /
    /// advertising router). Used by tests and the
    /// `ospf_flood`-to-this-neighbor short-circuit (§13.3 step 4 —
    /// "if the LSA is already on the retransmission list for this
    /// neighbor, do not add it again").
    pub fn contains(&self, key: &LsaKey) -> bool {
        self.entries.contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lsa(ls_type: u16, ls_id: u32, adv: u32, seq: u32) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: 0,
                ls_type,
                link_state_id: ls_id,
                advertising_router: adv,
                ls_sequence_number: seq,
                ls_checksum: 0,
                length: 20,
            },
            body: Vec::new(),
        }
    }

    #[test]
    fn record_flood_adds_entry() {
        let mut list = LinkStateRetransmissionList::new();
        assert!(list.is_empty());
        list.record_flood(lsa(1, 0x01020304, 0x01020304, 0x80000001), 1_000);
        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
    }

    #[test]
    fn record_flood_replaces_on_same_key() {
        // A newer instance of the same LSA (same (type, ls_id, adv))
        // overwrites the older instance — the retransmit list always
        // carries the most recently flooded instance.
        let mut list = LinkStateRetransmissionList::new();
        list.record_flood(lsa(1, 0x01020304, 0x01020304, 0x80000001), 1_000);
        list.record_flood(lsa(1, 0x01020304, 0x01020304, 0x80000002), 2_000);
        assert_eq!(list.len(), 1);
        let (k, e) = list.iter().next().unwrap();
        assert_eq!(k.ls_type, 1);
        assert_eq!(e.lsa.header.ls_sequence_number, 0x80000002);
        assert_eq!(e.last_sent_ms, 2_000);
    }

    #[test]
    fn apply_acks_removes_matching_entries() {
        let mut list = LinkStateRetransmissionList::new();
        list.record_flood(lsa(1, 1, 0xa, 1), 0);
        list.record_flood(lsa(1, 2, 0xa, 1), 0);
        list.record_flood(lsa(1, 3, 0xa, 1), 0);

        let ack = vec![lsa(1, 1, 0xa, 1).header, lsa(1, 3, 0xa, 1).header];
        let removed = list.apply_acks(&ack);
        assert_eq!(removed, 2);
        assert_eq!(list.len(), 1);
        let (k, _) = list.iter().next().unwrap();
        assert_eq!(k.link_state_id, 2);
    }

    #[test]
    fn apply_acks_matches_on_key_not_instance() {
        // §13.7: acks match on (type, LS-ID, advertising router), NOT
        // on sequence number — an ack for an older instance still
        // clears the entry because the receiver is signaling "I have
        // a more recent instance than the one you sent".
        let mut list = LinkStateRetransmissionList::new();
        list.record_flood(lsa(1, 1, 0xa, 0x80000005), 0);
        let ack = vec![LsaHeader {
            ls_age: 0,
            options: 0,
            ls_type: 1,
            link_state_id: 1,
            advertising_router: 0xa,
            ls_sequence_number: 0x80000001, // older seq
            ls_checksum: 0,
            length: 20,
        }];
        assert_eq!(list.apply_acks(&ack), 1);
        assert!(list.is_empty());
    }

    #[test]
    fn apply_acks_silent_on_stray_ack() {
        // An ack for an LSA we never flooded is a no-op (§13.7 step 5:
        // the receiver "may" send a duplicate ack; we must accept it
        // silently). Returns 0 — caller can log if it cares.
        let mut list = LinkStateRetransmissionList::new();
        list.record_flood(lsa(1, 1, 0xa, 1), 0);
        let ack = vec![lsa(1, 99, 0xa, 1).header];
        assert_eq!(list.apply_acks(&ack), 0);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn poll_returns_aged_entries_and_bumps_timestamp() {
        let mut list = LinkStateRetransmissionList::new();
        list.record_flood(lsa(1, 1, 0xa, 1), 1_000);
        list.record_flood(lsa(1, 2, 0xa, 1), 6_000);

        // rxmt_interval = 5_000ms. At now=6_000 the first LSA is 5_000ms
        // old and the second is 0ms old — only the first retransmits.
        let out = list.poll(6_000, 5_000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].header.link_state_id, 1);

        // The bumped timestamp means the next poll 5s later does not
        // re-emit the same LSA.
        let out2 = list.poll(11_000, 5_000);
        assert_eq!(out2.len(), 2); // both LSAs now aged past 5s
        assert!(out2.iter().any(|l| l.header.link_state_id == 1));
        assert!(out2.iter().any(|l| l.header.link_state_id == 2));
    }

    #[test]
    fn poll_returns_nothing_when_interval_not_elapsed() {
        let mut list = LinkStateRetransmissionList::new();
        list.record_flood(lsa(1, 1, 0xa, 1), 1_000);
        assert!(list.poll(2_000, 5_000).is_empty());
        assert!(list.poll(5_999, 5_000).is_empty());
    }

    #[test]
    fn remove_drops_single_entry() {
        let mut list = LinkStateRetransmissionList::new();
        list.record_flood(lsa(1, 1, 0xa, 1), 0);
        list.record_flood(lsa(1, 2, 0xa, 1), 0);
        let key = LsaKey {
            ls_type: 1,
            link_state_id: 1,
            advertising_router: 0xa,
        };
        assert!(list.remove(&key));
        assert_eq!(list.len(), 1);
        let (k, _) = list.iter().next().unwrap();
        assert_eq!(k.link_state_id, 2);
        // Removing a key that's not present is a no-op (returns false).
        assert!(!list.remove(&key));
    }

    #[test]
    fn clear_drops_everything() {
        let mut list = LinkStateRetransmissionList::new();
        list.record_flood(lsa(1, 1, 0xa, 1), 0);
        list.record_flood(lsa(1, 2, 0xa, 1), 0);
        list.clear();
        assert!(list.is_empty());
    }

    #[test]
    fn contains_checks_identity() {
        let mut list = LinkStateRetransmissionList::new();
        list.record_flood(lsa(1, 1, 0xa, 1), 0);
        let key_present = LsaKey {
            ls_type: 1,
            link_state_id: 1,
            advertising_router: 0xa,
        };
        let key_absent = LsaKey {
            ls_type: 1,
            link_state_id: 2,
            advertising_router: 0xa,
        };
        assert!(list.contains(&key_present));
        assert!(!list.contains(&key_absent));
    }
}
