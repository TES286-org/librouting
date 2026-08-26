//! Link-state database (per area). Stores LSAs keyed by (type, ls_id, adv).

use core::fmt;
use std::collections::BTreeMap;

use crate::lsa::{Lsa, LsaHeader, LsaKey};

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

    /// Install or refresh an LSA. Returns the previous entry, if any.
    pub fn install(&mut self, lsa: Lsa, now_ms: u64) -> Option<LsaEntry> {
        let key = lsa.key();
        // Accept if newer than what we have.
        let prev_seq = self.seq_watermark.get(&key).copied().unwrap_or(0);
        if (lsa.header.ls_sequence_number as i32) <= (prev_seq as i32) && prev_seq != 0 {
            // Older or duplicate; ignore.
            return None;
        }
        self.seq_watermark
            .insert(key, lsa.header.ls_sequence_number);
        let entry = LsaEntry {
            lsa,
            installed_ms: now_ms,
        };
        self.entries.insert(key, entry)
    }

    pub fn remove(&mut self, key: &LsaKey) -> Option<LsaEntry> {
        self.seq_watermark.remove(key);
        self.entries.remove(key)
    }

    pub fn get(&self, key: &LsaKey) -> Option<&LsaEntry> {
        self.entries.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&LsaKey, &LsaEntry)> {
        self.entries.iter()
    }

    /// Aging — LSAs whose age exceeds MAX_AGE (3600s) are removed.
    pub fn age_out(&mut self, now_ms: u64) -> Vec<Lsa> {
        const MAX_AGE: u64 = 3600 * 1000;
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
        let prev = db.install(lsa.clone(), 0);
        assert!(prev.is_none());
        assert_eq!(db.len(), 1);
        let e = db.get(&lsa.key()).unwrap();
        assert_eq!(e.lsa.header.ls_sequence_number, 0x80000001);
    }

    #[test]
    fn older_ignored() {
        let mut db = Lsdb::new();
        let l1 = make_lsa(1, 2, 0x80000005);
        let l2 = make_lsa(1, 2, 0x80000003);
        assert!(db.install(l1, 0).is_none());
        assert!(db.install(l2, 1).is_none()); // older
        assert_eq!(db.len(), 1);
        let e = db.get(&make_lsa(1, 2, 0).key()).unwrap();
        assert_eq!(e.lsa.header.ls_sequence_number, 0x80000005);
    }

    #[test]
    fn age_out_max_age() {
        let mut db = Lsdb::new();
        let mut lsa = make_lsa(1, 2, 0x80000001);
        lsa.header.ls_age = 3600; // at max age already
        db.install(lsa, 0);
        assert_eq!(db.len(), 1);
        let removed = db.age_out(0);
        assert_eq!(removed.len(), 1);
        assert!(db.is_empty());
    }
}
