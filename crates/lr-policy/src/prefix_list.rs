//! Prefix-list semantics (FRR/Cisco: exact match unless a `ge`/`le`
//! window is given).

use lr_core::addr::Prefix;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct PrefixListEntry {
    pub prefix: Prefix,
    /// Greater-or-equal: minimum prefix length.
    pub ge: u8,
    /// Less-or-equal: maximum prefix length. 255 = no upper bound
    /// (the FFI spelling; the daemon uses the family maximum instead).
    pub le: u8,
    /// True: permit, False: deny.
    pub permit: bool,
}

impl PrefixListEntry {
    /// Exact-match entry: only the prefix itself matches. This is the
    /// FRR/Cisco default when neither `ge` nor `le` is configured
    /// (`ip prefix-list NAME permit 10.0.0.0/8` never admits
    /// `10.1.2.0/24`). Callers wanting a window set `ge`/`le`
    /// explicitly — `ge` alone widens `le` to the family maximum
    /// (32 for IPv4, 128 for IPv6).
    pub fn new(prefix: Prefix, permit: bool) -> Self {
        let pl = prefix.prefix_len;
        Self {
            prefix,
            ge: pl,
            le: pl,
            permit,
        }
    }

    pub fn matches(&self, p: &Prefix) -> bool {
        if !self.prefix.contains_prefix(p) {
            return false;
        }
        let pl = p.prefix_len;
        !(pl < self.ge || pl > self.le)
    }
}

#[derive(Clone, Default)]
pub struct PrefixList {
    entries: Vec<PrefixListEntry>,
}

impl PrefixList {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, e: PrefixListEntry) {
        self.entries.push(e);
    }

    /// True if any permit matches and no earlier deny matches.
    pub fn evaluate(&self, p: &Prefix) -> bool {
        for e in &self.entries {
            if e.matches(p) {
                return e.permit;
            }
        }
        false // implicit deny
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Default)]
pub struct PrefixListBank {
    lists: BTreeMap<u32, PrefixList>,
}

impl PrefixListBank {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, id: u32, list: PrefixList) {
        self.lists.insert(id, list);
    }
    pub fn len(&self) -> usize {
        self.lists.len()
    }
    pub fn is_empty(&self) -> bool {
        self.lists.is_empty()
    }
    pub fn get(&self, id: u32) -> Option<&PrefixList> {
        self.lists.get(&id)
    }
    pub fn evaluate(&self, id: u32, p: &Prefix) -> bool {
        match self.lists.get(&id) {
            Some(list) => list.evaluate(p),
            // Unknown list id: deny — consistent with the community-list
            // and AS-path-filter banks, and with FRR (an undefined
            // reference must not silently pass traffic).
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_permit() {
        let mut list = PrefixList::new();
        list.push(PrefixListEntry::new(Prefix::new_v4([10, 0, 0, 0], 8), true));
        assert!(list.evaluate(&Prefix::new_v4([10, 1, 0, 0], 8)));
        // FRR/Cisco semantics: without ge/le the entry matches the
        // prefix length exactly — a longer prefix under 10/8 does
        // NOT match (it used to, which made every `permit 10/8`
        // silently admit the covering space).
        assert!(!list.evaluate(&Prefix::new_v4([10, 0, 0, 0], 16)));
        assert!(!list.evaluate(&Prefix::new_v4([10, 0, 0, 0], 9)));
        assert!(!list.evaluate(&Prefix::new_v4([11, 0, 0, 0], 8)));
    }

    #[test]
    fn deny_then_permit() {
        let mut list = PrefixList::new();
        list.push(PrefixListEntry::new(
            Prefix::new_v4([10, 0, 0, 0], 24),
            false,
        ));
        // A permit that means "the /8 or anything under it" spells
        // the window explicitly (FRR: `permit 10.0.0.0/8 le 32`).
        let mut permit = PrefixListEntry::new(Prefix::new_v4([10, 0, 0, 0], 8), true);
        permit.le = 32;
        list.push(permit);
        // 10.0.0.0/24 is denied explicitly.
        assert!(!list.evaluate(&Prefix::new_v4([10, 0, 0, 0], 24)));
        // 10.0.1.0/24 falls through to the widened /8 permit.
        assert!(list.evaluate(&Prefix::new_v4([10, 0, 1, 0], 24)));
    }

    #[test]
    fn ge_le_range() {
        let mut list = PrefixList::new();
        let mut e = PrefixListEntry::new(Prefix::new_v4([10, 0, 0, 0], 8), true);
        e.ge = 16;
        e.le = 24;
        list.push(e);
        assert!(!list.evaluate(&Prefix::new_v4([10, 0, 0, 0], 8)));
        assert!(list.evaluate(&Prefix::new_v4([10, 0, 0, 0], 16)));
        assert!(list.evaluate(&Prefix::new_v4([10, 0, 0, 0], 24)));
        assert!(!list.evaluate(&Prefix::new_v4([10, 0, 0, 0], 25)));
    }
}
