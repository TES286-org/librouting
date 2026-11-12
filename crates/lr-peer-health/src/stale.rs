//! Stale prefix tracking (issue #99 §Recovery).

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

use core::fmt;

use lr_core::addr::Prefix;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StaleEntry {
    pub prefix: Prefix,
    pub marked_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaleSet {
    inner: BTreeMap<Prefix, u64>,
}

impl StaleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn mark(&mut self, prefix: &Prefix, now_ms: u64) {
        self.inner.insert(*prefix, now_ms);
    }

    pub fn clear(&mut self, prefix: &Prefix) {
        self.inner.remove(prefix);
    }

    pub fn is_stale(&self, prefix: &Prefix) -> bool {
        self.inner.contains_key(prefix)
    }

    pub fn iter(&self) -> impl Iterator<Item = StaleEntry> + '_ {
        self.inner.iter().map(|(p, &ms)| StaleEntry {
            prefix: *p,
            marked_ms: ms,
        })
    }

    pub fn sweep(&mut self, now_ms: u64, max_stale_age_s: u64) -> StaleSweepReport {
        let mut report = StaleSweepReport::default();
        let max_age_ms = max_stale_age_s * 1000;
        let to_remove: Vec<Prefix> = self
            .inner
            .iter()
            .filter(|(_, &marked)| now_ms.saturating_sub(marked) >= max_age_ms)
            .map(|(p, _)| *p)
            .collect();
        for p in &to_remove {
            self.inner.remove(p);
        }
        report.expired = to_remove.len() as u64;
        report.remaining = self.len() as u64;
        report.readmitted = 0;
        report
    }

    pub fn clear_all(&mut self) {
        self.inner.clear();
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StaleSweepReport {
    pub readmitted: u64,
    pub expired: u64,
    pub remaining: u64,
}

impl fmt::Display for StaleSweepReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "readmitted={} expired={} remaining={}",
            self.readmitted, self.expired, self.remaining
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn mark_and_clear() {
        let mut s = StaleSet::new();
        s.mark(&p("10.0.0.0/8"), 1_000);
        assert!(s.is_stale(&p("10.0.0.0/8")));
        assert_eq!(s.len(), 1);
        s.clear(&p("10.0.0.0/8"));
        assert!(!s.is_stale(&p("10.0.0.0/8")));
    }

    #[test]
    fn sweep_expires_aged_entries() {
        let mut s = StaleSet::new();
        s.mark(&p("10.0.0.0/8"), 1_000);
        s.mark(&p("10.0.0.0/24"), 100_000);
        let r = s.sweep(70_000, 60);
        assert_eq!(r.expired, 1);
        assert_eq!(r.remaining, 1);
        assert!(!s.is_stale(&p("10.0.0.0/8")));
        assert!(s.is_stale(&p("10.0.0.0/24")));
    }

    #[test]
    fn mark_refreshes_timestamp() {
        let mut s = StaleSet::new();
        s.mark(&p("10.0.0.0/8"), 1_000);
        s.mark(&p("10.0.0.0/8"), 100_000);
        let r = s.sweep(70_000, 60);
        assert_eq!(r.expired, 0);
        assert_eq!(r.remaining, 1);
    }

    #[test]
    fn clear_all_resets() {
        let mut s = StaleSet::new();
        s.mark(&p("10.0.0.0/8"), 0);
        s.mark(&p("10.0.0.0/24"), 0);
        s.clear_all();
        assert!(s.is_empty());
    }
}
