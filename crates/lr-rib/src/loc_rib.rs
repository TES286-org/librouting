//! Loc-RIB — post-policy best routes.

use std::collections::BTreeMap;

use lr_core::rib::{Route, RouteKey};

/// Generation counter — callers can ask "what changed since generation X?"
#[derive(Debug, Default, Clone)]
pub struct RibDiff {
    pub added: Vec<Route>,
    pub removed: Vec<RouteKey>,
    pub modified: Vec<Route>,
}

/// Local RIB after policy. Stores the best path per key, plus — when
/// Add-Path (RFC 7911) keeps more than one path per prefix — the ranked
/// runner-ups behind it. The first element of each set is always the best
/// path (the one non-Add-Path consumers see); single-path operation
/// degenerates to one-element sets.
#[derive(Default)]
pub struct LocRib {
    inner: BTreeMap<RouteKey, Vec<Route>>,
    gen: u64,
    /// History of (gen, change) — keeps last 16 diffs.
    history: std::collections::VecDeque<(u64, RibDiff)>,
}

impl LocRib {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install one path for a key, replacing any existing path with the
    /// same RFC 7911 identifier. Callers that only ever install the
    /// single best path get exactly the pre-Add-Path behaviour.
    pub fn install(&mut self, route: Route) {
        let key = route.key.clone();
        let was_present = self.inner.contains_key(&key);
        let set = self.inner.entry(key.clone()).or_default();
        match set.iter_mut().find(|r| r.path_id == route.path_id) {
            Some(existing) => *existing = route,
            None => set.push(route),
        }
        self.gen += 1;
        let best = self.inner.get(&key).and_then(|s| s.first()).cloned();
        let diff = if was_present {
            RibDiff {
                added: vec![],
                removed: vec![],
                modified: best.into_iter().collect(),
            }
        } else {
            RibDiff {
                added: best.into_iter().collect(),
                removed: vec![],
                modified: vec![],
            }
        };
        self.push_history(diff);
    }

    /// Replace the whole ranked path set for a key (best first). An empty
    /// set removes the key. Used by the decision process when Add-Path
    /// selection re-ranks every path for a prefix, and by local
    /// origination.
    ///
    /// Whole-set replacement is only appropriate for callers that own the
    /// *full* ranking of the key: the previous set is discarded wholesale,
    /// so replacing a set with a single path without having re-ranked the
    /// key's other candidates (e.g. a peer's Adj-RIB-In paths) silently
    /// evicts them. The BGP decision process (`lr-router::reselect`) and
    /// the redistribution path run their candidate selection first and
    /// hand the complete ranking to this method; the single-path
    /// [`Self::install`] entry exists for callers that only ever manage
    /// one path per key (OSPF/Babel runtimes).
    ///
    /// Diff semantics follow the best path: unchanged best → no event,
    /// same-identifier new best → modified, different best → remove + add.
    pub fn install_set(&mut self, key: &RouteKey, ranked: Vec<Route>) {
        debug_assert!(ranked.iter().all(|r| &r.key == key));
        if ranked.is_empty() {
            self.uninstall(key);
            return;
        }
        let prev_best = self.inner.get(key).and_then(|s| s.first()).cloned();
        let new_best = ranked.first().expect("ranked non-empty").clone();
        if self.inner.get(key).map(|s| s.as_slice()) == Some(ranked.as_slice()) {
            // Identical set: nothing to record.
            return;
        }
        self.inner.insert(key.clone(), ranked);
        self.gen += 1;
        let diff = match &prev_best {
            None => RibDiff {
                added: vec![new_best],
                removed: vec![],
                modified: vec![],
            },
            Some(old) if old.path_id == new_best.path_id => RibDiff {
                added: vec![],
                removed: vec![],
                modified: vec![new_best],
            },
            Some(_) => RibDiff {
                added: vec![new_best],
                removed: vec![key.clone()],
                modified: vec![],
            },
        };
        self.push_history(diff);
    }

    pub fn uninstall(&mut self, key: &RouteKey) -> Option<Route> {
        let removed_set = self.inner.remove(key);
        let best = removed_set.as_ref().and_then(|s| s.first()).cloned();
        if removed_set.is_some() {
            self.gen += 1;
            self.push_history(RibDiff {
                added: vec![],
                removed: vec![key.clone()],
                modified: vec![],
            });
        }
        best
    }

    fn push_history(&mut self, diff: RibDiff) {
        if self.history.len() >= 16 {
            self.history.pop_front();
        }
        self.history.push_back((self.gen, diff));
    }

    /// The best path for a key (first of the ranked set).
    pub fn best(&self, key: &RouteKey) -> Option<&Route> {
        self.inner.get(key).and_then(|set| set.first())
    }

    /// The full ranked path set for a key (best first); empty for absent
    /// keys.
    pub fn paths(&self, key: &RouteKey) -> &[Route] {
        self.inner.get(key).map(|s| s.as_slice()).unwrap_or(&[])
    }

    /// Iterate the best path of every key.
    pub fn iter_best(&self) -> impl Iterator<Item = &Route> {
        self.inner.values().filter_map(|set| set.first())
    }

    /// Iterate every path in every set (the Add-Path view of the Loc-RIB).
    pub fn iter_paths(&self) -> impl Iterator<Item = &Route> {
        self.inner.values().flatten()
    }

    /// Iterate whole path sets with their keys: `(key, ranked set)`.
    pub fn iter_sets(&self) -> impl Iterator<Item = (&RouteKey, &[Route])> {
        self.inner.iter().map(|(k, v)| (k, v.as_slice()))
    }

    /// Number of keys (prefixes), not paths.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Total number of stored paths (>= `len()` with Add-Path).
    pub fn paths_len(&self) -> usize {
        self.inner.values().map(|s| s.len()).sum()
    }

    pub fn generation(&self) -> u64 {
        self.gen
    }

    /// All changes since `gen`.
    pub fn diff_since(&self, gen: u64) -> RibDiff {
        let mut out = RibDiff::default();
        for (g, d) in self.history.iter().rev() {
            if *g <= gen {
                break;
            }
            out.added.extend(d.added.iter().cloned());
            out.removed.extend(d.removed.iter().cloned());
            out.modified.extend(d.modified.iter().cloned());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteOrigin};

    fn route(p: [u8; 4], pl: u8) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4(p, pl), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 1, peer: 1 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    #[test]
    fn install_and_diff() {
        let mut rib = LocRib::new();
        let before = rib.generation();
        rib.install(route([10, 0, 0, 0], 8));
        rib.install(route([192, 168, 0, 0], 24));
        let diff = rib.diff_since(before);
        assert_eq!(diff.added.len(), 2);
        rib.uninstall(&route([10, 0, 0, 0], 8).key);
        let diff2 = rib.diff_since(rib.generation() - 1);
        assert_eq!(diff2.removed.len(), 1);
    }

    #[test]
    fn install_set_ranks_paths_best_first() {
        let mut rib = LocRib::new();
        let key = route([203, 0, 113, 0], 24).key;
        let mut best = route([203, 0, 113, 0], 24);
        best.path_id = 1;
        let mut second = route([203, 0, 113, 0], 24);
        second.path_id = 2;
        second.preference.metric = 5;
        rib.install_set(&key, vec![best.clone(), second.clone()]);
        assert_eq!(rib.len(), 1, "one prefix");
        assert_eq!(rib.paths_len(), 2, "two paths");
        assert_eq!(rib.best(&key).unwrap().path_id, 1);
        assert_eq!(rib.paths(&key).len(), 2);
        // Replacing with an empty set removes the key.
        rib.install_set(&key, vec![]);
        assert!(rib.is_empty());
    }

    #[test]
    fn install_replaces_same_path_id() {
        let mut rib = LocRib::new();
        let key = route([198, 51, 100, 0], 24).key;
        let mut a = route([198, 51, 100, 0], 24);
        a.path_id = 3;
        let mut b = route([198, 51, 100, 0], 24);
        b.path_id = 3;
        b.preference.metric = 9;
        rib.install(a);
        rib.install(b);
        assert_eq!(rib.paths_len(), 1);
        assert_eq!(rib.best(&key).unwrap().preference.metric, 9);
    }

    /// Identical re-installation is a no-op (no spurious diff generation).
    #[test]
    fn install_set_no_change_is_quiet() {
        let mut rib = LocRib::new();
        let key = route([203, 0, 113, 0], 24).key;
        let mut a = route([203, 0, 113, 0], 24);
        a.path_id = 1;
        rib.install_set(&key, vec![a.clone()]);
        let gen = rib.generation();
        rib.install_set(&key, vec![a]);
        assert_eq!(rib.generation(), gen, "no change → no generation bump");
    }
}
