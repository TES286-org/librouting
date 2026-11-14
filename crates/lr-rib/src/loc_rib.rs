//! Loc-RIB — post-policy best routes.
//!
//! Per-AFI sharding (issue #101, ROADMAP §"Scaling" — Per-AFI RIB
//! sharding). The Loc-RIB is sharded by [`NlriFamily`]: one
//! [`RibShard`] per address family that has at least one route. The
//! family is part of every [`RouteKey`], so the shard lookup is one
//! `BTreeMap` descent on the (small) family map plus one descent on
//! the shard's inner map — O(log F + log N) instead of the O(log N)
//! single-map case, where F is the family count (typically 1–3 in
//! practice). The payoff is family-isolated iteration: a walk over
//! the IPv6 table does not touch the IPv4 table's pages, and the
//! multi-threaded RIB follow-up (ROADMAP §"Scaling" — Multi-threaded
//! RIB) shards its per-family lock on top of this boundary.
//!
//! The public API is frozen (the C ABI exposes `LocRib` as
//! `lr_loc_rib_t`); every existing method keeps its signature and
//! semantics. Cross-family iterators ([`iter_best`], [`iter_paths`],
//! [`iter_sets`]) chain across shards in `NlriFamily` order, so a
//! snapshot's iteration order changes from "all keys sorted by
//! `RouteKey`" to "keys sorted by `RouteKey` within each family,
//! families sorted by `NlriFamily`". Both orders are deterministic;
//! callers that collect into a `Vec` and assert on `len()` or
//! `contains()` are unaffected. New family-aware methods
//! ([`iter_best_by_family`], [`len_by_family`],
//! [`diff_since_by_family`], etc.) land alongside the cross-family
//! ones and are the preparation for the multi-threaded RIB.

use std::collections::BTreeMap;

use lr_core::nlri::NlriFamily;
use lr_core::rib::{Route, RouteKey};

/// Generation counter — callers can ask "what changed since generation X?"
#[derive(Debug, Default, Clone)]
pub struct RibDiff {
    pub added: Vec<Route>,
    pub removed: Vec<RouteKey>,
    pub modified: Vec<Route>,
}

/// One per-family shard of the Loc-RIB. The shard owns the
/// `RouteKey → ranked path set` map for one [`NlriFamily`]; the
/// family is the shard's identity, so a `RouteKey`'s family field
/// and the shard it lives in always agree (debug-asserted on every
/// install).
#[derive(Default)]
struct RibShard {
    inner: BTreeMap<RouteKey, Vec<Route>>,
}

impl RibShard {
    fn len(&self) -> usize {
        self.inner.len()
    }
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    fn paths_len(&self) -> usize {
        self.inner.values().map(|s| s.len()).sum()
    }
}

/// Local RIB after policy. Stores the best path per key, plus — when
/// Add-Path (RFC 7911) keeps more than one path per prefix — the ranked
/// runner-ups behind it. The first element of each set is always the best
/// path (the one non-Add-Path consumers see); single-path operation
/// degenerates to one-element sets.
///
/// Storage is sharded by [`NlriFamily`] (see the module docs); the
/// shard lookup rides `RouteKey::family`. The generation counter and
/// the 16-entry history ring stay at the `LocRib` level because the
/// decision process today walks the whole Loc-RIB — a per-family
/// history lands alongside the multi-threaded RIB follow-up.
#[derive(Default)]
pub struct LocRib {
    shards: BTreeMap<NlriFamily, RibShard>,
    gen: u64,
    /// History of (gen, change) — keeps last 16 diffs.
    history: std::collections::VecDeque<(u64, RibDiff)>,
}

impl LocRib {
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the shard for `family`, creating an empty one if the
    /// family has never been touched. The entry API is the cheapest
    /// way to materialise a shard on first use — a `BTreeMap` lookup
    /// plus an `or_default` insertion that is a no-op when the shard
    /// already exists.
    fn shard_mut(&mut self, family: NlriFamily) -> &mut RibShard {
        self.shards.entry(family).or_default()
    }

    /// Borrow the shard for `family` without materialising one. Used
    /// by the read-side methods so a lookup against a family the RIB
    /// has never held does not create an empty shard entry.
    fn shard(&self, family: NlriFamily) -> Option<&RibShard> {
        self.shards.get(&family)
    }

    /// Install one path for a key, replacing any existing path with the
    /// same RFC 7911 identifier. Callers that only ever install the
    /// single best path get exactly the pre-Add-Path behaviour.
    ///
    /// A re-install of a byte-identical route (same key, same path_id,
    /// same content) is a no-op: the generation counter is not bumped
    /// and no `RibDiff` is pushed. OSPF / Babel runtimes call this
    /// after every SPF recompute, and a recompute that yields the same
    /// routes must not produce a storm of spurious "modified" events
    /// downstream (the API socket thread, the BMP mirror, the
    /// redistribution pipe).
    ///
    /// Returns `true` when the install actually changed the Loc-RIB
    /// (a new path was added, or an existing path was replaced with a
    /// non-identical one). Returns `false` for the byte-identical
    /// no-op so callers can skip the downstream `RouteInstalled`
    /// event — without this signal, OSPF/Babel runtimes that recompute
    /// the same best path on every tick (or every Babel UPDATE
    /// re-advertisement) flood the kernel mirror with redundant
    /// `CreateIpForwardEntry2` / `ip route replace` calls (Windows
    /// returns `ERROR_OBJECT_ALREADY_EXISTS`, Linux burns an RTM_NEWROUTE).
    pub fn install(&mut self, route: Route) -> bool {
        let key = route.key.clone();
        let family = key.family;
        let shard = self.shard_mut(family);
        let was_present = shard.inner.contains_key(&key);
        let set = shard.inner.entry(key.clone()).or_default();
        match set.iter_mut().find(|r| r.path_id == route.path_id) {
            Some(existing) => {
                if *existing == route {
                    // Byte-identical re-install: silent no-op. Matches
                    // `install_set`'s identical-set early-return.
                    return false;
                }
                *existing = route;
            }
            None => set.push(route),
        }
        self.gen += 1;
        let best = self
            .shard(family)
            .and_then(|s| s.inner.get(&key))
            .and_then(|s| s.first())
            .cloned();
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
        true
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
        debug_assert!(
            ranked.iter().all(|r| &r.key == key),
            "install_set: route key mismatch"
        );
        if ranked.is_empty() {
            self.uninstall(key);
            return;
        }
        let family = key.family;
        let shard = self.shard_mut(family);
        let prev_best = shard.inner.get(key).and_then(|s| s.first()).cloned();
        let new_best = ranked.first().expect("ranked non-empty").clone();
        if shard.inner.get(key).map(|s| s.as_slice()) == Some(ranked.as_slice()) {
            // Identical set: nothing to record.
            return;
        }
        shard.inner.insert(key.clone(), ranked);
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
        let family = key.family;
        let removed_set = self.shard_mut(family).inner.remove(key);
        let best = removed_set.as_ref().and_then(|s| s.first()).cloned();
        if removed_set.is_some() {
            self.gen += 1;
            self.push_history(RibDiff {
                added: vec![],
                removed: vec![key.clone()],
                modified: vec![],
            });
            // Drop the shard if it emptied — keeps `families()` and
            // the cross-family iterators from touching empty shards.
            if self
                .shards
                .get(&family)
                .map(|s| s.is_empty())
                .unwrap_or(false)
            {
                self.shards.remove(&family);
            }
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
        self.shard(key.family)
            .and_then(|s| s.inner.get(key))
            .and_then(|set| set.first())
    }

    /// The full ranked path set for a key (best first); empty for absent
    /// keys.
    pub fn paths(&self, key: &RouteKey) -> &[Route] {
        self.shard(key.family)
            .and_then(|s| s.inner.get(key))
            .map(|s| s.as_slice())
            .unwrap_or(&[])
    }

    /// Iterate the best path of every key, across every family. Families
    /// appear in [`NlriFamily`] order; within a family, keys appear in
    /// [`RouteKey`] order.
    pub fn iter_best(&self) -> impl Iterator<Item = &Route> {
        self.shards
            .values()
            .flat_map(|shard| shard.inner.values().filter_map(|set| set.first()))
    }

    /// Iterate every path in every set (the Add-Path view of the Loc-RIB).
    /// Families appear in [`NlriFamily`] order; within a family, keys
    /// appear in [`RouteKey`] order.
    pub fn iter_paths(&self) -> impl Iterator<Item = &Route> {
        self.shards
            .values()
            .flat_map(|shard| shard.inner.values().flatten())
    }

    /// Iterate whole path sets with their keys: `(key, ranked set)`.
    /// Families appear in [`NlriFamily`] order; within a family, keys
    /// appear in [`RouteKey`] order.
    pub fn iter_sets(&self) -> impl Iterator<Item = (&RouteKey, &[Route])> {
        self.shards
            .values()
            .flat_map(|shard| shard.inner.iter().map(|(k, v)| (k, v.as_slice())))
    }

    /// Number of keys (prefixes), not paths, across every family.
    pub fn len(&self) -> usize {
        self.shards.values().map(|s| s.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.shards.values().all(|s| s.is_empty())
    }

    /// Total number of stored paths (>= `len()` with Add-Path), across
    /// every family.
    pub fn paths_len(&self) -> usize {
        self.shards.values().map(|s| s.paths_len()).sum()
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

    // ---- Family-aware accessors (issue #101 — Per-AFI RIB sharding) ----
    //
    // The cross-family methods above are the frozen public API; the
    // methods below are the new family-aware surface the
    // multi-threaded RIB follow-up shards its per-family lock on.
    // They are additive — no existing caller needs to change — and
    // each is a single-shard walk, so a caller iterating the IPv6
    // table does not touch the IPv4 table's memory.

    /// The families that currently hold at least one route, in
    /// [`NlriFamily`] order. Empty shards are dropped on uninstall, so
    /// every family this yields has a non-empty shard behind it.
    ///
    /// Returns a `Vec` rather than `impl Iterator` because the family
    /// set is small (typically 1–3 entries) and the caller usually
    /// wants to iterate it twice or hold it across a mutation — a
    /// borrowed iterator would fight the `&mut self` the mutation
    /// needs.
    pub fn families(&self) -> Vec<NlriFamily> {
        self.shards.keys().copied().collect()
    }

    /// Iterate the best path of every key in one family. Returns an
    /// empty iterator when the RIB holds no routes for `family`.
    pub fn iter_best_by_family(&self, family: NlriFamily) -> impl Iterator<Item = &Route> {
        self.shard(family)
            .into_iter()
            .flat_map(|s| s.inner.values().filter_map(|set| set.first()))
    }

    /// Iterate every path in every set in one family (the Add-Path view
    /// for one family). Returns an empty iterator when the RIB holds no
    /// routes for `family`.
    pub fn iter_paths_by_family(&self, family: NlriFamily) -> impl Iterator<Item = &Route> {
        self.shard(family)
            .into_iter()
            .flat_map(|s| s.inner.values().flatten())
    }

    /// Iterate whole path sets with their keys in one family. Returns an
    /// empty iterator when the RIB holds no routes for `family`.
    pub fn iter_sets_by_family(
        &self,
        family: NlriFamily,
    ) -> impl Iterator<Item = (&RouteKey, &[Route])> {
        self.shard(family)
            .into_iter()
            .flat_map(|s| s.inner.iter().map(|(k, v)| (k, v.as_slice())))
    }

    /// Number of keys (prefixes) in one family. `0` when the RIB holds
    /// no routes for `family`.
    pub fn len_by_family(&self, family: NlriFamily) -> usize {
        self.shard(family).map(|s| s.len()).unwrap_or(0)
    }

    /// Total number of stored paths in one family. `0` when the RIB
    /// holds no routes for `family`.
    pub fn paths_len_by_family(&self, family: NlriFamily) -> usize {
        self.shard(family).map(|s| s.paths_len()).unwrap_or(0)
    }

    /// All changes since `gen`, filtered to one family. The history
    /// ring is cross-family (the decision process walks the whole
    /// Loc-RIB today); this method filters the diff entries by the
    /// family carried on every [`RouteKey`]. A per-family history
    /// lands alongside the multi-threaded RIB follow-up.
    pub fn diff_since_by_family(&self, gen: u64, family: NlriFamily) -> RibDiff {
        let mut out = RibDiff::default();
        for (g, d) in self.history.iter().rev() {
            if *g <= gen {
                break;
            }
            out.added
                .extend(d.added.iter().filter(|r| r.key.family == family).cloned());
            out.removed
                .extend(d.removed.iter().filter(|k| k.family == family).cloned());
            out.modified.extend(
                d.modified
                    .iter()
                    .filter(|r| r.key.family == family)
                    .cloned(),
            );
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

    fn route_v6(p: [u8; 16], pl: u8) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v6(p, pl), NlriFamily::IPV6_UNICAST),
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

    /// Single-path `install` of a byte-identical route is a no-op —
    /// no generation bump, no diff entry. Mirrors `install_set`'s
    /// identical-set early-return. OSPF / Babel runtimes call `install`
    /// after every SPF recompute, and a recompute that yields the
    /// same routes must not produce a storm of spurious "modified"
    /// diffs downstream.
    #[test]
    fn install_identical_route_is_no_op() {
        let mut rib = LocRib::new();
        let r = route([192, 0, 2, 0], 24);
        rib.install(r.clone());
        let gen = rib.generation();
        let diff_len_before = rib.diff_since(gen).added.len()
            + rib.diff_since(gen).modified.len()
            + rib.diff_since(gen).removed.len();
        // Re-install the byte-identical route.
        rib.install(r);
        assert_eq!(
            rib.generation(),
            gen,
            "identical re-install does not bump the generation"
        );
        let diff = rib.diff_since(gen);
        let diff_len_after = diff.added.len() + diff.modified.len() + diff.removed.len();
        assert_eq!(diff_len_before, 0);
        assert_eq!(diff_len_after, 0, "no diff entries pushed");
    }

    /// `install` still detects a content change (different metric on
    /// the same path_id) and bumps the generation accordingly. The
    /// no-op fast path only fires on full byte equality, matching
    /// `install_set`'s identical-set contract.
    #[test]
    fn install_with_changed_metric_bumps_generation() {
        let mut rib = LocRib::new();
        let mut a = route([192, 0, 2, 0], 24);
        a.preference.metric = 5;
        rib.install(a.clone());
        let gen = rib.generation();
        let mut b = route([192, 0, 2, 0], 24);
        b.preference.metric = 9;
        rib.install(b.clone());
        assert_eq!(
            rib.generation(),
            gen + 1,
            "different content → generation bump"
        );
        assert_eq!(
            rib.best(&a.key).unwrap().preference.metric,
            9,
            "new content took effect"
        );
    }

    /// The `bool` return value is the signal `apply_runtime_delta`
    /// uses to skip the downstream `RouteInstalled` event for
    /// byte-identical re-installs. A fresh install returns `true`;
    /// a byte-identical re-install returns `false`; a content change
    /// returns `true` again.
    #[test]
    fn install_returns_changed_signal() {
        let mut rib = LocRib::new();
        let r = route([198, 51, 100, 0], 24);
        assert!(rib.install(r.clone()), "fresh install must signal changed");
        assert!(
            !rib.install(r.clone()),
            "byte-identical re-install must signal unchanged"
        );
        let mut changed = route([198, 51, 100, 0], 24);
        changed.preference.metric = 7;
        assert!(
            rib.install(changed.clone()),
            "content change must signal changed"
        );
        assert!(
            !rib.install(changed),
            "re-install of the new content must signal unchanged"
        );
    }

    // ---- Per-AFI sharding tests (issue #101) ----

    /// A route installed in one family is invisible to a family-aware
    /// walk of a different family. The shard boundary is the
    /// correctness invariant the multi-threaded RIB follow-up shards
    /// its per-family lock on.
    #[test]
    fn families_are_isolated() {
        let mut rib = LocRib::new();
        rib.install(route([203, 0, 113, 0], 24));
        rib.install(route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        ));
        assert_eq!(rib.len(), 2, "two routes total across two families");
        assert_eq!(
            rib.len_by_family(NlriFamily::IPV4_UNICAST),
            1,
            "one IPv4 route"
        );
        assert_eq!(
            rib.len_by_family(NlriFamily::IPV6_UNICAST),
            1,
            "one IPv6 route"
        );
        assert_eq!(
            rib.len_by_family(NlriFamily::IPV4_MPLS_VPN),
            0,
            "no routes in an untouched family"
        );
        // Family-aware iteration sees only its own family.
        let v4_best: Vec<_> = rib.iter_best_by_family(NlriFamily::IPV4_UNICAST).collect();
        let v6_best: Vec<_> = rib.iter_best_by_family(NlriFamily::IPV6_UNICAST).collect();
        assert_eq!(v4_best.len(), 1);
        assert_eq!(v6_best.len(), 1);
        assert_eq!(
            v4_best[0].key.family,
            NlriFamily::IPV4_UNICAST,
            "v4 walk yields only v4"
        );
        assert_eq!(
            v6_best[0].key.family,
            NlriFamily::IPV6_UNICAST,
            "v6 walk yields only v6"
        );
    }

    /// The cross-family iterators are the union of the per-family
    /// shards, in `NlriFamily` order. A caller collecting into a
    /// `Vec` and asserting on `len()` sees every route exactly once.
    #[test]
    fn cross_family_iterators_are_the_union() {
        let mut rib = LocRib::new();
        rib.install(route([10, 0, 0, 0], 8));
        rib.install(route([192, 0, 2, 0], 24));
        rib.install(route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        ));
        rib.install(route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            64,
        ));
        // IPv4 sorts before IPv6 in NlriFamily order (AFI=1 < AFI=2),
        // so the cross-family iteration yields the two v4 routes first,
        // then the two v6 routes.
        let best: Vec<_> = rib.iter_best().collect();
        assert_eq!(best.len(), 4, "every route appears exactly once");
        assert_eq!(best[0].key.family, NlriFamily::IPV4_UNICAST);
        assert_eq!(best[1].key.family, NlriFamily::IPV4_UNICAST);
        assert_eq!(best[2].key.family, NlriFamily::IPV6_UNICAST);
        assert_eq!(best[3].key.family, NlriFamily::IPV6_UNICAST);
        // Within IPv4, keys are in RouteKey order: 10.0.0.0/8 < 192.0.2.0/24.
        assert_eq!(best[0].key.prefix, Prefix::new_v4([10, 0, 0, 0], 8));
        assert_eq!(best[1].key.prefix, Prefix::new_v4([192, 0, 2, 0], 24));
    }

    /// `families()` yields exactly the families that hold routes, in
    /// `NlriFamily` order. An empty RIB yields no families; a
    /// single-family RIB yields one; a multi-family RIB yields all.
    #[test]
    fn families_lists_populated_shards_only() {
        let mut rib = LocRib::new();
        assert!(rib.families().is_empty(), "empty rib has no families");
        rib.install(route([10, 0, 0, 0], 8));
        assert_eq!(rib.families().len(), 1, "one family after a v4 install");
        assert_eq!(rib.families()[0], NlriFamily::IPV4_UNICAST);
        rib.install(route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        ));
        assert_eq!(rib.families().len(), 2, "two families after a v6 install");
        let fams = rib.families();
        assert_eq!(
            fams,
            vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST],
            "families in NlriFamily order"
        );
        // Uninstalling the last route in a family drops the shard.
        let v4_key = route([10, 0, 0, 0], 8).key;
        rib.uninstall(&v4_key);
        assert_eq!(
            rib.families().len(),
            1,
            "family dropped when its last route is uninstalled"
        );
        assert_eq!(rib.families()[0], NlriFamily::IPV6_UNICAST);
    }

    /// `diff_since_by_family` filters the cross-family history to one
    /// family. A change in IPv4 does not appear in the IPv6 diff, and
    /// vice versa — the family isolation the multi-threaded RIB
    /// follow-up depends on.
    #[test]
    fn diff_since_by_family_isolates_changes() {
        let mut rib = LocRib::new();
        let before = rib.generation();
        rib.install(route([203, 0, 113, 0], 24));
        rib.install(route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        ));
        let v4_diff = rib.diff_since_by_family(before, NlriFamily::IPV4_UNICAST);
        let v6_diff = rib.diff_since_by_family(before, NlriFamily::IPV6_UNICAST);
        assert_eq!(v4_diff.added.len(), 1, "one v4 add");
        assert_eq!(v4_diff.added[0].key.family, NlriFamily::IPV4_UNICAST);
        assert_eq!(v6_diff.added.len(), 1, "one v6 add");
        assert_eq!(v6_diff.added[0].key.family, NlriFamily::IPV6_UNICAST);
        // The cross-family diff carries both.
        let all_diff = rib.diff_since(before);
        assert_eq!(all_diff.added.len(), 2);
    }

    /// `paths_len_by_family` counts Add-Path runner-ups within one
    /// family. A multi-path IPv4 set does not inflate the IPv6 count.
    #[test]
    fn paths_len_by_family_counts_only_its_own_shard() {
        let mut rib = LocRib::new();
        let key = route([203, 0, 113, 0], 24).key;
        let mut a = route([203, 0, 113, 0], 24);
        a.path_id = 1;
        let mut b = route([203, 0, 113, 0], 24);
        b.path_id = 2;
        rib.install_set(&key, vec![a, b]);
        rib.install(route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        ));
        assert_eq!(
            rib.paths_len_by_family(NlriFamily::IPV4_UNICAST),
            2,
            "two paths in the v4 shard (Add-Path)"
        );
        assert_eq!(
            rib.paths_len_by_family(NlriFamily::IPV6_UNICAST),
            1,
            "one path in the v6 shard"
        );
        assert_eq!(rib.paths_len(), 3, "three paths total");
    }

    /// `iter_sets_by_family` yields the `(key, ranked set)` pairs for
    /// one family only. A caller walking the IPv6 shard does not
    /// touch the IPv4 shard's memory — the payoff the sharding work
    /// exists for.
    #[test]
    fn iter_sets_by_family_is_one_shard() {
        let mut rib = LocRib::new();
        let v4_key = route([203, 0, 113, 0], 24).key;
        let v6_key = route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        )
        .key;
        rib.install(route([203, 0, 113, 0], 24));
        rib.install(route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        ));
        let v4_sets: Vec<_> = rib.iter_sets_by_family(NlriFamily::IPV4_UNICAST).collect();
        let v6_sets: Vec<_> = rib.iter_sets_by_family(NlriFamily::IPV6_UNICAST).collect();
        assert_eq!(v4_sets.len(), 1);
        assert_eq!(v6_sets.len(), 1);
        assert_eq!(v4_sets[0].0, &v4_key);
        assert_eq!(v6_sets[0].0, &v6_key);
        // A family the RIB has never held yields nothing.
        let empty_sets: Vec<_> = rib.iter_sets_by_family(NlriFamily::IPV4_MPLS_VPN).collect();
        assert!(empty_sets.is_empty());
    }
}
