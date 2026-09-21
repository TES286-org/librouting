//! Adj-RIB-In — pre-policy routes received from peers.

use std::collections::BTreeMap;

use lr_core::rib::{Route, RouteKey, RouteOrigin};

/// Per-peer pre-policy RIB. Keyed by `(origin, route key, path_id)`.
///
/// The third key element is the RFC 7911 Add-Path identifier: a peer that
/// negotiated Add-Path may advertise several paths to the same prefix,
/// distinguished by their path identifiers. For single-path operation
/// every identifier is 0, so the map degenerates to one entry per
/// `(origin, key)` — exactly the pre-Add-Path behaviour.
#[derive(Default)]
pub struct AdjRibIn {
    inner: BTreeMap<(RouteOrigin, RouteKey, u32), Route>,
}

impl AdjRibIn {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed_pre_policy(&mut self, origin: RouteOrigin, route: Route) {
        let key = (origin, route.key.clone(), route.path_id);
        self.inner.insert(key, route);
    }

    /// Remove one path: `(origin, key, path_id)`. Returns the removed
    /// route when it existed.
    pub fn withdraw(&mut self, origin: RouteOrigin, key: &RouteKey, path_id: u32) -> Option<Route> {
        self.inner.remove(&(origin, key.clone(), path_id))
    }

    /// Every route contributed by `origin`, across all address families.
    ///
    /// The map is keyed by `(origin, RouteKey, path_id)` with `RouteKey`'s
    /// derived `(prefix, family, source)` ordering, in which every IPv6
    /// prefix sorts above every IPv4 one. A range bounded at an
    /// IPv4-unicast ceiling would therefore hide a peer's IPv6,
    /// labelled-unicast and source-specific routes — breaking session
    /// teardown, soft reconfiguration and GR/LLGR retention for
    /// multi-family peers. Bounding with the absolute RouteKey extremes
    /// instead covers every key of the origin.
    pub fn iter_origin<'a>(&'a self, origin: RouteOrigin) -> impl Iterator<Item = &'a Route> + 'a {
        self.inner
            .range(
                (origin, crate::min_route_key(), u32::MIN)
                    ..=(origin, crate::max_route_key(), u32::MAX),
            )
            .map(|(_, r)| r)
    }

    pub fn get(&self, origin: RouteOrigin, key: &RouteKey, path_id: u32) -> Option<&Route> {
        self.inner.get(&(origin, key.clone(), path_id))
    }

    /// Mutate every route contributed by `origin`. The closure returns the
    /// replacement route, or `None` to remove it. Used by the graceful
    /// restart / LLGR retention logic to mark or purge retained routes in
    /// place (RFC 4724 §4, RFC 9494 §4.2). Returns the number of routes
    /// removed, so callers can keep incremental per-origin counters exact.
    ///
    /// The closure is contractually expected to preserve the route's
    /// `(origin, key, path_id)` identity — only the route content (its
    /// attributes, metric, age) may change. The map key tuple is rebuilt
    /// from the original `origin` parameter and the route's own
    /// `key` / `path_id`, so a closure that mutates those fields would
    /// drop the route under its old identity and re-insert it under a
    /// new one — but no current caller does that.
    ///
    /// Performance: the (origin, key, path_id) ordering keeps every
    /// key for one origin contiguous in the BTreeMap, so a single
    /// `range` walk collects exactly the matching keys. The previous
    /// `keys().filter()` implementation was O(N) over the *whole*
    /// Adj-RIB-In on every GR / LLGR pass — a full-table peer
    /// restart paid 800k iterations to find ~10k matching keys.
    pub fn mutate_origin<F>(&mut self, origin: RouteOrigin, mut f: F) -> usize
    where
        F: FnMut(Route) -> Option<Route>,
    {
        let keys: Vec<(RouteOrigin, RouteKey, u32)> = self
            .inner
            .range(
                (origin, crate::min_route_key(), u32::MIN)
                    ..=(origin, crate::max_route_key(), u32::MAX),
            )
            .map(|(k, _)| k.clone())
            .collect();
        let mut removed = 0usize;
        for k in keys {
            let route = self.inner.remove(&k).expect("key just collected");
            if let Some(r) = f(route) {
                self.inner.insert(k, r);
            } else {
                removed += 1;
            }
        }
        removed
    }

    /// Iterate every route in the Adj-RIB-In across all origins.
    pub fn iter_all(&self) -> impl Iterator<Item = &Route> {
        self.inner.values()
    }

    /// Iterate every origin that contributed to a key.
    pub fn origins_for<'a>(&'a self, key: &'a RouteKey) -> impl Iterator<Item = RouteOrigin> + 'a {
        self.inner
            .keys()
            .filter(move |(_, k, _)| k == key)
            .map(|(o, _, _)| *o)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub fn clear(&mut self) {
        self.inner.clear();
    }
    /// Drop every route `origin` contributed. Range-bounded to the
    /// origin's slot in the (origin, key, path_id) ordering — the old
    /// `keys().filter()` shape scanned the whole Adj-RIB-In to clear
    /// one peer's slice of it.
    pub fn clear_for(&mut self, origin: RouteOrigin) {
        let keys: Vec<(RouteOrigin, RouteKey, u32)> = self
            .inner
            .range(
                (origin, crate::min_route_key(), u32::MIN)
                    ..=(origin, crate::max_route_key(), u32::MAX),
            )
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.inner.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route};

    fn route(prefix: [u8; 4], pl: u8, origin: RouteOrigin, path_id: u32) -> Route {
        route_in(
            Prefix::new_v4(prefix, pl),
            NlriFamily::IPV4_UNICAST,
            origin,
            path_id,
        )
    }

    fn route_in(prefix: Prefix, family: NlriFamily, origin: RouteOrigin, path_id: u32) -> Route {
        Route {
            key: RouteKey::new(prefix, family),
            origin,
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id,
            tag: None,
        }
    }

    #[test]
    fn feed_and_get() {
        let mut rib = AdjRibIn::new();
        let o = RouteOrigin { proto: 1, peer: 1 };
        rib.feed_pre_policy(o, route([10, 0, 0, 0], 8, o, 0));
        assert_eq!(rib.len(), 1);
        let k = RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST);
        let r = rib.get(o, &k, 0);
        assert!(r.is_some());
        rib.withdraw(o, &k, 0);
        assert_eq!(rib.len(), 0);
    }

    /// RFC 7911: two paths to the same prefix from one peer coexist when
    /// their path identifiers differ; withdrawing one leaves the other.
    #[test]
    fn add_path_paths_coexist_per_identifier() {
        let mut rib = AdjRibIn::new();
        let o = RouteOrigin { proto: 0, peer: 9 };
        rib.feed_pre_policy(o, route([203, 0, 113, 0], 24, o, 1));
        rib.feed_pre_policy(o, route([203, 0, 113, 0], 24, o, 2));
        assert_eq!(rib.len(), 2);

        let k = RouteKey::new(
            Prefix::new_v4([203, 0, 113, 0], 24),
            NlriFamily::IPV4_UNICAST,
        );
        assert!(rib.withdraw(o, &k, 1).is_some());
        assert_eq!(rib.len(), 1);
        assert!(rib.get(o, &k, 2).is_some());
        // A re-advertisement under the same identifier replaces in place.
        rib.feed_pre_policy(o, route([203, 0, 113, 0], 24, o, 2));
        assert_eq!(rib.len(), 1);
    }

    /// Same identifier from two different origins is two distinct paths
    /// (identifiers are scoped to the advertising session).
    #[test]
    fn same_identifier_different_origins_coexist() {
        let mut rib = AdjRibIn::new();
        let a = RouteOrigin { proto: 0, peer: 1 };
        let b = RouteOrigin { proto: 0, peer: 2 };
        rib.feed_pre_policy(a, route([203, 0, 113, 0], 24, a, 1));
        rib.feed_pre_policy(b, route([203, 0, 113, 0], 24, b, 1));
        assert_eq!(rib.len(), 2);
    }

    /// Regression (audit C1): `iter_origin` must return every family one
    /// origin advertised. IPv6, labelled-unicast and source-specific keys
    /// sort *above* the IPv4-unicast ceiling the old range used, so they
    /// used to be invisible — breaking session teardown, soft-reconfig
    /// and GR/LLGR retention for multi-family peers.
    #[test]
    fn iter_origin_covers_every_family_of_the_origin() {
        let mut rib = AdjRibIn::new();
        let o = RouteOrigin { proto: 0, peer: 1 };
        // IPv4 unicast.
        rib.feed_pre_policy(o, route([203, 0, 113, 0], 24, o, 0));
        // IPv6 unicast — sorts above every IPv4 key.
        rib.feed_pre_policy(
            o,
            route_in(
                Prefix::new_v6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
                NlriFamily::IPV6_UNICAST,
                o,
                0,
            ),
        );
        // IPv4 labelled unicast (RFC 8277 SAFI 4).
        rib.feed_pre_policy(
            o,
            route_in(
                Prefix::new_v4([198, 51, 100, 0], 24),
                NlriFamily::IPV4_LABELED_UNICAST,
                o,
                0,
            ),
        );
        // A route exactly at the old range's upper bound in a *different*
        // family must also be visible.
        rib.feed_pre_policy(
            o,
            route_in(
                Prefix::new_v4([255, 255, 255, 255], 32),
                NlriFamily::IPV4_LABELED_UNICAST,
                o,
                0,
            ),
        );
        let got: Vec<_> = rib.iter_origin(o).cloned().collect();
        assert_eq!(
            got.len(),
            4,
            "v4, v6, labelled and bound-adjacent routes all visible"
        );
        let families: std::collections::BTreeSet<NlriFamily> =
            got.iter().map(|r| r.key.family).collect();
        assert!(families.contains(&NlriFamily::IPV4_UNICAST));
        assert!(families.contains(&NlriFamily::IPV6_UNICAST));
        assert!(families.contains(&NlriFamily::IPV4_LABELED_UNICAST));
        // A different origin stays excluded.
        let other = RouteOrigin { proto: 0, peer: 2 };
        rib.feed_pre_policy(other, route([10, 0, 0, 0], 8, other, 0));
        assert_eq!(rib.iter_origin(o).count(), 4);
        assert_eq!(rib.iter_origin(other).count(), 1);
    }

    /// `mutate_origin` must touch only the routes of one origin across
    /// every family — the (origin, key, path_id) range bounds cover v4,
    /// v6 and labelled-unicast keys alike. Exercises the GR / LLGR
    /// retention path (RFC 4724 §4, RFC 9494 §4.2).
    #[test]
    fn mutate_origin_only_touches_one_origin_across_families() {
        let mut rib = AdjRibIn::new();
        let a = RouteOrigin { proto: 0, peer: 1 };
        let b = RouteOrigin { proto: 0, peer: 2 };
        // Three routes for `a` across three families + one for `b`.
        rib.feed_pre_policy(a, route([203, 0, 113, 0], 24, a, 0));
        rib.feed_pre_policy(
            a,
            route_in(
                Prefix::new_v6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
                NlriFamily::IPV6_UNICAST,
                a,
                0,
            ),
        );
        rib.feed_pre_policy(
            a,
            route_in(
                Prefix::new_v4([198, 51, 100, 0], 24),
                NlriFamily::IPV4_LABELED_UNICAST,
                a,
                0,
            ),
        );
        rib.feed_pre_policy(b, route([10, 0, 0, 0], 8, b, 0));
        assert_eq!(rib.len(), 4);

        // Drop only `a`'s routes; `b`'s contribution must survive.
        let removed = rib.mutate_origin(a, |_| None);
        assert_eq!(removed, 3, "all three of a's families purged");
        assert_eq!(rib.len(), 1, "b's route untouched");
        assert_eq!(rib.iter_origin(a).count(), 0);
        assert_eq!(rib.iter_origin(b).count(), 1);

        // Rebuild `a`'s slice and verify the closure sees every family.
        rib.feed_pre_policy(a, route([203, 0, 113, 0], 24, a, 0));
        rib.feed_pre_policy(
            a,
            route_in(
                Prefix::new_v6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
                NlriFamily::IPV6_UNICAST,
                a,
                0,
            ),
        );
        let mut seen_families = std::collections::BTreeSet::new();
        rib.mutate_origin(a, |r| {
            seen_families.insert(r.key.family);
            Some(r)
        });
        assert!(seen_families.contains(&NlriFamily::IPV4_UNICAST));
        assert!(seen_families.contains(&NlriFamily::IPV6_UNICAST));
        // `b` was never visited: its slice is intact.
        assert_eq!(rib.iter_origin(b).count(), 1, "b's route still there");
    }

    /// `clear_for` mirrors the multi-family, multi-origin contract: only
    /// the named origin's slice is dropped, every other origin keeps its
    /// routes across every family.
    #[test]
    fn clear_for_only_drops_one_origin_across_families() {
        let mut rib = AdjRibIn::new();
        let a = RouteOrigin { proto: 0, peer: 1 };
        let b = RouteOrigin { proto: 0, peer: 2 };
        rib.feed_pre_policy(a, route([203, 0, 113, 0], 24, a, 0));
        rib.feed_pre_policy(
            a,
            route_in(
                Prefix::new_v6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
                NlriFamily::IPV6_UNICAST,
                a,
                0,
            ),
        );
        rib.feed_pre_policy(b, route([10, 0, 0, 0], 8, b, 0));
        rib.feed_pre_policy(
            b,
            route_in(
                Prefix::new_v6(
                    [0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
                NlriFamily::IPV6_UNICAST,
                b,
                0,
            ),
        );
        assert_eq!(rib.len(), 4);
        rib.clear_for(a);
        assert_eq!(rib.len(), 2, "only a's slice (v4 + v6) is gone");
        assert_eq!(rib.iter_origin(a).count(), 0);
        assert_eq!(rib.iter_origin(b).count(), 2);
    }
}
