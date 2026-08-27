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

    pub fn iter_origin<'a>(&'a self, origin: RouteOrigin) -> impl Iterator<Item = &'a Route> + 'a {
        self.inner
            .range(
                (
                    origin,
                    RouteKey::new(
                        lr_core::addr::Prefix::new_v4([0; 4], 0),
                        lr_core::nlri::NlriFamily::IPV4_UNICAST,
                    ),
                    u32::MIN,
                )
                    ..(
                        origin,
                        RouteKey::new(
                            lr_core::addr::Prefix::new_v4([0xff; 4], 32),
                            lr_core::nlri::NlriFamily::IPV4_UNICAST,
                        ),
                        u32::MAX,
                    ),
            )
            .filter(move |((o, _, _), _)| *o == origin)
            .map(|(_, r)| r)
    }

    pub fn get(&self, origin: RouteOrigin, key: &RouteKey, path_id: u32) -> Option<&Route> {
        self.inner.get(&(origin, key.clone(), path_id))
    }

    /// Mutate every route contributed by `origin`. The closure returns the
    /// replacement route, or `None` to remove it. Used by the graceful
    /// restart / LLGR retention logic to mark or purge retained routes in
    /// place (RFC 4724 §4, RFC 9494 §4.2).
    pub fn mutate_origin<F>(&mut self, origin: RouteOrigin, mut f: F)
    where
        F: FnMut(Route) -> Option<Route>,
    {
        let keys: Vec<(RouteOrigin, RouteKey, u32)> = self
            .inner
            .keys()
            .filter(|(o, _, _)| *o == origin)
            .cloned()
            .collect();
        for k in keys {
            let route = self.inner.remove(&k).expect("key just collected");
            if let Some(r) = f(route) {
                self.inner.insert(k, r);
            }
        }
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
    pub fn clear_for(&mut self, origin: RouteOrigin) {
        let keys: Vec<_> = self
            .inner
            .keys()
            .filter(|(o, _, _)| *o == origin)
            .cloned()
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
        Route {
            key: RouteKey::new(Prefix::new_v4(prefix, pl), NlriFamily::IPV4_UNICAST),
            origin,
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id,
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
}
