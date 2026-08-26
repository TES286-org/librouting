//! Adj-RIB-In — pre-policy routes received from peers.

use std::collections::BTreeMap;

use lr_core::rib::{Route, RouteKey, RouteOrigin};

/// Per-peer pre-policy RIB. Keyed by `(origin, route key)`.
#[derive(Default)]
pub struct AdjRibIn {
    inner: BTreeMap<(RouteOrigin, RouteKey), Route>,
}

impl AdjRibIn {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed_pre_policy(&mut self, origin: RouteOrigin, route: Route) {
        let key = (origin, route.key.clone());
        self.inner.insert(key, route);
    }

    pub fn withdraw(&mut self, origin: RouteOrigin, key: &RouteKey) -> Option<Route> {
        self.inner.remove(&(origin, key.clone()))
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
                )
                    ..(
                        origin,
                        RouteKey::new(
                            lr_core::addr::Prefix::new_v4([0xff; 4], 32),
                            lr_core::nlri::NlriFamily::IPV4_UNICAST,
                        ),
                    ),
            )
            .filter(move |((o, _), _)| *o == origin)
            .map(|(_, r)| r)
    }

    pub fn get(&self, origin: RouteOrigin, key: &RouteKey) -> Option<&Route> {
        self.inner.get(&(origin, key.clone()))
    }

    /// Iterate every route in the Adj-RIB-In across all origins.
    pub fn iter_all(&self) -> impl Iterator<Item = &Route> {
        self.inner.values()
    }

    /// Iterate every origin that contributed to a key.
    pub fn origins_for<'a>(&'a self, key: &'a RouteKey) -> impl Iterator<Item = RouteOrigin> + 'a {
        self.inner
            .keys()
            .filter(move |(_, k)| k == key)
            .map(|(o, _)| *o)
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
            .filter(|(o, _)| *o == origin)
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

    fn route(prefix: [u8; 4], pl: u8, origin: RouteOrigin) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4(prefix, pl), NlriFamily::IPV4_UNICAST),
            origin,
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
        }
    }

    #[test]
    fn feed_and_get() {
        let mut rib = AdjRibIn::new();
        let o = RouteOrigin { proto: 1, peer: 1 };
        rib.feed_pre_policy(o, route([10, 0, 0, 0], 8, o));
        assert_eq!(rib.len(), 1);
        let k = RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST);
        let r = rib.get(o, &k);
        assert!(r.is_some());
        rib.withdraw(o, &k);
        assert_eq!(rib.len(), 0);
    }
}
