//! Cross-protocol RIB merging by admin distance.

use std::collections::BTreeMap;

use lr_core::rib::{Route, RouteKey};

/// A multiplexer that takes routes from multiple Loc-RIBs (per protocol) and
/// picks the best per key.
#[derive(Default)]
pub struct RibMux {
    inner: BTreeMap<RouteKey, Route>,
}

impl RibMux {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a route. If a route already exists for the same key, the
    /// lower-preference one wins.
    pub fn install(&mut self, route: Route) {
        let key = route.key.clone();
        match self.inner.get(&key) {
            Some(prev) if prev.preference <= route.preference => (),
            _ => {
                self.inner.insert(key, route);
            }
        }
    }

    pub fn uninstall(&mut self, key: &RouteKey) -> Option<Route> {
        self.inner.remove(key)
    }

    pub fn get(&self, key: &RouteKey) -> Option<&Route> {
        self.inner.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.inner.values()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

    fn route(pref: Preference, protocol: Protocol) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol,
            preference: pref,
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
        }
    }

    #[test]
    fn lower_admin_distance_wins() {
        let mut mux = RibMux::new();
        mux.install(route(Preference::new(110, 10), Protocol::Ospfv2));
        mux.install(route(Preference::new(20, 100), Protocol::Bgp));
        let best = mux
            .get(&route(Preference::new(0, 0), Protocol::Bgp).key)
            .unwrap();
        assert_eq!(best.protocol, Protocol::Bgp);
    }

    #[test]
    fn uninstall_removes() {
        let mut mux = RibMux::new();
        let r = route(Preference::new(20, 100), Protocol::Bgp);
        mux.install(r.clone());
        let removed = mux.uninstall(&r.key);
        assert!(removed.is_some());
        assert!(mux.is_empty());
    }
}
