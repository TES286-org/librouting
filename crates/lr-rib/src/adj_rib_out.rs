//! Adj-RIB-Out — pre-policy routes advertised to peers.

use std::collections::BTreeMap;

use lr_core::rib::{Route, RouteKey, RouteOrigin};

/// Per-peer pre-policy RIB for outgoing advertisement.
#[derive(Default)]
pub struct AdjRibOut {
    inner: BTreeMap<(RouteOrigin, RouteKey), Route>,
}

impl AdjRibOut {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn advertise(&mut self, dest: RouteOrigin, route: &Route) {
        self.inner.insert((dest, route.key.clone()), route.clone());
    }

    pub fn suppress(&mut self, dest: RouteOrigin, key: &RouteKey) -> Option<Route> {
        self.inner.remove(&(dest, key.clone()))
    }

    pub fn iter_for<'a>(&'a self, dest: RouteOrigin) -> impl Iterator<Item = &'a Route> + 'a {
        self.inner
            .range(
                (
                    dest,
                    RouteKey::new(
                        lr_core::addr::Prefix::new_v4([0; 4], 0),
                        lr_core::nlri::NlriFamily::IPV4_UNICAST,
                    ),
                )
                    ..(
                        dest,
                        RouteKey::new(
                            lr_core::addr::Prefix::new_v4([0xff; 4], 32),
                            lr_core::nlri::NlriFamily::IPV4_UNICAST,
                        ),
                    ),
            )
            .filter(move |((d, _), _)| *d == dest)
            .map(|(_, r)| r)
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
    pub fn clear_for(&mut self, dest: RouteOrigin) {
        let keys: Vec<_> = self
            .inner
            .keys()
            .filter(|(d, _)| *d == dest)
            .cloned()
            .collect();
        for k in keys {
            self.inner.remove(&k);
        }
    }
}
