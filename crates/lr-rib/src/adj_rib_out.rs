//! Adj-RIB-Out — routes advertised to peers.

use std::collections::BTreeMap;

use lr_core::rib::{Route, RouteKey, RouteOrigin};

/// Per-peer pre-policy RIB for outgoing advertisement.
///
/// Entries are keyed by `(destination, route key)` and, within a key, by
/// the RFC 7911 path identifier *this speaker assigned* when advertising
/// (rank slot + 1). Single-path operation uses identifier 0 exclusively,
/// which preserves the pre-Add-Path one-entry-per-key behaviour.
#[derive(Default)]
pub struct AdjRibOut {
    inner: BTreeMap<(RouteOrigin, RouteKey), BTreeMap<u32, Route>>,
}

impl AdjRibOut {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the advertisement of one path.
    pub fn advertise(&mut self, dest: RouteOrigin, route: &Route, tx_path_id: u32) {
        self.inner
            .entry((dest, route.key.clone()))
            .or_default()
            .insert(tx_path_id, route.clone());
    }

    /// Remove one advertised path. Returns the withdrawn route when it
    /// existed.
    pub fn suppress(
        &mut self,
        dest: RouteOrigin,
        key: &RouteKey,
        tx_path_id: u32,
    ) -> Option<Route> {
        let map = self.inner.get_mut(&(dest, key.clone()))?;
        let removed = map.remove(&tx_path_id);
        if map.is_empty() {
            self.inner.remove(&(dest, key.clone()));
        }
        removed
    }

    /// The path identifiers currently advertised for a key, ascending.
    pub fn tx_path_ids(&self, dest: RouteOrigin, key: &RouteKey) -> Vec<u32> {
        self.inner
            .get(&(dest, key.clone()))
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Every advertised path of a key: `(tx_path_id, route)` pairs.
    pub fn paths_for(&self, dest: RouteOrigin, key: &RouteKey) -> Vec<(u32, Route)> {
        self.inner
            .get(&(dest, key.clone()))
            .map(|m| m.iter().map(|(id, r)| (*id, r.clone())).collect())
            .unwrap_or_default()
    }

    /// Every key of `dest` belonging to `family`, with its advertised
    /// path identifiers — the withdrawal bookkeeping for table refreshes.
    pub fn advertised_keys(
        &self,
        dest: RouteOrigin,
        family: lr_core::nlri::NlriFamily,
    ) -> Vec<(RouteKey, Vec<u32>)> {
        self.inner
            .iter()
            .filter(|((d, k), _)| *d == dest && k.family == family)
            .map(|((_, k), m)| (k.clone(), m.keys().copied().collect()))
            .collect()
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
            .flat_map(|(_, m)| m.values())
    }

    pub fn len(&self) -> usize {
        self.inner.values().map(|m| m.len()).sum()
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

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteOrigin};

    fn route(prefix: [u8; 4], pl: u8, path_id: u32) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4(prefix, pl), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 7 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id,
        }
    }

    #[test]
    fn advertise_and_suppress_paths() {
        let mut rib = AdjRibOut::new();
        let dest = RouteOrigin { proto: 0, peer: 1 };
        let key = RouteKey::new(
            Prefix::new_v4([203, 0, 113, 0], 24),
            NlriFamily::IPV4_UNICAST,
        );
        rib.advertise(dest, &route([203, 0, 113, 0], 24, 0), 1);
        rib.advertise(dest, &route([203, 0, 113, 0], 24, 0), 2);
        assert_eq!(rib.len(), 2);
        assert_eq!(rib.tx_path_ids(dest, &key), vec![1, 2]);
        assert!(rib.suppress(dest, &key, 1).is_some());
        assert_eq!(rib.tx_path_ids(dest, &key), vec![2]);
        assert!(rib.suppress(dest, &key, 2).is_some());
        assert_eq!(rib.len(), 0);
    }

    #[test]
    fn clear_for_drops_every_path_of_a_session() {
        let mut rib = AdjRibOut::new();
        let a = RouteOrigin { proto: 0, peer: 1 };
        let b = RouteOrigin { proto: 0, peer: 2 };
        rib.advertise(a, &route([10, 0, 0, 0], 8, 0), 1);
        rib.advertise(a, &route([10, 0, 0, 0], 8, 0), 2);
        rib.advertise(b, &route([10, 0, 0, 0], 8, 0), 1);
        rib.clear_for(a);
        assert_eq!(rib.len(), 1);
    }
}
