//! Babel route table (RFC 8966 §3.2). Implements Adj-RIB-In feasibility tracking
//! per source and selects best routes per destination.

use std::collections::BTreeMap;

use crate::metric::feasible;
use crate::source::SourcePrefix;
use lr_core::addr::Prefix;

/// Key for a route in the Babel table. Includes the destination prefix and
/// optional source-specific prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteKey {
    pub destination: Prefix,
    pub source: Option<SourcePrefix>,
    pub router_id: [u8; 8],
}

/// A single Babel route entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BabelRoute {
    pub key: RouteKey,
    pub seqno: u16,
    pub metric: u32,
    pub next_hop: lr_core::addr::IpAddr,
    pub feasible: bool,
    pub installed: bool,
}

/// Babel route table: tracks routes per source-prefix tuple and selects
/// feasible best routes.
#[derive(Default)]
pub struct BabelRouteTable {
    routes: BTreeMap<RouteKey, BabelRoute>,
    /// Best-known feasible (seqno, metric) per destination+source.
    feasible: BTreeMap<(Prefix, Option<Prefix>), (u16, u32)>,
}

impl BabelRouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, route: BabelRoute) {
        let dst = route.key.destination;
        let src = route.key.source.as_ref().map(|s| s.prefix);
        let feas = self.feasible.get(&(dst, src)).copied();
        let is_feasible = match feas {
            Some((fs, fm)) => feasible(route.seqno, route.metric, fs, fm),
            None => true,
        };
        let mut r = route.clone();
        r.feasible = is_feasible;
        if is_feasible {
            let prev = self.feasible.get(&(dst, src)).copied();
            if prev.is_none_or(|(fs, fm)| {
                let s_cmp = (route.seqno as i16).wrapping_sub(fs as i16);
                s_cmp > 0 || (s_cmp == 0 && route.metric < fm)
            }) {
                self.feasible
                    .insert((dst, src), (route.seqno, route.metric));
            }
        }
        self.routes.insert(r.key.clone(), r);
    }

    pub fn withdraw(&mut self, key: &RouteKey) {
        self.routes.remove(key);
    }

    pub fn get(&self, key: &RouteKey) -> Option<&BabelRoute> {
        self.routes.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&RouteKey, &BabelRoute)> {
        self.routes.iter()
    }

    /// Select the best (lowest-metric) feasible route per destination.
    pub fn best_routes(&self) -> Vec<&BabelRoute> {
        let mut by_dst: BTreeMap<(Prefix, Option<Prefix>), &BabelRoute> = BTreeMap::new();
        for r in self.routes.values() {
            if !r.feasible {
                continue;
            }
            let k = (r.key.destination, r.key.source.as_ref().map(|s| s.prefix));
            match by_dst.get(&k) {
                Some(prev) if prev.metric <= r.metric => continue,
                _ => {
                    by_dst.insert(k, r);
                }
            }
        }
        by_dst.into_values().collect()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::{IpAddr, Prefix};

    fn make_route(seqno: u16, metric: u32, rid: [u8; 8]) -> BabelRoute {
        BabelRoute {
            key: RouteKey {
                destination: Prefix::new_v4([10, 0, 0, 0], 8),
                source: None,
                router_id: rid,
            },
            seqno,
            metric,
            next_hop: IpAddr::V4([10, 0, 0, 1]),
            feasible: false,
            installed: false,
        }
    }

    #[test]
    fn feasible_route_in_table() {
        let mut t = BabelRouteTable::new();
        let r = make_route(1, 100, [1; 8]);
        t.insert(r);
        assert_eq!(t.len(), 1);
        let best = t.best_routes();
        assert_eq!(best.len(), 1);
        assert!(best[0].feasible);
    }

    #[test]
    fn older_seqno_not_feasible() {
        let mut t = BabelRouteTable::new();
        // First route with seqno 5 metric 100
        t.insert(make_route(5, 100, [1; 8]));
        // Second route (different router-id) with seqno 4 metric 50 (older).
        t.insert(make_route(4, 50, [2; 8]));
        let routes = t.iter().collect::<Vec<_>>();
        assert_eq!(routes.len(), 2);
        // The one with seqno 4 should NOT be feasible.
        let r4 = routes.iter().find(|(_, r)| r.seqno == 4).unwrap().1;
        assert!(!r4.feasible);
    }
}
