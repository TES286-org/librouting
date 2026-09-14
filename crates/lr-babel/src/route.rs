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

/// Route expiry bookkeeping (RFC 8966 §3.2.5) — reception metadata the
/// route itself does not carry: the interval the origin's Update
/// announced and when its last re-announcement was seen. Kept on the
/// side so [`BabelRoute`]'s equality (the Loc-RIB diff key) stays purely
/// protocol state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteTiming {
    interval_cs: u16,
    last_seen_ms: u64,
}

/// babeld's route hold time for an announced interval, in milliseconds:
/// `MAX(4 × I/100 + I/50, 15)` seconds with `I` in centiseconds — six
/// times the update interval, at least 15 s.
fn hold_ms(interval_cs: u16) -> u64 {
    (u64::from(interval_cs) * 60).max(15_000)
}

/// Babel route table: tracks routes per source-prefix tuple and selects
/// feasible best routes.
#[derive(Default)]
pub struct BabelRouteTable {
    routes: BTreeMap<RouteKey, BabelRoute>,
    /// Best-known feasible (seqno, metric) per destination+source.
    feasible: BTreeMap<(Prefix, Option<Prefix>), (u16, u32)>,
    /// Expiry clock per route (RFC 8966 §3.2.5).
    timing: BTreeMap<RouteKey, RouteTiming>,
}

impl BabelRouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, route: BabelRoute) {
        self.insert_timed(route, 0, 0);
    }

    /// Insert one route together with its reception time and the
    /// interval its Update announced (RFC 8966 §3.2.5): an exact
    /// re-announcement of the same claim (same source, same seqno, same
    /// metric) is a *refresh* — it must not re-enter the feasibility
    /// machinery, but it does push the expiry deadline out (the
    /// re-announcement is what keeps the route alive).
    pub fn insert_timed(&mut self, route: BabelRoute, interval_cs: u16, now_ms: u64) {
        let timing = RouteTiming {
            interval_cs,
            last_seen_ms: now_ms,
        };
        if let Some(prev) = self.routes.get(&route.key) {
            if prev.seqno == route.seqno && prev.metric == route.metric {
                self.timing.insert(route.key, timing);
                return;
            }
        }
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
        self.timing.insert(route.key, timing);
    }

    pub fn withdraw(&mut self, key: &RouteKey) {
        self.routes.remove(key);
        self.timing.remove(key);
    }

    /// Expire the routes whose re-announcement hold time lapsed
    /// (RFC 8966 §3.2.5): every Update refreshes the hold deadline of
    /// its claim; `hold_ms` out the route goes — babeld's
    /// `hold_time = MAX(4 × I/100 + I/50, 15)` s. Returns the withdrawn
    /// keys so the caller can publish the retraction delta.
    pub fn expire(&mut self, now_ms: u64) -> Vec<RouteKey> {
        let gone: Vec<RouteKey> = self
            .timing
            .iter()
            .filter(|(_, t)| now_ms.saturating_sub(t.last_seen_ms) > hold_ms(t.interval_cs))
            .map(|(k, _)| k.clone())
            .collect();
        for k in &gone {
            self.withdraw(k);
        }
        gone
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

    /// RFC 8966 §3.2.5: a route expires when its hold time (6× the
    /// announced interval, babeld's formula) lapses without a
    /// re-announcement, and a refresh keeps it alive.
    #[test]
    fn routes_expire_without_refresh() {
        let mut t = BabelRouteTable::new();
        let r = make_route(1, 100, [1; 8]);
        let key = r.key.clone();
        // Announced interval 300 cs → hold 18 s.
        t.insert_timed(r, 300, 1_000);
        // Not yet: 17 999 ms of age is inside the hold.
        assert!(t.expire(1_000 + 17_999).is_empty());
        // A refresh at t+10 s pushes the deadline to t+10 s + 18 s.
        t.insert_timed(make_route(1, 100, [1; 8]), 300, 11_000);
        // One ms before the refreshed deadline: still alive.
        assert!(t.expire(11_000 + 17_999).is_empty());
        // Past the refreshed deadline (11 000 + 18 000 + 1): gone.
        let gone = t.expire(11_000 + 18_001);
        assert_eq!(gone, vec![key.clone()]);
        assert!(t.get(&key).is_none());
    }

    /// The hold time has babeld's 15 s floor: even a zero-interval
    /// announcement (or `insert`'s default) survives short windows.
    #[test]
    fn hold_time_floor_is_15s() {
        let mut t = BabelRouteTable::new();
        let r = make_route(1, 100, [1; 8]);
        let key = r.key.clone();
        t.insert_timed(r, 0, 0);
        assert!(t.expire(14_999).is_empty());
        assert_eq!(t.expire(15_001), vec![key]);
    }
}
