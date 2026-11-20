//! Per-neighbour Babel route cache and best-path selection (RFC 8966 §3.5).
//!
//! BIRD keeps one `struct babel_route` per (prefix, neighbour) and picks the
//! lowest-metric feasible route for each prefix across all neighbours. FRR
//! uses the same (prefix, neighbour) shape in `babeld/route.c`. A single
//! speaker represents one interface, which normally has several neighbours,
//! so a table that stores one link cost and one next hop for the whole
//! interface cannot select routes: the last datagram heard wins.
//!
//! This module holds the per-neighbour state BIRD and FRR keep. It is
//! additive: [`BabelRouteTable`](crate::route::BabelRouteTable) and the C ABI
//! built on it keep their existing surface.
//!
//! The three indexes mirror BIRD's names:
//!
//! - `routes` — one [`PeerRoute`] per (destination, neighbour), keyed by the
//!   neighbour's source address, with the metric the receiver computed
//!   (`advertised metric + that neighbour's link cost`).
//! - `sources` — the best (seqno, advertised metric) per (destination,
//!   origin router-id), the feasibility source table of RFC 8966 §3.5.1.
//! - the caller's `selected` map — the neighbour whose route won each
//!   destination's election, kept so a tie does not churn the next hop.

use std::collections::BTreeMap;

use lr_core::addr::{IpAddr, Prefix};

use crate::route::{hold_ms, BabelRoute, RouteKey};

/// A destination plus its optional source-specific prefix (RFC 9079).
pub type RouteDest = (Prefix, Option<Prefix>);

/// Return the destination key a route belongs to.
pub fn dest_of(key: &RouteKey) -> RouteDest {
    (key.destination, key.source.as_ref().map(|s| s.prefix))
}

/// One route learned from one neighbour. `advert_metric` is what the origin
/// advertised; `metric` adds this neighbour's link cost (RFC 8966 §3.4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRoute {
    pub key: RouteKey,
    /// Source address of the neighbour that sent the Update. This is the
    /// route's identity inside one interface, as in BIRD's `r->neigh`.
    pub neighbor: IpAddr,
    pub seqno: u16,
    pub advert_metric: u32,
    pub metric: u32,
    pub next_hop: IpAddr,
    pub feasible: bool,
    pub interval_cs: u16,
    pub last_seen_ms: u64,
}

impl PeerRoute {
    /// Project onto the embedding-facing [`BabelRoute`] type.
    pub fn to_babel_route(&self) -> BabelRoute {
        BabelRoute {
            key: self.key.clone(),
            seqno: self.seqno,
            metric: self.metric,
            next_hop: self.next_hop,
            feasible: self.feasible,
            installed: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceMetric {
    seqno: u16,
    metric: u32,
}

/// Best-known feasible (seqno, advertised metric) claimed by an origin.
fn better_claim(new: &SourceMetric, old: Option<SourceMetric>) -> bool {
    old.is_none_or(|prev| {
        let s_cmp = (new.seqno as i16).wrapping_sub(prev.seqno as i16);
        s_cmp > 0 || (s_cmp == 0 && new.metric < prev.metric)
    })
}

/// RFC 8966 §3.5.1 applied to an advertisement for a source we have
/// already heard. The RFC compares with `<`, but its feasibility distance
/// is the minimum we have *sent* (§3.7.3), so BIRD and FRR keep an infinite
/// baseline for learned sources and accept an equal metric from another
/// neighbour. Our source table records the best claim actually heard, so
/// `<=` is required: the same origin claim re-advertised by a second
/// neighbour is an equal-cost alternate route, not a loop. A strictly
/// worse metric at the same seqno is still rejected, which keeps a link
/// cost spike from displacing the feasible route.
fn advertisement_feasible(seqno: u16, metric: u32, fd: SourceMetric) -> bool {
    let s_cmp = (seqno as i16).wrapping_sub(fd.seqno as i16);
    s_cmp > 0 || (s_cmp == 0 && metric <= fd.metric)
}

/// Babel route cache for one interface, holding every neighbour's routes.
#[derive(Default)]
pub struct BabelRouteCache {
    routes: BTreeMap<(RouteDest, IpAddr), PeerRoute>,
    sources: BTreeMap<(RouteDest, [u8; 8]), SourceMetric>,
}

impl BabelRouteCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or refresh one neighbour's claim. Returns `true` when the
    /// route set or a metric changed, so the caller can recompute the delta.
    ///
    /// RFC 8966 §3.5.1 / §3.5.3: an infeasible update is ignored. It never
    /// displaces a feasible route, and it does not change the source table,
    /// so a later feasible update from the same origin can still be
    /// accepted.
    pub fn update(&mut self, route: PeerRoute) -> bool {
        let dest = dest_of(&route.key);
        let key = (dest, route.neighbor);

        // An exact re-announcement is a refresh (RFC 8966 §3.2.5). Handle
        // it before the feasibility gate: the source table holds the best
        // claim, so repeating that exact claim is not "strictly better",
        // yet it must still keep the route alive. BIRD's `babel_handle_update`
        // has the same no-change early return after stamping `expires`.
        if let Some(prev) = self.routes.get_mut(&key) {
            let same_claim = prev.seqno == route.seqno
                && prev.advert_metric == route.advert_metric
                && prev.key.router_id == route.key.router_id
                && prev.next_hop == route.next_hop
                && prev.feasible;
            if same_claim {
                prev.interval_cs = route.interval_cs;
                prev.last_seen_ms = route.last_seen_ms;
                let changed = prev.metric != route.metric;
                prev.metric = route.metric;
                return changed;
            }
        }

        let src_key = (dest, route.key.router_id);
        let claim = SourceMetric {
            seqno: route.seqno,
            metric: route.advert_metric,
        };
        let known = self.sources.get(&src_key).copied();
        let admissible =
            known.is_none_or(|prev| advertisement_feasible(route.seqno, route.advert_metric, prev));
        if !admissible {
            return false;
        }

        if better_claim(&claim, known) {
            self.sources.insert(src_key, claim);
        }
        let mut stored = route;
        stored.feasible = true;
        let changed = self.routes.get(&key).is_none_or(|prev| {
            prev.seqno != stored.seqno
                || prev.advert_metric != stored.advert_metric
                || prev.key.router_id != stored.key.router_id
                || prev.next_hop != stored.next_hop
                || prev.metric != stored.metric
                || !prev.feasible
        });
        self.routes.insert(key, stored);
        changed
    }

    /// Recompute every route learned from `neighbor` after its link cost
    /// changed (BIRD `babel_update_cost`). Returns `true` when a metric
    /// moved, i.e. when the caller must re-run best-path selection.
    pub fn set_neighbor_cost(&mut self, neighbor: IpAddr, cost: u32) -> bool {
        let mut changed = false;
        for r in self.routes.values_mut().filter(|r| r.neighbor == neighbor) {
            let metric = r.advert_metric.saturating_add(cost).min(0xfffe);
            if r.metric != metric {
                r.metric = metric;
                changed = true;
            }
        }
        changed
    }

    /// Retract one neighbour's claim for a destination. Returns the removed
    /// route so the caller can render a precise withdrawal reason.
    pub fn retract(&mut self, dest: RouteDest, neighbor: IpAddr) -> Option<PeerRoute> {
        let removed = self.routes.remove(&(dest, neighbor));
        if let Some(r) = &removed {
            // When the last route from an origin for a destination goes
            // away, forget its feasibility source. This lets the same claim
            // return after a link flap (RFC 8966 §3.5.1 selected-successor
            // exception) without being starved by a stale source entry.
            if !self
                .routes
                .values()
                .any(|x| dest_of(&x.key) == dest && x.key.router_id == r.key.router_id)
            {
                self.sources.remove(&(dest, r.key.router_id));
            }
        }
        removed
    }

    /// Retract every route learned from one neighbour (RFC 8966 §4.6.9
    /// wildcard retraction). BIRD's `babel_flush_neighbor` does the same.
    pub fn retract_all(&mut self, neighbor: IpAddr) -> Vec<PeerRoute> {
        let keys: Vec<RouteDest> = self
            .routes
            .iter()
            .filter(|(_, r)| r.neighbor == neighbor)
            .map(|((dest, _), _)| *dest)
            .collect();
        keys.into_iter()
            .filter_map(|dest| self.retract(dest, neighbor))
            .collect()
    }

    /// Drop routes whose re-announcement hold time lapsed (RFC 8966
    /// §3.2.5), returning the ones removed.
    pub fn expire(&mut self, now_ms: u64) -> Vec<PeerRoute> {
        let gone: Vec<(RouteDest, IpAddr)> = self
            .routes
            .iter()
            .filter(|(_, r)| now_ms.saturating_sub(r.last_seen_ms) > hold_ms(r.interval_cs))
            .map(|((dest, nh), _)| (*dest, *nh))
            .collect();
        gone.into_iter()
            .filter_map(|(dest, nh)| self.retract(dest, nh))
            .collect()
    }

    /// Select the lowest-metric feasible route per destination across all
    /// neighbours (BIRD `babel_select_route`). On a metric tie the neighbour
    /// in `keep` stays selected, matching BIRD's "keep the old one in case
    /// of a tie" rule and avoiding next-hop churn.
    pub fn best_routes(&self, keep: &BTreeMap<RouteDest, IpAddr>) -> Vec<PeerRoute> {
        let mut best: BTreeMap<RouteDest, &PeerRoute> = BTreeMap::new();
        for r in self.routes.values() {
            if !r.feasible {
                continue;
            }
            let dest = dest_of(&r.key);
            match best.get(&dest) {
                Some(prev) if prev.metric < r.metric => continue,
                Some(prev)
                    if prev.metric == r.metric && keep.get(&dest) == Some(&prev.neighbor) =>
                {
                    continue
                }
                _ => {}
            }
            best.insert(dest, r);
        }
        best.into_values().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(last: u8) -> IpAddr {
        IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last])
    }

    fn prefix(last: u8) -> Prefix {
        Prefix::new_v6([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last], 64)
    }

    fn route(neighbor: IpAddr, rid: u8, metric: u32, seqno: u16) -> PeerRoute {
        let dst = prefix(1);
        PeerRoute {
            key: RouteKey {
                destination: dst,
                source: None,
                router_id: [0, 0, 0, 0, 0, 0, 0, rid],
            },
            neighbor,
            seqno,
            advert_metric: metric,
            metric: metric + 96,
            next_hop: neighbor,
            feasible: false,
            interval_cs: 300,
            last_seen_ms: 0,
        }
    }

    fn best(cache: &BabelRouteCache) -> Vec<PeerRoute> {
        cache.best_routes(&BTreeMap::new())
    }

    #[test]
    fn lower_total_metric_wins_across_neighbours() {
        let mut c = BabelRouteCache::new();
        c.update(route(v6(1), 1, 10, 1));
        c.update(route(v6(2), 2, 20, 1));
        let chosen = best(&c);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].neighbor, v6(1));
        assert_eq!(chosen[0].metric, 106);
    }

    #[test]
    fn neighbour_cost_change_reselects_without_new_update() {
        let mut c = BabelRouteCache::new();
        c.update(route(v6(1), 1, 10, 1));
        c.update(route(v6(2), 2, 20, 1));
        // Neighbour 2's link improves; its total metric now beats
        // neighbour 1's. No new Update arrives (BIRD babel_update_cost).
        assert!(c.set_neighbor_cost(v6(2), 1));
        let chosen = best(&c);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].neighbor, v6(2));
        assert_eq!(chosen[0].metric, 21);
    }

    #[test]
    fn metric_tie_keeps_the_selected_neighbour() {
        let mut c = BabelRouteCache::new();
        c.update(route(v6(3), 1, 10, 1));
        c.update(route(v6(1), 2, 10, 1));
        let mut keep = BTreeMap::new();
        keep.insert(dest_of(&route(v6(1), 1, 0, 1).key), v6(3));
        let chosen = c.best_routes(&keep);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].neighbor, v6(3));
    }

    #[test]
    fn retraction_is_scoped_to_one_neighbour() {
        let mut c = BabelRouteCache::new();
        c.update(route(v6(1), 1, 10, 1));
        c.update(route(v6(2), 2, 20, 1));
        assert!(c.retract((prefix(1), None), v6(1)).is_some());
        let chosen = best(&c);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].neighbor, v6(2));
    }

    #[test]
    fn wildcard_retraction_removes_only_the_senders_routes() {
        let mut c = BabelRouteCache::new();
        c.update(route(v6(1), 1, 10, 1));
        let mut other = route(v6(2), 2, 20, 1);
        other.key.destination = prefix(2);
        c.update(other);
        assert_eq!(c.retract_all(v6(1)).len(), 1);
        assert_eq!(best(&c).len(), 1);
        assert_eq!(best(&c)[0].neighbor, v6(2));
    }

    #[test]
    fn infeasible_from_same_origin_is_ignored() {
        let mut c = BabelRouteCache::new();
        c.update(route(v6(1), 1, 10, 5));
        // Same origin, same seqno, worse advertised metric: RFC 8966 §3.5.2.
        assert!(!c.update(route(v6(2), 1, 50, 5)));
        let chosen = best(&c);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].advert_metric, 10);
        assert_eq!(chosen[0].neighbor, v6(1));
    }

    #[test]
    fn same_claim_via_a_second_neighbour_stays_an_alternate() {
        let mut c = BabelRouteCache::new();
        // One origin, one seqno, one advertised metric, heard through two
        // different neighbours. RFC 8966 §3.2.6 keys routes by neighbour,
        // so both entries must survive and the cheapest link wins.
        c.update(route(v6(1), 1, 100, 7));
        assert!(c.update(route(v6(2), 1, 100, 7)));
        assert_eq!(c.len(), 2);
        let chosen = best(&c);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].metric, 196);
    }

    #[test]
    fn distinct_origins_can_advertise_the_same_prefix() {
        let mut c = BabelRouteCache::new();
        c.update(route(v6(1), 1, 100, 5));
        // A different origin's source table is independent, so its worse
        // metric is still feasible.
        assert!(c.update(route(v6(2), 2, 150, 5)));
        assert_eq!(best(&c).len(), 1);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn expiry_is_per_route_and_refresh_pushes_the_deadline() {
        let mut c = BabelRouteCache::new();
        let mut short = route(v6(1), 1, 10, 1);
        short.interval_cs = 300; // hold 30 s
        c.update(short);
        let mut long = route(v6(2), 2, 20, 1);
        long.interval_cs = 1_000; // hold 60 s
        c.update(long);
        // A refresh keeps the short-lived route alive past its first
        // deadline; the long-lived neighbour is untouched.
        let mut refresh = route(v6(1), 1, 10, 1);
        refresh.interval_cs = 300;
        refresh.last_seen_ms = 20_000;
        c.update(refresh);
        assert!(c.expire(30_001).is_empty());
        let gone = c.expire(50_001);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].neighbor, v6(1));
        assert_eq!(c.expire(80_001).len(), 1);
    }
}
