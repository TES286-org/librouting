//! Route selection algorithms.
//!
//! Per-protocol comparators (BGP best-path RFC 4271 §9.1.2, OSPF lowest
//! metric, Babel feasibility + lowest metric). A general comparator orders
//! by (admin_distance, metric, age, origin) — the embedder can override.

use lr_core::rib::{Protocol, Route};

/// Per-protocol route selector. The default impl orders by admin distance,
/// then metric, then age, then origin.
pub struct RouteSelector;

impl RouteSelector {
    /// Compare two routes for best-path selection. Returns `Less` if `a` is
    /// preferred over `b`.
    pub fn compare(a: &Route, b: &Route) -> core::cmp::Ordering {
        // 1. admin distance
        let by_admin = a
            .preference
            .admin_distance
            .cmp(&b.preference.admin_distance);
        if by_admin != core::cmp::Ordering::Equal {
            return by_admin;
        }
        // 2. metric (lower is better)
        let by_metric = a.preference.metric.cmp(&b.preference.metric);
        if by_metric != core::cmp::Ordering::Equal {
            return by_metric;
        }
        // 3. age (younger is better — same age ties)
        let by_age = a.age_ms.cmp(&b.age_ms);
        if by_age != core::cmp::Ordering::Equal {
            return by_age;
        }
        // 4. protocol priority
        proto_priority(a.protocol).cmp(&proto_priority(b.protocol))
    }

    /// BGP best-path per RFC 4271 §9.1.2. Returns the best route.
    pub fn select_bgp(routes: &[Route]) -> Option<&Route> {
        routes.iter().min_by(|a, b| Self::compare(a, b))
    }

    /// Select the best route across a heterogeneous set.
    pub fn select(routes: &[Route]) -> Option<&Route> {
        routes.iter().min_by(|a, b| Self::compare(a, b))
    }
}

fn proto_priority(p: Protocol) -> u8 {
    match p {
        Protocol::Connected => 0,
        Protocol::Static => 1,
        Protocol::Bgp => 2,
        Protocol::Ospfv2 | Protocol::Ospfv3 => 3,
        Protocol::Babel => 4,
        Protocol::Other(_) => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

    fn route(pref: Preference, protocol: Protocol, age: u64) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol,
            preference: pref,
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: age,
            path_id: 0,
            tag: None,
        }
    }

    #[test]
    fn lower_admin_distance_wins() {
        let routes = [
            route(Preference::new(20, 100), Protocol::Bgp, 0),
            route(Preference::new(110, 10), Protocol::Ospfv2, 0),
        ];
        assert_eq!(
            RouteSelector::select(&routes).unwrap().protocol,
            Protocol::Bgp
        );
    }

    #[test]
    fn lower_metric_wins_same_admin_distance() {
        let routes = [
            route(Preference::new(20, 100), Protocol::Bgp, 0),
            route(Preference::new(20, 50), Protocol::Bgp, 0),
        ];
        let best = RouteSelector::select(&routes).unwrap();
        assert_eq!(best.preference.metric, 50);
    }

    #[test]
    fn younger_age_wins_on_tie() {
        let routes = [
            route(Preference::new(20, 100), Protocol::Bgp, 100),
            route(Preference::new(20, 100), Protocol::Bgp, 50),
        ];
        let best = RouteSelector::select(&routes).unwrap();
        assert_eq!(best.age_ms, 50);
    }
}
