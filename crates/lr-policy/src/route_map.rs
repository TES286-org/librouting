//! Route-map: ordered sequence of (match, set) entries.

use crate::action::{apply_set_checked, evaluate_match, MatchCondition, MatchResolver, SetAction};
use lr_core::rib::Route;

#[derive(Debug, Clone, Default)]
pub struct RouteMapEntry {
    /// Optional match conditions (all must be true).
    pub matches: Vec<MatchCondition>,
    /// Optional set actions.
    pub sets: Vec<SetAction>,
    /// None = continue to next entry; Some(true) = permit; Some(false) = deny.
    pub verdict: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct RouteMap {
    pub entries: Vec<RouteMapEntry>,
}

impl RouteMap {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, e: RouteMapEntry) {
        self.entries.push(e);
    }

    /// Returns `Some(true)` if the route is accepted (with sets applied),
    /// `Some(false)` if rejected, `None` if the map fell through.
    ///
    /// Fail-closed: a [`SetAction`] that cannot be applied (e.g. a
    /// BGP-specific variant configured against a no-`bgp` build of
    /// `lr-policy`) yields [`crate::action::ApplySetError`], and the
    /// route is denied — `Some(false)` — rather than silently passing
    /// through with a partial policy applied. This matches the
    /// fail-closed tightening that landed for `CommunityList` /
    /// `AsPathFilter`: an operator who configures a BGP-specific
    /// action against a build that cannot execute it sees the route
    /// rejected (and a `tracing::warn!` line in the daemon's log
    /// stream) instead of slipping past the policy.
    pub fn evaluate(&self, route: &mut Route, resolver: &dyn MatchResolver) -> Option<bool> {
        for e in &self.entries {
            let all_match = e.matches.iter().all(|m| evaluate_match(m, route, resolver));
            if !all_match {
                continue;
            }
            for s in &e.sets {
                if let Err(err) = apply_set_checked(s, route) {
                    tracing::warn!(
                        "route-map: set action `{}` denied the route: {}",
                        s.name(),
                        err
                    );
                    return Some(false);
                }
            }
            match e.verdict {
                Some(v) => return Some(v),
                None => continue,
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{MatchCondition, SetAction};
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

    struct DummyResolver;
    impl MatchResolver for DummyResolver {
        fn prefix_in(&self, _id: u32, _p: &Prefix) -> bool {
            true
        }
        fn as_path_in(&self, _id: u32, _r: &Route) -> bool {
            true
        }
        fn community_in(&self, _id: u32, _r: &Route) -> bool {
            true
        }
        fn next_hop_in(&self, _id: u32, _r: &Route) -> bool {
            true
        }
    }

    fn route() -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    #[test]
    fn permit_and_set_metric() {
        let mut map = RouteMap::new();
        map.push(RouteMapEntry {
            matches: vec![MatchCondition::PrefixIn { list_id: 1 }],
            sets: vec![SetAction::SetMetric(50)],
            verdict: Some(true),
        });
        let mut r = route();
        let verdict = map.evaluate(&mut r, &DummyResolver);
        assert_eq!(verdict, Some(true));
        assert_eq!(r.preference.metric, 50);
    }

    #[test]
    fn deny_then_permit() {
        let mut map = RouteMap::new();
        map.push(RouteMapEntry {
            matches: vec![],
            sets: vec![],
            verdict: Some(false),
        });
        let mut r = route();
        let v = map.evaluate(&mut r, &DummyResolver);
        assert_eq!(v, Some(false));
    }

    #[test]
    fn fallthrough_returns_none() {
        let map = RouteMap::new();
        let mut r = route();
        let v = map.evaluate(&mut r, &DummyResolver);
        assert_eq!(v, None);
    }
}

// ============================================================
// no-bgp fail-closed coverage
// ============================================================
//
// `lr-policy`'s default build turns `bgp` on; the fail-closed
// contract for `RouteMap::evaluate` against a no-`bgp` build is
// only exercised when an embedder explicitly opts out of `bgp`.
// The crate's `--no-default-features --features std` build is
// currently blocked upstream of this module (`filter/eval.rs`'s
// default method bodies reference `crate::bgp::*` unconditionally),
// so these tests pin the contract: a regression that re-introduces
// the silent no-op for the four BGP-specific `SetAction` variants
// (flagged in defects.txt issue #92) will fail here.
#[cfg(not(feature = "bgp"))]
#[cfg(test)]
mod no_bgp_tests {
    use super::*;
    use crate::action::SetAction;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

    struct DummyResolver;
    impl MatchResolver for DummyResolver {
        fn prefix_in(&self, _id: u32, _p: &Prefix) -> bool {
            true
        }
        fn as_path_in(&self, _id: u32, _r: &Route) -> bool {
            true
        }
        fn community_in(&self, _id: u32, _r: &Route) -> bool {
            true
        }
        fn next_hop_in(&self, _id: u32, _r: &Route) -> bool {
            true
        }
    }

    fn route() -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    #[test]
    fn set_local_pref_denies_route_when_bgp_decoder_absent() {
        let mut map = RouteMap::new();
        map.push(RouteMapEntry {
            matches: vec![],
            sets: vec![SetAction::SetLocalPref(100)],
            verdict: Some(true),
        });
        let mut r = route();
        let v = map.evaluate(&mut r, &DummyResolver);
        assert_eq!(
            v,
            Some(false),
            "no-bgp stub: SetLocalPref must deny (fail-closed), not silently permit"
        );
    }

    #[test]
    fn set_med_denies_route_when_bgp_decoder_absent() {
        let mut map = RouteMap::new();
        map.push(RouteMapEntry {
            matches: vec![],
            sets: vec![SetAction::SetMed(50)],
            verdict: Some(true),
        });
        let mut r = route();
        assert_eq!(map.evaluate(&mut r, &DummyResolver), Some(false));
    }

    #[test]
    fn prepend_as_denies_route_when_bgp_decoder_absent() {
        let mut map = RouteMap::new();
        map.push(RouteMapEntry {
            matches: vec![],
            sets: vec![SetAction::PrependAs(lr_core::addr::Asn(65000))],
            verdict: Some(true),
        });
        let mut r = route();
        assert_eq!(map.evaluate(&mut r, &DummyResolver), Some(false));
    }

    #[test]
    fn add_community_denies_route_when_bgp_decoder_absent() {
        let mut map = RouteMap::new();
        map.push(RouteMapEntry {
            matches: vec![],
            sets: vec![SetAction::AddCommunity(lr_core::addr::Asn(65000), 1)],
            verdict: Some(true),
        });
        let mut r = route();
        assert_eq!(map.evaluate(&mut r, &DummyResolver), Some(false));
    }

    #[test]
    fn cross_protocol_actions_still_permit_without_bgp() {
        // SetMetric / SetTag / SetNextHop are cross-protocol and
        // must continue to permit the route under a no-`bgp` build —
        // fail-closed applies only to the four BGP-specific variants.
        let mut map = RouteMap::new();
        map.push(RouteMapEntry {
            matches: vec![],
            sets: vec![SetAction::SetMetric(42), SetAction::SetTag(7)],
            verdict: Some(true),
        });
        let mut r = route();
        let v = map.evaluate(&mut r, &DummyResolver);
        assert_eq!(v, Some(true));
        assert_eq!(r.preference.metric, 42);
        assert_eq!(r.tag, Some(7));
    }
}
