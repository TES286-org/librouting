//! Route-map: ordered sequence of (match, set) entries.

use crate::action::{apply_set, evaluate_match, MatchCondition, MatchResolver, SetAction};
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
    pub fn evaluate(&self, route: &mut Route, resolver: &dyn MatchResolver) -> Option<bool> {
        for e in &self.entries {
            let all_match = e.matches.iter().all(|m| evaluate_match(m, route, resolver));
            if !all_match {
                continue;
            }
            for s in &e.sets {
                apply_set(s, route);
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
