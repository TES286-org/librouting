//! Policy chain — ordered list of route-maps evaluated against a route.

use crate::action::MatchResolver;
use crate::route_map::RouteMap;
use lr_core::rib::Route;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    Accept,
    Reject,
    Continue,
}

#[derive(Default)]
pub struct PolicyChain {
    maps: Vec<RouteMap>,
}

impl PolicyChain {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, m: RouteMap) {
        self.maps.push(m);
    }

    pub fn evaluate(&self, route: &mut Route, resolver: &dyn MatchResolver) -> PolicyVerdict {
        for m in &self.maps {
            match m.evaluate(route, resolver) {
                Some(true) => return PolicyVerdict::Accept,
                Some(false) => return PolicyVerdict::Reject,
                None => continue,
            }
        }
        PolicyVerdict::Continue
    }
}

/// A named policy that wraps a chain.
#[derive(Default)]
pub struct Policy {
    pub name: String,
    pub chain: PolicyChain,
}

impl Policy {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            chain: PolicyChain::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{MatchCondition, MatchResolver, SetAction};
    use crate::route_map::{RouteMap, RouteMapEntry};
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

    fn make_route() -> Route {
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
    fn chain_accept() {
        let mut chain = PolicyChain::new();
        let mut m = RouteMap::new();
        m.push(RouteMapEntry {
            matches: vec![MatchCondition::PrefixIn { list_id: 1 }],
            sets: vec![SetAction::SetMetric(50)],
            verdict: Some(true),
        });
        chain.push(m);
        let mut r = make_route();
        let v = chain.evaluate(&mut r, &DummyResolver);
        assert_eq!(v, PolicyVerdict::Accept);
        assert_eq!(r.preference.metric, 50);
    }
}
