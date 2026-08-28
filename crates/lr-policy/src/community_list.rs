//! Community list — matches a set of communities (RFC 1997).
//!
//! Semantics follow the FRR/BIRD *standard community list*: entries are
//! evaluated in order; a route matches an entry when **any** of the
//! route's communities appears in the entry, and that entry's
//! `permit` decides. When no entry matches the list is an implicit
//! deny (`false`) — the safe default for operator-written lists.
//!
//! Requires the `bgp` feature (default) for typed attribute decoding;
//! without it lists evaluate to the permissive stub for embedders
//! that only use prefix-based policy.

use lr_core::rib::Route;

#[derive(Debug, Clone)]
pub struct CommunityListEntry {
    pub communities: Vec<u32>,
    pub permit: bool,
}

#[derive(Default)]
pub struct CommunityList {
    entries: Vec<CommunityListEntry>,
}

impl CommunityList {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, e: CommunityListEntry) {
        self.entries.push(e);
    }

    /// First-match evaluation against the route's communities.
    #[cfg(feature = "bgp")]
    pub fn evaluate(&self, route: &Route) -> bool {
        let route_comms = crate::bgp::communities(route);
        if route_comms.is_empty() {
            return false;
        }
        for entry in &self.entries {
            if entry
                .communities
                .iter()
                .any(|c| route_comms.iter().any(|rc| rc.as_u32() == *c))
            {
                return entry.permit;
            }
        }
        false // implicit deny
    }

    /// Stub (no `bgp` feature): permissive, matching historical
    /// behaviour for prefix-only deployments.
    #[cfg(not(feature = "bgp"))]
    pub fn evaluate(&self, _route: &Route) -> bool {
        true
    }
}

#[derive(Default)]
pub struct CommunityListBank {
    lists: Vec<CommunityList>,
}

impl CommunityListBank {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, list: CommunityList) {
        self.lists.push(list);
    }
    pub fn evaluate(&self, id: u32, route: &Route) -> bool {
        match self.lists.get(id as usize) {
            Some(list) => list.evaluate(route),
            None => false, // unknown list id: deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp;
    use lr_bgp::path::communities::Community;
    use lr_core::addr::Prefix;
    use lr_core::attr::{AttrTag, Attribute};
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Protocol, Route, RouteKey, RouteOrigin};

    fn route_with_communities(comms: &[Community]) -> Route {
        let mut r = Route {
            key: RouteKey::new(
                Prefix::new_v4([203, 0, 113, 0], 24),
                NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Bgp,
            preference: lr_core::rib::Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
        };
        if !comms.is_empty() {
            r.attributes.insert(Attribute {
                tag: AttrTag::raw(8),
                flags: 0xC0,
                value: Community::encode_set(comms),
            });
        }
        r
    }

    #[test]
    fn first_match_permit_deny() {
        let mut list = CommunityList::new();
        list.push(CommunityListEntry {
            communities: vec![Community::new(64512, 100).as_u32()],
            permit: false,
        });
        list.push(CommunityListEntry {
            communities: vec![Community::new(64512, 200).as_u32()],
            permit: true,
        });

        let tagged_100 = route_with_communities(&[Community::new(64512, 100)]);
        assert!(!list.evaluate(&tagged_100), "first entry denies");

        let tagged_200 = route_with_communities(&[Community::new(64512, 200)]);
        assert!(list.evaluate(&tagged_200), "second entry permits");

        let tagged_both =
            route_with_communities(&[Community::new(64512, 100), Community::new(64512, 200)]);
        assert!(!list.evaluate(&tagged_both), "first match wins");
    }

    #[test]
    fn no_match_or_no_communities_denies() {
        let mut list = CommunityList::new();
        list.push(CommunityListEntry {
            communities: vec![Community::new(64512, 100).as_u32()],
            permit: true,
        });
        assert!(!list.evaluate(&route_with_communities(&[])));
        assert!(!list.evaluate(&route_with_communities(&[Community::new(65001, 1)])));
    }

    #[test]
    fn bank_dispatch_and_unknown_id_denies() {
        let mut bank = CommunityListBank::new();
        let mut list = CommunityList::new();
        list.push(CommunityListEntry {
            communities: vec![Community::new(64512, 100).as_u32()],
            permit: true,
        });
        bank.add(list);
        let route = route_with_communities(&[Community::new(64512, 100)]);
        assert!(bank.evaluate(0, &route));
        assert!(!bank.evaluate(9, &route), "unknown list id denies");
        let _ = bgp::communities(&route);
    }
}
