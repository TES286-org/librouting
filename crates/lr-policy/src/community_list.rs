//! Community list — matches a set of communities (RFC 1997).
//!
//! Semantics follow the FRR/BIRD *standard community list*: entries are
//! evaluated in order; a route matches an entry when **any** of the
//! route's communities appears in the entry, and that entry's
//! `permit` decides. When no entry matches the list is an implicit
//! deny (`false`) — the safe default for operator-written lists.
//!
//! Requires the `bgp` feature (default) for typed attribute decoding;
//! without it [`CommunityList::evaluate`] fails **closed** (returns
//! `false`): a configured community list cannot be evaluated when the
//! crate is built without the typed BGP path-attribute decoder, and
//! the safe default for a security-sensitive filter is to deny the
//! route rather than silently admit it. Embedders that want
//! prefix-only policy should use [`PrefixList`](crate::PrefixList)
//! and not configure a `CommunityList`.

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

    /// Stub (no `bgp` feature): **fail-closed** — a configured
    /// community list cannot be evaluated when the crate is built
    /// without the typed BGP path-attribute decoder, so the safe
    /// default is to deny the route. The previous shape of this
    /// stub returned `true` (permit-all), which silently admitted
    /// every route past a configured-but-unparseable filter — an
    /// unsafe default for a security-sensitive control plane.
    ///
    /// Embedders that build `lr-policy` without `bgp` and want
    /// prefix-only filtering should use [`PrefixList`] and not
    /// configure a [`CommunityList`] at all.
    #[cfg(not(feature = "bgp"))]
    pub fn evaluate(&self, _route: &Route) -> bool {
        false
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
    pub fn len(&self) -> usize {
        self.lists.len()
    }
    pub fn is_empty(&self) -> bool {
        self.lists.is_empty()
    }
    pub fn evaluate(&self, id: u32, route: &Route) -> bool {
        match self.lists.get(id as usize) {
            Some(list) => list.evaluate(route),
            None => false, // unknown list id: deny
        }
    }
}

#[cfg(all(test, feature = "bgp"))]
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
            tag: None,
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

// ============================================================
// no-bgp fail-closed coverage
// ============================================================
//
// `lr-policy`'s default build turns `bgp` on; the stub path covered
// here is only compiled when an embedder explicitly opts out. The
// crate's `--no-default-features --features std` build is currently
// blocked upstream of this module — `filter/eval.rs`'s default method
// bodies reference `crate::bgp::*` unconditionally — so a future
// follow-up that lands the no-bgp build will see these tests pin the
// fail-closed verdict (and a regression that re-introduces the
// permissive permit-all stub flagged in defects.txt will fail here).
#[cfg(not(feature = "bgp"))]
#[cfg(test)]
mod no_bgp_tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Protocol, Route, RouteKey, RouteOrigin};

    fn any_route() -> Route {
        Route {
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
            tag: None,
        }
    }

    #[test]
    fn configured_list_denies_when_bgp_decoder_absent() {
        // A non-empty community list configured to *permit* a route
        // carrying community (64512, 100). Without the `bgp` feature
        // the crate cannot decode the route's communities, so the
        // safe default is to deny the route — fail-closed.
        let mut list = CommunityList::new();
        list.push(CommunityListEntry {
            communities: vec![0u32],
            permit: true,
        });
        assert!(
            !list.evaluate(&any_route()),
            "no-bgp stub must deny (fail-closed), not silently admit"
        );
    }

    #[test]
    fn empty_list_denies_when_bgp_decoder_absent() {
        // Even an empty community list (which the bgp-enabled path
        // also evaluates as implicit-deny) stays deny under the no-bgp
        // stub — the two paths agree on the deny verdict for an empty
        // list, so a no-bgp build does not introduce a discrepancy.
        let list = CommunityList::new();
        assert!(
            !list.evaluate(&any_route()),
            "no-bgp stub on an empty list must deny (matching the bgp path's implicit deny)"
        );
    }

    #[test]
    fn bank_known_id_denies_when_bgp_decoder_absent() {
        // The bank delegates to the inner list's `evaluate`, which
        // fails closed. The unknown-id branch already denies in the
        // bank (independent of the bgp feature), so the known-id and
        // unknown-id branches now agree: both deny.
        let mut bank = CommunityListBank::new();
        let mut list = CommunityList::new();
        list.push(CommunityListEntry {
            communities: vec![0u32],
            permit: true,
        });
        bank.add(list);
        assert!(
            !bank.evaluate(0, &any_route()),
            "no-bgp stub: known list id must deny (fail-closed)"
        );
        assert!(
            !bank.evaluate(99, &any_route()),
            "no-bgp stub: unknown list id still denies"
        );
    }
}
