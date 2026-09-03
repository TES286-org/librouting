//! Match + set primitives.

use lr_core::addr::Prefix;
use lr_core::rib::Route;

/// A match condition. Returns true if the route satisfies it.
#[derive(Debug, Clone)]
pub enum MatchCondition {
    PrefixIn { list_id: u32 },
    AsPathIn { list_id: u32 },
    CommunityIn { list_id: u32 },
    ProtocolIs { proto: u8 },
    NextHopIn { list_id: u32 },
}

/// A set action applied to the route (returns a modified copy).
#[derive(Debug, Clone)]
pub enum SetAction {
    SetLocalPref(u32),
    SetMed(u32),
    SetNextHop(lr_core::addr::IpAddr),
    PrependAs(lr_core::addr::Asn),
    AddCommunity(lr_core::addr::Asn, u16),
    SetMetric(u32),
    SetTag(u32),
}

pub trait MatchResolver {
    fn prefix_in(&self, list_id: u32, p: &Prefix) -> bool;
    fn as_path_in(&self, list_id: u32, route: &Route) -> bool;
    fn community_in(&self, list_id: u32, route: &Route) -> bool;
    fn next_hop_in(&self, list_id: u32, route: &Route) -> bool;
}

pub fn evaluate_match(m: &MatchCondition, route: &Route, resolver: &dyn MatchResolver) -> bool {
    match m {
        MatchCondition::PrefixIn { list_id } => resolver.prefix_in(*list_id, &route.key.prefix),
        MatchCondition::AsPathIn { list_id } => resolver.as_path_in(*list_id, route),
        MatchCondition::CommunityIn { list_id } => resolver.community_in(*list_id, route),
        MatchCondition::ProtocolIs { proto } => proto_id(route.protocol) == *proto,
        MatchCondition::NextHopIn { list_id } => resolver.next_hop_in(*list_id, route),
    }
}

pub fn apply_set(action: &SetAction, route: &mut Route) {
    match action {
        // LOCAL_PREF is a BGP path attribute (RFC 4271 §5.1.5), not the
        // cross-protocol admin distance; the two must not be conflated.
        #[cfg(feature = "bgp")]
        SetAction::SetLocalPref(v) => crate::bgp::set_local_pref(route, *v),
        #[cfg(not(feature = "bgp"))]
        SetAction::SetLocalPref(_) => { /* needs the bgp feature: no-op */ }
        #[cfg(feature = "bgp")]
        SetAction::SetMed(v) => crate::bgp::set_med(route, *v),
        #[cfg(not(feature = "bgp"))]
        SetAction::SetMed(_) => { /* needs the bgp feature: no-op */ }
        SetAction::SetNextHop(ip) => route.next_hop = Some(*ip),
        #[cfg(feature = "bgp")]
        SetAction::PrependAs(asn) => crate::bgp::prepend_as(route, *asn),
        #[cfg(not(feature = "bgp"))]
        SetAction::PrependAs(_) => { /* needs the bgp feature: no-op */ }
        #[cfg(feature = "bgp")]
        SetAction::AddCommunity(asn, local) => {
            // RFC 1997 communities carry a 2-byte AS number; larger ASNs
            // cannot be encoded and are silently dropped.
            if asn.0 <= u16::MAX as u32 {
                crate::bgp::add_community(
                    route,
                    lr_bgp::path::communities::Community::new(asn.0 as u16, *local),
                );
            }
        }
        #[cfg(not(feature = "bgp"))]
        SetAction::AddCommunity(_, _) => { /* needs the bgp feature: no-op */ }
        SetAction::SetMetric(v) => route.preference.metric = *v,
        SetAction::SetTag(v) => route.tag = Some(*v),
    }
}

fn proto_id(p: lr_core::rib::Protocol) -> u8 {
    match p {
        lr_core::rib::Protocol::Bgp => 1,
        lr_core::rib::Protocol::Ospfv2 => 2,
        lr_core::rib::Protocol::Ospfv3 => 3,
        lr_core::rib::Protocol::Babel => 4,
        lr_core::rib::Protocol::Static => 5,
        lr_core::rib::Protocol::Connected => 6,
        lr_core::rib::Protocol::Other(_) => 0xff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn empty_route() -> Route {
        Route {
            key: RouteKey::new(
                Prefix::new_v4([203, 0, 113, 0], 24),
                NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    #[test]
    fn set_tag_assigns_route_tag() {
        let mut r = empty_route();
        assert_eq!(r.tag, None);
        apply_set(&SetAction::SetTag(0xdead_beef), &mut r);
        assert_eq!(r.tag, Some(0xdead_beef));
    }

    #[test]
    fn set_tag_overwrites_previous_tag() {
        let mut r = empty_route();
        apply_set(&SetAction::SetTag(1), &mut r);
        apply_set(&SetAction::SetTag(2), &mut r);
        assert_eq!(r.tag, Some(2));
    }

    #[test]
    fn set_metric_is_independent_of_tag() {
        let mut r = empty_route();
        apply_set(&SetAction::SetTag(99), &mut r);
        apply_set(&SetAction::SetMetric(42), &mut r);
        assert_eq!(r.tag, Some(99));
        assert_eq!(r.preference.metric, 42);
    }
}
