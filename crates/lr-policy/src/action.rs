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
        SetAction::SetLocalPref(v) => route.preference.admin_distance = *v,
        SetAction::SetMed(_) => { /* TODO: BGP-specific path attr */ }
        SetAction::SetNextHop(ip) => route.next_hop = Some(*ip),
        SetAction::PrependAs(_) => { /* TODO: BGP-specific path attr */ }
        SetAction::AddCommunity(_, _) => { /* TODO: BGP-specific path attr */ }
        SetAction::SetMetric(v) => route.preference.metric = *v,
        SetAction::SetTag(_) => { /* TODO: route tags */ }
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
