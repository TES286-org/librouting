//! Typed BGP path-attribute access for policy evaluation and mutation.
//!
//! The [`Route`] data model carries path attributes as a raw
//! tag-keyed bag (`lr_core::attr::Attributes`). This module decodes
//! just the attributes policy cares about (AS_PATH, COMMUNITIES,
//! MULTI_EXIT_DISC) using `lr-bgp`'s wire codecs — no whole-bag
//! conversion, so evaluation stays allocation-light on routes with
//! many attributes.
//!
//! Attribute flags follow RFC 4271 §4.2 / RFC 1997:
//!
//! | Attribute            | flags | class                  |
//! |----------------------|-------|------------------------|
//! | AS_PATH (2)          | 0x40 | well-known, transitive |
//! | MULTI_EXIT_DISC (4)  | 0x80 | optional, non-transitive |
//! | COMMUNITIES (8)      | 0xC0 | optional, transitive   |
//!
//! The AS_PATH inside `Route.attributes` is the canonical 4-byte
//! encoding (ingress normalizes; egress re-encodes to the negotiated
//! width) — see `docs/ARCHITECTURE.md`, "Canonical AS_PATH".

use lr_bgp::path::as_path::AsPath;
use lr_bgp::path::communities::Community;
use lr_core::addr::Asn;
use lr_core::attr::{AttrTag, Attribute};
use lr_core::rib::Route;

/// Well-known attribute type codes (RFC 4271 §4.2 / RFC 1997 §4).
const TAG_AS_PATH: u8 = 2;
const TAG_MED: u8 = 4;
const TAG_LOCAL_PREF: u8 = 5;
const TAG_COMMUNITIES: u8 = 8;

const FLAGS_AS_PATH: u8 = 0x40;
const FLAGS_MED: u8 = 0x80;
const FLAGS_LOCAL_PREF: u8 = 0x40; // well-known discretionary
const FLAGS_COMMUNITIES: u8 = 0xC0;

fn attr_bytes(route: &Route, tag: u8) -> Option<&[u8]> {
    route
        .attributes
        .get(AttrTag::raw(tag))
        .map(|a| a.value.as_slice())
}

/// The route's communities (RFC 1997); empty when absent.
pub fn communities(route: &Route) -> Vec<Community> {
    attr_bytes(route, TAG_COMMUNITIES)
        .map(Community::decode_set)
        .unwrap_or_default()
}

/// The route's canonical (4-byte) AS_PATH; `None` when absent
/// (locally originated routes carry no AS_PATH until egress).
pub fn as_path(route: &Route) -> Option<AsPath> {
    attr_bytes(route, TAG_AS_PATH).and_then(AsPath::decode_4)
}

/// The route's MULTI_EXIT_DISC; `None` when absent.
pub fn med(route: &Route) -> Option<u32> {
    attr_bytes(route, TAG_MED).and_then(|b| b.try_into().ok().map(u32::from_be_bytes))
}

/// Flat AS sequence of the route's AS_PATH (sets flattened in order).
pub fn as_sequence(route: &Route) -> Vec<Asn> {
    as_path(route).map(|p| p.as_sequence()).unwrap_or_default()
}

fn put(route: &mut Route, tag: u8, flags: u8, value: Vec<u8>) {
    route.attributes.insert(Attribute {
        tag: AttrTag::raw(tag),
        flags,
        value,
    });
}

/// Set the MULTI_EXIT_DISC (RFC 4271 §4.2.4). Inserts or replaces.
pub fn set_med(route: &mut Route, value: u32) {
    put(route, TAG_MED, FLAGS_MED, value.to_be_bytes().to_vec());
}

/// Set the LOCAL_PREF (RFC 4271 §5.1.5). Inserts or replaces.
///
/// LOCAL_PREF is a BGP path attribute, distinct from the cross-protocol
/// administrative distance carried in `Route.preference.admin_distance`;
/// writing it into the preference would corrupt the admin-distance merge.
pub fn set_local_pref(route: &mut Route, value: u32) {
    put(
        route,
        TAG_LOCAL_PREF,
        FLAGS_LOCAL_PREF,
        value.to_be_bytes().to_vec(),
    );
}

/// The route's LOCAL_PREF; `None` when absent (defaults to 100 on eBGP).
pub fn local_pref(route: &Route) -> Option<u32> {
    attr_bytes(route, TAG_LOCAL_PREF).and_then(|b| b.try_into().ok().map(u32::from_be_bytes))
}

/// Prepend `asn` to the route's AS_PATH (RFC 4271 §4.3), creating the
/// attribute when the route has none yet (locally originated).
pub fn prepend_as(route: &mut Route, asn: Asn) {
    let mut path = as_path(route).unwrap_or_default();
    path.prepend(asn);
    put(route, TAG_AS_PATH, FLAGS_AS_PATH, path.encode_4());
}

/// Append a community (RFC 1997 §4), creating the attribute when the
/// route has none yet. Duplicates are not added.
pub fn add_community(route: &mut Route, community: Community) {
    let mut set = communities(route);
    if set.contains(&community) {
        return;
    }
    set.push(community);
    put(
        route,
        TAG_COMMUNITIES,
        FLAGS_COMMUNITIES,
        Community::encode_set(&set),
    );
}

/// Remove every occurrence of a community; drops the attribute when
/// it becomes empty.
pub fn remove_community(route: &mut Route, community: Community) {
    let mut set = communities(route);
    set.retain(|c| *c != community);
    if set.is_empty() {
        route.attributes.remove(AttrTag::raw(TAG_COMMUNITIES));
    } else {
        put(
            route,
            TAG_COMMUNITIES,
            FLAGS_COMMUNITIES,
            Community::encode_set(&set),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn route_with(attrs: Vec<Attribute>) -> Route {
        let mut r = Route {
            key: RouteKey::new(
                Prefix::new_v4([203, 0, 113, 0], 24),
                NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        for a in attrs {
            r.attributes.insert(a);
        }
        r
    }

    fn raw_attr(tag: u8, flags: u8, value: Vec<u8>) -> Attribute {
        Attribute {
            tag: AttrTag::raw(tag),
            flags,
            value,
        }
    }

    #[test]
    fn decode_communities_as_path_med() {
        // AS_PATH = AS_SEQUENCE(1) len(2) [65001, 65002] (4-byte)
        let as_path = AsPath::from_sequence([Asn(65001), Asn(65002)]);
        let comm_bytes =
            Community::encode_set(&[Community::new(64512, 100), Community::from_u32(0x00ff_00ff)]);
        let r = route_with(vec![
            raw_attr(TAG_AS_PATH, FLAGS_AS_PATH, as_path.encode_4()),
            raw_attr(TAG_MED, FLAGS_MED, 50u32.to_be_bytes().to_vec()),
            raw_attr(TAG_COMMUNITIES, FLAGS_COMMUNITIES, comm_bytes),
        ]);
        assert_eq!(as_sequence(&r), vec![Asn(65001), Asn(65002)]);
        assert_eq!(med(&r), Some(50));
        assert_eq!(communities(&r).len(), 2);
        assert!(communities(&r).contains(&Community::new(64512, 100)));
    }

    #[test]
    fn empty_route_decodes_to_defaults() {
        let r = route_with(vec![]);
        assert!(as_sequence(&r).is_empty());
        assert_eq!(med(&r), None);
        assert!(communities(&r).is_empty());
    }

    #[test]
    fn set_and_mutate_attributes() {
        let mut r = route_with(vec![]);
        set_med(&mut r, 42);
        assert_eq!(med(&r), Some(42));

        prepend_as(&mut r, Asn(65010));
        prepend_as(&mut r, Asn(65010));
        prepend_as(&mut r, Asn(65000));
        assert_eq!(as_sequence(&r), vec![Asn(65000), Asn(65010), Asn(65010)]);

        add_community(&mut r, Community::new(64512, 1));
        add_community(&mut r, Community::new(64512, 1)); // duplicate is a no-op
        add_community(&mut r, Community::new(64512, 2));
        assert_eq!(communities(&r).len(), 2);

        remove_community(&mut r, Community::new(64512, 1));
        remove_community(&mut r, Community::new(64512, 2));
        // Last community removed -> attribute dropped entirely.
        assert!(r.attributes.get(AttrTag::raw(TAG_COMMUNITIES)).is_none());
    }

    #[test]
    fn flags_round_trip_through_typed_conversion() {
        // The raw flags we write must survive the lr-bgp typed view.
        let mut r = route_with(vec![]);
        set_med(&mut r, 7);
        let typed: lr_bgp::path::PathAttributes = r.attributes.clone().into();
        assert_eq!(typed.med().map(|m| m.0), Some(7));
    }
}
