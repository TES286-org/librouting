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
use lr_bgp::path::communities::{Community, ExtendedCommunity, LargeCommunity};
use lr_bgp::path::well_known::{ClusterList, OriginatorId};
use lr_core::addr::{Asn, IpAddr};
use lr_core::attr::{AttrTag, Attribute};
use lr_core::rib::Route;

/// Well-known attribute type codes (RFC 4271 §4.2 / RFC 1997 §4 /
/// RFC 4360 §2 / RFC 8092 §2 / RFC 9234 §3.1).
const TAG_ORIGIN: u8 = 1;
const TAG_AS_PATH: u8 = 2;
const TAG_MED: u8 = 4;
const TAG_LOCAL_PREF: u8 = 5;
const TAG_ATOMIC_AGGREGATE: u8 = 6;
const TAG_COMMUNITIES: u8 = 8;
const TAG_ORIGINATOR_ID: u8 = 9;
const TAG_CLUSTER_LIST: u8 = 10;
const TAG_EXT_COMMUNITIES: u8 = 16;
const TAG_LARGE_COMMUNITIES: u8 = 32;
/// RFC 9234 §3.1: OTC ("Only To Customer") attribute type code.
const TAG_OTC: u8 = 35;

const FLAGS_AS_PATH: u8 = 0x40;
const FLAGS_MED: u8 = 0x80;
const FLAGS_LOCAL_PREF: u8 = 0x40; // well-known discretionary
const FLAGS_COMMUNITIES: u8 = 0xC0; // optional transitive
const FLAGS_EXT_COMMUNITIES: u8 = 0xC0; // optional transitive (RFC 4360 §3)
const FLAGS_LARGE_COMMUNITIES: u8 = 0xC0; // optional transitive (RFC 8092 §2)

// The read-only path attributes the filter DSL exposes below
// (ATOMIC_AGGREGATE = well-known discretionary per RFC 4271 §5.1.6,
// ORIGINATOR_ID and CLUSTER_LIST = optional non-transitive per RFC
// 4456 §8) live in `lr-bgp::path`; the accessors here read by tag,
// not by flags, so no `FLAGS_*` constant is needed until the
// corresponding setters land.

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

/// The route's extended communities (RFC 4360); empty when absent.
pub fn ext_communities(route: &Route) -> Vec<ExtendedCommunity> {
    attr_bytes(route, TAG_EXT_COMMUNITIES)
        .map(ExtendedCommunity::decode_set)
        .unwrap_or_default()
}

/// The route's large communities (RFC 8092); empty when absent.
pub fn large_communities(route: &Route) -> Vec<LargeCommunity> {
    attr_bytes(route, TAG_LARGE_COMMUNITIES)
        .map(LargeCommunity::decode_set)
        .unwrap_or_default()
}

/// The route's canonical (4-byte) AS_PATH; `None` when absent
/// (locally originated routes carry no AS_PATH until egress).
pub fn as_path(route: &Route) -> Option<AsPath> {
    attr_bytes(route, TAG_AS_PATH).and_then(AsPath::decode_4)
}

/// The route's MULTI_EXIT_DISC; `None` when absent.
///
/// GitHub #19 P3: reads the 4-byte big-endian value in place via
/// `Attributes::get_u32_be` — no `Vec<u8>` clone, no intermediate
/// `&[u8]` slice beyond the BTreeMap lookup. The previous path
/// (`attr_bytes(route, TAG_MED).and_then(|b| b.try_into().ok().map(u32::from_be_bytes))`)
/// was already zero-clone (the slice was read off the stored `Vec`),
/// but `get_u32_be` fuses the lookup + conversion into one call so
/// the compiler can inline the whole read.
pub fn med(route: &Route) -> Option<u32> {
    route.attributes.get_u32_be(AttrTag::raw(TAG_MED))
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
///
/// GitHub #19 P3: reads the 4-byte big-endian value in place via
/// `Attributes::get_u32_be` — see `med` for the rationale.
pub fn local_pref(route: &Route) -> Option<u32> {
    route.attributes.get_u32_be(AttrTag::raw(TAG_LOCAL_PREF))
}

/// The route's ORIGIN (RFC 4271 §4.2.1): `0 = IGP`, `1 = EGP`,
/// `2 = INCOMPLETE`. `None` when the attribute is absent — the
/// `FilterContext::bgp_origin` accessor defaults to `Some(0)` (IGP)
/// for routes that never carried an ORIGIN (e.g. locally originated),
/// matching BIRD's `f_new` default.
///
/// GitHub #19 P3: reads the 1-byte value in place via
/// `Attributes::get_u8` — no `Vec<u8>` clone.
pub fn origin(route: &Route) -> Option<u8> {
    route.attributes.get_u8(AttrTag::raw(TAG_ORIGIN))
}

/// True when the route carries an ATOMIC_AGGREGATE attribute (RFC 4271
/// §5.1.6). The attribute is a length-zero marker — its presence is
/// the entire signal — so this collapses to a tag lookup with no
/// value decoding. Returns `false` for routes originated without the
/// marker (the common case).
pub fn atomic_aggregate(route: &Route) -> bool {
    route
        .attributes
        .get(AttrTag::raw(TAG_ATOMIC_AGGREGATE))
        .is_some()
}

/// The route's ORIGINATOR_ID (RFC 4456 §8) as an IPv4 `IpAddr`;
/// `None` when the attribute is absent (a non-reflected route) or
/// when the wire form is malformed (any length other than 4 bytes).
/// BIRD spells ORIGINATOR_ID as an `ip` in its filter language; the
/// `IpAddr::V4` representation matches so a BIRD filter like
/// `if bgp_originator_id = 10.0.0.1 then reject;` translates
/// faithfully.
pub fn originator_id(route: &Route) -> Option<IpAddr> {
    let bytes = attr_bytes(route, TAG_ORIGINATOR_ID)?;
    OriginatorId::decode(bytes).map(|id| id.to_ip())
}

/// The route's CLUSTER_LIST (RFC 4456 §8) as a `Vec<IpAddr>` in
/// reflection order (most-recently-prepended first). Returns an
/// empty `Vec` when the attribute is absent (a non-reflected route)
/// or when the wire form is malformed; the two cases are
/// indistinguishable through this accessor — callers that need the
/// distinction should check `route.attributes.get(TAG_CLUSTER_LIST)`
/// directly. BIRD spells CLUSTER_LIST as a `clist` of IPv4-typed
/// entries; the `IpAddr::V4` representation matches so a BIRD filter
/// like `if local_cluster ~ bgp_cluster_list then reject;` translates
/// faithfully.
pub fn cluster_list(route: &Route) -> Vec<IpAddr> {
    match attr_bytes(route, TAG_CLUSTER_LIST) {
        None => Vec::new(),
        Some(bytes) => match ClusterList::decode(bytes) {
            Some(list) => list.iter_ips().collect(),
            None => Vec::new(),
        },
    }
}

/// True when a CLUSTER_LIST attribute is physically present on the
/// route (RFC 4456 §8). Use this to distinguish "no attribute" from
/// "present but empty" — `cluster_list()` collapses both to an empty
/// `Vec`.
pub fn has_cluster_list(route: &Route) -> bool {
    route
        .attributes
        .get(AttrTag::raw(TAG_CLUSTER_LIST))
        .is_some()
}

/// The route's OTC attribute (RFC 9234 §3.1) as a 4-byte AS number;
/// `None` when the attribute is absent (e.g. a route from a peer with
/// no OTC role) or when the wire form is malformed (any length other
/// than 4 bytes). BIRD spells OTC as an integer in its filter
/// language; the `u32` representation matches so a BIRD filter like
/// `if bgp_otc != 0 then reject;` translates faithfully to
/// `if bgp.otc != 0 then reject;`.
///
/// A present value of `0` ("set but zero") is returned as `Some(0)`
/// — use [`has_otc`] to distinguish "absent" from "set to zero" in
/// policies that need the distinction (the `defined(bgp.otc)` filter
/// DSL predicate consults `has_otc`, not this accessor).
///
/// GitHub #19 P3: reads the 4-byte big-endian value in place via
/// `Attributes::get_u32_be` — no `Vec<u8>` clone, no intermediate
/// `&[u8]` slice beyond the BTreeMap lookup.
pub fn otc(route: &Route) -> Option<u32> {
    route.attributes.get_u32_be(AttrTag::raw(TAG_OTC))
}

/// True when an OTC attribute is physically present on the route
/// (RFC 9234 §3.1). Use this to distinguish "no attribute" from
/// "present but zero" — `otc()` returns `Some(0)` for the latter.
pub fn has_otc(route: &Route) -> bool {
    route.attributes.get(AttrTag::raw(TAG_OTC)).is_some()
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
    set_communities(route, set);
}

/// Replace the whole COMMUNITIES set; drops the attribute when the
/// new set is empty (the D3.4 `delete`/`filter` write-back path).
pub fn set_communities(route: &mut Route, set: Vec<Community>) {
    if set.is_empty() {
        route.attributes.remove(AttrTag::raw(TAG_COMMUNITIES));
        return;
    }
    put(
        route,
        TAG_COMMUNITIES,
        FLAGS_COMMUNITIES,
        Community::encode_set(&set),
    );
}

/// Replace the AS_PATH with a flat AS_SEQUENCE; drops the attribute
/// when the sequence is empty (the D3.4 path write-back).
pub fn set_as_sequence(route: &mut Route, seq: Vec<Asn>) {
    if seq.is_empty() {
        route.attributes.remove(AttrTag::raw(TAG_AS_PATH));
        return;
    }
    let path = AsPath::from_sequence(seq);
    put(route, TAG_AS_PATH, FLAGS_AS_PATH, path.encode_4());
}

/// Append a large community (RFC 8092 §2), creating the attribute
/// when the route has none yet. Duplicates are not added.
pub fn add_large_community(route: &mut Route, community: LargeCommunity) {
    let mut set = large_communities(route);
    if set.contains(&community) {
        return;
    }
    set.push(community);
    set_large_communities(route, set);
}

/// Replace the whole LARGE_COMMUNITIES set; drops the attribute when
/// the new set is empty.
pub fn set_large_communities(route: &mut Route, set: Vec<LargeCommunity>) {
    if set.is_empty() {
        route.attributes.remove(AttrTag::raw(TAG_LARGE_COMMUNITIES));
        return;
    }
    put(
        route,
        TAG_LARGE_COMMUNITIES,
        FLAGS_LARGE_COMMUNITIES,
        LargeCommunity::encode_set(&set),
    );
}

/// Append an extended community (RFC 4360 §3), creating the
/// attribute when the route has none yet. Duplicates are not added.
pub fn add_ext_community(route: &mut Route, community: ExtendedCommunity) {
    let mut set = ext_communities(route);
    if set.contains(&community) {
        return;
    }
    set.push(community);
    set_ext_communities(route, set);
}

/// Replace the whole EXTENDED_COMMUNITIES set; drops the attribute
/// when the new set is empty.
pub fn set_ext_communities(route: &mut Route, set: Vec<ExtendedCommunity>) {
    if set.is_empty() {
        route.attributes.remove(AttrTag::raw(TAG_EXT_COMMUNITIES));
        return;
    }
    put(
        route,
        TAG_EXT_COMMUNITIES,
        FLAGS_EXT_COMMUNITIES,
        ExtendedCommunity::encode_set(&set),
    );
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

    /// GitHub #19 P3 — `get_u32_be` reads the 4-byte big-endian value
    /// in place, no `Vec<u8>` clone. Pin the round-trip for LOCAL_PREF
    /// and MED (the two u32 attributes the filter DSL reads on the hot
    /// path), plus the edge cases (absent attribute, wrong-length
    /// value).
    #[test]
    fn p3_get_u32_be_reads_local_pref_and_med_in_place() {
        let mut r = route_with(vec![]);
        set_local_pref(&mut r, 100);
        set_med(&mut r, 42);
        // Round-trip via the fast path.
        assert_eq!(
            r.attributes.get_u32_be(AttrTag::raw(TAG_LOCAL_PREF)),
            Some(100)
        );
        assert_eq!(r.attributes.get_u32_be(AttrTag::raw(TAG_MED)), Some(42));
        // Absent attribute.
        let r2 = route_with(vec![]);
        assert_eq!(r2.attributes.get_u32_be(AttrTag::raw(TAG_LOCAL_PREF)), None);
        // Wrong-length value — treated as "absent" (the caller's
        // `unwrap_or(0)` default applies).
        let mut r3 = route_with(vec![]);
        r3.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_LOCAL_PREF),
            flags: 0x40,
            value: vec![1, 2, 3], // 3 bytes, not 4
        });
        assert_eq!(r3.attributes.get_u32_be(AttrTag::raw(TAG_LOCAL_PREF)), None);
    }

    /// GitHub #19 P3 — `get_u8` reads the 1-byte ORIGIN attribute in
    /// place. Pin the round-trip and the edge cases.
    #[test]
    fn p3_get_u8_reads_origin_in_place() {
        let mut r = route_with(vec![]);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_ORIGIN),
            flags: 0x40,
            value: vec![2], // INCOMPLETE
        });
        assert_eq!(origin(&r), Some(2));
        assert_eq!(r.attributes.get_u8(AttrTag::raw(TAG_ORIGIN)), Some(2));
        // Absent attribute.
        let r2 = route_with(vec![]);
        assert_eq!(origin(&r2), None);
        // Empty value — `get_u8` returns None (no first byte).
        let mut r3 = route_with(vec![]);
        r3.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_ORIGIN),
            flags: 0x40,
            value: vec![],
        });
        assert_eq!(r3.attributes.get_u8(AttrTag::raw(TAG_ORIGIN)), None);
    }

    /// RFC 4271 §5.1.6 — ATOMIC_AGGREGATE is a length-zero marker;
    /// `atomic_aggregate()` reports presence, nothing more.
    #[test]
    fn atomic_aggregate_is_a_presence_marker() {
        let r_with = route_with(vec![raw_attr(TAG_ATOMIC_AGGREGATE, 0x40, Vec::new())]);
        assert!(atomic_aggregate(&r_with));
        let r_without = route_with(vec![]);
        assert!(!atomic_aggregate(&r_without));
    }

    /// RFC 4456 §8 — ORIGINATOR_ID is exactly 4 bytes; the helper
    /// surfaces it as `IpAddr::V4` and stays `None` on the absent
    /// and malformed cases.
    #[test]
    fn originator_id_decodes_as_v4_ipaddr() {
        let r = route_with(vec![raw_attr(TAG_ORIGINATOR_ID, 0x80, vec![10, 0, 0, 1])]);
        assert_eq!(originator_id(&r), Some(IpAddr::V4([10, 0, 0, 1])));
        // Absent.
        let r_absent = route_with(vec![]);
        assert_eq!(originator_id(&r_absent), None);
        // Malformed width.
        let r_bad = route_with(vec![raw_attr(TAG_ORIGINATOR_ID, 0x80, vec![1, 2, 3])]);
        assert_eq!(originator_id(&r_bad), None);
    }

    /// RFC 4456 §8 — CLUSTER_LIST is a flat 4-byte-per-id sequence;
    /// the helper surfaces it as `Vec<IpAddr>` in reflection order
    /// and falls back to empty for absent and malformed.
    #[test]
    fn cluster_list_decodes_to_v4_vec() {
        let r = route_with(vec![raw_attr(
            TAG_CLUSTER_LIST,
            0x80,
            vec![10, 0, 0, 1, 10, 0, 0, 2],
        )]);
        assert_eq!(
            cluster_list(&r),
            vec![IpAddr::V4([10, 0, 0, 1]), IpAddr::V4([10, 0, 0, 2])]
        );
        assert!(has_cluster_list(&r));
        // Absent — empty list and `has_cluster_list` false.
        let r_absent = route_with(vec![]);
        assert!(cluster_list(&r_absent).is_empty());
        assert!(!has_cluster_list(&r_absent));
        // Malformed — partial-tail collapses to empty; the
        // presence flag still reports the attribute is on the route.
        let r_bad = route_with(vec![raw_attr(TAG_CLUSTER_LIST, 0x80, vec![1, 2, 3, 4, 5])]);
        assert!(cluster_list(&r_bad).is_empty());
        assert!(has_cluster_list(&r_bad));
    }

    /// RFC 9234 §3.1 — OTC is a 4-byte AS number; the helper surfaces
    /// it as `u32` and stays `None` on the absent and malformed
    /// cases. A present value of `0` ("set but zero") is returned as
    /// `Some(0)` so policies that need the distinction consult
    /// `has_otc` instead.
    #[test]
    fn otc_decodes_as_u32() {
        // Present, value 64512.
        let r = route_with(vec![raw_attr(
            TAG_OTC,
            0xC0,
            64512u32.to_be_bytes().to_vec(),
        )]);
        assert_eq!(otc(&r), Some(64512));
        assert!(has_otc(&r));
        // Absent.
        let r_absent = route_with(vec![]);
        assert_eq!(otc(&r_absent), None);
        assert!(!has_otc(&r_absent));
        // Present, value 0 — "set but zero". `otc()` returns
        // `Some(0)`; `has_otc()` reports presence. This is the case
        // `defined(bgp.otc)` in the filter DSL must distinguish from
        // "absent".
        let r_zero = route_with(vec![raw_attr(TAG_OTC, 0xC0, vec![0, 0, 0, 0])]);
        assert_eq!(otc(&r_zero), Some(0));
        assert!(has_otc(&r_zero));
        // Malformed width — `otc()` returns None (the u32 fast path
        // rejects anything but 4 bytes); `has_otc()` still reports
        // presence (the attribute is on the route; only the value is
        // unreadable). Mirrors the `cluster_list()` accessor's
        // behaviour on a partial tail.
        let r_bad = route_with(vec![raw_attr(TAG_OTC, 0xC0, vec![1, 2, 3])]);
        assert_eq!(otc(&r_bad), None);
        assert!(has_otc(&r_bad));
    }
}
