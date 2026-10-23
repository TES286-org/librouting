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
use lr_bgp::path::well_known::{Aggregator, Aigp, ClusterList, OriginatorId, PmsiTunnel};
use lr_core::addr::{Asn, IpAddr};
use lr_core::attr::{AttrTag, Attribute};
use lr_core::rib::Route;

/// Well-known attribute type codes (RFC 4271 §4.2 / RFC 1997 §4 /
/// RFC 4360 §2 / RFC 8092 §2 / RFC 9234 §3.1 / RFC 7311 §3 /
/// RFC 6514 §5).
const TAG_ORIGIN: u8 = 1;
const TAG_AS_PATH: u8 = 2;
const TAG_MED: u8 = 4;
const TAG_LOCAL_PREF: u8 = 5;
const TAG_ATOMIC_AGGREGATE: u8 = 6;
const TAG_COMMUNITIES: u8 = 8;
const TAG_ORIGINATOR_ID: u8 = 9;
const TAG_CLUSTER_LIST: u8 = 10;
/// RFC 4271 §5.1.7: AGGREGATOR attribute type code. The attribute is
/// optional transitive; the value is 6 bytes (2-byte AS + 4-byte
/// speaker IP) on legacy sessions or 8 bytes (4-byte AS + 4-byte
/// speaker IP) on 4-byte-AS-capable sessions. The codec in
/// `lr-bgp::path::well_known::Aggregator` accepts both widths and
/// the ingress normalisation reconciles AS4_AGGREGATOR (type 18)
/// into the canonical 4-byte form stored under this tag.
const TAG_AGGREGATOR: u8 = 7;
const TAG_EXT_COMMUNITIES: u8 = 16;
const TAG_LARGE_COMMUNITIES: u8 = 32;
/// RFC 9234 §3.1: OTC ("Only To Customer") attribute type code.
const TAG_OTC: u8 = 35;
/// RFC 7311 §3: AIGP ("Accumulated IGP Metric") attribute type code.
const TAG_AIGP: u8 = 26;
/// RFC 6514 §5: PMSI Tunnel attribute type code (22, optional
/// transitive). The value field is a fixed 5-byte header (Flags +
/// Tunnel Type + MPLS Label) followed by a variable-length Tunnel
/// Identifier.
const TAG_PMSI_TUNNEL: u8 = 22;

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

/// The route's AIGP attribute (RFC 7311) as the accumulated IGP
/// metric — the sum of every type-1 TLV's 8-byte value in the
/// attribute's TLV stream. `None` when the attribute is absent or
/// the TLV stream is malformed (a TLV length runs past the end, or
/// a type-1 TLV's value is not exactly 8 bytes). An empty value
/// field decodes to `Some(0)` — RFC 7311 does not forbid an empty
/// AIGP attribute.
///
/// A present value of `0` ("set but zero") is returned as `Some(0)`
/// — use [`has_aigp`] to distinguish "absent" from "set to zero" in
/// policies that need the distinction (the `defined(bgp.aigp)`
/// filter DSL predicate consults `has_aigp`, not this accessor).
///
/// The metric is a `u64` on the wire (RFC 7311 §3); the filter DSL
/// surfaces it as a signed `i64` (the `Value::Int` width), so a
/// metric exceeding `i64::MAX` saturates to `i64::MAX` on the DSL
/// read — practical IGP metrics are far below `i64::MAX`, and the
/// alternative (`u64` as an unsigned DSL value) would need a new
/// `Value` variant.
///
/// Reads pay one BTreeMap lookup + one TLV-stream parse per route.
/// Unlike `local_pref` / `med` / `otc` (which use the in-place
/// `get_u32_be` fast path), AIGP's value is a TLV stream so a
/// single `get_u32_be` cannot read it; the parse is bounded by the
/// attribute length and skips unknown TLVs in O(n).
pub fn aigp(route: &Route) -> Option<u64> {
    let bytes = route
        .attributes
        .get(AttrTag::raw(TAG_AIGP))?
        .value
        .as_slice();
    Aigp::decode(bytes).map(|a| a.metric())
}

/// True when an AIGP attribute is physically present on the route
/// (RFC 7311). Use this to distinguish "no attribute" from "present
/// but zero" — `aigp()` returns `Some(0)` for the latter (e.g. an
/// empty value field).
pub fn has_aigp(route: &Route) -> bool {
    route.attributes.get(AttrTag::raw(TAG_AIGP)).is_some()
}

/// The route's AGGREGATOR attribute (RFC 4271 §5.1.7) decoded into
/// its `(asn, speaker)` pair. `None` when the attribute is absent (a
/// route that was not aggregated) or when the wire form is malformed
/// (any length other than 6 or 8 bytes). The stored form is the
/// canonical 4-byte-AS encoding — ingress reconciles AS4_AGGREGATOR
/// (type 18, RFC 6793) into this tag so a single read sees the
/// resolved value regardless of the peer's AS-width capability.
///
/// BIRD spells AGGREGATOR as a structured `egroup` value in its
/// filter language; lr's DSL decomposes the pair into two fields
/// (`bgp.aggregator.asn`, `bgp.aggregator.speaker`) so a policy can
/// match either component independently. The canonical idiom
/// `defined(bgp_aggregator)` — "was this route aggregated?" —
/// translates to `defined(bgp.aggregator.asn)`; both components are
/// present together or absent together, so the presence probe is
/// faithful on either field.
///
/// Reads pay one BTreeMap lookup + one `Aggregator::decode` (a
/// length check + two fixed-size copies); no allocation on the
/// common path. The 2-byte-AS legacy wire form (6 bytes) is widened
/// to a 32-bit `Asn` by the codec, so the accessor never returns a
/// truncated AS.
pub fn aggregator(route: &Route) -> Option<Aggregator> {
    let bytes = attr_bytes(route, TAG_AGGREGATOR)?;
    Aggregator::decode(bytes)
}

/// The route's aggregator AS number (RFC 4271 §5.1.7) as a `u32`;
/// `None` when the AGGREGATOR attribute is absent or malformed. A
/// present value of `0` ("set but zero") is returned as `Some(0)` —
/// use [`has_aggregator`] to distinguish "absent" from "set to zero"
/// in policies that need the distinction (the
/// `defined(bgp.aggregator.asn)` filter DSL predicate consults
/// `has_aggregator`, not this accessor).
pub fn aggregator_asn(route: &Route) -> Option<u32> {
    aggregator(route).map(|a| a.asn.0)
}

/// The route's aggregator speaker IP (RFC 4271 §5.1.7) as an
/// `IpAddr::V4`; `None` when the AGGREGATOR attribute is absent or
/// malformed. BIRD spells the speaker as an `ip`; the `IpAddr::V4`
/// representation matches so a BIRD filter like
/// `if bgp_aggregator.speaker = 10.0.0.1 then reject;` translates
/// faithfully.
pub fn aggregator_speaker(route: &Route) -> Option<IpAddr> {
    aggregator(route).map(|a| IpAddr::V4(a.speaker))
}

/// True when an AGGREGATOR attribute is physically present on the
/// route (RFC 4271 §5.1.7). Use this to distinguish "no attribute"
/// from "present but the AS/speaker is zero" — `aggregator_asn()`
/// returns `Some(0)` for the latter.
pub fn has_aggregator(route: &Route) -> bool {
    route.attributes.get(AttrTag::raw(TAG_AGGREGATOR)).is_some()
}

/// The route's PMSI Tunnel attribute (RFC 6514 §5) decoded into the
/// typed view the policy layer reads — the provider-tunnel binding a
/// BGP UPDATE advertises for an MVPN auto-discovery route. `None`
/// when the attribute is absent (the route is not an MVPN A-D route)
/// or when the value field is malformed (shorter than the 5-byte
/// header; Tunnel Type 0 with a non-empty Tunnel Identifier; Tunnel
/// Type 6 with an endpoint width other than 4 or 16 bytes). The
/// codec stores the raw attribute bytes verbatim so any well-formed
/// attribute round-trips byte-for-byte.
///
/// BIRD exposes the attribute in its filter language as
/// `bgp_pmsi_tunnel` (an opaque bytestring; the only meaningful
/// operation is `defined(bgp_pmsi_tunnel)` — "does the route carry
/// a PMSI Tunnel binding?"). The lr DSL mirrors that surface as a
/// read-only `bool` field `bgp.pmsi_tunnel` (read through
/// `has_pmsi_tunnel`, not `pmsi_tunnel()` — the latter collapses
/// "absent" and "malformed" together, but the former keeps
/// "present but malformed" defined so a partial-bit UPDATE from a
/// non-MVPN peer does not get a false `defined()` read).
///
/// Reads pay one BTreeMap lookup + one `PmsiTunnel::decode` (a
/// length check, three fixed-size copies and a per-Tunnel-Type
/// length validation); no allocation on the common path beyond the
/// `tunnel_id` Vec (mirrors AIGP's TLV-stream read cost). Like
/// AIGP, the read is not a single `get_u32_be`, so the peephole
/// pass does not fuse `bgp.pmsi_tunnel` integer comparisons into
/// `BranchFieldIntCmp` — but the field surfaces as a `Bool`, so the
/// comparison shape does not arise in the DSL.
pub fn pmsi_tunnel(route: &Route) -> Option<PmsiTunnel> {
    let bytes = attr_bytes(route, TAG_PMSI_TUNNEL)?;
    PmsiTunnel::decode(bytes)
}

/// True when a PMSI Tunnel attribute is physically present on the
/// route (RFC 6514 §5). Use this to distinguish "no attribute" from
/// "present but malformed" — `pmsi_tunnel()` returns `None` for
/// both, but `has_pmsi_tunnel()` reports the attribute's physical
/// presence so the `defined(bgp.pmsi_tunnel)` filter DSL predicate
/// can distinguish them exactly as BIRD's `defined(bgp_pmsi_tunnel)`
/// does.
pub fn has_pmsi_tunnel(route: &Route) -> bool {
    route
        .attributes
        .get(AttrTag::raw(TAG_PMSI_TUNNEL))
        .is_some()
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

    /// RFC 7311 §3 — AIGP's value is a TLV stream whose type-1 TLV
    /// carries an 8-byte accumulated metric; the helper surfaces it
    /// as `u64` and stays `None` on the absent and malformed cases.
    /// A present value of `0` ("set but zero") is returned as
    /// `Some(0)` so policies that need the distinction consult
    /// `has_aigp` instead.
    #[test]
    fn aigp_decodes_as_u64() {
        use lr_bgp::path::well_known::Aigp as AigpTy;
        // Present, metric 64512.
        let r = route_with(vec![raw_attr(
            TAG_AIGP,
            0x80,
            AigpTy::from_metric(64512).encode(),
        )]);
        assert_eq!(aigp(&r), Some(64512));
        assert!(has_aigp(&r));
        // Absent.
        let r_absent = route_with(vec![]);
        assert_eq!(aigp(&r_absent), None);
        assert!(!has_aigp(&r_absent));
        // Present, metric 0 — "set but zero". `aigp()` returns
        // `Some(0)`; `has_aigp()` reports presence. This is the case
        // `defined(bgp.aigp)` in the filter DSL must distinguish from
        // "absent".
        let r_zero = route_with(vec![raw_attr(
            TAG_AIGP,
            0x80,
            AigpTy::from_metric(0).encode(),
        )]);
        assert_eq!(aigp(&r_zero), Some(0));
        assert!(has_aigp(&r_zero));
        // Empty value field — RFC 7311 does not forbid an empty
        // AIGP attribute; the helper surfaces it as `Some(0)`.
        let r_empty = route_with(vec![raw_attr(TAG_AIGP, 0x80, Vec::new())]);
        assert_eq!(aigp(&r_empty), Some(0));
        assert!(has_aigp(&r_empty));
        // Malformed TLV stream (truncated header) — `aigp()` returns
        // None; `has_aigp()` still reports presence (the attribute is
        // on the route; only the value is unreadable). Mirrors the
        // `cluster_list()` accessor's behaviour on a partial tail.
        let r_bad = route_with(vec![raw_attr(TAG_AIGP, 0x80, vec![0, 1, 2])]);
        assert_eq!(aigp(&r_bad), None);
        assert!(has_aigp(&r_bad));
    }

    /// RFC 4271 §5.1.7 — AGGREGATOR is a 6-byte (2-byte AS) or 8-byte
    /// (4-byte AS) value; the helper surfaces the AS as `u32` (the
    /// 2-byte form is widened) and the speaker as `IpAddr::V4`, and
    /// stays `None` on the absent and malformed cases. A present
    /// value of AS 0 ("set but zero") is returned as `Some(0)` so
    /// policies that need the distinction consult `has_aggregator`
    /// instead.
    #[test]
    fn aggregator_decodes_asn_and_speaker() {
        use lr_bgp::path::well_known::Aggregator as AggregatorTy;
        // Present, 4-byte AS form (the canonical stored encoding).
        let r = route_with(vec![raw_attr(
            TAG_AGGREGATOR,
            0xC0,
            AggregatorTy {
                asn: Asn(64512),
                speaker: [10, 0, 0, 1],
            }
            .encode_4()
            .to_vec(),
        )]);
        assert_eq!(aggregator_asn(&r), Some(64512));
        assert_eq!(aggregator_speaker(&r), Some(IpAddr::V4([10, 0, 0, 1])));
        assert!(has_aggregator(&r));
        // Absent.
        let r_absent = route_with(vec![]);
        assert_eq!(aggregator_asn(&r_absent), None);
        assert_eq!(aggregator_speaker(&r_absent), None);
        assert!(!has_aggregator(&r_absent));
        // Present, AS 0 — "set but zero". `aggregator_asn()` returns
        // `Some(0)`; `has_aggregator()` reports presence. This is the
        // case `defined(bgp.aggregator.asn)` in the filter DSL must
        // distinguish from "absent".
        let r_zero = route_with(vec![raw_attr(
            TAG_AGGREGATOR,
            0xC0,
            AggregatorTy {
                asn: Asn(0),
                speaker: [0, 0, 0, 0],
            }
            .encode_4()
            .to_vec(),
        )]);
        assert_eq!(aggregator_asn(&r_zero), Some(0));
        assert!(has_aggregator(&r_zero));
        // Legacy 2-byte-AS wire form (6 bytes) — widened to a 32-bit
        // `Asn` by the codec so the accessor never returns a
        // truncated AS.
        let r_legacy = route_with(vec![raw_attr(
            TAG_AGGREGATOR,
            0xC0,
            vec![0xFC, 0x00, 10, 0, 0, 1], // AS 64512, speaker 10.0.0.1
        )]);
        assert_eq!(aggregator_asn(&r_legacy), Some(64512));
        assert_eq!(
            aggregator_speaker(&r_legacy),
            Some(IpAddr::V4([10, 0, 0, 1]))
        );
        // Malformed width — `aggregator_asn()` / `aggregator_speaker()`
        // return None; `has_aggregator()` still reports presence (the
        // attribute is on the route; only the value is unreadable).
        // Mirrors the `cluster_list()` accessor's behaviour on a
        // partial tail.
        let r_bad = route_with(vec![raw_attr(TAG_AGGREGATOR, 0xC0, vec![1, 2, 3])]);
        assert_eq!(aggregator_asn(&r_bad), None);
        assert_eq!(aggregator_speaker(&r_bad), None);
        assert!(has_aggregator(&r_bad));
    }

    /// RFC 6514 §5 — PMSI Tunnel is a 5-byte minimum (Flags + Tunnel
    /// Type + MPLS Label) plus a variable-length Tunnel Identifier.
    /// The helper surfaces the typed view (Flags, Tunnel Type,
    /// MPLS Label, Tunnel Identifier) and stays `None` on the
    /// absent and malformed cases. A present-but-malformed attribute
    /// (truncated header, Tunnel Type 0 with a non-empty Tunnel
    /// Identifier, Tunnel Type 6 with an endpoint width other than
    /// 4 or 16) is reported as physically present by `has_pmsi_tunnel`
    /// so the `defined(bgp.pmsi_tunnel)` filter DSL predicate can
    /// distinguish "present but malformed" from "absent".
    #[test]
    fn pmsi_tunnel_decodes_typed_view() {
        use lr_bgp::path::well_known::{
            PmsiTunnel as PmsiTy, PMSI_FLAG_LEAF_INFO_REQUIRED, TUNNEL_TYPE_INGRESS_REPLICATION,
            TUNNEL_TYPE_NO_INFO,
        };
        // Present, Tunnel Type 6 (Ingress Replication), IPv4
        // endpoint, MPLS label 64512, L bit set.
        let r = route_with(vec![raw_attr(
            TAG_PMSI_TUNNEL,
            0xC0,
            PmsiTy::new(
                PMSI_FLAG_LEAF_INFO_REQUIRED,
                TUNNEL_TYPE_INGRESS_REPLICATION,
                64512,
                vec![10, 0, 0, 1],
            )
            .encode(),
        )]);
        let p = pmsi_tunnel(&r).expect("present, well-formed");
        assert_eq!(p.tunnel_type, TUNNEL_TYPE_INGRESS_REPLICATION);
        assert_eq!(p.mpls_label, 64512);
        assert_eq!(p.tunnel_id, vec![10, 0, 0, 1]);
        assert!(p.leaf_info_required());
        assert!(has_pmsi_tunnel(&r));
        // Absent.
        let r_absent = route_with(vec![]);
        assert_eq!(pmsi_tunnel(&r_absent), None);
        assert!(!has_pmsi_tunnel(&r_absent));
        // Present, Tunnel Type 0 ("No tunnel information present")
        // — the attribute carries no Tunnel Identifier; the helper
        // surfaces the typed view (`mpls_label = 0`, empty
        // `tunnel_id`).
        let r_no_info = route_with(vec![raw_attr(
            TAG_PMSI_TUNNEL,
            0xC0,
            PmsiTy::new(0, TUNNEL_TYPE_NO_INFO, 0, Vec::new()).encode(),
        )]);
        let p = pmsi_tunnel(&r_no_info).expect("no-info decodes");
        assert_eq!(p.tunnel_type, TUNNEL_TYPE_NO_INFO);
        assert_eq!(p.mpls_label, 0);
        assert!(p.tunnel_id.is_empty());
        assert!(!p.leaf_info_required());
        assert!(has_pmsi_tunnel(&r_no_info));
        // Malformed value (truncated header) — `pmsi_tunnel()`
        // returns None; `has_pmsi_tunnel()` still reports presence
        // (the attribute is on the route; only the value is
        // unreadable). Mirrors the AIGP accessor's behaviour on a
        // malformed TLV stream.
        let r_bad = route_with(vec![raw_attr(TAG_PMSI_TUNNEL, 0xC0, vec![0, 0, 0, 0])]);
        assert_eq!(pmsi_tunnel(&r_bad), None);
        assert!(has_pmsi_tunnel(&r_bad));
        // Tunnel Type 0 with a non-empty Tunnel Identifier — RFC
        // 6514 §5 forbids this; the helper surfaces it as `None`
        // while `has_pmsi_tunnel` still reports presence.
        let r_bad_no_info = route_with(vec![raw_attr(
            TAG_PMSI_TUNNEL,
            0xC0,
            vec![0, TUNNEL_TYPE_NO_INFO, 0, 0, 0, 0xaa],
        )]);
        assert_eq!(pmsi_tunnel(&r_bad_no_info), None);
        assert!(has_pmsi_tunnel(&r_bad_no_info));
    }
}
