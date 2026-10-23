//! Typed OSPF route-attribute access for policy evaluation.
//!
//! Mirrors [`crate::bgp`] for the per-protocol route attributes BIRD's
//! filter language exposes under the `ospf_*` prefix. The lr
//! [`Route`](lr_core::rib::Route) data model carries the OSPF metric
//! in [`Route::preference`]`.metric` (the same field every protocol
//! feeds into the cross-protocol admin-distance sort), so the
//! accessors here read by protocol kind — not by tag — and return
//! `None` for non-OSPF routes. That mirrors BIRD's eattr semantics: an
//! `ospf_metric1` reference on a non-OSPF route reads as the
//! attribute's default (zero), and `defined(ospf_metric1)` is false
//! because the OSPF protocol never attached the attribute.
//!
//! The lr surface is `ospf.metric1`, `ospf.metric2`, `ospf.tag`,
//! `ospf.router_id` over time; this module opens with `metric1`,
//! `metric2`, `tag` and `router_id`. Each `metric1` accessor is one branch on
//! [`Route::protocol`] plus a field read — no allocation, no codec.
//! The `metric2` accessor reads the private `LrOspfMetric2`
//! path-attribute tag the OSPF route computation attaches to type-2
//! external routes — one BTreeMap lookup plus one 4-byte read, no
//! allocation, no codec dependency. The `tag` accessor reads
//! [`Route::tag`] for OSPF routes — one branch on
//! [`Route::protocol`] plus one `Option<u32>` field read — no
//! allocation, no codec, no BTreeMap lookup. The OSPF route
//! computation populates `Route::tag` from the LSA's external route
//! tag (RFC 2328 §A.4.5 bullet h / RFC 3101 §2.3 / RFC 5340 §A.4.7 T
//! bit / RFC 8362 §3.6 External-Prefix sub-TLV 3) for external
//! routes; intra-area and inter-area routes carry no tag (the LSA
//! body has no tag field for those). The existing `SetTag` policy
//! action overwrites `Route::tag` for the operator-side override.
//! The `router_id` accessor reads the private `LrOspfRouterId`
//! path-attribute tag the OSPF route computation attaches to every
//! OSPF route with a known originating LSA — one BTreeMap lookup
//! plus one 4-byte read, no allocation, no codec dependency. The
//! value is the 32-bit OSPF Router-ID of the router that originated
//! the LSA the route was computed from (RFC 2328 §A.4 `Advertising
//! Router` field / RFC 5340 §A.4 the same field on every v3 LSA) —
//! the Router-LSA's advertising router for intra-area stub routes,
//! the Network-LSA's advertising router (the DR) for intra-area
//! transit routes, the summary-LSA's advertising router (the ABR)
//! for inter-area routes, and the AS-external-LSA's advertising
//! router (the ASBR) for external routes.
//!
//! RFC references:
//! - RFC 2328 §16 — OSPFv2 route preference order and metric
//!   semantics (the `metric1` field the decision process ranks
//!   against for intra-area, inter-area and type-1 external routes;
//!   the cost alone for type-2 external routes; the `metric2` field
//!   that holds the type-2 external metric — the E-bit-set LSA
//!   metric, §16.4 (6)).
//! - RFC 2328 §A.4 — the LSA header's `Advertising Router` field
//!   (the 32-bit OSPF Router-ID of the router that originated the
//!   LSA; the value the `router_id` accessor surfaces for every
//!   OSPF route).
//! - RFC 2328 §A.4.5 bullet h — the 32-bit external route tag
//!   carried in the type-5 AS-external-LSA body (the v2 form always
//!   carries a 4-byte tag field, zero being well-formed).
//! - RFC 3101 §2.3 / Appendix A — the type-7 NSSA-external-LSA
//!   body is byte-identical to the type-5 body, so the same tag
//!   field applies.
//! - RFC 5340 §4.1 — OSPFv3 route preference (mirrors OSPFv2).
//! - RFC 5340 §4.8.5 — OSPFv3 external route calculation (mirrors
//!   §16.4).
//! - RFC 5340 §A.4 — the v3 LSA header's `Advertising Router`
//!   field (mirrors RFC 2328 §A.4 — the same field, the same
//!   semantics; the value the `router_id` accessor surfaces for v3
//!   routes).
//! - RFC 5340 §A.4.7 — the v3 AS-external-LSA body's T bit / tag
//!   field (the v3 form treats a missing tag — T bit clear — as a
//!   meaningful state distinct from a tag of zero).
//! - RFC 8362 §3.6 — the Extended-LSA External-Prefix sub-TLV 3
//!   carries the v3 external route tag for the OSPFv3 Extended-LSA
//!   form.
//! - BIRD 2 `proto/ospf/ospf.c` — `ea_ospf_metric1`, `ea_ospf_metric2`,
//!   `ea_ospf_tag` and `ea_ospf_router_id` are the eattrs these
//!   accessors surface.

use lr_core::attr::AttrTag;
use lr_core::rib::{Protocol, Route};

/// The path-attribute tag carrying the OSPF type-2 external metric
/// (RFC 2328 §16.4 / RFC 5340 §4.8.5). Mirrors
/// `lr_bgp::path::AttrType::LrOspfMetric2` (value 253); kept as a
/// `u8` here so the accessor stays unconditional — no `lr-bgp`
/// dependency. The BGP codec strips the tag at encode so peers never
/// see it; only the OSPF route computation
/// (`lr-router::instance::ospf_ops`) populates the attribute, and
/// only for type-2 external routes (where the type-5 / type-7 LSA's
/// E-bit is set).
///
/// The value layout is a single 4-byte big-endian `u32` holding the
/// 24-bit external metric (zero-extended — RFC 2328 §2.3 caps the
/// metric at 24 bits, so the high byte is always zero on a
/// well-formed value).
const LR_OSPF_METRIC2_TAG: u8 = 253;

/// The path-attribute tag carrying the OSPF advertising-router ID
/// (RFC 2328 §A.4 `Advertising Router` field / RFC 5340 §A.4 the
/// same field on every v3 LSA). Mirrors
/// `lr_bgp::path::AttrType::LrOspfRouterId` (value 252); kept as a
/// `u8` here so the accessor stays unconditional — no `lr-bgp`
/// dependency. The BGP codec strips the tag at encode so peers
/// never see it; the OSPF route computation
/// (`lr-router::instance::ospf_ops`) populates the attribute for
/// every OSPFv2 / OSPFv3 route with a known originating LSA —
/// intra-area (Router-LSA / Network-LSA advertising router),
/// inter-area (summary-LSA advertising router = the ABR), and
/// external (AS-external-LSA advertising router = the ASBR).
///
/// The value layout is a single 4-byte big-endian `u32` holding the
/// 32-bit OSPF Router-ID (the LSA `Advertising Router` field is a
/// 32-bit dotted-quad per RFC 2328 §A.4 — no masking needed; the
/// high byte is meaningful).
const LR_OSPF_ROUTER_ID_TAG: u8 = 252;

/// The route's primary OSPF metric (RFC 2328 §16 / RFC 5340 §4.1) —
/// the SPF cost for intra-area and inter-area routes, the
/// cost-plus-external-metric for type-1 external routes, and the
/// cost alone for type-2 external routes. This is the field the OSPF
/// decision process ranks against.
///
/// Returns `Some(metric)` for OSPFv2 / OSPFv3 routes (the metric the
/// SPF computation placed in [`Route::preference`]`.metric`) and
/// `None` for non-OSPF routes — mirroring BIRD's eattr semantics,
/// where an `ospf_metric1` reference on a non-OSPF route has no
/// attached attribute. A present metric of `0` ("cost zero") is
/// returned as `Some(0)` — use [`has_metric1`] to distinguish "non-OSPF
/// route" from "OSPF route with metric 0" in policies that need the
/// distinction (the `defined(ospf.metric1)` filter DSL predicate
/// consults `has_metric1`, not this accessor).
///
/// Reads pay one `match` on [`Route::protocol`] plus one field read
/// — no allocation, no codec, no BTreeMap lookup. Cheaper than any
/// `bgp_*` accessor that decodes a path attribute.
pub fn metric1(route: &Route) -> Option<u32> {
    match route.protocol {
        Protocol::Ospfv2 | Protocol::Ospfv3 => Some(route.preference.metric),
        _ => None,
    }
}

/// True when the route is an OSPFv2 / OSPFv3 route and therefore
/// carries a primary OSPF metric (RFC 2328 §16 / RFC 5340 §4.1). Use
/// this to distinguish "non-OSPF route" from "OSPF route with metric
/// 0" — [`metric1`] returns `Some(0)` for the latter.
///
/// The filter DSL's `defined(ospf.metric1)` predicate consults this
/// helper, not `metric1().is_some()`: the two agree on the OSPF case
/// (both true), but the distinction matters when a downstream caller
/// adds a "metric zero is meaningful" semantic — `has_metric1` keeps
/// "OSPF route with metric 0" defined, the same shape `has_otc` /
/// `has_aigp` / `has_aggregator` expose for the BGP path-attribute
/// presence probes.
pub fn has_metric1(route: &Route) -> bool {
    matches!(route.protocol, Protocol::Ospfv2 | Protocol::Ospfv3)
}

/// The route's secondary OSPF metric (RFC 2328 §16.4 / RFC 5340
/// §4.8.5) — the type-2 external metric the OSPF decision process
/// ranks against for type-2 external routes (the E-bit-set LSA
/// metric — the value that, alone, decides type-2 preference per
/// §16.4 (6); the cost to the ASBR breaks the tie, and that cost
/// lives in [`metric1`] for type-2 externals in lr's
/// `preference.metric` model). Zero for non-type-2 OSPF routes
/// (intra-area, inter-area, type-1 external) — the OSPF route
/// computation only attaches the [`LrOspfMetric2`](lr_bgp::path::AttrType::LrOspfMetric2)
/// attribute for type-2 externals, so its absence reads as `0`
/// (BIRD's eattr default for an unattached `ospf_metric2` reference).
///
/// Returns `Some(metric)` for OSPFv2 / OSPFv3 routes that are
/// type-2 external (the attribute is present) and `None` for
/// everything else — non-OSPF routes, OSPF intra-area / inter-area
/// routes, and OSPF type-1 external routes. A present metric of `0`
/// is returned as `Some(0)` — use [`has_metric2`] to distinguish
/// "not a type-2 external" from "type-2 external with metric 0"
/// in policies that need the distinction (the
/// `defined(ospf.metric2)` filter DSL predicate consults
/// `has_metric2`, not this accessor).
///
/// Reads pay one BTreeMap lookup plus one 4-byte read on
/// [`Route::attributes`] — no allocation, no codec (the value layout
/// is a fixed 4-byte big-endian `u32`). Cheaper than any `bgp_*`
/// accessor that decodes a multi-byte TLV stream, but more
/// expensive than [`metric1`] (which reads a struct field, no
/// lookup).
pub fn metric2(route: &Route) -> Option<u32> {
    // Only OSPF routes can carry the LrOspfMetric2 attribute — the
    // OSPF route computation (`lr-router::instance::ospf_ops`) is
    // the only producer. The protocol check is a cheap fast-path
    // rejection for non-OSPF routes that avoids the BTreeMap lookup
    // entirely.
    if !matches!(route.protocol, Protocol::Ospfv2 | Protocol::Ospfv3) {
        return None;
    }
    route
        .attributes
        .get_u32_be(AttrTag::raw(LR_OSPF_METRIC2_TAG))
}

/// True when the route is an OSPFv2 / OSPFv3 type-2 external route
/// (RFC 2328 §16.4 / RFC 5340 §4.8.5) and therefore carries a
/// secondary OSPF metric. Use this to distinguish "not a type-2
/// external" from "type-2 external with metric 0" — [`metric2`]
/// returns `Some(0)` for the latter (an E-bit-set type-5 LSA whose
/// 24-bit external metric happens to be zero, which is unusual but
/// well-formed per RFC 2328 §2.3).
///
/// The filter DSL's `defined(ospf.metric2)` predicate consults this
/// helper, not `metric2().is_some()`: the two agree on the
/// type-2-external case (both true), but the distinction matters
/// when a downstream caller adds a "metric zero is meaningful"
/// semantic — `has_metric2` keeps "type-2 external with metric 0"
/// defined, the same shape [`has_metric1`] / `has_otc` / `has_aigp`
/// / `has_aggregator` expose for the other presence probes.
pub fn has_metric2(route: &Route) -> bool {
    if !matches!(route.protocol, Protocol::Ospfv2 | Protocol::Ospfv3) {
        return false;
    }
    route
        .attributes
        .get(AttrTag::raw(LR_OSPF_METRIC2_TAG))
        .is_some()
}

/// The route's external route tag (RFC 2328 §A.4.5 bullet h /
/// RFC 3101 §2.3 / RFC 5340 §A.4.7 T bit / RFC 8362 §3.6
/// External-Prefix sub-TLV 3) — the 32-bit tag carried in the
/// type-5 / type-7 AS-external-LSA body. The OSPF route computation
/// populates [`Route::tag`] from the LSA's tag for external routes
/// (the v2 form always surfaces `Some(tag)`, since the v2 LSA body
/// always carries a 4-byte tag field, zero being well-formed; the
/// v3 form surfaces `Some(tag)` when the T bit / sub-TLV is present,
/// `None` otherwise — the v3 T bit distinguishes "no tag" from
/// "tag of zero"). Returns `None` for OSPF intra-area and inter-area
/// routes (the LSA carries no tag for those) and for non-OSPF
/// routes — mirroring BIRD's eattr semantics, where an `ospf_tag`
/// reference on a non-OSPF route has no attached attribute. A
/// present tag of `0` is returned as `Some(0)` (the v2 form) — use
/// [`has_tag`] to distinguish "no tag" from "tag of zero" in
/// policies that need the distinction (the `defined(ospf.tag)`
/// filter DSL predicate consults `has_tag`, not this accessor).
///
/// Reads pay one `match` on [`Route::protocol`] plus one
/// `Option<u32>` field read off [`Route::tag`] — no allocation, no
/// codec, no BTreeMap lookup. Cheaper than [`metric2`] (which
/// pays a BTreeMap lookup plus a 4-byte read) and the same shape
/// as [`metric1`] (which reads a struct field, no lookup). The
/// existing `SetTag` policy action overwrites [`Route::tag`] for
/// the operator-side override; the read here is the receive-side
/// input the OSPF daemon attaches.
pub fn tag(route: &Route) -> Option<u32> {
    match route.protocol {
        Protocol::Ospfv2 | Protocol::Ospfv3 => route.tag,
        _ => None,
    }
}

/// True when the route is an OSPFv2 / OSPFv3 external route (RFC 2328
/// §16.4 / RFC 5340 §4.8.5) and therefore carries an external route
/// tag (RFC 2328 §A.4.5 bullet h / RFC 3101 §2.3 / RFC 5340 §A.4.7 T
/// bit / RFC 8362 §3.6 External-Prefix sub-TLV 3). Use this to
/// distinguish "no tag" from "tag of zero" — [`tag`] returns
/// `Some(0)` for the v2 form when the LSA's tag is zero (the v2
/// LSA body always carries a 4-byte tag field, zero being
/// well-formed), but returns `None` for the v3 form when the T bit
/// is clear (the v3 T bit distinguishes "no tag" from "tag of
/// zero"). For intra-area and inter-area OSPF routes, `has_tag`
/// is false (the LSA carries no tag for those).
///
/// The filter DSL's `defined(ospf.tag)` predicate consults this
/// helper, not `tag().is_some()`: the two agree on the v3 case
/// (both true when the T bit is set, both false when it is clear),
/// but the distinction matters for the v2 form — `has_tag` keeps
/// "v2 external with tag 0" defined so the canonical idiom `if
/// defined(ospf.tag) && ospf.tag == 0 then accept;` does not drop a
/// v2 external with a zero tag (a v2 LSA whose 4-byte tag field
/// happens to be zero, which is well-formed per RFC 2328 §A.4.5).
/// For non-OSPF routes, `has_tag` is false (the protocol-kind fast
/// path rejects them, mirroring BIRD's eattr absence on non-OSPF
/// routes).
pub fn has_tag(route: &Route) -> bool {
    match route.protocol {
        Protocol::Ospfv2 | Protocol::Ospfv3 => route.tag.is_some(),
        _ => false,
    }
}

/// The route's OSPF advertising-router ID (RFC 2328 §A.4
/// `Advertising Router` field / RFC 5340 §A.4 the same field on
/// every v3 LSA) — the 32-bit OSPF Router-ID of the router that
/// originated the LSA the route was computed from. For intra-area
/// stub routes this is the Router-LSA's advertising router (the
/// router that owns the stub network); for intra-area transit
/// routes it is the Network-LSA's advertising router (the DR); for
/// inter-area routes it is the summary-LSA's advertising router
/// (the ABR); for external routes it is the AS-external-LSA's
/// advertising router (the ASBR). Returns `None` for non-OSPF
/// routes (no LSA, no advertising router) and for OSPF routes whose
/// route computation could not identify the originating LSA's
/// advertising router (a defensive fallback; the LSA header always
/// carries the field per RFC 2328 §A.4, so the OSPF route
/// computation populates it for every received OSPF route).
/// `Some(0)` is a meaningful value (a router may legally carry
/// Router-ID 0.0.0.0, though RFC 2328 §3.1.b recommends a non-zero
/// value) — use [`has_router_id`] to distinguish "no attribute"
/// from "attribute present but zero" in policies that need the
/// distinction (the `defined(ospf.router_id)` filter DSL predicate
/// consults `has_router_id`, not this accessor).
///
/// Reads pay one BTreeMap lookup plus one 4-byte read on
/// [`Route::attributes`] — no allocation, no codec (the value
/// layout is a fixed 4-byte big-endian `u32`). Cheaper than any
/// `bgp_*` accessor that decodes a multi-byte TLV stream, the same
/// shape as [`metric2`] (which reads a different private tag) and
/// more expensive than [`metric1`] / [`tag`] (which read struct
/// fields, no lookup). The BGP codec strips the tag at encode so
/// peers never see it.
pub fn router_id(route: &Route) -> Option<u32> {
    // Only OSPF routes can carry the LrOspfRouterId attribute — the
    // OSPF route computation (`lr-router::instance::ospf_ops`) is
    // the only producer. The protocol check is a cheap fast-path
    // rejection for non-OSPF routes that avoids the BTreeMap
    // lookup entirely.
    if !matches!(route.protocol, Protocol::Ospfv2 | Protocol::Ospfv3) {
        return None;
    }
    route
        .attributes
        .get_u32_be(AttrTag::raw(LR_OSPF_ROUTER_ID_TAG))
}

/// True when the route is an OSPFv2 / OSPFv3 route (RFC 2328 / RFC
/// 5340) with a known originating LSA's advertising router, and
/// therefore carries an OSPF router-id attribute. Use this to
/// distinguish "no attribute" (a non-OSPF route, or an OSPF route
/// whose route computation could not identify the originating
/// LSA's advertising router) from "attribute present but zero"
/// — [`router_id`] returns `Some(0)` for the latter (a router may
/// legally carry Router-ID 0.0.0.0 per RFC 2328 §3.1.b, though
/// non-zero is recommended).
///
/// The filter DSL's `defined(ospf.router_id)` predicate consults
/// this helper, not `router_id().is_some()`: the two agree on the
/// present-with-non-zero case (both true), but the distinction
/// matters when a router carries Router-ID 0.0.0.0 — `has_router_id`
/// keeps "OSPF route with Router-ID 0" defined so the canonical
/// idiom `if defined(ospf.router_id) && ospf.router_id == 0.0.0.0
/// then accept;` does not drop such a route. For non-OSPF routes,
/// `has_router_id` is false (the protocol-kind fast path rejects
/// them, mirroring BIRD's eattr absence on non-OSPF routes). For
/// OSPF routes whose route computation populated `router_id =
/// Some(id)`, `has_router_id` is true even when `id == 0`.
pub fn has_router_id(route: &Route) -> bool {
    if !matches!(route.protocol, Protocol::Ospfv2 | Protocol::Ospfv3) {
        return false;
    }
    route
        .attributes
        .get(AttrTag::raw(LR_OSPF_ROUTER_ID_TAG))
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::attr::{AttrTag, Attribute};
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, RouteKey, RouteOrigin};

    fn route(protocol: Protocol, metric: u32) -> Route {
        Route {
            key: RouteKey::new(
                Prefix::new_v4([203, 0, 113, 0], 24),
                NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol,
            preference: Preference::new(protocol.default_admin_distance(), metric),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    /// Build an OSPF route carrying the `LrOspfMetric2` attribute —
    /// mirrors what `lr-router::instance::ospf_ops` attaches for a
    /// type-2 external route. The attribute's value layout is the
    /// 4-byte big-endian form `set_ospf_metric2` writes.
    fn ospf_route_with_metric2(protocol: Protocol, metric1: u32, metric2: u32) -> Route {
        let mut r = route(protocol, metric1);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(LR_OSPF_METRIC2_TAG),
            flags: 0x80, // optional, non-transitive (matches the BGP path-attribute flag set the codec uses)
            value: metric2.to_be_bytes().to_vec(),
        });
        r
    }

    #[test]
    fn metric1_reads_for_ospf_routes() {
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            assert_eq!(metric1(&route(proto, 42)), Some(42));
            assert!(has_metric1(&route(proto, 42)));
        }
    }

    #[test]
    fn metric1_is_none_for_non_ospf_routes() {
        for proto in [
            Protocol::Bgp,
            Protocol::Babel,
            Protocol::Static,
            Protocol::Connected,
        ] {
            assert_eq!(metric1(&route(proto, 100)), None);
            assert!(!has_metric1(&route(proto, 100)));
        }
    }

    #[test]
    fn metric1_zero_is_present_for_ospf() {
        // An OSPF route with metric 0 is "present but zero" — the
        // distinction `has_metric1` exists to make precise. The
        // `defined(ospf.metric1)` filter DSL predicate consults
        // `has_metric1`, so an OSPF route with cost 0 stays defined
        // (mirrors `has_otc` for the BGP OTC attribute).
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            let r = route(proto, 0);
            assert_eq!(metric1(&r), Some(0));
            assert!(has_metric1(&r), "OSPF route with metric 0 is defined");
        }
    }

    #[test]
    fn other_protocol_is_not_defined() {
        // A BGP route with a metric (the LOCAL_PREF the BGP decision
        // process ranks against) is not an OSPF route — `has_metric1`
        // is false even though the route carries a metric in the
        // same `preference.metric` slot.
        let r = route(Protocol::Bgp, 100);
        assert!(!has_metric1(&r));
    }

    // ---- ospf.metric2 ------------------------------------------------

    #[test]
    fn metric2_reads_for_type2_external_ospf_routes() {
        // A type-2 external OSPFv2 route with external metric 200 —
        // the OSPF route computation attaches the LrOspfMetric2
        // attribute with value 200, and the accessor surfaces it.
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            let r = ospf_route_with_metric2(proto, 10, 200);
            assert_eq!(metric2(&r), Some(200));
            assert!(has_metric2(&r));
        }
    }

    #[test]
    fn metric2_is_none_for_ospf_routes_without_the_attribute() {
        // An OSPF route with no LrOspfMetric2 attribute — i.e. an
        // intra-area, inter-area or type-1 external route (the OSPF
        // route computation only attaches the tag for type-2
        // externals). `metric2` returns `None` and `has_metric2` is
        // false.
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            let r = route(proto, 42);
            assert_eq!(metric2(&r), None);
            assert!(!has_metric2(&r));
        }
    }

    #[test]
    fn metric2_is_none_for_non_ospf_routes_even_with_the_attribute() {
        // The accessor's protocol-kind fast path rejects a non-OSPF
        // route even if the attribute is somehow present (the OSPF
        // route computation never attaches the tag to a non-OSPF
        // route, but a hand-crafted test route that violates the
        // invariant still reads as `None` — defensive, mirrors
        // `metric1`'s protocol-kind check).
        let r = ospf_route_with_metric2(Protocol::Bgp, 100, 200);
        assert_eq!(metric2(&r), None);
        assert!(!has_metric2(&r));
    }

    #[test]
    fn metric2_zero_is_present_for_type2_external() {
        // A type-2 external OSPF route with external metric 0 is
        // "present but zero" — the distinction `has_metric2` exists
        // to make precise. The `defined(ospf.metric2)` filter DSL
        // predicate consults `has_metric2`, so a type-2 external
        // with metric 0 stays defined (mirrors `has_metric1` /
        // `has_otc` for the BGP presence probes).
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            let r = ospf_route_with_metric2(proto, 10, 0);
            assert_eq!(metric2(&r), Some(0));
            assert!(has_metric2(&r), "type-2 external with metric 0 is defined");
        }
    }

    #[test]
    fn metric2_malformed_value_is_absent() {
        // A value field that is not exactly 4 bytes is "malformed"
        // — the codec rejects it at decode (mirrors
        // `Attributes::get_u32_be`'s length check). `metric2`
        // returns `None` but `has_metric2` reports the attribute's
        // physical presence (the same shape `pmsi_tunnel` /
        // `has_pmsi_tunnel` expose for the BGP PMSI Tunnel
        // attribute).
        let mut r = route(Protocol::Ospfv2, 10);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(LR_OSPF_METRIC2_TAG),
            flags: 0x80,
            value: vec![0x00, 0x00, 0x64], // 3 bytes, not 4 — malformed
        });
        assert_eq!(metric2(&r), None);
        assert!(
            has_metric2(&r),
            "physical presence is true even when malformed"
        );
    }

    // ---- ospf.tag ----------------------------------------------------

    /// Build an OSPF route carrying a non-`None` `Route::tag` —
    /// mirrors what `lr-router::instance::ospf_ops` attaches for an
    /// external route whose LSA body carries a non-zero (v2) or
    /// T-bit-set (v3) tag. The route's `tag` field is the
    /// receive-side input the OSPF daemon attaches; the existing
    /// `SetTag` policy action would overwrite it.
    fn ospf_route_with_tag(protocol: Protocol, metric: u32, tag: u32) -> Route {
        let mut r = route(protocol, metric);
        r.tag = Some(tag);
        r
    }

    #[test]
    fn tag_reads_for_ospf_external_routes() {
        // An OSPFv2 / OSPFv3 external route whose LSA carried a
        // non-zero tag — the OSPF route computation surfaces the
        // tag through `Route::tag`, and the accessor surfaces it.
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            let r = ospf_route_with_tag(proto, 10, 0xdead_beef);
            assert_eq!(tag(&r), Some(0xdead_beef));
            assert!(has_tag(&r));
        }
    }

    #[test]
    fn tag_is_none_for_ospf_routes_without_a_tag() {
        // An OSPF route with `Route::tag = None` — i.e. an
        // intra-area, inter-area, or (v3 only) external without the
        // T bit set. The OSPF route computation leaves `Route::tag`
        // as `None` for those, so `tag` returns `None` and
        // `has_tag` is false.
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            let r = route(proto, 42);
            assert_eq!(tag(&r), None);
            assert!(!has_tag(&r));
        }
    }

    #[test]
    fn tag_is_none_for_non_ospf_routes_even_with_a_tag() {
        // The accessor's protocol-kind fast path rejects a non-OSPF
        // route even if `Route::tag` is somehow `Some` (a
        // hand-crafted test route or a `SetTag` action's
        // operator-side override on a non-OSPF route — the latter
        // is the legitimate case where `Route::tag` carries an
        // operator-assigned tag for OSPF redistribution). `tag`
        // returns `None` and `has_tag` is false — defensive,
        // mirrors `metric1`'s protocol-kind check.
        let r = ospf_route_with_tag(Protocol::Bgp, 100, 99);
        assert_eq!(tag(&r), None);
        assert!(!has_tag(&r));
    }

    #[test]
    fn tag_zero_is_present_for_ospf_external_v2() {
        // A v2 external route with a zero tag is "present but
        // zero" — the distinction `has_tag` exists to make
        // precise. The v2 LSA body always carries a 4-byte tag
        // field (zero being well-formed per RFC 2328 §A.4.5), so
        // the OSPF route computation surfaces `Some(0)` for any v2
        // external. The `defined(ospf.tag)` filter DSL predicate
        // consults `has_tag`, so a v2 external with tag 0 stays
        // defined — mirrors `has_metric1` / `has_otc` for the BGP
        // presence probes. (The v3 form's T bit does NOT have
        // this semantic — a missing v3 tag stays `None`.)
        let r = ospf_route_with_tag(Protocol::Ospfv2, 10, 0);
        assert_eq!(tag(&r), Some(0));
        assert!(has_tag(&r), "v2 external with tag 0 is defined");
    }

    #[test]
    fn tag_zero_is_present_for_ospf_external_v3_when_t_bit_set() {
        // An OSPFv3 external route with the T bit set and a zero
        // tag value is "present but zero" — same shape as the v2
        // case, but the v3 form requires the T bit / sub-TLV to
        // surface the tag. The OSPF route computation attaches
        // `Route::tag = Some(0)` only when the T bit is set; the
        // `defined(ospf.tag)` filter DSL predicate consults
        // `has_tag`, so a v3 external with T bit set and tag 0
        // stays defined.
        let r = ospf_route_with_tag(Protocol::Ospfv3, 10, 0);
        assert_eq!(tag(&r), Some(0));
        assert!(
            has_tag(&r),
            "v3 external with T bit set and tag 0 is defined"
        );
    }

    #[test]
    fn tag_independent_of_metric1_and_metric2() {
        // A filter that reads `ospf.tag` does not leak `metric1` or
        // `metric2` through. The three fields live on different
        // slots — `Route::tag`, `Route::preference.metric` and the
        // private `LrOspfMetric2` attribute — and the accessors
        // do not cross-read.
        let r = ospf_route_with_metric2(Protocol::Ospfv2, 50, 200);
        // No tag attached by the metric2 helper — `tag` is `None`.
        assert_eq!(tag(&r), None);
        assert!(!has_tag(&r));
        // The metric1 / metric2 reads are unchanged.
        assert_eq!(metric1(&r), Some(50));
        assert_eq!(metric2(&r), Some(200));
    }

    // ---- ospf.router_id -----------------------------------------------

    /// Build an OSPF route carrying the `LrOspfRouterId` attribute —
    /// mirrors what `lr-router::instance::ospf_ops` attaches for any
    /// OSPF route with a known originating LSA (intra-area, inter-area
    /// or external). The attribute's value layout is the 4-byte
    /// big-endian form `set_ospf_router_id` writes.
    fn ospf_route_with_router_id(protocol: Protocol, metric: u32, router_id: u32) -> Route {
        let mut r = route(protocol, metric);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(LR_OSPF_ROUTER_ID_TAG),
            flags: 0x80, // optional, non-transitive (matches the BGP path-attribute flag set the codec uses)
            value: router_id.to_be_bytes().to_vec(),
        });
        r
    }

    #[test]
    fn router_id_reads_for_ospf_routes_with_the_attribute() {
        // An OSPFv2 / OSPFv3 route whose route computation populated
        // `OspfTableEntry::router_id = Some(rid)` — `ospf_recompute`
        // attaches the LrOspfRouterId attribute with that value, and
        // the accessor surfaces it.
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            let r = ospf_route_with_router_id(proto, 10, 0xc0a8_0101);
            assert_eq!(router_id(&r), Some(0xc0a8_0101));
            assert!(has_router_id(&r));
        }
    }

    #[test]
    fn router_id_is_none_for_ospf_routes_without_the_attribute() {
        // An OSPF route with no LrOspfRouterId attribute — i.e. a
        // synthetic test route, or a route whose OSPF computation
        // could not identify the originating LSA's advertising
        // router (the defensive fallback the OSPF route computation
        // leaves as `None`). `router_id` returns `None` and
        // `has_router_id` is false.
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            let r = route(proto, 42);
            assert_eq!(router_id(&r), None);
            assert!(!has_router_id(&r));
        }
    }

    #[test]
    fn router_id_is_none_for_non_ospf_routes_even_with_the_attribute() {
        // The accessor's protocol-kind fast path rejects a non-OSPF
        // route even if the attribute is somehow present (the OSPF
        // route computation never attaches the tag to a non-OSPF
        // route, but a hand-crafted test route that violates the
        // invariant still reads as `None` — defensive, mirrors
        // `metric2`'s protocol-kind check).
        let r = ospf_route_with_router_id(Protocol::Bgp, 100, 0xc0a8_0101);
        assert_eq!(router_id(&r), None);
        assert!(!has_router_id(&r));
    }

    #[test]
    fn router_id_zero_is_present_for_ospf() {
        // An OSPF route with a Router-ID of 0.0.0.0 is "present but
        // zero" — the distinction `has_router_id` exists to make
        // precise. RFC 2328 §3.1.b recommends a non-zero value but
        // does not forbid 0.0.0.0, so the OSPF route computation
        // surfaces `Some(0)` for such a route, and the
        // `defined(ospf.router_id)` filter DSL predicate consults
        // `has_router_id`, so an OSPF route with Router-ID 0.0.0.0
        // stays defined — mirrors `has_metric1` / `has_tag` /
        // `has_otc` for the other presence probes.
        for proto in [Protocol::Ospfv2, Protocol::Ospfv3] {
            let r = ospf_route_with_router_id(proto, 10, 0);
            assert_eq!(router_id(&r), Some(0));
            assert!(has_router_id(&r), "OSPF route with Router-ID 0 is defined");
        }
    }

    #[test]
    fn router_id_malformed_value_is_absent() {
        // A value field that is not exactly 4 bytes is "malformed"
        // — the codec rejects it at decode (mirrors
        // `Attributes::get_u32_be`'s length check). `router_id`
        // returns `None` but `has_router_id` reports the attribute's
        // physical presence (the same shape `metric2` /
        // `has_metric2` expose for the OSPF type-2 external metric
        // attribute, and `pmsi_tunnel` / `has_pmsi_tunnel` expose
        // for the BGP PMSI Tunnel attribute).
        let mut r = route(Protocol::Ospfv2, 10);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(LR_OSPF_ROUTER_ID_TAG),
            flags: 0x80,
            value: vec![0xc0, 0xa8, 0x01], // 3 bytes, not 4 — malformed
        });
        assert_eq!(router_id(&r), None);
        assert!(
            has_router_id(&r),
            "physical presence is true even when malformed"
        );
    }

    #[test]
    fn router_id_independent_of_metric1_metric2_and_tag() {
        // A filter that reads `ospf.router_id` does not leak
        // `metric1`, `metric2` or `tag` through. The four fields
        // live on different slots — `Route::preference.metric`,
        // the private `LrOspfMetric2` attribute, `Route::tag` and
        // the private `LrOspfRouterId` attribute — and the
        // accessors do not cross-read.
        let r = ospf_route_with_metric2(Protocol::Ospfv2, 50, 200);
        // No router_id attached by the metric2 helper — `router_id`
        // is `None`.
        assert_eq!(router_id(&r), None);
        assert!(!has_router_id(&r));
        // The metric1 / metric2 reads are unchanged.
        assert_eq!(metric1(&r), Some(50));
        assert_eq!(metric2(&r), Some(200));
        // And the router_id route's metric1 / metric2 are unchanged.
        let r2 = ospf_route_with_router_id(Protocol::Ospfv2, 50, 0xc0a8_0101);
        assert_eq!(metric1(&r2), Some(50));
        assert_eq!(metric2(&r2), None);
        assert_eq!(router_id(&r2), Some(0xc0a8_0101));
        // `ospf.tag` is `None` for both — neither helper attaches
        // `Route::tag`.
        assert_eq!(tag(&r), None);
        assert_eq!(tag(&r2), None);
    }
}
