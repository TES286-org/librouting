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
//! `ospf.router_id` over time; this module opens with `metric1` and
//! `metric2`. Each `metric1` accessor is one branch on
//! [`Route::protocol`] plus a field read — no allocation, no codec.
//! The `metric2` accessor reads the private `LrOspfMetric2`
//! path-attribute tag the OSPF route computation attaches to type-2
//! external routes — one BTreeMap lookup plus one 4-byte read, no
//! allocation, no codec dependency.
//!
//! RFC references:
//! - RFC 2328 §16 — OSPFv2 route preference order and metric
//!   semantics (the `metric1` field the decision process ranks
//!   against for intra-area, inter-area and type-1 external routes;
//!   the cost alone for type-2 external routes; the `metric2` field
//!   that holds the type-2 external metric — the E-bit-set LSA
//!   metric, §16.4 (6)).
//! - RFC 5340 §4.1 — OSPFv3 route preference (mirrors OSPFv2).
//! - RFC 5340 §4.8.5 — OSPFv3 external route calculation (mirrors
//!   §16.4).
//! - BIRD 2 `proto/ospf/ospf.c` — `ea_ospf_metric1` and
//!   `ea_ospf_metric2` are the eattrs these accessors surface.

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
}
