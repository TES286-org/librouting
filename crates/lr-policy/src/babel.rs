//! Typed Babel route-attribute access for policy evaluation.
//!
//! Mirrors [`crate::bgp`] and [`crate::ospf`] for the per-protocol
//! route attributes BIRD's filter language exposes under the
//! `babel_*` prefix. The lr [`Route`](lr_core::rib::Route) data model
//! carries the Babel metric in [`Route::preference`]`.metric` (the
//! same field every protocol feeds into the cross-protocol
//! admin-distance sort), so the `metric` accessor reads by protocol
//! kind — not by tag — and returns `None` for non-Babel routes.
//! That mirrors BIRD's eattr semantics: a `babel_metric` reference
//! on a non-Babel route reads as the attribute's default (zero),
//! and `defined(babel_metric)` is false because the Babel protocol
//! never attached the attribute.
//!
//! The Babel seqno and Router-ID ride private path-attribute tags —
//! `LrBabelSeqno` (code point 249) and `LrBabelRouterId` (250) —
//! the Babel route computation attaches to every Babel route the
//! router's Babel runtime publishes. The codec strips both at BGP
//! encode so peers never see them; only the Babel runtime
//! (the only producer) populates the attributes, and only for Babel
//! routes. The accessors here read the tags via one BTreeMap
//! lookup plus one fixed-width read — no allocation, no codec
//! dependency.
//!
//! RFC references:
//! - RFC 8966 §3.2 — the route's `(prefix, source-prefix, router-id,
//!   seqno)` four-tuple key, the metric and feasibility that the
//!   decision process ranks against, and the route table's role
//!   in the Babel route selection.
//! - RFC 8966 §3.4.3 — the metric the route's Update TLV advertised
//!   (the value the Babel route computation surfaces through
//!   [`Route::preference`]`.metric`; the field the decision process
//!   ranks against — the same shape OSPF's metric1 surfaces).
//! - RFC 8966 §4.6.8 — the Router-Id TLV (8 bytes, an EUI-64-style
//!   value the route's source claims; carried in every Update TLV
//!   so the receiver pairs the route with its source).
//! - RFC 8966 §4.6.9 — the Update TLV's `Seqno` field (16-bit
//!   unsigned, the source's sequence number the feasibility
//!   machinery ranks against).
//! - BIRD 2 `proto/babel/babel.c` — `ea_babel_metric`,
//!   `ea_babel_router_id` and `ea_babel_seqno` are the eattrs
//!   these accessors surface.

use lr_core::attr::AttrTag;
use lr_core::rib::{Protocol, Route};

/// The path-attribute tag carrying the Babel seqno (RFC 8966 §3.2 +
/// §4.6.9 — the 16-bit unsigned sequence number carried in every
/// Update TLV). Mirrors `lr_bgp::path::AttrType::LrBabelSeqno`
/// (value 249); kept as a `u8` here so the accessor stays
/// unconditional — no `lr-bgp` dependency. The BGP codec strips the
/// tag at encode so peers never see it; only the Babel route
/// computation (`lr-router::instance::babel::BabelRuntime`)
/// populates the attribute, for every Babel route the runtime
/// publishes.
///
/// The value layout is a single 4-byte big-endian `u32` holding the
/// 16-bit Babel seqno (zero-extended — RFC 8966 §4.6.9 caps the
/// seqno at 16 bits, so the high two bytes are always zero on a
/// well-formed value).
const LR_BABEL_SEQNO_TAG: u8 = 249;

/// The path-attribute tag carrying the Babel Router-ID (RFC 8966
/// §3.2 + §4.6.8 — the 64-bit EUI-64-style Router-ID carried in
/// every Update TLV's Router-Id TLV). Mirrors
/// `lr_bgp::path::AttrType::LrBabelRouterId` (value 250); kept as a
/// `u8` here so the accessor stays unconditional — no `lr-bgp`
/// dependency. The BGP codec strips the tag at encode so peers
/// never see it; only the Babel route computation
/// (`lr-router::instance::babel::BabelRuntime`) populates the
/// attribute, for every Babel route the runtime publishes.
///
/// The value layout is 8 bytes, big-endian, holding the 64-bit
/// Babel Router-ID. RFC 8966 §4.6.8 specifies the 64-bit value —
/// no masking needed. The DSL exposes it as an `Int` (i64); a
/// value with the high bit set (>= `0x8000_0000_0000_0000`) reads
/// as a negative i64 but round-trips through `as i64` / `as u64`
/// losslessly for the comparison operator.
const LR_BABEL_ROUTER_ID_TAG: u8 = 250;

/// The route's Babel metric (RFC 8966 §3.2 + §3.4.3 — the value the
/// Update TLV advertised, folded into [`Route::preference`]`.metric`
/// by the Babel route computation after applying the receiver-side
/// link cost). This is the field the Babel decision process ranks
/// against (lowest-metric feasible route wins per RFC 8966 §3.5.1).
///
/// Returns `Some(metric)` for Babel routes (the metric the Babel
/// route computation placed in [`Route::preference`]`.metric`) and
/// `None` for non-Babel routes — mirroring BIRD's eattr semantics,
/// where a `babel_metric` reference on a non-Babel route has no
/// attached attribute. A present metric of `0` ("cost zero") is
/// returned as `Some(0)` — use [`has_metric`] to distinguish "non-Babel
/// route" from "Babel route with metric 0" in policies that need
/// the distinction (the `defined(babel.metric)` filter DSL
/// predicate consults `has_metric`, not this accessor).
///
/// Reads pay one `match` on [`Route::protocol`] plus one field
/// read — no allocation, no codec, no BTreeMap lookup. Cheaper than
/// any `bgp_*` accessor that decodes a path attribute. The same
/// shape as [`crate::ospf::metric1`].
pub fn metric(route: &Route) -> Option<u32> {
    match route.protocol {
        Protocol::Babel => Some(route.preference.metric),
        _ => None,
    }
}

/// True when the route is a Babel route (RFC 8966 §3.2) and therefore
/// carries a primary Babel metric. Use this to distinguish "non-Babel
/// route" from "Babel route with metric 0" — [`metric`] returns
/// `Some(0)` for the latter.
///
/// The filter DSL's `defined(babel.metric)` predicate consults this
/// helper, not `metric().is_some()`: the two agree on the Babel
/// case (both true), but the distinction matters when a downstream
/// caller adds a "metric zero is meaningful" semantic — `has_metric`
/// keeps "Babel route with metric 0" defined, the same shape
/// [`crate::ospf::has_metric1`] exposes for the OSPF primary-metric
/// presence probe.
pub fn has_metric(route: &Route) -> bool {
    matches!(route.protocol, Protocol::Babel)
}

/// The route's Babel seqno (RFC 8966 §3.2 + §4.6.9 — the 16-bit
/// unsigned sequence number carried in every Update TLV, the
/// source's sequence number the feasibility machinery ranks
/// against per RFC 8966 §3.4.2). Zero for non-Babel routes — the
/// Babel route computation only attaches the
/// [`LrBabelSeqno`](lr_bgp::path::AttrType::LrBabelSeqno) attribute
/// for Babel routes, so its absence reads as `0` (BIRD's eattr
/// default for an unattached `babel_seqno` reference).
///
/// Returns `Some(seqno)` for Babel routes (the attribute is
/// present) and `None` for everything else — non-Babel routes.
/// A present seqno of `0` is returned as `Some(0)` — use
/// [`has_seqno`] to distinguish "non-Babel route" from "Babel
/// route with seqno 0" in policies that need the distinction
/// (the `defined(babel.seqno)` filter DSL predicate consults
/// `has_seqno`, not this accessor).
///
/// Reads pay one BTreeMap lookup plus one 4-byte read on
/// [`Route::attributes`] — no allocation, no codec (the value
/// layout is a fixed 4-byte big-endian `u32` holding the 16-bit
/// seqno zero-extended). Cheaper than any `bgp_*` accessor that
/// decodes a multi-byte TLV stream, but more expensive than
/// [`metric`] (which reads a struct field, no lookup). The same
/// shape as [`crate::ospf::metric2`] (which reads a different
/// private tag).
pub fn seqno(route: &Route) -> Option<u16> {
    // Only Babel routes can carry the LrBabelSeqno attribute — the
    // Babel route computation (`lr-router::instance::babel`) is
    // the only producer. The protocol check is a cheap fast-path
    // rejection for non-Babel routes that avoids the BTreeMap
    // lookup entirely.
    if !matches!(route.protocol, Protocol::Babel) {
        return None;
    }
    let raw = route
        .attributes
        .get_u32_be(AttrTag::raw(LR_BABEL_SEQNO_TAG))?;
    Some(raw as u16)
}

/// True when the route is a Babel route (RFC 8966 §3.2) and
/// therefore carries a Babel seqno attribute. Use this to
/// distinguish "non-Babel route" from "Babel route with seqno 0"
/// — [`seqno`] returns `Some(0)` for the latter (a Babel source
/// may legally carry seqno 0 — the wrapping arithmetic in RFC
/// 8966 §3.1 treats 0 as a valid sequence number, and the
/// feasibility machinery's comparison ranks
/// against it the same as any other value).
///
/// The filter DSL's `defined(babel.seqno)` predicate consults
/// this helper, not `seqno().is_some()`: the two agree on the
/// Babel case (both true), but the distinction matters when a
/// downstream caller adds a "seqno zero is meaningful" semantic
/// — `has_seqno` keeps "Babel route with seqno 0" defined, the
/// same shape [`crate::ospf::has_metric2`] exposes for the OSPF
/// type-2-external metric presence probe. For non-Babel routes,
/// `has_seqno` is false (the protocol-kind fast path rejects
/// them, mirroring BIRD's eattr absence on non-Babel routes).
pub fn has_seqno(route: &Route) -> bool {
    if !matches!(route.protocol, Protocol::Babel) {
        return false;
    }
    route
        .attributes
        .get(AttrTag::raw(LR_BABEL_SEQNO_TAG))
        .is_some()
}

/// The route's Babel Router-ID (RFC 8966 §3.2 + §4.6.8 — the
/// 64-bit EUI-64-style Router-ID carried in every Update TLV's
/// Router-Id TLV, identifying the router that originated the
/// route's source). Returns `None` for non-Babel routes (the
/// Babel route computation is the only producer of the
/// `LrBabelRouterId` attribute). `Some(0)` is a meaningful value
/// — a Babel source may legally carry Router-ID 0 — use
/// [`has_router_id`] to distinguish "no attribute" from
/// "attribute present but zero" in policies that need the
/// distinction (the `defined(babel.router_id)` filter DSL
/// predicate consults `has_router_id`, not this accessor).
///
/// Reads pay one BTreeMap lookup plus one 8-byte read on
/// [`Route::attributes`] — no allocation, no codec (the value
/// layout is a fixed 8-byte big-endian `u64`). Cheaper than any
/// `bgp_*` accessor that decodes a multi-byte TLV stream, the
/// same shape as [`seqno`] (which reads a 4-byte tag) and more
/// expensive than [`metric`] (which reads a struct field, no
/// lookup). The DSL exposes the 64-bit value as an `Int` (i64);
/// a value with the high bit set reads as a negative i64 but
/// round-trips losslessly for the comparison operator (the lexer
/// parses i64 literals). The BGP codec strips the tag at encode
/// so peers never see it.
pub fn router_id(route: &Route) -> Option<u64> {
    // Only Babel routes can carry the LrBabelRouterId attribute —
    // the Babel route computation (`lr-router::instance::babel`)
    // is the only producer. The protocol check is a cheap
    // fast-path rejection for non-Babel routes that avoids the
    // BTreeMap lookup entirely.
    if !matches!(route.protocol, Protocol::Babel) {
        return None;
    }
    route
        .attributes
        .get_u64_be(AttrTag::raw(LR_BABEL_ROUTER_ID_TAG))
}

/// True when the route is a Babel route (RFC 8966 §3.2) with a
/// known source Router-ID and therefore carries a Babel
/// router-id attribute. Use this to distinguish "no attribute"
/// (a non-Babel route) from "attribute present but zero" (a
/// Babel route whose source claims Router-ID 0) —
/// [`router_id`] returns `Some(0)` for the latter (a Babel
/// source may legally carry Router-ID 0; the EUI-64 form
/// discourages it but RFC 8966 §3.1 does not forbid it).
///
/// The filter DSL's `defined(babel.router_id)` predicate
/// consults this helper, not `router_id().is_some()`: the two
/// agree on the present-with-non-zero case (both true), but the
/// distinction matters when a source carries Router-ID 0 —
/// `has_router_id` keeps "Babel route with Router-ID 0" defined
/// so the canonical idiom `if defined(babel.router_id) &&
/// babel.router_id == 0 then accept;` does not drop such a
/// route. For non-Babel routes, `has_router_id` is false (the
/// protocol-kind fast path rejects them, mirroring BIRD's
/// eattr absence on non-Babel routes).
pub fn has_router_id(route: &Route) -> bool {
    if !matches!(route.protocol, Protocol::Babel) {
        return false;
    }
    route
        .attributes
        .get(AttrTag::raw(LR_BABEL_ROUTER_ID_TAG))
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

    fn babel_route_with_seqno(protocol: Protocol, metric: u32, seqno: u16) -> Route {
        let mut r = route(protocol, metric);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(LR_BABEL_SEQNO_TAG),
            flags: 0x80,
            value: (u32::from(seqno)).to_be_bytes().to_vec(),
        });
        r
    }

    fn babel_route_with_router_id(protocol: Protocol, metric: u32, router_id: u64) -> Route {
        let mut r = route(protocol, metric);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(LR_BABEL_ROUTER_ID_TAG),
            flags: 0x80,
            value: router_id.to_be_bytes().to_vec(),
        });
        r
    }

    #[test]
    fn metric_reads_for_babel_routes() {
        let r = route(Protocol::Babel, 192);
        assert_eq!(metric(&r), Some(192));
        assert!(has_metric(&r));
    }

    #[test]
    fn metric_is_none_for_non_babel_routes() {
        for proto in [
            Protocol::Bgp,
            Protocol::Ospfv2,
            Protocol::Ospfv3,
            Protocol::Static,
            Protocol::Connected,
        ] {
            assert_eq!(metric(&route(proto, 100)), None);
            assert!(!has_metric(&route(proto, 100)));
        }
    }

    #[test]
    fn metric_zero_is_present_for_babel() {
        let r = route(Protocol::Babel, 0);
        assert_eq!(metric(&r), Some(0));
        assert!(has_metric(&r), "Babel route with metric 0 is defined");
    }

    #[test]
    fn seqno_reads_for_babel_routes_with_the_attribute() {
        let r = babel_route_with_seqno(Protocol::Babel, 192, 7);
        assert_eq!(seqno(&r), Some(7));
        assert!(has_seqno(&r));
    }

    #[test]
    fn seqno_is_none_for_babel_routes_without_the_attribute() {
        let r = route(Protocol::Babel, 192);
        assert_eq!(seqno(&r), None);
        assert!(!has_seqno(&r));
    }

    #[test]
    fn seqno_is_none_for_non_babel_routes_even_with_the_attribute() {
        let r = babel_route_with_seqno(Protocol::Bgp, 100, 7);
        assert_eq!(seqno(&r), None);
        assert!(!has_seqno(&r));
    }

    #[test]
    fn seqno_zero_is_present_for_babel() {
        let r = babel_route_with_seqno(Protocol::Babel, 192, 0);
        assert_eq!(seqno(&r), Some(0));
        assert!(has_seqno(&r), "Babel route with seqno 0 is defined");
    }

    #[test]
    fn seqno_wraps_to_u16_truncating_reserved_high_bytes() {
        let mut r = route(Protocol::Babel, 192);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(LR_BABEL_SEQNO_TAG),
            flags: 0x80,
            value: 0xffff_0007u32.to_be_bytes().to_vec(),
        });
        assert_eq!(seqno(&r), Some(7));
    }

    #[test]
    fn seqno_malformed_value_is_absent() {
        let mut r = route(Protocol::Babel, 192);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(LR_BABEL_SEQNO_TAG),
            flags: 0x80,
            value: vec![0x00, 0x07],
        });
        assert_eq!(seqno(&r), None);
        assert!(
            has_seqno(&r),
            "physical presence is true even when malformed"
        );
    }

    #[test]
    fn router_id_reads_for_babel_routes_with_the_attribute() {
        let r = babel_route_with_router_id(Protocol::Babel, 192, 0x0102_0304_0506_0708);
        assert_eq!(router_id(&r), Some(0x0102_0304_0506_0708));
        assert!(has_router_id(&r));
    }

    #[test]
    fn router_id_is_none_for_babel_routes_without_the_attribute() {
        let r = route(Protocol::Babel, 192);
        assert_eq!(router_id(&r), None);
        assert!(!has_router_id(&r));
    }

    #[test]
    fn router_id_is_none_for_non_babel_routes_even_with_the_attribute() {
        let r = babel_route_with_router_id(Protocol::Bgp, 100, 0x0102_0304_0506_0708);
        assert_eq!(router_id(&r), None);
        assert!(!has_router_id(&r));
    }

    #[test]
    fn router_id_zero_is_present_for_babel() {
        let r = babel_route_with_router_id(Protocol::Babel, 192, 0);
        assert_eq!(router_id(&r), Some(0));
        assert!(has_router_id(&r), "Babel route with Router-ID 0 is defined");
    }

    #[test]
    fn router_id_high_bit_set_round_trips_through_i64() {
        let r = babel_route_with_router_id(Protocol::Babel, 192, 0xffff_ffff_ffff_ffff);
        assert_eq!(router_id(&r), Some(0xffff_ffff_ffff_ffff));
    }

    #[test]
    fn router_id_malformed_value_is_absent() {
        let mut r = route(Protocol::Babel, 192);
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(LR_BABEL_ROUTER_ID_TAG),
            flags: 0x80,
            value: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        });
        assert_eq!(router_id(&r), None);
        assert!(
            has_router_id(&r),
            "physical presence is true even when malformed"
        );
    }

    #[test]
    fn babel_fields_independent_of_each_other() {
        let r = babel_route_with_seqno(Protocol::Babel, 192, 7);
        assert_eq!(router_id(&r), None);
        assert!(!has_router_id(&r));
        assert_eq!(metric(&r), Some(192));
        assert_eq!(seqno(&r), Some(7));

        let r2 = babel_route_with_router_id(Protocol::Babel, 192, 0x0102_0304_0506_0708);
        assert_eq!(seqno(&r2), None);
        assert!(!has_seqno(&r2));
        assert_eq!(metric(&r2), Some(192));
        assert_eq!(router_id(&r2), Some(0x0102_0304_0506_0708));
    }

    #[test]
    fn babel_fields_isolated_from_ospf_fields() {
        let r = babel_route_with_seqno(Protocol::Babel, 192, 7);
        assert_eq!(crate::ospf::metric1(&r), None);
        assert!(!crate::ospf::has_metric1(&r));
        assert_eq!(crate::ospf::metric2(&r), None);
        assert!(!crate::ospf::has_metric2(&r));
        assert_eq!(crate::ospf::tag(&r), None);
        assert!(!crate::ospf::has_tag(&r));
        assert_eq!(crate::ospf::router_id(&r), None);
        assert!(!crate::ospf::has_router_id(&r));
        assert_eq!(metric(&r), Some(192));
        assert_eq!(seqno(&r), Some(7));
        assert!(has_metric(&r));
        assert!(has_seqno(&r));
    }
}
