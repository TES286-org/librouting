//! Typed OSPF route-attribute access for policy evaluation.
//!
//! Mirrors [`crate::bgp`] for the per-protocol route attributes BIRD's
//! filter language exposes under the `ospf_*` prefix. The lr
//! [`Route`](lr_core::rib::Route) data model carries the OSPF metric
//! in [`Route::preference`]` .metric` (the same field every protocol
//! feeds into the cross-protocol admin-distance sort), so the
//! accessors here read by protocol kind — not by tag — and return
//! `None` for non-OSPF routes. That mirrors BIRD's eattr semantics: an
//! `ospf_metric1` reference on a non-OSPF route reads as the
//! attribute's default (zero), and `defined(ospf_metric1)` is false
//! because the OSPF protocol never attached the attribute.
//!
//! The lr surface is `ospf.metric1`, `ospf.metric2`, `ospf.tag`,
//! `ospf.router_id` over time; this module opens with `metric1` only.
//! Each accessor is one branch on [`Route::protocol`] plus a field
//! read — no allocation, no codec.
//!
//! RFC references:
//! - RFC 2328 §16 — OSPFv2 route preference order and metric
//!   semantics (the `metric1` field the decision process ranks
//!   against for intra-area, inter-area and type-1 external routes;
//!   the cost alone for type-2 external routes).
//! - RFC 5340 §4.1 — OSPFv3 route preference (mirrors OSPFv2).
//! - BIRD 2 `proto/ospf/ospf.c` — `ea_ospf_metric1` is the
//!   eattr this accessor surfaces.

use lr_core::rib::{Protocol, Route};

/// The route's primary OSPF metric (RFC 2328 §16 / RFC 5340 §4.1) —
/// the SPF cost for intra-area and inter-area routes, the
/// cost-plus-external-metric for type-1 external routes, and the
/// cost alone for type-2 external routes. This is the field the OSPF
/// decision process ranks against.
///
/// Returns `Some(metric)` for OSPFv2 / OSPFv3 routes (the metric the
/// SPF computation placed in [`Route::preference`]` .metric`) and
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

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
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
}
