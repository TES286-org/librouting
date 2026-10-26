//! Match + set primitives.
//!
//! The `bgp` feature (default) gates the four BGP-specific
//! [`SetAction`] variants: [`SetAction::SetLocalPref`],
//! [`SetAction::SetMed`], [`SetAction::PrependAs`] and
//! [`SetAction::AddCommunity`]. Without the feature, the typed BGP
//! path-attribute decoder is unavailable, so the four variants cannot
//! mutate the route. Past releases silently dropped the action in
//! that case — an operator who configured `set local-preference`
//! against a no-`bgp` build saw the route pass through unchanged,
//! with no signal that the policy had been silently bypassed.
//!
//! The fail-closed contract is now exposed through
//! [`apply_set_checked`], which returns
//! [`ApplySetError::RequiresBgpFeature`] for the four BGP-specific
//! variants when the `bgp` feature is off. [`RouteMap::evaluate`]
//! (see `crate::route_map`) consumes the checked form and denies the
//! route on `Err` — matching the fail-closed tightening that landed
//! for `CommunityList` / `AsPathFilter`. The legacy [`apply_set`]
//! keeps its infallible signature for ABI-stable embedders and now
//! logs the dropped action through `tracing::warn!` so the silent
//! failure is at least observable in the daemon's log stream.

use core::fmt;
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

/// Failure modes for [`apply_set_checked`].
///
/// Each variant names the [`SetAction`] variant that triggered the
/// failure (its `&'static str` name) so the embedder can log a
/// precise diagnostic. `RequiresBgpFeature` is the fail-closed
/// surface for the four BGP-specific actions when the crate is
/// built without the `bgp` feature — see the module docs for the
/// rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplySetError {
    /// The action requires the `bgp` feature (RFC 4271 §5.1.5
    /// `LOCAL_PREF`, §5.1.4 `MULTI_EXIT_DISC`, §5.1.2 `AS_PATH`
    /// prepend, RFC 1997 community add) but the crate was built
    /// without it. The set was silently dropped in past releases —
    /// surfacing the failure lets the embedder reject the route (or
    /// log it) rather than silently apply a partial policy.
    RequiresBgpFeature(&'static str),
}

impl fmt::Display for ApplySetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplySetError::RequiresBgpFeature(name) => write!(
                f,
                "set action `{name}` requires the `bgp` feature, which is not enabled \
                 in this build of lr-policy; the route is denied (fail-closed)"
            ),
        }
    }
}

impl std::error::Error for ApplySetError {}

impl SetAction {
    /// `&'static str` name of the variant — used for diagnostics in
    /// [`ApplySetError`] and the `tracing::warn!` line emitted by
    /// [`apply_set`] when it drops an action.
    pub fn name(&self) -> &'static str {
        match self {
            SetAction::SetLocalPref(_) => "SetLocalPref",
            SetAction::SetMed(_) => "SetMed",
            SetAction::SetNextHop(_) => "SetNextHop",
            SetAction::PrependAs(_) => "PrependAs",
            SetAction::AddCommunity(_, _) => "AddCommunity",
            SetAction::SetMetric(_) => "SetMetric",
            SetAction::SetTag(_) => "SetTag",
        }
    }
}

/// Apply a [`SetAction`] to the route, returning `Err` for the
/// BGP-specific variants when the crate is built without `bgp`.
///
/// The infallible [`apply_set`] is a thin wrapper that drops the
/// `Err` (with a `tracing::warn!`); new embedders should prefer
/// this checked form so the failure surfaces explicitly.
pub fn apply_set_checked(action: &SetAction, route: &mut Route) -> Result<(), ApplySetError> {
    match action {
        // LOCAL_PREF is a BGP path attribute (RFC 4271 §5.1.5), not the
        // cross-protocol admin distance; the two must not be conflated.
        #[cfg(feature = "bgp")]
        SetAction::SetLocalPref(v) => crate::bgp::set_local_pref(route, *v),
        #[cfg(not(feature = "bgp"))]
        SetAction::SetLocalPref(_) => {
            return Err(ApplySetError::RequiresBgpFeature(action.name()));
        }
        #[cfg(feature = "bgp")]
        SetAction::SetMed(v) => crate::bgp::set_med(route, *v),
        #[cfg(not(feature = "bgp"))]
        SetAction::SetMed(_) => {
            return Err(ApplySetError::RequiresBgpFeature(action.name()));
        }
        SetAction::SetNextHop(ip) => route.next_hop = Some(*ip),
        #[cfg(feature = "bgp")]
        SetAction::PrependAs(asn) => crate::bgp::prepend_as(route, *asn),
        #[cfg(not(feature = "bgp"))]
        SetAction::PrependAs(_) => {
            return Err(ApplySetError::RequiresBgpFeature(action.name()));
        }
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
        SetAction::AddCommunity(_, _) => {
            return Err(ApplySetError::RequiresBgpFeature(action.name()));
        }
        SetAction::SetMetric(v) => route.preference.metric = *v,
        SetAction::SetTag(v) => route.tag = Some(*v),
    }
    Ok(())
}

/// Apply a [`SetAction`] to the route.
///
/// Infallible for ABI-stable embedders: BGP-specific actions that
/// cannot be applied without the `bgp` feature are dropped with a
/// `tracing::warn!` line so the silent failure is at least
/// observable in the daemon's log stream. New embedders should
/// prefer [`apply_set_checked`], which surfaces the failure as an
/// `Err` so the route can be denied (fail-closed) — see
/// [`RouteMap::evaluate`](crate::route_map::RouteMap::evaluate)
/// for the consumer that does exactly that.
pub fn apply_set(action: &SetAction, route: &mut Route) {
    if let Err(e) = apply_set_checked(action, route) {
        tracing::warn!("dropping set action: {e}");
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

    #[test]
    fn checked_set_tag_round_trips() {
        let mut r = empty_route();
        assert_eq!(r.tag, None);
        apply_set_checked(&SetAction::SetTag(7), &mut r).unwrap();
        assert_eq!(r.tag, Some(7));
    }

    #[test]
    fn checked_set_metric_round_trips() {
        let mut r = empty_route();
        apply_set_checked(&SetAction::SetMetric(31337), &mut r).unwrap();
        assert_eq!(r.preference.metric, 31337);
    }

    #[test]
    fn set_action_name_covers_every_variant() {
        // Pin the name() contract — every variant must produce a
        // non-empty `&'static str`. The fail-closed no-bg path
        // (below) and the `tracing::warn!` line in `apply_set`
        // rely on this string being non-empty for diagnostics.
        assert_eq!(SetAction::SetLocalPref(0).name(), "SetLocalPref");
        assert_eq!(SetAction::SetMed(0).name(), "SetMed");
        assert_eq!(
            SetAction::SetNextHop(lr_core::addr::IpAddr::V4([0; 4])).name(),
            "SetNextHop"
        );
        assert_eq!(
            SetAction::PrependAs(lr_core::addr::Asn(0)).name(),
            "PrependAs"
        );
        assert_eq!(
            SetAction::AddCommunity(lr_core::addr::Asn(0), 0).name(),
            "AddCommunity"
        );
        assert_eq!(SetAction::SetMetric(0).name(), "SetMetric");
        assert_eq!(SetAction::SetTag(0).name(), "SetTag");
    }
}

// ============================================================
// no-bgp fail-closed coverage
// ============================================================
//
// `lr-policy`'s default build turns `bgp` on; the fail-closed
// contract for `SetLocalPref` / `SetMed` / `PrependAs` /
// `AddCommunity` is only exercised when an embedder explicitly
// opts out of `bgp`. The crate's `--no-default-features --features
// std` build is currently blocked upstream of this module —
// `filter/eval.rs`'s default method bodies reference `crate::bgp::*`
// unconditionally — so a future follow-up that lands the no-bgp
// build will see these tests pin the fail-closed verdict. A
// regression that re-introduces the permissive silent-no-op stub
// flagged in defects.txt (issue #92) will fail here.
#[cfg(not(feature = "bgp"))]
#[cfg(test)]
mod no_bgp_tests {
    use super::*;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn any_route() -> Route {
        Route {
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
        }
    }

    #[test]
    fn set_local_pref_errors_when_bgp_decoder_absent() {
        let mut r = any_route();
        let err = apply_set_checked(&SetAction::SetLocalPref(100), &mut r).unwrap_err();
        assert_eq!(err, ApplySetError::RequiresBgpFeature("SetLocalPref"));
    }

    #[test]
    fn set_med_errors_when_bgp_decoder_absent() {
        let mut r = any_route();
        let err = apply_set_checked(&SetAction::SetMed(50), &mut r).unwrap_err();
        assert_eq!(err, ApplySetError::RequiresBgpFeature("SetMed"));
    }

    #[test]
    fn prepend_as_errors_when_bgp_decoder_absent() {
        let mut r = any_route();
        let err = apply_set_checked(&SetAction::PrependAs(lr_core::addr::Asn(65000)), &mut r)
            .unwrap_err();
        assert_eq!(err, ApplySetError::RequiresBgpFeature("PrependAs"));
    }

    #[test]
    fn add_community_errors_when_bgp_decoder_absent() {
        let mut r = any_route();
        let err = apply_set_checked(
            &SetAction::AddCommunity(lr_core::addr::Asn(65000), 1),
            &mut r,
        )
        .unwrap_err();
        assert_eq!(err, ApplySetError::RequiresBgpFeature("AddCommunity"));
    }

    #[test]
    fn set_metric_and_tag_still_apply_without_bgp() {
        // Cross-protocol actions are not gated by the `bgp` feature
        // and must keep working — fail-closed applies only to the
        // four BGP-specific variants.
        let mut r = any_route();
        apply_set_checked(&SetAction::SetMetric(99), &mut r).unwrap();
        apply_set_checked(&SetAction::SetTag(7), &mut r).unwrap();
        assert_eq!(r.preference.metric, 99);
        assert_eq!(r.tag, Some(7));
    }

    #[test]
    fn set_next_hop_still_applies_without_bgp() {
        let mut r = any_route();
        apply_set_checked(
            &SetAction::SetNextHop(lr_core::addr::IpAddr::V4([10, 0, 0, 1])),
            &mut r,
        )
        .unwrap();
        assert_eq!(r.next_hop, Some(lr_core::addr::IpAddr::V4([10, 0, 0, 1])));
    }
}
