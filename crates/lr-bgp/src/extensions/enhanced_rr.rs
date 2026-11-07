//! RFC 7313 Enhanced Route Refresh orchestration helpers.
//!
//! The wire-level pieces live elsewhere: capability encoding in
//! [`crate::capabilities::Capability::enhanced_rr`], message subtypes in
//! [`crate::message::RouteRefreshSubtype`], and the FSM's send-side
//! methods ([`crate::fsm::BgpPeer::begin_enhanced_route_refresh`] /
//! [`crate::fsm::BgpPeer::end_enhanced_route_refresh`]) in
//! [`crate::fsm`]. This module computes what a session should advertise
//! and what it may consume after the OPEN exchange:
//!
//! - [`advertised`] — whether the local config opts the session into
//!   the capability. The FSM gates the wire on this; the helper
//!   centralises the check so a caller can test the posture without
//!   constructing a peer.
//! - [`negotiated`] — whether both speakers advertised the capability,
//!   so the BoRR/EoRR demarcation subtypes are safe to send and to
//!   interpret on receive. Mirrors
//!   [`BgpPeer::enhanced_route_refresh_negotiated`] but takes the
//!   inputs the caller already has, so an embedder that builds the
//!   OPEN capabilities with [`open_capability`] can verify the
//!   negotiation without a peer instance.
//! - [`open_capability`] — the capability to put in the OPEN, or
//!   `None` when the knob is off. Mirrors
//!   [`crate::extensions::long_lived::open_capability`] in shape so
//!   the FSM's OPEN builder can call them uniformly.
//!
//! # Receive-side handling
//!
//! RFC 7313 §3.2 mandates that a receiver silently ignore unknown
//! subtypes. The three known subtypes are:
//!
//! - `Normal` (0) — RFC 2918 route-refresh request. The FSM surfaces
//!   this as [`crate::fsm::BgpAction::RouteRefreshRequested`] so the
//!   embedder re-announces the requested family.
//! - `BeginOfRib` (1) — BoRR. The peer is about to start sending the
//!   refreshed table. The FSM surfaces this as
//!   [`crate::fsm::BgpAction::BeginOfRouteRefresh`] so the embedder
//!   can pre-mark the session's routes as "expected to be replaced"
//!   (the helper that consumes the marker can correlate the BoRR
//!   with the matching EoRR and purge routes the peer did not
//!   refresh).
//! - `EndOfRib` (2) — EoRR. The peer finished sending the refreshed
//!   table. RFC 7313 §3.3 says the EoRR is treated as the End-of-RIB
//!   marker (RFC 4724 §4) for the family, so the FSM surfaces it as
//!   the existing [`crate::fsm::BgpAction::EndOfRib`] — the helper
//!   that consumes that action (the router's `on_end_of_rib`) runs
//!   the same stale-route purge it runs for the implicit EoR marker.
//!
//! Before the issue #92 fix, the FSM receive arm dispatched only the
//! `Normal` subtype; a peer that sent a BoRR or EoRR had its message
//! silently discarded, so an embedder relying on the demarcation to
//! coordinate a route-refresh response (BIRD `route refresh` /
//! `enhanced route refresh`, FRR `bgp route-refresh` with the
//! `enhanced` knob) saw the markers vanish at the wire boundary.

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;

/// Whether the local config opts this session into the RFC 7313
/// capability. The FSM gates the OPEN advertisement on this; the
/// helper centralises the check so a caller can test the posture
/// without constructing a peer.
///
/// RFC 7313 §2: the capability is advertised by sending a
/// `CapabilityCode` 70 (Enhanced Route Refresh) capability with an
/// empty value. There is no per-family negotiation: the capability
/// applies to every address family the session speaks.
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.enhanced_rr
}

/// Whether both speakers advertised the RFC 7313 capability, so the
/// BoRR/EoRR demarcation subtypes are safe to send and to interpret.
///
/// RFC 7313 §3.1: a speaker that did not advertise the capability
/// must not send BoRR/EoRR (the receiver treats them as unknown
/// subtypes and silently ignores per §3.2). RFC 2918 §2 (the base
/// route-refresh capability) is also required — RFC 7313 §1:
/// "Enhanced Route Refresh is an extension of the BGP Route Refresh
/// message defined in [RFC2918]"; without the base capability the
/// peer cannot send a route-refresh at all.
///
/// `peer_caps` is the peer's advertised capabilities (the
/// [`crate::fsm::BgpPeer::peer_capabilities`] slice). A capability
/// with a non-empty value is malformed (RFC 7313 §2 mandates an
/// empty value); the negotiation rejects it so a malformed OPEN
/// does not turn the demarcation on.
pub fn negotiated(cfg: &PeerConfig, peer_caps: &[Capability]) -> bool {
    cfg.route_refresh
        && cfg.enhanced_rr
        && peer_caps
            .iter()
            .any(|cap| cap.code == CapabilityCode::EnhancedRouteRefresh && cap.value.is_empty())
}

/// Build the RFC 7313 capability for a configured peer's OPEN.
/// Returns `None` when the local config has the knob off — the OPEN
/// does not advertise the capability, and the receiver must not send
/// demarcation messages back (RFC 7313 §3.1).
///
/// Mirrors
/// [`crate::extensions::long_lived::open_capability`] in shape so
/// the FSM's OPEN builder can call them uniformly.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    if cfg.enhanced_rr {
        Some(Capability::enhanced_rr())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(enhanced_rr: bool) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.enhanced_rr = enhanced_rr;
        c
    }

    #[test]
    fn advertised_tracks_knob() {
        assert!(!advertised(&cfg(false)));
        assert!(advertised(&cfg(true)));
    }

    #[test]
    fn open_capability_off_when_knob_off() {
        assert!(open_capability(&cfg(false)).is_none());
    }

    #[test]
    fn open_capability_on_when_knob_on() {
        let cap = open_capability(&cfg(true)).unwrap();
        assert_eq!(cap.code, CapabilityCode::EnhancedRouteRefresh);
        assert!(cap.value.is_empty());
    }

    #[test]
    fn negotiated_requires_local_knob_and_peer_cap() {
        // No local knob → not negotiated even if the peer advertised.
        let peer_caps = vec![Capability::enhanced_rr()];
        assert!(!negotiated(&cfg(false), &peer_caps));
    }

    #[test]
    fn negotiated_requires_peer_cap() {
        // Local knob on, but peer did not advertise → not negotiated.
        assert!(!negotiated(&cfg(true), &[]));
    }

    #[test]
    fn negotiated_when_both_sides_advertise() {
        let peer_caps = vec![Capability::enhanced_rr()];
        assert!(negotiated(&cfg(true), &peer_caps));
    }

    #[test]
    fn negotiated_rejects_malformed_capability() {
        // RFC 7313 §2 mandates an empty value; a non-empty value is
        // malformed and must not turn the demarcation on.
        let mut cap = Capability::enhanced_rr();
        cap.value = vec![0u8];
        assert!(!negotiated(&cfg(true), &[cap]));
    }

    #[test]
    fn negotiated_requires_base_route_refresh_too() {
        // RFC 7313 §1: enhanced refresh extends RFC 2918 — without
        // the base capability the peer cannot send a route-refresh at
        // all, so the demarcation has nothing to ride on.
        let mut c = cfg(true);
        c.route_refresh = false;
        let peer_caps = vec![Capability::enhanced_rr()];
        assert!(!negotiated(&c, &peer_caps));
    }
}
