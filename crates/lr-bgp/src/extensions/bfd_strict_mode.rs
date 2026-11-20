//! BFD Strict-Mode capability
//! (draft-ietf-idr-bgp-bfd-strict-mode-13) orchestration helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::bfd_strict_mode`] (code 74,
//! empty value). This module computes what a session should
//! advertise and what the daemon may consume after the OPEN
//! exchange:
//!
//! - [`advertised`] — whether the local config opts the session
//!   into the capability.
//! - [`peer_offered`] — whether the peer advertised the capability.
//! - [`negotiated`] — whether both speakers advertised it, so the
//!   daemon's BFD supervisor gates session establishment on BFD Up
//!   (the draft's strict-mode behaviour: no hold-timer fallback).
//!
//! # Negotiation posture
//!
//! The draft requires both speakers to advertise the capability
//! for strict-mode to apply. A speaker that does not advertise it
//! keeps the hold-timer fallback: when BFD reports Down the
//! session tears down *and* the hold timer still bounds how long
//! the peer's routes stay in the Adj-RIB-In. With strict-mode
//! negotiated, the session establishment itself is gated on BFD
//! Up — the BGP FSM does not transition to Established until BFD
//! reports Up.

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;

/// Whether the local config opts this session into the BFD
/// Strict-Mode capability. The FSM gates the OPEN advertisement on
/// this; the helper centralises the check.
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.bfd_strict_mode
}

/// Whether the peer advertised the BFD Strict-Mode capability in
/// its OPEN. The value is ignored on reception per the draft.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .any(|c| c.code == CapabilityCode::BfdStrictMode)
}

/// Whether *both* speakers advertised the BFD Strict-Mode
/// capability, so the daemon gates session establishment on BFD
/// Up (the draft's strict-mode behaviour).
pub fn negotiated(cfg: &PeerConfig, peer_caps: &[Capability]) -> bool {
    advertised(cfg) && peer_offered(peer_caps)
}

/// Build the BFD Strict-Mode capability for a configured peer's
/// OPEN. Returns `None` when the local config has the knob off.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    if advertised(cfg) {
        Some(Capability::bfd_strict_mode())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(bfd_strict_mode: bool) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.bfd_strict_mode = bfd_strict_mode;
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
        assert_eq!(cap.code, CapabilityCode::BfdStrictMode);
        assert!(cap.value.is_empty());
    }

    #[test]
    fn peer_offered_when_capability_present() {
        let cap = open_capability(&cfg(true)).unwrap();
        assert!(peer_offered(&[cap]));
    }

    #[test]
    fn peer_not_offered_when_capability_absent() {
        assert!(!peer_offered(&[]));
    }

    #[test]
    fn negotiated_requires_both_sides() {
        let cap = open_capability(&cfg(true)).unwrap();
        assert!(!negotiated(&cfg(false), std::slice::from_ref(&cap)));
        assert!(!negotiated(&cfg(true), &[]));
        assert!(negotiated(&cfg(true), &[cap]));
    }
}
