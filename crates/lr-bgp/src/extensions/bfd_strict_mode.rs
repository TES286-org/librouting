//! BFD Strict-Mode capability
//! (draft-ietf-idr-bgp-bfd-strict-mode-19) orchestration helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::bfd_strict_mode`] (code 74,
//! empty value). This module computes what a session should
//! advertise, what the peer offered, and how the FSM consumes the
//! BFD liveness events the embedder feeds:
//!
//! - [`advertised`] — whether the local config has both BFD and
//!   strict-mode enabled for the session (the draft's `BfdEnabled`
//!   and `BfdStrictEnabled` attributes; strict-mode has no effect
//!   without BFD).
//! - [`peer_offered`] — whether the peer advertised the capability.
//! - [`negotiated`] — whether both speakers advertised it, so the
//!   session establishment is gated on BFD Up (the draft's
//!   `BfdStrictNegotiated` attribute).
//! - [`BfdState`] — the BFD liveness the embedder reports to the
//!   FSM through [`crate::BgpEvent::Bfd`].
//!
//! # Negotiation posture
//!
//! The draft requires both speakers to advertise the capability
//! for strict-mode to apply. A speaker that does not advertise it
//! keeps the hold-timer fallback: when BFD reports Down the
//! session tears down *and* the hold timer still bounds how long
//! the peer's routes stay in the Adj-RIB-In. With strict-mode
//! negotiated, the session establishment itself is gated on BFD
//! Up — the BGP FSM does not send its KEEPALIVE or transition to
//! OpenConfirm until BFD reports Up (or AdminDown, which the draft
//! treats as an acceptable non-Down state for the gate).

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;

/// BFD session liveness as reported to the BGP FSM.
///
/// The draft's event set (draft-ietf-idr-bgp-bfd-strict-mode-19 §4)
/// also carries a `BfdStrict_ConfigChanged` event; configuration
/// changes are applied by starting a fresh session, so the FSM only
/// consumes the liveness states below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfdState {
    /// The BFD session is Up.
    Up,
    /// The BFD session is Down (including Init — not yet Up).
    Down,
    /// The BFD session is administratively down. The strict-mode gate
    /// treats AdminDown like Up (the draft's OpenSent/Connect/Active
    /// transitions advance on `BfdAdminDown`), while Established
    /// sessions ignore it.
    AdminDown,
    /// BFD was disabled for the session (`Bfd_Disabled`).
    Disabled,
}

impl BfdState {
    /// True when the state satisfies the strict-mode establishment
    /// gate: the draft advances on Up, AdminDown and Disabled, and
    /// holds on Down.
    pub fn satisfies_gate(self) -> bool {
        matches!(self, Self::Up | Self::AdminDown | Self::Disabled)
    }
}

/// Whether the local config opts this session into the BFD
/// Strict-Mode capability. Both BFD itself and the strict-mode knob
/// must be enabled: the draft's `BfdStrictEnabled` attribute has no
/// impact when `BfdEnabled` is false, so a strict-mode-only
/// configuration neither advertises the capability nor gates the
/// session.
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.bfd_strict_mode && cfg.bfd_enabled
}

/// Whether the peer advertised the BFD Strict-Mode capability in
/// its OPEN. The value is ignored on reception per the draft.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .any(|c| c.code == CapabilityCode::BfdStrictMode)
}

/// Whether *both* speakers advertised the BFD Strict-Mode
/// capability, so the FSM gates session establishment on BFD Up
/// (the draft's `BfdStrictNegotiated`).
pub fn negotiated(cfg: &PeerConfig, peer_caps: &[Capability]) -> bool {
    advertised(cfg) && peer_offered(peer_caps)
}

/// Build the BFD Strict-Mode capability for a configured peer's
/// OPEN. Returns `None` when BFD or the strict-mode knob is off.
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

    fn cfg(bfd_enabled: bool, bfd_strict_mode: bool) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.bfd_enabled = bfd_enabled;
        c.bfd_strict_mode = bfd_strict_mode;
        c
    }

    #[test]
    fn advertised_requires_both_knobs() {
        assert!(!advertised(&cfg(false, false)));
        assert!(!advertised(&cfg(false, true)));
        assert!(!advertised(&cfg(true, false)));
        assert!(advertised(&cfg(true, true)));
    }

    #[test]
    fn open_capability_off_when_knob_off() {
        assert!(open_capability(&cfg(true, false)).is_none());
        assert!(open_capability(&cfg(false, true)).is_none());
    }

    #[test]
    fn open_capability_on_when_knob_on() {
        let cap = open_capability(&cfg(true, true)).unwrap();
        assert_eq!(cap.code, CapabilityCode::BfdStrictMode);
        assert!(cap.value.is_empty());
    }

    #[test]
    fn peer_offered_when_capability_present() {
        let cap = open_capability(&cfg(true, true)).unwrap();
        assert!(peer_offered(&[cap]));
    }

    #[test]
    fn peer_not_offered_when_capability_absent() {
        assert!(!peer_offered(&[]));
    }

    #[test]
    fn negotiated_requires_both_sides() {
        let cap = open_capability(&cfg(true, true)).unwrap();
        assert!(!negotiated(&cfg(true, false), std::slice::from_ref(&cap)));
        assert!(!negotiated(&cfg(true, true), &[]));
        assert!(negotiated(&cfg(true, true), &[cap]));
    }

    #[test]
    fn gate_accepts_every_non_down_state() {
        assert!(BfdState::Up.satisfies_gate());
        assert!(BfdState::AdminDown.satisfies_gate());
        assert!(BfdState::Disabled.satisfies_gate());
        assert!(!BfdState::Down.satisfies_gate());
    }
}
