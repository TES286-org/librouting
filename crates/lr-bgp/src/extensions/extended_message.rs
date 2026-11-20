//! RFC 8654 BGP Extended Message orchestration helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::extended_message`] (code 6,
//! empty value). This module computes what a session should
//! advertise and what it may consume after the OPEN exchange:
//!
//! - [`advertised`] — whether the local config opts the session into
//!   the capability.
//! - [`peer_offered`] — whether the peer advertised the capability.
//! - [`negotiated`] — whether both speakers advertised it, so the
//!   codec may use the 65535-octet message ceiling (RFC 8654 §3).
//!
//! # Negotiation posture
//!
//! RFC 8654 §3: a speaker that does not advertise the capability
//! must continue to send and accept messages up to the RFC 4271
//! §4.1 4096-octet limit. The codec's per-session message length
//! ceiling gates on [`negotiated`] — both speakers must advertise
//! for the larger ceiling to apply, so a non-conforming peer never
//! receives a message it cannot parse.

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;

/// Whether the local config opts this session into the RFC 8654
/// capability. The FSM gates the OPEN advertisement on this; the
/// helper centralises the check so a caller can test the posture
/// without constructing a peer (mirrors
/// [`crate::extensions::enhanced_rr::advertised`]).
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.extended_message
}

/// Whether the peer advertised the RFC 8654 capability in its OPEN.
/// The value field is ignored on reception — RFC 8654 §3 defines the
/// capability with `Capability Length 0`; a peer that ships bytes
/// anyway is in violation but not harmful (mirrors FRR's
/// `bgp_capability_ext_message` which only checks the code).
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .any(|c| c.code == CapabilityCode::ExtendedMessage)
}

/// Whether *both* speakers advertised the RFC 8654 capability, so
/// the codec may use the 65535-octet message ceiling (RFC 8654 §3).
/// `cfg.extended_message` is the local policy; `peer_offered` is the
/// peer's posture read from its OPEN.
pub fn negotiated(cfg: &PeerConfig, peer_caps: &[Capability]) -> bool {
    advertised(cfg) && peer_offered(peer_caps)
}

/// Build the RFC 8654 capability for a configured peer's OPEN.
/// Returns `None` when the local config has the knob off. Mirrors
/// [`crate::extensions::enhanced_rr::open_capability`] in shape so
/// the FSM's OPEN builder can call them uniformly.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    if advertised(cfg) {
        Some(Capability::extended_message())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(extended_message: bool) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.extended_message = extended_message;
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
        assert_eq!(cap.code, CapabilityCode::ExtendedMessage);
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
    fn negotiated_requires_local_knob() {
        let peer_caps = vec![open_capability(&cfg(true)).unwrap()];
        assert!(!negotiated(&cfg(false), &peer_caps));
    }

    #[test]
    fn negotiated_requires_peer_cap() {
        assert!(!negotiated(&cfg(true), &[]));
    }

    #[test]
    fn negotiated_when_both_sides_advertise() {
        let peer_caps = vec![open_capability(&cfg(true)).unwrap()];
        assert!(negotiated(&cfg(true), &peer_caps));
    }
}
