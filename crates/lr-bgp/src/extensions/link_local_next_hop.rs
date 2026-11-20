//! Link-Local Next Hop capability
//! (draft-white-linklocal-capability-04) orchestration helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::link_local_next_hop`] (code
//! 77, empty value). The module computes what a session should
//! advertise and what the codec may consume after the OPEN
//! exchange:
//!
//! - [`advertised`] — whether the local config opts the session
//!   into the capability.
//! - [`peer_offered`] — whether the peer advertised the capability.
//! - [`negotiated`] — whether both speakers advertised it, so the
//!   codec accepts a link-local IPv6 next-hop in MP_REACH_NLRI for
//!   IPv6 NLRI.
//!
//! # Negotiation posture
//!
//! The draft defines the capability with `Capability Length 0` —
//! presence alone signals that the speaker can accept a
//! link-local IPv6 next-hop. The actual next-hop data rides
//! MP_REACH_NLRI's Next Hop field with the length the draft
//! defines: 16 octets for a link-local-only next hop, 32 octets
//! for a link-local + global pair. The codec gates the larger
//! Next Hop field widths on [`negotiated`].

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;

/// Whether the local config opts this session into the Link-Local
/// Next Hop capability. The FSM gates the OPEN advertisement on
/// this.
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.link_local_next_hop
}

/// Whether the peer advertised the Link-Local Next Hop capability
/// in its OPEN. The value is ignored on reception per the draft.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .any(|c| c.code == CapabilityCode::LinkLocalNextHop)
}

/// Whether *both* speakers advertised the Link-Local Next Hop
/// capability, so the codec may accept a link-local IPv6 next-hop
/// in MP_REACH_NLRI for IPv6 NLRI (16- or 32-octet Next Hop field).
pub fn negotiated(cfg: &PeerConfig, peer_caps: &[Capability]) -> bool {
    advertised(cfg) && peer_offered(peer_caps)
}

/// Build the Link-Local Next Hop capability for a configured
/// peer's OPEN. Returns `None` when the local config has the knob
/// off.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    if advertised(cfg) {
        Some(Capability::link_local_next_hop())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(link_local_next_hop: bool) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.link_local_next_hop = link_local_next_hop;
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
        assert_eq!(cap.code, CapabilityCode::LinkLocalNextHop);
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
