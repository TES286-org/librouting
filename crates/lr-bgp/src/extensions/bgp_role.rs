//! RFC 9234 §3 BGP Role capability orchestration helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::bgp_role`] (code 9). The
//! existing OTC attribute path
//! ([`crate::role::otc`]) carries the
//! runtime valley-free propagation rules; this module advertises
//! the local role on the OPEN so the peer can do the same.
//!
//! # Negotiation posture
//!
//! RFC 9234 §3: both speakers MUST advertise the capability and the
//! roles MUST be complementary (Provider ↔ Customer, RS ↔
//! RS-Client, Peer ↔ Peer). A mismatched role pair is a
//! configuration error the daemon logs at session establishment;
//! the OTC attribute path keeps running under the local
//! [`PeerConfig::otc_role`] so a peer that does not advertise the
//! capability still interoperates with the local policy.
//!
//! # Strict bit
//!
//! The FRR/BIRD extension carries a strict bit in a second value
//! octet: when set, the receiver rejects a peer whose configured
//! role does not pair correctly with the local role. The library
//! advertises the bit when the operator configures it and surfaces
//! the peer's strict bit to the daemon for the reject decision.

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;
use crate::role::OtcRole;

/// Whether the local config opts this session into the RFC 9234
/// capability. The FSM gates the OPEN advertisement on this; the
/// helper centralises the check so a caller can test the posture
/// without constructing a peer.
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.bgp_role.is_some()
}

/// The `(role, strict)` pair the local config established for this
/// session, or `None` when the capability is not advertised. The
/// daemon's finalize step reconciles the configured `bgp_role` with
/// the existing `otc_role` field — when only `otc_role` is set the
/// capability is not advertised but the OTC attribute path still
/// runs.
pub fn local_role(cfg: &PeerConfig) -> Option<(OtcRole, bool)> {
    cfg.bgp_role
}

/// Whether the peer advertised the RFC 9234 capability in its OPEN,
/// regardless of value well-formedness. The daemon consults this to
/// decide whether to log a role-pairing warning.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps.iter().any(|c| c.code == CapabilityCode::BgpRole)
}

/// The peer's advertised `(role, strict)` pair, decoded from its
/// OPEN capability. Returns `None` when the peer did not advertise
/// the capability or its value is malformed (empty or longer than
/// 2 octets).
pub fn peer_role(peer_caps: &[Capability]) -> Option<(u8, bool)> {
    peer_caps
        .iter()
        .find(|c| c.code == CapabilityCode::BgpRole)
        .and_then(Capability::as_bgp_role)
}

/// Whether *both* speakers advertised the RFC 9234 capability, so
/// the role pairing check applies.
pub fn negotiated(cfg: &PeerConfig, peer_caps: &[Capability]) -> bool {
    advertised(cfg) && peer_offered(peer_caps)
}

/// Whether the local and peer roles form a complementary pair per
/// RFC 9234 §3: Provider ↔ Customer, RS ↔ RS-Client, Peer ↔ Peer.
/// Returns `false` when either side did not advertise a role or
/// when the pair is not complementary (a configuration error the
/// daemon logs at session establishment).
pub fn roles_complementary(local: OtcRole, peer_role_value: u8) -> bool {
    let Some(peer) = OtcRole::from_bgp_role_value(peer_role_value) else {
        return false;
    };
    matches!(
        (local, peer),
        (OtcRole::Provider, OtcRole::Customer)
            | (OtcRole::Customer, OtcRole::Provider)
            | (OtcRole::RouteServer, OtcRole::RsClient)
            | (OtcRole::RsClient, OtcRole::RouteServer)
            | (OtcRole::Peer, OtcRole::Peer)
    )
}

/// Build the RFC 9234 capability for a configured peer's OPEN.
/// Returns `None` when the local config has the knob off. The
/// role octet uses the FRR/BIRD wire values (0 = Provider, 1 = RS,
/// 2 = RS-Client, 3 = Customer, 4 = Peer) — distinct from the
/// `OtcRole` enum's `to_u8` (the OTC attribute path's
/// representation) — see [`OtcRole::to_bgp_role_value`].
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    let (role, strict) = cfg.bgp_role?;
    Some(Capability::bgp_role(role.to_bgp_role_value(), strict))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(role: Option<(OtcRole, bool)>) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.bgp_role = role;
        c
    }

    #[test]
    fn advertised_tracks_knob() {
        assert!(!advertised(&cfg(None)));
        assert!(advertised(&cfg(Some((OtcRole::Provider, false)))));
    }

    #[test]
    fn open_capability_off_when_knob_off() {
        assert!(open_capability(&cfg(None)).is_none());
    }

    #[test]
    fn open_capability_on_when_knob_on() {
        let cap = open_capability(&cfg(Some((OtcRole::Customer, true)))).unwrap();
        assert_eq!(cap.code, CapabilityCode::BgpRole);
        assert_eq!(cap.as_bgp_role(), Some((3, true)));
    }

    #[test]
    fn peer_offered_when_capability_present() {
        let cap = open_capability(&cfg(Some((OtcRole::Peer, false)))).unwrap();
        assert!(peer_offered(&[cap]));
    }

    #[test]
    fn peer_not_offered_when_capability_absent() {
        assert!(!peer_offered(&[]));
    }

    #[test]
    fn peer_role_returns_value_when_present() {
        let cap = open_capability(&cfg(Some((OtcRole::Provider, true)))).unwrap();
        assert_eq!(peer_role(&[cap]), Some((0, true)));
    }

    #[test]
    fn peer_role_returns_none_when_malformed() {
        let malformed = Capability::new(CapabilityCode::BgpRole, vec![]);
        assert!(peer_role(&[malformed]).is_none());
    }

    #[test]
    fn negotiated_requires_both_sides() {
        let cap = open_capability(&cfg(Some((OtcRole::Provider, false)))).unwrap();
        assert!(!negotiated(&cfg(None), std::slice::from_ref(&cap)));
        assert!(!negotiated(&cfg(Some((OtcRole::Provider, false))), &[]));
        assert!(negotiated(
            &cfg(Some((OtcRole::Provider, false))),
            std::slice::from_ref(&cap)
        ));
    }

    /// RFC 9234 §3: Provider ↔ Customer, RS ↔ RS-Client, Peer ↔
    /// Peer. Anything else is a configuration error.
    #[test]
    fn complementary_pairs() {
        assert!(roles_complementary(OtcRole::Provider, 3)); // Customer
        assert!(roles_complementary(OtcRole::Customer, 0)); // Provider
        assert!(roles_complementary(OtcRole::RouteServer, 2)); // RS-Client
        assert!(roles_complementary(OtcRole::RsClient, 1)); // RS
        assert!(roles_complementary(OtcRole::Peer, 4)); // Peer
    }

    #[test]
    fn non_complementary_pairs() {
        assert!(!roles_complementary(OtcRole::Provider, 0)); // Provider ↔ Provider
        assert!(!roles_complementary(OtcRole::Customer, 3)); // Customer ↔ Customer
        assert!(!roles_complementary(OtcRole::Provider, 4)); // Provider ↔ Peer
        assert!(!roles_complementary(OtcRole::Peer, 0)); // Peer ↔ Provider
    }

    /// An unknown peer role value (5-255) is not complementary with
    /// any local role.
    #[test]
    fn unknown_peer_role_is_not_complementary() {
        assert!(!roles_complementary(OtcRole::Provider, 5));
        assert!(!roles_complementary(OtcRole::Peer, 255));
    }
}
