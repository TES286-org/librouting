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
//! RFC 9234 §4.2: when both speakers advertise the capability the
//! roles MUST be complementary (Provider ↔ Customer, RS ↔
//! RS-Client, Peer ↔ Peer). A mismatched pair is rejected with the
//! OPEN error "Role Mismatch" (code 2, subcode 11). The OTC
//! attribute path keeps running under the local
//! [`PeerConfig::otc_role`] so a peer that does not advertise the
//! capability still interoperates with the local policy.
//!
//! # Strict mode
//!
//! "Strict mode" is a local policy, not a wire field: RFC 9234
//! §4.2 says an operator may require receipt of the peer's role
//! capability and reject the session with the Role Mismatch
//! NOTIFICATION when it is absent. It is the `bool` in
//! [`PeerConfig::bgp_role`]; the capability value carries only the
//! one-octet role.

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

/// The peer's advertised role value, decoded from its OPEN
/// capability. Returns `None` when the peer did not advertise the
/// capability or its value is malformed (not exactly one octet).
pub fn peer_role(peer_caps: &[Capability]) -> Option<u8> {
    peer_caps
        .iter()
        .find(|c| c.code == CapabilityCode::BgpRole)
        .and_then(Capability::as_bgp_role)
}

/// Validate the peer's BGP Role advertisement against the local
/// configuration (RFC 9234 §4.2). Returns `Ok(())` when the session
/// may proceed and the OPEN error subcode to raise otherwise.
///
/// The rules, in order:
///
/// 1. Multiple role capabilities with different values are a
///    mismatch; identical duplicates are treated as one (RFC 5492
///    §3, RFC 9234 §4.2).
/// 2. A malformed role value is a mismatch.
/// 3. When both sides advertise a role, the pair must be
///    complementary (Table 2).
/// 4. When the local side advertises a role and the peer does not,
///    lenient mode proceeds; strict mode raises the mismatch.
pub fn validate(cfg: &PeerConfig, peer_caps: &[Capability]) -> Result<(), u8> {
    let roles: Vec<&Capability> = peer_caps
        .iter()
        .filter(|c| c.code == CapabilityCode::BgpRole)
        .collect();
    if roles.is_empty() {
        return match cfg.bgp_role {
            Some((_, true)) => Err(crate::error::BgpOpenErrorSubcode::RoleMismatch as u8),
            _ => Ok(()),
        };
    }
    let Some(first) = roles.first().and_then(|c| c.as_bgp_role()) else {
        return Err(crate::error::BgpOpenErrorSubcode::RoleMismatch as u8);
    };
    if roles
        .iter()
        .any(|c| c.as_bgp_role().is_none_or(|role| role != first))
    {
        return Err(crate::error::BgpOpenErrorSubcode::RoleMismatch as u8);
    }
    match cfg.bgp_role {
        Some((local, _)) if !roles_complementary(local, first) => {
            Err(crate::error::BgpOpenErrorSubcode::RoleMismatch as u8)
        }
        _ => Ok(()),
    }
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
/// role octet uses the IANA wire values (0 = Provider, 1 = RS,
/// 2 = RS-Client, 3 = Customer, 4 = Peer) — distinct from the
/// `OtcRole` enum's `to_u8` (the OTC attribute path's
/// representation) — see [`OtcRole::to_bgp_role_value`]. The local
/// strict flag is not encoded; it only drives [`validate`].
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    let (role, _strict) = cfg.bgp_role?;
    Some(Capability::bgp_role(role.to_bgp_role_value()))
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
        assert_eq!(cap.as_bgp_role(), Some(3));
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
        assert_eq!(peer_role(&[cap]), Some(0));
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

    #[test]
    fn validate_accepts_complementary_pair() {
        let c = cfg(Some((OtcRole::Provider, true)));
        let peer = Capability::bgp_role(3); // Customer
        assert_eq!(validate(&c, &[peer]), Ok(()));
    }

    #[test]
    fn validate_rejects_non_complementary_pair() {
        let c = cfg(Some((OtcRole::Provider, false)));
        let peer = Capability::bgp_role(0); // Provider
        assert_eq!(
            validate(&c, &[peer]),
            Err(crate::error::BgpOpenErrorSubcode::RoleMismatch as u8)
        );
    }

    #[test]
    fn validate_lenient_allows_missing_peer_role() {
        assert_eq!(
            validate(&cfg(Some((OtcRole::Provider, false))), &[]),
            Ok(())
        );
    }

    #[test]
    fn validate_strict_rejects_missing_peer_role() {
        assert_eq!(
            validate(&cfg(Some((OtcRole::Provider, true))), &[]),
            Err(crate::error::BgpOpenErrorSubcode::RoleMismatch as u8)
        );
    }

    #[test]
    fn validate_accepts_identical_duplicate_roles() {
        let c = cfg(Some((OtcRole::Provider, false)));
        let peer = Capability::bgp_role(3);
        assert_eq!(validate(&c, &[peer.clone(), peer]), Ok(()));
    }

    #[test]
    fn validate_rejects_conflicting_duplicate_roles() {
        let c = cfg(Some((OtcRole::Provider, false)));
        let caps = [Capability::bgp_role(3), Capability::bgp_role(4)];
        assert_eq!(
            validate(&c, &caps),
            Err(crate::error::BgpOpenErrorSubcode::RoleMismatch as u8)
        );
    }

    #[test]
    fn validate_rejects_malformed_peer_role() {
        let c = cfg(Some((OtcRole::Provider, false)));
        let malformed = Capability::new(CapabilityCode::BgpRole, vec![3, 0]);
        assert_eq!(
            validate(&c, &[malformed]),
            Err(crate::error::BgpOpenErrorSubcode::RoleMismatch as u8)
        );
    }
}
