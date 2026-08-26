//! BGP peer configuration. Transport is abstract — the FSM emits bytes via
//! [`crate::fsm::BgpAction::Send`] and the embedder pumps inbound bytes via
//! [`crate::fsm::BgpPeer::feed_bytes`].

use lr_core::addr::{Asn, RouterId};

use crate::role::{
    ConfederationConfig, OtcRole, PeerRole, PeerTopology, RouteReflectorConfig, RouteServerConfig,
};

/// Per-peer configuration. Used to build a [`crate::fsm::BgpPeer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// Local AS number.
    pub local_as: Asn,
    /// Peer AS number. Determines whether the session is eBGP.
    pub peer_as: Asn,
    /// Local BGP identifier.
    pub local_bgp_id: RouterId,
    /// Proposed hold time (seconds). 0 = use peer's value.
    pub hold_time: u16,
    /// True if this is a route-reflector client (RFC 4456).
    pub route_reflector_client: bool,
    /// True if this is a confederation peer (RFC 3065).
    pub confederation_member: bool,
    /// Optional: override the peer's BGP identifier.
    pub peer_bgp_id: Option<RouterId>,
    /// Optional: enable 4-byte AS capability (RFC 4893).
    pub asn4: bool,
    /// Optional: enable MP-BGP for given families.
    pub mp_families: Vec<lr_core::nlri::NlriFamily>,
    /// Optional: enable AddPath (RFC 7911).
    pub add_path: bool,
    /// Optional: enable graceful restart (RFC 4724).
    pub graceful_restart: bool,
    /// Optional: enable enhanced route refresh (RFC 7313).
    pub enhanced_rr: bool,
    /// Optional: keepalive interval (seconds). 0 = hold_time / 3.
    pub keepalive: u16,
    /// Optional: long-lived graceful restart (RFC 8277).
    pub long_lived: bool,
    /// Topological role (eBGP/iBGP/confed-*) — overrides the auto-detection.
    /// If `None`, [`PeerConfig::compute_topology`] derives it from local/peer
    /// ASN + confederation configuration.
    pub role_override: Option<PeerRole>,
    /// OTC role (RFC 9234). Defaults to [`OtcRole::Unset`].
    pub otc_role: OtcRole,
    /// Confederation configuration (RFC 6793). Optional.
    pub confederation: Option<ConfederationConfig>,
    /// Route-reflector configuration (RFC 4456). Used when
    /// `route_reflector_client` is true.
    pub route_reflector: RouteReflectorConfig,
    /// Route-server configuration (RFC 7947).
    pub route_server: RouteServerConfig,
}

impl PeerConfig {
    pub fn new(local_as: Asn, peer_as: Asn, local_bgp_id: RouterId) -> Self {
        Self {
            local_as,
            peer_as,
            local_bgp_id,
            hold_time: 90,
            route_reflector_client: false,
            confederation_member: false,
            peer_bgp_id: None,
            asn4: true,
            mp_families: Vec::new(),
            add_path: false,
            graceful_restart: false,
            enhanced_rr: false,
            keepalive: 0,
            long_lived: false,
            role_override: None,
            otc_role: OtcRole::Unset,
            confederation: None,
            route_reflector: RouteReflectorConfig::default(),
            route_server: RouteServerConfig::default(),
        }
    }

    /// True if this is an eBGP session (peer in a different AS).
    pub fn is_ebgp(&self) -> bool {
        !self.peer_role().is_internal()
    }

    /// Returns the topological role of the peer (eBGP/iBGP/confed-*).
    pub fn peer_role(&self) -> PeerRole {
        self.role_override.unwrap_or_else(|| {
            PeerRole::from_asns(self.local_as, self.peer_as, self.confederation.as_ref())
        })
    }

    /// True if this peer is a route-reflector client (RFC 4456).
    pub fn is_rr_client(&self) -> bool {
        self.route_reflector_client
    }

    /// True if this peer is a route-server client (RFC 7947).
    pub fn is_rs_client(&self) -> bool {
        self.route_server.client
    }

    /// Build the full peer topology, combining role, RR-client, RS-client,
    /// and OTC role.
    pub fn compute_topology(&self) -> PeerTopology {
        PeerTopology {
            role: self.peer_role(),
            rr_client: self.route_reflector_client,
            rs_client: self.route_server.client,
            otc: self.otc_role,
        }
    }

    pub fn keepalive_interval(&self) -> u16 {
        if self.keepalive != 0 {
            self.keepalive
        } else {
            (self.hold_time / 3).max(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebgp_role_auto_detected() {
        let cfg = PeerConfig::new(Asn(100), Asn(200), RouterId::from_v4([10, 0, 0, 1]));
        assert_eq!(cfg.peer_role(), PeerRole::Ebgp);
        assert!(cfg.is_ebgp());
    }

    #[test]
    fn ibgp_role_auto_detected() {
        let cfg = PeerConfig::new(Asn(100), Asn(100), RouterId::from_v4([10, 0, 0, 1]));
        assert_eq!(cfg.peer_role(), PeerRole::Ibgp);
        assert!(!cfg.is_ebgp());
    }

    #[test]
    fn confederation_role_auto_detected() {
        let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg.confederation = Some(ConfederationConfig::new(vec![64512, 64513, 64514]));
        assert_eq!(cfg.peer_role(), PeerRole::ConfederationExternal);
    }

    #[test]
    fn role_override_takes_precedence() {
        let mut cfg = PeerConfig::new(Asn(100), Asn(100), RouterId::from_v4([10, 0, 0, 1]));
        cfg.role_override = Some(PeerRole::Ebgp);
        assert_eq!(cfg.peer_role(), PeerRole::Ebgp);
        assert!(cfg.is_ebgp());
    }
}
