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
    /// True if this is a confederation peer (RFC 5065 / RFC 6793).
    pub confederation_member: bool,
    /// Optional: override the peer's BGP identifier.
    pub peer_bgp_id: Option<RouterId>,
    /// Optional: enable 4-byte AS capability (RFC 4893).
    pub asn4: bool,
    /// Optional: enable MP-BGP for given families.
    pub mp_families: Vec<lr_core::nlri::NlriFamily>,
    /// FRR `bgp default ipv4-unicast` (W2.1): when `true` (the default —
    /// matches FRR and the RFC 4271 implicit IPv4 unicast family), IPv4
    /// unicast is implicitly active for this peer even when
    /// [`mp_families`](Self::mp_families) does not list it. When `false`,
    /// IPv4 unicast must be added explicitly to `mp_families` to be
    /// active — the FRR `no bgp default ipv4-unicast` posture where each
    /// peer is activated per address-family.
    ///
    /// See [`PeerConfig::ipv4_unicast_active`] for the negotiated view.
    pub default_ipv4_unicast: bool,
    /// Optional: enable AddPath (RFC 7911).
    pub add_path: bool,
    /// Optional: RFC 5549 Extended Next-Hop tuples this session
    /// advertises in OPEN. The canonical entry is `(1, 1, 2)` — IPv4
    /// unicast NLRI resolved over an IPv6 next-hop. Tuples for families
    /// the session does not speak are filtered out at OPEN time.
    pub extended_next_hop: Vec<(u16, u8, u16)>,
    /// Optional: enable graceful restart (RFC 4724).
    pub graceful_restart: bool,
    /// Maximum restart time advertised in the RFC 4724 capability, in seconds.
    pub graceful_restart_time: u16,
    /// Optional: advertise and accept route refresh (RFC 2918).
    pub route_refresh: bool,
    /// Optional: enable enhanced route refresh (RFC 7313).
    pub enhanced_rr: bool,
    /// Optional: keepalive interval (seconds). 0 = hold_time / 3.
    pub keepalive: u16,
    /// Optional: long-lived graceful restart (RFC 9494). Requires
    /// `graceful_restart` — RFC 9494 §4.1 mandates the GR capability
    /// accompanies LLGR, otherwise LLGR is ignored.
    pub long_lived: bool,
    /// Long-Lived Stale Time (seconds) advertised per address family
    /// (RFC 9494 §3.1). Zero advertises negotiation without retention.
    pub long_lived_stale_time: u32,
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
    /// Session identifier stamped into every route this peer installs
    /// (`RouteOrigin::peer`). The router assigns it; routes decoded by the
    /// FSM carry it so the RIB can attribute them back to the session.
    pub peer_id: u64,
    /// Local interface address used as NEXT_HOP when advertising to eBGP
    /// peers ("next-hop-self"). When `None` the received NEXT_HOP is
    /// preserved, which is correct for iBGP and for shared-medium eBGP.
    pub local_address: Option<lr_core::addr::IpAddr>,
    /// FRR `neighbor X allowas-in N` / BIRD `allow local as`
    /// (W2.3): the maximum number of times the local AS may appear in
    /// a received UPDATE's AS_PATH before the route is rejected.
    ///
    /// `0` (the default) rejects ANY occurrence — the RFC 4271
    /// §9.1.2.15 AS_PATH loop check the safety net enforces. `N > 0`
    /// admits a route whose AS_PATH contains the local AS up to N
    /// times (FRR's `allowas-in N`, default N=1). The special value
    /// `u32::MAX` admits any number (FRR `allowas-any`).
    ///
    /// iBGP is exempt by default — FRR/BIRD scope this to eBGP
    /// sessions, where the local AS would otherwise always form a
    /// loop; the router applies the same exemption.
    pub local_as_tolerance: u32,
    /// FRR `neighbor X soft-reconfiguration inbound` (W2.4): when
    /// `true`, the router retains the **pre-policy** view of the
    /// peer's Adj-RIB-In — the raw received routes before the import
    /// hook chain runs — so a policy reconfiguration can be applied
    /// without re-fetching from the peer (`clear ip bgp * soft in`).
    /// Off by default (FRR's default; the cost is duplicate RIB
    /// memory per peer).
    pub soft_reconfig_inbound: bool,
    /// Per-peer maximum-prefix limit. When the peer's Adj-RIB-In exceeds
    /// this many prefixes the router fires the configured action
    /// ([`MaxPrefixAction`]). `None` = no limit (the default).
    pub maximum_prefix: Option<u32>,
    /// Action to take when the maximum-prefix limit is exceeded.
    /// Defaults to [`MaxPrefixAction::Warn`].
    pub maximum_prefix_action: MaxPrefixAction,
    /// Threshold percentage (0..=100) at which a warning is logged before
    /// the hard limit is reached. 0 disables the early warning. Defaults
    /// to 75 (BIRD/FRR convention).
    pub maximum_prefix_threshold: u8,
}

/// Action taken when a peer exceeds its configured maximum-prefix limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MaxPrefixAction {
    /// Log a warning but keep the session and all routes. The operator
    /// is expected to notice the log and adjust the configuration.
    #[default]
    Warn,
    /// Tear the session down immediately with a NOTIFICATION CEASE
    /// (subcode 8, "Maximum Number of Prefixes Exceeded"). The routes
    /// the peer already installed are purged (RFC 4271 §8.2.2).
    Teardown,
    /// Tear down and refuse to re-establish for the configured cooldown
    /// period. The daemon implements the cooldown; the library just
    /// reports the event.
    Restart,
}

impl MaxPrefixAction {
    pub fn name(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Teardown => "teardown",
            Self::Restart => "restart",
        }
    }
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
            default_ipv4_unicast: true,
            add_path: false,
            extended_next_hop: Vec::new(),
            graceful_restart: false,
            graceful_restart_time: 120,
            route_refresh: true,
            enhanced_rr: true,
            keepalive: 0,
            long_lived: false,
            long_lived_stale_time: 0,
            role_override: None,
            otc_role: OtcRole::Unset,
            confederation: None,
            route_reflector: RouteReflectorConfig::default(),
            route_server: RouteServerConfig::default(),
            peer_id: 0,
            local_address: None,
            local_as_tolerance: 0,
            soft_reconfig_inbound: false,
            maximum_prefix: None,
            maximum_prefix_action: MaxPrefixAction::Warn,
            maximum_prefix_threshold: 75,
        }
    }

    /// True if this is an eBGP session (peer in a different AS).
    pub fn is_ebgp(&self) -> bool {
        !self.peer_role().is_internal()
    }

    /// True when IPv4 unicast is active for this peer (W2.1).
    ///
    /// IPv4 unicast is active when either:
    /// - [`default_ipv4_unicast`](Self::default_ipv4_unicast) is `true`
    ///   (the FRR default — RFC 4271's implicit IPv4 unicast family), or
    /// - the peer's [`mp_families`](Self::mp_families) explicitly lists
    ///   `NlriFamily::IPV4_UNICAST` (FRR `no bgp default ipv4-unicast`
    ///   with an explicit `address-family ipv4 unicast` /
    ///   `neighbor X activate`).
    ///
    /// This gates legacy-section IPv4 NLRI processing in the FSM,
    /// egress in `advertise.rs`, End-of-RIB emission and the families
    /// listed by Add-Path / LLGR capabilities.
    pub fn ipv4_unicast_active(&self) -> bool {
        self.default_ipv4_unicast
            || self
                .mp_families
                .contains(&lr_core::nlri::NlriFamily::IPV4_UNICAST)
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

    // ===== FRR `bgp default ipv4-unicast` (W2.1) =====

    #[test]
    fn default_ipv4_unicast_defaults_on() {
        // Library default: matches FRR `bgp default ipv4-unicast` and
        // the RFC 4271 implicit IPv4 unicast family.
        let cfg = PeerConfig::new(Asn(100), Asn(200), RouterId::from_v4([10, 0, 0, 1]));
        assert!(cfg.default_ipv4_unicast);
        assert!(cfg.ipv4_unicast_active());
    }

    #[test]
    fn no_default_ipv4_unicast_excludes_implicit_v4() {
        // FRR `no bgp default ipv4-unicast`: IPv4 unicast must be added
        // explicitly to `mp_families`.
        let mut cfg = PeerConfig::new(Asn(100), Asn(200), RouterId::from_v4([10, 0, 0, 1]));
        cfg.default_ipv4_unicast = false;
        assert!(!cfg.ipv4_unicast_active());
    }

    #[test]
    fn explicit_v4_in_mp_families_activates_v4_even_when_default_off() {
        // FRR `no bgp default ipv4-unicast` + explicit
        // `neighbor X activate` in `address-family ipv4 unicast`:
        // IPv4 unicast is active again.
        let mut cfg = PeerConfig::new(Asn(100), Asn(200), RouterId::from_v4([10, 0, 0, 1]));
        cfg.default_ipv4_unicast = false;
        cfg.mp_families
            .push(lr_core::nlri::NlriFamily::IPV4_UNICAST);
        assert!(cfg.ipv4_unicast_active());
    }

    #[test]
    fn no_default_ipv4_unicast_keeps_other_mp_families_independent() {
        // A pure IPv6 BGP session: `default_ipv4_unicast = false` +
        // `mp_families = [ipv6-unicast]`. IPv4 unicast is NOT active,
        // IPv6 unicast is in mp_families as configured.
        let mut cfg = PeerConfig::new(Asn(100), Asn(200), RouterId::from_v4([10, 0, 0, 1]));
        cfg.default_ipv4_unicast = false;
        cfg.mp_families
            .push(lr_core::nlri::NlriFamily::IPV6_UNICAST);
        assert!(!cfg.ipv4_unicast_active());
    }
}
