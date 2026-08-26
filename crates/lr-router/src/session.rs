//! Sessions — one per peer/neighbor/adjacency.

use lr_core::addr::{Asn, RouterId};

/// What kind of session this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionKind {
    Bgp,
    Ospfv2,
    Ospfv3,
    Babel,
}

/// Opaque per-session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionHandle(pub u64);

/// Configuration for a new session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub kind: SessionKind,
    pub local_as: Asn,
    pub peer_as: Asn,
    pub local_bgp_id: RouterId,
    pub hold_time: u16,
    pub keepalive: u16,
    pub asn4: bool,
    /// Advertise and use RFC 2918 route refresh when the peer supports it.
    pub route_refresh: bool,
    /// Advertise and use RFC 7313 enhanced refresh when the peer supports it.
    pub enhanced_route_refresh: bool,
    /// Retain peer routes over an RFC 4724 graceful restart.
    pub graceful_restart: bool,
    /// Maximum restart duration advertised to the peer, in seconds.
    pub graceful_restart_time: u16,
    /// Minimum interval between UPDATE advertisements for one prefix.
    /// Zero disables MRAI batching for this session.
    pub mrai_ms: u64,
    pub mp_families: Vec<lr_core::nlri::NlriFamily>,
    /// Local interface address: used as NEXT_HOP for eBGP egress
    /// (next-hop-self) and as the local identity for Babel/OSPF runtimes.
    pub local_address: Option<lr_core::addr::IpAddr>,
    /// OSPF area ID (0 = backbone).
    pub area_id: u32,
}

impl SessionConfig {
    pub fn bgp(local_as: Asn, peer_as: Asn, local_bgp_id: RouterId) -> Self {
        Self {
            kind: SessionKind::Bgp,
            local_as,
            peer_as,
            local_bgp_id,
            hold_time: 90,
            keepalive: 0,
            asn4: true,
            route_refresh: true,
            enhanced_route_refresh: true,
            graceful_restart: true,
            graceful_restart_time: 120,
            // RFC 4271 §9.2.1.1: common defaults are 30 seconds for eBGP
            // and 5 seconds for iBGP. `DefaultRouter` selects the latter
            // automatically when local and peer ASNs are equal.
            mrai_ms: if local_as == peer_as { 5_000 } else { 30_000 },
            // Advertise MP-BGP for IPv4 unicast (RFC 4760). Modern
            // speakers (BIRD 2, FRR) require the capability to match one
            // of their channels — without it BIRD refuses the session
            // with "Required capability missing".
            mp_families: vec![lr_core::nlri::NlriFamily::IPV4_UNICAST],
            local_address: None,
            area_id: 0,
        }
    }

    /// Override the MP-BGP address families advertised in OPEN.
    pub fn with_mp_families(mut self, families: Vec<lr_core::nlri::NlriFamily>) -> Self {
        self.mp_families = families;
        self
    }

    /// Configure RFC 4724 graceful-restart advertisement and retention.
    pub fn with_graceful_restart(mut self, restart_time_secs: u16) -> Self {
        self.graceful_restart = restart_time_secs != 0;
        self.graceful_restart_time = restart_time_secs.min(0x0fff);
        self
    }

    /// Override the RFC 4271 MRAI interval for this BGP session.
    /// Set to zero to disable batching.
    pub fn with_mrai_ms(mut self, mrai_ms: u64) -> Self {
        self.mrai_ms = mrai_ms;
        self
    }

    /// Set the local interface address (next-hop-self / protocol identity).
    pub fn with_local_address(mut self, addr: lr_core::addr::IpAddr) -> Self {
        self.local_address = Some(addr);
        self
    }

    /// Build an OSPFv2 session config.
    pub fn ospfv2(router_id: RouterId, area_id: u32) -> Self {
        Self {
            kind: SessionKind::Ospfv2,
            local_as: Asn(0),
            peer_as: Asn(0),
            local_bgp_id: router_id,
            hold_time: 0,
            keepalive: 0,
            asn4: false,
            route_refresh: false,
            enhanced_route_refresh: false,
            graceful_restart: false,
            graceful_restart_time: 0,
            mrai_ms: 0,
            mp_families: Vec::new(),
            local_address: None,
            area_id,
        }
    }

    /// Build a Babel session config.
    pub fn babel(local_addr: lr_core::addr::IpAddr) -> Self {
        Self {
            kind: SessionKind::Babel,
            local_as: Asn(0),
            peer_as: Asn(0),
            local_bgp_id: RouterId::from_u32(0),
            hold_time: 0,
            keepalive: 0,
            asn4: false,
            route_refresh: false,
            enhanced_route_refresh: false,
            graceful_restart: false,
            graceful_restart_time: 0,
            mrai_ms: 0,
            mp_families: Vec::new(),
            local_address: Some(local_addr),
            area_id: 0,
        }
    }
}

/// One session.
pub struct Session {
    pub handle: SessionHandle,
    pub kind: SessionKind,
    pub state: &'static str,
    pub established: bool,
    pub outbound: Vec<u8>,
}

impl Session {
    pub fn new(handle: SessionHandle, kind: SessionKind) -> Self {
        Self {
            handle,
            kind,
            state: "Idle",
            established: false,
            outbound: Vec::new(),
        }
    }
}
