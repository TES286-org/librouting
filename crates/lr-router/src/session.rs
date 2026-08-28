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

/// OSPF area type policy (RFC 2328 §3.6 stub areas; RFC 3101 NSSA).
///
/// Attached to a session via [`SessionConfig::ospfv2`] +
/// [`SessionConfig::with_ospf_area_type`]; the first session attaching
/// to an area fixes its type (mismatching later sessions are rejected
/// unless [`crate::DefaultRouter::ospf_set_area_type`] changed it).
/// Stub/NSSA semantics apply to OSPFv2 areas only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfAreaType {
    /// Regular area: type-3/type-4 summaries and type-5 externals flow.
    Normal,
    /// Stub area (RFC 2328 §3.6): no type-5 or type-4 LSAs enter; the
    /// border routers inject a type-3 summary default (`0.0.0.0/0`)
    /// with `default_metric`. `no_summary` additionally suppresses all
    /// other type-3 summaries ("totally stubby").
    Stub {
        default_metric: u32,
        no_summary: bool,
    },
    /// Not-So-Stubby area (RFC 3101): like stub, but internal ASBRs
    /// may redistribute externals as area-scoped type-7 LSAs, which the
    /// elected border router translates into type-5s for the rest of
    /// the AS (§3.2). The border-router default is a type-7 LSA while
    /// summaries are imported, or a type-3 summary default with
    /// `no_summary` ("totally NSSA", §2.7).
    Nssa {
        default_metric: u32,
        no_summary: bool,
    },
}

impl OspfAreaType {
    /// A stub area with the given default-route metric (summaries
    /// imported — the RFC 2328 default).
    pub fn stub(default_metric: u32) -> Self {
        Self::Stub {
            default_metric,
            no_summary: false,
        }
    }

    /// A totally-stubby stub area (no type-3 summaries except the
    /// injected default).
    pub fn stub_no_summary(default_metric: u32) -> Self {
        Self::Stub {
            default_metric,
            no_summary: true,
        }
    }

    /// An NSSA with the given default-route metric (summaries
    /// imported — the RFC 3101 §2.7 default).
    pub fn nssa(default_metric: u32) -> Self {
        Self::Nssa {
            default_metric,
            no_summary: false,
        }
    }

    /// A totally-NSSA (no type-3 summaries except the type-3 default).
    pub fn nssa_no_summary(default_metric: u32) -> Self {
        Self::Nssa {
            default_metric,
            no_summary: true,
        }
    }

    pub fn is_stub(&self) -> bool {
        matches!(self, Self::Stub { .. })
    }

    pub fn is_nssa(&self) -> bool {
        matches!(self, Self::Nssa { .. })
    }

    /// Type-5 and type-4 LSAs are refused (flooded to no stub/NSSA area).
    pub fn is_stubby(&self) -> bool {
        self.is_stub() || self.is_nssa()
    }

    pub fn no_summary(&self) -> bool {
        match self {
            Self::Normal => false,
            Self::Stub { no_summary, .. } | Self::Nssa { no_summary, .. } => *no_summary,
        }
    }

    /// Metric of the border-router-injected default route, if any.
    pub fn default_metric(&self) -> Option<u32> {
        match self {
            Self::Normal => None,
            Self::Stub { default_metric, .. } | Self::Nssa { default_metric, .. } => {
                Some(*default_metric)
            }
        }
    }
}

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
    /// Advertise RFC 7911 Add-Path (send + receive) for the session's
    /// families. Effective only when the peer also offers the capability;
    /// the router additionally limits how many paths per prefix are kept
    /// and advertised (see `DefaultRouter::set_add_path_max_paths`).
    pub add_path: bool,
    /// RFC 5549 Extended Next-Hop tuples advertised in OPEN. Each tuple
    /// is `(NLRI AFI, NLRI SAFI, Nexthop AFI)`; the canonical entry is
    /// `(1, 1, 2)` (IPv4 unicast NLRI resolved over an IPv6 next-hop).
    /// Effective only when the peer also offers the capability.
    pub extended_next_hop: Vec<(u16, u8, u16)>,
    /// Retain peer routes over an RFC 4724 graceful restart.
    pub graceful_restart: bool,
    /// Maximum restart duration advertised to the peer, in seconds.
    pub graceful_restart_time: u16,
    /// Advertise RFC 9494 Long-Lived Graceful Restart and retain the
    /// peer's routes for the negotiated long-lived stale time after the
    /// RFC 4724 restart window elapses. Requires `graceful_restart`.
    pub long_lived_gr: bool,
    /// Long-Lived Stale Time (seconds) advertised per address family
    /// (RFC 9494 §3.1).
    pub long_lived_stale_time: u32,
    /// Optional local cap (seconds) applied to the LLGR stale time
    /// received from peers (RFC 9494 §4.2: received timers SHOULD be
    /// modifiable by local configuration). `None` = honour the peer.
    pub llgr_max_stale_time: Option<u32>,
    /// Minimum interval between UPDATE advertisements for one prefix.
    /// Zero disables MRAI batching for this session.
    pub mrai_ms: u64,
    pub mp_families: Vec<lr_core::nlri::NlriFamily>,
    /// Local interface address: used as NEXT_HOP for eBGP egress
    /// (next-hop-self) and as the local identity for Babel/OSPF runtimes.
    pub local_address: Option<lr_core::addr::IpAddr>,
    /// OSPF area ID (0 = backbone).
    pub area_id: u32,
    /// OSPF area type policy (stub/NSSA, RFC 2328 §3.6 + RFC 3101).
    pub ospf_area_type: OspfAreaType,
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
            add_path: false,
            extended_next_hop: Vec::new(),
            graceful_restart: true,
            graceful_restart_time: 120,
            long_lived_gr: false,
            long_lived_stale_time: 0,
            llgr_max_stale_time: None,
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
            ospf_area_type: OspfAreaType::Normal,
        }
    }

    /// Override the MP-BGP address families advertised in OPEN.
    pub fn with_mp_families(mut self, families: Vec<lr_core::nlri::NlriFamily>) -> Self {
        self.mp_families = families;
        self
    }

    /// Advertise RFC 7911 Add-Path for this session's families (send +
    /// receive). Requires the peer to offer the capability too.
    pub fn with_add_path(mut self) -> Self {
        self.add_path = true;
        self
    }

    /// Advertise RFC 5549 Extended Next-Hop with the canonical
    /// `(1, 1, 2)` tuple — IPv4 unicast NLRI resolved over an IPv6
    /// next-hop. Effective only when the peer also offers the capability.
    /// Idempotent: calling twice adds the tuple once.
    pub fn with_extended_next_hop(mut self) -> Self {
        let t = (1, 1, 2);
        if !self.extended_next_hop.contains(&t) {
            self.extended_next_hop.push(t);
        }
        self
    }

    /// Advertise an arbitrary RFC 5549 Extended Next-Hop tuple
    /// `(NLRI AFI, NLRI SAFI, Nexthop AFI)`. Idempotent.
    pub fn with_extended_next_hop_tuple(
        mut self,
        nlri_afi: u16,
        nlri_safi: u8,
        nexthop_afi: u16,
    ) -> Self {
        let t = (nlri_afi, nlri_safi, nexthop_afi);
        if !self.extended_next_hop.contains(&t) {
            self.extended_next_hop.push(t);
        }
        self
    }

    /// Configure RFC 4724 graceful-restart advertisement and retention.
    pub fn with_graceful_restart(mut self, restart_time_secs: u16) -> Self {
        self.graceful_restart = restart_time_secs != 0;
        self.graceful_restart_time = restart_time_secs.min(0x0fff);
        self
    }

    /// Advertise RFC 9494 Long-Lived Graceful Restart with the given
    /// stale time (seconds) and retain the peer's routes accordingly.
    /// Zero disables LLGR for this session.
    pub fn with_long_lived_gr(mut self, stale_time_secs: u32) -> Self {
        self.long_lived_gr = stale_time_secs != 0;
        self.long_lived_stale_time = stale_time_secs;
        self
    }

    /// Cap the LLGR stale time received from peers (RFC 9494 §4.2).
    pub fn with_llgr_max_stale_time(mut self, cap_secs: u32) -> Self {
        self.llgr_max_stale_time = Some(cap_secs);
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

    /// Set the OSPF area type policy (stub/NSSA) of the area this
    /// session attaches to (RFC 2328 §3.6, RFC 3101). Ignored for
    /// non-OSPF sessions.
    pub fn with_ospf_area_type(mut self, area_type: OspfAreaType) -> Self {
        self.ospf_area_type = area_type;
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
            add_path: false,
            extended_next_hop: Vec::new(),
            graceful_restart: false,
            graceful_restart_time: 0,
            long_lived_gr: false,
            long_lived_stale_time: 0,
            llgr_max_stale_time: None,
            mrai_ms: 0,
            mp_families: Vec::new(),
            local_address: None,
            area_id,
            ospf_area_type: OspfAreaType::Normal,
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
            add_path: false,
            extended_next_hop: Vec::new(),
            graceful_restart: false,
            graceful_restart_time: 0,
            long_lived_gr: false,
            long_lived_stale_time: 0,
            llgr_max_stale_time: None,
            mrai_ms: 0,
            mp_families: Vec::new(),
            local_address: Some(local_addr),
            area_id: 0,
            ospf_area_type: OspfAreaType::Normal,
        }
    }
}

/// Operational summary of one session — the introspection view behind
/// management surfaces (`lr-daemon` runtime API, FFI dumps, bindings).
///
/// Produced by [`crate::DefaultRouter::session_summaries`]; fields outside
/// the session's protocol are zero/`None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSummary {
    /// Opaque session handle.
    pub handle: SessionHandle,
    /// Protocol kind: `"bgp"`, `"ospf"` or `"babel"`.
    pub kind: &'static str,
    /// Configured local AS (BGP only).
    pub local_as: Asn,
    /// Configured peer AS (BGP only).
    pub peer_as: Asn,
    /// Current protocol state name (`"Established"`, `"Full"`, `"Up"`, ...).
    pub state: &'static str,
    /// Whether the session is currently fully established.
    pub established: bool,
    /// BGP identifier advertised by the peer (BGP only, post-OPEN).
    pub peer_bgp_id: Option<RouterId>,
    /// Hold time negotiated on the current connection (BGP only).
    pub negotiated_hold_time: u16,
    /// Routes currently held in this session's Adj-RIB-In.
    pub adj_rib_in_len: usize,
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
