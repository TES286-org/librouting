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

/// OSPF interface network type (RFC 2328 §9.1/§9.4). Determines how
/// adjacencies form on the segment: point-to-point links always become
/// adjacent, broadcast segments elect a DR/BDR and only become adjacent
/// with them (§10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfNetworkType {
    /// RFC 2328 §9.1 point-to-point: every bidirectional neighbor
    /// becomes adjacent (the historical lr behavior — matches the
    /// `type ptp` BIRD/FRR configurations the interop labs pin).
    PointToPoint,
    /// RFC 2328 §9.1 broadcast: the segment elects a DR/BDR
    /// (§9.4) and adjacencies follow §10.4. Hellos carry the elected
    /// DR/BDR IP interface addresses (§A.3.2) and the DR originates
    /// the Network-LSA (§12.4.2).
    Broadcast,
}

impl OspfNetworkType {
    pub fn name(self) -> &'static str {
        match self {
            Self::PointToPoint => "point-to-point",
            Self::Broadcast => "broadcast",
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
    /// FRR `bgp default ipv4-unicast` (W2.1): when `true` (the default),
    /// IPv4 unicast is implicitly active for this peer even when
    /// `mp_families` does not list it. When `false`, IPv4 unicast must
    /// be added explicitly to `mp_families` to be active. The daemon
    /// populates this from the per-peer or router-level config; the
    /// FSM gates legacy-section IPv4 NLRI processing on it.
    pub default_ipv4_unicast: bool,
    /// FRR `neighbor X allowas-in N` / BIRD `allow local as` (W2.3):
    /// the maximum number of times the local AS may appear in a
    /// received UPDATE's AS_PATH before the route is rejected. `0`
    /// (the default) rejects any occurrence; `N > 0` admits up to N
    /// occurrences; `u32::MAX` admits any number (FRR `allowas-any`).
    /// iBGP is exempt.
    pub local_as_tolerance: u32,
    /// FRR `neighbor X soft-reconfiguration inbound` (W2.4): retain
    /// the pre-policy Adj-RIB-In so a policy reconfiguration can be
    /// applied without re-fetching from the peer. Off by default
    /// (FRR's default; the cost is duplicate RIB memory per peer).
    pub soft_reconfig_inbound: bool,
    /// Local interface address: used as NEXT_HOP for eBGP egress
    /// (next-hop-self) and as the local identity for Babel/OSPF runtimes.
    pub local_address: Option<lr_core::addr::IpAddr>,
    /// OSPF area ID (0 = backbone).
    pub area_id: u32,
    /// OSPF area type policy (stub/NSSA, RFC 2328 §3.6 + RFC 3101).
    pub ospf_area_type: OspfAreaType,
    /// OSPF interface MTU advertised in DBD packets (RFC 2328 §10.6 —
    /// peers reject DBDs announcing a larger MTU). The daemon fills
    /// this from the kernel interface.
    pub ospf_mtu: u16,
    /// OSPF interface network type (RFC 2328 §9.4). `PointToPoint`
    /// (the default) always becomes adjacent with every bidirectional
    /// neighbor; `Broadcast` gates adjacency on the §10.4 DR/BDR
    /// relationship driven by the election results pushed via
    /// `DefaultRouter::set_ospf_dr_state`.
    pub ospf_network_type: OspfNetworkType,
    /// Our own IPv4 interface address on the segment (RFC 2328 §12.4.1.2
    /// transit-link Link Data; the identity the election compares
    /// against when deciding whether *we* are DR/BDR). `None` = the
    /// embedder has not supplied one (§10.4 treats us as DR-Other).
    pub ospf_interface_ip: Option<u32>,
    /// The neighbor's IPv4 interface address on the segment (the
    /// election identity a received Hello's DR/BDR fields are compared
    /// against when deciding whether the *neighbor* is DR/BDR).
    pub ospf_neighbor_ip: Option<u32>,
    /// Per-peer maximum-prefix limit (BIRD `maximum prefix`, FRR
    /// `maximum-prefix`). `None` = no limit.
    pub maximum_prefix: Option<u32>,
    /// Action when the limit is exceeded: warn / teardown / restart.
    pub maximum_prefix_action: lr_bgp::MaxPrefixAction,
    /// Early-warning threshold percentage (0..=100). 0 disables.
    pub maximum_prefix_threshold: u8,
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
            // W2.1: FRR `bgp default ipv4-unicast` defaults to on. The
            // daemon overrides per-peer when `[bgp] default_ipv4_unicast
            // = false` is set, then `add_session` propagates it here.
            default_ipv4_unicast: true,
            local_as_tolerance: 0,
            soft_reconfig_inbound: false,
            local_address: None,
            area_id: 0,
            ospf_area_type: OspfAreaType::Normal,
            ospf_mtu: 1500,
            ospf_network_type: OspfNetworkType::PointToPoint,
            ospf_interface_ip: None,
            ospf_neighbor_ip: None,
            maximum_prefix: None,
            maximum_prefix_action: lr_bgp::MaxPrefixAction::Warn,
            maximum_prefix_threshold: 75,
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

    /// Configure per-peer maximum-prefix (BIRD `maximum prefix`, FRR
    /// `maximum-prefix`). When the peer's Adj-RIB-In exceeds `limit`
    /// prefixes the router fires `action`. The early-warning threshold
    /// defaults to 75% (BIRD/FRR convention).
    pub fn with_maximum_prefix(mut self, limit: u32, action: lr_bgp::MaxPrefixAction) -> Self {
        self.maximum_prefix = Some(limit);
        self.maximum_prefix_action = action;
        self
    }

    /// Override the early-warning threshold percentage (0..=100). 0
    /// disables the warning. Takes effect only when
    /// [`with_maximum_prefix`] is also set.
    pub fn with_maximum_prefix_threshold(mut self, pct: u8) -> Self {
        self.maximum_prefix_threshold = pct.min(100);
        self
    }

    /// Set the OSPF interface MTU (RFC 2328 §10.6).
    pub fn with_ospf_mtu(mut self, mtu: u16) -> Self {
        self.ospf_mtu = mtu;
        self
    }

    /// Set the OSPF interface network type (RFC 2328 §9.4). Broadcast
    /// segments gate adjacency on the elected DR/BDR (§10.4) and take
    /// part in Network-LSA origination (§12.4.2) on the daemon side.
    pub fn with_ospf_network_type(mut self, network: OspfNetworkType) -> Self {
        self.ospf_network_type = network;
        self
    }

    /// Set our own IPv4 interface address on the OSPF segment (the
    /// §10.4 identity and the transit-link Link Data, §12.4.1.2).
    pub fn with_ospf_interface_ip(mut self, ip: u32) -> Self {
        self.ospf_interface_ip = Some(ip);
        self
    }

    /// Set the neighbor's IPv4 interface address on the OSPF segment
    /// (the identity the elected DR/BDR is compared against, §10.4).
    pub fn with_ospf_neighbor_ip(mut self, ip: u32) -> Self {
        self.ospf_neighbor_ip = Some(ip);
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
            default_ipv4_unicast: true,
            local_as_tolerance: 0,
            soft_reconfig_inbound: false,
            local_address: None,
            area_id,
            ospf_area_type: OspfAreaType::Normal,
            ospf_mtu: 1500,
            ospf_network_type: OspfNetworkType::PointToPoint,
            ospf_interface_ip: None,
            ospf_neighbor_ip: None,
            maximum_prefix: None,
            maximum_prefix_action: lr_bgp::MaxPrefixAction::Warn,
            maximum_prefix_threshold: 75,
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
            default_ipv4_unicast: true,
            local_as_tolerance: 0,
            soft_reconfig_inbound: false,
            local_address: Some(local_addr),
            area_id: 0,
            ospf_area_type: OspfAreaType::Normal,
            ospf_mtu: 1500,
            ospf_network_type: OspfNetworkType::PointToPoint,
            ospf_interface_ip: None,
            ospf_neighbor_ip: None,
            maximum_prefix: None,
            maximum_prefix_action: lr_bgp::MaxPrefixAction::Warn,
            maximum_prefix_threshold: 75,
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
