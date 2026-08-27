//! High-level router instance. Ties sessions + Adj-RIBs + Loc-RIB + policy.
//!
//! # Data-plane pipeline
//!
//! ```text
//!              feed_input(session, bytes)
//!                        │
//!                        v
//!              ┌──────────────────┐
//!              │ protocol FSM     │  (BgpPeer / OspfSession / BabelSession)
//!              └────────┬─────────┘
//!                       │ InstallRoute / WithdrawRoute actions
//!                       v
//!   ┌─────────── import pipeline ───────────┐
//!   │ 1. SafetyNet  (AS-loop, martian, …)   │
//!   │ 2. Import hooks (HookChain)           │
//!   │ 3. Adj-RIB-In                         │
//!   │ 4. Decision: BestPath / RouteSelector │
//!   │ 5. Loc-RIB + RouterEvent              │
//!   └───────────────┬───────────────────────┘
//!                   │ best route changed
//!                   v
//!   ┌─────────── export pipeline ───────────┐
//!   │ 1. iBGP split-horizon / RR / OTC      │
//!   │ 2. Export hooks (HookChain)           │
//!   │ 3. egress rules (AS prepend, …)       │
//!   │ 4. Adj-RIB-Out → outbound bytes       │
//!   └───────────────────────────────────────┘
//! ```
//!
//! The router is poll-driven: the embedder pushes bytes in, pumps the clock
//! via [`RouterInstance::tick`], drains bytes per session via
//! [`RouterInstance::drain_output`] and consumes events via
//! [`RouterInstance::poll_events`]. It never owns sockets.

use std::collections::{BTreeMap, BTreeSet};

use crate::connection::{Connection, MemoryConn};
use crate::event::RouterEvent;
use crate::session::{SessionConfig, SessionHandle, SessionKind, SessionSummary};

use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};

use lr_core::codec::Decoder;
use lr_core::fsm::{StateMachine, TimerId};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Protocol, Route, RouteKey, RouteOrigin};
use lr_core::time::Instant;
use lr_core::timer::TimerQueue;

use lr_babel::{BabelCodec, BabelFrame, BabelNeighbor, BabelRoute, BabelRouteTable};
use lr_bgp::best_path::{BestPath, BestPathConfig};
use lr_bgp::path::{AttrType, Community, PathAttrFlags, PathAttribute, PathAttributes};
use lr_bgp::{BgpAction, BgpEvent, BgpPeer, PeerConfig as BgpPeerConfig};
use lr_ospf::abr::{flush_summary_lsa, originate_summary_lsa, SummaryDestination};
use lr_ospf::lsa::{prefix_len_to_mask, Lsa, LsaTypeV2};
use lr_ospf::lsdb::Lsdb;
use lr_ospf::neighbor::{NeighborEvent, NeighborState, OspfNeighbor};
use lr_ospf::packet::{
    LsUpdateBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType, OspfVersion,
};
use lr_ospf::spf;
use lr_policy::hooks::{HookChain, HookVerdict};
use lr_policy::safety::SafetyNet;
use lr_rib::selection::RouteSelector;
use lr_rib::{AdjRibIn, AdjRibOut, LocRib, RibMux};

/// The router trait — embedders can plug a mock implementation.
pub trait RouterInstance {
    fn add_session(&mut self, cfg: SessionConfig) -> Result<SessionHandle, String>;
    fn remove_session(&mut self, h: SessionHandle) -> Result<(), String>;
    /// Begin protocol operation on a session (BGP: ManualStart +
    /// TransportOpen). Call once the transport is connected.
    fn start_session(&mut self, h: SessionHandle) -> Result<(), String>;
    fn feed_input(&mut self, h: SessionHandle, bytes: &[u8]) -> Result<(), String>;
    fn drain_output(&mut self, h: SessionHandle) -> Vec<u8>;
    fn tick(&mut self, now: Instant);
    /// Request that an established peer resend its Adj-RIB-Out for `family`.
    /// Returns `false` if RFC 2918 was not negotiated for that session.
    fn request_route_refresh(&mut self, h: SessionHandle, family: NlriFamily) -> bool;
    /// Set the per-prefix RFC 4271 MRAI interval for a BGP session.
    fn set_mrai(&mut self, h: SessionHandle, interval_ms: u64) -> Result<(), String>;
    fn poll_events(&mut self) -> Vec<RouterEvent>;
    fn rib_snapshot(&self) -> Vec<&Route>;

    /// Every path of every prefix (the RFC 7911 Add-Path view of the
    /// Loc-RIB). Defaults to the best-path snapshot for implementors
    /// without path multiplicity.
    fn rib_paths_snapshot(&self) -> Vec<&Route> {
        self.rib_snapshot()
    }
}

/// Per-session protocol runtime.
enum SessionState {
    Bgp {
        /// Boxed: the FSM outweighs the other runtimes by far and would
        /// inflate every session slot otherwise.
        peer: Box<BgpPeer>,
        conn: MemoryConn,
        established: bool,
    },
    Ospf {
        runtime: OspfRuntime,
        conn: MemoryConn,
    },
    Babel {
        runtime: BabelRuntime,
        conn: MemoryConn,
    },
}

/// Pending per-prefix outbound UPDATE state for one BGP session.
///
/// The latest desired advertisement set supersedes any older pending one,
/// so route churn collapses to the final state at MRAI expiry. The set
/// holds every RFC 7911 path of the prefix destined for the wire (one
/// element in single-path mode); withdrawals bypass MRAI entirely and are
/// transmitted immediately.
#[derive(Debug, Clone)]
struct PendingMraiUpdate {
    routes: Vec<Route>,
    due_ms: u64,
}

/// Per-session MRAI state. `last_sent` is keyed by prefix so unrelated routes
/// are never delayed by a busy peer; this matches RFC 4271 §9.2.1.1's
/// per-destination model.
#[derive(Debug, Default)]
struct MraiState {
    interval_ms: u64,
    last_sent: BTreeMap<RouteKey, u64>,
    pending: BTreeMap<RouteKey, PendingMraiUpdate>,
}

/// RFC 4724 + RFC 9494 retention bookkeeping for one down BGP session.
///
/// While the state exists the session's routes stay in Adj-RIB-In. The
/// RFC 4724 restart window elapses first; if LLGR was negotiated for an
/// address family the routes of that family are marked `LLGR_STALE` and
/// retained until the family's long-lived stale deadline, otherwise they
/// are purged (RFC 9494 §4.2 applies the two windows serially).
#[derive(Debug, Clone)]
struct GracefulRestartState {
    /// End of the RFC 4724 restart window (ms since the router epoch).
    restart_expires_at_ms: u64,
    /// Per-family long-lived stale deadlines (ms): restart expiry + the
    /// family's negotiated (and locally capped) LLST.
    llgr_deadlines: BTreeMap<NlriFamily, u64>,
    /// Whether the retained routes have already been marked LLGR_STALE.
    marked_stale: bool,
    /// Keys refreshed since the session re-established — used at EoR and
    /// at LLST expiry during resync to drop routes the peer did not
    /// resend (RFC 4724 §4.1, RFC 9494 §4.2).
    refreshed: BTreeSet<(RouteKey, u32)>,
}

impl SessionState {
    fn conn(&mut self) -> &mut MemoryConn {
        match self {
            SessionState::Bgp { conn, .. } => conn,
            SessionState::Ospf { conn, .. } => conn,
            SessionState::Babel { conn, .. } => conn,
        }
    }
}

/// OSPF protocol runtime for one adjacency: neighbor FSM + per-session
/// decode state.
///
/// The LSDB is *per area* (shared by every session attached to the same
/// area — LSAs flooded within an area belong to the area, not to the
/// adjacency that happened to deliver them). See [`OspfAreaState`].
///
/// This is a simplified but functional driver: Hellos advance the
/// neighbor FSM and LS-Updates are handed to the area LSDB. Full
/// DBD/LSR exchange sequencing is the embedder's job to extend (the FSM
/// states are all exposed).
struct OspfRuntime {
    router_id: u32,
    area_id: u32,
    neighbor: OspfNeighbor,
    /// Protocol origin tag used when installing routes.
    protocol: Protocol,
    /// Per-session streaming decoder (carryover must never leak between
    /// different peers' transports).
    codec: lr_ospf::codec::OspfCodec,
}

/// Per-area OSPF state shared by every session attached to that area.
struct OspfAreaState {
    lsdb: Lsdb,
    /// Protocol version the area runs (v2 and v3 cannot mix in one area).
    protocol: Protocol,
}

/// One entry of an area's computed route table: the metric plus how the
/// route was derived. Inter-area entries remember the advertising border
/// router — ABR summary origination must never re-advertise a route whose
/// only justification is the router's own (possibly stale) summary.
#[derive(Debug, Clone, Copy)]
struct OspfTableEntry {
    metric: u64,
    intra_area: bool,
    /// Advertising border router for inter-area entries.
    border_router: Option<u32>,
}

impl OspfTableEntry {
    fn intra(metric: u64) -> Self {
        Self {
            metric,
            intra_area: true,
            border_router: None,
        }
    }

    fn inter(metric: u64, border_router: Option<u32>) -> Self {
        Self {
            metric,
            intra_area: false,
            border_router,
        }
    }

    /// RFC 2328 §16.2 preference order for identical prefixes: intra-area
    /// beats inter-area, then lower metric wins.
    fn beats(&self, prev: &Self) -> bool {
        (self.intra_area && !prev.intra_area)
            || (self.intra_area == prev.intra_area && self.metric < prev.metric)
    }
}

impl OspfRuntime {
    fn new(router_id: u32, area_id: u32, v3: bool) -> Self {
        Self {
            router_id,
            area_id,
            neighbor: OspfNeighbor::new(RouterId::from_u32(router_id)),
            protocol: if v3 {
                Protocol::Ospfv3
            } else {
                Protocol::Ospfv2
            },
            codec: if v3 {
                lr_ospf::codec::OspfCodec::v3()
            } else {
                lr_ospf::codec::OspfCodec::v2()
            },
        }
    }

    /// Feed one decoded OSPF packet. Hello packets advance the neighbor
    /// FSM; LS-Updates yield their LSAs for the area LSDB.
    fn handle_packet(&mut self, pkt: &OspfPacket) -> Vec<Lsa> {
        match &pkt.body {
            OspfBody::Hello(h) => {
                // If our router-id appears in the neighbor list, the remote
                // side has seen us → 2-Way eligibility.
                let seen_us = h.neighbors.contains(&self.router_id);
                let ev = if self.neighbor.state == NeighborState::Down || seen_us {
                    NeighborEvent::HelloSeen {
                        dr: h.dr,
                        bdr: h.bdr,
                        priority: h.priority,
                    }
                } else {
                    // Hello without us in it — just refresh timers.
                    return Vec::new();
                };
                let _ = self.neighbor.step(ev);
                // Simplified adjacency bring-up: proceed to ExStart on 2-Way.
                if self.neighbor.state == NeighborState::TwoWay {
                    let _ = self.neighbor.step(NeighborEvent::AdjOk { proceed: true });
                    let _ = self.neighbor.step(NeighborEvent::NegotiationDone);
                    let _ = self.neighbor.step(NeighborEvent::ExchangeDone);
                    let _ = self.neighbor.step(NeighborEvent::LsaUpdateArrived);
                }
                Vec::new()
            }
            OspfBody::LsUpdate(u) => u.lsas.clone(),
            _ => Vec::new(),
        }
    }
}

/// Babel protocol runtime for one adjacency: neighbor table + route table.
struct BabelRuntime {
    neighbor: BabelNeighbor,
    routes: BabelRouteTable,
    /// Per-session streaming decoder (carryover must never leak between
    /// different peers' transports).
    codec: BabelCodec,
    /// Current next-hop (learned from NextHop TLVs, RFC 8966 §4.6.4).
    next_hop: Option<IpAddr>,
    /// Router-id of the peer (learned from Router-Id TLVs).
    router_id: [u8; 8],
    /// Routes previously published to Loc-RIB — used to compute deltas.
    published: BTreeMap<RouteKey, Route>,
}

/// Result of one protocol-runtime step: routes to install into / withdraw
/// from Loc-RIB.
struct RuntimeDelta {
    installed: Vec<Route>,
    withdrawn: Vec<RouteKey>,
}

impl BabelRuntime {
    fn new(local: IpAddr, now_ms: u64) -> Self {
        Self {
            neighbor: BabelNeighbor::new(local, now_ms),
            routes: BabelRouteTable::new(),
            codec: BabelCodec::new(),
            next_hop: None,
            router_id: [0; 8],
            published: BTreeMap::new(),
        }
    }

    /// Feed one decoded Babel frame; returns the Loc-RIB delta.
    fn handle_frame(&mut self, frame: &BabelFrame, now_ms: u64) -> RuntimeDelta {
        use lr_babel::message::{Hello, Ihu, NextHop, RouterId as RouterIdTlv, Update};
        use lr_babel::tlv::TlvType;

        for tlv in &frame.body {
            match tlv.kind {
                TlvType::Hello => {
                    if let Some(h) = Hello::decode(&tlv.value) {
                        self.neighbor.hello(h.seqno, h.interval_cs, now_ms);
                    }
                }
                TlvType::Ihu => {
                    if let Some(ihu) = Ihu::decode(&tlv.value) {
                        self.neighbor.ihu(ihu.rxcost, ihu.interval_cs, now_ms);
                    }
                }
                TlvType::RouterId => {
                    if let Some(rid) = RouterIdTlv::decode(&tlv.value) {
                        self.router_id = rid.id;
                    }
                }
                TlvType::NextHop => {
                    if let Some(nh) = NextHop::decode(&tlv.value) {
                        self.next_hop = Some(nh.address);
                    }
                }
                TlvType::Update => {
                    if let Some(u) = Update::decode(&tlv.value) {
                        self.apply_update(&u);
                    }
                }
                _ => {}
            }
        }
        self.diff()
    }

    fn apply_update(&mut self, u: &lr_babel::message::Update) {
        // AE 0 = wildcard; AE 1 = IPv4. Only IPv4 is handled here.
        if u.ae != 1 || u.prefix.is_empty() || u.prefix.len() > 4 {
            return;
        }
        let mut addr = [0u8; 4];
        addr[..u.prefix.len()].copy_from_slice(&u.prefix);
        let prefix = Prefix::new_v4(addr, u.prefix_len);
        // Source-specific destination (RFC 9079) — tracked in the route key.
        let source = if u.src_prefix_len > 0 && !u.src_prefix.is_empty() && u.src_prefix.len() <= 4
        {
            let mut s = [0u8; 4];
            s[..u.src_prefix.len()].copy_from_slice(&u.src_prefix);
            Some(lr_babel::source::SourcePrefix::new(Prefix::new_v4(
                s,
                u.src_prefix_len,
            )))
        } else {
            None
        };
        let key = lr_babel::route::RouteKey {
            destination: prefix,
            source,
            router_id: self.router_id,
        };
        // metric 0xFFFF (infinity) → retraction (RFC 8966 §3.5.5).
        if u.metric == 0xFFFF {
            self.routes.withdraw(&key);
            return;
        }
        let nh = self.next_hop.unwrap_or(self.neighbor.address);
        self.routes.insert(BabelRoute {
            key,
            seqno: u.seqno,
            metric: u32::from(u.metric),
            next_hop: nh,
            feasible: true,
            installed: false,
        });
    }

    /// Diff the current feasible best set against the previously published
    /// set: new/changed routes are installed, disappeared ones withdrawn.
    fn diff(&mut self) -> RuntimeDelta {
        let current: BTreeMap<RouteKey, Route> = self
            .best_routes()
            .into_iter()
            .map(|r| (r.key.clone(), r))
            .collect();
        let mut delta = RuntimeDelta {
            installed: Vec::new(),
            withdrawn: Vec::new(),
        };
        for (k, r) in &current {
            match self.published.get(k) {
                Some(prev) if prev == r => {}
                _ => delta.installed.push(r.clone()),
            }
        }
        for k in self.published.keys() {
            if !current.contains_key(k) {
                delta.withdrawn.push(k.clone());
            }
        }
        self.published = current;
        delta
    }

    /// Convert the Babel route table's feasible best routes into RIB routes.
    fn best_routes(&mut self) -> Vec<Route> {
        let nh_default = self.next_hop.unwrap_or(self.neighbor.address);
        self.routes
            .best_routes()
            .into_iter()
            .map(|r| Route {
                key: RouteKey::new(r.key.destination, NlriFamily::IPV4_UNICAST),
                origin: RouteOrigin {
                    proto: 4, // Babel adjacency tag
                    peer: u64::from(u32::from_be_bytes([
                        self.router_id[4],
                        self.router_id[5],
                        self.router_id[6],
                        self.router_id[7],
                    ])),
                },
                protocol: Protocol::Babel,
                preference: lr_core::rib::Preference::new(
                    Protocol::Babel.default_admin_distance(),
                    r.metric,
                ),
                next_hop: Some(if r.next_hop == lr_core::addr::IpAddr::V4([0, 0, 0, 0]) {
                    nh_default
                } else {
                    r.next_hop
                }),
                attributes: lr_core::attr::Attributes::new(),
                age_ms: 0,
                path_id: 0,
            })
            .collect()
    }
}

/// Default router implementation. Poll-based, embedder-driven.
pub struct DefaultRouter {
    sessions: BTreeMap<u64, SessionState>,
    next_handle: u64,
    timers: TimerQueue,
    /// Logical "now" the embedder sets via tick().
    now_ms: u64,
    /// Import pipeline state.
    adj_rib_in: AdjRibIn,
    /// Export bookkeeping (what we advertised to whom).
    adj_rib_out: AdjRibOut,
    loc_rib: LocRib,
    #[allow(dead_code)]
    rib_mux: RibMux,
    safety: Option<SafetyNet>,
    hooks: HookChain,
    best_path_cfg: BestPathConfig,
    /// RFC 7911: how many paths per prefix the decision process keeps in
    /// Loc-RIB (and therefore can advertise to Add-Path peers). 1 = the
    /// historical single-path behaviour.
    add_path_max_paths: usize,
    /// Locally originated routes (kept so unoriginate can remove them).
    originated: BTreeMap<RouteKey, Route>,
    pending_events: Vec<RouterEvent>,
    /// OSPF: per-area link-state databases, shared by all sessions of an
    /// area and keyed by area ID.
    ospf_areas: BTreeMap<u32, OspfAreaState>,
    /// OSPF router ID (all OSPF sessions must agree on it).
    ospf_router_id: Option<u32>,
    /// OSPF route table currently published to Loc-RIB: the merged view
    /// across all areas, diffed on every recompute.
    ospf_published: BTreeMap<RouteKey, Route>,
    /// RFC 4271 MRAI state keyed by BGP session.
    mrai: BTreeMap<u64, MraiState>,
    /// RFC 4724 / RFC 9494 stale-route retention keyed by BGP session.
    graceful_restart: BTreeMap<u64, GracefulRestartState>,
    /// Local cap (seconds) for the LLGR stale time received from a peer
    /// (RFC 9494 §4.2), keyed by BGP session.
    llgr_caps: BTreeMap<u64, u32>,
}

impl Default for DefaultRouter {
    fn default() -> Self {
        Self {
            sessions: BTreeMap::new(),
            next_handle: 1,
            timers: TimerQueue::new(),
            now_ms: 0,
            adj_rib_in: AdjRibIn::new(),
            adj_rib_out: AdjRibOut::new(),
            loc_rib: LocRib::new(),
            rib_mux: RibMux::new(),
            safety: None,
            hooks: HookChain::new(),
            best_path_cfg: BestPathConfig::default(),
            add_path_max_paths: 1,
            originated: BTreeMap::new(),
            pending_events: Vec::new(),
            ospf_areas: BTreeMap::new(),
            ospf_router_id: None,
            ospf_published: BTreeMap::new(),
            mrai: BTreeMap::new(),
            graceful_restart: BTreeMap::new(),
            llgr_caps: BTreeMap::new(),
        }
    }
}

/// Timer IDs are encoded as `(session_handle << 8) | timer_code` so expiry
/// can be routed back to the owning session. Protocol timer codes live in
/// the low byte (BGP uses 1..=4, see [`lr_bgp::fsm::timer_ids`]).
fn encode_timer(session: u64, timer: TimerId) -> TimerId {
    TimerId((((session & 0x00ff_ffff) << 8) | u64::from(timer.0 & 0xff)) as u32)
}

fn decode_timer(id: TimerId) -> (u64, u8) {
    (u64::from(id.0) >> 8, (id.0 & 0xff) as u8)
}

impl DefaultRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the import/export safety net (enabled by default: none).
    pub fn set_safety_net(&mut self, net: SafetyNet) {
        self.safety = Some(net);
    }

    /// Access the hook chain to register import/selection/export hooks.
    pub fn hooks_mut(&mut self) -> &mut HookChain {
        &mut self.hooks
    }

    /// Access the BGP best-path configuration knobs.
    pub fn best_path_config_mut(&mut self) -> &mut BestPathConfig {
        &mut self.best_path_cfg
    }

    /// RFC 7911: how many paths per prefix the decision process keeps in
    /// Loc-RIB and advertises to Add-Path peers. Values below 1 are
    /// treated as 1 (single-path). Only takes effect for sessions whose
    /// Add-Path capability was negotiated.
    pub fn set_add_path_max_paths(&mut self, max_paths: usize) {
        self.add_path_max_paths = max_paths.max(1);
    }

    /// RFC 7911 path cap currently in force.
    pub fn add_path_max_paths(&self) -> usize {
        self.add_path_max_paths
    }

    /// Enable or disable RFC 7911 Add-Path on one BGP session. Must be
    /// called before the session establishes (the capability is exchanged
    /// in OPEN); later calls are rejected.
    pub fn set_session_add_path(&mut self, h: SessionHandle, enabled: bool) -> Result<(), String> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => {
                if peer.is_established() {
                    return Err(format!(
                        "session {} already established: add-path must be set before start",
                        h.0
                    ));
                }
                peer.config_mut().add_path = enabled;
                Ok(())
            }
            _ => Err(format!("BGP session {} not found", h.0)),
        }
    }

    /// Originate a local route (e.g. from `network` statements): injects it
    /// into Loc-RIB and advertises it to all suitable BGP peers.
    pub fn originate(&mut self, prefix: Prefix, next_hop: Option<IpAddr>) -> RouteKey {
        let key = RouteKey::new(prefix, NlriFamily::IPV4_UNICAST);
        let mut attrs = PathAttributes::new();
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0], // IGP
        ));
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            Vec::new(), // empty AS_PATH: locally originated
        ));
        if let Some(nh) = next_hop {
            attrs.insert(PathAttribute::new(
                PathAttrFlags::new().set_transitive(true),
                AttrType::NextHop,
                match nh {
                    IpAddr::V4(b) => b.to_vec(),
                    IpAddr::V6(b) => b.to_vec(),
                },
            ));
        }
        let route = Route {
            key: key.clone(),
            origin: RouteOrigin { proto: 2, peer: 0 }, // 2 = locally originated
            protocol: Protocol::Bgp,
            preference: lr_core::rib::Preference::new(Protocol::Bgp.default_admin_distance(), 0),
            next_hop,
            attributes: attrs.into(),
            age_ms: 0,
            path_id: 0,
        };
        self.loc_rib.install_set(&key, vec![route.clone()]);
        self.originated.insert(key.clone(), route.clone());
        self.pending_events
            .push(RouterEvent::RouteInstalled(route.clone()));
        self.export_selection(&key, &[route]);
        key
    }

    /// Remove a locally originated route and withdraw it everywhere.
    pub fn unoriginate(&mut self, key: &RouteKey) {
        if self.originated.remove(key).is_some() {
            self.loc_rib.uninstall(key);
            self.pending_events
                .push(RouterEvent::RouteWithdrawn(key.clone()));
            self.propagate_withdrawal(key);
        }
    }

    /// Number of routes currently in Loc-RIB.
    pub fn rib_len(&self) -> usize {
        self.loc_rib.len()
    }

    /// Operational summaries of every configured session, ordered by
    /// handle. Intended for management surfaces (runtime APIs, dumps).
    pub fn session_summaries(&self) -> Vec<SessionSummary> {
        self.sessions
            .iter()
            .map(|(id, state)| {
                let adj_rib_in_len = self
                    .adj_rib_in
                    .iter_all()
                    .filter(|r| r.origin.peer == *id)
                    .count();
                match state {
                    SessionState::Bgp {
                        peer, established, ..
                    } => SessionSummary {
                        handle: SessionHandle(*id),
                        kind: "bgp",
                        local_as: peer.config().local_as,
                        peer_as: peer.config().peer_as,
                        state: peer.state().name(),
                        established: *established,
                        peer_bgp_id: peer.peer_bgp_id(),
                        negotiated_hold_time: peer.negotiated_hold_time(),
                        adj_rib_in_len,
                    },
                    SessionState::Ospf { runtime, .. } => SessionSummary {
                        handle: SessionHandle(*id),
                        kind: "ospf",
                        local_as: Asn(0),
                        peer_as: Asn(0),
                        state: runtime.neighbor.state.name(),
                        established: runtime.neighbor.state == NeighborState::Full,
                        peer_bgp_id: None,
                        negotiated_hold_time: 0,
                        adj_rib_in_len,
                    },
                    SessionState::Babel { runtime, .. } => {
                        let heard = !runtime.neighbor.hello_history.is_empty();
                        SessionSummary {
                            handle: SessionHandle(*id),
                            kind: "babel",
                            local_as: Asn(0),
                            peer_as: Asn(0),
                            state: if heard { "Up" } else { "Down" },
                            established: heard,
                            peer_bgp_id: None,
                            negotiated_hold_time: 0,
                            adj_rib_in_len,
                        }
                    }
                }
            })
            .collect()
    }

    fn alloc_handle(&mut self) -> SessionHandle {
        let h = SessionHandle(self.next_handle);
        self.next_handle += 1;
        h
    }

    // ----- import pipeline -----

    fn import_route(&mut self, route: Route) {
        let is_ebgp = route.protocol == Protocol::Bgp && route.origin.proto == 0;
        if let Some(net) = &self.safety {
            if let Err(v) = net.check(&route, is_ebgp) {
                self.pending_events.push(RouterEvent::Log(format!(
                    "safety: rejected {}: {}",
                    route.key.prefix, v
                )));
                return;
            }
        }
        let mut route = route;
        route.age_ms = self.now_ms;
        if matches!(self.hooks.run_import(&mut route), HookVerdict::Drop) {
            return;
        }
        let key = route.key.clone();
        let origin = route.origin;
        // Track re-advertised routes while the session is resynchronizing
        // after a restart (RFC 4724 §4.1: at EoR, unrefreshed stale routes
        // are deleted; RFC 9494 §4.2 keeps the LLST timer running until
        // then).
        if let Some(state) = self.graceful_restart.get_mut(&origin.peer) {
            state.refreshed.insert((key.clone(), route.path_id));
        }
        self.adj_rib_in.feed_pre_policy(origin, route);
        self.reselect(&key);
    }

    fn withdraw_from_session(&mut self, origin: RouteOrigin, key: &RouteKey, path_id: u32) {
        if self.adj_rib_in.withdraw(origin, key, path_id).is_some() {
            self.reselect(key);
        }
    }

    /// Re-run the decision process for one prefix and propagate deltas.
    ///
    /// RFC 7911: instead of a single best path the decision process now
    /// produces a *ranking* (best first, [`BestPath::rank`]) truncated to
    /// `add_path_max_paths`. The whole ranked set is installed into
    /// Loc-RIB; Add-Path peers receive every path while single-path peers
    /// continue to see only the head of the set.
    fn reselect(&mut self, key: &RouteKey) {
        let candidates: Vec<Route> = self
            .adj_rib_in
            .iter_all()
            .filter(|r| &r.key == key)
            .cloned()
            .chain(self.originated.values().filter(|r| r.key == *key).cloned())
            .collect();

        let ranked: Vec<Route> = if candidates.is_empty() {
            Vec::new()
        } else if candidates.iter().all(|r| r.protocol == Protocol::Bgp) {
            BestPath::rank(&candidates, &self.best_path_cfg)
                .into_iter()
                .take(self.add_path_max_paths)
                .cloned()
                .collect()
        } else {
            RouteSelector::select(&candidates)
                .cloned()
                .into_iter()
                .collect()
        };
        self.apply_selection(key, ranked);
    }

    /// Apply a fresh ranking for one prefix to Loc-RIB, events and egress.
    fn apply_selection(&mut self, key: &RouteKey, ranked: Vec<Route>) {
        let old_best = self.loc_rib.best(key).cloned();
        if ranked.is_empty() {
            self.loc_rib.uninstall(key);
            self.pending_events
                .push(RouterEvent::RouteWithdrawn(key.clone()));
            self.propagate_withdrawal(key);
            return;
        }
        let new_best = ranked[0].clone();
        self.loc_rib.install_set(key, ranked.clone());
        if old_best.as_ref() != Some(&new_best) {
            self.pending_events
                .push(RouterEvent::RouteInstalled(new_best.clone()));
        }
        self.export_selection(key, &ranked);
    }

    // ----- export pipeline -----

    /// Queue an UPDATE (one per path) until the per-prefix MRAI expires,
    /// or transmit it immediately when the prefix has no active interval.
    /// `routes` is the desired advertisement set for one prefix: multiple
    /// elements only occur on Add-Path sessions (RFC 7911).
    fn queue_or_send_advertisement(&mut self, session: u64, routes: Vec<Route>) {
        let Some(first) = routes.first() else {
            return;
        };
        let key = first.key.clone();
        let now_ms = self.now_ms;
        let state = self.mrai.entry(session).or_default();
        if state.interval_ms != 0 {
            if let Some(last) = state.last_sent.get(&key) {
                let due_ms = last.saturating_add(state.interval_ms);
                if now_ms < due_ms {
                    state
                        .pending
                        .insert(key, PendingMraiUpdate { routes, due_ms });
                    return;
                }
            }
        }
        self.send_advertisement_set(session, &routes);
    }

    /// Transmit the advertisement set: one UPDATE per path (each path has
    /// its own attributes), recorded in Adj-RIB-Out under its assigned
    /// transmit path identifier.
    fn send_advertisement_set(&mut self, session: u64, routes: &[Route]) {
        let Some(first) = routes.first() else {
            return;
        };
        let key = first.key.clone();
        let sent =
            if let Some(SessionState::Bgp { peer, conn, .. }) = self.sessions.get_mut(&session) {
                let mut sent = false;
                for route in routes {
                    sent |= peer.advertise(route);
                }
                let bytes = peer.drain_outgoing();
                if !bytes.is_empty() {
                    conn.put_output(&bytes);
                }
                sent
            } else {
                false
            };
        if sent {
            self.mrai
                .entry(session)
                .or_default()
                .last_sent
                .insert(key, self.now_ms);
            let dest = RouteOrigin {
                proto: 0,
                peer: session,
            };
            for route in routes {
                self.adj_rib_out.advertise(dest, route, route.path_id);
            }
            self.pending_events
                .push(RouterEvent::PrefixAdvertised(first.key.prefix));
        }
    }

    /// Push the current ranking of one prefix to every BGP session:
    /// Add-Path peers (RFC 7911) receive each path under the transmit
    /// identifier `rank slot + 1`; single-path peers receive only the best
    /// path. Transmits are diffs against Adj-RIB-Out, so paths that fell
    /// out of the ranking (or are no longer exported) are withdrawn.
    ///
    /// Split horizon (RFC 4271 §10) is per path: a path learned from a
    /// session is never re-advertised to that same session.
    fn export_selection(&mut self, key: &RouteKey, ranked: &[Route]) {
        // Hooks borrow self immutably while session enumeration requires a
        // mutable borrow, so collect policy-approved work before transmitting.
        let hooks = std::mem::take(&mut self.hooks);
        let mut work: Vec<(u64, Vec<Route>, Vec<u32>)> = Vec::new();
        for (session, state) in &self.sessions {
            let SessionState::Bgp { peer, .. } = state else {
                continue;
            };
            if !peer.is_established() {
                continue;
            }
            let add_path_tx = peer.add_path_tx_for(key.family);
            let mut desired: Vec<Route> = Vec::new();
            if add_path_tx {
                for (slot, route) in ranked.iter().enumerate() {
                    if route.origin.peer == *session {
                        continue; // split horizon, per path
                    }
                    let mut candidate = route.clone();
                    candidate.path_id = slot as u32 + 1;
                    if matches!(hooks.run_export(&mut candidate), HookVerdict::Drop) {
                        continue;
                    }
                    desired.push(candidate);
                }
            } else if let Some(best) = ranked.first() {
                if best.origin.peer == *session {
                    continue;
                }
                let mut candidate = best.clone();
                candidate.path_id = 0;
                if !matches!(hooks.run_export(&mut candidate), HookVerdict::Drop) {
                    desired.push(candidate);
                }
            }
            let current = self.adj_rib_out.paths_for(
                RouteOrigin {
                    proto: 0,
                    peer: *session,
                },
                key,
            );
            let mut withdraw_ids: Vec<u32> = Vec::new();
            let mut advertise: Vec<Route> = Vec::new();
            for (id, cur) in &current {
                match desired.iter().find(|r| r.path_id == *id) {
                    None => withdraw_ids.push(*id),
                    Some(new) if new == cur => {}
                    Some(new) => advertise.push(new.clone()),
                }
            }
            for new in &desired {
                if !current.iter().any(|(id, _)| *id == new.path_id) {
                    advertise.push(new.clone());
                }
            }
            work.push((*session, advertise, withdraw_ids));
        }
        self.hooks = hooks;
        for (session, advertise, withdraw_ids) in work {
            if !withdraw_ids.is_empty() {
                self.queue_or_send_withdrawal(session, key, &withdraw_ids);
            }
            if !advertise.is_empty() {
                self.queue_or_send_advertisement(session, advertise);
            }
        }
    }

    /// Re-evaluate and resend one address family after an RFC 2918 request.
    ///
    /// This intentionally re-runs export hooks rather than replaying cached
    /// bytes so a policy update is reflected immediately. Entries no longer
    /// permitted by policy are withdrawn before the refreshed advertisements.
    fn reannounce_to_session(&mut self, session: u64, family: NlriFamily) {
        let origin = RouteOrigin {
            proto: 0,
            peer: session,
        };
        let prior: Vec<(RouteKey, Vec<u32>)> = self
            .adj_rib_out
            .advertised_keys(origin, family)
            .into_iter()
            .filter(|(key, _)| key.family == family)
            .collect();
        // Single-path peers refresh the best path per prefix; Add-Path
        // peers (RFC 7911) refresh the whole ranked set.
        let add_path_tx = self
            .sessions
            .get(&session)
            .map(|state| match state {
                SessionState::Bgp { peer, .. } => peer.add_path_tx_for(family),
                _ => false,
            })
            .unwrap_or(false);
        let snapshot: Vec<Vec<Route>> = self
            .loc_rib
            .iter_sets()
            .filter(|(key, _)| key.family == family)
            .map(|(_key, set)| {
                if add_path_tx {
                    set.iter()
                        .enumerate()
                        .filter(|(_, r)| r.origin.peer != session)
                        .map(|(slot, r)| {
                            let mut c = r.clone();
                            c.path_id = slot as u32 + 1;
                            c
                        })
                        .collect::<Vec<_>>()
                } else {
                    set.first()
                        .filter(|r| r.origin.peer != session)
                        .cloned()
                        .into_iter()
                        .collect::<Vec<_>>()
                }
            })
            .collect();
        let hooks = std::mem::take(&mut self.hooks);
        let mut advertised = Vec::new();

        if let Some(SessionState::Bgp { peer, conn, .. }) = self.sessions.get_mut(&session) {
            if !peer.is_established() {
                self.hooks = hooks;
                return;
            }
            // RFC 7313 brackets the refreshed table with BoRR/EoRR when
            // negotiated. Older RFC 2918 peers receive the same UPDATE delta
            // without the optional demarcation messages.
            let enhanced_refresh = peer.begin_enhanced_route_refresh(family);
            for (key, ids) in &prior {
                let entries: Vec<lr_bgp::message::update::Nlri> = ids
                    .iter()
                    .map(|id| lr_bgp::message::update::Nlri::new(*id, key.prefix))
                    .collect();
                peer.withdraw_paths(&entries, family);
                for id in ids {
                    self.adj_rib_out.suppress(origin, key, *id);
                }
            }
            for set in snapshot {
                for mut route in set {
                    if matches!(hooks.run_export(&mut route), HookVerdict::Drop) {
                        continue;
                    }
                    if peer.advertise(&route) {
                        advertised.push(route);
                    }
                }
            }
            peer.send_end_of_rib();
            if enhanced_refresh {
                peer.end_enhanced_route_refresh(family);
            }
            let bytes = peer.drain_outgoing();
            if !bytes.is_empty() {
                conn.put_output(&bytes);
            }
        }
        self.hooks = hooks;
        for route in advertised {
            self.adj_rib_out.advertise(origin, &route, route.path_id);
            self.pending_events
                .push(RouterEvent::PrefixAdvertised(route.key.prefix));
        }
    }

    /// Withdraw specific advertised paths of one prefix. Withdrawals are
    /// transmitted immediately (RFC 4271 §9.2.1.1 applies MRAI to
    /// advertisements only) and cancel any pending advertisement set for
    /// the prefix.
    fn queue_or_send_withdrawal(&mut self, session: u64, key: &RouteKey, ids: &[u32]) {
        if let Some(state) = self.mrai.get_mut(&session) {
            state.pending.remove(key);
        }
        self.send_withdrawal(session, key, ids);
    }

    fn send_withdrawal(&mut self, session: u64, key: &RouteKey, ids: &[u32]) {
        let sent =
            if let Some(SessionState::Bgp { peer, conn, .. }) = self.sessions.get_mut(&session) {
                let entries: Vec<lr_bgp::message::update::Nlri> = ids
                    .iter()
                    .map(|id| lr_bgp::message::update::Nlri::new(*id, key.prefix))
                    .collect();
                peer.withdraw_paths(&entries, key.family);
                let bytes = peer.drain_outgoing();
                let sent = !bytes.is_empty();
                if sent {
                    conn.put_output(&bytes);
                }
                sent
            } else {
                false
            };
        if sent {
            self.mrai
                .entry(session)
                .or_default()
                .last_sent
                .insert(key.clone(), self.now_ms);
            let dest = RouteOrigin {
                proto: 0,
                peer: session,
            };
            for id in ids {
                self.adj_rib_out.suppress(dest, key, *id);
            }
            self.pending_events
                .push(RouterEvent::PrefixRetracted(key.prefix));
        }
    }

    fn flush_mrai(&mut self) {
        let due: Vec<(u64, RouteKey, Vec<Route>)> = self
            .mrai
            .iter_mut()
            .flat_map(|(session, state)| {
                let ready: Vec<RouteKey> = state
                    .pending
                    .iter()
                    .filter(|(_, update)| update.due_ms <= self.now_ms)
                    .map(|(key, _)| key.clone())
                    .collect();
                ready.into_iter().filter_map(|key| {
                    state
                        .pending
                        .remove(&key)
                        .map(|update| (*session, key, update.routes))
                })
            })
            .collect();
        for (session, _key, routes) in due {
            self.send_advertisement_set(session, &routes);
        }
    }

    /// Withdraw every advertised path of one prefix from every session
    /// (the prefix has left the Loc-RIB entirely).
    fn propagate_withdrawal(&mut self, key: &RouteKey) {
        let sessions: Vec<u64> = self
            .sessions
            .iter()
            .filter_map(|(session, state)| {
                matches!(state, SessionState::Bgp { peer, .. } if peer.is_established())
                    .then_some(*session)
            })
            .filter(|session| {
                !self
                    .adj_rib_out
                    .tx_path_ids(
                        RouteOrigin {
                            proto: 0,
                            peer: *session,
                        },
                        key,
                    )
                    .is_empty()
            })
            .collect();
        for session in sessions {
            let ids = self.adj_rib_out.tx_path_ids(
                RouteOrigin {
                    proto: 0,
                    peer: session,
                },
                key,
            );
            self.queue_or_send_withdrawal(session, key, &ids);
        }
    }

    /// When a BGP session first reaches Established, advertise the whole
    /// Loc-RIB to it (initial table dump). Add-Path peers (RFC 7911)
    /// receive every ranked path of each prefix, single-path peers the
    /// best path only.
    fn on_bgp_established(&mut self, h: u64) {
        // The families the session speaks, each with its Add-Path mode —
        // the pair decides which Loc-RIB view to dump.
        let families: Vec<(NlriFamily, bool)> = match self.sessions.get(&h) {
            Some(SessionState::Bgp { peer, .. }) => {
                let mut fams = vec![NlriFamily::IPV4_UNICAST];
                for f in &peer.config().mp_families {
                    if !fams.contains(f) {
                        fams.push(*f);
                    }
                }
                fams.into_iter()
                    .map(|f| (f, peer.add_path_tx_for(f)))
                    .collect()
            }
            _ => Vec::new(),
        };
        let mut snapshot: Vec<Route> = Vec::new();
        for (family, add_path_tx) in families {
            if add_path_tx {
                for (key, set) in self.loc_rib.iter_sets() {
                    if key.family != family {
                        continue;
                    }
                    for (slot, route) in set.iter().enumerate() {
                        let mut r = route.clone();
                        r.path_id = slot as u32 + 1;
                        snapshot.push(r);
                    }
                }
            } else {
                snapshot.extend(
                    self.loc_rib
                        .iter_best()
                        .filter(|route| route.key.family == family)
                        .cloned(),
                );
            }
        }
        let hooks = std::mem::take(&mut self.hooks);
        let mut advertised: Vec<Route> = Vec::new();
        if let Some(SessionState::Bgp { peer, conn, .. }) = self.sessions.get_mut(&h) {
            for route in &snapshot {
                let mut r = route.clone();
                if matches!(hooks.run_export(&mut r), HookVerdict::Drop) {
                    continue;
                }
                if peer.advertise(&r) {
                    advertised.push(r);
                }
            }
            // RFC 4724 §4: mark the end of the initial dump so the peer can
            // detect convergence (BIRD/FRR log End-of-RIB reception).
            peer.send_end_of_rib();
            let bytes = peer.drain_outgoing();
            if !bytes.is_empty() {
                conn.put_output(&bytes);
            }
        }
        self.hooks = hooks;
        for r in advertised {
            self.adj_rib_out
                .advertise(RouteOrigin { proto: 0, peer: h }, &r, r.path_id);
        }
    }

    // ----- BGP action dispatch -----

    fn dispatch_bgp_actions(&mut self, session: u64, actions: Vec<BgpAction>) {
        // Track establishment transitions so embedders learn about session
        // death from tick() too, not only from feed_input().
        if let Some(SessionState::Bgp {
            peer, established, ..
        }) = self.sessions.get_mut(&session)
        {
            let now_est = peer.is_established();
            if now_est && !*established {
                *established = true;
                self.pending_events.push(RouterEvent::PeerStateChange {
                    session: SessionHandle(session),
                    state: "Established",
                });
            } else if !now_est && *established {
                *established = false;
                self.pending_events.push(RouterEvent::PeerStateChange {
                    session: SessionHandle(session),
                    state: "Idle",
                });
            }
        }
        for a in actions {
            match a {
                BgpAction::Send(b) => {
                    if let Some(state) = self.sessions.get_mut(&session) {
                        state.conn().put_output(&b);
                    }
                }
                BgpAction::SetTimer(id, spec) => {
                    self.timers
                        .arm(Instant(self.now_ms), encode_timer(session, id), spec);
                }
                BgpAction::CancelTimer(id) => {
                    self.timers.cancel(encode_timer(session, id));
                }
                BgpAction::InstallRoute(r) => self.import_route(r),
                BgpAction::WithdrawRoute { key, path_id } => {
                    // Withdrawals carry the origin implicitly: the session
                    // that reports them is the origin.
                    let origin = RouteOrigin {
                        proto: 0,
                        peer: session,
                    };
                    self.withdraw_from_session(origin, &key, path_id);
                }
                BgpAction::RouteRefreshRequested(family) => {
                    self.reannounce_to_session(session, family);
                }
                BgpAction::EndOfRib(family) => {
                    // RFC 4724 §4 / RFC 9494 §4.2: table synchronization for
                    // this family is complete; retention tracking ends.
                    self.on_end_of_rib(session, family);
                }
                BgpAction::Emit(ev) => {
                    let ev: RouterEvent = ev.into();
                    self.pending_events.push(ev);
                }
                BgpAction::Close | BgpAction::None => {}
            }
        }
        // The FSM buffers outbound bytes internally (OPEN/KEEPALIVE/UPDATE
        // are appended to `peer.out_buf`, not emitted as Send actions).
        // Flush them into the session connection so drain_output sees them.
        self.flush_peer_output(session);
    }

    /// Move any bytes the peer FSM buffered into the session connection.
    fn flush_peer_output(&mut self, session: u64) {
        if let Some(SessionState::Bgp { peer, conn, .. }) = self.sessions.get_mut(&session) {
            let bytes = peer.drain_outgoing();
            if !bytes.is_empty() {
                conn.put_output(&bytes);
            }
        }
    }
    /// Tell a session its transport went away (peer closed, TCP reset,
    /// connect timeout). RFC 4724 / RFC 9494 peers retain routes until the
    /// negotiated deadline; all other sessions follow RFC 4271 immediate
    /// purge.
    pub fn close_session(&mut self, h: SessionHandle) {
        if let Some(mrai) = self.mrai.get_mut(&h.0) {
            mrai.last_sent.clear();
            mrai.pending.clear();
        }
        // Compute the retention windows *before* stepping the FSM (the
        // step clears nothing, but keep the ordering explicit).
        let retention = match self.sessions.get(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => {
                let restart_time = peer.negotiated_graceful_restart_time().unwrap_or(0);
                // RFC 9494 §4.2: per-family LLST extends the retention
                // window beyond the RFC 4724 restart time. The received
                // timer may be capped by local configuration.
                let cap = self.llgr_caps.get(&h.0).copied();
                let mut llgr_deadlines = BTreeMap::new();
                if peer.llgr_negotiated() {
                    for (family, llst) in peer.negotiated_llgr_families() {
                        let llst = cap.map(|c| llst.min(c)).unwrap_or(llst);
                        let deadline = self
                            .now_ms
                            .saturating_add(u64::from(restart_time).saturating_mul(1_000))
                            .saturating_add(u64::from(llst).saturating_mul(1_000));
                        llgr_deadlines.insert(family, deadline);
                    }
                }
                Some((restart_time, llgr_deadlines))
            }
            _ => None,
        };
        let Some(state) = self.sessions.get_mut(&h.0) else {
            return;
        };
        let actions = match state {
            SessionState::Bgp { peer, .. } => peer.step(BgpEvent::TransportClose),
            SessionState::Ospf { .. } | SessionState::Babel { .. } => Vec::new(),
        };
        self.dispatch_bgp_actions(h.0, actions);
        match retention {
            Some((restart_time, llgr_deadlines))
                if restart_time > 0 || !llgr_deadlines.is_empty() =>
            {
                let families: Vec<String> = llgr_deadlines
                    .keys()
                    .map(|f| format!("{}/{}", f.afi, f.safi))
                    .collect();
                self.graceful_restart.insert(
                    h.0,
                    GracefulRestartState {
                        restart_expires_at_ms: self
                            .now_ms
                            .saturating_add(u64::from(restart_time).saturating_mul(1_000)),
                        llgr_deadlines,
                        marked_stale: false,
                        refreshed: BTreeSet::new(),
                    },
                );
                self.pending_events.push(RouterEvent::Log(format!(
                    "session {} entered graceful-restart retention for {} seconds{}",
                    h.0,
                    restart_time,
                    if families.is_empty() {
                        String::new()
                    } else {
                        format!(" + LLGR for families {:?}", families)
                    }
                )));
            }
            _ => self.session_down_cleanup(h.0),
        }
    }

    /// Purge a session's contribution from the RIB pipeline after the
    /// session went down: clear its Adj-RIB-In slice and re-run selection
    /// for the affected prefixes (RFC 4271: routes learned from a peer do
    /// not survive the session that carried them).
    fn session_down_cleanup(&mut self, session: u64) {
        let origins = [
            RouteOrigin {
                proto: 0,
                peer: session,
            },
            RouteOrigin {
                proto: 1,
                peer: session,
            },
        ];
        let affected: Vec<RouteKey> = origins
            .into_iter()
            .flat_map(|origin| self.adj_rib_in.iter_origin(origin))
            .map(|r| r.key.clone())
            .collect();
        if affected.is_empty() {
            return;
        }
        for origin in origins {
            self.adj_rib_in.clear_for(origin);
            self.adj_rib_out.clear_for(origin);
        }
        for key in affected {
            self.reselect(&key);
        }
        self.pending_events.push(RouterEvent::Log(format!(
            "session {} down: purged its Adj-RIB-In routes",
            session
        )));
    }

    // ----- RFC 4724 + RFC 9494 retention processing -----

    /// Begin the LLGR period for a session whose RFC 4724 restart window
    /// just elapsed (RFC 9494 §4.2): routes of LLGR-protected families are
    /// marked `LLGR_STALE`, routes of unprotected families and routes
    /// carrying `NO_LLGR` are deleted, selection is re-run so stale paths
    /// lose to fresh ones, and the stale routes are withdrawn from
    /// neighbors without LLGR. Routes in `refreshed` (re-advertised after
    /// the session re-established) are fresh and left untouched.
    fn enter_llgr_period(
        &mut self,
        session: u64,
        llgr_deadlines: &BTreeMap<NlriFamily, u64>,
        refreshed: &BTreeSet<(RouteKey, u32)>,
    ) {
        let origins = [
            RouteOrigin {
                proto: 0,
                peer: session,
            },
            RouteOrigin {
                proto: 1,
                peer: session,
            },
        ];
        let mut affected: Vec<RouteKey> = Vec::new();
        for origin in origins {
            affected.extend(
                self.adj_rib_in
                    .iter_origin(origin)
                    .filter(|r| !refreshed.contains(&(r.key.clone(), r.path_id)))
                    .map(|r| r.key.clone()),
            );
            self.adj_rib_in.mutate_origin(origin, |mut route| {
                if refreshed.contains(&(route.key.clone(), route.path_id)) {
                    // Freshly re-advertised during resynchronization.
                    return Some(route);
                }
                let mut attrs: PathAttributes = route.attributes.clone().into();
                let no_llgr = attrs.has_community(Community::NO_LLGR);
                let llgr_protected = llgr_deadlines.contains_key(&route.key.family);
                if no_llgr || !llgr_protected {
                    // RFC 9494 §4.2: NO_LLGR routes are never retained;
                    // families without a negotiated LLST follow plain GR.
                    None
                } else {
                    attrs.insert_community(Community::LLGR_STALE);
                    route.attributes = attrs.into();
                    Some(route)
                }
            });
        }
        for key in &affected {
            self.reselect(key);
            self.withdraw_stale_from_non_llgr_sessions(key);
        }
        if !affected.is_empty() {
            self.pending_events.push(RouterEvent::Log(format!(
                "session {} restart window elapsed: {} route(s) entered LLGR stale state",
                session,
                affected.len()
            )));
        }
    }

    /// RFC 9494 §4.3: an LLGR_STALE route is not advertised to neighbors
    /// that did not negotiate LLGR — the previous advertisement must be
    /// withdrawn from them.
    fn withdraw_stale_from_non_llgr_sessions(&mut self, key: &RouteKey) {
        let dest = |session: u64| RouteOrigin {
            proto: 0,
            peer: session,
        };
        let sessions: Vec<u64> = self
            .sessions
            .iter()
            .filter_map(|(session, state)| match state {
                SessionState::Bgp { peer, .. }
                    if peer.is_established() && !peer.llgr_negotiated() =>
                {
                    Some(*session)
                }
                _ => None,
            })
            .filter(|session| !self.adj_rib_out.tx_path_ids(dest(*session), key).is_empty())
            .collect();
        for session in sessions {
            let ids = self.adj_rib_out.tx_path_ids(dest(session), key);
            self.queue_or_send_withdrawal(session, key, &ids);
        }
    }

    /// Delete a session's unrefreshed routes of one address family and
    /// re-run selection for them. Used at EoR (RFC 4724 §4.1) and at LLST
    /// expiry during resynchronization (RFC 9494 §4.2): anything the peer
    /// did not re-advertise goes away.
    fn purge_unrefreshed_family(
        &mut self,
        session: u64,
        family: NlriFamily,
        refreshed: &BTreeSet<(RouteKey, u32)>,
    ) {
        let origins = [
            RouteOrigin {
                proto: 0,
                peer: session,
            },
            RouteOrigin {
                proto: 1,
                peer: session,
            },
        ];
        let mut purged = 0usize;
        for origin in origins {
            let stale: Vec<(RouteKey, u32)> = self
                .adj_rib_in
                .iter_origin(origin)
                .filter(|r| {
                    r.key.family == family && !refreshed.contains(&(r.key.clone(), r.path_id))
                })
                .map(|r| (r.key.clone(), r.path_id))
                .collect();
            purged += stale.len();
            for (key, path_id) in stale {
                self.adj_rib_in.withdraw(origin, &key, path_id);
                self.reselect(&key);
            }
        }
        if purged > 0 {
            self.pending_events.push(RouterEvent::Log(format!(
                "session {} resynchronized for AFI {}/SAFI {}: purged {} stale route(s)",
                session, family.afi, family.safi, purged
            )));
        }
    }

    /// End-of-RIB received for one family (RFC 4724 §4): the peer finished
    /// re-advertising its table. Stale routes it did not refresh are
    /// deleted and the family's LLGR deadline is retired (RFC 9494 §4.2).
    fn on_end_of_rib(&mut self, session: u64, family: NlriFamily) {
        let Some(state) = self.graceful_restart.get_mut(&session) else {
            return;
        };
        state.llgr_deadlines.remove(&family);
        let refreshed = state.refreshed.clone();
        let more_families = !state.llgr_deadlines.is_empty();
        if !more_families {
            self.graceful_restart.remove(&session);
        }
        self.purge_unrefreshed_family(session, family, &refreshed);
        self.pending_events.push(RouterEvent::Log(format!(
            "session {} received End-of-RIB for AFI {}/SAFI {} — synchronization complete",
            session, family.afi, family.safi
        )));
    }

    /// Drive the RFC 4724 / RFC 9494 retention state machines for all
    /// down-but-retained sessions. Called from [`Self::tick`].
    fn process_graceful_restart(&mut self) {
        // Phase 1: RFC 4724 restart-window expiry — either purge the
        // session (no LLGR) or enter the LLGR stale period.
        let expired: Vec<u64> = self
            .graceful_restart
            .iter()
            .filter(|(_, st)| !st.marked_stale && st.restart_expires_at_ms <= self.now_ms)
            .map(|(session, _)| *session)
            .collect();
        for session in expired {
            let Some(mut state) = self.graceful_restart.remove(&session) else {
                continue;
            };
            // A session that already re-established is resynchronizing:
            // its freshly re-advertised routes are *not* stale. Only a
            // session that is still down purges wholesale at restart-time
            // expiry (RFC 4724 §4.2); the re-established case waits for
            // End-of-RIB, which removes whatever was not refreshed.
            let established = matches!(
                self.sessions.get(&session),
                Some(SessionState::Bgp {
                    established: true,
                    ..
                })
            );
            if state.llgr_deadlines.is_empty() {
                if established {
                    // Keep the bookkeeping alive so on_end_of_rib can purge
                    // unrefreshed routes; the restart window itself is moot.
                    state.marked_stale = true;
                    self.graceful_restart.insert(session, state);
                } else {
                    self.session_down_cleanup(session);
                    self.pending_events.push(RouterEvent::Log(format!(
                        "session {} graceful-restart retention expired; purged stale routes",
                        session
                    )));
                }
            } else {
                state.marked_stale = true;
                let deadlines = state.llgr_deadlines.clone();
                let refreshed = state.refreshed.clone();
                self.graceful_restart.insert(session, state);
                self.enter_llgr_period(session, &deadlines, &refreshed);
            }
        }

        // Phase 2: per-family LLGR deadline expiry. The timer keeps
        // running across re-establishment until EoR (RFC 9494 §4.2), so
        // only routes the peer has not refreshed are removed.
        let expired_llgr: Vec<(u64, NlriFamily)> = self
            .graceful_restart
            .iter()
            .filter(|(_, st)| st.marked_stale)
            .flat_map(|(session, st)| {
                st.llgr_deadlines
                    .iter()
                    .filter(|(_, deadline)| **deadline <= self.now_ms)
                    .map(|(family, _)| (*session, *family))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (session, family) in expired_llgr {
            let Some(state) = self.graceful_restart.get_mut(&session) else {
                continue;
            };
            state.llgr_deadlines.remove(&family);
            let refreshed = state.refreshed.clone();
            let done = state.llgr_deadlines.is_empty();
            if done {
                self.graceful_restart.remove(&session);
            }
            // When the session is still down every route of the family is
            // unrefreshed, so this degenerates to a full family purge.
            self.purge_unrefreshed_family(session, family, &refreshed);
            self.pending_events.push(RouterEvent::Log(format!(
                "session {} long-lived stale time expired for AFI {}/SAFI {}; purged",
                session, family.afi, family.safi
            )));
        }
    }
}

impl RouterInstance for DefaultRouter {
    fn add_session(&mut self, cfg: SessionConfig) -> Result<SessionHandle, String> {
        let h = self.alloc_handle();
        match cfg.kind {
            SessionKind::Bgp => {
                let mut p_cfg = BgpPeerConfig::new(cfg.local_as, cfg.peer_as, cfg.local_bgp_id);
                p_cfg.hold_time = cfg.hold_time;
                p_cfg.keepalive = cfg.keepalive;
                p_cfg.asn4 = cfg.asn4;
                p_cfg.route_refresh = cfg.route_refresh;
                p_cfg.enhanced_rr = cfg.enhanced_route_refresh;
                p_cfg.add_path = cfg.add_path;
                p_cfg.graceful_restart = cfg.graceful_restart;
                p_cfg.graceful_restart_time = cfg.graceful_restart_time;
                p_cfg.long_lived = cfg.long_lived_gr;
                p_cfg.long_lived_stale_time = cfg.long_lived_stale_time;
                if let Some(cap) = cfg.llgr_max_stale_time {
                    self.llgr_caps.insert(h.0, cap);
                }
                p_cfg.mp_families = cfg.mp_families.clone();
                p_cfg.peer_id = h.0;
                p_cfg.local_address = cfg.local_address;
                let peer = BgpPeer::new(p_cfg);
                self.sessions.insert(
                    h.0,
                    SessionState::Bgp {
                        peer: Box::new(peer),
                        conn: MemoryConn::new(),
                        established: false,
                    },
                );
                self.mrai.insert(
                    h.0,
                    MraiState {
                        interval_ms: cfg.mrai_ms,
                        ..MraiState::default()
                    },
                );
                if self.safety.is_none() {
                    self.safety = Some(SafetyNet::new(cfg.local_as));
                }
            }
            SessionKind::Ospfv2 | SessionKind::Ospfv3 => {
                let router_id = cfg.local_bgp_id.as_u32();
                if let Some(existing) = self.ospf_router_id {
                    if existing != router_id {
                        return Err(format!(
                            "OSPF router-id {router_id} does not match established {existing}"
                        ));
                    }
                } else {
                    self.ospf_router_id = Some(router_id);
                }
                let protocol = if cfg.kind == SessionKind::Ospfv3 {
                    Protocol::Ospfv3
                } else {
                    Protocol::Ospfv2
                };
                if let Some(area) = self.ospf_areas.get(&cfg.area_id) {
                    if area.protocol != protocol {
                        return Err(format!(
                            "OSPF area {} already runs {}",
                            cfg.area_id,
                            if area.protocol == Protocol::Ospfv3 {
                                "OSPFv3"
                            } else {
                                "OSPFv2"
                            }
                        ));
                    }
                }
                self.ospf_areas.entry(cfg.area_id).or_insert(OspfAreaState {
                    lsdb: Lsdb::new(),
                    protocol,
                });
                let runtime =
                    OspfRuntime::new(router_id, cfg.area_id, protocol == Protocol::Ospfv3);
                self.sessions.insert(
                    h.0,
                    SessionState::Ospf {
                        runtime,
                        conn: MemoryConn::new(),
                    },
                );
            }
            SessionKind::Babel => {
                let runtime = BabelRuntime::new(
                    cfg.local_address.unwrap_or(IpAddr::V4([127, 0, 0, 1])),
                    self.now_ms,
                );
                self.sessions.insert(
                    h.0,
                    SessionState::Babel {
                        runtime,
                        conn: MemoryConn::new(),
                    },
                );
            }
        }
        Ok(h)
    }

    fn remove_session(&mut self, h: SessionHandle) -> Result<(), String> {
        // Remember the OSPF area before the session goes away so the last
        // session of an area can tear its shared LSDB down.
        let ospf_area = match self.sessions.get(&h.0) {
            Some(SessionState::Ospf { runtime, .. }) => Some(runtime.area_id),
            _ => None,
        };
        if self.sessions.remove(&h.0).is_none() {
            return Err(format!("session {} not found", h.0));
        }
        self.mrai.remove(&h.0);
        self.graceful_restart.remove(&h.0);
        // Remove every route that session contributed and re-select.
        let keys: Vec<(RouteKey, u32)> = self
            .adj_rib_in
            .iter_all()
            .filter(|r| r.origin.peer == h.0)
            .map(|r| (r.key.clone(), r.path_id))
            .collect();
        for (k, path_id) in keys {
            self.withdraw_from_session(
                RouteOrigin {
                    proto: 0,
                    peer: h.0,
                },
                &k,
                path_id,
            );
        }
        // OSPF: LSAs live per area, so the area survives while any session
        // remains. Dropping the last session discards the area LSDB and
        // recomputes — its routes must not outlive the area (and summaries
        // that lost their source area are flushed).
        if let Some(area_id) = ospf_area {
            let still_attached = self.sessions.values().any(
                |s| matches!(s, SessionState::Ospf { runtime, .. } if runtime.area_id == area_id),
            );
            if !still_attached {
                self.ospf_areas.remove(&area_id);
                if self.ospf_areas.is_empty() {
                    self.ospf_router_id = None;
                }
                let delta = self.ospf_on_lsdb_change();
                self.apply_runtime_delta(delta);
            }
        }
        Ok(())
    }

    fn start_session(&mut self, h: SessionHandle) -> Result<(), String> {
        if let Some(mrai) = self.mrai.get_mut(&h.0) {
            mrai.last_sent.clear();
            mrai.pending.clear();
        }
        let state = self
            .sessions
            .get_mut(&h.0)
            .ok_or_else(|| format!("no session {}", h.0))?;
        match state {
            SessionState::Bgp { peer, .. } => {
                // A (re)start must begin from a clean slate: a previous run
                // of this session may have died mid-conversation, leaving
                // the FSM in Established with stale peer state. RFC 4271
                // §8.2.2 sends the FSM to Idle on transport failure — the
                // next ManualStart then re-runs the full handshake.
                peer.reset();
                let a1 = peer.step(BgpEvent::ManualStart);
                let a2 = peer.step(BgpEvent::TransportOpen);
                let mut actions = a1;
                actions.extend(a2);
                self.dispatch_bgp_actions(h.0, actions);
            }
            SessionState::Ospf { .. } | SessionState::Babel { .. } => {
                // Link-state/distance-vector protocols begin exchanging as
                // soon as bytes flow — no explicit start event needed.
            }
        }
        // Clear the established latch so a re-established session is
        // recognised as *newly* established (initial table dump).
        if let Some(SessionState::Bgp { established, .. }) = self.sessions.get_mut(&h.0) {
            *established = false;
        }
        Ok(())
    }

    fn feed_input(&mut self, h: SessionHandle, bytes: &[u8]) -> Result<(), String> {
        // Phase 1 (borrow sessions): decode + drive the protocol FSM.
        enum Pending {
            Bgp {
                actions: Vec<BgpAction>,
                newly_established: bool,
            },
            Other {
                delta: RuntimeDelta,
            },
            OspfLsas {
                lsas: Vec<Lsa>,
            },
        }
        let pending = {
            let state = self
                .sessions
                .get_mut(&h.0)
                .ok_or_else(|| format!("no session {}", h.0))?;
            match state {
                SessionState::Bgp {
                    peer,
                    conn,
                    established,
                } => {
                    conn.push_input(bytes);
                    let input = conn.take_input();
                    if input.is_empty() {
                        return Ok(());
                    }
                    let actions = peer.feed_bytes(&input).map_err(|e| e.to_string())?;
                    let was_established = *established;
                    *established = peer.is_established();
                    Pending::Bgp {
                        actions,
                        newly_established: *established && !was_established,
                    }
                }
                SessionState::Ospf { runtime, conn } => {
                    conn.push_input(bytes);
                    let input = conn.take_input();
                    if input.is_empty() {
                        return Ok(());
                    }
                    let mut lsas = Vec::new();
                    let mut r = lr_core::buf::ReadBuf::new(&input);
                    while let Ok(Some(pkt)) = runtime.codec.decode(&mut r) {
                        lsas.extend(runtime.handle_packet(&pkt));
                    }
                    Pending::OspfLsas { lsas }
                }
                SessionState::Babel { runtime, conn } => {
                    conn.push_input(bytes);
                    let input = conn.take_input();
                    if input.is_empty() {
                        return Ok(());
                    }
                    let mut delta = RuntimeDelta {
                        installed: Vec::new(),
                        withdrawn: Vec::new(),
                    };
                    let mut r = lr_core::buf::ReadBuf::new(&input);
                    while let Ok(Some(frame)) = runtime.codec.decode(&mut r) {
                        let d = runtime.handle_frame(&frame, self.now_ms);
                        delta.installed.extend(d.installed);
                        delta.withdrawn.extend(d.withdrawn);
                    }
                    Pending::Other { delta }
                }
            }
        };
        // Phase 2 (borrow released): apply results to the RIB pipeline.
        match pending {
            Pending::Bgp {
                actions,
                newly_established,
            } => {
                self.dispatch_bgp_actions(h.0, actions);
                if newly_established {
                    // Initial table dump to the newly established peer.
                    self.on_bgp_established(h.0);
                }
            }
            Pending::Other { delta } => {
                // Babel routes land directly in Loc-RIB (their egress
                // is protocol-internal, not BGP advertisement).
                self.apply_runtime_delta(delta);
            }
            Pending::OspfLsas { lsas } => {
                // LSAs belong to the session's area: install into the
                // shared area LSDB, flood what changed to the area's other
                // sessions (RFC 2328 §13.3) and recompute.
                let Some(SessionState::Ospf { runtime, .. }) = self.sessions.get(&h.0) else {
                    return Ok(()); // session vanished between phases
                };
                let area_id = runtime.area_id;
                let mut changed = false;
                let mut to_flood = Vec::new();
                if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                    for lsa in lsas {
                        if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                            to_flood.push(lsa);
                            changed = true;
                        }
                    }
                }
                if changed {
                    self.ospf_flood(area_id, &to_flood, Some(h.0));
                    let delta = self.ospf_on_lsdb_change();
                    self.apply_runtime_delta(delta);
                }
            }
        }
        Ok(())
    }

    fn drain_output(&mut self, h: SessionHandle) -> Vec<u8> {
        match self.sessions.get_mut(&h.0) {
            Some(state) => state.conn().drain_output(),
            None => Vec::new(),
        }
    }

    fn tick(&mut self, now: Instant) {
        self.now_ms = now.0;
        let expired = self.timers.tick(now);
        for tid in expired {
            let (session, code) = decode_timer(tid);
            let Some(state) = self.sessions.get_mut(&session) else {
                continue;
            };
            let SessionState::Bgp { peer, .. } = state else {
                continue;
            };
            let ev = match code {
                c if c == lr_bgp::fsm::timer_ids::HOLD.0 as u8 => BgpEvent::TimerHoldExpired,
                c if c == lr_bgp::fsm::timer_ids::KEEPALIVE.0 as u8 => BgpEvent::TimerKeepalive,
                c if c == lr_bgp::fsm::timer_ids::CONNECT_RETRY.0 as u8 => {
                    BgpEvent::TimerConnectRetry
                }
                c if c == lr_bgp::fsm::timer_ids::IDLE_HOLD.0 as u8 => BgpEvent::TimerIdleHold,
                _ => continue,
            };
            let actions = peer.step(ev);
            self.dispatch_bgp_actions(session, actions);
        }

        // OSPF uses periodic self-LSA refresh (RFC 2328 §14.1) rather than
        // an individual timer per LSA. One poll-driven pass keeps the router
        // compact while preserving exact caller-controlled timestamps.
        if let Some(router_id) = self.ospf_router_id {
            let mut refreshed: Vec<(u32, Vec<Lsa>)> = Vec::new();
            let mut aged = false;
            for (area_id, area) in self.ospf_areas.iter_mut() {
                let lsas = area.lsdb.refresh_due(router_id, self.now_ms);
                if !lsas.is_empty() {
                    refreshed.push((*area_id, lsas));
                }
                if !area.lsdb.age_out(self.now_ms).is_empty() {
                    aged = true;
                }
            }
            for (area_id, lsas) in &refreshed {
                self.ospf_flood(*area_id, lsas, None);
            }
            if aged {
                let delta = self.ospf_on_lsdb_change();
                self.apply_runtime_delta(delta);
            }
        }
        self.flush_mrai();
        self.process_graceful_restart();
    }

    fn request_route_refresh(&mut self, h: SessionHandle, family: NlriFamily) -> bool {
        let requested = match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => peer.request_route_refresh(family),
            _ => false,
        };
        if requested {
            self.flush_peer_output(h.0);
        }
        requested
    }

    fn set_mrai(&mut self, h: SessionHandle, interval_ms: u64) -> Result<(), String> {
        if !matches!(self.sessions.get(&h.0), Some(SessionState::Bgp { .. })) {
            return Err(format!("BGP session {} not found", h.0));
        }
        let state = self.mrai.entry(h.0).or_default();
        state.interval_ms = interval_ms;
        if interval_ms == 0 {
            let pending: Vec<(RouteKey, Vec<Route>)> = state
                .pending
                .iter()
                .map(|(key, update)| (key.clone(), update.routes.clone()))
                .collect();
            state.pending.clear();
            for (_key, routes) in pending {
                self.send_advertisement_set(h.0, &routes);
            }
        }
        Ok(())
    }

    fn poll_events(&mut self) -> Vec<RouterEvent> {
        core::mem::take(&mut self.pending_events)
    }

    fn rib_snapshot(&self) -> Vec<&Route> {
        self.loc_rib.iter_best().collect()
    }

    fn rib_paths_snapshot(&self) -> Vec<&Route> {
        self.loc_rib.iter_paths().collect()
    }
}

impl DefaultRouter {
    // ------------------------------------------------------------------
    // OSPF multi-area plumbing
    // ------------------------------------------------------------------

    /// Apply one protocol-runtime delta (installed/withdrawn routes) to
    /// Loc-RIB and emit the corresponding events.
    fn apply_runtime_delta(&mut self, delta: RuntimeDelta) {
        for route in delta.installed {
            self.loc_rib.install(route.clone());
            self.pending_events.push(RouterEvent::RouteInstalled(route));
        }
        for key in delta.withdrawn {
            self.loc_rib.uninstall(&key);
            self.pending_events.push(RouterEvent::RouteWithdrawn(key));
        }
    }

    /// Flood `lsas` to every OSPF session of `area` except `exclude`
    /// (RFC 2328 §13.3, simplified: no ack/retransmission bookkeeping —
    /// the poll-driven embedder handles transport reliability).
    fn ospf_flood(&mut self, area_id: u32, lsas: &[Lsa], exclude: Option<u64>) {
        if lsas.is_empty() {
            return;
        }
        for (handle, state) in self.sessions.iter_mut() {
            let SessionState::Ospf { runtime, conn } = state else {
                continue;
            };
            if runtime.area_id != area_id || exclude == Some(*handle) {
                continue;
            }
            let packet =
                ospf_ls_update(runtime.protocol, runtime.router_id, area_id, lsas.to_vec());
            if let Ok(bytes) = runtime.codec.encode_vec(&packet) {
                conn.put_output(&bytes);
            }
        }
    }

    /// Recompute the OSPF route table after any area LSDB changed:
    /// first re-run ABR summary origination (RFC 2328 §12.4.3) so inter-
    /// area knowledge propagates, then rebuild the merged area view.
    fn ospf_on_lsdb_change(&mut self) -> RuntimeDelta {
        self.ospf_summarize_areas();
        self.ospf_recompute()
    }

    /// One area's computed route table: intra-area routes from SPF
    /// (RFC 2328 §16.1) merged with inter-area routes derived from
    /// summary-LSAs (§16.2). Intra-area paths win per prefix.
    fn ospf_area_table(lsdb: &Lsdb, router_id: u32) -> BTreeMap<Prefix, OspfTableEntry> {
        let spf_result = spf::run_spf(lsdb, router_id);
        let mut table: BTreeMap<Prefix, OspfTableEntry> = BTreeMap::new();
        for r in spf_result
            .stub_routes
            .iter()
            .chain(spf_result.transit_routes.iter())
        {
            table.insert(r.prefix, OspfTableEntry::intra(r.metric));
        }
        for r in spf::summary_routes(lsdb, &spf_result) {
            table
                .entry(r.prefix)
                .or_insert_with(|| OspfTableEntry::inter(r.metric, r.border_router));
        }
        table
    }

    /// Rebuild the merged OSPF route table across all areas and diff it
    /// against the published set. Across areas: intra-area beats
    /// inter-area, then lowest metric, then lowest area ID (areas iterate
    /// in sorted order, so the first entry of a full tie wins —
    /// deterministic).
    fn ospf_recompute(&mut self) -> RuntimeDelta {
        let Some(router_id) = self.ospf_router_id else {
            return self.ospf_diff_published(BTreeMap::new());
        };
        // Best entry per prefix across areas.
        let mut global: BTreeMap<Prefix, (OspfTableEntry, u32, Protocol)> = BTreeMap::new();
        for (area_id, area) in &self.ospf_areas {
            for (prefix, entry) in Self::ospf_area_table(&area.lsdb, router_id) {
                let better = match global.get(&prefix) {
                    None => true,
                    Some((prev, _, _)) => entry.beats(prev),
                };
                if better {
                    global.insert(prefix, (entry, *area_id, area.protocol));
                }
            }
        }
        let current: BTreeMap<RouteKey, Route> = global
            .into_iter()
            .map(|(prefix, (entry, area_id, protocol))| {
                let key = RouteKey::new(prefix, NlriFamily::IPV4_UNICAST);
                let route = Route {
                    key: key.clone(),
                    origin: RouteOrigin {
                        proto: 3, // OSPF adjacency tag
                        peer: u64::from(area_id),
                    },
                    protocol,
                    preference: lr_core::rib::Preference::new(
                        protocol.default_admin_distance(),
                        entry.metric as u32,
                    ),
                    next_hop: None,
                    attributes: lr_core::attr::Attributes::new(),
                    age_ms: 0,
                    path_id: 0,
                };
                (key, route)
            })
            .collect();
        self.ospf_diff_published(current)
    }

    /// Diff `current` against the published OSPF table and swap it in.
    fn ospf_diff_published(&mut self, current: BTreeMap<RouteKey, Route>) -> RuntimeDelta {
        let mut delta = RuntimeDelta {
            installed: Vec::new(),
            withdrawn: Vec::new(),
        };
        for (k, r) in &current {
            match self.ospf_published.get(k) {
                Some(prev) if prev == r => {}
                _ => delta.installed.push(r.clone()),
            }
        }
        for k in self.ospf_published.keys() {
            if !current.contains_key(k) {
                delta.withdrawn.push(k.clone());
            }
        }
        self.ospf_published = current;
        delta
    }

    /// RFC 2328 §12.4.3: originate and flush type-3 summary-LSAs so each
    /// area learns what is reachable outside it. Rules enforced here:
    ///
    /// - ABRs need a backbone attachment (`area 0`) and v2-only areas;
    ///   otherwise every self-originated summary is flushed (nothing can
    ///   justify it any more — e.g. after the last session of a remote
    ///   area went away).
    /// - Into the backbone: the intra-area networks of each non-backbone
    ///   area. Into a non-backbone area: backbone intra nets, inter-area
    ///   routes other ABRs summarized into the backbone, and the intra
    ///   nets of the remaining non-backbone areas (the mirror of what the
    ///   router itself injects into the backbone). Routes whose only
    ///   justification is the router's *own* backbone summary are never
    ///   sources — that path is exactly the loop a stale summary would
    ///   otherwise take back into its area of origin.
    /// - A target area never receives summaries for its own intra-area
    ///   networks (loop guard, §12.4.3/§16.2).
    ///
    /// Originated/flushed LSAs are installed into the target area LSDB and
    /// queued for flooding on that area's sessions. Returns whether any
    /// LSDB changed.
    fn ospf_summarize_areas(&mut self) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        let abr = self.ospf_areas.len() >= 2
            && self.ospf_areas.contains_key(&0)
            && self
                .ospf_areas
                .values()
                .all(|a| a.protocol == Protocol::Ospfv2);
        if !abr {
            // Not a functioning ABR: flush every self-originated summary.
            let mut changed = false;
            let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
            let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
            for target in areas {
                let mut flushes = Vec::new();
                if let Some(area) = self.ospf_areas.get(&target) {
                    for (key, entry) in area.lsdb.iter() {
                        if key.ls_type == LsaTypeV2::SummaryIpLsa as u8
                            && key.advertising_router == router_id
                        {
                            if let Some(flush) = flush_summary_lsa(&entry.lsa) {
                                flushes.push(flush);
                            }
                        }
                    }
                }
                if let Some(area) = self.ospf_areas.get_mut(&target) {
                    for flush in flushes {
                        if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                            floods.push((target, vec![flush]));
                            changed = true;
                        }
                    }
                }
            }
            for (area_id, lsas) in floods {
                self.ospf_flood(area_id, &lsas, None);
            }
            return changed;
        }
        // 1. Fresh per-area tables.
        let tables: BTreeMap<u32, BTreeMap<Prefix, OspfTableEntry>> = self
            .ospf_areas
            .iter()
            .map(|(id, area)| (*id, Self::ospf_area_table(&area.lsdb, router_id)))
            .collect();
        let backbone = tables.get(&0).cloned().unwrap_or_default();

        // 2. Per-target source sets, then diff against the self-originated
        //    type-3 LSAs already in the target LSDB.
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        for (&target, table) in &tables {
            // Sources: what the target should learn about the outside.
            let mut sources: BTreeMap<Prefix, u64> = if target == 0 {
                // Backbone: intra-area nets of every non-backbone area.
                let mut s = BTreeMap::new();
                for (id, t) in &tables {
                    if *id == 0 {
                        continue;
                    }
                    for (p, e) in t {
                        if e.intra_area {
                            s.entry(*p)
                                .and_modify(|m: &mut u64| *m = (*m).min(e.metric))
                                .or_insert(e.metric);
                        }
                    }
                }
                s
            } else {
                let mut s = BTreeMap::new();
                // (a) Backbone intra nets.
                for (p, e) in &backbone {
                    if e.intra_area {
                        s.insert(*p, e.metric);
                    }
                }
                // (b) Inter-area routes other ABRs put into the backbone.
                for (p, e) in &backbone {
                    if !e.intra_area && e.border_router != Some(router_id) {
                        s.insert(*p, e.metric);
                    }
                }
                // (c) Intra nets of the remaining non-backbone areas — the
                //     mirror of this router's own backbone summaries.
                for (id, t) in &tables {
                    if *id == 0 || *id == target {
                        continue;
                    }
                    for (p, e) in t {
                        if e.intra_area {
                            s.entry(*p)
                                .and_modify(|m: &mut u64| *m = (*m).min(e.metric))
                                .or_insert(e.metric);
                        }
                    }
                }
                s
            };
            // Loop guard: never summarize the target's own intra nets back
            // into the target.
            for (p, e) in table {
                if e.intra_area {
                    sources.remove(p);
                }
            }

            // 3. Existing self-originated summaries, keyed by LS-ID.
            let existing: BTreeMap<u32, Lsa> = self
                .ospf_areas
                .get(&target)
                .map(|area| {
                    area.lsdb
                        .iter()
                        .filter(|(key, _)| {
                            key.ls_type == LsaTypeV2::SummaryIpLsa as u8
                                && key.advertising_router == router_id
                        })
                        .map(|(key, entry)| (key.link_state_id, entry.lsa.clone()))
                        .collect()
                })
                .unwrap_or_default();

            let mut to_originate: Vec<Lsa> = Vec::new();
            let mut used_lsids: BTreeSet<u32> = BTreeSet::new();
            for (prefix, metric) in &sources {
                let dest = SummaryDestination::new(*prefix, *metric as u32);
                let mask = prefix_len_to_mask(prefix.prefix_len);
                let network = match prefix.addr {
                    lr_core::addr::IpAddr::V4(o) => u32::from_be_bytes(o) & mask,
                    lr_core::addr::IpAddr::V6(_) => continue,
                };
                used_lsids.insert(network);
                let prev = existing.get(&network);
                let unchanged = prev.is_some_and(|lsa| {
                    lr_ospf::lsa::decode_summary_lsa_body(&lsa.body).is_some_and(|body| {
                        body.network_mask == mask && body.tos0_metric() == Some(dest.metric)
                    })
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_summary_lsa(router_id, &dest, prev_seq) {
                    to_originate.push(lsa);
                }
            }
            // 4. Flush summaries whose destination disappeared.
            let mut to_flush: Vec<Lsa> = Vec::new();
            for (lsid, lsa) in &existing {
                if !used_lsids.contains(lsid) {
                    if let Some(flush) = flush_summary_lsa(lsa) {
                        to_flush.push(flush);
                    }
                }
            }

            if to_originate.is_empty() && to_flush.is_empty() {
                continue;
            }
            // 5. Install into the target LSDB and queue for flooding.
            //    Origination replaces (seq+1); MaxAge flush purges.
            let mut flooded = Vec::with_capacity(to_originate.len() + to_flush.len());
            if let Some(area) = self.ospf_areas.get_mut(&target) {
                for lsa in to_originate.into_iter().chain(to_flush) {
                    if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                        flooded.push(lsa);
                        changed = true;
                    }
                }
            }
            if !flooded.is_empty() {
                floods.push((target, flooded));
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        changed
    }
}

/// Build one LS-Update packet for an area.
fn ospf_ls_update(protocol: Protocol, router_id: u32, area_id: u32, lsas: Vec<Lsa>) -> OspfPacket {
    OspfPacket {
        header: OspfHeader {
            version: if protocol == Protocol::Ospfv3 {
                OspfVersion::V3 as u8
            } else {
                OspfVersion::V2 as u8
            },
            kind: OspfPacketType::LinkStateUpdate as u8,
            length: 0,
            router_id,
            area_id,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: OspfBody::LsUpdate(LsUpdateBody {
            lsa_count: lsas.len() as u32,
            lsas,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Asn;
    use lr_core::fsm::TimerSpec;

    /// Test helper: encode one LS-Update carrying `lsas` as if received
    /// from a peer in `area`.
    fn ospf_lsu_bytes(router_id: u32, area_id: u32, lsas: Vec<Lsa>) -> Vec<u8> {
        let packet = ospf_ls_update(Protocol::Ospfv2, router_id, area_id, lsas);
        lr_ospf::codec::OspfCodec::v2()
            .encode_vec(&packet)
            .expect("encode LSU")
    }

    /// Decode every LS-Update packet from a drained output stream.
    fn decode_lsus(bytes: &[u8]) -> Vec<LsUpdateBody> {
        let mut out = Vec::new();
        let mut codec = lr_ospf::codec::OspfCodec::v2();
        let mut r = lr_core::buf::ReadBuf::new(bytes);
        while let Ok(Some(pkt)) = codec.decode(&mut r) {
            if let OspfBody::LsUpdate(u) = pkt.body {
                out.push(u);
            }
        }
        out
    }

    #[test]
    fn ospf_self_lsa_refresh_emits_new_lsu() {
        // Router with one OSPF session in area 0 and a self-originated
        // Router-LSA installed in the area LSDB at t=0. The refresh pass
        // at the 1800 s boundary must re-originate it (seq+1, age 0) and
        // queue an LSU on the session.
        let mut r = DefaultRouter::new();
        let h = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(0x01020304), 0))
            .unwrap();
        let lsa = Lsa {
            header: lr_ospf::lsa::LsaHeader {
                ls_age: 0,
                options: 0,
                ls_type: 1,
                link_state_id: 0x01020304,
                advertising_router: 0x01020304,
                ls_sequence_number: 0x80000001,
                ls_checksum: 0,
                length: lr_ospf::lsa::LsaHeader::LEN as u16,
            },
            body: Vec::new(),
        };
        r.ospf_areas.get_mut(&0).unwrap().lsdb.install(lsa, 0);
        r.tick(Instant(1_799_999));
        assert!(r.drain_output(h).is_empty());
        r.tick(Instant(1_800_000));
        let updates = decode_lsus(&r.drain_output(h));
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].lsa_count, 1);
        assert_eq!(updates[0].lsas[0].header.ls_sequence_number, 0x80000002);
        assert_eq!(updates[0].lsas[0].header.ls_age, 0);
    }

    /// Router-LSA test constructor: `(link_id, link_data, link_type, metric)`.
    fn router_lsa(rid: u32, links: Vec<(u32, u32, u8, u16)>) -> Lsa {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // flags
        body.extend_from_slice(&(links.len() as u16).to_be_bytes());
        for (lid, ldata, ltype, metric) in links {
            body.extend_from_slice(&lid.to_be_bytes());
            body.extend_from_slice(&ldata.to_be_bytes());
            body.push(ltype);
            body.push(0); // tos
            body.extend_from_slice(&metric.to_be_bytes());
        }
        Lsa {
            header: lr_ospf::lsa::LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: 1,
                link_state_id: rid,
                advertising_router: rid,
                ls_sequence_number: 0x80000001,
                ls_checksum: 0,
                length: (lr_ospf::lsa::LsaHeader::LEN + body.len()) as u16,
            },
            body,
        }
    }

    const P2P: u8 = 1; // RouterLinkType::PointToPoint
    const STUB: u8 = 3; // RouterLinkType::StubNetwork

    #[test]
    fn ospf_same_area_sessions_share_lsdb() {
        // Two sessions in one area: an LSA arriving on one must be flooded
        // to the other (RFC 2328 §13.3) and both share the area LSDB, so
        // the route installs exactly once.
        let mut r = DefaultRouter::new();
        let rid = RouterId::from_u32(0x01010101);
        let a = r.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();
        let b = r.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();

        let ours = router_lsa(0x01010101, vec![(0x0a0a0a00, 0xffff_ff00, STUB, 10)]);
        r.feed_input(a, &ospf_lsu_bytes(0x02020202, 0, vec![ours]))
            .unwrap();

        let updates = decode_lsus(&r.drain_output(b));
        assert_eq!(updates.len(), 1, "session b must see the flooded LSA");
        assert_eq!(updates[0].lsas[0].header.advertising_router, 0x01010101);
        assert!(r.drain_output(a).is_empty(), "no flood back to the source");

        let snap = r.rib_snapshot();
        assert!(snap
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)));
    }

    #[test]
    fn ospf_abr_originates_summary_into_backbone() {
        // ABR attached to area 0 and area 1. An intra-area net in area 1
        // (10.10.10.0/24, total metric 15) must be summarized into the
        // backbone as a type-3 LSA with a valid §C.4 checksum.
        let mut r = DefaultRouter::new();
        let rid = 0x01010101;
        let h0 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
            .unwrap();
        let h1 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
            .unwrap();

        let ours = router_lsa(rid, vec![(0x02020202, 0, P2P, 5)]);
        let r2 = router_lsa(
            0x02020202,
            vec![(rid, 0, P2P, 5), (0x0a0a0a00, 0xffff_ff00, STUB, 10)],
        );
        r.feed_input(h1, &ospf_lsu_bytes(0x02020202, 1, vec![ours, r2]))
            .unwrap();

        // Intra-area route: 5 (to R2) + 10 (stub) = 15.
        let route = r
            .rib_snapshot()
            .into_iter()
            .find(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24))
            .expect("intra-area route installed");
        assert_eq!(route.preference.metric, 15);

        // Backbone session received exactly the type-3 summary.
        let updates = decode_lsus(&r.drain_output(h0));
        assert_eq!(updates.len(), 1);
        let lsa = &updates[0].lsas[0];
        assert_eq!(lsa.header.ls_type, 3);
        assert_eq!(lsa.header.advertising_router, rid);
        assert_eq!(lsa.header.link_state_id, 0x0a0a0a00);
        assert_eq!(lsa.header.ls_sequence_number, 0x80000001);
        let body = lr_ospf::lsa::decode_summary_lsa_body(&lsa.body).unwrap();
        assert_eq!(body.network_mask, 0xffff_ff00);
        assert_eq!(body.tos0_metric(), Some(15));
        assert!(
            lsa.checksum_ok(),
            "originated summary must checksum correctly"
        );
        // The summary targets the backbone only.
        assert!(r.drain_output(h1).is_empty());
    }

    #[test]
    fn ospf_inter_area_route_installed() {
        // Single backbone area: border router 3.3.3.3 (metric 5 away)
        // summarizes 10.20.20.0/24 metric 7 → inter-area route metric 12.
        // A summary from an unreachable border router must yield nothing.
        let mut r = DefaultRouter::new();
        let rid = 0x01010101;
        let h0 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
            .unwrap();

        let ours = router_lsa(rid, vec![(0x03030303, 0, P2P, 5)]);
        let br = router_lsa(0x03030303, vec![(rid, 0, P2P, 5)]);
        let reachable_summary = originate_summary_lsa(
            0x03030303,
            &SummaryDestination::new(Prefix::new_v4([10, 20, 20, 0], 24), 7),
            None,
        )
        .unwrap();
        let ghost_summary = originate_summary_lsa(
            0x09090909,
            &SummaryDestination::new(Prefix::new_v4([10, 30, 30, 0], 24), 7),
            None,
        )
        .unwrap();
        r.feed_input(
            h0,
            &ospf_lsu_bytes(
                0x03030303,
                0,
                vec![ours, br, reachable_summary, ghost_summary],
            ),
        )
        .unwrap();

        let snap = r.rib_snapshot();
        let route = snap
            .iter()
            .find(|rt| rt.key.prefix == Prefix::new_v4([10, 20, 20, 0], 24))
            .expect("inter-area route via reachable border router");
        assert_eq!(route.preference.metric, 12); // 5 + 7
        assert_eq!(route.protocol, Protocol::Ospfv2);
        assert!(
            !snap
                .iter()
                .any(|rt| rt.key.prefix == Prefix::new_v4([10, 30, 30, 0], 24)),
            "unreachable border router's summary must not install a route"
        );
    }

    #[test]
    fn ospf_inter_area_loop_guard() {
        // ABR attached to areas 0, 1, 2. A route learned *inter-area* in
        // area 1 (from border router 4.4.4.4) must never be re-advertised
        // into area 2 or the backbone — only the backbone's knowledge is
        // summarized into non-backbone areas (RFC 2328 §12.4.3).
        let mut r = DefaultRouter::new();
        let rid = 0x01010101;
        let h0 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
            .unwrap();
        let h1 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
            .unwrap();
        let h2 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 2))
            .unwrap();

        // Area 1: BR 4.4.4.4 reachable at 5, advertising 10.40.40.0/24 (7).
        let ours_a1 = router_lsa(rid, vec![(0x04040404, 0, P2P, 5)]);
        let br = router_lsa(0x04040404, vec![(rid, 0, P2P, 5)]);
        let br_summary = originate_summary_lsa(
            0x04040404,
            &SummaryDestination::new(Prefix::new_v4([10, 40, 40, 0], 24), 7),
            None,
        )
        .unwrap();
        r.feed_input(
            h1,
            &ospf_lsu_bytes(0x04040404, 1, vec![ours_a1, br, br_summary]),
        )
        .unwrap();
        // Area 2: our stub net 10.50.50.0/24 metric 3.
        let ours_a2 = router_lsa(rid, vec![(0x0a323200, 0xffff_ff00, STUB, 3)]);
        r.feed_input(h2, &ospf_lsu_bytes(0x05050505, 2, vec![ours_a2]))
            .unwrap();

        // The area-1-learned inter-area route is usable locally...
        let snap = r.rib_snapshot();
        let route = snap
            .iter()
            .find(|rt| rt.key.prefix == Prefix::new_v4([10, 40, 40, 0], 24))
            .expect("inter-area route via area 1");
        assert_eq!(route.preference.metric, 12); // 5 + 7

        // ...but area 2 must NOT learn it. Area 2 receives nothing at all:
        // the backbone knows no routes beyond area 2's own intra net,
        // which the loop guard excludes.
        assert!(
            r.drain_output(h2).is_empty(),
            "non-backbone inter-area knowledge must not transit areas"
        );
        // The backbone only gets area 2's intra net (10.50.50.0/24), never
        // the area-1-learned 10.40.40.0/24.
        let backbone_updates = decode_lsus(&r.drain_output(h0));
        let backbone_prefixes: Vec<u32> = backbone_updates
            .iter()
            .flat_map(|u| u.lsas.iter().map(|l| l.header.link_state_id))
            .collect();
        assert_eq!(backbone_prefixes, vec![0x0a323200]);
    }

    #[test]
    fn ospf_summary_flushed_when_net_disappears() {
        // ABR setup as in ospf_abr_originates_summary_into_backbone; then
        // R2's Router-LSA ages out (MaxAge instance) → the backbone
        // summary is flushed with a MaxAge LSA and the route withdraws.
        let mut r = DefaultRouter::new();
        let rid = 0x01010101;
        let h0 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
            .unwrap();
        let h1 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
            .unwrap();

        let ours = router_lsa(rid, vec![(0x02020202, 0, P2P, 5)]);
        let mut r2 = router_lsa(
            0x02020202,
            vec![(rid, 0, P2P, 5), (0x0a0a0a00, 0xffff_ff00, STUB, 10)],
        );
        r.feed_input(h1, &ospf_lsu_bytes(0x02020202, 1, vec![ours, r2.clone()]))
            .unwrap();
        assert!(r
            .rib_snapshot()
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)));
        let _ = r.drain_output(h0);

        // Flush R2's LSA with a MaxAge instance (seq advanced).
        r2.header.ls_age = 3600;
        r2.header.ls_sequence_number += 1;
        r.feed_input(h1, &ospf_lsu_bytes(0x02020202, 1, vec![r2]))
            .unwrap();

        let updates = decode_lsus(&r.drain_output(h0));
        let flushed = updates
            .iter()
            .flat_map(|u| u.lsas.iter())
            .find(|l| l.header.ls_type == 3 && l.header.link_state_id == 0x0a0a0a00)
            .expect("backbone summary must be flushed");
        assert_eq!(flushed.header.ls_age, 3600);

        assert!(
            !r.rib_snapshot()
                .iter()
                .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)),
            "route must withdraw with its summary"
        );
    }

    #[test]
    fn ospf_no_backbone_no_summaries() {
        // Router attached to areas 1 and 2 only: without a backbone
        // attachment it is not a functioning ABR and must not summarize.
        let mut r = DefaultRouter::new();
        let rid = 0x01010101;
        let h1 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
            .unwrap();
        let h2 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 2))
            .unwrap();
        let ours = router_lsa(rid, vec![(0x0a0a0a00, 0xffff_ff00, STUB, 10)]);
        r.feed_input(h1, &ospf_lsu_bytes(0x02020202, 1, vec![ours]))
            .unwrap();
        assert!(r.drain_output(h2).is_empty());
        assert!(r.drain_output(h1).is_empty());
        assert!(r
            .rib_snapshot()
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)));
    }

    #[test]
    fn ospf_area_teardown_with_last_session() {
        // Routes must not outlive their area: removing the last session of
        // an area withdraws its routes, while other areas keep theirs.
        let mut r = DefaultRouter::new();
        let rid = 0x01010101;
        let h0 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
            .unwrap();
        let h1 = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
            .unwrap();
        // Area 0: our stub net.
        let ours_a0 = router_lsa(rid, vec![(0x0b0b0b00, 0xffff_ff00, STUB, 4)]);
        r.feed_input(h0, &ospf_lsu_bytes(0x02020202, 0, vec![ours_a0]))
            .unwrap();
        // Area 1: our stub net.
        let ours_a1 = router_lsa(rid, vec![(0x0c0c0c00, 0xffff_ff00, STUB, 6)]);
        r.feed_input(h1, &ospf_lsu_bytes(0x03030303, 1, vec![ours_a1]))
            .unwrap();
        assert_eq!(r.rib_snapshot().len(), 2);

        r.remove_session(h1).unwrap();
        let snap = r.rib_snapshot();
        assert!(
            !snap
                .iter()
                .any(|rt| rt.key.prefix == Prefix::new_v4([12, 12, 12, 0], 24)),
            "area 1 routes must withdraw with the last session"
        );
        assert!(
            snap.iter()
                .any(|rt| rt.key.prefix == Prefix::new_v4([11, 11, 11, 0], 24)),
            "area 0 routes must survive"
        );
    }

    #[test]
    fn ospf_rejects_mismatched_router_id_and_version() {
        let mut r = DefaultRouter::new();
        let _h = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(0x01010101), 0))
            .unwrap();
        assert!(
            r.add_session(SessionConfig::ospfv2(RouterId::from_u32(0x02020202), 1))
                .is_err(),
            "a second OSPF router ID must be rejected"
        );
        // v3 into the same area as v2 must be rejected.
        let mut v3_cfg = SessionConfig::ospfv2(RouterId::from_u32(0x01010101), 0);
        v3_cfg.kind = crate::session::SessionKind::Ospfv3;
        assert!(
            r.add_session(v3_cfg).is_err(),
            "OSPFv3 must not mix into a v2 area"
        );
    }

    #[test]
    fn add_and_remove_bgp_session() {
        let mut r = DefaultRouter::new();
        let h = r
            .add_session(SessionConfig::bgp(
                Asn(64512),
                Asn(64513),
                RouterId::from_v4([10, 0, 0, 1]),
            ))
            .unwrap();
        assert_eq!(h.0, 1);
        assert!(r.remove_session(h).is_ok());
    }

    #[test]
    fn tick_drives_timers() {
        let mut r = DefaultRouter::new();
        let _h = r
            .add_session(SessionConfig::bgp(
                Asn(64512),
                Asn(64513),
                RouterId::from_v4([10, 0, 0, 1]),
            ))
            .unwrap();
        r.timers.arm(Instant(0), TimerId(7), TimerSpec::once(100));
        r.tick(Instant(50));
        r.tick(Instant(100));
    }

    #[test]
    fn timer_encoding_roundtrips() {
        let t = encode_timer(42, TimerId(3));
        assert_eq!(decode_timer(t), (42, 3));
    }

    #[test]
    fn originate_fills_rib() {
        let mut r = DefaultRouter::new();
        let key = r.originate(Prefix::new_v4([203, 0, 113, 0], 24), None);
        assert_eq!(r.rib_len(), 1);
        r.unoriginate(&key);
        assert_eq!(r.rib_len(), 0);
    }

    #[test]
    fn mrai_batches_prefix_reannouncements() {
        let mut a = DefaultRouter::new();
        let mut b = DefaultRouter::new();
        let a_session = a
            .add_session(
                SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                    .with_mrai_ms(100),
            )
            .unwrap();
        let b_session = b
            .add_session(SessionConfig::bgp(
                Asn(64513),
                Asn(64512),
                RouterId::from_v4([10, 0, 0, 2]),
            ))
            .unwrap();
        a.start_session(a_session).unwrap();
        b.start_session(b_session).unwrap();
        let a_open = a.drain_output(a_session);
        let b_open = b.drain_output(b_session);
        a.feed_input(a_session, &b_open).unwrap();
        b.feed_input(b_session, &a_open).unwrap();
        let a_keepalive = a.drain_output(a_session);
        let b_keepalive = b.drain_output(b_session);
        a.feed_input(a_session, &b_keepalive).unwrap();
        b.feed_input(b_session, &a_keepalive).unwrap();

        let key = a.originate(
            Prefix::new_v4([203, 0, 113, 0], 24),
            Some(IpAddr::V4([192, 0, 2, 1])),
        );
        let advertisement = a.drain_output(a_session);
        assert!(!advertisement.is_empty());
        b.feed_input(b_session, &advertisement).unwrap();
        assert_eq!(b.rib_len(), 1);

        // Re-origination changes the path and would normally advertise an
        // UPDATE immediately; MRAI holds it until the 100 ms boundary.
        a.unoriginate(&key);
        let withdrawal = a.drain_output(a_session);
        assert!(!withdrawal.is_empty(), "withdrawals bypass MRAI");
        b.feed_input(b_session, &withdrawal).unwrap();
        let _replacement = a.originate(
            Prefix::new_v4([203, 0, 113, 0], 24),
            Some(IpAddr::V4([192, 0, 2, 2])),
        );
        assert!(a.drain_output(a_session).is_empty());
        a.tick(Instant(99));
        assert!(a.drain_output(a_session).is_empty());
        a.tick(Instant(100));
        let replacement = a.drain_output(a_session);
        assert!(!replacement.is_empty());
        b.feed_input(b_session, &replacement).unwrap();
        assert_eq!(b.rib_len(), 1);
    }

    #[test]
    fn route_refresh_reannounces_current_family() {
        let mut a = DefaultRouter::new();
        let mut b = DefaultRouter::new();
        let a_session = a
            .add_session(SessionConfig::bgp(
                Asn(64512),
                Asn(64513),
                RouterId::from_v4([10, 0, 0, 1]),
            ))
            .unwrap();
        let b_session = b
            .add_session(SessionConfig::bgp(
                Asn(64513),
                Asn(64512),
                RouterId::from_v4([10, 0, 0, 2]),
            ))
            .unwrap();
        a.start_session(a_session).unwrap();
        b.start_session(b_session).unwrap();
        let a_open = a.drain_output(a_session);
        let b_open = b.drain_output(b_session);
        a.feed_input(a_session, &b_open).unwrap();
        b.feed_input(b_session, &a_open).unwrap();
        let a_keepalive = a.drain_output(a_session);
        let b_keepalive = b.drain_output(b_session);
        a.feed_input(a_session, &b_keepalive).unwrap();
        b.feed_input(b_session, &a_keepalive).unwrap();

        a.originate(
            Prefix::new_v4([203, 0, 113, 0], 24),
            Some(IpAddr::V4([192, 0, 2, 1])),
        );
        let initial_advertisement = a.drain_output(a_session);
        b.feed_input(b_session, &initial_advertisement).unwrap();
        assert_eq!(b.rib_len(), 1);

        assert!(b.request_route_refresh(b_session, NlriFamily::IPV4_UNICAST));
        let request = b.drain_output(b_session);
        a.feed_input(a_session, &request).unwrap();
        let refreshed = a.drain_output(a_session);
        assert!(!refreshed.is_empty());
        b.feed_input(b_session, &refreshed).unwrap();
        assert_eq!(b.rib_len(), 1);
    }

    // ===== RFC 4724 + RFC 9494 retention tests =====

    fn establish(
        a: &mut DefaultRouter,
        a_session: SessionHandle,
        b: &mut DefaultRouter,
        b_session: SessionHandle,
    ) {
        a.start_session(a_session).unwrap();
        b.start_session(b_session).unwrap();
        let a_open = a.drain_output(a_session);
        let b_open = b.drain_output(b_session);
        a.feed_input(a_session, &b_open).unwrap();
        b.feed_input(b_session, &a_open).unwrap();
        let a_keepalive = a.drain_output(a_session);
        let b_keepalive = b.drain_output(b_session);
        a.feed_input(a_session, &b_keepalive).unwrap();
        b.feed_input(b_session, &a_keepalive).unwrap();
    }

    /// Wire B's Loc-RIB into A: originate on B, pump the UPDATE across.
    fn b_advertise_to_a(
        a: &mut DefaultRouter,
        a_session: SessionHandle,
        b: &mut DefaultRouter,
        b_session: SessionHandle,
    ) {
        b.originate(
            Prefix::new_v4([198, 51, 100, 0], 24),
            Some(IpAddr::V4([192, 0, 2, 10])),
        );
        let advertisement = b.drain_output(b_session);
        assert!(!advertisement.is_empty());
        a.feed_input(a_session, &advertisement).unwrap();
        assert_eq!(a.rib_len(), 1);
    }

    fn llgr_pair() -> (DefaultRouter, SessionHandle, DefaultRouter, SessionHandle) {
        let mut a = DefaultRouter::new();
        let mut b = DefaultRouter::new();
        let a_session = a
            .add_session(
                SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(1)
                    .with_long_lived_gr(10),
            )
            .unwrap();
        // B advertises LLST 20 s: A must retain B's routes for
        // restart (1 s) + LLST (20 s) per RFC 9494 §4.2.
        let b_session = b
            .add_session(
                SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(1)
                    .with_long_lived_gr(20),
            )
            .unwrap();
        (a, a_session, b, b_session)
    }

    fn best_has_llgr_stale(a: &DefaultRouter) -> bool {
        let snap = a.rib_snapshot();
        assert_eq!(snap.len(), 1);
        let attrs: PathAttributes = snap[0].attributes.clone().into();
        attrs.has_community(Community::LLGR_STALE)
    }

    /// RFC 4724: routes are retained for the restart window and purged
    /// when it expires (no LLGR negotiated).
    #[test]
    fn plain_gr_retains_then_purges() {
        let mut a = DefaultRouter::new();
        let mut b = DefaultRouter::new();
        let a_session = a
            .add_session(
                SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(1),
            )
            .unwrap();
        let b_session = b
            .add_session(
                SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(1),
            )
            .unwrap();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);

        a.tick(Instant(0));
        a.close_session(a_session);
        a.tick(Instant(500));
        assert_eq!(a.rib_len(), 1, "still inside the restart window");
        a.tick(Instant(1_500));
        assert_eq!(a.rib_len(), 0, "restart window expired — purge");
    }

    /// RFC 9494 §4.2: after the restart window the routes are marked
    /// LLGR_STALE and retained for the negotiated long-lived stale time.
    #[test]
    fn llgr_marks_stale_then_purges_at_llst_expiry() {
        let (mut a, a_session, mut b, b_session) = llgr_pair();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);

        a.tick(Instant(0));
        a.close_session(a_session);
        a.tick(Instant(500));
        assert_eq!(a.rib_len(), 1, "retained inside the restart window");
        assert!(!best_has_llgr_stale(&a), "not yet long-lived stale");

        // Restart window (1 s) elapses → LLGR period begins.
        a.tick(Instant(1_500));
        assert_eq!(a.rib_len(), 1, "LLGR retains the route");
        assert!(best_has_llgr_stale(&a), "marked LLGR_STALE");

        // LLST (20 s after the restart window) not yet over.
        a.tick(Instant(20_999));
        assert_eq!(a.rib_len(), 1);

        a.tick(Instant(21_000));
        assert_eq!(a.rib_len(), 0, "long-lived stale time expired — purge");
    }

    /// RFC 9494 §4.2: when the session re-establishes and resends its
    /// table (EoR received), the routes are refreshed and outlive the
    /// original LLST deadline.
    #[test]
    fn llgr_reestablishment_with_eor_refreshes_routes() {
        let (mut a, a_session, mut b, b_session) = llgr_pair();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);

        a.tick(Instant(0));
        a.close_session(a_session);
        a.tick(Instant(1_500)); // enter LLGR stale period
        assert!(best_has_llgr_stale(&a));

        // B restarts and re-advertises everything (initial dump + EoR).
        establish(&mut a, a_session, &mut b, b_session);
        let b_dump = b.drain_output(b_session);
        assert!(!b_dump.is_empty());
        a.feed_input(a_session, &b_dump).unwrap();
        assert_eq!(a.rib_len(), 1);
        assert!(
            !best_has_llgr_stale(&a),
            "fresh route replaced the stale one"
        );

        // Well past the original LLST deadline: nothing may be purged
        // because synchronization completed at EoR.
        a.tick(Instant(60_000));
        assert_eq!(a.rib_len(), 1, "refreshed routes survive past LLST");
    }

    /// RFC 4724 §4.1 / RFC 9494 §4.2: at EoR, stale routes the peer did
    /// not re-advertise are deleted.
    #[test]
    fn llgr_eor_purges_unrefreshed_routes() {
        let (mut a, a_session, mut b, b_session) = llgr_pair();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);
        let key = RouteKey::new(
            Prefix::new_v4([198, 51, 100, 0], 24),
            NlriFamily::IPV4_UNICAST,
        );

        a.tick(Instant(0));
        a.close_session(a_session);
        a.tick(Instant(1_500)); // LLGR stale period

        // B no longer originates the prefix when it comes back.
        b.unoriginate(&key);
        establish(&mut a, a_session, &mut b, b_session);
        let b_dump = b.drain_output(b_session);
        a.feed_input(a_session, &b_dump).unwrap();
        assert_eq!(
            a.rib_len(),
            0,
            "EoR arrived without a refresh — stale route purged"
        );
    }

    /// RFC 9494 §4.2: routes marked NO_LLGR are not retained.
    #[test]
    fn llgr_no_llgr_routes_are_dropped() {
        struct TagNoLlgr;
        impl lr_policy::hooks::ImportHook for TagNoLlgr {
            fn on_import(&self, route: &mut Route) -> lr_policy::hooks::HookVerdict {
                let mut attrs: PathAttributes = route.attributes.clone().into();
                attrs.insert_community(Community::NO_LLGR);
                route.attributes = attrs.into();
                lr_policy::hooks::HookVerdict::Keep
            }
        }
        let (mut a, a_session, mut b, b_session) = llgr_pair();
        a.hooks_mut().import.push(Box::new(TagNoLlgr));
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);

        a.tick(Instant(0));
        a.close_session(a_session);
        a.tick(Instant(500));
        assert_eq!(a.rib_len(), 1, "retained inside the restart window");
        a.tick(Instant(1_500));
        assert_eq!(
            a.rib_len(),
            0,
            "NO_LLGR routes must not survive into the LLGR period"
        );
    }

    /// RFC 9494 §4.2: a locally configured cap limits the received LLST.
    #[test]
    fn llgr_local_cap_limits_received_stale_time() {
        let mut a = DefaultRouter::new();
        let mut b = DefaultRouter::new();
        let a_session = a
            .add_session(
                SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(1)
                    .with_long_lived_gr(10)
                    .with_llgr_max_stale_time(5),
            )
            .unwrap();
        let b_session = b
            .add_session(
                SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(1)
                    .with_long_lived_gr(20), // peer proposes 20 s
            )
            .unwrap();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);

        a.tick(Instant(0));
        a.close_session(a_session);
        a.tick(Instant(1_500));
        assert_eq!(a.rib_len(), 1, "LLGR period, still retained");
        // 1 s restart + 5 s capped LLST = 6 s deadline; 20 s would be
        // the un-capped expiry.
        a.tick(Instant(6_000));
        assert_eq!(a.rib_len(), 0, "capped LLST expired the retention early");
    }

    /// RFC 4724 §4.2: when the session re-establishes *before* the restart
    /// window elapses and re-advertises its routes, expiry of the (now
    /// moot) restart timer must NOT purge the fresh routes.
    #[test]
    fn fast_reestablishment_survives_restart_window_expiry() {
        let (mut a, a_session, mut b, b_session) = llgr_pair();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);

        a.tick(Instant(0));
        a.close_session(a_session);
        // Re-establish immediately and refresh the route.
        establish(&mut a, a_session, &mut b, b_session);
        let b_dump = b.drain_output(b_session);
        a.feed_input(a_session, &b_dump).unwrap();
        assert_eq!(a.rib_len(), 1);

        // Long past the 1 s restart window (and past the 20 s LLST): the
        // session is up and synchronized, so nothing may be purged.
        a.tick(Instant(30_000));
        assert_eq!(a.rib_len(), 1, "resynchronized routes survive expiry");
    }

    /// LLGR variant: the LLST timer keeps running across re-establishment
    /// (RFC 9494 §4.2) but only removes routes the peer did not refresh.
    #[test]
    fn llgr_timer_runs_during_resync_but_spares_refreshed_routes() {
        let (mut a, a_session, mut b, b_session) = llgr_pair();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);
        let key = RouteKey::new(
            Prefix::new_v4([198, 51, 100, 0], 24),
            NlriFamily::IPV4_UNICAST,
        );

        a.tick(Instant(0));
        a.close_session(a_session);
        // Enter the LLGR stale period while still down.
        a.tick(Instant(1_500));
        assert_eq!(a.rib_len(), 1);

        // B comes back but no longer originates the prefix; the session
        // re-establishes without refreshing the stale route.
        b.unoriginate(&key);
        establish(&mut a, a_session, &mut b, b_session);
        let b_dump = b.drain_output(b_session);
        a.feed_input(a_session, &b_dump).unwrap();

        // LLST deadline (1 s restart + 20 s LLST) passes while the session
        // is up: the unrefreshed stale route must go.
        a.tick(Instant(21_500));
        assert_eq!(
            a.rib_len(),
            0,
            "LLST expiry during resync removes unrefreshed stale routes"
        );
    }

    #[test]
    fn session_summaries_track_bgp_lifecycle() {
        // A plain (no-GR) pair: session loss must purge the Adj-RIB-In
        // immediately, which the summary counter reflects.
        let mut a = DefaultRouter::new();
        let mut b = DefaultRouter::new();
        let a_session = a
            .add_session(
                SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                    .with_graceful_restart(0),
            )
            .unwrap();
        let b_session = b
            .add_session(
                SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                    .with_graceful_restart(0),
            )
            .unwrap();

        // Pre-start: configured but idle.
        let s = a.session_summaries();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].handle, a_session);
        assert_eq!(s[0].kind, "bgp");
        assert_eq!(s[0].state, "Idle");
        assert!(!s[0].established);
        assert_eq!(s[0].local_as, Asn(64512));
        assert_eq!(s[0].peer_as, Asn(64513));
        assert_eq!(s[0].peer_bgp_id, None);
        assert_eq!(s[0].adj_rib_in_len, 0);

        // Post-handshake: established, peer identity + hold time known.
        establish(&mut a, a_session, &mut b, b_session);
        let s = a.session_summaries();
        assert_eq!(s[0].state, "Established");
        assert!(s[0].established);
        assert_eq!(s[0].peer_bgp_id, Some(RouterId::from_v4([10, 0, 0, 2])));
        assert!(s[0].negotiated_hold_time > 0);

        // Adj-RIB-In counter follows the peer's advertisements.
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);
        let s = a.session_summaries();
        assert_eq!(s[0].adj_rib_in_len, 1);

        // Session loss flips the summary back to Idle and purges the RIB.
        a.close_session(a_session);
        a.tick(Instant(0));
        let s = a.session_summaries();
        assert_eq!(s[0].state, "Idle");
        assert!(!s[0].established);
        assert_eq!(s[0].adj_rib_in_len, 0);
    }

    #[test]
    fn session_summaries_list_multiple_sessions_in_order() {
        let mut r = DefaultRouter::new();
        r.add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 1]),
        ))
        .unwrap();
        r.add_session(SessionConfig::ospfv2(RouterId::from_u32(0x01020304), 0))
            .unwrap();
        r.add_session(SessionConfig::babel(IpAddr::V4([192, 0, 2, 1])))
            .unwrap();

        let s = r.session_summaries();
        assert_eq!(s.len(), 3);
        // Ordered by handle.
        assert_eq!(s[0].handle, SessionHandle(1));
        assert_eq!(s[0].kind, "bgp");
        assert_eq!(s[1].handle, SessionHandle(2));
        assert_eq!(s[1].kind, "ospf");
        assert_eq!(s[1].state, "Down");
        assert_eq!(s[2].handle, SessionHandle(3));
        assert_eq!(s[2].kind, "babel");
        assert_eq!(s[2].state, "Down");
        assert!(!s.iter().any(|x| x.established));
    }
}
