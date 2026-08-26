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
use crate::session::{SessionConfig, SessionHandle, SessionKind};

use lr_core::addr::{IpAddr, Prefix, RouterId};
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
}

/// Per-session protocol runtime.
enum SessionState {
    Bgp {
        peer: BgpPeer,
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
/// The latest desired route supersedes any older pending advertisement. A
/// `None` route represents a withdrawal, allowing route churn to collapse to
/// one wire UPDATE at MRAI expiry.
#[derive(Debug, Clone)]
struct PendingMraiUpdate {
    route: Option<Route>,
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
    refreshed: BTreeSet<RouteKey>,
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

/// OSPF protocol runtime for one adjacency: neighbor FSM + LSDB view + SPF.
///
/// This is a simplified but functional driver: Hellos advance the neighbor
/// FSM, LS-Updates populate the LSDB, and every LSDB change re-runs SPF. The
/// resulting intra-area routes land in the router's Loc-RIB. Full DBD/LSR
/// exchange sequencing is the embedder's job to extend (the FSM states are
/// all exposed).
struct OspfRuntime {
    router_id: u32,
    #[allow(dead_code)] // reserved for ABR / inter-area routing
    area_id: u32,
    neighbor: OspfNeighbor,
    lsdb: Lsdb,
    /// Protocol origin tag used when installing routes.
    protocol: Protocol,
    /// Routes previously published to Loc-RIB — used to compute deltas.
    published: BTreeMap<RouteKey, Route>,
}

impl OspfRuntime {
    fn new(router_id: u32, area_id: u32, v3: bool) -> Self {
        Self {
            router_id,
            area_id,
            neighbor: OspfNeighbor::new(RouterId::from_u32(router_id)),
            lsdb: Lsdb::new(),
            protocol: if v3 {
                Protocol::Ospfv3
            } else {
                Protocol::Ospfv2
            },
            published: BTreeMap::new(),
        }
    }

    /// Refresh locally originated LSAs and construct an LSU for flooding.
    fn refresh_due(&mut self, now_ms: u64) -> Option<OspfPacket> {
        let lsas = self.lsdb.refresh_due(self.router_id, now_ms);
        (!lsas.is_empty()).then(|| OspfPacket {
            header: OspfHeader {
                version: if self.protocol == Protocol::Ospfv3 {
                    OspfVersion::V3 as u8
                } else {
                    OspfVersion::V2 as u8
                },
                kind: OspfPacketType::LinkStateUpdate as u8,
                length: 0,
                router_id: self.router_id,
                area_id: self.area_id,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::LsUpdate(LsUpdateBody {
                lsa_count: lsas.len() as u32,
                lsas,
            }),
        })
    }

    /// Age received LSAs and recompute if expiry changes the topology.
    fn age_out(&mut self, now_ms: u64) -> RuntimeDelta {
        if self.lsdb.age_out(now_ms).is_empty() {
            RuntimeDelta {
                installed: Vec::new(),
                withdrawn: Vec::new(),
            }
        } else {
            self.recompute()
        }
    }

    /// Feed one decoded OSPF packet; returns the Loc-RIB delta.
    fn handle_packet(&mut self, pkt: &OspfPacket, now_ms: u64) -> RuntimeDelta {
        let mut changed = false;
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
                    return RuntimeDelta {
                        installed: Vec::new(),
                        withdrawn: Vec::new(),
                    };
                };
                let _ = self.neighbor.step(ev);
                // Simplified adjacency bring-up: proceed to ExStart on 2-Way.
                if self.neighbor.state == NeighborState::TwoWay {
                    let _ = self.neighbor.step(NeighborEvent::AdjOk { proceed: true });
                    let _ = self.neighbor.step(NeighborEvent::NegotiationDone);
                    let _ = self.neighbor.step(NeighborEvent::ExchangeDone);
                    let _ = self.neighbor.step(NeighborEvent::LsaUpdateArrived);
                }
            }
            OspfBody::LsUpdate(u) => {
                for lsa in &u.lsas {
                    self.lsdb.install(lsa.clone(), now_ms);
                    changed = true;
                }
            }
            _ => {}
        }
        if changed {
            self.recompute()
        } else {
            RuntimeDelta {
                installed: Vec::new(),
                withdrawn: Vec::new(),
            }
        }
    }

    /// Run SPF over the LSDB and diff against the published set.
    fn recompute(&mut self) -> RuntimeDelta {
        let current: BTreeMap<RouteKey, Route> = self
            .compute_routes()
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

    /// Run SPF over the LSDB and return the resulting intra-area routes.
    fn compute_routes(&mut self) -> Vec<Route> {
        let result = spf::run_spf(&self.lsdb, self.router_id);
        let mut routes = Vec::new();
        let mut push = |prefix: Prefix, metric: u64, next_hop: Option<IpAddr>| {
            routes.push(Route {
                key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
                origin: RouteOrigin {
                    proto: 3, // OSPF adjacency tag
                    peer: u64::from(self.neighbor.router_id.as_u32()),
                },
                protocol: self.protocol,
                preference: lr_core::rib::Preference::new(
                    self.protocol.default_admin_distance(),
                    metric as u32,
                ),
                next_hop,
                attributes: lr_core::attr::Attributes::new(),
                age_ms: 0,
            });
        };
        for r in result
            .stub_routes
            .iter()
            .chain(result.transit_routes.iter())
        {
            push(r.prefix, r.metric, r.next_hop);
        }
        routes
    }
}

/// Babel protocol runtime for one adjacency: neighbor table + route table.
struct BabelRuntime {
    neighbor: BabelNeighbor,
    routes: BabelRouteTable,
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
    /// Locally originated routes (kept so unoriginate can remove them).
    originated: BTreeMap<RouteKey, Route>,
    pending_events: Vec<RouterEvent>,
    /// Decoders for connectionless protocols (OSPF/Babel) keyed by session.
    ospf_codec: lr_ospf::codec::OspfCodec,
    babel_codec: BabelCodec,
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
            originated: BTreeMap::new(),
            pending_events: Vec::new(),
            ospf_codec: lr_ospf::codec::OspfCodec::v2(),
            babel_codec: BabelCodec::new(),
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
        };
        self.loc_rib.install(route.clone());
        self.originated.insert(key.clone(), route.clone());
        self.pending_events
            .push(RouterEvent::RouteInstalled(route.clone()));
        self.export_route(&route);
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
            state.refreshed.insert(key.clone());
        }
        self.adj_rib_in.feed_pre_policy(origin, route);
        self.reselect(&key);
    }

    fn withdraw_from_session(&mut self, origin: RouteOrigin, key: &RouteKey) {
        if self.adj_rib_in.withdraw(origin, key).is_some() {
            self.reselect(key);
        }
    }

    /// Re-run the decision process for one prefix and propagate deltas.
    fn reselect(&mut self, key: &RouteKey) {
        let candidates: Vec<Route> = self
            .adj_rib_in
            .iter_all()
            .filter(|r| &r.key == key)
            .cloned()
            .chain(self.originated.values().filter(|r| r.key == *key).cloned())
            .collect();

        let new_best: Option<Route> = if candidates.is_empty() {
            None
        } else if candidates.iter().all(|r| r.protocol == Protocol::Bgp) {
            BestPath::select(&candidates, &self.best_path_cfg).cloned()
        } else {
            RouteSelector::select(&candidates).cloned()
        };

        let old_best = self.loc_rib.best(key).cloned();
        match (new_best, old_best) {
            (Some(nb), Some(ob)) if nb == ob => {}
            (Some(nb), _) => {
                self.loc_rib.install(nb.clone());
                self.pending_events
                    .push(RouterEvent::RouteInstalled(nb.clone()));
                self.export_route(&nb);
            }
            (None, Some(_)) => {
                self.loc_rib.uninstall(key);
                self.pending_events
                    .push(RouterEvent::RouteWithdrawn(key.clone()));
                self.propagate_withdrawal(key);
            }
            (None, None) => {}
        }
    }

    // ----- export pipeline -----

    /// Queue an UPDATE until the per-prefix MRAI expires, or transmit it
    /// immediately when the prefix has no active interval.
    fn queue_or_send_advertisement(&mut self, session: u64, route: Route) {
        let key = route.key.clone();
        let now_ms = self.now_ms;
        let state = self.mrai.entry(session).or_default();
        if state.interval_ms != 0 {
            if let Some(last) = state.last_sent.get(&key) {
                let due_ms = last.saturating_add(state.interval_ms);
                if now_ms < due_ms {
                    state.pending.insert(
                        key,
                        PendingMraiUpdate {
                            route: Some(route),
                            due_ms,
                        },
                    );
                    return;
                }
            }
        }
        self.send_advertisement(session, route);
    }

    fn send_advertisement(&mut self, session: u64, route: Route) {
        let sent =
            if let Some(SessionState::Bgp { peer, conn, .. }) = self.sessions.get_mut(&session) {
                let sent = peer.advertise(&route);
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
                .insert(route.key.clone(), self.now_ms);
            self.adj_rib_out.advertise(
                RouteOrigin {
                    proto: 0,
                    peer: session,
                },
                &route,
            );
            self.pending_events
                .push(RouterEvent::PrefixAdvertised(route.key.prefix));
        }
    }

    fn export_route(&mut self, route: &Route) {
        // Hooks borrow self immutably while session enumeration requires a
        // mutable borrow, so collect policy-approved work before transmitting.
        let hooks = std::mem::take(&mut self.hooks);
        let origin_session = route.origin.peer;
        let mut exports = Vec::new();
        for (session, state) in &self.sessions {
            let SessionState::Bgp { peer, .. } = state else {
                continue;
            };
            if *session == origin_session || !peer.is_established() {
                continue;
            }
            let mut candidate = route.clone();
            if !matches!(hooks.run_export(&mut candidate), HookVerdict::Drop) {
                exports.push((*session, candidate));
            }
        }
        self.hooks = hooks;
        for (session, route) in exports {
            self.queue_or_send_advertisement(session, route);
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
        let prior: Vec<RouteKey> = self
            .adj_rib_out
            .iter_for(origin)
            .filter(|route| route.key.family == family)
            .map(|route| route.key.clone())
            .collect();
        let snapshot: Vec<Route> = self
            .loc_rib
            .iter_best()
            .filter(|route| route.key.family == family && route.origin.peer != session)
            .cloned()
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
            for key in &prior {
                peer.withdraw(&[key.prefix], family);
                self.adj_rib_out.suppress(origin, key);
            }
            for route in snapshot {
                let mut route = route;
                if matches!(hooks.run_export(&mut route), HookVerdict::Drop) {
                    continue;
                }
                if peer.advertise(&route) {
                    advertised.push(route);
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
            self.adj_rib_out.advertise(origin, &route);
            self.pending_events
                .push(RouterEvent::PrefixAdvertised(route.key.prefix));
        }
    }

    fn queue_or_send_withdrawal(&mut self, session: u64, key: RouteKey) {
        // RFC 4271 §9.2.1.1 applies MRAI to advertisements. A withdrawal is
        // sent immediately so remote routers stop forwarding to an invalid
        // path without waiting for the advertisement rate limiter.
        if let Some(state) = self.mrai.get_mut(&session) {
            state.pending.remove(&key);
        }
        self.send_withdrawal(session, key);
    }

    fn send_withdrawal(&mut self, session: u64, key: RouteKey) {
        let sent =
            if let Some(SessionState::Bgp { peer, conn, .. }) = self.sessions.get_mut(&session) {
                peer.withdraw(&[key.prefix], key.family);
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
            self.adj_rib_out.suppress(
                RouteOrigin {
                    proto: 0,
                    peer: session,
                },
                &key,
            );
            self.pending_events
                .push(RouterEvent::PrefixRetracted(key.prefix));
        }
    }

    fn flush_mrai(&mut self) {
        let due: Vec<(u64, RouteKey, Option<Route>)> = self
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
                        .map(|update| (*session, key, update.route))
                })
            })
            .collect();
        for (session, key, route) in due {
            if let Some(route) = route {
                self.send_advertisement(session, route);
            } else {
                self.send_withdrawal(session, key);
            }
        }
    }

    fn propagate_withdrawal(&mut self, key: &RouteKey) {
        let sessions: Vec<u64> = self
            .sessions
            .iter()
            .filter_map(|(session, state)| {
                matches!(state, SessionState::Bgp { peer, .. } if peer.is_established())
                    .then_some(*session)
            })
            .filter(|session| {
                self.adj_rib_out
                    .iter_for(RouteOrigin {
                        proto: 0,
                        peer: *session,
                    })
                    .any(|route| route.key == *key)
            })
            .collect();
        for session in sessions {
            self.queue_or_send_withdrawal(session, key.clone());
        }
    }

    /// When a BGP session first reaches Established, advertise the whole
    /// Loc-RIB to it (initial table dump).
    fn on_bgp_established(&mut self, h: u64) {
        let snapshot: Vec<Route> = self.loc_rib.iter_best().cloned().collect();
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
                .advertise(RouteOrigin { proto: 0, peer: h }, &r);
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
                BgpAction::WithdrawRoute(k) => {
                    // Withdrawals carry the origin implicitly: the session
                    // that reports them is the origin.
                    let origin = RouteOrigin {
                        proto: 0,
                        peer: session,
                    };
                    self.withdraw_from_session(origin, &k);
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
        refreshed: &BTreeSet<RouteKey>,
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
                    .filter(|r| !refreshed.contains(&r.key))
                    .map(|r| r.key.clone()),
            );
            self.adj_rib_in.mutate_origin(origin, |mut route| {
                if refreshed.contains(&route.key) {
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
            .filter(|session| {
                self.adj_rib_out
                    .iter_for(RouteOrigin {
                        proto: 0,
                        peer: *session,
                    })
                    .any(|route| route.key == *key)
            })
            .collect();
        for session in sessions {
            self.queue_or_send_withdrawal(session, key.clone());
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
        refreshed: &BTreeSet<RouteKey>,
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
            let stale_keys: Vec<RouteKey> = self
                .adj_rib_in
                .iter_origin(origin)
                .filter(|r| r.key.family == family && !refreshed.contains(&r.key))
                .map(|r| r.key.clone())
                .collect();
            purged += stale_keys.len();
            for key in stale_keys {
                self.adj_rib_in.withdraw(origin, &key);
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
                        peer,
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
                let runtime = OspfRuntime::new(
                    cfg.local_bgp_id.as_u32(),
                    cfg.area_id,
                    cfg.kind == SessionKind::Ospfv3,
                );
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
        if self.sessions.remove(&h.0).is_none() {
            return Err(format!("session {} not found", h.0));
        }
        self.mrai.remove(&h.0);
        self.graceful_restart.remove(&h.0);
        // Remove every route that session contributed and re-select.
        let keys: Vec<RouteKey> = self
            .adj_rib_in
            .iter_all()
            .filter(|r| r.origin.peer == h.0)
            .map(|r| r.key.clone())
            .collect();
        for k in keys {
            self.withdraw_from_session(
                RouteOrigin {
                    proto: 0,
                    peer: h.0,
                },
                &k,
            );
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
                    let mut delta = RuntimeDelta {
                        installed: Vec::new(),
                        withdrawn: Vec::new(),
                    };
                    let mut r = lr_core::buf::ReadBuf::new(&input);
                    while let Ok(Some(pkt)) = self.ospf_codec.decode(&mut r) {
                        let d = runtime.handle_packet(&pkt, self.now_ms);
                        delta.installed.extend(d.installed);
                        delta.withdrawn.extend(d.withdrawn);
                    }
                    Pending::Other { delta }
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
                    while let Ok(Some(frame)) = self.babel_codec.decode(&mut r) {
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
                // OSPF/Babel routes land directly in Loc-RIB (their egress
                // is protocol-internal flooding, not BGP advertisement).
                for route in delta.installed {
                    self.loc_rib.install(route.clone());
                    self.pending_events.push(RouterEvent::RouteInstalled(route));
                }
                for key in delta.withdrawn {
                    self.loc_rib.uninstall(&key);
                    self.pending_events.push(RouterEvent::RouteWithdrawn(key));
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
        let mut ospf_deltas = Vec::new();
        for state in self.sessions.values_mut() {
            let SessionState::Ospf { runtime, conn } = state else {
                continue;
            };
            if let Some(packet) = runtime.refresh_due(self.now_ms) {
                let codec = match runtime.protocol {
                    Protocol::Ospfv3 => lr_ospf::codec::OspfCodec::v3(),
                    _ => lr_ospf::codec::OspfCodec::v2(),
                };
                if let Ok(bytes) = codec.encode_vec(&packet) {
                    conn.put_output(&bytes);
                }
            }
            ospf_deltas.push(runtime.age_out(self.now_ms));
        }
        for delta in ospf_deltas {
            for route in delta.installed {
                self.loc_rib.install(route.clone());
                self.pending_events.push(RouterEvent::RouteInstalled(route));
            }
            for key in delta.withdrawn {
                self.loc_rib.uninstall(&key);
                self.pending_events.push(RouterEvent::RouteWithdrawn(key));
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
            let pending: Vec<(RouteKey, Option<Route>)> = state
                .pending
                .iter()
                .map(|(key, update)| (key.clone(), update.route.clone()))
                .collect();
            state.pending.clear();
            for (key, route) in pending {
                if let Some(route) = route {
                    self.send_advertisement(h.0, route);
                } else {
                    self.send_withdrawal(h.0, key);
                }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Asn;
    use lr_core::fsm::TimerSpec;

    #[test]
    fn ospf_self_lsa_refresh_emits_new_lsu() {
        let mut runtime = OspfRuntime::new(0x01020304, 0, false);
        let lsa = lr_ospf::lsa::Lsa {
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
        runtime.lsdb.install(lsa, 0);
        assert!(runtime.refresh_due(1_799_999).is_none());
        let packet = runtime.refresh_due(1_800_000).expect("LSU refresh");
        let OspfBody::LsUpdate(update) = packet.body else {
            panic!("expected LS Update");
        };
        assert_eq!(update.lsa_count, 1);
        assert_eq!(update.lsas[0].header.ls_sequence_number, 0x80000002);
        assert_eq!(update.lsas[0].header.ls_age, 0);
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
}
