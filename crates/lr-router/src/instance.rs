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
use crate::session::{OspfAreaType, SessionConfig, SessionHandle, SessionKind, SessionSummary};

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
use lr_ospf::external::{
    external_routes, flush_external_lsa, originate_external_lsa, originate_summary_asbr_lsa,
    ExternalDestination, ExternalMetricType,
};
use lr_ospf::lsa::{prefix_len_to_mask, Lsa, LsaTypeV2};
use lr_ospf::lsdb::Lsdb;
use lr_ospf::neighbor::{NeighborEvent, NeighborState, OspfNeighbor};
use lr_ospf::nssa::{
    flush_nssa_lsa, is_elected_translator, nssa_routes, originate_nssa_default_lsa,
    originate_nssa_lsa, NssaCalcOpts, NssaDefault, N_P_BIT,
};
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
    /// RFC 2328 §7.2 database synchronization driver: DBD negotiation,
    /// header exchange and LS-Request loading up to Full.
    exchange: lr_ospf::exchange::DbExchange,
}

/// One configured virtual link (RFC 2328 §15): a backbone adjacency
/// between two area border routers, riding through `transit_area`.
#[derive(Debug, Clone, Copy)]
struct OspfVirtualLink {
    /// The backbone session materialized while the link is up. Its
    /// transport is the embedder's responsibility (tunnel the drained
    /// bytes through the transit area to the peer's virtual session).
    session: Option<SessionHandle>,
}

/// Per-area OSPF state shared by every session attached to that area.
struct OspfAreaState {
    lsdb: Lsdb,
    /// Protocol version the area runs (v2 and v3 cannot mix in one area).
    protocol: Protocol,
    /// Area type policy — stub/NSSA gating of LSA flooding and the
    /// border-router default injection (RFC 2328 §3.6, RFC 3101).
    kind: OspfAreaType,
}

/// Whether an area of type `kind` accepts `lsa` (RFC 2328 §3.6, RFC 3101):
/// stub and NSSA areas refuse type-5 AS-external and type-4 summary-ASBR
/// LSAs; `no_summary` areas refuse every type-3 summary except the
/// default; type-7 LSAs only exist inside NSSAs.
fn ospf_area_accepts(kind: &OspfAreaType, lsa: &Lsa) -> bool {
    match lsa.header.ls_type {
        t if t == LsaTypeV2::AsExternalLsa as u8 || t == LsaTypeV2::SummaryAsbrLsa as u8 => {
            !kind.is_stubby()
        }
        t if t == LsaTypeV2::NssaExternalLsa as u8 => kind.is_nssa(),
        t if t == LsaTypeV2::SummaryIpLsa as u8 => {
            !kind.no_summary() || lsa.header.link_state_id == 0
        }
        _ => true,
    }
}

/// One entry of an area's computed route table: the metric plus how the
/// route was derived. Inter-area entries remember the advertising border
/// router — ABR summary origination must never re-advertise a route whose
/// only justification is the router's own (possibly stale) summary.
/// External entries (RFC 2328 §16.4) keep the ASBR and metric type so the
/// merged table can apply the §11 preference order.
#[derive(Debug, Clone, Copy)]
struct OspfTableEntry {
    metric: u64,
    kind: OspfKind,
}

#[derive(Debug, Clone, Copy)]
enum OspfKind {
    Intra,
    Inter {
        /// Advertising border router of the summary-LSA.
        border_router: u32,
    },
    External {
        metric_type: ExternalMetricType,
        /// Advertising ASBR of the type-5 LSA.
        asbr: u32,
        /// Forwarding address from the type-5 LSA (0 = ASBR itself).
        forwarding_addr: u32,
        /// Internal cost to the ASBR — type-2 tie-breaker (§16.4 (6)).
        internal_cost: u64,
    },
}

impl OspfTableEntry {
    fn intra(metric: u64) -> Self {
        Self {
            metric,
            kind: OspfKind::Intra,
        }
    }

    fn inter(metric: u64, border_router: Option<u32>) -> Self {
        Self {
            metric,
            kind: OspfKind::Inter {
                border_router: border_router.unwrap_or(0),
            },
        }
    }

    fn external(
        metric: u64,
        metric_type: ExternalMetricType,
        asbr: u32,
        forwarding_addr: u32,
        internal_cost: u64,
    ) -> Self {
        Self {
            metric,
            kind: OspfKind::External {
                metric_type,
                asbr,
                forwarding_addr,
                internal_cost,
            },
        }
    }

    fn is_intra(&self) -> bool {
        matches!(self.kind, OspfKind::Intra)
    }

    /// Whether this entry is an inter-area route advertised by
    /// `router_id` (the router's own summary — never a summary source).
    fn is_own_inter(&self, router_id: u32) -> bool {
        matches!(self.kind, OspfKind::Inter { border_router } if border_router == router_id)
    }

    /// §16.2/§16.4 preference order for identical prefixes: intra-area
    /// beats inter-area beats type-1 external beats type-2 external
    /// (RFC 2328 §11); within one class the lower metric wins, and type-2
    /// externals additionally compare the internal cost to the ASBR
    /// (§16.4 (6)) before falling back to a deterministic tie-break.
    fn beats(&self, prev: &Self) -> bool {
        match (self.kind, prev.kind) {
            (OspfKind::Intra, OspfKind::Intra) => self.metric < prev.metric,
            (OspfKind::Intra, _) => true,
            (_, OspfKind::Intra) => false,
            (OspfKind::Inter { .. }, OspfKind::Inter { .. }) => self.metric < prev.metric,
            (OspfKind::Inter { .. }, _) => true,
            (_, OspfKind::Inter { .. }) => false,
            (
                OspfKind::External {
                    metric_type: t_self,
                    internal_cost: c_self,
                    asbr: a_self,
                    ..
                },
                OspfKind::External {
                    metric_type: t_prev,
                    internal_cost: c_prev,
                    asbr: a_prev,
                    ..
                },
            ) => {
                if t_self != t_prev {
                    // Type 1 always beats type 2 (§16.4 (6)).
                    return t_self < t_prev;
                }
                if self.metric != prev.metric {
                    return self.metric < prev.metric;
                }
                if t_self == ExternalMetricType::Type2 && c_self != c_prev {
                    return c_self < c_prev;
                }
                a_self < a_prev
            }
        }
    }
}

impl OspfRuntime {
    fn new(router_id: u32, area_id: u32, v3: bool, iface_mtu: u16) -> Self {
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
            exchange: lr_ospf::exchange::DbExchange::new(router_id, area_id, iface_mtu),
        }
    }

    /// Feed one decoded OSPF packet. Hellos advance the neighbor FSM
    /// and start the DBD exchange on adjacency; DBDs, LS-Requests,
    /// LS-Updates and LS-Acks drive the RFC 2328 §7.2 synchronization.
    fn handle_packet(
        &mut self,
        pkt: &OspfPacket,
        lsdb: &lr_ospf::lsdb::Lsdb,
        now_ms: u64,
    ) -> OspfStep {
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
                    return OspfStep::default();
                };
                let _ = self.neighbor.step(ev);
                // §10.2: 2-Way + adjacency decision → ExStart. ptp
                // segments always adjoint (no DR election yet).
                if self.neighbor.state == NeighborState::TwoWay {
                    let _ = self.neighbor.step(NeighborEvent::AdjOk { proceed: true });
                }
                // Entering ExStart emits the initial DBD (§10.3); after
                // a sequence-mismatch restart the exchange driver
                // already queued a fresh one.
                let mut step = OspfStep::default();
                if self.neighbor.state == NeighborState::ExStart && !self.exchange.started() {
                    let seq = now_ms as u32 ^ self.router_id | 1;
                    step.outbound
                        .push(self.exchange.initial_db_desc(seq, now_ms));
                }
                step
            }
            OspfBody::DbDesc(d) => {
                // A DBD proves the neighbor sees us: RFC 2328 §10.6
                // (via BIRD's INM_2WAYREC) advances Init/2-Way to
                // ExStart before the exchange runs — the peer may have
                // completed 2-Way detection on its side first.
                if self.neighbor.state == NeighborState::Init {
                    let _ = self.neighbor.step(NeighborEvent::HelloSeen {
                        dr: 0,
                        bdr: 0,
                        priority: 1,
                    });
                }
                if self.neighbor.state == NeighborState::TwoWay {
                    let _ = self.neighbor.step(NeighborEvent::AdjOk { proceed: true });
                }
                self.exchange
                    .on_db_desc(d, pkt.header.router_id, lsdb, &mut self.neighbor, now_ms)
                    .into()
            }
            OspfBody::LsRequest(r) => self
                .exchange
                .on_ls_request(r, lsdb, &mut self.neighbor, now_ms)
                .into(),
            OspfBody::LsUpdate(u) => {
                // The exchange driver acks and tracks the request queue;
                // the LSAs flow to the area LSDB via the returned step.
                self.exchange
                    .on_ls_update(&u.lsas, &mut self.neighbor)
                    .into()
            }
            OspfBody::LsAck(_) => {
                // Acknowledgements of our flooded LSAs (§13.7) — the
                // flood path is fire-and-forget; nothing to track yet.
                OspfStep::default()
            }
            _ => OspfStep::default(),
        }
    }
}

/// One OSPF protocol step's output (the router-facing twin of
/// `lr_ospf::exchange::ExchangeStep`).
#[derive(Default)]
struct OspfStep {
    lsas: Vec<Lsa>,
    outbound: Vec<OspfPacket>,
}

impl From<lr_ospf::exchange::ExchangeStep> for OspfStep {
    fn from(step: lr_ospf::exchange::ExchangeStep) -> Self {
        Self {
            lsas: step.lsas,
            outbound: step.outbound,
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
        // AE 0 = wildcard; AE 1 = IPv4; AE 2 = IPv6. Both are handled.
        let prefix = match u.ae {
            1 => {
                if u.prefix.is_empty() || u.prefix.len() > 4 {
                    return;
                }
                let mut addr = [0u8; 4];
                addr[..u.prefix.len()].copy_from_slice(&u.prefix);
                Prefix::new_v4(addr, u.prefix_len)
            }
            2 => {
                if u.prefix.is_empty() || u.prefix.len() > 16 {
                    return;
                }
                let mut addr = [0u8; 16];
                addr[..u.prefix.len()].copy_from_slice(&u.prefix);
                Prefix::new_v6(addr, u.prefix_len)
            }
            _ => return, // AE 0 (wildcard) and unknown AEs are ignored.
        };
        // Source-specific destination (RFC 9079) — tracked in the route key.
        // The source prefix uses the same AE as the destination.
        let source = if u.src_prefix_len > 0 && !u.src_prefix.is_empty() {
            match u.ae {
                1 if u.src_prefix.len() <= 4 => {
                    let mut s = [0u8; 4];
                    s[..u.src_prefix.len()].copy_from_slice(&u.src_prefix);
                    Some(lr_babel::source::SourcePrefix::new(Prefix::new_v4(
                        s,
                        u.src_prefix_len,
                    )))
                }
                2 if u.src_prefix.len() <= 16 => {
                    let mut s = [0u8; 16];
                    s[..u.src_prefix.len()].copy_from_slice(&u.src_prefix);
                    Some(lr_babel::source::SourcePrefix::new(Prefix::new_v6(
                        s,
                        u.src_prefix_len,
                    )))
                }
                _ => None,
            }
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
            .map(|r| {
                // The Loc-RIB key family depends on the destination's
                // address family: IPv4 destinations → IPV4_UNICAST,
                // IPv6 destinations → IPV6_UNICAST.
                let family = match r.key.destination.addr {
                    lr_core::addr::IpAddr::V4(_) => NlriFamily::IPV4_UNICAST,
                    lr_core::addr::IpAddr::V6(_) => NlriFamily::IPV6_UNICAST,
                };
                Route {
                    key: RouteKey::new(r.key.destination, family),
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
                }
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
    /// Externally redistributed destinations requested through
    /// [`Self::ospf_redistribute`] (RFC 2328 §12.4.3), keyed by their
    /// link-state ID (the masked network). Re-originated into every
    /// attached OSPFv2 area so areas that (re)attach later catch up.
    ospf_externals: BTreeMap<u32, ExternalDestination>,
    /// Type-7 → type-5 translations this router currently maintains as
    /// an elected NSSA border router (RFC 3101 §3.2), keyed by the
    /// source type-7 (NSSA area ID, link-state ID, advertising router).
    /// A tracked translation is flushed when its source disappears, the
    /// P-bit clears or the translator role is lost.
    ospf_translations: BTreeSet<(u32, u32, u32)>,
    /// Configured virtual links (RFC 2328 §15), keyed by
    /// (transit area, endpoint router ID).
    ospf_vlinks: BTreeMap<(u32, u32), OspfVirtualLink>,
    /// RFC 4271 MRAI state keyed by BGP session.
    mrai: BTreeMap<u64, MraiState>,
    /// RFC 4724 / RFC 9494 stale-route retention keyed by BGP session.
    graceful_restart: BTreeMap<u64, GracefulRestartState>,
    /// Local cap (seconds) for the LLGR stale time received from a peer
    /// (RFC 9494 §4.2), keyed by BGP session.
    llgr_caps: BTreeMap<u64, u32>,
    /// Per-peer maximum-prefix state: `(exceeded, threshold_warned)`.
    /// `exceeded` is latched once the hard limit is hit so the teardown
    /// event fires only once per session lifetime. `threshold_warned`
    /// is latched when the early-warning percentage is crossed.
    max_prefix_state: BTreeMap<u64, MaxPrefixState>,
    /// Configured redistribution pipes (BIRD `pipe` / FRR `redistribute`).
    /// Each pipe bridges routes from `source` to `target` protocol.
    pipes: Vec<crate::redistribution::RedistributionPipe>,
    /// Routes this router has redistributed into BGP, keyed by the
    /// original Loc-RIB key. When the source route disappears, the
    /// redistributed BGP route is unoriginated.
    redistributed_bgp: BTreeMap<RouteKey, RouteKey>,
    /// Optional BMP (RFC 7854) sink: when set, the router mirrors
    /// peer state changes and route events to this closure as encoded
    /// BMP messages. The embedder connects the closure to a TCP
    /// collector.
    #[allow(clippy::type_complexity)]
    bmp_sink: Option<Box<dyn Fn(&[u8]) + Send + Sync>>,
    /// Registered BGP route aggregates (RFC 4271 §9.2.2.2). When the
    /// Loc-RIB contains at least one route more specific than a
    /// registered aggregate, the aggregate is originated with a zeroed
    /// AS_PATH and ATOMIC_AGGREGATE. When all specifics disappear, the
    /// aggregate is withdrawn.
    aggregates: BTreeSet<lr_core::addr::Prefix>,
    /// RFC 8212 mode: external BGP sessions (eBGP *and* confederation
    /// boundaries, per §1) without an explicit import policy discard
    /// all received routes, and without an explicit export policy
    /// advertise nothing. Off by default (the library embedder opts
    /// in; the shipped daemon turns it on).
    ebgp_requires_policy: bool,
    /// RFC 8212 §3 per-session state: which directions the embedder
    /// attached an explicit policy to, plus one-time denial log
    /// latches (a full table from a policy-less peer must not produce
    /// one log event per route).
    session_policy: BTreeMap<u64, SessionPolicy>,
}

/// RFC 8212 bookkeeping for one BGP session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SessionPolicy {
    /// The embedder attached an explicit import policy to the session.
    has_import: bool,
    /// The embedder attached an explicit export policy to the session.
    has_export: bool,
    /// Latched after the first import denial is logged.
    warned_import: bool,
    /// Latched after the first export denial is logged.
    warned_export: bool,
}

/// Per-session maximum-prefix bookkeeping.
#[derive(Debug, Clone, Copy, Default)]
struct MaxPrefixState {
    /// True once the hard limit was exceeded and the action fired.
    /// Cleared on session reset.
    exceeded: bool,
    /// True once the threshold percentage was crossed and the warning
    /// was emitted. Cleared on session reset.
    threshold_warned: bool,
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
            ospf_externals: BTreeMap::new(),
            ospf_translations: BTreeSet::new(),
            ospf_vlinks: BTreeMap::new(),
            mrai: BTreeMap::new(),
            graceful_restart: BTreeMap::new(),
            llgr_caps: BTreeMap::new(),
            max_prefix_state: BTreeMap::new(),
            pipes: Vec::new(),
            redistributed_bgp: BTreeMap::new(),
            bmp_sink: None,
            aggregates: BTreeSet::new(),
            ebgp_requires_policy: false,
            session_policy: BTreeMap::new(),
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

    /// Enable or disable RFC 8212 default eBGP route behaviors.
    ///
    /// When on, an external BGP session (eBGP or a confederation
    /// boundary — RFC 8212 §1 counts both) whose embedder declared no
    /// explicit import policy discards every received route, and a
    /// session with no explicit export policy advertises nothing
    /// (RFC 8212 §3 replaces the RFC 4271 default-accept behavior).
    ///
    /// Policy presence is declared per session with
    /// [`DefaultRouter::set_session_policy`]; absence means no policy,
    /// so enabling the mode is fail-closed by construction. The
    /// library default is off to keep embedder pipelines untouched;
    /// the shipped daemon enables it.
    pub fn set_ebgp_requires_policy(&mut self, on: bool) {
        self.ebgp_requires_policy = on;
    }

    /// Declare which directions of a BGP session carry an explicit
    /// policy (RFC 8212 §3). Call after `add_session` returned the
    /// handle; `Err` on unknown handles (typo protection, fail
    /// closed).
    ///
    /// A direction declared `true` suppresses the RFC 8212 default
    /// deny for it; the policy itself runs through the ordinary hook
    /// chain (e.g. `lr-policy` route-maps bound to the session).
    /// Changing the export declaration re-evaluates every prefix
    /// toward the session immediately: a newly declared policy
    /// advertises what it permits, a removed one withdraws what the
    /// session still carried.
    pub fn set_session_policy(
        &mut self,
        h: SessionHandle,
        import: bool,
        export: bool,
    ) -> Result<(), String> {
        if !self.sessions.contains_key(&h.0) {
            return Err(format!("set_session_policy: unknown session {}", h.0));
        }
        let export_changed = self
            .session_policy
            .get(&h.0)
            .is_none_or(|p| p.has_export != export);
        let st = self.session_policy.entry(h.0).or_default();
        st.has_import = import;
        st.has_export = export;
        if export_changed {
            // Re-evaluate every prefix toward the session: a newly
            // declared policy advertises what it permits, a removed
            // one withdraws what the session still carries (RFC 8212
            // §3 keeps routes without an explicit export policy out
            // of the Adj-RIB-Out). No-op before the session
            // establishes.
            let hooks = std::mem::take(&mut self.hooks);
            let sets: Vec<(RouteKey, Vec<Route>)> = self
                .loc_rib
                .iter_sets()
                .map(|(k, s)| (k.clone(), s.to_vec()))
                .collect();
            let mut work: Vec<(RouteKey, Vec<Route>, Vec<u32>)> = Vec::new();
            for (key, ranked) in &sets {
                let (advertise, withdraw_ids) = self.export_work_for(&hooks, h.0, key, ranked);
                if advertise.is_empty() && withdraw_ids.is_empty() {
                    continue;
                }
                work.push((key.clone(), advertise, withdraw_ids));
            }
            self.hooks = hooks;
            for (key, advertise, withdraw_ids) in work {
                if !withdraw_ids.is_empty() {
                    self.queue_or_send_withdrawal(h.0, &key, &withdraw_ids);
                }
                if !advertise.is_empty() {
                    self.queue_or_send_advertisement(h.0, advertise);
                }
            }
        }
        Ok(())
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

    /// Install a BMP (RFC 7854) sink. When set, the router mirrors
    /// peer state changes (Peer Up / Peer Down) and route events (Route
    /// Monitoring) to this closure as encoded BMP messages. The
    /// embedder connects the closure to a TCP collector.
    ///
    /// The closure receives raw BMP message bytes — one call per
    /// message. It is called from within `tick()` / `feed_input()`, so
    /// it must be non-blocking.
    pub fn set_bmp_sink(&mut self, sink: impl Fn(&[u8]) + Send + Sync + 'static) {
        self.bmp_sink = Some(Box::new(sink));
    }

    /// Build a BMP Peer Header for the given BGP session, using the
    /// session's negotiated peer info. Returns `None` for non-BGP
    /// sessions or sessions that haven't completed OPEN.
    fn bmp_peer_header(&self, session: u64) -> Option<lr_bmp::PeerHeader> {
        let state = self.sessions.get(&session)?;
        let SessionState::Bgp { peer, .. } = state else {
            return None;
        };
        let cfg = peer.config();
        let peer_bgp_id = peer.peer_bgp_id()?;
        let peer_as = peer.peer_as()?;
        let mut addr = [0u8; 16];
        let flags = match cfg.local_address {
            Some(lr_core::addr::IpAddr::V6(_)) => {
                // We don't store the peer's address; use the local
                // address family as a proxy. In practice the embedder
                // knows the peer address.
                lr_bmp::PeerFlags::ipv4() // conservative default
            }
            _ => lr_bmp::PeerFlags::ipv4(),
        };
        // Place the BGP ID in the last 4 bytes (IPv4 convention).
        let id_bytes = peer_bgp_id.to_v4_bytes();
        addr[12..16].copy_from_slice(&id_bytes);
        Some(lr_bmp::PeerHeader {
            peer_type: lr_bmp::PeerType::Global,
            peer_flags: flags,
            peer_distinguisher: 0,
            peer_address: addr,
            peer_as: peer_as.as_u32(),
            peer_bgp_id: peer_bgp_id.as_u32(),
            timestamp_secs: (self.now_ms / 1000) as u32,
            timestamp_fraction: 0,
        })
    }

    /// Emit a BMP Peer Up message (RFC 7854 §4.6) to the sink, when
    /// configured. Called when a BGP session transitions to Established.
    fn bmp_peer_up(&self, session: u64) {
        let Some(sink) = &self.bmp_sink else {
            return;
        };
        let Some(peer) = self.bmp_peer_header(session) else {
            return;
        };
        let msg = lr_bmp::BmpMessage::peer_up(
            peer,
            [0u8; 16], // local address — embedder can patch
            179,
            0, // remote port — embedder can patch
            &[],
            &[],
        );
        if let Ok(bytes) = lr_bmp::BmpCodec::new().encode_vec(&msg) {
            sink(&bytes);
        }
    }

    /// Emit a BMP Peer Down message (RFC 7854 §4.5) to the sink, when
    /// configured. Called when a BGP session leaves Established.
    fn bmp_peer_down(&self, session: u64) {
        let Some(sink) = &self.bmp_sink else {
            return;
        };
        let Some(peer) = self.bmp_peer_header(session) else {
            return;
        };
        let msg = lr_bmp::BmpMessage::peer_down(peer, lr_bmp::PeerDownReason::LocalClose, &[]);
        if let Ok(bytes) = lr_bmp::BmpCodec::new().encode_vec(&msg) {
            sink(&bytes);
        }
    }

    /// Emit a BMP Route Monitoring message (RFC 7854 §4.3) for a route
    /// that just entered the Loc-RIB. The payload is a minimal BGP
    /// UPDATE carrying the route's prefix — a full BGP UPDATE encode
    /// would require the path-attribute bag, which we delegate to the
    /// embedder. For now we send the prefix as a BMP Route Mirroring
    /// message with a synthetic BGP header so the collector sees the
    /// event.
    fn bmp_route_monitor(&self, route: &Route) {
        let Some(sink) = &self.bmp_sink else {
            return;
        };
        // A real BGP UPDATE (RFC 7854 §4.3 mirrors what the session
        // sent): the route's own path attributes, IPv4 NLRI in the
        // legacy section, IPv6 via MP_REACH_NLRI.
        use lr_bgp::message::update::{Nlri, Update};
        let mut attrs: PathAttributes = route.attributes.clone().into();
        let update = if route.key.family == NlriFamily::IPV4_UNICAST {
            Update {
                withdrawn: Vec::new(),
                attributes: attrs,
                nlri: vec![Nlri {
                    path_id: route.path_id,
                    prefix: route.key.prefix,
                }],
            }
        } else {
            let next_hop = match route.next_hop {
                Some(IpAddr::V4(b)) => lr_bgp::path::MpNextHop::V4(b),
                Some(IpAddr::V6(b)) => lr_bgp::path::MpNextHop::V6Global(b),
                None => lr_bgp::path::MpNextHop::V6Global([0; 16]),
            };
            let mp = lr_bgp::path::MpReach::new(
                route.key.family,
                next_hop,
                vec![Nlri {
                    path_id: route.path_id,
                    prefix: route.key.prefix,
                }],
            );
            attrs.insert(PathAttribute::new(
                PathAttrFlags::new().set_optional(true),
                AttrType::MpReachNlri,
                mp.encode(),
            ));
            Update {
                withdrawn: Vec::new(),
                attributes: attrs,
                nlri: Vec::new(),
            }
        };
        let Ok(bgp_msg) =
            lr_bgp::codec::BgpCodec::new().encode_vec(&lr_bgp::message::BgpMessage::Update(update))
        else {
            return;
        };
        let peer = match self.bmp_peer_header(route.origin.peer) {
            Some(p) => p,
            None => return,
        };
        let msg = lr_bmp::BmpMessage::route_monitoring(peer, &bgp_msg);
        if let Ok(bytes) = lr_bmp::BmpCodec::new().encode_vec(&msg) {
            sink(&bytes);
        }
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

    /// Configure RFC 5549 Extended Next-Hop tuples on a BGP session.
    /// Each tuple is `(NLRI AFI, NLRI SAFI, Nexthop AFI)`; the canonical
    /// entry is `(1, 1, 2)` — IPv4 unicast NLRI resolved over an IPv6
    /// next-hop. Must be called before `start_session` (OPEN negotiation).
    pub fn set_session_extended_next_hop(
        &mut self,
        h: SessionHandle,
        tuples: &[(u16, u8, u16)],
    ) -> Result<(), String> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => {
                if peer.is_established() {
                    return Err(format!(
                        "session {} already established: extended-next-hop must be set before start",
                        h.0
                    ));
                }
                peer.config_mut().extended_next_hop = tuples.to_vec();
                Ok(())
            }
            _ => Err(format!("BGP session {} not found", h.0)),
        }
    }

    /// Override the MP-BGP families advertised in OPEN. Must be called
    /// before `start_session`. Use this to enable IPv6 unicast
    /// (`NlriFamily::IPV6_UNICAST`) alongside the default IPv4 unicast,
    /// or to restrict the session to a single family.
    pub fn set_session_mp_families(
        &mut self,
        h: SessionHandle,
        families: &[NlriFamily],
    ) -> Result<(), String> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => {
                if peer.is_established() {
                    return Err(format!(
                        "session {} already established: mp_families must be set before start",
                        h.0
                    ));
                }
                peer.config_mut().mp_families = families.to_vec();
                Ok(())
            }
            _ => Err(format!("BGP session {} not found", h.0)),
        }
    }

    /// Set the local source address used for next-hop-self egress
    /// (eBGP) and as the protocol identity for Babel/OSPF runtimes.
    /// Must be called before `start_session`. For RFC 5549 ENH egress
    /// over IPv6 the address should be IPv6.
    pub fn set_session_local_address(
        &mut self,
        h: SessionHandle,
        addr: IpAddr,
    ) -> Result<(), String> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => {
                if peer.is_established() {
                    return Err(format!(
                        "session {} already established: local_address must be set before start",
                        h.0
                    ));
                }
                peer.config_mut().local_address = Some(addr);
                Ok(())
            }
            _ => Err(format!("BGP session {} not found", h.0)),
        }
    }

    /// Originate a local route (e.g. from `network` statements): injects it
    /// into Loc-RIB and advertises it to all suitable BGP peers.
    pub fn originate(&mut self, prefix: Prefix, next_hop: Option<IpAddr>) -> RouteKey {
        self.originate_family(prefix, NlriFamily::IPV4_UNICAST, next_hop)
    }

    /// Originate a route for an explicit address family. Use this for
    /// IPv6 unicast (`NlriFamily::IPV6_UNICAST`) or any other MP-BGP
    /// family the session speaks. The IPv4 unicast convenience wrapper
    /// [`Self::originate`] covers the historical single-family case.
    pub fn originate_family(
        &mut self,
        prefix: Prefix,
        family: NlriFamily,
        next_hop: Option<IpAddr>,
    ) -> RouteKey {
        let key = RouteKey::new(prefix, family);
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
        // IPv4 unicast uses the well-known NEXT_HOP attribute; every
        // other family is carried by MP_REACH_NLRI. The egress path will
        // synthesize the correct attribute from `next_hop` regardless of
        // where it lives, but populating it here keeps the Loc-RIB route
        // self-describing for tools that snapshot it directly.
        if family == NlriFamily::IPV4_UNICAST {
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

    /// Originate a route with an explicit attribute set (the BMP
    /// collector and MRT restore paths: observation feeds the Loc-RIB
    /// with the attributes exactly as received). NEXT_HOP is injected
    /// only when the caller's set does not already carry one.
    pub fn originate_with_attributes(
        &mut self,
        prefix: Prefix,
        family: NlriFamily,
        next_hop: Option<IpAddr>,
        attributes: lr_core::attr::Attributes,
    ) -> RouteKey {
        let key = RouteKey::new(prefix, family);
        let mut attrs: PathAttributes = attributes.into();
        if next_hop.is_some() && attrs.next_hop().is_none() {
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

    /// Register a BGP route aggregate (RFC 4271 §9.2.2.2). When the
    /// Loc-RIB contains at least one route more specific than `prefix`,
    /// the aggregate is originated with a zeroed AS_PATH,
    /// ATOMIC_AGGREGATE, and AGGREGATOR attributes. When all specifics
    /// disappear, the aggregate is withdrawn.
    ///
    /// This is the BIRD `aggregate` / FRR `aggregate-address` equivalent.
    pub fn add_aggregate(&mut self, prefix: lr_core::addr::Prefix) {
        self.aggregates.insert(prefix);
        self.recompute_aggregates();
    }

    /// Remove a registered aggregate. The aggregate route (if currently
    /// originated) is withdrawn.
    pub fn remove_aggregate(&mut self, prefix: &lr_core::addr::Prefix) {
        if self.aggregates.remove(prefix) {
            // Withdraw the aggregate if it was originated.
            let family = match prefix.addr {
                lr_core::addr::IpAddr::V4(_) => NlriFamily::IPV4_UNICAST,
                lr_core::addr::IpAddr::V6(_) => NlriFamily::IPV6_UNICAST,
            };
            let key = RouteKey::new(*prefix, family);
            self.unoriginate(&key);
        }
    }

    /// Scan the Loc-RIB for routes more specific than each registered
    /// aggregate. Originates or withdraws aggregate routes as needed.
    fn recompute_aggregates(&mut self) {
        if self.aggregates.is_empty() {
            return;
        }
        // Collect the current Loc-RIB prefixes (best routes only).
        let loc_rib_prefixes: Vec<lr_core::addr::Prefix> =
            self.loc_rib.iter_best().map(|r| r.key.prefix).collect();
        // Collect the aggregate list and local AS first to avoid
        // borrowing self while we mutate it below.
        let aggregates: Vec<lr_core::addr::Prefix> = self.aggregates.iter().copied().collect();
        let local_as = self
            .sessions
            .values()
            .find_map(|s| match s {
                SessionState::Bgp { peer, .. } => Some(peer.config().local_as.as_u32()),
                _ => None,
            })
            .unwrap_or(0);
        for agg in &aggregates {
            let family = match agg.addr {
                lr_core::addr::IpAddr::V4(_) => NlriFamily::IPV4_UNICAST,
                lr_core::addr::IpAddr::V6(_) => NlriFamily::IPV6_UNICAST,
            };
            let key = RouteKey::new(*agg, family);
            let has_specific = loc_rib_prefixes
                .iter()
                .any(|p| agg.contains_prefix(p) && p.prefix_len > agg.prefix_len);
            let already_originated = self.originated.contains_key(&key);
            if has_specific && !already_originated {
                let mut attrs = PathAttributes::new();
                attrs.insert(PathAttribute::new(
                    PathAttrFlags::new().set_transitive(true),
                    AttrType::Origin,
                    vec![0],
                ));
                attrs.insert(PathAttribute::new(
                    PathAttrFlags::new().set_transitive(true),
                    AttrType::AsPath,
                    Vec::new(),
                ));
                attrs.insert(PathAttribute::new(
                    PathAttrFlags::new().set_transitive(true),
                    AttrType::AtomicAggregate,
                    Vec::new(),
                ));
                let mut agg_val = Vec::with_capacity(8);
                agg_val.extend_from_slice(&local_as.to_be_bytes());
                agg_val.extend_from_slice(&[0, 0, 0, 0]);
                attrs.insert(PathAttribute::new(
                    PathAttrFlags::new().set_transitive(true),
                    AttrType::Aggregator,
                    agg_val,
                ));
                let route = Route {
                    key: key.clone(),
                    origin: RouteOrigin { proto: 2, peer: 0 },
                    protocol: Protocol::Bgp,
                    preference: lr_core::rib::Preference::new(
                        Protocol::Bgp.default_admin_distance(),
                        0,
                    ),
                    next_hop: None,
                    attributes: attrs.into(),
                    age_ms: self.now_ms,
                    path_id: 0,
                };
                self.loc_rib.install_set(&key, vec![route.clone()]);
                self.originated.insert(key.clone(), route.clone());
                self.pending_events.push(RouterEvent::RouteInstalled(route));
            } else if !has_specific && already_originated {
                self.unoriginate(&key);
            }
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

    /// RFC 8212 §3 classification for one session: `(deny_import,
    /// deny_export)`. Both are false unless the mode is enabled and the
    /// session is an external BGP session (eBGP or confederation
    /// boundary, per §1); for those, a direction is denied exactly when
    /// the embedder declared no explicit policy for it. Pure — callers
    /// with a `&mut self` handle the one-time log latching themselves.
    fn rfc8212_denies(&self, session: u64) -> (bool, bool) {
        if !self.ebgp_requires_policy {
            return (false, false);
        }
        match self.sessions.get(&session) {
            Some(SessionState::Bgp { peer, .. }) if peer.config().peer_role().is_external() => {
                let p = self.session_policy.get(&session).copied();
                (
                    !p.is_some_and(|p| p.has_import),
                    !p.is_some_and(|p| p.has_export),
                )
            }
            _ => (false, false),
        }
    }

    fn import_route(&mut self, route: Route) {
        let is_ebgp = route.protocol == Protocol::Bgp && route.origin.proto == 0;
        // RFC 8212 §3: routes from an external peer with no explicit
        // import policy are not eligible for the decision process —
        // drop them before Adj-RIB-In (a policy-less peer must not
        // leak a single route into the pipeline).
        let (rfc8212_deny_import, _) = self.rfc8212_denies(route.origin.peer);
        if rfc8212_deny_import {
            let session = route.origin.peer;
            let prefix = route.key.prefix;
            let st = self.session_policy.entry(session).or_default();
            if !st.warned_import {
                st.warned_import = true;
                self.pending_events.push(RouterEvent::Log(format!(
                    "session {session}: no import policy — discarding received routes (RFC 8212), e.g. {prefix}"
                )));
            }
            return;
        }
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
        let session = origin.peer;
        // Track re-advertised routes while the session is resynchronizing
        // after a restart (RFC 4724 §4.1: at EoR, unrefreshed stale routes
        // are deleted; RFC 9494 §4.2 keeps the LLST timer running until
        // then).
        if let Some(state) = self.graceful_restart.get_mut(&session) {
            state.refreshed.insert((key.clone(), route.path_id));
        }
        self.adj_rib_in.feed_pre_policy(origin, route);
        self.reselect(&key);
        // Per-peer maximum-prefix enforcement (BIRD `maximum prefix`,
        // FRR `maximum-prefix`). Count the session's routes in Adj-RIB-In
        // after the install; if the count crosses the threshold or the
        // hard limit, fire the corresponding event.
        self.check_max_prefix(session);
    }

    /// Count a session's Adj-RIB-In and enforce the maximum-prefix limit.
    /// Emits [`RouterEvent::MaxPrefixThreshold`] once when the early-warning
    /// percentage is crossed, and [`RouterEvent::MaxPrefixExceeded`] once
    /// when the hard limit is hit. For `Teardown`/`Restart` the session is
    /// closed with a NOTIFICATION CEASE (subcode 8).
    fn check_max_prefix(&mut self, session: u64) {
        // Read the config without borrowing self mutably.
        let (limit, action, threshold_pct) = match self.sessions.get(&session) {
            Some(SessionState::Bgp { peer, .. }) => {
                let cfg = peer.config();
                match cfg.maximum_prefix {
                    Some(limit) => (
                        limit,
                        cfg.maximum_prefix_action,
                        cfg.maximum_prefix_threshold,
                    ),
                    None => return, // no limit configured
                }
            }
            _ => return, // not a BGP session
        };
        let count: u32 = self
            .adj_rib_in
            .iter_all()
            .filter(|r| r.origin.peer == session)
            .count() as u32;
        // Early-warning threshold (fires once per crossing).
        if threshold_pct > 0 && count > 0 {
            let threshold_count = (u64::from(limit) * u64::from(threshold_pct) / 100) as u32;
            if count >= threshold_count && count < limit {
                let state = self.max_prefix_state.entry(session).or_default();
                if !state.threshold_warned {
                    state.threshold_warned = true;
                    self.pending_events.push(RouterEvent::MaxPrefixThreshold {
                        session: SessionHandle(session),
                        count,
                        limit,
                        pct: threshold_pct,
                    });
                }
            }
        }
        // Hard limit (fires once per session lifetime).
        if count > limit {
            let state = self.max_prefix_state.entry(session).or_default();
            if !state.exceeded {
                state.exceeded = true;
                self.pending_events.push(RouterEvent::MaxPrefixExceeded {
                    session: SessionHandle(session),
                    count,
                    limit,
                    action,
                });
                match action {
                    lr_bgp::MaxPrefixAction::Warn => {
                        self.pending_events.push(RouterEvent::Log(format!(
                            "max-prefix: session {} exceeded limit ({count}/{limit}), action=warn",
                            session
                        )));
                    }
                    lr_bgp::MaxPrefixAction::Teardown | lr_bgp::MaxPrefixAction::Restart => {
                        self.pending_events.push(RouterEvent::Log(format!(
                            "max-prefix: session {} exceeded limit ({count}/{limit}), action={}",
                            session,
                            action.name()
                        )));
                        // Tear the session down with a CEASE NOTIFICATION
                        // (subcode 8 — "Maximum Number of Prefixes
                        // Exceeded", RFC 4486 §2.1).
                        if let Some(SessionState::Bgp { peer, .. }) =
                            self.sessions.get_mut(&session)
                        {
                            peer.enqueue_notification(lr_bgp::BgpErrorCode::Cease, 8);
                        }
                        self.flush_peer_output(session);
                    }
                }
            }
        }
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
            self.unredistribute_route(key);
            self.recompute_aggregates();
            return;
        }
        let new_best = ranked[0].clone();
        self.loc_rib.install_set(key, ranked.clone());
        if old_best.as_ref() != Some(&new_best) {
            self.pending_events
                .push(RouterEvent::RouteInstalled(new_best.clone()));
            self.redistribute_route(&new_best);
            self.bmp_route_monitor(&new_best);
        }
        self.export_selection(key, &ranked);
        // Recompute aggregates after the Loc-RIB changes — a new
        // specific may trigger an aggregate, or a withdrawn specific
        // may remove the last covering route.
        self.recompute_aggregates();
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
        let sessions: Vec<u64> = self.sessions.keys().copied().collect();
        let mut work: Vec<(u64, Vec<Route>, Vec<u32>)> = Vec::new();
        for session in sessions {
            let (advertise, withdraw_ids) = self.export_work_for(&hooks, session, key, ranked);
            work.push((session, advertise, withdraw_ids));
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

    /// Per-session slice of [`Self::export_selection`]: the (advertise,
    /// withdraw) delta for `key` toward one established session under
    /// `hooks`, computed against Adj-RIB-Out. Pure with respect to the
    /// wire — callers transmit the returned work after restoring the
    /// hook chain (the borrow split forces this two-phase shape).
    fn export_work_for(
        &self,
        hooks: &HookChain,
        session: u64,
        key: &RouteKey,
        ranked: &[Route],
    ) -> (Vec<Route>, Vec<u32>) {
        let Some(SessionState::Bgp { peer, .. }) = self.sessions.get(&session) else {
            return (Vec::new(), Vec::new());
        };
        if !peer.is_established() {
            return (Vec::new(), Vec::new());
        }
        // RFC 8212 §3: an external session with no explicit export
        // policy must not carry routes in its Adj-RIB-Out. Desired
        // stays empty so the diff below withdraws anything the
        // session still advertises (e.g. exported before the mode was
        // enabled or the policy removed).
        let (_, rfc8212_deny_export) = self.rfc8212_denies(session);
        let add_path_tx = peer.add_path_tx_for(key.family);
        let mut desired: Vec<Route> = Vec::new();
        if add_path_tx && !rfc8212_deny_export {
            for (slot, route) in ranked.iter().enumerate() {
                if route.origin.peer == session {
                    continue; // split horizon, per path
                }
                let mut candidate = route.clone();
                candidate.path_id = slot as u32 + 1;
                if matches!(
                    hooks.run_export_to(&mut candidate, session),
                    HookVerdict::Drop
                ) {
                    continue;
                }
                desired.push(candidate);
            }
        } else if let Some(best) = ranked.first() {
            if best.origin.peer != session && !rfc8212_deny_export {
                let mut candidate = best.clone();
                candidate.path_id = 0;
                if !matches!(
                    hooks.run_export_to(&mut candidate, session),
                    HookVerdict::Drop
                ) {
                    desired.push(candidate);
                }
            }
        }
        let current = self.adj_rib_out.paths_for(
            RouteOrigin {
                proto: 0,
                peer: session,
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
        (advertise, withdraw_ids)
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
        // RFC 8212 §3: an external session with no explicit export
        // policy re-advertises nothing after a route refresh — the
        // prior entries were withdrawn above, leaving the session's
        // Adj-RIB-Out empty as the RFC requires.
        let (_, rfc8212_deny_export) = self.rfc8212_denies(session);

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
                    if rfc8212_deny_export {
                        continue;
                    }
                    if matches!(hooks.run_export_to(&mut route, session), HookVerdict::Drop) {
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
        // RFC 8212 §3: an external session with no explicit export
        // policy receives an empty initial dump (EoR still flows — the
        // peer's convergence logic depends on it). Warn once per
        // session lifetime, not per establishment.
        let (_, rfc8212_deny_export) = self.rfc8212_denies(h);
        if rfc8212_deny_export {
            let st = self.session_policy.entry(h).or_default();
            if !st.warned_export {
                st.warned_export = true;
                self.pending_events.push(RouterEvent::Log(format!(
                    "session {h}: no export policy — advertising nothing (RFC 8212)"
                )));
            }
        }
        if let Some(SessionState::Bgp { peer, conn, .. }) = self.sessions.get_mut(&h) {
            for route in &snapshot {
                if rfc8212_deny_export {
                    continue;
                }
                let mut r = route.clone();
                if matches!(hooks.run_export_to(&mut r, h), HookVerdict::Drop) {
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
        let mut transition_up = false;
        let mut transition_down = false;
        if let Some(SessionState::Bgp {
            peer, established, ..
        }) = self.sessions.get_mut(&session)
        {
            let now_est = peer.is_established();
            if now_est && !*established {
                *established = true;
                transition_up = true;
                self.pending_events.push(RouterEvent::PeerStateChange {
                    session: SessionHandle(session),
                    state: "Established",
                });
            } else if !now_est && *established {
                *established = false;
                transition_down = true;
                self.pending_events.push(RouterEvent::PeerStateChange {
                    session: SessionHandle(session),
                    state: "Idle",
                });
            }
        }
        // BMP events fire outside the borrow scope so they can read
        // session state without conflicting with the mutable borrow above.
        if transition_up {
            self.bmp_peer_up(session);
        }
        if transition_down {
            self.bmp_peer_down(session);
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
        // Clear maximum-prefix bookkeeping so a re-established session
        // starts with fresh threshold/exceeded latches.
        if let Some(state) = self.max_prefix_state.get_mut(&h.0) {
            state.exceeded = false;
            state.threshold_warned = false;
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
                p_cfg.extended_next_hop = cfg.extended_next_hop.clone();
                p_cfg.maximum_prefix = cfg.maximum_prefix;
                p_cfg.maximum_prefix_action = cfg.maximum_prefix_action;
                p_cfg.maximum_prefix_threshold = cfg.maximum_prefix_threshold;
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
                    if area.kind != cfg.ospf_area_type {
                        return Err(format!(
                            "OSPF area {} already configured as {:?} (requested {:?}); \
                             use ospf_set_area_type to change it",
                            cfg.area_id, area.kind, cfg.ospf_area_type
                        ));
                    }
                }
                // RFC 2328 §3.6: the backbone is never a stub area (nor
                // an NSSA — RFC 3101 §2.1).
                if cfg.area_id == 0 && cfg.ospf_area_type != OspfAreaType::Normal {
                    return Err("the OSPF backbone (area 0) cannot be a stub or NSSA area".into());
                }
                self.ospf_areas.entry(cfg.area_id).or_insert(OspfAreaState {
                    lsdb: Lsdb::new(),
                    protocol,
                    kind: cfg.ospf_area_type,
                });
                let runtime = OspfRuntime::new(
                    router_id,
                    cfg.area_id,
                    protocol == Protocol::Ospfv3,
                    cfg.ospf_mtu,
                );
                self.sessions.insert(
                    h.0,
                    SessionState::Ospf {
                        runtime,
                        conn: MemoryConn::new(),
                    },
                );
                // Areas attached after a redistribution call catch up on
                // the self-originated type-5 set (RFC 2328 §12.4.3).
                if self.ospf_sync_externals() {
                    let delta = self.ospf_on_lsdb_change();
                    self.apply_runtime_delta(delta);
                }
                // A newly attached (transit) area may bring configured
                // virtual links up (RFC 2328 §15).
                if self.ospf_eval_virtual_links() {
                    let delta = self.ospf_on_lsdb_change();
                    self.apply_runtime_delta(delta);
                }
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
        self.session_policy.remove(&h.0);
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
                    let mut outbound: Vec<u8> = Vec::new();
                    let area_id = runtime.area_id;
                    // The area LSDB is the header-comparison source for
                    // the DBD exchange (disjoint field borrow from the
                    // session map entry).
                    let empty_lsdb = lr_ospf::lsdb::Lsdb::new();
                    let lsdb = self
                        .ospf_areas
                        .get(&area_id)
                        .map(|a| &a.lsdb)
                        .unwrap_or(&empty_lsdb);
                    let mut r = lr_core::buf::ReadBuf::new(&input);
                    while let Ok(Some(pkt)) = runtime.codec.decode(&mut r) {
                        let step = runtime.handle_packet(&pkt, lsdb, self.now_ms);
                        lsas.extend(step.lsas);
                        for p in step.outbound {
                            if let Ok(bytes) = runtime.codec.encode_vec(&p) {
                                outbound.extend_from_slice(&bytes);
                            }
                        }
                    }
                    if !outbound.is_empty() {
                        conn.put_output(&outbound);
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
                if newly_established {
                    // BMP (RFC 7854 §4.6): the Peer Up event mirrors
                    // *before* any Route Monitoring from the same batch
                    // — with TCP coalescing the KEEPALIVE that completes
                    // the handshake and the first UPDATE arrive in one
                    // read, and collectors expect Peer Up ordering.
                    self.bmp_peer_up(h.0);
                    // Initial table dump to the newly established peer.
                    self.on_bgp_established(h.0);
                }
                self.dispatch_bgp_actions(h.0, actions);
            }
            Pending::Other { delta } => {
                // Babel routes land directly in Loc-RIB (their egress
                // is protocol-internal, not BGP advertisement).
                self.apply_runtime_delta(delta);
            }
            Pending::OspfLsas { lsas } => {
                // LSAs belong to the session's area: install into the
                // shared area LSDB, flood what changed to the area's other
                // sessions (RFC 2328 §13.3) and recompute. Type-5
                // AS-external-LSAs are AS-scoped: they are additionally
                // installed into every other attached *regular* area and
                // flooded there (§13.3) — stub/NSSA areas refuse them
                // (RFC 2328 §3.6, RFC 3101 §2.1).
                let Some(SessionState::Ospf { runtime, .. }) = self.sessions.get(&h.0) else {
                    return Ok(()); // session vanished between phases
                };
                let area_id = runtime.area_id;
                let kind = self
                    .ospf_areas
                    .get(&area_id)
                    .map(|a| a.kind)
                    .unwrap_or(OspfAreaType::Normal);
                let mut changed = false;
                let mut to_flood = Vec::new();
                let mut as_scope: Vec<Lsa> = Vec::new();
                if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                    for lsa in lsas {
                        // Stub/NSSA LSA policy (RFC 2328 §3.6, RFC 3101).
                        if !ospf_area_accepts(&kind, &lsa) {
                            continue;
                        }
                        if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                            if lsa.header.ls_type == LsaTypeV2::AsExternalLsa as u8 {
                                as_scope.push(lsa.clone());
                            }
                            to_flood.push(lsa);
                            changed = true;
                        }
                    }
                }
                if !as_scope.is_empty() {
                    // v2 type-5 bodies never enter OSPFv3 areas and are
                    // refused by stub/NSSA areas.
                    let others: Vec<u32> = self
                        .ospf_areas
                        .iter()
                        .filter(|(a, area)| {
                            **a != area_id
                                && area.protocol == Protocol::Ospfv2
                                && !area.kind.is_stubby()
                        })
                        .map(|(a, _)| *a)
                        .collect();
                    for other in others {
                        let mut newly = Vec::new();
                        if let Some(area) = self.ospf_areas.get_mut(&other) {
                            for lsa in &as_scope {
                                if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                                    newly.push(lsa.clone());
                                    changed = true;
                                }
                            }
                        }
                        if !newly.is_empty() {
                            self.ospf_flood(other, &newly, None);
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

        // OSPF DBD/LSR exchange retransmissions (RFC 2328 §10.8
        // RxmtInterval): poll every session's driver and queue what it
        // wants repeated.
        for state in self.sessions.values_mut() {
            let SessionState::Ospf { runtime, conn } = state else {
                continue;
            };
            for p in runtime.exchange.poll(self.now_ms) {
                if let Ok(bytes) = runtime.codec.encode_vec(&p) {
                    conn.put_output(&bytes);
                }
            }
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

    /// Whether this router currently acts as an OSPF area border router:
    /// attached to the backbone plus at least one other area, all v2
    /// (RFC 2328 §12.4.3). Stub/NSSA summaries, defaults and type-7 →
    /// type-5 translation all hinge on border-router status.
    fn ospf_is_abr(&self) -> bool {
        self.ospf_router_id.is_some()
            && self.ospf_areas.len() >= 2
            && self.ospf_areas.contains_key(&0)
            && self
                .ospf_areas
                .values()
                .all(|a| a.protocol == Protocol::Ospfv2)
    }

    /// Recompute the OSPF route table after any area LSDB changed:
    /// first re-evaluate the virtual links (RFC 2328 §15 — a link coming
    /// up attaches the backbone and changes border-router status), then
    /// re-run ABR summary origination (§12.4.3) so inter-area knowledge
    /// propagates, refresh the NSSA type-7 → type-5 translations
    /// (RFC 3101 §3.2) and finally rebuild the merged view.
    fn ospf_on_lsdb_change(&mut self) -> RuntimeDelta {
        self.ospf_eval_virtual_links();
        self.ospf_summarize_areas();
        self.ospf_translate_nssa();
        self.ospf_recompute()
    }

    /// One area's computed route table: intra-area routes from SPF
    /// (RFC 2328 §16.1) merged with inter-area routes derived from
    /// summary-LSAs (§16.2) and external routes from type-5 LSAs (§16.4)
    /// or, in an NSSA, type-7 LSAs (RFC 3101 §2.5). Intra-area paths win
    /// per prefix, then inter-area, then external (§11) —
    /// `OspfTableEntry::beats` encodes the full order.
    ///
    /// Stub/NSSA areas (`kind`) never see type-5/type-4 LSAs (they are
    /// refused at install time — this filter is a second line of
    /// defence), `no_summary` areas only honour the default type-3
    /// summary, and the NSSA external calculation receives the
    /// border-router default-install rules of RFC 3101 §2.5 step (3).
    fn ospf_area_table(
        kind: &OspfAreaType,
        border_router: bool,
        lsdb: &Lsdb,
        spf_result: &spf::SpfResult,
    ) -> BTreeMap<Prefix, OspfTableEntry> {
        let mut table: BTreeMap<Prefix, OspfTableEntry> = BTreeMap::new();
        for r in spf_result
            .stub_routes
            .iter()
            .chain(spf_result.transit_routes.iter())
        {
            table.insert(r.prefix, OspfTableEntry::intra(r.metric));
        }
        for r in spf::summary_routes(lsdb, spf_result) {
            // `no_summary` areas must only ever derive the default from
            // type-3 summaries (RFC 2328 §12.4.3; RFC 3101 §2.7). A /0
            // prefix is necessarily 0.0.0.0/0.
            if kind.no_summary() && r.prefix.prefix_len != 0 {
                continue;
            }
            table
                .entry(r.prefix)
                .or_insert_with(|| OspfTableEntry::inter(r.metric, r.border_router));
        }
        match kind {
            OspfAreaType::Normal => {
                // `external_routes` already resolves §16.4 (6) among
                // competing type-5 candidates per prefix, so at most one
                // external candidate remains — it only fills prefixes
                // without an internal route.
                for r in external_routes(lsdb, spf_result) {
                    table.entry(r.prefix).or_insert_with(|| {
                        OspfTableEntry::external(
                            r.metric,
                            r.metric_type,
                            r.asbr,
                            r.forwarding_addr,
                            r.internal_cost,
                        )
                    });
                }
            }
            OspfAreaType::Nssa { .. } => {
                // RFC 3101 §2.5: type-7 externals with the same §16.4
                // metric semantics (type-5 and type-7 metrics are
                // directly comparable).
                let opts = NssaCalcOpts {
                    border_router,
                    summaries_suppressed: kind.no_summary(),
                };
                for r in nssa_routes(lsdb, spf_result, opts) {
                    table.entry(r.prefix).or_insert_with(|| {
                        OspfTableEntry::external(
                            r.metric,
                            r.metric_type,
                            r.asbr,
                            r.forwarding_addr,
                            r.internal_cost,
                        )
                    });
                }
            }
            OspfAreaType::Stub { .. } => {}
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
        let abr = self.ospf_is_abr();
        // Best entry per prefix across areas.
        let mut global: BTreeMap<Prefix, (OspfTableEntry, u32, Protocol)> = BTreeMap::new();
        for (area_id, area) in &self.ospf_areas {
            let spf_result = spf::run_spf(&area.lsdb, router_id);
            for (prefix, entry) in Self::ospf_area_table(&area.kind, abr, &area.lsdb, &spf_result) {
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
                // §16.4: an external route with a forwarding address
                // forwards traffic to that address, not to the ASBR.
                let next_hop = match entry.kind {
                    OspfKind::External {
                        forwarding_addr, ..
                    } if forwarding_addr != 0 => Some(IpAddr::V4(forwarding_addr.to_be_bytes())),
                    _ => None,
                };
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
                    next_hop,
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
    /// - Stub/NSSA targets receive the border-router type-3 default
    ///   (`0.0.0.0/0` at the configured metric); `no_summary` targets
    ///   receive the default *only* (RFC 2328 §3.6, RFC 3101 §2.7 —
    ///   including NSSAs, which switch to a type-3 default when summary
    ///   import is suppressed).
    ///
    /// Originated/flushed LSAs are installed into the target area LSDB and
    /// queued for flooding on that area's sessions. Returns whether any
    /// LSDB changed.
    fn ospf_summarize_areas(&mut self) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        let abr = self.ospf_is_abr();
        if !abr {
            // Not a functioning ABR: flush every self-originated summary
            // (type-3) and summary-ASBR (type-4) LSA.
            let mut changed = self.ospf_flush_self_lsa_types(router_id, |key| {
                key.ls_type == LsaTypeV2::SummaryIpLsa as u8
                    || key.ls_type == LsaTypeV2::SummaryAsbrLsa as u8
            });
            // ... and the ABR-injected NSSA defaults lose their
            // justification too (RFC 3101 §2.4).
            changed |= self.ospf_nssa_defaults();
            return changed;
        }
        // 1. Fresh per-area SPF results and route tables.
        let spf_results: BTreeMap<u32, spf::SpfResult> = self
            .ospf_areas
            .iter()
            .map(|(id, area)| (*id, spf::run_spf(&area.lsdb, router_id)))
            .collect();
        let tables: BTreeMap<u32, BTreeMap<Prefix, OspfTableEntry>> = self
            .ospf_areas
            .iter()
            .map(|(id, area)| {
                (
                    *id,
                    Self::ospf_area_table(
                        &area.kind,
                        true,
                        &area.lsdb,
                        spf_results.get(id).unwrap(),
                    ),
                )
            })
            .collect();
        let backbone = tables.get(&0).cloned().unwrap_or_default();

        // 2. Per-target source sets, then diff against the self-originated
        //    type-3 LSAs already in the target LSDB.
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        for (&target, table) in &tables {
            let kind = self
                .ospf_areas
                .get(&target)
                .map(|a| a.kind)
                .unwrap_or(OspfAreaType::Normal);
            // Sources: what the target should learn about the outside.
            let mut sources: BTreeMap<Prefix, u64> = if target == 0 {
                // Backbone: intra-area nets of every non-backbone area.
                let mut s = BTreeMap::new();
                for (id, t) in &tables {
                    if *id == 0 {
                        continue;
                    }
                    for (p, e) in t {
                        if e.is_intra() {
                            s.entry(*p)
                                .and_modify(|m: &mut u64| *m = (*m).min(e.metric))
                                .or_insert(e.metric);
                        }
                    }
                }
                s
            } else if kind.no_summary() {
                // Totally-stubby / totally-NSSA target: only the injected
                // default (RFC 2328 §3.6; RFC 3101 §2.7 switches NSSAs to
                // a type-3 default when summaries are suppressed).
                BTreeMap::new()
            } else {
                let mut s = BTreeMap::new();
                // (a) Backbone intra nets.
                for (p, e) in &backbone {
                    if e.is_intra() {
                        s.insert(*p, e.metric);
                    }
                }
                // (b) Inter-area routes other ABRs put into the backbone.
                //     External routes (§16.4) are never summarized — they
                //     travel as type-5 LSAs at AS scope.
                for (p, e) in &backbone {
                    if !e.is_intra()
                        && !e.is_own_inter(router_id)
                        && !matches!(e.kind, OspfKind::External { .. })
                    {
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
                        if e.is_intra() {
                            s.entry(*p)
                                .and_modify(|m: &mut u64| *m = (*m).min(e.metric))
                                .or_insert(e.metric);
                        }
                    }
                }
                s
            };
            // Border-router default into stub/NSSA targets (RFC 2328
            // §3.6; RFC 3101 §2.7): a type-3 summary default with the
            // configured metric. NSSAs with summaries imported carry the
            // default as a type-7 LSA instead (see `ospf_nssa_defaults`).
            if target != 0 {
                if let Some(metric) = kind.default_metric() {
                    if !kind.is_nssa() || kind.no_summary() {
                        sources.insert(Prefix::new_v4([0, 0, 0, 0], 0), u64::from(metric));
                    }
                }
            }
            // Loop guard: never summarize the target's own intra nets back
            // into the target (a stub area never carries an intra 0/0, so
            // the injected default survives the guard).
            for (p, e) in table {
                if e.is_intra() {
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
        // RFC 3101 §2.4: border-router type-7 defaults for NSSAs that
        // still import summaries.
        let nssa_default_changed = self.ospf_nssa_defaults();
        // §12.4.3: summary-ASBR (type-4) origination for ASBRs that this
        // ABR can reach but the target area cannot (see the helper).
        self.ospf_summarize_asbrs(router_id, &spf_results) | changed | nssa_default_changed
    }

    /// MaxAge-flush every self-originated LSA whose key satisfies `pred`
    /// across all areas (RFC 2328 §14.1). Returns whether any LSDB
    /// changed; flushes are flooded on their area.
    fn ospf_flush_self_lsa_types(
        &mut self,
        router_id: u32,
        pred: impl Fn(&lr_ospf::lsa::LsaKey) -> bool,
    ) -> bool {
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for target in areas {
            let mut flushes = Vec::new();
            if let Some(area) = self.ospf_areas.get(&target) {
                for (key, entry) in area.lsdb.iter() {
                    if pred(key) && key.advertising_router == router_id {
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
        changed
    }

    /// RFC 3101 §2.4/§2.7: keep the border-router type-7 default
    /// (`0.0.0.0/0`, P-bit clear, zero forwarding address) in sync in
    /// every attached NSSA that imports summaries. Defaults for
    /// `no_summary` NSSAs and for non-ABR routers are flushed. A
    /// redistributed default (`ospf_redistribute` of `0.0.0.0/0`) takes
    /// precedence and suppresses the injected one. Returns whether any
    /// LSDB changed.
    fn ospf_nssa_defaults(&mut self) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        let abr = self.ospf_is_abr();
        let redistributed_default = self.ospf_externals.contains_key(&0);
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for target in areas {
            // One immutable pass: existing self type-7 default + policy.
            let Some((existing, desired, default_metric)) =
                self.ospf_areas.get(&target).and_then(|area| {
                    if area.protocol != Protocol::Ospfv2 {
                        return None;
                    }
                    let existing = area
                        .lsdb
                        .iter()
                        .find(|(key, _)| {
                            key.ls_type == LsaTypeV2::NssaExternalLsa as u8
                                && key.link_state_id == 0
                                && key.advertising_router == router_id
                        })
                        .map(|(_, entry)| entry.lsa.clone());
                    let desired = abr
                        && area.kind.is_nssa()
                        && !area.kind.no_summary()
                        && !redistributed_default;
                    Some((existing, desired, area.kind.default_metric().unwrap_or(1)))
                })
            else {
                continue;
            };
            if desired {
                let unchanged = existing.as_ref().is_some_and(|lsa| {
                    lr_ospf::lsa::decode_as_external_body(&lsa.body)
                        .is_some_and(|body| body.metric_value() == default_metric)
                });
                if unchanged {
                    continue;
                }
                let prev_seq = existing.as_ref().map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_nssa_default_lsa(
                    router_id,
                    &NssaDefault::new(default_metric),
                    prev_seq,
                ) {
                    if let Some(area) = self.ospf_areas.get_mut(&target) {
                        if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                            floods.push((target, vec![lsa]));
                            changed = true;
                        }
                    }
                }
            } else if let Some(lsa) = existing {
                if let Some(flush) = flush_nssa_lsa(&lsa) {
                    if let Some(area) = self.ospf_areas.get_mut(&target) {
                        if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                            floods.push((target, vec![flush]));
                            changed = true;
                        }
                    }
                }
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        changed
    }

    /// RFC 2328 §12.4.3 (type-4): for every ASBR — the advertisers of the
    /// type-5 LSAs present in the LSDB, which are synchronized across
    /// areas at AS scope — originate into each attached area a
    /// summary-ASBR-LSA when the ASBR is intra-area reachable through one
    /// of the router's other areas but not through the target. The
    /// advertised metric is the ABR's own cost to the ASBR. Existing
    /// self-originated type-4s whose ASBR lost reachability are flushed.
    /// Stub/NSSA targets never receive type-4s (RFC 2328 §3.6, RFC 3101
    /// §2.1 — no type-5s live there, so ASBR locations are meaningless);
    /// stale ones are flushed.
    fn ospf_summarize_asbrs(
        &mut self,
        router_id: u32,
        spf_results: &BTreeMap<u32, spf::SpfResult>,
    ) -> bool {
        // AS-scope type-5s are installed in every area; derive the ASBR
        // set from whichever area has an LSDB (backbone preferred).
        let source_area = self.ospf_areas.keys().copied().min().unwrap_or_default();
        let Some(source) = self.ospf_areas.get(&source_area) else {
            return false;
        };
        let asbrs: BTreeSet<u32> = source
            .lsdb
            .iter()
            .filter(|(key, _)| key.ls_type == LsaTypeV2::AsExternalLsa as u8)
            .map(|(key, _)| key.advertising_router)
            .collect();

        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for target in areas {
            // Stub/NSSA areas refuse type-4s — flush any stale ones and
            // move on.
            if self
                .ospf_areas
                .get(&target)
                .is_some_and(|area| area.kind.is_stubby())
            {
                let flushes: Vec<Lsa> = self
                    .ospf_areas
                    .get(&target)
                    .map(|area| {
                        area.lsdb
                            .iter()
                            .filter(|(key, _)| {
                                key.ls_type == LsaTypeV2::SummaryAsbrLsa as u8
                                    && key.advertising_router == router_id
                            })
                            .filter_map(|(_, entry)| flush_summary_lsa(&entry.lsa))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(area) = self.ospf_areas.get_mut(&target) {
                    for flush in flushes {
                        if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                            floods.push((target, vec![flush]));
                            changed = true;
                        }
                    }
                }
                continue;
            }
            // Existing self-originated type-4s, keyed by ASBR.
            let existing: BTreeMap<u32, Lsa> = self
                .ospf_areas
                .get(&target)
                .map(|area| {
                    area.lsdb
                        .iter()
                        .filter(|(key, _)| {
                            key.ls_type == LsaTypeV2::SummaryAsbrLsa as u8
                                && key.advertising_router == router_id
                        })
                        .map(|(key, entry)| (key.link_state_id, entry.lsa.clone()))
                        .collect()
                })
                .unwrap_or_default();

            let mut to_originate: Vec<Lsa> = Vec::new();
            let mut to_flush: Vec<Lsa> = Vec::new();
            let mut used_lsids: BTreeSet<u32> = BTreeSet::new();
            for &asbr in &asbrs {
                if asbr == router_id {
                    continue; // our own ASBR location is intra-area wherever we attach
                }
                let intra_here = spf_results
                    .get(&target)
                    .is_some_and(|r| r.vertices.contains_key(&spf::VertexId::Router(asbr)));
                if intra_here {
                    continue; // no type-4 needed
                }
                // The ABR's best cost to the ASBR across its other areas.
                let best: Option<u64> = spf_results
                    .iter()
                    .filter(|(id, _)| **id != target)
                    .filter_map(|(_, r)| r.vertices.get(&spf::VertexId::Router(asbr)))
                    .copied()
                    .min();
                let Some(cost) = best else {
                    continue; // unreachable through us — nothing to advertise
                };
                let dest =
                    lr_ospf::external::AsbrDestination::new(asbr, cost.min(0x00ff_fffe) as u32);
                used_lsids.insert(asbr);
                let prev = existing.get(&asbr);
                let unchanged = prev.is_some_and(|lsa| {
                    lr_ospf::lsa::decode_summary_lsa_body(&lsa.body)
                        .is_some_and(|b| b.tos0_metric() == Some(dest.metric))
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_summary_asbr_lsa(router_id, &dest, prev_seq) {
                    to_originate.push(lsa);
                }
            }
            // Flush type-4s whose ASBR no longer needs advertising.
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

    /// RFC 3101 §3.2: refresh the type-7 → type-5 translations this router
    /// maintains as a border router of its NSSAs.
    ///
    /// For every installed type-7 LSA in an attached NSSA that (a) is not
    /// the default, (b) carries the P-bit and (c) has a non-zero
    /// forwarding address (§3.2 step (1)), the elected translator
    /// (§3.1: highest router ID among the area's B-bit routers, Nt-bit
    /// wins) originates a type-5 copy — same network, mask, metric type,
    /// metric, forwarding address and tag; itself as advertising router —
    /// into every attached *regular* area (AS scope). Translations whose
    /// source disappeared, lost its P-bit or forwarding address, or whose
    /// translator role was lost are MaxAge-flushed. A locally redistributed
    /// network with the same link-state ID suppresses translation (the
    /// locally sourced type-5 wins, §3.2 note) and shields its LSA from
    /// the flush.
    ///
    /// Returns whether any LSDB changed.
    fn ospf_translate_nssa(&mut self) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        let abr = self.ospf_is_abr();
        // Desired translations keyed by their source type-7.
        let mut desired: BTreeMap<(u32, u32, u32), ExternalDestination> = BTreeMap::new();
        if abr {
            for (area_id, area) in &self.ospf_areas {
                if !area.kind.is_nssa() || area.protocol != Protocol::Ospfv2 {
                    continue;
                }
                if !is_elected_translator(&area.lsdb, router_id) {
                    continue; // §3.1: another border router translates
                }
                for (key, entry) in area.lsdb.iter() {
                    if key.ls_type != LsaTypeV2::NssaExternalLsa as u8 {
                        continue;
                    }
                    let Some(body) = lr_ospf::lsa::decode_as_external_body(&entry.lsa.body) else {
                        continue;
                    };
                    // §3.2 step (1): defaults, P-bit-clear LSAs and
                    // zero-forwarding-address LSAs are not translated.
                    if entry.lsa.header.options & N_P_BIT == 0
                        || body.forwarding_addr == 0
                        || body.network_mask == 0
                    {
                        continue;
                    }
                    // Locally sourced type-5s are never supplanted.
                    if self.ospf_externals.contains_key(&key.link_state_id) {
                        continue;
                    }
                    let prefix_len = lr_ospf::lsa::mask_to_prefix_len(body.network_mask);
                    let network = entry.lsa.header.link_state_id & body.network_mask;
                    let dest = ExternalDestination {
                        prefix: Prefix::new_v4(network.to_be_bytes(), prefix_len),
                        metric: body.metric_value(),
                        metric_type: ExternalMetricType::from_e_bit(body.external_type2()),
                        forwarding_addr: body.forwarding_addr,
                        route_tag: body.route_tag,
                        p_bit: false, // type-5s carry no P-bit
                    };
                    desired.insert((*area_id, key.link_state_id, key.advertising_router), dest);
                }
            }
        }
        // Track + flush bookkeeping for previously maintained translations.
        let stale: Vec<(u32, u32, u32)> = self
            .ospf_translations
            .iter()
            .filter(|k| !desired.contains_key(*k))
            .copied()
            .collect();
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        for key in stale {
            self.ospf_translations.remove(&key);
            // MaxAge-flush the self-originated type-5 copy of `key` from
            // every regular area (locally sourced type-5s are shielded).
            if self.ospf_externals.contains_key(&key.1) {
                continue;
            }
            let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
            for area_id in areas {
                let flush = self.ospf_areas.get(&area_id).and_then(|area| {
                    if area.kind.is_stubby() || area.protocol != Protocol::Ospfv2 {
                        return None;
                    }
                    area.lsdb
                        .iter()
                        .find(|(k, _)| {
                            k.ls_type == LsaTypeV2::AsExternalLsa as u8
                                && k.advertising_router == router_id
                                && k.link_state_id == key.1
                        })
                        .and_then(|(_, entry)| flush_external_lsa(&entry.lsa))
                });
                if let Some(flush) = flush {
                    if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                        if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                            floods.push((area_id, vec![flush]));
                            changed = true;
                        }
                    }
                }
            }
        }
        // Ensure every desired translation exists (unchanged) in every
        // regular area.
        for (key, dest) in &desired {
            self.ospf_translations.insert(*key);
            let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
            for area_id in areas {
                if !self
                    .ospf_areas
                    .get(&area_id)
                    .is_some_and(|a| !a.kind.is_stubby() && a.protocol == Protocol::Ospfv2)
                {
                    continue;
                }
                let prev = self.ospf_areas.get(&area_id).and_then(|area| {
                    area.lsdb
                        .iter()
                        .find(|(k, _)| {
                            k.ls_type == LsaTypeV2::AsExternalLsa as u8
                                && k.advertising_router == router_id
                                && k.link_state_id == key.1
                        })
                        .map(|(_, entry)| entry.lsa.clone())
                });
                let unchanged = prev.as_ref().is_some_and(|lsa| {
                    lr_ospf::lsa::decode_as_external_body(&lsa.body).is_some_and(|body| {
                        body.network_mask == prefix_len_to_mask(dest.prefix.prefix_len)
                            && body.external_type2() == dest.metric_type.e_bit()
                            && body.metric_value() == dest.metric
                            && body.forwarding_addr == dest.forwarding_addr
                            && body.route_tag == dest.route_tag
                    })
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.as_ref().map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_external_lsa(router_id, dest, prev_seq) {
                    if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                        if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                            floods.push((area_id, vec![lsa]));
                            changed = true;
                        }
                    }
                }
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        changed
    }

    // ----- cross-protocol redistribution engine -----

    /// Add a redistribution pipe (BIRD `pipe` / FRR `redistribute`).
    /// Routes from `pipe.source` that enter the Loc-RIB will be
    /// re-originated into `pipe.target` with the configured metric
    /// policy. Existing Loc-RIB routes are scanned immediately so the
    /// pipe takes effect on already-installed routes.
    pub fn add_redistribution_pipe(&mut self, pipe: crate::redistribution::RedistributionPipe) {
        self.pipes.push(pipe);
        // Scan existing Loc-RIB for routes that match the new pipe.
        let routes: Vec<Route> = self.loc_rib.iter_best().cloned().collect();
        for route in routes {
            self.redistribute_route(&route);
        }
    }

    /// Remove all redistribution pipes matching `(source, target)`.
    /// Returns the number of pipes removed.
    pub fn remove_redistribution_pipe(&mut self, source: Protocol, target: Protocol) -> usize {
        let before = self.pipes.len();
        self.pipes
            .retain(|p| !(p.source == source && p.target == target));
        before - self.pipes.len()
    }

    /// Apply redistribution for a single route that just entered (or
    /// changed in) the Loc-RIB. Called from `apply_selection` when the
    /// best route for a prefix changes.
    fn redistribute_route(&mut self, route: &Route) {
        // Collect matching pipes first to avoid borrowing self.pipes
        // while we mutate self via ospf_redistribute.
        let matches: Vec<crate::redistribution::RedistributionPipe> = self
            .pipes
            .iter()
            .filter(|p| p.source == route.protocol && p.matches(&route.key.prefix))
            .cloned()
            .collect();
        for pipe in matches {
            let metric = pipe.metric.apply(route.preference.metric);
            match pipe.target {
                Protocol::Bgp => {
                    let family = match route.key.family {
                        NlriFamily::IPV4_UNICAST => NlriFamily::IPV4_UNICAST,
                        NlriFamily::IPV6_UNICAST => NlriFamily::IPV6_UNICAST,
                        _ => continue,
                    };
                    let mut attrs = PathAttributes::new();
                    attrs.insert(PathAttribute::new(
                        PathAttrFlags::new().set_transitive(true),
                        AttrType::Origin,
                        vec![0],
                    ));
                    attrs.insert(PathAttribute::new(
                        PathAttrFlags::new().set_transitive(true),
                        AttrType::AsPath,
                        Vec::new(),
                    ));
                    if family == NlriFamily::IPV4_UNICAST {
                        if let Some(nh) = route.next_hop {
                            attrs.insert(PathAttribute::new(
                                PathAttrFlags::new().set_transitive(true),
                                AttrType::NextHop,
                                match nh {
                                    IpAddr::V4(b) => b.to_vec(),
                                    IpAddr::V6(b) => b.to_vec(),
                                },
                            ));
                        }
                    }
                    let bgp_route = Route {
                        key: route.key.clone(),
                        origin: RouteOrigin { proto: 2, peer: 0 },
                        protocol: Protocol::Bgp,
                        preference: lr_core::rib::Preference::new(
                            Protocol::Bgp.default_admin_distance(),
                            metric,
                        ),
                        next_hop: route.next_hop,
                        attributes: attrs.into(),
                        age_ms: self.now_ms,
                        path_id: 0,
                    };
                    self.loc_rib.install_set(&route.key, vec![bgp_route]);
                    self.redistributed_bgp
                        .insert(route.key.clone(), route.key.clone());
                    self.pending_events.push(RouterEvent::Log(format!(
                        "redistribute: {} -> BGP (metric={})",
                        route.key.prefix, metric
                    )));
                }
                Protocol::Ospfv2 | Protocol::Ospfv3 => {
                    if matches!(route.key.prefix.addr, IpAddr::V4(_)) {
                        let dest = ExternalDestination {
                            prefix: route.key.prefix,
                            metric,
                            metric_type: ExternalMetricType::Type1,
                            forwarding_addr: 0,
                            route_tag: pipe.tag,
                            p_bit: true,
                        };
                        self.ospf_redistribute(dest);
                        self.pending_events.push(RouterEvent::Log(format!(
                            "redistribute: {} -> OSPF (metric={})",
                            route.key.prefix, metric
                        )));
                    }
                }
                _ => {}
            }
        }
    }

    /// Withdraw a redistributed route. Called when the source route
    /// disappears from the Loc-RIB.
    fn unredistribute_route(&mut self, key: &RouteKey) {
        if let Some(bgp_key) = self.redistributed_bgp.remove(key) {
            self.loc_rib.uninstall(&bgp_key);
            self.pending_events.push(RouterEvent::Log(format!(
                "redistribute: withdraw {} from BGP",
                key.prefix
            )));
        }
    }

    /// Redistribute one external destination into OSPF (RFC 2328
    /// §12.4.3): originate a type-5 AS-external-LSA into every attached
    /// regular OSPFv2 area — type-5s are AS-scoped — and flood it. In
    /// NSSA areas the destination is originated as an area-scoped type-7
    /// LSA instead (RFC 3101 §2.4): with the P-bit set and a non-zero
    /// forwarding address it is later translated back into a type-5 by
    /// the elected border router; when this router is itself a border
    /// router that also sources the type-5 elsewhere, the P-bit is
    /// forced clear (§2.4). Stub areas receive nothing — they cannot
    /// carry external routing.
    ///
    /// The destination is remembered so areas attached later (or
    /// re-attached after their LSDB was dropped) receive it too.
    ///
    /// Returns `false` (and records nothing) for non-IPv4 destinations.
    /// The intent is still recorded when no OSPF session exists yet; it
    /// is originated as soon as the first OSPFv2 area attaches.
    ///
    /// Overlapping prefixes whose masked networks coincide (e.g.
    /// `10.0.0.0/8` and `10.0.0.0/16`) collide on one link-state ID — the
    /// later call replaces the earlier LSA (same limitation as summary
    /// origination; see `lr_ospf::abr`).
    pub fn ospf_redistribute(&mut self, dest: ExternalDestination) -> bool {
        let lr_core::addr::IpAddr::V4(octets) = dest.prefix.addr else {
            return false;
        };
        let mask = prefix_len_to_mask(dest.prefix.prefix_len);
        let network = u32::from_be_bytes(octets) & mask;
        self.ospf_externals.insert(network, dest);
        let changed = self.ospf_originate_externals(network);
        if changed {
            let delta = self.ospf_on_lsdb_change();
            self.apply_runtime_delta(delta);
        }
        true
    }

    /// Stop redistributing the external destination covering `prefix`
    /// (RFC 2328 §12.4.3, RFC 3101 §2.4): MaxAge-flush the
    /// self-originated type-5 LSA (regular areas) and type-7 LSA (NSSAs)
    /// from every area and flood the flush. Returns `false` when no
    /// matching redistribution exists.
    pub fn ospf_unredistribute(&mut self, prefix: Prefix) -> bool {
        let lr_core::addr::IpAddr::V4(octets) = prefix.addr else {
            return false;
        };
        let mask = prefix_len_to_mask(prefix.prefix_len);
        let network = u32::from_be_bytes(octets) & mask;
        if self.ospf_externals.remove(&network).is_none() {
            return false;
        }
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for area_id in areas {
            let mut flushes = Vec::new();
            if let Some(area) = self.ospf_areas.get(&area_id) {
                for (key, entry) in area.lsdb.iter() {
                    let external = key.ls_type == LsaTypeV2::AsExternalLsa as u8
                        || key.ls_type == LsaTypeV2::NssaExternalLsa as u8;
                    if external
                        && key.advertising_router == self.ospf_router_id.unwrap_or(0)
                        && key.link_state_id == network
                    {
                        if let Some(flush) = flush_external_lsa(&entry.lsa) {
                            flushes.push(flush);
                        }
                    }
                }
            }
            if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                for flush in flushes {
                    if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                        floods.push((area_id, vec![flush]));
                        changed = true;
                    }
                }
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        if changed {
            let delta = self.ospf_on_lsdb_change();
            self.apply_runtime_delta(delta);
        }
        changed
    }

    /// Ensure every attached OSPFv2 area carries the current
    /// self-originated type-5 set (areas that attached after the
    /// redistribution call, or whose LSDB was dropped and recreated,
    /// re-originate from [`Self::ospf_externals`]). Installs nothing when
    /// every area is already up to date. Returns whether any LSDB changed.
    fn ospf_sync_externals(&mut self) -> bool {
        if self.ospf_externals.is_empty() {
            return false;
        }
        let mut changed = false;
        let networks: Vec<u32> = self.ospf_externals.keys().copied().collect();
        for network in networks {
            changed |= self.ospf_originate_externals(network);
        }
        changed
    }

    /// Originate (or refresh) the self-originated external LSA for
    /// `network` in every attached OSPFv2 area: a type-5 in regular
    /// areas, an area-scoped type-7 in NSSAs (RFC 3101 §2.4 — with the
    /// P-bit forced clear when this border router also sources the
    /// type-5 into its regular areas, so no other border router
    /// translates a duplicate) and nothing in stub areas. Floods what
    /// changed. Returns whether any LSDB changed.
    fn ospf_originate_externals(&mut self, network: u32) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false; // no OSPF session yet — kept for later
        };
        let Some(&dest) = self.ospf_externals.get(&network) else {
            return false;
        };
        // RFC 3101 §2.4: an NSSA border router originating both the
        // type-5 and the type-7 for one network must clear the type-7's
        // P-bit (otherwise another border router would translate a
        // duplicate type-5).
        let sources_type5_too = self.ospf_is_abr()
            && self
                .ospf_areas
                .values()
                .any(|a| a.protocol == Protocol::Ospfv2 && !a.kind.is_stubby());
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for area_id in areas {
            let Some(kind) = self
                .ospf_areas
                .get(&area_id)
                .filter(|a| a.protocol == Protocol::Ospfv2)
                .map(|a| a.kind)
            else {
                continue; // v2 bodies only
            };
            // NSSA: area-scoped type-7 (RFC 3101 §2.4).
            if kind.is_nssa() {
                let mut nssa_dest = dest;
                if sources_type5_too {
                    nssa_dest.p_bit = false;
                }
                let prev = self.ospf_areas.get(&area_id).and_then(|area| {
                    area.lsdb
                        .iter()
                        .find(|(key, _)| {
                            key.ls_type == LsaTypeV2::NssaExternalLsa as u8
                                && key.advertising_router == router_id
                                && key.link_state_id == network
                        })
                        .map(|(_, entry)| entry.lsa.clone())
                });
                let desired_p = nssa_dest.p_bit && nssa_dest.forwarding_addr != 0;
                let unchanged = prev.as_ref().is_some_and(|lsa| {
                    (lsa.header.options & N_P_BIT != 0) == desired_p
                        && lr_ospf::lsa::decode_as_external_body(&lsa.body).is_some_and(|body| {
                            body.network_mask == prefix_len_to_mask(dest.prefix.prefix_len)
                                && body.external_type2() == dest.metric_type.e_bit()
                                && body.metric_value() == dest.metric
                                && body.forwarding_addr == dest.forwarding_addr
                                && body.route_tag == dest.route_tag
                        })
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.as_ref().map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_nssa_lsa(router_id, &nssa_dest, prev_seq) {
                    if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                        if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                            floods.push((area_id, vec![lsa]));
                            changed = true;
                        }
                    }
                }
                continue;
            }
            // Stub areas carry no externals at all.
            if kind.is_stub() {
                // Stale self type-5s from a pre-conversion era are
                // flushed so they cannot linger in the LSDB.
                let flush = self.ospf_areas.get(&area_id).and_then(|area| {
                    area.lsdb
                        .iter()
                        .find(|(key, _)| {
                            key.ls_type == LsaTypeV2::AsExternalLsa as u8
                                && key.advertising_router == router_id
                                && key.link_state_id == network
                        })
                        .and_then(|(_, entry)| flush_external_lsa(&entry.lsa))
                });
                if let Some(flush) = flush {
                    if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                        if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                            floods.push((area_id, vec![flush]));
                            changed = true;
                        }
                    }
                }
                continue;
            }
            // Regular area: AS-scoped type-5.
            let prev = self.ospf_areas.get(&area_id).and_then(|area| {
                area.lsdb
                    .iter()
                    .find(|(key, _)| {
                        key.ls_type == LsaTypeV2::AsExternalLsa as u8
                            && key.advertising_router == router_id
                            && key.link_state_id == network
                    })
                    .map(|(_, entry)| entry.lsa.clone())
            });
            let unchanged = prev.as_ref().is_some_and(|lsa| {
                lr_ospf::lsa::decode_as_external_body(&lsa.body).is_some_and(|body| {
                    body.network_mask == prefix_len_to_mask(dest.prefix.prefix_len)
                        && body.external_type2() == dest.metric_type.e_bit()
                        && body.metric_value() == dest.metric
                        && body.forwarding_addr == dest.forwarding_addr
                        && body.route_tag == dest.route_tag
                })
            });
            if unchanged {
                continue;
            }
            let prev_seq = prev.as_ref().map(|lsa| lsa.header.ls_sequence_number);
            if let Some(lsa) = originate_external_lsa(router_id, &dest, prev_seq) {
                if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                    if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                        floods.push((area_id, vec![lsa]));
                        changed = true;
                    }
                }
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        changed
    }

    /// Change the type policy of an attached OSPF area (RFC 2328 §3.6,
    /// RFC 3101). Self-originated LSAs the new type refuses are
    /// MaxAge-flushed and flooded; LSAs of other routers that the new
    /// type refuses are dropped locally (they age out at their
    /// originators' refresh, which the install filter refuses from now
    /// on). The route table is recomputed. Returns whether the
    /// conversion was applied — `false` for unknown areas or no-op
    /// conversions.
    pub fn ospf_set_area_type(&mut self, area_id: u32, kind: OspfAreaType) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        // Scoped LSDB surgery: partition refused LSAs — ours get flushed
        // (so neighbors purge them too), others' are dropped locally.
        let mut to_flood: Vec<Lsa> = Vec::new();
        {
            let Some(area) = self.ospf_areas.get_mut(&area_id) else {
                return false;
            };
            if area.kind == kind {
                return false;
            }
            // RFC 2328 §3.6: the backbone is never a stub area (nor an
            // NSSA — RFC 3101 §2.1).
            if area_id == 0 && kind != OspfAreaType::Normal {
                return false;
            }
            area.kind = kind;
            let mut flushes: Vec<Lsa> = Vec::new();
            let mut drop_keys = Vec::new();
            for (key, entry) in area.lsdb.iter() {
                if ospf_area_accepts(&kind, &entry.lsa) {
                    continue;
                }
                if key.advertising_router == router_id {
                    if let Some(flush) = flush_summary_lsa(&entry.lsa) {
                        flushes.push(flush);
                    }
                } else {
                    drop_keys.push(*key);
                }
            }
            for key in drop_keys {
                area.lsdb.remove(&key);
            }
            for flush in flushes {
                if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                    to_flood.push(flush);
                }
            }
        }
        if !to_flood.is_empty() {
            self.ospf_flood(area_id, &to_flood, None);
        }
        // Re-run the origination machinery: summaries per the new kind,
        // defaults, externals per area type — then recompute.
        let delta = self.ospf_on_lsdb_change();
        self.apply_runtime_delta(delta);
        true
    }

    // ------------------------------------------------------------------
    // Virtual links (RFC 2328 §15)
    // ------------------------------------------------------------------

    /// Configure a virtual link to the area border router `endpoint`,
    /// riding through `transit_area` (RFC 2328 §15). Both endpoints must
    /// configure each other; the link is up as soon as this router's
    /// transit-area SPF reaches the endpoint. While up it materializes a
    /// backbone (area 0) adjacency — see
    /// [`Self::ospf_virtual_link_session`] for the transport handle.
    ///
    /// Refused (`false`) when OSPF is not active, the transit area is not
    /// attached, runs OSPFv3 or is a stub/NSSA area (§15: virtual links
    /// cannot cross stub areas; RFC 3101 §2.1 extends this to NSSAs), the
    /// endpoint is this router itself, or the link already exists.
    ///
    /// Router-LSA origination stays with the embedder: the endpoints
    /// advertise the link as a type-4 link in their backbone router-LSAs
    /// (metric = transit-area path cost) and set the V-bit in their
    /// transit-area router-LSAs, exactly as on the wire.
    pub fn ospf_add_virtual_link(&mut self, transit_area: u32, endpoint: u32) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        if endpoint == router_id {
            return false;
        }
        if self.ospf_vlinks.contains_key(&(transit_area, endpoint)) {
            return false;
        }
        match self.ospf_areas.get(&transit_area) {
            Some(area) if area.protocol == Protocol::Ospfv2 && !area.kind.is_stubby() => {}
            _ => return false,
        }
        self.ospf_vlinks
            .insert((transit_area, endpoint), OspfVirtualLink { session: None });
        if self.ospf_eval_virtual_links() {
            let delta = self.ospf_on_lsdb_change();
            self.apply_runtime_delta(delta);
        }
        true
    }

    /// Remove a configured virtual link, tearing down its backbone
    /// adjacency (and the routes it justified) when it was up. Returns
    /// whether the link existed.
    pub fn ospf_remove_virtual_link(&mut self, transit_area: u32, endpoint: u32) -> bool {
        let Some(vlink) = self.ospf_vlinks.remove(&(transit_area, endpoint)) else {
            return false;
        };
        if let Some(h) = vlink.session {
            if self.sessions.contains_key(&h.0) {
                let _ = self.remove_session(h);
            }
        }
        true
    }

    /// Whether the virtual link through `transit_area` to `endpoint` is
    /// currently up (RFC 2328 §15: the endpoint is intra-area reachable
    /// through the transit area).
    pub fn ospf_virtual_link_up(&self, transit_area: u32, endpoint: u32) -> bool {
        self.ospf_vlinks
            .get(&(transit_area, endpoint))
            .is_some_and(|v| v.session.is_some())
    }

    /// The backbone session handle of an up virtual link — the embedder
    /// wires its transport: drain it with
    /// [`RouterInstance::drain_output`] and deliver the bytes to the
    /// peer endpoint's virtual session (tunnelled through the transit
    /// area), feeding what returns the same way. `None` while the link
    /// is down.
    pub fn ospf_virtual_link_session(
        &self,
        transit_area: u32,
        endpoint: u32,
    ) -> Option<SessionHandle> {
        self.ospf_vlinks
            .get(&(transit_area, endpoint))
            .and_then(|v| v.session)
    }

    /// Re-evaluate every configured virtual link (RFC 2328 §15): a link
    /// is up when this router's SPF over the transit area's LSDB reaches
    /// the endpoint. Coming up materializes a backbone (area 0) session —
    /// restoring border-router status for a router without a physical
    /// backbone attachment; going down tears that session down again
    /// (flushing whatever it justified). Returns whether any session
    /// churned; callers follow up with [`Self::ospf_on_lsdb_change`].
    fn ospf_eval_virtual_links(&mut self) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        let mut changed = false;
        let keys: Vec<(u32, u32)> = self.ospf_vlinks.keys().copied().collect();
        for key in keys {
            let up = self
                .ospf_areas
                .get(&key.0)
                .filter(|area| area.protocol == Protocol::Ospfv2)
                .is_some_and(|area| {
                    let transit_spf = spf::run_spf(&area.lsdb, router_id);
                    transit_spf
                        .vertices
                        .contains_key(&spf::VertexId::Router(key.1))
                });
            // A session the embedder removed behind our back counts as
            // down so the link is re-materialized on the next pass.
            let current = self
                .ospf_vlinks
                .get(&key)
                .and_then(|v| v.session)
                .filter(|h| self.sessions.contains_key(&h.0));
            if let Some(v) = self.ospf_vlinks.get_mut(&key) {
                v.session = current;
            }
            match (up, current) {
                (true, None) => {
                    // Materialize the backbone adjacency. The session is
                    // registered before any re-entrant evaluation so the
                    // link cannot be brought up twice.
                    let handle = SessionHandle(self.next_handle);
                    self.next_handle += 1;
                    self.ospf_areas.entry(0).or_insert(OspfAreaState {
                        lsdb: Lsdb::new(),
                        protocol: Protocol::Ospfv2,
                        kind: OspfAreaType::Normal,
                    });
                    let runtime = OspfRuntime::new(router_id, 0, false, 1500);
                    self.sessions.insert(
                        handle.0,
                        SessionState::Ospf {
                            runtime,
                            conn: MemoryConn::new(),
                        },
                    );
                    if let Some(v) = self.ospf_vlinks.get_mut(&key) {
                        v.session = Some(handle);
                    }
                    changed = true;
                }
                (false, Some(h)) => {
                    // Tear the adjacency down; `remove_session` runs the
                    // full pipeline (flushing summaries that lost their
                    // justification).
                    if let Some(v) = self.ospf_vlinks.get_mut(&key) {
                        v.session = None;
                    }
                    let _ = self.remove_session(h);
                    changed = true;
                }
                _ => {}
            }
        }
        if changed {
            // A freshly attached virtual backbone must catch up on the
            // self-originated type-5 set, like any newly attached area.
            self.ospf_sync_externals();
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

    /// True when the session's output carries only LS-Acks (no data).
    fn drain_is_ack_only(r: &mut DefaultRouter, h: SessionHandle) -> bool {
        let bytes = r.drain_output(h);
        let mut codec = lr_ospf::codec::OspfCodec::v2();
        let mut reader = lr_core::buf::ReadBuf::new(&bytes);
        let mut ack_only = true;
        let mut any = false;
        while let Ok(Some(pkt)) = codec.decode(&mut reader) {
            any = true;
            if !matches!(pkt.body, OspfBody::LsAck(_)) {
                ack_only = false;
            }
        }
        any && ack_only
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
        // Session a's output is at most the acknowledgement of what it
        // delivered — never a flood of its own LSA back.
        assert!(
            drain_is_ack_only(&mut r, a) || r.drain_output(a).is_empty(),
            "no flood back to the source"
        );

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
        // The summary targets the backbone only (area 1 sees at most the
        // acknowledgement of what it delivered).
        assert!(drain_is_ack_only(&mut r, h1) || r.drain_output(h1).is_empty());
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
            drain_is_ack_only(&mut r, h2) || r.drain_output(h2).is_empty(),
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
        // h1's output is at most its acknowledgement of the delivery;
        // h2 (backbone) must see nothing without an ABR summary.
        assert!(drain_is_ack_only(&mut r, h1) || r.drain_output(h1).is_empty());
        assert!(r.drain_output(h2).is_empty());
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
    fn ospf_area_type_mismatch_rejected_and_runtime_change_allowed() {
        let mut r = DefaultRouter::new();
        let rid = RouterId::from_u32(0x01010101);
        let _h = r
            .add_session(SessionConfig::ospfv2(rid, 1).with_ospf_area_type(OspfAreaType::nssa(10)))
            .unwrap();
        // A second session with a different area type must be rejected...
        assert!(
            r.add_session(
                SessionConfig::ospfv2(rid, 1).with_ospf_area_type(OspfAreaType::stub(5)),
            )
            .is_err(),
            "conflicting area types must be rejected at attach"
        );
        // ...while the same type attaches fine.
        assert!(r
            .add_session(SessionConfig::ospfv2(rid, 1).with_ospf_area_type(OspfAreaType::nssa(10)),)
            .is_ok());
        // Runtime conversion through the dedicated API works.
        assert!(r.ospf_set_area_type(1, OspfAreaType::stub(5)));
        assert!(
            !r.ospf_set_area_type(1, OspfAreaType::stub(5)),
            "a no-op conversion changes nothing"
        );
        assert!(!r.ospf_set_area_type(99, OspfAreaType::stub(5)));
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

    // ===== RFC 8212 default eBGP route behaviors =====

    /// A plain eBGP pair (no graceful restart, no MRAI) with the
    /// RFC 8212 mode armed on the receiving side.
    fn ebgp_pair() -> (DefaultRouter, SessionHandle, DefaultRouter, SessionHandle) {
        let mut a = DefaultRouter::new();
        let mut b = DefaultRouter::new();
        let a_session = a
            .add_session(
                SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(0),
            )
            .unwrap();
        let b_session = b
            .add_session(
                SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(0),
            )
            .unwrap();
        (a, a_session, b, b_session)
    }

    fn logs_contain(a: &mut DefaultRouter, needle: &str) -> bool {
        a.poll_events()
            .iter()
            .any(|e| matches!(e, RouterEvent::Log(m) if m.contains(needle)))
    }

    #[test]
    fn rfc8212_off_by_default_keeps_rfc4271_behaviour() {
        // Without the mode, a policy-less eBGP session accepts and
        // advertises everything (library back-compat; the daemon is
        // what turns the mode on).
        let (mut a, a_session, mut b, b_session) = ebgp_pair();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);
        assert_eq!(a.rib_len(), 1);
    }

    #[test]
    fn rfc8212_ebgp_import_denied_without_policy() {
        let (mut a, a_session, mut b, b_session) = ebgp_pair();
        a.set_ebgp_requires_policy(true);
        establish(&mut a, a_session, &mut b, b_session);

        b.originate(
            Prefix::new_v4([198, 51, 100, 0], 24),
            Some(IpAddr::V4([192, 0, 2, 10])),
        );
        let advertisement = b.drain_output(b_session);
        assert!(!advertisement.is_empty());
        a.feed_input(a_session, &advertisement).unwrap();
        assert_eq!(
            a.rib_len(),
            0,
            "routes from a policy-less external peer must not reach the Loc-RIB"
        );
        assert!(
            logs_contain(&mut a, "no import policy"),
            "the denial is surfaced once as a log event"
        );
    }

    #[test]
    fn rfc8212_ebgp_import_allowed_with_explicit_policy() {
        let (mut a, a_session, mut b, b_session) = ebgp_pair();
        a.set_ebgp_requires_policy(true);
        a.set_session_policy(a_session, true, false).unwrap();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);
        assert_eq!(a.rib_len(), 1);
    }

    #[test]
    fn rfc8212_ebgp_export_denied_without_policy() {
        let (mut a, a_session, mut b, b_session) = ebgp_pair();
        a.set_ebgp_requires_policy(true);
        establish(&mut a, a_session, &mut b, b_session);
        assert!(logs_contain(&mut a, "no export policy"));

        a.originate(
            Prefix::new_v4([203, 0, 113, 0], 24),
            Some(IpAddr::V4([192, 0, 2, 1])),
        );
        // The drained bytes may carry the session's End-of-RIB marker
        // from establishment — what matters is that no UPDATE flows.
        let bytes = a.drain_output(a_session);
        if !bytes.is_empty() {
            b.feed_input(b_session, &bytes).unwrap();
        }
        assert_eq!(
            b.rib_len(),
            0,
            "a policy-less external peer must not receive advertisements"
        );
    }

    #[test]
    fn rfc8212_ebgp_export_allowed_with_explicit_policy() {
        let (mut a, a_session, mut b, b_session) = ebgp_pair();
        a.set_ebgp_requires_policy(true);
        a.set_session_policy(a_session, false, true).unwrap();
        establish(&mut a, a_session, &mut b, b_session);

        a.originate(
            Prefix::new_v4([203, 0, 113, 0], 24),
            Some(IpAddr::V4([192, 0, 2, 1])),
        );
        let advertisement = a.drain_output(a_session);
        assert!(!advertisement.is_empty());
        b.feed_input(b_session, &advertisement).unwrap();
        assert_eq!(b.rib_len(), 1);
    }

    #[test]
    fn rfc8212_spared_for_ibgp() {
        // RFC 8212 §1 scopes the default behaviors to EBGP sessions;
        // iBGP keeps the RFC 4271 default-accept.
        let mut a = DefaultRouter::new();
        let mut b = DefaultRouter::new();
        a.set_ebgp_requires_policy(true);
        b.set_ebgp_requires_policy(true);
        let a_session = a
            .add_session(
                SessionConfig::bgp(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(0),
            )
            .unwrap();
        let b_session = b
            .add_session(
                SessionConfig::bgp(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                    .with_mrai_ms(0)
                    .with_graceful_restart(0),
            )
            .unwrap();
        establish(&mut a, a_session, &mut b, b_session);
        b_advertise_to_a(&mut a, a_session, &mut b, b_session);
        assert_eq!(a.rib_len(), 1);

        a.originate(
            Prefix::new_v4([203, 0, 113, 0], 24),
            Some(IpAddr::V4([192, 0, 2, 1])),
        );
        let advertisement = a.drain_output(a_session);
        assert!(!advertisement.is_empty());
        b.feed_input(b_session, &advertisement).unwrap();
        // B holds its own 198.51.100.0/24 plus the learned
        // 203.0.113.0/24 — iBGP exchanges flow without policy.
        assert!(
            b.rib_snapshot()
                .iter()
                .any(|r| r.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24)),
            "iBGP keeps the RFC 4271 default-accept"
        );
    }

    #[test]
    fn rfc8212_export_policy_removal_withdraws_advertised_routes() {
        let (mut a, a_session, mut b, b_session) = ebgp_pair();
        a.set_ebgp_requires_policy(true);
        a.set_session_policy(a_session, false, true).unwrap();
        establish(&mut a, a_session, &mut b, b_session);

        a.originate(
            Prefix::new_v4([203, 0, 113, 0], 24),
            Some(IpAddr::V4([192, 0, 2, 1])),
        );
        let advertisement = a.drain_output(a_session);
        b.feed_input(b_session, &advertisement).unwrap();
        assert_eq!(b.rib_len(), 1);

        // Policy withdrawn at runtime: the Adj-RIB-Out must be emptied
        // and the far side must see the withdrawal (RFC 8212 §3).
        a.set_session_policy(a_session, false, false).unwrap();
        let withdrawal = a.drain_output(a_session);
        assert!(!withdrawal.is_empty());
        b.feed_input(b_session, &withdrawal).unwrap();
        assert_eq!(b.rib_len(), 0);
    }

    #[test]
    fn rfc8212_unknown_session_rejected() {
        let mut a = DefaultRouter::new();
        let err = a
            .set_session_policy(SessionHandle(99), true, true)
            .unwrap_err();
        assert!(err.contains("unknown session 99"), "{err}");
    }
}
