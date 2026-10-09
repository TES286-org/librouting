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
use crate::event::{OspfGraceEvent, RouterEvent};
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
use lr_bgp::error::{BgpCeaseSubcode, BgpErrorCode};
use lr_bgp::path::{AttrType, Community, PathAttrFlags, PathAttribute, PathAttributes};
use lr_bgp::{BgpAction, BgpEvent, BgpPeer, BgpState, PeerConfig as BgpPeerConfig};
use lr_ospf::abr::{
    flush_summary_lsa, originate_summary_lsa, originate_v3_inter_area_prefix_lsa,
    SummaryDestination,
};
use lr_ospf::external::{
    external_routes, flush_external_lsa, originate_external_lsa, originate_summary_asbr_lsa,
    ExternalDestination, ExternalMetricType,
};
use lr_ospf::lsa::v3::{
    originate_v3_as_external_lsa, originate_v3_inter_area_router_lsa, V3ExternalDestination,
};
use lr_ospf::lsa::{prefix_len_to_mask, Lsa, LsaTypeV2};
use lr_ospf::lsdb::Lsdb;
use lr_ospf::neighbor::{NeighborEvent, NeighborState, OspfNeighbor};
use lr_ospf::nssa::{
    flush_nssa_lsa, is_elected_translator, nssa_routes, originate_nssa_default_lsa,
    originate_nssa_lsa, NssaCalcOpts, NssaDefault, N_P_BIT,
};
use lr_ospf::packet::{OspfBody, OspfPacket};
use lr_ospf::spf;
use lr_policy::hooks::{HookChain, HookVerdict};
use lr_policy::safety::{SafetyNet, SafetyViolation};
use lr_rib::selection::RouteSelector;
use lr_rib::{AdjRibIn, AdjRibOut, LocRib, RibMux};

mod babel;
mod ospf;

use babel::*;
use ospf::*;

/// The router trait — embedders can plug a mock implementation.
pub trait RouterInstance {
    fn add_session(&mut self, cfg: SessionConfig) -> Result<SessionHandle, String>;
    fn remove_session(&mut self, h: SessionHandle) -> Result<(), String>;
    /// Begin protocol operation on a session (BGP: ManualStart +
    /// TransportOpen). Call once the transport is connected.
    fn start_session(&mut self, h: SessionHandle) -> Result<(), String>;
    fn feed_input(&mut self, h: SessionHandle, bytes: &[u8]) -> Result<(), String>;
    /// Feed one received datagram together with the transport's clocks:
    /// `now_ms` — wall-clock milliseconds since the transport started,
    /// the liveness/expiry reference (RFC 8966 §3.2.5) — and `now_us` —
    /// the 32-bit microsecond BABEL-RTT timestamp reference (RFC 8966
    /// §A.2.4). Both must be drawn from the same clock the outgoing
    /// Hello/IHU timestamps use. Defaults to zeroing both for
    /// implementors without fine-grained clocks; only the Babel runtime
    /// consumes the extra precision.
    fn feed_input_at(
        &mut self,
        h: SessionHandle,
        bytes: &[u8],
        now_ms: u64,
        now_us: u32,
    ) -> Result<(), String> {
        let _ = (now_ms, now_us);
        self.feed_input(h, bytes)
    }
    fn drain_output(&mut self, h: SessionHandle) -> Vec<u8>;
    fn tick(&mut self, now: Instant);
    /// Request that an established peer resend its Adj-RIB-Out for `family`.
    /// Returns `false` if RFC 2918 was not negotiated for that session.
    fn request_route_refresh(&mut self, h: SessionHandle, family: NlriFamily) -> bool;
    /// Set the per-prefix RFC 4271 MRAI interval for a BGP session.
    fn set_mrai(&mut self, h: SessionHandle, interval_ms: u64) -> Result<(), String>;
    fn poll_events(&mut self) -> Vec<RouterEvent>;
    /// Push events back to the *front* of the pending queue, keeping
    /// their relative order. Used by embedders whose poll buffer fills
    /// mid-batch (the FFI event-poll shape): poll + serialize + requeue
    /// is one logical drain, so no event is lost. The default no-op
    /// keeps mock implementations source-compatible.
    fn requeue_events(&mut self, _events: Vec<RouterEvent>) {}
    fn rib_snapshot(&self) -> Vec<&Route>;

    /// Current BGP FSM state name of a session ("Idle", "Connect", …,
    /// "Established"), or `None` for non-BGP / unknown sessions.
    /// Embedders use it to notice a transport the router closed while
    /// the TCP connection is still alive — the RFC 4271 §6.8 collision
    /// loser: the Cease NOTIFICATION was queued and must be flushed,
    /// then the socket goes away.
    fn session_peer_state(&self, _h: SessionHandle) -> Option<&'static str> {
        None
    }

    /// Remaining milliseconds of the max-prefix `Restart` cooldown for a
    /// session, or `None` when no cooldown is in effect (the session never
    /// tripped `Restart`, or the configured cooldown has elapsed). The
    /// daemon's outbound connector reads this before dialing so a peer that
    /// exceeded its prefix limit cannot re-establish until the configured
    /// cooldown elapses (FRR `bgp maximum-prefix restart <secs>`, BIRD
    /// `restart time`). Driven by the router clock advanced in [`tick`].
    fn session_restart_cooldown_remaining(&self, _h: SessionHandle) -> Option<u64> {
        None
    }

    /// Consume the §6.8 collision-loss latch of a session: `true` when
    /// the session lost an RFC 4271 §6.8 collision — its own resolver
    /// closed it, or a Cease / Connection Collision Resolution
    /// NOTIFICATION (RFC 4486 subcode 7) arrived — since the latch was
    /// last consumed (or the session last started). Embedders use it to
    /// back the connector off instead of redialing into a peer that
    /// already holds a live session (BIRD parity: the collision loser
    /// waits out its ConnectRetry, it does not hammer).
    fn take_collision_lost(&mut self, _h: SessionHandle) -> bool {
        false
    }

    /// Whether the session's CURRENT transport incarnation ever reached
    /// Established. Used by embedders to reset reconnect backoff only
    /// after a genuinely working session (a handshake that died at
    /// OpenConfirm must keep the exponential backoff growing).
    fn session_was_established(&self, _h: SessionHandle) -> bool {
        false
    }

    /// Every path of every prefix (the RFC 7911 Add-Path view of the
    /// Loc-RIB). Defaults to the best-path snapshot for implementors
    /// without path multiplicity.
    fn rib_paths_snapshot(&self) -> Vec<&Route> {
        self.rib_snapshot()
    }

    /// The feasible routes learned over every Babel session except
    /// `exclude` (per-session split horizon — the re-advertisement set
    /// RFC 8966 §3.7.1 requires a multi-interface speaker to offer on
    /// its other interfaces). Duplicates across sessions collapse to
    /// the lowest metric per (destination, source, router-id) claim.
    /// Defaults to empty for implementors without a Babel runtime.
    fn babel_reachable(&self, _exclude: SessionHandle) -> Vec<lr_babel::BabelRoute> {
        Vec::new()
    }

    /// Drop every route learned over the Babel session `h` and apply the
    /// withdrawal delta to Loc-RIB — the `check link` response when an
    /// interface goes operationally down (BIRD `check link yes`,
    /// RFC 8966 §A.2). Defaults to a no-op for implementors without a
    /// Babel runtime.
    fn babel_flush_session(&mut self, _h: SessionHandle) {}

    /// The smoothed RTT measured toward the peer of Babel session `h`
    /// (BABEL-RTT, RFC 8966 §A.2.4), when a fresh sample exists.
    /// Defaults to `None` for implementors without a Babel runtime.
    fn babel_rtt_us(&self, _h: SessionHandle, _now_ms: u64) -> Option<u32> {
        None
    }

    /// The BABEL-RTT pair the next IHU toward the session's peer should
    /// echo — `(peer Hello timestamp, our receive time)`, valid only
    /// while the Hello is fresh (RFC 8966 §A.2.4; babeld's 1 s echo
    /// window). Defaults to `None` for implementors without a Babel
    /// runtime.
    fn babel_rtt_echo(&self, _h: SessionHandle, _now_ms: u64) -> Option<(u32, u32)> {
        None
    }

    /// One Babel expiry sweep (RFC 8966 §3.2.5): expire routes whose
    /// re-announcement hold time lapsed and retract everything a dead
    /// neighbour taught us, applying the Loc-RIB deltas. The transport
    /// should call this about once a second. Default: no-op for
    /// implementors without a Babel runtime.
    fn babel_gc(&mut self, _now_ms: u64) {}

    /// Pin the Babel router-id this node announces on session `h`
    /// (RFC 8966 §3.3). Updates that echo it back — a peer re-advertising
    /// our own claims — are then ignored, exactly like BIRD's
    /// `babel_handle_update` self-router-id guard. Default: no-op for
    /// implementors without a Babel runtime.
    fn set_babel_own_router_id(&mut self, _h: SessionHandle, _id: [u8; 8]) {}

    /// Configure the reception-side link-cost ramp of Babel session `h`
    /// (RFC 8966 §A.2.4): the RTT penalty bounds and maximum applied on
    /// top of the txcost learned from the peer's IHU when an Update's
    /// advertised metric is folded into the local route metric.
    /// `rtt_cost` 0 (babeld's default) keeps the RTT feature off.
    /// Default: no-op for implementors without a Babel runtime.
    fn set_babel_link_cost_params(
        &mut self,
        _h: SessionHandle,
        _rtt_min_us: u32,
        _rtt_max_us: u32,
        _rtt_cost: u16,
    ) {
    }

    /// Tell the Babel runtime the address the peer's datagrams come
    /// from. RFC 8966 §3.5.3: an Update with no preceding NextHop TLV
    /// resolves its next hop to the *sender* — BIRD relies on this and
    /// omits the v6 NextHop TLV for its own announcements. The runtime
    /// is constructed with the local bind address, so the transport
    /// MUST call this per datagram or v6 routes fall back to our own
    /// address as the next hop. Default: no-op for implementors without
    /// a Babel runtime.
    fn babel_note_peer(&mut self, _h: SessionHandle, _peer: lr_core::addr::IpAddr) {}

    /// The current next-hop addresses the Babel peer of session `h`
    /// advertises in its Update streams — `(AE 1 v4, AE 2/3 v6)` as
    /// learned from the NextHop TLVs (RFC 8966 §4.6.4), plus the
    /// implicit peer-address fallbacks once a datagram has been seen.
    ///
    /// The egress interface for every route learned on the session is
    /// the session's own interface (babeld installs kernel routes with
    /// `neigh->ifp`; BIRD resolves through the neighbour's iface) —
    /// *not* whatever interface the kernel's own next-hop resolution
    /// prefers. Embedders that mirror the Loc-RIB into the kernel FIB
    /// use these addresses to pin the egress interface per next hop,
    /// especially for v4-in-v6 transport where the v4 next hop is not
    /// on-link anywhere and longest-prefix resolution can land the
    /// route on an unrelated adapter (the rc.4 Windows production
    /// defect). Default: `None` for implementors without a Babel
    /// runtime.
    fn babel_egress_nexthops(
        &self,
        _h: SessionHandle,
    ) -> Option<(Option<lr_core::addr::IpAddr>, Option<lr_core::addr::IpAddr>)> {
        None
    }

    /// Withdraw every Loc-RIB route (queueing the RouteWithdrawn events
    /// the kernel mirror consumes). Called once during daemon shutdown
    /// after the sessions flushed their close NOTIFICATIONs, so the
    /// routes this daemon installed leave the kernel with it — BIRD's
    /// krt parity. Default: no-op for implementors without a RIB.
    fn flush_rib_for_shutdown(&mut self) {}

    /// Take the pending "a Route Request arrived" flag (RFC 8966
    /// §3.2.6): true exactly once after any Route Request TLV (wildcard
    /// or specific) was seen on session `h`. The transport answers by
    /// announcing immediately instead of waiting for the periodic tick.
    /// Default: `false` for implementors without a Babel runtime.
    fn babel_take_route_request(&mut self, _h: SessionHandle) -> bool {
        false
    }

    /// Take the pending "a Seqno Request for *our own* router-id
    /// arrived" event (RFC 8966 §3.2.6.2): `Some(seqno)` exactly once
    /// after a peer asked us to re-announce with (at least) that seqno
    /// — the restart-recovery path when a peer remembers a higher
    /// seqno than our fresh boot value. The transport bumps its
    /// announcement seqno to at least `seqno` and re-announces.
    /// Default: `None` for implementors without a Babel runtime.
    fn babel_take_own_seqno_request(&mut self, _h: SessionHandle) -> Option<u16> {
        None
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
        /// Whether THIS transport incarnation ever reached Established.
        /// Latched for the transport's lifetime: RFC 4724 retention only
        /// protects routes a session actually learned, so the teardown
        /// path gates on this instead of the live `established` flag
        /// (which the FSM clears the moment the session drops).
        was_established: bool,
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

impl OspfTableEntry {
    fn intra(metric: u64, next_hop: Option<IpAddr>) -> Self {
        Self {
            metric,
            kind: OspfKind::Intra,
            label: None,
            label_nh: None,
            next_hop,
        }
    }

    /// An OSPFv3 intra-area entry carrying its resolved link-local next
    /// hop (RFC 5340 §16.1 v3 form).
    fn intra_v3(metric: u64, next_hop: Option<IpAddr>) -> Self {
        Self {
            metric,
            kind: OspfKind::Intra,
            label: None,
            label_nh: None,
            next_hop,
        }
    }

    fn inter(metric: u64, border_router: Option<u32>) -> Self {
        Self {
            metric,
            kind: OspfKind::Inter {
                border_router: border_router.unwrap_or(0),
            },
            label: None,
            label_nh: None,
            next_hop: None,
        }
    }

    fn external(
        metric: u64,
        metric_type: ExternalMetricType,
        asbr: u32,
        forwarding_addr: Option<IpAddr>,
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
            label: None,
            label_nh: None,
            next_hop: None,
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
    fn new(
        router_id: u32,
        area_id: u32,
        v3: bool,
        iface_mtu: u16,
        network_type: crate::session::OspfNetworkType,
        our_ip: Option<u32>,
        neighbor_ip: Option<u32>,
    ) -> Self {
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
            exchange: lr_ospf::exchange::DbExchange::with_version(
                router_id,
                area_id,
                iface_mtu,
                if v3 {
                    lr_ospf::packet::OspfVersion::V3
                } else {
                    lr_ospf::packet::OspfVersion::V2
                },
            ),
            iface_mtu,
            network_type,
            our_ip: our_ip.unwrap_or(0),
            neighbor_ip: neighbor_ip.unwrap_or(0),
            dr: 0,
            bdr: 0,
        }
    }

    /// RFC 2328 §10.4 — whether we should become adjacent with this
    /// bidirectional neighbor. Point-to-point (and Point-to-MultiPoint /
    /// virtual) links always become adjacent; broadcast/NBMA segments
    /// require one side to be the elected DR or BDR. While the segment
    /// has not elected a DR (interface Waiting, §9.4) no adjacency
    /// forms — mirroring BIRD's `can_do_adj`. The comparison runs on
    /// the segment identity: IP interface addresses on v2 (§A.3.2),
    /// Router IDs on v3 (RFC 5340 §4.1.2) — the embedder supplies them
    /// through the session config and `set_ospf_dr_state`.
    fn adjacency_viable(&self) -> bool {
        match self.network_type {
            crate::session::OspfNetworkType::PointToPoint => true,
            crate::session::OspfNetworkType::Broadcast => {
                if self.dr == 0 && self.bdr == 0 {
                    return false; // Waiting, or nothing elected yet
                }
                // The router itself is the DR/BDR...
                (self.our_ip != 0 && (self.our_ip == self.dr || self.our_ip == self.bdr))
                    // ...or the neighboring router is.
                    || (self.neighbor_ip != 0 && (self.neighbor_ip == self.dr || self.neighbor_ip == self.bdr))
            }
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
                // §10.2: 2-Way + adjacency decision → ExStart. The
                // decision is §10.4: ptp always adjoints; broadcast
                // segments require the DR/BDR relationship.
                if self.neighbor.state == NeighborState::TwoWay {
                    let proceed = self.adjacency_viable();
                    let _ = self.neighbor.step(NeighborEvent::AdjOk { proceed });
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
                    let proceed = self.adjacency_viable();
                    let _ = self.neighbor.step(NeighborEvent::AdjOk { proceed });
                }
                // §10.6: Database Description packets carry exchange
                // state only from ExStart on. A neighbor that never
                // made it past 2-Way (the §10.4 gate is closed — on a
                // broadcast segment before the segment elected its
                // DR/BDR, §9.4) must NOT start the exchange on a
                // peer's behalf: the peer may already be the elected
                // DR and eager to exchange (FRR fires its initial DBD
                // the moment it sees us bidirectional), and absorbing
                // it here leaves the exchange half-negotiated with no
                // one to drive it to Full. The adjacency re-opens
                // through set_ospf_dr_state (§9.4 step 7) or the next
                // Hello, both of which emit the initial DBD.
                if self.neighbor.state < NeighborState::ExStart {
                    return OspfStep::default();
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

impl From<lr_ospf::exchange::ExchangeStep> for OspfStep {
    fn from(step: lr_ospf::exchange::ExchangeStep) -> Self {
        Self {
            lsas: step.lsas,
            outbound: step.outbound,
        }
    }
}

impl BabelRuntime {
    fn new(local: IpAddr, now_ms: u64) -> Self {
        Self {
            neighbor: BabelNeighbor::new(local, now_ms),
            routes: BabelRouteTable::new(),
            codec: BabelCodec::new(),
            rtt_min_us: 10_000,
            rtt_max_us: 120_000,
            rtt_cost: 0,
            next_hop_v4: None,
            next_hop_v6: None,
            router_id: [0; 8],
            own_router_id: None,
            route_request: false,
            own_seqno_request: None,
            published: BTreeMap::new(),
            last_withdraw: LastWithdraw::default(),
        }
    }

    /// The reception-side link cost toward this peer (RFC 8966 §3.4.3,
    /// babeld `neighbour_cost`, BIRD `babel_update_cost`): the
    /// transmission cost learned from the peer's IHU (its receive cost
    /// for our packets) plus the measured-RTT penalty. `None` while no
    /// IHU has arrived — babeld treats such a neighbour's routes as
    /// unusable (cost INFINITY), so Updates from it are not accepted
    /// yet.
    fn link_cost(&self, now_ms: u64) -> Option<u32> {
        if self.neighbor.txcost >= 0xffff {
            return None;
        }
        let rtt = u32::from(self.neighbor.rtt_cost(
            now_ms,
            self.rtt_min_us,
            self.rtt_max_us,
            self.rtt_cost,
        ));
        Some(self.neighbor.txcost.saturating_add(rtt))
    }

    /// Feed one decoded Babel frame; returns the Loc-RIB delta.
    ///
    /// `now_us` is the transport's 32-bit microsecond clock at frame
    /// reception — the BABEL-RTT reference clock for timestamp bookkeeping
    /// (RFC 8966 §A.2.4). Passing the same clock the outgoing Hello/IHU
    /// timestamps are drawn from keeps the round-trip differences
    /// single-clock.
    fn handle_frame(&mut self, frame: &BabelFrame, now_ms: u64, now_us: u32) -> RuntimeDelta {
        use lr_babel::message::{
            Hello, Ihu, NextHop, PrefixCache, RouteRequest, RouterId as RouterIdTlv, SeqnoRequest,
            Update,
        };
        use lr_babel::tlv::TlvType;

        // RFC 8966 §4.5.2 prefix-compression state — one per packet,
        // exactly like BIRD's parse state.
        let mut cache = PrefixCache::default();
        for tlv in &frame.body {
            match tlv.kind {
                TlvType::Hello => {
                    if let Some(h) = Hello::decode(&tlv.value) {
                        match h.timestamp {
                            Some(ts) => {
                                self.neighbor.hello_timestamped(
                                    h.seqno,
                                    h.interval_cs,
                                    ts,
                                    now_ms,
                                    now_us,
                                );
                            }
                            None => self.neighbor.hello(h.seqno, h.interval_cs, now_ms),
                        }
                    }
                }
                TlvType::Ihu => {
                    if let Some(ihu) = Ihu::decode(&tlv.value) {
                        match ihu.timestamp_echo {
                            Some((ts1, ts2)) => self.neighbor.ihu_echo(
                                ihu.rxcost,
                                ihu.interval_cs,
                                ts1,
                                ts2,
                                now_ms,
                            ),
                            None => self.neighbor.ihu(ihu.rxcost, ihu.interval_cs, now_ms),
                        }
                    }
                }
                TlvType::RouterId => {
                    if let Some(rid) = RouterIdTlv::decode(&tlv.value) {
                        self.router_id = rid.id;
                    }
                }
                TlvType::NextHop => {
                    if let Some(nh) = NextHop::decode(&tlv.value) {
                        // Per-family next-hop state (RFC 8966 §3.5.3):
                        // AE 1 feeds the IPv4 Updates, AE 2/3 the IPv6
                        // ones (and AE 4 v4-over-v6 resolution).
                        match nh.ae {
                            1 => self.next_hop_v4 = Some(nh.address),
                            _ => self.next_hop_v6 = Some(nh.address),
                        }
                    }
                }
                TlvType::Update => {
                    if let Some(u) = Update::decode(&tlv.value) {
                        if let Some(u) = cache.expand(&u) {
                            self.apply_update(&u, now_ms);
                        }
                    }
                }
                TlvType::RouteRequest => {
                    // RFC 8966 §3.2.6: answer any request (wildcard or
                    // specific) with the routes we announce — the
                    // embedder drains the flag and announces immediately.
                    if RouteRequest::decode(&tlv.value).is_some() {
                        self.route_request = true;
                    }
                }
                TlvType::SeqnoRequest => {
                    if let Some(req) = SeqnoRequest::decode(&tlv.value) {
                        // §3.2.6.2: a request naming our own router-id
                        // means a peer remembers a higher seqno than our
                        // boot value — bump and re-announce so its
                        // feasibility check accepts our routes again.
                        if let Some(own) = self.own_router_id {
                            if req.router_id == own {
                                self.own_seqno_request =
                                    Some(self.own_seqno_request.map_or(req.seqno, |prev| {
                                        // Several requests: serve the highest.
                                        let a = prev as i16;
                                        let b = req.seqno as i16;
                                        if b.wrapping_sub(a) > 0 {
                                            req.seqno
                                        } else {
                                            prev
                                        }
                                    }));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let mut delta = self.diff();
        if !delta.withdrawn.is_empty() {
            // Render the structured `last_withdraw` record into the
            // delta's `withdraw_reason`. The kind tells the operator
            // WHAT peer-side event caused the withdrawal (a per-prefix
            // retraction, a wildcard retraction, or — when kind is None
            // — a local best-path displacement); the count of affected
            // routes comes from `delta.withdrawn.len()`, the actual
            // number that left the Loc-RIB. `std::mem::take` resets
            // the record for the next frame.
            let lw = std::mem::take(&mut self.last_withdraw);
            delta.withdraw_reason = match lw.kind {
                WithdrawKind::None => format!(
                    "babel best-path displacement ({} route(s) lost the best-path election)",
                    delta.withdrawn.len()
                ),
                WithdrawKind::PerPrefix => {
                    if delta.withdrawn.len() == 1 {
                        format!(
                            "babel peer retraction (metric=infinity) for {}",
                            lw.first_prefix
                                .expect("first_prefix is set on the first per-prefix retraction")
                        )
                    } else {
                        format!(
                            "babel peer retraction (metric=infinity) for {} route(s)",
                            delta.withdrawn.len()
                        )
                    }
                }
                WithdrawKind::Wildcard => format!(
                    "babel peer wildcard retraction (AE 0, metric=infinity) — {} route(s) flushed",
                    delta.withdrawn.len()
                ),
            };
        }
        delta
    }

    fn apply_update(&mut self, u: &lr_babel::message::Update, now_ms: u64) {
        // A peer re-advertising our own claims back at us: ignore (BIRD's
        // `msg->router_id == p->router_id` guard). Without this, our own
        // /64s echoed by a no-split-horizon peer would be learned as
        // Babel routes and — pre-fix — displaced the static routes we
        // originate them from.
        if let Some(own) = self.own_router_id {
            if u.metric != 0xFFFF && self.router_id == own {
                return;
            }
        }
        // AE 0 = wildcard retraction; AE 1 = IPv4; AE 2 = IPv6;
        // AE 4 = IPv4-via-IPv6 (RFC 9229 §2.4 — an IPv4 destination
        // reached over the IPv6 next hop). AE 3 (link-local IPv6) is not
        // a destination encoding and is ignored like BIRD does.
        let prefix = match u.ae {
            1 | 4 => {
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
            0 => {
                // Wildcard retraction (§4.6.9): flush everything this
                // neighbour taught us — babeld's `retract_neighbour_routes`.
                if u.metric == 0xFFFF && !self.routes.is_empty() {
                    self.routes = lr_babel::BabelRouteTable::new();
                    // Record the kind so `handle_frame` renders the
                    // "wildcard retraction" reason instead of the
                    // misleading fallback "best-path displacement".
                    // Wildcard takes precedence over any per-prefix
                    // retractions in the same frame (the wildcard
                    // supersedes them — it retracts EVERY route this
                    // neighbour taught us, not just the named ones).
                    self.last_withdraw.kind = WithdrawKind::Wildcard;
                    self.last_withdraw.first_prefix = None;
                }
                return;
            }
            _ => return, // AE 3 and unknown AEs are ignored.
        };
        // Source-specific destination (RFC 9079) — tracked in the route key.
        // The source prefix uses the same AE as the destination.
        let source = if u.src_prefix_len > 0 && !u.src_prefix.is_empty() {
            match u.ae {
                1 | 4 if u.src_prefix.len() <= 4 => {
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
            // Record the retraction so `handle_frame` can render the
            // "peer retraction (metric=infinity)" reason. The FIRST
            // per-prefix retraction in a frame records its prefix; a
            // subsequent retraction in the same frame (or a wildcard
            // retraction, which sets `Wildcard`) leaves `first_prefix`
            // alone — `handle_frame` switches to the count-annotated
            // form when `delta.withdrawn.len() > 1`. A wildcard
            // retraction already set `kind = Wildcard`, which takes
            // precedence — do not downgrade it.
            if self.last_withdraw.kind != WithdrawKind::Wildcard {
                if self.last_withdraw.kind == WithdrawKind::None {
                    self.last_withdraw.first_prefix = Some(key.destination);
                }
                self.last_withdraw.kind = WithdrawKind::PerPrefix;
            }
            return;
        }
        // Per-family next-hop resolution (RFC 8966 §3.5.3): an AE 1
        // Update rides the AE 1 NextHop TLV (or, in its absence, the
        // neighbour's own v4 address — the v4-transport shape); AE 2/3
        // and the AE 4 IPv4-via-IPv6 encoding ride the v6 next hop (or
        // the neighbour's address). An AE 1 Update with no usable v4
        // next hop is dropped exactly like BIRD's "Update must have
        // next hop" PARSE_ERROR.
        let peer_v4 = match self.neighbor.address {
            IpAddr::V4(_) => Some(self.neighbor.address),
            IpAddr::V6(_) => None,
        };
        let peer_v6 = match self.neighbor.address {
            IpAddr::V6(_) => Some(self.neighbor.address),
            IpAddr::V4(_) => None,
        };
        let nh = match u.ae {
            1 => match self.next_hop_v4.or(peer_v4) {
                Some(nh) => nh,
                None => return,
            },
            _ => self
                .next_hop_v6
                .or(peer_v6)
                .unwrap_or(self.neighbor.address),
        };
        // RFC 8966 §3.4.3 (babeld `route_metric + neighbour_cost`, BIRD
        // `babel_compute_metric`): the RECEIVER folds the link cost
        // toward the announcer into the route metric — the txcost
        // learned from the peer's IHU plus the RTT penalty. The
        // advertised metric never carries the announcer's own interface
        // cost: adding it there *and* here double-counts the link, the
        // production symptom where BIRD displayed metric 394 for
        // lr-originated routes (192 announced + 192 re-added) while
        // every BIRD peer's route showed just the link cost. Until the
        // first IHU arrives the txcost is infinite and no Update from
        // this neighbour is accepted (babeld parity).
        let Some(link) = self.link_cost(now_ms) else {
            return;
        };
        let metric = u32::from(u.metric).saturating_add(link).min(0xfffe);
        self.routes.insert_timed(
            BabelRoute {
                key,
                seqno: u.seqno,
                metric,
                next_hop: nh,
                feasible: true,
                installed: false,
            },
            u.interval_cs,
            now_ms,
        );
    }

    /// One expiry sweep (RFC 8966 §3.2.5): routes whose re-announcement
    /// hold time lapsed are dropped, and the diff against `published`
    /// becomes the Loc-RIB withdrawal delta.
    ///
    /// Unlike the previous implementation, this does NOT drop all routes
    /// immediately when the neighbour's Hello hold window (4× the Hello
    /// interval) lapses. On tunnel interfaces (WireGuard, etc.) a 4 s
    /// Hello gap is common — latency spikes, packet reordering, or
    /// scheduler hiccups all produce it. Dropping every route on a
    /// brief blip caused the "flaky Babel" symptom: routes withdrawn,
    /// then re-installed a second later when the next Hello arrived,
    /// with a brief outage during the gap. babeld does not have this
    /// path — it relies on each route's own hold timer (6× the Update
    /// interval, 15 s minimum) and the neighbour's retraction Updates.
    /// lr now matches that behaviour: a dead neighbour's routes expire
    /// through `routes.expire(now_ms)` within 15–18 s, which is fast
    /// enough for production and avoids the flap.
    fn gc(&mut self, now_ms: u64) -> RuntimeDelta {
        let expired = self.routes.expire(now_ms);
        if !expired.is_empty() {
            let mut delta = self.diff();
            if delta.withdrawn.is_empty() {
                // expire() removed routes from the table but they were
                // not in `published` (already displaced by a better
                // route). No delta to emit.
                return RuntimeDelta::default();
            }
            delta.withdraw_reason = format!(
                "babel route hold time expired ({} route(s) aged out at {} ms)",
                expired.len(),
                now_ms
            );
            return delta;
        }
        RuntimeDelta::default()
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
            withdraw_reason: String::new(),
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
        // The per-family "next hop of last resort" for a 0.0.0.0 / ::
        // next hop announced on the wire: the family's NextHop TLV value
        // when seen, else the neighbour's own address.
        let peer_v4 = match self.neighbor.address {
            IpAddr::V4(_) => Some(self.neighbor.address),
            IpAddr::V6(_) => None,
        };
        let peer_v6 = match self.neighbor.address {
            IpAddr::V6(_) => Some(self.neighbor.address),
            IpAddr::V4(_) => None,
        };
        let nh_v4_default = self
            .next_hop_v4
            .or(peer_v4)
            .unwrap_or(self.neighbor.address);
        let nh_v6_default = self
            .next_hop_v6
            .or(peer_v6)
            .unwrap_or(self.neighbor.address);
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
                let next_hop = match r.next_hop {
                    lr_core::addr::IpAddr::V4([0, 0, 0, 0]) => nh_v4_default,
                    lr_core::addr::IpAddr::V6(b) if b == [0u8; 16] => nh_v6_default,
                    other => other,
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
                    next_hop: Some(next_hop),
                    attributes: lr_core::attr::Attributes::new(),
                    age_ms: 0,
                    path_id: 0,
                    tag: None,
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
    /// Import pipeline state (post-safety-net, post-import-hook —
    /// the "post-policy" Adj-RIB-In consumed by the decision process).
    adj_rib_in: AdjRibIn,
    /// Pre-policy Adj-RIB-In (W2.4 — FRR soft-reconfiguration inbound):
    /// the **raw** received routes before the safety net or import
    /// hooks run, kept only for peers with `soft_reconfig_inbound` on.
    /// `soft_reconfig_inbound(h)` re-runs the import hooks against
    /// this view and replaces the session's entries in `adj_rib_in`,
    /// so a policy change can be applied without re-fetching from the
    /// peer (`clear ip bgp * soft in`).
    pre_policy_adj_rib_in: AdjRibIn,
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
    /// Operator-configured static routes (BIRD `protocol static`, FRR
    /// `ip route`). Kept so [`Self::uninstall_static`] can remove
    /// them, and so a configuration reload can diff old vs new (the
    /// daemon's reload path re-applies the static table wholesale
    /// like it does for the ROA table).
    static_routes: BTreeMap<RouteKey, Route>,
    pending_events: Vec<RouterEvent>,
    /// OSPF: per-area link-state databases, shared by all sessions of an
    /// area and keyed by area ID.
    ospf_areas: BTreeMap<u32, OspfAreaState>,
    /// OSPF: last Grace-LSA instance seen per (area, advertising
    /// router) — dedup so a retransmitted copy of the same instance
    /// emits one [`OspfGraceEvent`], not N (RFC 3623 flooding
    /// is reliable, retransmissions are expected). Instance identity
    /// is the RFC 2328 §13 tuple (sequence, age, checksum, length) —
    /// NOT sequence alone: a flush (MaxAge, empty body) and a fresh
    /// announcement can share a sequence number at second boundaries
    /// of the wallclock-derived lineage and are different LSAs.
    ospf_grace_seen: BTreeMap<(u32, u32), (u32, u16, u16, u16)>,
    /// OSPF: received Grace-LSA instances (RFC 3623 §3.1 /
    /// RFC 5187 §2) awaiting the embedder's helper-mode policy — drained
    /// through [`Self::drain_ospf_grace_events`]. A channel of its own
    /// (not `pending_events`) so an embedder that delegates event
    /// consumption to a mirror/ticker thread still sees every grace
    /// instance.
    ospf_grace_events: Vec<OspfGraceEvent>,
    /// OSPF router ID (all OSPF sessions must agree on it).
    ospf_router_id: Option<u32>,
    /// RFC 8665 reception: when on, every area recompute projects the
    /// area LSDB into a per-node SR database and attaches the resolved
    /// Prefix-SID labels (RFC 8660 head-end) to the routes they map
    /// onto. Off by default — fail-closed like every behavioural flag.
    ospf_sr_receive: bool,
    /// RFC 9513 §5 reception: when on, every OSPFv3 area recompute
    /// installs the SRv6 locators of supported algorithms as IPv6
    /// forwarding entries (the Srv6Database exposes the End SIDs for
    /// embedders). Off by default — fail-closed like every behavioural
    /// flag.
    ospf_srv6_receive: bool,
    /// RFC 8362 Extended-LSA mode for OSPFv3 (the `ExtendedLSASupport`
    /// knob of Appendix A): the v3 calculations prefer a speaker's
    /// E-Router/E-Network/E-Link/E-Intra-Area-Prefix LSAs over its
    /// legacy shapes and admit the E inter-area/external forms; E-LSAs
    /// still store and re-flood in legacy mode (§6.2). Off by default
    /// — a router that never enables it stays byte-identical to a
    /// pre-E-LSA one.
    ospf_v3_extended_lsas: bool,
    /// OSPF route table currently published to Loc-RIB: the merged view
    /// across all areas, diffed on every recompute.
    ospf_published: BTreeMap<RouteKey, Route>,
    /// Externally redistributed destinations requested through
    /// [`Self::ospf_redistribute`] (RFC 2328 §12.4.3), keyed by their
    /// link-state ID (the masked network). Re-originated into every
    /// attached OSPFv2 area so areas that (re)attach later catch up.
    ospf_externals: BTreeMap<u32, ExternalDestination>,
    /// Externally redistributed IPv6 destinations on the OSPFv3 plane
    /// (RFC 5340 §4.4.3.6), keyed by prefix. Re-originated as 0x4005
    /// LSAs into every attached OSPFv3 area so areas that (re)attach
    /// later catch up.
    ospf_v3_externals: BTreeMap<Prefix, lr_ospf::lsa::v3::V3ExternalDestination>,
    /// Stable 0x4005 LS IDs per external prefix — the LS ID carries no
    /// addressing semantics (§4.4.3.6) and must match across the areas
    /// the LSA is installed in (FRR reuses the previous instance's ID).
    ospf_v3_external_lsids: BTreeMap<Prefix, u32>,
    /// Stable 0x2003 inter-area-prefix LS IDs per (area, prefix) — the
    /// v3 LS ID carries no addressing semantics (§4.4.3.4), so the ABR
    /// must keep a stable prefix → LS ID mapping across
    /// re-origination (FRR reuses the previous instance's LS ID).
    ospf_v3_summary_lsids: BTreeMap<u32, BTreeMap<Prefix, u32>>,
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
    /// RFC 4271 §6.8 connection-collision bookkeeping for BGP sessions
    /// with a `collision_group`, keyed by session:
    /// `(group, locally_initiated)`. Sessions absent from the map never
    /// participate in collision resolution.
    collision_meta: BTreeMap<u64, (u64, bool)>,
    /// Sessions that LOST a §6.8 collision — either the resolver closed
    /// them (`close_collision_loser`) or a Cease / Connection Collision
    /// Resolution NOTIFICATION arrived from the peer (the peer's resolver
    /// decided against us). Latched until the embedder consumes it via
    /// [`Router::take_collision_lost`], so the embedder can distinguish
    /// the two Idle causes and stop dialing into a peer that already
    /// holds a live session.
    collision_lost: BTreeSet<u64>,
    /// Sessions closed by an administrative [`Self::shutdown_session`]:
    /// the deliberate goodbye (RFC 4486 §4.1) must not arm RFC 4724 /
    /// RFC 9494 stale-route retention — nobody is restarting, the
    /// session ended on purpose (BIRD protocol-disable parity).
    administrative_close: BTreeSet<u64>,
    /// Configured redistribution pipes (BIRD `pipe` / FRR `redistribute`).
    /// Each pipe bridges routes from `source` to `target` protocol.
    pipes: Vec<crate::redistribution::RedistributionPipe>,
    /// Routes this router has redistributed into BGP, keyed by the
    /// original Loc-RIB key. The value is the re-originated BGP route:
    /// it carries the source route's peer (so the export split horizon
    /// never re-advertises it to the session it came from) and competes
    /// with the peer's Adj-RIB-In paths for the Loc-RIB slot through the
    /// decision process. When the source route disappears, the copy is
    /// dropped via `unredistribute_route`.
    redistributed_bgp: BTreeMap<RouteKey, Route>,
    /// Protocol-direct Loc-RIB contributions (OSPF/Babel runtimes, rc.3):
    /// routes installed through `apply_runtime_delta` without passing
    /// through the Adj-RIB-In pipeline. Keyed like
    /// [`Self::redistributed_bgp`]; consulted by `reselect` so a BGP
    /// re-ranking of a shared key never evicts them, and by the export
    /// filter so they never leak into BGP advertisements (redistribution
    /// into BGP stays opt-in through pipes).
    direct_rib: BTreeMap<RouteKey, Route>,
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
    /// FRR `bgp enforce-first-as`: when on, an eBGP UPDATE whose
    /// leftmost AS_PATH segment's first AS is not equal to the peer's
    /// AS is rejected before Adj-RIB-In. Off by default — matches
    /// FRR's default and the RFC 4271 §9.1.2.2 "MAY reject" latitude
    /// (RFC 4271 §6.3 MUST accept when the first AS is the peer's AS,
    /// but does not mandate rejection otherwise).
    enforce_first_as: bool,
    /// RFC 8212 §3 per-session state: which directions the embedder
    /// attached an explicit policy to, plus one-time denial log
    /// latches (a full table from a policy-less peer must not produce
    /// one log event per route).
    session_policy: BTreeMap<u64, SessionPolicy>,
    /// W6.3 exchange-plane state per BGP session (feature
    /// `exchange-plane`): the last verified record set per prefix and
    /// the partial-transit counter (design §7).
    #[cfg(feature = "exchange-plane")]
    exchange_plane_state: BTreeMap<u64, ExchangePlaneState>,
}

/// W6.3 exchange-plane bookkeeping for one BGP session (feature
/// `exchange-plane`).
#[cfg(feature = "exchange-plane")]
#[derive(Debug, Clone, Default)]
struct ExchangePlaneState {
    /// The last verified record set per announced prefix (design §5:
    /// hints are per prefix, policy intent per session — the latest
    /// record set a session sent replaces its previous entries).
    records: BTreeMap<lr_core::addr::Prefix, lr_bgp::extensions::exchange_plane::ExchangeRecord>,
    /// Number of record sets that arrived with the Partial bit set on
    /// this session — provenance that crossed a non-lr transit speaker
    /// (design §7, reported in the runtime API).
    partial_transit: u64,
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
    /// Current number of routes this session contributed to the
    /// post-policy Adj-RIB-In, maintained incrementally on every
    /// install/withdraw/purge so `check_max_prefix` is O(1) per install
    /// instead of scanning the whole Adj-RIB-In (which made table
    /// convergence O(R²)).
    count: u32,
    /// When [`lr_bgp::MaxPrefixAction::Restart`] tore the session down,
    /// the router time (ms) after which the connector may re-establish.
    /// `None` (or a value <= `now_ms`) means "no cooldown in effect".
    /// Survives the teardown so the connector can read it; a fresh
    /// exceedance overwrites it, and once `now_ms` passes it the gate
    /// re-opens.
    restart_cooldown_until: Option<u64>,
}

impl Default for DefaultRouter {
    fn default() -> Self {
        Self {
            sessions: BTreeMap::new(),
            next_handle: 1,
            timers: TimerQueue::new(),
            now_ms: 0,
            adj_rib_in: AdjRibIn::new(),
            pre_policy_adj_rib_in: AdjRibIn::new(),
            adj_rib_out: AdjRibOut::new(),
            loc_rib: LocRib::new(),
            rib_mux: RibMux::new(),
            safety: None,
            hooks: HookChain::new(),
            best_path_cfg: BestPathConfig::default(),
            add_path_max_paths: 1,
            originated: BTreeMap::new(),
            static_routes: BTreeMap::new(),
            pending_events: Vec::new(),
            ospf_areas: BTreeMap::new(),
            ospf_grace_seen: BTreeMap::new(),
            ospf_grace_events: Vec::new(),
            ospf_router_id: None,
            ospf_sr_receive: false,
            ospf_srv6_receive: false,
            ospf_v3_extended_lsas: false,
            ospf_published: BTreeMap::new(),
            ospf_externals: BTreeMap::new(),
            ospf_v3_externals: BTreeMap::new(),
            ospf_v3_external_lsids: BTreeMap::new(),
            ospf_v3_summary_lsids: BTreeMap::new(),
            ospf_translations: BTreeSet::new(),
            ospf_vlinks: BTreeMap::new(),
            mrai: BTreeMap::new(),
            graceful_restart: BTreeMap::new(),
            llgr_caps: BTreeMap::new(),
            max_prefix_state: BTreeMap::new(),
            collision_meta: BTreeMap::new(),
            collision_lost: BTreeSet::new(),
            administrative_close: BTreeSet::new(),
            pipes: Vec::new(),
            redistributed_bgp: BTreeMap::new(),
            direct_rib: BTreeMap::new(),
            bmp_sink: None,
            aggregates: BTreeSet::new(),
            ebgp_requires_policy: false,
            enforce_first_as: false,
            session_policy: BTreeMap::new(),
            #[cfg(feature = "exchange-plane")]
            exchange_plane_state: BTreeMap::new(),
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

    /// Enable or disable FRR `bgp enforce-first-as`.
    ///
    /// When on, an UPDATE from an external peer (eBGP or a confederation
    /// boundary, mirroring the [`Self::set_ebgp_requires_policy`] scope)
    /// whose AS_PATH's leftmost sequence segment's first AS is not equal
    /// to the peer's negotiated AS is dropped before Adj-RIB-In, and the
    /// rejection is surfaced once per session as a [`RouterEvent::Log`].
    /// When off (the default — FRR `no bgp enforce-first-as`), the route
    /// is admitted subject to the ordinary policy and safety checks.
    ///
    /// This matches FRR's deployment-meaningful read of RFC 4271 §6.3:
    /// the spec mandates that an UPDATE with the peer's AS as the first
    /// AS be accepted, and leaves the other case (peer did not prepend
    /// its own AS) to the implementation; operators with this flag on
    /// reject it as a forgery / misconfiguration guard. iBGP and
    /// confederation-internal sessions are exempt, mirroring FRR.
    pub fn set_enforce_first_as(&mut self, on: bool) {
        self.enforce_first_as = on;
    }

    /// True when [`Self::set_enforce_first_as`] is currently engaged.
    pub fn enforce_first_as(&self) -> bool {
        self.enforce_first_as
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

    /// Set the FRR `bgp default ipv4-unicast` posture (W2.1) for a
    /// single BGP session. When `on` is `true` (the library default —
    /// matches FRR), IPv4 unicast is implicitly active even when
    /// `mp_families` does not list it. When `false`, IPv4 unicast must
    /// be added explicitly to `mp_families` to be active (FRR
    /// `no bgp default ipv4-unicast` with explicit
    /// `address-family ipv4 unicast` activation).
    ///
    /// Must be called before `start_session`. Affects the FSM's
    /// processing of legacy-section IPv4 NLRI, the egress in
    /// `advertise.rs`, End-of-RIB emission, and the families listed
    /// by the Add-Path / LLGR capabilities.
    pub fn set_session_default_ipv4_unicast(
        &mut self,
        h: SessionHandle,
        on: bool,
    ) -> Result<(), String> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => {
                if peer.is_established() {
                    return Err(format!(
                        "session {} already established: default_ipv4_unicast must be set before start",
                        h.0
                    ));
                }
                peer.config_mut().default_ipv4_unicast = on;
                Ok(())
            }
            _ => Err(format!("BGP session {} not found", h.0)),
        }
    }

    /// Set the FRR `neighbor X allowas-in N` / BIRD `allow local as`
    /// tolerance (W2.3) for a single BGP session.
    ///
    /// `tolerance = 0` (the default) rejects any occurrence of the
    /// local AS in a received AS_PATH (RFC 4271 §9.1.2.15 AS_PATH loop
    /// check). `tolerance = N > 0` admits a route whose AS_PATH
    /// contains the local AS up to N times (FRR `allowas-in N`,
    /// default N=1). `tolerance = u32::MAX` admits any number (FRR
    /// `allowas-any`). iBGP sessions are exempt (FRR/BIRD scope the
    /// relaxation to eBGP).
    ///
    /// Must be called after `add_session` and before `start_session`;
    /// unknown handles or already-established sessions return Err.
    pub fn set_session_local_as_tolerance(
        &mut self,
        h: SessionHandle,
        tolerance: u32,
    ) -> Result<(), String> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => {
                if peer.is_established() {
                    return Err(format!(
                        "session {} already established: local_as_tolerance must be set before start",
                        h.0
                    ));
                }
                peer.config_mut().local_as_tolerance = tolerance;
                Ok(())
            }
            _ => Err(format!("BGP session {} not found", h.0)),
        }
    }

    /// Enable or disable FRR `neighbor X soft-reconfiguration inbound`
    /// (W2.4) for a BGP session.
    ///
    /// When `on`, the router retains the **pre-policy** view of the
    /// peer's Adj-RIB-In — the raw received routes before the import
    /// hook chain runs — so [`Self::soft_reconfig_inbound`] can apply
    /// a policy reconfiguration without re-fetching from the peer
    /// (`clear ip bgp * soft in`). Off by default (FRR's default; the
    /// cost is duplicate RIB memory per peer).
    ///
    /// Must be called after `add_session` and before `start_session`;
    /// unknown handles or already-established sessions return Err.
    pub fn set_session_soft_reconfig_inbound(
        &mut self,
        h: SessionHandle,
        on: bool,
    ) -> Result<(), String> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => {
                if peer.is_established() {
                    return Err(format!(
                        "session {} already established: soft_reconfig_inbound must be set before start",
                        h.0
                    ));
                }
                peer.config_mut().soft_reconfig_inbound = on;
                Ok(())
            }
            _ => Err(format!("BGP session {} not found", h.0)),
        }
    }

    /// W6.3 exchange-plane (feature `exchange-plane`): attach the
    /// plane configuration to a single BGP session. The config is
    /// advertised in OPEN (capability 251) and — when the peer also
    /// advertises it with a shared key id — activates the record
    /// attach/detach hooks for the session
    /// (`docs/research/EXCHANGE-PLANE.md`). Sessions without a config
    /// never advertise the capability and are byte-identical to a
    /// build without the feature.
    ///
    /// Must be called after `add_session` and before `start_session`;
    /// unknown handles or already-established sessions return Err.
    #[cfg(feature = "exchange-plane")]
    pub fn set_session_exchange_plane(
        &mut self,
        h: SessionHandle,
        cfg: lr_bgp::extensions::exchange_plane::ExchangePlaneConfig,
    ) -> Result<(), String> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => {
                if peer.is_established() {
                    return Err(format!(
                        "session {} already established: exchange_plane must be set before start",
                        h.0
                    ));
                }
                peer.set_exchange_plane(cfg);
                Ok(())
            }
            _ => Err(format!("BGP session {} not found", h.0)),
        }
    }

    /// W6.3 exchange-plane (feature `exchange-plane`): the last
    /// verified record set per prefix the session `h` sent us, most
    /// recent first. Empty when the plane never activated for the
    /// session or nothing was received yet.
    #[cfg(feature = "exchange-plane")]
    pub fn exchange_plane_records(
        &self,
        h: SessionHandle,
    ) -> Vec<(
        lr_core::addr::Prefix,
        lr_bgp::extensions::exchange_plane::ExchangeRecord,
    )> {
        self.exchange_plane_state
            .get(&h.0)
            .map(|st| st.records.iter().map(|(k, v)| (*k, v.clone())).collect())
            .unwrap_or_default()
    }

    /// W6.3 exchange-plane (feature `exchange-plane`): how many record
    /// sets arrived with the Partial bit set on session `h` —
    /// provenance that crossed a non-lr transit speaker (design §7).
    #[cfg(feature = "exchange-plane")]
    pub fn exchange_plane_partial_transit(&self, h: SessionHandle) -> u64 {
        self.exchange_plane_state
            .get(&h.0)
            .map(|st| st.partial_transit)
            .unwrap_or(0)
    }

    /// FRR `clear ip bgp * soft in` (W2.4): re-evaluate the import
    /// policy against the pre-policy Adj-RIB-In for `h`, replacing the
    /// session's entries in the post-policy `adj_rib_in` with the
    /// re-imported routes, and re-selecting every affected prefix.
    ///
    /// Returns the number of routes re-evaluated. No-ops (returns 0)
    /// when the session did not have `soft_reconfig_inbound` enabled
    /// (the pre-policy RIB was not retained), or when the session is
    /// not a known BGP peer.
    pub fn soft_reconfig_inbound(&mut self, h: SessionHandle) -> Result<usize, String> {
        let origin = RouteOrigin {
            proto: 0,
            peer: h.0,
        };
        // Collect the session's raw routes (clone to release the
        // borrow on `pre_policy_adj_rib_in` before we mutate
        // `adj_rib_in` / `loc_rib` via `reselect`).
        let raw_routes: Vec<Route> = self
            .pre_policy_adj_rib_in
            .iter_origin(origin)
            .cloned()
            .collect();
        if raw_routes.is_empty() {
            return Ok(0);
        }
        // Drop the session's existing post-policy slice — every raw
        // route will be re-imported below.
        let affected_keys: Vec<RouteKey> = self
            .adj_rib_in
            .iter_origin(origin)
            .map(|r| r.key.clone())
            .collect();
        self.adj_rib_in.clear_for(origin);
        // Re-run the import pipeline against every raw route. We do
        // NOT re-run the safety net / enforce-first-as / RFC 8212
        // here — those are invariant under a policy change (they
        // reject routes for protocol-level reasons, not policy
        // reasons). Only the import hook chain is re-evaluated.
        let hooks = std::mem::take(&mut self.hooks);
        let mut reimported_keys: Vec<RouteKey> = Vec::new();
        for mut route in raw_routes {
            route.age_ms = self.now_ms;
            if matches!(hooks.run_import(&mut route), HookVerdict::Drop) {
                continue;
            }
            let key = route.key.clone();
            let route_origin = route.origin;
            // Track re-advertised routes during GR resync (same as
            // the live import path).
            if let Some(state) = self.graceful_restart.get_mut(&h.0) {
                state.refreshed.insert((key.clone(), route.path_id));
            }
            self.adj_rib_in.feed_pre_policy(route_origin, route);
            reimported_keys.push(key);
        }
        self.hooks = hooks;
        // Re-select every affected prefix (the union of old + new).
        let mut all_keys: std::collections::BTreeSet<RouteKey> =
            affected_keys.into_iter().collect();
        all_keys.extend(reimported_keys);
        for key in all_keys {
            self.reselect(&key);
        }
        // Count the post-policy slice for this session.
        let count = self.adj_rib_in.iter_origin(origin).count();
        // The slice was cleared and re-imported wholesale: reset the
        // incremental max-prefix counter to the new slice size.
        if let Some(st) = self.max_prefix_state.get_mut(&h.0) {
            st.count = count as u32;
        }
        self.pending_events.push(RouterEvent::Log(format!(
            "session {}: soft reconfiguration inbound — re-evaluated {} routes",
            h.0, count
        )));
        Ok(count)
    }

    /// Return the **pre-policy** Adj-RIB-In snapshot for `h` — the
    /// raw received routes (before the safety net or import hook
    /// chain ran), retained only when `soft_reconfig_inbound` is on
    /// for the session (W2.4 — FRR `neighbor X soft-reconfiguration
    /// inbound`). Returns an empty vec when the session is unknown
    /// or has no pre-policy routes retained.
    pub fn adj_rib_in_snapshot(&self, h: SessionHandle) -> Vec<Route> {
        let origin = RouteOrigin {
            proto: 0,
            peer: h.0,
        };
        self.pre_policy_adj_rib_in
            .iter_origin(origin)
            .cloned()
            .collect()
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
            tag: None,
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
            tag: None,
        };
        self.loc_rib.install_set(&key, vec![route.clone()]);
        self.originated.insert(key.clone(), route.clone());
        self.pending_events
            .push(RouterEvent::RouteInstalled(route.clone()));
        self.export_selection(&key, &[route]);
        key
    }

    /// Originate a labelled BGP route (RFC 8277). The label stack is
    /// stored under the private `LrMplsLabelStack` attribute so egress
    /// encoding can put it back into the labelled NLRI. The family must
    /// be `IPV4_LABELED_UNICAST` or `IPV6_LABELED_UNICAST`; for any other
    /// family this falls back to plain origination (the label stack is
    /// silently dropped, matching the conservative behaviour of BIRD's
    /// `route` filter when MPLS is not in scope).
    #[cfg(feature = "labeled_unicast")]
    pub fn originate_labeled(
        &mut self,
        prefix: Prefix,
        family: NlriFamily,
        label_stack: lr_mpls::LabelStack,
        next_hop: Option<IpAddr>,
    ) -> RouteKey {
        if !family.is_labeled_unicast() {
            // Defensive: caller passed a non-labelled family. Originate
            // the route without the label stack rather than panicking.
            return self.originate_family(prefix, family, next_hop);
        }
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
        attrs.set_label_stack(&label_stack);
        let route = Route {
            key: key.clone(),
            origin: RouteOrigin { proto: 2, peer: 0 },
            protocol: Protocol::Bgp,
            preference: lr_core::rib::Preference::new(Protocol::Bgp.default_admin_distance(), 0),
            next_hop,
            attributes: attrs.into(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        self.loc_rib.install_set(&key, vec![route.clone()]);
        self.originated.insert(key.clone(), route.clone());
        self.pending_events
            .push(RouterEvent::RouteInstalled(route.clone()));
        self.export_selection(&key, &[route]);
        key
    }

    /// Remove a locally originated route and withdraw it everywhere
    /// (FRR `no network ...`, BIRD removing the protocol's static route).
    ///
    /// The decision process re-runs for the prefix (RFC 4271 §9.1.2): a
    /// peer path that was ranked below the originated route is restored,
    /// and an empty candidate set withdraws the prefix from every session
    /// (via `apply_selection`). Any redistribution-sourced copy of the
    /// route is flushed first — its source (this originated route) is
    /// gone.
    ///
    /// Returns `true` when a locally originated route was removed and
    /// `false` when the key was not locally originated (never
    /// `originate`d, or already unoriginated) — nothing changes in that
    /// case, matching FRR/BIRD `no network` on an absent statement.
    pub fn unoriginate(&mut self, key: &RouteKey) -> bool {
        if self.originated.remove(key).is_some() {
            // Flush the redistributed BGP copy whose source was this
            // originated route.
            self.unredistribute_route(key);
            // Re-run selection: a beaten peer path comes back, or the
            // empty ranking withdraws the prefix everywhere.
            self.reselect(key);
            true
        } else {
            false
        }
    }

    /// Install a static route into the Loc-RIB (BIRD `protocol static
    /// { route; }`, FRR `ip route <prefix> <next-hop>`). The route's
    /// `protocol` is [`Protocol::Static`]; its admin distance is 1
    /// (FRR's default for static); its metric is the operator-
    /// configured value (default 0). The route is tracked in the
    /// router's static-route map so [`Self::uninstall_static`] can
    /// remove it and the daemon's reload path can re-apply the table
    /// wholesale.
    ///
    /// A static route wins over every other protocol except Connected
    /// (admin distance 0) and competes with BGP-originated routes
    /// (admin distance 20) by admin distance — the FRR/BIRD model.
    /// When `next_hop` is `None`, the route is a blackhole (FRR
    /// `ip route <prefix> Null0`, BIRD `route <prefix> blackhole`).
    pub fn install_static(
        &mut self,
        prefix: Prefix,
        family: NlriFamily,
        next_hop: Option<IpAddr>,
        metric: u32,
        tag: Option<u32>,
    ) -> RouteKey {
        let key = RouteKey::new(prefix, family);
        let route = Route {
            key: key.clone(),
            origin: RouteOrigin { proto: 2, peer: 0 },
            protocol: Protocol::Static,
            preference: lr_core::rib::Preference::new(
                Protocol::Static.default_admin_distance(),
                metric,
            ),
            next_hop,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag,
        };
        self.loc_rib.install_set(&key, vec![route.clone()]);
        self.static_routes.insert(key.clone(), route.clone());
        self.pending_events
            .push(RouterEvent::RouteInstalled(route.clone()));
        self.export_selection(&key, &[route]);
        key
    }

    /// Remove a previously-installed static route. Returns `true` when
    /// a static route was removed and `false` when the key was not a
    /// static route (matching `unoriginate`'s contract for BGP
    /// originated routes).
    pub fn uninstall_static(&mut self, key: &RouteKey) -> bool {
        if self.static_routes.remove(key).is_some() {
            self.unredistribute_route(key);
            self.reselect(key);
            true
        } else {
            false
        }
    }

    /// Read-only access to the operator-configured static routes —
    /// the daemon's reload path diffs the configured set against
    /// this map and removes dropped entries.
    pub fn static_routes(&self) -> &BTreeMap<RouteKey, Route> {
        &self.static_routes
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
        // RFC 4271 §9.2.2.2: the AGGREGATOR carries "the AS number and
        // BGP Identifier of the last BGP speaker that performed route
        // aggregation" — both come from the originating session.
        let (local_as, bgp_id) = self
            .sessions
            .values()
            .find_map(|s| match s {
                SessionState::Bgp { peer, .. } => {
                    Some((peer.config().local_as.as_u32(), peer.config().local_bgp_id))
                }
                _ => None,
            })
            .unwrap_or((0, lr_core::addr::RouterId::from_u32(0)));
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
                agg_val.extend_from_slice(&bgp_id.to_v4_bytes());
                attrs.insert(PathAttribute::new(
                    // AGGREGATOR is optional transitive (RFC 4271 §4.3,
                    // flags 0xC0). BIRD rejects a non-optional AGGREGATOR
                    // with "Malformed attribute - conflicting flags" —
                    // caught live in the aggregate_bird.sh interop.
                    PathAttrFlags::new().set_optional(true).set_transitive(true),
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
                    tag: None,
                };
                self.loc_rib.install_set(&key, vec![route.clone()]);
                self.originated.insert(key.clone(), route.clone());
                self.pending_events
                    .push(RouterEvent::RouteInstalled(route.clone()));
                // Flush the export pipeline for the aggregate: this
                // origination fires from `apply_selection` (a specific
                // just arrived) while the peer sessions are already
                // Established — without the flush the aggregate sits in
                // the Loc-RIB but is never queued into any Adj-RIB-Out
                // (the session-up full sync has already run). Mirrors
                // the `export_selection` tail of `originate_family`.
                self.export_selection(&key, std::slice::from_ref(&route));
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
                    } => {
                        let stats = peer.message_stats();
                        SessionSummary {
                            handle: SessionHandle(*id),
                            kind: "bgp",
                            local_as: peer.config().local_as,
                            peer_as: peer.config().peer_as,
                            state: peer.state().name(),
                            established: *established,
                            peer_bgp_id: peer.peer_bgp_id(),
                            negotiated_hold_time: peer.negotiated_hold_time(),
                            adj_rib_in_len,
                            updates_received: stats.update_received,
                            updates_sent: stats.update_sent,
                        }
                    }
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
                        updates_received: 0,
                        updates_sent: 0,
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
                            updates_received: 0,
                            updates_sent: 0,
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
        // W6.3 exchange-plane (feature `exchange-plane`): snapshot the
        // private record store off the raw route before the admission
        // gates run — the store is surfaced only if the route is
        // admitted, but the route is consumed by the pipeline.
        #[cfg(feature = "exchange-plane")]
        let xp_store: Option<(u8, std::vec::Vec<u8>)> = route
            .attributes
            .get(lr_core::attr::AttrTag(
                lr_bgp::path::AttrType::LrExchangePlaneRecords.to_u8(),
            ))
            .and_then(|a| {
                lr_bgp::extensions::exchange_plane::load_store(&a.value)
                    .map(|(k, payload)| (k, payload.to_vec()))
            });
        // W2.4 — FRR soft-reconfiguration inbound: retain the raw
        // received route in the pre-policy RIB before any safety net
        // or import hook runs. Only peers with `soft_reconfig_inbound`
        // on pay the memory cost; the snapshot is consumed by
        // `soft_reconfig_inbound(h)` on a policy change.
        let soft_reconfig = self
            .sessions
            .get(&route.origin.peer)
            .and_then(|s| match s {
                SessionState::Bgp { peer, .. } => Some(peer.config().soft_reconfig_inbound),
                _ => None,
            })
            .unwrap_or(false);
        if soft_reconfig {
            self.pre_policy_adj_rib_in
                .feed_pre_policy(route.origin, route.clone());
        }
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
                // FRR `neighbor X allowas-in N` / BIRD `allow local as`
                // (W2.3): a per-peer tolerance of `N > 0` admits a route
                // whose AS_PATH contains the local AS up to N times,
                // overriding the safety net's strict AS_PATH loop check
                // (RFC 4271 §9.1.2.15). iBGP is exempt — FRR/BIRD scope
                // the relaxation to eBGP sessions.
                if let SafetyViolation::AsLoop { .. } = &v {
                    if is_ebgp {
                        let tolerance = self
                            .sessions
                            .get(&route.origin.peer)
                            .and_then(|s| match s {
                                SessionState::Bgp { peer, .. } => {
                                    Some(peer.config().local_as_tolerance)
                                }
                                _ => None,
                            })
                            .unwrap_or(0);
                        if tolerance > 0 {
                            let count = self.count_local_as(&route);
                            if count <= tolerance {
                                // Admitted under the per-peer tolerance.
                                // Fall through to the rest of the
                                // import pipeline.
                            } else {
                                self.pending_events.push(RouterEvent::Log(format!(
                                    "safety: rejected {}: AS_PATH contains local AS {} times \
                                     (peer tolerance {}, is_ebgp={})",
                                    route.key.prefix, count, tolerance, is_ebgp
                                )));
                                return;
                            }
                        } else {
                            self.pending_events.push(RouterEvent::Log(format!(
                                "safety: rejected {}: {}",
                                route.key.prefix, v
                            )));
                            return;
                        }
                    } else {
                        self.pending_events.push(RouterEvent::Log(format!(
                            "safety: rejected {}: {}",
                            route.key.prefix, v
                        )));
                        return;
                    }
                } else {
                    self.pending_events.push(RouterEvent::Log(format!(
                        "safety: rejected {}: {}",
                        route.key.prefix, v
                    )));
                    return;
                }
            }
        }
        // FRR `bgp enforce-first-as`: for an external BGP peer, the
        // leftmost AS of the first AS_PATH sequence segment must equal
        // the peer's AS — a peer that did not prepend its own AS is
        // either misconfigured or forging the path. The check is
        // silent when there is no AS_PATH at all (the safety net's
        // `reject_empty_as_path_ebgp` knob handles that case if the
        // operator wants it).
        if self.enforce_first_as && is_ebgp {
            if let Some(rejection) = self.check_first_as(&route) {
                self.pending_events.push(RouterEvent::Log(rejection));
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
        // Maintain the incremental per-session Adj-RIB-In count that
        // `check_max_prefix` reads (O(1) per install). Re-announcing an
        // existing (origin, key, path_id) replaces in place and does not
        // double-count.
        let is_new = self.adj_rib_in.get(origin, &key, route.path_id).is_none();
        self.adj_rib_in.feed_pre_policy(origin, route);
        if is_new {
            let st = self.max_prefix_state.entry(session).or_default();
            st.count = st.count.saturating_add(1);
        }
        self.reselect(&key);
        // Per-peer maximum-prefix enforcement (BIRD `maximum prefix`,
        // FRR `maximum-prefix`). Count the session's routes in Adj-RIB-In
        // after the install; if the count crosses the threshold or the
        // hard limit, fire the corresponding event.
        self.check_max_prefix(session);
        // W6.3 exchange-plane (feature `exchange-plane`): surface the
        // record set the route carried. Only admitted routes reach this
        // point — records of routes dropped by policy/safety die with
        // them.
        #[cfg(feature = "exchange-plane")]
        self.consume_exchange_plane_store(session, &key, xp_store);
    }

    /// W6.3 exchange-plane (feature `exchange-plane`): expose a record
    /// set from a freshly admitted route — the scope-1 classes go to
    /// the log + the typed accessor, Partial-bit forwarding material
    /// bumps the partial-transit counter (design §7). The store itself
    /// stays on the route for the egress re-sign path.
    #[cfg(feature = "exchange-plane")]
    fn consume_exchange_plane_store(
        &mut self,
        session: u64,
        key: &RouteKey,
        xp_store: Option<(u8, std::vec::Vec<u8>)>,
    ) {
        use lr_bgp::extensions::exchange_plane as xp;

        let Some((kind, payload)) = xp_store else {
            return;
        };
        let state = self.exchange_plane_state.entry(session).or_default();
        match kind {
            xp::STORE_VERIFIED => {
                let Ok(record) = xp::ExchangeRecord::decode(&payload) else {
                    return;
                };
                // One log line per record set (not per prefix per second:
                // a full table from a plane-active peer would flood).
                let summary = record
                    .records
                    .iter()
                    .map(|r| match r {
                        xp::Record::Hint(_) => "hint",
                        xp::Record::Policy(_) => "policy",
                        xp::Record::Origin(_) => "origin",
                        xp::Record::Segment(_) => "segment",
                    })
                    .collect::<Vec<_>>()
                    .join("+");
                self.pending_events.push(RouterEvent::Log(format!(
                    "exchange-plane: session {session} {} records for {} [{}]",
                    record.records.len(),
                    key.prefix,
                    summary
                )));
                state.records.insert(key.prefix, record);
            }
            xp::STORE_PARTIAL_RAW => {
                state.partial_transit = state.partial_transit.saturating_add(1);
            }
            _ => {}
        }
    }

    /// FRR `bgp enforce-first-as` check: return `Some(log)` when the
    /// route's AS_PATH leftmost sequence segment's first AS does not
    /// equal the session's peer AS (the peer did not prepend its own
    /// AS — either a forgery or a misconfiguration). Returns `None`
    /// when the route is acceptable, when the route carries no
    /// AS_PATH (the safety net handles the empty case), or when the
    /// session is not a known BGP peer (no peer AS to compare
    /// against — fail-open to keep the import pipeline moving).
    ///
    /// The route attributes have already been through the BGP FSM's
    /// normalize step (see `lr-bgp::fsm`): AS4_PATH (RFC 4893) is
    /// merged into AS_PATH, and AS_PATH is stored in the canonical
    /// 4-byte form. We therefore decode with
    /// [`PathAttributes::as_path`] (which always reads 4-byte) rather
    /// than guessing the wire width from the tag.
    ///
    /// Only AS_SEQUENCE / AS_CONFED_SEQUENCE segments participate —
    /// RFC 4271 §5.1.2 puts the "first AS" in the leftmost
    /// AS_SEQUENCE. An AS_SET on the left has no single "first AS",
    /// so we fall back to `None` (do not reject) for that shape; the
    /// safety net covers the genuinely malformed cases.
    fn check_first_as(&self, route: &Route) -> Option<String> {
        let session = route.origin.peer;
        let peer_as = match self.sessions.get(&session) {
            Some(SessionState::Bgp { peer, .. }) => peer.config().peer_as,
            _ => return None,
        };
        let attrs: PathAttributes = route.attributes.clone().into();
        let path = attrs.as_path()?;
        // Find the leftmost AS_SEQUENCE / AS_CONFED_SEQUENCE segment
        // and inspect its first AS — FRR's "first AS" is the one the
        // peer is supposed to prepend when advertising eBGP.
        for seg in &path.segments {
            if !matches!(
                seg.kind,
                lr_bgp::path::AsPathType::Sequence | lr_bgp::path::AsPathType::ConfedSequence
            ) {
                continue;
            }
            if let Some(first) = seg.ases.first() {
                if first.0 == peer_as.0 {
                    return None;
                }
                return Some(format!(
                    "enforce-first-as: session {session} rejected {} — first AS {} != peer AS {}",
                    route.key.prefix, first.0, peer_as.0
                ));
            }
            // Empty sequence segment — keep scanning; the safety
            // net's `reject_empty_as_path_ebgp` covers this shape.
        }
        None
    }

    /// Count how many times the local AS appears in the route's
    /// normalized AS_PATH (W2.3 — FRR `neighbor X allowas-in N` /
    /// BIRD `allow local as`). Uses the FSM-normalized canonical
    /// AS_PATH (always 4-byte after the `lr-bgp` codec's AS4_PATH
    /// merge) via `PathAttributes::as_path()` — fixes the latent
    /// width-guessing bug in the safety net's `local_as_count`
    /// (which treats tag-2 AS_PATH as 2-byte even after the FSM
    /// rewrites it to 4-byte).
    ///
    /// Counts AS_SEQUENCE and AS_CONFED_SEQUENCE segments only (RFC
    /// 4271 §5.1.2 puts the loop check on ordered segments). AS_SET
    /// and AS_CONFED_SET membership is also counted by FRR's
    /// implementation, so we follow parity.
    fn count_local_as(&self, route: &Route) -> u32 {
        let session = route.origin.peer;
        let local_as = match self.sessions.get(&session) {
            Some(SessionState::Bgp { peer, .. }) => peer.config().local_as,
            _ => return 0,
        };
        let attrs: PathAttributes = route.attributes.clone().into();
        let Some(path) = attrs.as_path() else {
            return 0;
        };
        let mut count = 0u32;
        for seg in &path.segments {
            for as_ in &seg.ases {
                if as_.0 == local_as.0 {
                    count = count.saturating_add(1);
                }
            }
        }
        count
    }

    /// Enforce the per-session maximum-prefix limit. Emits
    /// [`RouterEvent::MaxPrefixThreshold`] once when the early-warning
    /// percentage is crossed, and [`RouterEvent::MaxPrefixExceeded`] once
    /// when the hard limit is hit. For `Teardown`/`Restart` the session is
    /// closed with a NOTIFICATION CEASE (subcode 1 — "Maximum Number of
    /// Prefixes Reached", RFC 4486 §3/§4).
    fn check_max_prefix(&mut self, session: u64) {
        // Read the config without borrowing self mutably.
        let (limit, action, threshold_pct, restart_time) = match self.sessions.get(&session) {
            Some(SessionState::Bgp { peer, .. }) => {
                let cfg = peer.config();
                match cfg.maximum_prefix {
                    Some(limit) => (
                        limit,
                        cfg.maximum_prefix_action,
                        cfg.maximum_prefix_threshold,
                        cfg.maximum_prefix_restart_time,
                    ),
                    None => return, // no limit configured
                }
            }
            _ => return, // not a BGP session
        };
        // The per-session Adj-RIB-In count is maintained incrementally on
        // every install/withdraw/purge — no whole-RIB scan per install.
        let count: u32 = self
            .max_prefix_state
            .get(&session)
            .map(|s| s.count)
            .unwrap_or(0);
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
                        // A Restart with a non-zero cooldown arms the
                        // re-establishment gate the connector reads before
                        // it dials again (FRR `bgp maximum-prefix restart
                        // <secs>` / BIRD `restart time`). A zero cooldown
                        // keeps the historical behaviour: Restart tears
                        // down exactly like Teardown.
                        if matches!(action, lr_bgp::MaxPrefixAction::Restart) && restart_time > 0 {
                            if let Some(st) = self.max_prefix_state.get_mut(&session) {
                                st.restart_cooldown_until =
                                    Some(self.now_ms.saturating_add(restart_time as u64 * 1000));
                            }
                        }
                        self.pending_events.push(RouterEvent::Log(format!(
                            "max-prefix: session {} exceeded limit ({count}/{limit}), action={}",
                            session,
                            action.name()
                        )));
                        // Tear the session down with a CEASE NOTIFICATION
                        // (subcode 1 — "Maximum Number of Prefixes
                        // Reached", RFC 4486 §3).
                        if let Some(SessionState::Bgp { peer, .. }) =
                            self.sessions.get_mut(&session)
                        {
                            peer.enqueue_notification(
                                lr_bgp::BgpErrorCode::Cease,
                                lr_bgp::BgpCeaseSubcode::MaximumPrefixes as u8,
                            );
                        }
                        self.flush_peer_output(session);
                    }
                }
            }
        }
    }

    fn withdraw_from_session(&mut self, origin: RouteOrigin, key: &RouteKey, path_id: u32) {
        // Notify import hooks that a route has been withdrawn. The
        // notification fires for every withdraw, including routes
        // that were dropped by an import hook (never made it into
        // Adj-RIB-In) — RFC 2439 damping needs every flap event to
        // keep its figure-of-merit accurate. The hook's return is
        // informational only; it cannot "drop" a withdraw.
        self.hooks.run_import_withdraw(key, self.now_ms / 1000);
        // W2.4: a withdrawal also removes the route from the pre-policy
        // RIB (it is gone from the peer either way).
        self.pre_policy_adj_rib_in.withdraw(origin, key, path_id);
        if self.adj_rib_in.withdraw(origin, key, path_id).is_some() {
            if let Some(st) = self.max_prefix_state.get_mut(&origin.peer) {
                st.count = st.count.saturating_sub(1);
            }
            self.reselect(key);
        }
        // W6.3 exchange-plane: the prefix's record set leaves with the
        // route that carried it (feature `exchange-plane`).
        #[cfg(feature = "exchange-plane")]
        if let Some(st) = self.exchange_plane_state.get_mut(&origin.peer) {
            st.records.remove(&key.prefix);
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
            .chain(
                self.static_routes
                    .values()
                    .filter(|r| r.key == *key)
                    .cloned(),
            )
            .chain(self.direct_rib.values().filter(|r| r.key == *key).cloned())
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
                if route.protocol != Protocol::Bgp {
                    // rc.3 shared RIB: protocol-direct contributions
                    // (OSPF, Babel) never enter BGP advertisements —
                    // cross-protocol export stays opt-in through
                    // redistribution pipes (FRR `redistribute` / BIRD
                    // `pipe` semantics).
                    continue;
                }
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
            if best.protocol == Protocol::Bgp && best.origin.peer != session && !rfc8212_deny_export
            {
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
                        // Split horizon (RFC 4271 §9.1.3 Phase 3): a
                        // route retained from this very session (e.g.
                        // under graceful restart) is not advertised back
                        // to it — the steady-state export path applies
                        // the same filter.
                        if route.origin.peer == h {
                            continue;
                        }
                        // rc.3 shared RIB: protocol-direct contributions
                        // (OSPF, Babel) never enter BGP advertisements —
                        // cross-protocol export stays opt-in through
                        // redistribution pipes (FRR `redistribute` /
                        // BIRD `pipe` semantics). The steady-state
                        // `export_selection` applies the same gate; the
                        // initial dump must agree, or every session
                        // establishment leaks non-BGP routes onto the
                        // wire without BGP's mandatory attributes
                        // (BIRD: "Missing mandatory ORIGIN attribute").
                        if route.protocol != Protocol::Bgp {
                            continue;
                        }
                        let mut r = route.clone();
                        r.path_id = slot as u32 + 1;
                        snapshot.push(r);
                    }
                }
            } else {
                snapshot.extend(
                    self.loc_rib
                        .iter_best()
                        .filter(|route| {
                            // Same two gates as the Add-Path branch:
                            // family + split horizon, and the
                            // protocol-direct exclusion (see above).
                            route.key.family == family
                                && route.origin.peer != h
                                && route.protocol == Protocol::Bgp
                        })
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
                BgpAction::Close => {
                    // The FSM ended the session (hold timer expiry,
                    // NOTIFICATION received, parse error, ManualStop):
                    // tear it down exactly like a transport close —
                    // purge the peer's routes (or retain them under
                    // RFC 4724/9494) — and let the embedder close the
                    // transport. When the transport also closes later,
                    // the teardown re-runs idempotently (nothing left
                    // to purge).
                    self.teardown_bgp_session(session);
                }
                BgpAction::None => {}
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
    ///
    /// `BgpEvent::TransportClose` always yields [`BgpAction::Close`],
    /// which [`Self::dispatch_bgp_actions`] routes through
    /// [`Self::teardown_bgp_session`] — the same path an FSM-initiated
    /// close takes (hold timer expiry, NOTIFICATION received, parse
    /// error, ManualStop). A transport close arriving after the FSM
    /// already closed re-runs the teardown idempotently, so nothing is
    /// double-purged.
    pub fn close_session(&mut self, h: SessionHandle) {
        let Some(state) = self.sessions.get_mut(&h.0) else {
            return;
        };
        let actions = match state {
            SessionState::Bgp { peer, .. } => peer.step(BgpEvent::TransportClose),
            SessionState::Ospf { .. } | SessionState::Babel { .. } => Vec::new(),
        };
        self.dispatch_bgp_actions(h.0, actions);
    }

    /// Administratively close a live session with a Cease / Administrative
    /// Shutdown NOTIFICATION (RFC 4486 §4.1 subcode 2) instead of a bare
    /// FIN — the graceful-shutdown path for embedders (FRR `neighbor
    /// shutdown`, BIRD protocol disable parity). A session whose FSM is
    /// already Idle (the transport died first, or the peer already sent
    /// its own NOTIFICATION) is closed without a queued message.
    pub fn shutdown_session(&mut self, h: SessionHandle) {
        let mut administrative = false;
        if let Some(SessionState::Bgp { peer, .. }) = self.sessions.get_mut(&h.0) {
            if peer.state() != BgpState::Idle {
                peer.enqueue_notification(
                    BgpErrorCode::Cease,
                    BgpCeaseSubcode::AdministrativeShutdown as u8,
                );
                administrative = true;
            }
        }
        // Only a session we actually said goodbye to (FSM still live,
        // RFC 4486 §4.1 NOTIFICATION queued) counts as a deliberate
        // teardown; a session the transport already killed keeps its
        // silent-death semantics (RFC 4724/9494 retention).
        if administrative {
            self.administrative_close.insert(h.0);
        }
        self.close_session(h);
    }

    /// RFC 4271 §6.8 connection collision resolution. Called after an
    /// OPEN advanced `session` out of OpenSent (it is in OpenConfirm or
    /// — with an OPEN+KEEPALIVE in one read — Established).
    ///
    /// A sibling session collides when it belongs to the same
    /// `collision_group`, speaks BGP to a remote whose BGP Identifier
    /// equals the one in the just-received OPEN, and is in OpenSent or
    /// OpenConfirm (§6.8: OpenConfirm MUST be examined, OpenSent MAY —
    /// we follow FRR `bgp_collision_detect` and examine both; the
    /// OPEN-bearing sibling's role settles the winner without racy
    /// arrival-order assumptions). An Established sibling always wins:
    /// "unless allowed via configuration, a connection collision with
    /// an existing BGP connection that is in the Established state
    /// causes closing of the newly created connection".
    ///
    /// Resolution follows the convention — retain the connection
    /// initiated by the speaker with the higher BGP Identifier
    /// (4-octet unsigned comparison, RFC 4271 §6.8 step 1) — expressed
    /// through the sessions' TCP initiator roles, which is the
    /// convergent reading of the (erratum-corrected) steps 2/3 and
    /// exactly what FRR implements. Identical BGP Identifiers never
    /// reach this path: the FSM's OPEN validation rejects a peer
    ///Identifier equal to the local one (FRR
    /// `BGP_NOTIFY_OPEN_BAD_BGP_ID` parity) before OpenConfirm; the AS
    /// tie-break below remains as a defensive fallback.
    ///
    /// The losing side gets its FSM-buffered OPEN reply dropped, a
    /// Cease / Connection Collision Resolution NOTIFICATION (RFC 4486
    /// subcode 7) queued, and a full teardown — the embedder flushes
    /// the notification and closes the transport.
    ///
    /// Returns `true` when `session` itself lost: the caller must drop
    /// the pending actions its feed produced (the FSM already moved to
    /// Idle here).
    fn resolve_connection_collision(&mut self, session: u64) -> bool {
        // Sessions without a group never collide (the zero-overhead path
        // for every single-transport peer).
        let Some((group, s_locally_initiated)) = self.collision_meta.get(&session).copied() else {
            return false;
        };
        let Some(SessionState::Bgp { peer, .. }) = self.sessions.get(&session) else {
            return false;
        };
        let Some(remote_id) = peer.peer_bgp_id() else {
            return false;
        };
        let local_id = peer.config().local_bgp_id;
        let local_as = peer.config().local_as;
        let peer_as = peer.config().peer_as;

        let siblings: Vec<u64> = self
            .collision_meta
            .iter()
            .filter(|(sid, (g, _))| **sid != session && *g == group)
            .map(|(sid, _)| *sid)
            .collect();

        for t in siblings {
            let Some(SessionState::Bgp { peer: t_peer, .. }) = self.sessions.get(&t) else {
                continue;
            };
            // §6.8: only a connection to a speaker whose BGP Identifier
            // equals the one in the OPEN message collides. An OpenSent
            // sibling has not received an OPEN yet, so it cannot carry
            // its peer's Identifier — but the shared collision group is
            // precisely the "BGP Identifier of the peer known by means
            // outside of the protocol" the RFC's OpenSent clause asks
            // for: the embedder declared both sessions to be the same
            // peer.
            if t_peer.state() != BgpState::OpenSent && t_peer.peer_bgp_id() != Some(remote_id) {
                continue;
            }
            match t_peer.state() {
                BgpState::Established => {
                    self.close_collision_loser(
                        session,
                        t,
                        "an Established connection wins (RFC 4271 §6.8)",
                    );
                    return true;
                }
                BgpState::OpenSent | BgpState::OpenConfirm => {
                    let t_locally_initiated = self
                        .collision_meta
                        .get(&t)
                        .map(|(_, li)| *li)
                        .unwrap_or(false);
                    if t_locally_initiated == s_locally_initiated {
                        // Both sides play the same transport role — the
                        // §6.8 convention cannot rank them; leave the
                        // embedder's configuration alone.
                        continue;
                    }
                    let remote_initiated_wins = if local_id.0 < remote_id.0 {
                        true
                    } else if local_id.0 > remote_id.0 {
                        false
                    } else {
                        // Identical BGP Identifiers are a misconfiguration;
                        // FRR tie-breaks by AS number and logs loudly.
                        self.pending_events.push(RouterEvent::Log(format!(
                            "connection collision: peer's router-id {remote_id} equals ours \
                             (RFC 4271 §6.8); tie-breaking by AS number"
                        )));
                        local_as < peer_as
                    };
                    let session_wins = if s_locally_initiated {
                        !remote_initiated_wins
                    } else {
                        remote_initiated_wins
                    };
                    if session_wins {
                        self.close_collision_loser(
                            t,
                            session,
                            "the connection initiated by the higher BGP Identifier wins \
                             (RFC 4271 §6.8)",
                        );
                    } else {
                        self.close_collision_loser(
                            session,
                            t,
                            "the connection initiated by the higher BGP Identifier wins \
                             (RFC 4271 §6.8)",
                        );
                        return true;
                    }
                    return false;
                }
                _ => {}
            }
        }
        false
    }

    /// Close one side of a resolved §6.8 collision: drop any
    /// FSM-buffered reply (the KEEPALIVE an OpenConfirm peer already
    /// queued), queue the Cease / Connection Collision Resolution
    /// NOTIFICATION (RFC 4486 subcode 7), drive the FSM to Idle and run
    /// the ordinary teardown. `winner` only feeds the log line.
    fn close_collision_loser(&mut self, loser: u64, winner: u64, why: &str) {
        let actions = if let Some(SessionState::Bgp { peer, .. }) = self.sessions.get_mut(&loser) {
            peer.drain_outgoing();
            peer.enqueue_notification(
                BgpErrorCode::Cease,
                BgpCeaseSubcode::ConnectionCollision as u8,
            );
            peer.step(BgpEvent::ManualStop)
        } else {
            return;
        };
        // Latch the loss so the embedder's connector backs off instead of
        // redialing while the winning transport (here or at the peer)
        // completes its handshake.
        self.collision_lost.insert(loser);
        self.pending_events.push(RouterEvent::Log(format!(
            "connection collision between sessions #{loser} and #{winner} resolved: \
             closing #{loser} — {why}"
        )));
        self.dispatch_bgp_actions(loser, actions);
    }

    /// Common teardown for a BGP session that went down — whether the
    /// FSM itself reported it via [`BgpAction::Close`] or the transport
    /// closed underneath us (see [`Self::close_session`]). Clears the
    /// session's outbound bookkeeping, then either enters RFC 4724 /
    /// RFC 9494 retention (routes stay in Adj-RIB-In until the
    /// negotiated deadline) or purges the session's contribution from
    /// the RIB pipeline (RFC 4271 §6: the Adj-RIB-In is cleared and the
    /// Loc-RIB re-selected, withdrawing the stale best routes from the
    /// other sessions' Adj-RIB-Out).
    fn teardown_bgp_session(&mut self, session: u64) {
        if let Some(mrai) = self.mrai.get_mut(&session) {
            mrai.last_sent.clear();
            mrai.pending.clear();
        }
        // Clear maximum-prefix bookkeeping so a re-established session
        // starts with fresh threshold/exceeded latches.
        if let Some(state) = self.max_prefix_state.get_mut(&session) {
            state.exceeded = false;
            state.threshold_warned = false;
        }
        // W6.3 exchange-plane: the record sets a session sent leave with
        // it; the partial-transit counter resets too (feature
        // `exchange-plane`).
        #[cfg(feature = "exchange-plane")]
        self.exchange_plane_state.remove(&session);
        // Compute the retention windows from the peer's negotiated
        // GR/LLGR values. The FSM step that produced Close clears
        // nothing, but keep the ordering explicit: this must run before
        // any mutation that could reset the negotiated state.
        let retention = match self.sessions.get(&session) {
            Some(SessionState::Bgp {
                peer,
                was_established,
                ..
            }) => {
                // RFC 4724 §2: retention protects the routes an
                // ESTABLISHED session learned. A transport that died
                // mid-handshake (e.g. a §6.8 collision loser) carries no
                // routes — entering retention would only pin an empty
                // window and short-circuit the next teardown's cleanup.
                //
                // Deliberate goodbyes never retain either (BIRD parity —
                // BIRD arms GR only on a silent transport failure, never
                // on a received NOTIFICATION): the peer announced it is
                // going away on purpose (any received NOTIFICATION,
                // RFC 4486), or WE administratively closed the session —
                // nobody is restarting, so stale routes would only
                // blackhole traffic for the whole window.
                if !*was_established
                    || peer.notification_received()
                    || self.administrative_close.contains(&session)
                {
                    return self.session_down_cleanup(session);
                }
                let restart_time = peer.negotiated_graceful_restart_time().unwrap_or(0);
                // RFC 9494 §4.2: per-family LLST extends the retention
                // window beyond the RFC 4724 restart time. The received
                // timer may be capped by local configuration.
                let cap = self.llgr_caps.get(&session).copied();
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
        match retention {
            Some((restart_time, llgr_deadlines))
                if restart_time > 0 || !llgr_deadlines.is_empty() =>
            {
                // A session already in retention (the FSM closed it and
                // the transport close arrived later) keeps its original
                // deadline rather than restarting the clock.
                if self.graceful_restart.contains_key(&session) {
                    return;
                }
                let families: Vec<String> = llgr_deadlines
                    .keys()
                    .map(|f| format!("{}/{}", f.afi, f.safi))
                    .collect();
                self.graceful_restart.insert(
                    session,
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
                    session,
                    restart_time,
                    if families.is_empty() {
                        String::new()
                    } else {
                        format!(" + LLGR for families {:?}", families)
                    }
                )));
            }
            _ => self.session_down_cleanup(session),
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
        // One entry per purged route (both origins counted) — keep the
        // incremental max-prefix counter exact.
        if let Some(st) = self.max_prefix_state.get_mut(&session) {
            st.count = st.count.saturating_sub(affected.len() as u32);
        }
        for origin in origins {
            self.adj_rib_in.clear_for(origin);
            // W2.4: also drop the session's pre-policy slice — the
            // peer's raw routes do not survive the session either.
            self.pre_policy_adj_rib_in.clear_for(origin);
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
            let removed = self.adj_rib_in.mutate_origin(origin, |mut route| {
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
            // Deleted routes leave the session's Adj-RIB-In: keep the
            // incremental max-prefix counter exact.
            if let Some(st) = self.max_prefix_state.get_mut(&session) {
                st.count = st.count.saturating_sub(removed as u32);
            }
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
                if let Some(st) = self.max_prefix_state.get_mut(&session) {
                    st.count = st.count.saturating_sub(1);
                }
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

    /// End-of-RIB received for one family (RFC 4271 initial
    /// synchronization / RFC 4724 §4): the peer finished re-advertising
    /// its table. The convergence event is emitted for EVERY session —
    /// the marker is how a speaker signals "initial table dump complete"
    /// regardless of graceful restart; operators and e2e suites key on
    /// it ("session established + synchronized"). Pre-fix the event only
    /// fired for GR-retained sessions, so an ordinary iBGP session
    /// synchronized silently. The stale-route purge only applies to
    /// GR-retained sessions.
    fn on_end_of_rib(&mut self, session: u64, family: NlriFamily) {
        // Collect the GR bookkeeping without holding the borrow across
        // the removal.
        let refreshed = match self.graceful_restart.get_mut(&session) {
            Some(state) => {
                state.llgr_deadlines.remove(&family);
                let refreshed = state.refreshed.clone();
                let more_families = !state.llgr_deadlines.is_empty();
                if !more_families {
                    self.graceful_restart.remove(&session);
                }
                Some(refreshed)
            }
            None => None,
        };
        if let Some(refreshed) = refreshed {
            self.purge_unrefreshed_family(session, family, &refreshed);
        }
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
                // W2.1: propagate the FRR `bgp default ipv4-unicast`
                // posture to PeerConfig so the FSM can gate legacy-section
                // IPv4 NLRI on it (see PeerConfig::ipv4_unicast_active).
                p_cfg.default_ipv4_unicast = cfg.default_ipv4_unicast;
                // W2.3: propagate the FRR `neighbor X allowas-in N` /
                // BIRD `allow local as` tolerance to PeerConfig so the
                // router's per-peer AS-loop tolerance check sees it.
                p_cfg.local_as_tolerance = cfg.local_as_tolerance;
                // W2.4: propagate the FRR `neighbor X soft-reconfiguration
                // inbound` flag to PeerConfig so import_route knows to
                // retain the raw received route in the pre-policy RIB.
                p_cfg.soft_reconfig_inbound = cfg.soft_reconfig_inbound;
                p_cfg.peer_id = h.0;
                p_cfg.local_address = cfg.local_address;
                p_cfg.extended_next_hop = cfg.extended_next_hop.clone();
                p_cfg.maximum_prefix = cfg.maximum_prefix;
                p_cfg.maximum_prefix_action = cfg.maximum_prefix_action;
                p_cfg.maximum_prefix_threshold = cfg.maximum_prefix_threshold;
                p_cfg.maximum_prefix_restart_time = cfg.maximum_prefix_restart_time;
                let peer = BgpPeer::new(p_cfg);
                if let Some(group) = cfg.collision_group {
                    self.collision_meta
                        .insert(h.0, (group, cfg.locally_initiated));
                }
                self.sessions.insert(
                    h.0,
                    SessionState::Bgp {
                        peer: Box::new(peer),
                        conn: MemoryConn::new(),
                        established: false,
                        was_established: false,
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
                    topology_version: 0,
                });
                let runtime = OspfRuntime::new(
                    router_id,
                    cfg.area_id,
                    protocol == Protocol::Ospfv3,
                    cfg.ospf_mtu,
                    cfg.ospf_network_type,
                    cfg.ospf_interface_ip,
                    cfg.ospf_neighbor_ip,
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
        // Per-session bookkeeping must not outlive the session: LLGR caps,
        // max-prefix state and the Adj-RIB-Out / pre-policy slices.
        self.llgr_caps.remove(&h.0);
        self.max_prefix_state.remove(&h.0);
        // §6.8 bookkeeping must not outlive the session either — a stale
        // group entry would make a future session collide with a ghost.
        self.collision_meta.remove(&h.0);
        for origin in [
            RouteOrigin {
                proto: 0,
                peer: h.0,
            },
            RouteOrigin {
                proto: 1,
                peer: h.0,
            },
        ] {
            self.adj_rib_out.clear_for(origin);
            self.pre_policy_adj_rib_in.clear_for(origin);
        }
        // Remove every route that session contributed and re-select.
        // Withdraw with each route's *actual* origin (proto 0 or 1) so
        // iBGP-origin paths are not left behind.
        let keys: Vec<(RouteOrigin, RouteKey, u32)> = self
            .adj_rib_in
            .iter_all()
            .filter(|r| r.origin.peer == h.0)
            .map(|r| (r.origin, r.key.clone(), r.path_id))
            .collect();
        for (origin, k, path_id) in keys {
            self.withdraw_from_session(origin, &k, path_id);
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
        // recognised as *newly* established (initial table dump), and
        // start the new transport incarnation with fresh RFC 4724 /
        // §6.8 bookkeeping.
        if let Some(SessionState::Bgp {
            established,
            was_established,
            ..
        }) = self.sessions.get_mut(&h.0)
        {
            *established = false;
            *was_established = false;
        }
        self.collision_lost.remove(&h.0);
        self.administrative_close.remove(&h.0);
        Ok(())
    }

    fn feed_input(&mut self, h: SessionHandle, bytes: &[u8]) -> Result<(), String> {
        self.feed_input_at(h, bytes, 0, 0)
    }

    fn feed_input_at(
        &mut self,
        h: SessionHandle,
        bytes: &[u8],
        now_ms: u64,
        now_us: u32,
    ) -> Result<(), String> {
        // Phase 1 (borrow sessions): decode + drive the protocol FSM.
        enum Pending {
            Bgp {
                actions: Vec<BgpAction>,
                newly_established: bool,
                /// FSM state before/after the feed — the RFC 4271 §6.8
                /// collision hook keys on an OpenSent → OpenConfirm
                /// (or Established) transition.
                prev_state: BgpState,
                post_state: BgpState,
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
                    was_established,
                } => {
                    conn.push_input(bytes);
                    let input = conn.take_input();
                    if input.is_empty() {
                        return Ok(());
                    }
                    let prev_state = peer.state();
                    let actions = peer.feed_bytes(&input).map_err(|e| e.to_string())?;
                    let was_established_before = *established;
                    *established = peer.is_established();
                    if *established {
                        *was_established = true;
                    }
                    // A Cease / Connection Collision Resolution (RFC 4486
                    // subcode 7) NOTIFICATION means the PEER's resolver
                    // closed this transport — the same loss a local
                    // resolver produces, just decided remotely. Latch it
                    // so the embedder can hold the connector back instead
                    // of redialing into an occupied peer.
                    if peer.received_cease_collision() {
                        self.collision_lost.insert(h.0);
                    }
                    let post_state = peer.state();
                    Pending::Bgp {
                        actions,
                        newly_established: *established && !was_established_before,
                        prev_state,
                        post_state,
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
                        Self::finalize_ospf_v2_egress(runtime.protocol, &mut outbound);
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
                        withdraw_reason: String::new(),
                    };
                    let mut r = lr_core::buf::ReadBuf::new(&input);
                    while let Ok(Some(frame)) = runtime.codec.decode(&mut r) {
                        let d = runtime.handle_frame(&frame, now_ms, now_us);
                        delta.installed.extend(d.installed);
                        delta.withdrawn.extend(d.withdrawn);
                        // Preserve the withdraw reason from the last
                        // frame that carried one — the operator's
                        // diagnostic. A multi-frame batch where some
                        // frames retract and others install keeps the
                        // retraction reason (the actionable one).
                        if !d.withdraw_reason.is_empty() {
                            delta.withdraw_reason = d.withdraw_reason;
                        }
                    }
                    Pending::Other { delta }
                }
            }
        };
        // Phase 1.5 (borrow released): RFC 4271 §6.8 collision
        // resolution. Runs before any of the fresh actions dispatch so
        // a losing session never emits its OPEN-confirm state or arms
        // its timers.
        let collision_lost = match &pending {
            Pending::Bgp {
                prev_state,
                post_state,
                ..
            } => {
                *prev_state == BgpState::OpenSent
                    && matches!(post_state, BgpState::OpenConfirm | BgpState::Established)
                    && self.resolve_connection_collision(h.0)
            }
            _ => false,
        };
        // Phase 2 (borrow released): apply results to the RIB pipeline.
        match pending {
            Pending::Bgp {
                actions,
                newly_established,
                ..
            } => {
                if collision_lost {
                    // This session lost the §6.8 collision: the resolver
                    // already queued the Cease/7 NOTIFICATION, drove the
                    // FSM to Idle and tore the session down. The actions
                    // the feed produced (OPEN-confirm timer arms, …) are
                    // stale — drop them.
                    return Ok(());
                }
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
                //
                // Grace-LSAs (RFC 3623/5187: OSPFv2 type-9 opaque type 3,
                // OSPFv3 LS type 0x000b) are the exception: link-scoped
                // (RFC 5250 §3.1 / RFC 5187 §2.1), never installed into
                // the area LSDB nor re-flooded — each changed instance
                // surfaces through drain_ospf_grace_events() for the
                // embedder's helper-mode policy instead.
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
                let mut grace_lsas: Vec<Lsa> = Vec::new();
                if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                    for lsa in lsas {
                        // Grace-LSA: the graceful-restart signal, not
                        // topology. Link-scoped (RFC 5250 §3.1) —
                        // parked here and surfaced after the LSDB
                        // borrow ends; never installed, never flooded.
                        if is_grace_lsa(&lsa) {
                            grace_lsas.push(lsa.clone());
                            continue;
                        }
                        // Stub/NSSA LSA policy (RFC 2328 §3.6, RFC 3101).
                        if !ospf_area_accepts(&kind, &lsa) {
                            continue;
                        }
                        // Topology-change bookkeeping (RFC 3623 §3.2 (3))
                        // needs the *previous* instance before install.
                        let prev = area.lsdb.get(&lsa.key()).map(|e| e.lsa.clone());
                        let outcome = area.lsdb.install(lsa.clone(), self.now_ms);
                        if outcome.changed() {
                            if lsa_topology_changed(prev.as_ref(), &lsa, outcome) {
                                area.topology_version += 1;
                            }
                            if lsa.header.ls_type == LsaTypeV2::AsExternalLsa as u16
                                || lsa.header.ls_type == lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
                                || lsa.header.ls_type == lr_ospf::lsa::LS_TYPE_E_AS_EXTERNAL
                            {
                                as_scope.push(lsa.clone());
                            }
                            to_flood.push(lsa);
                            changed = true;
                        }
                    }
                }
                for lsa in &grace_lsas {
                    self.on_ospf_grace_lsa(area_id, lsa);
                }
                if !as_scope.is_empty() {
                    // v2 type-5 bodies never enter OSPFv3 areas and are
                    // refused by stub/NSSA areas; v3 0x4005 LSAs mirror
                    // them onto the v3 areas (RFC 5340 §4.4.3.6 — AS
                    // flooding scope).
                    let others: Vec<u32> = self
                        .ospf_areas
                        .iter()
                        .filter(|(a, area)| {
                            **a != area_id
                                && !area.kind.is_stubby()
                                && area.protocol
                                    == if as_scope[0].header.ls_type
                                        == LsaTypeV2::AsExternalLsa as u16
                                    {
                                        Protocol::Ospfv2
                                    } else {
                                        Protocol::Ospfv3
                                    }
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
                if let Ok(mut bytes) = runtime.codec.encode_vec(&p) {
                    Self::finalize_ospf_v2_egress(runtime.protocol, &mut bytes);
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

    /// Push events back to the *front* of the pending queue, keeping
    /// their relative order. The FFI embedder shape: a caller whose
    /// poll buffer filled mid-batch requeues the remainder so no event
    /// is lost (poll + serialize + requeue is one logical drain).
    fn requeue_events(&mut self, mut events: Vec<RouterEvent>) {
        if events.is_empty() {
            return;
        }
        events.append(&mut self.pending_events);
        self.pending_events = events;
    }

    fn rib_snapshot(&self) -> Vec<&Route> {
        self.loc_rib.iter_best().collect()
    }

    fn rib_paths_snapshot(&self) -> Vec<&Route> {
        self.loc_rib.iter_paths().collect()
    }

    fn session_peer_state(&self, h: SessionHandle) -> Option<&'static str> {
        match self.sessions.get(&h.0) {
            Some(SessionState::Bgp { peer, .. }) => Some(peer.state().name()),
            _ => None,
        }
    }

    fn session_restart_cooldown_remaining(&self, h: SessionHandle) -> Option<u64> {
        let until = self
            .max_prefix_state
            .get(&h.0)
            .and_then(|s| s.restart_cooldown_until)?;
        // `now_ms` is advanced by the daemon's ticker; a cooldown whose
        // deadline has passed is "no cooldown" so the connector dials at
        // once. Saturating subtract guards against a clock that jumped.
        if until <= self.now_ms {
            return None;
        }
        Some(until - self.now_ms)
    }

    fn take_collision_lost(&mut self, h: SessionHandle) -> bool {
        self.collision_lost.remove(&h.0)
    }

    fn session_was_established(&self, h: SessionHandle) -> bool {
        match self.sessions.get(&h.0) {
            Some(SessionState::Bgp {
                was_established, ..
            }) => *was_established,
            _ => false,
        }
    }

    fn babel_reachable(&self, exclude: SessionHandle) -> Vec<lr_babel::BabelRoute> {
        // The feasible best set per foreign session, deduplicated by the
        // full source claim (destination, source prefix, router-id) with
        // the lowest metric winning — what one interface re-advertises on
        // every other (RFC 8966 §3.7.1).
        let mut best: BTreeMap<lr_babel::RouteKey, lr_babel::BabelRoute> = BTreeMap::new();
        for (handle, state) in &self.sessions {
            if *handle == exclude.0 {
                continue;
            }
            let SessionState::Babel { runtime, .. } = state else {
                continue;
            };
            for r in runtime.routes.best_routes() {
                match best.get(&r.key) {
                    Some(prev) if prev.metric <= r.metric => {}
                    _ => {
                        best.insert(r.key.clone(), r.clone());
                    }
                }
            }
        }
        best.into_values().collect()
    }

    fn babel_flush_session(&mut self, h: SessionHandle) {
        let Some(SessionState::Babel { runtime, .. }) = self.sessions.get_mut(&h.0) else {
            return;
        };
        // Drop the learned table; the diff against `published` emits the
        // withdrawal delta, and the session stays alive for the link's
        // return (routes re-learn from the peer's Updates).
        runtime.routes = lr_babel::BabelRouteTable::new();
        let mut delta = runtime.diff();
        if !delta.withdrawn.is_empty() {
            delta.withdraw_reason = format!(
                "babel interface link-down flush ({} route(s))",
                delta.withdrawn.len()
            );
        }
        self.apply_runtime_delta(delta);
    }

    fn babel_rtt_us(&self, h: SessionHandle, now_ms: u64) -> Option<u32> {
        match self.sessions.get(&h.0) {
            Some(SessionState::Babel { runtime, .. }) => runtime.neighbor.rtt_us(now_ms),
            _ => None,
        }
    }

    fn babel_rtt_echo(&self, h: SessionHandle, now_ms: u64) -> Option<(u32, u32)> {
        match self.sessions.get(&h.0) {
            Some(SessionState::Babel { runtime, .. }) => runtime.neighbor.rtt_echo_pair(now_ms),
            _ => None,
        }
    }

    fn babel_gc(&mut self, now_ms: u64) {
        // Collect first, apply after: the sessions map borrows self.
        let mut deltas: Vec<RuntimeDelta> = Vec::new();
        for state in self.sessions.values_mut() {
            let SessionState::Babel { runtime, .. } = state else {
                continue;
            };
            deltas.push(runtime.gc(now_ms));
        }
        for delta in deltas {
            self.apply_runtime_delta(delta);
        }
    }

    fn set_babel_own_router_id(&mut self, h: SessionHandle, id: [u8; 8]) {
        if let Some(SessionState::Babel { runtime, .. }) = self.sessions.get_mut(&h.0) {
            runtime.own_router_id = Some(id);
        }
    }

    fn set_babel_link_cost_params(
        &mut self,
        h: SessionHandle,
        rtt_min_us: u32,
        rtt_max_us: u32,
        rtt_cost: u16,
    ) {
        if let Some(SessionState::Babel { runtime, .. }) = self.sessions.get_mut(&h.0) {
            runtime.rtt_min_us = rtt_min_us;
            runtime.rtt_max_us = rtt_max_us;
            runtime.rtt_cost = rtt_cost;
        }
    }

    fn babel_note_peer(&mut self, h: SessionHandle, peer: lr_core::addr::IpAddr) {
        if let Some(SessionState::Babel { runtime, .. }) = self.sessions.get_mut(&h.0) {
            // The transport already filters our own looped-back
            // multicasts (the `locals` set); every datagram that reaches
            // here is a genuine peer source.
            runtime.neighbor.address = peer;
        }
    }

    fn babel_egress_nexthops(
        &self,
        h: SessionHandle,
    ) -> Option<(Option<lr_core::addr::IpAddr>, Option<lr_core::addr::IpAddr>)> {
        let SessionState::Babel { runtime, .. } = self.sessions.get(&h.0)? else {
            return None;
        };
        // The next hop of last resort per family is the peer's own
        // source address (RFC 8966 §3.5.3) — once traffic has been seen
        // both that and any TLV-advertised address egress the session's
        // interface, so both are useful to an egress-pinning embedder.
        let peer_v4 = match runtime.neighbor.address {
            IpAddr::V4(_) => Some(runtime.neighbor.address),
            IpAddr::V6(_) => None,
        };
        let peer_v6 = match runtime.neighbor.address {
            IpAddr::V6(_) => Some(runtime.neighbor.address),
            IpAddr::V4(_) => None,
        };
        Some((
            runtime.next_hop_v4.or(peer_v4),
            runtime.next_hop_v6.or(peer_v6),
        ))
    }

    fn flush_rib_for_shutdown(&mut self) {
        // The process is on its way out: queue one withdrawal per
        // Loc-RIB key. The event consumer (the ticker's final drain)
        // hands them to the kernel mirror; no bookkeeping beyond the
        // events is needed.
        let keys: Vec<RouteKey> = self.loc_rib.iter_best().map(|r| r.key.clone()).collect();
        for key in keys {
            self.pending_events.push(RouterEvent::RouteWithdrawn(key));
        }
    }

    fn babel_take_route_request(&mut self, h: SessionHandle) -> bool {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Babel { runtime, .. }) => {
                core::mem::replace(&mut runtime.route_request, false)
            }
            _ => false,
        }
    }

    fn babel_take_own_seqno_request(&mut self, h: SessionHandle) -> Option<u16> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Babel { runtime, .. }) => runtime.own_seqno_request.take(),
            _ => None,
        }
    }
}

impl DefaultRouter {
    // ------------------------------------------------------------------
    // OSPF multi-area plumbing
    // ------------------------------------------------------------------

    /// Apply one protocol-runtime delta (installed/withdrawn routes) to
    /// Loc-RIB and emit the corresponding events.
    ///
    /// rc.3 shared RIB: the OSPF/Babel runtimes install *protocol-direct*
    /// routes that never passed through the Adj-RIB-In pipeline. When the
    /// key also carries BGP candidates (Adj-RIB-In paths or a local
    /// origination) — or an operator-configured static route — the change
    /// goes through the merged decision process so the best path falls
    /// out of the full preference order (static 1 < BGP 20 < OSPF 110 <
    /// Babel 120) and a withdrawal from either side falls back to the
    /// other's contribution. Keys with no other contributor keep the
    /// historical direct-install behaviour (single-path `install` +
    /// event) — exactly what a single-protocol OSPF/Babel daemon sees
    /// today.
    ///
    /// The static-side comparison is load-bearing: before it existed, a
    /// Babel-learned route for a prefix the operator had *also*
    /// configured as a static (e.g. both ends of a tunnel announcing the
    /// same aggregate) blindly replaced the static in the Loc-RIB — the
    /// daemon then stopped announcing its own aggregate (the remote
    /// peer's copy expired: "babel routes not fully propagated") and the
    /// kernel mirror clobbered the operator's blackhole with the learned
    /// route.
    fn apply_runtime_delta(&mut self, delta: RuntimeDelta) {
        for route in delta.installed {
            let key = route.key.clone();
            self.direct_rib.insert(key.clone(), route.clone());
            let other_side = self.adj_rib_in.iter_all().any(|r| r.key == key)
                || self.originated.contains_key(&key)
                || self.redistributed_bgp.contains_key(&key)
                || self.static_routes.contains_key(&key);
            if other_side {
                self.reselect(&key);
            } else {
                // Deduplicate on the byte-identical re-install: OSPF/Babel
                // runtimes call this on every SPF recompute / every Babel
                // UPDATE re-advertisement, and a recompute that yields the
                // same best route must not emit a fresh `RouteInstalled`
                // event — without this guard the kernel mirror would
                // re-issue `CreateIpForwardEntry2` (Windows:
                // `ERROR_OBJECT_ALREADY_EXISTS` delete+recreate) or
                // `ip route replace` (Linux: redundant RTM_NEWROUTE) on
                // every tick, exactly the churn observed in the Windows
                // production report (`mirror: route installed ...` four
                // times in a row for the same prefix).
                let changed = self.loc_rib.install(route.clone());
                if changed {
                    self.pending_events
                        .push(RouterEvent::RouteInstalled(route.clone()));
                }
                // Opt-in redistribution still sees the new direct best:
                // a BGP-side candidate reaches the same call through
                // apply_selection, and the direct path must not skip it
                // (an OSPF/Babel-learned route with an Ospf/Babel → BGP
                // pipe re-originates into BGP exactly like a BGP-side
                // route would). `redistribute_route` itself is a no-op
                // when the route is byte-identical to what was last
                // redistributed for the key.
                self.redistribute_route(&route);
            }
        }
        // If the delta carries a withdraw reason, surface it as a Log
        // event BEFORE the RouteWithdrawn events so the operator can
        // correlate the withdrawal with its cause. This is the
        // diagnostic the production report asked for: "why does Babel
        // withdraw routes?" — the reason is now in the daemon log.
        if !delta.withdrawn.is_empty() && !delta.withdraw_reason.is_empty() {
            self.pending_events.push(RouterEvent::Log(format!(
                "babel withdraw: {} — {} route(s): {}",
                delta.withdraw_reason,
                delta.withdrawn.len(),
                delta
                    .withdrawn
                    .iter()
                    .map(|k| k.prefix.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        for key in delta.withdrawn {
            if let Some(withdrawn) = self.direct_rib.remove(&key) {
                // A pipe copy this route sourced goes with it; a copy
                // sourced from a different protocol's contribution to
                // the same key survives (its source is still alive).
                let sourced = self
                    .redistributed_bgp
                    .get(&key)
                    .is_some_and(|copy| copy.origin.peer == withdrawn.origin.peer);
                if sourced {
                    self.unredistribute_route(&key);
                }
                // The direct contribution is gone; the merged decision
                // process restores a surviving BGP/originated/static
                // candidate (or uninstalls the key when none is left).
                self.reselect(&key);
            } else {
                self.loc_rib.uninstall(&key);
                self.pending_events.push(RouterEvent::RouteWithdrawn(key));
            }
        }
    }

    /// Patch the RFC 2328 §A.1 packet checksum into every encoded OSPFv2
    /// packet of an egress stream. The `lr-ospf` codec deliberately emits
    /// the checksum field zeroed and the receive side validates it
    /// (RFC 2328 §8.2 discards bad packets), so every v2 packet this
    /// router puts on the wire must be finalized first. OSPFv3 streams
    /// are left untouched — RFC 5340 computes a different checksum over a
    /// pseudo-header.
    fn finalize_ospf_v2_egress(protocol: Protocol, bytes: &mut [u8]) {
        if protocol == Protocol::Ospfv2 {
            lr_ospf::origination::finalize_v2_stream(bytes);
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
            if let Ok(mut bytes) = runtime.codec.encode_vec(&packet) {
                Self::finalize_ospf_v2_egress(runtime.protocol, &mut bytes);
                conn.put_output(&bytes);
            }
        }
    }

    /// Whether this router currently acts as an OSPF area border router
    /// for `protocol`: attached to the backbone plus at least one other
    /// area, all areas running that version (RFC 2328 §12.4.3 for v2;
    /// RFC 5340 §4.4.3.4 for v3). Stub/NSSA summaries, defaults,
    /// type-7 → type-5 translation and the v3 inter-area/ASBR
    /// summaries all hinge on border-router status.
    fn ospf_is_abr_for(&self, protocol: Protocol) -> bool {
        self.ospf_router_id.is_some()
            && self.ospf_areas.len() >= 2
            && self.ospf_areas.contains_key(&0)
            && self.ospf_areas.values().all(|a| a.protocol == protocol)
    }

    /// Whether this router currently acts as an OSPF area border router:
    /// attached to the backbone plus at least one other area, all v2
    /// (RFC 2328 §12.4.3). Stub/NSSA summaries, defaults and type-7 →
    /// type-5 translation all hinge on border-router status.
    fn ospf_is_abr(&self) -> bool {
        self.ospf_is_abr_for(Protocol::Ospfv2)
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
            // SPF visits vertices in order of increasing distance, so
            // the first entry for a given prefix has the lowest metric.
            // Use `or_insert_with` so a connected stub route (next_hop
            // = None, lowest metric) is NOT overwritten by a via-peer
            // route to the same prefix (next_hop = Some, higher metric).
            // Overwriting would install a gateway route for a directly
            // connected network, which the kernel FIB mirror then uses
            // to replace the connected route — breaking reachability to
            // the gateway itself and cascading ENETUNREACH on every
            // downstream route that points through it.
            table
                .entry(r.prefix)
                .or_insert_with(|| OspfTableEntry::intra(r.metric, r.next_hop));
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
                            (r.forwarding_addr != 0)
                                .then(|| IpAddr::V4(r.forwarding_addr.to_be_bytes())),
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
                            (r.forwarding_addr != 0)
                                .then(|| IpAddr::V4(r.forwarding_addr.to_be_bytes())),
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
            if area.protocol == Protocol::Ospfv3 {
                // OSPFv3 area (RFC 5340): the intra-area calculation
                // runs over the v3 LSDB — intra-area prefixes plus,
                // with `ospf_srv6_receive` on, the RFC 9513 §5 SRv6
                // locators; then the inter-area summaries (§4.8.3,
                // 0x2003) and AS externals (§4.8.5, 0x4005).
                let spf3 = if self.ospf_v3_extended_lsas {
                    spf::run_spf_v3_extended(&area.lsdb, router_id)
                } else {
                    spf::run_spf_v3(&area.lsdb, router_id)
                };
                let mut table: BTreeMap<Prefix, OspfTableEntry> = BTreeMap::new();
                for r in &spf3.routes {
                    table
                        .entry(r.prefix)
                        .or_insert_with(|| OspfTableEntry::intra_v3(r.metric, r.next_hop));
                }
                if self.ospf_srv6_receive {
                    // RFC 9513 §5: locators of supported algorithms
                    // install as forwarding entries. A prefix
                    // reachability advertisement covering the same
                    // prefix (the Intra-Area-Prefix routes above)
                    // MUST be preferred (§5), so this only fills the
                    // gaps the IAP routes left.
                    for loc in &spf3.locators {
                        if !Self::ospf_srv6_algorithm_supported(loc.algorithm) {
                            continue;
                        }
                        table
                            .entry(loc.prefix)
                            .or_insert_with(|| OspfTableEntry::intra_v3(loc.metric, loc.next_hop));
                    }
                }
                // §4.8.3: inter-area routes from 0x2003 summaries —
                // intra-area paths win per prefix (§16.2 (b)), and
                // `no_summary` areas derive only the default (the same
                // rule the v2 area table applies).
                for r in if self.ospf_v3_extended_lsas {
                    spf::summary_routes_v3_extended(&area.lsdb, &spf3)
                } else {
                    spf::summary_routes_v3(&area.lsdb, &spf3)
                } {
                    if area.kind.no_summary() && r.prefix.prefix_len != 0 {
                        continue;
                    }
                    table.entry(r.prefix).or_insert_with(|| OspfTableEntry {
                        metric: r.metric,
                        kind: OspfKind::Inter {
                            border_router: r.border_router.unwrap_or(0),
                        },
                        label: None,
                        label_nh: None,
                        next_hop: r.next_hop,
                    });
                }
                // §4.8.5: AS externals from 0x4005 — `external_routes_v3`
                // resolves the §16.4 (6) preference among candidates, and
                // the entry only fills prefixes without an internal or
                // inter-area route (§11 path preference).
                for r in if self.ospf_v3_extended_lsas {
                    lr_ospf::external::external_routes_v3_extended(&area.lsdb, &spf3)
                } else {
                    lr_ospf::external::external_routes_v3(&area.lsdb, &spf3)
                } {
                    table.entry(r.prefix).or_insert_with(|| OspfTableEntry {
                        metric: r.metric,
                        kind: OspfKind::External {
                            metric_type: r.metric_type,
                            asbr: r.asbr,
                            forwarding_addr: r.forwarding_addr,
                            internal_cost: r.internal_cost,
                        },
                        label: None,
                        label_nh: None,
                        next_hop: r.next_hop,
                    });
                }
                for (prefix, entry) in table {
                    let better = match global.get(&prefix) {
                        None => true,
                        Some((prev, _, _)) => entry.beats(prev),
                    };
                    if better {
                        global.insert(prefix, (entry, *area_id, Protocol::Ospfv3));
                    }
                }
                continue;
            }
            let spf_result = spf::run_spf(&area.lsdb, router_id);
            let mut table = Self::ospf_area_table(&area.kind, abr, &area.lsdb, &spf_result);
            if self.ospf_sr_receive {
                // RFC 8665 reception: project the area's SR state and
                // attach the resolved labels to the routes they map
                // onto (fail-soft — an LSDB without SR LSAs yields an
                // empty database and changes nothing).
                let srdb = lr_ospf::srdb::SrDatabase::from_lsdb(&area.lsdb);
                Self::ospf_attach_sr_labels(&mut table, &srdb, &spf_result);
            }
            for (prefix, entry) in table {
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
                // OSPFv3 routes are IPv6 routes: the v3 SPF derives
                // IPv6 prefixes and link-local next hops, so they key
                // into the v6-unicast family (RFC 5340 §3.1 — OSPF for
                // IPv6 installs IPv6 routes).
                let key = if protocol == Protocol::Ospfv3 {
                    RouteKey::new(prefix, NlriFamily::IPV6_UNICAST)
                } else {
                    RouteKey::new(prefix, NlriFamily::IPV4_UNICAST)
                };
                // §16.4: an external route with a forwarding address
                // forwards traffic to that address, not to the ASBR.
                let mut next_hop = match entry.kind {
                    OspfKind::External {
                        forwarding_addr: Some(fa),
                        ..
                    } => Some(fa),
                    _ => entry.next_hop,
                };
                // RFC 8660 head end: an SR-labelled route enters the
                // LSP — the private LrMplsLabelStack attribute carries
                // the label to the kernel mirror (same channel the
                // RFC 8277 BGP-LU routes use), and the next hop is the
                // first hop toward the prefix-SID originator.
                let mut attributes = lr_core::attr::Attributes::new();
                if let (Some(label), Some(nh)) = (entry.label, entry.label_nh) {
                    let stack =
                        lr_mpls::LabelStack::from_labels([lr_mpls::Label::new_value(label)]);
                    let mut attrs = PathAttributes::new();
                    attrs.insert(PathAttribute::new(
                        PathAttrFlags::new().set_optional(true),
                        AttrType::LrMplsLabelStack,
                        stack.encode_4octet(),
                    ));
                    attributes = attrs.into();
                    next_hop = Some(nh);
                }
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
                    attributes,
                    age_ms: 0,
                    path_id: 0,
                    tag: None,
                };
                (key, route)
            })
            .collect();
        self.ospf_diff_published(current)
    }

    /// Attach the RFC 8665 §5 labels an SR database resolves for the
    /// table's prefixes. Only intra-area and inter-area entries are
    /// labelled: their paths follow the prefix-SID originator, while an
    /// external route forwards to the ASBR or the type-5 forwarding
    /// address — a different path than the one the SID encodes. The
    /// label plus its next hop ride the entry (see
    /// [`OspfTableEntry::label`]); the entry kind and metric are
    /// untouched, so route selection is unaffected.
    ///
    /// Prefixes without a direct Prefix-SID advertisement fall back to
    /// the SR Mapping Server's M-flagged ranges (RFC 8665 §4, RFC 8661
    /// §3.2.3): the LSP rides the prefix's *own* path, so the entry
    /// keeps the route's regular next hop and only the label is
    /// attached.
    fn ospf_attach_sr_labels(
        table: &mut BTreeMap<Prefix, OspfTableEntry>,
        srdb: &lr_ospf::srdb::SrDatabase,
        spf: &spf::SpfResult,
    ) {
        for (prefix, entry) in table.iter_mut() {
            if !entry.is_intra() && !matches!(entry.kind, OspfKind::Inter { .. }) {
                continue;
            }
            if let Some((label, next_hop)) = srdb.label_for(prefix, spf) {
                entry.label = Some(label);
                entry.label_nh = Some(next_hop);
                continue;
            }
            if let Some(label) = srdb.mapping_label_for(prefix, spf) {
                // RFC 8661 §3.2.2: install the mapping exactly as if
                // the prefix owner had advertised it — the LSP rides
                // the prefix's own path (intra: the SPF route's next
                // hop; inter: the path toward the advertising border
                // router), not the path toward the mapping server.
                let next_hop = match entry.kind {
                    OspfKind::Inter { border_router } => spf
                        .next_hops
                        .get(&spf::VertexId::Router(border_router))
                        .copied(),
                    _ => spf
                        .stub_routes
                        .iter()
                        .chain(&spf.transit_routes)
                        .find(|r| r.prefix == *prefix)
                        .and_then(|r| r.next_hop),
                };
                entry.label = Some(label);
                entry.label_nh = next_hop;
            }
        }
    }

    /// Diff `current` against the published OSPF table and swap it in.
    fn ospf_diff_published(&mut self, current: BTreeMap<RouteKey, Route>) -> RuntimeDelta {
        let mut delta = RuntimeDelta {
            installed: Vec::new(),
            withdrawn: Vec::new(),
            withdraw_reason: String::new(),
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

    /// ABR summary origination for both protocol planes (RFC 2328
    /// §12.4.3 / RFC 5340 §4.4.3.4): each version's ABR machinery runs
    /// when every attached area speaks it, and its self-originated
    /// summaries are flushed when it does not (fail-closed — e.g. a
    /// mixed v2/v3 router acts as an ABR for neither version).
    fn ospf_summarize_areas(&mut self) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        let mut changed = false;
        // OSPFv2 plane: type-3 summaries, type-4 ASBR summaries, the
        // stub/NSSA defaults.
        if self.ospf_is_abr() {
            changed |= self.ospf_summarize_areas_v2(router_id);
        } else {
            // Not a functioning v2 ABR: flush every self-originated
            // summary (type-3) and summary-ASBR (type-4) LSA ...
            changed |= self.ospf_flush_self_lsa_types(router_id, |key| {
                key.ls_type == LsaTypeV2::SummaryIpLsa as u16
                    || key.ls_type == LsaTypeV2::SummaryAsbrLsa as u16
            });
            // ... and the ABR-injected NSSA defaults lose their
            // justification too (RFC 3101 §2.4).
            changed |= self.ospf_nssa_defaults();
        }
        // OSPFv3 plane: 0x2003 inter-area-prefix and 0x2004
        // inter-area-router summaries (RFC 5340 §4.4.3.4/§4.4.3.5).
        if self.ospf_is_abr_for(Protocol::Ospfv3) {
            changed |= self.ospf_summarize_areas_v3(router_id);
        } else {
            changed |= self.ospf_flush_self_lsa_types(router_id, |key| {
                key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX
                    || key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER
            });
            self.ospf_v3_summary_lsids.clear();
        }
        changed
    }

    /// OSPFv2 ABR summary origination (RFC 2328 §12.4.3). See
    /// [`Self::ospf_summarize_areas`] for the dispatch rules.
    fn ospf_summarize_areas_v2(&mut self, router_id: u32) -> bool {
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
                            key.ls_type == LsaTypeV2::SummaryIpLsa as u16
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

    /// OSPFv3 ABR summary origination (RFC 5340 §4.4.3.4 and
    /// §4.4.3.5) — the v3 mirror of [`Self::ospf_summarize_areas_v2`]:
    ///
    /// - 0x2003 inter-area-prefix-LSAs follow the v2 type-3 source
    ///   rules (into the backbone: every non-backbone area's
    ///   intra-area prefixes; into a non-backbone area: the backbone's
    ///   intra-area prefixes plus the inter-area routes other ABRs
    ///   summarized there; the target's own intra-area prefixes are
    ///   never summarized back; stubby targets receive the configured
    ///   default instead — a zero-length prefix, the v3 default form).
    /// - 0x2004 inter-area-router-LSAs advertise ASBRs (the
    ///   advertisers of 0x4005 LSAs) that are reachable through other
    ///   areas but not intra-area in the target, at the ABR's own cost
    ///   — LS ID = the destination router ID.
    ///
    /// The 0x2003 LS ID carries no addressing semantics (§4.4.3.4), so
    /// each prefix keeps a stable per-area LS ID: the previous
    /// instance's LS ID is reused when one exists, else the next free
    /// ID is allocated (FRR `ospf6_new_ls_id` parity).
    fn ospf_summarize_areas_v3(&mut self, router_id: u32) -> bool {
        // 1. Fresh per-area v3 SPF results and route tables (the same
        //    merge the recompute uses: intra + inter, externals
        //    excluded from the sources).
        let spf_results: BTreeMap<u32, spf::SpfResultV3> = self
            .ospf_areas
            .iter()
            .filter(|(_, area)| area.protocol == Protocol::Ospfv3)
            .map(|(id, area)| {
                (
                    *id,
                    if self.ospf_v3_extended_lsas {
                        spf::run_spf_v3_extended(&area.lsdb, router_id)
                    } else {
                        spf::run_spf_v3(&area.lsdb, router_id)
                    },
                )
            })
            .collect();
        let tables: BTreeMap<u32, BTreeMap<Prefix, OspfTableEntry>> = self
            .ospf_areas
            .iter()
            .filter(|(_, area)| area.protocol == Protocol::Ospfv3)
            .map(|(id, area)| {
                let spf3 = spf_results.get(id).expect("v3 spf result");
                let mut t: BTreeMap<Prefix, OspfTableEntry> = BTreeMap::new();
                for r in &spf3.routes {
                    t.entry(r.prefix)
                        .or_insert_with(|| OspfTableEntry::intra_v3(r.metric, r.next_hop));
                }
                for r in if self.ospf_v3_extended_lsas {
                    spf::summary_routes_v3_extended(&area.lsdb, spf3)
                } else {
                    spf::summary_routes_v3(&area.lsdb, spf3)
                } {
                    if area.kind.no_summary() && r.prefix.prefix_len != 0 {
                        continue;
                    }
                    t.entry(r.prefix).or_insert_with(|| OspfTableEntry {
                        metric: r.metric,
                        kind: OspfKind::Inter {
                            border_router: r.border_router.unwrap_or(0),
                        },
                        label: None,
                        label_nh: None,
                        next_hop: r.next_hop,
                    });
                }
                (*id, t)
            })
            .collect();
        let backbone = tables.get(&0).cloned().unwrap_or_default();

        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for &target in &areas {
            let Some(kind) = self
                .ospf_areas
                .get(&target)
                .filter(|a| a.protocol == Protocol::Ospfv3)
                .map(|a| a.kind)
            else {
                continue;
            };
            // Sources: what the target should learn about the outside.
            let mut sources: BTreeMap<Prefix, u64> = if target == 0 {
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
                BTreeMap::new()
            } else {
                let mut s = BTreeMap::new();
                for (p, e) in &backbone {
                    if e.is_intra() {
                        s.insert(*p, e.metric);
                    }
                }
                for (p, e) in &backbone {
                    if !e.is_intra()
                        && !e.is_own_inter(router_id)
                        && !matches!(e.kind, OspfKind::External { .. })
                    {
                        s.insert(*p, e.metric);
                    }
                }
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
            // Stubby v3 targets receive the border-router default (the
            // zero-length prefix form of §4.4.3.4).
            if target != 0 {
                if let Some(metric) = kind.default_metric() {
                    if kind.is_stub() {
                        sources.insert(Prefix::new_v6([0u8; 16], 0), u64::from(metric));
                    }
                }
            }
            // Loop guard: never summarize the target's own intra-area
            // prefixes back into the target.
            if let Some(table) = tables.get(&target) {
                for (p, e) in table {
                    if e.is_intra() {
                        sources.remove(p);
                    }
                }
            }

            // Existing self-originated 0x2003s, keyed by LS ID.
            let existing: BTreeMap<u32, Lsa> = self
                .ospf_areas
                .get(&target)
                .map(|area| {
                    area.lsdb
                        .iter()
                        .filter(|(key, _)| {
                            key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX
                                && key.advertising_router == router_id
                        })
                        .map(|(key, entry)| (key.link_state_id, entry.lsa.clone()))
                        .collect()
                })
                .unwrap_or_default();

            // Stable LS ID allocation: the router's mapping first,
            // else a previous instance advertising the same prefix,
            // else the lowest free ID.
            let area_map = self.ospf_v3_summary_lsids.entry(target).or_default();
            let mut used_lsids: BTreeSet<u32> = BTreeSet::new();
            let mut to_originate: Vec<Lsa> = Vec::new();
            for (prefix, metric) in &sources {
                let ls_id = match area_map.get(prefix) {
                    Some(&id) => id,
                    None => {
                        let reused = existing.iter().find_map(|(id, lsa)| {
                            lr_ospf::lsa::decode_v3_inter_area_prefix_body(&lsa.body)
                                .filter(|b| b.to_prefix().as_ref() == Some(prefix))
                                .map(|_| *id)
                        });
                        let id = reused.unwrap_or_else(|| {
                            (1u32..)
                                .find(|id| !existing.contains_key(id) && !used_lsids.contains(id))
                                .unwrap_or(0)
                        });
                        area_map.insert(*prefix, id);
                        id
                    }
                };
                used_lsids.insert(ls_id);
                let dest = SummaryDestination::new(*prefix, *metric as u32);
                let prev = existing.get(&ls_id);
                let unchanged = prev.is_some_and(|lsa| {
                    lr_ospf::lsa::decode_v3_inter_area_prefix_body(&lsa.body).is_some_and(|b| {
                        b.metric == dest.metric
                            && b.prefix_len == dest.prefix.prefix_len
                            && b.to_prefix().as_ref() == Some(prefix)
                    })
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) =
                    originate_v3_inter_area_prefix_lsa(router_id, ls_id, &dest, prev_seq)
                {
                    to_originate.push(lsa);
                }
            }
            // Flush summaries whose destination disappeared.
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
        // §4.4.3.5: 0x2004 inter-area-router summaries for ASBRs this
        // ABR can reach but the target area cannot.
        self.ospf_summarize_asbrs_v3(router_id, &spf_results) | changed
    }

    /// RFC 5340 §4.4.3.5 (the v3 type-4): for every ASBR — the
    /// advertisers of the 0x4005 LSAs present in the v3 LSDBs —
    /// originate into each attached v3 area an inter-area-router-LSA
    /// when the ASBR is intra-area reachable through one of the
    /// router's other areas but not through the target. The advertised
    /// metric is the ABR's own cost to the ASBR; the Options field
    /// mirrors the destination's Router-LSA options (§4.4.3.5); the LS
    /// ID is the destination router ID. Stale self-originated 0x2004s
    /// whose ASBR lost reachability are flushed.
    fn ospf_summarize_asbrs_v3(
        &mut self,
        router_id: u32,
        spf_results: &BTreeMap<u32, spf::SpfResultV3>,
    ) -> bool {
        // AS-scope 0x4005s are installed in every v3 area; derive the
        // ASBR set from whichever v3 area has an LSDB (lowest ID).
        let source_area = self
            .ospf_areas
            .iter()
            .filter(|(_, area)| area.protocol == Protocol::Ospfv3)
            .map(|(id, _)| *id)
            .min();
        let Some(source_area) = source_area else {
            return false;
        };
        let Some(source) = self.ospf_areas.get(&source_area) else {
            return false;
        };
        let asbrs: BTreeSet<u32> = source
            .lsdb
            .iter()
            .filter(|(key, _)| {
                key.ls_type == lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
                    && key.advertising_router != router_id
            })
            .map(|(key, _)| key.advertising_router)
            .collect();

        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for target in areas {
            let Some(target_kind) = self.ospf_areas.get(&target).map(|a| a.kind) else {
                continue;
            };
            let is_v3 = self
                .ospf_areas
                .get(&target)
                .is_some_and(|a| a.protocol == Protocol::Ospfv3);
            // Stale self-originated 0x2004s: flushed everywhere when the
            // target left the v3 plane or went stubby.
            if !is_v3 || target_kind.is_stubby() {
                let flushes: Vec<Lsa> = self
                    .ospf_areas
                    .get(&target)
                    .map(|area| {
                        area.lsdb
                            .iter()
                            .filter(|(key, _)| {
                                key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER
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
            // Existing self-originated 0x2004s, keyed by destination
            // (the LS ID is the destination router ID).
            let existing: BTreeMap<u32, Lsa> = self
                .ospf_areas
                .get(&target)
                .map(|area| {
                    area.lsdb
                        .iter()
                        .filter(|(key, _)| {
                            key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER
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
                    continue;
                }
                let intra_here = spf_results
                    .get(&target)
                    .is_some_and(|r| r.vertices.contains_key(&spf::V3VertexId::Router(asbr)));
                if intra_here {
                    continue; // the target reaches the ASBR itself
                }
                let best: Option<(u64, u32)> = spf_results
                    .iter()
                    .filter(|(id, _)| **id != target)
                    .filter_map(|(_, r)| {
                        let d = r.vertices.get(&spf::V3VertexId::Router(asbr)).copied()?;
                        // The options the destination's own Router-LSA
                        // advertises (§4.4.3.5).
                        let opts = r.router_options.get(&asbr).copied().unwrap_or(0);
                        Some((d, opts))
                    })
                    .min_by_key(|(d, _)| *d);
                let Some((cost, options)) = best else {
                    continue; // unreachable through us
                };
                used_lsids.insert(asbr);
                let prev = existing.get(&asbr);
                let unchanged = prev.is_some_and(|lsa| {
                    lr_ospf::lsa::v3::V3InterAreaRouterBody::decode(&lsa.body).is_some_and(|b| {
                        b.metric == cost.min(0x00ff_fffe) as u32 && b.options == options
                    })
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_v3_inter_area_router_lsa(
                    router_id,
                    asbr,
                    options,
                    asbr,
                    cost.min(0x00ff_fffe) as u32,
                    prev_seq,
                ) {
                    to_originate.push(lsa);
                }
            }
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
                            key.ls_type == LsaTypeV2::NssaExternalLsa as u16
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
            .filter(|(key, _)| key.ls_type == LsaTypeV2::AsExternalLsa as u16)
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
                                key.ls_type == LsaTypeV2::SummaryAsbrLsa as u16
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
                            key.ls_type == LsaTypeV2::SummaryAsbrLsa as u16
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
                    if key.ls_type != LsaTypeV2::NssaExternalLsa as u16 {
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
                            k.ls_type == LsaTypeV2::AsExternalLsa as u16
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
                            k.ls_type == LsaTypeV2::AsExternalLsa as u16
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
    /// Returns the number of pipes removed. When a pipe targeting BGP is
    /// removed, the re-originated copies it produced are flushed and the
    /// affected prefixes re-selected, so the Loc-RIB falls back to the
    /// remaining candidates (a copy produced by another still-configured
    /// BGP-target pipe is re-created on the next source change).
    pub fn remove_redistribution_pipe(&mut self, source: Protocol, target: Protocol) -> usize {
        let before = self.pipes.len();
        self.pipes
            .retain(|p| !(p.source == source && p.target == target));
        let removed = before - self.pipes.len();
        if removed > 0 && target == Protocol::Bgp {
            let keys: Vec<RouteKey> = self.redistributed_bgp.keys().cloned().collect();
            for key in keys {
                self.unredistribute_route(&key);
                self.reselect(&key);
            }
        }
        removed
    }

    /// Apply redistribution for a single route that just entered (or
    /// changed in) the Loc-RIB. Called from `apply_selection` when the
    /// best route for a prefix changes.
    fn redistribute_route(&mut self, route: &Route) {
        // Terminate the apply_selection → redistribute_route feedback
        // loop: a stored copy is locally originated (proto 2), so it
        // outranks the peer path that produced it, becomes the Loc-RIB
        // best and re-enters this function with the copy itself. The
        // copy is the engine's own output — re-running it through the
        // pipes would be a feedback cycle. The `unchanged` guard in the
        // BGP arm below is not sufficient on its own: under
        // `MetricPolicy::Add(N)` the metric grows on every pass, so the
        // produced copy never equals the stored one and the recursion
        // only stops when the stack overflows.
        if self
            .redistributed_bgp
            .get(&route.key)
            .is_some_and(|existing| {
                existing.protocol == route.protocol
                    && existing.origin == route.origin
                    && existing.preference == route.preference
                    && existing.attributes == route.attributes
                    && existing.next_hop == route.next_hop
            })
        {
            return;
        }
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
                        // The re-originated copy keeps the source route's
                        // peer so the export split horizon (RFC 4271
                        // §9.1.3 Phase 3) never re-advertises it to the
                        // session it was learned from; proto 2 marks it as
                        // locally (re-)originated.
                        origin: RouteOrigin {
                            proto: 2,
                            peer: route.origin.peer,
                        },
                        protocol: Protocol::Bgp,
                        preference: lr_core::rib::Preference::new(
                            Protocol::Bgp.default_admin_distance(),
                            metric,
                        ),
                        next_hop: route.next_hop,
                        attributes: attrs.into(),
                        age_ms: self.now_ms,
                        path_id: 0,
                        tag: None,
                    };
                    let key = route.key.clone();
                    // No-op when the copy is unchanged (age aside). This
                    // also terminates the apply_selection →
                    // redistribute_route cycle when the copy itself is
                    // the Loc-RIB best and re-matches its own pipe.
                    let unchanged = self.redistributed_bgp.get(&key).is_some_and(|existing| {
                        existing.origin == bgp_route.origin
                            && existing.preference == bgp_route.preference
                            && existing.attributes == bgp_route.attributes
                            && existing.next_hop == bgp_route.next_hop
                    });
                    if unchanged {
                        continue;
                    }
                    self.redistributed_bgp
                        .insert(key.clone(), bgp_route.clone());
                    // Run the decision process instead of a wholesale
                    // install_set: the best path by the configured
                    // preference (admin distance / BGP decision process)
                    // wins the Loc-RIB slot, and a beaten peer path stays
                    // in Adj-RIB-In to be restored when the winner
                    // disappears (RFC 4271 §9.1.2).
                    let mut candidates: Vec<Route> = self
                        .adj_rib_in
                        .iter_all()
                        .filter(|r| r.key == key)
                        .cloned()
                        .collect();
                    candidates.push(bgp_route);
                    let ranked: Vec<Route> =
                        if candidates.iter().all(|r| r.protocol == Protocol::Bgp) {
                            BestPath::rank(&candidates, &self.best_path_cfg)
                                .into_iter()
                                .take(self.add_path_max_paths)
                                .cloned()
                                .collect()
                        } else {
                            RouteSelector::select(&candidates)
                                .into_iter()
                                .cloned()
                                .collect()
                        };
                    self.apply_selection(&key, ranked);
                    self.pending_events.push(RouterEvent::Log(format!(
                        "redistribute: {} -> BGP (metric={})",
                        route.key.prefix, metric
                    )));
                }
                Protocol::Ospfv2 | Protocol::Ospfv3 => {
                    match route.key.prefix.addr {
                        IpAddr::V4(_) if pipe.target == Protocol::Ospfv2 => {
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
                        IpAddr::V6(_) if pipe.target == Protocol::Ospfv3 => {
                            let dest = V3ExternalDestination {
                                prefix: route.key.prefix,
                                metric,
                                type2: false, // type 1, the v4 path's choice
                                forwarding_addr: None,
                                // 0 means "no tag" — the T bit stays clear.
                                route_tag: (pipe.tag != 0).then_some(pipe.tag),
                            };
                            self.ospf_redistribute_v3(dest);
                            self.pending_events.push(RouterEvent::Log(format!(
                                "redistribute: {} -> OSPFv3 (metric={})",
                                route.key.prefix, metric
                            )));
                        }
                        // A v6 prefix cannot ride the v2 external plane
                        // and a v4 prefix cannot ride the v3 one.
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    /// Withdraw a redistributed BGP route. Called when the source route
    /// disappears from the Loc-RIB (or a locally originated route is
    /// unoriginated, or the producing pipe is removed). The copy is
    /// dropped from the redistributed pool; the caller re-runs the
    /// decision process so the Loc-RIB converges to the remaining
    /// candidates (RFC 4271 §9.1.2).
    fn unredistribute_route(&mut self, key: &RouteKey) {
        if self.redistributed_bgp.remove(key).is_some() {
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
    /// Returns `false` (and records nothing) for non-IPv4 destinations
    /// — IPv6 destinations belong on the OSPFv3 plane, see
    /// [`Self::ospf_redistribute_v3`]. The intent is still recorded when
    /// no OSPF session exists yet; it is originated as soon as the
    /// first OSPFv2 area attaches.
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
        if matches!(prefix.addr, lr_core::addr::IpAddr::V6(_)) {
            return self.ospf_unredistribute_v3(prefix);
        }
        let mask = prefix_len_to_mask(prefix.prefix_len);
        let lr_core::addr::IpAddr::V4(octets) = prefix.addr else {
            return false;
        };
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
                    let external = key.ls_type == LsaTypeV2::AsExternalLsa as u16
                        || key.ls_type == LsaTypeV2::NssaExternalLsa as u16;
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
        let mut changed = false;
        if !self.ospf_externals.is_empty() {
            let networks: Vec<u32> = self.ospf_externals.keys().copied().collect();
            for network in networks {
                changed |= self.ospf_originate_externals(network);
            }
        }
        if !self.ospf_v3_externals.is_empty() {
            let prefixes: Vec<Prefix> = self.ospf_v3_externals.keys().copied().collect();
            for prefix in prefixes {
                changed |= self.ospf_originate_externals_v3(prefix);
            }
        }
        changed
    }

    /// Redistribute an IPv6 external destination on the OSPFv3 plane
    /// (RFC 5340 §4.4.3.6): originate a 0x4005 AS-external-LSA into
    /// every attached OSPFv3 area and remember the destination so areas
    /// that attach later catch up (see [`Self::ospf_sync_externals`]).
    ///
    /// The forwarding address, when set, must be a *global* IPv6
    /// address — unspecified and link-local values are illegal
    /// (§A.4.7) and are refused. Returns `false` (and records nothing)
    /// for non-IPv6 destinations. The intent is still recorded when no
    /// OSPF session exists yet; it is originated as soon as the first
    /// OSPFv3 area attaches.
    pub fn ospf_redistribute_v3(&mut self, dest: V3ExternalDestination) -> bool {
        let lr_core::addr::IpAddr::V6(_) = dest.prefix.addr else {
            return false;
        };
        if let Some(fa) = dest.forwarding_addr {
            let illegal = fa == [0u8; 16] || (fa[0] == 0xfe && (fa[1] & 0xc0) == 0x80);
            if illegal {
                return false;
            }
        }
        // Store the network-normalized form — the LS ID and the
        // unchanged-detection compare against the wire body, which is
        // always normalized (§A.4.1).
        let mut dest = dest;
        let lr_core::addr::IpAddr::V6(net) = dest.prefix.network() else {
            return false;
        };
        dest.prefix = Prefix::new_v6(net, dest.prefix.prefix_len);
        let prefix = dest.prefix;
        self.ospf_v3_externals.insert(prefix, dest);
        let changed = self.ospf_originate_externals_v3(prefix);
        if changed {
            let delta = self.ospf_on_lsdb_change();
            self.apply_runtime_delta(delta);
        }
        true
    }

    /// Stop redistributing an IPv6 external destination (RFC 5340
    /// §4.4.3.6): MaxAge-flush the self-originated 0x4005 LSA from
    /// every attached OSPFv3 area and flood the flush. Returns `false`
    /// when no matching redistribution exists.
    pub fn ospf_unredistribute_v3(&mut self, prefix: Prefix) -> bool {
        // Compare against the network-normalized key.
        let lr_core::addr::IpAddr::V6(net) = prefix.network() else {
            return false;
        };
        let prefix = Prefix::new_v6(net, prefix.prefix_len);
        if self.ospf_v3_externals.remove(&prefix).is_none() {
            return false;
        }
        let Some(ls_id) = self.ospf_v3_external_lsids.remove(&prefix) else {
            return false;
        };
        let router_id = self.ospf_router_id.unwrap_or(0);
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for area_id in areas {
            let mut flushes = Vec::new();
            if let Some(area) = self.ospf_areas.get(&area_id) {
                for (key, entry) in area.lsdb.iter() {
                    if key.ls_type == lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
                        && key.advertising_router == router_id
                        && key.link_state_id == ls_id
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

    /// Originate (or refresh) the self-originated 0x4005 for `prefix`
    /// in every attached OSPFv3 area (RFC 5340 §4.4.3.6): the same LSA
    /// content everywhere — the LS ID is stable per prefix so every
    /// area's instance is the same LSA. Floods what changed. Returns
    /// whether any LSDB changed.
    fn ospf_originate_externals_v3(&mut self, prefix: Prefix) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false; // no OSPF session yet — kept for later
        };
        let Some(&dest) = self.ospf_v3_externals.get(&prefix) else {
            return false;
        };
        // Stable LS ID: the router's mapping first, else a previous
        // instance advertising the same prefix in any v3 area, else the
        // lowest ID free across all v3 areas.
        let v3_areas: Vec<u32> = self
            .ospf_areas
            .iter()
            .filter(|(_, a)| a.protocol == Protocol::Ospfv3)
            .map(|(id, _)| *id)
            .collect();
        let ls_id = match self.ospf_v3_external_lsids.get(&prefix) {
            Some(&id) => id,
            None => {
                let reused = v3_areas.iter().find_map(|&area| {
                    self.ospf_areas
                        .get(&area)?
                        .lsdb
                        .iter()
                        .find(|(key, entry)| {
                            key.ls_type == lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
                                && key.advertising_router == router_id
                                && lr_ospf::lsa::v3::V3AsExternalBody::decode(&entry.lsa.body)
                                    .and_then(|b| b.prefix_addr_prefix())
                                    .is_some_and(|p| p == prefix)
                        })
                        .map(|(key, _)| key.link_state_id)
                });
                let in_use: BTreeSet<u32> = v3_areas
                    .iter()
                    .filter_map(|&area| self.ospf_areas.get(&area))
                    .flat_map(|area| {
                        area.lsdb
                            .iter()
                            .filter(|(key, _)| {
                                key.ls_type == lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
                                    && key.advertising_router == router_id
                            })
                            .map(|(key, _)| key.link_state_id)
                    })
                    .collect();
                let id =
                    reused.unwrap_or_else(|| (1u32..).find(|id| !in_use.contains(id)).unwrap_or(0));
                self.ospf_v3_external_lsids.insert(prefix, id);
                id
            }
        };
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        for area_id in v3_areas {
            let prev = self.ospf_areas.get(&area_id).and_then(|area| {
                area.lsdb
                    .iter()
                    .find(|(key, _)| {
                        key.ls_type == lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
                            && key.advertising_router == router_id
                            && key.link_state_id == ls_id
                    })
                    .map(|(_, entry)| entry.lsa.clone())
            });
            let unchanged = prev.as_ref().is_some_and(|lsa| {
                lr_ospf::lsa::v3::V3AsExternalBody::decode(&lsa.body).is_some_and(|b| {
                    b.e_bit == dest.type2
                        && b.metric == dest.metric
                        && b.prefix.prefix_len == dest.prefix.prefix_len
                        && b.forwarding_addr == dest.forwarding_addr
                        && b.route_tag == dest.route_tag
                })
            });
            if unchanged {
                continue;
            }
            let prev_seq = prev.map(|lsa| lsa.header.ls_sequence_number);
            if let Some(lsa) = originate_v3_as_external_lsa(router_id, ls_id, &dest, prev_seq) {
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
                            key.ls_type == LsaTypeV2::NssaExternalLsa as u16
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
                            key.ls_type == LsaTypeV2::AsExternalLsa as u16
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
                        key.ls_type == LsaTypeV2::AsExternalLsa as u16
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

    /// Toggle RFC 8665 SR reception: when on, every OSPF area recompute
    /// projects the area LSDB into a per-node SR database and attaches
    /// the resolved Prefix-SID labels (RFC 8660 head end) to the routes
    /// they map onto. Off by default — the kernel mirror only acts on
    /// labelled routes, so a router that never enables this stays
    /// byte-identical to a pre-SR one. Set once at startup, before
    /// sessions feed the router.
    pub fn set_ospf_sr_receive(&mut self, on: bool) {
        self.ospf_sr_receive = on;
    }

    /// Whether RFC 8665 SR reception is enabled (see
    /// [`Self::set_ospf_sr_receive`]).
    pub fn ospf_sr_receive(&self) -> bool {
        self.ospf_sr_receive
    }

    /// Toggle RFC 9513 §5 SRv6 reception: when on, every OSPFv3 area
    /// recompute installs the intra-area SRv6 locators of supported
    /// algorithms as IPv6 forwarding entries (§5 — a locator route's
    /// metric is the advertising router's SPF distance). Off by
    /// default; a router that never enables this stays byte-identical
    /// to a pre-SRv6 one. Set once at startup, before sessions feed
    /// the router.
    pub fn set_ospf_srv6_receive(&mut self, on: bool) {
        self.ospf_srv6_receive = on;
    }

    /// Whether RFC 9513 SRv6 reception is enabled (see
    /// [`Self::set_ospf_srv6_receive`]).
    pub fn ospf_srv6_receive(&self) -> bool {
        self.ospf_srv6_receive
    }

    /// Enable the RFC 8362 Extended-LSA mode for the OSPFv3
    /// calculations (`ExtendedLSASupport`, Appendix A): the v3 SPF,
    /// inter-area and external calculations prefer a speaker's
    /// Extended LSAs and admit the E inter-area/external forms. Set
    /// once at startup, before sessions feed the router — the flag is
    /// read at every recompute, but origination switches belong to the
    /// embedder (the daemon pairs this with its own E-LSA
    /// origination).
    pub fn set_ospf_v3_extended_lsas(&mut self, on: bool) {
        self.ospf_v3_extended_lsas = on;
    }

    /// Whether the RFC 8362 Extended-LSA mode is enabled (see
    /// [`Self::set_ospf_v3_extended_lsas`]).
    pub fn ospf_v3_extended_lsas(&self) -> bool {
        self.ospf_v3_extended_lsas
    }

    /// The IGP algorithms this router supports for SRv6 locator
    /// installation (RFC 9513 §5: locators "associated with algorithms
    /// supported by the receiving OSPFv3 router" install). Algorithm 0
    /// (SPF) only — flexible algorithm support is future work.
    fn ospf_srv6_algorithm_supported(algorithm: u8) -> bool {
        algorithm == 0
    }

    /// Project every area's SRv6 database (RFC 9513): capabilities,
    /// algorithms, MSDs, locators and End SIDs per advertising router.
    /// Area ID → [`lr_ospf::srv6db::Srv6Database`]; empty map when no
    /// OSPFv3 areas are attached. The runtime API surfaces this for
    /// its SRv6 status; embedders get the same read-only view.
    pub fn ospf_srv6_databases(&self) -> BTreeMap<u32, lr_ospf::srv6db::Srv6Database> {
        self.ospf_areas
            .iter()
            .map(|(id, area)| (*id, lr_ospf::srv6db::Srv6Database::from_lsdb(&area.lsdb)))
            .collect()
    }

    /// Project every area's SR database (RFC 8665): SRGBs, Prefix-SID
    /// mappings, adjacency segments (Extended Link LSAs) and
    /// mapping-server ranges (Extended Prefix Range TLVs). Area ID →
    /// [`lr_ospf::srdb::SrDatabase`]; empty map when no OSPF areas are
    /// attached. The daemon's runtime API uses this for its `sr`
    /// status lines; embedders get the same read-only view.
    pub fn ospf_sr_databases(&self) -> BTreeMap<u32, lr_ospf::srdb::SrDatabase> {
        self.ospf_areas
            .iter()
            .map(|(id, area)| (*id, lr_ospf::srdb::SrDatabase::from_lsdb(&area.lsdb)))
            .collect()
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

    /// Monotonic topology version of one OSPF area: bumped on every
    /// content change of a topology LSA (v2 types 1-5, 7; periodic
    /// refreshes excluded) in that area's LSDB — the RFC 3623 §3.2 (3)
    /// "network topology change" signal. Embedders running
    /// graceful-restart helper mode poll this (once per main-loop pass,
    /// the same pattern as the LSDB refresh driver) and exit helping
    /// when the counter moves. `None` for unknown areas.
    pub fn ospf_area_topology_version(&self, area_id: u32) -> Option<u64> {
        self.ospf_areas.get(&area_id).map(|a| a.topology_version)
    }

    /// Read one LSA out of an area's LSDB by its exact key
    /// (type, link-state ID, advertising router). The
    /// graceful-restart restarting router uses this to fetch its own
    /// pre-restart router-LSA — re-received from helping neighbours
    /// through database exchange (RFC 3623 §2.2 (1)) — and walk the
    /// adjacencies it used to carry. `None` for unknown areas or
    /// missing LSAs.
    pub fn ospf_area_lsa(&self, area_id: u32, ls_type: u16, ls_id: u32, adv: u32) -> Option<Lsa> {
        let area = self.ospf_areas.get(&area_id)?;
        area.lsdb
            .get(&lr_ospf::lsa::LsaKey {
                ls_type,
                link_state_id: ls_id,
                advertising_router: adv,
            })
            .map(|e| e.lsa.clone())
    }

    /// Surface one received Grace-LSA as an [`OspfGraceEvent`] (the
    /// RFC 3623 §3.1 / RFC 5187 §2 helper trigger, drained through
    /// [`Self::drain_ospf_grace_events`]). Deduplicated by sequence
    /// number per (area, advertising router): the restarting router
    /// retransmits its Grace-LSAs until acknowledged, and the helper
    /// decision must run once per instance, not per copy. A MaxAge
    /// instance maps to `purged = true` — the §3.2 (1) successful-exit
    /// signal.
    fn on_ospf_grace_lsa(&mut self, area_id: u32, lsa: &Lsa) {
        use lr_ospf::lsa::grace::{GraceLsaBody, GraceReason};
        let adv = lsa.header.advertising_router;
        let key = (area_id, adv);
        // RFC 2328 §13 instance identity: same sequence AND age AND
        // checksum AND length = the same instance (a retransmission);
        // anything else is a new instance worth an event. Sequence
        // alone is not enough: a flush (MaxAge, empty body) and a
        // fresh announcement can share a sequence number at second
        // boundaries of the wallclock-derived lineage and are
        // different LSAs.
        let instance = (
            lsa.header.ls_sequence_number,
            lsa.header.ls_age,
            lsa.header.ls_checksum,
            lsa.header.length,
        );
        if self.ospf_grace_seen.get(&key) == Some(&instance) {
            return;
        }
        // The signed sequence comparison of RFC 2328 §12.1.2 guards
        // against going backwards to an older instance; equal-seq
        // different-content instances still pass (they are distinct).
        let seen_seq = self.ospf_grace_seen.get(&key).map(|(s, ..)| *s);
        let is_older = match seen_seq {
            Some(prev) => (lsa.header.ls_sequence_number as i32) < (prev as i32),
            None => false,
        };
        if is_older {
            return;
        }
        self.ospf_grace_seen.insert(key, instance);
        let purged = lsa.header.ls_age >= lr_ospf::lsdb::MAX_AGE_SECS;
        // A MaxAge flush does not carry a meaningful body (and a
        // restart-completing router may zero it) — period/reason fall
        // back to the last seen instance's values.
        let (period, reason, addr_v4, addr_v6, age) = if purged {
            (
                0,
                GraceReason::Unknown as u8,
                None,
                None,
                lr_ospf::lsdb::MAX_AGE_SECS,
            )
        } else {
            match GraceLsaBody::decode(&lsa.body) {
                Some(body) => (
                    body.grace_period,
                    body.reason as u8,
                    body.ipv4_address,
                    body.ipv6_address,
                    lsa.header.ls_age,
                ),
                None => {
                    self.pending_events.push(RouterEvent::Log(format!(
                        "ospf: malformed grace-LSA from {} (area {}) ignored",
                        lr_core::addr::RouterId::from_u32(adv),
                        area_id
                    )));
                    return;
                }
            }
        };
        self.ospf_grace_events.push(OspfGraceEvent {
            area: area_id,
            advertising_router: adv,
            grace_period_secs: period,
            reason,
            interface_addr_v4: addr_v4,
            interface_addr_v6: addr_v6,
            ls_age_secs: age,
            purged,
        });
    }

    /// Drain the received Grace-LSA events (RFC 3623 §3.1 /
    /// RFC 5187 §2) accumulated by OSPF LSA processing — one per
    /// changed instance. Embedders running OSPF graceful-restart
    /// helper (or restarting-router) policy call this from their poll
    /// loop; the events never ride `poll_events()` so an embedder
    /// that delegates general event consumption to a ticker/mirror
    /// thread (the daemon's shape) still receives every grace
    /// instance deterministically.
    pub fn drain_ospf_grace_events(&mut self) -> Vec<OspfGraceEvent> {
        core::mem::take(&mut self.ospf_grace_events)
    }

    /// Push the current DR/BDR election result (RFC 2328 §9.4) for the
    /// segment a session's interface attaches to. The embedder (the
    /// daemon or an OSPF-speaking embedder) runs the election over the
    /// bidirectional neighbors — [`lr_ospf::interface::elect`] is the
    /// reference algorithm — and reports the elected routers here as
    /// their IP interface addresses (§A.3.2 wire identity).
    ///
    /// When the result changes, this re-runs the §10.4 adjacency
    /// decision for the session's neighbor (§9.4 step 7 — the AdjOK?
    /// event): a bidirectional neighbor that now qualifies advances to
    /// ExStart (the initial DBD is queued), and one that no longer
    /// qualifies drops back to 2-Way with its exchange state reset.
    ///
    /// Returns whether the DR/BDR pair changed. Unknown handles and
    /// non-OSPF sessions return `Err`.
    pub fn set_ospf_dr_state(
        &mut self,
        h: SessionHandle,
        dr: u32,
        bdr: u32,
    ) -> Result<bool, String> {
        let mut outbound: Vec<u8> = Vec::new();
        {
            let state = self
                .sessions
                .get_mut(&h.0)
                .ok_or_else(|| format!("no session {}", h.0))?;
            let SessionState::Ospf { runtime, conn } = state else {
                return Err(format!("session {} is not an OSPF session", h.0));
            };
            if runtime.dr == dr && runtime.bdr == bdr {
                return Ok(false);
            }
            runtime.dr = dr;
            runtime.bdr = bdr;
            // §9.4 step 7 / §10.3: the AdjOK? event re-examines the
            // adjacency eligibility of the neighbor.
            let was = runtime.neighbor.state;
            if was == NeighborState::TwoWay && runtime.adjacency_viable() {
                let _ = runtime
                    .neighbor
                    .step(NeighborEvent::AdjOk { proceed: true });
            } else if was >= NeighborState::ExStart && !runtime.adjacency_viable() {
                let _ = runtime
                    .neighbor
                    .step(NeighborEvent::AdjOk { proceed: false });
                // BIRD's INM_ADJOK demotion resets the exchange lists so
                // a later re-adjacency starts a fresh DBD negotiation.
                runtime.exchange = lr_ospf::exchange::DbExchange::new(
                    runtime.router_id,
                    runtime.area_id,
                    runtime.iface_mtu,
                );
            }
            // Entering ExStart emits the initial DBD (§10.3), exactly
            // like the Hello path.
            if runtime.neighbor.state == NeighborState::ExStart && !runtime.exchange.started() {
                let seq = self.now_ms as u32 ^ runtime.router_id | 1;
                let pkt = runtime.exchange.initial_db_desc(seq, self.now_ms);
                if let Ok(bytes) = runtime.codec.encode_vec(&pkt) {
                    outbound.extend_from_slice(&bytes);
                }
            }
            if !outbound.is_empty() {
                Self::finalize_ospf_v2_egress(runtime.protocol, &mut outbound);
                conn.put_output(&outbound);
            }
        }
        Ok(true)
    }

    // ------------------------------------------------------------------
    // Virtual links (RFC 2328 §15)
    // ------------------------------------------------------------------

    /// The Router-LSA body flags (RFC 2328 §A.4.2 V/E/B bits) this
    /// router should advertise for `area`, derived from its current
    /// state:
    ///
    /// * `E` (ASBR) — any AS-external redistribution intent exists
    ///   ([`Self::ospf_redistribute`] recorded one and no withdraw
    ///   removed it since). Peers key RFC 2328 §16.4 external-route
    ///   eligibility on this bit; without it a type-5 LSA sits in
    ///   every neighbour's LSDB but computes to nothing (BIRD and FRR
    ///   behaviour, caught live by `tests/interop/redistribute_bird.sh`).
    /// * `B` (ABR) — the router is attached to more than one area
    ///   (§12.4.1 / BIRD `oa_arearange` posture).
    /// * `V` — the router is an endpoint of a virtual link whose
    ///   transit area is `area` (§15: the V-bit rides the transit
    ///   area's Router-LSA).
    ///
    /// The daemon re-originate path consults this on every
    /// Router-LSA; embedders doing their own origination should too.
    pub fn ospf_router_lsa_flags(&self, area: u32) -> lr_ospf::origination::RouterLsaFlags {
        let v2_areas = self
            .ospf_areas
            .values()
            .filter(|a| a.protocol == Protocol::Ospfv2)
            .count();
        lr_ospf::origination::RouterLsaFlags {
            virtual_link: self.ospf_vlinks.keys().any(|&(ta, _)| ta == area),
            asbr: !self.ospf_externals.is_empty(),
            border: v2_areas > 1,
        }
    }

    /// True while at least one AS-external redistribution intent is
    /// recorded (the `E`-bit condition of
    /// [`Self::ospf_router_lsa_flags`]) — lets the daemon notice the
    /// ASBR status flip and re-originate its Router-LSAs immediately.
    pub fn ospf_is_asbr(&self) -> bool {
        !self.ospf_externals.is_empty() || !self.ospf_v3_externals.is_empty()
    }

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
                        topology_version: 0,
                    });
                    // Virtual links are point-to-point by definition
                    // (RFC 2328 §10.4) — no DR relationship applies.
                    let runtime = OspfRuntime::new(
                        router_id,
                        0,
                        false,
                        1500,
                        crate::session::OspfNetworkType::PointToPoint,
                        None,
                        None,
                    );
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

#[cfg(test)]
mod collision_tests;
#[cfg(test)]
mod tests;
