//! The LDP engine: discovery + sessions + label bindings in one unit.
//!
//! [`LdpEngine`] is the embedder-facing glue, engine-shaped like
//! `lr-bfd`'s session: the library performs no I/O, the embedder moves
//! bytes and owns the sockets.
//!
//! ## Flow
//!
//! 1. Construct the engine with the local transport address and label
//!    space. The embedder listens on TCP (passive role) and a UDP
//!    socket.
//! 2. Feed received UDP datagrams to [`feed_udp`](LdpEngine::feed_udp)
//!    and drive [`tick`](LdpEngine::tick). Hellos build adjacencies;
//!    when an adjacency exists without a session the §2.5.2 role
//!    decision runs: the active side gets an
//!    [`EngineEvent::EstablishTransport`] and must call
//!    [`on_connected`](LdpEngine::on_connected) once its TCP connect
//!    succeeds; the passive side calls
//!    [`on_accepted`](LdpEngine::on_accepted) for each accepted
//!    connection.
//! 3. Feed TCP stream bytes to [`feed_tcp`](LdpEngine::feed_tcp). The
//!    engine buffers per connection, frames PDUs, drives the §2.5.4
//!    session FSM and answers label-message bookkeeping (learning
//!    mappings into the LIB, replying Release to Withdraw, answering
//!    Label Requests from the advertised half).
//! 4. Drain [`take_events`](LdpEngine::take_events),
//!    [`drain_udp`](LdpEngine::drain_udp) and
//!    [`drain_tcp_all`](LdpEngine::drain_tcp_all) after every call and
//!    transmit what comes out.

use crate::discovery::{
    DiscoveryEvent, DiscoveryKind, HelloAdjacency, LdpDiscovery, LdpDiscoveryConfig, OutgoingHello,
};
use crate::mapping::{FecKey, LabelMappingStore};
use crate::message::{
    LabelMappingMsg, LabelReleaseMsg, LabelWithdrawMsg, LdpCodec, LdpMessage, LdpPdu,
    NotificationMsg, RawMessage,
};
use crate::pdu::{AdvertisementMode, LdpId, MessageType, LDP_VERSION};
use crate::session::{
    role_for, SessionConfig, SessionDownReason, SessionEvent, SessionRole, SessionState,
};
use crate::tlv::{AddressList, GenericLabel, Status, StatusCode, TransportPreference};
use crate::transit::PeerBinding;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use lr_core::addr::{IpAddr, Prefix};
use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::time::Instant;

/// Engine configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdpEngineConfig {
    /// The local label space (platform-wide spaces use label space 0).
    pub local_id: LdpId,
    /// The IPv4 transport address advertised in IPv4 Hellos and used
    /// for the §2.5.2 role decision on IPv4 adjacencies.
    pub transport_addr: IpAddr,
    /// The IPv6 transport address advertised in IPv6 Hellos (RFC
    /// 7552). `None` = single-stack IPv4 speaker.
    pub transport_addr_v6: Option<IpAddr>,
    /// The §6.1.1 transport-connection preference for dual-stack
    /// peers (the RFC default is LDPoIPv6).
    pub prefer_ipv6: bool,
    /// Proposed KeepAlive Time in seconds (§3.5.3).
    pub keepalive_time: u16,
    /// Proposed Max PDU Length.
    pub max_pdu_len: u16,
    /// Proposed advertisement discipline.
    pub advertisement: AdvertisementMode,
    /// Targeted-discovery peers (extended discovery).
    pub targeted_peers: Vec<IpAddr>,
    /// Whether targeted Hellos from others are accepted.
    pub accept_targeted: bool,
    /// Local interface addresses advertised in the Address message.
    pub interface_addresses: Vec<IpAddr>,
    /// Proposed Link Hello hold time.
    pub link_hello_hold: u16,
    /// Proposed Targeted Hello hold time.
    pub targeted_hello_hold: u16,
    /// RFC 5036 §2.8: Loop Detection is a configurable option. When
    /// on, the Init proposes the D bit with `path_vector_limit` as
    /// PVLim, and received Label Mapping / Label Request attributes
    /// are checked per §3.4.4.1 / A.2.6 (the local configuration
    /// governs enforcement — the D bit is not negotiated).
    pub loop_detection: bool,
    /// RFC 5036 §2.8: the configured maximum Hop Count. A received
    /// Hop Count TLV above it behaves like a loop (0 = unknown, never
    /// enforced). Only meaningful with `loop_detection` on.
    pub hop_count_limit: u8,
    /// RFC 5036 §2.8: the maximum allowable Path Vector length. A
    /// received Path Vector at or above its own LSR Id or exceeding
    /// this length behaves like a loop. Only meaningful with
    /// `loop_detection` on.
    pub path_vector_limit: u8,
    /// Transit-LSR label allocation (RFC 5036 §3.5.7.1.1, independent
    /// control): when on, the engine allocates one local label per FEC
    /// learned from peers, re-advertises it upstream to every
    /// operational peer, and surfaces the resulting swap state as
    /// [`EngineEvent::TransitSwapChanged`] / [`EngineEvent::TransitSwapRemoved`]
    /// so the embedder can mirror the transit LSP into a dataplane.
    /// FECs the embedder already advertises (local bindings) are
    /// egress FECs and never transit-allocated.
    pub transit_allocation: bool,
    /// Lower bound of the transit label range (§3.5.7.1.1 platform
    /// label space). RFC 3032 §1.2: 16..=1048575.
    pub label_min: u32,
    /// Upper bound of the transit label range.
    pub label_max: u32,
    /// Label values already promised to embedder-configured bindings;
    /// the transit allocator never hands them out.
    pub reserved_labels: Vec<u32>,
    /// RFC 3478 graceful restart. When on, the Initialization message
    /// carries the FT Session TLV (§2) and a peer's bindings are
    /// retained across an unexpected session failure (§3.3) instead of
    /// being purged: they are marked stale, kept for the lesser of the
    /// peer's advertised FT Reconnect Timeout and
    /// [`Self::gr_neighbor_liveness_ms`], and either refreshed (the
    /// peer came back within the window and preserved its forwarding
    /// state) or deleted (window expired, or the peer came back with a
    /// zero Recovery Time).
    pub graceful_restart: bool,
    /// Advertised FT Reconnect Timeout in milliseconds (§2): how long
    /// a peer should keep the forwarding state for OUR LSPs when the
    /// session with us fails. 0 = don't bother waiting (we still
    /// support the §3.3 procedures for them).
    pub gr_reconnect_ms: u32,
    /// Advertised Recovery Time in milliseconds (§2). 0 = honest
    /// default: this speaker does not preserve MPLS forwarding state
    /// across its own restart (the daemon deletes the kernel mirror on
    /// shutdown), so peers delete their stale bindings for us on
    /// reconnection and relearn from our re-advertisements.
    pub gr_recovery_ms: u32,
    /// Local Neighbor Liveness Timer in milliseconds (§3.3): the cap
    /// on how long stale bindings of a failed peer are kept, no matter
    /// what the peer advertised.
    pub gr_neighbor_liveness_ms: u64,
    /// Local Maximum Recovery Time in milliseconds (§3.3): the cap on
    /// the recovery window of a reconnected peer.
    pub gr_max_recovery_ms: u64,
}

impl LdpEngineConfig {
    /// A config with the RFC defaults for tests and simple embedders.
    pub fn new(local_id: LdpId, transport_addr: IpAddr) -> Self {
        Self {
            local_id,
            transport_addr,
            transport_addr_v6: None,
            prefer_ipv6: true,
            keepalive_time: crate::pdu::DEFAULT_KEEPALIVE_TIME,
            max_pdu_len: crate::pdu::DEFAULT_MAX_PDU_LEN,
            advertisement: AdvertisementMode::DownstreamUnsolicited,
            targeted_peers: Vec::new(),
            accept_targeted: true,
            interface_addresses: Vec::new(),
            link_hello_hold: crate::pdu::DEFAULT_LINK_HELLO_HOLD,
            targeted_hello_hold: crate::pdu::DEFAULT_TARGETED_HELLO_HOLD,
            loop_detection: false,
            hop_count_limit: 32,
            path_vector_limit: 32,
            transit_allocation: false,
            label_min: 16,
            label_max: 1_048_575,
            reserved_labels: Vec::new(),
            graceful_restart: false,
            gr_reconnect_ms: 15_000,
            gr_recovery_ms: 0,
            gr_neighbor_liveness_ms: 15_000,
            gr_max_recovery_ms: 120_000,
        }
    }
}

/// Events the engine surfaces to the embedder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    AdjacencyUp(HelloAdjacency),
    AdjacencyDown {
        peer_id: LdpId,
        kind: DiscoveryKind,
        source: IpAddr,
    },
    TargetedHelloRequested {
        source: IpAddr,
        peer_id: LdpId,
    },
    /// A Hello was discarded (RFC 7552 §6.1.1 checks) — for logging.
    HelloDiscarded {
        peer_id: LdpId,
        source: IpAddr,
        reason: &'static str,
    },
    /// RFC 5036 §2.8: a received Label Mapping or Label Request
    /// triggered the §3.4.4.1/A.2.6 loop check (Hop Count over the
    /// limit, or a Path Vector containing our LSR Id / over the
    /// limit). The offending message was dropped and Loop Detected
    /// was signaled to the source; a looping mapping is not installed
    /// (and an existing one for the FEC is released).
    LoopDetected {
        peer_id: LdpId,
        prefix: Prefix,
        reason: &'static str,
    },
    /// Open a TCP connection to the peer's transport address (port per
    /// the deployment; 646 per RFC 5036 §3.10.1). Call `on_connected`
    /// when established.
    EstablishTransport {
        peer_id: LdpId,
        transport_addr: IpAddr,
    },
    SessionUp {
        peer_id: LdpId,
        conn: u64,
        params: crate::session::NegotiatedParams,
    },
    SessionDown {
        peer_id: LdpId,
        reason: SessionDownReason,
        /// RFC 3478 §3.3: the bindings learned from this peer were
        /// retained (marked stale) because the failure was unexpected
        /// and the peer advertised graceful restart. The embedder must
        /// keep the dataplane state for this peer's LSPs; they are
        /// either refreshed when the session recovers or withdrawn via
        /// a later `MappingWithdrawn` when the stale window expires.
        graceful: bool,
    },
    /// The embedder must close this connection.
    CloseConnection(u64),
    /// A label binding was learned from a peer.
    MappingLearned {
        peer_id: LdpId,
        prefix: Prefix,
        label: GenericLabel,
    },
    /// A peer withdrew bindings.
    MappingWithdrawn {
        peer_id: LdpId,
        prefixes: Vec<Prefix>,
    },
    /// A peer released one of our advertised bindings.
    MappingReleased {
        peer_id: LdpId,
        prefix: Prefix,
    },
    AddressReceived {
        peer_id: LdpId,
        addresses: AddressList,
    },
    NotificationReceived {
        peer_id: LdpId,
        status: Status,
    },
    /// A message the engine passes through for logging (U=1 unknowns).
    UnknownMessage {
        peer_id: LdpId,
        message: RawMessage,
    },
    /// Transit allocation (§3.5.7.1.1): the engine allocated (or
    /// refreshed) the local label for a FEC learned from peers and
    /// re-advertised it upstream. `in_label` is the locally allocated
    /// label, `next_hop` the current next hop's transport address and
    /// `out_label` that peer's advertised label. The embedder mirrors
    /// the swap into the dataplane when one is attached.
    TransitSwapChanged {
        prefix: Prefix,
        in_label: GenericLabel,
        next_hop: IpAddr,
        out_label: GenericLabel,
    },
    /// Transit allocation: the last peer advertising the FEC went
    /// away — the upstream advertisement was withdrawn (Label
    /// Withdraw sent) and the local label released. The embedder must
    /// remove the swap (and any ingress state for the FEC).
    TransitSwapRemoved {
        prefix: Prefix,
        in_label: GenericLabel,
    },
    /// Transit allocation: the configured label range could not serve
    /// a new transit FEC; the binding was kept but no LSP is set up
    /// for it.
    TransitLabelExhausted {
        prefix: Prefix,
    },
}

/// Per-FEC transit state: the downstream bindings as received from
/// every peer plus the selected next hop.
///
/// Next-hop selection without an IGP view: the **first** peer that
/// advertised the FEC wins — bindings propagate outward from the
/// egress, so the first binding a transit LSR sees is causally the one
/// closest to the egress along the live LSP (an upstream
/// re-advertisement always arrives later).
///
/// When that peer's binding goes away, the fallback considers only
/// **non-reflected** bindings: peers whose mapping arrived before the
/// local label was allocated. A binding that arrived *after* our own
/// allocation is a reflection of our own advertisement (we taught it
/// to that peer and it echoed its allocation back) — falling back to
/// it would point the LSP upstream and loop the mapping exchange. If
/// no non-reflected binding remains, the transit LSP is torn down
/// (label released, upstream withdrawn, reflected bindings released).
#[derive(Debug, Default)]
struct TransitFec {
    bindings: BTreeMap<LdpId, PeerBinding>,
    nh: Option<LdpId>,
    /// Engine receive sequence at which the local label was allocated.
    allocated_seq: Option<u64>,
}

/// RFC 3478 §3.3: bindings retained for a peer whose session failed
/// unexpectedly. The FECs remain in the LIB (and in the transit state)
/// so the dataplane keeps forwarding; this entry only carries the
/// bookkeeping: which FECs are stale and when to give up waiting.
#[derive(Debug)]
struct GrStaleState {
    fecs: BTreeSet<FecKey>,
    deadline: Instant,
}

/// RFC 3478 §3.3: a recovered session whose peer preserved its
/// forwarding state. Stale FECs are un-marked as their mappings
/// re-arrive; the leftovers are deleted at the deadline.
#[derive(Debug)]
struct GrRecoveryState {
    fecs: BTreeSet<FecKey>,
    deadline: Instant,
}

/// A session plus the connection it rides on, with the RFC 7552
/// context needed for per-family behavior: which address family the
/// transport rides on and whether the peer advertised the Dual-Stack
/// capability (a peer without it is a legacy single-stack LSR per
/// §7 — IPv6 bindings must not be sent to it).
struct LdpSessionState {
    session: crate::session::LdpSession,
    conn: u64,
    /// The session's transport rides on IPv6 (else IPv4).
    af_v6: bool,
    /// The peer advertised the RFC 7552 §6.1.1 Dual-Stack capability
    /// in its Hellos.
    peer_dual_stack: bool,
}

/// One LDP speaker engine.
pub struct LdpEngine {
    cfg: LdpEngineConfig,
    discovery: LdpDiscovery,
    sessions: BTreeMap<LdpId, LdpSessionState>,
    /// Passive-role connections that have not decoded their first PDU
    /// yet (the peer is unknown until the Initialization arrives,
    /// §2.5.3), remembering which address family the accepted socket
    /// rides on (RFC 7552 §7.1 address-distribution rules).
    awaiting_init: BTreeMap<u64, (crate::session::LdpSession, bool)>,
    /// Active-role establishments awaiting a successful connect.
    pending_connect: Vec<LdpId>,
    /// Peers found noncompliant with RFC 7552 §6.1.1 (both address
    /// families of Hellos, no Dual-Stack capability): no session is
    /// ever established with them, and the verdict is reported once.
    noncompliant_peers: Vec<LdpId>,
    lib: LabelMappingStore,
    /// Transit-LSR downstream state (RFC 5036 §3.5.7.1.1): FEC → the
    /// per-peer bindings as received plus the selected next hop. The
    /// engine allocates one local label per FEC with at least one
    /// downstream binding and re-advertises it upstream. Kept even when
    /// `transit_allocation` is off (then always empty — the hooks gate
    /// on the flag).
    transit: BTreeMap<Prefix, TransitFec>,
    /// The transit label allocator (platform-wide independent-control
    /// label space).
    transit_allocator: crate::transit::TransitAllocator,
    /// Per-connection TCP input accumulation.
    in_bufs: BTreeMap<u64, Vec<u8>>,
    /// Per-connection TCP output.
    out_bufs: BTreeMap<u64, Vec<u8>>,
    /// Scratch buffer reused to encode outgoing PDUs (grown on demand).
    enc_scratch: Vec<u8>,
    /// Monotonic receive-order counter for transit bookkeeping (see
    /// `TransitFec`).
    transit_seq: u64,
    /// RFC 3478 §3.3 stale bindings per peer whose session failed
    /// unexpectedly: the FECs stay in the LIB (and the transit state
    /// stays) until the reconnect window expires or the session
    /// recovers.
    gr_stale: BTreeMap<LdpId, GrStaleState>,
    /// RFC 3478 §3.3 recovery: the peer's session was re-established
    /// within the reconnect window and it preserved its forwarding
    /// state. The stale FECs are refreshed by the peer's
    /// re-advertisements; whatever is still stale when the recovery
    /// window expires is deleted.
    gr_recovering: BTreeMap<LdpId, GrRecoveryState>,
    out_udp: Vec<(IpAddr, Vec<u8>)>,
    events: VecDeque<EngineEvent>,
    codec: LdpCodec,
    next_message_id: u32,
}

impl LdpEngine {
    pub fn new(cfg: LdpEngineConfig) -> Self {
        let discovery = LdpDiscovery::new(LdpDiscoveryConfig {
            local_id: cfg.local_id,
            transport_addr: cfg.transport_addr,
            transport_addr_v6: cfg.transport_addr_v6,
            prefer_ipv6: cfg.prefer_ipv6,
            link_hello_hold: cfg.link_hello_hold,
            targeted_hello_hold: cfg.targeted_hello_hold,
            targeted_peers: cfg.targeted_peers.clone(),
            accept_targeted: cfg.accept_targeted,
        });
        let transit_allocator = crate::transit::TransitAllocator::new(
            cfg.label_min,
            cfg.label_max,
            &cfg.reserved_labels,
        );
        Self {
            cfg,
            discovery,
            sessions: BTreeMap::new(),
            awaiting_init: BTreeMap::new(),
            pending_connect: Vec::new(),
            noncompliant_peers: Vec::new(),
            lib: LabelMappingStore::new(),
            transit: BTreeMap::new(),
            transit_allocator,
            in_bufs: BTreeMap::new(),
            out_bufs: BTreeMap::new(),
            enc_scratch: Vec::new(),
            transit_seq: 0,
            gr_stale: BTreeMap::new(),
            gr_recovering: BTreeMap::new(),
            out_udp: Vec::new(),
            events: VecDeque::new(),
            codec: LdpCodec,
            next_message_id: 1,
        }
    }

    pub fn config(&self) -> &LdpEngineConfig {
        &self.cfg
    }

    /// The label information base (read-only view).
    pub fn lib(&self) -> &LabelMappingStore {
        &self.lib
    }

    /// The locally allocated transit label for a FEC, when the engine
    /// allocated one (§3.5.7.1.1 transit allocation).
    pub fn transit_label_of(&self, prefix: &Prefix) -> Option<GenericLabel> {
        self.transit_allocator.label_of(prefix)
    }

    /// Number of FECs currently holding a transit label.
    pub fn transit_label_count(&self) -> usize {
        self.transit_allocator.allocated_count()
    }

    /// The current transit next hop for a FEC and its advertised
    /// label, when transit state exists for it.
    pub fn transit_next_hop(&self, prefix: &Prefix) -> Option<(LdpId, GenericLabel)> {
        let fec = self.transit.get(prefix)?;
        let nh = fec.nh?;
        Some((nh, fec.bindings.get(&nh)?.label))
    }

    /// The live adjacencies.
    pub fn adjacencies(&self) -> &[HelloAdjacency] {
        self.discovery.adjacencies()
    }

    pub fn session_state(&self, peer: LdpId) -> Option<SessionState> {
        self.sessions.get(&peer).map(|s| s.session.state())
    }

    // ------------------------------------------------------------------
    // Input
    // ------------------------------------------------------------------

    /// Feed a received UDP datagram (Hellos only on the LDP UDP port).
    pub fn feed_udp(&mut self, now: Instant, from: IpAddr, datagram: &[u8]) {
        let mut read = ReadBuf::new(datagram);
        // A datagram carries at most one PDU; decode and ignore the rest.
        if let Ok(Some(pdu)) = self.codec.decode(&mut read) {
            // Self-Hello protection: a datagram carrying our own LDP
            // Identifier is our own Hello echoed back (multicast loop,
            // a miswired shared host, …). An adjacency with our own
            // label space is meaningless — drop it before discovery
            // state is created.
            if pdu.sender == self.cfg.local_id {
                return;
            }
            for msg in &pdu.messages {
                if let LdpMessage::Hello(hello) = msg {
                    let events = self.discovery.feed_hello(now, &pdu, hello, from);
                    self.absorb_discovery_events(events, now);
                }
            }
            // A new adjacency may enable session establishment.
            self.establish_sessions();
        }
    }

    fn absorb_discovery_events(&mut self, events: Vec<DiscoveryEvent>, now: Instant) {
        for ev in events {
            match ev {
                DiscoveryEvent::AdjacencyUp(a) => {
                    self.events.push_back(EngineEvent::AdjacencyUp(a));
                }
                DiscoveryEvent::AdjacencyDown {
                    peer_id,
                    kind,
                    source,
                } => {
                    self.events.push_back(EngineEvent::AdjacencyDown {
                        peer_id,
                        kind,
                        source,
                    });
                    // Losing the last adjacency for a label space tears
                    // the session down (§3.5.2.1 "Maintaining Hello
                    // Adjacencies").
                    if self.discovery.adjacency_for_peer(peer_id).is_none() {
                        self.noncompliant_peers.retain(|p| *p != peer_id);
                        if let Some(st) = self.sessions.remove(&peer_id) {
                            let conn = st.conn;
                            let mut session = st.session;
                            let max_pdu_len = Self::effective_max_pdu(&session);
                            let down_events = session.shutdown(now);
                            let outgoing = session.drain_outgoing();
                            self.absorb_session_events(now, peer_id, conn, down_events);
                            self.encode_outgoing(conn, outgoing, max_pdu_len);
                            self.lib.unlearn_peer(peer_id);
                        }
                        self.pending_connect.retain(|p| *p != peer_id);
                    }
                }
                DiscoveryEvent::TargetedHelloRequested { source, peer_id } => {
                    self.events
                        .push_back(EngineEvent::TargetedHelloRequested { source, peer_id });
                }
                DiscoveryEvent::HelloDiscarded {
                    peer_id,
                    source,
                    reason,
                } => {
                    // RFC 7552 §6.1.1 rule 1: a preference mismatch on
                    // a peer with an established session sends a fatal
                    // Transport Connection Mismatch notification and
                    // resets the session.
                    if reason == "dual-stack transport preference mismatch" {
                        if let Some(st) = self.sessions.remove(&peer_id) {
                            let conn = st.conn;
                            let mut session = st.session;
                            let max_pdu_len = Self::effective_max_pdu(&session);
                            session.enqueue_notification(Status {
                                code: StatusCode::TRANSPORT_CONNECTION_MISMATCH,
                                message_id: 0,
                                message_type: 0,
                            });
                            let down_events = session.shutdown(now);
                            let outgoing = session.drain_outgoing();
                            self.absorb_session_events(now, peer_id, conn, down_events);
                            self.encode_outgoing(conn, outgoing, max_pdu_len);
                            self.lib.unlearn_peer(peer_id);
                            self.events.push_back(EngineEvent::CloseConnection(conn));
                        }
                    }
                    self.events.push_back(EngineEvent::HelloDiscarded {
                        peer_id,
                        source,
                        reason,
                    });
                }
            }
        }
    }

    /// Run the §2.5.2 role decision for adjacencies without sessions.
    /// With RFC 7552, a dual-stack peer heard in both address families
    /// gets exactly one session (§6.1 rule 7): the transport family is
    /// the §6.1.1 preference (which both sides must agree on), the
    /// §2.5.2 comparison runs within that family, and a peer heard in
    /// both families without the Dual-Stack capability is noncompliant
    /// (§6.1.1 rule 3c) and gets no session at all.
    fn establish_sessions(&mut self) {
        // One decision per peer, not per adjacency.
        let mut peers: Vec<LdpId> = Vec::new();
        for adj in self.discovery.adjacencies() {
            if !peers.contains(&adj.peer_id) {
                peers.push(adj.peer_id);
            }
        }
        for peer_id in peers {
            if self.sessions.contains_key(&peer_id)
                || self.pending_connect.contains(&peer_id)
                || self.noncompliant_peers.contains(&peer_id)
            {
                continue;
            }
            let adjacencies: Vec<HelloAdjacency> = self
                .discovery
                .adjacencies()
                .iter()
                .filter(|a| a.peer_id == peer_id)
                .cloned()
                .collect();
            let has_v4 = adjacencies
                .iter()
                .any(|a| matches!(a.source, IpAddr::V4(_)));
            let has_v6 = adjacencies
                .iter()
                .any(|a| matches!(a.source, IpAddr::V6(_)));
            // §6.1.1: the capability must be uniform (§2.5.5 matching
            // Hellos: either all carry it with the same TR or none do).
            let caps: Vec<Option<TransportPreference>> =
                adjacencies.iter().map(|a| a.dual_stack).collect();
            if caps.iter().any(|c| c.is_some()) && caps.iter().any(|c| c.is_none()) {
                self.events.push_back(EngineEvent::HelloDiscarded {
                    peer_id,
                    source: adjacencies[0].source,
                    reason: "inconsistent Dual-Stack capability across Hellos",
                });
                continue;
            }
            // The transport family for the §2.5.2 decision.
            let prefer_v6 = self.cfg.prefer_ipv6;
            let local_dual = self.cfg.transport_addr_v6.is_some();
            let use_v6 = if has_v4 && has_v6 {
                if local_dual {
                    if caps[0].is_none() {
                        // §6.1.1 rule 3c: both families, no
                        // capability — noncompliant neighbor.
                        self.noncompliant_peers.push(peer_id);
                        self.events.push_back(EngineEvent::HelloDiscarded {
                            peer_id,
                            source: adjacencies[0].source,
                            reason: "dual-stack noncompliance (both AFs, no capability)",
                        });
                        continue;
                    }
                    prefer_v6
                } else {
                    // Single-stack local speaker: only its own family
                    // is enabled (the embedder filters Hellos).
                    self.cfg.transport_addr_v6.is_some() && prefer_v6
                }
            } else {
                has_v6
            };
            let adj = adjacencies
                .iter()
                .find(|a| matches!(a.source, IpAddr::V6(_)) == use_v6)
                .cloned();
            let Some(adj) = adj else {
                continue;
            };
            // The role comparison runs within the chosen family: the
            // local transport address of that family vs the peer's
            // advertised one (RFC 7552 §6.1.1 rule 2a/2b). A
            // single-stack IPv6 speaker keeps its address in the
            // primary field.
            let local = if use_v6 {
                match self.cfg.transport_addr_v6 {
                    Some(v6) => Some(v6),
                    None => match self.cfg.transport_addr {
                        IpAddr::V6(_) => Some(self.cfg.transport_addr),
                        IpAddr::V4(_) => None,
                    },
                }
            } else {
                match self.cfg.transport_addr {
                    IpAddr::V4(_) => Some(self.cfg.transport_addr),
                    IpAddr::V6(_) => None,
                }
            };
            let Some(local) = local else { continue };
            match role_for(&local, &adj.transport_addr) {
                Some(SessionRole::Active) => {
                    self.pending_connect.push(peer_id);
                    self.events.push_back(EngineEvent::EstablishTransport {
                        peer_id,
                        transport_addr: adj.transport_addr,
                    });
                }
                Some(SessionRole::Passive) => {
                    // Wait for the peer to connect; on_accepted handles
                    // the rest.
                }
                None => {}
            }
        }
    }

    /// An active-role TCP connection succeeded.
    pub fn on_connected(&mut self, now: Instant, conn: u64, peer_id: LdpId) {
        self.pending_connect.retain(|p| *p != peer_id);
        if self.sessions.contains_key(&peer_id) {
            // Already have a session (collision); the embedder should
            // close this extra connection.
            self.events.push_back(EngineEvent::CloseConnection(conn));
            return;
        }
        // The chosen adjacency's family (the establish_sessions
        // decision) tells which transport the connection rides on.
        let (af_v6, peer_dual_stack) = self
            .discovery
            .adjacency_for_peer(peer_id)
            .map(|a| (matches!(a.source, IpAddr::V6(_)), a.dual_stack.is_some()))
            .unwrap_or((false, false));
        let session = crate::session::LdpSession::new(SessionConfig {
            local_id: self.cfg.local_id,
            role: SessionRole::Active,
            peer: Some(peer_id),
            keepalive_time: self.cfg.keepalive_time,
            max_pdu_len: self.cfg.max_pdu_len,
            advertisement: self.cfg.advertisement,
            supports_downstream_unsolicited: true,
            supports_downstream_on_demand: true,
            loop_detection: self.cfg.loop_detection,
            path_vector_limit: self.cfg.path_vector_limit,
            graceful_restart: self.gr_advise(),
        });
        self.register_session(peer_id, conn, session, af_v6, peer_dual_stack, now);
    }

    /// An active-role TCP connection attempt failed. The peer returns
    /// to "awaiting transport": the next Hello re-runs the §2.5.2 role
    /// decision and re-emits [`EngineEvent::EstablishTransport`], so an
    /// embedder that surfaces connect errors through this method gets
    /// natural reconnect-on-hello behavior instead of a stuck peer.
    pub fn on_connect_failed(&mut self, peer_id: LdpId) {
        self.pending_connect.retain(|p| *p != peer_id);
    }

    /// A passive-role connection was accepted. The peer is unknown
    /// until its Initialization arrives (§2.5.3); `local_addr` is the
    /// local endpoint of the accepted socket and fixes the session's
    /// address family for the RFC 7552 §7.1 rules.
    pub fn on_accepted(&mut self, conn: u64, local_addr: IpAddr) {
        let af_v6 = matches!(local_addr, IpAddr::V6(_));
        let session = crate::session::LdpSession::new(SessionConfig {
            local_id: self.cfg.local_id,
            role: SessionRole::Passive,
            peer: None,
            keepalive_time: self.cfg.keepalive_time,
            max_pdu_len: self.cfg.max_pdu_len,
            advertisement: self.cfg.advertisement,
            supports_downstream_unsolicited: true,
            supports_downstream_on_demand: true,
            loop_detection: self.cfg.loop_detection,
            path_vector_limit: self.cfg.path_vector_limit,
            graceful_restart: self.gr_advise(),
        });
        self.awaiting_init.insert(conn, (session, af_v6));
        self.in_bufs.entry(conn).or_default();
        self.out_bufs.entry(conn).or_default();
    }

    /// Feed TCP stream bytes received on a connection.
    pub fn feed_tcp(&mut self, now: Instant, conn: u64, bytes: &[u8]) {
        {
            let buf = self.in_bufs.entry(conn).or_default();
            buf.extend_from_slice(bytes);
        }
        self.pump_connection(now, conn);
    }

    /// The embedder observed a connection close (peer FIN/RST).
    pub fn on_closed(&mut self, now: Instant, conn: u64) {
        self.in_bufs.remove(&conn);
        self.out_bufs.remove(&conn);
        let peer = self
            .sessions
            .iter()
            .find(|(_, st)| st.conn == conn)
            .map(|(k, _)| *k);
        if let Some(peer_id) = peer {
            // Route the failure through the shared SessionDown path so
            // RFC 3478 retention applies here too.
            let mut events = Vec::new();
            if let Some(st) = self.sessions.get_mut(&peer_id) {
                st.session.transport_closed(&mut events);
            }
            let down = self.absorb_session_events(now, peer_id, conn, events);
            if down {
                if let Some(mut st) = self.sessions.remove(&peer_id) {
                    let max_pdu_len = Self::effective_max_pdu(&st.session);
                    self.encode_outgoing(conn, st.session.drain_outgoing(), max_pdu_len);
                }
            }
            return;
        }
        // Awaiting-init connection: no session was established.
        self.awaiting_init.remove(&conn);
    }

    fn pump_connection(&mut self, now: Instant, conn: u64) {
        let mut buf = self.in_bufs.remove(&conn).unwrap_or_default();
        loop {
            if buf.is_empty() {
                break;
            }
            let mut read = ReadBuf::new(&buf);
            match self.codec.decode(&mut read) {
                Ok(Some(pdu)) => {
                    let consumed = read.position();
                    buf.drain(..consumed);
                    // The PDU length field excludes the 4-octet
                    // Version+Length header (§3.2).
                    self.handle_session_pdu(now, conn, pdu, consumed - 4);
                }
                Ok(None) => break,
                Err(_) => {
                    // Framing error: drop the connection.
                    self.events.push_back(EngineEvent::CloseConnection(conn));
                    self.on_closed(now, conn);
                    return;
                }
            }
        }
        self.in_bufs.insert(conn, buf);
    }

    fn handle_session_pdu(&mut self, now: Instant, conn: u64, pdu: LdpPdu, pdu_len: usize) {
        // Passive sessions waiting for their first PDU: bind the peer.
        if let Some((session, af_v6)) = self.awaiting_init.remove(&conn) {
            // §2.5.3: the passive LSR matches the sender's label space
            // against a Hello adjacency; without one, reject.
            if self.discovery.adjacency_for_peer(pdu.sender).is_none() {
                let reject = LdpPdu {
                    version: 1,
                    sender: self.cfg.local_id,
                    messages: vec![LdpMessage::Notification(NotificationMsg {
                        message_id: self.alloc_id(),
                        status: Status {
                            code: StatusCode::SESSION_REJECTED_NO_HELLO,
                            message_id: 0,
                            message_type: MessageType::Initialization as u16,
                        },
                        unknown_tlvs: Vec::new(),
                    })],
                };
                let bytes = self.encode_pdu(&reject);
                self.out_bufs
                    .entry(conn)
                    .or_default()
                    .extend_from_slice(&bytes);
                self.events.push_back(EngineEvent::CloseConnection(conn));
                return;
            }
            let peer = pdu.sender;
            if self.sessions.contains_key(&peer) {
                // Session collision: refuse the duplicate connection.
                self.events.push_back(EngineEvent::CloseConnection(conn));
                return;
            }
            let peer_dual_stack = self
                .discovery
                .adjacency_for_peer(peer)
                .map(|a| a.dual_stack.is_some())
                .unwrap_or(false);
            self.register_session(peer, conn, session, af_v6, peer_dual_stack, now);
        }

        let peer = pdu.sender;
        // RFC 5036 §3.5.3: a PDU longer than the negotiated Max PDU
        // Length is a fatal error — answer with a Bad PDU Length
        // Notification and take the session down (cf. FRR's
        // S_BAD_PDU_LEN path). Before negotiation the 4096 default
        // applies.
        let pdu_max = self
            .sessions
            .get(&peer)
            .map(|st| Self::effective_max_pdu(&st.session) as usize);
        if let Some(max) = pdu_max {
            if pdu_len > max {
                let outgoing = match self.sessions.get_mut(&peer) {
                    Some(st) => {
                        st.session.enqueue_notification(Status {
                            code: StatusCode::BAD_PDU_LENGTH,
                            message_id: 0,
                            message_type: 0,
                        });
                        st.session.drain_outgoing()
                    }
                    None => Vec::new(),
                };
                self.encode_outgoing(conn, outgoing, max as u16);
                self.sessions.remove(&peer);
                self.events.push_back(EngineEvent::CloseConnection(conn));
                self.events.push_back(EngineEvent::SessionDown {
                    peer_id: peer,
                    reason: SessionDownReason::ProtocolError,
                    graceful: false,
                });
                self.gr_stale.remove(&peer);
                self.gr_recovering.remove(&peer);
                self.lib.unlearn_peer(peer);
                return;
            }
        }
        if let Some(st) = self.sessions.get_mut(&peer) {
            let events = st.session.feed_pdu(&pdu, now);
            let conn = st.conn;
            let down = self.absorb_session_events(now, peer, conn, events);
            if down {
                if let Some(mut st) = self.sessions.remove(&peer) {
                    let max_pdu_len = Self::effective_max_pdu(&st.session);
                    self.encode_outgoing(conn, st.session.drain_outgoing(), max_pdu_len);
                }
            } else {
                self.flush_session(peer, conn);
            }
        }
    }

    fn register_session(
        &mut self,
        peer: LdpId,
        conn: u64,
        mut session: crate::session::LdpSession,
        af_v6: bool,
        peer_dual_stack: bool,
        now: Instant,
    ) {
        let events = session.start(now);
        self.sessions.insert(
            peer,
            LdpSessionState {
                session,
                conn,
                af_v6,
                peer_dual_stack,
            },
        );
        self.in_bufs.entry(conn).or_default();
        self.out_bufs.entry(conn).or_default();
        let down = self.absorb_session_events(now, peer, conn, events);
        if down {
            if let Some(mut st) = self.sessions.remove(&peer) {
                let max_pdu_len = Self::effective_max_pdu(&st.session);
                self.encode_outgoing(conn, st.session.drain_outgoing(), max_pdu_len);
            }
        } else {
            self.flush_session(peer, conn);
        }
    }

    fn absorb_session_events(
        &mut self,
        now: Instant,
        peer: LdpId,
        conn: u64,
        events: Vec<SessionEvent>,
    ) -> bool {
        let mut down = false;
        for ev in events {
            match ev {
                SessionEvent::SessionUp(params) => {
                    self.events.push_back(EngineEvent::SessionUp {
                        peer_id: peer,
                        conn,
                        params,
                    });
                    self.gr_on_session_up(now, peer, params.peer_graceful_restart);
                    // §3.5.5.1: advertise interface addresses before any
                    // Label Mapping. RFC 7552 §7.1 scopes the set per
                    // peer: with the Dual-Stack capability both
                    // families flow; without it the session carries
                    // only addresses of its own transport family (a
                    // legacy IPv4-only peer must never receive IPv6
                    // addresses).
                    if !self.cfg.interface_addresses.is_empty() {
                        let (af_v6, peer_dual_stack) = match self.sessions.get(&peer) {
                            Some(st) => (st.af_v6, st.peer_dual_stack),
                            None => (false, false),
                        };
                        let addresses: Vec<IpAddr> = self
                            .cfg
                            .interface_addresses
                            .iter()
                            .filter(|a| match a {
                                IpAddr::V6(_) => af_v6 || peer_dual_stack,
                                IpAddr::V4(_) => !af_v6 || peer_dual_stack,
                            })
                            .copied()
                            .collect();
                        if !addresses.is_empty() {
                            if let Some(st) = self.sessions.get_mut(&peer) {
                                st.session.send_address_message(AddressList { addresses });
                            }
                        }
                    }
                    // §3.5.7.1.1 (DU): after a session is established,
                    // advertise the transit bindings the peer has not
                    // seen yet. Locally configured bindings are the
                    // embedder's business (the daemon re-pushes them on
                    // SessionUp); the engine owns the transit half.
                    if self.cfg.transit_allocation && !self.transit.is_empty() {
                        let (af_v6, peer_dual_stack) = match self.sessions.get(&peer) {
                            Some(st) => (st.af_v6, st.peer_dual_stack),
                            None => (false, false),
                        };
                        let entries: Vec<(Prefix, PeerBinding)> = self
                            .transit
                            .iter()
                            .filter_map(|(prefix, fec)| {
                                let nh = fec.nh?;
                                Some((*prefix, fec.bindings.get(&nh)?.clone()))
                            })
                            .collect();
                        for (prefix, nhb) in entries {
                            // RFC 7552 §7: no IPv6 FECs to legacy peers.
                            if prefix.addr.is_ipv6() && !(af_v6 || peer_dual_stack) {
                                continue;
                            }
                            let Some(local) = self.transit_allocator.label_of(&prefix) else {
                                continue;
                            };
                            let Some((hop_count, path_vector)) =
                                self.transit_advertised_attributes(&nhb)
                            else {
                                continue; // hop count cannot be propagated
                            };
                            if let Some(st) = self.sessions.get_mut(&peer) {
                                // Inline `alloc_id`: `st` holds a mutable
                                // borrow of the session, so the counter
                                // must be bumped through disjoint field
                                // access.
                                let message_id = self.next_message_id;
                                self.next_message_id += 1;
                                st.session.send_label_mapping(LabelMappingMsg {
                                    message_id,
                                    fec: crate::tlv::Fec::prefix(prefix),
                                    label: local,
                                    hop_count,
                                    path_vector,
                                    request_message_id: None,
                                    unknown_tlvs: Vec::new(),
                                });
                            }
                        }
                    }
                }
                SessionEvent::SessionDown(reason) => {
                    down = true;
                    self.events.push_back(EngineEvent::CloseConnection(conn));
                    let peer_gr = self
                        .sessions
                        .get(&peer)
                        .and_then(|st| st.session.negotiated())
                        .and_then(|n| n.peer_graceful_restart);
                    // RFC 3478 §3.3: retain the bindings (marked
                    // stale) for an unexpected failure of a
                    // graceful-restart-capable peer. A deliberate
                    // Shutdown, a local shutdown, or a pre-operational
                    // error purges as before.
                    if self.gr_should_retain(reason, peer_gr) {
                        let fecs: BTreeSet<FecKey> =
                            self.lib.bindings_from(peer).map(|(k, _)| *k).collect();
                        let window = (peer_gr.map(|g| g.reconnect_ms as u64).unwrap_or(0))
                            .min(self.cfg.gr_neighbor_liveness_ms);
                        let deadline = Instant::from_millis(now.as_millis() + window);
                        self.gr_stale.insert(peer, GrStaleState { fecs, deadline });
                        self.gr_recovering.remove(&peer);
                        self.events.push_back(EngineEvent::SessionDown {
                            peer_id: peer,
                            reason,
                            graceful: true,
                        });
                    } else {
                        self.events.push_back(EngineEvent::SessionDown {
                            peer_id: peer,
                            reason,
                            graceful: false,
                        });
                        self.gr_stale.remove(&peer);
                        self.gr_recovering.remove(&peer);
                        self.lib.unlearn_peer(peer);
                        // Transit bookkeeping: every FEC the peer had a
                        // binding for may need a new next hop (or lose
                        // its LSP entirely, §3.5.7.1.1).
                        let prefixes: Vec<Prefix> = self.transit.keys().copied().collect();
                        for prefix in prefixes {
                            self.transit_on_unlearn(peer, prefix);
                        }
                    }
                }
                SessionEvent::NotificationReceived(status) => {
                    self.events.push_back(EngineEvent::NotificationReceived {
                        peer_id: peer,
                        status,
                    });
                }
                SessionEvent::AddressReceived(addresses) => {
                    self.events.push_back(EngineEvent::AddressReceived {
                        peer_id: peer,
                        addresses,
                    });
                }
                SessionEvent::AddressWithdrawReceived(_) => {
                    // No address database in this slice; ignored.
                }
                SessionEvent::LabelMappingReceived(m) => {
                    // RFC 5036 §3.4.5.1.2 + A.2.6: check the received
                    // attributes when Loop Detection is configured. On a
                    // loop: stop using the label, reject the mapping by
                    // releasing it with a Loop Detected Status TLV, and
                    // never install it.
                    let reason =
                        self.check_received_attributes(m.hop_count, m.path_vector.as_ref());
                    if let Some(reason) = reason {
                        for el in &m.fec.elements {
                            if let crate::tlv::FecElement::Prefix(p) = el {
                                let key = FecKey::new(*p);
                                // §3.4.5.1.2 step 3: unsplice the LSP —
                                // drop any mapping learned for this FEC.
                                if self.lib.unlearn(peer, &key).is_some() {
                                    self.transit_on_unlearn(peer, *p);
                                }
                                let release_id = self.alloc_id();
                                if let Some(st) = self.sessions.get_mut(&peer) {
                                    st.session.send_label_release(
                                        crate::message::LabelReleaseMsg {
                                            message_id: release_id,
                                            fec: crate::tlv::Fec::prefix(*p),
                                            label: Some(m.label),
                                            status: Some(crate::tlv::Status {
                                                code: StatusCode::LOOP_DETECTED,
                                                message_id: m.message_id,
                                                message_type: MessageType::LabelMapping as u16,
                                            }),
                                            unknown_tlvs: Vec::new(),
                                        },
                                    );
                                }
                                self.events.push_back(EngineEvent::LoopDetected {
                                    peer_id: peer,
                                    prefix: *p,
                                    reason,
                                });
                            }
                        }
                    } else {
                        for el in &m.fec.elements {
                            if let crate::tlv::FecElement::Prefix(p) = el {
                                let key = FecKey::new(*p);
                                if self.lib.learn(peer, key, m.label) {
                                    self.events.push_back(EngineEvent::MappingLearned {
                                        peer_id: peer,
                                        prefix: *p,
                                        label: m.label,
                                    });
                                    self.transit_on_learn(
                                        peer,
                                        *p,
                                        m.label,
                                        m.hop_count.map(|h| h.0),
                                        m.path_vector.as_ref().map(|pv| pv.0.as_slice()),
                                    );
                                }
                                // RFC 3478 §3.3 (b)/(c): a mapping
                                // received during recovery refreshes
                                // the stale entry.
                                self.gr_on_mapping_received(peer, *p);
                            }
                        }
                    }
                }
                SessionEvent::LabelRequestReceived(m) => {
                    // RFC 5036 §3.4.5.1.1 + A.2.6: a looping Label
                    // Request is answered with a Loop Detected
                    // Notification and dropped — no mapping, no
                    // propagation.
                    let reason =
                        self.check_received_attributes(m.hop_count, m.path_vector.as_ref());
                    if let Some(reason) = reason {
                        if let Some(st) = self.sessions.get_mut(&peer) {
                            st.session.enqueue_notification(crate::tlv::Status {
                                code: StatusCode::LOOP_DETECTED,
                                message_id: m.message_id,
                                message_type: MessageType::LabelRequest as u16,
                            });
                        }
                        for el in &m.fec.elements {
                            if let crate::tlv::FecElement::Prefix(p) = el {
                                self.events.push_back(EngineEvent::LoopDetected {
                                    peer_id: peer,
                                    prefix: *p,
                                    reason,
                                });
                            }
                        }
                    } else {
                        // DU-mode answer: map when we advertise the FEC,
                        // No Route otherwise (§3.5.8.1). Transit FECs
                        // answer with the locally allocated label and
                        // the §3.4.4.1 propagated hop count.
                        for el in &m.fec.elements {
                            if let crate::tlv::FecElement::Prefix(p) = el {
                                let key = FecKey::new(*p);
                                let message_id = self.alloc_id();
                                let transit = if self.cfg.transit_allocation {
                                    self.transit.get(p).and_then(|fec| {
                                        let nh = fec.nh?;
                                        let binding = fec.bindings.get(&nh)?;
                                        let (hop_count, path_vector) =
                                            self.transit_advertised_attributes(binding)?;
                                        Some((
                                            self.transit_allocator.label_of(p)?,
                                            hop_count,
                                            path_vector,
                                        ))
                                    })
                                } else {
                                    None
                                };
                                if let Some(st) = self.sessions.get_mut(&peer) {
                                    if let Some((label, hop_count, path_vector)) = transit {
                                        st.session.send_label_mapping(LabelMappingMsg {
                                            message_id,
                                            fec: crate::tlv::Fec::prefix(*p),
                                            label,
                                            hop_count,
                                            path_vector,
                                            request_message_id: Some(
                                                crate::tlv::LabelRequestMessageId(m.message_id),
                                            ),
                                            unknown_tlvs: Vec::new(),
                                        });
                                    } else if let Some(label) = self.lib.advertised_label(&key) {
                                        st.session.send_label_mapping(LabelMappingMsg {
                                            message_id,
                                            fec: crate::tlv::Fec::prefix(*p),
                                            label,
                                            hop_count: Some(crate::tlv::HopCount(1)),
                                            path_vector: None,
                                            request_message_id: Some(
                                                crate::tlv::LabelRequestMessageId(m.message_id),
                                            ),
                                            unknown_tlvs: Vec::new(),
                                        });
                                    } else {
                                        st.session.enqueue_notification(Status {
                                            code: StatusCode::NO_ROUTE,
                                            message_id: m.message_id,
                                            message_type: MessageType::LabelRequest as u16,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                SessionEvent::LabelWithdrawReceived(m) => {
                    let mut prefixes = Vec::new();
                    if m.fec.is_wildcard() {
                        match m.label {
                            Some(label) => {
                                for key in self.lib.unlearn_by_label(peer, label) {
                                    prefixes.push(key.prefix);
                                }
                            }
                            None => {
                                for key in self.lib.unlearn_all_from(peer) {
                                    prefixes.push(key.prefix);
                                }
                            }
                        }
                    } else {
                        for el in &m.fec.elements {
                            if let crate::tlv::FecElement::Prefix(p) = el {
                                if self.lib.unlearn(peer, &FecKey::new(*p)).is_some() {
                                    prefixes.push(*p);
                                }
                            }
                        }
                    }
                    // §3.5.10.1: a receiver of Label Withdraw MUST
                    // respond with Label Release.
                    let message_id = self.alloc_id();
                    if let Some(st) = self.sessions.get_mut(&peer) {
                        st.session.send_label_release(LabelReleaseMsg {
                            message_id,
                            fec: m.fec.clone(),
                            label: m.label,
                            status: None,
                            unknown_tlvs: Vec::new(),
                        });
                    }
                    if !prefixes.is_empty() {
                        self.events.push_back(EngineEvent::MappingWithdrawn {
                            peer_id: peer,
                            prefixes: prefixes.clone(),
                        });
                    }
                    // Transit bookkeeping for every withdrawn FEC.
                    for prefix in prefixes {
                        self.transit_on_unlearn(peer, prefix);
                    }
                }
                SessionEvent::LabelReleaseReceived(m) => {
                    for el in &m.fec.elements {
                        if let crate::tlv::FecElement::Prefix(p) = el {
                            self.events.push_back(EngineEvent::MappingReleased {
                                peer_id: peer,
                                prefix: *p,
                            });
                        }
                    }
                }
                SessionEvent::LabelAbortReceived(_) => {}
                SessionEvent::UnknownMessage(raw) => {
                    self.events.push_back(EngineEvent::UnknownMessage {
                        peer_id: peer,
                        message: raw,
                    });
                }
            }
        }
        down
    }

    // ------------------------------------------------------------------
    // Timers
    // ------------------------------------------------------------------

    pub fn tick(&mut self, now: Instant) {
        // RFC 3478: reconnect/recovery window expiry.
        self.gr_tick(now);
        // Discovery: adjacency expiry + hello scheduling.
        let events = self.discovery.tick(now);
        self.absorb_discovery_events(events, now);
        let hello_out = self.discovery.drain_outgoing();
        for OutgoingHello { dest, message } in hello_out {
            let pdu = LdpPdu {
                version: 1,
                sender: self.cfg.local_id,
                messages: vec![message],
            };
            let bytes = self.encode_pdu(&pdu);
            self.out_udp.push((dest, bytes));
        }
        // Sessions: keepalive timers.
        let peers: Vec<LdpId> = self.sessions.keys().copied().collect();
        for peer in peers {
            let (events, conn) = match self.sessions.get_mut(&peer) {
                Some(st) => (st.session.tick(now), st.conn),
                None => continue,
            };
            let down = self.absorb_session_events(now, peer, conn, events);
            if down {
                if let Some(mut st) = self.sessions.remove(&peer) {
                    let max_pdu_len = Self::effective_max_pdu(&st.session);
                    self.encode_outgoing(conn, st.session.drain_outgoing(), max_pdu_len);
                }
            } else {
                self.flush_session(peer, conn);
            }
        }
    }

    // ------------------------------------------------------------------
    // Local label distribution (DU, independent control)
    // ------------------------------------------------------------------

    /// Advertise a local FEC-label binding to every operational peer
    /// (downstream unsolicited, independent control).
    pub fn advertise_mapping(&mut self, prefix: Prefix, label: GenericLabel) {
        // §3.4.1.1: a prefix FEC carries no host bits on the wire (the
        // encoder drops them, every decoder zero-pads) — normalize so
        // state keyed by this FEC matches what peers send back.
        let prefix = normalize_fec(prefix);
        let key = FecKey::new(prefix);
        self.lib.advertise(key, label);
        let peers: Vec<LdpId> = self
            .sessions
            .iter()
            .filter(|(_, st)| st.session.is_operational())
            // RFC 7552 §7: an LSR MUST NOT send IPv6 bindings to a
            // legacy peer (an IPv4-transport session whose peer never
            // advertised the Dual-Stack capability).
            .filter(|(_, st)| !prefix.addr.is_ipv6() || st.af_v6 || st.peer_dual_stack)
            .map(|(k, _)| *k)
            .collect();
        for peer in peers {
            let message_id = self.alloc_id();
            if let Some(st) = self.sessions.get_mut(&peer) {
                st.session.send_label_mapping(LabelMappingMsg {
                    message_id,
                    fec: crate::tlv::Fec::prefix(prefix),
                    label,
                    hop_count: Some(crate::tlv::HopCount(1)),
                    path_vector: None,
                    request_message_id: None,
                    unknown_tlvs: Vec::new(),
                });
            }
            self.flush_session(peer, peer_conn_of(&self.sessions, peer));
        }
    }

    /// Withdraw a previously advertised binding from every peer.
    pub fn withdraw_mapping(&mut self, prefix: Prefix) {
        let prefix = normalize_fec(prefix);
        let key = FecKey::new(prefix);
        if self.lib.withdraw_advertised(&key).is_none() {
            return;
        }
        self.send_withdraw_all(prefix);
    }

    /// Label Withdraw for a FEC to every operational peer, without
    /// consulting the advertised LIB half — the transit teardown path
    /// (a transit allocation is engine state, not an embedder
    /// advertisement, so `withdraw_mapping` would early-return).
    fn withdraw_transit_mapping(&mut self, prefix: Prefix) {
        self.send_withdraw_all(normalize_fec(prefix));
    }

    /// The message flow of both withdraw flavors.
    fn send_withdraw_all(&mut self, prefix: Prefix) {
        let peers: Vec<LdpId> = self
            .sessions
            .iter()
            .filter(|(_, st)| st.session.is_operational())
            .map(|(k, _)| *k)
            .collect();
        for peer in peers {
            let message_id = self.alloc_id();
            if let Some(st) = self.sessions.get_mut(&peer) {
                st.session.send_label_withdraw(LabelWithdrawMsg {
                    message_id,
                    fec: crate::tlv::Fec::prefix(prefix),
                    label: None,
                    unknown_tlvs: Vec::new(),
                });
            }
            self.flush_session(peer, peer_conn_of(&self.sessions, peer));
        }
    }

    // ------------------------------------------------------------------
    // Transit-LSR label allocation (RFC 5036 §3.5.7.1.1)
    // ------------------------------------------------------------------

    /// The advertised attributes for a transit mapping propagated from
    /// the next hop's binding: the §3.4.4.1 incremented hop count
    /// (unknown stays unknown; 0 on the wire means unknown) and — when
    /// Loop Detection is configured — the §A.2.6.4 Path Vector extended
    /// with our own LSR Id (a received mapping without a Path Vector
    /// gets a length-1 vector with just our Id). `None` = the mapping
    /// must not be propagated (the hop count cannot be incremented,
    /// §A.1.1.2.3).
    fn transit_advertised_attributes(
        &self,
        binding: &PeerBinding,
    ) -> Option<(Option<crate::tlv::HopCount>, Option<crate::tlv::PathVector>)> {
        let hop_count = match binding.hop_count {
            None | Some(0) => None,
            // Cannot increment past the wire maximum — do not
            // propagate (§A.1.1.2.3: the LSR MUST NOT advertise the
            // FEC with a hop count over the maximum).
            Some(255) => return None,
            Some(h) => Some(crate::tlv::HopCount(h + 1)),
        };
        let path_vector = if self.cfg.loop_detection {
            let mut pv = binding.path_vector.clone();
            pv.push(u32::from_be_bytes(self.cfg.local_id.lsr_id));
            Some(crate::tlv::PathVector(pv))
        } else {
            None
        };
        Some((hop_count, path_vector))
    }

    /// Transit bookkeeping after a new or changed binding for `prefix`
    /// arrived from `peer` (the LIB already recorded it). Allocates
    /// the local label on first sight, re-advertises upstream per
    /// §3.5.7.1.1 (#5a first mapping, #5c attribute change, #3 next-hop
    /// change with Loop Detection) and surfaces the dataplane swap
    /// state to the embedder.
    fn transit_on_learn(
        &mut self,
        peer: LdpId,
        prefix: Prefix,
        label: GenericLabel,
        hop_count: Option<u8>,
        path_vector: Option<&[u32]>,
    ) {
        if !self.cfg.transit_allocation {
            return;
        }
        // FECs we already advertise are egress FECs (local bindings) —
        // no transit allocation for them.
        if self.lib.advertised_label(&FecKey::new(prefix)).is_some() {
            return;
        }
        self.transit_seq += 1;
        let seq = self.transit_seq;
        let binding = PeerBinding {
            label,
            hop_count,
            path_vector: path_vector.unwrap_or_default().to_vec(),
            received_seq: seq,
        };
        let (prev_nh, prev_nh_binding) = {
            let fec = self.transit.entry(prefix).or_default();
            let prev_nh = fec.nh;
            let prev_nh_binding = prev_nh.and_then(|nh| fec.bindings.get(&nh)).cloned();
            let same_attrs = prev_nh_binding
                .as_ref()
                .map(|old| old.same_wire_attrs(&binding))
                .unwrap_or(false);
            fec.bindings.insert(peer, binding);
            // §3.5.7.1.1 next-hop model: the first peer that advertised
            // the FEC becomes (and stays) the next hop.
            if fec.nh.is_none() {
                fec.nh = Some(peer);
            }
            (prev_nh, if same_attrs { prev_nh_binding } else { None })
        };
        let is_first = prev_nh.is_none();
        let nh = match self.transit.get(&prefix).and_then(|fec| fec.nh) {
            Some(nh) => nh,
            None => return,
        };
        let nh_binding = match self
            .transit
            .get(&prefix)
            .and_then(|fec| fec.bindings.get(&nh))
        {
            Some(b) => b.clone(),
            None => return,
        };
        // Allocate the local label (idempotent) or give up on the FEC.
        let local = if let Some(l) = self.transit_allocator.label_of(&prefix) {
            l
        } else {
            match self.transit_allocator.allocate(prefix) {
                Some(l) => {
                    if let Some(fec) = self.transit.get_mut(&prefix) {
                        fec.allocated_seq = Some(seq);
                    }
                    l
                }
                None => {
                    self.transit.remove(&prefix);
                    self.events
                        .push_back(EngineEvent::TransitLabelExhausted { prefix });
                    return;
                }
            }
        };
        // §3.5.7.1.1 #5a (first mapping from the downstream next hop)
        // and #5c (the next hop's attributes changed): re-advertise.
        // `prev_nh_binding` was nulled above exactly when the next
        // hop's wire attributes changed.
        let nh_binding_changed = prev_nh_binding.is_none();
        if is_first || nh_binding_changed {
            self.advertise_transit(prefix, local, &nh_binding);
        }
        // Dataplane swap state: new FEC, or the next hop's label (or
        // identity) changed.
        if is_first || (peer == nh && nh_binding_changed) {
            if let Some(next_hop) = self.peer_reach_addr(nh) {
                self.events.push_back(EngineEvent::TransitSwapChanged {
                    prefix,
                    in_label: local,
                    next_hop,
                    out_label: nh_binding.label,
                });
            }
        }
    }

    /// Transit bookkeeping after the binding for `prefix` from `peer`
    /// went away (withdraw, release-on-loop, session teardown).
    /// Re-selects the next hop or — when this was the last downstream
    /// binding — withdraws the upstream advertisement and releases the
    /// local label.
    fn transit_on_unlearn(&mut self, peer: LdpId, prefix: Prefix) {
        if !self.cfg.transit_allocation {
            return;
        }
        let Some(fec) = self.transit.get_mut(&prefix) else {
            return;
        };
        if fec.bindings.remove(&peer).is_none() {
            return;
        }
        let was_nh = fec.nh == Some(peer);
        if was_nh {
            // The next hop's binding is gone. Fall back to the lowest
            // LDP Id among the *non-reflected* remaining peers (their
            // mapping predates our own allocation — see `TransitFec`).
            let allocated_seq = fec.allocated_seq.unwrap_or(u64::MAX);
            fec.nh = fec
                .bindings
                .iter()
                .find(|(_, b)| b.received_seq < allocated_seq)
                .map(|(&id, _)| id);
        }
        let Some(nh) = fec.nh else {
            // No usable downstream binding remains: undo the whole
            // transit LSP — release the local label, withdraw the
            // upstream advertisement, and release the reflected
            // bindings we no longer trust as next-hop candidates.
            let reflected: Vec<(LdpId, GenericLabel)> = self
                .transit
                .get(&prefix)
                .map(|fec| fec.bindings.iter().map(|(&id, b)| (id, b.label)).collect())
                .unwrap_or_default();
            self.transit.remove(&prefix);
            if let Some(in_label) = self.transit_allocator.release(&prefix) {
                self.withdraw_transit_mapping(prefix);
                for (id, label) in reflected {
                    if self.lib.unlearn(id, &FecKey::new(prefix)).is_some() {
                        let message_id = self.alloc_id();
                        if let Some(st) = self.sessions.get_mut(&id) {
                            st.session.send_label_release(LabelReleaseMsg {
                                message_id,
                                fec: crate::tlv::Fec::prefix(prefix),
                                label: Some(label),
                                status: None,
                                unknown_tlvs: Vec::new(),
                            });
                        }
                        self.flush_session(id, peer_conn_of(&self.sessions, id));
                    }
                }
                self.events
                    .push_back(EngineEvent::TransitSwapRemoved { prefix, in_label });
            }
            return;
        };
        let Some(local) = self.transit_allocator.label_of(&prefix) else {
            return;
        };
        let nh_binding = match self
            .transit
            .get(&prefix)
            .and_then(|fec| fec.bindings.get(&nh))
        {
            Some(b) => b.clone(),
            None => return,
        };
        // The next hop moved to a different peer: its attributes are
        // what we now advertise upstream (§3.5.7.1.1 #5c/#3).
        if was_nh {
            self.advertise_transit(prefix, local, &nh_binding);
            if let Some(next_hop) = self.peer_reach_addr(nh) {
                self.events.push_back(EngineEvent::TransitSwapChanged {
                    prefix,
                    in_label: local,
                    next_hop,
                    out_label: nh_binding.label,
                });
            }
        }
    }

    /// Advertise a transit label for `prefix` to every operational
    /// peer (downstream unsolicited, independent control) with the
    /// §3.4.4.1/A.2.6 propagated attributes.
    fn advertise_transit(&mut self, prefix: Prefix, local: GenericLabel, nh: &PeerBinding) {
        let Some((hop_count, path_vector)) = self.transit_advertised_attributes(nh) else {
            return; // hop count cannot be propagated — stop here
        };
        let peers: Vec<LdpId> = self
            .sessions
            .iter()
            .filter(|(_, st)| st.session.is_operational())
            // RFC 7552 §7: an LSR MUST NOT send IPv6 bindings to a
            // legacy peer (an IPv4-transport session whose peer never
            // advertised the Dual-Stack capability).
            .filter(|(_, st)| !prefix.addr.is_ipv6() || st.af_v6 || st.peer_dual_stack)
            .map(|(k, _)| *k)
            .collect();
        for peer in peers {
            let message_id = self.alloc_id();
            if let Some(st) = self.sessions.get_mut(&peer) {
                st.session.send_label_mapping(LabelMappingMsg {
                    message_id,
                    fec: crate::tlv::Fec::prefix(prefix),
                    label: local,
                    hop_count,
                    path_vector: path_vector.clone(),
                    request_message_id: None,
                    unknown_tlvs: Vec::new(),
                });
            }
            self.flush_session(peer, peer_conn_of(&self.sessions, peer));
        }
    }

    /// Whether the bindings of a failed session are retained (RFC
    /// 3478 §3.3): the peer advertised the FT Session TLV and the
    /// failure was unexpected. A deliberate Shutdown means the peer is
    /// going away on purpose; local shutdowns and pre-operational
    /// errors are never covered.
    fn gr_should_retain(
        &self,
        reason: SessionDownReason,
        peer_gr: Option<crate::tlv::FtSessionParams>,
    ) -> bool {
        let unexpected = matches!(
            reason,
            SessionDownReason::TransportClosed | SessionDownReason::KeepAliveExpired
        );
        unexpected && self.cfg.graceful_restart && peer_gr.is_some()
    }

    /// The session with `peer` is operational again while its bindings
    /// are retained (RFC 3478 §3.3): the peer's fresh Recovery Time
    /// decides between recovery (keep the stale bindings for
    /// min(recovery, Maximum Recovery Time) and let the peer's
    /// re-advertisements refresh them) and immediate deletion (zero
    /// Recovery Time — the peer did not preserve its forwarding
    /// state).
    fn gr_on_session_up(
        &mut self,
        now: Instant,
        peer: LdpId,
        peer_gr: Option<crate::tlv::FtSessionParams>,
    ) {
        let Some(stale) = self.gr_stale.remove(&peer) else {
            // Bindings for the peer were purged while the session was
            // down (the reconnect window expired) — or there never
            // were any: normal (re)learning applies.
            self.gr_recovering.remove(&peer);
            return;
        };
        let recovery_ms = peer_gr.map(|g| g.recovery_ms as u64).unwrap_or(0);
        if recovery_ms == 0 {
            // §3.3: "the LSR SHOULD immediately delete all the stale
            // label-FEC bindings received from that neighbor" — the
            // peer did not preserve its forwarding state. Surface the
            // withdrawals so the embedder reverts the dataplane; the
            // peer's fresh re-advertisements re-learn everything.
            let prefixes = self.gr_purge_stale(peer, stale.fecs);
            if !prefixes.is_empty() {
                self.events.push_back(EngineEvent::MappingWithdrawn {
                    peer_id: peer,
                    prefixes,
                });
            }
            self.gr_recovering.remove(&peer);
            return;
        }
        let window = recovery_ms.min(self.cfg.gr_max_recovery_ms);
        let deadline = Instant::from_millis(now.as_millis() + window);
        self.gr_recovering.insert(
            peer,
            GrRecoveryState {
                fecs: stale.fecs,
                deadline,
            },
        );
    }

    /// A mapping arrived from a peer in recovery: refresh the stale
    /// entry (§3.3 (b)/(c)) — the LIB update already happened.
    fn gr_on_mapping_received(&mut self, peer: LdpId, prefix: Prefix) {
        if let Some(rec) = self.gr_recovering.get_mut(&peer) {
            rec.fecs.remove(&FecKey::new(prefix));
        }
        // A fresh mapping from a session that just re-established
        // while the stale set is still pending is treated the same
        // way once recovery starts (the SessionUp handler moves the
        // whole set).
    }

    /// Expire the RFC 3478 timers: reconnect windows of peers that
    /// never came back, and recovery windows of peers that did not
    /// refresh every binding in time. Returns the purge events.
    fn gr_tick(&mut self, now: Instant) {
        let now_ms = now.as_millis();
        let expired_reconnect: Vec<LdpId> = self
            .gr_stale
            .iter()
            .filter(|(_, st)| st.deadline.as_millis() <= now_ms)
            .map(|(k, _)| *k)
            .collect();
        for peer in expired_reconnect {
            let stale = self.gr_stale.remove(&peer).expect("just checked");
            let prefixes = self.gr_purge_stale(peer, stale.fecs);
            if !prefixes.is_empty() {
                self.events.push_back(EngineEvent::MappingWithdrawn {
                    peer_id: peer,
                    prefixes,
                });
            }
        }
        let expired_recovery: Vec<LdpId> = self
            .gr_recovering
            .iter()
            .filter(|(_, st)| st.deadline.as_millis() <= now_ms)
            .map(|(k, _)| *k)
            .collect();
        for peer in expired_recovery {
            let rec = self.gr_recovering.remove(&peer).expect("just checked");
            let prefixes = self.gr_purge_stale(peer, rec.fecs);
            if !prefixes.is_empty() {
                self.events.push_back(EngineEvent::MappingWithdrawn {
                    peer_id: peer,
                    prefixes,
                });
            }
        }
    }

    /// Remove `fecs` from a peer's LIB and transit state (the
    /// dataplane mirror goes away with the MappingWithdrawn events the
    /// caller emits).
    fn gr_purge_stale(&mut self, peer: LdpId, fecs: BTreeSet<FecKey>) -> Vec<Prefix> {
        let mut prefixes = Vec::new();
        for fec in fecs {
            if self.lib.unlearn(peer, &fec).is_some() {
                prefixes.push(fec.prefix);
            }
        }
        for prefix in prefixes.clone() {
            self.transit_on_unlearn(peer, prefix);
        }
        prefixes
    }

    /// The FT Session TLV timers to advertise (RFC 3478 §2), when
    /// graceful restart is configured.
    fn gr_advise(&self) -> Option<crate::session::GrAdvise> {
        if !self.cfg.graceful_restart {
            return None;
        }
        Some(crate::session::GrAdvise {
            reconnect_ms: self.cfg.gr_reconnect_ms,
            recovery_ms: self.cfg.gr_recovery_ms,
        })
    }

    /// The address traffic toward `peer` is sent to: its advertised
    /// transport address (the TCP endpoint; the adjacency falls back
    /// to the Hello source when the peer sent no Transport Address
    /// TLV).
    fn peer_reach_addr(&self, peer: LdpId) -> Option<IpAddr> {
        self.discovery
            .adjacencies()
            .iter()
            .find(|a| a.peer_id == peer)
            .map(|a| a.transport_addr)
    }

    /// Queue a link Hello (basic discovery, RFC 5036 §3.5.2) to `dest`.
    ///
    /// The engine schedules *targeted* Hellos itself, but link Hellos
    /// are interface-scoped: the embedder owns the interfaces, so it
    /// calls this on its discovery cadence (at most one Hello per
    /// hold-time third, §3.5.2.1) per attached link and transmits the
    /// drained datagram with an IP TTL of 1. `dest` is the link's
    /// all-routers multicast group (224.0.0.2 / ff02::2) or a unicast
    /// address for testing.
    pub fn send_link_hello(&mut self, dest: IpAddr) {
        // Per-family transport TLV + the RFC 7552 Dual-Stack
        // capability on dual-stack speakers; None = no local address
        // in the destination family (skip — e.g. an IPv6 multicast
        // Hello from a single-stack IPv4 speaker).
        if let Some(message) = self.discovery.build_hello(&dest, false) {
            let pdu = LdpPdu {
                version: LDP_VERSION,
                sender: self.cfg.local_id,
                messages: vec![LdpMessage::Hello(message)],
            };
            let bytes = self.encode_pdu(&pdu);
            self.out_udp.push((dest, bytes));
        }
    }

    /// Send a targeted Shutdown to one peer and tear the session down.
    pub fn shutdown_peer(&mut self, now: Instant, peer: LdpId) {
        if let Some(st) = self.sessions.remove(&peer) {
            let conn = st.conn;
            let mut session = st.session;
            let max_pdu_len = Self::effective_max_pdu(&session);
            let down_events = session.shutdown(now);
            let outgoing = session.drain_outgoing();
            self.absorb_session_events(now, peer, conn, down_events);
            self.encode_outgoing(conn, outgoing, max_pdu_len);
            self.events.push_back(EngineEvent::CloseConnection(conn));
            self.lib.unlearn_peer(peer);
        }
    }

    // ------------------------------------------------------------------
    // Output
    // ------------------------------------------------------------------

    /// Drain outbound UDP datagrams (dest, bytes).
    pub fn drain_udp(&mut self) -> Vec<(IpAddr, Vec<u8>)> {
        core::mem::take(&mut self.out_udp)
    }

    /// Drain outbound TCP bytes for one connection.
    pub fn drain_tcp(&mut self, conn: u64) -> Vec<u8> {
        self.out_bufs.remove(&conn).unwrap_or_default()
    }

    /// Drain every pending TCP payload (conn, bytes).
    pub fn drain_tcp_all(&mut self) -> Vec<(u64, Vec<u8>)> {
        let conns: Vec<u64> = self.out_bufs.keys().copied().collect();
        let mut out = Vec::new();
        for c in conns {
            if let Some(b) = self.out_bufs.remove(&c) {
                if !b.is_empty() {
                    out.push((c, b));
                }
            }
        }
        out
    }

    /// Take the queued events.
    pub fn take_events(&mut self) -> Vec<EngineEvent> {
        self.events.drain(..).collect()
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        id
    }

    /// Move queued session messages onto the connection's output
    /// buffer, wrapped in PDUs.
    fn flush_session(&mut self, peer: LdpId, conn: u64) {
        let (max_pdu_len, outgoing) = match self.sessions.get_mut(&peer) {
            Some(st) => {
                let max_pdu_len = Self::effective_max_pdu(&st.session);
                (max_pdu_len, st.session.drain_outgoing())
            }
            None => return,
        };
        self.encode_outgoing(conn, outgoing, max_pdu_len);
    }

    /// Encode drained session messages onto a connection, wrapped in
    /// PDUs and split so no PDU exceeds `max_pdu_len` (§3.5.3 — a PDU
    /// longer than the negotiated Max PDU Length is a fatal error at
    /// the receiver).
    fn encode_outgoing(&mut self, conn: u64, outgoing: Vec<LdpMessage>, max_pdu_len: u16) {
        if outgoing.is_empty() {
            return;
        }
        // The PDU length field counts the 6-octet LDP Identifier plus
        // the messages (§3.2).
        let max_body = (max_pdu_len as usize).saturating_sub(6);
        let mut scratch = core::mem::take(&mut self.enc_scratch);
        let mut pdus: Vec<Vec<u8>> = Vec::new();
        let mut cur: Vec<u8> = Vec::new();
        let mut body = 0usize; // message octets packed into `cur`
        for msg in outgoing {
            let n = encode_message_scratched(&mut scratch, &msg);
            if n == 0 {
                continue;
            }
            if body + n > max_body && !cur.is_empty() {
                close_pdu(&mut cur, body);
                pdus.push(core::mem::take(&mut cur));
                body = 0;
            }
            if cur.is_empty() {
                // PDU header: Version, length placeholder, sender LDP
                // Id — mirroring `LdpCodec::encode` (§3.2).
                cur.extend_from_slice(&crate::pdu::LDP_VERSION.to_be_bytes());
                cur.extend_from_slice(&[0u8, 0u8]);
                cur.extend_from_slice(&self.cfg.local_id.as_bytes());
            }
            cur.extend_from_slice(&scratch[..n]);
            body += n;
        }
        if !cur.is_empty() {
            close_pdu(&mut cur, body);
            pdus.push(cur);
        }
        self.enc_scratch = scratch;
        let out = self.out_bufs.entry(conn).or_default();
        for pdu in pdus {
            out.extend_from_slice(&pdu);
        }
    }

    fn encode_pdu(&mut self, pdu: &LdpPdu) -> Vec<u8> {
        let mut scratch = core::mem::take(&mut self.enc_scratch);
        scratch.clear();
        scratch.resize(scratch.capacity().max(4096), 0);
        let mut w = WriteBuf::new(&mut scratch);
        let _ = self.codec.encode(pdu, &mut w);
        let bytes = Vec::from(w.written());
        self.enc_scratch = scratch;
        bytes
    }

    /// The effective outbound PDU cap for a session: the negotiated
    /// Max PDU Length once known, the 4096 default otherwise (§3.5.3).
    fn effective_max_pdu(session: &crate::session::LdpSession) -> u16 {
        session
            .negotiated()
            .map(|n| n.max_pdu_len)
            .unwrap_or(crate::pdu::DEFAULT_MAX_PDU_LEN)
    }

    /// RFC 5036 A.2.6 `Check_Received_Attributes` (§3.4.4.1 / §2.8):
    /// when Loop Detection is configured, a received Label Mapping or
    /// Label Request carrying a Hop Count over `hop_count_limit` (a
    /// value of 0 means unknown and is never enforced), or a Path
    /// Vector containing our own LSR Id or longer than
    /// `path_vector_limit`, has traversed a loop. Returns the reason
    /// for the event log when the message must be rejected, `None`
    /// when it may be processed (also `None` when Loop Detection is
    /// off — the TLVs are then informational only).
    fn check_received_attributes(
        &self,
        hop_count: Option<crate::tlv::HopCount>,
        path_vector: Option<&crate::tlv::PathVector>,
    ) -> Option<&'static str> {
        if !self.cfg.loop_detection {
            return None;
        }
        let own = u32::from_be_bytes(self.cfg.local_id.lsr_id);
        if let Some(hc) = hop_count {
            // §3.4.4.1: a count of 0 is "unknown" — incrementing and
            // enforcing it would reject every mapping; the RFC treats
            // only known values over the maximum as a loop.
            if hc.0 != 0 && hc.0 > self.cfg.hop_count_limit {
                return Some("hop count exceeds the configured maximum");
            }
        }
        if let Some(pv) = path_vector {
            if pv.0.contains(&own) {
                return Some("path vector contains the local LSR Id");
            }
            if pv.0.len() > self.cfg.path_vector_limit as usize {
                return Some("path vector exceeds the maximum allowable length");
            }
        }
        None
    }
}

fn peer_conn_of(sessions: &BTreeMap<LdpId, LdpSessionState>, peer: LdpId) -> u64 {
    sessions.get(&peer).map(|st| st.conn).unwrap_or(0)
}

/// The wire form of a prefix FEC (§3.4.1.1): host bits beyond the
/// prefix length do not fit the encoding — normalize locally so state
/// keyed by the FEC matches what the peers send back.
fn normalize_fec(prefix: Prefix) -> Prefix {
    Prefix {
        addr: prefix.network(),
        prefix_len: prefix.prefix_len,
    }
}

/// Encode one message into `scratch` and return its wire size
/// (message header + body). The scratch grows by doubling until the
/// message fits; 0 means the message cannot fit any LDP message
/// bounds (u16 length field) and is dropped.
fn encode_message_scratched(scratch: &mut Vec<u8>, msg: &LdpMessage) -> usize {
    loop {
        scratch.clear();
        let cap = scratch.capacity().max(1024);
        scratch.resize(cap, 0);
        let mut w = WriteBuf::new(scratch);
        match crate::message::encode_message(msg, &mut w) {
            Ok(n) => return n,
            Err(_) if cap < 65_540 => scratch.reserve_exact(cap * 2),
            Err(_) => return 0,
        }
    }
}

/// Patch the PDU length field: 6-octet LDP Id plus the packed body.
fn close_pdu(cur: &mut [u8], body: usize) {
    let pdu_len = 6u32 + body as u32;
    if let Some(slot) = cur.get_mut(2..4) {
        slot.copy_from_slice(&(pdu_len as u16).to_be_bytes());
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::pdu::DEFAULT_LINK_HELLO_HOLD;
    use crate::tlv::TransportAddress;
    use lr_core::buf::ReadBuf;
    use lr_core::codec::Decoder;

    #[test]
    fn link_hello_encodes_discovery_parameters() {
        let local = LdpId::new([1, 1, 1, 1], 0);
        let mut cfg = LdpEngineConfig::new(local, IpAddr::V4([10, 0, 0, 1]));
        cfg.link_hello_hold = 15;
        let mut engine = LdpEngine::new(cfg);

        // Queue a link Hello to the all-routers multicast group and
        // decode what the embedder would transmit.
        engine.send_link_hello(IpAddr::V4([224, 0, 0, 2]));
        let out = engine.drain_udp();
        assert_eq!(out.len(), 1);
        let (dest, bytes) = &out[0];
        assert_eq!(*dest, IpAddr::V4([224, 0, 0, 2]));

        let mut read = ReadBuf::new(bytes);
        let pdu = LdpCodec.decode(&mut read).unwrap().unwrap();
        assert_eq!(pdu.sender, local);
        assert_eq!(pdu.messages.len(), 1);
        match &pdu.messages[0] {
            LdpMessage::Hello(hello) => {
                assert!(!hello.params.targeted, "a link Hello is not targeted");
                assert!(!hello.params.request_targeted);
                assert_eq!(hello.params.hold_time, DEFAULT_LINK_HELLO_HOLD);
                assert_eq!(
                    hello.transport_addr,
                    Some(TransportAddress(IpAddr::V4([10, 0, 0, 1]))),
                    "the Hello advertises the session transport address"
                );
            }
            other => panic!("expected a Hello, got {other:?}"),
        }
        // The drained queue is empty afterwards.
        assert!(engine.drain_udp().is_empty());
    }

    #[test]
    fn loop_check_gates_on_local_configuration() {
        // RFC 5036 §2.8: the local configuration governs enforcement
        // (A.2.6 "Is Loop Detection configured on LSR?") — the D bit
        // is not negotiated.
        let local = LdpId::new([2, 2, 2, 2], 0);
        let mut cfg = LdpEngineConfig::new(local, IpAddr::V4([10, 0, 0, 2]));
        cfg.loop_detection = true;
        cfg.hop_count_limit = 32;
        cfg.path_vector_limit = 32;
        let engine = LdpEngine::new(cfg);

        let own_pv = crate::tlv::PathVector(Vec::from([0x0202_0202]));
        let other_pv = crate::tlv::PathVector(Vec::from([0x0101_0101]));
        let long_pv = crate::tlv::PathVector(Vec::from([0x0a0a_0a0a; 33]));

        // Hop Count: over the limit is a loop; 0 is "unknown" (§3.4.4.1)
        // and never enforced; within the limit is fine.
        assert_eq!(
            engine.check_received_attributes(Some(crate::tlv::HopCount(33)), None),
            Some("hop count exceeds the configured maximum")
        );
        assert_eq!(
            engine.check_received_attributes(Some(crate::tlv::HopCount(0)), None),
            None
        );
        assert_eq!(
            engine.check_received_attributes(Some(crate::tlv::HopCount(32)), None),
            None
        );

        // Path Vector: containing our own LSR Id or exceeding the
        // maximum length is a loop; another LSR's Id is fine.
        assert_eq!(
            engine.check_received_attributes(None, Some(&own_pv)),
            Some("path vector contains the local LSR Id")
        );
        assert_eq!(
            engine.check_received_attributes(None, Some(&long_pv)),
            Some("path vector exceeds the maximum allowable length")
        );
        assert_eq!(
            engine.check_received_attributes(None, Some(&other_pv)),
            None
        );

        // No attributes at all: nothing to reject.
        assert_eq!(engine.check_received_attributes(None, None), None);

        // With Loop Detection off, the same looping attributes are
        // informational only (§2.8: "MUST if configured").
        let plain = LdpEngine::new(LdpEngineConfig::new(local, IpAddr::V4([10, 0, 0, 2])));
        assert_eq!(
            plain.check_received_attributes(Some(crate::tlv::HopCount(255)), Some(&own_pv)),
            None
        );
    }

    #[test]
    fn self_hello_is_ignored() {
        let local = LdpId::new([1, 1, 1, 1], 0);
        let mut cfg = LdpEngineConfig::new(local, IpAddr::V4([127, 0, 0, 1]));
        cfg.targeted_peers = Vec::from([IpAddr::V4([127, 0, 0, 2])]);
        let mut engine = LdpEngine::new(cfg);

        // Take one of our own outgoing Hellos and feed it back as if a
        // loop or miswired host echoed it: no adjacency may form with
        // our own label space.
        engine.tick(Instant::from_millis(0));
        let echoed: Vec<(IpAddr, Vec<u8>)> = engine.drain_udp();
        assert!(!echoed.is_empty());
        for (_, bytes) in echoed {
            engine.feed_udp(Instant::from_millis(1), IpAddr::V4([127, 0, 0, 1]), &bytes);
        }
        assert!(
            engine.adjacencies().is_empty(),
            "own Hellos must not create adjacencies"
        );
        assert!(engine.take_events().is_empty());
    }
}
