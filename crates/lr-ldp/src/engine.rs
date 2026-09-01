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
use alloc::collections::{BTreeMap, VecDeque};
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
    /// Per-connection TCP input accumulation.
    in_bufs: BTreeMap<u64, Vec<u8>>,
    /// Per-connection TCP output.
    out_bufs: BTreeMap<u64, Vec<u8>>,
    /// Scratch buffer reused to encode outgoing PDUs (grown on demand).
    enc_scratch: Vec<u8>,
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
        Self {
            cfg,
            discovery,
            sessions: BTreeMap::new(),
            awaiting_init: BTreeMap::new(),
            pending_connect: Vec::new(),
            noncompliant_peers: Vec::new(),
            lib: LabelMappingStore::new(),
            in_bufs: BTreeMap::new(),
            out_bufs: BTreeMap::new(),
            enc_scratch: Vec::new(),
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
                            self.absorb_session_events(peer_id, conn, down_events);
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
                            self.absorb_session_events(peer_id, conn, down_events);
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
            if let Some(mut st) = self.sessions.remove(&peer_id) {
                let mut events = Vec::new();
                st.session.transport_closed(&mut events);
                self.events.push_back(EngineEvent::SessionDown {
                    peer_id,
                    reason: SessionDownReason::TransportClosed,
                });
                self.lib.unlearn_peer(peer_id);
            }
            return;
        }
        let _ = now;
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
                });
                self.lib.unlearn_peer(peer);
                return;
            }
        }
        if let Some(st) = self.sessions.get_mut(&peer) {
            let events = st.session.feed_pdu(&pdu, now);
            let conn = st.conn;
            let down = self.absorb_session_events(peer, conn, events);
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
        let down = self.absorb_session_events(peer, conn, events);
        if down {
            if let Some(mut st) = self.sessions.remove(&peer) {
                let max_pdu_len = Self::effective_max_pdu(&st.session);
                self.encode_outgoing(conn, st.session.drain_outgoing(), max_pdu_len);
            }
        } else {
            self.flush_session(peer, conn);
        }
    }

    fn absorb_session_events(&mut self, peer: LdpId, conn: u64, events: Vec<SessionEvent>) -> bool {
        let mut down = false;
        for ev in events {
            match ev {
                SessionEvent::SessionUp(params) => {
                    self.events.push_back(EngineEvent::SessionUp {
                        peer_id: peer,
                        conn,
                        params,
                    });
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
                }
                SessionEvent::SessionDown(reason) => {
                    down = true;
                    self.events.push_back(EngineEvent::CloseConnection(conn));
                    self.events.push_back(EngineEvent::SessionDown {
                        peer_id: peer,
                        reason,
                    });
                    self.lib.unlearn_peer(peer);
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
                                self.lib.unlearn(peer, &key);
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
                                }
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
                        // No Route otherwise (§3.5.8.1).
                        for el in &m.fec.elements {
                            if let crate::tlv::FecElement::Prefix(p) = el {
                                let key = FecKey::new(*p);
                                let message_id = self.alloc_id();
                                if let Some(st) = self.sessions.get_mut(&peer) {
                                    if let Some(label) = self.lib.advertised_label(&key) {
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
                            prefixes,
                        });
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
            let down = self.absorb_session_events(peer, conn, events);
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
        let key = FecKey::new(prefix);
        if self.lib.withdraw_advertised(&key).is_none() {
            return;
        }
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
            self.absorb_session_events(peer, conn, down_events);
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
