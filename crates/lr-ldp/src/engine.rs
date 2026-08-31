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
use crate::pdu::{AdvertisementMode, LdpId, MessageType};
use crate::session::{
    role_for, SessionConfig, SessionDownReason, SessionEvent, SessionRole, SessionState,
};
use crate::tlv::{AddressList, GenericLabel, Status, StatusCode};
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
    /// The transport address advertised in Hellos and used for the
    /// §2.5.2 role decision.
    pub transport_addr: IpAddr,
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
}

impl LdpEngineConfig {
    /// A config with the RFC defaults for tests and simple embedders.
    pub fn new(local_id: LdpId, transport_addr: IpAddr) -> Self {
        Self {
            local_id,
            transport_addr,
            keepalive_time: crate::pdu::DEFAULT_KEEPALIVE_TIME,
            max_pdu_len: crate::pdu::DEFAULT_MAX_PDU_LEN,
            advertisement: AdvertisementMode::DownstreamUnsolicited,
            targeted_peers: Vec::new(),
            accept_targeted: true,
            interface_addresses: Vec::new(),
            link_hello_hold: crate::pdu::DEFAULT_LINK_HELLO_HOLD,
            targeted_hello_hold: crate::pdu::DEFAULT_TARGETED_HELLO_HOLD,
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

/// A session plus the connection it rides on.
struct LdpSessionState {
    session: crate::session::LdpSession,
    conn: u64,
}

/// One LDP speaker engine.
pub struct LdpEngine {
    cfg: LdpEngineConfig,
    discovery: LdpDiscovery,
    sessions: BTreeMap<LdpId, LdpSessionState>,
    /// Passive-role connections that have not decoded their first PDU
    /// yet (the peer is unknown until the Initialization arrives,
    /// §2.5.3).
    awaiting_init: BTreeMap<u64, crate::session::LdpSession>,
    /// Active-role establishments awaiting a successful connect.
    pending_connect: Vec<LdpId>,
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
            }
        }
    }

    /// Run the §2.5.2 role decision for adjacencies without sessions.
    fn establish_sessions(&mut self) {
        let adjacencies: Vec<HelloAdjacency> = self.discovery.adjacencies().to_vec();
        for adj in adjacencies {
            if self.sessions.contains_key(&adj.peer_id)
                || self.pending_connect.contains(&adj.peer_id)
            {
                continue;
            }
            match role_for(&self.cfg.transport_addr, &adj.transport_addr) {
                Some(SessionRole::Active) => {
                    self.pending_connect.push(adj.peer_id);
                    self.events.push_back(EngineEvent::EstablishTransport {
                        peer_id: adj.peer_id,
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
        let session = crate::session::LdpSession::new(SessionConfig {
            local_id: self.cfg.local_id,
            role: SessionRole::Active,
            peer: Some(peer_id),
            keepalive_time: self.cfg.keepalive_time,
            max_pdu_len: self.cfg.max_pdu_len,
            advertisement: self.cfg.advertisement,
            supports_downstream_unsolicited: true,
            supports_downstream_on_demand: true,
            loop_detection: false,
            path_vector_limit: 0,
        });
        self.register_session(peer_id, conn, session, now);
    }

    /// A passive-role connection was accepted. The peer is unknown
    /// until its Initialization arrives (§2.5.3).
    pub fn on_accepted(&mut self, conn: u64) {
        let session = crate::session::LdpSession::new(SessionConfig {
            local_id: self.cfg.local_id,
            role: SessionRole::Passive,
            peer: None,
            keepalive_time: self.cfg.keepalive_time,
            max_pdu_len: self.cfg.max_pdu_len,
            advertisement: self.cfg.advertisement,
            supports_downstream_unsolicited: true,
            supports_downstream_on_demand: true,
            loop_detection: false,
            path_vector_limit: 0,
        });
        self.awaiting_init.insert(conn, session);
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
        if self.awaiting_init.contains_key(&conn) {
            let session = self.awaiting_init.remove(&conn).unwrap();
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
            self.register_session(peer, conn, session, now);
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
        now: Instant,
    ) {
        let events = session.start(now);
        self.sessions
            .insert(peer, LdpSessionState { session, conn });
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
                    // Label Mapping.
                    if !self.cfg.interface_addresses.is_empty() {
                        let addrs = AddressList {
                            addresses: self.cfg.interface_addresses.clone(),
                        };
                        if let Some(st) = self.sessions.get_mut(&peer) {
                            st.session.send_address_message(addrs);
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
                SessionEvent::LabelRequestReceived(m) => {
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
