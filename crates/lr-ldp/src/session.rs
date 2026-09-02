//! LDP session state machine (RFC 5036 §2.5.3 / §2.5.4).
//!
//! One [`LdpSession`] drives a single TCP transport connection and the
//! label-space pair it serves. The five states from the §2.5.4
//! initialization state transition table:
//!
//! ```text
//! NON_EXISTENT --(transport connection established)--> INITIALIZED
//! INITIALIZED --(active: transmit Initialization)--> OPENSENT
//! INITIALIZED --(passive: receive acceptable Init; send Init+KeepAlive)--> OPENREC
//! OPENSENT    --(receive acceptable Init; send KeepAlive)--> OPENREC
//! OPENREC     --(receive KeepAlive)--> OPERATIONAL
//! OPERATIONAL --(Shutdown or timeout)--> NON_EXISTENT
//! ```
//!
//! Any other message received before OPERATIONAL is answered with an
//! error Notification and tears the connection down, per the table.
//!
//! Parameter negotiation follows §3.5.3: the KeepAlive Time is the
//! smaller of the two proposals (0 is rejected as
//! Session Rejected/Bad KeepAlive Time), the Max PDU Length is the
//! smaller of the two proposals (values of 255 or less mean the 4096
//! default), and a Downstream Unsolicited vs Downstream On Demand
//! disagreement resolves to Downstream Unsolicited (non-ATM rule) —
//! rejected with Session Rejected/Parameters Advertisement Mode when
//! the local speaker cannot support the resolved discipline.
//!
//! Like every module in this crate, the session performs no I/O: the
//! embedder drains [`LdpSession::drain_outgoing`] onto the TCP
//! connection and feeds decoded PDUs into [`LdpSession::feed_pdu`].

use crate::message::{InitMsg, KeepAliveMsg, LdpMessage, NotificationMsg, RawMessage};
use crate::pdu::{AdvertisementMode, LdpId, LDP_VERSION};
use crate::tlv::{AddressList, SessionParams, Status, StatusCode};
use alloc::vec::Vec;
use lr_core::time::Instant;

/// The §2.5.4 session states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    NonExistent,
    Initialized,
    OpenRec,
    OpenSent,
    Operational,
}

/// Whether the local speaker established the TCP connection (active)
/// or accepted it (passive), decided by the §2.5.2 transport address
/// comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Active,
    Passive,
}

/// Session parameters (RFC 5036 §3.5.3 / §2.5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// The local label space for the session.
    pub local_id: LdpId,
    pub role: SessionRole,
    /// The peer's label space. Known up front for the active role
    /// (from the Hello adjacency); learned from the first PDU for the
    /// passive role.
    pub peer: Option<LdpId>,
    /// Proposed KeepAlive Time in seconds (§3.5.3).
    pub keepalive_time: u16,
    /// Proposed Max PDU Length in octets.
    pub max_pdu_len: u16,
    /// Proposed label advertisement discipline.
    pub advertisement: AdvertisementMode,
    /// Whether the local speaker can operate Downstream Unsolicited.
    pub supports_downstream_unsolicited: bool,
    /// Whether the local speaker can operate Downstream On Demand.
    pub supports_downstream_on_demand: bool,
    /// Loop Detection (D-bit) proposal.
    pub loop_detection: bool,
    /// Path Vector Limit proposal; 0 when loop detection is off.
    pub path_vector_limit: u8,
    /// RFC 3478 §2 graceful-restart advertisement: when `Some`, the
    /// Initialization message carries the FT Session TLV with the
    /// configured timers (the L flag is always set).
    pub graceful_restart: Option<GrAdvise>,
}

/// The FT Session TLV timers this speaker advertises (RFC 3478 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrAdvise {
    /// FT Reconnect Timeout (ms): how long a peer should wait — and
    /// keep the forwarding state for our LSPs — when the session with
    /// us fails.
    pub reconnect_ms: u32,
    /// Recovery Time (ms): how long this speaker would keep its own
    /// preserved forwarding state after a restart. 0 = "not
    /// preserved" — peers delete their stale bindings for us as soon
    /// as the session is re-established (§3.3).
    pub recovery_ms: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            local_id: LdpId::default(),
            role: SessionRole::Passive,
            peer: None,
            keepalive_time: crate::pdu::DEFAULT_KEEPALIVE_TIME,
            max_pdu_len: crate::pdu::DEFAULT_MAX_PDU_LEN,
            advertisement: AdvertisementMode::DownstreamUnsolicited,
            supports_downstream_unsolicited: true,
            supports_downstream_on_demand: true,
            loop_detection: false,
            path_vector_limit: 0,
            graceful_restart: None,
        }
    }
}

/// The negotiated session parameters (§3.5.3 rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedParams {
    pub keepalive_time: u16,
    pub max_pdu_len: u16,
    pub advertisement: AdvertisementMode,
    pub loop_detection: bool,
    pub peer_path_vector_limit: u8,
    /// The peer's FT Session TLV from its Initialization, when it sent
    /// one (RFC 3478 §2). The Reconnect Timeout caps how long this
    /// speaker retains the peer's bindings after the session fails
    /// (§3.3); the Recovery Time of a re-established session decides
    /// whether the stale bindings are kept (recovery) or deleted.
    pub peer_graceful_restart: Option<crate::tlv::FtSessionParams>,
}

/// Why a session went down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDownReason {
    /// The peer sent a fatal Notification (Shutdown or other).
    PeerNotification(StatusCode),
    /// The KeepAlive Timer expired (§3.5.1.2.3).
    KeepAliveExpired,
    /// The transport connection was closed by the embedder.
    TransportClosed,
    /// A protocol error before the session was operational.
    ProtocolError,
    /// Session parameter negotiation failed.
    ParameterMismatch,
    /// Local shutdown.
    LocalShutdown,
}

/// Events surfaced by the session state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// The session is fully operational (§2.5.4 OPENREC → OPERATIONAL).
    SessionUp(NegotiatedParams),
    SessionDown(SessionDownReason),
    /// A Notification was received in the OPERATIONAL state.
    NotificationReceived(Status),
    AddressReceived(AddressList),
    AddressWithdrawReceived(AddressList),
    LabelMappingReceived(crate::message::LabelMappingMsg),
    LabelRequestReceived(crate::message::LabelRequestMsg),
    LabelWithdrawReceived(crate::message::LabelWithdrawMsg),
    LabelReleaseReceived(crate::message::LabelReleaseMsg),
    LabelAbortReceived(crate::message::LabelAbortMsg),
    /// An unrecognized message arrived (U-bit handling per §3.5).
    UnknownMessage(RawMessage),
}

/// An LDP session over one TCP connection.
pub struct LdpSession {
    cfg: SessionConfig,
    state: SessionState,
    peer: Option<LdpId>,
    negotiated: Option<NegotiatedParams>,
    next_message_id: u32,
    outgoing: Vec<LdpMessage>,
    last_rx: Option<Instant>,
    last_tx: Instant,
    /// Seconds between transmitted KeepAlives (negotiated/3).
    keepalive_send_interval: u64,
    down: bool,
}

impl LdpSession {
    /// Build a session. Call [`start`](Self::start) once the transport
    /// connection is established (§2.5.4 NON_EXISTENT → INITIALIZED).
    pub fn new(cfg: SessionConfig) -> Self {
        Self {
            cfg,
            state: SessionState::NonExistent,
            peer: None,
            negotiated: None,
            next_message_id: 1,
            outgoing: Vec::new(),
            last_rx: None,
            last_tx: Instant::ZERO,
            keepalive_send_interval: 0,
            down: false,
        }
    }

    /// The current §2.5.4 state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// The peer's label space, known once a PDU arrived (passive role)
    /// or from construction (active role).
    pub fn peer(&self) -> Option<LdpId> {
        self.peer
    }

    /// The negotiated parameters, valid once the session is up.
    pub fn negotiated(&self) -> Option<&NegotiatedParams> {
        self.negotiated.as_ref()
    }

    pub fn is_operational(&self) -> bool {
        self.state == SessionState::Operational
    }

    /// Begin session establishment (transport connection established).
    /// The active side transmits the Initialization message
    /// (§2.5.3 step 2); the passive side waits for the peer's Init.
    pub fn start(&mut self, now: Instant) -> Vec<SessionEvent> {
        debug_assert_eq!(self.state, SessionState::NonExistent);
        self.state = SessionState::Initialized;
        if self.cfg.role == SessionRole::Active {
            let message_id = self.alloc_message_id();
            let init = LdpMessage::Initialization(InitMsg {
                message_id,
                params: SessionParams {
                    protocol_version: LDP_VERSION,
                    keepalive_time: self.cfg.keepalive_time,
                    advertisement: self.cfg.advertisement,
                    loop_detection: self.cfg.loop_detection,
                    path_vector_limit: self.cfg.path_vector_limit,
                    max_pdu_len: self.cfg.max_pdu_len,
                    // The receiver field identifies the *passive* LSR's
                    // label space (§3.5.3).
                    receiver: self.cfg.peer.unwrap_or_default(),
                },
                ft_session: self
                    .cfg
                    .graceful_restart
                    .map(|gr| crate::tlv::FtSessionParams {
                        reconnect_ms: gr.reconnect_ms,
                        recovery_ms: gr.recovery_ms,
                    }),
                unknown_tlvs: Vec::new(),
            });
            self.outgoing.push(init);
            self.last_tx = now;
            // §2.5.4: transmit Initialization (Active Role) → OPENSENT.
            self.state = SessionState::OpenSent;
        }
        Vec::new()
    }

    /// Process one decoded PDU from the peer.
    pub fn feed_pdu(&mut self, pdu: &crate::message::LdpPdu, now: Instant) -> Vec<SessionEvent> {
        if self.down {
            return Vec::new();
        }
        if self.peer.is_none() {
            self.peer = Some(pdu.sender);
        }
        self.last_rx = Some(now);
        let mut events = Vec::new();
        for msg in &pdu.messages {
            match self.state {
                SessionState::NonExistent => break,
                SessionState::Initialized | SessionState::OpenSent => {
                    // §2.5.4: "Receive Any other LDP msg" → NAK + close.
                    match msg {
                        LdpMessage::Initialization(init) => {
                            self.handle_init(init, now, &mut events);
                            if self.state == SessionState::NonExistent {
                                break;
                            }
                        }
                        _ => {
                            self.nak_and_down(
                                now,
                                StatusCode::BAD_MESSAGE_LENGTH,
                                msg.message_id(),
                                msg.message_type(),
                                &mut events,
                                SessionDownReason::ProtocolError,
                            );
                            break;
                        }
                    }
                }
                SessionState::OpenRec => {
                    // Only a KeepAlive completes the handshake.
                    match msg {
                        LdpMessage::KeepAlive(_) => {
                            // §2.5.4: receive KeepAlive → OPERATIONAL.
                            self.state = SessionState::Operational;
                            if let Some(n) = self.negotiated {
                                events.push(SessionEvent::SessionUp(n));
                                self.keepalive_send_interval =
                                    (n.keepalive_time as u64).max(1) * 1000 / 3;
                            }
                        }
                        _ => {
                            self.nak_and_down(
                                now,
                                StatusCode::BAD_MESSAGE_LENGTH,
                                msg.message_id(),
                                msg.message_type(),
                                &mut events,
                                SessionDownReason::ProtocolError,
                            );
                            break;
                        }
                    }
                }
                SessionState::Operational => {
                    self.handle_operational(msg, now, &mut events);
                }
            }
        }
        events
    }

    fn handle_init(&mut self, init: &InitMsg, now: Instant, events: &mut Vec<SessionEvent>) {
        let params = &init.params;
        // §3.5.3: the receiver's label space must be ours (passive role
        // adjacency match; the active side checks it as a courtesy).
        if params.receiver != self.cfg.local_id {
            self.reject(
                now,
                StatusCode::SESSION_REJECTED_NO_HELLO,
                init.message_id,
                events,
            );
            return;
        }
        // Protocol version (§3.5.3).
        if params.protocol_version != LDP_VERSION {
            self.reject(
                now,
                StatusCode::BAD_PROTOCOL_VERSION,
                init.message_id,
                events,
            );
            return;
        }
        // KeepAlive Time must be non-zero (§3.5.3).
        if params.keepalive_time == 0 {
            self.reject(
                now,
                StatusCode::SESSION_REJECTED_BAD_KEEPALIVE_TIME,
                init.message_id,
                events,
            );
            return;
        }
        // Advertisement discipline resolution (§3.5.3): disagreement
        // resolves to Downstream Unsolicited on non-ATM links.
        let resolved = if params.advertisement == self.cfg.advertisement {
            params.advertisement
        } else {
            AdvertisementMode::DownstreamUnsolicited
        };
        let supported = match resolved {
            AdvertisementMode::DownstreamUnsolicited => self.cfg.supports_downstream_unsolicited,
            AdvertisementMode::DownstreamOnDemand => self.cfg.supports_downstream_on_demand,
        };
        if !supported {
            self.reject(
                now,
                StatusCode::SESSION_REJECTED_PARAMETERS_ADV_MODE,
                init.message_id,
                events,
            );
            return;
        }
        // Max PDU Length: a value of 255 or less means the 4096 default
        // (§3.5.3); the session value is the smaller of the proposals.
        let peer_max = if params.max_pdu_len <= 255 {
            crate::pdu::DEFAULT_MAX_PDU_LEN
        } else {
            params.max_pdu_len
        };
        let local_max = if self.cfg.max_pdu_len <= 255 {
            crate::pdu::DEFAULT_MAX_PDU_LEN
        } else {
            self.cfg.max_pdu_len
        };
        let negotiated = NegotiatedParams {
            keepalive_time: params.keepalive_time.min(self.cfg.keepalive_time),
            max_pdu_len: peer_max.min(local_max),
            advertisement: resolved,
            loop_detection: params.loop_detection && self.cfg.loop_detection,
            peer_path_vector_limit: params.path_vector_limit,
            peer_graceful_restart: init.ft_session,
        };
        self.negotiated = Some(negotiated);

        match self.cfg.role {
            SessionRole::Passive => {
                // §2.5.4: receive acceptable Init (Passive Role);
                // transmit Initialization msg and KeepAlive msg.
                let reply = LdpMessage::Initialization(InitMsg {
                    message_id: self.alloc_message_id(),
                    params: SessionParams {
                        protocol_version: LDP_VERSION,
                        keepalive_time: self.cfg.keepalive_time,
                        advertisement: self.cfg.advertisement,
                        loop_detection: self.cfg.loop_detection,
                        path_vector_limit: self.cfg.path_vector_limit,
                        max_pdu_len: self.cfg.max_pdu_len,
                        receiver: self.peer.unwrap_or(params.receiver),
                    },
                    ft_session: self
                        .cfg
                        .graceful_restart
                        .map(|gr| crate::tlv::FtSessionParams {
                            reconnect_ms: gr.reconnect_ms,
                            recovery_ms: gr.recovery_ms,
                        }),
                    unknown_tlvs: Vec::new(),
                });
                self.outgoing.push(reply);
                let message_id = self.alloc_message_id();
                self.outgoing
                    .push(LdpMessage::KeepAlive(KeepAliveMsg { message_id }));
                self.last_tx = now;
                self.state = SessionState::OpenRec;
            }
            SessionRole::Active => {
                // §2.5.4: receive acceptable Init (in OPENSENT);
                // transmit KeepAlive msg.
                let message_id = self.alloc_message_id();
                self.outgoing
                    .push(LdpMessage::KeepAlive(KeepAliveMsg { message_id }));
                self.last_tx = now;
                self.state = SessionState::OpenRec;
            }
        }
    }

    fn handle_operational(
        &mut self,
        msg: &LdpMessage,
        now: Instant,
        events: &mut Vec<SessionEvent>,
    ) {
        match msg {
            LdpMessage::KeepAlive(_) => { /* timer refresh happens in feed_pdu */ }
            LdpMessage::Notification(n) => {
                events.push(SessionEvent::NotificationReceived(n.status));
                if n.status.code.is_fatal() {
                    // §3.5.1.2.4: a fatal notification tears the session
                    // down; echo a Shutdown unless it *is* one.
                    if n.status.code != StatusCode::SHUTDOWN {
                        self.send_shutdown(now, n.status.code);
                    }
                    self.transition_down(
                        SessionDownReason::PeerNotification(n.status.code),
                        events,
                    );
                }
            }
            LdpMessage::Address(m) => {
                events.push(SessionEvent::AddressReceived(m.addresses.clone()))
            }
            LdpMessage::AddressWithdraw(m) => {
                events.push(SessionEvent::AddressWithdrawReceived(m.addresses.clone()))
            }
            LdpMessage::LabelMapping(m) => {
                events.push(SessionEvent::LabelMappingReceived(m.clone()))
            }
            LdpMessage::LabelRequest(m) => {
                events.push(SessionEvent::LabelRequestReceived(m.clone()))
            }
            LdpMessage::LabelWithdraw(m) => {
                events.push(SessionEvent::LabelWithdrawReceived(m.clone()))
            }
            LdpMessage::LabelRelease(m) => {
                events.push(SessionEvent::LabelReleaseReceived(m.clone()))
            }
            LdpMessage::LabelAbortRequest(m) => {
                events.push(SessionEvent::LabelAbortReceived(m.clone()))
            }
            LdpMessage::Hello(_) => {
                // §3.5.2: "MUST NOT be sent on a session TCP connection";
                // ignore stray hellos rather than tearing the session.
            }
            LdpMessage::Initialization(_) => {
                // A duplicate Init on an established session: §2.5.4 has
                // no transition; treat as a protocol error.
                self.nak_and_down(
                    now,
                    StatusCode::BAD_MESSAGE_LENGTH,
                    msg.message_id(),
                    msg.message_type(),
                    events,
                    SessionDownReason::ProtocolError,
                );
            }
            LdpMessage::Unknown(raw) => {
                if raw.u_bit {
                    // §3.5: silently ignored.
                    events.push(SessionEvent::UnknownMessage(raw.clone()));
                } else {
                    // U=0: notify the originator (§3.5) and keep going.
                    let message_id = self.alloc_message_id();
                    self.outgoing
                        .push(LdpMessage::Notification(NotificationMsg {
                            message_id,
                            status: Status {
                                code: StatusCode::UNKNOWN_MESSAGE_TYPE,
                                message_id: raw.message_id,
                                message_type: raw.msg_type & 0x7fff,
                            },
                            unknown_tlvs: Vec::new(),
                        }));
                    self.last_tx = now;
                }
            }
        }
    }

    /// Drive the KeepAlive timer. Resets on any PDU receipt (§3.5.3)
    /// and transmits a KeepAlive when nothing has been sent for
    /// negotiated/3 seconds, the customary third-of-hold interval.
    pub fn tick(&mut self, now: Instant) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        if self.state != SessionState::Operational || self.down {
            return events;
        }
        let keepalive_ms = self
            .negotiated
            .map(|n| n.keepalive_time as u64 * 1000)
            .unwrap_or(0);
        if keepalive_ms > 0 {
            if let Some(last) = self.last_rx {
                if now.saturating_sub(last).as_millis() >= keepalive_ms {
                    // §3.5.1.2.3: send Shutdown + close.
                    self.send_shutdown(now, StatusCode::KEEPALIVE_TIMER_EXPIRED);
                    self.transition_down(SessionDownReason::KeepAliveExpired, &mut events);
                    return events;
                }
            }
        }
        if self.keepalive_send_interval > 0
            && now.saturating_sub(self.last_tx).as_millis() >= self.keepalive_send_interval
        {
            let message_id = self.alloc_message_id();
            self.outgoing
                .push(LdpMessage::KeepAlive(KeepAliveMsg { message_id }));
            self.last_tx = now;
        }
        events
    }

    /// The embedder closed the transport connection.
    pub fn transport_closed(&mut self, events: &mut Vec<SessionEvent>) {
        self.transition_down(SessionDownReason::TransportClosed, events);
    }

    /// Local shutdown: transmit a Shutdown notification (§3.5.1.2.4)
    /// and take the session down.
    pub fn shutdown(&mut self, now: Instant) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        self.send_shutdown(now, StatusCode::SHUTDOWN);
        self.transition_down(SessionDownReason::LocalShutdown, &mut events);
        events
    }

    /// Queue a Label Mapping for transmission (embedder-driven, DU).
    pub fn send_label_mapping(&mut self, message: crate::message::LabelMappingMsg) {
        self.outgoing.push(LdpMessage::LabelMapping(message));
    }

    pub fn send_label_withdraw(&mut self, message: crate::message::LabelWithdrawMsg) {
        self.outgoing.push(LdpMessage::LabelWithdraw(message));
    }

    pub fn send_label_request(&mut self, message: crate::message::LabelRequestMsg) {
        self.outgoing.push(LdpMessage::LabelRequest(message));
    }

    pub fn send_label_release(&mut self, message: crate::message::LabelReleaseMsg) {
        self.outgoing.push(LdpMessage::LabelRelease(message));
    }

    pub fn send_address_message(&mut self, addresses: AddressList) {
        let message_id = self.alloc_message_id();
        self.outgoing
            .push(LdpMessage::Address(crate::message::AddressMsg {
                message_id,
                addresses,
                unknown_tlvs: Vec::new(),
            }));
    }

    /// Queue a Notification carrying one Status TLV (used e.g. for the
    /// No Route answer to a Label Request, §3.5.8.1).
    pub fn enqueue_notification(&mut self, status: Status) {
        let message_id = self.alloc_message_id();
        self.outgoing
            .push(LdpMessage::Notification(NotificationMsg {
                message_id,
                status,
                unknown_tlvs: Vec::new(),
            }));
    }

    /// Drain messages queued for the TCP connection.
    pub fn drain_outgoing(&mut self) -> Vec<LdpMessage> {
        core::mem::take(&mut self.outgoing)
    }

    fn alloc_message_id(&mut self) -> u32 {
        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        id
    }

    fn send_shutdown(&mut self, now: Instant, code: StatusCode) {
        let message_id = self.alloc_message_id();
        self.outgoing
            .push(LdpMessage::Notification(NotificationMsg {
                message_id,
                status: Status {
                    code,
                    message_id: 0,
                    message_type: 0,
                },
                unknown_tlvs: Vec::new(),
            }));
        self.last_tx = now;
    }

    fn reject(
        &mut self,
        now: Instant,
        code: StatusCode,
        reported_message_id: u32,
        events: &mut Vec<SessionEvent>,
    ) {
        let message_id = self.alloc_message_id();
        self.outgoing
            .push(LdpMessage::Notification(NotificationMsg {
                message_id,
                status: Status {
                    code,
                    message_id: reported_message_id,
                    message_type: crate::pdu::MessageType::Initialization as u16,
                },
                unknown_tlvs: Vec::new(),
            }));
        self.last_tx = now;
        self.transition_down(SessionDownReason::ParameterMismatch, events);
    }

    fn nak_and_down(
        &mut self,
        now: Instant,
        code: StatusCode,
        reported_message_id: u32,
        message_type: u16,
        events: &mut Vec<SessionEvent>,
        reason: SessionDownReason,
    ) {
        let message_id = self.alloc_message_id();
        self.outgoing
            .push(LdpMessage::Notification(NotificationMsg {
                message_id,
                status: Status {
                    code,
                    message_id: reported_message_id,
                    message_type,
                },
                unknown_tlvs: Vec::new(),
            }));
        self.last_tx = now;
        self.transition_down(reason, events);
    }

    fn transition_down(&mut self, reason: SessionDownReason, events: &mut Vec<SessionEvent>) {
        if !self.down {
            self.down = true;
            self.state = SessionState::NonExistent;
            events.push(SessionEvent::SessionDown(reason));
        }
    }
}

/// The §2.5.2 transport-address comparison. Returns `None` when the
/// addresses are in different families (incomparable — no session can
/// be established). Compares as unsigned integers with the earliest
/// byte as the most significant.
pub fn compare_transport_addrs(
    a: &crate::IpAddr,
    b: &crate::IpAddr,
) -> Option<core::cmp::Ordering> {
    use crate::IpAddr;
    match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => Some(x.cmp(y)),
        (IpAddr::V6(x), IpAddr::V6(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

/// The §2.5.2 role decision: the LSR with the higher transport address
/// plays the active role.
pub fn role_for(local: &crate::IpAddr, remote: &crate::IpAddr) -> Option<SessionRole> {
    match compare_transport_addrs(local, remote) {
        Some(core::cmp::Ordering::Greater) => Some(SessionRole::Active),
        Some(_) => Some(SessionRole::Passive),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{LabelMappingMsg, LdpPdu};
    use crate::pdu::DEFAULT_KEEPALIVE_TIME;
    use crate::tlv::{Fec, GenericLabel};

    fn id(v: u8) -> LdpId {
        LdpId::new([v, 0, 0, 1], 0)
    }

    fn init_pdu(sender: LdpId, receiver: LdpId, keepalive: u16) -> LdpPdu {
        LdpPdu {
            version: 1,
            sender,
            messages: vec![LdpMessage::Initialization(InitMsg {
                message_id: 1,
                params: SessionParams {
                    protocol_version: LDP_VERSION,
                    keepalive_time: keepalive,
                    advertisement: AdvertisementMode::DownstreamUnsolicited,
                    loop_detection: false,
                    path_vector_limit: 0,
                    max_pdu_len: crate::pdu::DEFAULT_MAX_PDU_LEN,
                    receiver,
                },
                ft_session: None,
                unknown_tlvs: Vec::new(),
            })],
        }
    }

    fn ka_pdu(sender: LdpId) -> LdpPdu {
        LdpPdu {
            version: 1,
            sender,
            messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 2 })],
        }
    }

    fn passive_cfg() -> SessionConfig {
        SessionConfig {
            local_id: id(1),
            role: SessionRole::Passive,
            ..SessionConfig::default()
        }
    }

    fn active_cfg() -> SessionConfig {
        SessionConfig {
            local_id: id(1),
            role: SessionRole::Active,
            // The active role knows the passive peer up front from its
            // Hello adjacency (§2.5.2 / §3.5.3).
            peer: Some(id(2)),
            ..SessionConfig::default()
        }
    }

    #[test]
    fn passive_handshake_reaches_operational() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(passive_cfg());
        s.start(now);
        assert_eq!(s.state(), SessionState::Initialized);
        assert!(s.drain_outgoing().is_empty());

        let events = s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
        assert_eq!(s.state(), SessionState::OpenRec);
        assert!(events.is_empty());
        let out = s.drain_outgoing();
        // Init + KeepAlive per §2.5.4 passive transition.
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], LdpMessage::Initialization(_)));
        assert!(matches!(out[1], LdpMessage::KeepAlive(_)));

        let events = s.feed_pdu(&ka_pdu(id(2)), now);
        assert_eq!(s.state(), SessionState::Operational);
        assert_eq!(events.len(), 1);
        match &events[0] {
            SessionEvent::SessionUp(n) => {
                assert_eq!(n.keepalive_time, 15); // min(15, 15)
                assert_eq!(n.max_pdu_len, crate::pdu::DEFAULT_MAX_PDU_LEN);
            }
            other => panic!("wrong event {other:?}"),
        }
    }

    #[test]
    fn active_handshake_reaches_operational() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(active_cfg());
        s.start(now);
        assert_eq!(s.state(), SessionState::OpenSent);
        let out = s.drain_outgoing();
        assert_eq!(out.len(), 1);
        match &out[0] {
            LdpMessage::Initialization(i) => {
                // The Init's Receiver LDP Identifier identifies the
                // passive peer's label space (RFC 5036 §3.5.3).
                assert_eq!(i.params.receiver, id(2));
                assert_eq!(i.params.keepalive_time, DEFAULT_KEEPALIVE_TIME);
            }
            other => panic!("wrong message {other:?}"),
        }

        // Peer's Init arrives (peer proposes keepalive 30 → min 15).
        let events = s.feed_pdu(&init_pdu(id(2), id(1), 30), now);
        assert_eq!(s.state(), SessionState::OpenRec);
        assert!(events.is_empty());
        let out = s.drain_outgoing();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], LdpMessage::KeepAlive(_)));

        let events = s.feed_pdu(&ka_pdu(id(2)), now);
        match &events[0] {
            SessionEvent::SessionUp(n) => assert_eq!(n.keepalive_time, 15),
            other => panic!("wrong event {other:?}"),
        }
    }

    #[test]
    fn non_init_message_in_initialized_is_naked() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(passive_cfg());
        s.start(now);
        let pdu = LdpPdu {
            version: 1,
            sender: id(2),
            messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 9 })],
        };
        let events = s.feed_pdu(&pdu, now);
        assert_eq!(s.state(), SessionState::NonExistent);
        match &events[0] {
            SessionEvent::SessionDown(SessionDownReason::ProtocolError) => {}
            other => panic!("wrong event {other:?}"),
        }
        let out = s.drain_outgoing();
        match &out[0] {
            LdpMessage::Notification(n) => {
                assert_eq!(n.status.code, StatusCode::BAD_MESSAGE_LENGTH)
            }
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn keepalive_time_zero_rejected() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(passive_cfg());
        s.start(now);
        let events = s.feed_pdu(&init_pdu(id(2), id(1), 0), now);
        assert_eq!(s.state(), SessionState::NonExistent);
        match &events[0] {
            SessionEvent::SessionDown(SessionDownReason::ParameterMismatch) => {}
            other => panic!("wrong event {other:?}"),
        }
        let out = s.drain_outgoing();
        match &out[0] {
            LdpMessage::Notification(n) => {
                assert_eq!(
                    n.status.code,
                    StatusCode::SESSION_REJECTED_BAD_KEEPALIVE_TIME
                );
            }
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn wrong_receiver_rejected() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(passive_cfg());
        s.start(now);
        let _events = s.feed_pdu(&init_pdu(id(2), id(9), 15), now);
        assert_eq!(s.state(), SessionState::NonExistent);
        let out = s.drain_outgoing();
        match &out[0] {
            LdpMessage::Notification(n) => {
                assert_eq!(n.status.code, StatusCode::SESSION_REJECTED_NO_HELLO);
            }
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn advertisement_disagreement_resolves_to_du() {
        let now = Instant::from_secs(0);
        let cfg = SessionConfig {
            local_id: id(1),
            role: SessionRole::Passive,
            advertisement: AdvertisementMode::DownstreamOnDemand,
            ..SessionConfig::default()
        };
        let mut s = LdpSession::new(cfg);
        s.start(now);
        // Peer proposes DoD too - resolved DoD (both agree).
        let pdu = LdpPdu {
            version: 1,
            sender: id(2),
            messages: vec![LdpMessage::Initialization(InitMsg {
                message_id: 1,
                params: SessionParams {
                    protocol_version: LDP_VERSION,
                    keepalive_time: 15,
                    advertisement: AdvertisementMode::DownstreamOnDemand,
                    loop_detection: false,
                    path_vector_limit: 0,
                    max_pdu_len: crate::pdu::DEFAULT_MAX_PDU_LEN,
                    receiver: id(1),
                },
                ft_session: None,
                unknown_tlvs: Vec::new(),
            })],
        };
        s.feed_pdu(&pdu, now);
        s.feed_pdu(&ka_pdu(id(2)), now);
        match s.negotiated {
            Some(n) => assert_eq!(n.advertisement, AdvertisementMode::DownstreamOnDemand),
            None => panic!("not negotiated"),
        }
    }

    #[test]
    fn dod_only_speaker_rejects_du_resolution() {
        let now = Instant::from_secs(0);
        let cfg = SessionConfig {
            local_id: id(1),
            role: SessionRole::Passive,
            advertisement: AdvertisementMode::DownstreamOnDemand,
            supports_downstream_unsolicited: false,
            ..SessionConfig::default()
        };
        let mut s = LdpSession::new(cfg);
        s.start(now);
        // Peer proposes DU, we propose DoD → DU wins → we cannot support
        // it → Session Rejected/Parameters Advertisement Mode.
        let events = s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
        assert_eq!(s.state(), SessionState::NonExistent);
        let out = s.drain_outgoing();
        match &out[0] {
            LdpMessage::Notification(n) => {
                assert_eq!(
                    n.status.code,
                    StatusCode::SESSION_REJECTED_PARAMETERS_ADV_MODE
                );
            }
            other => panic!("wrong message {other:?}"),
        }
        match &events[0] {
            SessionEvent::SessionDown(SessionDownReason::ParameterMismatch) => {}
            other => panic!("wrong event {other:?}"),
        }
    }

    #[test]
    fn keepalive_expiry_tears_down() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(passive_cfg());
        s.start(now);
        s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
        assert_eq!(s.drain_outgoing().len(), 2); // Init + KeepAlive
        s.feed_pdu(&ka_pdu(id(2)), now);
        assert!(s.is_operational());
        assert!(s.drain_outgoing().is_empty());

        // Nothing received for 15s → KeepAlive Timer Expired.
        let events = s.tick(Instant::from_secs(15));
        match &events[0] {
            SessionEvent::SessionDown(SessionDownReason::KeepAliveExpired) => {}
            other => panic!("wrong event {other:?}"),
        }
        let out = s.drain_outgoing();
        match &out[0] {
            LdpMessage::Notification(n) => {
                assert_eq!(n.status.code, StatusCode::KEEPALIVE_TIMER_EXPIRED);
            }
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn keepalive_sent_every_third() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(passive_cfg());
        s.start(now);
        s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
        assert_eq!(s.drain_outgoing().len(), 2); // Init + KeepAlive
        s.feed_pdu(&ka_pdu(id(2)), now);
        assert!(s.drain_outgoing().is_empty());

        // 4s in: nothing yet (15/3 = 5s).
        assert!(s.drain_outgoing().is_empty());
        let events = s.tick(Instant::from_secs(4));
        assert!(events.is_empty());
        assert!(s.drain_outgoing().is_empty());
        // 5s in: a KeepAlive is due.
        let _ = s.tick(Instant::from_secs(5));
        let out = s.drain_outgoing();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], LdpMessage::KeepAlive(_)));
        // A received PDU resets the KeepAlive timer, so 15s of
        // continuous traffic never expires.
        s.feed_pdu(&ka_pdu(id(2)), Instant::from_secs(6));
        let events = s.tick(Instant::from_secs(20));
        assert!(events.is_empty());
        assert!(s.is_operational());
    }

    #[test]
    fn shutdown_notification_ends_session() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(passive_cfg());
        s.start(now);
        s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
        assert_eq!(s.drain_outgoing().len(), 2); // Init + KeepAlive
        s.feed_pdu(&ka_pdu(id(2)), now);
        assert!(s.drain_outgoing().is_empty());

        let pdu = LdpPdu {
            version: 1,
            sender: id(2),
            messages: vec![LdpMessage::Notification(NotificationMsg {
                message_id: 3,
                status: Status {
                    code: StatusCode::SHUTDOWN,
                    message_id: 0,
                    message_type: 0,
                },
                unknown_tlvs: Vec::new(),
            })],
        };
        let events = s.feed_pdu(&pdu, now);
        assert_eq!(s.state(), SessionState::NonExistent);
        match &events[0] {
            SessionEvent::NotificationReceived(st) => assert_eq!(st.code, StatusCode::SHUTDOWN),
            other => panic!("wrong event {other:?}"),
        }
        match &events[1] {
            SessionEvent::SessionDown(SessionDownReason::PeerNotification(_)) => {}
            other => panic!("wrong event {other:?}"),
        }
        // No Shutdown echo when the peer already sent one.
        assert!(s.drain_outgoing().is_empty());
    }

    #[test]
    fn label_traffic_surfaces_as_events() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(passive_cfg());
        s.start(now);
        s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
        s.feed_pdu(&ka_pdu(id(2)), now);

        let pdu = LdpPdu {
            version: 1,
            sender: id(2),
            messages: vec![LdpMessage::LabelMapping(LabelMappingMsg {
                message_id: 5,
                fec: Fec::prefix(lr_core::addr::Prefix::new_v4([10, 0, 0, 0], 8)),
                label: GenericLabel(100),
                hop_count: None,
                path_vector: None,
                request_message_id: None,
                unknown_tlvs: Vec::new(),
            })],
        };
        let events = s.feed_pdu(&pdu, now);
        match &events[0] {
            SessionEvent::LabelMappingReceived(m) => {
                assert_eq!(m.label, GenericLabel(100));
                assert_eq!(m.fec.single_prefix().map(|p| p.prefix_len), Some(8));
            }
            other => panic!("wrong event {other:?}"),
        }
    }

    #[test]
    fn local_shutdown_sends_shutdown_notification() {
        let now = Instant::from_secs(0);
        let mut s = LdpSession::new(passive_cfg());
        s.start(now);
        s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
        assert_eq!(s.drain_outgoing().len(), 2); // Init + KeepAlive
        s.feed_pdu(&ka_pdu(id(2)), now);
        assert!(s.drain_outgoing().is_empty());
        let events = s.shutdown(now);
        match &events[0] {
            SessionEvent::SessionDown(SessionDownReason::LocalShutdown) => {}
            other => panic!("wrong event {other:?}"),
        }
        let out = s.drain_outgoing();
        match &out[0] {
            LdpMessage::Notification(n) => {
                assert_eq!(n.status.code, StatusCode::SHUTDOWN);
                assert!(n.status.code.is_fatal());
            }
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn role_decision_matches_rfc_252() {
        use crate::IpAddr;
        let a = IpAddr::V4([192, 0, 2, 1]);
        let b = IpAddr::V4([192, 0, 2, 2]);
        assert_eq!(role_for(&b, &a), Some(SessionRole::Active));
        assert_eq!(role_for(&a, &b), Some(SessionRole::Passive));
        assert_eq!(role_for(&a, &a), Some(SessionRole::Passive));
        // Mixed families are incomparable.
        let v6 = IpAddr::V6([0x20; 16]);
        assert_eq!(role_for(&a, &v6), None);
    }

    #[test]
    fn duration_math_is_millisecond_based() {
        assert_eq!(lr_core::time::Duration::from_secs(15).as_millis(), 15_000);
        assert_eq!(
            Instant::from_secs(20)
                .saturating_sub(Instant::from_secs(5))
                .as_millis(),
            15_000
        );
    }
}
