//! BGP peer FSM (RFC 4271 §8).
//!
//! Implements the 6-state peer state machine:
//! `Idle → Connect → Active → OpenSent → OpenConfirm → Established`.
//!
//! The FSM is event-driven. Events are passed to [`BgpPeer::step`] which
//! returns a list of [`BgpAction`]s for the embedder to dispatch (send bytes,
//! arm/cancel timers, install/withdraw routes, etc.).
//!
//! Inbound bytes are pushed via [`BgpPeer::feed_bytes`] which decodes them and
//! feeds the resulting [`BgpMessage`]s into the FSM. Outbound bytes are
//! drained via [`BgpPeer::drain_outgoing`].

use core::fmt;

use crate::capabilities::Capability;
use crate::codec::BgpCodec;
use crate::error::{BgpCeaseSubcode, BgpError, BgpErrorCode, BgpNotification};
use crate::extensions::extended_next_hop::ExtNextHopTuple;
use crate::message::{keepalive::Keepalive, open::Open, update::Update, BgpMessage};
use crate::path::{AttrType, PathAttrFlags, PathAttribute, PathAttributes};
use crate::peer::PeerConfig;

use lr_core::addr::{Asn, RouterId};
use lr_core::error::ParseError;
use lr_core::fsm::{Action, StateId, StateMachine, TimerId, TimerSpec};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

/// BGP peer state (RFC 4271 §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BgpState {
    Idle = 1,
    Connect = 2,
    Active = 3,
    OpenSent = 4,
    OpenConfirm = 5,
    Established = 6,
}

impl BgpState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Connect => "Connect",
            Self::Active => "Active",
            Self::OpenSent => "OpenSent",
            Self::OpenConfirm => "OpenConfirm",
            Self::Established => "Established",
        }
    }

    pub fn state_id(self) -> StateId {
        self as u8 as u32
    }
}

impl fmt::Display for BgpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// BGP FSM event (RFC 4271 §8.1, §8.2).
#[derive(Debug, Clone)]
pub enum BgpEvent {
    ManualStart,
    ManualStop,
    TransportOpen,
    TransportFatal,
    TransportClose,
    Message(BgpMessage),
    ParseError(BgpNotification),
    TimerConnectRetry,
    TimerHoldExpired,
    TimerKeepalive,
    TimerIdleHold,
}

/// BGP FSM action — what the embedder must do in response to an event.
#[derive(Debug, Clone)]
pub enum BgpAction {
    Send(Vec<u8>),
    SetTimer(TimerId, TimerSpec),
    CancelTimer(TimerId),
    Close,
    InstallRoute(lr_core::rib::Route),
    /// Withdraw a route from the local RIB. `path_id` is the RFC 7911
    /// Add-Path identifier of the withdrawn path (0 = single-path mode).
    WithdrawRoute {
        key: lr_core::rib::RouteKey,
        path_id: u32,
    },
    /// A negotiated peer requested that this family be re-advertised.
    RouteRefreshRequested(lr_core::nlri::NlriFamily),
    /// End-of-RIB marker received for an address family (RFC 4724 §4).
    /// Emitted for an empty UPDATE (IPv4 unicast) or an UPDATE whose only
    /// content is an empty MP_UNREACH_NLRI (other families).
    EndOfRib(lr_core::nlri::NlriFamily),
    Emit(lr_core::event::Event),
    None,
}

/// Per-peer BGP message counters (FRR `show bgp neighbor` "Message
/// statistics" parity): OPEN / UPDATE / NOTIFICATION / KEEPALIVE /
/// ROUTE-REFRESH, each direction separately.
///
/// The counters are **monotonic for the lifetime of the
/// [`BgpPeer`]** — a session re-establishment (`reset()` + fresh
/// OPEN handshake) does not zero them, matching FRR's per-neighbor
/// counters that survive flaps. Only constructing a new peer starts
/// from zero.
///
/// Counting is at the wire boundary, not the FSM boundary: every
/// message encoded onto the outbound buffer counts as sent (whether
/// or not the embedder drains and transmits those bytes), and every
/// message decoded from fed input counts as received (even one the
/// FSM discards as a state violation) — the same accounting FRR's
/// per-neighbor counters use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerMessageStats {
    /// OPEN messages sent / received.
    pub open_sent: u64,
    pub open_received: u64,
    /// UPDATE messages sent / received (advertisements, withdrawals
    /// and End-of-RIB markers alike — each is one UPDATE PDU).
    pub update_sent: u64,
    pub update_received: u64,
    /// NOTIFICATION messages sent / received.
    pub notification_sent: u64,
    pub notification_received: u64,
    /// KEEPALIVE messages sent / received.
    pub keepalive_sent: u64,
    pub keepalive_received: u64,
    /// ROUTE-REFRESH messages sent / received (RFC 2918 / RFC 7313,
    /// including the BoRR/EoRR demarcation PDUs).
    pub route_refresh_sent: u64,
    pub route_refresh_received: u64,
}

impl PeerMessageStats {
    /// Account one decoded inbound message.
    fn count_received(&mut self, msg: &BgpMessage) {
        match msg {
            BgpMessage::Open(_) => self.open_received += 1,
            BgpMessage::Update(_) => self.update_received += 1,
            BgpMessage::Notification(_) => self.notification_received += 1,
            BgpMessage::Keepalive(_) => self.keepalive_received += 1,
            BgpMessage::RouteRefresh(_) => self.route_refresh_received += 1,
        }
    }

    /// Account one encoded outbound message.
    fn count_sent(&mut self, msg: &BgpMessage) {
        match msg {
            BgpMessage::Open(_) => self.open_sent += 1,
            BgpMessage::Update(_) => self.update_sent += 1,
            BgpMessage::Notification(_) => self.notification_sent += 1,
            BgpMessage::Keepalive(_) => self.keepalive_sent += 1,
            BgpMessage::RouteRefresh(_) => self.route_refresh_sent += 1,
        }
    }
}

/// BGP peer FSM. Owns codec, peer state, and timers.
pub struct BgpPeer {
    pub(crate) cfg: PeerConfig,
    pub(crate) codec: BgpCodec,
    state: BgpState,
    negotiated_hold_time: u16,
    peer_bgp_id: Option<RouterId>,
    peer_as: Option<Asn>,
    peer_capabilities: Vec<Capability>,
    /// RFC 7911 families on which this speaker transmits Add-Path
    /// (negotiated at OPEN: the peer advertised Receive).
    add_path_tx: Vec<NlriFamily>,
    /// RFC 7911 families on which this speaker receives Add-Path
    /// (negotiated at OPEN: the peer advertised Send).
    add_path_rx: Vec<NlriFamily>,
    /// RFC 5549 Extended Next-Hop tuples negotiated with the peer
    /// (intersection of our advertised tuples and the peer's). Empty when
    /// the capability was not advertised by either side.
    extended_next_hop: Vec<ExtNextHopTuple>,
    /// W6.3 exchange-plane prototype (feature `exchange-plane`): the
    /// local configuration advertised in OPEN, when enabled.
    #[cfg(feature = "exchange-plane")]
    exchange_plane: Option<crate::extensions::exchange_plane::ExchangePlaneConfig>,
    /// W6.3 exchange-plane prototype: the negotiation result — `Some`
    /// only when both OPENs carried the capability with the same
    /// version and a non-empty key intersection
    /// (`docs/research/EXCHANGE-PLANE.md` §3).
    #[cfg(feature = "exchange-plane")]
    exchange_plane_session: Option<crate::extensions::exchange_plane::ExchangePlaneSession>,
    /// W6.3 exchange-plane prototype: the per-sender monotonic record
    /// sequence (design §6) — strictly increasing across every record
    /// set this session sends.
    #[cfg(feature = "exchange-plane")]
    exchange_plane_sequence: u32,
    /// W6.3 exchange-plane prototype: inbound replay protection
    /// (design §6) — highest accepted sequence per key id, bound to
    /// the current session instance's OPEN nonce.
    #[cfg(feature = "exchange-plane")]
    exchange_plane_replay: crate::extensions::exchange_plane::ReplayTracker,
    /// W6.3 exchange-plane prototype: the OPEN nonce in effect for the
    /// current session instance — the configured nonce mixed with the
    /// per-OPEN counter. The nonce is a session-instance tag (it
    /// travels in the clear), so uniqueness across instances is what
    /// matters for replay protection; mixing the OPEN counter delivers
    /// that without an RNG in the no-std FSM.
    #[cfg(feature = "exchange-plane")]
    exchange_plane_open_nonce: [u8; 8],
    /// W6.3 exchange-plane prototype: how many OPENs this FSM sent
    /// (session instances).
    #[cfg(feature = "exchange-plane")]
    exchange_plane_open_count: u32,
    pub(crate) out_buf: Vec<u8>,
    /// Per-type message counters (FRR "Message statistics" parity).
    /// Lives beside the FSM state so `reset()` (a re-establishment)
    /// leaves it untouched — see [`PeerMessageStats`].
    msg_stats: PeerMessageStats,
    hold_remaining: u64,
    keepalive_remaining: u64,
    established: bool,
    /// Latched when a Cease / Connection Collision Resolution NOTIFICATION
    /// (RFC 4486 subcode 7) arrives from the peer: the peer's §6.8 resolver
    /// decided against this transport. Cleared by [`BgpPeer::reset`] (the
    /// next transport incarnation) — embedders read it after a session
    /// drops to tell a collision loss from every other Idle cause.
    received_cease_collision: bool,
    /// Latched when ANY NOTIFICATION arrives from the peer: the peer told
    /// us the session is going down deliberately (RFC 4486) — the helper
    /// semantics differ from a silent transport death (BIRD parity: no
    /// stale-route retention after a NOTIFICATION, the peer announced it
    /// is not coming back). Cleared by [`BgpPeer::reset`].
    received_notification: bool,
}

/// Timer IDs used by BgpPeer.
pub mod timer_ids {
    use lr_core::fsm::TimerId;
    pub const CONNECT_RETRY: TimerId = TimerId(1);
    pub const HOLD: TimerId = TimerId(2);
    pub const KEEPALIVE: TimerId = TimerId(3);
    pub const IDLE_HOLD: TimerId = TimerId(4);
}

impl BgpPeer {
    pub fn new(cfg: PeerConfig) -> Self {
        let codec = BgpCodec::new().with_asn4(cfg.asn4);
        Self {
            cfg,
            codec,
            state: BgpState::Idle,
            negotiated_hold_time: 0,
            peer_bgp_id: None,
            peer_as: None,
            peer_capabilities: Vec::new(),
            add_path_tx: Vec::new(),
            add_path_rx: Vec::new(),
            extended_next_hop: Vec::new(),
            #[cfg(feature = "exchange-plane")]
            exchange_plane: None,
            #[cfg(feature = "exchange-plane")]
            exchange_plane_session: None,
            #[cfg(feature = "exchange-plane")]
            exchange_plane_sequence: 0,
            #[cfg(feature = "exchange-plane")]
            exchange_plane_replay: crate::extensions::exchange_plane::ReplayTracker::new(),
            #[cfg(feature = "exchange-plane")]
            exchange_plane_open_nonce: [0u8; 8],
            #[cfg(feature = "exchange-plane")]
            exchange_plane_open_count: 0,
            out_buf: Vec::new(),
            msg_stats: PeerMessageStats::default(),
            hold_remaining: 0,
            keepalive_remaining: 0,
            established: false,
            received_cease_collision: false,
            received_notification: false,
        }
    }

    /// Per-type message counters for this peer (FRR `show bgp neighbor`
    /// "Message statistics" parity). Monotonic across re-establishment;
    /// see [`PeerMessageStats`].
    pub fn message_stats(&self) -> &PeerMessageStats {
        &self.msg_stats
    }

    pub fn state(&self) -> BgpState {
        self.state
    }
    pub fn is_established(&self) -> bool {
        self.established
    }
    pub fn peer_bgp_id(&self) -> Option<RouterId> {
        self.peer_bgp_id
    }
    pub fn peer_as(&self) -> Option<Asn> {
        self.peer_as
    }
    pub fn negotiated_hold_time(&self) -> u16 {
        self.negotiated_hold_time
    }
    pub fn config(&self) -> &PeerConfig {
        &self.cfg
    }

    /// Mutable config access for pre-establishment tuning (e.g. enabling
    /// Add-Path). Changing identity or capability settings after the
    /// session establishes has no effect until it re-establishes.
    pub fn config_mut(&mut self) -> &mut PeerConfig {
        &mut self.cfg
    }

    /// Whether RFC 7911 Add-Path NLRI framing is active outbound for
    /// `family` (we may advertise multiple paths, each identified by a
    /// path identifier).
    pub fn add_path_tx_for(&self, family: NlriFamily) -> bool {
        self.add_path_tx.contains(&family)
    }

    /// Whether RFC 7911 Add-Path NLRI framing is active inbound for
    /// `family` (the peer may advertise multiple paths to us).
    pub fn add_path_rx_for(&self, family: NlriFamily) -> bool {
        self.add_path_rx.contains(&family)
    }

    /// Whether Add-Path was negotiated in either direction.
    pub fn add_path_negotiated(&self) -> bool {
        !self.add_path_tx.is_empty() || !self.add_path_rx.is_empty()
    }

    /// RFC 5549 tuples negotiated with the peer (intersection of our
    /// advertised tuples and the peer's). Empty when neither side
    /// advertised the capability.
    pub fn negotiated_extended_next_hop(&self) -> &[ExtNextHopTuple] {
        &self.extended_next_hop
    }

    /// True when `(nlri_afi, nlri_safi, nexthop_afi)` is in the
    /// negotiated set — i.e. we may emit IPv6 next-hops for IPv4 NLRI on
    /// this session.
    pub fn extended_next_hop_for(&self, nlri_afi: u16, nlri_safi: u8, nexthop_afi: u16) -> bool {
        crate::extensions::extended_next_hop::supports(
            &self.extended_next_hop,
            nlri_afi,
            nlri_safi,
            nexthop_afi,
        )
    }

    /// W6.3 exchange-plane prototype (feature `exchange-plane`):
    /// enable the plane for this session. The capability is advertised
    /// in the next OPEN; the plane activates only when the peer
    /// advertises it too (design §3). Off by default.
    #[cfg(feature = "exchange-plane")]
    pub fn set_exchange_plane(
        &mut self,
        cfg: crate::extensions::exchange_plane::ExchangePlaneConfig,
    ) {
        self.exchange_plane = Some(cfg);
    }

    /// W6.3 exchange-plane prototype: the negotiation result.
    /// `Some` only after OPEN when both speakers advertised the
    /// capability and the key intersection is non-empty.
    #[cfg(feature = "exchange-plane")]
    pub fn exchange_plane_session(
        &self,
    ) -> Option<&crate::extensions::exchange_plane::ExchangePlaneSession> {
        self.exchange_plane_session.as_ref()
    }

    /// Whether both speakers negotiated the RFC 2918 route-refresh capability.
    pub fn route_refresh_negotiated(&self) -> bool {
        self.cfg.route_refresh
            && self
                .peer_capabilities
                .iter()
                .any(|cap| cap.code == crate::capabilities::CapabilityCode::RouteRefresh)
    }

    /// Whether both speakers negotiated RFC 7313 enhanced route refresh.
    /// Peer-advertised RFC 4724 restart time, when graceful restart was
    /// negotiated. The caller retains stale routes no longer than this limit.
    pub fn negotiated_graceful_restart_time(&self) -> Option<u16> {
        if !self.cfg.graceful_restart {
            return None;
        }
        self.peer_capabilities
            .iter()
            .find_map(crate::capabilities::Capability::as_graceful_restart)
            .map(|(_, time)| time)
    }

    /// Whether both speakers exchanged the RFC 9494 Long-Lived Graceful
    /// Restart capability *and* the RFC 4724 GR capability. Per §4.5 an
    /// LLGR capability received without GR is ignored.
    pub fn llgr_negotiated(&self) -> bool {
        if !self.cfg.long_lived || !self.cfg.graceful_restart {
            return false;
        }
        let peer_gr = self
            .peer_capabilities
            .iter()
            .any(|cap| cap.code == crate::capabilities::CapabilityCode::GracefulRestart);
        let peer_llgr = self
            .peer_capabilities
            .iter()
            .any(|cap| cap.code == crate::capabilities::CapabilityCode::LongLivedGracefulRestart);
        peer_gr && peer_llgr
    }

    /// Peer-advertised Long-Lived Stale Time for one address family
    /// (RFC 9494 §4.2): the extra retention window that begins after the
    /// RFC 4724 restart time elapses. Families the peer did not list are
    /// deemed zero (§4.2); `None` means LLGR is not usable at all.
    pub fn negotiated_llgr_stale_time(&self, family: NlriFamily) -> Option<u32> {
        if !self.llgr_negotiated() {
            return None;
        }
        Some(
            self.peer_capabilities
                .iter()
                .filter_map(crate::capabilities::Capability::as_long_lived_gr)
                .flatten()
                .find(|(afi, safi, _, _)| *afi == family.afi && *safi == family.safi)
                .map(|(_, _, _, llst)| llst)
                .unwrap_or(0),
        )
    }

    /// Address families for which the peer advertised a nonzero LLGR
    /// stale time (RFC 9494 §4.2): these are the families whose routes
    /// may be retained beyond the RFC 4724 restart window, each with its
    /// own long-lived stale deadline.
    pub fn negotiated_llgr_families(&self) -> Vec<(NlriFamily, u32)> {
        if !self.llgr_negotiated() {
            return Vec::new();
        }
        self.peer_capabilities
            .iter()
            .filter_map(crate::capabilities::Capability::as_long_lived_gr)
            .flatten()
            .filter(|(afi, safi, _, llst)| {
                *llst > 0
                    && crate::extensions::long_lived::advertised_families(&self.cfg)
                        .iter()
                        .any(|f| f.afi == *afi && f.safi == *safi)
            })
            .map(|(afi, safi, _, llst)| (NlriFamily { afi, safi }, llst))
            .collect()
    }

    pub fn enhanced_route_refresh_negotiated(&self) -> bool {
        self.route_refresh_negotiated()
            && self.cfg.enhanced_rr
            && self.peer_capabilities.iter().any(|cap| {
                cap.code == crate::capabilities::CapabilityCode::EnhancedRouteRefresh
                    && cap.value.is_empty()
            })
    }

    /// Queue an RFC 2918 ROUTE-REFRESH request for an address family.
    ///
    /// Returns `false` without writing bytes unless the session is established
    /// and both speakers advertised the capability in OPEN.
    pub fn request_route_refresh(&mut self, family: NlriFamily) -> bool {
        self.enqueue_route_refresh(crate::message::RouteRefresh::new(family))
    }

    fn enqueue_route_refresh(&mut self, refresh: crate::message::RouteRefresh) -> bool {
        if !self.is_established() || !self.route_refresh_negotiated() {
            return false;
        }
        self.send_msg(&BgpMessage::RouteRefresh(refresh))
    }

    /// Start an RFC 7313 enhanced-refresh response for an address family.
    pub fn begin_enhanced_route_refresh(&mut self, family: NlriFamily) -> bool {
        self.enhanced_route_refresh_negotiated()
            && self.enqueue_route_refresh(crate::message::RouteRefresh::begin_of_rib(family))
    }

    /// Finish an RFC 7313 enhanced-refresh response for an address family.
    pub fn end_enhanced_route_refresh(&mut self, family: NlriFamily) -> bool {
        self.enhanced_route_refresh_negotiated()
            && self.enqueue_route_refresh(crate::message::RouteRefresh::end_of_rib(family))
    }

    /// Push inbound bytes; decode and emit any actions for consumed
    /// messages. A protocol-level parse error is converted into the FSM's
    /// `BgpEvent::ParseError`, which sends the required NOTIFICATION and
    /// closes the session (RFC 4271 §6) — the error is not surfaced to the
    /// embedder as a generic parse failure.
    pub fn feed_bytes(&mut self, bytes: &[u8]) -> Result<Vec<BgpAction>, ParseError> {
        let mut actions = Vec::new();
        let mut r = lr_core::buf::ReadBuf::new(bytes);
        loop {
            let before = r.position();
            match self.codec.decode_bgp(&mut r) {
                Ok(None) => break,
                Ok(Some(msg)) => {
                    // Wire-boundary accounting (FRR parity): count
                    // every decoded message, even one the FSM's
                    // current state then refuses.
                    self.msg_stats.count_received(&msg);
                    actions.extend(self.step(BgpEvent::Message(msg)));
                }
                Err(BgpError::Notification(n)) => {
                    // A well-formed NOTIFICATION from the peer: it
                    // decoded (and counts at the wire boundary) even
                    // though the FSM surfaces it as a parse-level
                    // fatal event.
                    self.msg_stats.notification_received += 1;
                    actions.extend(self.step(BgpEvent::ParseError(n)));
                    break;
                }
                Err(BgpError::Truncated) => break,
                Err(BgpError::Codec(s)) => {
                    actions.extend(self.step(BgpEvent::ParseError(BgpNotification::new(
                        crate::error::BgpErrorCode::Update as u8,
                        crate::error::BgpUpdateErrorSubcode::MalformedAttributeList as u8,
                        s.into_bytes(),
                    ))));
                    break;
                }
            }
            if r.position() == before && r.remaining() > 0 {
                break;
            }
        }
        Ok(actions)
    }

    pub fn drain_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out_buf)
    }

    /// Encode one message onto the outbound buffer and account it in
    /// [`PeerMessageStats`]. Every egress message goes through this
    /// single choke point so the counters stay exact — including the
    /// End-of-RIB marker (an empty UPDATE) and the NOTIFICATION a
    /// parse error produces. Returns whether the encode succeeded.
    pub(crate) fn send_msg(&mut self, msg: &BgpMessage) -> bool {
        match self.codec.encode_vec(msg) {
            Ok(bytes) => {
                self.out_buf.extend_from_slice(&bytes);
                self.msg_stats.count_sent(msg);
                true
            }
            Err(_) => false,
        }
    }

    fn enqueue_open(&mut self) {
        let mut caps: Vec<Capability> = Vec::new();
        if self.cfg.asn4 {
            caps.push(Capability::four_octet_as(self.cfg.local_as.as_u32()));
        }
        for fam in &self.cfg.mp_families {
            caps.push(Capability::multiprotocol(fam.afi, fam.safi));
        }
        if self.cfg.route_refresh {
            caps.push(Capability::route_refresh());
        }
        if self.cfg.enhanced_rr {
            caps.push(Capability::enhanced_rr());
        }
        if self.cfg.graceful_restart {
            // RFC 4724 §3: list the families whose state we can preserve —
            // the receiving speaker retains routes exactly for these
            // (§4.2). The F bit is set: the library keeps Adj-RIB-In across
            // reconnects within the same process (the reference daemon).
            let families: Vec<(u16, u8, bool)> =
                crate::extensions::long_lived::advertised_families(&self.cfg)
                    .into_iter()
                    .map(|f| (f.afi, f.safi, true))
                    .collect();
            caps.push(Capability::graceful_restart(
                0,
                self.cfg.graceful_restart_time,
                &families,
            ));
        }
        // RFC 9494 §4.1: LLGR is advertised alongside the GR capability.
        if let Some(llgr) = crate::extensions::long_lived::open_capability(&self.cfg) {
            caps.push(llgr);
        }
        // RFC 7911 §4.4: offer to send and receive multiple paths for
        // every family this session speaks.
        let add_path_families = crate::extensions::addpath::advertised_families(&self.cfg);
        if !add_path_families.is_empty() {
            let tuples: Vec<(u16, u8, bool, bool)> = add_path_families
                .iter()
                .map(|f| (f.afi, f.safi, true, true))
                .collect();
            caps.push(Capability::add_path(&tuples));
        }
        // RFC 5549 §4: advertise the Extended Next-Hop tuples configured
        // for this session (filtered to families the session speaks).
        let enh_tuples = crate::extensions::extended_next_hop::advertised_tuples(&self.cfg);
        if !enh_tuples.is_empty() {
            let raw: Vec<(u16, u8, u16)> = enh_tuples
                .iter()
                .map(|t| (t.nlri_afi, t.nlri_safi, t.nexthop_afi))
                .collect();
            caps.push(Capability::extended_next_hop(&raw));
        }
        // W6.3 exchange-plane prototype: advertise when configured
        // (feature-gated; RFC 5492 §3 makes the unknown capability
        // inert for peers without it). Each OPEN bumps the instance
        // counter and mixes it into the advertised nonce — a fresh
        // session instance gets a fresh nonce, which is what makes
        // cross-instance replay detectable (design §6).
        #[cfg(feature = "exchange-plane")]
        if let Some(xp) = self.exchange_plane_for_open() {
            caps.push(xp.capability());
        }
        let param_value = Capability::encode_set(&caps);
        let mut open = Open::new(self.cfg.local_as, self.cfg.hold_time, self.cfg.local_bgp_id);
        open.params.push(crate::message::open::OpenParam {
            param_type: crate::message::open::OpenParam::PARAM_TYPE_CAPABILITY,
            value: param_value,
        });
        if let Ok(bytes) = self.codec.encode_vec(&BgpMessage::Open(open)) {
            self.out_buf.extend_from_slice(&bytes);
            self.msg_stats.open_sent += 1;
        }
    }

    fn enqueue_keepalive(&mut self) {
        if let Ok(bytes) = self.codec.encode_vec(&BgpMessage::Keepalive(Keepalive)) {
            self.out_buf.extend_from_slice(&bytes);
            self.msg_stats.keepalive_sent += 1;
        }
    }

    /// W6.3 exchange-plane (feature `exchange-plane`): the effective
    /// OPEN-time plane configuration — the configured nonce mixed with
    /// the OPEN instance counter. Returns a clone carrying the nonce
    /// this session instance advertises (used for both the capability
    /// value and the negotiation's local_nonce).
    #[cfg(feature = "exchange-plane")]
    fn exchange_plane_for_open(
        &mut self,
    ) -> Option<crate::extensions::exchange_plane::ExchangePlaneConfig> {
        self.exchange_plane_open_count = self.exchange_plane_open_count.wrapping_add(1);
        let mut nonce = self
            .exchange_plane
            .as_ref()
            .map(|c| c.nonce)
            .unwrap_or([0u8; 8]);
        // Mix the instance counter into the last four octets: an XOR of
        // a be-encoded counter is enough to make per-instance nonces
        // distinct (the nonce tags the session instance; it is not a
        // secret).
        let count = self.exchange_plane_open_count.to_be_bytes();
        for (i, b) in count.iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        self.exchange_plane_open_nonce = nonce;
        let mut cfg = self.exchange_plane.clone()?;
        cfg.nonce = nonce;
        Some(cfg)
    }

    /// W6.3 exchange-plane ingress (feature `exchange-plane`): take
    /// over a received type-251 attribute. Returns the private record
    /// store attribute to ride the route bag (`None` = drop the
    /// records; the route's standard content always survives — design
    /// §8 fail-open for route data). Verification order per design §6:
    /// nonce echo, then sequence, then the authentication tag.
    ///
    /// `actions` collects `Event::Log` lines for verification failures
    /// so embedders can see tampering/replay attempts without the
    /// session being affected.
    #[cfg(feature = "exchange-plane")]
    pub(crate) fn consume_exchange_plane(
        &mut self,
        wire: Option<&crate::path::PathAttribute>,
        actions: &mut Vec<BgpAction>,
    ) -> Option<crate::path::PathAttribute> {
        use crate::extensions::exchange_plane as xp;

        let wire = wire?;
        let Some(session) = self.exchange_plane_session.as_ref() else {
            // Plane inactive on this session (not configured, or the
            // negotiation did not activate): the attribute is unknown
            // optional-transitive forwarding material — keep it in the
            // bag; the §5.3 relay pass marks it Partial.
            return Some(wire.clone());
        };

        // Design §7: a Partial-bit record is forwarding material — the
        // attribute crossed a non-lr speaker, so it is not consumed and
        // not verifiable here (the tag was computed against the last lr
        // hop's receiver nonce, not ours). Park the raw body so egress
        // can re-emit it byte-identically.
        if wire.flags.partial() {
            return Some(crate::path::PathAttribute::new(
                crate::path::PathAttrFlags::new().set_optional(true),
                AttrType::LrExchangePlaneRecords,
                xp::store_partial_raw(&wire.value),
            ));
        }

        let record = match xp::ExchangeRecord::decode(&wire.value) {
            Ok(r) => r,
            Err(e) => {
                actions.push(BgpAction::Emit(lr_core::event::Event::Log(format!(
                    "exchange-plane: dropping malformed record set on session {}: {:?}",
                    self.cfg.peer_id, e
                ))));
                return None;
            }
        };
        // Design §6 order: (1) the nonce echo must match our OPEN nonce
        // (a record captured from another session instance replays into
        // a dead corner); (2) the sequence must be strictly greater than
        // the last accepted one for this key id; (3) the tag must verify.
        if record.nonce_echo != session.local_nonce {
            actions.push(BgpAction::Emit(lr_core::event::Event::Log(format!(
                "exchange-plane: dropped record with foreign-session nonce on session {}",
                self.cfg.peer_id
            ))));
            return None;
        }
        if self.exchange_plane_replay.accept(
            record.key_id,
            record.sequence,
            &record.nonce_echo,
            &session.local_nonce,
        ) != xp::ReplayDecision::Accept
        {
            actions.push(BgpAction::Emit(lr_core::event::Event::Log(format!(
                "exchange-plane: dropped stale sequence {} (replay?) on session {}",
                record.sequence, self.cfg.peer_id
            ))));
            return None;
        }
        let Some(key) = session.keys.iter().find(|k| k.id == record.key_id) else {
            actions.push(BgpAction::Emit(lr_core::event::Event::Log(format!(
                "exchange-plane: dropped record signed under unknown key id {} on session {}",
                record.key_id, self.cfg.peer_id
            ))));
            return None;
        };
        if !record.verify(key) {
            actions.push(BgpAction::Emit(lr_core::event::Event::Log(format!(
                "exchange-plane: authentication tag mismatch on session {} (tampering?)",
                self.cfg.peer_id
            ))));
            return None;
        }
        Some(crate::path::PathAttribute::new(
            crate::path::PathAttrFlags::new().set_optional(true),
            AttrType::LrExchangePlaneRecords,
            xp::store_verified(&record),
        ))
    }

    /// W6.3 exchange-plane egress (feature `exchange-plane`): attach the
    /// wire record-set attribute to an advertised route, or forward the
    /// route's existing type-251 attribute as-is when it carries
    /// forwarding material this session did not consume. Called after
    /// all the early-return egress gates, before the UPDATE is encoded.
    #[cfg(feature = "exchange-plane")]
    pub(crate) fn attach_exchange_plane(
        &mut self,
        attrs: &mut crate::path::PathAttributes,
        route: &Route,
    ) {
        use crate::extensions::exchange_plane as xp;

        // The private record store never leaves this speaker.
        let store = attrs.remove(AttrType::LrExchangePlaneRecords);

        // A wire attribute the session did not consume at ingress (the
        // plane was inactive then, or the peer is not an lr speaker) is
        // forwarding material: re-emit byte-identically and never stack
        // a second type-251 attribute on top (RFC 4271 §6.3 duplicate
        // attribute check).
        if let Some(received) = attrs.remove(AttrType::Other(xp::ATTRIBUTE_TYPE)) {
            attrs.insert(received);
            return;
        }

        let (Some(local), Some(session)) = (&self.exchange_plane, &self.exchange_plane_session)
        else {
            return;
        };

        // Decode the parked record set (if any) so build_record_set can
        // forward the provenance chain with the scope decremented.
        let received = match store.as_ref().map(|a| xp::load_store(&a.value)) {
            Some(Some((xp::STORE_VERIFIED, payload))) => xp::ExchangeRecord::decode(payload).ok(),
            Some(Some((xp::STORE_PARTIAL_RAW, raw))) => {
                // Forwarding material from an inactive ingress: re-emit
                // with the Partial bit set (§5.3).
                attrs.insert(crate::path::PathAttribute::new(
                    crate::path::PathAttrFlags::new()
                        .set_optional(true)
                        .set_transitive(true)
                        .set_partial(true),
                    AttrType::Other(xp::ATTRIBUTE_TYPE),
                    raw.to_vec(),
                ));
                return;
            }
            _ => None,
        };

        // The outbound sequence is per-session monotonic (design §6); a
        // u32 counter exhausted means the plane stops attaching rather
        // than wrapping into replayed sequence space.
        let Some(sequence) = self.exchange_plane_sequence.checked_add(1) else {
            return;
        };
        let input = xp::EgressInput {
            local_as: self.cfg.local_as.as_u32(),
            locally_originated: route.origin.proto == 2,
            prefix: &route.key.prefix,
            received: received.as_ref(),
            peer_as: self.cfg.peer_as.as_u32(),
        };
        let Some(out) = xp::build_record_set(local, session, &input, sequence) else {
            return;
        };
        self.exchange_plane_sequence = sequence;
        attrs.insert(crate::path::PathAttribute::new(
            crate::path::PathAttrFlags::new()
                .set_optional(true)
                .set_transitive(true),
            AttrType::Other(xp::ATTRIBUTE_TYPE),
            out.record.encode(),
        ));
    }

    pub fn enqueue_notification(&mut self, code: BgpErrorCode, subcode: u8) {
        let n = BgpNotification::new(code as u8, subcode, vec![]);
        self.send_msg(&BgpMessage::Notification(n));
    }

    fn handle_open_in_opensent(&mut self, open: &Open) -> (BgpState, Vec<BgpAction>) {
        if open.version != 4 {
            self.enqueue_notification(BgpErrorCode::Open, 1);
            return (BgpState::Idle, vec![BgpAction::Close]);
        }
        let mut peer_as = open.my_as;
        let mut caps: Vec<Capability> = Vec::new();
        for p in &open.params {
            if p.param_type == crate::message::open::OpenParam::PARAM_TYPE_CAPABILITY {
                caps.extend(Capability::decode_set(&p.value));
            }
        }
        // Dynamic AS4 negotiation (RFC 6793 §4.2.2): 4-byte AS_PATH encoding
        // is only used when *both* speakers advertised the capability. Our
        // OPEN was already sent with the AS4 capability when configured; if
        // the peer did not offer it, downgrade both directions to the
        // 2-byte width for the lifetime of this session. The downgrade is
        // applied to the codec only — `cfg.asn4` keeps the configured
        // value so a later re-establishment re-negotiates fresh (RFC 6793
        // negotiation is per-session).
        let peer_offered_as4 = caps
            .iter()
            .any(|c| c.code == crate::capabilities::CapabilityCode::FourOctetAs);
        let session_asn4 = self.cfg.asn4 && peer_offered_as4;
        self.codec.set_asn4(session_asn4);
        if let Some(c) = caps
            .iter()
            .find(|c| c.code == crate::capabilities::CapabilityCode::FourOctetAs)
        {
            if let Some(as4) = c.as_four_octet() {
                peer_as = Asn(as4);
            }
        }
        if peer_as != self.cfg.peer_as && !self.cfg.confederation_member {
            self.enqueue_notification(BgpErrorCode::Open, 2);
            return (BgpState::Idle, vec![BgpAction::Close]);
        }
        if open.bgp_id == self.cfg.local_bgp_id {
            self.enqueue_notification(BgpErrorCode::Open, 3);
            return (BgpState::Idle, vec![BgpAction::Close]);
        }
        if open.hold_time != 0 && open.hold_time < 3 {
            self.enqueue_notification(BgpErrorCode::Open, 6);
            return (BgpState::Idle, vec![BgpAction::Close]);
        }
        self.peer_bgp_id = Some(open.bgp_id);
        self.peer_as = Some(peer_as);
        self.peer_capabilities = caps;

        // RFC 7911 §4.4: Add-Path works per address family and per
        // direction. We transmit multiple paths only where the peer
        // offered to receive them, and accept them only where the peer
        // offered to send. The codec switches NLRI framing accordingly.
        let peer_add_path: Vec<(u16, u8, bool, bool)> = self
            .peer_capabilities
            .iter()
            .filter_map(Capability::as_add_path)
            .flatten()
            .collect();
        let (tx, rx) = crate::extensions::addpath::negotiated_directions(&self.cfg, &peer_add_path);
        self.add_path_tx = tx;
        self.add_path_rx = rx;
        self.codec
            .set_add_path(self.add_path_tx.clone(), self.add_path_rx.clone());

        // RFC 5549 §4: Extended Next-Hop is usable only for tuples both
        // speakers advertised. Store the intersection; the egress path
        // consults it before rewriting an IPv4 NEXT_HOP to IPv6.
        let peer_enh: Vec<ExtNextHopTuple> = self
            .peer_capabilities
            .iter()
            .filter_map(|cap| cap.as_extended_next_hop())
            .flatten()
            .map(|(a, s, n)| ExtNextHopTuple::new(a, s, n))
            .collect();
        self.extended_next_hop =
            crate::extensions::extended_next_hop::negotiated_tuples(&self.cfg, &peer_enh);

        // W6.3 exchange-plane prototype: activate only when both sides
        // advertised the capability with the same version and a
        // non-empty key intersection (design §3). Otherwise the plane
        // stays off — the session is unaffected either way. Each new
        // OPEN nonce is a fresh sequence space (design §6): the replay
        // window and the outbound sequence counter reset with it.
        #[cfg(feature = "exchange-plane")]
        {
            // Negotiate against the nonce this session instance actually
            // advertised (the OPEN counter is mixed in — see
            // `exchange_plane_for_open`).
            let local = self.exchange_plane.as_ref().map(|c| {
                let mut l = c.clone();
                l.nonce = self.exchange_plane_open_nonce;
                l
            });
            self.exchange_plane_session = match local {
                Some(local) => self
                    .peer_capabilities
                    .iter()
                    .find_map(crate::extensions::exchange_plane::parse_capability)
                    .and_then(|peer_open| {
                        crate::extensions::exchange_plane::negotiate(&local, &peer_open)
                    }),
                None => None,
            };
            self.exchange_plane_replay.reset();
            self.exchange_plane_sequence = 0;
        }

        // RFC 4271 §4.2: the Hold Timer is the smaller of our configured
        // hold time and the peer's. A zero received hold time disables the
        // hold timer entirely (and with it KEEPALIVEs, per §4.4) — we must
        // not substitute our own value.
        self.negotiated_hold_time = open.hold_time.min(self.cfg.hold_time);
        self.hold_remaining = (self.negotiated_hold_time as u64) * 1000;
        let keepalive = self.cfg.keepalive_interval();
        self.keepalive_remaining =
            u64::from(keepalive.min((self.negotiated_hold_time / 3).max(1))) * 1000;
        let mut actions = vec![];
        if self.negotiated_hold_time > 0 {
            self.enqueue_keepalive();
            actions.push(BgpAction::SetTimer(
                timer_ids::HOLD,
                TimerSpec::once(self.hold_remaining),
            ));
            actions.push(BgpAction::SetTimer(
                timer_ids::KEEPALIVE,
                TimerSpec::once(self.keepalive_remaining),
            ));
        }
        (BgpState::OpenConfirm, actions)
    }

    /// Drive the FSM with an event; return actions to dispatch.
    pub fn step(&mut self, ev: BgpEvent) -> Vec<BgpAction> {
        let mut my_actions: Vec<BgpAction> = Vec::new();
        let new_state: BgpState = match (self.state, &ev) {
            (BgpState::Idle, BgpEvent::ManualStart) => {
                my_actions.push(BgpAction::SetTimer(
                    timer_ids::CONNECT_RETRY,
                    TimerSpec::once(5_000),
                ));
                BgpState::Connect
            }
            (BgpState::Connect, BgpEvent::TransportOpen)
            | (BgpState::Active, BgpEvent::TransportOpen) => {
                self.enqueue_open();
                BgpState::OpenSent
            }
            (BgpState::Connect, BgpEvent::TimerConnectRetry) => BgpState::Active,
            (BgpState::OpenSent, BgpEvent::Message(BgpMessage::Open(_))) => {
                let open = if let BgpEvent::Message(BgpMessage::Open(ref o)) = ev {
                    o.clone()
                } else {
                    unreachable!()
                };
                let (s, a) = self.handle_open_in_opensent(&open);
                my_actions.extend(a);
                s
            }
            (BgpState::OpenConfirm, BgpEvent::Message(BgpMessage::Keepalive(_))) => {
                self.established = true;
                my_actions.push(BgpAction::Emit(lr_core::event::Event::PeerStateChange {
                    session: self.cfg.peer_id,
                    peer_state: "Established",
                }));
                BgpState::Established
            }
            (BgpState::Established, BgpEvent::Message(BgpMessage::Keepalive(_))) => {
                self.hold_remaining = (self.negotiated_hold_time as u64) * 1000;
                my_actions.push(BgpAction::CancelTimer(timer_ids::HOLD));
                my_actions.push(BgpAction::SetTimer(
                    timer_ids::HOLD,
                    TimerSpec::once(self.hold_remaining),
                ));
                BgpState::Established
            }
            (BgpState::Established, BgpEvent::Message(BgpMessage::RouteRefresh(refresh))) => {
                if self.route_refresh_negotiated()
                    && refresh.subtype == crate::message::RouteRefreshSubtype::Normal
                {
                    my_actions.push(BgpAction::RouteRefreshRequested(refresh.family));
                }
                BgpState::Established
            }
            (BgpState::Established, BgpEvent::Message(BgpMessage::Update(_))) => {
                let update = if let BgpEvent::Message(BgpMessage::Update(ref u)) = ev {
                    u.clone()
                } else {
                    unreachable!()
                };
                my_actions.extend(self.handle_update_in_established(&update));
                // Feasibility: re-arm the hold timer — any valid message
                // refreshes it (RFC 4271 §4.4).
                my_actions.push(BgpAction::CancelTimer(timer_ids::HOLD));
                my_actions.push(BgpAction::SetTimer(
                    timer_ids::HOLD,
                    TimerSpec::once((self.negotiated_hold_time as u64) * 1000),
                ));
                BgpState::Established
            }
            (BgpState::Established, BgpEvent::TimerKeepalive) => {
                self.enqueue_keepalive();
                my_actions.push(BgpAction::SetTimer(
                    timer_ids::KEEPALIVE,
                    TimerSpec::once(self.keepalive_remaining),
                ));
                BgpState::Established
            }
            (BgpState::Established, BgpEvent::TimerHoldExpired) => {
                self.enqueue_notification(BgpErrorCode::HoldTimerExpired, 0);
                self.established = false;
                my_actions.push(BgpAction::Close);
                BgpState::Idle
            }
            (_, BgpEvent::ManualStop)
            | (_, BgpEvent::TransportFatal)
            | (_, BgpEvent::TransportClose) => {
                self.established = false;
                my_actions.push(BgpAction::Close);
                BgpState::Idle
            }
            // RFC 4271 §6.8: receiving a NOTIFICATION is always fatal to
            // the session — transition to Idle and let the embedder close
            // the transport. Without this arm a peer-initiated teardown
            // (hold-time expiry, ceasing, malformed UPDATE) would leave us
            // stuck in Established.
            (_, BgpEvent::Message(BgpMessage::Notification(n))) => {
                // RFC 4271 §6.8 / RFC 4486: a Cease / Connection Collision
                // Resolution means the peer's resolver closed this
                // transport — latch it for the embedder's churn guard.
                self.received_notification = true;
                if n.error_code == BgpErrorCode::Cease as u8
                    && n.error_subcode == BgpCeaseSubcode::ConnectionCollision as u8
                {
                    self.received_cease_collision = true;
                }
                my_actions.push(BgpAction::Emit(lr_core::event::Event::PeerStateChange {
                    session: self.cfg.peer_id,
                    peer_state: "Idle (notification received)",
                }));
                my_actions.push(BgpAction::Emit(lr_core::event::Event::Log(format!(
                    "peer sent NOTIFICATION code={} sub={} — closing session",
                    n.error_code, n.error_subcode
                ))));
                self.established = false;
                my_actions.push(BgpAction::Close);
                BgpState::Idle
            }
            (_, BgpEvent::ParseError(n)) => {
                let n = n.clone();
                self.send_msg(&BgpMessage::Notification(n));
                self.established = false;
                my_actions.push(BgpAction::Close);
                BgpState::Idle
            }
            (s, _) => s,
        };
        self.state = new_state;
        // Outbound bytes stay in out_buf; the embedder drains them via
        // drain_outgoing(). This keeps "actions emitted by step" purely
        // about timers/control.
        my_actions
    }

    /// Reset to Idle. Does not close transport — embedder handles that.
    pub fn reset(&mut self) {
        self.codec = BgpCodec::new().with_asn4(self.cfg.asn4);
        self.state = BgpState::Idle;
        self.established = false;
        self.peer_bgp_id = None;
        self.peer_as = None;
        self.peer_capabilities.clear();
        self.add_path_tx.clear();
        self.add_path_rx.clear();
        self.extended_next_hop.clear();
        self.out_buf.clear();
        self.hold_remaining = 0;
        self.keepalive_remaining = 0;
        self.negotiated_hold_time = 0;
        self.received_cease_collision = false;
        self.received_notification = false;
    }

    /// Whether a Cease / Connection Collision Resolution NOTIFICATION
    /// (RFC 4486 subcode 7) arrived since the last [`BgpPeer::reset`].
    /// The embedder combines this with the FSM going Idle to recognise a
    /// lost §6.8 collision (as opposed to every other Idle cause) and
    /// stop hammering a peer that already holds a live session.
    pub fn received_cease_collision(&self) -> bool {
        self.received_cease_collision
    }

    /// Whether ANY NOTIFICATION arrived from the peer since the last
    /// [`BgpPeer::reset`]. RFC 4486 deaths are deliberate goodbyes — the
    /// helper must not retain the peer's routes (BIRD parity: retention
    /// follows silent transport deaths, not announced shutdowns).
    pub fn notification_received(&self) -> bool {
        self.received_notification
    }

    /// Extract routes from an inbound UPDATE (RFC 4271 §9.1.1 "update
    /// filtering" stage-0: pure decode-to-route conversion, no policy).
    ///
    /// Withdrawals become [`BgpAction::WithdrawRoute`] and announcements
    /// become [`BgpAction::InstallRoute`] with the full path-attribute set
    /// carried in the route's attribute bag. The router layer (or a
    /// standalone embedder) then applies its import pipeline: safety net,
    /// import hooks, Adj-RIB-In, decision process.
    ///
    /// Conventions:
    /// - `RouteOrigin::peer` is this session's `peer_id`.
    /// - `RouteOrigin::proto` is `1` for iBGP-learned and `0` for
    ///   eBGP-learned routes (the convention consumed by
    ///   [`crate::best_path::BestPath`]).
    /// - `Preference::metric` carries the AS-path length so cross-protocol
    ///   merging has a comparable figure of merit.
    fn handle_update_in_established(&mut self, u: &Update) -> Vec<BgpAction> {
        let mut actions: Vec<BgpAction> = Vec::new();

        // --- End-of-RIB detection (RFC 4724 §4) ---
        // An UPDATE with no withdrawn routes, no path attributes and no
        // NLRI is the EoR marker for <IPv4, Unicast>; for other families
        // the marker carries a lone, empty MP_UNREACH_NLRI attribute
        // (RFC 4724 §4 + RFC 4760). Downstream (graceful restart, RFC
        // 9494 §4.2) uses it to conclude table synchronization.
        if u.withdrawn.is_empty() && u.nlri.is_empty() {
            if let Some(attr) = u.attributes.get(AttrType::MpUnreachNlri) {
                // EoR marker = MP_UNREACH with just the 3-byte AFI/SAFI
                // prefix and no NLRI bytes. We do not need to fully decode
                // the (possibly labelled) NLRI — just check the length.
                if attr.value.len() == 3 && u.attributes.len() == 1 {
                    let fam = NlriFamily {
                        afi: u16::from_be_bytes([attr.value[0], attr.value[1]]),
                        safi: attr.value[2],
                    };
                    actions.push(BgpAction::EndOfRib(fam));
                }
            } else if u.attributes.is_empty() && self.cfg.ipv4_unicast_active() {
                // RFC 4724 §4: an empty UPDATE is the End-of-RIB marker for
                // IPv4 unicast (the implicit family). Only emit it when
                // IPv4 unicast is active for this peer (FRR `bgp default
                // ipv4-unicast` semantics, W2.1) — a peer that is not
                // activated for IPv4 unicast must not signal convergence
                // for it.
                actions.push(BgpAction::EndOfRib(NlriFamily::IPV4_UNICAST));
            }
        }

        let topo = self.cfg.compute_topology();
        let origin = RouteOrigin {
            // Convention (consumed by best_path / the safety net):
            // 0 = eBGP-learned, 1 = iBGP-learned.
            proto: u32::from(topo.role.is_internal()),
            peer: self.cfg.peer_id,
        };

        // --- Withdrawals (IPv4 legacy section) ---
        // FRR `no bgp default ipv4-unicast` (W2.1): a peer not activated
        // for IPv4 unicast must not have its legacy-section withdrawals
        // processed — silently drop them (the peer should not be sending
        // them in the first place, but we fail closed).
        if self.cfg.ipv4_unicast_active() {
            for w in &u.withdrawn {
                actions.push(BgpAction::WithdrawRoute {
                    key: RouteKey::new(w.prefix, NlriFamily::IPV4_UNICAST),
                    path_id: w.path_id,
                });
            }
        }

        // --- MP_UNREACH_NLRI withdrawals (RFC 4760 + RFC 8277) ---
        // The plain MP_UNREACH decoder assumes NLRI is `<plen><prefix>`;
        // RFC 8277 labelled NLRI is `<plen><labels><prefix>`. Dispatch on
        // the family read from the first 3 bytes of the attribute value so
        // labelled families go through the labelled decoder only.
        #[cfg(feature = "labeled_unicast")]
        if let Some(attr) = u.attributes.get(crate::path::AttrType::MpUnreachNlri) {
            if attr.value.len() >= 3 {
                let fam = NlriFamily {
                    afi: u16::from_be_bytes([attr.value[0], attr.value[1]]),
                    safi: attr.value[2],
                };
                let add_path = self.add_path_rx_for(fam);
                if fam.is_labeled_unicast() {
                    if let Some((family, entries)) =
                        crate::path::decode_labeled_mp_unreach(&attr.value, add_path)
                    {
                        for e in &entries {
                            actions.push(BgpAction::WithdrawRoute {
                                key: RouteKey::new(e.prefix, family),
                                path_id: e.path_id,
                            });
                        }
                    }
                } else if let Some(mp) = crate::path::MpUnreach::decode_ex(&attr.value, add_path) {
                    for w in &mp.nlri {
                        actions.push(BgpAction::WithdrawRoute {
                            key: RouteKey::new(w.prefix, mp.family),
                            path_id: w.path_id,
                        });
                    }
                }
            }
        }
        #[cfg(not(feature = "labeled_unicast"))]
        if let Some(mp) = u
            .attributes
            .mp_unreach_with(|fam| self.add_path_rx_for(fam))
        {
            for w in &mp.nlri {
                actions.push(BgpAction::WithdrawRoute {
                    key: RouteKey::new(w.prefix, mp.family),
                    path_id: w.path_id,
                });
            }
        }

        // --- Announcements ---
        // A valid announcement needs at least ORIGIN, AS_PATH and NEXT_HOP
        // (RFC 4271 §6.3); rather than tearing the session down we skip
        // malformed NLRI — the safety net at the router layer reports it.
        // The NEXT_HOP may live in the well-known attribute (IPv4) or in
        // MP_REACH_NLRI (RFC 4760 / RFC 8277) — checking for the attribute's
        // presence is enough; the per-family decoder validates the body.
        let attrs_ok = u.attributes.origin().is_some()
            && (u.attributes.as_path().is_some() || u.attributes.as4_path().is_some())
            && (u.attributes.next_hop().is_some()
                || u.attributes.get(AttrType::MpReachNlri).is_some());

        // Normalize the attribute bag: the route's internal AS_PATH is
        // always 4-byte-encoded (canonical form) so that downstream
        // consumers (best-path, safety net, egress) never have to guess the
        // wire width. AS4_PATH (RFC 6793 transition) is merged in per
        // §4.2.3 (count comparison + leading-segment reconstruction) and
        // dropped.
        let mut normalized: PathAttributes = u.attributes.clone();

        // W6.3 exchange-plane ingress (feature `exchange-plane`): take
        // over the wire attribute (type 251) before the bag is normalized
        // into route state. When the plane is active on this session the
        // records are verified (nonce echo → sequence → tag, design §6)
        // and parked in the private record store so the router can expose
        // the scope-1 classes and egress can re-sign the provenance
        // chain (design §7). When the plane is inactive the attribute is
        // left in the bag as unknown optional-transitive forwarding
        // material — the §5.3 relay pass below marks it Partial, exactly
        // like any other attribute this session does not understand.
        #[cfg(feature = "exchange-plane")]
        {
            let wire = normalized.remove(AttrType::Other(
                crate::extensions::exchange_plane::ATTRIBUTE_TYPE,
            ));
            if let Some(store) = self.consume_exchange_plane(wire.as_ref(), &mut actions) {
                normalized.insert(store);
            }
        }

        // RFC 4271 §5.3 relay processing for unknown optional attributes:
        // a transitive attribute this speaker does not interpret is
        // forwarded with the Partial bit set; an optional NON-transitive
        // attribute is never propagated (locally significant to the
        // peering). Without this the bag would silently re-emit received
        // unknown attributes with their original flags.
        let unknown_non_transitive: Vec<AttrType> = normalized
            .iter_mut()
            .filter_map(|a| {
                if !matches!(a.attr_type, AttrType::Other(_)) {
                    return None;
                }
                if a.flags.transitive() {
                    a.flags = a.flags.set_partial(true);
                    None
                } else {
                    Some(a.attr_type)
                }
            })
            .collect();
        for t in unknown_non_transitive {
            normalized.remove(t);
        }

        let wire_path = normalized.as_path_wire(self.cfg.asn4);
        let as4 = normalized.as4_path();
        let canonical_path = match &wire_path {
            Some(w) => crate::path::as_path::reconcile_as4(w, as4.as_ref()),
            None => as4.unwrap_or_default(),
        };
        normalized.remove(AttrType::As4Path);
        if !canonical_path.segments.is_empty() {
            normalized.insert(PathAttribute::new(
                PathAttrFlags::new().set_transitive(true),
                AttrType::AsPath,
                canonical_path.encode_4(),
            ));
        }

        // RFC 5065 §5: AS_CONFED_SEQUENCE / AS_CONFED_SET segments are
        // valid only between members of the same confederation. A peer
        // that is not a member of the local confederation (including the
        // no-confederation case) MUST NOT send them; receiving them is a
        // malformed AS_PATH. Consistent with the malformed-NLRI posture
        // above, the routes are rejected rather than tearing the session
        // down — the safety net surfaces the rejection so the operator
        // sees the misbehaving peer.
        let confed_peer = self
            .cfg
            .confederation
            .as_ref()
            .map(|c| c.contains(self.cfg.peer_as.0))
            .unwrap_or(false);
        let mut attrs_ok = attrs_ok;
        if !confed_peer && canonical_path.has_confed() {
            attrs_ok = false;
            actions.push(BgpAction::Emit(lr_core::event::Event::Log(format!(
                "bgp: peer {}: AS_PATH carries AS_CONFED_* segments from a non-confederation peer (RFC 5065 §5); routes rejected",
                self.cfg.peer_as
            ))));
        }

        let announce = |prefix: lr_core::addr::Prefix,
                        family: NlriFamily,
                        path_id: u32,
                        next_hop: Option<lr_core::addr::IpAddr>,
                        actions: &mut Vec<BgpAction>| {
            if !attrs_ok {
                return;
            }
            let metric = canonical_path.length() as u32;
            let route = Route {
                key: RouteKey::new(prefix, family),
                origin,
                protocol: Protocol::Bgp,
                preference: Preference::new(Protocol::Bgp.default_admin_distance(), metric),
                next_hop,
                attributes: normalized.clone().into(),
                age_ms: 0, // stamped by the router when it imports
                path_id,
                tag: None,
            };
            actions.push(BgpAction::InstallRoute(route));
        };

        // IPv4 NLRI: NEXT_HOP from the well-known attribute.
        // FRR `no bgp default ipv4-unicast` (W2.1): a peer not activated
        // for IPv4 unicast must not have its legacy-section NLRI installed
        // — silently drop the entries (the peer should not be sending
        // them, but failing closed is the safe posture).
        if !u.nlri.is_empty() && self.cfg.ipv4_unicast_active() {
            let nh = u.attributes.next_hop().map(|n| n.to_ip());
            for entry in &u.nlri {
                announce(
                    entry.prefix,
                    NlriFamily::IPV4_UNICAST,
                    entry.path_id,
                    nh,
                    &mut actions,
                );
            }
        }

        // MP_REACH_NLRI (RFC 4760 + RFC 8277): family + next-hop from the
        // attribute. For labelled families the NLRI carries a label stack
        // before the prefix; the route stores it under the private
        // `LrMplsLabelStack` attribute so egress can put it back into the
        // NLRI on re-advertisement.
        if let Some(attr) = u.attributes.get(AttrType::MpReachNlri) {
            #[cfg(feature = "labeled_unicast")]
            if attr.value.len() >= 3 {
                let fam = NlriFamily {
                    afi: u16::from_be_bytes([attr.value[0], attr.value[1]]),
                    safi: attr.value[2],
                };
                let add_path = self.add_path_rx_for(fam);
                if fam.is_labeled_unicast() {
                    if let Some((family, mp_nh, entries)) =
                        crate::path::decode_labeled_mp_reach(&attr.value, add_path)
                    {
                        let nh = mp_next_hop_to_ip(&mp_nh);
                        for e in &entries {
                            let mut attrs = normalized.clone();
                            attrs.set_label_stack(&e.label_stack);
                            let metric = canonical_path.length() as u32;
                            if attrs_ok {
                                let route = Route {
                                    key: RouteKey::new(e.prefix, family),
                                    origin,
                                    protocol: Protocol::Bgp,
                                    preference: Preference::new(
                                        Protocol::Bgp.default_admin_distance(),
                                        metric,
                                    ),
                                    next_hop: nh,
                                    attributes: attrs.into(),
                                    age_ms: 0,
                                    path_id: e.path_id,
                                    tag: None,
                                };
                                actions.push(BgpAction::InstallRoute(route));
                            }
                        }
                    }
                } else if let Some(mp) = crate::path::MpReach::decode_ex(&attr.value, add_path) {
                    let nh = mp_next_hop_to_ip(&mp.next_hop);
                    for entry in &mp.nlri {
                        announce(entry.prefix, mp.family, entry.path_id, nh, &mut actions);
                    }
                }
            }
            #[cfg(not(feature = "labeled_unicast"))]
            if let Some(mp) = u.attributes.mp_reach_with(|fam| self.add_path_rx_for(fam)) {
                let nh = mp_next_hop_to_ip(&mp.next_hop);
                for entry in &mp.nlri {
                    announce(entry.prefix, mp.family, entry.path_id, nh, &mut actions);
                }
            }
        }

        actions
    }
}

/// Convert an [`MpNextHop`] into the [`IpAddr`] carried by a route.
fn mp_next_hop_to_ip(nh: &crate::path::MpNextHop) -> Option<lr_core::addr::IpAddr> {
    match nh {
        crate::path::MpNextHop::V4(b) => Some(lr_core::addr::IpAddr::V4(*b)),
        crate::path::MpNextHop::V6Global(b)
        | crate::path::MpNextHop::V6LinkLocal(b)
        | crate::path::MpNextHop::V6GlobalLinkLocal(b, _)
        | crate::path::MpNextHop::V4OverV6(b) => Some(lr_core::addr::IpAddr::V6(*b)),
    }
}

impl StateMachine for BgpPeer {
    type State = BgpState;
    type Event = BgpEvent;
    fn state(&self) -> Self::State {
        self.state
    }
    fn step(&mut self, ev: Self::Event) -> Vec<Action> {
        // Reuse our own step() that returns BgpAction, then convert.
        let bgp_actions = BgpPeer::step(self, ev);
        bgp_actions
            .into_iter()
            .map(|a| match a {
                BgpAction::Send(b) => Action::Send(b),
                BgpAction::SetTimer(id, spec) => Action::SetTimer(id, spec),
                BgpAction::CancelTimer(id) => Action::CancelTimer(id),
                BgpAction::Close => Action::Close,
                BgpAction::Emit(ev) => Action::EmitEvent(ev),
                BgpAction::InstallRoute(r) => Action::InstallRoute(r),
                BgpAction::WithdrawRoute { key, path_id } => Action::WithdrawRoute { key, path_id },
                // The generic core FSM has no route-refresh-specific action;
                // router-aware embedders consume it through `BgpAction`.
                BgpAction::RouteRefreshRequested(_) => Action::None,
                BgpAction::EndOfRib(_) => Action::None,
                BgpAction::None => Action::None,
            })
            .collect()
    }
    fn reset(&mut self) {
        BgpPeer::reset(self);
    }
}

#[cfg(test)]
#[path = "fsm_tests.rs"]
mod tests;
