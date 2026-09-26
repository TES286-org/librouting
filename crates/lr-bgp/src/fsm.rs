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
    }

    /// Whether a Cease / Connection Collision Resolution NOTIFICATION
    /// (RFC 4486 subcode 7) arrived since the last [`BgpPeer::reset`].
    /// The embedder combines this with the FSM going Idle to recognise a
    /// lost §6.8 collision (as opposed to every other Idle cause) and
    /// stop hammering a peer that already holds a live session.
    pub fn received_cease_collision(&self) -> bool {
        self.received_cease_collision
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
mod tests {
    use super::*;
    use crate::message::update::Nlri;
    use crate::path::AsPath;
    #[cfg(feature = "exchange-plane")]
    use lr_core::addr::IpAddr;
    use lr_core::addr::Prefix;

    fn make_peer_pair() -> (BgpPeer, BgpPeer) {
        let cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        let cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        (BgpPeer::new(cfg1), BgpPeer::new(cfg2))
    }

    #[test]
    fn basic_establishment() {
        let (mut a, mut b) = make_peer_pair();
        // Start both peers; each enqueues OPEN.
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        // Drain OPENs from each.
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        // A's OPEN is 19-byte header + body.
        assert!(a_open.len() >= 29);
        assert_eq!(a_open[18], 1); // type = OPEN
                                   // Cross-feed OPENs.
        let _ = b.feed_bytes(&a_open).unwrap();
        assert_eq!(b.state(), BgpState::OpenConfirm);
        let _ = a.feed_bytes(&b_open).unwrap();
        assert_eq!(a.state(), BgpState::OpenConfirm);
        // Drain KEEPALIVEs each enqueued in OpenConfirm.
        let b_ka = b.drain_outgoing();
        assert_eq!(b_ka[18], 4); // type = KEEPALIVE
        let a_ka = a.drain_outgoing();
        assert_eq!(a_ka[18], 4);
        // Cross-feed KEEPALIVEs → both go Established.
        let _ = a.feed_bytes(&b_ka).unwrap();
        assert!(a.is_established());
        let _ = b.feed_bytes(&a_ka).unwrap();
        assert!(b.is_established());
    }

    #[test]
    fn open_with_4byte_asn_capability() {
        let cfg = PeerConfig::new(Asn(70000), Asn(80000), RouterId::from_v4([10, 0, 0, 1]));
        let mut peer = BgpPeer::new(cfg);
        peer.step(BgpEvent::ManualStart);
        peer.step(BgpEvent::TransportOpen);
        let out = peer.drain_outgoing();
        let body = &out[19..];
        assert_eq!(body[0], 4); // version
        let as16 = u16::from_be_bytes([body[1], body[2]]);
        assert_eq!(as16, 23456); // AS_TRANS
    }

    #[test]
    fn reset_clears_state() {
        let mut p = BgpPeer::new(PeerConfig::new(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([1, 2, 3, 4]),
        ));
        p.step(BgpEvent::ManualStart);
        p.step(BgpEvent::TransportOpen);
        assert_eq!(p.state(), BgpState::OpenSent);
        p.reset();
        assert_eq!(p.state(), BgpState::Idle);
        assert!(!p.is_established());
    }

    /// RFC 6793 §4.2.2: when the peer's OPEN lacks the 4-octet-AS
    /// capability the session must downgrade both directions to 2-byte
    /// AS_PATH encoding — BIRD/FRR would reject 4-byte paths otherwise.
    #[test]
    fn as4_downgrades_when_peer_lacks_capability() {
        let mut peer = BgpPeer::new(PeerConfig::new(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 1]),
        ));
        peer.step(BgpEvent::ManualStart);
        peer.step(BgpEvent::TransportOpen);
        assert!(peer.cfg.asn4); // we advertise the capability
                                // Hand-craft an OPEN *without* any capabilities.
        let open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 2]));
        let (state, _) = {
            // handle_open_in_opensent is private; drive through step().
            let ev = BgpEvent::Message(BgpMessage::Open(open));
            let actions = peer.step(ev);
            (peer.state(), actions)
        };
        let _ = state;
        // The downgrade applies to the codec for the session's lifetime,
        // not to the configured capability — a re-establishment must
        // re-negotiate fresh (RFC 6793 negotiation is per-session).
        assert!(peer.cfg.asn4, "configured capability is unchanged");
        assert!(
            !peer.codec.asn4_active(),
            "session codec must downgrade to 2-byte AS_PATH"
        );
    }

    /// RFC 4271 §6.8: a NOTIFICATION received in Established tears the
    /// session down to Idle instead of being ignored.
    #[test]
    fn notification_tears_down_established_session() {
        let (mut a, mut b) = make_peer_pair();
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        let _ = a.feed_bytes(&b_open).unwrap();
        let _ = b.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        let _ = a.feed_bytes(&b_ka).unwrap();
        let _ = b.feed_bytes(&a_ka).unwrap();
        assert!(a.is_established());

        let n = BgpNotification::new(4, 0, vec![]); // Hold Timer Expired
        let actions = a.step(BgpEvent::Message(BgpMessage::Notification(n)));
        assert_eq!(a.state(), BgpState::Idle);
        assert!(!a.is_established());
        assert!(actions.iter().any(|x| matches!(x, BgpAction::Close)));
    }

    /// RFC 4271 §6: malformed inbound data must raise the required
    /// NOTIFICATION and close the session instead of surfacing a generic
    /// parse error to the embedder.
    #[test]
    fn malformed_update_produces_notification_and_closes() {
        let (mut a, mut b) = make_peer_pair();
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
        let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
        let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
        let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
        assert!(a.is_established());

        // Craft an UPDATE with a duplicate well-known attribute (RFC 4271
        // §6.3 Malformed Attribute List): two ORIGIN attributes.
        let mut frame = vec![0xffu8; 16];
        frame.extend_from_slice(&(19 + 12u16).to_be_bytes());
        frame.push(2); // UPDATE
        frame.extend_from_slice(&0u16.to_be_bytes()); // withdrawn len
        frame.extend_from_slice(&8u16.to_be_bytes()); // attrs len
                                                      // ORIGIN(1) flags=0x40, len=1, value=0
        frame.extend_from_slice(&[0x40, 1, 1, 0]);
        // ORIGIN(1) again — duplicate.
        frame.extend_from_slice(&[0x40, 1, 1, 0]);
        // No NLRI.
        let actions = a.feed_bytes(&frame).unwrap();
        assert_eq!(
            a.state(),
            BgpState::Idle,
            "malformed UPDATE must close the session"
        );
        assert!(!a.is_established());
        assert!(actions.iter().any(|x| matches!(x, BgpAction::Close)));
        // The peer must receive the NOTIFICATION (Malformed Attribute List:
        // code 3, subcode 1).
        let out = a.drain_outgoing();
        assert!(!out.is_empty(), "a NOTIFICATION must be sent");
        assert_eq!(out[18], 3, "message type = NOTIFICATION");
        assert_eq!(out[19], 3, "error code = UPDATE Message Error");
        assert_eq!(out[20], 1, "subcode = Malformed Attribute List");
    }

    /// `PeerMessageStats` counts every message at the wire boundary:
    /// the establishment handshake books one OPEN + one KEEPALIVE per
    /// direction, and a received NOTIFICATION books on the receiving
    /// side even though it tears the session down.
    #[test]
    fn message_stats_count_wire_exchange() {
        let (mut a, mut b) = make_peer_pair();
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        let _ = a.feed_bytes(&b_open).unwrap();
        let _ = b.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        let _ = a.feed_bytes(&b_ka).unwrap();
        let _ = b.feed_bytes(&a_ka).unwrap();
        assert!(a.is_established());

        for p in [&a, &b] {
            let s = p.message_stats();
            assert_eq!(s.open_sent, 1, "one OPEN sent");
            assert_eq!(s.open_received, 1, "one OPEN received");
            assert_eq!(s.keepalive_sent, 1, "one KEEPALIVE sent");
            assert_eq!(s.keepalive_received, 1, "one KEEPALIVE received");
            assert_eq!(s.update_sent, 0);
            assert_eq!(s.update_received, 0);
            assert_eq!(s.notification_sent, 0);
            assert_eq!(s.notification_received, 0);
            assert_eq!(s.route_refresh_sent, 0);
            assert_eq!(s.route_refresh_received, 0);
        }

        // A wire NOTIFICATION from the peer counts on the receiver;
        // sending it as real bytes (marker + len + type 3 + code/sub)
        // exercises the decode path the daemon uses.
        let mut frame = vec![0xffu8; 16];
        frame.extend_from_slice(&21u16.to_be_bytes()); // 19 header + code + sub
        frame.push(3); // NOTIFICATION
        frame.push(4); // Hold Timer Expired
        frame.push(0); // subcode
        let _ = a.feed_bytes(&frame).unwrap();
        assert_eq!(a.message_stats().notification_received, 1);
        assert_eq!(a.message_stats().notification_sent, 0);
    }

    /// `reset()` (a session re-establishment) must NOT zero the
    /// message counters — FRR's per-neighbor statistics survive flaps.
    #[test]
    fn message_stats_survive_reset() {
        let (mut a, mut b) = make_peer_pair();
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
        let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
        let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
        let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
        assert!(a.is_established());
        assert_eq!(a.message_stats().open_sent, 1);

        a.reset();
        assert_eq!(a.state(), BgpState::Idle);
        assert_eq!(a.message_stats().open_sent, 1, "counters survive reset");
        assert_eq!(a.message_stats().open_received, 1);
        assert_eq!(a.message_stats().keepalive_received, 1);
    }

    /// A parse error produces the NOTIFICATION on the outbound side:
    /// the required NOTIFICATION counts as sent. The malformed UPDATE
    /// itself never decodes (codec-level error), so it does not book
    /// `update_received` — counting is post-decode, and a PDU that
    /// fails structural validation never becomes a message.
    #[test]
    fn message_stats_count_parse_error_exchange() {
        let (mut a, mut b) = make_peer_pair();
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
        let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
        let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
        let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
        assert!(a.is_established());

        // Malformed UPDATE (duplicate ORIGIN — RFC 4271 §6.3).
        let mut frame = vec![0xffu8; 16];
        frame.extend_from_slice(&(19 + 12u16).to_be_bytes());
        frame.push(2); // UPDATE
        frame.extend_from_slice(&0u16.to_be_bytes()); // withdrawn len
        frame.extend_from_slice(&8u16.to_be_bytes()); // attrs len
        frame.extend_from_slice(&[0x40, 1, 1, 0]); // ORIGIN
        frame.extend_from_slice(&[0x40, 1, 1, 0]); // duplicate ORIGIN
        let _ = a.feed_bytes(&frame).unwrap();
        assert_eq!(a.state(), BgpState::Idle);
        let _ = a.drain_outgoing();

        let s = a.message_stats();
        assert_eq!(
            s.update_received, 0,
            "a structurally invalid PDU is not a message"
        );
        assert_eq!(s.notification_sent, 1, "the required NOTIFICATION was sent");
    }

    #[test]
    fn route_refresh_is_negotiated_and_dispatched() {
        let (mut a, mut b) = make_peer_pair();
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        a.feed_bytes(&b_open).unwrap();
        b.feed_bytes(&a_open).unwrap();
        let a_keepalive = a.drain_outgoing();
        let b_keepalive = b.drain_outgoing();
        a.feed_bytes(&b_keepalive).unwrap();
        b.feed_bytes(&a_keepalive).unwrap();

        assert!(a.route_refresh_negotiated());
        assert!(a.enhanced_route_refresh_negotiated());
        assert!(a.request_route_refresh(NlriFamily::IPV4_UNICAST));
        let request = a.drain_outgoing();
        let actions = b.feed_bytes(&request).unwrap();
        assert!(actions.iter().any(|action| {
            matches!(
                action,
                BgpAction::RouteRefreshRequested(NlriFamily { afi: 1, safi: 1 })
            )
        }));
    }

    #[test]
    fn enhanced_route_refresh_emits_demarcation_messages() {
        let (mut a, mut b) = make_peer_pair();
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        a.feed_bytes(&b_open).unwrap();
        b.feed_bytes(&a_open).unwrap();
        let a_keepalive = a.drain_outgoing();
        let b_keepalive = b.drain_outgoing();
        a.feed_bytes(&b_keepalive).unwrap();
        b.feed_bytes(&a_keepalive).unwrap();

        assert!(a.begin_enhanced_route_refresh(NlriFamily::IPV4_UNICAST));
        assert!(a.end_enhanced_route_refresh(NlriFamily::IPV4_UNICAST));
        let bytes = a.drain_outgoing();
        let mut codec = BgpCodec::new();
        let first = codec.decode_slice(&bytes).unwrap().unwrap();
        let second = codec.decode_slice(&[]).unwrap().unwrap();
        assert_eq!(
            first,
            BgpMessage::RouteRefresh(crate::message::RouteRefresh::begin_of_rib(
                NlriFamily::IPV4_UNICAST
            ))
        );
        assert_eq!(
            second,
            BgpMessage::RouteRefresh(crate::message::RouteRefresh::end_of_rib(
                NlriFamily::IPV4_UNICAST
            ))
        );
    }

    #[test]
    fn route_refresh_requires_negotiated_capability() {
        let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg.route_refresh = false;
        let peer = BgpPeer::new(cfg);
        assert!(!peer.route_refresh_negotiated());
    }

    /// A peer that *does* offer the AS4 capability keeps 4-byte encoding.
    #[test]
    fn as4_kept_when_peer_offers_capability() {
        let mut peer = BgpPeer::new(PeerConfig::new(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 1]),
        ));
        peer.step(BgpEvent::ManualStart);
        peer.step(BgpEvent::TransportOpen);
        let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 2]));
        open.params.push(crate::message::open::OpenParam {
            param_type: crate::message::open::OpenParam::PARAM_TYPE_CAPABILITY,
            value: Capability::encode_set(&[Capability::four_octet_as(64513)]),
        });
        peer.step(BgpEvent::Message(BgpMessage::Open(open)));
        assert!(peer.cfg.asn4, "4-byte encoding must be negotiated up");
    }

    /// W6.3 exchange-plane prototype: both speakers configure the plane
    /// and exchange OPENs — the negotiation activates with the shared
    /// key and each side's nonces in the right places.
    #[cfg(feature = "exchange-plane")]
    #[test]
    fn exchange_plane_negotiates_when_both_sides_advertise() {
        use crate::extensions::exchange_plane::{ExchangeKey, ExchangePlaneConfig};

        let nonce_a = [1u8; 8];
        let nonce_b = [2u8; 8];
        let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));

        let mut xp_a = ExchangePlaneConfig::new(nonce_a);
        xp_a.keys = vec![ExchangeKey::hmac_sha256(1, "alpha")];
        let mut xp_b = ExchangePlaneConfig::new(nonce_b);
        xp_b.keys = vec![
            ExchangeKey::hmac_sha256(1, "alpha"),
            ExchangeKey::hmac_sha256(2, "beta"),
        ];
        a.set_exchange_plane(xp_a);
        b.set_exchange_plane(xp_b);

        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        a.feed_bytes(&b_open).unwrap();
        b.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        a.feed_bytes(&b_ka).unwrap();
        b.feed_bytes(&a_ka).unwrap();
        assert!(a.is_established() && b.is_established());

        // Each side mixes its OPEN instance counter into the advertised
        // nonce (first OPEN = counter 1 → the last four octets differ
        // from the configured nonce by 0x00000001). The session binds to
        // the advertised values.
        let mixed = |n: [u8; 8]| {
            let mut m = n;
            m[7] ^= 1;
            m
        };
        let session_a = a.exchange_plane_session().expect("activated on a");
        assert_eq!(session_a.peer_nonce, mixed(nonce_b));
        assert_eq!(session_a.local_nonce, mixed(nonce_a));
        assert_eq!(session_a.keys.len(), 1);
        assert_eq!(session_a.keys[0].id, 1);

        let session_b = b.exchange_plane_session().expect("activated on b");
        assert_eq!(session_b.peer_nonce, mixed(nonce_a));
        assert_eq!(session_b.local_nonce, mixed(nonce_b));
    }

    /// W6.3 exchange-plane prototype: only one side configures the
    /// plane — the capability is advertised (RFC 5492 §3 makes it
    /// inert for the peer) but the negotiation stays off, and the
    /// session establishes normally.
    #[cfg(feature = "exchange-plane")]
    #[test]
    fn exchange_plane_stays_off_when_peer_lacks_capability() {
        use crate::extensions::exchange_plane::{ExchangeKey, ExchangePlaneConfig};

        let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));

        let mut xp = ExchangePlaneConfig::new([5u8; 8]);
        xp.keys = vec![ExchangeKey::hmac_sha256(1, "alpha")];
        a.set_exchange_plane(xp);

        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        // b has no exchange-plane config: b's OPEN handling must not
        // trip over a's capability (RFC 5492 §3 ignore rule).
        a.feed_bytes(&b_open).unwrap();
        b.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        a.feed_bytes(&b_ka).unwrap();
        b.feed_bytes(&a_ka).unwrap();
        assert!(a.is_established() && b.is_established());
        assert!(a.exchange_plane_session().is_none());
        assert!(b.exchange_plane_session().is_none());
    }

    // ----- W6.3 follow-up: attach/detach hooks over a live FSM pair -----

    #[cfg(feature = "exchange-plane")]
    fn establish_pair_with_plane(
        xp_a: Option<crate::extensions::exchange_plane::ExchangePlaneConfig>,
        xp_b: Option<crate::extensions::exchange_plane::ExchangePlaneConfig>,
    ) -> (BgpPeer, BgpPeer) {
        let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));
        if let Some(x) = xp_a {
            a.set_exchange_plane(x);
        }
        if let Some(x) = xp_b {
            b.set_exchange_plane(x);
        }
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        a.feed_bytes(&b_open).unwrap();
        b.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        a.feed_bytes(&b_ka).unwrap();
        b.feed_bytes(&a_ka).unwrap();
        assert!(a.is_established() && b.is_established());
        (a, b)
    }

    #[cfg(feature = "exchange-plane")]
    fn xp_config(
        nonce: [u8; 8],
        key_secret: &str,
    ) -> crate::extensions::exchange_plane::ExchangePlaneConfig {
        use crate::extensions::exchange_plane::{ExchangeKey, ExchangePlaneConfig};
        let mut cfg = ExchangePlaneConfig::new(nonce);
        cfg.keys = vec![ExchangeKey::hmac_sha256(1, key_secret)];
        cfg.origin_base_secs = 1_700_000_000;
        cfg
    }

    #[cfg(feature = "exchange-plane")]
    fn local_route(origin_proto: u32) -> Route {
        let mut attrs = PathAttributes::new();
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));
        let path = AsPath::from_sequence([64512].iter().copied().map(Asn));
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            path.encode_4(),
        ));
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::NextHop,
            vec![10, 0, 0, 1],
        ));
        Route {
            key: RouteKey::new(
                Prefix::new_v4([203, 0, 113, 0], 24),
                NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin {
                proto: origin_proto,
                peer: 7,
            },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 1),
            next_hop: Some(IpAddr::V4([10, 0, 0, 1])),
            attributes: attrs.into(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    #[cfg(feature = "exchange-plane")]
    fn decode_updates(bytes: &[u8]) -> Vec<Update> {
        use lr_core::codec::Decoder;
        let mut codec = BgpCodec::new().with_asn4(true);
        let mut out = Vec::new();
        let mut r = lr_core::buf::ReadBuf::new(bytes);
        while let Ok(Some(BgpMessage::Update(u))) = codec.decode(&mut r) {
            out.push(u);
        }
        out
    }

    /// The attach hook: a locally originated route advertised over a
    /// plane-active session carries the signed record-set attribute;
    /// the receiving peer verifies it and parks the record set in the
    /// private store on the installed route (no wire 251 in the bag).
    #[cfg(feature = "exchange-plane")]
    #[test]
    fn exchange_plane_attaches_and_verifies_over_live_session() {
        use crate::extensions::exchange_plane as xp;

        let (mut a, mut b) = establish_pair_with_plane(
            Some(xp_config([1u8; 8], "alpha")),
            Some(xp_config([2u8; 8], "alpha")),
        );
        let route = local_route(2); // locally originated
        assert!(a.advertise(&route));
        let bytes = a.drain_outgoing();

        // The wire UPDATE carries the exchange-plane attribute.
        let updates = decode_updates(&bytes);
        assert!(!updates.is_empty());
        let wire_attr = updates[0]
            .attributes
            .get(AttrType::Other(xp::ATTRIBUTE_TYPE))
            .expect("record-set attribute attached");
        let record = xp::ExchangeRecord::decode(&wire_attr.value).unwrap();
        assert!(
            record.verify(&crate::extensions::exchange_plane::ExchangeKey::hmac_sha256(1, "alpha"))
        );
        // Hint + origin attestation + our segment signature.
        assert!(matches!(record.records.first(), Some(xp::Record::Hint(_))));
        assert!(record
            .records
            .iter()
            .any(|r| matches!(r, xp::Record::Origin(_))));
        assert!(record
            .records
            .iter()
            .any(|r| matches!(r, xp::Record::Segment(_))));

        // B consumes the attribute: the installed route carries the
        // private store (verified kind) and no wire 251.
        let actions = b.feed_bytes(&bytes).unwrap();
        let installed = actions
            .iter()
            .find_map(|a| match a {
                BgpAction::InstallRoute(r) => Some(r.clone()),
                _ => None,
            })
            .expect("route installed");
        let bag: crate::path::PathAttributes = installed.attributes.into();
        assert!(bag.get(AttrType::Other(xp::ATTRIBUTE_TYPE)).is_none());
        let stored = bag
            .get(AttrType::LrExchangePlaneRecords)
            .expect("record store parked");
        let (kind, payload) = xp::load_store(&stored.value).expect("well-formed store");
        assert_eq!(kind, xp::STORE_VERIFIED);
        let stored_record = xp::ExchangeRecord::decode(payload).unwrap();
        assert_eq!(stored_record.records.len(), record.records.len());
    }

    /// The detach hook strips the wire attribute: egress rebuilds from
    /// the store, so a re-advertised route never carries the received
    /// scope-1 records (design §7) — and never two type-251 attributes.
    #[cfg(feature = "exchange-plane")]
    #[test]
    fn exchange_plane_scope1_records_do_not_leak() {
        use crate::extensions::exchange_plane as xp;

        let (mut a, mut b) = establish_pair_with_plane(
            Some(xp_config([1u8; 8], "alpha")),
            Some(xp_config([2u8; 8], "alpha")),
        );
        // A -> B: a transit-learned route (proto 0) still gets fresh
        // scope-1 records but no origin attestation.
        assert!(a.advertise(&local_route(0)));
        let bytes = a.drain_outgoing();
        let actions = b.feed_bytes(&bytes).unwrap();
        let installed = actions
            .iter()
            .find_map(|a| match a {
                BgpAction::InstallRoute(r) => Some(r.clone()),
                _ => None,
            })
            .expect("route installed");
        let bag: crate::path::PathAttributes = installed.attributes.into();
        let stored = bag.get(AttrType::LrExchangePlaneRecords).unwrap();
        let (_, payload) = xp::load_store(&stored.value).unwrap();
        let record = xp::ExchangeRecord::decode(payload).unwrap();
        assert!(record
            .records
            .iter()
            .any(|r| matches!(r, xp::Record::Hint(_))));
        assert!(!record
            .records
            .iter()
            .any(|r| matches!(r, xp::Record::Origin(_))));
    }

    /// Flag off = byte-identical egress: with the peer not advertising
    /// the capability, a session with the plane configured emits exactly
    /// the bytes a session without the plane emits.
    #[cfg(feature = "exchange-plane")]
    #[test]
    fn exchange_plane_one_sided_is_byte_identical() {
        // `a`: the plane is configured, but the dummy partner below does
        // not advertise the capability — the negotiation stays off.
        let (mut a, _b) = establish_pair_with_plane(Some(xp_config([1u8; 8], "alpha")), None);
        // `plain`: same peer config, no plane at all, established
        // against the same shape of dummy partner.
        let mut plain_cfg =
            PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        plain_cfg.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let mut dummy = BgpPeer::new(PeerConfig::new(
            Asn(64513),
            Asn(64512),
            RouterId::from_v4([10, 9, 9, 9]),
        ));
        let mut plain = BgpPeer::new(plain_cfg);
        plain.step(BgpEvent::ManualStart);
        plain.step(BgpEvent::TransportOpen);
        dummy.step(BgpEvent::ManualStart);
        dummy.step(BgpEvent::TransportOpen);
        let p_open = plain.drain_outgoing();
        let d_open = dummy.drain_outgoing();
        let _ = plain.feed_bytes(&d_open).unwrap();
        let _ = dummy.feed_bytes(&p_open).unwrap();
        let p_ka = plain.drain_outgoing();
        let d_ka = dummy.drain_outgoing();
        let _ = plain.feed_bytes(&d_ka).unwrap();
        let _ = dummy.feed_bytes(&p_ka).unwrap();
        assert!(plain.is_established());

        let route = local_route(2);
        let a_with = {
            let _ = a.advertise(&route);
            a.drain_outgoing()
        };
        let a_without = {
            let _ = plain.advertise(&route);
            plain.drain_outgoing()
        };
        assert_eq!(
            a_with, a_without,
            "one-sided plane must not change egress bytes"
        );
    }

    /// A record captured from one session instance replays into a fresh
    /// one (new OPEN nonces) and is dropped on the nonce check (design §6).
    #[cfg(feature = "exchange-plane")]
    #[test]
    fn exchange_plane_replay_across_sessions_is_dropped() {
        let (mut a, mut b) = establish_pair_with_plane(
            Some(xp_config([1u8; 8], "alpha")),
            Some(xp_config([2u8; 8], "alpha")),
        );
        assert!(a.advertise(&local_route(2)));
        let captured = a.drain_outgoing();
        let _ = b.feed_bytes(&captured).unwrap();

        // A fresh session instance: new OPEN nonces both sides.
        let (_a2, mut b2) = establish_pair_with_plane(
            Some(xp_config([9u8; 8], "alpha")),
            Some(xp_config([7u8; 8], "alpha")),
        );
        let actions = b2.feed_bytes(&captured).unwrap();
        assert!(actions.iter().any(|a| matches!(
            a,
            BgpAction::Emit(lr_core::event::Event::Log(msg))
                if msg.contains("foreign-session nonce")
        )));
        // The route's standard content survives (fail-open, design §8).
        assert!(actions
            .iter()
            .any(|a| matches!(a, BgpAction::InstallRoute(_))));
    }

    /// A tampered record body fails the tag check and is dropped with a
    /// log line, while the route itself still installs.
    #[cfg(feature = "exchange-plane")]
    #[test]
    fn exchange_plane_tampered_record_is_dropped() {
        let (mut a, mut b) = establish_pair_with_plane(
            Some(xp_config([1u8; 8], "alpha")),
            Some(xp_config([2u8; 8], "alpha")),
        );
        assert!(a.advertise(&local_route(2)));
        let bytes = a.drain_outgoing();

        // Decode the UPDATE, flip a bit inside the record-set value (the
        // authentication tag covers it) and re-encode.
        let mut updates = decode_updates(&bytes);
        let u = updates.last_mut().expect("update present");
        let attr = u
            .attributes
            .get_mut(AttrType::Other(
                crate::extensions::exchange_plane::ATTRIBUTE_TYPE,
            ))
            .expect("record attribute");
        let tag_start = attr.value.len() - 32;
        attr.value[tag_start] ^= 0x01;
        let codec = BgpCodec::new().with_asn4(true);
        let wire = codec.encode_vec(&BgpMessage::Update(u.clone())).unwrap();

        let actions = b.feed_bytes(&wire).unwrap();
        assert!(actions.iter().any(|a| matches!(
            a,
            BgpAction::Emit(lr_core::event::Event::Log(msg))
                if msg.contains("tag mismatch") || msg.contains("malformed")
        )));
        assert!(actions
            .iter()
            .any(|a| matches!(a, BgpAction::InstallRoute(_))));
    }

    /// RFC 4271 §5.3 relay processing: an unknown optional-transitive
    /// attribute is forwarded with Partial set; an optional
    /// NON-transitive one is not propagated. (Unconditional code —
    /// tested without the exchange-plane feature too.)
    #[test]
    fn unknown_attribute_relay_sets_partial_and_drops_non_transitive() {
        let (mut a, _b) = make_peer_pair();
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        let mut dummy = BgpPeer::new(PeerConfig::new(
            Asn(64513),
            Asn(64512),
            RouterId::from_v4([10, 9, 9, 9]),
        ));
        dummy.step(BgpEvent::ManualStart);
        dummy.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let d_open = dummy.drain_outgoing();
        let _ = a.feed_bytes(&d_open).unwrap();
        let _ = dummy.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let d_ka = dummy.drain_outgoing();
        let _ = a.feed_bytes(&d_ka).unwrap();
        let _ = dummy.feed_bytes(&a_ka).unwrap();
        assert!(a.is_established());

        // Build an UPDATE carrying (1) an unknown transitive attr with
        // flags 0xC0 and (2) an unknown optional non-transitive attr
        // with flags 0x80.
        let mut u = Update::new();
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true).set_transitive(true),
            AttrType::Other(250),
            vec![1, 2, 3],
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true),
            AttrType::Other(249),
            vec![4, 5],
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));
        let path = AsPath::from_sequence([64513].iter().copied().map(Asn));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            path.encode_4(),
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::NextHop,
            vec![10, 0, 0, 2],
        ));
        u.nlri
            .push(Nlri::plain(Prefix::new_v4([198, 51, 100, 0], 24)));
        let codec = BgpCodec::new().with_asn4(true);
        let wire = codec.encode_vec(&BgpMessage::Update(u)).unwrap();
        let actions = a.feed_bytes(&wire).unwrap();
        let installed = actions
            .iter()
            .find_map(|a| match a {
                BgpAction::InstallRoute(r) => Some(r.clone()),
                _ => None,
            })
            .expect("route installed");
        let bag: crate::path::PathAttributes = installed.attributes.into();
        let relayed = bag
            .get(AttrType::Other(250))
            .expect("transitive unknown forwarded");
        assert!(relayed.flags.partial(), "Partial bit set per RFC 4271 §5.3");
        assert!(
            bag.get(AttrType::Other(249)).is_none(),
            "optional non-transitive unknown not propagated"
        );
    }

    fn establish_llgr_pair() -> (BgpPeer, BgpPeer) {
        let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg1.graceful_restart = true;
        cfg1.graceful_restart_time = 90;
        cfg1.long_lived = true;
        cfg1.long_lived_stale_time = 3600;
        cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        cfg2.graceful_restart = true;
        cfg2.graceful_restart_time = 120;
        cfg2.long_lived = true;
        cfg2.long_lived_stale_time = 1800;
        cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        a.feed_bytes(&b_open).unwrap();
        b.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        a.feed_bytes(&b_ka).unwrap();
        b.feed_bytes(&a_ka).unwrap();
        (a, b)
    }

    #[test]
    fn llgr_negotiated_after_open_exchange() {
        let (a, b) = establish_llgr_pair();
        assert!(a.is_established() && b.is_established());
        // Both sides see LLGR negotiated and the *peer's* LLST per family.
        assert!(a.llgr_negotiated());
        assert_eq!(
            a.negotiated_llgr_stale_time(NlriFamily::IPV4_UNICAST),
            Some(1800)
        );
        assert!(b.llgr_negotiated());
        assert_eq!(
            b.negotiated_llgr_stale_time(NlriFamily::IPV4_UNICAST),
            Some(3600)
        );
        // Restart time comes from the peer's GR capability.
        assert_eq!(a.negotiated_graceful_restart_time(), Some(120));
        assert_eq!(b.negotiated_graceful_restart_time(), Some(90));
    }

    /// RFC 9494 §4.5: an LLGR capability received without the GR
    /// capability MUST be ignored.
    #[test]
    fn llgr_without_gr_capability_is_ignored() {
        let mut peer = BgpPeer::new(PeerConfig::new(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 1]),
        ));
        peer.cfg.graceful_restart = true;
        peer.cfg.long_lived = true;
        peer.step(BgpEvent::ManualStart);
        peer.step(BgpEvent::TransportOpen);
        // Peer offers LLGR (71) but no GR (64).
        let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 2]));
        open.params.push(crate::message::open::OpenParam {
            param_type: crate::message::open::OpenParam::PARAM_TYPE_CAPABILITY,
            value: Capability::encode_set(&[Capability::long_lived_gr(&[(1, 1, true, 600)])]),
        });
        peer.step(BgpEvent::Message(BgpMessage::Open(open)));
        assert!(!peer.llgr_negotiated());
        assert_eq!(
            peer.negotiated_llgr_stale_time(NlriFamily::IPV4_UNICAST),
            None
        );
    }

    /// Families not listed in the peer's LLGR capability are deemed zero
    /// (RFC 9494 §4.2) — LLGR is negotiated but grants no extra retention.
    #[test]
    fn unlisted_family_has_zero_llst() {
        let (a, _) = establish_llgr_pair();
        assert_eq!(
            a.negotiated_llgr_stale_time(NlriFamily::IPV6_UNICAST),
            Some(0)
        );
    }

    /// RFC 4724 §4: an empty UPDATE is the End-of-RIB marker.
    #[test]
    fn empty_update_is_end_of_rib() {
        let (mut a, _b) = establish_llgr_pair();
        let actions = a.step(BgpEvent::Message(BgpMessage::Update(Update::new())));
        assert!(actions
            .iter()
            .any(|x| matches!(x, BgpAction::EndOfRib(NlriFamily::IPV4_UNICAST))));
    }

    /// A non-empty UPDATE carrying a route must NOT be mistaken for EoR.
    #[test]
    fn route_update_is_not_end_of_rib() {
        use crate::message::update::Update;
        let (mut a, _b) = establish_llgr_pair();
        let mut u = Update::new();
        u.nlri.push(crate::message::update::Nlri::plain(
            lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));
        let actions = a.step(BgpEvent::Message(BgpMessage::Update(u)));
        assert!(!actions.iter().any(|x| matches!(x, BgpAction::EndOfRib(_))));
    }

    // ===== FRR `no bgp default ipv4-unicast` (W2.1) =====

    /// Build a BGP peer with `default_ipv4_unicast = false` and IPv4
    /// unicast NOT in `mp_families` — the FRR `no bgp default
    /// ipv4-unicast` posture without explicit per-peer activation.
    fn peer_no_default_ipv4() -> BgpPeer {
        let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg.default_ipv4_unicast = false;
        cfg.mp_families = Vec::new();
        let mut peer = BgpPeer::new(cfg);
        peer.step(BgpEvent::ManualStart);
        peer.step(BgpEvent::TransportOpen);
        peer
    }

    /// A peer with `default_ipv4_unicast = false` must NOT emit an
    /// End-of-RIB marker for IPv4 unicast on receipt of an empty UPDATE.
    #[test]
    fn no_default_ipv4_unicast_suppresses_v4_eor() {
        let mut a = peer_no_default_ipv4();
        let actions = a.step(BgpEvent::Message(BgpMessage::Update(Update::new())));
        assert!(
            !actions
                .iter()
                .any(|x| matches!(x, BgpAction::EndOfRib(NlriFamily::IPV4_UNICAST))),
            "no IPv4 unicast EoR when the family is not active for this peer"
        );
    }

    /// A peer with `default_ipv4_unicast = false` must NOT install
    /// legacy-section IPv4 NLRI received from the peer.
    #[test]
    fn no_default_ipv4_unicast_drops_v4_nlri() {
        use crate::message::update::Update;
        use crate::path::AsPath;
        let mut a = peer_no_default_ipv4();
        let mut u = Update::new();
        u.nlri.push(crate::message::update::Nlri::plain(
            lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            AsPath::from_sequence([Asn(64513)]).encode_4(),
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::NextHop,
            vec![192, 0, 2, 1],
        ));
        let actions = a.step(BgpEvent::Message(BgpMessage::Update(u)));
        assert!(
            !actions
                .iter()
                .any(|x| matches!(x, BgpAction::InstallRoute(_))),
            "legacy-section IPv4 NLRI must be dropped when default_ipv4_unicast is off"
        );
    }

    /// A peer with `default_ipv4_unicast = false` must NOT process
    /// legacy-section withdrawals either — the family is not active,
    /// so a withdrawal would be a no-op anyway, but we fail closed
    /// (the peer should not be sending them).
    #[test]
    fn no_default_ipv4_unicast_drops_v4_withdrawals() {
        use crate::message::update::{Nlri, Update};
        let mut a = peer_no_default_ipv4();
        let mut u = Update::new();
        u.withdrawn.push(Nlri::plain(lr_core::addr::Prefix::new_v4(
            [203, 0, 113, 0],
            24,
        )));
        let actions = a.step(BgpEvent::Message(BgpMessage::Update(u)));
        assert!(
            !actions
                .iter()
                .any(|x| matches!(x, BgpAction::WithdrawRoute { .. })),
            "legacy-section IPv4 withdrawals must be dropped when default_ipv4_unicast is off"
        );
    }

    // ----- RFC 7911 Add-Path -----

    fn establish_add_path_pair() -> (BgpPeer, BgpPeer) {
        let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg1.add_path = true;
        cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        cfg2.add_path = true;
        cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        a.feed_bytes(&b_open).unwrap();
        b.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        a.feed_bytes(&b_ka).unwrap();
        b.feed_bytes(&a_ka).unwrap();
        assert!(a.is_established() && b.is_established());
        (a, b)
    }

    /// RFC 7911 §4.4: when both speakers advertise Add-Path for a family
    /// both directions are enabled on both sides.
    #[test]
    fn add_path_negotiated_both_directions() {
        let (a, b) = establish_add_path_pair();
        assert!(a.add_path_negotiated() && b.add_path_negotiated());
        assert!(a.add_path_tx_for(NlriFamily::IPV4_UNICAST));
        assert!(a.add_path_rx_for(NlriFamily::IPV4_UNICAST));
        assert!(b.add_path_tx_for(NlriFamily::IPV4_UNICAST));
        assert!(b.add_path_rx_for(NlriFamily::IPV4_UNICAST));
        // A family nobody negotiated stays single-path.
        assert!(!a.add_path_tx_for(NlriFamily::IPV6_UNICAST));
        assert!(!a.add_path_rx_for(NlriFamily::IPV6_UNICAST));
    }

    /// RFC 7911 §4.4: a peer that did not advertise Add-Path keeps the
    /// session in single-path mode even when we offered it.
    #[test]
    fn add_path_not_negotiated_when_peer_silent() {
        let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg1.add_path = true;
        cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        a.feed_bytes(&b_open).unwrap();
        b.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        a.feed_bytes(&b_ka).unwrap();
        b.feed_bytes(&a_ka).unwrap();
        assert!(a.is_established());
        assert!(!a.add_path_negotiated());
        assert!(!a.add_path_tx_for(NlriFamily::IPV4_UNICAST));
        assert!(!a.add_path_rx_for(NlriFamily::IPV4_UNICAST));
    }

    /// RFC 7911 §4.3: two paths to the same prefix advertised with distinct
    /// path identifiers arrive as two InstallRoute actions carrying those
    /// identifiers; withdrawing one identifier yields a WithdrawRoute for
    /// exactly that path.
    #[test]
    fn add_path_two_paths_install_and_withdraw() {
        use crate::message::update::{Nlri as Entry, Update};
        let (_a, mut b) = establish_add_path_pair();

        let mut u = Update::new();
        u.nlri.push(Entry::new(
            1,
            lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
        ));
        u.nlri.push(Entry::new(
            2,
            lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            vec![],
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::NextHop,
            vec![192, 0, 2, 1],
        ));
        let actions = b.step(BgpEvent::Message(BgpMessage::Update(u)));
        let installed: Vec<u32> = actions
            .iter()
            .filter_map(|x| match x {
                BgpAction::InstallRoute(r) => Some(r.path_id),
                _ => None,
            })
            .collect();
        assert_eq!(installed, vec![1, 2], "both paths must install");

        let mut w = Update::new();
        w.withdrawn.push(Entry::new(
            1,
            lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
        ));
        let actions = b.step(BgpEvent::Message(BgpMessage::Update(w)));
        assert!(matches!(
            actions.first(),
            Some(BgpAction::WithdrawRoute { path_id: 1, .. })
        ));
    }
}
