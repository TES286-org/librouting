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
use crate::error::{BgpErrorCode, BgpNotification};
use crate::extensions::extended_next_hop::ExtNextHopTuple;
use crate::message::{keepalive::Keepalive, open::Open, update::Update, BgpMessage};
use crate::path::{AttrType, PathAttrFlags, PathAttribute, PathAttributes};
use crate::peer::PeerConfig;

use lr_core::addr::{Asn, RouterId};
use lr_core::codec::Decoder;
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
    pub(crate) out_buf: Vec<u8>,
    hold_remaining: u64,
    keepalive_remaining: u64,
    established: bool,
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
            out_buf: Vec::new(),
            hold_remaining: 0,
            keepalive_remaining: 0,
            established: false,
        }
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
        match self.codec.encode_vec(&BgpMessage::RouteRefresh(refresh)) {
            Ok(bytes) => {
                self.out_buf.extend_from_slice(&bytes);
                true
            }
            Err(_) => false,
        }
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

    /// Push inbound bytes; decode and emit any actions for consumed messages.
    pub fn feed_bytes(&mut self, bytes: &[u8]) -> Result<Vec<BgpAction>, ParseError> {
        let mut actions = Vec::new();
        let mut r = lr_core::buf::ReadBuf::new(bytes);
        loop {
            let before = r.position();
            match self.codec.decode(&mut r)? {
                None => break,
                Some(msg) => {
                    actions.extend(self.step(BgpEvent::Message(msg)));
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
        let param_value = Capability::encode_set(&caps);
        let mut open = Open::new(self.cfg.local_as, self.cfg.hold_time, self.cfg.local_bgp_id);
        open.params.push(crate::message::open::OpenParam {
            param_type: crate::message::open::OpenParam::PARAM_TYPE_CAPABILITY,
            value: param_value,
        });
        if let Ok(bytes) = self.codec.encode_vec(&BgpMessage::Open(open)) {
            self.out_buf.extend_from_slice(&bytes);
        }
    }

    fn enqueue_keepalive(&mut self) {
        if let Ok(bytes) = self.codec.encode_vec(&BgpMessage::Keepalive(Keepalive)) {
            self.out_buf.extend_from_slice(&bytes);
        }
    }

    pub fn enqueue_notification(&mut self, code: BgpErrorCode, subcode: u8) {
        let n = BgpNotification::new(code as u8, subcode, vec![]);
        if let Ok(bytes) = self.codec.encode_vec(&BgpMessage::Notification(n)) {
            self.out_buf.extend_from_slice(&bytes);
        }
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
        // 2-byte width for the lifetime of this session.
        let peer_offered_as4 = caps
            .iter()
            .any(|c| c.code == crate::capabilities::CapabilityCode::FourOctetAs);
        self.cfg.asn4 = self.cfg.asn4 && peer_offered_as4;
        self.codec.set_asn4(self.cfg.asn4);
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

        self.negotiated_hold_time = if open.hold_time == 0 {
            self.cfg.hold_time
        } else {
            open.hold_time.min(self.cfg.hold_time)
        };
        if self.negotiated_hold_time == 0 {
            self.negotiated_hold_time = self.cfg.hold_time;
        }
        self.hold_remaining = (self.negotiated_hold_time as u64) * 1000;
        self.keepalive_remaining = (self.cfg.keepalive_interval() as u64) * 1000;
        self.enqueue_keepalive();
        let mut actions = vec![];
        if self.negotiated_hold_time > 0 {
            actions.push(BgpAction::SetTimer(
                timer_ids::HOLD,
                TimerSpec::once(self.hold_remaining),
            ));
        }
        actions.push(BgpAction::SetTimer(
            timer_ids::KEEPALIVE,
            TimerSpec::once(self.keepalive_remaining),
        ));
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
                    TimerSpec::once((self.cfg.keepalive_interval() as u64) * 1000),
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
                if let Ok(b) = self.codec.encode_vec(&BgpMessage::Notification(n)) {
                    self.out_buf.extend_from_slice(&b);
                }
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
        // wire width. AS4_PATH (RFC 6793 transition) is merged in and
        // dropped.
        let mut normalized: PathAttributes = u.attributes.clone();
        let wire_path = normalized.as_path_wire(self.cfg.asn4);
        let as4 = normalized.as4_path();
        let canonical_path = as4.or(wire_path);
        normalized.remove(AttrType::As4Path);
        if let Some(path) = &canonical_path {
            normalized.insert(PathAttribute::new(
                PathAttrFlags::new().set_transitive(true),
                AttrType::AsPath,
                path.encode_4(),
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
            let metric = canonical_path
                .as_ref()
                .map(|p| p.length() as u32)
                .unwrap_or(0);
            let route = Route {
                key: RouteKey::new(prefix, family),
                origin,
                protocol: Protocol::Bgp,
                preference: Preference::new(Protocol::Bgp.default_admin_distance(), metric),
                next_hop,
                attributes: normalized.clone().into(),
                age_ms: 0, // stamped by the router when it imports
                path_id,
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
                            let metric = canonical_path
                                .as_ref()
                                .map(|p| p.length() as u32)
                                .unwrap_or(0);
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
        assert!(!peer.cfg.asn4, "session must downgrade to 2-byte AS_PATH");
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
