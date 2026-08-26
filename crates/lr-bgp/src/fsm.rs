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
    WithdrawRoute(lr_core::rib::RouteKey),
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
        if self.cfg.enhanced_rr {
            caps.push(Capability::enhanced_rr());
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

    fn enqueue_notification(&mut self, code: BgpErrorCode, subcode: u8) {
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
        let topo = self.cfg.compute_topology();
        let origin = RouteOrigin {
            // Convention (consumed by best_path / the safety net):
            // 0 = eBGP-learned, 1 = iBGP-learned.
            proto: u32::from(topo.role.is_internal()),
            peer: self.cfg.peer_id,
        };

        // --- Withdrawals (IPv4 legacy section) ---
        for p in &u.withdrawn {
            actions.push(BgpAction::WithdrawRoute(RouteKey::new(
                *p,
                NlriFamily::IPV4_UNICAST,
            )));
        }

        // --- MP_UNREACH_NLRI withdrawals (RFC 4760) ---
        if let Some(mp) = u.attributes.mp_unreach() {
            for p in &mp.nlri {
                actions.push(BgpAction::WithdrawRoute(RouteKey::new(*p, mp.family)));
            }
        }

        // --- Announcements ---
        // A valid announcement needs at least ORIGIN, AS_PATH and NEXT_HOP
        // (RFC 4271 §6.3); rather than tearing the session down we skip
        // malformed NLRI — the safety net at the router layer reports it.
        let attrs_ok = u.attributes.origin().is_some()
            && (u.attributes.as_path().is_some() || u.attributes.as4_path().is_some())
            && (u.attributes.next_hop().is_some() || u.attributes.mp_reach().is_some());

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
            };
            actions.push(BgpAction::InstallRoute(route));
        };

        // IPv4 NLRI: NEXT_HOP from the well-known attribute.
        if !u.nlri.is_empty() {
            let nh = u.attributes.next_hop().map(|n| n.to_ip());
            for p in &u.nlri {
                announce(*p, NlriFamily::IPV4_UNICAST, nh, &mut actions);
            }
        }

        // MP_REACH_NLRI (RFC 4760): family + next-hop from the attribute.
        if let Some(mp) = u.attributes.mp_reach() {
            let nh = match &mp.next_hop {
                crate::path::MpNextHop::V4(b) => Some(lr_core::addr::IpAddr::V4(*b)),
                crate::path::MpNextHop::V6Global(b)
                | crate::path::MpNextHop::V6LinkLocal(b)
                | crate::path::MpNextHop::V6GlobalLinkLocal(b, _)
                | crate::path::MpNextHop::V4OverV6(b) => Some(lr_core::addr::IpAddr::V6(*b)),
            };
            for p in &mp.nlri {
                announce(*p, mp.family, nh, &mut actions);
            }
        }

        actions
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
                BgpAction::WithdrawRoute(k) => Action::WithdrawRoute(k),
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
}
