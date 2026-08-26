//! BFD session state machine (RFC 5880 §6).
//!
//! Each session is uniquely identified by a 4-byte "discriminator" (the
//! *local* discriminator). The session progresses through four states:
//!
//! - `AdminDown` — operator forced-down; no packets are sent.
//! - `Down` — link is down; packets are sent with `State=Down`.
//! - `Init` — the peer has spoken; we wait for confirmation.
//! - `Up` — link is up; both sides are exchanging packets.
//!
//! Transitions (RFC 5880 §6.2):
//!
//! - `AdminDown` → `Down`: operator up command.
//! - `Down` → `Init`: received a packet with `State=Down` or `Init`.
//! - `Init` → `Up`: received a packet with `State=Up` and our discriminator.
//! - `*` → `Down`: detection time expired, or peer signaled `Down`.
//!
//! Detection time = `detect_mult × max(required_min_rx, peer's desired_min_tx)`.

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::fsm::{TimerId, TimerSpec};
use lr_core::time::Instant;
use lr_core::timer::TimerQueue;

use crate::packet::{BfdCodec, BfdPacket, Diagnostic, PacketFlags, State};

/// Session role: Active side probes with `your_disc=0`; Passive side waits
/// for the peer to fill it in (RFC 5880 §6.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SessionRole {
    /// Active: we initiate; we send with `your_disc=0` until we see a packet
    /// from the peer that contains our discriminator.
    Active,
    /// Passive: we wait for the peer's first packet before starting.
    #[default]
    Passive,
}

/// Per-session configuration. All intervals in microseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdConfig {
    pub local_as: u32,
    pub detect_mult: u8,
    pub desired_min_tx_interval: u32,
    pub required_min_rx_interval: u32,
    pub required_min_echo_interval: u32,
    pub role: SessionRole,
}

impl Default for BfdConfig {
    fn default() -> Self {
        Self {
            local_as: 0,
            detect_mult: 3,
            desired_min_tx_interval: 1_000_000,
            required_min_rx_interval: 1_000_000,
            required_min_echo_interval: 0,
            role: SessionRole::Passive,
        }
    }
}

/// Session events surfaced by the FSM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BfdSessionEvent {
    /// Session state changed.
    StateChanged { from: State, to: State },
    /// Peer signaled a diagnostic.
    PeerDiagnostic(Diagnostic),
    /// Detection time expired — the link is down.
    Timeout,
    /// Auth check failed.
    AuthFailed,
    /// Outbound packet ready (bytes are pre-queued in `out_buf`).
    OutboundQueued,
}

/// Timer IDs used by [`BfdSession`].
pub mod timer_ids {
    use lr_core::fsm::TimerId;
    /// Periodic control packet transmission timer.
    pub const TX: TimerId = TimerId(1);
    /// Detection-time timer (fires when peer is silent for detect_mult * interval).
    pub const DETECT: TimerId = TimerId(2);
}

/// BFD session FSM. Owns the codec, state, timers, and outbound buffer.
pub struct BfdSession {
    cfg: BfdConfig,
    codec: BfdCodec,
    state: State,
    my_disc: u32,
    peer_disc: u32,
    /// Negotiated detection multiplier (the smaller of local and peer's).
    detect_mult: u8,
    /// Negotiated rx interval (max of local required and peer's desired).
    negotiated_rx: u32,
    /// Peer's advertised desired tx interval.
    peer_tx: u32,
    out_buf: Vec<u8>,
    last_state_change_ms: u64,
    pending_events: Vec<BfdSessionEvent>,
    timers: TimerQueue,
}

impl BfdSession {
    /// Allocate a session with a non-zero local discriminator.
    pub fn new(cfg: BfdConfig, my_disc: u32) -> Self {
        let detect_mult = cfg.detect_mult;
        let negotiated_rx = cfg.required_min_rx_interval;
        Self {
            cfg,
            codec: BfdCodec::new(),
            state: State::Down,
            my_disc,
            peer_disc: 0,
            detect_mult,
            negotiated_rx,
            peer_tx: 0,
            out_buf: Vec::new(),
            last_state_change_ms: 0,
            pending_events: Vec::new(),
            timers: TimerQueue::new(),
        }
    }

    pub fn state(&self) -> State {
        self.state
    }
    pub fn is_up(&self) -> bool {
        self.state == State::Up
    }
    pub fn my_discriminator(&self) -> u32 {
        self.my_disc
    }
    pub fn peer_discriminator(&self) -> u32 {
        self.peer_disc
    }
    pub fn negotiated_detect_mult(&self) -> u8 {
        self.detect_mult
    }
    pub fn negotiated_rx_interval(&self) -> u32 {
        self.negotiated_rx
    }
    pub fn peer_tx_interval(&self) -> u32 {
        self.peer_tx
    }

    /// Push inbound bytes; decode packets; feed the FSM. Returns the list of
    /// events emitted.
    pub fn feed_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<BfdSessionEvent>, lr_core::error::ParseError> {
        let mut events = Vec::new();
        let mut r = ReadBuf::new(bytes);
        loop {
            let before = r.position();
            match self.codec.decode(&mut r)? {
                None => break,
                Some(pkt) => {
                    let mut evs = self.on_packet(pkt);
                    events.append(&mut evs);
                }
            }
            if r.position() == before && r.remaining() > 0 {
                break;
            }
        }
        Ok(events)
    }

    /// Drain outbound bytes.
    pub fn drain_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out_buf)
    }

    /// Drive the FSM forward in time. Emits `Timeout` if the detection time
    /// expired.
    pub fn tick(&mut self, now: Instant) -> Vec<BfdSessionEvent> {
        let mut events = Vec::new();
        let expired = self.timers.tick(now);
        for tid in expired {
            match tid {
                TimerId(id) if id == timer_ids::DETECT.0 => {
                    self.transition(State::Down);
                    events.push(BfdSessionEvent::Timeout);
                }
                TimerId(id) if id == timer_ids::TX.0 => {
                    self.enqueue_packet();
                    events.push(BfdSessionEvent::OutboundQueued);
                    self.arm_tx_timer(now);
                }
                _ => {}
            }
        }
        events
    }

    /// Start the session (transition AdminDown → Down, arm timers, send
    /// an initial control packet).
    pub fn start(&mut self, now: Instant) -> Vec<BfdSessionEvent> {
        if self.state == State::AdminDown || self.state == State::Down {
            self.transition(State::Down);
            self.enqueue_packet();
            self.arm_tx_timer(now);
        }
        core::mem::take(&mut self.pending_events)
    }

    /// Operator-down: force the session to AdminDown.
    pub fn admin_down(&mut self) -> Vec<BfdSessionEvent> {
        self.transition(State::AdminDown);
        core::mem::take(&mut self.pending_events)
    }

    fn on_packet(&mut self, pkt: BfdPacket) -> Vec<BfdSessionEvent> {
        // Discriminator sanity-check.
        if pkt.your_discriminator != 0 && pkt.your_discriminator != self.my_disc {
            // Not addressed to us — ignore.
            return Vec::new();
        }
        // Adopt the peer's discriminator if our session was previously in
        // the discovery phase.
        if self.peer_disc == 0 {
            self.peer_disc = pkt.my_discriminator;
        }
        // Negotiate parameters: detect_mult = min(local, peer).
        self.detect_mult = self.cfg.detect_mult.min(pkt.detect_mult).max(1);
        // negotiated_rx = max(local required, peer desired_tx).
        self.negotiated_rx = self
            .cfg
            .required_min_rx_interval
            .max(pkt.desired_min_tx_interval)
            .max(1);
        self.peer_tx = pkt.desired_min_tx_interval;

        // Re-arm detection timer.
        let now_ms = self.last_state_change_ms;
        let detect_ms = self.detection_time_ms();
        self.timers.arm(
            Instant(now_ms),
            timer_ids::DETECT,
            TimerSpec::once(detect_ms * 1000),
        );

        // State machine (RFC 5880 §6.2).
        let prev = self.state;
        let next = match (prev, pkt.state) {
            (State::Down, State::Down) | (State::Down, State::Init) => State::Init,
            (State::Init, State::Init) => State::Init,
            (State::Init, State::Up) => State::Up,
            (State::Up, State::Up) => State::Up,
            (_, State::Down) => State::Down,
            (s, _) => s,
        };
        if next != prev {
            self.transition(next);
            core::mem::take(&mut self.pending_events)
        } else {
            Vec::new()
        }
    }

    fn transition(&mut self, to: State) {
        if to == self.state {
            return;
        }
        let from = self.state;
        self.state = to;
        self.pending_events
            .push(BfdSessionEvent::StateChanged { from, to });
    }

    fn enqueue_packet(&mut self) {
        let p = BfdPacket {
            diag: Diagnostic::None,
            state: self.state,
            flags: PacketFlags::empty(),
            detect_mult: self.detect_mult,
            my_discriminator: self.my_disc,
            your_discriminator: self.peer_disc,
            desired_min_tx_interval: self.cfg.desired_min_tx_interval,
            required_min_rx_interval: self.cfg.required_min_rx_interval,
            required_min_echo_interval: self.cfg.required_min_echo_interval,
            auth: None,
        };
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        if self.codec.encode(&p, &mut w).is_ok() {
            let n = w.position();
            self.out_buf.extend_from_slice(&buf[..n]);
        }
    }

    fn arm_tx_timer(&mut self, now: Instant) {
        let tx_ms = (self.cfg.desired_min_tx_interval / 1000).max(1) as u64;
        self.timers.arm(now, timer_ids::TX, TimerSpec::once(tx_ms));
    }

    /// Detection time in milliseconds = `detect_mult × max(local_required_rx, peer_desired_tx) / 1000`.
    fn detection_time_ms(&self) -> u64 {
        let interval_us = self.cfg.required_min_rx_interval.max(self.peer_tx).max(1) as u64;
        (self.detect_mult as u64 * interval_us) / 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> BfdSession {
        let cfg = BfdConfig {
            local_as: 100,
            detect_mult: 3,
            desired_min_tx_interval: 100_000, // 100ms
            required_min_rx_interval: 100_000,
            required_min_echo_interval: 0,
            role: SessionRole::Active,
        };
        let mut s = BfdSession::new(cfg, 0x11111111);
        let _ = s.start(Instant(0));
        s
    }

    fn make_packet(state: State, my_disc: u32, your_disc: u32) -> BfdPacket {
        BfdPacket {
            diag: Diagnostic::None,
            state,
            flags: PacketFlags::empty(),
            detect_mult: 3,
            my_discriminator: my_disc,
            your_discriminator: your_disc,
            desired_min_tx_interval: 100_000,
            required_min_rx_interval: 100_000,
            required_min_echo_interval: 0,
            auth: None,
        }
    }

    fn encode_packet(p: &BfdPacket) -> Vec<u8> {
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        let codec = BfdCodec::new();
        let n = codec.encode(p, &mut w).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn session_starts_down() {
        let mut s = make_session();
        assert_eq!(s.state(), State::Down);
        // Session should have queued an outbound packet (its first Down).
        let out = s.drain_outgoing();
        assert!(out.len() >= BfdPacket::MIN_LEN);
        // The first packet should have State=Down and your_disc=0.
        let mut codec = BfdCodec::new();
        let mut r = ReadBuf::new(&out);
        let p = codec.decode(&mut r).unwrap().unwrap();
        assert_eq!(p.state, State::Down);
        assert_eq!(p.my_discriminator, 0x11111111);
        assert_eq!(p.your_discriminator, 0);
    }

    #[test]
    fn down_to_init_on_peer_down() {
        let mut s = make_session();
        let _ = s.drain_outgoing();
        // Peer sends Down with their discriminator.
        let p = make_packet(State::Down, 0x22222222, 0);
        let bytes = encode_packet(&p);
        let evs = s.feed_bytes(&bytes).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            BfdSessionEvent::StateChanged {
                to: State::Init,
                ..
            }
        )));
        assert_eq!(s.state(), State::Init);
        assert_eq!(s.peer_discriminator(), 0x22222222);
    }

    #[test]
    fn init_to_up_on_peer_up() {
        let mut s = make_session();
        let _ = s.drain_outgoing();
        let p1 = make_packet(State::Down, 0x22222222, 0);
        let _ = s.feed_bytes(&encode_packet(&p1)).unwrap();
        assert_eq!(s.state(), State::Init);
        let _ = s.drain_outgoing();
        // Peer now sends Up with our discriminator.
        let p2 = make_packet(State::Up, 0x22222222, 0x11111111);
        let evs = s.feed_bytes(&encode_packet(&p2)).unwrap();
        assert!(evs
            .iter()
            .any(|e| matches!(e, BfdSessionEvent::StateChanged { to: State::Up, .. })));
        assert!(s.is_up());
    }

    #[test]
    fn timeout_brings_session_down() {
        let mut s = make_session();
        let _ = s.drain_outgoing();
        let p = make_packet(State::Down, 0x22222222, 0);
        let _ = s.feed_bytes(&encode_packet(&p)).unwrap();
        assert_eq!(s.state(), State::Init);
        // Advance past the detection time (300ms = 3 × 100ms).
        let evs = s.tick(Instant(500_000));
        assert!(evs.iter().any(|e| matches!(e, BfdSessionEvent::Timeout)));
        assert_eq!(s.state(), State::Down);
    }
}
