//! BFD session state machine (RFC 5880 §6).
//!
//! Each session is uniquely identified by a 4-byte "discriminator" (the
//! *local* discriminator). The session progresses through four states:
//!
//! - `AdminDown` — operator forced-down; received packets are discarded.
//! - `Down` — link is down; packets are sent with `State=Down`.
//! - `Init` — the peer has spoken; we wait for confirmation.
//! - `Up` — link is up; both sides are exchanging packets.
//!
//! Transitions follow §6.8.6 exactly. Two of them matter for
//! interoperability and were historically implemented wrong in many
//! stacks: receiving `Init` while `Down` goes **straight to `Up`**, and
//! receiving `Init` while `Init` also goes **straight to `Up`** —
//! otherwise two conforming peers deadlock in `Init` forever.
//!
//! Timing (§6.8.2-§6.8.4):
//!
//! - Transmit interval = `max(DesiredMinTxInterval, RemoteMinRxInterval)`,
//!   jittered down by 0-25% (75-90% when the local detect multiplier is
//!   1, so a packet always arrives before the peer's detection timer
//!   expires). While the session is not `Up` the desired interval is
//!   floored at one second (§6.8.3).
//! - Detection time = the *remote* system's Detect Mult ×
//!   `max(RequiredMinRxInterval, RemoteDesiredMinTxInterval)`. The timer
//!   re-arms on every received (non-discarded) packet and only takes
//!   the session down from `Init` or `Up` (§6.8.4).
//! - Interval changes while `Up` are confirmed with a Poll/Final
//!   sequence (§6.5) carried on the regular periodic packets; increased
//!   TX / reduced RX values apply only after the peer's Final arrives
//!   (§6.8.3).
//!
//! Reception applies the §6.8.6 MUST-discard rules in order (version
//! and Length are enforced by the codec; this layer checks Detect Mult,
//! the Multipoint bit, Poll+Final together, the discriminators and the
//! Authentication bit).

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::fsm::{TimerId, TimerSpec};
use lr_core::time::Instant;
use lr_core::timer::TimerQueue;

use crate::auth::{AuthSection, AuthType};
use crate::packet::{BfdCodec, BfdPacket, Diagnostic, PacketFlags, State};

/// Session role: Active side probes with `your_disc=0`; Passive side
/// waits for the peer to fill it in (RFC 5880 §6.1). Single-hop BFD
/// (RFC 5881 §3) requires BOTH sides to take the Active role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SessionRole {
    /// Active: we initiate; we send with `your_disc=0` until we see a
    /// packet from the peer that contains our discriminator.
    #[default]
    Active,
    /// Passive: we wait for the peer's first packet before starting.
    Passive,
}

/// Per-session configuration. All intervals in microseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdConfig {
    /// Detection multiplier: how many peer packets may be missed
    /// before the session is declared down (§6.8.4). Must be >= 1.
    pub detect_mult: u8,
    /// Minimum interval we would like to transmit at.
    pub desired_min_tx_interval: u32,
    /// Minimum interval we are prepared to receive at.
    pub required_min_rx_interval: u32,
    /// Minimum echo interval we are prepared to receive at (0 = the
    /// echo function is disabled; it is not used over multihop paths,
    /// RFC 5883 §3).
    pub required_min_echo_interval: u32,
    /// Active or Passive role (see [`SessionRole`]).
    pub role: SessionRole,
    /// Optional Simple Password authentication key (RFC 5880 §4.2).
    /// When set, outbound packets carry the auth section and inbound
    /// packets must carry a matching one. The keyed-hash types are
    /// framing-only (the embedder computes digests).
    pub auth_key: Option<crate::auth::AuthKey>,
}

impl Default for BfdConfig {
    fn default() -> Self {
        Self {
            detect_mult: 3,
            desired_min_tx_interval: 1_000_000,
            required_min_rx_interval: 1_000_000,
            required_min_echo_interval: 0,
            role: SessionRole::Active,
            auth_key: None,
        }
    }
}

/// While the session is not Up, the transmit interval must be at
/// least one second (RFC 5880 §6.8.3).
const IDLE_TX_INTERVAL_US: u32 = 1_000_000;

/// Session events surfaced by the FSM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BfdSessionEvent {
    /// Session state changed (with the diagnostic code explaining the
    /// transition, as it will be advertised to the peer).
    StateChanged {
        from: State,
        to: State,
        diag: Diagnostic,
    },
    /// The peer changed the diagnostic code it advertises.
    PeerDiagnostic(Diagnostic),
    /// Detection time expired — the link is down.
    Timeout,
    /// Auth check failed; the offending packet was discarded.
    AuthFailed,
    /// Outbound packet ready (bytes are pre-queued in `out_buf`).
    OutboundQueued,
}

/// Timer IDs used by [`BfdSession`].
pub mod timer_ids {
    use lr_core::fsm::TimerId;
    /// Periodic control packet transmission timer.
    pub const TX: TimerId = TimerId(1);
    /// Detection-time timer (fires when peer is silent for
    /// detect_mult × negotiated interval).
    pub const DETECT: TimerId = TimerId(2);
}

/// BFD session FSM. Owns the codec, state, timers, and outbound buffer.
///
/// The embedder drives time: pass the current [`Instant`] to every
/// call (packets included, so the detection timer is anchored to
/// packet arrival), then drain outbound bytes onto the wire.
pub struct BfdSession {
    cfg: BfdConfig,
    codec: BfdCodec,
    state: State,
    my_disc: u32,
    remote_disc: u32,
    /// Local diagnostic explaining the last transition (§4.1).
    local_diag: Diagnostic,
    remote_state: State,
    remote_diag: Diagnostic,
    /// Peer's advertised detect multiplier (drives OUR detection time).
    remote_detect_mult: u8,
    /// Peer's advertised desired min tx interval (part of the
    /// detection-time calculation).
    remote_desired_tx: u32,
    /// Peer's advertised required min rx interval (caps our tx rate).
    remote_min_rx: u32,
    /// Peer's Demand bit.
    remote_demand: bool,
    /// Active timer values (what cadence/detection we run at now).
    desired_min_tx: u32,
    required_min_rx: u32,
    /// Pending values advertised during a Poll sequence; applied when
    /// the peer's Final arrives (§6.8.3).
    pending_tx: Option<u32>,
    pending_rx: Option<u32>,
    /// True while we are running a Poll sequence (P bit on our
    /// periodic packets, §6.5).
    poll_active: bool,
    out_buf: Vec<u8>,
    last_peer_diag: Diagnostic,
    pending_events: Vec<BfdSessionEvent>,
    timers: TimerQueue,
    /// True when a TX timer entry is in the queue (the queue cannot
    /// answer "is id X armed" itself).
    tx_armed: bool,
    /// Logical time of the last transmission, in ms (§6.8.3: a
    /// reduced interval must apply immediately).
    last_tx_ms: u64,
    /// xorshift32 state for tx jitter (deterministic per session).
    rng: u32,
    started: bool,
}

impl BfdSession {
    /// Allocate a session with a non-zero local discriminator.
    pub fn new(cfg: BfdConfig, my_disc: u32) -> Self {
        debug_assert!(my_disc != 0, "local discriminator must be non-zero");
        let desired_min_tx = cfg.desired_min_tx_interval.max(1);
        let required_min_rx = cfg.required_min_rx_interval.max(1);
        Self {
            cfg,
            codec: BfdCodec::new(),
            state: State::Down,
            my_disc: my_disc.max(1),
            remote_disc: 0,
            local_diag: Diagnostic::None,
            remote_state: State::Down,
            remote_diag: Diagnostic::None,
            remote_detect_mult: 0,
            remote_desired_tx: 0,
            remote_min_rx: 0,
            remote_demand: false,
            desired_min_tx,
            required_min_rx,
            pending_tx: None,
            pending_rx: None,
            poll_active: false,
            out_buf: Vec::new(),
            last_peer_diag: Diagnostic::None,
            pending_events: Vec::new(),
            timers: TimerQueue::new(),
            tx_armed: false,
            last_tx_ms: 0,
            rng: my_disc.wrapping_mul(2_654_435_761) | 1,
            started: false,
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
    pub fn remote_discriminator(&self) -> u32 {
        self.remote_disc
    }
    /// The diagnostic we advertise for the last transition.
    pub fn local_diag(&self) -> Diagnostic {
        self.local_diag
    }
    pub fn remote_diag(&self) -> Diagnostic {
        self.remote_diag
    }
    pub fn remote_state(&self) -> State {
        self.remote_state
    }
    pub fn remote_detect_mult(&self) -> u8 {
        self.remote_detect_mult
    }
    /// True while a Poll sequence is being transmitted (§6.5).
    pub fn poll_active(&self) -> bool {
        self.poll_active
    }
    /// The transmit interval currently in force, in microseconds
    /// (before jitter) — `max(desired tx, remote required rx)` (§6.8.7),
    /// floored at one second while not Up (§6.8.3).
    pub fn tx_interval_us(&self) -> u32 {
        let base = if self.state == State::Up {
            self.desired_min_tx
        } else {
            self.desired_min_tx.max(IDLE_TX_INTERVAL_US)
        };
        base.max(self.remote_min_rx).max(1)
    }
    /// The detection time currently in force, in microseconds —
    /// remote detect multiplier × `max(required rx, remote desired tx)`
    /// (§6.8.4, Asynchronous mode).
    pub fn detection_time_us(&self) -> u64 {
        let interval = self.required_min_rx.max(self.remote_desired_tx).max(1) as u64;
        self.remote_detect_mult.max(1) as u64 * interval
    }

    /// Push inbound bytes; decode packets; feed the FSM. Invalid
    /// packets are discarded (RFC 5880 §6.8.6 MUST-discard rules);
    /// processing of the remainder of the buffer stops after one
    /// malformed packet (one BFD Control packet per datagram).
    pub fn feed_bytes(&mut self, now: Instant, bytes: &[u8]) -> Vec<BfdSessionEvent> {
        let mut events = Vec::new();
        let mut r = ReadBuf::new(bytes);
        while let Ok(Some(pkt)) = self.codec.decode(&mut r) {
            let mut evs = self.on_packet(now, pkt);
            events.append(&mut evs);
        }
        events
    }

    /// Drain outbound bytes.
    pub fn drain_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out_buf)
    }

    /// Drive the FSM forward in time. Emits `Timeout` (and takes the
    /// session to Down) when the detection time expires while the
    /// session is Init or Up (§6.8.4).
    pub fn tick(&mut self, now: Instant) -> Vec<BfdSessionEvent> {
        let mut events = core::mem::take(&mut self.pending_events);
        let expired = self.timers.tick(now);
        for tid in expired {
            match tid {
                TimerId(id) if id == timer_ids::DETECT.0 => {
                    if self.state == State::Init || self.state == State::Up {
                        self.local_diag = Diagnostic::CtrlExpired;
                        self.transition(State::Down);
                        events.push(BfdSessionEvent::Timeout);
                        // Re-arm the (now idle-floored) cadence.
                        if self.tx_allowed() {
                            self.arm_tx_timer(now);
                        }
                    }
                }
                TimerId(id) if id == timer_ids::TX.0 => {
                    self.tx_armed = false;
                    if self.tx_allowed() {
                        self.enqueue_packet(now, false);
                        events.push(BfdSessionEvent::OutboundQueued);
                        self.arm_tx_timer(now);
                    }
                }
                _ => {}
            }
        }
        events.append(&mut self.pending_events);
        events
    }

    /// Start the session (AdminDown → Down, arm timers, send an
    /// initial control packet when we are allowed to transmit).
    pub fn start(&mut self, now: Instant) -> Vec<BfdSessionEvent> {
        if !self.started {
            self.started = true;
            self.transition(State::Down);
            if self.tx_allowed() {
                self.enqueue_packet(now, false);
                self.arm_tx_timer(now);
            }
        }
        core::mem::take(&mut self.pending_events)
    }

    /// Operator-down: force the session to AdminDown (§6.8.16). Timers
    /// stop; received packets are discarded until `start` again.
    pub fn admin_down(&mut self) -> Vec<BfdSessionEvent> {
        self.local_diag = Diagnostic::AdminDown;
        self.transition(State::AdminDown);
        self.timers.cancel_all();
        self.tx_armed = false;
        core::mem::take(&mut self.pending_events)
    }

    /// Change timer parameters at runtime (§6.8.3). While the session
    /// is Up the change is confirmed with a Poll sequence carried on
    /// the periodic packets (§6.5); an increased TX interval / reduced
    /// RX interval takes effect only after the peer's Final, everything
    /// else applies immediately.
    pub fn update_timers(
        &mut self,
        now: Instant,
        desired_min_tx: u32,
        required_min_rx: u32,
    ) -> Vec<BfdSessionEvent> {
        let desired_min_tx = desired_min_tx.max(1);
        let required_min_rx = required_min_rx.max(1);
        let old_tx = self.desired_min_tx;
        let old_rx = self.required_min_rx;
        let live = self.state == State::Up && self.remote_disc != 0;

        // §6.8.3: defer application of an increased tx interval / a
        // reduced rx interval until the poll completes; everything
        // else applies immediately.
        if live && desired_min_tx > old_tx {
            self.pending_tx = Some(desired_min_tx);
        } else {
            self.desired_min_tx = desired_min_tx;
            self.pending_tx = None;
        }
        if live && required_min_rx < old_rx {
            self.pending_rx = Some(required_min_rx);
        } else {
            self.required_min_rx = required_min_rx;
            self.pending_rx = None;
        }

        // §6.8.3: a change to either interval MUST initiate a Poll
        // sequence (meaningful only with a live session).
        if live && (desired_min_tx != old_tx || required_min_rx != old_rx) {
            self.poll_active = true;
        } else if !live {
            self.poll_active = false;
        }

        // Re-arm the tx timer: a reduced interval must be honored
        // immediately (§6.8.3).
        if self.tx_allowed() {
            self.arm_tx_timer(now);
        } else if self.tx_armed {
            self.timers.cancel(timer_ids::TX);
            self.tx_armed = false;
        }
        core::mem::take(&mut self.pending_events)
    }

    /// The desired min tx interval currently advertised in packets
    /// (the pending value while a poll runs; floored at one second
    /// while not Up, §6.8.3).
    fn advertised_tx(&self) -> u32 {
        let v = self.pending_tx.unwrap_or(self.desired_min_tx);
        if self.state == State::Up {
            v
        } else {
            v.max(IDLE_TX_INTERVAL_US)
        }
    }

    /// The required min rx interval currently advertised in packets.
    fn advertised_rx(&self) -> u32 {
        self.pending_rx.unwrap_or(self.required_min_rx)
    }

    /// §6.8.7: no transmission when Passive with no remote
    /// discriminator, when the remote demands silence, or when the
    /// remote cannot receive.
    fn tx_allowed(&self) -> bool {
        if self.state == State::AdminDown {
            return false;
        }
        if self.cfg.role == SessionRole::Passive && self.remote_disc == 0 {
            return false;
        }
        if self.remote_demand
            && !self.poll_active
            && self.state == State::Up
            && self.remote_state == State::Up
        {
            return false;
        }
        if self.remote_min_rx == 0 && self.remote_disc != 0 {
            return false;
        }
        true
    }

    fn on_packet(&mut self, now: Instant, pkt: BfdPacket) -> Vec<BfdSessionEvent> {
        // --- §6.8.6 MUST-discard rules, in order. ---
        // (Version and Length-field checks live in the codec.)
        if pkt.detect_mult == 0 {
            return Vec::new();
        }
        if pkt.flags.contains(PacketFlags::MULTIPOINT) {
            return Vec::new();
        }
        // §6.5: a packet MUST NOT have both Poll and Final set.
        if pkt.flags.contains(PacketFlags::POLL | PacketFlags::FINAL) {
            return Vec::new();
        }
        if pkt.my_discriminator == 0 {
            return Vec::new();
        }
        if pkt.your_discriminator != 0 && pkt.your_discriminator != self.my_disc {
            // Not addressed to us — the demultiplexer above us should
            // have routed it elsewhere; ignore defensively.
            return Vec::new();
        }
        if pkt.your_discriminator == 0 && pkt.state != State::Down && pkt.state != State::AdminDown
        {
            return Vec::new();
        }
        if self.state == State::AdminDown {
            // §6.8.6: discard while administratively down.
            return Vec::new();
        }
        // Authentication (§6.7): the A bit must match our config and,
        // when set, the section must validate.
        if !self.check_auth(&pkt) {
            return core::mem::take(&mut self.pending_events);
        }

        // --- Update remote state variables (§6.8.6). ---
        self.remote_disc = pkt.my_discriminator;
        self.remote_state = pkt.state;
        self.remote_diag = pkt.diag;
        self.remote_demand = pkt.flags.contains(PacketFlags::DEMAND);
        let old_remote_min_rx = self.remote_min_rx;
        self.remote_min_rx = pkt.required_min_rx_interval;
        self.remote_desired_tx = pkt.desired_min_tx_interval;
        self.remote_detect_mult = pkt.detect_mult;

        if pkt.diag != self.last_peer_diag {
            self.last_peer_diag = pkt.diag;
            if pkt.diag != Diagnostic::None {
                self.pending_events
                    .push(BfdSessionEvent::PeerDiagnostic(pkt.diag));
            }
        }

        // --- Poll sequence bookkeeping (§6.5, §6.8.6). ---
        if self.poll_active && pkt.flags.contains(PacketFlags::FINAL) {
            self.poll_active = false;
            if let Some(tx) = self.pending_tx.take() {
                self.desired_min_tx = tx;
            }
            if let Some(rx) = self.pending_rx.take() {
                self.required_min_rx = rx;
            }
        }

        // --- State machine (§6.8.6). ---
        let prev = self.state;
        if pkt.state == State::AdminDown {
            if self.state != State::Down {
                self.local_diag = Diagnostic::NeighborSignaled;
                self.transition(State::Down);
            }
        } else {
            let next = match self.state {
                State::Down => match pkt.state {
                    State::Down => Some(State::Init),
                    State::Init => Some(State::Up),
                    _ => None,
                },
                State::Init => match pkt.state {
                    State::Init | State::Up => Some(State::Up),
                    _ => None,
                },
                State::Up => {
                    if pkt.state == State::Down {
                        self.local_diag = Diagnostic::NeighborSignaled;
                        Some(State::Down)
                    } else {
                        None
                    }
                }
                State::AdminDown => None,
            };
            if let Some(next) = next {
                if next != State::Down {
                    // No diagnostic explains coming up (BIRD resets
                    // LocalDiag to 0 on up-transitions).
                    self.local_diag = Diagnostic::None;
                }
                self.transition(next);
            }
        }

        // --- Detection timer: every non-discarded packet re-arms it
        // (§6.8.4, anchored to arrival time). Replace any pending
        // entry — the queue has no re-schedule, and a stale one would
        // fire one detection-time later and tear a healthy session
        // down. ---
        let detect_ms = (self.detection_time_us() / 1000).max(1);
        self.timers.cancel(timer_ids::DETECT);
        self.timers
            .arm(now, timer_ids::DETECT, TimerSpec::once(detect_ms));

        // --- Transmit cadence bookkeeping (§6.8.7): recalculate when
        // the peer's required rx changed; (re)start the timer when
        // transmission just became allowed or the session state (and
        // with it the idle floor) changed. ---
        if self.tx_allowed() {
            if !self.tx_armed || prev != self.state || old_remote_min_rx != self.remote_min_rx {
                self.arm_tx_timer(now);
            }
        } else if self.tx_armed {
            self.timers.cancel(timer_ids::TX);
            self.tx_armed = false;
        }

        // --- Announce a state change immediately (§6.8.7 SHOULD:
        // "transmit when the contents would differ"). ---
        if prev != self.state && self.tx_allowed() {
            self.enqueue_packet(now, false);
            self.pending_events.push(BfdSessionEvent::OutboundQueued);
        }

        // --- Respond to a Poll with Final "as soon as practicable"
        // (§6.8.6, §6.8.7), independent of the periodic timer. ---
        if pkt.flags.contains(PacketFlags::POLL) && self.state != State::AdminDown {
            self.enqueue_packet(now, true);
            self.pending_events.push(BfdSessionEvent::OutboundQueued);
        }
        core::mem::take(&mut self.pending_events)
    }

    /// §6.7 A-bit / section validation. Returns false (and queues an
    /// `AuthFailed` event) when the packet must be discarded.
    fn check_auth(&mut self, pkt: &BfdPacket) -> bool {
        let mismatch = |events: &mut Vec<BfdSessionEvent>| {
            events.push(BfdSessionEvent::AuthFailed);
        };
        match (&self.cfg.auth_key, &pkt.auth) {
            (None, None) => true,
            (None, Some(_)) => {
                // A set but authentication is not in use.
                mismatch(&mut self.pending_events);
                false
            }
            (Some(_), None) => {
                // A clear but authentication is in use.
                mismatch(&mut self.pending_events);
                false
            }
            (Some(key), Some(section)) => {
                if section.auth_type != AuthType::SimplePassword
                    || section.key_id != key.key_id
                    || section.data != key.data
                {
                    mismatch(&mut self.pending_events);
                    false
                } else {
                    true
                }
            }
        }
    }

    fn transition(&mut self, to: State) {
        if to == self.state {
            return;
        }
        let from = self.state;
        self.state = to;
        if from == State::Up {
            // Leaving Up cancels any in-flight Poll sequence; the
            // active values re-negotiate with the next transition to
            // Up (§6.5, §6.8.3).
            self.poll_active = false;
            self.pending_tx = None;
            self.pending_rx = None;
        }
        self.pending_events.push(BfdSessionEvent::StateChanged {
            from,
            to,
            diag: self.local_diag,
        });
    }

    fn enqueue_packet(&mut self, now: Instant, final_bit: bool) {
        let mut flags = PacketFlags::empty();
        if self.poll_active {
            flags |= PacketFlags::POLL;
        }
        if final_bit {
            flags |= PacketFlags::FINAL;
        }
        let auth = self.cfg.auth_key.as_ref().map(|k| {
            flags |= PacketFlags::AUTH;
            AuthSection::simple_password(k.data.clone(), k.key_id)
        });
        let p = BfdPacket {
            diag: self.local_diag,
            state: self.state,
            flags,
            detect_mult: self.cfg.detect_mult.max(1),
            my_discriminator: self.my_disc,
            your_discriminator: self.remote_disc,
            desired_min_tx_interval: self.advertised_tx(),
            required_min_rx_interval: self.advertised_rx(),
            required_min_echo_interval: self.cfg.required_min_echo_interval,
            auth,
        };
        self.last_tx_ms = now.0;
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        if self.codec.encode(&p, &mut w).is_ok() {
            let n = w.position();
            self.out_buf.extend_from_slice(&buf[..n]);
        }
    }

    /// Arm the periodic transmission timer at the negotiated interval
    /// with per-packet jitter of 0-25% (§6.8.7). With a local detect
    /// multiplier of 1 the interval is 75-90% of the negotiated value
    /// so the next packet always precedes the peer's detection time.
    /// A reduced interval is honored immediately: the next packet
    /// never waits longer than one new interval past the previous
    /// transmission (§6.8.3).
    fn arm_tx_timer(&mut self, now: Instant) {
        if !self.tx_allowed() {
            self.timers.cancel(timer_ids::TX);
            self.tx_armed = false;
            return;
        }
        // Replace any pending TX entry (the queue has no
        // re-schedule; a stale entry would double the cadence).
        self.timers.cancel(timer_ids::TX);
        let base_us = self.tx_interval_us() as u64;
        // Deterministic xorshift32 jitter.
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 17;
        self.rng ^= self.rng << 5;
        let span: u64 = if self.cfg.detect_mult <= 1 { 15 } else { 25 };
        // detect_mult == 1: reduce by 10-25% (75-90% of the interval);
        // otherwise reduce by 0-25%.
        let jitter_pct = if self.cfg.detect_mult <= 1 {
            10 + (self.rng as u64 % (span + 1))
        } else {
            self.rng as u64 % (span + 1)
        };
        let interval_us = base_us - base_us * jitter_pct / 100;
        let interval_ms = (interval_us / 1000).max(1);
        let normal = now.0 + interval_ms;
        let deadline = self.last_tx_ms.saturating_add(interval_ms);
        let fire_at = normal.min(deadline.max(now.0));
        self.timers
            .arm(now, timer_ids::TX, TimerSpec::once(fire_at - now.0));
        self.tx_armed = true;
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
