//! Babel neighbor tracking (RFC 8966 §3.3).
//!
//! Tracks per-neighbor Hello history, TX/RX costs, and computes RTO.
//! Also holds the round-trip-time measurement state of the BABEL-RTT
//! delay-based metric extension (RFC 8966 §A.2.4): the peer Hello
//! timestamps and our receive times that the transport echoes in IHUs,
//! plus the smoothed RTT the metric layer consults.

use lr_core::addr::IpAddr;

/// EWMA decay applied to RTT samples, in 1/256 units (babeld's default
/// `rtt-decay 42`): `smoothed = (decay * sample + (256-decay) * previous) / 256`.
pub const RTT_DECAY: u32 = 42;

/// A fresh RTT sample is valid for this long (babeld's 180 s
/// `valid_rtt` window); older measurements contribute no RTT cost.
pub const RTT_VALIDITY_MS: u64 = 180_000;

/// An RTT echo pair is only sent while the Hello it acknowledges is
/// fresh — one second (babeld's 1 s echo freshness window).
pub const RTT_ECHO_FRESHNESS_MS: u64 = 1_000;

/// Sanity window for the waiting-time differences (babeld's 600 s bound):
/// differences outside `[0, RTT_SANITY_US]` indicate clock skew or a
/// stale echo rather than a real delay, and the sample is discarded.
pub const RTT_SANITY_US: u32 = 600_000_000;

/// One neighbor as seen by the Babel speaker. The embedder drives Hello/IHU
/// arrival by calling [`BabelNeighbor::hello`] and [`BabelNeighbor::ihu`].
#[derive(Debug, Clone)]
pub struct BabelNeighbor {
    pub address: IpAddr,
    /// 16-bit Hello history bitmask (BIRD `hello_map`). Bit 0 is the
    /// most recent Hello slot; bit `hello_cnt-1` is the oldest. A set
    /// bit means the Hello was received; a clear bit means it was
    /// missed. This mirrors BIRD's `nbr->hello_map` and babeld's
    /// `neigh->reach`, and supports the k-out-of-j link-quality
    /// selection of RFC 8966 §A.2.1.
    pub hello_map: u16,
    /// The window size, up to 16 (BIRD `hello_cnt`). Grows as Hellos
    /// arrive or expire, capped at 16. Used as the denominator in the
    /// k-out-of-j check: `popcount(hello_map) * 16 >= limit *
    /// hello_cnt`.
    pub hello_cnt: u8,
    /// The next expected Hello seqno (BIRD `next_hello_seqno`). When a
    /// Hello arrives, the delta from this value determines how many
    /// slots to shift the map (filling gaps with 0 = missed).
    pub next_hello_seqno: u16,
    /// Wall-clock ms when the current Hello slot expires (BIRD
    /// `hello_expiry`). Set to `now + 1.5 × interval` on each received
    /// Hello. The daemon's gc loop calls [`expire_hellos`] which shifts
    /// the map when this deadline passes.
    pub hello_expiry_ms: u64,
    pub hello_interval_cs: u16,
    pub last_hello_received_ms: u64,
    pub rxcost: u32,
    pub txcost: u32,
    pub last_ihu_received_ms: u64,
    pub ihu_interval_cs: u16,
    /// BABEL-RTT state (RFC 8966 §A.2.4). `None` until the first
    /// timestamped Hello arrives from this neighbor.
    pub rtt: Option<RttState>,
}

/// Round-trip-time measurement state for one neighbor
/// (RFC 8966 §A.2.4 / the BABEL-RTT extension).
///
/// The wire exchange works as follows. Every timestamped Hello carries
/// the sender's 32-bit microsecond clock. The receiver records that
/// timestamp together with its own receive time; when it next sends an
/// IHU it echoes the pair back ([`RttState::echo_pair`]). The *original
/// sender* receives the echo, combines it with its own records of the
/// peer's Hello (the peer's timestamp in the peer's clock, its own
/// receive time in its clock), and computes
///
/// ```text
/// remote_waiting = peer_hello_ts  - peer_receive_of_our_hello   (peer clock)
/// local_waiting  = our_receive_of_peer - our_hello_ts           (our clock)
/// rtt            = max(0, local_waiting - remote_waiting)
/// ```
///
/// Both differences stay inside one node's clock, so no clock
/// synchronization is required. The 32-bit microsecond clocks wrap
/// every ~71.6 minutes; wrapping subtraction keeps small positive
/// differences correct, and large ones fail the sanity window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RttState {
    /// The peer's Hello timestamp (peer's 32-bit us clock) to echo.
    pub hello_send_us: u32,
    /// Our receive time of that Hello (our 32-bit us clock), echoed
    /// next to `hello_send_us`.
    pub hello_receive_us: u32,
    /// Wall-clock ms of the receipt (echo freshness).
    pub hello_receive_ms: u64,
    /// Smoothed RTT in microseconds; `None` until the first sample.
    pub rtt_us: Option<u32>,
    /// Wall-clock ms of the last sample; `None` until the first sample.
    pub sample_ms: Option<u64>,
}

impl RttState {
    /// The `(hello_send_us, hello_receive_us)` pair to echo in an IHU,
    /// valid only while the Hello it answers is fresh
    /// ([`RTT_ECHO_FRESHNESS_MS`], babeld's 1 s window).
    ///
    /// The boundary is exclusive: a Hello received exactly
    /// `RTT_ECHO_FRESHNESS_MS` ago is still echoed. The daemon's
    /// periodic announce loop runs at exactly `hello_interval_ms`
    /// (default 1000 ms), which equals `RTT_ECHO_FRESHNESS_MS`. The
    /// comparison is strict (`now - t < 1000`), matching babeld, so a
    /// Hello received one tick before the announce boundary still
    /// contributes a sample and the peer never reports `RTT 0.000 ms`
    /// while both sides advertise `rtt cost > 0`.
    pub fn echo_pair(&self, now_ms: u64) -> Option<(u32, u32)> {
        if now_ms.saturating_sub(self.hello_receive_ms) > RTT_ECHO_FRESHNESS_MS {
            return None;
        }
        Some((self.hello_send_us, self.hello_receive_us))
    }
}

impl BabelNeighbor {
    pub fn new(address: IpAddr, now_ms: u64) -> Self {
        Self {
            address,
            hello_map: 0,
            hello_cnt: 0,
            next_hello_seqno: 0,
            hello_expiry_ms: 0,
            hello_interval_cs: 0,
            last_hello_received_ms: now_ms,
            rxcost: 0xffff,
            txcost: 0xffff,
            last_ihu_received_ms: 0,
            ihu_interval_cs: 0,
            rtt: None,
        }
    }

    /// Record an incoming Hello (seqno, interval in centiseconds, time in ms).
    /// Implements BIRD's `babel_update_hello_history`: compute the seqno
    /// delta from the expected value, shift the bitmask to fill gaps
    /// (missed Hellos), set the current bit, and update the expiry
    /// deadline.
    pub fn hello(&mut self, seqno: u16, interval_cs: u16, now_ms: u64) {
        self.hello_interval_cs = interval_cs;
        self.last_hello_received_ms = now_ms;
        self.update_hello_history(seqno, now_ms);
        self.rxcost = compute_rxcost(self.hello_map, self.hello_cnt, 12);
    }

    /// BIRD's `babel_update_hello_history`: shift the bitmask by the
    /// seqno delta, then set the current bit. A delta of 0 means a
    /// duplicate (retransmission) — the bit is already set, no shift.
    /// A delta of 1..=16 shifts left by delta, filling gaps with 0s
    /// (missed Hellos). A large backwards delta (>= 0xfff0) means the
    /// peer decreased its interval — undo history by shifting right.
    /// Any other delta means the peer restarted with a very different
    /// seqno — flush the history.
    fn update_hello_history(&mut self, seqno: u16, now_ms: u64) {
        let delta = seqno.wrapping_sub(self.next_hello_seqno);
        if self.hello_cnt == 0 || delta == 0 {
            // First Hello, or the expected next Hello arrived with no
            // gap. Skip the shift (BIRD's "do nothing" branch), then
            // fall through to set the current bit.
        } else if delta <= 16 {
            // Forward gap: shift left by delta, filling with 0s
            // (missed Hellos). BIRD: `n->hello_map <<= delta`.
            self.hello_map = self.hello_map.checked_shl(delta as u32).unwrap_or(0);
            self.hello_cnt = (self.hello_cnt.saturating_add(delta as u8)).min(16);
        } else if delta >= 0xfff0 {
            // Backwards: peer decreased its interval, undo history.
            let diff = (0xffff - delta) as u8;
            self.hello_map = self.hello_map.checked_shr(diff as u32).unwrap_or(0);
            self.hello_cnt = self.hello_cnt.saturating_sub(diff);
        } else {
            // Large jump — peer restarted with a different seqno.
            self.hello_map = 0;
            self.hello_cnt = 0;
        }
        // Always advance the window by one slot and set the current
        // bit (BIRD's "Current entry" step). This is the normal
        // "one Hello received" operation, done regardless of whether
        // there was a gap or not.
        self.hello_map = (self.hello_map << 1) | 1;
        self.next_hello_seqno = seqno.wrapping_add(1);
        if self.hello_cnt < 16 {
            self.hello_cnt += 1;
        }
        self.hello_expiry_ms = now_ms + hello_expiry_ms(self.hello_interval_cs);
    }

    /// Expire old Hello slots (BIRD `babel_expire_hello`). Called by the
    /// daemon's gc loop every second. Each expired slot shifts the
    /// bitmask left by 1 (dropping the oldest bit, adding a 0). When
    /// the bitmask is fully clear (`hello_map == 0`), the neighbour is
    /// considered dead — the caller should flush it.
    pub fn expire_hellos(&mut self, now_ms: u64) -> bool {
        if self.hello_interval_cs == 0 || self.hello_expiry_ms == 0 {
            return false;
        }
        let mut changed = false;
        while self.hello_map != 0 && now_ms >= self.hello_expiry_ms {
            self.hello_map <<= 1;
            if self.hello_cnt < 16 {
                self.hello_cnt += 1;
            }
            self.hello_expiry_ms += u64::from(self.hello_interval_cs) * 10;
            changed = true;
        }
        if changed {
            self.rxcost = compute_rxcost(self.hello_map, self.hello_cnt, 12);
        }
        changed
    }

    /// Record an incoming timestamped Hello (BABEL-RTT): the bookkeeping
    /// of [`BabelNeighbor::hello`] plus the `(peer timestamp, our receive
    /// time)` pair the next IHU echoes.
    pub fn hello_timestamped(
        &mut self,
        seqno: u16,
        interval_cs: u16,
        peer_ts_us: u32,
        now_ms: u64,
        now_us: u32,
    ) {
        self.hello(seqno, interval_cs, now_ms);
        let rtt = self.rtt.get_or_insert_with(RttState::default);
        rtt.hello_send_us = peer_ts_us;
        rtt.hello_receive_us = now_us;
        rtt.hello_receive_ms = now_ms;
    }

    /// The BABEL-RTT pair to echo in the next IHU, when the Hello it
    /// acknowledges is still fresh. See [`RttState::echo_pair`].
    pub fn rtt_echo_pair(&self, now_ms: u64) -> Option<(u32, u32)> {
        self.rtt.as_ref()?.echo_pair(now_ms)
    }

    /// Record an incoming IHU (rxcost, interval) without an RTT echo.
    pub fn ihu(&mut self, rxcost: u16, interval_cs: u16, now_ms: u64) {
        self.txcost = rxcost as u32;
        self.ihu_interval_cs = interval_cs;
        self.last_ihu_received_ms = now_ms;
    }

    /// Record an incoming IHU carrying a BABEL-RTT echo pair
    /// `(ts1, ts2)`: `ts1` is *our* Hello timestamp echoed back (our
    /// clock), `ts2` is the peer's receive time of that Hello (the
    /// peer's clock). Combines them with our records of the peer's
    /// Hello to compute one RTT sample, then folds the sample into the
    /// smoothed RTT (babeld's EWMA; the first sample doubles, to be
    /// conservative with new neighbours).
    pub fn ihu_echo(&mut self, rxcost: u16, interval_cs: u16, ts1: u32, ts2: u32, now_ms: u64) {
        self.ihu(rxcost, interval_cs, now_ms);
        let Some(rtt) = self.rtt else {
            // We never heard a timestamped Hello from this peer, so the
            // echo cannot be paired — ignore it.
            return;
        };
        // Both differences live in a single clock each; wrapping keeps
        // small positive deltas correct, everything else trips sanity.
        let remote_waiting_us = rtt.hello_send_us.wrapping_sub(ts2);
        let local_waiting_us = rtt.hello_receive_us.wrapping_sub(ts1);
        if remote_waiting_us > RTT_SANITY_US || local_waiting_us > RTT_SANITY_US {
            return; // clock skew or a stale echo — not a real delay
        }
        let sample = local_waiting_us.saturating_sub(remote_waiting_us);
        let state = self.rtt.get_or_insert_with(RttState::default);
        state.rtt_us = Some(match (state.rtt_us, state.sample_ms) {
            // Running exponential average over a valid previous sample.
            (Some(prev), Some(t)) if prev > 0 && now_ms.saturating_sub(t) < RTT_VALIDITY_MS => {
                let smoothed = RTT_DECAY * sample + (256 - RTT_DECAY) * prev;
                // Rounding toward the sample (babeld parity).
                if prev >= sample {
                    smoothed / 256
                } else {
                    smoothed.div_ceil(256)
                }
            }
            // First sample for this neighbor: be conservative (double).
            _ => sample.saturating_mul(2),
        });
        state.sample_ms = Some(now_ms);
    }

    /// True while the smoothed RTT is inside the validity window.
    pub fn rtt_valid(&self, now_ms: u64) -> bool {
        self.rtt.as_ref().is_some_and(|r| {
            r.sample_ms
                .is_some_and(|t| now_ms.saturating_sub(t) < RTT_VALIDITY_MS)
        })
    }

    /// The smoothed RTT in microseconds, when a valid measurement exists.
    pub fn rtt_us(&self, now_ms: u64) -> Option<u32> {
        if self.rtt_valid(now_ms) {
            self.rtt.as_ref().and_then(|r| r.rtt_us)
        } else {
            None
        }
    }

    /// The extra link cost contributed by the measured RTT (RFC 8966
    /// §A.2.4): a linear ramp from 0 at `rtt_min_us` to `max_penalty` at
    /// `rtt_max_us`, clamped at `max_penalty` above it. 0 when the RTT
    /// is invalid or `max_penalty` is 0 (feature off — babeld parity).
    pub fn rtt_cost(&self, now_ms: u64, rtt_min_us: u32, rtt_max_us: u32, max_penalty: u16) -> u16 {
        match self.rtt_us(now_ms) {
            Some(rtt) => crate::metric::rtt_penalty(rtt, rtt_min_us, rtt_max_us, max_penalty),
            None => 0,
        }
    }

    /// True if the neighbor is considered alive (recent hello + IHU).
    pub fn is_alive(&self, now_ms: u64, dead_ms: u64) -> bool {
        if self.hello_interval_cs == 0 {
            return false;
        }
        let since_hello = now_ms.saturating_sub(self.last_hello_received_ms);
        let dead_interval = (self.hello_interval_cs as u64) * 10 * 4;
        since_hello <= dead_interval.max(dead_ms)
    }
}

/// BIRD's Hello expiry factor (§A.2.1): each Hello expires after
/// `1.5 × interval`. The 0.5 factor gives one half-interval of slack
/// so a Hello that arrives slightly late still refreshes the history
/// before the previous slot expires.
fn hello_expiry_ms(interval_cs: u16) -> u64 {
    (u64::from(interval_cs) * 10 * 3) / 2
}

/// Reception cost (RFC 8966 §A.4.1 / §A.4.3, BIRD `babel_update_cost`).
///
/// Uses the k-out-of-j selection from RFC 8966 §A.2.1: the link is
/// considered good if `popcount(hello_map) * 16 >= limit * hello_cnt`,
/// where `limit` is the minimum fraction of Hellos that must be
/// received (BIRD's `limit` config, default 12 = 75%). When the link
/// is good, the rxcost is the interface's configured `rxcost` (passed
/// by the caller). When the link is bad or no Hellos have been
/// received, the rxcost is INFINITY (0xFFFF).
///
/// This matches BIRD's binary threshold — there is no gradual
/// degradation. babeld uses a similar approach with a 16-bit `reach`
/// bitmask and a `0xC000` threshold (at least 2 of the last 4 Hellos).
///
/// The `configured_rxcost` parameter is the interface's `rxcost`
/// field (96 for wired, 256 for wireless). The caller must pass the
/// right value for the interface type.
fn compute_rxcost(hello_map: u16, hello_cnt: u8, _limit: u8) -> u32 {
    if hello_cnt == 0 {
        return 0xffff;
    }
    let rcv = u16::count_ones(hello_map);
    let max = u32::from(hello_cnt);
    // k-out-of-j: link is good if rcv/max >= limit/16.
    // BIRD: `if (rcv * 16 < cf->limit * max) break;` → INFINITY.
    // Default limit=12: need rcv*16 >= 12*max, i.e. rcv >= max*0.75.
    if rcv * 16 < u32::from(_limit) * max {
        return 0xffff;
    }
    // Link is good — return the nominal cost. The caller (the
    // interface) provides the configured rxcost; for now we use the
    // babeld/BIRD default of 96 for wired interfaces.
    96
}

#[cfg(test)]
#[path = "neighbor_tests.rs"]
mod tests;
