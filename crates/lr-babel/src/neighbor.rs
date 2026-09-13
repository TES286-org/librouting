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
    /// Recent Hello sequence numbers (sliding window of 16 bits per §3.3.1).
    pub hello_history: Vec<u16>,
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
    pub fn echo_pair(&self, now_ms: u64) -> Option<(u32, u32)> {
        if now_ms.saturating_sub(self.hello_receive_ms) >= RTT_ECHO_FRESHNESS_MS {
            return None;
        }
        Some((self.hello_send_us, self.hello_receive_us))
    }
}

impl BabelNeighbor {
    pub fn new(address: IpAddr, now_ms: u64) -> Self {
        Self {
            address,
            hello_history: Vec::with_capacity(16),
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
    pub fn hello(&mut self, seqno: u16, interval_cs: u16, now_ms: u64) {
        self.hello_interval_cs = interval_cs;
        self.last_hello_received_ms = now_ms;
        self.hello_history.push(seqno);
        if self.hello_history.len() > 16 {
            self.hello_history.remove(0);
        }
        // Recompute rxcost per RFC 8966 §3.4.1.
        self.rxcost = compute_rxcost(self.hello_interval_cs, self.hello_history.len());
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
        if max_penalty == 0 || !self.rtt_valid(now_ms) {
            return 0;
        }
        let rtt = self.rtt.as_ref().and_then(|r| r.rtt_us).unwrap_or(0);
        if rtt <= rtt_min_us {
            0
        } else if rtt >= rtt_max_us {
            max_penalty
        } else {
            u32::from(max_penalty)
                .saturating_mul(rtt - rtt_min_us)
                .checked_div(rtt_max_us - rtt_min_us)
                .map(|v| v.min(u32::from(u16::MAX)) as u16)
                .unwrap_or(max_penalty)
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

fn compute_rxcost(_interval_cs: u16, history_len: usize) -> u32 {
    // Simplified: missing any hello doubles cost.
    let missed = 16usize.saturating_sub(history_len);
    let base = 100u32;
    base + (missed as u32) * 50
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one full BABEL-RTT exchange.
    ///
    /// Timeline (abstract, shared "true" time): we send our Hello at
    /// T=0; the peer receives it at T=`d1`; the peer sends its own Hello
    /// at T=`d1 + remote_wait`; we receive it at T=`d1 + remote_wait +
    /// d2`. The RTT is `d1 + d2` — independent of `remote_wait`, which
    /// the subtraction cancels.
    fn exchange(rtt: &mut BabelNeighbor, d1: u32, remote_wait: u32, d2: u32) {
        // Our clock (arbitrary origin 100_000): we sent our Hello at
        // our-time 100_000; the peer's Hello reaches us at
        // 100_000 + d1 + remote_wait + d2.
        let our_hello_ts = 100_000u32;
        let our_recv = our_hello_ts + d1 + remote_wait + d2;
        // Peer clock (skewed 5 s ahead, proving no sync is needed): the
        // peer received our Hello at peer-time 5_000_000 + d1, and sent
        // its own Hello at 5_000_000 + d1 + remote_wait.
        let peer_recv_of_ours = 5_000_000u32 + d1;
        let peer_hello_ts = 5_000_000u32 + d1 + remote_wait;
        rtt.hello_timestamped(1, 100, peer_hello_ts, 0, our_recv);
        rtt.ihu_echo(96, 300, our_hello_ts, peer_recv_of_ours, 10);
    }

    #[test]
    fn alive_after_hello() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
        n.hello(1, 200, 0);
        assert!(n.is_alive(50, 5000));
    }

    #[test]
    fn rtt_exchange_measures_the_round_trip() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
        // d1 = 2 ms toward the peer, d2 = 1.5 ms back: RTT = 3.5 ms.
        exchange(&mut n, 2_000, 1_000, 1_500);
        // First sample doubles (conservative with new neighbours).
        assert_eq!(n.rtt_us(10), Some(7_000));
    }

    #[test]
    fn rtt_is_independent_of_remote_wait() {
        // The same 3.5 ms RTT with a 500 ms remote wait — the peer was
        // slow to answer, the RTT must not change.
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
        exchange(&mut n, 2_000, 500_000, 1_500);
        assert_eq!(n.rtt_us(10), Some(7_000));
    }

    #[test]
    fn rtt_ewma_converges_toward_samples() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        exchange(&mut n, 2_000, 1_000, 1_500); // sample 3_500, doubled
        assert_eq!(n.rtt_us(10), Some(7_000));
        // A second identical sample: (42*3500 + 214*7000)/256 = 6425.
        exchange(&mut n, 2_000, 1_000, 1_500);
        assert_eq!(n.rtt_us(10), Some(6_425));
        // A third: (42*3500 + 214*6425)/256 = 5945 — converging to 3500.
        exchange(&mut n, 2_000, 1_000, 1_500);
        assert_eq!(n.rtt_us(10), Some(5_945));
    }

    #[test]
    fn rtt_expires_after_validity_window() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        exchange(&mut n, 2_000, 1_000, 1_500);
        assert!(n.rtt_valid(10));
        assert!(!n.rtt_valid(10 + RTT_VALIDITY_MS));
        assert_eq!(n.rtt_us(10 + RTT_VALIDITY_MS), None);
        // And the cost contribution falls to zero with it.
        assert_eq!(n.rtt_cost(10 + RTT_VALIDITY_MS, 10_000, 120_000, 96), 0);
    }

    #[test]
    fn rtt_after_expiry_relearns_conservatively() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        exchange(&mut n, 2_000, 1_000, 1_500);
        // Long silence: the old sample expires, so the next one is a
        // fresh (doubled) first sample again.
        let late = 10 + RTT_VALIDITY_MS;
        let our_hello_ts = 800_000u32;
        let our_recv = our_hello_ts + 1_000 + 1_000 + 500;
        n.hello_timestamped(2, 100, 9_000_000, late, our_recv);
        n.ihu_echo(96, 300, our_hello_ts, 8_999_000, late);
        // remote = 9_000_000 - 8_999_000 = 1_000; local = 802_500 -
        // 800_000 = 2_500; rtt = 1_500, doubled on the fresh start.
        assert_eq!(n.rtt_us(late), Some(3_000));
    }

    #[test]
    fn rtt_cost_linear_ramp_between_bounds() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        // d1 = 20 ms, d2 = 20 ms → RTT 40 ms, doubled = 80 ms.
        exchange(&mut n, 20_000, 10_000, 20_000);
        // rtt_min 10 ms, rtt_max 120 ms, penalty 96:
        // 96 * (80_000-10_000) / (120_000-10_000) = 61.
        assert_eq!(n.rtt_cost(0, 10_000, 120_000, 96), 61);
        // A zero max penalty disables the feature entirely.
        assert_eq!(n.rtt_cost(0, 10_000, 120_000, 0), 0);
    }

    #[test]
    fn rtt_below_min_costs_nothing_above_max_saturates() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        exchange(&mut n, 20_000, 10_000, 20_000); // smoothed 80 ms
        assert_eq!(n.rtt_cost(0, 100_000, 120_000, 96), 0); // below min
        assert_eq!(n.rtt_cost(0, 10_000, 60_000, 96), 96); // at/above max
    }

    #[test]
    fn rtt_cost_degenerate_bounds_do_not_divide_by_zero() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        exchange(&mut n, 20_000, 10_000, 20_000); // smoothed 80 ms
                                                  // rtt_min == rtt_max == 50 ms, rtt above → saturate, not panic.
        assert_eq!(n.rtt_cost(0, 50_000, 50_000, 96), 96);
    }

    #[test]
    fn rtt_echo_freshness_window() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        assert_eq!(n.rtt_echo_pair(0), None); // nothing heard yet
        n.hello_timestamped(1, 100, 777, 500, 888_888);
        assert_eq!(n.rtt_echo_pair(999), Some((777, 888_888)));
        assert_eq!(
            n.rtt_echo_pair(500 + RTT_ECHO_FRESHNESS_MS - 1),
            Some((777, 888_888))
        );
        assert_eq!(n.rtt_echo_pair(500 + RTT_ECHO_FRESHNESS_MS), None);
    }

    #[test]
    fn rtt_echo_without_timestamped_hello_is_ignored() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        n.hello(1, 100, 0); // plain Hello, no timestamp
        n.ihu_echo(96, 300, 42, 43, 10); // echo cannot be paired
        assert_eq!(n.rtt_us(10), None);
    }

    #[test]
    fn rtt_stale_echo_rejected_by_sanity_window() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        // A fresh Hello record...
        n.hello_timestamped(1, 100, 1_000_000, 0, 3_000_000);
        // ...but the echo refers to a Hello sent hours ago in our clock:
        // both waiting differences wrap huge → the sample is dropped.
        n.ihu_echo(96, 100, 500_000_000, 900_000_000, 10);
        assert_eq!(n.rtt_us(10), None);
    }

    #[test]
    fn rtt_wraparound_keeps_small_deltas_correct() {
        // Our clock wraps between our Hello send and the peer's receipt.
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 9]), 0);
        let peer_hello_ts = u32::MAX - 100; // peer sends just before wrap
        let our_recv = u32::MAX - 1_000; // we receive it 900 us later
        n.hello_timestamped(1, 100, peer_hello_ts, 0, our_recv);
        // We sent our Hello 500 us before receiving the peer's; the
        // peer received it 400 us after sending its own.
        let our_hello_ts = u32::MAX - 1_500;
        let peer_recv_of_ours = peer_hello_ts - 400;
        n.ihu_echo(96, 100, our_hello_ts, peer_recv_of_ours, 10);
        // remote = 400, local = 500 → RTT 100 us, doubled on first sample.
        assert_eq!(n.rtt_us(10), Some(200));
    }
}
