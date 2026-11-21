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
    // The boundary is exclusive on the upper end: a Hello received
    // exactly `RTT_ECHO_FRESHNESS_MS` ago is still echoed. The
    // daemon's announce loop runs at `hello_interval_ms` (default
    // 1000 ms) — `>=` would drop the echo at the exact tick the
    // announce needs it, producing the persistent `RTT 0.000`
    // symptom on the BIRD peer even with both sides advertising
    // `rtt cost > 0`.
    assert_eq!(
        n.rtt_echo_pair(500 + RTT_ECHO_FRESHNESS_MS),
        Some((777, 888_888))
    );
    assert_eq!(n.rtt_echo_pair(500 + RTT_ECHO_FRESHNESS_MS + 1), None);
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

// ---------------------------------------------------------------------------
// rxcost — regression for the missed-hellos computation that used to
// confuse "history length" with "missed count" (defects.txt L244-L249).
// ---------------------------------------------------------------------------

/// First Hello: no missed packets to count yet — the bitmask has one
/// bit set, hello_cnt is 1. With limit=12: rcv=1, max=1, 1*16 >= 12*1,
/// link is good → rxcost = 96 (nominal wired cost).
#[test]
fn rxcost_first_hello_is_nominal() {
    let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
    n.hello(1, 100, 0);
    assert_eq!(n.rxcost, 96);
}

/// Consecutive Hellos with no gap: all bits set, link stays good.
#[test]
fn rxcost_perfect_reception_stays_at_nominal() {
    let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
    for seqno in 1..=8u16 {
        n.hello(seqno, 100, 0);
    }
    assert_eq!(n.rxcost, 96, "no missed Hellos => nominal rxcost");
}

/// Hellos 1, 2, 3, 5 (missed 4) — the bitmask has 3 bits set in a
/// 4-slot window. With limit=12: rcv=3, max=4, 3*16=48 >= 12*4=48,
/// link is still good → rxcost = 96. One missed Hello out of 4 is
/// 75% reception, exactly at the default limit threshold.
#[test]
fn rxcost_one_missed_hello_stays_nominal_at_default_limit() {
    let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
    n.hello(1, 100, 0);
    n.hello(2, 100, 0);
    n.hello(3, 100, 0);
    n.hello(5, 100, 0); // missed 4 in transit
    assert_eq!(
        n.rxcost, 96,
        "one missed Hello out of 4 is 75% — at the default limit=12 threshold"
    );
}

/// When enough Hellos are missed that the reception ratio drops below
/// the limit threshold, the rxcost flips to INFINITY (0xffff). This
/// matches BIRD's binary k-out-of-j selection — there is no gradual
/// degradation.
#[test]
fn rxcost_saturates_to_infinity_below_limit_threshold() {
    let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
    n.hello(1, 100, 0);
    n.hello(2, 100, 0);
    // Miss 14 Hellos (seqnos 3..=16), then receive 17. The bitmask
    // has 2 bits set in a 16-slot window: rcv=2, max=16,
    // 2*16=32 < 12*16=192 → INFINITY.
    n.hello(17, 100, 0);
    assert_eq!(
        n.rxcost, 0xffff,
        "2 of 16 Hellos received (12.5%) is below the 75% limit → INFINITY"
    );
}

/// Sequence numbers wrap modulo 2^16. The delta computation must handle
/// the wrap correctly.
#[test]
fn rxcost_wraps_correctly_across_seqno_modulus() {
    let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
    n.hello(u16::MAX - 1, 100, 0); // 65534
    n.hello(u16::MAX, 100, 0); // 65535
    n.hello(1, 100, 0); // wraps to 1; delta = 1 - 0 = 1 (mod 2^16)
    assert_eq!(n.rxcost, 96, "no gaps across the wrap → nominal");
}

/// Hello expiry: when the gc loop calls expire_hellos after the
/// 1.5× interval deadline, the bitmask shifts left, dropping old bits.
/// After enough expiries, the bitmask clears and rxcost goes to
/// INFINITY. This is BIRD's babel_expire_hello behavior.
#[test]
fn hello_expiry_shifts_bitmask_and_degrades_rxcost() {
    let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
    // interval_cs = 100 → 10 seconds. Expiry = 15 seconds.
    n.hello(1, 100, 0);
    assert_eq!(n.hello_map, 0b1);
    assert_eq!(n.rxcost, 96);
    // At t=1600ms, just past the 1500ms (1.5× interval) expiry.
    // One shift fires.
    let changed = n.expire_hellos(1_600);
    assert!(changed, "expiry should have fired");
    // Map shifted left by 1: 0b10 (the received bit moved, a 0 took
    // its place). hello_cnt grew to 2.
    assert_eq!(n.hello_map, 0b10);
    assert_eq!(n.hello_cnt, 2);
    // rcv=1, max=2, 1*16=16 >= 12*2=24? No, 16 < 24 → INFINITY.
    assert_eq!(
        n.rxcost, 0xffff,
        "one of two slots filled (50%) is below 75%"
    );
}

/// A large seqno jump (> 16) resets the history — the peer restarted
/// with a very different seqno (BIRD's "flush entries" branch).
#[test]
fn large_seqno_jump_resets_history() {
    let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
    n.hello(1, 100, 0);
    n.hello(2, 100, 0);
    n.hello(3, 100, 0);
    assert_eq!(n.hello_cnt, 3);
    // Jump by 100 — peer restarted.
    n.hello(103, 100, 0);
    assert_eq!(n.hello_cnt, 1, "history was reset by the large jump");
    assert_eq!(n.hello_map, 0b1);
    assert_eq!(n.rxcost, 96);
}
