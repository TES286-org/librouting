//! The KEEPALIVE-arrival timestamp (`SessionStats::last_keepalive_received_ms`)
//! is the "peer response speed" health metric issue #52 asks for: a
//! recent value means the peer is alive and responsive; a stale value
//! (relative to `now_ms` and the negotiated hold time) means the
//! session is heading for a hold-timer expiry.
//!
//! The router latches the timestamp inside `feed_input_at` when the
//! `PeerMessageStats::keepalive_received` counter advances — so the
//! arrival time is whatever `now_ms` the caller passes. The BGP
//! reactor computes `now_ms` once per iteration *after* `poll.poll`
//! returns (matching the Babel and OSPF mio loops) and threads it
//! through `pump_readable` → `feed_input_at`, so the timestamp is the
//! post-poll arrival time — the same class of fix PR #118 applied to
//! the BFD mio loop's detection timer.
//!
//! These tests pin the router-level contract the reactor relies on:
//! a KEEPALIVE that arrives through `feed_input_at(now_ms = T)` latches
//! `last_keepalive_received_ms = T`, and a later KEEPALIVE at `T'` moves
//! the latch to `T'`. The daemon-level end-to-end test (the reactor
//! driving a real socket pair) lives in `crates/lr-cli/src/bgp_reactor.rs`.

use lr_bgp::message::Keepalive;
use lr_bgp::{BgpCodec, BgpMessage};
use lr_core::addr::{Asn, IpAddr, RouterId};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

/// Drive the byte pump until both routers' output buffers drain. The
/// shape mirrors `crates/lr-tests/tests/tutorial_snippets.rs::pump`,
/// kept local so this test stays a single-crate dependency.
fn pump(
    a: &mut DefaultRouter,
    ha: lr_router::SessionHandle,
    b: &mut DefaultRouter,
    hb: lr_router::SessionHandle,
) {
    for _ in 0..16 {
        let out_a = a.drain_output(ha);
        if !out_a.is_empty() {
            b.feed_input(hb, &out_a).unwrap();
        }
        let out_b = b.drain_output(hb);
        if !out_b.is_empty() {
            a.feed_input(ha, &out_b).unwrap();
        }
        if out_a.is_empty() && out_b.is_empty() {
            return;
        }
    }
    panic!("byte pump did not converge");
}

/// One BGP session configured for a peer at 192.0.2.2, ready to start.
fn bgp_session(router: &mut DefaultRouter) -> lr_router::SessionHandle {
    router
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap()
}

/// `last_keepalive_received_ms` is zero before any KEEPALIVE arrives.
/// After two routers exchange OPENs (no KEEPALIVEs yet — the FSM
/// transitions OpenConfirm → Established on the OPEN arrival itself
/// when both sides use the default hold-time / keepalive interval),
/// the metric stays zero on both sides.
#[test]
fn last_keepalive_received_ms_is_zero_before_first_keepalive() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = bgp_session(&mut a);
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    let summaries = a.session_summaries();
    let s = summaries
        .iter()
        .find(|s| s.handle == ha)
        .expect("session summary present");
    assert_eq!(
        s.stats.last_keepalive_received_ms, 0,
        "no KEEPALIVE has arrived yet — the metric stays at its zero default"
    );
}

/// A KEEPALIVE that arrives through `feed_input_at(now_ms = T)` latches
/// `last_keepalive_received_ms = T`. This is the router-level contract
/// the BGP reactor's post-poll `now_ms` threading relies on: the
/// arrival time is whatever `now_ms` the caller passes, so the reactor
/// must pass the post-poll instant — a pre-poll `now_ms` would age
/// the metric by up to `POLL_TIMEOUT` (50 ms on the BGP reactor).
#[test]
fn feed_input_at_latches_keepalive_arrival_time() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = bgp_session(&mut a);
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    // Establish the session: the OPEN exchange drives both FSMs to
    // Established, where a KEEPALIVE is a legal inbound message.
    pump(&mut a, ha, &mut b, hb);

    // A standalone KEEPALIVE on the wire.
    let ka_bytes = BgpCodec::new()
        .encode_vec(&BgpMessage::Keepalive(Keepalive))
        .unwrap();
    // The arrival time is the post-poll logical clock. The reactor
    // would pass `start.elapsed().as_millis() as u64` after `poll.poll`
    // returned; the test passes a recognisable non-zero value so a
    // regression that latches 0 (the `feed_input` no-`now_ms` default)
    // surfaces.
    let arrival_ms = 12_345u64;
    a.feed_input_at(ha, &ka_bytes, arrival_ms, 0).unwrap();

    let summaries = a.session_summaries();
    let s = summaries
        .iter()
        .find(|s| s.handle == ha)
        .expect("session summary present");
    assert_eq!(
        s.stats.last_keepalive_received_ms, arrival_ms,
        "the KEEPALIVE's arrival time is the `now_ms` the caller passed — \
         a pre-poll `now_ms` or a `feed_input` default of 0 would \
         surface here as 0 or as a stale value"
    );
}

/// A later KEEPALIVE at `T'` moves the latch to `T'`. The metric is
/// the *most recent* arrival, not the first.
#[test]
fn feed_input_at_latches_the_most_recent_keepalive() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = bgp_session(&mut a);
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    let ka_bytes = BgpCodec::new()
        .encode_vec(&BgpMessage::Keepalive(Keepalive))
        .unwrap();
    a.feed_input_at(ha, &ka_bytes, 1_000, 0).unwrap();
    a.feed_input_at(ha, &ka_bytes, 2_500, 0).unwrap();
    a.feed_input_at(ha, &ka_bytes, 4_200, 0).unwrap();

    let summaries = a.session_summaries();
    let s = summaries
        .iter()
        .find(|s| s.handle == ha)
        .expect("session summary present");
    assert_eq!(
        s.stats.last_keepalive_received_ms, 4_200,
        "the most recent KEEPALIVE's arrival time wins"
    );
}

/// The legacy `feed_input` (no `now_ms` argument) latches zero — the
/// default `feed_input_at(h, bytes, 0, 0)` delegation. This pins the
/// behaviour every caller that has not yet migrated to `feed_input_at`
/// sees, so the migration is non-breaking on the wire side (the FSM
/// still receives the KEEPALIVE; only the metric stays at its zero
/// default). The BGP reactor's migration to `feed_input_at` is what
/// revives the metric in production.
#[test]
fn feed_input_without_now_ms_latches_zero() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = bgp_session(&mut a);
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    let ka_bytes = BgpCodec::new()
        .encode_vec(&BgpMessage::Keepalive(Keepalive))
        .unwrap();
    // `feed_input` is `feed_input_at(h, bytes, 0, 0)`: the KEEPALIVE
    // arrives, the FSM advances, but the metric latches 0 (the
    // legacy default). This is the behaviour the BGP reactor had
    // before the post-poll `now_ms` threading landed — the metric
    // was unconditionally dead in production.
    a.feed_input(ha, &ka_bytes).unwrap();

    let summaries = a.session_summaries();
    let s = summaries
        .iter()
        .find(|s| s.handle == ha)
        .expect("session summary present");
    assert_eq!(
        s.stats.last_keepalive_received_ms, 0,
        "feed_input (no now_ms) latches zero — the legacy default. \
         The reactor's migration to feed_input_at is what revives the metric."
    );
}
