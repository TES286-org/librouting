//! Multi-session Babel semantics at the router level (ROADMAP-v3 D1):
//! per-session split horizon through `babel_reachable`, link-down route
//! flushing through `babel_flush_session`, and the BABEL-RTT round trip
//! through `feed_input_at` (RFC 8966 §A.2.4).

use lr_babel::message::{Hello, Ihu, NextHop, RouterId as RouterIdTlv, Update};
use lr_babel::tlv::{Tlv, TlvType};
use lr_core::addr::{IpAddr, Prefix};
use lr_core::rib::Protocol;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

/// Build a Babel frame announcing `prefix` on behalf of `router_id`
/// (the source claim, §4.6.7: the Router-Id TLV applies to the Updates
/// that follow it).
fn peer_frame(router_id: [u8; 8], prefix: [u8; 3], seqno: u16, metric: u16) -> Vec<u8> {
    let mut frame = lr_babel::BabelFrame::empty();
    frame.body.push(Tlv::new(
        TlvType::RouterId,
        RouterIdTlv { id: router_id }.encode().to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 1,
            address: IpAddr::V4([127, 10, 0, 1]),
        }
        .encode(),
    ));
    frame.body.push(Tlv::new(
        TlvType::Update,
        Update {
            ae: 1,
            flags: 0,
            prefix_len: 24,
            omitted: 0,
            interval_cs: 300,
            seqno,
            metric,
            prefix: prefix.to_vec(),
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        }
        .encode(),
    ));
    lr_babel::BabelCodec::new().encode_vec(&frame).unwrap()
}

fn babel_session(r: &mut DefaultRouter, local: IpAddr) -> lr_router::SessionHandle {
    let h = r.add_session(SessionConfig::babel(local)).unwrap();
    r.start_session(h).unwrap();
    h
}

#[test]
fn babel_reachable_excludes_the_learning_session() {
    let mut r = DefaultRouter::new();
    let a = babel_session(&mut r, IpAddr::V4([127, 10, 0, 2]));
    let b = babel_session(&mut r, IpAddr::V4([127, 20, 0, 2]));
    // Session A learns 10.99.1.0/24 from origin 8.8.8.8.
    r.feed_input(a, &peer_frame([8, 8, 8, 8, 0, 0, 0, 1], [10, 99, 1], 7, 96))
        .unwrap();
    // Session B learns 10.99.2.0/24 from origin 9.9.9.9.
    r.feed_input(b, &peer_frame([9, 9, 9, 9, 0, 0, 0, 2], [10, 99, 2], 3, 96))
        .unwrap();

    let from_a = r.babel_reachable(a);
    assert_eq!(from_a.len(), 1, "A re-advertises only B's route");
    assert_eq!(
        from_a[0].key.destination,
        Prefix::new_v4([10, 99, 2, 0], 24)
    );
    assert_eq!(from_a[0].key.router_id, [9, 9, 9, 9, 0, 0, 0, 2]);
    assert_eq!(from_a[0].seqno, 3, "the origin's seqno is preserved");

    let from_b = r.babel_reachable(b);
    assert_eq!(from_b.len(), 1, "B re-advertises only A's route");
    assert_eq!(
        from_b[0].key.destination,
        Prefix::new_v4([10, 99, 1, 0], 24)
    );
    assert_eq!(from_b[0].key.router_id, [8, 8, 8, 8, 0, 0, 0, 1]);

    // Both routes are in Loc-RIB (the merged view).
    assert_eq!(
        r.rib_snapshot()
            .iter()
            .filter(|rt| rt.protocol == Protocol::Babel)
            .count(),
        2
    );
}

#[test]
fn babel_reachable_dedups_by_source_claim_lowest_metric() {
    let mut r = DefaultRouter::new();
    let a = babel_session(&mut r, IpAddr::V4([127, 10, 0, 2]));
    let b = babel_session(&mut r, IpAddr::V4([127, 20, 0, 2]));
    let c = babel_session(&mut r, IpAddr::V4([127, 30, 0, 2]));
    // A and B both learn the same claim from the same origin, A cheaper.
    r.feed_input(a, &peer_frame([8, 8, 8, 8, 0, 0, 0, 1], [10, 99, 1], 7, 96))
        .unwrap();
    r.feed_input(
        b,
        &peer_frame([8, 8, 8, 8, 0, 0, 0, 1], [10, 99, 1], 7, 150),
    )
    .unwrap();
    let from_c = r.babel_reachable(c);
    assert_eq!(from_c.len(), 1);
    assert_eq!(from_c[0].metric, 96, "the cheaper claim wins");
}

#[test]
fn babel_flush_session_withdraws_its_routes() {
    let mut r = DefaultRouter::new();
    let a = babel_session(&mut r, IpAddr::V4([127, 10, 0, 2]));
    let b = babel_session(&mut r, IpAddr::V4([127, 20, 0, 2]));
    r.feed_input(a, &peer_frame([8, 8, 8, 8, 0, 0, 0, 1], [10, 99, 1], 7, 96))
        .unwrap();
    r.feed_input(b, &peer_frame([9, 9, 9, 9, 0, 0, 0, 2], [10, 99, 2], 3, 96))
        .unwrap();
    assert_eq!(
        r.rib_snapshot()
            .iter()
            .filter(|rt| rt.protocol == Protocol::Babel)
            .count(),
        2
    );

    // The link behind A goes down: A's learned route leaves the RIB...
    r.babel_flush_session(a);
    let babel_routes: Vec<_> = r
        .rib_snapshot()
        .iter()
        .filter(|rt| rt.protocol == Protocol::Babel)
        .map(|rt| rt.key.prefix)
        .collect();
    assert_eq!(babel_routes, [Prefix::new_v4([10, 99, 2, 0], 24)]);

    // ...and with it the re-advertisement of A's route toward B.
    assert!(r.babel_reachable(b).is_empty());
    // The session itself survives (the link may come back).
    let _ = r.session_summaries(); // must not panic for the flushed session
}

#[test]
fn babel_flush_session_on_unknown_handle_is_a_noop() {
    let mut r = DefaultRouter::new();
    r.babel_flush_session(lr_router::SessionHandle(999));
}

/// One full BABEL-RTT exchange over the router's feed path: our Hello
/// timestamp, the peer's timestamped Hello, and the peer's IHU echoing
/// our pair. The transport's 32-bit microsecond clock is the same one
/// the daemon draws outgoing timestamps from.
#[test]
fn feed_input_at_drives_the_rtt_measurement() {
    let mut r = DefaultRouter::new();
    let a = babel_session(&mut r, IpAddr::V4([127, 10, 0, 2]));

    // Our clock says we sent our Hello at 100_000 us.
    let our_hello_ts = 100_000u32;
    // The peer received it at peer-time 5_002_000, and sent its own
    // timestamped Hello at peer-time 5_003_000, which reaches us at
    // our-time 104_500 (d1=2ms, remote_wait=1ms, d2=1.5ms → RTT 3.5ms).
    let mut frame = lr_babel::BabelFrame::empty();
    frame.body.push(Tlv::new(
        TlvType::Hello,
        Hello::new(1, 100).with_timestamp(5_003_000).encode(),
    ));
    let wire = lr_babel::BabelCodec::new().encode_vec(&frame).unwrap();
    r.feed_input_at(a, &wire, 104_500).unwrap();

    // The peer's IHU echoes (our 100_000, its 5_002_000).
    let mut ihu = lr_babel::BabelFrame::empty();
    ihu.body.push(Tlv::new(
        TlvType::Ihu,
        Ihu::new(96, 300)
            .with_timestamp_echo(our_hello_ts, 5_002_000)
            .encode(),
    ));
    let wire = lr_babel::BabelCodec::new().encode_vec(&ihu).unwrap();
    r.feed_input_at(a, &wire, 110_000).unwrap();

    // First sample doubles (conservative start): 2 × 3.5 ms.
    assert_eq!(r.babel_rtt_us(a, 110), Some(7_000));
    // An unknown session reports nothing.
    assert_eq!(r.babel_rtt_us(lr_router::SessionHandle(999), 110), None);
}
