//! Compile-and-run anchors for `docs/tutorial.md`.
//!
//! Every chapter of the tutorial mirrors a snippet from this file; if
//! the API drifts, this test breaks and the tutorial gets fixed in the
//! same commit. The snippets stay minimal on purpose — the deep
//! coverage lives in the neighboring e2e tests (`tcp_smoke.rs`,
//! `route_propagation.rs`).

use lr_bgp::message::keepalive::Keepalive;
use lr_bgp::message::{BgpMessage, Update};
use lr_bgp::path::{AsPath, AttrType, PathAttrFlags, PathAttribute};
use lr_bgp::{BgpCodec, BgpEvent, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

// ---- Chapter 1 — the wire -------------------------------------------------

#[test]
fn chapter1_keepalive_roundtrip() {
    let codec = BgpCodec::new();
    let bytes = codec.encode_vec(&BgpMessage::Keepalive(Keepalive)).unwrap();

    // `bytes` is the full RFC 4271 message: marker (16 x 0xFF), length,
    // type 4 (KEEPALIVE).
    assert_eq!(bytes[18], 4);
}

#[test]
fn chapter1_update_roundtrip() {
    let update = Update::new()
        .with_nlri([Prefix::new_v4([203, 0, 113, 0], 24)])
        .with_attribute(PathAttribute::new(
            PathAttrFlags(PathAttrFlags::TRANSITIVE),
            AttrType::AsPath,
            AsPath::from_sequence([Asn(64512)]).encode_4(),
        ));

    let codec = BgpCodec::new();
    let bytes = codec.encode_vec(&BgpMessage::Update(update)).unwrap();

    // The peer receives bytes and decodes them back.
    let mut peer_codec = BgpCodec::new();
    let msg = peer_codec.decode_slice(&bytes).unwrap().unwrap();
    match msg {
        BgpMessage::Update(u) => {
            assert_eq!(u.nlri.len(), 1);
            assert_eq!(u.nlri[0].prefix, Prefix::new_v4([203, 0, 113, 0], 24));
            // Read the AS path back from the attribute bag (canonical
            // 4-byte form — the codec merges AS4_PATH when present).
            let path = u.attributes.as_path().unwrap();
            assert_eq!(path.as_sequence(), vec![Asn(64512)]);
        }
        _ => panic!("expected an UPDATE"),
    }
}

// ---- Chapter 2 — two peers ------------------------------------------------

#[test]
fn chapter2_open_bytes() {
    let mut peer = BgpPeer::new(PeerConfig::new(
        Asn(64512),                       // local AS
        Asn(64513),                       // peer AS
        RouterId::from_v4([10, 0, 0, 1]), // local BGP identifier
    ));
    peer.step(BgpEvent::ManualStart);
    peer.step(BgpEvent::TransportOpen); // the TCP connection is up
    let open = peer.drain_outgoing(); // send these bytes to the peer
    assert!(
        !open.is_empty(),
        "OPEN queued on ManualStart + TransportOpen"
    );
}

#[test]
fn chapter2_two_peers_establish() {
    let mut a = BgpPeer::new(PeerConfig::new(
        Asn(64512),
        Asn(64513),
        RouterId::from_v4([10, 0, 0, 1]),
    ));
    let mut b = BgpPeer::new(PeerConfig::new(
        Asn(64513),
        Asn(64512),
        RouterId::from_v4([10, 0, 0, 2]),
    ));

    // Both sides start and their transports open.
    for peer in [&mut a, &mut b] {
        peer.step(BgpEvent::ManualStart);
        peer.step(BgpEvent::TransportOpen);
    }

    // Exchange each side's output with the other until the buffers run
    // dry. The FSM answers OPEN with KEEPALIVE; one exchange round is
    // enough for the default configuration.
    let a_out = a.drain_outgoing();
    let b_out = b.drain_outgoing();
    a.feed_bytes(&b_out).unwrap();
    b.feed_bytes(&a_out).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    a.feed_bytes(&b_ka).unwrap();
    b.feed_bytes(&a_ka).unwrap();

    assert!(a.is_established() && b.is_established());
}

// ---- Chapter 3 — the router pipeline --------------------------------------

fn pump(a: &mut DefaultRouter, ha: SessionHandle, b: &mut DefaultRouter, hb: SessionHandle) {
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

#[test]
fn chapter3_originate_propagate_withdraw() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    let _ = b.poll_events();

    let key = a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])), // NEXT_HOP for the eBGP advertisement
    );
    pump(&mut a, ha, &mut b, hb);

    let snapshot = b.rib_snapshot();
    assert_eq!(snapshot.len(), 1);
    let route = &snapshot[0];
    assert_eq!(route.key.prefix, Prefix::new_v4([203, 0, 113, 0], 24));
    assert_eq!(route.next_hop, Some(IpAddr::V4([192, 0, 2, 1])));

    // The AS path survived the wire: canonical 4-byte decode from the
    // route's attribute bag.
    let attrs: lr_bgp::path::PathAttributes = route.attributes.clone().into();
    assert_eq!(attrs.as_path().unwrap().as_sequence(), vec![Asn(64512)]);

    // b emitted RouteInstalled for it.
    assert!(b
        .poll_events()
        .into_iter()
        .any(|e| matches!(e, lr_router::RouterEvent::RouteInstalled(_))));

    // Withdrawing reverses everything.
    a.unoriginate(&key);
    pump(&mut a, ha, &mut b, hb);
    assert!(b.rib_snapshot().is_empty());
    assert!(b
        .poll_events()
        .into_iter()
        .any(|e| matches!(e, lr_router::RouterEvent::RouteWithdrawn(_))));
}
