//! Daemon-shaped Babel announcements: the periodic Hello + Router-Id +
//! Next-Hop + Update frame the babel daemon transport emits must install
//! into the Loc-RIB, both unsigned and through the RFC 8967 MAC layer
//! (the accepted plain body must keep its payload parseable).

use lr_babel::message::{Hello, Ihu, NextHop, RouterId as RouterIdTlv, Update};
use lr_babel::tlv::{Tlv, TlvType};
use lr_core::addr::{IpAddr, Prefix};
use lr_core::rib::Protocol;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

/// The exact announcement frame the daemon builds each second: Hello
/// followed by the IHU carrying the sender's rxcost for us (babeld/BIRD
/// parity — without an IHU the txcost stays infinite and no Update from
/// the neighbour can be accepted), then Router-Id + Next-Hop + Update.
fn announcement_frame(seqno: u16) -> Vec<u8> {
    let mut frame = lr_babel::BabelFrame::empty();
    frame.body.push(Tlv::new(
        TlvType::Hello,
        Hello::new(seqno, 100).encode().to_vec(),
    ));
    frame
        .body
        .push(Tlv::new(TlvType::Ihu, Ihu::new(96, 300).encode()));
    frame.body.push(Tlv::new(
        TlvType::RouterId,
        RouterIdTlv {
            id: [1, 2, 3, 4, 5, 6, 7, 8],
        }
        .encode()
        .to_vec(),
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
            metric: 96,
            prefix: vec![10, 99, 1],
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        }
        .encode(),
    ));
    lr_babel::BabelCodec::new().encode_vec(&frame).unwrap()
}

fn babel_session() -> (Box<dyn RouterInstance>, lr_router::SessionHandle) {
    let mut r: Box<dyn RouterInstance> = Box::new(DefaultRouter::new());
    let h = r
        .add_session(SessionConfig::babel(IpAddr::V4([127, 10, 0, 2])))
        .unwrap();
    r.start_session(h).unwrap();
    (r, h)
}

fn babel_route_metric(r: &dyn RouterInstance) -> Option<u32> {
    r.rib_snapshot()
        .iter()
        .find(|rt| {
            rt.protocol == Protocol::Babel && rt.key.prefix == Prefix::new_v4([10, 99, 1, 0], 24)
        })
        .map(|rt| rt.preference.metric)
}

#[test]
fn unsigned_announcement_installs_route() {
    let (mut r, h) = babel_session();
    r.feed_input(h, &announcement_frame(1)).unwrap();
    // The route installs with the RECEIVER-side link cost folded in
    // (RFC 8966 §3.4.3): advertised 96 + txcost 96 from the peer's IHU
    // = 192 — the metric the daemon re-advertises unchanged and the
    // Loc-RIB presents.
    assert_eq!(babel_route_metric(r.as_ref()), Some(192));
}

#[test]
fn authenticated_announcement_installs_route() {
    use lr_babel::{
        BabelAuthAction, BabelAuthConfig, BabelAuthInterface, BabelMacKey, BabelPseudoHeader,
        CounterNonceSource,
    };

    let (mut r, h) = babel_session();
    let key = BabelMacKey::new(b"link-secret");
    let mut cfg = BabelAuthConfig::new(key.clone());
    // Zero rate limits so the handshake completes inside the test loop.
    cfg.challenge_interval_ms = 0;
    cfg.reply_interval_ms = 0;
    let mut a = BabelAuthInterface::new(
        cfg.clone(),
        b"aaaa-index".to_vec(),
        0,
        Box::new(CounterNonceSource::default()),
    )
    .unwrap();
    let mut b = BabelAuthInterface::new(
        cfg,
        b"bbbb-index".to_vec(),
        0,
        Box::new(CounterNonceSource::default()),
    )
    .unwrap();

    let ph_mc = BabelPseudoHeader {
        source: IpAddr::V4([127, 10, 0, 1]),
        source_port: 16696,
        destination: IpAddr::V4([224, 0, 0, 111]),
        destination_port: 16696,
    };
    let ph_uc = BabelPseudoHeader {
        source: IpAddr::V4([127, 10, 0, 1]),
        source_port: 16696,
        destination: IpAddr::V4([127, 10, 0, 2]),
        destination_port: 16696,
    };
    let codec = lr_babel::BabelCodec::new();

    // B has no state for A: the first datagram triggers a Challenge Request
    // (§4.3.1.1); A answers with a Challenge Reply (§4.3.1.2) which B
    // accepts, seeding its neighbour state.
    let wire = a
        .authenticate_packet(&announcement_frame(1), ph_mc)
        .unwrap();
    let out = b.verify(&wire, ph_mc, 100);
    assert_eq!(out.reason, Some(lr_babel::BabelAuthError::IndexMismatch));
    let nonce = match &out.actions[0] {
        BabelAuthAction::SendChallengeRequest(n) => n.clone(),
        other => panic!("expected a challenge request, got {other:?}"),
    };
    let mut reply = lr_babel::BabelFrame::empty();
    reply.body.push(lr_babel::challenge_reply_tlv(&nonce));
    let reply_wire = a
        .authenticate_packet(&codec.encode_vec(&reply).unwrap(), ph_uc)
        .unwrap();
    let out = b.verify(&reply_wire, ph_uc, 110);
    assert!(out.accepted.is_some(), "challenge reply accepted");

    // The next announcement is accepted; its plain body still carries the
    // Update and installs the route (with the IHU-learned link cost
    // folded into the metric, exactly like the unsigned path).
    let wire = a
        .authenticate_packet(&announcement_frame(2), ph_mc)
        .unwrap();
    let out = b.verify(&wire, ph_mc, 200);
    let plain = out.accepted.expect("authenticated announcement accepted");
    r.feed_input(h, &plain).unwrap();
    assert_eq!(
        babel_route_metric(r.as_ref()),
        Some(192),
        "route must install through the RFC 8967 layer"
    );
}
