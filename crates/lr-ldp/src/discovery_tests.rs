
use super::*;
use crate::message::LdpPdu;
use crate::tlv::{ConfigSequenceNumber, HelloParams};

fn id(v: u8) -> LdpId {
    LdpId::new([v, 0, 0, 1], 0)
}

fn hello_pdu(
    sender: LdpId,
    targeted: bool,
    hold: u16,
    transport: Option<IpAddr>,
) -> (LdpPdu, HelloMsg) {
    let msg = HelloMsg {
        message_id: 1,
        params: HelloParams {
            hold_time: hold,
            targeted,
            request_targeted: false,
        },
        transport_addr: transport.map(TransportAddress),
        transport_addr_v6: None,
        config_seq: None,
        dual_stack: None,
        unknown_tlvs: Vec::new(),
    };
    let pdu = LdpPdu {
        version: 1,
        sender,
        messages: vec![LdpMessage::Hello(msg.clone())],
    };
    (pdu, msg)
}

fn cfg() -> LdpDiscoveryConfig {
    LdpDiscoveryConfig {
        local_id: id(1),
        transport_addr: IpAddr::V4([192, 0, 2, 1]),
        ..LdpDiscoveryConfig::default()
    }
}

#[test]
fn adjacency_created_and_refreshed() {
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(cfg());
    let (pdu, msg) = hello_pdu(id(2), true, 45, Some(IpAddr::V4([192, 0, 2, 2])));
    let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
    assert_eq!(events.len(), 1);
    match &events[0] {
        DiscoveryEvent::AdjacencyUp(a) => {
            assert_eq!(a.peer_id, id(2));
            assert_eq!(a.kind, DiscoveryKind::Targeted);
            assert_eq!(a.transport_addr, IpAddr::V4([192, 0, 2, 2]));
            // min(45, 45) seconds.
            assert_eq!(a.hold_time.as_secs(), 45);
        }
        other => panic!("wrong event {other:?}"),
    }
    // A second hello refreshes instead of re-creating.
    let events = d.feed_hello(
        Instant::from_secs(5),
        &pdu,
        &msg,
        IpAddr::V4([192, 0, 2, 2]),
    );
    assert!(events.is_empty());
    assert_eq!(d.adjacencies().len(), 1);
    assert_eq!(d.adjacencies()[0].last_seen, Instant::from_secs(5));
}

#[test]
fn hold_time_negotiated_to_minimum() {
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(cfg());
    // Peer proposes 0 → default 45 (targeted); we propose 45 → 45.
    let (pdu, msg) = hello_pdu(id(2), true, 0, None);
    let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
    assert_eq!(d.adjacencies()[0].hold_time.as_secs(), 45);
    // Peer proposes 10 → min(10, 45) = 10.
    let (pdu, msg) = hello_pdu(id(3), true, 10, None);
    let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 3]));
    assert_eq!(d.adjacencies()[1].hold_time.as_secs(), 10);
    // Link hello default: peer 0 → we propose 15 → 15.
    let (pdu, msg) = hello_pdu(id(4), false, 0, None);
    let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 4]));
    assert_eq!(d.adjacencies()[2].hold_time.as_secs(), 15);
}

#[test]
fn adjacency_expiry() {
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(cfg());
    let (pdu, msg) = hello_pdu(id(2), true, 9, None);
    let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
    // 8s: still alive (9s hold).
    let events = d.tick(Instant::from_secs(8));
    assert!(events.is_empty());
    assert_eq!(d.adjacencies().len(), 1);
    // 9s: expired.
    let events = d.tick(Instant::from_secs(9));
    match &events[0] {
        DiscoveryEvent::AdjacencyDown { peer_id, kind, .. } => {
            assert_eq!(*peer_id, id(2));
            assert_eq!(*kind, DiscoveryKind::Targeted);
        }
        other => panic!("wrong event {other:?}"),
    }
    assert!(d.adjacencies().is_empty());
}

#[test]
fn targeted_accept_policy() {
    let now = Instant::from_secs(0);
    let cfg = LdpDiscoveryConfig {
        accept_targeted: false,
        ..cfg()
    };
    let mut d = LdpDiscovery::new(cfg);
    let (pdu, msg) = hello_pdu(id(2), true, 45, None);
    let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
    assert!(events.is_empty());
    assert!(d.adjacencies().is_empty());
}

#[test]
fn targeted_peers_get_periodic_hellos() {
    let cfg = LdpDiscoveryConfig {
        targeted_peers: Vec::from([IpAddr::V4([192, 0, 2, 9])]),
        ..cfg()
    };
    let mut d = LdpDiscovery::new(cfg);
    let _ = d.tick(Instant::from_secs(0));
    let out = d.drain_outgoing();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].dest, IpAddr::V4([192, 0, 2, 9]));
    match &out[0].message {
        LdpMessage::Hello(h) => {
            assert!(h.params.targeted);
            assert_eq!(h.params.hold_time, DEFAULT_TARGETED_HELLO_HOLD);
            assert_eq!(
                h.transport_addr,
                Some(TransportAddress(IpAddr::V4([192, 0, 2, 1])))
            );
        }
        other => panic!("wrong message {other:?}"),
    }
    // The interval is hold/3 = 15s; a tick at 10s sends nothing.
    let _ = d.drain_outgoing();
    let _ = d.tick(Instant::from_secs(10));
    assert!(d.drain_outgoing().is_empty());
    // At 15s the next Hello is due.
    let _ = d.tick(Instant::from_secs(15));
    assert_eq!(d.drain_outgoing().len(), 1);
    let _ = d.drain_outgoing();
}

#[test]
fn r1_request_creates_response_target() {
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(cfg());
    let msg = HelloMsg {
        message_id: 1,
        params: HelloParams {
            hold_time: 45,
            targeted: true,
            request_targeted: true,
        },
        transport_addr: None,
        transport_addr_v6: None,
        config_seq: None,
        dual_stack: None,
        unknown_tlvs: Vec::new(),
    };
    let pdu = LdpPdu {
        version: 1,
        sender: id(2),
        messages: vec![LdpMessage::Hello(msg.clone())],
    };
    let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 7]));
    match &events[1] {
        DiscoveryEvent::TargetedHelloRequested { source, .. } => {
            assert_eq!(*source, IpAddr::V4([192, 0, 2, 7]));
        }
        other => panic!("wrong event {other:?}"),
    }
    // The responder now emits periodic targeted Hellos to the source.
    let _ = d.tick(Instant::from_secs(1));
    let out = d.drain_outgoing();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].dest, IpAddr::V4([192, 0, 2, 7]));
}

#[test]
fn config_sequence_number_tracked() {
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(cfg());
    let msg = HelloMsg {
        message_id: 1,
        params: HelloParams {
            hold_time: 45,
            targeted: true,
            request_targeted: false,
        },
        transport_addr: None,
        transport_addr_v6: None,
        config_seq: Some(ConfigSequenceNumber(7)),
        dual_stack: None,
        unknown_tlvs: Vec::new(),
    };
    let pdu = LdpPdu {
        version: 1,
        sender: id(2),
        messages: vec![LdpMessage::Hello(msg.clone())],
    };
    let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 7]));
    assert_eq!(d.adjacencies()[0].config_seq, Some(7));
}

#[test]
fn transport_address_falls_back_to_source() {
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(cfg());
    let (pdu, msg) = hello_pdu(id(2), true, 45, None);
    let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 8]));
    assert_eq!(
        d.adjacencies()[0].transport_addr,
        IpAddr::V4([192, 0, 2, 8])
    );
}

// ---- RFC 7552 §6.1: per-family transport-address handling ----

fn hello_pdu_full(
    sender: LdpId,
    targeted: bool,
    hold: u16,
    transport_v4: Option<IpAddr>,
    transport_v6: Option<IpAddr>,
    dual_stack: Option<TransportPreference>,
) -> (LdpPdu, HelloMsg) {
    let msg = HelloMsg {
        message_id: 1,
        params: HelloParams {
            hold_time: hold,
            targeted,
            request_targeted: false,
        },
        transport_addr: transport_v4.map(TransportAddress),
        transport_addr_v6: transport_v6.map(TransportAddress),
        config_seq: None,
        dual_stack: dual_stack.map(|preference| DualStackCapability { preference }),
        unknown_tlvs: Vec::new(),
    };
    let pdu = LdpPdu {
        version: 1,
        sender,
        messages: vec![LdpMessage::Hello(msg.clone())],
    };
    (pdu, msg)
}

fn dual_cfg() -> LdpDiscoveryConfig {
    LdpDiscoveryConfig {
        local_id: id(1),
        transport_addr: IpAddr::V4([192, 0, 2, 1]),
        transport_addr_v6: Some(IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])),
        ..LdpDiscoveryConfig::default()
    }
}

#[test]
fn rfc7552_same_af_transport_tlv_wins() {
    // A (noncompliant) Hello carrying both families inside an IPv6
    // datagram: only the v6 transport address may be used (§6.1
    // rule 2).
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(dual_cfg());
    let (pdu, msg) = hello_pdu_full(
        id(2),
        true,
        45,
        Some(IpAddr::V4([192, 0, 2, 2])),
        Some(IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ])),
        Some(TransportPreference::Ipv6),
    );
    let _ = d.feed_hello(
        now,
        &pdu,
        &msg,
        IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
    );
    let adj = &d.adjacencies()[0];
    assert_eq!(
        adj.transport_addr,
        IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
    );
    assert_eq!(adj.dual_stack, Some(TransportPreference::Ipv6));
}

#[test]
fn rfc7552_dual_stack_v6_hello_without_v6_tlv_uses_source() {
    // A v6 Hello with no v6 transport TLV: the source-address
    // fallback of §3.5.2.1 applies (not the v4 TLV!).
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(dual_cfg());
    let (pdu, msg) = hello_pdu_full(
        id(2),
        true,
        45,
        Some(IpAddr::V4([192, 0, 2, 2])),
        None,
        None,
    );
    let _ = d.feed_hello(
        now,
        &pdu,
        &msg,
        IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]),
    );
    assert_eq!(
        d.adjacencies()[0].transport_addr,
        IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9])
    );
}

#[test]
fn rfc7552_preference_mismatch_discards_hello() {
    // §6.1.1 rule 1: local prefers IPv6, the peer advertises
    // TR=LDPoIPv4 — the Hello MUST be discarded and an error
    // logged.
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(dual_cfg()); // prefer_ipv6 default true
    let (pdu, msg) = hello_pdu_full(
        id(2),
        true,
        45,
        Some(IpAddr::V4([192, 0, 2, 2])),
        None,
        Some(TransportPreference::Ipv4),
    );
    let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
    assert!(
        matches!(events[0], DiscoveryEvent::HelloDiscarded { .. }),
        "mismatched preference must surface HelloDiscarded"
    );
    assert!(d.adjacencies().is_empty());
}

#[test]
fn rfc7552_matching_preference_creates_adjacency() {
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(dual_cfg());
    let (pdu, msg) = hello_pdu_full(
        id(2),
        true,
        45,
        Some(IpAddr::V4([192, 0, 2, 2])),
        None,
        Some(TransportPreference::Ipv6),
    );
    let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
    assert!(matches!(events[0], DiscoveryEvent::AdjacencyUp(_)));
    assert_eq!(
        d.adjacencies()[0].dual_stack,
        Some(TransportPreference::Ipv6)
    );
}

#[test]
fn rfc7552_single_stack_speaker_ignores_capability() {
    // §6.1.1: "A Single-stack LSR ... SHOULD ignore this
    // capability if received" — no preference enforcement.
    let now = Instant::from_secs(0);
    let mut d = LdpDiscovery::new(cfg()); // v4-only speaker
    let (pdu, msg) = hello_pdu_full(
        id(2),
        true,
        45,
        Some(IpAddr::V4([192, 0, 2, 2])),
        None,
        Some(TransportPreference::Ipv6),
    );
    let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
    assert!(matches!(events[0], DiscoveryEvent::AdjacencyUp(_)));
}

#[test]
fn rfc7552_targeted_hello_per_family_transport() {
    // Targeted Hellos to a v6 destination carry the v6 transport
    // address; a v4-only speaker emits none for a v6 target.
    let now = Instant::from_secs(0);
    let mut dual = dual_cfg();
    dual.targeted_peers = vec![IpAddr::V6([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99,
    ])];
    let mut d = LdpDiscovery::new(dual);
    let _ = d.tick(now);
    let out = d.drain_outgoing();
    assert_eq!(out.len(), 1);
    let LdpMessage::Hello(hello) = &out[0].message else {
        panic!("expected a Hello");
    };
    match hello.transport_addr_v6 {
        Some(TransportAddress(IpAddr::V6(b))) => assert_eq!(b[1], 1),
        other => panic!("expected a v6 transport TLV, got {other:?}"),
    }
    assert!(hello.transport_addr.is_none());
    // The dual-stack capability rides along (§6.1.1: "in all of
    // its LDP Hellos").
    assert_eq!(
        hello.dual_stack.map(|c| c.preference),
        Some(TransportPreference::Ipv6)
    );

    // A v4-only speaker must not emit a Hello it cannot sign with
    // a v6 transport address.
    let now = Instant::from_secs(0);
    let mut single = cfg();
    single.targeted_peers = vec![IpAddr::V6([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99,
    ])];
    let mut d = LdpDiscovery::new(single);
    let _ = d.tick(now);
    assert!(d.drain_outgoing().is_empty());
}
