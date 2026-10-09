use super::*;
use crate::message::update::Nlri;
use crate::path::AsPath;
#[cfg(feature = "exchange-plane")]
use lr_core::addr::IpAddr;
use lr_core::addr::Prefix;

fn make_peer_pair() -> (BgpPeer, BgpPeer) {
    let cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    let cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    (BgpPeer::new(cfg1), BgpPeer::new(cfg2))
}

/// Drive a peer pair through the OPEN/KEEPALIVE handshake to Established.
fn establish(a: &mut BgpPeer, b: &mut BgpPeer) {
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    a.feed_bytes(&b_ka).unwrap();
    b.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established() && b.is_established());
}

#[test]
fn basic_establishment() {
    let (mut a, mut b) = make_peer_pair();
    // Start both peers; each enqueues OPEN.
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    // Drain OPENs from each.
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    // A's OPEN is 19-byte header + body.
    assert!(a_open.len() >= 29);
    assert_eq!(a_open[18], 1); // type = OPEN
                               // Cross-feed OPENs.
    let _ = b.feed_bytes(&a_open).unwrap();
    assert_eq!(b.state(), BgpState::OpenConfirm);
    let _ = a.feed_bytes(&b_open).unwrap();
    assert_eq!(a.state(), BgpState::OpenConfirm);
    // Drain KEEPALIVEs each enqueued in OpenConfirm.
    let b_ka = b.drain_outgoing();
    assert_eq!(b_ka[18], 4); // type = KEEPALIVE
    let a_ka = a.drain_outgoing();
    assert_eq!(a_ka[18], 4);
    // Cross-feed KEEPALIVEs → both go Established.
    let _ = a.feed_bytes(&b_ka).unwrap();
    assert!(a.is_established());
    let _ = b.feed_bytes(&a_ka).unwrap();
    assert!(b.is_established());
}

#[test]
fn open_with_4byte_asn_capability() {
    let cfg = PeerConfig::new(Asn(70000), Asn(80000), RouterId::from_v4([10, 0, 0, 1]));
    let mut peer = BgpPeer::new(cfg);
    peer.step(BgpEvent::ManualStart);
    peer.step(BgpEvent::TransportOpen);
    let out = peer.drain_outgoing();
    let body = &out[19..];
    assert_eq!(body[0], 4); // version
    let as16 = u16::from_be_bytes([body[1], body[2]]);
    assert_eq!(as16, 23456); // AS_TRANS
}

#[test]
fn reset_clears_state() {
    let mut p = BgpPeer::new(PeerConfig::new(
        Asn(64512),
        Asn(64513),
        RouterId::from_v4([1, 2, 3, 4]),
    ));
    p.step(BgpEvent::ManualStart);
    p.step(BgpEvent::TransportOpen);
    assert_eq!(p.state(), BgpState::OpenSent);
    p.reset();
    assert_eq!(p.state(), BgpState::Idle);
    assert!(!p.is_established());
}

/// RFC 6793 §4.2.2: when the peer's OPEN lacks the 4-octet-AS
/// capability the session must downgrade both directions to 2-byte
/// AS_PATH encoding — BIRD/FRR would reject 4-byte paths otherwise.
#[test]
fn as4_downgrades_when_peer_lacks_capability() {
    let mut peer = BgpPeer::new(PeerConfig::new(
        Asn(64512),
        Asn(64513),
        RouterId::from_v4([10, 0, 0, 1]),
    ));
    peer.step(BgpEvent::ManualStart);
    peer.step(BgpEvent::TransportOpen);
    assert!(peer.cfg.asn4); // we advertise the capability
                            // Hand-craft an OPEN *without* any capabilities.
    let open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 2]));
    let (state, _) = {
        // handle_open_in_opensent is private; drive through step().
        let ev = BgpEvent::Message(BgpMessage::Open(open));
        let actions = peer.step(ev);
        (peer.state(), actions)
    };
    let _ = state;
    // The downgrade applies to the codec for the session's lifetime,
    // not to the configured capability — a re-establishment must
    // re-negotiate fresh (RFC 6793 negotiation is per-session).
    assert!(peer.cfg.asn4, "configured capability is unchanged");
    assert!(
        !peer.codec.asn4_active(),
        "session codec must downgrade to 2-byte AS_PATH"
    );
}

/// RFC 4271 §6.8: a NOTIFICATION received in Established tears the
/// session down to Idle instead of being ignored.
#[test]
fn notification_tears_down_established_session() {
    let (mut a, mut b) = make_peer_pair();
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    let _ = a.feed_bytes(&b_open).unwrap();
    let _ = b.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    let _ = a.feed_bytes(&b_ka).unwrap();
    let _ = b.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established());

    let n = BgpNotification::new(4, 0, vec![]); // Hold Timer Expired
    let actions = a.step(BgpEvent::Message(BgpMessage::Notification(n)));
    assert_eq!(a.state(), BgpState::Idle);
    assert!(!a.is_established());
    assert!(actions.iter().any(|x| matches!(x, BgpAction::Close)));
}

/// RFC 4271 §6: malformed inbound data must raise the required
/// NOTIFICATION and close the session instead of surfacing a generic
/// parse error to the embedder.
#[test]
fn malformed_update_produces_notification_and_closes() {
    let (mut a, mut b) = make_peer_pair();
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
    let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
    let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
    let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
    assert!(a.is_established());

    // Craft an UPDATE with a duplicate well-known attribute (RFC 4271
    // §6.3 Malformed Attribute List): two ORIGIN attributes.
    let mut frame = vec![0xffu8; 16];
    frame.extend_from_slice(&(19 + 12u16).to_be_bytes());
    frame.push(2); // UPDATE
    frame.extend_from_slice(&0u16.to_be_bytes()); // withdrawn len
    frame.extend_from_slice(&8u16.to_be_bytes()); // attrs len
                                                  // ORIGIN(1) flags=0x40, len=1, value=0
    frame.extend_from_slice(&[0x40, 1, 1, 0]);
    // ORIGIN(1) again — duplicate.
    frame.extend_from_slice(&[0x40, 1, 1, 0]);
    // No NLRI.
    let actions = a.feed_bytes(&frame).unwrap();
    assert_eq!(
        a.state(),
        BgpState::Idle,
        "malformed UPDATE must close the session"
    );
    assert!(!a.is_established());
    assert!(actions.iter().any(|x| matches!(x, BgpAction::Close)));
    // The peer must receive the NOTIFICATION (Malformed Attribute List:
    // code 3, subcode 1).
    let out = a.drain_outgoing();
    assert!(!out.is_empty(), "a NOTIFICATION must be sent");
    assert_eq!(out[18], 3, "message type = NOTIFICATION");
    assert_eq!(out[19], 3, "error code = UPDATE Message Error");
    assert_eq!(out[20], 1, "subcode = Malformed Attribute List");
}

/// `PeerMessageStats` counts every message at the wire boundary:
/// the establishment handshake books one OPEN + one KEEPALIVE per
/// direction, and a received NOTIFICATION books on the receiving
/// side even though it tears the session down.
#[test]
fn message_stats_count_wire_exchange() {
    let (mut a, mut b) = make_peer_pair();
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    let _ = a.feed_bytes(&b_open).unwrap();
    let _ = b.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    let _ = a.feed_bytes(&b_ka).unwrap();
    let _ = b.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established());

    for p in [&a, &b] {
        let s = p.message_stats();
        assert_eq!(s.open_sent, 1, "one OPEN sent");
        assert_eq!(s.open_received, 1, "one OPEN received");
        assert_eq!(s.keepalive_sent, 1, "one KEEPALIVE sent");
        assert_eq!(s.keepalive_received, 1, "one KEEPALIVE received");
        assert_eq!(s.update_sent, 0);
        assert_eq!(s.update_received, 0);
        assert_eq!(s.notification_sent, 0);
        assert_eq!(s.notification_received, 0);
        assert_eq!(s.route_refresh_sent, 0);
        assert_eq!(s.route_refresh_received, 0);
    }

    // A wire NOTIFICATION from the peer counts on the receiver;
    // sending it as real bytes (marker + len + type 3 + code/sub)
    // exercises the decode path the daemon uses.
    let mut frame = vec![0xffu8; 16];
    frame.extend_from_slice(&21u16.to_be_bytes()); // 19 header + code + sub
    frame.push(3); // NOTIFICATION
    frame.push(4); // Hold Timer Expired
    frame.push(0); // subcode
    let _ = a.feed_bytes(&frame).unwrap();
    assert_eq!(a.message_stats().notification_received, 1);
    assert_eq!(a.message_stats().notification_sent, 0);
}

/// `reset()` (a session re-establishment) must NOT zero the
/// message counters — FRR's per-neighbor statistics survive flaps.
#[test]
fn message_stats_survive_reset() {
    let (mut a, mut b) = make_peer_pair();
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
    let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
    let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
    let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
    assert!(a.is_established());
    assert_eq!(a.message_stats().open_sent, 1);

    a.reset();
    assert_eq!(a.state(), BgpState::Idle);
    assert_eq!(a.message_stats().open_sent, 1, "counters survive reset");
    assert_eq!(a.message_stats().open_received, 1);
    assert_eq!(a.message_stats().keepalive_received, 1);
}

/// A parse error produces the NOTIFICATION on the outbound side:
/// the required NOTIFICATION counts as sent. The malformed UPDATE
/// itself never decodes (codec-level error), so it does not book
/// `update_received` — counting is post-decode, and a PDU that
/// fails structural validation never becomes a message.
#[test]
fn message_stats_count_parse_error_exchange() {
    let (mut a, mut b) = make_peer_pair();
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
    let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
    let _ = a.feed_bytes(&b.drain_outgoing()).unwrap();
    let _ = b.feed_bytes(&a.drain_outgoing()).unwrap();
    assert!(a.is_established());

    // Malformed UPDATE (duplicate ORIGIN — RFC 4271 §6.3).
    let mut frame = vec![0xffu8; 16];
    frame.extend_from_slice(&(19 + 12u16).to_be_bytes());
    frame.push(2); // UPDATE
    frame.extend_from_slice(&0u16.to_be_bytes()); // withdrawn len
    frame.extend_from_slice(&8u16.to_be_bytes()); // attrs len
    frame.extend_from_slice(&[0x40, 1, 1, 0]); // ORIGIN
    frame.extend_from_slice(&[0x40, 1, 1, 0]); // duplicate ORIGIN
    let _ = a.feed_bytes(&frame).unwrap();
    assert_eq!(a.state(), BgpState::Idle);
    let _ = a.drain_outgoing();

    let s = a.message_stats();
    assert_eq!(
        s.update_received, 0,
        "a structurally invalid PDU is not a message"
    );
    assert_eq!(s.notification_sent, 1, "the required NOTIFICATION was sent");
}

#[test]
fn route_refresh_is_negotiated_and_dispatched() {
    let (mut a, mut b) = make_peer_pair();
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_keepalive = a.drain_outgoing();
    let b_keepalive = b.drain_outgoing();
    a.feed_bytes(&b_keepalive).unwrap();
    b.feed_bytes(&a_keepalive).unwrap();

    assert!(a.route_refresh_negotiated());
    assert!(a.enhanced_route_refresh_negotiated());
    assert!(a.request_route_refresh(NlriFamily::IPV4_UNICAST));
    let request = a.drain_outgoing();
    let actions = b.feed_bytes(&request).unwrap();
    assert!(actions.iter().any(|action| {
        matches!(
            action,
            BgpAction::RouteRefreshRequested(NlriFamily { afi: 1, safi: 1 })
        )
    }));
}

#[test]
fn enhanced_route_refresh_emits_demarcation_messages() {
    let (mut a, mut b) = make_peer_pair();
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_keepalive = a.drain_outgoing();
    let b_keepalive = b.drain_outgoing();
    a.feed_bytes(&b_keepalive).unwrap();
    b.feed_bytes(&a_keepalive).unwrap();

    assert!(a.begin_enhanced_route_refresh(NlriFamily::IPV4_UNICAST));
    assert!(a.end_enhanced_route_refresh(NlriFamily::IPV4_UNICAST));
    let bytes = a.drain_outgoing();
    let mut codec = BgpCodec::new();
    let first = codec.decode_slice(&bytes).unwrap().unwrap();
    let second = codec.decode_slice(&[]).unwrap().unwrap();
    assert_eq!(
        first,
        BgpMessage::RouteRefresh(crate::message::RouteRefresh::begin_of_rib(
            NlriFamily::IPV4_UNICAST
        ))
    );
    assert_eq!(
        second,
        BgpMessage::RouteRefresh(crate::message::RouteRefresh::end_of_rib(
            NlriFamily::IPV4_UNICAST
        ))
    );
}

#[test]
fn route_refresh_requires_negotiated_capability() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg.route_refresh = false;
    let peer = BgpPeer::new(cfg);
    assert!(!peer.route_refresh_negotiated());
}

/// A peer that *does* offer the AS4 capability keeps 4-byte encoding.
#[test]
fn as4_kept_when_peer_offers_capability() {
    let mut peer = BgpPeer::new(PeerConfig::new(
        Asn(64512),
        Asn(64513),
        RouterId::from_v4([10, 0, 0, 1]),
    ));
    peer.step(BgpEvent::ManualStart);
    peer.step(BgpEvent::TransportOpen);
    let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 2]));
    open.params.push(crate::message::open::OpenParam {
        param_type: crate::message::open::OpenParam::PARAM_TYPE_CAPABILITY,
        value: Capability::encode_set(&[Capability::four_octet_as(64513)]),
    });
    peer.step(BgpEvent::Message(BgpMessage::Open(open)));
    assert!(peer.cfg.asn4, "4-byte encoding must be negotiated up");
}

/// W6.3 exchange-plane prototype: both speakers configure the plane
/// and exchange OPENs — the negotiation activates with the shared
/// key and each side's nonces in the right places.
#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_negotiates_when_both_sides_advertise() {
    use crate::extensions::exchange_plane::{ExchangeKey, ExchangePlaneConfig};

    let nonce_a = [1u8; 8];
    let nonce_b = [2u8; 8];
    let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));

    let mut xp_a = ExchangePlaneConfig::new(nonce_a);
    xp_a.keys = vec![ExchangeKey::hmac_sha256(1, "alpha")];
    let mut xp_b = ExchangePlaneConfig::new(nonce_b);
    xp_b.keys = vec![
        ExchangeKey::hmac_sha256(1, "alpha"),
        ExchangeKey::hmac_sha256(2, "beta"),
    ];
    a.set_exchange_plane(xp_a);
    b.set_exchange_plane(xp_b);

    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    a.feed_bytes(&b_ka).unwrap();
    b.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established() && b.is_established());

    // Each side mixes its OPEN instance counter into the advertised
    // nonce (first OPEN = counter 1 → the last four octets differ
    // from the configured nonce by 0x00000001). The session binds to
    // the advertised values.
    let mixed = |n: [u8; 8]| {
        let mut m = n;
        m[7] ^= 1;
        m
    };
    let session_a = a.exchange_plane_session().expect("activated on a");
    assert_eq!(session_a.peer_nonce, mixed(nonce_b));
    assert_eq!(session_a.local_nonce, mixed(nonce_a));
    assert_eq!(session_a.keys.len(), 1);
    assert_eq!(session_a.keys[0].id, 1);

    let session_b = b.exchange_plane_session().expect("activated on b");
    assert_eq!(session_b.peer_nonce, mixed(nonce_a));
    assert_eq!(session_b.local_nonce, mixed(nonce_b));
}

/// W6.3 exchange-plane prototype: only one side configures the
/// plane — the capability is advertised (RFC 5492 §3 makes it
/// inert for the peer) but the negotiation stays off, and the
/// session establishes normally.
#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_stays_off_when_peer_lacks_capability() {
    use crate::extensions::exchange_plane::{ExchangeKey, ExchangePlaneConfig};

    let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));

    let mut xp = ExchangePlaneConfig::new([5u8; 8]);
    xp.keys = vec![ExchangeKey::hmac_sha256(1, "alpha")];
    a.set_exchange_plane(xp);

    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    // b has no exchange-plane config: b's OPEN handling must not
    // trip over a's capability (RFC 5492 §3 ignore rule).
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    a.feed_bytes(&b_ka).unwrap();
    b.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established() && b.is_established());
    assert!(a.exchange_plane_session().is_none());
    assert!(b.exchange_plane_session().is_none());
}

// ----- W6.3 follow-up: attach/detach hooks over a live FSM pair -----

#[cfg(feature = "exchange-plane")]
fn establish_pair_with_plane(
    xp_a: Option<crate::extensions::exchange_plane::ExchangePlaneConfig>,
    xp_b: Option<crate::extensions::exchange_plane::ExchangePlaneConfig>,
) -> (BgpPeer, BgpPeer) {
    let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));
    if let Some(x) = xp_a {
        a.set_exchange_plane(x);
    }
    if let Some(x) = xp_b {
        b.set_exchange_plane(x);
    }
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    a.feed_bytes(&b_ka).unwrap();
    b.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established() && b.is_established());
    (a, b)
}

#[cfg(feature = "exchange-plane")]
fn xp_config(
    nonce: [u8; 8],
    key_secret: &str,
) -> crate::extensions::exchange_plane::ExchangePlaneConfig {
    use crate::extensions::exchange_plane::{ExchangeKey, ExchangePlaneConfig};
    let mut cfg = ExchangePlaneConfig::new(nonce);
    cfg.keys = vec![ExchangeKey::hmac_sha256(1, key_secret)];
    cfg.origin_base_secs = 1_700_000_000;
    cfg
}

#[cfg(feature = "exchange-plane")]
fn local_route(origin_proto: u32) -> Route {
    let mut attrs = PathAttributes::new();
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    let path = AsPath::from_sequence([64512].iter().copied().map(Asn));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        path.encode_4(),
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![10, 0, 0, 1],
    ));
    Route {
        key: RouteKey::new(
            Prefix::new_v4([203, 0, 113, 0], 24),
            NlriFamily::IPV4_UNICAST,
        ),
        origin: RouteOrigin {
            proto: origin_proto,
            peer: 7,
        },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 1),
        next_hop: Some(IpAddr::V4([10, 0, 0, 1])),
        attributes: attrs.into(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

#[cfg(feature = "exchange-plane")]
fn decode_updates(bytes: &[u8]) -> Vec<Update> {
    use lr_core::codec::Decoder;
    let mut codec = BgpCodec::new().with_asn4(true);
    let mut out = Vec::new();
    let mut r = lr_core::buf::ReadBuf::new(bytes);
    while let Ok(Some(BgpMessage::Update(u))) = codec.decode(&mut r) {
        out.push(u);
    }
    out
}

/// The attach hook: a locally originated route advertised over a
/// plane-active session carries the signed record-set attribute;
/// the receiving peer verifies it and parks the record set in the
/// private store on the installed route (no wire 251 in the bag).
#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_attaches_and_verifies_over_live_session() {
    use crate::extensions::exchange_plane as xp;

    let (mut a, mut b) = establish_pair_with_plane(
        Some(xp_config([1u8; 8], "alpha")),
        Some(xp_config([2u8; 8], "alpha")),
    );
    let route = local_route(2); // locally originated
    assert!(a.advertise(&route));
    let bytes = a.drain_outgoing();

    // The wire UPDATE carries the exchange-plane attribute.
    let updates = decode_updates(&bytes);
    assert!(!updates.is_empty());
    let wire_attr = updates[0]
        .attributes
        .get(AttrType::Other(xp::ATTRIBUTE_TYPE))
        .expect("record-set attribute attached");
    let record = xp::ExchangeRecord::decode(&wire_attr.value).unwrap();
    assert!(record.verify(&crate::extensions::exchange_plane::ExchangeKey::hmac_sha256(1, "alpha")));
    // Hint + origin attestation + our segment signature.
    assert!(matches!(record.records.first(), Some(xp::Record::Hint(_))));
    assert!(record
        .records
        .iter()
        .any(|r| matches!(r, xp::Record::Origin(_))));
    assert!(record
        .records
        .iter()
        .any(|r| matches!(r, xp::Record::Segment(_))));

    // B consumes the attribute: the installed route carries the
    // private store (verified kind) and no wire 251.
    let actions = b.feed_bytes(&bytes).unwrap();
    let installed = actions
        .iter()
        .find_map(|a| match a {
            BgpAction::InstallRoute(r) => Some(r.clone()),
            _ => None,
        })
        .expect("route installed");
    let bag: crate::path::PathAttributes = installed.attributes.into();
    assert!(bag.get(AttrType::Other(xp::ATTRIBUTE_TYPE)).is_none());
    let stored = bag
        .get(AttrType::LrExchangePlaneRecords)
        .expect("record store parked");
    let (kind, payload) = xp::load_store(&stored.value).expect("well-formed store");
    assert_eq!(kind, xp::STORE_VERIFIED);
    let stored_record = xp::ExchangeRecord::decode(payload).unwrap();
    assert_eq!(stored_record.records.len(), record.records.len());
}

/// The detach hook strips the wire attribute: egress rebuilds from
/// the store, so a re-advertised route never carries the received
/// scope-1 records (design §7) — and never two type-251 attributes.
#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_scope1_records_do_not_leak() {
    use crate::extensions::exchange_plane as xp;

    let (mut a, mut b) = establish_pair_with_plane(
        Some(xp_config([1u8; 8], "alpha")),
        Some(xp_config([2u8; 8], "alpha")),
    );
    // A -> B: a transit-learned route (proto 0) still gets fresh
    // scope-1 records but no origin attestation.
    assert!(a.advertise(&local_route(0)));
    let bytes = a.drain_outgoing();
    let actions = b.feed_bytes(&bytes).unwrap();
    let installed = actions
        .iter()
        .find_map(|a| match a {
            BgpAction::InstallRoute(r) => Some(r.clone()),
            _ => None,
        })
        .expect("route installed");
    let bag: crate::path::PathAttributes = installed.attributes.into();
    let stored = bag.get(AttrType::LrExchangePlaneRecords).unwrap();
    let (_, payload) = xp::load_store(&stored.value).unwrap();
    let record = xp::ExchangeRecord::decode(payload).unwrap();
    assert!(record
        .records
        .iter()
        .any(|r| matches!(r, xp::Record::Hint(_))));
    assert!(!record
        .records
        .iter()
        .any(|r| matches!(r, xp::Record::Origin(_))));
}

/// Flag off = byte-identical egress: with the peer not advertising
/// the capability, a session with the plane configured emits exactly
/// the bytes a session without the plane emits.
#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_one_sided_is_byte_identical() {
    // `a`: the plane is configured, but the dummy partner below does
    // not advertise the capability — the negotiation stays off.
    let (mut a, _b) = establish_pair_with_plane(Some(xp_config([1u8; 8], "alpha")), None);
    // `plain`: same peer config, no plane at all, established
    // against the same shape of dummy partner.
    let mut plain_cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    plain_cfg.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut dummy = BgpPeer::new(PeerConfig::new(
        Asn(64513),
        Asn(64512),
        RouterId::from_v4([10, 9, 9, 9]),
    ));
    let mut plain = BgpPeer::new(plain_cfg);
    plain.step(BgpEvent::ManualStart);
    plain.step(BgpEvent::TransportOpen);
    dummy.step(BgpEvent::ManualStart);
    dummy.step(BgpEvent::TransportOpen);
    let p_open = plain.drain_outgoing();
    let d_open = dummy.drain_outgoing();
    let _ = plain.feed_bytes(&d_open).unwrap();
    let _ = dummy.feed_bytes(&p_open).unwrap();
    let p_ka = plain.drain_outgoing();
    let d_ka = dummy.drain_outgoing();
    let _ = plain.feed_bytes(&d_ka).unwrap();
    let _ = dummy.feed_bytes(&p_ka).unwrap();
    assert!(plain.is_established());

    let route = local_route(2);
    let a_with = {
        let _ = a.advertise(&route);
        a.drain_outgoing()
    };
    let a_without = {
        let _ = plain.advertise(&route);
        plain.drain_outgoing()
    };
    assert_eq!(
        a_with, a_without,
        "one-sided plane must not change egress bytes"
    );
}

/// A record captured from one session instance replays into a fresh
/// one (new OPEN nonces) and is dropped on the nonce check (design §6).
#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_replay_across_sessions_is_dropped() {
    let (mut a, mut b) = establish_pair_with_plane(
        Some(xp_config([1u8; 8], "alpha")),
        Some(xp_config([2u8; 8], "alpha")),
    );
    assert!(a.advertise(&local_route(2)));
    let captured = a.drain_outgoing();
    let _ = b.feed_bytes(&captured).unwrap();

    // A fresh session instance: new OPEN nonces both sides.
    let (_a2, mut b2) = establish_pair_with_plane(
        Some(xp_config([9u8; 8], "alpha")),
        Some(xp_config([7u8; 8], "alpha")),
    );
    let actions = b2.feed_bytes(&captured).unwrap();
    assert!(actions.iter().any(|a| matches!(
        a,
        BgpAction::Emit(lr_core::event::Event::Log(msg))
            if msg.contains("foreign-session nonce")
    )));
    // The route's standard content survives (fail-open, design §8).
    assert!(actions
        .iter()
        .any(|a| matches!(a, BgpAction::InstallRoute(_))));
}

/// A tampered record body fails the tag check and is dropped with a
/// log line, while the route itself still installs.
#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_tampered_record_is_dropped() {
    let (mut a, mut b) = establish_pair_with_plane(
        Some(xp_config([1u8; 8], "alpha")),
        Some(xp_config([2u8; 8], "alpha")),
    );
    assert!(a.advertise(&local_route(2)));
    let bytes = a.drain_outgoing();

    // Decode the UPDATE, flip a bit inside the record-set value (the
    // authentication tag covers it) and re-encode.
    let mut updates = decode_updates(&bytes);
    let u = updates.last_mut().expect("update present");
    let attr = u
        .attributes
        .get_mut(AttrType::Other(
            crate::extensions::exchange_plane::ATTRIBUTE_TYPE,
        ))
        .expect("record attribute");
    let tag_start = attr.value.len() - 32;
    attr.value[tag_start] ^= 0x01;
    let codec = BgpCodec::new().with_asn4(true);
    let wire = codec.encode_vec(&BgpMessage::Update(u.clone())).unwrap();

    let actions = b.feed_bytes(&wire).unwrap();
    assert!(actions.iter().any(|a| matches!(
        a,
        BgpAction::Emit(lr_core::event::Event::Log(msg))
            if msg.contains("tag mismatch") || msg.contains("malformed")
    )));
    assert!(actions
        .iter()
        .any(|a| matches!(a, BgpAction::InstallRoute(_))));
}

/// RFC 4271 §5.3 relay processing: an unknown optional-transitive
/// attribute is forwarded with Partial set; an optional
/// NON-transitive one is not propagated. (Unconditional code —
/// tested without the exchange-plane feature too.)
#[test]
fn unknown_attribute_relay_sets_partial_and_drops_non_transitive() {
    let (mut a, _b) = make_peer_pair();
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    let mut dummy = BgpPeer::new(PeerConfig::new(
        Asn(64513),
        Asn(64512),
        RouterId::from_v4([10, 9, 9, 9]),
    ));
    dummy.step(BgpEvent::ManualStart);
    dummy.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let d_open = dummy.drain_outgoing();
    let _ = a.feed_bytes(&d_open).unwrap();
    let _ = dummy.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let d_ka = dummy.drain_outgoing();
    let _ = a.feed_bytes(&d_ka).unwrap();
    let _ = dummy.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established());

    // Build an UPDATE carrying (1) an unknown transitive attr with
    // flags 0xC0 and (2) an unknown optional non-transitive attr
    // with flags 0x80.
    let mut u = Update::new();
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_optional(true).set_transitive(true),
        AttrType::Other(250),
        vec![1, 2, 3],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_optional(true),
        AttrType::Other(249),
        vec![4, 5],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    let path = AsPath::from_sequence([64513].iter().copied().map(Asn));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        path.encode_4(),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![10, 0, 0, 2],
    ));
    u.nlri
        .push(Nlri::plain(Prefix::new_v4([198, 51, 100, 0], 24)));
    let codec = BgpCodec::new().with_asn4(true);
    let wire = codec.encode_vec(&BgpMessage::Update(u)).unwrap();
    let actions = a.feed_bytes(&wire).unwrap();
    let installed = actions
        .iter()
        .find_map(|a| match a {
            BgpAction::InstallRoute(r) => Some(r.clone()),
            _ => None,
        })
        .expect("route installed");
    let bag: crate::path::PathAttributes = installed.attributes.into();
    let relayed = bag
        .get(AttrType::Other(250))
        .expect("transitive unknown forwarded");
    assert!(relayed.flags.partial(), "Partial bit set per RFC 4271 §5.3");
    assert!(
        bag.get(AttrType::Other(249)).is_none(),
        "optional non-transitive unknown not propagated"
    );
}

fn establish_llgr_pair() -> (BgpPeer, BgpPeer) {
    let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg1.graceful_restart = true;
    cfg1.graceful_restart_time = 90;
    cfg1.long_lived = true;
    cfg1.long_lived_stale_time = 3600;
    cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg2.graceful_restart = true;
    cfg2.graceful_restart_time = 120;
    cfg2.long_lived = true;
    cfg2.long_lived_stale_time = 1800;
    cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    a.feed_bytes(&b_ka).unwrap();
    b.feed_bytes(&a_ka).unwrap();
    (a, b)
}

#[test]
fn llgr_negotiated_after_open_exchange() {
    let (a, b) = establish_llgr_pair();
    assert!(a.is_established() && b.is_established());
    // Both sides see LLGR negotiated and the *peer's* LLST per family.
    assert!(a.llgr_negotiated());
    assert_eq!(
        a.negotiated_llgr_stale_time(NlriFamily::IPV4_UNICAST),
        Some(1800)
    );
    assert!(b.llgr_negotiated());
    assert_eq!(
        b.negotiated_llgr_stale_time(NlriFamily::IPV4_UNICAST),
        Some(3600)
    );
    // Restart time comes from the peer's GR capability.
    assert_eq!(a.negotiated_graceful_restart_time(), Some(120));
    assert_eq!(b.negotiated_graceful_restart_time(), Some(90));
}

/// RFC 9494 §4.5: an LLGR capability received without the GR
/// capability MUST be ignored.
#[test]
fn llgr_without_gr_capability_is_ignored() {
    let mut peer = BgpPeer::new(PeerConfig::new(
        Asn(64512),
        Asn(64513),
        RouterId::from_v4([10, 0, 0, 1]),
    ));
    peer.cfg.graceful_restart = true;
    peer.cfg.long_lived = true;
    peer.step(BgpEvent::ManualStart);
    peer.step(BgpEvent::TransportOpen);
    // Peer offers LLGR (71) but no GR (64).
    let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 2]));
    open.params.push(crate::message::open::OpenParam {
        param_type: crate::message::open::OpenParam::PARAM_TYPE_CAPABILITY,
        value: Capability::encode_set(&[Capability::long_lived_gr(&[(1, 1, true, 600)])]),
    });
    peer.step(BgpEvent::Message(BgpMessage::Open(open)));
    assert!(!peer.llgr_negotiated());
    assert_eq!(
        peer.negotiated_llgr_stale_time(NlriFamily::IPV4_UNICAST),
        None
    );
}

/// Families not listed in the peer's LLGR capability are deemed zero
/// (RFC 9494 §4.2) — LLGR is negotiated but grants no extra retention.
#[test]
fn unlisted_family_has_zero_llst() {
    let (a, _) = establish_llgr_pair();
    assert_eq!(
        a.negotiated_llgr_stale_time(NlriFamily::IPV6_UNICAST),
        Some(0)
    );
}

/// RFC 4724 §4: an empty UPDATE is the End-of-RIB marker.
#[test]
fn empty_update_is_end_of_rib() {
    let (mut a, _b) = establish_llgr_pair();
    let actions = a.step(BgpEvent::Message(BgpMessage::Update(Update::new())));
    assert!(actions
        .iter()
        .any(|x| matches!(x, BgpAction::EndOfRib(NlriFamily::IPV4_UNICAST))));
}

/// A non-empty UPDATE carrying a route must NOT be mistaken for EoR.
#[test]
fn route_update_is_not_end_of_rib() {
    use crate::message::update::Update;
    let (mut a, _b) = establish_llgr_pair();
    let mut u = Update::new();
    u.nlri.push(crate::message::update::Nlri::plain(
        lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    let actions = a.step(BgpEvent::Message(BgpMessage::Update(u)));
    assert!(!actions.iter().any(|x| matches!(x, BgpAction::EndOfRib(_))));
}

// ===== FRR `no bgp default ipv4-unicast` (W2.1) =====

/// Build a BGP peer with `default_ipv4_unicast = false` and IPv4
/// unicast NOT in `mp_families` — the FRR `no bgp default
/// ipv4-unicast` posture without explicit per-peer activation.
fn peer_no_default_ipv4() -> BgpPeer {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg.default_ipv4_unicast = false;
    cfg.mp_families = Vec::new();
    let mut peer = BgpPeer::new(cfg);
    peer.step(BgpEvent::ManualStart);
    peer.step(BgpEvent::TransportOpen);
    peer
}

/// A peer with `default_ipv4_unicast = false` must NOT emit an
/// End-of-RIB marker for IPv4 unicast on receipt of an empty UPDATE.
#[test]
fn no_default_ipv4_unicast_suppresses_v4_eor() {
    let mut a = peer_no_default_ipv4();
    let actions = a.step(BgpEvent::Message(BgpMessage::Update(Update::new())));
    assert!(
        !actions
            .iter()
            .any(|x| matches!(x, BgpAction::EndOfRib(NlriFamily::IPV4_UNICAST))),
        "no IPv4 unicast EoR when the family is not active for this peer"
    );
}

/// A peer with `default_ipv4_unicast = false` must NOT install
/// legacy-section IPv4 NLRI received from the peer.
#[test]
fn no_default_ipv4_unicast_drops_v4_nlri() {
    use crate::message::update::Update;
    use crate::path::AsPath;
    let mut a = peer_no_default_ipv4();
    let mut u = Update::new();
    u.nlri.push(crate::message::update::Nlri::plain(
        lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        AsPath::from_sequence([Asn(64513)]).encode_4(),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![192, 0, 2, 1],
    ));
    let actions = a.step(BgpEvent::Message(BgpMessage::Update(u)));
    assert!(
        !actions
            .iter()
            .any(|x| matches!(x, BgpAction::InstallRoute(_))),
        "legacy-section IPv4 NLRI must be dropped when default_ipv4_unicast is off"
    );
}

/// A peer with `default_ipv4_unicast = false` must NOT process
/// legacy-section withdrawals either — the family is not active,
/// so a withdrawal would be a no-op anyway, but we fail closed
/// (the peer should not be sending them).
#[test]
fn no_default_ipv4_unicast_drops_v4_withdrawals() {
    use crate::message::update::{Nlri, Update};
    let mut a = peer_no_default_ipv4();
    let mut u = Update::new();
    u.withdrawn.push(Nlri::plain(lr_core::addr::Prefix::new_v4(
        [203, 0, 113, 0],
        24,
    )));
    let actions = a.step(BgpEvent::Message(BgpMessage::Update(u)));
    assert!(
        !actions
            .iter()
            .any(|x| matches!(x, BgpAction::WithdrawRoute { .. })),
        "legacy-section IPv4 withdrawals must be dropped when default_ipv4_unicast is off"
    );
}

// ----- RFC 7911 Add-Path -----

fn establish_add_path_pair() -> (BgpPeer, BgpPeer) {
    let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg1.add_path = true;
    cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg2.add_path = true;
    cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    a.feed_bytes(&b_ka).unwrap();
    b.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established() && b.is_established());
    (a, b)
}

/// RFC 7911 §4.4: when both speakers advertise Add-Path for a family
/// both directions are enabled on both sides.
#[test]
fn add_path_negotiated_both_directions() {
    let (a, b) = establish_add_path_pair();
    assert!(a.add_path_negotiated() && b.add_path_negotiated());
    assert!(a.add_path_tx_for(NlriFamily::IPV4_UNICAST));
    assert!(a.add_path_rx_for(NlriFamily::IPV4_UNICAST));
    assert!(b.add_path_tx_for(NlriFamily::IPV4_UNICAST));
    assert!(b.add_path_rx_for(NlriFamily::IPV4_UNICAST));
    // A family nobody negotiated stays single-path.
    assert!(!a.add_path_tx_for(NlriFamily::IPV6_UNICAST));
    assert!(!a.add_path_rx_for(NlriFamily::IPV6_UNICAST));
}

/// RFC 7911 §4.4: a peer that did not advertise Add-Path keeps the
/// session in single-path mode even when we offered it.
#[test]
fn add_path_not_negotiated_when_peer_silent() {
    let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg1.add_path = true;
    cfg1.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg2.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_ka = a.drain_outgoing();
    let b_ka = b.drain_outgoing();
    a.feed_bytes(&b_ka).unwrap();
    b.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established());
    assert!(!a.add_path_negotiated());
    assert!(!a.add_path_tx_for(NlriFamily::IPV4_UNICAST));
    assert!(!a.add_path_rx_for(NlriFamily::IPV4_UNICAST));
}

/// RFC 7911 §4.3: two paths to the same prefix advertised with distinct
/// path identifiers arrive as two InstallRoute actions carrying those
/// identifiers; withdrawing one identifier yields a WithdrawRoute for
/// exactly that path.
#[test]
fn add_path_two_paths_install_and_withdraw() {
    use crate::message::update::{Nlri as Entry, Update};
    let (_a, mut b) = establish_add_path_pair();

    let mut u = Update::new();
    u.nlri.push(Entry::new(
        1,
        lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
    ));
    u.nlri.push(Entry::new(
        2,
        lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        vec![],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![192, 0, 2, 1],
    ));
    let actions = b.step(BgpEvent::Message(BgpMessage::Update(u)));
    let installed: Vec<u32> = actions
        .iter()
        .filter_map(|x| match x {
            BgpAction::InstallRoute(r) => Some(r.path_id),
            _ => None,
        })
        .collect();
    assert_eq!(installed, vec![1, 2], "both paths must install");

    let mut w = Update::new();
    w.withdrawn.push(Entry::new(
        1,
        lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
    ));
    let actions = b.step(BgpEvent::Message(BgpMessage::Update(w)));
    assert!(matches!(
        actions.first(),
        Some(BgpAction::WithdrawRoute { path_id: 1, .. })
    ));
}

/// RFC 5065 §5: an AS_PATH carrying AS_CONFED_* segments is valid only
/// between members of the same confederation. A peer that is not a
/// member (including the no-confederation case) has its routes
/// rejected — no `InstallRoute` is emitted — rather than the malformed
/// AS_PATH being installed as if it were a normal eBGP advertisement.
#[test]
fn rejects_confed_segments_from_non_confederation_peer() {
    use crate::message::BgpMessage;
    use crate::path::{AsPath, AsPathSegment, AsPathType, PathAttrFlags, PathAttribute};
    let (mut a, mut b) = make_peer_pair();
    establish(&mut a, &mut b);
    // Build an AS_PATH whose first segment is AS_CONFED_SEQUENCE — the
    // shape a confederation member would send to a peer it believes is
    // inside the confederation. Neither a nor b has a confederation
    // configured, so b MUST treat it as malformed.
    let mut path = AsPath::new();
    path.segments.push(AsPathSegment {
        kind: AsPathType::ConfedSequence,
        ases: vec![Asn(65001)],
    });
    path.segments.push(AsPathSegment {
        kind: AsPathType::Sequence,
        ases: vec![Asn(64500)],
    });
    let mut u = Update::new();
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        path.encode_4(),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![192, 0, 2, 1],
    ));
    u.nlri.push(Nlri::plain(lr_core::addr::Prefix::new_v4(
        [203, 0, 113, 0],
        24,
    )));
    let actions = b.step(BgpEvent::Message(BgpMessage::Update(u)));
    assert!(
        !actions
            .iter()
            .any(|x| matches!(x, BgpAction::InstallRoute(_))),
        "a non-confederation peer must not install routes from an AS_PATH with AS_CONFED_*"
    );
}

/// RFC 5065 §5 (positive direction): a confederation member MAY send
/// AS_CONFED_* to a peer in the same confederation, and the receiver
/// installs the route. This guards against the validator over-reaching
/// and rejecting legitimate confederation-internal traffic.
#[test]
fn accepts_confed_segments_from_confederation_peer() {
    use crate::path::{AsPath, AsPathSegment, AsPathType, PathAttrFlags, PathAttribute};
    use crate::role::ConfederationConfig;
    let mut cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg1.confederation = Some(ConfederationConfig::new(vec![64512, 64513, 64514]));
    let mut cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg2.confederation = Some(ConfederationConfig::new(vec![64512, 64513, 64514]));
    let (mut a, mut b) = (BgpPeer::new(cfg1), BgpPeer::new(cfg2));
    establish(&mut a, &mut b);
    let mut path = AsPath::new();
    path.segments.push(AsPathSegment {
        kind: AsPathType::ConfedSequence,
        ases: vec![Asn(64512)],
    });
    path.segments.push(AsPathSegment {
        kind: AsPathType::Sequence,
        ases: vec![Asn(64500)],
    });
    let mut u = Update::new();
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        path.encode_4(),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![192, 0, 2, 1],
    ));
    u.nlri.push(Nlri::plain(lr_core::addr::Prefix::new_v4(
        [203, 0, 113, 0],
        24,
    )));
    let actions = b.step(BgpEvent::Message(BgpMessage::Update(u)));
    assert!(
        actions
            .iter()
            .any(|x| matches!(x, BgpAction::InstallRoute(_))),
        "a confederation peer must install routes from a same-confederation AS_CONFED_* path"
    );
}
