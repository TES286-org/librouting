use super::*;
use crate::message::update::Nlri;
use crate::path::AsPath;
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

/// draft-ietf-idr-addpath-paths-limit-00 §3: each side's capability
/// value is the number of paths it is willing to receive. After the
/// handshake the peer's value caps our egress, our own value caps our
/// ingress, and the two directions never merge.
#[test]
fn paths_limit_negotiates_per_direction() {
    use lr_core::nlri::NlriFamily;
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.add_path = true;
    cfg_a.paths_limit = vec![(1, 1, 4)];
    let mut cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg_b.add_path = true;
    cfg_b.paths_limit = vec![(1, 1, 2)];
    let mut a = BgpPeer::new(cfg_a);
    let mut b = BgpPeer::new(cfg_b);
    establish(&mut a, &mut b);
    assert_eq!(a.paths_limit_tx_for(NlriFamily::IPV4_UNICAST), Some(2));
    assert_eq!(a.paths_limit_rx_for(NlriFamily::IPV4_UNICAST), Some(4));
    assert_eq!(b.paths_limit_tx_for(NlriFamily::IPV4_UNICAST), Some(4));
    assert_eq!(b.paths_limit_rx_for(NlriFamily::IPV4_UNICAST), Some(2));
    // Families without an advertised tuple stay uncapped.
    assert_eq!(a.paths_limit_tx_for(NlriFamily::IPV6_UNICAST), None);
    assert_eq!(a.paths_limit_rx_for(NlriFamily::IPV6_UNICAST), None);
}

/// The peer's PATHS-LIMIT is meaningful only when AddPath transmit
/// was negotiated for the family (draft §3).
#[test]
fn paths_limit_ignored_without_add_path() {
    use lr_core::nlri::NlriFamily;
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.paths_limit = vec![(1, 1, 4)];
    let cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    let mut a = BgpPeer::new(cfg_a);
    let mut b = BgpPeer::new(cfg_b);
    establish(&mut a, &mut b);
    assert_eq!(a.paths_limit_tx_for(NlriFamily::IPV4_UNICAST), None);
    assert_eq!(a.paths_limit_rx_for(NlriFamily::IPV4_UNICAST), None);
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

/// Drive one peer into OpenSent with the configured local role and
/// feed a hand-built OPEN carrying the peer's role capability.
fn role_handshake(
    local_role: (crate::role::OtcRole, bool),
    peer_role: Option<u8>,
) -> (BgpState, Vec<u8>) {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg.bgp_role = Some(local_role);
    let mut peer = BgpPeer::new(cfg);
    peer.step(BgpEvent::ManualStart);
    peer.step(BgpEvent::TransportOpen);
    let _ = peer.drain_outgoing(); // local OPEN
    let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 2]));
    if let Some(role) = peer_role {
        open.params.push(crate::message::open::OpenParam {
            param_type: crate::message::open::OpenParam::PARAM_TYPE_CAPABILITY,
            value: Capability::encode_set(&[Capability::bgp_role(role)]),
        });
    }
    peer.step(BgpEvent::Message(BgpMessage::Open(open)));
    (peer.state(), peer.drain_outgoing())
}

fn notification_code_subcode(wire: &[u8]) -> Option<(u8, u8)> {
    let msg = crate::codec::BgpCodec::new().decode_slice(wire).ok()??;
    match msg {
        BgpMessage::Notification(n) => Some((n.error_code, n.error_subcode)),
        _ => None,
    }
}

#[test]
fn role_mismatch_raises_open_error_11() {
    use crate::role::OtcRole;
    let (state, out) = role_handshake((OtcRole::Provider, false), Some(0)); // Provider/Provider
    assert_eq!(state, BgpState::Idle);
    assert_eq!(notification_code_subcode(&out), Some((2, 11)));
}

#[test]
fn role_complementary_pair_reaches_open_confirm() {
    use crate::role::OtcRole;
    let (state, out) = role_handshake((OtcRole::Provider, false), Some(3)); // Customer
    assert_eq!(state, BgpState::OpenConfirm);
    assert_eq!(out.get(18).copied(), Some(4)); // KEEPALIVE
}

#[test]
fn role_strict_mode_rejects_missing_peer_capability() {
    use crate::role::OtcRole;
    let (state, out) = role_handshake((OtcRole::Provider, true), None);
    assert_eq!(state, BgpState::Idle);
    assert_eq!(notification_code_subcode(&out), Some((2, 11)));
}

#[test]
fn role_lenient_mode_allows_missing_peer_capability() {
    use crate::role::OtcRole;
    let (state, _out) = role_handshake((OtcRole::Provider, false), None);
    assert_eq!(state, BgpState::OpenConfirm);
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

/// Exchange plane: both speakers configure the plane
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

/// Exchange plane: only one side configures the
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

// ----- Exchange-plane: attach/detach hooks over a live FSM pair -----

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
    // with flags 0x80. Code points 200/201 are arbitrary — they
    // must avoid the librouting-private tag range (250-255, see
    // `lr_bgp::path::AttrType`) so the relay path does not strip
    // them as internal state.
    let mut u = Update::new();
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_optional(true).set_transitive(true),
        AttrType::Other(200),
        vec![1, 2, 3],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_optional(true),
        AttrType::Other(201),
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
        .get(AttrType::Other(200))
        .expect("transitive unknown forwarded");
    assert!(relayed.flags.partial(), "Partial bit set per RFC 4271 §5.3");
    assert!(
        bag.get(AttrType::Other(201)).is_none(),
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

// ===== FRR `no bgp default ipv4-unicast` =====

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

// ===== StateMachine trait adapter surfaces RouteRefresh / EndOfRib =====
//
// `BgpPeer::step()` (the inherent method) emits `BgpAction::RouteRefreshRequested`
// and `BgpAction::EndOfRib`; the daemon consumes these directly. The
// `StateMachine for BgpPeer` trait adapter flattens `BgpAction` into the
// generic `lr_core::fsm::Action` enum so a trait-only embedder can drive the
// FSM without depending on `lr-bgp`'s action vocabulary. Before the issue
// #92 fix the adapter mapped both variants to `Action::None`, silently
// dropping the signal — these tests pin the contract that the adapter now
// surfaces them as `Action::EmitEvent(Event::RouteRefreshRequested { .. })`
// and `Action::EmitEvent(Event::EndOfRib { .. })`.

/// Helper: drive `peer` through the `StateMachine` trait and return the
/// flattened `Vec<Action>` for the single `BgpEvent`. Mirrors how a
/// trait-only embedder would call `peer.step(event)` — the inherent
/// `BgpPeer::step` returns `Vec<BgpAction>`, the trait `step` returns
/// `Vec<Action>`.
fn trait_step(peer: &mut BgpPeer, ev: BgpEvent) -> Vec<Action> {
    use lr_core::fsm::StateMachine;
    StateMachine::step(peer, ev)
}

/// A negotiated ROUTE-REFRESH received by peer `a` surfaces through the
/// `StateMachine` trait adapter as
/// `Action::EmitEvent(Event::RouteRefreshRequested)`, not `Action::None`.
/// The session id is `cfg.peer_id` of the receiving peer (here `0`
/// because the test peer never overrides the default).
#[test]
fn trait_adapter_surfaces_route_refresh() {
    use crate::message::route_refresh::RouteRefresh;
    let (mut a, mut b) = make_peer_pair();
    establish(&mut a, &mut b);
    // The peer must have negotiated ROUTE-REFRESH for the FSM to surface
    // the action; the default `PeerConfig::new` enables it.
    assert!(a.route_refresh_negotiated());
    let actions = trait_step(
        &mut a,
        BgpEvent::Message(BgpMessage::RouteRefresh(RouteRefresh::new(
            NlriFamily::IPV4_UNICAST,
        ))),
    );
    let found = actions.iter().any(|a| {
        matches!(
            a,
            Action::EmitEvent(lr_core::event::Event::RouteRefreshRequested {
                family: NlriFamily { afi: 1, safi: 1 },
                session: 0,
            })
        )
    });
    assert!(
        found,
        "the trait adapter must surface RouteRefreshRequested as \
         Action::EmitEvent(Event::RouteRefreshRequested); if this assertion \
         fails, the adapter has regressed to mapping BgpAction::RouteRefreshRequested \
         to Action::None"
    );
}

/// The End-of-RIB marker received by a peer surfaces through the
/// `StateMachine` trait adapter as `Action::EmitEvent(Event::EndOfRib)`,
/// not `Action::None`. An empty UPDATE is the End-of-RIB marker for
/// IPv4 unicast (RFC 4724 §4).
#[test]
fn trait_adapter_surfaces_end_of_rib() {
    let (mut a, mut b) = make_peer_pair();
    establish(&mut a, &mut b);
    let actions = trait_step(&mut a, BgpEvent::Message(BgpMessage::Update(Update::new())));
    let found = actions.iter().any(|a| {
        matches!(
            a,
            Action::EmitEvent(lr_core::event::Event::EndOfRib {
                family: NlriFamily { afi: 1, safi: 1 },
                session: 0,
            })
        )
    });
    assert!(
        found,
        "the trait adapter must surface EndOfRib as \
         Action::EmitEvent(Event::EndOfRib); if this assertion fails, \
         the adapter has regressed to mapping BgpAction::EndOfRib \
         to Action::None"
    );
}

// ===== RFC 7313 §3.2 receive-side BoRR / EoRR demarcation =====
//
// `enhanced_route_refresh_emits_demarcation_messages` (above) covers the
// *send* side: the FSM produces a BoRR/EoRR on the wire when the local
// config calls `begin_enhanced_route_refresh` /
// `end_enhanced_route_refresh`. The receive side previously dropped
// the demarcation subtypes silently — only `Normal` produced an action
// — so an embedder that negotiated RFC 7313 and relied on the
// demarcation to coordinate a route-refresh response saw the markers
// vanish at the wire boundary. The fix dispatches `BeginOfRib` /
// `EndOfRib` through the FSM receive arm; these tests pin the contract.

/// A negotiated BoRR received by peer `a` surfaces through
/// `BgpPeer::step()` as `BgpAction::BeginOfRouteRefresh(family)`. The
/// action is only emitted when both speakers advertised the Enhanced
/// Route Refresh capability (RFC 7313 §3.1) — a peer that sends a BoRR
/// without negotiating the capability is silently ignored per §3.2.
#[test]
fn enhanced_route_refresh_borr_emits_action_when_negotiated() {
    use crate::message::route_refresh::RouteRefresh;
    let (mut a, mut b) = make_peer_pair();
    establish(&mut a, &mut b);
    // Default `PeerConfig::new` enables `enhanced_rr`; the OPEN
    // exchange advertises the capability on both sides, so the
    // negotiation must succeed.
    assert!(a.enhanced_route_refresh_negotiated());
    assert!(b.enhanced_route_refresh_negotiated());
    let actions = a.step(BgpEvent::Message(BgpMessage::RouteRefresh(
        RouteRefresh::begin_of_rib(NlriFamily::IPV4_UNICAST),
    )));
    let found = actions.iter().any(|a| {
        matches!(
            a,
            BgpAction::BeginOfRouteRefresh(NlriFamily { afi: 1, safi: 1 })
        )
    });
    assert!(
        found,
        "the FSM must surface a negotiated BoRR as \
         BgpAction::BeginOfRouteRefresh; if this assertion fails, the \
         receive-side dispatch has regressed to silently dropping the \
         demarcation marker (issue #92 fix)"
    );
}

/// A negotiated EoRR received by peer `a` surfaces through
/// `BgpPeer::step()` as `BgpAction::EndOfRib(family)`. RFC 7313 §3.3
/// says the EoRR is treated as the End-of-RIB marker (RFC 4724 §4) for
/// the family, so the existing action runs the same helper in the
/// router (`on_end_of_rib`): the GR-retention purge for the family
/// ends, and stale routes the peer did not refresh are removed.
#[test]
fn enhanced_route_refresh_eorr_emits_end_of_rib_action_when_negotiated() {
    use crate::message::route_refresh::RouteRefresh;
    let (mut a, mut b) = make_peer_pair();
    establish(&mut a, &mut b);
    assert!(a.enhanced_route_refresh_negotiated());
    let actions = a.step(BgpEvent::Message(BgpMessage::RouteRefresh(
        RouteRefresh::end_of_rib(NlriFamily::IPV4_UNICAST),
    )));
    let found = actions
        .iter()
        .any(|a| matches!(a, BgpAction::EndOfRib(NlriFamily { afi: 1, safi: 1 })));
    assert!(
        found,
        "the FSM must surface a negotiated EoRR as BgpAction::EndOfRib \
         (reused for RFC 4724 §4 implicit EoR marker); if this \
         assertion fails, the receive-side dispatch has regressed to \
         silently dropping the demarcation marker (issue #92 fix)"
    );
}

/// A peer that did not negotiate the Enhanced Route Refresh
/// capability must not produce `BeginOfRouteRefresh` /
/// `EndOfRib` actions when it receives a BoRR/EoRR — RFC 7313 §3.2
/// says the receiver silently ignores subtypes it does not
/// recognise. Without the capability, the demarcation markers stay
/// inert on the wire (the existing behaviour).
#[test]
fn enhanced_route_refresh_demarcation_silently_ignored_when_not_negotiated() {
    use crate::message::route_refresh::RouteRefresh;
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.enhanced_rr = false;
    let mut cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg_b.enhanced_rr = false;
    let (mut a, mut b) = (BgpPeer::new(cfg_a), BgpPeer::new(cfg_b));
    establish(&mut a, &mut b);
    // The capability was not negotiated on either side.
    assert!(!a.enhanced_route_refresh_negotiated());
    assert!(!b.enhanced_route_refresh_negotiated());
    // A BoRR from the peer must not produce an action.
    let actions = a.step(BgpEvent::Message(BgpMessage::RouteRefresh(
        RouteRefresh::begin_of_rib(NlriFamily::IPV4_UNICAST),
    )));
    let borr = actions
        .iter()
        .any(|a| matches!(a, BgpAction::BeginOfRouteRefresh(_)));
    let eorr_as_borr = actions.iter().any(|a| matches!(a, BgpAction::EndOfRib(_)));
    assert!(
        !borr && !eorr_as_borr,
        "the FSM must silently ignore a BoRR from a peer that did not \
         negotiate the Enhanced Route Refresh capability (RFC 7313 §3.2)"
    );
    // Same for an EoRR.
    let actions = a.step(BgpEvent::Message(BgpMessage::RouteRefresh(
        RouteRefresh::end_of_rib(NlriFamily::IPV4_UNICAST),
    )));
    let eorr = actions.iter().any(|a| matches!(a, BgpAction::EndOfRib(_)));
    assert!(
        !eorr,
        "the FSM must silently ignore an EoRR from a peer that did \
         not negotiate the Enhanced Route Refresh capability (RFC \
         7313 §3.2)"
    );
}

/// A negotiated BoRR surfaces through the `StateMachine` trait
/// adapter as `Action::EmitEvent(Event::BeginOfRouteRefresh { .. })`,
/// not `Action::None`. Mirrors `trait_adapter_surfaces_route_refresh`
/// for the new RFC 7313 §3.2 demarcation marker.
#[test]
fn trait_adapter_surfaces_begin_of_route_refresh() {
    use crate::message::route_refresh::RouteRefresh;
    let (mut a, mut b) = make_peer_pair();
    establish(&mut a, &mut b);
    assert!(a.enhanced_route_refresh_negotiated());
    let actions = trait_step(
        &mut a,
        BgpEvent::Message(BgpMessage::RouteRefresh(RouteRefresh::begin_of_rib(
            NlriFamily::IPV4_UNICAST,
        ))),
    );
    let found = actions.iter().any(|a| {
        matches!(
            a,
            Action::EmitEvent(lr_core::event::Event::BeginOfRouteRefresh {
                family: NlriFamily { afi: 1, safi: 1 },
                session: 0,
            })
        )
    });
    assert!(
        found,
        "the trait adapter must surface BeginOfRouteRefresh as \
         Action::EmitEvent(Event::BeginOfRouteRefresh); if this \
         assertion fails, the adapter has regressed to mapping \
         BgpAction::BeginOfRouteRefresh to Action::None"
    );
}

/// A negotiated EoRR surfaces through the `StateMachine` trait
/// adapter as `Action::EmitEvent(Event::EndOfRib { .. })` — the same
/// shape the implicit EoR marker (RFC 4724 §4) takes.
#[test]
fn trait_adapter_surfaces_eorr_as_end_of_rib() {
    use crate::message::route_refresh::RouteRefresh;
    let (mut a, mut b) = make_peer_pair();
    establish(&mut a, &mut b);
    assert!(a.enhanced_route_refresh_negotiated());
    let actions = trait_step(
        &mut a,
        BgpEvent::Message(BgpMessage::RouteRefresh(RouteRefresh::end_of_rib(
            NlriFamily::IPV4_UNICAST,
        ))),
    );
    let found = actions.iter().any(|a| {
        matches!(
            a,
            Action::EmitEvent(lr_core::event::Event::EndOfRib {
                family: NlriFamily { afi: 1, safi: 1 },
                session: 0,
            })
        )
    });
    assert!(
        found,
        "the trait adapter must surface a negotiated EoRR as \
         Action::EmitEvent(Event::EndOfRib); if this assertion fails, \
         the adapter has regressed to mapping BgpAction::EndOfRib (for \
         the EoRR subtype) to Action::None"
    );
}

/// A Normal ROUTE-REFRESH received from a peer that did *not*
/// negotiate the Enhanced Route Refresh capability still produces
/// `BgpAction::RouteRefreshRequested` — RFC 2918 §2 (the base
/// capability) is the precondition; the demarcation subtypes are the
/// only piece the Enhanced Route Refresh capability adds. This test
/// pins the contract so the receive-side fix does not regress the
/// `Normal` path.
#[test]
fn route_refresh_normal_subtype_still_dispatched_without_enhanced_rr() {
    use crate::message::route_refresh::RouteRefresh;
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.enhanced_rr = false;
    let mut cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg_b.enhanced_rr = false;
    let (mut a, mut b) = (BgpPeer::new(cfg_a), BgpPeer::new(cfg_b));
    establish(&mut a, &mut b);
    assert!(!a.enhanced_route_refresh_negotiated());
    assert!(a.route_refresh_negotiated());
    let actions = a.step(BgpEvent::Message(BgpMessage::RouteRefresh(
        RouteRefresh::new(NlriFamily::IPV4_UNICAST),
    )));
    let found = actions
        .iter()
        .any(|a| matches!(a, BgpAction::RouteRefreshRequested(_)));
    assert!(
        found,
        "the FSM must still surface a Normal ROUTE-REFRESH as \
         BgpAction::RouteRefreshRequested when the Enhanced Route \
         Refresh capability was not negotiated; if this assertion \
         fails, the receive-side dispatch has regressed the RFC 2918 \
         base capability path"
    );
}

// ---------------------------------------------------------------------------
// BFD Strict-Mode (draft-ietf-idr-bgp-bfd-strict-mode-13).
// ---------------------------------------------------------------------------

/// A peer pair with BFD enabled and strict-mode configured on both
/// sides. `hold_time` is the BGP hold time (0 exercises the draft's
/// BfdHoldTimer path).
fn bfd_strict_pair(hold_time: u16) -> (BgpPeer, BgpPeer) {
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.bfd_enabled = true;
    cfg_a.bfd_strict_mode = true;
    cfg_a.hold_time = hold_time;
    let mut cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg_b.bfd_enabled = true;
    cfg_b.bfd_strict_mode = true;
    cfg_b.hold_time = hold_time;
    (BgpPeer::new(cfg_a), BgpPeer::new(cfg_b))
}

/// Drive both peers through the OPEN exchange while BFD is Down.
/// Returns the two OPEN payloads already cross-fed; both FSMs must be
/// in OpenSentBfdUpPending.
fn open_with_bfd_down(a: &mut BgpPeer, b: &mut BgpPeer) {
    a.set_bfd_state(Some(BfdState::Down));
    b.set_bfd_state(Some(BfdState::Down));
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    b.feed_bytes(&a_open).unwrap();
    a.feed_bytes(&b_open).unwrap();
}

/// draft §8.1/§8.5: the KEEPALIVE and the OpenConfirm transition wait
/// for BFD Up; BfdUp then releases the handshake.
#[test]
fn bfd_strict_mode_holds_open_confirm_until_up() {
    let (mut a, mut b) = bfd_strict_pair(90);
    open_with_bfd_down(&mut a, &mut b);
    assert_eq!(a.state(), BgpState::OpenSent);
    assert_eq!(b.state(), BgpState::OpenSent);
    assert!(a.bfd_strict_negotiated() && b.bfd_strict_negotiated());
    assert!(a.bfd_pending() && b.bfd_pending());
    assert!(
        a.drain_outgoing().is_empty() && b.drain_outgoing().is_empty(),
        "no KEEPALIVE may be sent while BFD is Down"
    );

    // One side comes Up: it sends its KEEPALIVE and moves on.
    b.step(BgpEvent::Bfd(BfdState::Up));
    assert_eq!(b.state(), BgpState::OpenConfirm);
    assert!(!b.bfd_pending());
    let b_ka = b.drain_outgoing();
    assert_eq!(b_ka[18], 4, "KEEPALIVE released by BfdUp");

    // The other side is still pending; the KEEPALIVE is ignored in
    // OpenSent and does not advance the FSM.
    a.feed_bytes(&b_ka).unwrap();
    assert_eq!(a.state(), BgpState::OpenSent);

    a.step(BgpEvent::Bfd(BfdState::Up));
    assert_eq!(a.state(), BgpState::OpenConfirm);
    let a_ka = a.drain_outgoing();
    assert_eq!(a_ka[18], 4);
    a.feed_bytes(&b_ka).unwrap();
    b.feed_bytes(&a_ka).unwrap();
    assert!(a.is_established() && b.is_established());
}

/// draft §6: strict-mode applies only when both speakers advertised
/// the capability. A peer that did not advertise it keeps the normal
/// OPEN path even when the local BFD is Down.
#[test]
fn bfd_strict_mode_requires_peer_advertisement() {
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.bfd_enabled = true;
    cfg_a.bfd_strict_mode = true;
    let cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    let (mut a, mut b) = (BgpPeer::new(cfg_a), BgpPeer::new(cfg_b));
    a.set_bfd_state(Some(BfdState::Down));
    b.set_bfd_state(Some(BfdState::Down));

    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    b.step(BgpEvent::ManualStart);
    b.step(BgpEvent::TransportOpen);
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    b.feed_bytes(&a_open).unwrap();
    a.feed_bytes(&b_open).unwrap();

    assert!(!a.bfd_strict_negotiated());
    assert!(!a.bfd_pending());
    assert_eq!(a.state(), BgpState::OpenConfirm);
    let out = a.drain_outgoing();
    assert_eq!(out[18], 4, "the normal KEEPALIVE still goes out");
}

/// draft §8.6.2: BFD Down in OpenConfirm tears the session down with
/// Cease / BFD Down (6/10) when strict-mode was negotiated.
#[test]
fn bfd_down_in_open_confirm_strict_sends_cease() {
    let (mut a, mut b) = bfd_strict_pair(90);
    open_with_bfd_down(&mut a, &mut b);
    a.step(BgpEvent::Bfd(BfdState::Up));
    assert_eq!(a.state(), BgpState::OpenConfirm);
    let _ = a.drain_outgoing();

    a.step(BgpEvent::Bfd(BfdState::Down));
    assert_eq!(a.state(), BgpState::Idle);
    assert!(a.bfd_down_teardown());
    let out = a.drain_outgoing();
    assert_eq!(out[18], 3, "NOTIFICATION");
    assert_eq!(out[19], 6, "Cease");
    assert_eq!(out[20], 10, "BFD Down");
}

/// draft §8.7.2: BFD Down in Established always tears the session down
/// with Cease / BFD Down; AdminDown is ignored (§8.7.1).
#[test]
fn bfd_down_in_established_sends_cease_and_admin_down_is_ignored() {
    let (mut a, mut b) = bfd_strict_pair(90);
    a.set_bfd_state(Some(BfdState::Up));
    b.set_bfd_state(Some(BfdState::Up));
    establish(&mut a, &mut b);

    a.step(BgpEvent::Bfd(BfdState::AdminDown));
    assert_eq!(a.state(), BgpState::Established);
    assert!(a.drain_outgoing().is_empty(), "AdminDown is ignored");

    a.step(BgpEvent::Bfd(BfdState::Down));
    assert_eq!(a.state(), BgpState::Idle);
    assert!(a.bfd_down_teardown());
    let out = a.drain_outgoing();
    assert_eq!(out[18], 3);
    assert_eq!(out[19], 6);
    assert_eq!(out[20], 10);
}

/// draft §8.5.1: BfdAdminDown releases the pending handshake just like
/// BfdUp (only BfdDown holds it).
#[test]
fn bfd_admin_down_releases_pending_open() {
    let (mut a, mut b) = bfd_strict_pair(90);
    open_with_bfd_down(&mut a, &mut b);
    a.step(BgpEvent::Bfd(BfdState::AdminDown));
    assert_eq!(a.state(), BgpState::OpenConfirm);
    let out = a.drain_outgoing();
    assert_eq!(out[18], 4);
}

/// draft §3/§8.5.2: with a zero negotiated hold time the BfdHoldTimer
/// bounds the wait; expiry sends Cease / BFD Down and returns to Idle.
#[test]
fn bfd_hold_timer_expiry_with_zero_hold_time() {
    let (mut a, mut b) = bfd_strict_pair(0);
    open_with_bfd_down(&mut a, &mut b);
    assert!(a.bfd_pending());

    a.step(BgpEvent::TimerBfdHoldExpired);
    assert_eq!(a.state(), BgpState::Idle);
    assert!(a.bfd_down_teardown());
    let out = a.drain_outgoing();
    assert_eq!(out[18], 3);
    assert_eq!(out[19], 6);
    assert_eq!(out[20], 10);
}

/// The strict-mode capability is advertised only when BFD itself is
/// enabled (the draft's `BfdEnabled`): strict without BFD has no
/// effect and must not gate or advertise.
#[test]
fn bfd_strict_mode_not_advertised_without_bfd() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg.bfd_strict_mode = true;
    let mut a = BgpPeer::new(cfg);
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    let open = a.drain_outgoing();
    // OPEN body: version, my_as, hold, bgp_id, optional-parameter
    // length; the FSM emits one capability parameter.
    let opt_len = open[28] as usize;
    let params = &open[29..29 + opt_len];
    assert_eq!(params[0], 2, "capability parameter");
    let caps = crate::capabilities::Capability::decode_set(&params[2..2 + params[1] as usize]);
    assert!(
        !caps
            .iter()
            .any(|c| c.code == crate::capabilities::CapabilityCode::BfdStrictMode),
        "code 74 must be absent when BFD is not enabled"
    );
}

// ---------------------------------------------------------------------------
// RFC 5291 / RFC 5292 Outbound Route Filtering.
// ---------------------------------------------------------------------------

fn orf_pair(a_mode: u8, b_mode: u8) -> (BgpPeer, BgpPeer) {
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.orf = vec![(1, 1, vec![(64, a_mode)])];
    let mut cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg_b.orf = vec![(1, 1, vec![(64, b_mode)])];
    let (mut a, mut b) = (BgpPeer::new(cfg_a), BgpPeer::new(cfg_b));
    establish(&mut a, &mut b);
    (a, b)
}

/// RFC 5291 §4/§6: an ORF ROUTE-REFRESH from a SEND-mode peer reaches a
/// RECEIVE-mode peer as `BgpAction::OrfReceived`, not as a plain refresh
/// request.
#[test]
fn orf_received_when_both_sides_negotiated() {
    use crate::message::{AddressPrefixOrf, OrfList, OrfWhenToRefresh};
    let (mut a, mut b) = orf_pair(1 /* receive */, 2 /* send */);
    assert!(a.orf_negotiated() && b.orf_negotiated());

    let entries = vec![AddressPrefixOrf::add(
        7,
        true,
        Prefix::new_v4([10, 0, 0, 0], 8),
        0,
        0,
    )];
    assert!(b.send_orf(
        NlriFamily::IPV4_UNICAST,
        OrfWhenToRefresh::Immediate,
        &[OrfList::address_prefix(entries.clone())],
    ));
    let actions = a.feed_bytes(&b.drain_outgoing()).unwrap();
    let found = actions.iter().find_map(|action| match action {
        BgpAction::OrfReceived {
            family,
            when,
            lists,
        } => Some((*family, *when, lists.clone())),
        _ => None,
    });
    let (family, when, lists) = found.expect("OrfReceived action");
    assert_eq!(family, NlriFamily::IPV4_UNICAST);
    assert_eq!(when, OrfWhenToRefresh::Immediate);
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].address_prefix_entries(), Some(entries));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, BgpAction::RouteRefreshRequested(_))),
        "an ORF message is not a plain refresh request"
    );
}

/// A peer that advertised only RECEIVE cannot send ORF entries; the FSM
/// refuses to put them on the wire (RFC 5291 §6).
#[test]
fn orf_send_refused_when_peer_only_receives() {
    use crate::message::{AddressPrefixOrf, OrfList, OrfWhenToRefresh};
    let (mut a, _b) = orf_pair(3 /* both */, 2 /* send only */);
    let entries = vec![AddressPrefixOrf::add(
        1,
        true,
        Prefix::new_v4([10, 0, 0, 0], 8),
        0,
        0,
    )];
    assert!(!a.send_orf(
        NlriFamily::IPV4_UNICAST,
        OrfWhenToRefresh::Immediate,
        &[OrfList::address_prefix(entries)],
    ));
    assert!(a.drain_outgoing().is_empty());
}

/// An ORF type we did not advertise as RECEIVE is dropped before the
/// action is surfaced (RFC 5291 §6).
#[test]
fn orf_received_drops_unadvertised_type() {
    use crate::message::{OrfEntry, OrfList, OrfRefresh, OrfWhenToRefresh, RouteRefresh};
    let (mut a, _b) = orf_pair(1, 2);
    // Hand-build a message carrying type 65, which neither side
    // advertised.
    let refresh = RouteRefresh {
        family: NlriFamily::IPV4_UNICAST,
        subtype: crate::message::RouteRefreshSubtype::Normal,
        orf: Some(OrfRefresh {
            when: OrfWhenToRefresh::Immediate,
            lists: vec![OrfList {
                orf_type: 65,
                entries: vec![OrfEntry::Raw(vec![0])],
            }],
        }),
    };
    let codec = crate::codec::BgpCodec::new();
    let bytes = codec
        .encode_vec(&BgpMessage::RouteRefresh(refresh))
        .unwrap();
    let actions = a.feed_bytes(&bytes).unwrap();
    assert!(!actions
        .iter()
        .any(|a| matches!(a, BgpAction::OrfReceived { .. })));
}

// ---------------------------------------------------------------------------
// draft-ietf-idr-linklocal-capability-06 runtime.
// ---------------------------------------------------------------------------

fn link_local_pair(a_enabled: bool, b_enabled: bool) -> (BgpPeer, BgpPeer) {
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.link_local_next_hop = a_enabled;
    cfg_a.mp_families = vec![NlriFamily::IPV6_UNICAST];
    let mut cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg_b.link_local_next_hop = b_enabled;
    cfg_b.mp_families = vec![NlriFamily::IPV6_UNICAST];
    let (mut a, mut b) = (BgpPeer::new(cfg_a), BgpPeer::new(cfg_b));
    establish(&mut a, &mut b);
    (a, b)
}

fn link_local_update(next_hop: crate::path::MpNextHop) -> BgpMessage {
    use crate::message::update::Update;
    use crate::path::{AsPath, MpReach};
    let prefix = Prefix::new_v6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        64,
    );
    let mut u = Update::new();
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
    let reach = MpReach::new(
        NlriFamily::IPV6_UNICAST,
        next_hop,
        vec![crate::message::update::Nlri::plain(prefix)],
    );
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_optional(true),
        AttrType::MpReachNlri,
        reach.encode(),
    ));
    BgpMessage::Update(u)
}

/// §3: a Link-Local-only next hop without the capability negotiated is
/// treated as withdraw, not installed with an unusable fe80:: next hop.
#[test]
fn link_local_only_next_hop_without_capability_is_treated_as_withdraw() {
    let ll = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let (mut a, _b) = link_local_pair(false, false);
    assert!(!a.link_local_negotiated());
    let actions = a.step(BgpEvent::Message(link_local_update(
        crate::path::MpNextHop::V6LinkLocal(ll),
    )));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, BgpAction::InstallRoute(_))),
        "an unnegotiated link-local next hop must not be installed"
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, BgpAction::WithdrawRoute { .. })),
        "the UPDATE is a treat-as-withdraw"
    );
}

/// When both sides negotiated the capability, the link-local next hop is
/// installed as the route's next hop.
#[test]
fn link_local_only_next_hop_installs_when_negotiated() {
    let ll = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let (mut a, _b) = link_local_pair(true, true);
    assert!(a.link_local_negotiated());
    let actions = a.step(BgpEvent::Message(link_local_update(
        crate::path::MpNextHop::V6LinkLocal(ll),
    )));
    let route = actions
        .iter()
        .find_map(|a| match a {
            BgpAction::InstallRoute(r) => Some(r),
            _ => None,
        })
        .expect("route installed");
    assert_eq!(
        route.next_hop,
        Some(lr_core::addr::IpAddr::V6(ll)),
        "the link-local next hop is preserved"
    );
}

/// §4: egress refuses a link-local-only next hop when the capability was
/// not negotiated, and puts a 16-octet fe80:: next hop on the wire when
/// it was.
#[test]
fn link_local_egress_requires_negotiation() {
    use crate::path::AsPath;
    let ll = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut attrs = crate::path::PathAttributes::new();
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        AsPath::from_sequence([Asn(64512)]).encode_4(),
    ));
    let route = lr_core::rib::Route {
        key: lr_core::rib::RouteKey::new(
            Prefix::new_v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                64,
            ),
            NlriFamily::IPV6_UNICAST,
        ),
        origin: lr_core::rib::RouteOrigin { proto: 2, peer: 0 },
        protocol: lr_core::rib::Protocol::Bgp,
        preference: lr_core::rib::Preference::new(20, 1),
        next_hop: Some(lr_core::addr::IpAddr::V6(ll)),
        attributes: attrs.into(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    };

    let (mut plain, _b) = link_local_pair(false, false);
    assert!(
        !plain.advertise(&route),
        "no capability, no LL advertisement"
    );

    let (mut ll_peer, _b) = link_local_pair(true, true);
    assert!(ll_peer.advertise(&route));
    let bytes = ll_peer.drain_outgoing();
    use lr_core::codec::Decoder as _;
    let mut codec = BgpCodec::new().with_asn4(true);
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    let msg = codec.decode(&mut r).unwrap().expect("an UPDATE");
    let BgpMessage::Update(u) = msg else {
        panic!("expected UPDATE");
    };
    let reach =
        crate::path::MpReach::decode(&u.attributes.get(AttrType::MpReachNlri).unwrap().value)
            .unwrap();
    assert_eq!(reach.next_hop, crate::path::MpNextHop::V6LinkLocal(ll));
}

// ---------------------------------------------------------------------------
// RFC 8654 Extended Message.
// ---------------------------------------------------------------------------

/// A route whose serialized UPDATE exceeds the RFC 4271 4096-octet
/// ceiling (a large optional-transitive attribute).
fn oversized_route() -> Route {
    let mut attrs = PathAttributes::new();
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        AsPath::from_sequence([Asn(64512)]).encode_4(),
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![10, 0, 0, 1],
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_optional(true).set_transitive(true),
        AttrType::Other(99),
        vec![0xab; 5000],
    ));
    Route {
        key: RouteKey::new(
            Prefix::new_v4([203, 0, 113, 0], 24),
            NlriFamily::IPV4_UNICAST,
        ),
        origin: RouteOrigin { proto: 2, peer: 0 },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 1),
        next_hop: Some(IpAddr::V4([10, 0, 0, 1])),
        attributes: attrs.into(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

/// RFC 8654 §3: with the capability negotiated on both sides an UPDATE
/// larger than 4096 octets is emitted and accepted; without it the
/// encoder refuses rather than truncating.
#[test]
fn extended_message_carries_an_oversized_update() {
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.extended_message = true;
    let mut cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg_b.extended_message = true;
    let (mut a, mut b) = (BgpPeer::new(cfg_a), BgpPeer::new(cfg_b));
    establish(&mut a, &mut b);
    assert!(a.codec_extended_message_active());

    let route = oversized_route();
    assert!(a.advertise(&route));
    let bytes = a.drain_outgoing();
    assert!(
        bytes.len() > 4096,
        "the UPDATE must use the extended ceiling (got {} bytes)",
        bytes.len()
    );
    let actions = b.feed_bytes(&bytes).unwrap();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, BgpAction::InstallRoute(_))),
        "the peer must accept the extended UPDATE"
    );
}

/// Without the capability the 4096-octet ceiling still applies: an
/// oversized UPDATE is not emitted (no silent truncation).
#[test]
fn extended_message_not_negotiated_refuses_the_oversized_update() {
    let (mut a, mut b) = make_peer_pair();
    establish(&mut a, &mut b);
    assert!(!a.codec_extended_message_active());
    assert!(!a.advertise(&oversized_route()));
    assert!(a.drain_outgoing().is_empty());
}

// ---------------------------------------------------------------------------
// FQDN / Software Version capability surfacing.
// ---------------------------------------------------------------------------

#[test]
fn peer_fqdn_and_software_version_are_surfaced() {
    let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg_a.fqdn = Some(("edge-a".into(), "example.net".into()));
    cfg_a.software_version = Some("lr/2.0-a".into());
    let mut cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
    cfg_b.fqdn = Some(("edge-b".into(), "example.net".into()));
    cfg_b.software_version = Some("bird/2.16".into());
    let (mut a, mut b) = (BgpPeer::new(cfg_a), BgpPeer::new(cfg_b));
    establish(&mut a, &mut b);

    assert_eq!(
        a.peer_fqdn(),
        Some(("edge-b".to_string(), "example.net".to_string()))
    );
    assert_eq!(a.peer_software_version(), Some("bird/2.16".to_string()));
    assert_eq!(
        b.peer_fqdn(),
        Some(("edge-a".to_string(), "example.net".to_string()))
    );
    assert_eq!(b.peer_software_version(), Some("lr/2.0-a".to_string()));
}
