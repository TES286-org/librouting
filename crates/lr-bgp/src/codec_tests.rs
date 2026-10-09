use super::*;
use crate::capabilities::Capability;
use crate::path::{AsPath, AttrType, Med, Origin, OriginKind, PathAttrFlags, PathAttribute};
use lr_core::addr::{Asn, RouterId};

fn roundtrip(msg: BgpMessage, asn4: bool) -> BgpMessage {
    let codec = BgpCodec::new().with_asn4(asn4);
    let bytes = codec.encode_vec(&msg).unwrap();
    let mut c2 = BgpCodec::new().with_asn4(asn4);
    c2.decode_slice(&bytes).unwrap().unwrap()
}

/// RFC 7911 §4.3: encode and decode an UPDATE whose IPv4 NLRI and
/// withdrawn sections carry 4-octet path identifiers. The framing only
/// roundtrips when both sides use the negotiated mode.
#[test]
fn update_add_path_roundtrip() {
    let mut u = Update::new();
    u.nlri
        .push(Nlri::new(1, Prefix::new_v4([203, 0, 113, 0], 24)));
    u.nlri
        .push(Nlri::new(2, Prefix::new_v4([203, 0, 113, 0], 24)));
    u.withdrawn
        .push(Nlri::new(7, Prefix::new_v4([198, 51, 100, 0], 24)));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));

    let mut tx = BgpCodec::new().with_asn4(true);
    tx.set_add_path(vec![NlriFamily::IPV4_UNICAST], vec![]);
    let bytes = tx.encode_vec(&BgpMessage::Update(u.clone())).unwrap();
    // Each of the three entries carries 4 extra identifier octets.
    let plain = BgpCodec::new()
        .with_asn4(true)
        .encode_vec(&BgpMessage::Update(u.clone()))
        .unwrap();
    assert_eq!(bytes.len(), plain.len() + 12);

    let mut rx = BgpCodec::new().with_asn4(true);
    rx.set_add_path(
        vec![NlriFamily::IPV4_UNICAST],
        vec![NlriFamily::IPV4_UNICAST],
    );
    match rx.decode_slice(&bytes).unwrap().unwrap() {
        BgpMessage::Update(d) => {
            assert_eq!(d.nlri.len(), 2);
            assert_eq!(d.nlri[0].path_id, 1);
            assert_eq!(d.nlri[1].path_id, 2);
            assert_eq!(d.withdrawn[0].path_id, 7);
        }
        _ => panic!("expected UPDATE"),
    }

    // Without the negotiated mode the same bytes misparse (the
    // identifier octets are read as prefix data).
    let mut blind = BgpCodec::new().with_asn4(true);
    let mis = blind.decode_slice(&bytes);
    assert!(
        mis.is_err()
            || !matches!(&mis.unwrap().unwrap(), BgpMessage::Update(d)
                if d.nlri.iter().all(|n| n.path_id == 0) && d.nlri.len() == 2),
        "add-path bytes must not decode as clean single-path NLRI"
    );
}

#[test]
fn keepalive_roundtrip() {
    let m = BgpMessage::Keepalive(Keepalive);
    let dec = roundtrip(m, false);
    assert!(matches!(dec, BgpMessage::Keepalive(_)));
}

#[test]
fn open_roundtrip() {
    let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 1]));
    open.params.push(OpenParam {
        param_type: OpenParam::PARAM_TYPE_CAPABILITY,
        value: Capability::encode_set(&[
            Capability::four_octet_as(70000),
            Capability::multiprotocol(2, 1),
        ]),
    });
    let m = BgpMessage::Open(open.clone());
    let dec = roundtrip(m, true);
    match dec {
        BgpMessage::Open(o) => {
            assert_eq!(o.my_as, Asn(64513));
            assert_eq!(o.hold_time, 90);
            assert_eq!(o.bgp_id, RouterId::from_v4([10, 0, 0, 1]));
            assert_eq!(o.params.len(), 1);
            let caps = Capability::decode_set(&o.params[0].value);
            assert_eq!(caps.len(), 2);
            assert_eq!(caps[0].as_four_octet(), Some(70000));
            assert_eq!(caps[1].as_multiprotocol(), Some((2, 1)));
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn update_with_attributes() {
    let mut u = Update::new();
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![OriginKind::Igp as u8],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        AsPath::from_sequence([Asn(100), Asn(200)]).encode_4(),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![10, 0, 0, 1],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_optional(true),
        AttrType::MultiExitDisc,
        Med(100).encode().to_vec(),
    ));
    u.nlri
        .push(Nlri::plain(Prefix::new_v4([192, 168, 1, 0], 24)));

    let m = BgpMessage::Update(u.clone());
    let dec = roundtrip(m, true);
    match dec {
        BgpMessage::Update(d) => {
            assert_eq!(d.nlri.len(), 1);
            assert_eq!(d.nlri[0].prefix.prefix_len, 24);
            assert_eq!(d.attributes.origin(), Some(Origin::new(OriginKind::Igp)));
            assert!(d.attributes.as_path().is_some());
        }
        _ => panic!("expected UPDATE"),
    }
}

#[test]
fn update_withdrawn() {
    let mut u = Update::new();
    u.withdrawn
        .push(Nlri::plain(Prefix::new_v4([10, 0, 0, 0], 8)));
    u.withdrawn
        .push(Nlri::plain(Prefix::new_v4([192, 168, 0, 0], 16)));
    let m = BgpMessage::Update(u.clone());
    let dec = roundtrip(m, false);
    match dec {
        BgpMessage::Update(d) => {
            assert_eq!(d.withdrawn.len(), 2);
            assert!(d.nlri.is_empty());
        }
        _ => panic!("expected UPDATE"),
    }
}

#[test]
fn notification_roundtrip() {
    let n = BgpNotification::new(6, 2, vec![]);
    let m = BgpMessage::Notification(n.clone());
    let dec = roundtrip(m, false);
    match dec {
        BgpMessage::Notification(d) => {
            assert_eq!(d.error_code, 6);
            assert_eq!(d.error_subcode, 2);
        }
        _ => panic!("expected NOTIFICATION"),
    }
}

#[test]
fn route_refresh_roundtrip() {
    let r = RouteRefresh::new(NlriFamily::IPV4_UNICAST);
    let m = BgpMessage::RouteRefresh(r);
    let dec = roundtrip(m, false);
    match dec {
        BgpMessage::RouteRefresh(d) => {
            assert_eq!(d.family, NlriFamily::IPV4_UNICAST);
            assert_eq!(d.subtype, crate::message::RouteRefreshSubtype::Normal);
        }
        _ => panic!("expected ROUTE-REFRESH"),
    }
}

#[test]
fn enhanced_route_refresh_markers_roundtrip() {
    for refresh in [
        RouteRefresh::begin_of_rib(NlriFamily::IPV4_UNICAST),
        RouteRefresh::end_of_rib(NlriFamily::IPV4_UNICAST),
    ] {
        let decoded = roundtrip(BgpMessage::RouteRefresh(refresh), false);
        assert_eq!(decoded, BgpMessage::RouteRefresh(refresh));
    }
}

#[test]
fn route_refresh_rejects_invalid_length() {
    assert!(decode_route_refresh(&[0, 1, 0, 1, 0]).is_err());
    assert!(decode_route_refresh(&[0, 1, 3]).is_err());
}

/// RFC 7313 §3.2: an unknown subtype is silently ignored, not an error.
#[test]
fn route_refresh_unknown_subtype_is_ignored() {
    let r = decode_route_refresh(&[0, 1, 3, 1]).unwrap();
    assert_eq!(r.subtype, crate::message::RouteRefreshSubtype::Unknown);
}

#[test]
fn streaming_decoder_accumulates() {
    let codec = BgpCodec::new();
    let msg = BgpMessage::Keepalive(Keepalive);
    let bytes = codec.encode_vec(&msg).unwrap();
    let mut c = BgpCodec::new();
    assert!(c.decode_slice(&bytes[..10]).unwrap().is_none());
    let m = c.decode_slice(&bytes[10..]).unwrap().unwrap();
    assert!(matches!(m, BgpMessage::Keepalive(_)));
}

#[test]
fn bad_marker_returns_error() {
    let mut c = BgpCodec::new();
    let bad = vec![0u8; 19];
    let res = c.decode_slice(&bad);
    assert!(res.is_err());
}

/// Regression: an IPv4 prefix length above 32 bits is invalid (RFC 4271
/// §4.3) and must be rejected — never panic on the fixed-size address
/// buffer (a crafted UPDATE used to crash the process).
#[test]
fn legacy_nlri_rejects_prefix_length_above_32() {
    // Hand-build an UPDATE: withdrawn(0) + attrs(0) + NLRI with plen=255
    // followed by 32 address octets. The old decoder indexed a [u8; 4]
    // buffer with n = ceil(255/8) = 32 → panic.
    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // withdrawn len
    body.extend_from_slice(&0u16.to_be_bytes()); // path attrs len
    body.push(255); // invalid prefix length
    body.extend_from_slice(&[0xab; 32]);

    let mut frame = vec![0xffu8; 16];
    let len = 19 + body.len();
    frame.extend_from_slice(&(len as u16).to_be_bytes());
    frame.push(2); // UPDATE
    frame.extend_from_slice(&body);

    let mut c = BgpCodec::new();
    let res = c.decode_slice(&frame);
    assert!(res.is_err(), "invalid prefix length must error, not panic");
}

/// Regression: when a feed completes a frame started by an earlier feed
/// and contains more complete frames, every complete frame must decode
/// exactly once. The old decoder re-appended the source tail to the
/// carryover and decoded phantom messages.
#[test]
fn streaming_decoder_splits_feed_without_duplication() {
    let codec = BgpCodec::new();
    let msg = BgpMessage::Keepalive(Keepalive);
    let bytes = codec.encode_vec(&msg).unwrap();
    // Three complete frames back to back.
    let mut three = bytes.clone();
    three.extend_from_slice(&bytes);
    three.extend_from_slice(&bytes);

    let mut c = BgpCodec::new();
    // Feed a partial prefix of the first frame.
    assert!(c.decode_slice(&three[..10]).unwrap().is_none());
    // Feed the rest: completes frame 1 and contains frames 2 and 3.
    let mut decoded = Vec::new();
    let mut remaining = &three[10..];
    while let Some(m) = c.decode_slice(remaining).unwrap() {
        decoded.push(m);
        remaining = &[];
    }
    assert_eq!(decoded.len(), 3, "three frames must decode, not more");
    for m in &decoded {
        assert!(matches!(m, BgpMessage::Keepalive(_)));
    }
}
