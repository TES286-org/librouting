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

/// RFC 7911 §4.3: an Add-Path entry is `<path-id:4, prefix-len:1,
/// prefix>`. An NLRI section that ends with the 4-octet path-id (no
/// prefix-length byte after it) is truncated and must be rejected —
/// the decoder may never index one byte past the buffer.
#[test]
fn legacy_nlri_rejects_trailing_add_path_path_id() {
    assert!(
        decode_nlri_set(&[0, 0, 0, 1], true).is_err(),
        "path-id without a following prefix-length byte must be rejected"
    );
    // The same section with the length byte and prefix decodes.
    let ok = decode_nlri_set(&[0, 0, 0, 1, 24, 203, 0, 113], true).unwrap();
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].path_id, 1);
    assert_eq!(ok[0].prefix, Prefix::new_v4([203, 0, 113, 0], 24));
    // The trailing shape can also appear after a well-formed entry.
    assert!(
        decode_nlri_set(&[24, 203, 0, 113, 0, 0, 0, 2], true).is_err(),
        "a second entry reduced to a bare path-id must be rejected"
    );
    // Without Add-Path the guard is inert — a well-formed section
    // decodes exactly as before the fix.
    let plain = decode_nlri_set(&[24, 203, 0, 113], false).unwrap();
    assert_eq!(plain.len(), 1);
    assert_eq!(plain[0].prefix, Prefix::new_v4([203, 0, 113, 0], 24));
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

/// RFC 9072 §2: when the Optional Parameters field exceeds 255
/// octets the OPEN switches to the extended encoding — Non-Ext OP Len
/// 255, Non-Ext OP Type 255, a two-octet Optional Parameters Length,
/// and a two-octet length for every parameter. Both sides must
/// round-trip the parameters unchanged.
#[test]
fn open_extended_optional_parameters_roundtrip() {
    let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 1]));
    open.params.push(OpenParam {
        param_type: OpenParam::PARAM_TYPE_CAPABILITY,
        value: vec![0xaa; 300],
    });
    open.params.push(OpenParam {
        param_type: OpenParam::PARAM_TYPE_CAPABILITY,
        value: vec![0xbb; 100],
    });
    let msg = BgpMessage::Open(open.clone());
    let bytes = BgpCodec::new().encode_vec(&msg).unwrap();
    let body = &bytes[19..];
    assert_eq!(body[9], 255, "Non-Ext OP Len");
    assert_eq!(
        body[10],
        OpenParam::PARAM_TYPE_EXTENDED_LENGTH,
        "Non-Ext OP Type"
    );
    // Extended parameters carry 3 octets of overhead each: one type
    // and a two-octet length.
    assert_eq!(
        u16::from_be_bytes([body[11], body[12]]) as usize,
        3 + 300 + 3 + 100
    );
    assert_eq!(
        &body[13..16],
        &[OpenParam::PARAM_TYPE_CAPABILITY, 0x01, 0x2c]
    );

    match roundtrip(msg, false) {
        BgpMessage::Open(o) => assert_eq!(o.params, open.params),
        other => panic!("expected OPEN, got {other:?}"),
    }
}

/// RFC 9072 §2: the base encoding stays in use while the parameters
/// fit in 255 octets, even when the one-octet length field itself is
/// 255. The decoder must key on the type code, not on the length.
#[test]
fn open_uses_base_encoding_at_the_255_octet_boundary() {
    let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 1]));
    open.params.push(OpenParam {
        param_type: OpenParam::PARAM_TYPE_CAPABILITY,
        value: vec![0xaa; 253],
    });
    let msg = BgpMessage::Open(open.clone());
    let bytes = BgpCodec::new().encode_vec(&msg).unwrap();
    let body = &bytes[19..];
    assert_eq!(body[9], 255, "base encoding fits exactly");
    assert_eq!(
        body[10],
        OpenParam::PARAM_TYPE_CAPABILITY,
        "first parameter type, not the extended marker"
    );
    match roundtrip(msg, false) {
        BgpMessage::Open(o) => assert_eq!(o.params, open.params),
        other => panic!("expected OPEN, got {other:?}"),
    }
}

/// RFC 9072 §2: a receiver MUST accept the extended format even when
/// the parameters would fit in the base format. Hand-build a short
/// extended OPEN and decode it.
#[test]
fn open_decodes_extended_encoding_below_255_octets() {
    let body = [
        4, // version
        0xfc, 0x00, // my AS 64512
        0x00, 90, // hold time
        10, 0, 0, 1,   // BGP identifier
        255, // Non-Ext OP Len (ignored)
        255, // Non-Ext OP Type: extended
        0, 5, // Extended Optional Parameters Length
        2, 0, 2, 0xaa, 0xbb, // one capability parameter
    ];
    let mut frame = vec![0xffu8; 16];
    frame.extend_from_slice(&(19 + body.len() as u16).to_be_bytes());
    frame.push(crate::message::BgpMessageType::Open as u8);
    frame.extend_from_slice(&body);

    let mut codec = BgpCodec::new();
    match codec.decode_slice(&frame).unwrap().unwrap() {
        BgpMessage::Open(o) => {
            assert_eq!(o.params.len(), 1);
            assert_eq!(o.params[0].param_type, OpenParam::PARAM_TYPE_CAPABILITY);
            assert_eq!(o.params[0].value, vec![0xaa, 0xbb]);
        }
        other => panic!("expected OPEN, got {other:?}"),
    }
}

/// A declared extended parameter region that runs past the message is
/// a Bad OPEN Length error, not a silent truncation.
#[test]
fn open_rejects_truncated_extended_parameters() {
    let body = [
        4, 0xfc, 0x00, 0x00, 90, 10, 0, 0, 1, //
        255, 255, 0, 5, // extended length 5
        2, 0, 2, 0xaa, // only four parameter bytes follow
    ];
    let mut frame = vec![0xffu8; 16];
    frame.extend_from_slice(&(19 + body.len() as u16).to_be_bytes());
    frame.push(crate::message::BgpMessageType::Open as u8);
    frame.extend_from_slice(&body);

    let err = BgpCodec::new().decode_slice(&frame).unwrap_err();
    match err {
        BgpError::Notification(n) => {
            assert_eq!(n.error_code, crate::error::BgpErrorCode::Open as u8);
            assert_eq!(
                n.error_subcode,
                crate::error::BgpOpenErrorSubcode::BadOpenLength as u8
            );
        }
        other => panic!("expected a NOTIFICATION, got {other:?}"),
    }
}

/// A parameter whose extended length overruns the declared region is a
/// Bad OPEN Length error.
#[test]
fn open_rejects_extended_parameter_overrunning_the_region() {
    let body = [
        4, 0xfc, 0x00, 0x00, 90, 10, 0, 0, 1, //
        255, 255, 0, 4, // extended length 4
        2, 0, 5, 0xaa, // parameter claims 5 bytes, only 1 present
    ];
    let mut frame = vec![0xffu8; 16];
    frame.extend_from_slice(&(19 + body.len() as u16).to_be_bytes());
    frame.push(crate::message::BgpMessageType::Open as u8);
    frame.extend_from_slice(&body);

    let err = BgpCodec::new().decode_slice(&frame).unwrap_err();
    assert!(
        matches!(err, BgpError::Notification(_)),
        "expected a NOTIFICATION, got {err:?}"
    );
}

/// The encoder refuses a parameter value that cannot fit the
/// two-octet extended length field instead of truncating it.
#[test]
fn open_rejects_parameter_value_above_65535_octets() {
    let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 1]));
    open.params.push(OpenParam {
        param_type: OpenParam::PARAM_TYPE_CAPABILITY,
        value: vec![0u8; 65536],
    });
    let err = BgpCodec::new()
        .encode_vec(&BgpMessage::Open(open))
        .unwrap_err();
    assert!(
        matches!(err, EncodeError::InvalidValue(_)),
        "expected InvalidValue, got {err:?}"
    );
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

/// RFC 4271 §4.5: the Data field rides the NOTIFICATION body verbatim
/// — the PATHS-LIMIT Cease (draft-ietf-idr-addpath-paths-limit-00 §4
/// Figure 2) is the carrier this pins.
#[test]
fn notification_roundtrip_with_data() {
    let n = BgpNotification::new(6, 64, vec![0x00, 0x01, 0x01, 0x00, 0x10]);
    let m = BgpMessage::Notification(n);
    let dec = roundtrip(m, false);
    match dec {
        BgpMessage::Notification(d) => {
            assert_eq!(d.error_code, 6);
            assert_eq!(d.error_subcode, 64);
            assert_eq!(
                d.data,
                vec![0x00, 0x01, 0x01, 0x00, 0x10],
                "the Figure 2 Data field (AFI=1, SAFI=1, limit=16) survives the wire"
            );
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
        let decoded = roundtrip(BgpMessage::RouteRefresh(refresh.clone()), false);
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

/// RFC 5291 §4 / RFC 5292 §3: an ORF ROUTE-REFRESH round-trips every
/// Address Prefix entry action and the Minlen/Maxlen fields, for both
/// address families.
#[test]
fn orf_route_refresh_roundtrip() {
    use crate::message::route_refresh::{
        AddressPrefixOrf, OrfAction, OrfEntry, OrfList, OrfRefresh, OrfWhenToRefresh,
    };
    use lr_core::addr::Prefix;

    let v4 = AddressPrefixOrf {
        sequence: 10,
        action: OrfAction::Add,
        permit: true,
        prefix: Prefix::new_v4([192, 0, 2, 0], 24),
        min_len: 24,
        max_len: 28,
    };
    let deny = AddressPrefixOrf {
        sequence: 20,
        action: OrfAction::Add,
        permit: false,
        prefix: Prefix::new_v4([198, 51, 100, 0], 24),
        min_len: 0,
        max_len: 0,
    };
    let remove = AddressPrefixOrf {
        sequence: 30,
        action: OrfAction::Remove,
        permit: true,
        prefix: Prefix::new_v4([203, 0, 113, 0], 24),
        min_len: 0,
        max_len: 0,
    };
    let v6 = AddressPrefixOrf {
        sequence: 40,
        action: OrfAction::Add,
        permit: true,
        prefix: Prefix::new_v6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            48,
        ),
        min_len: 0,
        max_len: 64,
    };

    for (family, entries) in [
        (
            NlriFamily::IPV4_UNICAST,
            vec![
                OrfEntry::AddressPrefix(v4),
                OrfEntry::AddressPrefix(deny),
                OrfEntry::AddressPrefix(remove),
                OrfEntry::RemoveAll,
            ],
        ),
        (NlriFamily::IPV6_UNICAST, vec![OrfEntry::AddressPrefix(v6)]),
    ] {
        let refresh = RouteRefresh {
            family,
            subtype: crate::message::RouteRefreshSubtype::Normal,
            orf: Some(OrfRefresh {
                when: OrfWhenToRefresh::Immediate,
                lists: vec![OrfList {
                    orf_type: OrfList::ADDRESS_PREFIX,
                    entries,
                }],
            }),
        };
        let decoded = roundtrip(BgpMessage::RouteRefresh(refresh.clone()), false);
        assert_eq!(decoded, BgpMessage::RouteRefresh(refresh));
    }
}

/// RFC 5291 §4: an ORF type this implementation does not understand is
/// preserved as one raw block so it can be ignored without guessing at
/// its entry layout.
#[test]
fn orf_unknown_type_is_preserved_raw() {
    use crate::message::route_refresh::{OrfEntry, OrfList, OrfRefresh, OrfWhenToRefresh};
    let refresh = RouteRefresh {
        family: NlriFamily::IPV4_UNICAST,
        subtype: crate::message::RouteRefreshSubtype::Normal,
        orf: Some(OrfRefresh {
            when: OrfWhenToRefresh::Defer,
            lists: vec![OrfList {
                orf_type: 65,
                entries: vec![OrfEntry::Raw(vec![0xde, 0xad, 0xbe, 0xef])],
            }],
        }),
    };
    let decoded = roundtrip(BgpMessage::RouteRefresh(refresh.clone()), false);
    assert_eq!(decoded, BgpMessage::RouteRefresh(refresh));
}

/// A truncated ORF block is an invalid message length (RFC 7313 §5
/// subcode 1), not a silently ignored refresh.
#[test]
fn orf_route_refresh_rejects_truncated_block() {
    // AFI 1, reserved, SAFI 1, when=Immediate, type 64, length 8, only
    // two entry bytes.
    let err = decode_route_refresh(&[0, 1, 0, 1, 1, 64, 0, 8, 0, 0]).unwrap_err();
    match err {
        BgpError::Notification(n) => {
            assert_eq!(n.error_code, crate::error::BgpErrorCode::RouteRefresh as u8);
            assert_eq!(n.error_subcode, 1);
        }
        other => panic!("expected a NOTIFICATION, got {other:?}"),
    }
}

/// The When-to-refresh field only accepts IMMEDIATE (1) and DEFER (2).
#[test]
fn orf_route_refresh_rejects_unknown_when_to_refresh() {
    assert!(decode_route_refresh(&[0, 1, 0, 1, 3, 64, 0, 1, 0]).is_err());
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

/// Regression: an IPv6 prefix placed in the legacy IPv4 NLRI section of
/// an UPDATE must be rejected by the encoder with `EncodeError::InvalidValue`
/// — never panic via `unreachable!()`. RFC 4271 §4.3 reserves the
/// top-level NLRI list for IPv4; IPv6 NLRI must travel inside
/// `MP_REACH_NLRI` / `MP_UNREACH_NLRI` (RFC 4760 §3).
///
/// The legacy `encode_nlri` had a `_ => unreachable!()` arm in its
/// `match p.addr` block. The guard at function entry already returned
/// `InvalidValue` for `!p.is_ipv4()`, but the `unreachable!()` arm was
/// a `panic!` landmine if a future refactor dropped the guard. The
/// `IpAddr::V6(_)` arm now returns `InvalidValue` so the encoder is
/// panic-free on the data path regardless of the guard.
#[test]
fn encode_nlri_rejects_ipv6_prefix_without_panicking() {
    let mut u = Update::new();
    // Push an IPv6 prefix into the legacy NLRI section. This is
    // malformed by construction (RFC 4271 §4.3 / RFC 4760 §3) but
    // the encoder must surface it as `InvalidValue`, not as a panic.
    u.nlri.push(Nlri::new(
        0,
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            128,
        ),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        Vec::new(),
    ));
    let codec = BgpCodec::new();
    let res = codec.encode_vec(&BgpMessage::Update(u));
    let err = res.expect_err(
        "IPv6 NLRI in the legacy section must fail encoding with InvalidValue, not succeed",
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("NLRI in legacy section must be IPv4")
            || msg.contains("InvalidValue")
            || msg.contains("invalid value"),
        "expected an InvalidValue error, got: {msg}"
    );
}

// ===== RFC 8654 Extended Message support =====

/// A codec with Extended Message negotiated accepts messages up to
/// 65535 octets. A codec without it rejects anything above the RFC
/// 4271 §4.1 4096-octet ceiling.
#[test]
fn extended_message_raises_and_lowers_the_length_ceiling() {
    let mut codec = BgpCodec::new();
    assert!(!codec.extended_message_active());

    // Default ceiling: 4096. Build a header that claims a length of
    // 5000 — the default codec must refuse it.
    let mut big = vec![0xff; 16];
    big.extend_from_slice(&5000u16.to_be_bytes());
    big.push(2); // UPDATE
    big.resize(5000, 0);
    let err = codec.decode_slice(&big).unwrap_err();
    assert!(
        matches!(err, crate::error::BgpError::Notification(_)),
        "expected a BadMessageLength NOTIFICATION, got {err:?}"
    );

    // With Extended Message negotiated, the same frame is accepted
    // (the body parses as an empty UPDATE).
    codec.set_extended_message(true);
    assert!(codec.extended_message_active());
    let msg = codec.decode_slice(&big).unwrap().unwrap();
    assert!(
        matches!(msg, crate::message::BgpMessage::Update(_)),
        "expected an UPDATE, got {msg:?}"
    );
}

/// RFC 8654 §4: Extended Message applies to every message except
/// OPEN and KEEPALIVE, which keep the RFC 4271 §4.1 4096-octet
/// ceiling even after negotiation. RFC 9072 extends the optional
/// parameter length fields, not the OPEN message size.
#[test]
fn extended_message_does_not_raise_open_or_keepalive_ceiling() {
    let mut codec = BgpCodec::new();
    codec.set_extended_message(true);

    for kind in [
        crate::message::BgpMessageType::Open as u8,
        crate::message::BgpMessageType::Keepalive as u8,
    ] {
        let mut big = vec![0xffu8; 16];
        big.extend_from_slice(&5000u16.to_be_bytes());
        big.push(kind);
        big.resize(5000, 0);
        let err = codec.decode_slice(&big).unwrap_err();
        assert!(
            matches!(err, BgpError::Notification(_)),
            "message type {kind} must keep the 4096-octet ceiling"
        );
    }

    // An OPEN whose extended parameters push the frame past 4096 is
    // refused by the encoder, even with the negotiated ceiling.
    let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 1]));
    open.params.push(OpenParam {
        param_type: OpenParam::PARAM_TYPE_CAPABILITY,
        value: vec![0u8; 4096],
    });
    let err = codec.encode_vec(&BgpMessage::Open(open)).unwrap_err();
    assert!(
        matches!(err, EncodeError::InvalidValue(_)),
        "expected InvalidValue, got {err:?}"
    );
}

/// The encoder allocates for the negotiated ceiling so an
/// Extended-Message-sized UPDATE does not overflow the encode
/// buffer. The encode result is byte-for-byte the same as a
/// default-codec encode for any message that fits in 4096 octets.
#[test]
fn extended_message_encoder_allocates_for_the_negotiated_ceiling() {
    let msg = BgpMessage::Keepalive(crate::message::keepalive::Keepalive);
    let default_codec = BgpCodec::new();
    let ext_codec = {
        let mut c = BgpCodec::new();
        c.set_extended_message(true);
        c
    };
    let default_bytes = default_codec.encode_vec(&msg).unwrap();
    let ext_bytes = ext_codec.encode_vec(&msg).unwrap();
    // A KEEPALIVE is 19 octets regardless of the ceiling; the encode
    // output is byte-identical.
    assert_eq!(default_bytes, ext_bytes);
    assert_eq!(ext_bytes.len(), 19);
}
