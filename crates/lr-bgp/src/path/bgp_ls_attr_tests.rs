//! Tests for the BGP-LS Attribute TLV codec (RFC 7752 §3.3 +
//! RFC 9514 §7-§8).
//!
//! The vectors are derived from the RFC text directly — each test
//! pins the wire bytes for one TLV variant and asserts the codec
//! round-trips byte-for-byte. The "wrong length" tests verify the
//! fall-through to [`BgpLsAttrTlv::Unknown`] so a malformed well-known
//! TLV is preserved verbatim rather than silently dropping bytes.

use super::*;
use crate::path::AttrType;

/// Helper: encode `t` into a fresh `Vec<u8>` and return the bytes.
fn encode_tlv(t: &BgpLsAttrTlv) -> Vec<u8> {
    let mut v = vec![0u8; t.wire_len()];
    let mut w = WriteBuf::new(&mut v);
    let n = t.encode(&mut w).expect("encode");
    v.truncate(n);
    v
}

/// Helper: decode a single TLV from `b`, panicking on truncation.
fn decode_tlv(b: &[u8]) -> BgpLsAttrTlv {
    let mut r = ReadBuf::new(b);
    let t = Tlv::decode(&mut r).expect("decode TLV");
    BgpLsAttrTlv::decode(t)
}

#[test]
fn attr_type_29_is_bgp_ls_attribute() {
    // RFC 7752 §13: IANA has assigned value 29 (BGP-LS Attribute) in
    // the "BGP Path Attributes" sub-registry.
    assert_eq!(AttrType::BgpLsAttribute.to_u8(), 29);
    assert_eq!(AttrType::from_u8(29), AttrType::BgpLsAttribute);
}

#[test]
fn srv6_endpoint_behavior_round_trip() {
    // RFC 9514 §7.1: type 1250, length 4, value =
    // 2-byte endpoint behavior + 1-byte flags + 1-byte algorithm.
    let t = BgpLsAttrTlv::Srv6EndpointBehavior {
        behavior: Srv6EndpointBehavior::EndX,
        flags: 0,
        algorithm: 0,
    };
    assert_eq!(t.ty(), 1250);
    assert_eq!(t.value_len(), 4);
    let wire = encode_tlv(&t);
    // TLV header (4) + value (4) = 8 bytes total.
    assert_eq!(wire.len(), 8);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1250);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 4);
    // Endpoint Behavior = End.X = 5.
    assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), 5);
    // Flags = 0, Algorithm = 0.
    assert_eq!(wire[6], 0);
    assert_eq!(wire[7], 0);
    let decoded = decode_tlv(&wire);
    assert_eq!(decoded, t);
}

#[test]
fn srv6_endpoint_behavior_unknown_value_preserved() {
    // An unknown SRv6 Endpoint Behavior code point (e.g. 9999) is
    // preserved verbatim through the Unknown variant of
    // Srv6EndpointBehavior.
    let t = BgpLsAttrTlv::Srv6EndpointBehavior {
        behavior: Srv6EndpointBehavior::Unknown(9999),
        flags: 0x12,
        algorithm: 0x34,
    };
    let wire = encode_tlv(&t);
    assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), 9999);
    assert_eq!(wire[6], 0x12);
    assert_eq!(wire[7], 0x34);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn srv6_sid_structure_round_trip() {
    // RFC 9514 §8: type 1252, length 4, value =
    // 1-byte LB Length + 1-byte LN Length + 1-byte Fun. Length + 1-byte
    // Arg. Length.
    let s = Srv6SidStructure {
        locator_block_len: 32,
        locator_node_len: 16,
        function_len: 16,
        argument_len: 0,
    };
    assert!(s.is_valid());
    let t = BgpLsAttrTlv::Srv6SidStructure(s);
    assert_eq!(t.ty(), 1252);
    assert_eq!(t.value_len(), 4);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 8);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1252);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 4);
    assert_eq!(wire[4], 32);
    assert_eq!(wire[5], 16);
    assert_eq!(wire[6], 16);
    assert_eq!(wire[7], 0);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn srv6_sid_structure_overflow_rejected() {
    // RFC 9514 §8: sum of lengths MUST be <= 128. A structure that
    // overflows the 128-bit SID space is malformed — the codec
    // preserves it as Unknown so the stream still round-trips.
    let raw = Tlv {
        ty: tlv_type::SRV6_SID_STRUCTURE,
        value: vec![64, 64, 64, 64], // sum = 256 > 128
    };
    let decoded = BgpLsAttrTlv::decode(raw.clone());
    assert_eq!(decoded, BgpLsAttrTlv::Unknown(raw));
}

#[test]
fn srv6_bgp_peer_node_sid_round_trip() {
    // RFC 9514 §7.2: type 1251, length 12, value =
    // 1-byte flags + 1-byte weight + 2-byte reserved + 4-byte peer AS
    // + 4-byte peer BGP identifier.
    let t = BgpLsAttrTlv::Srv6BgpPeerNodeSid {
        flags: 0x05, // B + S flags set
        weight: 7,
        peer_as: 64512,
        peer_bgp_id: 0x0102_0304,
    };
    assert_eq!(t.ty(), 1251);
    assert_eq!(t.value_len(), 12);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 16);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1251);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 12);
    assert_eq!(wire[4], 0x05);
    assert_eq!(wire[5], 7);
    // reserved = 0
    assert_eq!(u16::from_be_bytes([wire[6], wire[7]]), 0);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        64512
    );
    assert_eq!(
        u32::from_be_bytes([wire[12], wire[13], wire[14], wire[15]]),
        0x0102_0304
    );
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn srv6_capabilities_round_trip() {
    // RFC 9514 §3.1: type 1038, length 4, value =
    // 2-byte flags + 2-byte reserved.
    let t = BgpLsAttrTlv::Srv6Capabilities {
        flags: 0x0001,
        reserved: 0,
    };
    assert_eq!(t.ty(), 1038);
    assert_eq!(t.value_len(), 4);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 8);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1038);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 4);
    assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), 0x0001);
    assert_eq!(u16::from_be_bytes([wire[6], wire[7]]), 0);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn srv6_locator_round_trip() {
    // RFC 9514 §5.1: type 1162, length variable, value =
    // 1-byte flags + 1-byte algorithm + 2-byte reserved + 4-byte metric
    // + sub-TLVs.
    let t = BgpLsAttrTlv::Srv6Locator {
        flags: 0,
        algorithm: 0,
        metric: 100,
        sub_tlvs: vec![],
    };
    assert_eq!(t.ty(), 1162);
    assert_eq!(t.value_len(), 8);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 12);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1162);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 8);
    assert_eq!(wire[4], 0); // flags
    assert_eq!(wire[5], 0); // algorithm
    assert_eq!(u16::from_be_bytes([wire[6], wire[7]]), 0); // reserved
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        100
    );
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn srv6_end_x_sid_round_trip() {
    // RFC 9514 §4.1: type 1106, length variable, value =
    // 2-byte endpoint behavior + 1-byte flags + 1-byte algorithm +
    // 1-byte weight + 1-byte reserved + 16-byte SID + sub-TLVs.
    let sid = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
        0x90,
    ];
    let t = BgpLsAttrTlv::Srv6EndXSid {
        endpoint_behavior: 5, // End.X
        flags: 0,
        algorithm: 0,
        weight: 0,
        sid,
        sub_tlvs: vec![],
    };
    assert_eq!(t.ty(), 1106);
    assert_eq!(t.value_len(), 22);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 26);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1106);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 22);
    assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), 5);
    assert_eq!(wire[6], 0); // flags
    assert_eq!(wire[7], 0); // algorithm
    assert_eq!(wire[8], 0); // weight
    assert_eq!(wire[9], 0); // reserved
    assert_eq!(&wire[10..26], &sid);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn srv6_end_x_sid_with_subtlvs_round_trip() {
    // The End.X SID TLV carries optional sub-TLVs after the 16-byte
    // SID (e.g. an SRv6 SID Structure sub-TLV, type 1252).
    let sid = [0xffu8; 16];
    let structure = BgpLsAttrTlv::Srv6SidStructure(Srv6SidStructure {
        locator_block_len: 32,
        locator_node_len: 16,
        function_len: 16,
        argument_len: 0,
    });
    let mut sub = vec![0u8; structure.wire_len()];
    let mut w = WriteBuf::new(&mut sub);
    let n = structure.encode(&mut w).expect("encode sub-tlv");
    sub.truncate(n);

    let t = BgpLsAttrTlv::Srv6EndXSid {
        endpoint_behavior: 5,
        flags: 0,
        algorithm: 0,
        weight: 0,
        sid,
        sub_tlvs: sub.clone(),
    };
    let wire = encode_tlv(&t);
    let decoded = decode_tlv(&wire);
    assert_eq!(decoded, t);
    // The sub-TLV bytes inside the End.X SID TLV round-trip
    // verbatim — the codec does not interpret them (a follow-up
    // that walks the sub-TLV stream lives in the projection layer).
}

#[test]
fn srv6_lan_end_x_sid_isis_round_trip() {
    // RFC 9514 §4.2: type 1107 (IS-IS), value =
    // 2 + 1 + 1 + 1 + 1 (reserved) + 6 (IS-IS neighbor System-ID) + 16
    // + sub-TLVs.
    let neighbor_id = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let sid = [0xaau8; 16];
    let t = BgpLsAttrTlv::Srv6LanEndXSid {
        is_isis: true,
        endpoint_behavior: 5,
        flags: 0,
        algorithm: 0,
        weight: 0,
        neighbor_id: neighbor_id.clone(),
        sid,
        sub_tlvs: vec![],
    };
    assert_eq!(t.ty(), 1107);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 4 + 28);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1107);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 28);
    // value layout: 2B endpoint behavior + 1B flags + 1B algorithm
    // + 1B weight + 1B reserved + 6B IS-IS neighbor System-ID +
    // 16B SID = 28 bytes.
    assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), 5);
    assert_eq!(wire[6], 0); // flags
    assert_eq!(wire[7], 0); // algorithm
    assert_eq!(wire[8], 0); // weight
    assert_eq!(wire[9], 0); // reserved
    assert_eq!(&wire[10..16], &neighbor_id[..]);
    assert_eq!(&wire[16..32], &sid);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn srv6_lan_end_x_sid_ospfv3_round_trip() {
    // RFC 9514 §4.2: type 1108 (OSPFv3), value =
    // 2 + 1 + 1 + 1 + 1 (reserved) + 4 (OSPFv3 Router-ID) + 16 + sub-TLVs.
    let neighbor_id = vec![0xc0, 0xa8, 0x01, 0x01];
    let sid = [0xbbu8; 16];
    let t = BgpLsAttrTlv::Srv6LanEndXSid {
        is_isis: false,
        endpoint_behavior: 5,
        flags: 0,
        algorithm: 0,
        weight: 0,
        neighbor_id: neighbor_id.clone(),
        sid,
        sub_tlvs: vec![],
    };
    assert_eq!(t.ty(), 1108);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 4 + 26);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1108);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 26);
    // value layout: 2B endpoint behavior + 1B flags + 1B algorithm
    // + 1B weight + 1B reserved + 4B OSPFv3 Router-ID + 16B SID =
    // 26 bytes.
    assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), 5);
    assert_eq!(wire[6], 0); // flags
    assert_eq!(wire[7], 0); // algorithm
    assert_eq!(wire[8], 0); // weight
    assert_eq!(wire[9], 0); // reserved
    assert_eq!(&wire[10..14], &neighbor_id[..]);
    assert_eq!(&wire[14..30], &sid);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn node_flag_bits_round_trip() {
    // RFC 7752 §3.3.1.1: type 1024, length 1.
    let t = BgpLsAttrTlv::NodeFlagBits(0x07);
    assert_eq!(t.ty(), 1024);
    assert_eq!(t.value_len(), 1);
    let wire = encode_tlv(&t);
    assert_eq!(wire, vec![0x04, 0x00, 0x00, 0x01, 0x07]);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn node_name_round_trip() {
    // RFC 7752 §3.3.1.3: type 1026, variable-length value (UTF-8
    // symbolic name).
    let name = b"lr-router-1".to_vec();
    let t = BgpLsAttrTlv::NodeName(name.clone());
    assert_eq!(t.ty(), 1026);
    let wire = encode_tlv(&t);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1026);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), name.len() as u16);
    assert_eq!(&wire[4..], &name[..]);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn ipv4_router_id_local_round_trip() {
    // RFC 5305 §4.3 via RFC 7752 §3.3.1.4: type 1028, length 4.
    let t = BgpLsAttrTlv::Ipv4RouterIdLocal([192, 0, 2, 1]);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 8);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1028);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 4);
    assert_eq!(&wire[4..8], &[192, 0, 2, 1]);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn ipv6_router_id_local_round_trip() {
    // RFC 6119 §4.1 via RFC 7752 §3.3.1.4: type 1029, length 16.
    let addr = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let t = BgpLsAttrTlv::Ipv6RouterIdLocal(addr);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 20);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1029);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 16);
    assert_eq!(&wire[4..20], &addr);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn admin_group_round_trip() {
    // RFC 7752 §3.3.2.1: type 1088, length 4 (color / admin group).
    let t = BgpLsAttrTlv::AdminGroup(0x0000_0001);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 8);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1088);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 4);
    assert_eq!(
        u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]),
        0x0000_0001
    );
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn te_default_metric_round_trip() {
    // RFC 7752 §3.3.2.3: type 1092, length 4.
    let t = BgpLsAttrTlv::TeDefaultMetric(0x0000_2710);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 8);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1092);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 4);
    assert_eq!(
        u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]),
        0x0000_2710
    );
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn unreserved_bandwidth_round_trip() {
    // RFC 7752 §3.3.2.2: type 1091, length 32 (8 × 4-byte IEEE floats).
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let t = BgpLsAttrTlv::UnreservedBandwidth(bytes);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 36);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1091);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 32);
    assert_eq!(&wire[4..36], &bytes);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn igp_metric_round_trip() {
    // RFC 7855 §2.1: type 1114, length 1-3 (1 for OSPF default metric).
    let t = BgpLsAttrTlv::IgpMetric(vec![42]);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 5);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1114);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 1);
    assert_eq!(wire[4], 42);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn prefix_metric_round_trip() {
    // RFC 7752 §3.3.3.3: type 1152, length 4.
    let t = BgpLsAttrTlv::PrefixMetric(0x0000_1388);
    let wire = encode_tlv(&t);
    assert_eq!(wire.len(), 8);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1152);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 4);
    assert_eq!(
        u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]),
        0x0000_1388
    );
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn prefix_attribute_flags_round_trip() {
    // RFC 7752 §3.3.3.6: type 1155, length 1.
    let t = BgpLsAttrTlv::PrefixAttributeFlags(0x01);
    let wire = encode_tlv(&t);
    assert_eq!(wire, vec![0x04, 0x83, 0x00, 0x01, 0x01]);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn unknown_tlv_preserved_verbatim() {
    // A TLV whose type the codec does not model is preserved verbatim
    // — a re-encode round-trips byte-for-byte, matching the contract
    // the NLRI codec enforces in `bgp_ls_tests.rs`.
    let raw = Tlv {
        ty: 0x6789,
        value: vec![0xde, 0xad, 0xbe, 0xef],
    };
    let t = BgpLsAttrTlv::Unknown(raw.clone());
    let wire = encode_tlv(&t);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 0x6789);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 4);
    assert_eq!(&wire[4..], &raw.value);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn well_known_tlv_wrong_length_falls_through_to_unknown() {
    // A well-known TLV with the wrong length is preserved verbatim
    // (rather than silently dropping bytes) — the codec returns the
    // `Unknown` variant so a re-encode round-trips. RFC 9514 §7.1
    // fixes the length of the SRv6 Endpoint Behavior TLV at 4; a TLV
    // 1250 with any other length is malformed.
    let raw = Tlv {
        ty: tlv_type::SRV6_ENDPOINT_BEHAVIOR,
        value: vec![0, 5, 0, 0, 0], // length 5 — too long
    };
    let decoded = BgpLsAttrTlv::decode(raw.clone());
    assert_eq!(decoded, BgpLsAttrTlv::Unknown(raw));
}

#[test]
fn attribute_value_round_trip() {
    // A BGP-LS Attribute value is a concatenation of TLVs. The
    // codec parses the stream into a `Vec<BgpLsAttrTlv>` and the
    // encoder produces the same bytes back.
    let attr = BgpLsAttr::new(vec![
        BgpLsAttrTlv::NodeFlagBits(0x07),
        BgpLsAttrTlv::NodeName(b"lr-router-1".to_vec()),
        BgpLsAttrTlv::Srv6EndpointBehavior {
            behavior: Srv6EndpointBehavior::End,
            flags: 0,
            algorithm: 0,
        },
        BgpLsAttrTlv::Srv6SidStructure(Srv6SidStructure {
            locator_block_len: 32,
            locator_node_len: 16,
            function_len: 16,
            argument_len: 0,
        }),
    ]);
    let bytes = attr.encode().expect("encode");
    let decoded = BgpLsAttr::decode(&bytes).expect("decode");
    assert_eq!(decoded, attr);
}

#[test]
fn attribute_empty_round_trip() {
    // An empty BGP-LS Attribute is a valid zero-length value.
    let attr = BgpLsAttr::default();
    assert!(attr.is_empty());
    let bytes = attr.encode().expect("encode");
    assert!(bytes.is_empty());
    let decoded = BgpLsAttr::decode(&bytes).expect("decode");
    assert_eq!(decoded, attr);
}

#[test]
fn attribute_truncated_tlv_rejected() {
    // A truncated TLV header (< 4 bytes) is rejected on decode.
    let err = BgpLsAttr::decode(&[0x04, 0x00, 0x00]).expect_err("reject");
    // ParseError::truncated sets ErrorKind::Truncated at offset 0
    // with the supplied context label.
    assert_eq!(err.kind, lr_core::error::ErrorKind::Truncated);
}

#[test]
fn attribute_find_and_iter_ty() {
    // Helper: find the first TLV of a given type, and iterate over
    // every TLV of a given type. RFC 7752 §3.3 permits multiple
    // instances of some TLVs (IS-IS Area Identifier, SRv6 End.X
    // SID).
    let attr = BgpLsAttr::new(vec![
        BgpLsAttrTlv::NodeFlagBits(0x01),
        BgpLsAttrTlv::IsisAreaIdentifier(vec![0x49, 0x00, 0x01]),
        BgpLsAttrTlv::IsisAreaIdentifier(vec![0x49, 0x00, 0x02]),
    ]);
    assert_eq!(
        attr.find(tlv_type::NODE_FLAG_BITS),
        Some(&BgpLsAttrTlv::NodeFlagBits(0x01))
    );
    let area_ids: Vec<_> = attr
        .iter_ty(tlv_type::ISIS_AREA_IDENTIFIER)
        .map(|t| match t {
            BgpLsAttrTlv::IsisAreaIdentifier(v) => v.as_slice(),
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(area_ids, [&[0x49, 0x00, 0x01][..], &[0x49, 0x00, 0x02][..]]);
}

#[test]
fn endpoint_behavior_iana_code_points() {
    // RFC 8986 §10.2 IANA registry: 1=End, 5=End.X, 9=End.T, 13=End.B,
    // 16=End.DX6, 17=End.DX4, 18=End.DT6, 19=End.DT4.
    assert_eq!(Srv6EndpointBehavior::End.to_u16(), 1);
    assert_eq!(Srv6EndpointBehavior::EndX.to_u16(), 5);
    assert_eq!(Srv6EndpointBehavior::EndT.to_u16(), 9);
    assert_eq!(Srv6EndpointBehavior::EndB.to_u16(), 13);
    assert_eq!(Srv6EndpointBehavior::EndDx6.to_u16(), 16);
    assert_eq!(Srv6EndpointBehavior::EndDx4.to_u16(), 17);
    assert_eq!(Srv6EndpointBehavior::EndDt6.to_u16(), 18);
    assert_eq!(Srv6EndpointBehavior::EndDt4.to_u16(), 19);
    assert_eq!(Srv6EndpointBehavior::from_u16(5), Srv6EndpointBehavior::EndX);
    assert_eq!(
        Srv6EndpointBehavior::from_u16(9999),
        Srv6EndpointBehavior::Unknown(9999)
    );
}

#[test]
fn sid_structure_is_valid_boundary() {
    // Sum exactly 128 is valid; sum > 128 is not (RFC 9514 §8).
    assert!(Srv6SidStructure {
        locator_block_len: 32,
        locator_node_len: 16,
        function_len: 16,
        argument_len: 64,
    }
    .is_valid());
    assert!(!Srv6SidStructure {
        locator_block_len: 33,
        locator_node_len: 16,
        function_len: 16,
        argument_len: 64,
    }
    .is_valid());
}

#[test]
fn opaque_node_attribute_passthrough() {
    // RFC 7752 §3.3.1.5: type 1025, variable-length opaque. The
    // codec does not interpret the bytes.
    let v = vec![0x01, 0x02, 0x03, 0x04];
    let t = BgpLsAttrTlv::OpaqueNodeAttribute(v.clone());
    let wire = encode_tlv(&t);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1025);
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 4);
    assert_eq!(&wire[4..], &v[..]);
    assert_eq!(decode_tlv(&wire), t);
}

#[test]
fn link_protection_type_passthrough() {
    // RFC 7752 §3.3.2.5: type 1093, variable-length. Stored raw.
    let v = vec![0x00, 0x01];
    let t = BgpLsAttrTlv::LinkProtectionType(v.clone());
    let wire = encode_tlv(&t);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1093);
    assert_eq!(&wire[4..], &v[..]);
    assert_eq!(decode_tlv(&wire), t);
}
