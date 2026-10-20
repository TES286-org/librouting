//! Tests for the BGP-LS NLRI codec (RFC 7752 §3.2-§3.3).
//!
//! The vectors here are derived from RFC 7752 §3.2-§3.3 figures and
//! cross-checked against the FRR 10 `bgp_ls_nlri.c` encoder output. Each
//! round-trip is asserted byte-for-byte so the codec cannot drift from
//! the wire format BIRD/FRR expect.

use super::*;

/// Encode a descriptor's sub-TLV stream into an owned `Vec<u8>` so the
/// malformed-input tests below can build a wire buffer by hand without
/// re-running the full NLRI encode path. Used only inside the SRv6 SID
/// negative tests; positive round-trips go through `BgpLsNlri::encode`.
fn encode_descriptor_value<F>(f: F) -> Vec<u8>
where
    F: FnOnce(&mut WriteBuf<'_>) -> Result<usize, EncodeError>,
{
    let mut v = vec![0u8; 64];
    let mut w = WriteBuf::new(&mut v);
    let n = f(&mut w).expect("encode descriptor");
    v.truncate(n);
    v
}

/// Build a Node NLRI matching RFC 7752 §3.3 Figure 7 with an OSPFv2
/// Local Node Descriptor carrying AS, BGP-LS ID, OSPF Area-ID and IGP
/// Router-ID.
fn sample_node_nlri() -> BgpLsNlri {
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::BgpLsId(0x0102_0304),
        NodeDescriptorSubTlv::OspfAreaId(0x0000_0001),
        NodeDescriptorSubTlv::IgpRouterId(vec![192, 0, 2, 1]),
    ]);
    BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Node(NodeNlri {
            protocol_id: ProtocolId::Ospfv2,
            identifier: 0,
            local_node: local,
        }),
    }
}

#[test]
fn node_nlri_roundtrip() {
    let nlri = sample_node_nlri();
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    // NLRI header (4) + Protocol-ID (1) + Identifier (8) +
    // Local Node Descriptor wrapper TLV header (4) +
    // 4 sub-TLVs each 4-byte header + 4-byte value = 4 * 8 = 32.
    // Total: 4 + 1 + 8 + 4 + 32 = 49.
    assert_eq!(n, 49);
    // NLRI Type = 1 (Node)
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 1);
    // Total NLRI Length = 49 - 4 = 45
    assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 45);
    // Protocol-ID = 3 (OSPFv2)
    assert_eq!(buf[4], 3);
    // Identifier = 0
    assert_eq!(&buf[5..13], &[0u8; 8]);
    // Local Node Descriptor TLV: type = 256
    assert_eq!(u16::from_be_bytes([buf[13], buf[14]]), 256);
    // Inner sub-TLV length: 4 * (4 + 4) = 32.
    assert_eq!(u16::from_be_bytes([buf[15], buf[16]]), 32);
    // First sub-TLV: AS = 512, length 4, value 64512.
    assert_eq!(u16::from_be_bytes([buf[17], buf[18]]), 512);
    assert_eq!(u16::from_be_bytes([buf[19], buf[20]]), 4);
    assert_eq!(
        u32::from_be_bytes([buf[21], buf[22], buf[23], buf[24]]),
        64512
    );
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn link_nlri_roundtrip() {
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::BgpLsId(0x0102_0304),
        NodeDescriptorSubTlv::OspfAreaId(0x0000_0001),
        NodeDescriptorSubTlv::IgpRouterId(vec![192, 0, 2, 1]),
    ]);
    let remote = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64513),
        NodeDescriptorSubTlv::BgpLsId(0x0506_0708),
        NodeDescriptorSubTlv::OspfAreaId(0x0000_0001),
        NodeDescriptorSubTlv::IgpRouterId(vec![192, 0, 2, 2]),
    ]);
    let link = LinkDescriptor::new(vec![
        LinkDescriptorSubTlv::Ipv4InterfaceAddress([10, 0, 0, 1]),
        LinkDescriptorSubTlv::Ipv4NeighborAddress([10, 0, 0, 2]),
    ]);
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Link(LinkNlri {
            protocol_id: ProtocolId::Ospfv2,
            identifier: 0,
            local_node: local,
            remote_node: remote,
            link,
        }),
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    // NLRI header (4) + Protocol-ID (1) + Identifier (8) +
    // Local Node Descriptor TLV (4 + 32) + Remote Node Descriptor TLV
    // (4 + 32) + 2 bare Link Descriptor sub-TLVs (2 * (4 + 4) = 16).
    // Total: 4 + 1 + 8 + 36 + 36 + 16 = 101.
    assert_eq!(n, 101);
    // NLRI Type = 2 (Link)
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 2);
    // Verify the third outer TLV is the first bare Link Descriptor
    // sub-TLV (IPv4 Interface Address, type 259).
    let after_remote = 4 + 1 + 8 + 36 + 36;
    assert_eq!(
        u16::from_be_bytes([buf[after_remote], buf[after_remote + 1]]),
        259
    );
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn ipv4_prefix_nlri_roundtrip() {
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::BgpLsId(0),
        NodeDescriptorSubTlv::OspfAreaId(0x0000_0001),
        NodeDescriptorSubTlv::IgpRouterId(vec![192, 0, 2, 1]),
    ]);
    // 203.0.113.0/24 → prefix_len=24, prefix_bytes=[203, 0, 113].
    let prefix = PrefixDescriptor::new(vec![
        PrefixDescriptorSubTlv::OspfRouteType(OspfRouteType::IntraArea),
        PrefixDescriptorSubTlv::IpReachabilityInfo {
            prefix_len: 24,
            prefix_bytes: vec![203, 0, 113],
        },
    ]);
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Ipv4Prefix(PrefixNlri {
            protocol_id: ProtocolId::Ospfv2,
            identifier: 0,
            local_node: local,
            prefix,
        }),
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn ipv6_prefix_nlri_roundtrip() {
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::BgpLsId(0),
        NodeDescriptorSubTlv::OspfAreaId(0x0000_0001),
        NodeDescriptorSubTlv::IgpRouterId(vec![1, 2, 3, 4]),
    ]);
    // 2001:db8::/32 → prefix_len=32, prefix_bytes = 2001:0db8.
    let prefix = PrefixDescriptor::new(vec![PrefixDescriptorSubTlv::IpReachabilityInfo {
        prefix_len: 32,
        prefix_bytes: vec![0x20, 0x01, 0x0d, 0xb8],
    }]);
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Ipv6Prefix(PrefixNlri {
            protocol_id: ProtocolId::Ospfv3,
            identifier: 0,
            local_node: local,
            prefix,
        }),
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    // NLRI Type = 4 (IPv6 Prefix).
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 4);
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn vpn_nlri_roundtrip() {
    // Same Node NLRI but emitted with a Route Distinguisher.
    let mut nlri = sample_node_nlri();
    nlri.route_distinguisher = Some([0, 0, 0, 1, 0, 0, 0, 0]);
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    // 4-byte NLRI header + 8-byte RD + the 45-byte value (Node NLRI body).
    assert_eq!(n, 4 + 8 + 45);
    // Verify the RD lands right after the NLRI header.
    assert_eq!(&buf[4..12], &[0, 0, 0, 1, 0, 0, 0, 0]);
    let (decoded, consumed) = BgpLsNlri::decode(true, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn unknown_subtlv_preserved_on_roundtrip() {
    // A Node Descriptor carrying an unknown sub-TLV (type 999, value
    // [0xaa, 0xbb]). Round-trip must preserve it byte-for-byte so
    // BIRD/FRR can still recognise the NLRI.
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::Unknown(Tlv {
            ty: 999,
            value: vec![0xaa, 0xbb],
        }),
    ]);
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Node(NodeNlri {
            protocol_id: ProtocolId::Ospfv2,
            identifier: 0,
            local_node: local,
        }),
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
    // Confirm the unknown sub-TLV is preserved.
    let decoded_local = match decoded.variant {
        BgpLsNlriVariant::Node(n) => n.local_node,
        _ => unreachable!(),
    };
    assert!(decoded_local.sub_tlvs.iter().any(|s| matches!(
        s,
        NodeDescriptorSubTlv::Unknown(Tlv { ty: 999, value } )
            if value == &vec![0xaa, 0xbb]
    )));
}

#[test]
fn unknown_nlri_type_passthrough() {
    // NLRI Type 0x42 — not assigned by RFC 7752 / RFC 9514 / IANA at
    // the time of writing. The codec must preserve it verbatim.
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Unknown {
            nlri_type: BgpLsNlriType::Unknown(0x42),
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        },
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    // NLRI Type = 0x42 preserved.
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x42);
    // Total NLRI Length = 4.
    assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 4);
    // Value bytes preserved at offset 4 (no Route Distinguisher).
    assert_eq!(&buf[4..8], &[0xde, 0xad, 0xbe, 0xef]);
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn srv6_sid_nlri_roundtrip() {
    // RFC 9514 §6 Figure 5: an SRv6 SID NLRI carries a Local Node
    // Descriptor wrapper followed by the bare SRv6 SID Descriptor TLV
    // stream. The stream MUST contain exactly one SRv6 SID Information
    // TLV (§6.1, type 518, 16-byte SID). The codec now models the full
    // NLRI shape; round-trip must be byte-exact.
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::BgpLsId(0x0102_0304),
        NodeDescriptorSubTlv::OspfAreaId(0x0000_0001),
        NodeDescriptorSubTlv::IgpRouterId(vec![192, 0, 2, 1]),
    ]);
    let srv6_sid = Srv6SidDescriptor::new(vec![Srv6SidDescriptorSubTlv::Srv6SidInformation([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01,
    ])]);
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Srv6Sid(Srv6SidNlri {
            protocol_id: ProtocolId::Ospfv3,
            identifier: 0,
            local_node: local,
            srv6_sid,
        }),
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    // NLRI header (4) + Protocol-ID (1) + Identifier (8) +
    // Local Node Descriptor wrapper TLV (4 + 32) + SRv6 SID Information
    // TLV (4 + 16) = 4 + 1 + 8 + 36 + 20 = 69.
    assert_eq!(n, 69);
    // NLRI Type = 6 (SRv6 SID).
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 6);
    // Total NLRI Length = 65 (69 - 4).
    assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 65);
    // Protocol-ID = 6 (OSPFv3).
    assert_eq!(buf[4], 6);
    // Local Node Descriptor wrapper at offset 13 (after the 4-byte
    // NLRI header + 1-byte Protocol-ID + 8-byte Identifier).
    assert_eq!(u16::from_be_bytes([buf[13], buf[14]]), 256);
    // SRv6 SID Information TLV at the offset right after the wrapper.
    let wrapper_end = 13 + 4 + 32;
    assert_eq!(
        u16::from_be_bytes([buf[wrapper_end], buf[wrapper_end + 1]]),
        518
    );
    assert_eq!(
        u16::from_be_bytes([buf[wrapper_end + 2], buf[wrapper_end + 3]]),
        16
    );
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn srv6_sid_nlri_with_mt_id_roundtrip() {
    // RFC 9514 §6: the SRv6 SID Descriptor stream MAY also carry a
    // Multi-Topology ID TLV (type 263, RFC 7752 §3.2.1.5). The codec
    // passes MT-IDs through verbatim — the topology context lives in
    // the projection, not the codec.
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::IgpRouterId(vec![1, 2, 3, 4]),
    ]);
    let srv6_sid = Srv6SidDescriptor::new(vec![
        Srv6SidDescriptorSubTlv::Srv6SidInformation([
            0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]),
        Srv6SidDescriptorSubTlv::MultiTopologyId(vec![0x00, 0x01, 0x00, 0x02]),
    ]);
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Srv6Sid(Srv6SidNlri {
            protocol_id: ProtocolId::Ospfv3,
            identifier: 0,
            local_node: local,
            srv6_sid,
        }),
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
    // Accessor: the SRv6 SID carried in the mandatory 518 TLV.
    let decoded_sid = match decoded.variant {
        BgpLsNlriVariant::Srv6Sid(n) => n.srv6_sid,
        _ => unreachable!(),
    };
    assert_eq!(
        decoded_sid.sid(),
        Some([0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01])
    );
}

#[test]
fn srv6_sid_nlri_with_unknown_subtlv_preserved() {
    // A SRv6 SID Descriptor stream carrying an unknown TLV (type 999,
    // value [0xaa, 0xbb]) alongside the mandatory 518. Round-trip
    // must preserve the unknown TLV byte-for-byte so a future revision
    // of the codec can still recognise the NLRI.
    let local = NodeDescriptor::new(vec![NodeDescriptorSubTlv::As(64512)]);
    let srv6_sid = Srv6SidDescriptor::new(vec![
        Srv6SidDescriptorSubTlv::Srv6SidInformation([0xfe; 16]),
        Srv6SidDescriptorSubTlv::Unknown(Tlv {
            ty: 999,
            value: vec![0xaa, 0xbb],
        }),
    ]);
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Srv6Sid(Srv6SidNlri {
            protocol_id: ProtocolId::Direct,
            identifier: 0,
            local_node: local,
            srv6_sid,
        }),
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
    // Confirm the unknown sub-TLV is preserved.
    let decoded_sid = match decoded.variant {
        BgpLsNlriVariant::Srv6Sid(n) => n.srv6_sid,
        _ => unreachable!(),
    };
    assert!(decoded_sid.sub_tlvs.iter().any(|s| matches!(
        s,
        Srv6SidDescriptorSubTlv::Unknown(Tlv { ty: 999, value } )
            if value == &vec![0xaa, 0xbb]
    )));
}

#[test]
fn srv6_sid_nlri_vpn_roundtrip() {
    // The SRv6 SID NLRI rides the same VPN SAFI (72) framing as the
    // other BGP-LS NLRIs: an 8-byte Route Distinguisher prepended to
    // the NLRI value, included in the Total NLRI Length.
    let local = NodeDescriptor::new(vec![NodeDescriptorSubTlv::As(64512)]);
    let srv6_sid = Srv6SidDescriptor::new(vec![Srv6SidDescriptorSubTlv::Srv6SidInformation([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ])]);
    let nlri = BgpLsNlri {
        route_distinguisher: Some([0, 0, 0, 1, 0, 0, 0, 0]),
        variant: BgpLsNlriVariant::Srv6Sid(Srv6SidNlri {
            protocol_id: ProtocolId::Ospfv3,
            identifier: 0,
            local_node: local,
            srv6_sid,
        }),
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    // Verify the RD lands right after the NLRI header.
    assert_eq!(&buf[4..12], &[0, 0, 0, 1, 0, 0, 0, 0]);
    let (decoded, consumed) = BgpLsNlri::decode(true, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn srv6_sid_nlri_missing_local_node_rejected() {
    // The first outer TLV must be the LOCAL_NODE_DESCRIPTOR wrapper
    // (256). Anything else is malformed and must be rejected so the
    // encode↔decode round-trip is byte-exact for any input the codec
    // accepts.
    let bad = &[
        0x00, 0x06, // NLRI Type = 6 (SRv6 SID)
        0x00, 0x18, // Total NLRI Length = 24
        0x06, // Protocol-ID = OSPFv3
        0, 0, 0, 0, 0, 0, 0, 0, // Identifier = 0
        0x02, 0x06, // Outer TLV Type = 518 (SRv6 SID Information,
        // not LOCAL_NODE_DESCRIPTOR)
        0x00, 0x10, // Length = 16
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    assert!(BgpLsNlri::decode(false, bad).is_none());
}

#[test]
fn srv6_sid_nlri_missing_sid_information_rejected() {
    // RFC 9514 §6: "This field MUST contain a single SRv6 SID
    // Information TLV (Section 6.1)". A stream with only an MT-ID TLV
    // and no 518 is malformed.
    let local = NodeDescriptor::new(vec![NodeDescriptorSubTlv::As(64512)]);
    let local_bytes = encode_descriptor_value(|w| local.encode_value(w));
    let mut body = vec![0u8; 128];
    let body_len = {
        let mut w = WriteBuf::new(&mut body);
        w.put_u8(ProtocolId::Ospfv3.to_u8()).unwrap();
        w.put_u64_be(0).unwrap();
        // LOCAL_NODE_DESCRIPTOR wrapper.
        w.put_u16_be(tlv_type::LOCAL_NODE_DESCRIPTOR).unwrap();
        w.put_u16_be(local_bytes.len() as u16).unwrap();
        w.put_bytes(&local_bytes).unwrap();
        // MT-ID TLV (263) but no SRv6 SID Information TLV (518).
        let mt_tlv = Tlv {
            ty: tlv_type::MULTI_TOPOLOGY_ID,
            value: vec![0x00, 0x01],
        };
        mt_tlv.encode(&mut w).unwrap();
        w.position()
    };
    body.truncate(body_len);
    let mut buf = vec![0u8; 4 + body_len];
    let mut w2 = WriteBuf::new(&mut buf);
    w2.put_u16_be(BgpLsNlriType::SRV6_SID).unwrap();
    w2.put_u16_be(body.len() as u16).unwrap();
    w2.put_bytes(&body).unwrap();
    assert!(BgpLsNlri::decode(false, &buf).is_none());
}

#[test]
fn srv6_sid_nlri_two_sid_information_rejected() {
    // RFC 9514 §6 mandates *exactly one* SRv6 SID Information TLV.
    // Two 518s (each 16 bytes) is malformed.
    let local = NodeDescriptor::new(vec![NodeDescriptorSubTlv::As(64512)]);
    let local_bytes = encode_descriptor_value(|w| local.encode_value(w));
    let mut body = vec![0u8; 128];
    let body_len = {
        let mut w = WriteBuf::new(&mut body);
        w.put_u8(ProtocolId::Ospfv3.to_u8()).unwrap();
        w.put_u64_be(0).unwrap();
        w.put_u16_be(tlv_type::LOCAL_NODE_DESCRIPTOR).unwrap();
        w.put_u16_be(local_bytes.len() as u16).unwrap();
        w.put_bytes(&local_bytes).unwrap();
        // First 518.
        let info1 = Tlv {
            ty: tlv_type::SRV6_SID_INFORMATION,
            value: vec![0x20; 16],
        };
        info1.encode(&mut w).unwrap();
        // Second 518 — duplicates the mandatory TLV.
        let info2 = Tlv {
            ty: tlv_type::SRV6_SID_INFORMATION,
            value: vec![0x21; 16],
        };
        info2.encode(&mut w).unwrap();
        w.position()
    };
    body.truncate(body_len);
    let mut buf = vec![0u8; 4 + body_len];
    let mut w2 = WriteBuf::new(&mut buf);
    w2.put_u16_be(BgpLsNlriType::SRV6_SID).unwrap();
    w2.put_u16_be(body.len() as u16).unwrap();
    w2.put_bytes(&body).unwrap();
    assert!(BgpLsNlri::decode(false, &buf).is_none());
}

#[test]
fn srv6_sid_nlri_malformed_518_length_rejected() {
    // RFC 9514 §6.1 fixes the SRv6 SID Information TLV length at 16
    // (a single 128-bit SRv6 SID). A TLV 518 with any other length
    // is malformed — it falls through to `Unknown` in the descriptor
    // stream, so the "exactly one 518" structural check fails.
    let local = NodeDescriptor::new(vec![NodeDescriptorSubTlv::As(64512)]);
    let local_bytes = encode_descriptor_value(|w| local.encode_value(w));
    let mut body = vec![0u8; 64];
    let body_len = {
        let mut w = WriteBuf::new(&mut body);
        w.put_u8(ProtocolId::Ospfv3.to_u8()).unwrap();
        w.put_u64_be(0).unwrap();
        w.put_u16_be(tlv_type::LOCAL_NODE_DESCRIPTOR).unwrap();
        w.put_u16_be(local_bytes.len() as u16).unwrap();
        w.put_bytes(&local_bytes).unwrap();
        // 518 with a 4-byte value — wrong length per RFC 9514 §6.1.
        let bad_info = Tlv {
            ty: tlv_type::SRV6_SID_INFORMATION,
            value: vec![0xde, 0xad, 0xbe, 0xef],
        };
        bad_info.encode(&mut w).unwrap();
        w.position()
    };
    body.truncate(body_len);
    let mut buf = vec![0u8; 4 + body_len];
    let mut w2 = WriteBuf::new(&mut buf);
    w2.put_u16_be(BgpLsNlriType::SRV6_SID).unwrap();
    w2.put_u16_be(body.len() as u16).unwrap();
    w2.put_bytes(&body).unwrap();
    assert!(BgpLsNlri::decode(false, &buf).is_none());
}

#[test]
fn srv6_sid_descriptor_subtlv_round_trip() {
    // Each variant of Srv6SidDescriptorSubTlv must round-trip on its
    // own (well-formed 518, MT-ID, unknown passthrough). Verifies the
    // per-sub-TLV encode/decode paths in isolation.
    let cases = vec![
        Srv6SidDescriptorSubTlv::Srv6SidInformation([0xab; 16]),
        Srv6SidDescriptorSubTlv::MultiTopologyId(vec![0x00, 0x01]),
        Srv6SidDescriptorSubTlv::Unknown(Tlv {
            ty: 9999,
            value: vec![0xca, 0xfe],
        }),
    ];
    for s in cases {
        let mut buf = vec![0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        let n = s.encode_into(&mut w).expect("encode");
        let tlv = {
            let mut r = ReadBuf::new(&buf[..n]);
            Tlv::decode(&mut r).expect("decode raw")
        };
        let s2 = Srv6SidDescriptorSubTlv::decode(tlv);
        assert_eq!(s.wire_len(), s2.wire_len());
        assert_eq!(s.ty(), s2.ty());
        assert_eq!(s, s2);
    }
}

#[test]
fn truncated_header_rejected() {
    // 3 bytes — not even enough for the 4-byte NLRI header.
    assert!(BgpLsNlri::decode(false, &[0, 1, 2]).is_none());
}

#[test]
fn truncated_value_rejected() {
    // 4-byte NLRI header claims 100 bytes of value, but only 4 bytes
    // follow. Decode must reject it.
    let bad = &[0x00, 0x01, 0x00, 0x64, 0x03, 0, 0, 0];
    assert!(BgpLsNlri::decode(false, bad).is_none());
}

#[test]
fn vpn_total_len_below_rd_size_rejected() {
    // Regression for a fuzz-found crash: a VPN NLRI (SAFI=72) with a
    // Total NLRI Length smaller than the 8-byte Route Distinguisher
    // must be rejected, not slice-into-negative-range. The original
    // bug was that `b[12..9]` underflowed because the buffer was
    // long enough to satisfy the length check but the VPN branch
    // advanced `i` past `value_end`.
    //
    // Byte 0 = 1 (is_vpn=true). NLRI Type = 0x05b1 = 1457 (unknown,
    // so the variant path is `Unknown`). Total NLRI Length = 5, which
    // is < 8 — invalid for VPN.
    let bad = &[
        0x01, // is_vpn = true
        0x05, 0xb1, // NLRI Type = 1457 (unknown)
        0x00, 0x05, // Total NLRI Length = 5
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    ];
    assert!(BgpLsNlri::decode(true, &bad[1..]).is_none());
}

#[test]
fn bad_descriptor_length_rejected() {
    // NLRI Type = 1 (Node), Total Length = 10. Value: Protocol-ID (1) +
    // Identifier (8) + Local Node Descriptor TLV header claims 4 bytes
    // of value but only 1 byte follows. Decode must reject — the
    // truncated sub-TLV stream fails.
    let mut bad = vec![
        0x00, 0x01, // NLRI Type = Node
        0x00, 0x0b, // Total NLRI Length = 11 (1 + 8 + 4 + 1 — wait)
    ];
    // Rebuild: NLRI Type=1, Total=11. Value: 1 (proto-id) + 8 (id) + 4
    // (outer TLV header) + 2 (claimed value) but actual = 0.
    // Wait, simpler: claim 4 bytes of sub-TLV value but provide 0.
    bad = vec![
        0x00, 0x01, // NLRI Type = Node
        0x00, 0x0d, // Total NLRI Length = 13
        0x03, // Protocol-ID = OSPFv2
        0, 0, 0, 0, 0, 0, 0, 0, // Identifier = 0
        0x01, 0x00, // Outer TLV Type = 256 (Local Node Descriptor)
        0x00,
        0x04, // Outer TLV Length = 4 (claims 4 bytes)
              // Only 0 bytes of value follow.
    ];
    assert!(BgpLsNlri::decode(false, &bad).is_none());
}

#[test]
fn ospf_route_type_round_trip() {
    for rt in [
        OspfRouteType::IntraArea,
        OspfRouteType::InterArea,
        OspfRouteType::External1,
        OspfRouteType::External2,
        OspfRouteType::Nssa1,
        OspfRouteType::Nssa2,
        OspfRouteType::Unknown(0xfe),
    ] {
        assert_eq!(OspfRouteType::from_u8(rt.to_u8()), rt);
    }
}

#[test]
fn protocol_id_round_trip() {
    for p in [
        ProtocolId::IsisLevel1,
        ProtocolId::IsisLevel2,
        ProtocolId::Ospfv2,
        ProtocolId::Direct,
        ProtocolId::Static,
        ProtocolId::Ospfv3,
        ProtocolId::Bgp,
        ProtocolId::Unknown(0xff),
    ] {
        assert_eq!(ProtocolId::from_u8(p.to_u8()), p);
    }
}

#[test]
fn bgp_ls_nlri_type_constants_match_iana() {
    // RFC 7752 §3.3 Table 1 + RFC 9514 §3.
    assert_eq!(BgpLsNlriType::Node.to_u16(), 1);
    assert_eq!(BgpLsNlriType::Link.to_u16(), 2);
    assert_eq!(BgpLsNlriType::Ipv4Prefix.to_u16(), 3);
    assert_eq!(BgpLsNlriType::Ipv6Prefix.to_u16(), 4);
    assert_eq!(BgpLsNlriType::Srv6Sid.to_u16(), 6);
    assert_eq!(BgpLsNlriType::from_u16(1), BgpLsNlriType::Node);
    assert_eq!(BgpLsNlriType::from_u16(6), BgpLsNlriType::Srv6Sid);
    assert_eq!(BgpLsNlriType::from_u16(999), BgpLsNlriType::Unknown(999));
}

#[test]
fn tlv_round_trip() {
    let t = Tlv {
        ty: 1024,
        value: vec![0xaa, 0xbb, 0xcc],
    };
    let mut buf = vec![0u8; 32];
    let mut w = WriteBuf::new(&mut buf);
    let n = t.encode(&mut w).expect("encode");
    assert_eq!(n, 7);
    let mut r = ReadBuf::new(&buf[..n]);
    let t2 = Tlv::decode(&mut r).expect("decode");
    assert_eq!(t, t2);
}

#[test]
fn ipv6_link_descriptor_round_trip() {
    // A Link NLRI whose Link Descriptor carries IPv6 interface and
    // neighbor addresses (TLVs 261/262). Confirms the 16-byte variants
    // of the IPv6 sub-TLVs parse correctly.
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::IgpRouterId(vec![1, 2, 3, 4, 5, 6]),
    ]);
    let remote = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::IgpRouterId(vec![1, 2, 3, 4, 5, 7]),
    ]);
    let link = LinkDescriptor::new(vec![
        LinkDescriptorSubTlv::Ipv6InterfaceAddress([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]),
        LinkDescriptorSubTlv::Ipv6NeighborAddress([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]),
        LinkDescriptorSubTlv::LinkLocalRemoteId {
            local: 1,
            remote: 2,
        },
    ]);
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Link(LinkNlri {
            protocol_id: ProtocolId::Ospfv3,
            identifier: 0,
            local_node: local,
            remote_node: remote,
            link,
        }),
    };
    let mut buf = vec![0u8; 512];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn multi_topology_id_passthrough() {
    // MT-ID TLV value bytes are passed through verbatim by the codec
    // — the codec does not unpack the 2-byte MT-IDs because the
    // topology context lives in the projection (RFC 7752 §3.2.1.5).
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::IgpRouterId(vec![1, 2, 3, 4]),
    ]);
    let link = LinkDescriptor::new(vec![LinkDescriptorSubTlv::MultiTopologyId(vec![
        0x00, 0x01, 0x00, 0x02,
    ])]);
    let nlri = BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Link(LinkNlri {
            protocol_id: ProtocolId::Ospfv2,
            identifier: 0,
            local_node: local,
            remote_node: NodeDescriptor::new(vec![
                NodeDescriptorSubTlv::As(64512),
                NodeDescriptorSubTlv::IgpRouterId(vec![5, 6, 7, 8]),
            ]),
            link,
        }),
    };
    let mut buf = vec![0u8; 256];
    let mut w = WriteBuf::new(&mut buf);
    let n = nlri.encode(&mut w).expect("encode");
    let (decoded, consumed) = BgpLsNlri::decode(false, &buf[..n]).expect("decode");
    assert_eq!(consumed, n);
    assert_eq!(decoded, nlri);
}

#[test]
fn descriptor_accessors_return_the_right_subtlvs() {
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::BgpLsId(0xdead_beef),
        NodeDescriptorSubTlv::OspfAreaId(0x0000_0001),
        NodeDescriptorSubTlv::IgpRouterId(vec![1, 2, 3, 4]),
        NodeDescriptorSubTlv::Unknown(Tlv {
            ty: 999,
            value: vec![0],
        }),
    ]);
    assert_eq!(local.as_number(), Some(64512));
    assert_eq!(local.bgp_ls_id(), Some(0xdead_beef));
    assert_eq!(local.ospf_area_id(), Some(0x0000_0001));
    assert_eq!(local.igp_router_id(), Some(&[1u8, 2, 3, 4][..]));
}
