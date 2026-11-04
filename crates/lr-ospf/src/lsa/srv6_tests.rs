use super::*;

/// A /48 locator needs ceil(48/32) = 2 address words on the wire
/// (RFC 5340 §A.4.1 "fewest possible 32-bit words").
#[test]
fn locator_tlv_wire_shape_matches_rfc_9513_figure_5() {
    // RFC 9513 §7.1: Route Type | Algorithm | Locator Length |
    // PrefixOptions | Metric(4) | Locator (up to 16 octets).
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 0,
        locator_len: 48,
        options: PREFIX_OPT_AC,
        metric: 10,
        prefix: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
        ..Default::default()
    };
    let mut wire = Vec::new();
    tlv.encode(&mut wire);
    // Type(2)=1 | Length(2)=16 | route_type | algorithm | 48 | 0x80 |
    // metric 10 (4B) | 8 bytes of locator (2 words) — the value is
    // already 4-aligned, no padding.
    assert_eq!(
        wire,
        vec![
            0x00, 0x01, // type 1
            0x00, 0x10, // length 16 (padding excluded)
            0x01, // intra-area
            0x00, // algorithm 0
            48,   // locator length
            0x80, // AC-bit (§6)
            0x00, 0x00, 0x00, 0x0a, // metric 10
            0x20, 0x01, 0x0d, 0xb8, // locator word 1
            0x00, 0x01, 0x00, 0x00, // locator word 2
        ]
    );
    let (back, used) = Srv6LocatorTlv::decode(&wire, 0).unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(back, tlv);
}

#[test]
fn locator_tlv_with_end_sid_and_structure_roundtrips() {
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 0,
        locator_len: 64,
        options: 0,
        metric: 0,
        prefix: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        end_sids: vec![Srv6EndSidSubTlv {
            flags: 0,
            behavior: 1, // End (RFC 8986 §6)
            sid: [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0x01,
            ],
            structure: Some(Srv6SidStructure {
                lb_len: 48,
                ln_len: 16,
                func_len: 16,
                arg_len: 0,
            }),
        }],
        fwd_addr: None,
        route_tag: None,
        ..Default::default()
    };
    let mut wire = Vec::new();
    tlv.encode(&mut wire);
    let (back, used) = Srv6LocatorTlv::decode(&wire, 0).unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(back, tlv);
    // The End SID value part is 20 bytes of fixed fields + the
    // 8-byte structure sub-TLV; the locator TLV value is
    // 12 + 8 (prefix words) + 28 = 48 — already 4-aligned.
    assert_eq!(wire.len(), 4 + 48);
}

/// The End SID sub-TLV wire shape against RFC 9513 Figure 6:
/// Flags | Reserved | Endpoint Behavior(2) | SID(16) | sub-TLVs.
#[test]
fn end_sid_sub_tlv_wire_shape_matches_rfc_9513_figure_6() {
    let sid = Srv6EndSidSubTlv {
        flags: 0,
        behavior: 18, // End.DT6
        sid: [0x11; 16],
        structure: None,
    };
    let mut wire = Vec::new();
    sid.encode(&mut wire);
    assert_eq!(
        wire,
        vec![
            0x00, 0x01, // type 1 (locator sub-TLV registry, §13.9)
            0x00, 0x14, // length 20, padding excluded
            0x00, // flags: none defined (§8)
            0x00, // reserved
            0x00, 0x12, // behavior 18 = End.DT6 (§11 Table 1)
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, // SID
        ]
    );
    let (back, used) = Srv6EndSidSubTlv::decode(&wire, 0).unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(back, sid);
}

/// The SID Structure sub-TLV (§10): exactly 4 value bytes, the
/// LOC:FUNCT:ARGS split in bits.
#[test]
fn sid_structure_wire_shape_matches_rfc_9513_figure_9() {
    let s = Srv6SidStructure {
        lb_len: 32,
        ln_len: 16,
        func_len: 16,
        arg_len: 0,
    };
    let mut wire = Vec::new();
    s.encode(&mut wire);
    assert_eq!(
        wire,
        vec![
            0x00, 0x0a, // type 10 (locator registry, §13.9)
            0x00, 0x04, // length MUST be 4 (§10)
            32, 16, 16, 0, // LB | LN | Fun | Arg
        ]
    );
    assert_eq!(Srv6SidStructure::decode_value(&wire[4..]).unwrap(), s);
    // §10: the sum must stay ≤ 128 bits — a 64+48+16+16 = 144 split
    // invalidates the parent.
    assert!(!Srv6SidStructure {
        lb_len: 64,
        ln_len: 48,
        func_len: 16,
        arg_len: 16,
    }
    .is_valid());
    assert!(Srv6SidStructure::decode_value(&[64, 48, 16, 16]).is_none());
}

/// An End SID carrying two SID Structure sub-TLVs violates §10
/// ("MUST NOT appear more than once in its parent") and the parent
/// must be ignored — the decoder reports that by returning None.
#[test]
fn duplicate_sid_structure_ignores_the_parent() {
    let mut wire = Vec::new();
    wire.extend_from_slice(&LOCATOR_SUBTLV_END_SID.to_be_bytes());
    wire.extend_from_slice(&36u16.to_be_bytes()); // 20 + 8 + 8
    wire.push(0);
    wire.push(0);
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&[0x22; 16]);
    wire.extend_from_slice(&LOCATOR_SUBTLV_SID_STRUCTURE.to_be_bytes());
    wire.extend_from_slice(&4u16.to_be_bytes());
    wire.extend_from_slice(&[48, 16, 16, 0]);
    wire.extend_from_slice(&LOCATOR_SUBTLV_SID_STRUCTURE.to_be_bytes());
    wire.extend_from_slice(&4u16.to_be_bytes());
    wire.extend_from_slice(&[48, 16, 16, 0]);
    assert!(Srv6EndSidSubTlv::decode(&wire, 0).is_none());
}

/// §7.1: a locator with a route type outside 1..=6, or a locator
/// length outside 1..=128, ignores the whole TLV.
#[test]
fn invalid_route_type_and_locator_length_are_rejected() {
    let mut wire = Vec::new();
    Srv6LocatorTlv {
        route_type: 7,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 0,
        prefix: [0; 16],
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
        ..Default::default()
    }
    .encode(&mut wire);
    assert!(Srv6LocatorTlv::decode(&wire, 0).is_none());

    for len in [0u8, 129] {
        let mut w = Vec::new();
        Srv6LocatorTlv {
            route_type: locator_route_type::INTRA_AREA,
            algorithm: 0,
            locator_len: len,
            options: 0,
            metric: 0,
            prefix: [0; 16],
            end_sids: vec![],
            fwd_addr: None,
            route_tag: None,
            ..Default::default()
        }
        .encode(&mut w);
        assert!(Srv6LocatorTlv::decode(&w, 0).is_none());
    }
}

/// §7.2: the IPv6-Forwarding-Address (RFC 8362 §4.2) and Route-Tag
/// (RFC 8362 §4.3) sub-TLVs decode; unknown sub-TLV types are
/// skipped without disturbing the rest.
#[test]
fn locator_sub_tlvs_fwd_addr_route_tag_unknown_skip() {
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTER_AREA,
        algorithm: 0,
        locator_len: 48,
        options: PREFIX_OPT_AC,
        metric: 20,
        prefix: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        end_sids: vec![],
        fwd_addr: Some([0xaa; 16]),
        route_tag: Some(0xdead_beef),
        ..Default::default()
    };
    let mut wire = Vec::new();
    tlv.encode(&mut wire);
    // Unknown sub-TLV (type 0x7fff) spliced in after the prefix,
    // ahead of the forwarding address: value 3 bytes, padded to 4 —
    // receivers skip it.
    let mut with_unknown = Vec::new();
    with_unknown.extend_from_slice(&wire[..20]); // header + fixed + /48 prefix
    with_unknown.extend_from_slice(&0x7fffu16.to_be_bytes());
    with_unknown.extend_from_slice(&3u16.to_be_bytes());
    with_unknown.extend_from_slice(&[1, 2, 3, 0]); // 3-byte value + pad
    with_unknown.extend_from_slice(&wire[20..]);
    // Fix the length field: original value + 8 for the unknown.
    let total_len = wire.len() - 4 + 8;
    with_unknown[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    let (back, used) = Srv6LocatorTlv::decode(&with_unknown, 0).unwrap();
    assert_eq!(used, with_unknown.len());
    assert_eq!(back, tlv);
    assert_eq!(back.fwd_addr, Some([0xaa; 16]));
    assert_eq!(back.route_tag, Some(0xdead_beef));
}

/// RFC 9084 §2.1 — Prefix Source OSPF Router-ID sub-TLV (Locator LSA
/// registry type 4). The 4-octet OSPF Router-ID of the router that
/// originated the locator. Round-trips through `encode`/`decode` and
/// preserves the bit-for-bit wire shape.
#[test]
fn locator_sub_tlv_prefix_src_router_id_roundtrips() {
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTER_AREA,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 20,
        prefix: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
        prefix_src_router_id: Some(0x0a00_0001),
        prefix_src_router_addr: None,
    };
    let mut wire = Vec::new();
    tlv.encode(&mut wire);
    // TLV value layout: 4 fixed bytes (route_type | algorithm |
    // locator_len | options) + 4-byte metric + 8-byte /48 prefix + 4
    // sub-TLV header + 4 sub-TLV value = 24 bytes. Wire = 4-byte TLV
    // header + 24 = 28. The value is already 4-aligned, so no padding.
    assert_eq!(wire.len(), 28);
    // Verify the sub-TLV wire shape byte-for-byte. The sub-TLV starts
    // at wire[20] — TLV header (4) + fixed (4) + metric (4) + prefix (8).
    assert_eq!(
        &wire[20..28],
        &[
            0x00, 0x04, // type 4 (Locator LSA sub-TLV registry)
            0x00, 0x04, // length 4
            0x0a, 0x00, 0x00, 0x01, // OSPF Router-ID 10.0.0.1
        ]
    );
    let (back, used) = Srv6LocatorTlv::decode(&wire, 0).unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(back, tlv);
    assert_eq!(back.prefix_src_router_id, Some(0x0a00_0001));
    assert_eq!(back.prefix_src_router_addr, None);
}

/// RFC 9084 §2.2 — Prefix Source Router Address sub-TLV (Locator LSA
/// registry type 5). The IPv4 form (Length 4) and IPv6 form (Length 16)
/// both round-trip through `encode`/`decode`.
#[test]
fn locator_sub_tlv_prefix_src_router_addr_roundtrips_v4_and_v6() {
    use lr_core::addr::IpAddr;

    // IPv4 form (Length 4).
    let v4 = Srv6LocatorTlv {
        route_type: locator_route_type::INTER_AREA,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 20,
        prefix: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
        prefix_src_router_id: None,
        prefix_src_router_addr: Some(IpAddr::V4([192, 0, 2, 1])),
    };
    let mut wire = Vec::new();
    v4.encode(&mut wire);
    // TLV value = 8 fixed + 8 prefix + 8 sub-TLV (4 hdr + 4 v4 value) = 24.
    // Wire = 4-byte header + 24 = 28. Already 4-aligned.
    assert_eq!(wire.len(), 28);
    assert_eq!(
        &wire[20..28],
        &[
            0x00, 0x05, // type 5
            0x00, 0x04, // length 4
            192, 0, 2, 1, // 192.0.2.1
        ]
    );
    let (back, used) = Srv6LocatorTlv::decode(&wire, 0).unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(back, v4);
    assert_eq!(
        back.prefix_src_router_addr,
        Some(IpAddr::V4([192, 0, 2, 1]))
    );

    // IPv6 form (Length 16).
    let v6 = Srv6LocatorTlv {
        route_type: locator_route_type::INTER_AREA,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 20,
        prefix: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
        prefix_src_router_id: None,
        prefix_src_router_addr: Some(IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])),
    };
    let mut wire = Vec::new();
    v6.encode(&mut wire);
    // TLV value = 8 fixed + 8 prefix + 20 sub-TLV (4 hdr + 16 v6 value) = 36.
    // Wire = 4-byte header + 36 = 40. Already 4-aligned.
    assert_eq!(wire.len(), 40);
    assert_eq!(
        &wire[20..40],
        &[
            0x00, 0x05, // type 5
            0x00, 0x10, // length 16
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
    );
    let (back, used) = Srv6LocatorTlv::decode(&wire, 0).unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(back, v6);
    assert_eq!(
        back.prefix_src_router_addr,
        Some(IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]))
    );
}

/// RFC 9084 §2.1/§2.2 — the two Prefix Source sub-TLVs together with
/// the existing fwd_addr/route_tag sub-TLVs all round-trip; the
/// decoder accepts them in any order the encoder emits them.
#[test]
fn locator_sub_tlv_prefix_src_pair_combined_with_existing_sub_tlvs() {
    use lr_core::addr::IpAddr;

    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTER_AREA,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 20,
        prefix: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        end_sids: vec![],
        fwd_addr: Some([0xaa; 16]),
        route_tag: Some(0xdead_beef),
        prefix_src_router_id: Some(0x0a00_0001),
        prefix_src_router_addr: Some(IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])),
    };
    let mut wire = Vec::new();
    tlv.encode(&mut wire);
    let (back, used) = Srv6LocatorTlv::decode(&wire, 0).unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(back, tlv);
    assert_eq!(back.fwd_addr, Some([0xaa; 16]));
    assert_eq!(back.route_tag, Some(0xdead_beef));
    assert_eq!(back.prefix_src_router_id, Some(0x0a00_0001));
    assert_eq!(
        back.prefix_src_router_addr,
        Some(IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]))
    );
}

/// RFC 9084 §2.1: the Prefix Source OSPF Router-ID sub-TLV's length
/// MUST be 4. Any other length invalidates the parent TLV (returns
/// `None`); the malformed originator attribution is not silently
/// skipped.
#[test]
fn locator_sub_tlv_prefix_src_router_id_wrong_length_rejected() {
    let mut wire = Vec::new();
    // Build a minimal Locator TLV: header + 12 fixed + 8 prefix
    // (locator_len = 48), then the malformed sub-TLV.
    let prefix_bytes = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0];
    let mut value = vec![
        locator_route_type::INTER_AREA, // route_type
        0,                              // algorithm
        48,                             // locator_len
        0,                              // options
        0,
        0,
        0,
        20, // metric
    ];
    value.extend_from_slice(&prefix_bytes);
    // Sub-TLV type 4 with length 3 (malformed — MUST be 4).
    value.extend_from_slice(&LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ID.to_be_bytes());
    value.extend_from_slice(&3u16.to_be_bytes());
    value.extend_from_slice(&[0x0a, 0x00, 0x00]);
    // Pad the sub-TLV value to 4-octet alignment (3 → 4).
    value.push(0);
    // Build the TLV header.
    wire.extend_from_slice(&LOCATOR_TLV_SRV6_LOCATOR.to_be_bytes());
    wire.extend_from_slice(&(value.len() as u16).to_be_bytes());
    wire.extend_from_slice(&value);
    // The Locator TLV value is 12 + 8 + 8 = 28 — already 4-aligned.
    assert!(Srv6LocatorTlv::decode(&wire, 0).is_none());
}

/// RFC 9084 §2.2: the Prefix Source Router Address sub-TLV's length
/// MUST be 4 (IPv4) or 16 (IPv6). Any other length invalidates the
/// parent TLV.
#[test]
fn locator_sub_tlv_prefix_src_router_addr_wrong_length_rejected() {
    let prefix_bytes = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0];
    for bad_len in [3u16, 5, 8, 12, 15, 17, 20] {
        let mut wire = Vec::new();
        let mut value = vec![locator_route_type::INTER_AREA, 0, 48, 0, 0, 0, 0, 20];
        value.extend_from_slice(&prefix_bytes);
        // Sub-TLV type 5 with the bad length; fill with zeros (the
        // decoder rejects on length before reading the value bytes).
        value.extend_from_slice(&LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ADDR.to_be_bytes());
        value.extend_from_slice(&bad_len.to_be_bytes());
        let n = bad_len as usize;
        value.extend(std::iter::repeat_n(0u8, n));
        // Pad to 4-octet alignment.
        let pad = (4 - (n % 4)) % 4;
        value.extend(std::iter::repeat_n(0u8, pad));
        wire.extend_from_slice(&LOCATOR_TLV_SRV6_LOCATOR.to_be_bytes());
        wire.extend_from_slice(&(value.len() as u16).to_be_bytes());
        wire.extend_from_slice(&value);
        assert!(
            Srv6LocatorTlv::decode(&wire, 0).is_none(),
            "length {bad_len} should invalidate the parent TLV"
        );
    }
}

/// The two Prefix Source sub-TLVs can also appear in arbitrary
/// order in the wire (RFC 3630 §2.5 TLV format allows any order). The
/// decoder accepts an out-of-order wire shape (router address before
/// router-id, both before fwd_addr) and reconstructs the same struct.
#[test]
fn locator_sub_tlvs_decode_in_arbitrary_order() {
    use lr_core::addr::IpAddr;

    let prefix_bytes = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0];
    let mut value = vec![
        locator_route_type::INTER_AREA,
        0,  // algorithm
        48, // locator_len
        0,  // options
        0,
        0,
        0,
        20, // metric
    ];
    value.extend_from_slice(&prefix_bytes);
    // Sub-TLV 5 (Prefix Source Router Address, IPv6) — emitted first.
    value.extend_from_slice(&LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ADDR.to_be_bytes());
    value.extend_from_slice(&16u16.to_be_bytes());
    value.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    // Sub-TLV 4 (Prefix Source OSPF Router-ID) — emitted second.
    value.extend_from_slice(&LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ID.to_be_bytes());
    value.extend_from_slice(&4u16.to_be_bytes());
    value.extend_from_slice(&0x0a00_0001u32.to_be_bytes());
    // Sub-TLV 2 (IPv6 Forwarding Address) — emitted third.
    value.extend_from_slice(&LOCATOR_SUBTLV_IPV6_FWD_ADDR.to_be_bytes());
    value.extend_from_slice(&16u16.to_be_bytes());
    value.extend_from_slice(&[0xaa; 16]);
    // Sub-TLV 1 (End SID) is omitted (no End SIDs in this test).

    let mut wire = Vec::new();
    wire.extend_from_slice(&LOCATOR_TLV_SRV6_LOCATOR.to_be_bytes());
    wire.extend_from_slice(&(value.len() as u16).to_be_bytes());
    wire.extend_from_slice(&value);
    let (back, used) = Srv6LocatorTlv::decode(&wire, 0).unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(back.route_type, locator_route_type::INTER_AREA);
    assert_eq!(back.locator_len, 48);
    assert_eq!(back.metric, 20);
    assert_eq!(back.end_sids, Vec::<Srv6EndSidSubTlv>::new());
    assert_eq!(back.fwd_addr, Some([0xaa; 16]));
    assert_eq!(back.route_tag, None);
    assert_eq!(back.prefix_src_router_id, Some(0x0a00_0001));
    assert_eq!(
        back.prefix_src_router_addr,
        Some(IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]))
    );
}

/// The Router Information body (RFC 9513 §2-§4): capabilities TLV
/// (type 20), SR-Algorithm TLV (type 8), Node MSD TLV (type 12).
#[test]
fn ri_body_wire_shape_and_decode() {
    let body = encode_v3_srv6_ri(
        SRV6_CAP_O_FLAG,
        &[0, 128],
        &[(msd_type::SRH_MAX_SL, 8), (msd_type::SRH_MAX_END_D, 4)],
    );
    assert_eq!(
        body,
        vec![
            0x00, 0x14, // RI TLV 20 = SRv6 Capabilities (§13.1)
            0x00, 0x04, // length 4
            0x00, 0x02, // flags: O-flag (bit 1)
            0x00, 0x00, // reserved
            0x00, 0x08, // RI TLV 8 = SR-Algorithm (RFC 8665 §3.1)
            0x00, 0x02, // length 2
            0x00, 128, // algorithms 0 (SPF) and 128 (private)
            0x00, 0x00, // padding to 4-octet alignment
            0x00, 0x0c, // RI TLV 12 = Node MSD (RFC 8476 §2)
            0x00, 0x04, // length 4 = two pairs
            41, 8, // SRH Max SL = 8 (RFC 9352 §4.1 IGP MSD-Types)
            45, 4, // SRH Max End D = 4 (RFC 9352 §4.4)
        ]
    );
    let block = decode_v3_srv6_ri(&body).unwrap();
    assert_eq!(block.capabilities, Some(SRV6_CAP_O_FLAG));
    assert_eq!(block.algorithms, vec![0, 128]);
    assert_eq!(
        block.msds,
        vec![(msd_type::SRH_MAX_SL, 8), (msd_type::SRH_MAX_END_D, 4)]
    );
}

/// A truncated RI TLV body is malformed (None), not silently
/// short-parsed; an odd-length Node MSD value is malformed too.
#[test]
fn ri_body_truncation_is_rejected() {
    assert!(decode_v3_srv6_ri(&[0x00, 0x14, 0x00, 0x08, 0x00]).is_none());
    assert!(decode_v3_srv6_ri(&[0x00, 0x0c, 0x00, 0x03, 41, 8, 45]).is_none());
}

/// RFC 9513 §11 Table 1: the behaviors valid inside an End SID
/// sub-TLV. End.X-family values are invalid there (they only ride
/// the End.X sub-TLVs of a later slice).
#[test]
fn end_sid_behavior_table() {
    for b in [1u16, 2, 3, 4, 18, 19, 20, 28, 29, 30, 31] {
        assert!(behavior_valid_for_end_sid(b), "behavior {b} must be valid");
    }
    for b in [0u16, 5, 8, 16, 17, 32, 35, 36, 1000] {
        assert!(
            !behavior_valid_for_end_sid(b),
            "behavior {b} must be invalid"
        );
    }
}

/// The origination helpers produce RFC 7770 §2.2 / RFC 9513 §7
/// headers: function code 12 (0xA00C) and 42 (0xA02A), U-bit set,
/// area-scoped, with a valid §C.4 checksum and the crate's
/// sequence-number convention.
#[test]
fn origination_headers_and_sequence_convention() {
    let ri = originate_v3_srv6_ri_lsa(0x0a00_0001, 0, &[0], &[], None).unwrap();
    assert_eq!(ri.header.ls_type, LS_TYPE_V3_ROUTER_INFORMATION);
    assert_eq!(ri.header.ls_type, 0xA00C);
    assert_eq!(ri.header.link_state_id, 0); // Instance ID 0 (§2.2)
    assert_eq!(ri.header.advertising_router, 0x0a00_0001);
    assert_eq!(
        ri.header.ls_sequence_number,
        crate::abr::INITIAL_SEQUENCE_NUMBER
    );
    assert!(ri.checksum_ok());
    assert_eq!(ri.header.length as usize % 4, 0);

    let locator = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 10,
        prefix: [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
        ..Default::default()
    };
    let lsa = originate_v3_srv6_locator_lsa(0x0a00_0001, 7, std::slice::from_ref(&locator), None)
        .unwrap();
    assert_eq!(lsa.header.ls_type, LS_TYPE_SRV6_LOCATOR);
    assert_eq!(lsa.header.ls_type, 0xA02A);
    assert_eq!(lsa.header.link_state_id, 7);
    assert!(lsa.checksum_ok());
    // Sequence advance: passing the previous instance's sequence
    // yields the next one; MAX_SEQUENCE_NUMBER exhausts the space.
    let next = originate_v3_srv6_locator_lsa(
        0x0a00_0001,
        7,
        std::slice::from_ref(&locator),
        Some(lsa.header.ls_sequence_number),
    )
    .unwrap();
    assert_eq!(
        next.header.ls_sequence_number,
        lsa.header.ls_sequence_number + 1
    );
    assert!(originate_v3_srv6_locator_lsa(
        0x0a00_0001,
        7,
        std::slice::from_ref(&locator),
        Some(crate::abr::MAX_SEQUENCE_NUMBER),
    )
    .is_none());
    // The body decodes back into the locator.
    let body = Srv6LocatorLsaBody::decode(&lsa.body).unwrap();
    assert_eq!(body.locators, vec![locator]);
}

/// A /128 locator occupies the full 16 address bytes — the §A.4.1
/// word-count ceiling.
#[test]
fn host_locator_uses_full_address_bytes() {
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 0,
        locator_len: 128,
        options: 0,
        metric: 0,
        prefix: [0x2a; 16],
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
        ..Default::default()
    };
    let mut wire = Vec::new();
    tlv.encode(&mut wire);
    assert_eq!(wire.len(), 4 + 24); // header + 12 fixed + 16 address
    let (back, _) = Srv6LocatorTlv::decode(&wire, 0).unwrap();
    assert_eq!(back, tlv);
}

/// A locator LSA body whose TLV value lies beyond the body is
/// malformed (None) — never a silent partial parse. An RI body is
/// not a locator body (the top-level TLV types differ).
#[test]
fn locator_body_truncation_is_rejected() {
    let locator = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 10,
        prefix: [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
        ..Default::default()
    };
    let lsa = originate_v3_srv6_locator_lsa(1, 0, std::slice::from_ref(&locator), None).unwrap();
    assert!(Srv6LocatorLsaBody::decode(&lsa.body).is_some());
    let ri_body = encode_v3_srv6_ri(0, &[], &[]);
    assert!(Srv6LocatorLsaBody::decode(&ri_body).is_none());
    let bad = vec![0x00, 0x01, 0xff, 0xff, 0x01];
    assert!(Srv6LocatorLsaBody::decode(&bad).is_none());
}

/// RFC 9513 §9.1 figure 7, byte-pinned: Type 31, Behavior(2),
/// Flags(1), Reserved1(1), Algorithm(1), Weight(1), Reserved2(2),
/// SID(16) — note the field order differs from the End SID sub-TLV
/// (§8), where Flags leads and no algorithm/weight travel.
#[test]
fn end_x_sid_sub_tlv_wire_and_round_trip() {
    let sid: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
    ];
    let tlv = Srv6EndXSidSubTlv {
        flags: END_X_FLAG_B | END_X_FLAG_P,
        behavior: 5, // End.X (RFC 8986)
        algorithm: 0,
        weight: 3,
        sid,
        structure: Some(Srv6SidStructure {
            lb_len: 32,
            ln_len: 16,
            func_len: 16,
            arg_len: 0,
        }),
    };
    let mut buf = Vec::new();
    tlv.encode(&mut buf);
    // Header (4) + 24 fixed + 8 SID Structure = 36, already
    // 4-octet aligned.
    assert_eq!(buf.len(), 36);
    assert_eq!(
        &buf[..8],
        &[
            0x00,
            0x1F, // type 31
            0x00,
            0x20, // length 32
            0x00,
            0x05, // Endpoint Behavior = End.X
            END_X_FLAG_B | END_X_FLAG_P,
            0, // Reserved1
        ]
    );
    assert_eq!(&buf[8..12], &[0, 3, 0, 0]); // algorithm 0, weight 3, Reserved2
    assert_eq!(&buf[12..28], &sid);
    // The nested SID Structure rides as registry type 30.
    assert_eq!(&buf[28..32], &[0x00, 0x1E, 0x00, 0x04]);
    assert_eq!(&buf[32..36], &[32, 16, 16, 0]);
    let (decoded, consumed) = Srv6EndXSidSubTlv::decode(&buf, 0).unwrap();
    assert_eq!(decoded, tlv);
    assert_eq!(consumed, 36);

    // A preceding foreign sub-TLV and a trailing one — the walker
    // picks only the End.X instance.
    let mut region = Vec::new();
    region.extend_from_slice(&[0x00, 0x63, 0x00, 0x04, 1, 2, 3, 4]); // unknown type 99
    region.extend_from_slice(&buf);
    region.extend_from_slice(&[0x00, 0x1E, 0x00, 0x04, 1, 1, 1, 1]); // stray structure
    assert_eq!(walk_end_x_sub_tlvs(&region), vec![tlv]);
    // Truncation and duplicate nested structures are ignored.
    assert!(Srv6EndXSidSubTlv::decode(&buf[..20], 0).is_none());
    let mut dup = buf.clone();
    dup.extend_from_slice(&[0x00, 0x1E, 0x00, 0x04, 1, 1, 1, 1]);
    // length still says 32 — the second structure sits outside the
    // sub-TLV, so the walker treats it as a separate (unknown
    // here) sub-TLV; extend the parent length to make it a true
    // duplicate violation instead.
    dup[2..4].copy_from_slice(&40u16.to_be_bytes());
    assert!(Srv6EndXSidSubTlv::decode(&dup, 0).is_none());
}

/// RFC 9513 §9.2 figure 8, byte-pinned: the LAN form inserts the
/// 4-octet Neighbor Router-ID between Reserved2 and the SID.
#[test]
fn lan_end_x_sid_sub_tlv_wire_and_round_trip() {
    let sid: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC8,
    ];
    let tlv = Srv6LanEndXSidSubTlv {
        flags: END_X_FLAG_S,
        behavior: 5,
        algorithm: 0,
        weight: 0,
        neighbor_router_id: 0x0a00_0002,
        sid,
        structure: None,
    };
    let mut buf = Vec::new();
    tlv.encode(&mut buf);
    assert_eq!(buf.len(), 32); // 4 header + 28 fixed
    assert_eq!(&buf[..4], &[0x00, 0x20, 0x00, 0x1C]); // type 32, length 28
    assert_eq!(&buf[4..6], &[0x00, 0x05]);
    assert_eq!(buf[6], END_X_FLAG_S);
    assert_eq!(&buf[12..16], &[0x0A, 0x00, 0x00, 0x02]); // neighbor router id
    assert_eq!(&buf[16..32], &sid);
    let (decoded, consumed) = Srv6LanEndXSidSubTlv::decode(&buf, 0).unwrap();
    assert_eq!(decoded, tlv);
    assert_eq!(consumed, 32);
    // Mixed region: both forms walk out with their own types.
    let mut region = Vec::new();
    let p2p = Srv6EndXSidSubTlv {
        flags: 0,
        behavior: 5,
        algorithm: 0,
        weight: 0,
        sid,
        structure: None,
    };
    p2p.encode(&mut region);
    tlv.encode(&mut region);
    assert_eq!(walk_end_x_sub_tlvs(&region), vec![p2p]);
    assert_eq!(walk_lan_end_x_sub_tlvs(&region), vec![tlv]);
}
