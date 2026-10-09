use super::*;

fn v6_prefix(bytes: &[u8], len: u8, options: u8) -> V3Prefix {
    let mut addr = [0u8; 16];
    addr[..bytes.len()].copy_from_slice(bytes);
    V3Prefix {
        prefix_len: len,
        options,
        metric: 0,
        addr,
    }
}

// --- TLV framing (RFC 8362 §3) -------------------------------------

/// §3's padding example: a 3-octet value has Length 3 but occupies
/// 8 octets on the wire.
#[test]
fn tlv_padding_is_not_counted_in_length() {
    let mut out = Vec::new();
    encode_tlv(&mut out, 7, &[0xAA, 0xBB, 0xCC]);
    assert_eq!(out, [0, 7, 0, 3, 0xAA, 0xBB, 0xCC, 0]);
    assert_eq!(
        walk_tlvs(&out),
        Some(vec![RawTlv {
            tlv_type: 7,
            value: &[0xAA, 0xBB, 0xCC]
        }])
    );
    // A second TLV walks past the padding.
    encode_tlv(&mut out, 9, &[0x01]);
    assert_eq!(out.len(), 8 + 8);
    let tlvs = walk_tlvs(&out).unwrap();
    assert_eq!(tlvs.len(), 2);
    assert_eq!(tlvs[1].tlv_type, 9);
    assert_eq!(tlvs[1].value, &[0x01]);
}

#[test]
fn tlv_walk_rejects_truncation() {
    assert_eq!(walk_tlvs(&[0, 7, 0, 3, 0xAA]), None); // value cut
    assert_eq!(walk_tlvs(&[0, 7]), None); // header cut
    assert_eq!(walk_tlvs(&[]), Some(vec![]));
    // A mid-region fragment shorter than a header is malformed.
    assert_eq!(walk_tlvs(&[0, 7, 0, 0, 0, 9]), None);
}

// --- E-Router-LSA (§4.1) -------------------------------------------

#[test]
fn e_router_lsa_wire_and_round_trip() {
    let body = ERouterLsaBody {
        bits: 0x04, // V6
        options: 0x00_00_13,
        links: vec![ERouterLinkTlv {
            link_type: 1, // p2p
            metric: 10,
            interface_id: 1,
            neighbor_interface_id: 2,
            neighbor_router_id: 0x0a00_0002,
            sub_tlvs: Vec::new(),
        }],
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    // bits|options (4), TLV header (4), fixed link (16).
    assert_eq!(wire.len(), 24);
    assert_eq!(
        wire,
        [
            0x04, 0x00, 0x00, 0x13, // bits + 24-bit options
            0x00, 0x01, 0x00, 0x10, // Router-Link TLV, length 16
            0x01, 0x00, 0x00, 0x0A, // type 1, 0, metric 10
            0x00, 0x00, 0x00, 0x01, // Interface ID
            0x00, 0x00, 0x00, 0x02, // Neighbor Interface ID
            0x0A, 0x00, 0x00, 0x02, // Neighbor Router ID
        ]
    );
    assert_eq!(ERouterLsaBody::decode(&wire), Some(body.clone()));

    // A link with sub-TLVs: the raw region rides the TLV value and
    // survives the round trip (the End.X extension point).
    let with_sub = ERouterLsaBody {
        links: vec![ERouterLinkTlv {
            link_type: 2, // transit
            metric: 0xFFFF,
            interface_id: 9,
            neighbor_interface_id: 9,
            neighbor_router_id: 0x0a00_0009,
            sub_tlvs: vec![0, 31, 0, 4, 1, 2, 3, 4], // an End.X-shaped sub-TLV
        }],
        ..body.clone()
    };
    let mut wire2 = Vec::new();
    with_sub.encode(&mut wire2);
    // TLV type 1 (Router-Link), length 16 + 8 (the sub-TLV).
    assert_eq!(&wire2[4..8], &[0x00, 0x01, 0x00, 0x18]);
    assert_eq!(ERouterLsaBody::decode(&wire2), Some(with_sub));

    // Malformed: a Router-Link TLV shorter than the 16-octet
    // minimum (§5).
    let short = [
        0x04, 0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
        0x01,
    ];
    assert_eq!(ERouterLsaBody::decode(&short), None);
    // Unknown top-level TLVs are skipped (§6.3 rule 1).
    let unknown = [
        0x04, 0x00, 0x00, 0x13, // header
        0x00, 0x63, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // unknown TLV 99
    ];
    assert_eq!(
        ERouterLsaBody::decode(&unknown).map(|b| b.links.len()),
        Some(0)
    );
}

// --- E-Network-LSA (§4.2) ------------------------------------------

#[test]
fn e_network_lsa_wire_and_round_trip() {
    let body = ENetworkLsaBody {
        options: 0x00_00_13,
        routers: vec![0x0a00_0001, 0x0a00_0002],
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    assert_eq!(
        wire,
        [
            0x00, 0x00, 0x00, 0x13, // 0 + options
            0x00, 0x02, 0x00, 0x08, // Attached-Routers TLV, length 8
            0x0A, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x02,
        ]
    );
    assert_eq!(ENetworkLsaBody::decode(&wire), Some(body.clone()));
    // A missing Attached-Routers TLV is malformed (§4.2).
    assert_eq!(ENetworkLsaBody::decode(&[0x00, 0x00, 0x00, 0x13]), None);
    // Later instances are ignored — the first wins.
    let mut dup = wire.clone();
    dup.extend_from_slice(&[0x00, 0x02, 0x00, 0x04, 0x0B, 0x00, 0x00, 0x03]);
    assert_eq!(ENetworkLsaBody::decode(&dup), Some(body));
    // A router list that is not 4-octet units is malformed
    // (the Attached-Routers value is truncated mid-router).
    assert_eq!(
        ENetworkLsaBody::decode(&[
            0x00, 0x00, 0x00, 0x13, 0x00, 0x02, 0x00, 0x03, 0x0A, 0x00, 0x00
        ]),
        None
    );
}

// --- Prefix TLVs (§3.4/§3.7) ---------------------------------------

#[test]
fn e_prefix_tlv_wire_and_round_trip() {
    let tlv = EPrefixTlv {
        metric: 10,
        prefix: v6_prefix(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0], 48, 0),
        sub_tlvs: Vec::new(),
    };
    let mut wire = Vec::new();
    tlv.encode_into(&mut wire, TLV_INTER_AREA_PREFIX);
    assert_eq!(
        wire,
        [
            0x00, 0x03, 0x00, 0x10, // Inter-Area-Prefix TLV, length 16
            0x00, 0x00, 0x00, 0x0A, // 0 + 24-bit metric 10
            0x30, 0x00, 0x00, 0x00, // PrefixLength 48, options 0, reserved 0
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, // 2001:db8::
        ]
    );
    let mut as_intra = Vec::new();
    tlv.encode_into(&mut as_intra, TLV_INTRA_AREA_PREFIX);
    assert_eq!(&as_intra[..2], &[0x00, 0x06]);
    assert_eq!(EPrefixTlv::decode_value(&wire[4..]), Some(tlv.clone()));
    // Sub-TLV region survives the round trip.
    let with_sub = EPrefixTlv {
        sub_tlvs: vec![0, 4, 0, 4, 1, 2, 3, 4],
        ..tlv.clone()
    };
    let mut w2 = Vec::new();
    with_sub.encode_into(&mut w2, TLV_INTRA_AREA_PREFIX);
    assert_eq!(EPrefixTlv::decode_value(&w2[4..]), Some(with_sub));
    // Truncated below the 8-octet minimum.
    assert_eq!(EPrefixTlv::decode_value(&[0, 0, 0, 1, 0x30]), None);
}

// --- E-Inter-Area-Router TLV (§3.5) --------------------------------

#[test]
fn e_inter_area_router_tlv_wire_and_round_trip() {
    let body = EInterAreaRouterLsaBody(EInterAreaRouterTlv {
        options: 0x00_00_13,
        metric: 20,
        dest_router_id: 0x0a00_0009,
    });
    let mut wire = Vec::new();
    body.encode(&mut wire);
    assert_eq!(
        wire,
        [
            0x00, 0x04, 0x00, 0x0C, // Inter-Area-Router TLV, length 12
            0x00, 0x00, 0x00, 0x13, // 0 + options
            0x00, 0x00, 0x00, 0x14, // 0 + metric 20
            0x0A, 0x00, 0x00, 0x09, // destination router ID
        ]
    );
    assert_eq!(EInterAreaRouterLsaBody::decode(&wire), Some(body));
    // Missing required TLV → malformed (§4.4).
    assert_eq!(
        EInterAreaRouterLsaBody::decode(&[0x00, 0x02, 0x00, 0x04, 1, 2, 3, 4]),
        None
    );
}

// --- External-Prefix TLV (§3.6) ------------------------------------

#[test]
fn e_as_external_lsa_wire_and_round_trip() {
    let body = EAsExternalLsaBody(EExternalPrefixTlv {
        e_bit: true,
        metric: 10,
        prefix: v6_prefix(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0], 48, 0),
        ipv6_fwd_addr: Some([
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
        ]),
        ipv4_fwd_addr: None,
        route_tag: Some(0xDEAD_BEEF),
    });
    let mut wire = Vec::new();
    body.encode(&mut wire);
    // TLV header: value = 4 (flags+metric) + 12 (prefix) + 20
    // (IPv6-FA sub-TLV) + 8 (Route-Tag sub-TLV) = 44 octets.
    assert_eq!(&wire[..4], &[0x00, 0x05, 0x00, 0x2C]);
    assert_eq!(&wire[4..8], &[0x04, 0x00, 0x00, 0x0A]); // E-bit + metric 10
    assert_eq!(EAsExternalLsaBody::decode(&wire), Some(body));
    // E-bit clear, no optional sub-TLVs.
    let plain = EAsExternalLsaBody(EExternalPrefixTlv {
        e_bit: false,
        metric: 0xFFFFFF,
        prefix: v6_prefix(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0], 48, 0),
        ipv6_fwd_addr: None,
        ipv4_fwd_addr: None,
        route_tag: None,
    });
    let mut w2 = Vec::new();
    plain.encode(&mut w2);
    assert_eq!(&w2[4..8], &[0x00, 0xFF, 0xFF, 0xFF]);
    assert_eq!(EAsExternalLsaBody::decode(&w2), Some(plain));
    // First instance of a repeated sub-TLV wins (§3.10-§3.12).
    let mut dup = wire.clone();
    dup[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x0A]); // clear the E-bit
    dup.extend_from_slice(&[0x00, 0x03, 0x00, 0x04, 0, 0, 0, 1]); // second Route-Tag
    let decoded = EAsExternalLsaBody::decode(&dup).unwrap();
    assert_eq!(decoded.0.route_tag, Some(0xDEAD_BEEF));
    assert!(!decoded.0.e_bit);
    // A too-short forwarding-address sub-TLV is malformed (§3.10).
    let bad = [
        0x00, 0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x0A, 0x30, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0D,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x0A, 0x0B,
    ];
    assert_eq!(EAsExternalLsaBody::decode(&bad), None);
}

// --- E-Link-LSA (§4.7) ---------------------------------------------

#[test]
fn e_link_lsa_wire_and_round_trip() {
    let body = ELinkLsaBody {
        priority: 1,
        options: 0x00_00_13,
        link_local: [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        link_local_v4: None,
        prefixes: vec![EPrefixTlv {
            metric: 0,
            prefix: v6_prefix(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0], 64, 0),
            sub_tlvs: Vec::new(),
        }],
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    assert_eq!(
        wire[..8],
        [
            0x01, 0x00, 0x00, 0x13, // priority + options
            0x00, 0x07, 0x00, 0x10, // IPv6 Link-Local Address TLV, length 16
        ]
    );
    assert_eq!(wire.len(), 8 + 16 + 4 + 16);
    assert_eq!(&wire[24..28], &[0x00, 0x06, 0x00, 0x10]);
    assert_eq!(ELinkLsaBody::decode(&wire), Some(body));
    // Missing IPv6 link-local TLV → malformed (§4.7, IPv6 AF):
    // header + only the IPv4 LL TLV.
    let no_ll = vec![
        0x01, 0x00, 0x00, 0x13, // header
        0x00, 0x08, 0x00, 0x04, 0x0A, 0x00, 0x00, 0x01, // only the IPv4 LL TLV
    ];
    assert_eq!(ELinkLsaBody::decode(&no_ll), None);
}

// --- E-Intra-Area-Prefix-LSA (§4.8) --------------------------------

#[test]
fn e_intra_area_prefix_lsa_wire_and_round_trip() {
    let body = EIntraAreaPrefixLsaBody {
        ref_type: LS_TYPE_E_ROUTER,
        ref_ls_id: 0,
        ref_adv_router: 0x0a00_0001,
        prefixes: vec![EPrefixTlv {
            metric: 0,
            prefix: v6_prefix(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0], 64, 0x02),
            sub_tlvs: Vec::new(),
        }],
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    assert_eq!(
        wire[..16],
        [
            0x00, 0x00, // reserved
            0xA0, 0x21, // referenced LS type = E-Router-LSA
            0x00, 0x00, 0x00, 0x00, // referenced LS ID
            0x0A, 0x00, 0x00, 0x01, // referenced advertising router
            0x00, 0x06, 0x00, 0x10, // Intra-Area-Prefix TLV, length 16
        ]
    );
    assert_eq!(EIntraAreaPrefixLsaBody::decode(&wire), Some(body.clone()));
    // Multiple prefix TLVs round-trip.
    let multi = EIntraAreaPrefixLsaBody {
        prefixes: vec![body.prefixes[0].clone(), body.prefixes[0].clone()],
        ..body.clone()
    };
    let mut w2 = Vec::new();
    multi.encode(&mut w2);
    assert_eq!(EIntraAreaPrefixLsaBody::decode(&w2), Some(multi));
}

// --- Origination helpers -------------------------------------------

#[test]
fn originate_e_router_lsa_header_and_sequence() {
    let l1 = originate_v3_e_router_lsa(
        0x0a00_0001,
        0x04,
        0x13,
        vec![ERouterLinkTlv {
            link_type: 1,
            metric: 1,
            interface_id: 3,
            neighbor_interface_id: 4,
            neighbor_router_id: 0x0a00_0002,
            sub_tlvs: Vec::new(),
        }],
        None,
    )
    .unwrap();
    assert_eq!(l1.header.ls_type, LS_TYPE_E_ROUTER);
    assert_eq!(l1.header.link_state_id, 0);
    assert_eq!(l1.header.advertising_router, 0x0a00_0001);
    assert_eq!(l1.header.ls_sequence_number, 0x8000_0001);
    assert!(lsa_checksum_ok(&l1));
    // The 16-bit LS type occupies header bytes 2-3 on the wire.
    let wire = l1.to_wire();
    assert_eq!(&wire[2..4], &[0xA0, 0x21]);
    // Re-origination advances the sequence.
    let l2 = originate_v3_e_router_lsa(
        0x0a00_0001,
        0x04,
        0x13,
        vec![],
        Some(l1.header.ls_sequence_number),
    )
    .unwrap();
    assert_eq!(l2.header.ls_sequence_number, 0x8000_0002);
    assert!(lsa_checksum_ok(&l2));
    assert!(ERouterLsaBody::decode(&l2.body).unwrap().links.is_empty());
}

#[test]
fn originate_e_link_and_iap_lsas() {
    let link = originate_v3_e_link_lsa(
        0x0a00_0001,
        7, // interface id / LS ID
        1,
        0x13,
        [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        vec![EPrefixTlv {
            metric: 0,
            prefix: v6_prefix(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0], 64, 0x02),
            sub_tlvs: Vec::new(),
        }],
        None,
    )
    .unwrap();
    assert_eq!(link.header.ls_type, LS_TYPE_E_LINK);
    assert_eq!(link.header.link_state_id, 7);
    assert_eq!(&link.to_wire()[2..4], &[0x80, 0x28]); // link scope bits
    assert!(lsa_checksum_ok(&link));
    let decoded = ELinkLsaBody::decode(&link.body).unwrap();
    assert_eq!(decoded.link_local[0], 0xFE);
    assert_eq!(decoded.prefixes.len(), 1);

    let iap = originate_v3_e_intra_area_prefix_lsa(
        0x0a00_0001,
        1,
        LS_TYPE_E_ROUTER,
        0,
        0x0a00_0001,
        vec![EPrefixTlv {
            metric: 0,
            prefix: v6_prefix(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0], 64, 0),
            sub_tlvs: Vec::new(),
        }],
        None,
    )
    .unwrap();
    assert_eq!(iap.header.ls_type, LS_TYPE_E_INTRA_PREFIX);
    assert_eq!(&iap.to_wire()[2..4], &[0xA0, 0x29]);
    assert!(lsa_checksum_ok(&iap));
}

#[test]
fn originate_e_inter_area_and_external_lsas() {
    use lr_core::addr::Prefix;
    let iap = originate_v3_e_inter_area_prefix_lsa(
        0x0a00_0001,
        1,
        20,
        &Prefix::new_v6(
            [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            48,
        ),
        None,
    )
    .unwrap();
    assert_eq!(iap.header.ls_type, LS_TYPE_E_INTER_PREFIX);
    assert_eq!(&iap.to_wire()[2..4], &[0xA0, 0x23]);
    assert!(lsa_checksum_ok(&iap));
    let decoded = EInterAreaPrefixLsaBody::decode(&iap.body).unwrap();
    assert_eq!(decoded.0.metric, 20);
    assert_eq!(decoded.0.prefix.prefix_len, 48);
    // Metric is capped just below LSInfinity.
    let big = originate_v3_e_inter_area_prefix_lsa(
        0x0a00_0001,
        2,
        0xFFFF_FFFF,
        &Prefix::new_v6(
            [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            48,
        ),
        None,
    )
    .unwrap();
    assert_eq!(
        EInterAreaPrefixLsaBody::decode(&big.body).unwrap().0.metric,
        0x00ff_fffe
    );
    // Non-IPv6 prefixes refuse to originate.
    assert!(originate_v3_e_inter_area_prefix_lsa(
        0x0a00_0001,
        3,
        1,
        &Prefix::new_v4([10, 0, 0, 0], 24),
        None
    )
    .is_none());

    let iar =
        originate_v3_e_inter_area_router_lsa(0x0a00_0001, 0x0a00_0009, 0x13, 0x0a00_0009, 30, None)
            .unwrap();
    assert_eq!(iar.header.ls_type, LS_TYPE_E_INTER_ROUTER);
    assert_eq!(&iar.to_wire()[2..4], &[0xA0, 0x24]);
    assert!(lsa_checksum_ok(&iar));

    let dest = crate::lsa::v3::V3ExternalDestination::new(
        Prefix::new_v6(
            [
                0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
            ],
            64,
        ),
        100,
        true,
    );
    let ext =
        originate_v3_e_as_external_lsa(LS_TYPE_E_AS_EXTERNAL, 0x0a00_0001, 1, &dest, None).unwrap();
    assert_eq!(ext.header.ls_type, LS_TYPE_E_AS_EXTERNAL);
    assert_eq!(&ext.to_wire()[2..4], &[0xC0, 0x25]); // AS scope + U-bit
    assert!(lsa_checksum_ok(&ext));
    let decoded = EAsExternalLsaBody::decode(&ext.body).unwrap();
    assert!(decoded.0.e_bit);
    assert_eq!(decoded.0.metric, 100);
    // The E-Type-7 form shares the body.
    let t7 = originate_v3_e_as_external_lsa(LS_TYPE_E_TYPE_7, 0x0a00_0001, 1, &dest, None).unwrap();
    assert_eq!(t7.header.ls_type, LS_TYPE_E_TYPE_7);
    assert_eq!(&t7.to_wire()[2..4], &[0xA0, 0x27]);
    // Any other LS type is refused.
    assert!(originate_v3_e_as_external_lsa(0x2001, 1, 1, &dest, None).is_none());
}

#[test]
fn e_network_origination_and_is_e_lsa_type() {
    let net = originate_v3_e_network_lsa(
        0x0a00_0001,
        9, // DR interface id / LS ID
        0x13,
        &[0x0a00_0001, 0x0a00_0002],
        None,
    )
    .unwrap();
    assert_eq!(net.header.ls_type, LS_TYPE_E_NETWORK);
    assert_eq!(net.header.link_state_id, 9);
    assert_eq!(&net.to_wire()[2..4], &[0xA0, 0x22]);
    assert!(lsa_checksum_ok(&net));
    assert_eq!(
        ENetworkLsaBody::decode(&net.body).unwrap().routers,
        vec![0x0a00_0001, 0x0a00_0002]
    );

    for t in [
        LS_TYPE_E_ROUTER,
        LS_TYPE_E_NETWORK,
        LS_TYPE_E_INTER_PREFIX,
        LS_TYPE_E_INTER_ROUTER,
        LS_TYPE_E_AS_EXTERNAL,
        LS_TYPE_E_TYPE_7,
        LS_TYPE_E_LINK,
        LS_TYPE_E_INTRA_PREFIX,
    ] {
        assert!(is_e_lsa_type(t), "{t:#06x} should classify as an E-LSA");
    }
    // Function code 38 stays unallocated; legacy types are not E-LSAs.
    assert!(!is_e_lsa_type(0xA026));
    assert!(!is_e_lsa_type(crate::lsa::v3::LS_TYPE_ROUTER));
    assert!(!is_e_lsa_type(crate::lsa::v3::LS_TYPE_INTRA_PREFIX));
}

fn lsa_checksum_ok(lsa: &Lsa) -> bool {
    lsa.checksum_ok()
}
