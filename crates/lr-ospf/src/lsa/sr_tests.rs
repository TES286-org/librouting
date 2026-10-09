use super::*;

fn sample_advert() -> SrPrefixAdvert {
    SrPrefixAdvert {
        route_type: 1, // intra-area
        flags: 0x40,   // N-flag: prefix is a node segment
        prefix: [10, 0, 0, 0],
        prefix_len: 24,
        sid_flags: sid_flags::NP,
        sid: 100,
        algorithm: 0,
    }
}

#[test]
fn ext_prefix_tlv_wire_shape_matches_rfc7684_8665() {
    let wire = sample_advert().encode_ext_prefix_tlv();
    // TLV type 1, length 20 (8 descriptor + 4 prefix + 12
    // sub-TLV) — the body is a multiple of 4 without padding.
    assert_eq!(&wire[0..2], &[0, 1]);
    assert_eq!(&wire[2..4], &20u16.to_be_bytes());
    // RFC 7684 §2.1: route_type, prefix_len, af, flags.
    assert_eq!(wire[4], 1);
    assert_eq!(wire[5], 24);
    assert_eq!(wire[6], 0);
    assert_eq!(wire[7], 0x40);
    // Prefix.
    assert_eq!(&wire[8..12], &[10, 0, 0, 0]);
    // Prefix-SID sub-TLV: type 2, len 8.
    assert_eq!(&wire[12..14], &[0, 2]);
    assert_eq!(&wire[14..16], &[0, 8]);
    // RFC 8665 §5: flags, reserved, MT-ID, algorithm, SID/Index(4).
    assert_eq!(wire[16], 0x40); // NP
    assert_eq!(wire[17], 0); // reserved
    assert_eq!(wire[18], 0); // MT-ID
    assert_eq!(wire[19], 0); // algorithm
                             // SID 100 as a 4-octet index.
    assert_eq!(&wire[20..24], &100u32.to_be_bytes());
    assert_eq!(wire.len(), 24);
}

#[test]
fn ext_prefix_lsa_roundtrip() {
    let wire = encode_ext_prefix_lsa_body(&sample_advert());
    let decoded = decode_ext_prefix_lsa_body(&wire).expect("decode");
    assert_eq!(decoded.len(), 1);
    let (core, sid) = &decoded[0];
    assert_eq!(core.route_type, 1);
    assert_eq!(core.flags, 0x40);
    assert_eq!(core.prefix, [10, 0, 0, 0]);
    assert_eq!(core.prefix_len, 24);
    let sid = sid.as_ref().expect("prefix-sid sub-TLV present");
    assert_eq!(sid.flags, sid_flags::NP);
    assert_eq!(sid.mt_id, 0);
    assert_eq!(sid.algorithm, 0);
    assert_eq!(sid.sid, 100);
}

#[test]
fn ext_prefix_lsa_decode_skips_unknown_subtlvs_and_tlbs() {
    // Extended Prefix TLV with the Prefix-SID sub-TLV followed by
    // an unknown sub-TLV (type 0xBEEF): the SID still decodes, the
    // unknown one is skipped per RFC 8665 §9. Value length: 8
    // (descriptor + prefix) + 12 (SID sub-TLV) + 8 (unknown, 1
    // octet value padded to 4) = 28.
    let mut wire = Vec::new();
    wire.extend_from_slice(&TLV_EXT_PREFIX.to_be_bytes());
    wire.extend_from_slice(&28u16.to_be_bytes());
    wire.extend_from_slice(&[1, 32, 0, 0]);
    wire.extend_from_slice(&[192, 0, 2, 9]);
    wire.extend_from_slice(&SUBTLV_PREFIX_SID.to_be_bytes());
    wire.extend_from_slice(&8u16.to_be_bytes());
    wire.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 200]);
    wire.extend_from_slice(&[0xBE, 0xEF, 0, 1, 0xAA, 0, 0, 0]);
    let decoded = decode_ext_prefix_lsa_body(&wire).expect("decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].0.prefix, [192, 0, 2, 9]);
    assert_eq!(decoded[0].1.as_ref().expect("sid").sid, 200);
}

#[test]
fn ext_prefix_lsa_decode_local_label_shape() {
    // RFC 8665 §5 length-7 shape: a 3-octet local label (V/L set).
    let mut wire = Vec::new();
    wire.extend_from_slice(&TLV_EXT_PREFIX.to_be_bytes());
    wire.extend_from_slice(&20u16.to_be_bytes());
    wire.extend_from_slice(&[1, 32, 0, 0]);
    wire.extend_from_slice(&[192, 0, 2, 9]);
    wire.extend_from_slice(&SUBTLV_PREFIX_SID.to_be_bytes());
    wire.extend_from_slice(&7u16.to_be_bytes());
    wire.extend_from_slice(&[sid_flags::V | sid_flags::L, 0, 0, 0]);
    wire.extend_from_slice(&[0x00, 0x01, 0x02, 0]); // label + pad
    let decoded = decode_ext_prefix_lsa_body(&wire).expect("decode");
    let sid = decoded[0].1.as_ref().expect("sid");
    assert_eq!(sid.sid, 0x000102);
}

#[test]
fn ext_prefix_lsa_decode_without_prefix_sid_subtlv_yields_none_sid() {
    // RFC 7684 shape without any sub-TLV: the prefix descriptor
    // alone is valid; no SID means no label mapping.
    let mut wire = Vec::new();
    wire.extend_from_slice(&TLV_EXT_PREFIX.to_be_bytes());
    wire.extend_from_slice(&8u16.to_be_bytes());
    wire.extend_from_slice(&[1, 24, 0, 0x40, 10, 0, 0, 0]);
    let decoded = decode_ext_prefix_lsa_body(&wire).expect("decode");
    assert!(decoded[0].1.is_none());
}

#[test]
fn ri_sr_lsa_wire_shape_matches_rfc8665() {
    let wire = encode_ri_sr_lsa_body(16_000, 8_000).expect("encode");
    // SR-Algorithm TLV: type 8, len 1, value 0, 3 padding.
    assert_eq!(&wire[0..2], &[0, 8]);
    assert_eq!(&wire[2..4], &[0, 1]);
    assert_eq!(wire[4], 0);
    assert_eq!(&wire[5..8], &[0, 0, 0]);
    // SID/Label Range TLV: type 9, len 12 — range size (3),
    // reserved (1), SID/Label sub-TLV (type 1, len 4, base).
    assert_eq!(&wire[8..10], &[0, 9]);
    assert_eq!(&wire[10..12], &12u16.to_be_bytes());
    assert_eq!(&wire[12..15], &8_000u32.to_be_bytes()[1..4]);
    assert_eq!(wire[15], 0); // reserved
    assert_eq!(&wire[16..18], &[0, 1]);
    assert_eq!(&wire[18..20], &4u16.to_be_bytes());
    assert_eq!(&wire[20..24], &16_000u32.to_be_bytes());
    assert_eq!(wire.len(), 24);
}

#[test]
fn ri_sr_lsa_roundtrip() {
    let wire = encode_ri_sr_lsa_body(16_000, 8_000).expect("encode");
    let block = decode_ri_sr_lsa_body(&wire)
        .expect("decode")
        .expect("SR node");
    assert_eq!(
        block,
        RiSrBlock {
            srgb_base: 16_000,
            srgb_range: 8_000
        }
    );
}

#[test]
fn ri_sr_lsa_without_srgb_is_not_an_sr_node() {
    // Only the algorithm TLV: no SRGB → Ok(None).
    let mut wire = Vec::new();
    wire.extend_from_slice(&TLV_SR_ALGORITHM.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.push(0);
    wire.extend_from_slice(&[0, 0, 0]);
    assert_eq!(decode_ri_sr_lsa_body(&wire), Some(None));
}

#[test]
fn ri_sr_lsa_rejects_invalid_srgb() {
    // Base below the label-space floor.
    assert!(encode_ri_sr_lsa_body(15, 8_000).is_none());
    // Range overflows the 20-bit label space.
    assert!(encode_ri_sr_lsa_body(1_048_500, 8_000).is_none());
}

#[test]
fn remote_label_math() {
    let srgb = RiSrBlock {
        srgb_base: 16_000,
        srgb_range: 8_000,
    };
    let sid = SrPrefixSidTlv {
        flags: 0,
        mt_id: 0,
        algorithm: 0,
        sid: 100,
    };
    assert_eq!(remote_label(&srgb, &sid), Some(16_100));
    // Index out of the SRGB range: discarded.
    let sid = SrPrefixSidTlv {
        flags: 0,
        mt_id: 0,
        algorithm: 0,
        sid: 8_001,
    };
    assert_eq!(remote_label(&srgb, &sid), None);
    // V/L flagged (absolute/local): not a global index mapping.
    let sid = SrPrefixSidTlv {
        flags: sid_flags::V | sid_flags::L,
        mt_id: 0,
        algorithm: 0,
        sid: 100,
    };
    assert_eq!(remote_label(&srgb, &sid), None);
}

#[test]
fn originate_prefix_lsa_is_finalized_area_opaque_type7() {
    let lsa = originate_sr_prefix_lsa(0x0a00_0001, &sample_advert(), 0, None).expect("originate");
    assert_eq!(lsa.header.ls_type, LsaTypeV2::OpaqueAreaLsa as u16);
    assert_eq!(
        (lsa.header.link_state_id >> 24) as u8,
        OPAQUE_TYPE_EXT_PREFIX
    );
    assert_eq!(lsa.header.options, 0x02 | OPTIONS_O_BIT);
    assert_eq!(lsa.header.advertising_router, 0x0a00_0001);
    assert!(lsa.header.length >= LsaHeader::LEN as u16);
    assert!(lsa.checksum_ok());
    // The body decodes back to the advertised prefix.
    let decoded = decode_ext_prefix_lsa_body(&lsa.body).expect("decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].0.prefix, [10, 0, 0, 0]);
    assert_eq!(decoded[0].1.as_ref().expect("sid").sid, 100);
}

#[test]
fn originate_ri_lsa_is_finalized_area_opaque_type4() {
    let lsa = originate_sr_ri_lsa(0x0a00_0001, 16_000, 8_000, None).expect("originate");
    assert_eq!(lsa.header.ls_type, LsaTypeV2::OpaqueAreaLsa as u16);
    assert_eq!((lsa.header.link_state_id >> 24) as u8, OPAQUE_TYPE_RI);
    assert!(lsa.checksum_ok());
    let block = decode_ri_sr_lsa_body(&lsa.body)
        .expect("decode")
        .expect("SR block");
    assert_eq!(block.srgb_base, 16_000);
    assert_eq!(block.srgb_range, 8_000);
}

#[test]
fn sequence_handling_matches_grace_lsa_originator() {
    // First origination starts at INITIAL_SEQUENCE_NUMBER; a
    // refresh advances by one.
    let first = originate_sr_prefix_lsa(1, &sample_advert(), 0, None).expect("first");
    let next = originate_sr_prefix_lsa(
        1,
        &sample_advert(),
        0,
        Some(first.header.ls_sequence_number),
    )
    .expect("next");
    assert_eq!(
        next.header.ls_sequence_number,
        first.header.ls_sequence_number + 1
    );
    // Sequence exhaustion returns None (§12.1.2).
    assert!(originate_sr_prefix_lsa(1, &sample_advert(), 0, Some(MAX_SEQUENCE_NUMBER)).is_none());
    assert!(originate_sr_ri_lsa(1, 16_000, 8_000, Some(MAX_SEQUENCE_NUMBER)).is_none());
}

// -------------------------------------------------------------
// RFC 8665 §6: Adj-SID / LAN Adj-SID sub-TLVs + Extended Link LSA
// -------------------------------------------------------------

/// A p2p link to neighbour 2.2.2.2 over 10.0.0.1 carrying one
/// local (V/L) adjacency SID 24001 — the shape lr originates.
fn sample_link() -> (SrLinkAdvert, Vec<SrAdjSidTlv>) {
    (
        SrLinkAdvert {
            link_type: link_type::POINT_TO_POINT,
            link_id: [2, 2, 2, 2],
            link_data: [10, 0, 0, 1],
        },
        vec![SrAdjSidTlv {
            flags: adj_flags::V | adj_flags::L | adj_flags::P,
            mt_id: 0,
            weight: 0,
            sid: 24001,
            neighbor_id: None,
        }],
    )
}

#[test]
fn adj_sid_subtlv_wire_shape_matches_rfc8665_6_1() {
    let (advert, sids) = sample_link();
    let wire = encode_ext_link_tlv(&advert, &sids);
    // TLV type 1, unpadded length 24: 12 descriptor + 12 sub-TLV
    // (4 header + 8 body: flags, rsvd, mt-id, weight, 3-octet
    // label + 1 pad — the length field excludes the pad,
    // RFC 7684 §2.3).
    assert_eq!(&wire[0..2], &[0, 1]);
    assert_eq!(&wire[2..4], &24u16.to_be_bytes());
    // RFC 7684 §3.1: link_type, reserved(3), link_id, link_data.
    assert_eq!(wire[4], link_type::POINT_TO_POINT);
    assert_eq!(&wire[5..8], &[0, 0, 0]);
    assert_eq!(&wire[8..12], &[2, 2, 2, 2]);
    assert_eq!(&wire[12..16], &[10, 0, 0, 1]);
    // Adj-SID sub-TLV: type 2, length 7 (3-octet label shape).
    assert_eq!(&wire[16..18], &[0, 2]);
    assert_eq!(&wire[18..20], &7u16.to_be_bytes());
    // RFC 8665 §6.1: flags (V|L|P), reserved, MT-ID, weight,
    // SID/Index/Label (3 octets) + pad.
    assert_eq!(wire[20], adj_flags::V | adj_flags::L | adj_flags::P);
    assert_eq!(wire[21], 0); // reserved
    assert_eq!(wire[22], 0); // MT-ID
    assert_eq!(wire[23], 0); // weight
    assert_eq!(&wire[24..27], &24001u32.to_be_bytes()[1..4]);
    assert_eq!(wire[27], 0); // 4-alignment pad
                             // The TLV is padded to a 4-octet multiple.
    assert_eq!(wire.len(), 28);
}

#[test]
fn adj_sid_subtlv_index_shape_is_length_8() {
    // V/L clear: the 4-octet global index shape (RFC 8665 §6.1).
    let (advert, mut sids) = sample_link();
    sids[0].flags = adj_flags::P;
    let wire = encode_ext_link_tlv(&advert, &sids);
    assert_eq!(&wire[18..20], &8u16.to_be_bytes());
    assert_eq!(wire[20], adj_flags::P);
    assert_eq!(&wire[24..28], &24001u32.to_be_bytes());
    assert_eq!(wire.len(), 28); // no padding needed
}

#[test]
fn lan_adj_sid_subtlv_wire_shape_matches_rfc8665_6_2() {
    let (advert, _) = sample_link();
    let lan = SrAdjSidTlv {
        flags: adj_flags::V | adj_flags::L | adj_flags::P,
        mt_id: 0,
        weight: 0,
        sid: 24002,
        neighbor_id: Some([3, 3, 3, 3]),
    };
    let wire = encode_ext_link_tlv(&advert, &[lan]);
    // LAN sub-TLV: type 3, length 11 (label shape + neighbour ID).
    assert_eq!(&wire[16..18], &[0, 3]);
    assert_eq!(&wire[18..20], &11u16.to_be_bytes());
    assert_eq!(&wire[24..28], &[3, 3, 3, 3]); // neighbour router id
    assert_eq!(&wire[28..31], &24002u32.to_be_bytes()[1..4]);
    assert_eq!(wire[31], 0); // pad
    assert_eq!(wire.len(), 32);
}

#[test]
fn ext_link_lsa_roundtrip() {
    let (advert, sids) = sample_link();
    let wire = encode_ext_link_lsa_body(&[(advert, sids)]);
    let decoded = decode_ext_link_lsa_body(&wire).expect("decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].0, sample_link().0);
    assert_eq!(decoded[0].1.len(), 1);
    let sid = &decoded[0].1[0];
    assert_eq!(sid.flags, adj_flags::V | adj_flags::L | adj_flags::P);
    assert_eq!(sid.sid, 24001);
    assert_eq!(sid.neighbor_id, None);
    assert!(!sid.is_lan());
    // The LSA body is a 4-octet multiple (RFC 2328 LSA shape).
    assert_eq!(wire.len() % 4, 0);
}

#[test]
fn ext_link_lsa_decode_accepts_index_and_label_lengths() {
    // FRR walks sub-TLVs with a 4-rounded body size: both the
    // index shape (length 8) and the label shape (length 7) must
    // decode, with the label read from the 20 rightmost bits.
    // Label shape: type 2, length 7.
    let mut value = Vec::new();
    value.extend_from_slice(&[link_type::POINT_TO_POINT, 0, 0, 0]);
    value.extend_from_slice(&[2, 2, 2, 2]);
    value.extend_from_slice(&[10, 0, 0, 1]);
    value.extend_from_slice(&SUBTLV_ADJ_SID.to_be_bytes());
    value.extend_from_slice(&7u16.to_be_bytes());
    value.extend_from_slice(&[adj_flags::V | adj_flags::L, 0, 0, 0]);
    value.extend_from_slice(&[0x00, 0x5D, 0xC1, 0]); // 24001 + pad
    let decoded = decode_ext_link_tlv_value(&value).expect("decode");
    assert_eq!(decoded.1.len(), 1);
    assert_eq!(decoded.1[0].sid, 24001);
    assert_eq!(decoded.1[0].flags, adj_flags::V | adj_flags::L);
    assert_eq!(decoded.1[0].neighbor_id, None);
}

#[test]
fn ext_link_lsa_decode_skips_unknown_subtlvs() {
    // An Adj-SID followed by an unknown sub-TLV (type 0xBEEF):
    // the SID still decodes, the unknown one is skipped per
    // RFC 8665 §9.
    let mut value = Vec::new();
    // 12 descriptor + 12 (padded label sub-TLV) + 8 unknown.
    value.extend_from_slice(&[link_type::POINT_TO_POINT, 0, 0, 0]);
    value.extend_from_slice(&[2, 2, 2, 2]);
    value.extend_from_slice(&[10, 0, 0, 1]);
    value.extend_from_slice(&SUBTLV_ADJ_SID.to_be_bytes());
    value.extend_from_slice(&7u16.to_be_bytes());
    value.extend_from_slice(&[adj_flags::V | adj_flags::L, 0, 0, 0]);
    value.extend_from_slice(&[0x00, 0x5D, 0xC1, 0]); // 24001 + pad
    value.extend_from_slice(&[0xBE, 0xEF, 0, 1, 0xAA, 0, 0, 0]);
    let decoded = decode_ext_link_tlv_value(&value).expect("decode");
    assert_eq!(decoded.1.len(), 1);
    assert_eq!(decoded.1[0].sid, 24001);
}

#[test]
fn ext_link_lsa_decode_lan_shape_roundtrip() {
    let (advert, _) = sample_link();
    let lan = SrAdjSidTlv {
        flags: adj_flags::P,
        mt_id: 0,
        weight: 5,
        sid: 24002,
        neighbor_id: Some([3, 3, 3, 3]),
    };
    let wire = encode_ext_link_lsa_body(&[(advert, vec![lan])]);
    let decoded = decode_ext_link_lsa_body(&wire).expect("decode");
    assert_eq!(decoded[0].1.len(), 1);
    let sid = &decoded[0].1[0];
    assert!(sid.is_lan());
    assert_eq!(sid.neighbor_id, Some([3, 3, 3, 3]));
    assert_eq!(sid.weight, 5);
    assert_eq!(sid.sid, 24002); // V/L clear: index preserved verbatim
}

#[test]
fn ext_link_lsa_decode_malformed_length_aborts() {
    // A TLV length running past the body aborts the walk.
    let mut wire = Vec::new();
    wire.extend_from_slice(&TLV_EXT_LINK.to_be_bytes());
    wire.extend_from_slice(&100u16.to_be_bytes()); // > actual body
    wire.extend_from_slice(&[link_type::POINT_TO_POINT, 0, 0, 0]);
    assert!(decode_ext_link_lsa_body(&wire).is_none());
}

#[test]
fn originate_link_lsa_is_finalized_area_opaque_type8() {
    let (advert, sids) = sample_link();
    let lsa = originate_sr_link_lsa(0x0a00_0001, &[(advert, sids)], 1, None).expect("originate");
    assert_eq!(lsa.header.ls_type, LsaTypeV2::OpaqueAreaLsa as u16);
    assert_eq!((lsa.header.link_state_id >> 24) as u8, OPAQUE_TYPE_EXT_LINK);
    assert_eq!(lsa.header.options, 0x02 | OPTIONS_O_BIT);
    assert!(lsa.header.length.is_multiple_of(4));
    assert!(lsa.checksum_ok());
    let decoded = decode_ext_link_lsa_body(&lsa.body).expect("decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].0.link_id, [2, 2, 2, 2]);
    assert_eq!(decoded[0].1[0].sid, 24001);
    // An empty link list is never originated.
    assert!(originate_sr_link_lsa(1, &[], 2, None).is_none());
    // Sequence exhaustion returns None (§12.1.2).
    assert!(originate_sr_link_lsa(1, &[sample_link()], 2, Some(MAX_SEQUENCE_NUMBER)).is_none());
}

#[test]
fn adj_sid_remote_label_resolves_local_and_global_shapes() {
    let srgb = RiSrBlock {
        srgb_base: 16_000,
        srgb_range: 8_000,
    };
    // V/L set: the SID *is* the absolute label (SRLB, local).
    let local = SrAdjSidTlv {
        flags: adj_flags::V | adj_flags::L,
        mt_id: 0,
        weight: 0,
        sid: 24001,
        neighbor_id: None,
    };
    assert_eq!(local.remote_label(&srgb), Some(24001));
    // V/L clear: index into the originator's SRGB.
    let global = SrAdjSidTlv {
        flags: 0,
        mt_id: 0,
        weight: 0,
        sid: 100,
        neighbor_id: None,
    };
    assert_eq!(global.remote_label(&srgb), Some(16_100));
    // Index outside the advertised range: discarded.
    let out_of_range = SrAdjSidTlv {
        flags: 0,
        mt_id: 0,
        weight: 0,
        sid: 8_001,
        neighbor_id: None,
    };
    assert_eq!(out_of_range.remote_label(&srgb), None);
}

// -------------------------------------------------------------
// RFC 8665 §4: Extended Prefix Range TLV (SR Mapping Server)
// -------------------------------------------------------------

/// A mapping-server range: prefixes 10.77.0.0/24 .. 10.77.0.3/24
/// (range size 4), first index 500, M-flag set.
fn sample_range() -> (SrPrefixRangeCore, SrPrefixSidTlv) {
    (
        SrPrefixRangeCore {
            prefix_len: 24,
            range_size: 4,
            flags: 0x00,
            prefix: [10, 77, 0, 0],
        },
        SrPrefixSidTlv {
            flags: sid_flags::M | sid_flags::NP,
            mt_id: 0,
            algorithm: 0,
            sid: 500,
        },
    )
}

#[test]
fn ext_prefix_range_tlv_wire_shape_matches_rfc8665_4() {
    let (range, sid) = sample_range();
    let wire = encode_ext_prefix_range_tlv(&range, &sid);
    // TLV type 2 (the Extended Prefix LSA TLV registry), value
    // length 24: 12 descriptor + 12 sub-TLV.
    assert_eq!(&wire[0..2], &[0, 2]);
    assert_eq!(&wire[2..4], &24u16.to_be_bytes());
    // RFC 8665 §4: prefix_len, af, range_size(2), flags,
    // reserved(3), prefix.
    assert_eq!(wire[4], 24);
    assert_eq!(wire[5], 0); // AF IPv4 unicast
    assert_eq!(&wire[6..8], &4u16.to_be_bytes());
    assert_eq!(wire[8], 0); // IA clear
    assert_eq!(&wire[9..12], &[0, 0, 0]); // reserved
    assert_eq!(&wire[12..16], &[10, 77, 0, 0]);
    // Prefix-SID sub-TLV: type 2, length 8.
    assert_eq!(&wire[16..18], &[0, 2]);
    assert_eq!(&wire[18..20], &8u16.to_be_bytes());
    // M-flag + NP set, algorithm 0, index 500 (first prefix).
    assert_eq!(wire[20], sid_flags::M | sid_flags::NP);
    assert_eq!(wire[21], 0);
    assert_eq!(wire[22], 0); // MT-ID
    assert_eq!(wire[23], 0); // algorithm
    assert_eq!(&wire[24..28], &500u32.to_be_bytes());
    assert_eq!(wire.len(), 28);
}

#[test]
fn ext_prefix_range_tlv_roundtrip_and_full_decode() {
    let (range, sid) = sample_range();
    let wire = encode_ext_prefix_range_tlv(&range, &sid);
    let (core, decoded_sid) = decode_ext_prefix_range_tlv_value(&wire[4..]).expect("decode");
    assert_eq!(core, range);
    assert_eq!(decoded_sid, Some(sid));
    // The full decode distinguishes the range shape from the
    // prefix shape.
    let tlvs = decode_ext_prefix_lsa_body_full(&wire).expect("decode");
    assert_eq!(tlvs.len(), 1);
    match &tlvs[0] {
        ExtPrefixTlvAdvert::Range(core, Some(sid)) => {
            assert_eq!(core.range_size, 4);
            assert_eq!(sid.flags & sid_flags::M, sid_flags::M);
            assert_eq!(sid.sid, 500);
        }
        other => panic!("expected Range advert, got {other:?}"),
    }
    // The plain prefix decode skips range TLVs (documented
    // behaviour — mapping-server entries need the full walk).
    assert!(decode_ext_prefix_lsa_body(&wire)
        .expect("decode")
        .is_empty());
}

#[test]
fn originate_prefix_range_lsa_is_finalized_opaque_type7() {
    let (range, sid) = sample_range();
    let lsa =
        originate_sr_prefix_range_lsa(0x0b00_0001, &range, &sid, 21, None).expect("originate");
    assert_eq!(lsa.header.ls_type, LsaTypeV2::OpaqueAreaLsa as u16);
    assert_eq!(
        (lsa.header.link_state_id >> 24) as u8,
        OPAQUE_TYPE_EXT_PREFIX
    );
    assert!(lsa.header.length.is_multiple_of(4));
    assert!(lsa.checksum_ok());
    let tlvs = decode_ext_prefix_lsa_body_full(&lsa.body).expect("decode");
    assert_eq!(tlvs.len(), 1);
    assert!(matches!(tlvs[0], ExtPrefixTlvAdvert::Range(_, Some(_))));
    // Malformed prefix length never originates.
    let bad = SrPrefixRangeCore {
        prefix_len: 40,
        ..range
    };
    assert!(originate_sr_prefix_range_lsa(1, &bad, &sid, 22, None).is_none());
    // Sequence exhaustion returns None (§12.1.2).
    assert!(
        originate_sr_prefix_range_lsa(1, &range, &sid, 23, Some(MAX_SEQUENCE_NUMBER)).is_none()
    );
}
