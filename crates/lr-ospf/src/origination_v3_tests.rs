use super::*;

/// A zeroed pseudo-header checksum input produces a defined value and
/// the verification property holds: summing the finalized packet with
/// the same pseudo-header yields 0xffff.
#[test]
fn v3_checksum_roundtrip() {
    let mut pkt = vec![0u8; 16 + 20];
    pkt[0] = 3; // version
    pkt[1] = 1; // Hello
    let n = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&n.to_be_bytes());
    let src = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0xff_u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    assert!(finalize_v3_packet(&mut pkt, &src, &dst));
    let stored = u16::from_be_bytes([pkt[12], pkt[13]]);
    // Recompute over the finalized packet with the checksum zeroed —
    // the standard one's-complement verification property.
    let mut verify = pkt.clone();
    verify[12] = 0;
    verify[13] = 0;
    assert_eq!(v3_packet_checksum(&verify, &src, &dst), stored);
    // A different pseudo-header must produce a different checksum.
    let dst2 = [0xff_u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6];
    assert_ne!(v3_packet_checksum(&verify, &src, &dst2), stored);
    // Stream finalization walks every packet.
    let mut stream = pkt.clone();
    stream.extend_from_slice(&pkt);
    assert_eq!(finalize_v3_stream(&mut stream, &src, &dst), 2);
}

/// A finalized packet verifies against the same pseudo-header and
/// fails against a different one — the receive-side gate
/// (`v3_packet_checksum_ok`) the codec uses to drop forged or
/// corrupted v3 frames.
#[test]
fn v3_packet_checksum_ok_roundtrip() {
    let mut pkt = vec![0u8; 16 + 20];
    pkt[0] = 3; // version
    pkt[1] = 1; // Hello
    let n = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&n.to_be_bytes());
    let src = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0xff_u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    assert!(finalize_v3_packet(&mut pkt, &src, &dst));
    // Same pseudo-header: verify.
    assert!(
        v3_packet_checksum_ok(&pkt, &src, &dst),
        "finalized packet must verify against its own pseudo-header"
    );
    // A different pseudo-header must fail (the sum no longer folds to 0).
    let dst2 = [0xff_u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6];
    assert!(
        !v3_packet_checksum_ok(&pkt, &src, &dst2),
        "verification against a different pseudo-header must fail"
    );
    // A byte flipped anywhere the checksum covers must break verification.
    let mut bad_body = pkt.clone();
    let last = bad_body.len() - 1;
    bad_body[last] ^= 0x01;
    assert!(
        !v3_packet_checksum_ok(&bad_body, &src, &dst),
        "corruption in the body must fail the verification"
    );
    let mut bad_hdr = pkt.clone();
    bad_hdr[4] ^= 0x01; // router-id byte
    assert!(
        !v3_packet_checksum_ok(&bad_hdr, &src, &dst),
        "corruption in the header (pre-checksum) must fail the verification"
    );
}

/// `v3_packet_checksum_ok` mirrors `v2_packet_checksum_ok`'s short-input
/// contract: a buffer shorter than the 16-byte v3 header returns
/// `false` without panicking (the codec relies on this to keep its
/// streaming drain path simple).
#[test]
fn v3_packet_checksum_ok_short_input() {
    let src = [0u8; 16];
    let dst = [0u8; 16];
    assert!(!v3_packet_checksum_ok(&[], &src, &dst));
    assert!(!v3_packet_checksum_ok(&[0u8; 15], &src, &dst));
    // Exactly 16 bytes passes the length gate; the sum check then runs
    // against a header-only buffer.
    let mut pkt = vec![0u8; 16];
    pkt[0] = 3; // version
    let n = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&n.to_be_bytes());
    // Without a body, finalize_v3_packet leaves the checksum field at
    // whatever finalize computed; verifying the same bytes must pass.
    assert!(finalize_v3_packet(&mut pkt, &src, &dst));
    assert!(v3_packet_checksum_ok(&pkt, &src, &dst));
}

/// `lr_ospf::origination` re-exports every v3 LSA origination helper
/// (RFC 5340 fixed-format LSAs from [`crate::lsa::v3`], RFC 8362
/// Extended-LSAs from [`crate::lsa::e_v3`], and the type-3 summary-LSA
/// equivalent from [`crate::abr`]) so an embedder building an OSPFv3
/// speaker has one module to grep — `lr_ospf::origination::originate_v3_*`
/// mirrors the v2 origination helpers (`originate_router_lsa`,
/// `originate_network_lsa`) already in this module.
///
/// The re-exports are name aliases of the originals (a `pub use` is not
/// a wrapping). A call through the unified path must produce the same
/// LSA as a call through the original module path with the same
/// inputs. This test is a regression guard against an accidental
/// `pub use` of the wrong function (e.g., a future move that breaks
/// the alias), and it covers one function from each source module so
/// the `pub use` block in `origination.rs` stays anchored.
#[test]
fn v3_origination_re_exports_alias_the_originals() {
    let router_id = 0x0a00_0001u32;
    let bits = 0u8;
    let options = 0u32;

    // (1) `crate::lsa::v3::originate_v3_router_lsa` — the fixed-format
    // RFC 5340 Router-LSA.
    let link = crate::lsa::v3::V3RouterLink {
        link_type: crate::lsa::v3::LINK_TYPE_POINTTOPOINT,
        metric: 1,
        interface_id: 3,
        neighbor_interface_id: 4,
        neighbor_router_id: 0x0a00_0002,
    };
    let links = vec![link];
    let via_re_export =
        crate::origination::originate_v3_router_lsa(router_id, bits, options, &links, None);
    let via_original =
        crate::lsa::v3::originate_v3_router_lsa(router_id, bits, options, &links, None);
    assert_eq!(
        via_re_export, via_original,
        "originate_v3_router_lsa re-export must alias the original in crate::lsa::v3"
    );

    // (2) `crate::lsa::e_v3::originate_v3_e_router_lsa` — the TLV-bodied
    // RFC 8362 E-Router-LSA. The function takes `Vec<ERouterLinkTlv>` by
    // value, so the second call re-uses the same vector through `clone`.
    let e_link = crate::lsa::e_v3::ERouterLinkTlv {
        link_type: crate::lsa::v3::LINK_TYPE_POINTTOPOINT,
        metric: 1,
        interface_id: 3,
        neighbor_interface_id: 4,
        neighbor_router_id: 0x0a00_0002,
        sub_tlvs: Vec::new(),
    };
    let via_re_export_e = crate::origination::originate_v3_e_router_lsa(
        router_id,
        bits,
        options,
        vec![e_link.clone()],
        None,
    );
    let via_original_e =
        crate::lsa::e_v3::originate_v3_e_router_lsa(router_id, bits, options, vec![e_link], None);
    assert_eq!(
        via_re_export_e, via_original_e,
        "originate_v3_e_router_lsa re-export must alias the original in crate::lsa::e_v3"
    );

    // (3) `crate::abr::originate_v3_inter_area_prefix_lsa` — the v3
    // type-3 summary-LSA equivalent. The ABR owns the LS-ID-to-prefix
    // mapping, so the helper lives in `abr` rather than `lsa`.
    let dest = crate::abr::SummaryDestination::new(
        lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
        10,
    );
    let via_re_export_abr =
        crate::origination::originate_v3_inter_area_prefix_lsa(router_id, 0, &dest, None);
    let via_original_abr =
        crate::abr::originate_v3_inter_area_prefix_lsa(router_id, 0, &dest, None);
    assert_eq!(
        via_re_export_abr, via_original_abr,
        "originate_v3_inter_area_prefix_lsa re-export must alias the original in crate::abr"
    );
}
