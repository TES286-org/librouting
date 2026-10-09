use super::*;

fn prefix64(addr_hi: u16) -> V3Prefix {
    let mut addr = [0u8; 16];
    addr[0..2].copy_from_slice(&addr_hi.to_be_bytes());
    addr[2] = 0x0d;
    addr[3] = 0xb8;
    V3Prefix {
        prefix_len: 64,
        options: 0,
        metric: 0,
        addr,
    }
}

/// §A.4.3: the Router-LSA body is bits(1) + options(3) + 16-byte link
/// descriptors running to the end of the LSA (no count field — the
/// receiver derives it from the LSA length, FRR ospf6_lsa.h parity).
/// Type 1 (p2p), metric 10, interface id 5, neighbor
/// interface id 3, neighbor router id 0x0a00_0002.
#[test]
fn router_lsa_body_wire_shape() {
    let body = V3RouterLsaBody {
        bits: ROUTER_BIT_B | ROUTER_BIT_E | ROUTER_BIT_V6,
        options: 0x13,
        links: vec![V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: 0x0a00_0002,
        }],
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    assert_eq!(wire.len(), 4 + 16);
    assert_eq!(wire[0], 0x07, "B|E|V6");
    assert_eq!(&wire[1..4], &[0, 0, 0x13], "24-bit options");
    assert_eq!(
        &wire[4..20],
        &[
            1, // p2p
            0, 0, 10, // metric
            0, 0, 0, 5, // interface id
            0, 0, 0, 3, // neighbor interface id
            0x0a, 0x00, 0x00, 0x02, // neighbor router id
        ]
    );
    let back = V3RouterLsaBody::decode(&wire).unwrap();
    assert_eq!(back, body);
    // Trailing garbage: decode must not run off the buffer.
    assert!(V3RouterLsaBody::decode(&wire[..15]).is_none());
}

/// §A.4.4: Network-LSA body = 0(1) + options(3) + Router IDs.
#[test]
fn network_lsa_body_wire_shape() {
    let body = V3NetworkLsaBody {
        options: 0x13,
        routers: vec![0x0a00_0001, 0x0a00_0002],
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    assert_eq!(wire.len(), 12);
    assert_eq!(
        &wire,
        &[0, 0, 0, 0x13, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02]
    );
    assert_eq!(V3NetworkLsaBody::decode(&wire).unwrap(), body);
}

/// §A.4.9: Link-LSA body = priority(1) + options(3) + link-local(16)
/// + #prefixes(4) + prefixes; a /64 prefix occupies 4 + 8 bytes.
#[test]
fn link_lsa_body_wire_shape() {
    let body = V3LinkLsaBody {
        priority: 1,
        options: 0x13,
        link_local: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        prefixes: vec![prefix64(0x2001)],
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    assert_eq!(wire.len(), 24 + 12);
    assert_eq!(wire[0], 1, "priority");
    assert_eq!(&wire[1..4], &[0, 0, 0x13]);
    assert_eq!(&wire[4..20], &body.link_local);
    assert_eq!(&wire[20..24], &1u32.to_be_bytes(), "prefix count");
    assert_eq!(wire[24], 64, "prefix length");
    assert_eq!(wire[25], 0, "prefix options");
    assert_eq!(&wire[26..28], &[0, 0], "metric word zero");
    assert_eq!(&wire[28..36], &body.prefixes[0].addr[..8]);
    assert_eq!(V3LinkLsaBody::decode(&wire).unwrap(), body);
}

/// §A.4.10: Intra-Area-Prefix body = #prefixes(2) + ref type(2) +
/// ref LS ID(4) + ref Adv Router(4) + prefixes.
#[test]
fn intra_area_prefix_body_wire_shape() {
    let body = V3IntraAreaPrefixBody {
        ref_type: LS_TYPE_ROUTER,
        ref_ls_id: 0,
        ref_adv_router: 0x0a00_0001,
        prefixes: vec![
            prefix64(0x2001),
            V3Prefix {
                prefix_len: 32,
                options: PREFIX_OPT_LA,
                metric: 0,
                addr: [0u8; 16],
            },
        ],
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    // /64 → 4+8 bytes; /32 → 4+4 bytes.
    assert_eq!(wire.len(), 12 + 12 + 8);
    assert_eq!(&wire[0..2], &2u16.to_be_bytes());
    assert_eq!(&wire[2..4], &[0x20, 0x01]);
    let back = V3IntraAreaPrefixBody::decode(&wire).unwrap();
    assert_eq!(back, body);
    assert_eq!(back.prefixes[1].prefix_len, 32);
    assert_eq!(back.prefixes[1].options, PREFIX_OPT_LA);
}

/// A /32 prefix occupies 4+4 bytes on the wire (ceil(32/32)×4);
/// a /127 occupies 4+16 (ceil(127/32)=4 words).
#[test]
fn prefix_addr_bytes_len_rounding() {
    assert_eq!(V3Prefix::addr_bytes_len(0), 0);
    assert_eq!(V3Prefix::addr_bytes_len(1), 4);
    assert_eq!(V3Prefix::addr_bytes_len(32), 4);
    assert_eq!(V3Prefix::addr_bytes_len(33), 8);
    assert_eq!(V3Prefix::addr_bytes_len(64), 8);
    assert_eq!(V3Prefix::addr_bytes_len(96), 12);
    assert_eq!(V3Prefix::addr_bytes_len(127), 16);
    assert_eq!(V3Prefix::addr_bytes_len(128), 16);
}

/// The originated v3 Router-LSA carries type 0x2001, LS ID 0 and a
/// valid Fletcher checksum; re-origination advances the sequence.
#[test]
fn originate_v3_router_lsa_shape() {
    let links = vec![V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: 5,
        neighbor_interface_id: 3,
        neighbor_router_id: 0x0a00_0002,
    }];
    let lsa = originate_v3_router_lsa(
        0x0a00_0001,
        ROUTER_BIT_B | ROUTER_BIT_V6,
        0x13,
        &links,
        None,
    )
    .unwrap();
    assert_eq!(lsa.header.ls_type, LS_TYPE_ROUTER);
    assert_eq!(lsa.header.link_state_id, 0);
    assert_eq!(lsa.header.advertising_router, 0x0a00_0001);
    assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
    assert_eq!(lsa.header.options, 0, "v3 headers carry no options byte");
    assert!(lsa.checksum_ok(), "LSA checksum must verify");
    let decoded = V3RouterLsaBody::decode(&lsa.body).unwrap();
    assert_eq!(decoded.bits, ROUTER_BIT_B | ROUTER_BIT_V6);
    assert_eq!(decoded.options, 0x13);
    assert_eq!(decoded.links, links);
    let next = originate_v3_router_lsa(
        0x0a00_0001,
        0,
        0x13,
        &links,
        Some(lsa.header.ls_sequence_number),
    )
    .unwrap();
    assert_eq!(next.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
    // Sequence exhaustion refuses to originate (§12.1.2).
    assert!(originate_v3_router_lsa(1, 0, 0, &links, Some(MAX_SEQUENCE_NUMBER)).is_none());
}

/// The Link-LSA's Link State ID is the Interface ID; the body
/// round-trips the link-local address.
#[test]
fn originate_v3_link_lsa_shape() {
    let ll = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    let lsa = originate_v3_link_lsa(0x0a00_0001, 7, 1, 0x13, ll, vec![], None).unwrap();
    assert_eq!(lsa.header.ls_type, LS_TYPE_LINK);
    assert_eq!(lsa.header.link_state_id, 7, "LS ID = interface id");
    assert!(lsa.checksum_ok());
    let decoded = V3LinkLsaBody::decode(&lsa.body).unwrap();
    assert_eq!(decoded.link_local, ll);
    assert!(decoded.prefixes.is_empty());
}

/// An Intra-Area-Prefix LSA referencing a Network-LSA round-trips
/// with its ref fields intact.
#[test]
fn originate_v3_intra_prefix_references_network() {
    let prefixes = vec![prefix64(0x2001)];
    let lsa = originate_v3_intra_area_prefix_lsa(
        0x0a00_0002,
        1,
        LS_TYPE_NETWORK,
        5,
        0x0a00_0002,
        prefixes.clone(),
        None,
    )
    .unwrap();
    assert_eq!(lsa.header.ls_type, LS_TYPE_INTRA_PREFIX);
    assert_eq!(lsa.header.link_state_id, 1);
    let decoded = V3IntraAreaPrefixBody::decode(&lsa.body).unwrap();
    assert_eq!(decoded.ref_type, LS_TYPE_NETWORK);
    assert_eq!(decoded.ref_ls_id, 5);
    assert_eq!(decoded.ref_adv_router, 0x0a00_0002);
    assert_eq!(decoded.prefixes, prefixes);
}

/// §A.4.6: the Inter-Area-Router body is 0(1) + options(3) +
/// 0(1) + metric(3) + destination router ID — 12 bytes total.
/// Shape from RFC 5340 §4.4.3.5's RT7 example: options
/// V6|E|R = 0x13 (v2 §A.2 bit values), metric 14, dest 0x0a00_0007.
#[test]
fn inter_area_router_body_wire_shape() {
    let body = V3InterAreaRouterBody {
        options: 0x13,
        metric: 14,
        dest_router_id: 0x0a00_0007,
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    assert_eq!(wire.len(), 12);
    assert_eq!(
        &wire,
        &[
            0, 0, 0, 0x13, // options (24-bit)
            0, 0, 0, 14, // metric (24-bit)
            0x0a, 0x00, 0x00, 0x07, // destination router ID
        ]
    );
    assert_eq!(V3InterAreaRouterBody::decode(&wire).unwrap(), body);
    assert!(V3InterAreaRouterBody::decode(&wire[..11]).is_none());
}

/// The originated 0x2004 LSA carries the destination in the body,
/// the caller's LS ID and a valid checksum; the metric is capped
/// below LSInfinity.
#[test]
fn originate_v3_inter_area_router_lsa_shape() {
    let lsa =
        originate_v3_inter_area_router_lsa(0x0a00_0004, 0x0a00_0007, 0x13, 0x0a00_0007, 14, None)
            .unwrap();
    assert_eq!(lsa.header.ls_type, LS_TYPE_INTER_ROUTER);
    assert_eq!(lsa.header.link_state_id, 0x0a00_0007, "LS ID = destination");
    assert_eq!(lsa.header.advertising_router, 0x0a00_0004);
    assert_eq!(lsa.header.length, 20 + 12);
    assert!(lsa.checksum_ok());
    let decoded = V3InterAreaRouterBody::decode(&lsa.body).unwrap();
    assert_eq!(decoded.dest_router_id, 0x0a00_0007);
    assert_eq!(decoded.metric, 14);
    assert_eq!(decoded.options, 0x13);
    let next = originate_v3_inter_area_router_lsa(
        0x0a00_0004,
        0x0a00_0007,
        0x13,
        0x0a00_0007,
        14,
        Some(lsa.header.ls_sequence_number),
    )
    .unwrap();
    assert_eq!(next.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
    // LSInfinity metrics are capped at origination.
    let capped = originate_v3_inter_area_router_lsa(1, 2, 0, 3, 0xffff_ffff, None).unwrap();
    assert_eq!(
        V3InterAreaRouterBody::decode(&capped.body).unwrap().metric,
        0x00ff_fffe
    );
}

/// §A.4.7: the AS-External body is E|F|T + metric(3) + prefix (with
/// the trailing word = Referenced LS Type), then the optional
/// forwarding address / route tag / referenced LS ID. The
/// RFC 5340 §4.4.3.6 N12 example: type 2 (E), tag, metric 2, /40
/// prefix (8 wire bytes); LS ID 123 is arbitrary per §4.4.3.6.
#[test]
fn as_external_body_wire_shape() {
    let mut addr = [0u8; 16];
    addr[0..2].copy_from_slice(&0x2001u16.to_be_bytes());
    addr[2] = 0x0d;
    addr[3] = 0xb8;
    addr[4] = 0x0a;
    let body = V3AsExternalBody {
        e_bit: true,
        metric: 2,
        prefix: V3Prefix {
            prefix_len: 40,
            options: 0,
            metric: 0,
            addr,
        },
        forwarding_addr: None,
        route_tag: Some(7),
        referenced_ls_id: None,
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    // 4 flags/metric + 4 prefix header + 8 prefix address + 4 tag.
    assert_eq!(wire.len(), 20);
    assert_eq!(&wire[0..4], &[0x05, 0, 0, 2], "E|T set, metric 2");
    assert_eq!(wire[4], 40, "prefix length");
    assert_eq!(wire[5], 0, "prefix options");
    assert_eq!(&wire[6..8], &[0, 0], "referenced LS type 0");
    assert_eq!(&wire[8..16], &addr[..8], "prefix address (8 words)");
    assert_eq!(&wire[16..20], &7u32.to_be_bytes(), "route tag");
    assert_eq!(V3AsExternalBody::decode(&wire).unwrap(), body);
    // Truncation never panics.
    for cut in [0usize, 3, 7, 11, 15, 19] {
        assert!(V3AsExternalBody::decode(&wire[..cut]).is_none());
    }
}

/// F/T bit round-trip: a forwarding address rides the body if and
/// only if the F bit is set; the tag if and only if T is set.
#[test]
fn as_external_forwarding_address_round_trip() {
    let mut fa = [0u8; 16];
    fa[0] = 0x20;
    fa[1] = 0x01;
    let body = V3AsExternalBody {
        e_bit: false,
        metric: 100,
        prefix: V3Prefix {
            prefix_len: 64,
            options: 0,
            metric: 0,
            addr: [0x20; 16],
        },
        forwarding_addr: Some(fa),
        route_tag: None,
        referenced_ls_id: None,
    };
    let mut wire = Vec::new();
    body.encode(&mut wire);
    assert_eq!(wire[0], 0x02, "F set, E clear");
    assert_eq!(wire.len(), 4 + 12 + 16);
    let back = V3AsExternalBody::decode(&wire).unwrap();
    assert_eq!(back.forwarding_addr, Some(fa));
    assert_eq!(back.route_tag, None);
    assert!(!back.e_bit);
    assert_eq!(back.metric, 100);
}

/// The originated 0x4005 LSA pins the E/F/T layout FRR uses
/// (E=0x04000000, distinct from the v2 top-bit form), normalizes
/// host bits on the prefix and refuses non-IPv6 destinations.
#[test]
fn originate_v3_as_external_lsa_shape() {
    let dest = V3ExternalDestination::new(
        Prefix::new_v6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x99,
            ],
            48,
        ),
        150,
        true,
    );
    let lsa = originate_v3_as_external_lsa(0x0a00_0007, 123, &dest, None).unwrap();
    assert_eq!(lsa.header.ls_type, LS_TYPE_AS_EXTERNAL);
    assert_eq!(lsa.header.link_state_id, 123);
    assert_eq!(lsa.header.advertising_router, 0x0a00_0007);
    assert!(lsa.checksum_ok());
    // /48 → 8 wire bytes; the /48 host bits (0x0999 in the last two
    // bytes) are zeroed.
    assert_eq!(lsa.header.length, 20 + 4 + 4 + 8);
    let decoded = V3AsExternalBody::decode(&lsa.body).unwrap();
    assert!(decoded.e_bit);
    assert_eq!(decoded.metric, 150);
    assert_eq!(decoded.prefix.prefix_len, 48);
    assert_eq!(decoded.prefix.metric, 0, "referenced LS type 0");
    assert_eq!(&decoded.prefix.addr[..6], &[0x20, 0x01, 0x0d, 0xb8, 0, 0]);
    assert!(decoded.forwarding_addr.is_none());
    let next = originate_v3_as_external_lsa(0x0a00_0007, 123, &dest, Some(0x8000_0005)).unwrap();
    assert_eq!(next.header.ls_sequence_number, 0x8000_0006);
    // Non-IPv6 destinations are refused.
    let v4dest = V3ExternalDestination::new(Prefix::new_v4([10, 0, 0, 0], 8), 10, false);
    assert!(originate_v3_as_external_lsa(1, 2, &v4dest, None).is_none());
    // A global forwarding address sets the F bit and rides the body.
    let mut with_fa = dest;
    with_fa.forwarding_addr = Some([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let lsa = originate_v3_as_external_lsa(0x0a00_0007, 123, &with_fa, None).unwrap();
    assert_eq!(lsa.header.length, 20 + 4 + 4 + 8 + 16);
    let decoded = V3AsExternalBody::decode(&lsa.body).unwrap();
    assert_eq!(
        decoded.forwarding_addr,
        Some([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
}
