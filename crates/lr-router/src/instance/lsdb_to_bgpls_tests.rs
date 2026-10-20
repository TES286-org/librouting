//! Unit tests for the OSPFv2/v3 LSDB → BGP-LS projection.
//!
//! Every test builds a small LSDB with the project's own LSA
//! origination helpers (`lr_ospf::origination`,
//! `lr_ospf::abr`, `lr_ospf::external`, `lr_ospf::lsa::v3`), runs
//! the projection, and asserts:
//!
//! - The projection emits the expected NLRI variant (Node / Link /
//!   IPv4 Prefix / IPv6 Prefix) per LSA type.
//! - The Local Node Descriptor sub-TLVs carry the AS, BGP-LS ID,
//!   OSPF Area-ID and IGP Router-ID that the LSA's advertising
//!   router and the projection context pin (RFC 7752 §3.2.1.4).
//! - The Link Descriptor TLVs pick the right sub-TLVs for the LSA
//!   version (IPv4 addresses for v2, Link Local/Remote IDs for v3).
//! - The Prefix Descriptor carries the OSPF Route Type TLV (264)
//!   and the IP Reachability Info TLV (265) with the expected
//!   prefix.
//! - AS-External LSAs carry an OSPF Area-ID sub-TLV of 0 per RFC
//!   7752 §3.2.1.4.
//! - The projection round-trips through the codec byte-for-byte for
//!   every emitted NLRI.
//! - `diff_bgpls` returns the expected added/removed/unchanged
//!   sets across two projections.

use super::*;
use lr_bgp::path::bgp_ls::{
    BgpLsNlriVariant, LinkDescriptorSubTlv, NodeDescriptorSubTlv, PrefixDescriptorSubTlv,
    ProtocolId,
};
use lr_core::addr::Prefix;
use lr_core::rib::Protocol;
use lr_ospf::abr::{originate_summary_lsa, originate_v3_inter_area_prefix_lsa, SummaryDestination};
use lr_ospf::external::{originate_external_lsa, ExternalDestination, ExternalMetricType};
use lr_ospf::lsa::v3::{
    originate_v3_as_external_lsa, originate_v3_intra_area_prefix_lsa, originate_v3_network_lsa,
    originate_v3_router_lsa, V3ExternalDestination, V3Prefix, V3RouterLink,
};
use lr_ospf::lsa::{Lsa, LsaHeader};
use lr_ospf::lsdb::Lsdb;
use lr_ospf::origination::{
    originate_network_lsa, originate_router_lsa, RouterLsaFlags, RouterLsaLink,
};

/// Default context for tests: AS 64512, BGP-LS ID 0x100, area 0.
const CTX_V2: OspfAreaBgplsContext = OspfAreaBgplsContext {
    as_number: 64512,
    bgp_ls_id: 0x100,
    area_id: 0,
    protocol: Protocol::Ospfv2,
};

const CTX_V3: OspfAreaBgplsContext = OspfAreaBgplsContext {
    as_number: 64512,
    bgp_ls_id: 0x100,
    area_id: 0,
    protocol: Protocol::Ospfv3,
};

fn install(db: &mut Lsdb, lsa: Lsa) {
    let _ = db.install(lsa, 0);
}

/// Find the first NLRI of a given variant in `nlris`.
fn first_variant(nlris: &[BgpLsNlri], pred: impl Fn(&BgpLsNlriVariant) -> bool) -> &BgpLsNlri {
    nlris
        .iter()
        .find(|n| pred(&n.variant))
        .expect("expected at least one matching NLRI")
}

fn count_variants(nlris: &[BgpLsNlri], pred: impl Fn(&BgpLsNlriVariant) -> bool) -> usize {
    nlris.iter().filter(|n| pred(&n.variant)).count()
}

/// Assert every NLRI in `nlris` round-trips byte-for-byte through
/// the codec — the codec's strict structural enforcement must accept
/// whatever the projection emits.
fn assert_all_round_trip(nlris: &[BgpLsNlri]) {
    for n in nlris {
        let mut v = vec![0u8; n.wire_len()];
        let mut buf = WriteBuf::new(&mut v);
        n.encode(&mut buf).expect("encode");
        let (back, used) = BgpLsNlri::decode(false, &v).expect("decode");
        assert_eq!(used, v.len(), "decode length matches encode length");
        assert_eq!(back, *n, "round-trip byte-for-byte");
    }
}

// ---------------------------------------------------------------------------
// OSPFv2 projection
// ---------------------------------------------------------------------------

#[test]
fn v2_router_lsa_emits_one_node_nlri_with_4_byte_igp_router_id() {
    let mut db = Lsdb::new();
    let lsa = originate_router_lsa(
        0x01020304,
        RouterLsaFlags::default(),
        &[RouterLsaLink::PointToPoint {
            neighbor: 0x05060708,
            local_addr: 0xc0a80101,
            metric: 10,
        }],
        None,
    )
    .unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    // One Node NLRI + one Link NLRI for the P2P link.
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Node(_))),
        1
    );
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Link(_))),
        1
    );
    assert_eq!(out.len(), 2);

    let node = first_variant(&out, |v| matches!(v, BgpLsNlriVariant::Node(_)));
    let BgpLsNlriVariant::Node(node_n) = &node.variant else {
        unreachable!()
    };
    assert_eq!(node_n.protocol_id, ProtocolId::Ospfv2);
    assert_eq!(node_n.identifier, 0);
    assert_eq!(node_n.local_node.as_number(), Some(64512));
    assert_eq!(node_n.local_node.bgp_ls_id(), Some(0x100));
    assert_eq!(node_n.local_node.ospf_area_id(), Some(0));
    assert_eq!(
        node_n.local_node.igp_router_id(),
        Some(&[0x01, 0x02, 0x03, 0x04][..])
    );
    assert_all_round_trip(&out);
}

#[test]
fn v2_router_lsa_p2p_link_emits_link_nlri_with_local_ipv4_iface() {
    let mut db = Lsdb::new();
    let lsa = originate_router_lsa(
        0x01020304,
        RouterLsaFlags::default(),
        &[RouterLsaLink::PointToPoint {
            neighbor: 0x05060708,
            local_addr: 0xc0a80101, // 192.168.1.1
            metric: 10,
        }],
        None,
    )
    .unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    let link = first_variant(&out, |v| matches!(v, BgpLsNlriVariant::Link(_)));
    let BgpLsNlriVariant::Link(link_n) = &link.variant else {
        unreachable!()
    };
    // Local node: the originating router (4-byte IGP Router-ID).
    assert_eq!(
        link_n.local_node.igp_router_id(),
        Some(&[0x01, 0x02, 0x03, 0x04][..])
    );
    // Remote node: the peer router (4-byte IGP Router-ID).
    assert_eq!(
        link_n.remote_node.igp_router_id(),
        Some(&[0x05, 0x06, 0x07, 0x08][..])
    );
    // Link Descriptor: IPv4 Interface Address (259) = local_addr.
    // IPv4 Neighbor Address (260) is omitted for P2P (RFC 7752 §3.2.2).
    let mut iface = None;
    let mut neighbor = 0;
    for s in &link_n.link.sub_tlvs {
        if let LinkDescriptorSubTlv::Ipv4InterfaceAddress(a) = s {
            iface = Some(*a);
        }
        if let LinkDescriptorSubTlv::Ipv4NeighborAddress(_) = s {
            neighbor += 1;
        }
    }
    assert_eq!(iface, Some([0xc0, 0xa8, 0x01, 0x01]));
    assert_eq!(neighbor, 0, "P2P links do not carry IPv4 neighbor address");
    assert_all_round_trip(&out);
}

#[test]
fn v2_router_lsa_transit_link_emits_link_nlri_with_dr_pseudonode() {
    let mut db = Lsdb::new();
    // DR originates the Network-LSA: link_state_id = DR's interface IP.
    let dr = originate_network_lsa(
        0x05060708,  // dr_router_id
        0xc0a80a01,  // dr_addr (192.168.10.1)
        0xffff_ff00, // /24 mask
        &[0x05060708, 0x01020304],
        None,
    )
    .unwrap();
    install(&mut db, dr);
    // The other router has a transit link to the DR.
    let rtr = originate_router_lsa(
        0x01020304,
        RouterLsaFlags::default(),
        &[RouterLsaLink::Transit {
            dr_addr: 0xc0a80a01,    // the DR's interface IP — link_id
            local_addr: 0xc0a80a02, // 192.168.10.2 — link_data
            metric: 10,
        }],
        None,
    )
    .unwrap();
    install(&mut db, rtr);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    // The DR's Network-LSA produces one pseudonode Node NLRI; the
    // router's transit link produces one Link NLRI; the router's
    // Router-LSA produces one Node NLRI; the DR's own Router-LSA is
    // not in the LSDB (not originated above), so no Node NLRI for it.
    // Total: 2 Node + 1 Link = 3 NLRIs.
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Node(_))),
        2
    );
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Link(_))),
        1
    );

    let link = first_variant(&out, |v| matches!(v, BgpLsNlriVariant::Link(_)));
    let BgpLsNlriVariant::Link(link_n) = &link.variant else {
        unreachable!()
    };
    // Remote node is the DR pseudonode: 8-byte IGP Router-ID =
    // (dr_router_id, dr_addr).
    let igp = link_n.remote_node.igp_router_id().unwrap();
    assert_eq!(igp.len(), 8, "OSPFv2 pseudonode IGP Router-ID is 8 bytes");
    assert_eq!(&igp[..4], &[0x05, 0x06, 0x07, 0x08]);
    assert_eq!(&igp[4..], &[0xc0, 0xa8, 0x0a, 0x01]);

    // Link Descriptor: IPv4 interface + neighbor addresses.
    let mut iface = None;
    let mut neigh = None;
    for s in &link_n.link.sub_tlvs {
        if let LinkDescriptorSubTlv::Ipv4InterfaceAddress(a) = s {
            iface = Some(*a);
        }
        if let LinkDescriptorSubTlv::Ipv4NeighborAddress(a) = s {
            neigh = Some(*a);
        }
    }
    assert_eq!(iface, Some([0xc0, 0xa8, 0x0a, 0x02]));
    assert_eq!(neigh, Some([0xc0, 0xa8, 0x0a, 0x01]));
    assert_all_round_trip(&out);
}

#[test]
fn v2_router_lsa_transit_link_without_network_lsa_skips_link_nlri() {
    // When the DR has not originated its Network-LSA yet, the
    // transit link's remote node descriptor cannot be built. The
    // projection skips emitting the Link NLRI rather than
    // synthesising an unknown remote node.
    let mut db = Lsdb::new();
    let rtr = originate_router_lsa(
        0x01020304,
        RouterLsaFlags::default(),
        &[RouterLsaLink::Transit {
            dr_addr: 0xc0a80a01,
            local_addr: 0xc0a80a02,
            metric: 10,
        }],
        None,
    )
    .unwrap();
    install(&mut db, rtr);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Node(_))),
        1
    );
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Link(_))),
        0
    );
    assert_all_round_trip(&out);
}

#[test]
fn v2_stub_link_emits_intra_area_ipv4_prefix_nlri() {
    let mut db = Lsdb::new();
    let lsa = originate_router_lsa(
        0x01020304,
        RouterLsaFlags::default(),
        &[RouterLsaLink::Stub {
            network: 0xc0a80100, // 192.168.1.0
            mask: 0xffff_ff00,   // /24
            metric: 10,
        }],
        None,
    )
    .unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Node(_))),
        1
    );
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Ipv4Prefix(_))),
        1
    );

    let pfx = first_variant(&out, |v| matches!(v, BgpLsNlriVariant::Ipv4Prefix(_)));
    let BgpLsNlriVariant::Ipv4Prefix(pfx_n) = &pfx.variant else {
        unreachable!()
    };
    let mut route_type = None;
    let mut reach = None;
    for s in &pfx_n.prefix.sub_tlvs {
        match s {
            PrefixDescriptorSubTlv::OspfRouteType(t) => route_type = Some(*t),
            PrefixDescriptorSubTlv::IpReachabilityInfo {
                prefix_len,
                prefix_bytes,
            } => reach = Some((*prefix_len, prefix_bytes.clone())),
            _ => {}
        }
    }
    assert_eq!(route_type, Some(OspfRouteType::IntraArea));
    assert_eq!(reach, Some((24, vec![0xc0, 0xa8, 0x01, 0x00])));
    assert_all_round_trip(&out);
}

#[test]
fn v2_summary_lsa_emits_inter_area_ipv4_prefix_nlri() {
    let mut db = Lsdb::new();
    let dest = SummaryDestination::new(Prefix::new_v4([0xc0, 0xa8, 0x02, 0x00], 24), 100);
    let lsa = originate_summary_lsa(0x01020304, &dest, None).unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    assert_eq!(out.len(), 1);
    let BgpLsNlriVariant::Ipv4Prefix(pfx_n) = &out[0].variant else {
        panic!("expected an IPv4 Prefix NLRI")
    };
    let mut route_type = None;
    let mut reach = None;
    for s in &pfx_n.prefix.sub_tlvs {
        match s {
            PrefixDescriptorSubTlv::OspfRouteType(t) => route_type = Some(*t),
            PrefixDescriptorSubTlv::IpReachabilityInfo {
                prefix_len,
                prefix_bytes,
            } => reach = Some((*prefix_len, prefix_bytes.clone())),
            _ => {}
        }
    }
    assert_eq!(route_type, Some(OspfRouteType::InterArea));
    assert_eq!(reach, Some((24, vec![0xc0, 0xa8, 0x02, 0x00])));
    // Local node: ABR (4-byte IGP Router-ID), area ID = the projection's.
    assert_eq!(pfx_n.local_node.ospf_area_id(), Some(0));
    assert_eq!(
        pfx_n.local_node.igp_router_id(),
        Some(&[0x01, 0x02, 0x03, 0x04][..])
    );
    assert_all_round_trip(&out);
}

#[test]
fn v2_as_external_lsa_emits_external_ipv4_prefix_nlri_with_area_id_zero() {
    let mut db = Lsdb::new();
    let dest = ExternalDestination::new(
        Prefix::new_v4([0xc0, 0xa8, 0x03, 0x00], 24),
        100,
        ExternalMetricType::Type1,
    );
    let lsa = originate_external_lsa(0x01020304, &dest, None).unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    assert_eq!(out.len(), 1);
    let BgpLsNlriVariant::Ipv4Prefix(pfx_n) = &out[0].variant else {
        panic!("expected an IPv4 Prefix NLRI")
    };
    let mut route_type = None;
    let mut reach = None;
    for s in &pfx_n.prefix.sub_tlvs {
        match s {
            PrefixDescriptorSubTlv::OspfRouteType(t) => route_type = Some(*t),
            PrefixDescriptorSubTlv::IpReachabilityInfo {
                prefix_len,
                prefix_bytes,
            } => reach = Some((*prefix_len, prefix_bytes.clone())),
            _ => {}
        }
    }
    assert_eq!(route_type, Some(OspfRouteType::External1));
    assert_eq!(reach, Some((24, vec![0xc0, 0xa8, 0x03, 0x00])));
    // RFC 7752 §3.2.1.4: OSPF Area-ID sub-TLV is 0 for AS-External
    // LSAs even when the projection context has a non-zero area ID.
    assert_eq!(pfx_n.local_node.ospf_area_id(), Some(0));
    assert_all_round_trip(&out);
}

#[test]
fn v2_as_external_lsa_type2_emits_external2_route_type() {
    let mut db = Lsdb::new();
    let dest = ExternalDestination::new(
        Prefix::new_v4([0xc0, 0xa8, 0x04, 0x00], 24),
        100,
        ExternalMetricType::Type2,
    );
    let lsa = originate_external_lsa(0x01020304, &dest, None).unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    let BgpLsNlriVariant::Ipv4Prefix(pfx_n) = &out[0].variant else {
        panic!()
    };
    let route_type = pfx_n.prefix.sub_tlvs.iter().find_map(|s| {
        if let PrefixDescriptorSubTlv::OspfRouteType(t) = s {
            Some(*t)
        } else {
            None
        }
    });
    assert_eq!(route_type, Some(OspfRouteType::External2));
}

#[test]
fn v2_network_lsa_emits_pseudonode_node_nlri() {
    let mut db = Lsdb::new();
    let lsa = originate_network_lsa(
        0x05060708, // DR Router ID
        0xc0a80a01, // DR's interface IP (link-state ID)
        0xffff_ff00,
        &[0x05060708, 0x01020304],
        None,
    )
    .unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    assert_eq!(out.len(), 1);
    let BgpLsNlriVariant::Node(node_n) = &out[0].variant else {
        panic!("expected a Node NLRI for the Network-LSA pseudonode")
    };
    let igp = node_n.local_node.igp_router_id().unwrap();
    assert_eq!(igp.len(), 8);
    assert_eq!(&igp[..4], &[0x05, 0x06, 0x07, 0x08]);
    assert_eq!(&igp[4..], &[0xc0, 0xa8, 0x0a, 0x01]);
    assert_all_round_trip(&out);
}

// ---------------------------------------------------------------------------
// OSPFv3 projection
// ---------------------------------------------------------------------------

fn v3_router_link_p2p(
    local_iface_id: u32,
    neighbor_iface_id: u32,
    neighbor_rid: u32,
) -> V3RouterLink {
    V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: local_iface_id,
        neighbor_interface_id: neighbor_iface_id,
        neighbor_router_id: neighbor_rid,
    }
}

fn v3_router_link_transit(local_iface_id: u32, dr_iface_id: u32, dr_rid: u32) -> V3RouterLink {
    V3RouterLink {
        link_type: LINK_TYPE_TRANSIT,
        metric: 10,
        interface_id: local_iface_id,
        neighbor_interface_id: dr_iface_id,
        neighbor_router_id: dr_rid,
    }
}

#[test]
fn v3_router_lsa_emits_node_nlri_with_4_byte_igp_router_id() {
    let mut db = Lsdb::new();
    let lsa = originate_v3_router_lsa(
        0x01020304,
        lr_ospf::lsa::v3::ROUTER_BIT_V6,
        0,
        &[v3_router_link_p2p(1, 2, 0x05060708)],
        None,
    )
    .unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V3);
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Node(_))),
        1
    );
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Link(_))),
        1
    );

    let node = first_variant(&out, |v| matches!(v, BgpLsNlriVariant::Node(_)));
    let BgpLsNlriVariant::Node(node_n) = &node.variant else {
        unreachable!()
    };
    assert_eq!(node_n.protocol_id, ProtocolId::Ospfv3);
    assert_eq!(node_n.identifier, 0);
    assert_eq!(node_n.local_node.as_number(), Some(64512));
    assert_eq!(node_n.local_node.bgp_ls_id(), Some(0x100));
    assert_eq!(node_n.local_node.ospf_area_id(), Some(0));
    assert_eq!(
        node_n.local_node.igp_router_id(),
        Some(&[0x01, 0x02, 0x03, 0x04][..])
    );
    assert_all_round_trip(&out);
}

#[test]
fn v3_p2p_link_emits_link_nlri_with_link_local_remote_id() {
    let mut db = Lsdb::new();
    let lsa = originate_v3_router_lsa(
        0x01020304,
        lr_ospf::lsa::v3::ROUTER_BIT_V6,
        0,
        &[v3_router_link_p2p(1, 2, 0x05060708)],
        None,
    )
    .unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V3);
    let link = first_variant(&out, |v| matches!(v, BgpLsNlriVariant::Link(_)));
    let BgpLsNlriVariant::Link(link_n) = &link.variant else {
        unreachable!()
    };
    // Local node: the originating router (4-byte IGP Router-ID).
    assert_eq!(
        link_n.local_node.igp_router_id(),
        Some(&[0x01, 0x02, 0x03, 0x04][..])
    );
    // Remote node: the peer router (4-byte IGP Router-ID).
    assert_eq!(
        link_n.remote_node.igp_router_id(),
        Some(&[0x05, 0x06, 0x07, 0x08][..])
    );
    // Link Descriptor: Link Local/Remote ID (258) only — no IPv4
    // or IPv6 addresses on a v3 Router-LSA link.
    let mut lr = None;
    for s in &link_n.link.sub_tlvs {
        if let LinkDescriptorSubTlv::LinkLocalRemoteId { local, remote } = s {
            lr = Some((*local, *remote));
        }
    }
    assert_eq!(lr, Some((1, 2)));
    assert_all_round_trip(&out);
}

#[test]
fn v3_transit_link_emits_link_nlri_with_dr_pseudonode() {
    let mut db = Lsdb::new();
    // DR originates the Network-LSA: link_state_id = DR's Interface ID.
    let dr = originate_v3_network_lsa(
        0x05060708, // dr_router_id
        42,         // dr_interface_id
        0,
        &[0x05060708, 0x01020304],
        None,
    )
    .unwrap();
    install(&mut db, dr);
    // The other router has a transit link to the DR.
    let rtr = originate_v3_router_lsa(
        0x01020304,
        lr_ospf::lsa::v3::ROUTER_BIT_V6,
        0,
        &[v3_router_link_transit(1, 42, 0x05060708)],
        None,
    )
    .unwrap();
    install(&mut db, rtr);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V3);
    // 2 Node NLRIs (router + pseudonode) + 1 Link NLRI.
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Node(_))),
        2
    );
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Link(_))),
        1
    );

    let link = first_variant(&out, |v| matches!(v, BgpLsNlriVariant::Link(_)));
    let BgpLsNlriVariant::Link(link_n) = &link.variant else {
        unreachable!()
    };
    // Remote node is the DR pseudonode: 8-byte IGP Router-ID =
    // (dr_router_id, dr_interface_id).
    let igp = link_n.remote_node.igp_router_id().unwrap();
    assert_eq!(igp.len(), 8, "OSPFv3 pseudonode IGP Router-ID is 8 bytes");
    assert_eq!(&igp[..4], &[0x05, 0x06, 0x07, 0x08]);
    assert_eq!(&igp[4..], &42u32.to_be_bytes());

    // Link Descriptor: Link Local/Remote ID with (1, 42).
    let mut lr = None;
    for s in &link_n.link.sub_tlvs {
        if let LinkDescriptorSubTlv::LinkLocalRemoteId { local, remote } = s {
            lr = Some((*local, *remote));
        }
    }
    assert_eq!(lr, Some((1, 42)));
    assert_all_round_trip(&out);
}

#[test]
fn v3_intra_area_prefix_lsa_emits_ipv6_prefix_nlris() {
    let mut db = Lsdb::new();
    let prefixes = vec![
        V3Prefix {
            prefix_len: 64,
            options: 0,
            metric: 0,
            addr: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
        },
        V3Prefix {
            prefix_len: 64,
            options: 0,
            metric: 0,
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        },
    ];
    let lsa = originate_v3_intra_area_prefix_lsa(
        0x01020304,                       // router_id (advertising router)
        1,                                // ls_id
        lr_ospf::lsa::v3::LS_TYPE_ROUTER, // ref_type — attached to a Router-LSA
        0,                                // ref_ls_id
        0x01020304,                       // ref_adv_router — same as advertising
        prefixes,
        None,
    )
    .unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V3);
    assert_eq!(
        count_variants(&out, |v| matches!(v, BgpLsNlriVariant::Ipv6Prefix(_))),
        2
    );
    for n in &out {
        let BgpLsNlriVariant::Ipv6Prefix(pfx_n) = &n.variant else {
            continue;
        };
        let route_type = pfx_n.prefix.sub_tlvs.iter().find_map(|s| {
            if let PrefixDescriptorSubTlv::OspfRouteType(t) = s {
                Some(*t)
            } else {
                None
            }
        });
        assert_eq!(route_type, Some(OspfRouteType::IntraArea));
        // Local node: the referenced router (ref_type=ROUTER).
        assert_eq!(
            pfx_n.local_node.igp_router_id(),
            Some(&[0x01, 0x02, 0x03, 0x04][..])
        );
    }
    assert_all_round_trip(&out);
}

#[test]
fn v3_inter_area_prefix_lsa_emits_inter_area_ipv6_prefix_nlri() {
    let mut db = Lsdb::new();
    let dest = SummaryDestination::new(
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            64,
        ),
        100,
    );
    let lsa = originate_v3_inter_area_prefix_lsa(0x01020304, 1, &dest, None).unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V3);
    assert_eq!(out.len(), 1);
    let BgpLsNlriVariant::Ipv6Prefix(pfx_n) = &out[0].variant else {
        panic!("expected an IPv6 Prefix NLRI")
    };
    let route_type = pfx_n.prefix.sub_tlvs.iter().find_map(|s| {
        if let PrefixDescriptorSubTlv::OspfRouteType(t) = s {
            Some(*t)
        } else {
            None
        }
    });
    assert_eq!(route_type, Some(OspfRouteType::InterArea));
    assert_eq!(
        pfx_n.local_node.igp_router_id(),
        Some(&[0x01, 0x02, 0x03, 0x04][..])
    );
    assert_all_round_trip(&out);
}

#[test]
fn v3_as_external_lsa_emits_external_ipv6_prefix_nlri_with_area_id_zero() {
    let mut db = Lsdb::new();
    let dest = V3ExternalDestination::new(
        Prefix::new_v6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
            64,
        ),
        100,
        false,
    );
    let lsa = originate_v3_as_external_lsa(0x01020304, 1, &dest, None).unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V3);
    assert_eq!(out.len(), 1);
    let BgpLsNlriVariant::Ipv6Prefix(pfx_n) = &out[0].variant else {
        panic!("expected an IPv6 Prefix NLRI")
    };
    let route_type = pfx_n.prefix.sub_tlvs.iter().find_map(|s| {
        if let PrefixDescriptorSubTlv::OspfRouteType(t) = s {
            Some(*t)
        } else {
            None
        }
    });
    assert_eq!(route_type, Some(OspfRouteType::External1));
    // RFC 7752 §3.2.1.4: OSPF Area-ID sub-TLV is 0 for AS-External
    // LSAs even when the projection context has a non-zero area ID.
    assert_eq!(pfx_n.local_node.ospf_area_id(), Some(0));
    assert_all_round_trip(&out);
}

#[test]
fn v3_as_external_lsa_type2_emits_external2_route_type() {
    let mut db = Lsdb::new();
    let dest = V3ExternalDestination::new(
        Prefix::new_v6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
            64,
        ),
        100,
        true, // type2
    );
    let lsa = originate_v3_as_external_lsa(0x01020304, 1, &dest, None).unwrap();
    install(&mut db, lsa);

    let out = project_area_lsdb_to_bgpls(&db, &CTX_V3);
    let BgpLsNlriVariant::Ipv6Prefix(pfx_n) = &out[0].variant else {
        panic!()
    };
    let route_type = pfx_n.prefix.sub_tlvs.iter().find_map(|s| {
        if let PrefixDescriptorSubTlv::OspfRouteType(t) = s {
            Some(*t)
        } else {
            None
        }
    });
    assert_eq!(route_type, Some(OspfRouteType::External2));
}

// ---------------------------------------------------------------------------
// diff_bgpls
// ---------------------------------------------------------------------------

#[test]
fn diff_empty_to_one_adds_everything() {
    let nlris = project_area_lsdb_to_bgpls(&Lsdb::new(), &CTX_V2);
    let d = diff_bgpls(&[], &nlris);
    assert_eq!(d.added, nlris);
    assert!(d.removed.is_empty());
    assert!(d.unchanged.is_empty());
}

#[test]
fn diff_one_to_empty_removes_everything() {
    let mut db = Lsdb::new();
    let lsa = originate_router_lsa(
        0x01020304,
        RouterLsaFlags::default(),
        &[RouterLsaLink::PointToPoint {
            neighbor: 0x05060708,
            local_addr: 0xc0a80101,
            metric: 10,
        }],
        None,
    )
    .unwrap();
    install(&mut db, lsa);
    let nlris = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    let d = diff_bgpls(&nlris, &[]);
    assert!(d.added.is_empty());
    assert_eq!(d.removed, nlris);
    assert!(d.unchanged.is_empty());
}

#[test]
fn diff_identical_projections_returns_only_unchanged() {
    let mut db = Lsdb::new();
    let lsa = originate_router_lsa(
        0x01020304,
        RouterLsaFlags::default(),
        &[RouterLsaLink::PointToPoint {
            neighbor: 0x05060708,
            local_addr: 0xc0a80101,
            metric: 10,
        }],
        None,
    )
    .unwrap();
    install(&mut db, lsa);
    let nlris = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    let d = diff_bgpls(&nlris, &nlris);
    assert!(d.added.is_empty());
    assert!(d.removed.is_empty());
    assert_eq!(d.unchanged.len(), nlris.len());
}

#[test]
fn diff_two_topologies_adds_and_removes_correctly() {
    // Two different router-LSAs: the projection of one has the
    // Node NLRI for router A; the projection of the other has the
    // Node NLRI for router B. The diff adds B's and removes A's.
    let mut db_a = Lsdb::new();
    install(
        &mut db_a,
        originate_router_lsa(
            0x01020304,
            RouterLsaFlags::default(),
            &[RouterLsaLink::PointToPoint {
                neighbor: 0x05060708,
                local_addr: 0xc0a80101,
                metric: 10,
            }],
            None,
        )
        .unwrap(),
    );
    let mut db_b = Lsdb::new();
    install(
        &mut db_b,
        originate_router_lsa(
            0x0a0b0c0d,
            RouterLsaFlags::default(),
            &[RouterLsaLink::PointToPoint {
                neighbor: 0x05060708,
                local_addr: 0xc0a80102,
                metric: 10,
            }],
            None,
        )
        .unwrap(),
    );
    let prev = project_area_lsdb_to_bgpls(&db_a, &CTX_V2);
    let curr = project_area_lsdb_to_bgpls(&db_b, &CTX_V2);
    let d = diff_bgpls(&prev, &curr);

    // Each projection has 1 Node + 1 Link = 2 NLRIs. The Node
    // NLRIs differ (different advertising router → different IGP
    // Router-ID → different bytes), and so do the Link NLRIs (the
    // local node + the IPv4 interface address differ).
    assert_eq!(d.added.len(), 2);
    assert_eq!(d.removed.len(), 2);
    assert!(d.unchanged.is_empty());
}

#[test]
fn diff_adds_new_router_when_router_lsa_appears() {
    // First projection: one router. Second projection: the same
    // router plus a new one. The diff should add the new router's
    // NLRIs and keep the existing ones unchanged.
    let mut db_a = Lsdb::new();
    install(
        &mut db_a,
        originate_router_lsa(
            0x01020304,
            RouterLsaFlags::default(),
            &[RouterLsaLink::PointToPoint {
                neighbor: 0x05060708,
                local_addr: 0xc0a80101,
                metric: 10,
            }],
            None,
        )
        .unwrap(),
    );
    let prev = project_area_lsdb_to_bgpls(&db_a, &CTX_V2);

    let mut db_b = db_a.clone_with_seq_bump(0);
    install(
        &mut db_b,
        originate_router_lsa(
            0x0a0b0c0d,
            RouterLsaFlags::default(),
            &[RouterLsaLink::PointToPoint {
                neighbor: 0x05060708,
                local_addr: 0xc0a80102,
                metric: 10,
            }],
            None,
        )
        .unwrap(),
    );
    let curr = project_area_lsdb_to_bgpls(&db_b, &CTX_V2);

    let d = diff_bgpls(&prev, &curr);
    assert_eq!(
        d.added.len(),
        2,
        "the new router contributes one Node + one Link NLRI"
    );
    assert!(d.removed.is_empty(), "no LSA was removed");
    assert_eq!(d.unchanged.len(), 2, "the existing router's NLRIs stay");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A `Lsdb` test helper: clones the LSDB but bumps the sequence
/// watermark of every entry by `n` so a fresh install with the same
/// sequence number does not get rejected as a duplicate. We use
/// this when we want to add a new LSA on top of an existing LSDB
/// without re-originating the existing LSAs — install() pushes
/// directly into the BTreeMap, bypassing the watermark check.
trait LsdbTestExt {
    fn clone_with_seq_bump(&self, _n: u32) -> Self;
}

impl LsdbTestExt for Lsdb {
    fn clone_with_seq_bump(&self, _n: u32) -> Self {
        // The Lsdb's `install` accepts a new LSA if its sequence is
        // strictly newer than the watermark. Tests that need to
        // build a fresh LSDB on top of an existing one should clone
        // the original — `Lsdb::clone` is available since `Lsdb`
        // derives Clone only in test code; we add a manual clone
        // here via `iter` + `install` so the watermark is rebuilt.
        let mut new = Lsdb::new();
        for (_, entry) in self.iter() {
            let _ = new.install(entry.lsa.clone(), 0);
        }
        new
    }
}

/// Verify the projection emits exactly the Local Node Descriptor
/// sub-TLV set we expect (AS, BGP-LS ID, OSPF Area-ID, IGP Router-ID),
/// in ascending sub-TLV type order (RFC 7752 §3.2.1.4 mandates it).
#[test]
fn node_descriptor_sub_tlv_order_is_ascending_by_type() {
    let mut db = Lsdb::new();
    install(
        &mut db,
        originate_router_lsa(
            0x01020304,
            RouterLsaFlags::default(),
            &[RouterLsaLink::PointToPoint {
                neighbor: 0x05060708,
                local_addr: 0xc0a80101,
                metric: 10,
            }],
            None,
        )
        .unwrap(),
    );
    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    let node = first_variant(&out, |v| matches!(v, BgpLsNlriVariant::Node(_)));
    let BgpLsNlriVariant::Node(node_n) = &node.variant else {
        unreachable!()
    };
    let tys: Vec<u16> = node_n.local_node.sub_tlvs.iter().map(|s| s.ty()).collect();
    assert_eq!(
        tys,
        vec![
            NodeDescriptorSubTlv::As(0).ty(),               // 512
            NodeDescriptorSubTlv::BgpLsId(0).ty(),          // 513
            NodeDescriptorSubTlv::OspfAreaId(0).ty(),       // 514
            NodeDescriptorSubTlv::IgpRouterId(vec![]).ty(), // 515
        ]
    );
}

/// Sanity: the empty LSDB projects to an empty NLRI set.
#[test]
fn empty_lsdb_projects_to_empty() {
    let out_v2 = project_area_lsdb_to_bgpls(&Lsdb::new(), &CTX_V2);
    let out_v3 = project_area_lsdb_to_bgpls(&Lsdb::new(), &CTX_V3);
    assert!(out_v2.is_empty());
    assert!(out_v3.is_empty());
}

/// The non-OSPF protocol context is a programming error; the
/// projection returns an empty NLRI set rather than panicking.
#[test]
fn non_ospf_protocol_context_yields_no_nlris() {
    let ctx = OspfAreaBgplsContext {
        as_number: 64512,
        bgp_ls_id: 0x100,
        area_id: 0,
        protocol: Protocol::Bgp,
    };
    let mut db = Lsdb::new();
    install(
        &mut db,
        originate_router_lsa(
            0x01020304,
            RouterLsaFlags::default(),
            &[RouterLsaLink::PointToPoint {
                neighbor: 0x05060708,
                local_addr: 0xc0a80101,
                metric: 10,
            }],
            None,
        )
        .unwrap(),
    );
    let out = project_area_lsdb_to_bgpls(&db, &ctx);
    assert!(out.is_empty());
}

/// A bare LSA with an unknown LSA type is silently skipped — the
/// projection does not synthesise Unknown NLRI for OSPF LSAs it
/// does not know how to model.
#[test]
fn unknown_lsa_type_is_silently_skipped() {
    let mut db = Lsdb::new();
    let lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0,
            ls_type: 99, // not a known OSPFv2 type
            link_state_id: 0,
            advertising_router: 0,
            ls_sequence_number: 0x80000001,
            ls_checksum: 0,
            length: LsaHeader::LEN as u16,
        },
        body: vec![],
    };
    install(&mut db, lsa);
    let out = project_area_lsdb_to_bgpls(&db, &CTX_V2);
    assert!(out.is_empty());
}
