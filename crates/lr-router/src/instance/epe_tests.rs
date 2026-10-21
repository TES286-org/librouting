//! Unit tests for the EPE projection (`project_epe_peer_sessions`).
//!
//! The codec surface (Node Descriptor sub-TLVs, BGP-LS Attribute
//! PeerNode/PeerAdj/PeerSet SID TLVs) is covered in
//! `lr-bgp/src/path/bgp_ls_tests.rs` and
//! `lr-bgp/src/path/bgp_ls_attr_tests.rs`. These tests verify the
//! projection assembles the codec surfaces correctly: the NLRI's
//! Protocol-ID is `Bgp`, the Local/Remote Node Descriptor carries
//! the expected sub-TLVs, the Link Descriptor carries MT-ID 0 plus
//! the supplied Interface/Neighbor addresses, and the attribute
//! carries the PeerNode SID + any optional PeerAdj/PeerSet SIDs.

#![cfg(test)]

use super::*;
use lr_bgp::path::bgp_ls::{
    BgpLsNlriVariant, LinkDescriptorSubTlv, NodeDescriptorSubTlv, ProtocolId,
};
use lr_bgp::path::bgp_ls_attr::{BgpPeeringSid, BgpPeeringSidFlags, BgpPeeringSidValue};
use lr_core::buf::WriteBuf;

/// Decode a `BgpLsNlri` from its canonical wire form. The codec
/// round-trips byte-for-byte (preserving every sub-TLV verbatim), so
/// a re-decode after the projection's encode is a stable identity
/// for assertions.
fn decode_nlri(bytes: &[u8]) -> BgpLsNlri {
    let (nlri, _consumed) = BgpLsNlri::decode(false, bytes).expect("decode BgpLsNlri");
    nlri
}

/// Round-trip helper: encode a `(BgpLsNlri, BgpLsAttr)` pair, decode
/// the NLRI back, and assert the decoded value equals the input.
/// Mirrors the contract the `bgp_ls_decode` fuzz target enforces.
fn assert_nlri_round_trips(nlri: &BgpLsNlri) {
    let mut buf = vec![0u8; nlri.wire_len()];
    let mut w = WriteBuf::new(&mut buf);
    nlri.encode(&mut w).expect("encode BgpLsNlri");
    let decoded = decode_nlri(&buf);
    assert_eq!(&decoded, nlri, "NLRI must round-trip byte-for-byte");
}

#[test]
fn empty_input_returns_empty_output() {
    let out = project_epe_peer_sessions(&[]);
    assert!(out.is_empty());
}

#[test]
fn one_session_emits_one_link_nlri_with_protocol_id_bgp() {
    let sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V | BgpPeeringSidFlags::L),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x21]),
    };
    let s = EpePeerSession::new(64512, 0x0a000001, 1, 64513, 0x0a000002, sid);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    assert_eq!(out.len(), 1);
    let (nlri, _attr) = &out[0];
    match &nlri.variant {
        BgpLsNlriVariant::Link(link) => {
            assert_eq!(
                link.protocol_id,
                ProtocolId::Bgp,
                "EPE Link NLRI Protocol-ID"
            );
            assert_eq!(link.identifier, 0, "EPE Link NLRI Identifier");
        }
        other => panic!("expected Link NLRI, got {other:?}"),
    }
    assert_nlri_round_trips(nlri);
}

#[test]
fn local_node_descriptor_carries_as_bgp_ls_id_and_bgp_router_id() {
    let sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x10]),
    };
    let s = EpePeerSession::new(64512, 0x0a000001, 0x01020304, 64513, 0x0a000002, sid);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (nlri, _) = &out[0];
    let BgpLsNlriVariant::Link(link) = &nlri.variant else {
        panic!("expected Link NLRI");
    };
    let local = &link.local_node;
    assert_eq!(
        &local.sub_tlvs,
        &[
            NodeDescriptorSubTlv::As(64512),
            NodeDescriptorSubTlv::BgpLsId(0x01020304),
            NodeDescriptorSubTlv::BgpRouterId(0x0a000001),
        ],
    );
}

#[test]
fn remote_node_descriptor_carries_peer_as_zero_bgp_ls_id_and_peer_bgp_id() {
    let sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x10]),
    };
    let s = EpePeerSession::new(64512, 0x0a000001, 1, 64513, 0x0a000002, sid);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (nlri, _) = &out[0];
    let BgpLsNlriVariant::Link(link) = &nlri.variant else {
        panic!("expected Link NLRI");
    };
    let remote = &link.remote_node;
    // BGP-LS ID is opaque to us — emit 0 (matches BIRD's bgp_ls).
    assert_eq!(
        &remote.sub_tlvs,
        &[
            NodeDescriptorSubTlv::As(64513),
            NodeDescriptorSubTlv::BgpLsId(0),
            NodeDescriptorSubTlv::BgpRouterId(0x0a000002),
        ],
    );
}

#[test]
fn local_confederation_member_emits_sub_tlv_in_local_node_descriptor() {
    let sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x10]),
    };
    let mut s = EpePeerSession::new(65000, 0x0a000001, 1, 65001, 0x0a000002, sid);
    s.local_confederation_member = Some(65000);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (nlri, _) = &out[0];
    let BgpLsNlriVariant::Link(link) = &nlri.variant else {
        panic!("expected Link NLRI");
    };
    assert_eq!(
        &link.local_node.sub_tlvs,
        &[
            NodeDescriptorSubTlv::As(65000),
            NodeDescriptorSubTlv::BgpLsId(1),
            NodeDescriptorSubTlv::BgpRouterId(0x0a000001),
            NodeDescriptorSubTlv::BgpConfederationMember(65000),
        ],
    );
}

#[test]
fn peer_confederation_member_emits_sub_tlv_in_remote_node_descriptor() {
    let sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x10]),
    };
    let mut s = EpePeerSession::new(65000, 0x0a000001, 1, 65001, 0x0a000002, sid);
    s.peer_confederation_member = Some(65001);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (nlri, _) = &out[0];
    let BgpLsNlriVariant::Link(link) = &nlri.variant else {
        panic!("expected Link NLRI");
    };
    assert_eq!(
        &link.remote_node.sub_tlvs,
        &[
            NodeDescriptorSubTlv::As(65001),
            NodeDescriptorSubTlv::BgpLsId(0),
            NodeDescriptorSubTlv::BgpRouterId(0x0a000002),
            NodeDescriptorSubTlv::BgpConfederationMember(65001),
        ],
    );
}

#[test]
fn link_descriptor_always_carries_mt_id_zero() {
    let sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x10]),
    };
    let s = EpePeerSession::new(64512, 0x0a000001, 1, 64513, 0x0a000002, sid);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (nlri, _) = &out[0];
    let BgpLsNlriVariant::Link(link) = &nlri.variant else {
        panic!("expected Link NLRI");
    };
    assert!(
        link.link
            .sub_tlvs
            .iter()
            .any(|t| matches!(t, LinkDescriptorSubTlv::MultiTopologyId(v) if v == &[0, 0])),
        "Link Descriptor must carry MT-ID 0; got {:?}",
        link.link.sub_tlvs,
    );
}

#[test]
fn ipv4_local_address_emits_ipv4_interface_address_sub_tlv() {
    let sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x10]),
    };
    let mut s = EpePeerSession::new(64512, 0x0a000001, 1, 64513, 0x0a000002, sid);
    s.local_address_v4 = Some([192, 0, 2, 1]);
    s.remote_address_v4 = Some([192, 0, 2, 2]);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (nlri, _) = &out[0];
    let BgpLsNlriVariant::Link(link) = &nlri.variant else {
        panic!("expected Link NLRI");
    };
    let sub_tlvs = &link.link.sub_tlvs;
    assert!(
        sub_tlvs.iter().any(
            |t| matches!(t, LinkDescriptorSubTlv::Ipv4InterfaceAddress(b) if b == &[192, 0, 2, 1])
        ),
        "Link Descriptor must carry IPv4 Interface Address 192.0.2.1; got {sub_tlvs:?}",
    );
    assert!(
        sub_tlvs.iter().any(
            |t| matches!(t, LinkDescriptorSubTlv::Ipv4NeighborAddress(b) if b == &[192, 0, 2, 2])
        ),
        "Link Descriptor must carry IPv4 Neighbor Address 192.0.2.2; got {sub_tlvs:?}",
    );
}

#[test]
fn ipv6_local_address_emits_ipv6_interface_address_sub_tlv() {
    let sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x10]),
    };
    let mut s = EpePeerSession::new(64512, 0x0a000001, 1, 64513, 0x0a000002, sid);
    let local_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let remote_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    s.local_address_v6 = Some(local_v6);
    s.remote_address_v6 = Some(remote_v6);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (nlri, _) = &out[0];
    let BgpLsNlriVariant::Link(link) = &nlri.variant else {
        panic!("expected Link NLRI");
    };
    let sub_tlvs = &link.link.sub_tlvs;
    assert!(
        sub_tlvs
            .iter()
            .any(|t| matches!(t, LinkDescriptorSubTlv::Ipv6InterfaceAddress(b) if b == &local_v6)),
        "Link Descriptor must carry IPv6 Interface Address; got {sub_tlvs:?}",
    );
    assert!(
        sub_tlvs
            .iter()
            .any(|t| matches!(t, LinkDescriptorSubTlv::Ipv6NeighborAddress(b) if b == &remote_v6)),
        "Link Descriptor must carry IPv6 Neighbor Address; got {sub_tlvs:?}",
    );
}

#[test]
fn attribute_carries_peer_node_sid_only_when_no_adj_or_set_provided() {
    let sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V | BgpPeeringSidFlags::L),
        weight: 5,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x21]),
    };
    let s = EpePeerSession::new(64512, 0x0a000001, 1, 64513, 0x0a000002, sid);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (_nlri, attr) = &out[0];
    let tlvs = &attr.tlvs;
    assert_eq!(tlvs.len(), 1, "only PeerNode SID when no adj/set provided");
    assert!(
        matches!(tlvs[0], BgpLsAttrTlv::PeerNodeSid(ref s) if s.flags.raw() == (BgpPeeringSidFlags::V | BgpPeeringSidFlags::L) && s.weight == 5 && matches!(s.sid, BgpPeeringSidValue::Label(b) if b == [0x00, 0x00, 0x21])),
        "PeerNode SID must match input; got {:?}",
        tlvs[0],
    );
}

#[test]
fn attribute_carries_peer_adj_and_peer_set_when_provided() {
    let peer_node_sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V | BgpPeeringSidFlags::L),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x21]),
    };
    let peer_adj_sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V | BgpPeeringSidFlags::L),
        weight: 1,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x22]),
    };
    let peer_set_sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V | BgpPeeringSidFlags::L),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x23]),
    };
    let mut s = EpePeerSession::new(64512, 0x0a000001, 1, 64513, 0x0a000002, peer_node_sid);
    s.peer_adj_sid = Some(peer_adj_sid);
    s.peer_set_sid = Some(peer_set_sid);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (_nlri, attr) = &out[0];
    let tlvs = &attr.tlvs;
    assert_eq!(tlvs.len(), 3, "PeerNode + PeerAdj + PeerSet TLVs");
    assert!(matches!(tlvs[0], BgpLsAttrTlv::PeerNodeSid(_)));
    assert!(matches!(tlvs[1], BgpLsAttrTlv::PeerAdjSid(_)));
    assert!(matches!(tlvs[2], BgpLsAttrTlv::PeerSetSid(_)));
}

#[test]
fn multiple_sessions_produce_one_nlri_per_session_in_input_order() {
    let sid_value = BgpPeeringSidValue::Label([0x00, 0x00, 0x21]);
    let mk_sid = |weight: u8| BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V | BgpPeeringSidFlags::L),
        weight,
        reserved: 0,
        sid: sid_value,
    };
    let sessions = vec![
        EpePeerSession::new(64512, 0x0a000001, 1, 64513, 0x0a000002, mk_sid(1)),
        EpePeerSession::new(64512, 0x0a000001, 1, 64514, 0x0a000003, mk_sid(2)),
        EpePeerSession::new(64512, 0x0a000001, 1, 64515, 0x0a000004, mk_sid(3)),
    ];
    let out = project_epe_peer_sessions(&sessions);
    assert_eq!(out.len(), 3);
    // Verify each NLRI has the expected peer BGP ID.
    for (i, (nlri, _)) in out.iter().enumerate() {
        let BgpLsNlriVariant::Link(link) = &nlri.variant else {
            panic!("expected Link NLRI");
        };
        let expected: u32 = 0x0a000000 | (i as u32 + 2);
        assert_eq!(
            &link.remote_node.sub_tlvs,
            &[
                NodeDescriptorSubTlv::As(64512 + 1 + i as u32),
                NodeDescriptorSubTlv::BgpLsId(0),
                NodeDescriptorSubTlv::BgpRouterId(expected),
            ],
            "session {i} must carry peer BGP ID 10.0.0.{}",
            i + 2,
        );
    }
}

#[test]
fn nlri_round_trips_byte_for_byte_on_full_epe_shape() {
    let peer_node_sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V | BgpPeeringSidFlags::L),
        weight: 7,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x21]),
    };
    let peer_adj_sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(
            BgpPeeringSidFlags::V | BgpPeeringSidFlags::L | BgpPeeringSidFlags::B,
        ),
        weight: 1,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x22]),
    };
    let peer_set_sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(BgpPeeringSidFlags::V | BgpPeeringSidFlags::P),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Label([0x00, 0x00, 0x23]),
    };
    let mut s = EpePeerSession::new(
        65000,
        0x0a000001,
        0x01020304,
        65001,
        0x0a000002,
        peer_node_sid,
    );
    s.local_confederation_member = Some(65000);
    s.peer_confederation_member = Some(65001);
    s.local_address_v4 = Some([192, 0, 2, 1]);
    s.remote_address_v4 = Some([192, 0, 2, 2]);
    s.peer_adj_sid = Some(peer_adj_sid);
    s.peer_set_sid = Some(peer_set_sid);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (nlri, attr) = &out[0];
    assert_nlri_round_trips(nlri);
    // Attribute round-trip: encode then decode.
    let encoded = attr.encode().expect("encode attribute");
    let decoded = lr_bgp::path::bgp_ls_attr::BgpLsAttr::decode(&encoded).expect("decode attribute");
    assert_eq!(&decoded, attr, "attribute must round-trip byte-for-byte");
}

#[test]
fn index_form_peer_node_sid_round_trips() {
    // PeerNode SID in index form (V flag clear, 4-byte SRGB index).
    let peer_node_sid = BgpPeeringSid {
        flags: BgpPeeringSidFlags::from_raw(0),
        weight: 0,
        reserved: 0,
        sid: BgpPeeringSidValue::Index(0x0000_0100),
    };
    let s = EpePeerSession::new(64512, 0x0a000001, 1, 64513, 0x0a000002, peer_node_sid);
    let out = project_epe_peer_sessions(std::slice::from_ref(&s));
    let (_nlri, attr) = &out[0];
    let tlvs = &attr.tlvs;
    assert_eq!(tlvs.len(), 1);
    assert!(
        matches!(tlvs[0], BgpLsAttrTlv::PeerNodeSid(ref s) if matches!(s.sid, BgpPeeringSidValue::Index(0x0000_0100))),
        "PeerNode SID must carry the index form; got {:?}",
        tlvs[0],
    );
    let encoded = attr.encode().expect("encode attribute");
    let decoded = lr_bgp::path::bgp_ls_attr::BgpLsAttr::decode(&encoded).expect("decode attribute");
    assert_eq!(&decoded, attr);
}
