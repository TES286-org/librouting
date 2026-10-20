//! OSPF LSDB → BGP-LS projection (RFC 7752 §3 + RFC 9514 §6-§8
//! SRv6 follow-up, including the End.X / LAN End.X projection that
//! attaches the §7 SRv6 Endpoint Behavior TLV to a projected SRv6
//! SID NLRI).
//!
//! Layer 2 of [issue #60]'s work breakdown. A pure function on the
//! area LSDB that produces the set of BGP-LS NLRI a controller needs
//! to rebuild the IGP graph the OSPF daemon holds. Sits beside
//! [`super::ospf`]; does not touch the daemon loop or transports.
//! The daemon-wiring half (Layer 3) and the interop lab against BIRD
//! (Layer 4) are follow-ups.
//!
//! # What the projection emits
//!
//! OSPFv2 (RFC 2328 → RFC 7752 §3.3):
//!
//! - **Node NLRI** per Router-LSA — the router's Local Node
//!   Descriptor carries the AS, BGP-LS ID, OSPF Area-ID, and a
//!   4-byte IGP Router-ID (the OSPF Router ID, RFC 7752 §3.2.1.4
//!   "OSPF non-pseudonode").
//! - **Node NLRI** per Network-LSA — the broadcast/NBMA pseudonode.
//!   The IGP Router-ID is 8 bytes: 4-byte OSPF Router ID of the DR
//!   followed by 4-byte Interface Address (the Network-LSA's
//!   link-state ID), per RFC 7752 §3.2.1.4 "OSPF pseudonode".
//! - **Link NLRI** per Router-LSA transit link — local router → DR
//!   pseudonode. The Link Descriptor carries IPv4 Interface Address
//!   (TLV 259, the router's interface IP = link-data) and IPv4
//!   Neighbor Address (TLV 260, the DR's interface IP = link-id).
//! - **Link NLRI** per Router-LSA point-to-point link — local
//!   router → peer router. The Link Descriptor carries the IPv4
//!   Interface Address (TLV 259). The remote IPv4 address is not
//!   carried by the Router-LSA, so TLV 260 is omitted (RFC 7752
//!   §3.2.2: "The IPv4 Neighbor Address is optional when the link
//!   is point-to-point").
//! - **IPv4 Topology Prefix NLRI** per Router-LSA stub link — the
//!   router's directly connected network. OSPF Route Type TLV (264)
//!   is `IntraArea`, prefix = link-id masked by link-data.
//! - **IPv4 Topology Prefix NLRI** per Summary-LSA (type 3) — the
//!   ABR's inter-area route. OSPF Route Type TLV is `InterArea`,
//!   prefix = link-state-id masked by the body's network mask.
//! - **IPv4 Topology Prefix NLRI** per AS-External-LSA (type 5) —
//!   the ASBR's external route. OSPF Route Type TLV is `External1`
//!   or `External2` (per the LSA's E-bit). Per RFC 7752 §3.2.1.4,
//!   the OSPF Area-ID sub-TLV is set to 0 for AS-External LSAs.
//!
//! OSPFv3 (RFC 5340 → RFC 7752 §3.3):
//!
//! - **Node NLRI** per Router-LSA (0x2001) — same shape as v2.
//! - **Node NLRI** per Network-LSA (0x2002) — pseudonode, with an
//!   8-byte IGP Router-ID (4-byte DR Router ID + 4-byte DR Interface
//!   ID = the Network-LSA's link-state ID).
//! - **Link NLRI** per Router-LSA transit / point-to-point link —
//!   the v3 Router-LSA carries interface IDs (not IPv4 addresses),
//!   so the Link Descriptor uses the Link Local/Remote Identifier
//!   TLV (258) with `(interface_id, neighbor_interface_id)`. For a
//!   transit link the remote node is the DR pseudonode, looked up
//!   from the Network-LSA whose link-state ID equals the transit
//!   link's `neighbor_interface_id`. For a P2P link the remote node
//!   is the peer router.
//! - **IPv6 Topology Prefix NLRI** per Intra-Area-Prefix-LSA (0x2009)
//!   — one NLRI per prefix in the body. The Local Node is the
//!   referenced LSA's node (router or pseudonode). OSPF Route Type
//!   is `IntraArea`.
//! - **IPv6 Topology Prefix NLRI** per Inter-Area-Prefix-LSA
//!   (0x2003) — one NLRI. Local Node is the ABR; OSPF Route Type is
//!   `InterArea`.
//! - **IPv6 Topology Prefix NLRI** per AS-External-LSA (0x4005) —
//!   one NLRI. Local Node is the ASBR; OSPF Area-ID sub-TLV is 0;
//!   OSPF Route Type is `External1` or `External2`.
//!
//! RFC 8362 Extended LSAs (E-Router, E-Network, E-Intra-Area-Prefix,
//! E-Inter-Area-Prefix, E-AS-External) carry the same topology
//! content in TLV-bodied shapes. The projection handles them when
//! they appear in the area LSDB — the v3 LSA type codes 0xA021,
//! 0xA022, 0xA023, 0xA029, 0xC025 are decoded with the same field
//! semantics.
//!
//! # Incremental republish
//!
//! [`diff_bgpls`] computes the added / removed / unchanged NLRI
//! sets between two projections by comparing the canonical wire
//! encoding of each NLRI (RFC 7752 §3.3 mandates byte-for-byte
//! NLRI comparison; the codec preserves every sub-TLV verbatim, so
//! the encoded bytes are a stable identity for set membership). A
//! caller running the projection once per LSDB change uses the
//! `added` and `removed` sets to drive incremental MP-BGP UPDATE
//! messages: a MP_REACH_NLRI for the `added` set, and an
//! MP_UNREACH_NLRI for the `removed` set.
//!
//! # Scope
//!
//! The SRv6 SID NLRI (RFC 9514 §6) projection from the OSPFv3
//! SRv6 database (RFC 9513 reception in [`lr_ospf::srv6db`]) is part
//! of the OSPFv3 path: [`project_v3`] builds a [`Srv6Database`] from
//! the same area LSDB and emits one SRv6 SID NLRI per End SID the
//! database holds. End.X / LAN End.X SIDs are projected separately by
//! [`project_v3_srv6_end_x_nlris`] because they carry a BGP-LS
//! Attribute (RFC 7752 §3.3) — the §7 SRv6 Endpoint Behavior TLV
//! (RFC 9514 §7.1) that distinguishes an End.X SID from an End SID
//! lives in the attribute surface, not in the NLRI. The plain NLRI
//! projection in [`project_area_lsdb_to_bgpls`] emits End SIDs only;
//! the End.X projection returns `(BgpLsNlri, BgpLsAttr)` pairs that
//! the daemon driver pushes through `advertise_bgpls_with_attr`.
//!
//! [issue #60]: https://github.com/TES286-org/librouting/issues/60

use std::collections::BTreeMap;

use lr_bgp::path::bgp_ls::{
    BgpLsNlri, BgpLsNlriVariant, LinkDescriptor, LinkDescriptorSubTlv, LinkNlri, NodeDescriptor,
    NodeDescriptorSubTlv, NodeNlri, OspfRouteType, PrefixDescriptor, PrefixDescriptorSubTlv,
    PrefixNlri, ProtocolId, Srv6SidDescriptor, Srv6SidDescriptorSubTlv, Srv6SidNlri,
};
use lr_bgp::path::bgp_ls_attr::{
    BgpLsAttr, BgpLsAttrTlv, Srv6EndpointBehavior, Srv6SidStructure as BgpLsSrv6SidStructure,
};
use lr_core::buf::WriteBuf;
use lr_core::rib::Protocol;
use lr_ospf::lsa::v3::{
    V3AsExternalBody, V3IntraAreaPrefixBody, V3Prefix, V3RouterLsaBody, LINK_TYPE_POINTTOPOINT,
    LINK_TYPE_TRANSIT, LINK_TYPE_VIRTUAL,
};
use lr_ospf::lsa::{
    self, decode_as_external_body, decode_summary_lsa_body, decode_v3_inter_area_prefix_body,
    mask_to_prefix_len, EAsExternalLsaBody, EInterAreaPrefixLsaBody, EIntraAreaPrefixLsaBody,
    ERouterLsaBody, Lsa, LsaTypeV2,
};
use lr_ospf::lsa::{
    LS_TYPE_AS_EXTERNAL, LS_TYPE_E_AS_EXTERNAL, LS_TYPE_E_INTER_PREFIX, LS_TYPE_E_INTRA_PREFIX,
    LS_TYPE_E_NETWORK, LS_TYPE_E_ROUTER, LS_TYPE_INTER_PREFIX, LS_TYPE_INTRA_PREFIX,
    LS_TYPE_NETWORK, LS_TYPE_ROUTER,
};
use lr_ospf::lsdb::Lsdb;
use lr_ospf::srv6db::Srv6Database;

/// Per-area context the projection needs from the daemon. The four
/// fields are exactly the Local Node Descriptor sub-TLVs every Node
/// NLRI emits (RFC 7752 §3.2.1.4). `as_number` and `bgp_ls_id` come
/// from the daemon's BGP-LS speaker configuration; `area_id` and
/// `protocol` come from the OSPF area being projected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfAreaBgplsContext {
    /// RFC 7752 §3.2.1.4 — Autonomous System sub-TLV (512). The 4-byte
    /// AS number of the BGP-LS speaker. The projection does not
    /// enforce uniqueness; the daemon's config surface owns that.
    pub as_number: u32,
    /// RFC 7752 §3.2.1.4 — BGP-LS Identifier sub-TLV (513). A 4-byte
    /// identifier unique within the AS; together with the AS it
    /// names one BGP-LS speaker.
    pub bgp_ls_id: u32,
    /// RFC 7752 §3.2.1.4 — OSPF Area-ID sub-TLV (514). The area being
    /// projected. Set to 0 for AS-External LSAs per RFC 7752
    /// §3.2.1.4.
    pub area_id: u32,
    /// Which OSPF version the area runs. Picks the
    /// [`ProtocolId::Ospfv2`] / [`ProtocolId::Ospfv3`] tag on every
    /// emitted NLRI and the LSA-type match arms in the projection.
    pub protocol: Protocol,
}

impl OspfAreaBgplsContext {
    /// The BGP-LS Protocol-ID (RFC 7752 §3.3 Table 2) for this area.
    pub fn bgpls_protocol_id(self) -> ProtocolId {
        match self.protocol {
            Protocol::Ospfv2 => ProtocolId::Ospfv2,
            Protocol::Ospfv3 => ProtocolId::Ospfv3,
            // Defensive: the projection is only called from an OSPF
            // area; any other value is a programming error. Fall
            // through to Ospfv2 so a misconfigured caller does not
            // produce NLRIs that pretend to be OSPFv3.
            _ => ProtocolId::Ospfv2,
        }
    }
}

/// Project one OSPF area's LSDB onto the BGP-LS NLRI set (RFC 7752
/// §3 + RFC 9514 §6 SRv6 SID NLRI for OSPFv3).
///
/// Pure function. Walks the LSDB once in `LsaKey` ascending order
/// (the LSDB's `BTreeMap` iteration order). The result is suitable
/// for direct MP-BGP UPDATE messages; sort or deduplicate as the
/// caller prefers — the projection does not coalesce, so two
/// areas that share a router will each emit a Node NLRI for it when
/// called separately with different `ctx.area_id`.
pub fn project_area_lsdb_to_bgpls(lsdb: &Lsdb, ctx: &OspfAreaBgplsContext) -> Vec<BgpLsNlri> {
    let mut out: Vec<BgpLsNlri> = Vec::new();
    match ctx.protocol {
        Protocol::Ospfv2 => project_v2(lsdb, ctx, &mut out),
        Protocol::Ospfv3 => project_v3(lsdb, ctx, &mut out),
        _ => {}
    }
    out
}

/// Result of comparing two projections for incremental republish.
///
/// The daemon emits `added` as MP_REACH_NLRI and `removed` as
/// MP_UNREACH_NLRI; `unchanged` is carried for accounting only and
/// is not re-advertised (RFC 4271 §9.2.1.2: "the route is not
/// added to the Adj-RIB-Out if the new path attribute equals the
/// old one").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgplsDiff {
    pub added: Vec<BgpLsNlri>,
    pub removed: Vec<BgpLsNlri>,
    pub unchanged: Vec<BgpLsNlri>,
}

/// Diff two projections by canonical wire form (RFC 7752 §3.3: NLRI
/// comparison is byte-for-byte).
///
/// Builds a `BTreeMap<Vec<u8>, BgpLsNlri>` keyed on the encoded NLRI
/// bytes (the codec round-trips byte-for-byte, so the encoded form
/// is a stable identity). Two NLRI instances that decode to equal
/// `BgpLsNlri` values encode to the same bytes — the codec's
/// unknown-TLV-passthrough guarantees no lossy normalisation.
pub fn diff_bgpls(prev: &[BgpLsNlri], curr: &[BgpLsNlri]) -> BgplsDiff {
    let prev_map = index_by_wire(prev);
    let curr_map = index_by_wire(curr);
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = Vec::new();
    // Walk prev first so the removed list stays in the prev order,
    // then walk curr for added and unchanged — keeps both lists
    // deterministic for a test.
    for (k, v) in &prev_map {
        if curr_map.contains_key(k) {
            unchanged.push(v.clone());
        } else {
            removed.push(v.clone());
        }
    }
    for (k, v) in &curr_map {
        if !prev_map.contains_key(k) {
            added.push(v.clone());
        }
    }
    BgplsDiff {
        added,
        removed,
        unchanged,
    }
}

/// Index NLRIs by their canonical wire bytes. Used by [`diff_bgpls`]
/// for byte-for-byte NLRI comparison (RFC 7752 §3.3).
fn index_by_wire(nlris: &[BgpLsNlri]) -> BTreeMap<Vec<u8>, BgpLsNlri> {
    let mut m = BTreeMap::new();
    for n in nlris {
        m.insert(nlri_wire_bytes(n), n.clone());
    }
    m
}

/// Encode one NLRI to its canonical wire form. The codec's
/// round-trip property (preserving every sub-TLV verbatim) makes
/// the encoded bytes a stable identity for set membership.
fn nlri_wire_bytes(n: &BgpLsNlri) -> Vec<u8> {
    let mut v = vec![0u8; n.wire_len()];
    let mut buf = WriteBuf::new(&mut v);
    let _ = n.encode(&mut buf).expect("buffer pre-sized");
    v
}

// ---------------------------------------------------------------------------
// OSPFv2 projection (RFC 2328 → RFC 7752 §3.3)
// ---------------------------------------------------------------------------

fn project_v2(lsdb: &Lsdb, ctx: &OspfAreaBgplsContext, out: &mut Vec<BgpLsNlri>) {
    // First pass: collect the Network-LSAs so the transit-link
    // projection can look the DR up by the link's `link_id` (the DR's
    // interface address) — see `project_v2_router_lsa`.
    let mut dr_by_iface_ip: BTreeMap<u32, u32> = BTreeMap::new();
    for (_, entry) in lsdb.iter() {
        if entry.lsa.header.ls_type == LsaTypeV2::NetworkLsa as u16 {
            dr_by_iface_ip.insert(
                entry.lsa.header.link_state_id,
                entry.lsa.header.advertising_router,
            );
        }
    }

    for (_, entry) in lsdb.iter() {
        let lsa = &entry.lsa;
        match lsa.header.ls_type {
            t if t == LsaTypeV2::RouterLsa as u16 => {
                project_v2_router_lsa(lsa, ctx, &dr_by_iface_ip, out)
            }
            t if t == LsaTypeV2::NetworkLsa as u16 => project_v2_network_lsa(lsa, ctx, out),
            t if t == LsaTypeV2::SummaryIpLsa as u16 => project_v2_summary_lsa(lsa, ctx, out),
            t if t == LsaTypeV2::AsExternalLsa as u16 => project_v2_as_external_lsa(lsa, ctx, out),
            _ => {}
        }
    }
}

/// Build the Local Node Descriptor for one OSPFv2 Router-LSA's
/// router: 4-byte IGP Router-ID, non-pseudonode (RFC 7752 §3.2.1.4).
fn v2_router_node_descriptor(router_id: u32, ctx: &OspfAreaBgplsContext) -> NodeDescriptor {
    NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(ctx.as_number),
        NodeDescriptorSubTlv::BgpLsId(ctx.bgp_ls_id),
        NodeDescriptorSubTlv::OspfAreaId(ctx.area_id),
        NodeDescriptorSubTlv::IgpRouterId(router_id.to_be_bytes().to_vec()),
    ])
}

/// Build the Local Node Descriptor for the OSPFv2 pseudonode of a
/// Network-LSA: 8-byte IGP Router-ID = DR Router ID + DR interface
/// address (RFC 7752 §3.2.1.4 "OSPF pseudonode").
fn v2_pseudonode_descriptor(
    dr_router_id: u32,
    dr_iface_addr: u32,
    ctx: &OspfAreaBgplsContext,
) -> NodeDescriptor {
    let mut igp = Vec::with_capacity(8);
    igp.extend_from_slice(&dr_router_id.to_be_bytes());
    igp.extend_from_slice(&dr_iface_addr.to_be_bytes());
    NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(ctx.as_number),
        NodeDescriptorSubTlv::BgpLsId(ctx.bgp_ls_id),
        NodeDescriptorSubTlv::OspfAreaId(ctx.area_id),
        NodeDescriptorSubTlv::IgpRouterId(igp),
    ])
}

fn project_v2_router_lsa(
    lsa: &Lsa,
    ctx: &OspfAreaBgplsContext,
    dr_by_iface_ip: &BTreeMap<u32, u32>,
    out: &mut Vec<BgpLsNlri>,
) {
    let adv = lsa.header.advertising_router;
    let local_node = v2_router_node_descriptor(adv, ctx);
    // One Node NLRI per Router-LSA. RFC 2328 §12.4.1: a router
    // originates one Router-LSA per area (ls_id = its own Router ID),
    // so the (adv, ls_id) pair is unique per area.
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Node(NodeNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node: local_node.clone(),
        }),
    });

    // Walk the link descriptors: transit + P2P produce Link NLRIs,
    // stub produces an IPv4 Prefix NLRI.
    for link in lr_ospf::spf::decode_router_links(&lsa.body) {
        match link.link_type {
            t if t == lsa::RouterLinkType::TransitNetwork as u8 => {
                // Local router → DR pseudonode. Remote node's IGP
                // Router-ID needs the DR's Router ID — look it up in
                // the Network-LSA table built in the first pass.
                if let Some(&dr) = dr_by_iface_ip.get(&link.link_id) {
                    let remote_node = v2_pseudonode_descriptor(dr, link.link_id, ctx);
                    let link_desc = LinkDescriptor::new(vec![
                        LinkDescriptorSubTlv::Ipv4InterfaceAddress(link.link_data.to_be_bytes()),
                        LinkDescriptorSubTlv::Ipv4NeighborAddress(link.link_id.to_be_bytes()),
                    ]);
                    out.push(BgpLsNlri {
                        route_distinguisher: None,
                        variant: BgpLsNlriVariant::Link(LinkNlri {
                            protocol_id: ctx.bgpls_protocol_id(),
                            identifier: 0,
                            local_node: local_node.clone(),
                            remote_node,
                            link: link_desc,
                        }),
                    });
                }
                // If the Network-LSA is not in the LSDB yet (the DR
                // has not originated it), the remote node descriptor
                // cannot be built — skip emitting the Link NLRI. The
                // caller will see the link when the Network-LSA
                // arrives and the next projection runs.
            }
            t if t == lsa::RouterLinkType::PointToPoint as u8
                || t == lsa::RouterLinkType::VirtualLink as u8 =>
            {
                // Local router → peer router. The peer is identified
                // by `link_id` (the peer's Router ID).
                let remote_node = v2_router_node_descriptor(link.link_id, ctx);
                let link_desc =
                    LinkDescriptor::new(vec![LinkDescriptorSubTlv::Ipv4InterfaceAddress(
                        link.link_data.to_be_bytes(),
                    )]);
                out.push(BgpLsNlri {
                    route_distinguisher: None,
                    variant: BgpLsNlriVariant::Link(LinkNlri {
                        protocol_id: ctx.bgpls_protocol_id(),
                        identifier: 0,
                        local_node: local_node.clone(),
                        remote_node,
                        link: link_desc,
                    }),
                });
            }
            t if t == lsa::RouterLinkType::StubNetwork as u8 => {
                // Stub network: link_id = network number, link_data =
                // network mask. The router is the originator; OSPF
                // Route Type is IntraArea.
                let prefix_len = mask_to_prefix_len(link.link_data);
                let prefix_bytes = link.link_id.to_be_bytes().to_vec();
                let prefix_desc = PrefixDescriptor::new(vec![
                    PrefixDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
                    PrefixDescriptorSubTlv::OspfRouteType(OspfRouteType::IntraArea),
                    PrefixDescriptorSubTlv::IpReachabilityInfo {
                        prefix_len,
                        prefix_bytes,
                    },
                ]);
                out.push(BgpLsNlri {
                    route_distinguisher: None,
                    variant: BgpLsNlriVariant::Ipv4Prefix(PrefixNlri {
                        protocol_id: ctx.bgpls_protocol_id(),
                        identifier: 0,
                        local_node: local_node.clone(),
                        prefix: prefix_desc,
                    }),
                });
            }
            _ => {}
        }
    }
}

fn project_v2_network_lsa(lsa: &Lsa, ctx: &OspfAreaBgplsContext, out: &mut Vec<BgpLsNlri>) {
    // Pseudonode Node NLRI. The DR is the advertising router; its
    // interface address is the link-state ID.
    let dr_router_id = lsa.header.advertising_router;
    let dr_iface_addr = lsa.header.link_state_id;
    let local_node = v2_pseudonode_descriptor(dr_router_id, dr_iface_addr, ctx);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Node(NodeNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node,
        }),
    });
}

fn project_v2_summary_lsa(lsa: &Lsa, ctx: &OspfAreaBgplsContext, out: &mut Vec<BgpLsNlri>) {
    // OSPFv2 type-3 Summary-LSA: the ABR's inter-area prefix.
    let Some(body) = decode_summary_lsa_body(&lsa.body) else {
        return;
    };
    if !body.tos_metrics.iter().any(|m| m.tos == 0) {
        // A Summary-LSA without a TOS-0 metric carries no usable
        // inter-area route — skip emitting a Prefix NLRI for it.
        return;
    }
    let prefix_len = mask_to_prefix_len(body.network_mask);
    let prefix_bytes = lsa.header.link_state_id.to_be_bytes().to_vec();
    let abr = lsa.header.advertising_router;
    let local_node = v2_router_node_descriptor(abr, ctx);
    let prefix_desc = PrefixDescriptor::new(vec![
        PrefixDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
        PrefixDescriptorSubTlv::OspfRouteType(OspfRouteType::InterArea),
        PrefixDescriptorSubTlv::IpReachabilityInfo {
            prefix_len,
            prefix_bytes,
        },
    ]);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Ipv4Prefix(PrefixNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node,
            prefix: prefix_desc,
        }),
    });
}

fn project_v2_as_external_lsa(lsa: &Lsa, ctx: &OspfAreaBgplsContext, out: &mut Vec<BgpLsNlri>) {
    let Some(entry) = decode_as_external_body(&lsa.body) else {
        return;
    };
    // RFC 7752 §3.2.1.4: OSPF Area-ID sub-TLV is 0 for AS-External
    // LSAs (the LSA is AS-scoped, not area-scoped).
    let asbr = lsa.header.advertising_router;
    let local_node = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(ctx.as_number),
        NodeDescriptorSubTlv::BgpLsId(ctx.bgp_ls_id),
        NodeDescriptorSubTlv::OspfAreaId(0),
        NodeDescriptorSubTlv::IgpRouterId(asbr.to_be_bytes().to_vec()),
    ]);
    let route_type = if entry.external_type2() {
        OspfRouteType::External2
    } else {
        OspfRouteType::External1
    };
    let prefix_len = mask_to_prefix_len(entry.network_mask);
    let prefix_bytes = lsa.header.link_state_id.to_be_bytes().to_vec();
    let prefix_desc = PrefixDescriptor::new(vec![
        PrefixDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
        PrefixDescriptorSubTlv::OspfRouteType(route_type),
        PrefixDescriptorSubTlv::IpReachabilityInfo {
            prefix_len,
            prefix_bytes,
        },
    ]);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Ipv4Prefix(PrefixNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node,
            prefix: prefix_desc,
        }),
    });
}

// ---------------------------------------------------------------------------
// OSPFv3 projection (RFC 5340 → RFC 7752 §3.3)
// ---------------------------------------------------------------------------

fn project_v3(lsdb: &Lsdb, ctx: &OspfAreaBgplsContext, out: &mut Vec<BgpLsNlri>) {
    // First pass: collect Network-LSAs (legacy + E-) so transit links
    // can look the DR up by Interface ID (the Network-LSA's link-
    // state ID equals the DR's Interface ID).
    let mut dr_by_iface_id: BTreeMap<u32, u32> = BTreeMap::new();
    for (_, entry) in lsdb.iter() {
        match entry.lsa.header.ls_type {
            LS_TYPE_NETWORK | LS_TYPE_E_NETWORK => {
                dr_by_iface_id.insert(
                    entry.lsa.header.link_state_id,
                    entry.lsa.header.advertising_router,
                );
            }
            _ => {}
        }
    }

    for (_, entry) in lsdb.iter() {
        let lsa = &entry.lsa;
        match lsa.header.ls_type {
            LS_TYPE_ROUTER => project_v3_router_lsa::<false>(lsa, ctx, &dr_by_iface_id, out),
            LS_TYPE_E_ROUTER => project_v3_router_lsa::<true>(lsa, ctx, &dr_by_iface_id, out),
            LS_TYPE_NETWORK | LS_TYPE_E_NETWORK => project_v3_network_lsa(lsa, ctx, out),
            LS_TYPE_INTRA_PREFIX => project_v3_intra_area_prefix_lsa(lsa, ctx, out),
            LS_TYPE_E_INTRA_PREFIX => project_v3_e_intra_area_prefix_lsa(lsa, ctx, out),
            LS_TYPE_INTER_PREFIX => project_v3_inter_area_prefix_lsa(lsa, ctx, out),
            LS_TYPE_E_INTER_PREFIX => project_v3_e_inter_area_prefix_lsa(lsa, ctx, out),
            LS_TYPE_AS_EXTERNAL => project_v3_as_external_lsa(lsa, ctx, out),
            LS_TYPE_E_AS_EXTERNAL => project_v3_e_as_external_lsa(lsa, ctx, out),
            _ => {}
        }
    }

    // RFC 9514 §6 SRv6 SID NLRIs. A second pass over the same area
    // LSDB through the SRv6 database (RFC 9513 reception) — the LSA
    // walk above does not touch the SRv6 LSA families (Router
    // Information 0xA00C and SRv6 Locator 0xA02A), so the SRv6
    // projection is its own concern. The OSPFv2 match arm does not
    // call this — SRv6 is OSPFv3-only per RFC 9513.
    project_v3_srv6_sid_nlris(lsdb, ctx, out);
}

/// Build the Local Node Descriptor for one OSPFv3 router: 4-byte
/// IGP Router-ID (RFC 7752 §3.2.1.4).
fn v3_router_node_descriptor(router_id: u32, ctx: &OspfAreaBgplsContext) -> NodeDescriptor {
    NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(ctx.as_number),
        NodeDescriptorSubTlv::BgpLsId(ctx.bgp_ls_id),
        NodeDescriptorSubTlv::OspfAreaId(ctx.area_id),
        NodeDescriptorSubTlv::IgpRouterId(router_id.to_be_bytes().to_vec()),
    ])
}

/// Build the Local Node Descriptor for an OSPFv3 pseudonode: 8-byte
/// IGP Router-ID = DR Router ID + DR Interface ID (RFC 7752
/// §3.2.1.4).
fn v3_pseudonode_descriptor(
    dr_router_id: u32,
    dr_iface_id: u32,
    ctx: &OspfAreaBgplsContext,
) -> NodeDescriptor {
    let mut igp = Vec::with_capacity(8);
    igp.extend_from_slice(&dr_router_id.to_be_bytes());
    igp.extend_from_slice(&dr_iface_id.to_be_bytes());
    NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(ctx.as_number),
        NodeDescriptorSubTlv::BgpLsId(ctx.bgp_ls_id),
        NodeDescriptorSubTlv::OspfAreaId(ctx.area_id),
        NodeDescriptorSubTlv::IgpRouterId(igp),
    ])
}

/// Common link shape — the legacy v3 Router-LSA link and the E-Router-LSA
/// Router-Link TLV carry the same five fields the projection cares about.
/// Used to share the Link NLRI emission between the two LSA shapes.
struct V3RouterLink {
    link_type: u8,
    interface_id: u32,
    neighbor_interface_id: u32,
    neighbor_router_id: u32,
}

/// Project a Router-LSA (legacy or E-) into a Node NLRI plus one
/// Link NLRI per transit / P2P link. The `EXTENDED` const selects
/// the decoder so the call-site keeps the E-LSA match arm separate
/// (the projection's behaviour is otherwise identical — both LSA
/// shapes carry the same Router-Link content).
fn project_v3_router_lsa<const EXTENDED: bool>(
    lsa: &Lsa,
    ctx: &OspfAreaBgplsContext,
    dr_by_iface_id: &BTreeMap<u32, u32>,
    out: &mut Vec<BgpLsNlri>,
) {
    let adv = lsa.header.advertising_router;
    let local_node = v3_router_node_descriptor(adv, ctx);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Node(NodeNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node: local_node.clone(),
        }),
    });

    // Decode the Router-LSA body — legacy v3 (0x2001) or E-Router
    // (0xA021). Both carry the same five link fields the projection
    // needs; the E-LSA wraps each in a Router-Link TLV.
    let links: Vec<V3RouterLink> = if EXTENDED {
        let Some(body) = ERouterLsaBody::decode(&lsa.body) else {
            return;
        };
        body.links
            .into_iter()
            .map(|l| V3RouterLink {
                link_type: l.link_type,
                interface_id: l.interface_id,
                neighbor_interface_id: l.neighbor_interface_id,
                neighbor_router_id: l.neighbor_router_id,
            })
            .collect()
    } else {
        let Some(body) = V3RouterLsaBody::decode(&lsa.body) else {
            return;
        };
        body.links
            .into_iter()
            .map(|l| V3RouterLink {
                link_type: l.link_type,
                interface_id: l.interface_id,
                neighbor_interface_id: l.neighbor_interface_id,
                neighbor_router_id: l.neighbor_router_id,
            })
            .collect()
    };

    for link in links {
        match link.link_type {
            LINK_TYPE_TRANSIT => {
                // Local router → DR pseudonode. The DR's Interface
                // ID is `link.neighbor_interface_id`; look the DR
                // Router ID up in the Network-LSA table built in
                // the first pass.
                if let Some(&dr) = dr_by_iface_id.get(&link.neighbor_interface_id) {
                    let remote_node = v3_pseudonode_descriptor(dr, link.neighbor_interface_id, ctx);
                    let link_desc =
                        LinkDescriptor::new(vec![LinkDescriptorSubTlv::LinkLocalRemoteId {
                            local: link.interface_id,
                            remote: link.neighbor_interface_id,
                        }]);
                    out.push(BgpLsNlri {
                        route_distinguisher: None,
                        variant: BgpLsNlriVariant::Link(LinkNlri {
                            protocol_id: ctx.bgpls_protocol_id(),
                            identifier: 0,
                            local_node: local_node.clone(),
                            remote_node,
                            link: link_desc,
                        }),
                    });
                }
            }
            LINK_TYPE_POINTTOPOINT | LINK_TYPE_VIRTUAL => {
                // Local router → peer router. The peer is identified
                // by `link.neighbor_router_id`.
                let remote_node = v3_router_node_descriptor(link.neighbor_router_id, ctx);
                let link_desc =
                    LinkDescriptor::new(vec![LinkDescriptorSubTlv::LinkLocalRemoteId {
                        local: link.interface_id,
                        remote: link.neighbor_interface_id,
                    }]);
                out.push(BgpLsNlri {
                    route_distinguisher: None,
                    variant: BgpLsNlriVariant::Link(LinkNlri {
                        protocol_id: ctx.bgpls_protocol_id(),
                        identifier: 0,
                        local_node: local_node.clone(),
                        remote_node,
                        link: link_desc,
                    }),
                });
            }
            _ => {}
        }
    }
}

fn project_v3_network_lsa(lsa: &Lsa, ctx: &OspfAreaBgplsContext, out: &mut Vec<BgpLsNlri>) {
    let dr_router_id = lsa.header.advertising_router;
    let dr_iface_id = lsa.header.link_state_id;
    let local_node = v3_pseudonode_descriptor(dr_router_id, dr_iface_id, ctx);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Node(NodeNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node,
        }),
    });
}

fn project_v3_intra_area_prefix_lsa(
    lsa: &Lsa,
    ctx: &OspfAreaBgplsContext,
    out: &mut Vec<BgpLsNlri>,
) {
    let Some(body) = V3IntraAreaPrefixBody::decode(&lsa.body) else {
        return;
    };
    // The referenced LSA identifies the local node. Per RFC 5340
    // §A.4.10, `ref_type` is LS_TYPE_ROUTER (the router's own
    // interface prefixes) or LS_TYPE_NETWORK (the network's prefix,
    // originated by the DR).
    let local_node = match body.ref_type {
        LS_TYPE_ROUTER => v3_router_node_descriptor(body.ref_adv_router, ctx),
        LS_TYPE_NETWORK => v3_pseudonode_descriptor(body.ref_adv_router, body.ref_ls_id, ctx),
        _ => return,
    };
    for prefix in body.prefixes {
        push_v3_ipv6_prefix_nlri(ctx, &local_node, &prefix, OspfRouteType::IntraArea, out);
    }
}

fn project_v3_e_intra_area_prefix_lsa(
    lsa: &Lsa,
    ctx: &OspfAreaBgplsContext,
    out: &mut Vec<BgpLsNlri>,
) {
    let Some(body) = EIntraAreaPrefixLsaBody::decode(&lsa.body) else {
        return;
    };
    // The E-Intra-Area-Prefix-LSA's ref_type points to the
    // E-Router-LSA or E-Network-LSA. Same local-node construction
    // as the legacy form, except `ref_type` is the E-LSA code.
    let local_node = if body.ref_type == LS_TYPE_E_ROUTER {
        v3_router_node_descriptor(body.ref_adv_router, ctx)
    } else if body.ref_type == LS_TYPE_E_NETWORK {
        v3_pseudonode_descriptor(body.ref_adv_router, body.ref_ls_id, ctx)
    } else {
        // Fall back to the advertising router for unknown ref types —
        // the projection still emits the prefix, the controller can
        // associate it.
        v3_router_node_descriptor(body.ref_adv_router, ctx)
    };
    for tlv in body.prefixes {
        push_v3_ipv6_prefix_nlri(ctx, &local_node, &tlv.prefix, OspfRouteType::IntraArea, out);
    }
}

fn project_v3_inter_area_prefix_lsa(
    lsa: &Lsa,
    ctx: &OspfAreaBgplsContext,
    out: &mut Vec<BgpLsNlri>,
) {
    let Some(body) = decode_v3_inter_area_prefix_body(&lsa.body) else {
        return;
    };
    let prefix_bytes = body.prefix_bytes.clone();
    let abr = lsa.header.advertising_router;
    let local_node = v3_router_node_descriptor(abr, ctx);
    let prefix_desc = PrefixDescriptor::new(vec![
        PrefixDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
        PrefixDescriptorSubTlv::OspfRouteType(OspfRouteType::InterArea),
        PrefixDescriptorSubTlv::IpReachabilityInfo {
            prefix_len: body.prefix_len,
            prefix_bytes,
        },
    ]);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Ipv6Prefix(PrefixNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node,
            prefix: prefix_desc,
        }),
    });
}

fn project_v3_e_inter_area_prefix_lsa(
    lsa: &Lsa,
    ctx: &OspfAreaBgplsContext,
    out: &mut Vec<BgpLsNlri>,
) {
    let Some(body) = EInterAreaPrefixLsaBody::decode(&lsa.body) else {
        return;
    };
    let prefix = &body.0.prefix;
    let abr = lsa.header.advertising_router;
    let local_node = v3_router_node_descriptor(abr, ctx);
    let prefix_desc = PrefixDescriptor::new(vec![
        PrefixDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
        PrefixDescriptorSubTlv::OspfRouteType(OspfRouteType::InterArea),
        PrefixDescriptorSubTlv::IpReachabilityInfo {
            prefix_len: prefix.prefix_len,
            prefix_bytes: prefix.addr.to_vec(),
        },
    ]);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Ipv6Prefix(PrefixNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node,
            prefix: prefix_desc,
        }),
    });
}

fn project_v3_as_external_lsa(lsa: &Lsa, ctx: &OspfAreaBgplsContext, out: &mut Vec<BgpLsNlri>) {
    let Some(body) = V3AsExternalBody::decode(&lsa.body) else {
        return;
    };
    let asbr = lsa.header.advertising_router;
    let local_node = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(ctx.as_number),
        NodeDescriptorSubTlv::BgpLsId(ctx.bgp_ls_id),
        // RFC 7752 §3.2.1.4: OSPF Area-ID sub-TLV is 0 for AS-External.
        NodeDescriptorSubTlv::OspfAreaId(0),
        NodeDescriptorSubTlv::IgpRouterId(asbr.to_be_bytes().to_vec()),
    ]);
    let route_type = if body.e_bit {
        OspfRouteType::External2
    } else {
        OspfRouteType::External1
    };
    let prefix_desc = PrefixDescriptor::new(vec![
        PrefixDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
        PrefixDescriptorSubTlv::OspfRouteType(route_type),
        PrefixDescriptorSubTlv::IpReachabilityInfo {
            prefix_len: body.prefix.prefix_len,
            prefix_bytes: body.prefix.addr.to_vec(),
        },
    ]);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Ipv6Prefix(PrefixNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node,
            prefix: prefix_desc,
        }),
    });
}

fn project_v3_e_as_external_lsa(lsa: &Lsa, ctx: &OspfAreaBgplsContext, out: &mut Vec<BgpLsNlri>) {
    let Some(body) = EAsExternalLsaBody::decode(&lsa.body) else {
        return;
    };
    let external = &body.0;
    let asbr = lsa.header.advertising_router;
    let local_node = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(ctx.as_number),
        NodeDescriptorSubTlv::BgpLsId(ctx.bgp_ls_id),
        NodeDescriptorSubTlv::OspfAreaId(0),
        NodeDescriptorSubTlv::IgpRouterId(asbr.to_be_bytes().to_vec()),
    ]);
    let route_type = if external.e_bit {
        OspfRouteType::External2
    } else {
        OspfRouteType::External1
    };
    let prefix_desc = PrefixDescriptor::new(vec![
        PrefixDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
        PrefixDescriptorSubTlv::OspfRouteType(route_type),
        PrefixDescriptorSubTlv::IpReachabilityInfo {
            prefix_len: external.prefix.prefix_len,
            prefix_bytes: external.prefix.addr.to_vec(),
        },
    ]);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Ipv6Prefix(PrefixNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node,
            prefix: prefix_desc,
        }),
    });
}

/// Shared tail for emitting one IPv6 Prefix NLRI from a `V3Prefix`
/// inside a v3 LSA. The OSPFv3 prefixes are always IPv6 — the
/// projection does not project IPv4-mapped v3 prefixes.
fn push_v3_ipv6_prefix_nlri(
    ctx: &OspfAreaBgplsContext,
    local_node: &NodeDescriptor,
    prefix: &V3Prefix,
    route_type: OspfRouteType,
    out: &mut Vec<BgpLsNlri>,
) {
    let prefix_desc = PrefixDescriptor::new(vec![
        PrefixDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
        PrefixDescriptorSubTlv::OspfRouteType(route_type),
        PrefixDescriptorSubTlv::IpReachabilityInfo {
            prefix_len: prefix.prefix_len,
            prefix_bytes: prefix.addr.to_vec(),
        },
    ]);
    out.push(BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Ipv6Prefix(PrefixNlri {
            protocol_id: ctx.bgpls_protocol_id(),
            identifier: 0,
            local_node: local_node.clone(),
            prefix: prefix_desc,
        }),
    });
}

// ---------------------------------------------------------------------------
// OSPFv3 SRv6 SID NLRI projection (RFC 9513 → RFC 9514 §6)
// ---------------------------------------------------------------------------

/// Project the OSPFv3 SRv6 database onto RFC 9514 §6 SRv6 SID NLRIs.
///
/// Builds a [`Srv6Database`] from the same area LSDB the LSA-driven
/// pass walks, then emits one [`BgpLsNlriVariant::Srv6Sid`] per End
/// SID the database holds. The [`Srv6Database`] applies the RFC 9513
/// §2/§7.1 preference and the §5/§8/§11 gates (route type, locator
/// length, metric, End-SID containment, behavior validity), so the
/// projection receives a clean per-router End-SID set in wire order
/// with duplicates removed (first wins per locator).
///
/// # NLRI shape
///
/// Each emitted NLRI carries:
///
/// - `protocol_id` — `Ospfv3` (RFC 7752 §3.3 Table 2).
/// - `identifier` — `0` for every NLRI the projection emits (RFC
///   7752 §3.3 leaves it opaque; the daemon-wiring follow-up may
///   pin it to a per-area monotonic counter to disambiguate
///   re-advertisements — that lives in the daemon, not here).
/// - `local_node` — the advertising router's 4-byte IGP Router-ID
///   (the OSPFv3 Router ID, RFC 7752 §3.2.1.4 "OSPF
///   non-pseudonode"). SRv6 End SIDs are per-router, not per-
///   pseudonode, so the projection reuses [`v3_router_node_descriptor`].
/// - `srv6_sid` — the SRv6 SID Descriptor TLV stream: the mandatory
///   SRv6 SID Information TLV (RFC 9514 §6.1, type 518, the 16-byte
///   SID value), followed by a Multi-Topology ID TLV (RFC 7752
///   §3.2.1.5, type 263, value 0) for consistency with the prefix-
///   NLRI projection's MT-ID convention.
///
/// # End.X scope
///
/// End.X / LAN End.X SIDs ([`lr_ospf::srv6db::Srv6Node::end_x_sids`])
/// are not projected here. The SRv6 SID NLRI carries only the 16-byte
/// SID value — the RFC 8986 endpoint behavior that distinguishes an
/// End SID from an End.X SID lives in the BGP-LS Attribute surface
/// (RFC 9514 §7 SRv6 Endpoint Behavior). Projecting End.X without
/// the behavior attribute loses the adjacency association a
/// controller needs. [`project_v3_srv6_end_x_nlris`] is the
/// sibling function that emits the End.X NLRIs paired with the §7
/// attribute; the daemon driver pushes those pairs through
/// `advertise_bgpls_with_attr`.
///
/// # Incremental republish
///
/// [`diff_bgpls`] handles the SRv6 SID NLRIs transparently — the
/// codec's strict structural enforcement on the SRv6 SID Descriptor
/// stream (exactly one TLV 518 with a 16-byte value) makes the
/// encoded bytes a stable identity for set membership, so a daemon
/// running the projection once per LSDB change uses the `added` and
/// `removed` sets to drive incremental MP-BGP UPDATE messages for
/// SRv6 SIDs the same way it does for Node/Link/Prefix NLRIs.
fn project_v3_srv6_sid_nlris(lsdb: &Lsdb, ctx: &OspfAreaBgplsContext, out: &mut Vec<BgpLsNlri>) {
    let db = Srv6Database::from_lsdb(lsdb);
    for (&router_id, node) in &db.nodes {
        // SRv6 End SIDs are per-router, not per-pseudonode — the
        // 4-byte IGP Router-ID form is correct even when the same
        // router also originated Network-LSAs (the pseudonode has
        // no SIDs of its own).
        let local_node = v3_router_node_descriptor(router_id, ctx);
        for (_locator, end_sid) in node.end_sids() {
            let srv6_sid = Srv6SidDescriptor::new(vec![
                Srv6SidDescriptorSubTlv::Srv6SidInformation(end_sid.sid),
                // MT-ID 0 for consistency with the prefix-NLRI
                // projection; the codec passes MT-IDs through verbatim
                // so a future multi-topology deployment can override
                // without touching the projection.
                Srv6SidDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
            ]);
            out.push(BgpLsNlri {
                route_distinguisher: None,
                variant: BgpLsNlriVariant::Srv6Sid(Srv6SidNlri {
                    protocol_id: ctx.bgpls_protocol_id(),
                    identifier: 0,
                    local_node: local_node.clone(),
                    srv6_sid,
                }),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// OSPFv3 SRv6 End.X / LAN End.X projection with attribute (RFC 9513 §9
// → RFC 9514 §6 NLRI + §7 attribute)
// ---------------------------------------------------------------------------

/// Project the OSPFv3 SRv6 End.X / LAN End.X SID database (RFC 9513
/// §9) onto RFC 9514 §6 SRv6 SID NLRIs paired with the BGP-LS
/// Attribute (RFC 7752 §3.3 + RFC 9514 §7-§8) that carries the SRv6
/// Endpoint Behavior TLV a controller needs to distinguish an End.X
/// SID from an End SID.
///
/// Returns one `(BgpLsNlri, BgpLsAttr)` pair per End.X / LAN End.X SID
/// in the database. Each pair carries:
///
/// - `nlri` — an SRv6 SID NLRI (RFC 9514 §6) with the Local Node
///   Descriptor set to the advertising router's 4-byte IGP Router-ID,
///   the SRv6 SID Descriptor stream carrying the mandatory SRv6 SID
///   Information TLV (§6.1, type 518, the 16-byte SID value) and a
///   Multi-Topology ID TLV (type 263, value 0) for consistency with
///   the End SID projection.
/// - `attr` — a BGP-LS Attribute carrying:
///   - the mandatory SRv6 Endpoint Behavior TLV (RFC 9514 §7.1, type
///     1250) with the behavior, flags and algorithm from the OSPFv3
///     End.X sub-TLV (RFC 9513 §9.1/§9.2);
///   - the optional SRv6 SID Structure TLV (RFC 9514 §8, type 1252)
///     when the OSPFv3 End.X sub-TLV carried the §10 SID Structure
///     sub-TLV — the four length fields pass through verbatim.
///
/// The Srv6Database applies the RFC 9513 §9 locator containment gate
/// (an End.X SID not subsumed by a locator the same router advertised
/// with the matching algorithm is ignored), so the projection sees a
/// clean per-router End.X SID set in wire order. Multiple instances
/// survive — the same SID may serve several links and a link may
/// carry several SIDs (§9 load-balancing).
///
/// # Wire shape
///
/// The NLRI shape is identical to the End SID projection — RFC 9514
/// §6 carries the 16-byte SID value; the endpoint behavior lives in
/// the BGP-LS Attribute (§7.1), not in the NLRI. A controller that
/// receives the NLRI without the attribute sees a SID with no
/// behavior; one that receives both knows the adjacency-steering
/// End.X behavior and can install a cross-connect accordingly.
///
/// # Incremental republish
///
/// [`diff_bgpls_with_attrs`] handles the End.X NLRIs transparently
/// — the codec's strict structural enforcement on both the NLRI and
/// the attribute makes the encoded bytes a stable identity for set
/// membership, so a daemon running the projection once per LSDB
/// change uses the `added`, `removed` and `updated` sets to drive
/// incremental MP-BGP UPDATE messages via
/// `BgpPeer::advertise_bgpls_with_attr` (added, updated) and
/// `BgpPeer::withdraw_bgpls` (removed).
///
/// [issue #60]: https://github.com/TES286-org/librouting/issues/60
pub fn project_v3_srv6_end_x_nlris(
    lsdb: &Lsdb,
    ctx: &OspfAreaBgplsContext,
) -> Vec<(BgpLsNlri, BgpLsAttr)> {
    let db = Srv6Database::from_lsdb(lsdb);
    let mut out = Vec::new();
    for (&router_id, node) in &db.nodes {
        // The Local Node Descriptor carries the advertising router's
        // 4-byte IGP Router-ID (the OSPFv3 Router ID). The LAN End.X
        // neighbor Router-ID lives in the OSPF link-state (it is
        // already projected onto the Link NLRI for the same adjacency)
        // and the BGP-LS Attribute (§7.2 SRv6 BGP PeerNode SID TLV is
        // EPE-only — not used by an IGP-originated End.X). The NLRI's
        // identity is the SID value alone.
        let local_node = v3_router_node_descriptor(router_id, ctx);
        for x in &node.end_x_sids {
            let nlri = BgpLsNlri {
                route_distinguisher: None,
                variant: BgpLsNlriVariant::Srv6Sid(Srv6SidNlri {
                    protocol_id: ctx.bgpls_protocol_id(),
                    identifier: 0,
                    local_node: local_node.clone(),
                    srv6_sid: Srv6SidDescriptor::new(vec![
                        Srv6SidDescriptorSubTlv::Srv6SidInformation(x.sid),
                        // MT-ID 0 for consistency with the End SID
                        // and prefix-NLRI projections.
                        Srv6SidDescriptorSubTlv::MultiTopologyId(0u16.to_be_bytes().to_vec()),
                    ]),
                }),
            };
            let mut tlvs = Vec::with_capacity(2);
            // RFC 9514 §7.1: SRv6 Endpoint Behavior TLV is mandatory
            // in the BGP-LS Attribute of every SRv6 SID NLRI. The
            // behavior value comes straight from the OSPFv3 End.X
            // sub-TLV (RFC 9513 §9.1/§9.2 carry the RFC 8986 §10.2
            // code point); the codec carries the raw 16-bit value so
            // unknown behaviors round-trip byte-for-byte.
            tlvs.push(BgpLsAttrTlv::Srv6EndpointBehavior {
                behavior: Srv6EndpointBehavior::from_u16(x.behavior),
                flags: x.flags,
                algorithm: x.algorithm,
            });
            // RFC 9514 §8: SRv6 SID Structure TLV is optional. The
            // OSPFv3 §10 sub-TLV (RFC 9513 §10) carries the same
            // four length fields; pass through verbatim when present.
            if let Some(s) = &x.structure {
                tlvs.push(BgpLsAttrTlv::Srv6SidStructure(BgpLsSrv6SidStructure {
                    locator_block_len: s.lb_len,
                    locator_node_len: s.ln_len,
                    function_len: s.func_len,
                    argument_len: s.arg_len,
                }));
            }
            let attr = BgpLsAttr::new(tlvs);
            out.push((nlri, attr));
        }
    }
    out
}

/// Result of comparing two `(BgpLsNlri, BgpLsAttr)` projections for
/// incremental republish of NLRIs that carry a BGP-LS Attribute
/// (RFC 7752 §3.3).
///
/// `added` rides MP_REACH_NLRI + BGP-LS Attribute via
/// `BgpPeer::advertise_bgpls_with_attr`; `removed` rides
/// MP_UNREACH_NLRI via `BgpPeer::withdraw_bgpls`; `updated` rides
/// MP_REACH_NLRI + BGP-LS Attribute (the new attribute value
/// re-advertises the NLRI's link-state metadata without a withdraw —
/// BGP permits attribute updates without MP_UNREACH_NLRI per RFC 4271
/// §9.2.1.2). `unchanged` is a count (the NLRI + attribute pair is
/// carried for accounting only and is not re-advertised).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgplsAttrDiff {
    pub added: Vec<(BgpLsNlri, BgpLsAttr)>,
    pub removed: Vec<BgpLsNlri>,
    pub updated: Vec<(BgpLsNlri, BgpLsAttr)>,
    pub unchanged: usize,
}

/// Diff two `(BgpLsNlri, BgpLsAttr)` projections by canonical wire
/// form (RFC 7752 §3.3 NLRI identity + RFC 7752 §3.3 attribute
/// comparison).
///
/// Indexes both projections by the encoded NLRI bytes — the NLRI is
/// the route identity, the attribute is the metadata. The codec's
/// byte-for-byte round-trip property (the NLRI codec preserves
/// unknown sub-TLVs verbatim; the attribute codec preserves unknown
/// TLVs verbatim) makes the encoded form a stable identity for set
/// membership. Two pairs with equal NLRI bytes and equal attribute
/// values are `unchanged`; equal NLRI bytes and differing attribute
/// values are `updated`; NLRI bytes only in `prev` are `removed`;
/// NLRI bytes only in `curr` are `added`.
///
/// A duplicate NLRI in either projection collapses to its last
/// occurrence — mirrors the dedup the plain-NLRI
/// [`diff_bgpls`] applies. The projection never emits duplicates
/// in practice (a SID maps to exactly one NLRI), so the dedup is
/// defensive.
pub fn diff_bgpls_with_attrs(
    prev: &[(BgpLsNlri, BgpLsAttr)],
    curr: &[(BgpLsNlri, BgpLsAttr)],
) -> BgplsAttrDiff {
    let prev_map = index_pairs_by_nlri(prev);
    let curr_map = index_pairs_by_nlri(curr);
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut updated = Vec::new();
    let mut unchanged = 0usize;
    // Walk prev first so removed stays in prev order, then walk curr
    // for added and updated — keeps both lists deterministic for a
    // test.
    for (k, (n, a)) in &prev_map {
        match curr_map.get(k) {
            Some((cn, ca)) if a == ca => {
                unchanged += 1;
                let _ = cn;
            }
            Some((cn, ca)) => {
                // NLRI present in both, attribute changed → re-
                // advertise with the new attribute (no withdraw).
                updated.push((cn.clone(), ca.clone()));
            }
            None => {
                removed.push(n.clone());
            }
        }
    }
    for (k, (n, a)) in &curr_map {
        if !prev_map.contains_key(k) {
            added.push((n.clone(), a.clone()));
        }
    }
    BgplsAttrDiff {
        added,
        removed,
        updated,
        unchanged,
    }
}

/// Index `(BgpLsNlri, BgpLsAttr)` pairs by the canonical wire bytes
/// of the NLRI. The NLRI is the route identity (the attribute is
/// metadata); the codec's round-trip property makes the encoded
/// NLRI bytes a stable identity for set membership.
fn index_pairs_by_nlri(
    pairs: &[(BgpLsNlri, BgpLsAttr)],
) -> BTreeMap<Vec<u8>, (BgpLsNlri, BgpLsAttr)> {
    let mut m = BTreeMap::new();
    for (n, a) in pairs {
        m.insert(nlri_wire_bytes(n), (n.clone(), a.clone()));
    }
    m
}

#[cfg(test)]
#[path = "lsdb_to_bgpls_tests.rs"]
mod tests;
