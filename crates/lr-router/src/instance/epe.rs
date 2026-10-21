//! BGP peer sessions → BGP-LS Egress Peer Engineering Link NLRI
//! projection (RFC 9086 §3 + §5). The peer of [`super::lsdb_to_bgpls`]
//! for the daemon's BGP peer sessions: a pure function on a snapshot
//! of the session table that produces the BGP-LS Link NLRI set an
//! EPE-aware controller learns to steer traffic to the daemon's BGP
//! peer sessions.
//!
//! # What the projection emits
//!
//! Per RFC 9086 §3, the BGP-LS Link NLRI for a BGP peering session
//! (Protocol-ID = `Bgp`) carries:
//!
//! - **Local Node Descriptor** (TLV 256) — `As` (512, the local
//!   AS), `BgpLsId` (513, the daemon's BGP-LS speaker ID), `BgpRouterId`
//!   (516, the local BGP Identifier from RFC 6286 §4), and the
//!   optional `BgpConfederationMember` (517) sub-TLV when the local
//!   speaker is a member of a BGP confederation (RFC 5065 §4).
//! - **Remote Node Descriptor** (TLV 257) — `As` (512, the peer's
//!   AS), `BgpLsId` (513, set to `0` — the remote speaker's BGP-LS
//!   ID is not negotiated in OPEN and is opaque to us, matching
//!   BIRD's `bgp_ls` channel behaviour), `BgpRouterId` (516, the
//!   peer's BGP Identifier learned in OPEN), and the optional
//!   `BgpConfederationMember` (517) sub-TLV when the operator has
//!   declared the peer is in a confederation.
//! - **Link Descriptor** — `MultiTopologyId` (263, value `0`) is
//!   always present; the IPv4/IPv6 Interface Address (TLV 259 / 261)
//!   and Neighbor Address (TLV 260 / 262) sub-TLVs are added when
//!   the caller supplies the corresponding interface addresses.
//!   IPv4 addresses ride TLV 259 / 260; IPv6 addresses ride
//!   RFC 6119 §4.2 / §4.3 TLV 261 / 262. Both are optional per
//!   RFC 7752 §3.2.2.
//!
//! The pair's BGP-LS Attribute (RFC 7752 §3.3, path attribute
//! type 29) carries the SR-MPLS BGP Peering SID TLVs from
//! RFC 9086 §5 — the PeerNode SID (TLV 1101, mandatory per
//! §5.1: "MUST be advertised for every BGP-LS Link NLRI
//! describing a BGP peer session"), and optionally the PeerAdj SID
//! (1102, §5.2) and PeerSet SID (1103, §5.3). The codec surface
//! lives in [`lr_bgp::path::bgp_ls_attr`] (PR #68); this module
//! only assembles the values the daemon passes in.
//!
//! # Scope boundary
//!
//! The projection itself is pure: it does not allocate MPLS labels,
//! does not consult the daemon's RIB, does not touch the daemon
//! loop. The daemon ticker integration lives in [`super::mod`]
//! ([`super::DefaultRouter::bgpls_republish_epe`]) and the
//! [`BgplsDriver`](crate::daemon::BgplsDriver) tick step — both
//! mirror the End.X projection wiring (see [`super::lsdb_to_bgpls`]
//! for the End.X sibling).
//!
//! The SID/Index/Label values the projection emits are the values
//! the daemon passes in via [`EpePeerSession`]; the daemon's
//! default policy is a deterministic placeholder derived from the
//! session handle (the local speaker's PeerNode SID allocation
//! surface is a follow-up — the controller receives a stable
//! identity per session that can be later bound to a real
//! SR-MPLS label or SRGB index without changing the projection
//! shape).
//!
//! [issue #60]: https://github.com/TES286-org/librouting/issues/60

use lr_bgp::path::bgp_ls::{
    BgpLsNlri, BgpLsNlriVariant, LinkDescriptor, LinkDescriptorSubTlv, LinkNlri, NodeDescriptor,
    NodeDescriptorSubTlv, ProtocolId,
};
use lr_bgp::path::bgp_ls_attr::{BgpLsAttr, BgpLsAttrTlv, BgpPeeringSid};

/// Per-session input the daemon collects for the EPE projection.
///
/// The daemon walks its live `DefaultRouter` session table, builds
/// one `EpePeerSession` per Established BGP peer, and passes the
/// slice to [`project_epe_peer_sessions`]. Every field the
/// projection needs to fill in the Local/Remote Node Descriptor,
/// Link Descriptor and BGP-LS Attribute is on this struct — the
/// projection does not consult the router again.
///
/// Fields are intentionally `Copy`-friendly where possible so the
/// daemon can build the slice without cloning session-owned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpePeerSession {
    /// RFC 7752 §3.2.1.4 + RFC 9086 §3.1 — Autonomous System sub-TLV
    /// (512) for the **Local Node Descriptor**. The local AS the
    /// session is established under.
    pub local_as: u32,
    /// RFC 7752 §3.2.1.4 + RFC 9086 §3.1 — BGP Router-ID sub-TLV
    /// (516) for the **Local Node Descriptor**. The local BGP
    /// Identifier (RFC 6286 §4).
    pub local_bgp_id: u32,
    /// RFC 7752 §3.2.1.4 — BGP-LS Identifier sub-TLV (513) for the
    /// **Local Node Descriptor**. The daemon-wide BGP-LS speaker
    /// identity from the `[bgp_ls]` config block.
    pub bgp_ls_id: u32,
    /// RFC 7752 §3.2.1.4 + RFC 9086 §3.1 — Autonomous System sub-TLV
    /// (512) for the **Remote Node Descriptor**. The peer's AS,
    /// learned in OPEN.
    pub peer_as: u32,
    /// RFC 7752 §3.2.1.4 + RFC 9086 §3.1 — BGP Router-ID sub-TLV
    /// (516) for the **Remote Node Descriptor**. The peer's BGP
    /// Identifier, learned in OPEN.
    pub peer_bgp_id: u32,
    /// RFC 9086 §3.2 — Member-AS Number sub-TLV (517) for the
    /// **Local Node Descriptor**. Set when the local speaker is a
    /// member of a BGP confederation (RFC 5065 §4). `None` omits
    /// the sub-TLV — matches a non-confederation speaker.
    pub local_confederation_member: Option<u32>,
    /// RFC 9086 §3.2 — Member-AS Number sub-TLV (517) for the
    /// **Remote Node Descriptor**. Set when the operator has
    /// declared the peer is in a confederation. `None` omits the
    /// sub-TLV.
    pub peer_confederation_member: Option<u32>,
    /// Local interface IPv4 address — emitted as the IPv4 Interface
    /// Address Link Descriptor sub-TLV (259) when present. `None`
    /// omits the sub-TLV (RFC 7752 §3.2.2 makes the Interface
    /// Address sub-TLV optional).
    pub local_address_v4: Option<[u8; 4]>,
    /// Local interface IPv6 address — emitted as the IPv6 Interface
    /// Address Link Descriptor sub-TLV (261, RFC 6119 §4.2) when
    /// present.
    pub local_address_v6: Option<[u8; 16]>,
    /// Remote peer's IPv4 address — emitted as the IPv4 Neighbor
    /// Address Link Descriptor sub-TLV (260) when present. The
    /// daemon does not currently store the peer's address on the
    /// BGP runtime, so this is `None` for sessions the daemon
    /// could not attribute a peer IP to.
    pub remote_address_v4: Option<[u8; 4]>,
    /// Remote peer's IPv6 address — emitted as the IPv6 Neighbor
    /// Address Link Descriptor sub-TLV (262, RFC 6119 §4.3) when
    /// present.
    pub remote_address_v6: Option<[u8; 16]>,
    /// RFC 9086 §5.1 PeerNode SID — mandatory. The daemon fills in
    /// a deterministic per-session placeholder when the operator
    /// has not configured a real value (the local speaker's
    /// PeerNode SID allocation surface is a follow-up).
    pub peer_node_sid: BgpPeeringSid,
    /// RFC 9086 §5.2 PeerAdj SID — optional. `None` omits the
    /// TLV. A future per-peer config surface can populate this.
    pub peer_adj_sid: Option<BgpPeeringSid>,
    /// RFC 9086 §5.3 PeerSet SID — optional. `None` omits the
    /// TLV. A future per-peer config surface can populate this.
    pub peer_set_sid: Option<BgpPeeringSid>,
}

impl EpePeerSession {
    /// Build an `EpePeerSession` with the mandatory identity fields
    /// and a PeerNode SID; the optional address / confederation /
    /// PeerAdj / PeerSet fields default to `None`.
    ///
    /// Convenience helper for the daemon path; tests usually build
    /// the struct literally so the wire form is visible at the call
    /// site.
    pub fn new(
        local_as: u32,
        local_bgp_id: u32,
        bgp_ls_id: u32,
        peer_as: u32,
        peer_bgp_id: u32,
        peer_node_sid: BgpPeeringSid,
    ) -> Self {
        Self {
            local_as,
            local_bgp_id,
            bgp_ls_id,
            peer_as,
            peer_bgp_id,
            local_confederation_member: None,
            peer_confederation_member: None,
            local_address_v4: None,
            local_address_v6: None,
            remote_address_v4: None,
            remote_address_v6: None,
            peer_node_sid,
            peer_adj_sid: None,
            peer_set_sid: None,
        }
    }
}

/// Project a snapshot of the daemon's BGP peer sessions onto BGP-LS
/// EPE Link NLRI + BGP-LS Attribute pairs (RFC 9086 §3 + §5).
///
/// Pure function. Emits one `(BgpLsNlri, BgpLsAttr)` pair per
/// [`EpePeerSession`] in the input order — the caller does not
/// need to sort; the incremental republish driver
/// ([`super::DefaultRouter::bgpls_republish_epe`]) keys the diff
/// on the canonical wire form of each NLRI (see
/// [`super::lsdb_to_bgpls::diff_bgpls_with_attrs`]), so order
/// does not affect correctness, only the order NLRIs land in the
/// `added` / `removed` / `updated` lists.
///
/// Each NLRI is a BGP-LS Link NLRI (RFC 7752 §3.3 NLRI Type 2)
/// with `ProtocolId::Bgp` (RFC 9086 §3, the BGP-LS Protocol-ID
/// for EPE) and `identifier = 0` — RFC 7752 §3.3 leaves the
/// 8-byte Identifier opaque; the daemon-wide monotonic counter
/// a strict reading might want is a follow-up (the End.X
/// projection in [`super::lsdb_to_bgpls::project_v3_srv6_end_x_nlris`]
/// uses the same value). The Local/Remote Node Descriptor carries
/// the `As` + `BgpLsId` + `BgpRouterId` sub-TLVs always, plus
/// `BgpConfederationMember` when the caller supplied it. The
/// Link Descriptor always carries `MultiTopologyId(0)`; the
/// Interface/Neighbor Address sub-TLVs are added when the
/// caller supplied them.
///
/// The attribute always carries the PeerNode SID TLV (1101,
/// RFC 9086 §5.1 mandatory); the PeerAdj SID (1102) and
/// PeerSet SID (1103) TLVs are added when the caller supplied
/// them. The codec in [`lr_bgp::path::bgp_ls_attr`] preserves the
/// flags / weight / reserved / SID-Index-Label byte-for-byte so
/// the round-trip is byte-exact.
pub fn project_epe_peer_sessions(sessions: &[EpePeerSession]) -> Vec<(BgpLsNlri, BgpLsAttr)> {
    let mut out = Vec::with_capacity(sessions.len());
    for s in sessions {
        let local_node = build_epe_node_descriptor(
            s.local_as,
            s.bgp_ls_id,
            s.local_bgp_id,
            s.local_confederation_member,
        );
        // RFC 9086 §3.1: the Remote Node Descriptor carries the
        // peer's AS + BGP Router-ID. The BGP-LS ID is opaque to us
        // (not negotiated in OPEN) — emit 0, matching BIRD's
        // bgp_ls channel.
        let remote_node =
            build_epe_node_descriptor(s.peer_as, 0, s.peer_bgp_id, s.peer_confederation_member);
        let mut link_sub_tlvs = Vec::with_capacity(5);
        // MT-ID 0 — the default topology. RFC 7752 §3.2.1.5: a
        // Link Descriptor MUST carry the MT-ID TLV when multi-
        // topology routing is in use, MAY otherwise. We always
        // emit it for parity with the OSPF LSDB projection
        // (the End.X projection does the same).
        link_sub_tlvs.push(LinkDescriptorSubTlv::MultiTopologyId(
            0u16.to_be_bytes().to_vec(),
        ));
        if let Some(v4) = s.local_address_v4 {
            link_sub_tlvs.push(LinkDescriptorSubTlv::Ipv4InterfaceAddress(v4));
        }
        if let Some(v6) = s.local_address_v6 {
            link_sub_tlvs.push(LinkDescriptorSubTlv::Ipv6InterfaceAddress(v6));
        }
        if let Some(v4) = s.remote_address_v4 {
            link_sub_tlvs.push(LinkDescriptorSubTlv::Ipv4NeighborAddress(v4));
        }
        if let Some(v6) = s.remote_address_v6 {
            link_sub_tlvs.push(LinkDescriptorSubTlv::Ipv6NeighborAddress(v6));
        }
        let link = LinkDescriptor::new(link_sub_tlvs);
        let nlri = BgpLsNlri {
            route_distinguisher: None,
            variant: BgpLsNlriVariant::Link(LinkNlri {
                protocol_id: ProtocolId::Bgp,
                identifier: 0,
                local_node,
                remote_node,
                link,
            }),
        };
        let mut attr_tlvs = Vec::with_capacity(3);
        // RFC 9086 §5.1: PeerNode SID is mandatory.
        attr_tlvs.push(BgpLsAttrTlv::PeerNodeSid(s.peer_node_sid));
        if let Some(adj) = s.peer_adj_sid {
            attr_tlvs.push(BgpLsAttrTlv::PeerAdjSid(adj));
        }
        if let Some(set) = s.peer_set_sid {
            attr_tlvs.push(BgpLsAttrTlv::PeerSetSid(set));
        }
        let attr = BgpLsAttr::new(attr_tlvs);
        out.push((nlri, attr));
    }
    out
}

/// Build a Node Descriptor for the EPE Link NLRI per RFC 7752
/// §3.2.1.4 and RFC 9086 §3.1/§3.2. Always carries the Autonomous
/// System, BGP-LS Identifier and BGP Router-ID sub-TLVs; appends
/// the BGP Confederation Member sub-TLV when the caller supplied a
/// member-AS.
fn build_epe_node_descriptor(
    as_number: u32,
    bgp_ls_id: u32,
    bgp_router_id: u32,
    confederation_member: Option<u32>,
) -> NodeDescriptor {
    let mut sub_tlvs = Vec::with_capacity(4);
    sub_tlvs.push(NodeDescriptorSubTlv::As(as_number));
    sub_tlvs.push(NodeDescriptorSubTlv::BgpLsId(bgp_ls_id));
    sub_tlvs.push(NodeDescriptorSubTlv::BgpRouterId(bgp_router_id));
    if let Some(member) = confederation_member {
        sub_tlvs.push(NodeDescriptorSubTlv::BgpConfederationMember(member));
    }
    NodeDescriptor::new(sub_tlvs)
}

#[cfg(test)]
#[path = "epe_tests.rs"]
mod tests;
