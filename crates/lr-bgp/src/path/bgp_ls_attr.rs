//! BGP-LS Attribute TLV codec (RFC 7752 §3.3 + RFC 9514 §7-§8).
//!
//! The BGP-LS Attribute is an optional, non-transitive BGP path
//! attribute (type 29 per RFC 7752 §13 IANA considerations) carried
//! alongside a BGP-LS NLRI. Its value is a single TLV stream following
//! the same 4-byte TLV framing the NLRI codec uses (RFC 7752 §3.1:
//! 16-bit `Type`, 16-bit `Length`, variable `Value`). Each TLV in the
//! stream describes one piece of link-state metadata for the
//! accompanying NLRI — Node flags, link metrics, prefix flags, SRv6
//! endpoint behavior, SRv6 SID structure, etc. The attribute is
//! mandatory on the SRv6 SID NLRI per RFC 9514 §7.1 (the SRv6
//! Endpoint Behavior TLV is mandatory inside it); other NLRI types
//! MAY carry the attribute, MAY omit it, or MAY carry multiple
//! instances of the attribute (RFC 7752 §3.3 specifies that a
//! receiver MUST concatenate the values when an UPDATE carries more
//! than one BGP-LS Attribute of the same type).
//!
//! # Wire shape (RFC 7752 §3.3 + §3.1)
//!
//! ```text
//! Path attribute type = 29, flags = optional + non-transitive.
//! Value = concatenation of TLVs:
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              Type             |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! //                         Value (variable)                   //
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `Type` and `Length` are 16-bit big-endian; `Length` excludes the
//! 4-byte TLV header. The attribute value is the concatenation of
//! these TLVs with no extra framing.
//!
//! # Scope
//!
//! This module implements Layer 1 (the stateless wire codec) for the
//! BGP-LS Attribute. It models the SRv6-specific TLVs from RFC 9514
//! that the existing SRv6 SID NLRI projection (in
//! `lr-router::instance::lsdb_to_bgpls`) needs to attach End.X
//! behaviors to projected SIDs, plus a representative subset of the
//! base RFC 7752 attribute TLVs that ride alongside the Node / Link /
//! Prefix NLRIs the projection already emits. Unknown TLVs are
//! preserved verbatim — the codec round-trips byte-for-byte on any
//! well-formed input, matching the contract the NLRI codec in
//! [`crate::path::bgp_ls`] already enforces.
//!
//! The End.X / LAN End.X projection update that consumes this codec
//! to attach the SRv6 Endpoint Behavior TLV to a projected End.X
//! NLRI is a separate follow-up; this module is the foundation.

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::error::{EncodeError, ParseError};

pub use crate::path::bgp_ls::Tlv;

/// BGP path attribute type code assigned to the BGP-LS Attribute by
/// RFC 7752 §13 ("IANA has assigned value 29 (BGP-LS Attribute) in
/// the 'BGP Path Attributes' sub-registry"). Re-exported here so the
/// attribute codec is self-contained; the canonical enum entry is
/// [`crate::path::AttrType::BgpLsAttribute`].
pub const ATTR_TYPE_BGP_LS: u8 = 29;

/// TLV type code points defined in the IANA "BGP-LS Node Descriptor,
/// Link Descriptor, Prefix Descriptor, and Attribute TLVs" registry
/// and the SRv6 additions from RFC 9514 §9.2 Table 2.
///
/// Only the well-known code points the codec models are named here.
/// Unknown code points are preserved verbatim via
/// [`BgpLsAttrTlv::Unknown`].
pub mod tlv_type {
    // RFC 7752 §3.3.1 — Node Attribute TLVs.
    /// Node Flag Bits (RFC 7752 §3.3.1.1). 1-byte value.
    pub const NODE_FLAG_BITS: u16 = 1024;
    /// Opaque Node Attribute (RFC 7752 §3.3.1.5). Variable-length.
    pub const OPAQUE_NODE_ATTRIBUTE: u16 = 1025;
    /// Node Name (RFC 7752 §3.3.1.3). Variable-length UTF-8.
    pub const NODE_NAME: u16 = 1026;
    /// IS-IS Area Identifier (RFC 7752 §3.3.1.2). Variable-length.
    pub const ISIS_AREA_IDENTIFIER: u16 = 1027;
    /// IPv4 Router-ID of Local Node (RFC 5305 §4.3). 4-byte value.
    pub const IPV4_ROUTER_ID_LOCAL: u16 = 1028;
    /// IPv6 Router-ID of Local Node (RFC 6119 §4.1). 16-byte value.
    pub const IPV6_ROUTER_ID_LOCAL: u16 = 1029;
    /// SRv6 Capabilities TLV (RFC 9514 §3.1). 4-byte value:
    /// 2-byte flags + 2-byte reserved.
    pub const SRV6_CAPABILITIES: u16 = 1038;

    // RFC 7752 §3.3.2 — Link Attribute TLVs (selected).
    /// Admin Group (RFC 7752 §3.3.2.1, a.k.a. Color). 4-byte value.
    pub const ADMIN_GROUP: u16 = 1088;
    /// Maximum Link Bandwidth (RFC 7752 §3.3.2.2). 4-byte IEEE float.
    pub const MAX_LINK_BANDWIDTH: u16 = 1089;
    /// Max Reservable Link Bandwidth (RFC 7752 §3.3.2.2). 4-byte
    /// IEEE float.
    pub const MAX_RESERVABLE_BANDWIDTH: u16 = 1090;
    /// Unreserved Bandwidth (RFC 7752 §3.3.2.2). 8 × 4-byte IEEE
    /// floats (one per priority level 0-7).
    pub const UNRESERVED_BANDWIDTH: u16 = 1091;
    /// TE Default Metric (RFC 7752 §3.3.2.3). 4-byte value per
    /// RFC 7752 (later RFCs extend this).
    pub const TE_DEFAULT_METRIC: u16 = 1092;
    /// Link Protection Type (RFC 7752 §3.3.2.5). Variable.
    pub const LINK_PROTECTION_TYPE: u16 = 1093;
    /// MPLS Metric (RFC 7752 §3.3.2.4). 1-byte value.
    pub const MPLS_METRIC: u16 = 1094;
    /// Shared Risk Link Group (RFC 7752 §3.3.2.6). Variable.
    pub const SHARED_RISK_LINK_GROUP: u16 = 1095;
    /// IGP Metric (RFC 7855 §2.1). Variable (1-3 bytes).
    pub const IGP_METRIC: u16 = 1114;
    /// SRv6 End.X SID TLV (RFC 9514 §4.1). Variable.
    pub const SRV6_END_X_SID: u16 = 1106;
    /// IS-IS SRv6 LAN End.X SID TLV (RFC 9514 §4.2). Variable.
    pub const ISIS_SRV6_LAN_END_X_SID: u16 = 1107;
    /// OSPFv3 SRv6 LAN End.X SID TLV (RFC 9514 §4.2). Variable.
    pub const OSPFV3_SRV6_LAN_END_X_SID: u16 = 1108;

    // RFC 7752 §3.3.3 — Prefix Attribute TLVs (selected).
    /// IGP Flags (RFC 7752 §3.3.3.1). 1-byte value.
    pub const IGP_FLAGS: u16 = 1150;
    /// IGP Route Tag (RFC 7752 §3.3.3.2). Variable.
    pub const IGP_ROUTE_TAG: u16 = 1151;
    /// Prefix Metric (RFC 7752 §3.3.3.3). 4-byte value.
    pub const PREFIX_METRIC: u16 = 1152;
    /// Forwarding Address Prefix (RFC 7752 §3.3.3.4). Variable.
    pub const FORWARDING_ADDRESS_PREFIX: u16 = 1153;
    /// Opaque Prefix Attribute (RFC 7752 §3.3.3.5). Variable.
    pub const OPAQUE_PREFIX_ATTRIBUTE: u16 = 1154;
    /// Prefix Attribute Flags (RFC 7752 §3.3.3.6). 1-byte value.
    pub const PREFIX_ATTRIBUTE_FLAGS: u16 = 1155;
    /// SRv6 Locator TLV (RFC 9514 §5.1). Variable: 1-byte flags +
    /// 1-byte algorithm + 2-byte reserved + 4-byte metric + sub-TLVs.
    pub const SRV6_LOCATOR: u16 = 1162;

    // RFC 9514 §7-§8 — SRv6 SID Attribute TLVs.
    /// SRv6 Endpoint Behavior TLV (RFC 9514 §7.1). 4-byte value:
    /// 2-byte endpoint behavior + 1-byte flags + 1-byte algorithm.
    pub const SRV6_ENDPOINT_BEHAVIOR: u16 = 1250;
    /// SRv6 BGP PeerNode SID TLV (RFC 9514 §7.2). 12-byte value:
    /// 1-byte flags + 1-byte weight + 2-byte reserved +
    /// 4-byte peer AS + 4-byte peer BGP identifier.
    pub const SRV6_BGP_PEER_NODE_SID: u16 = 1251;
    /// SRv6 SID Structure TLV (RFC 9514 §8). 4-byte value:
    /// 1-byte locator-block length + 1-byte locator-node length +
    /// 1-byte function length + 1-byte argument length.
    pub const SRV6_SID_STRUCTURE: u16 = 1252;
}

/// SRv6 Endpoint Behavior code points (RFC 8986 §10.2 IANA registry
/// "SRv6 Endpoint Behaviors"). The codec carries the raw 16-bit
/// value; this enum surfaces the values the projection needs to
/// distinguish End from End.X / End.T / End.DX* for the BGP-LS
/// Attribute it attaches to a projected SRv6 SID NLRI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Srv6EndpointBehavior {
    /// RFC 8986 §4.1 — End: the basic segment endpoint.
    End = 1,
    /// RFC 8986 §4.2 — End with penultimate segment pop.
    EndWithPsp = 2,
    /// RFC 8986 §4.2 — End with ultimate segment pop.
    EndWithUsP = 3,
    /// RFC 8986 §4.2 — End with PSP and USP.
    EndWithPspAndUsP = 4,
    /// RFC 8986 §5.1 — End.X: L3 cross-connect to a specific adjacency.
    EndX = 5,
    /// RFC 8986 §5.2 — End.X with PSP.
    EndXWithPsp = 6,
    /// RFC 8986 §5.2 — End.X with USP.
    EndXWithUsP = 7,
    /// RFC 8986 §5.2 — End.X with PSP and USP.
    EndXWithPspAndUsP = 8,
    /// RFC 8986 §6.1 — End.T: lookup in a specific table.
    EndT = 9,
    /// RFC 8986 §6.2 — End.T with PSP.
    EndTWithPsp = 10,
    /// RFC 8986 §6.2 — End.T with USP.
    EndTWithUsP = 11,
    /// RFC 8986 §6.2 — End.T with PSP and USP.
    EndTWithPspAndUsP = 12,
    /// RFC 8986 §4.3 — End.B: decapsulate and BGP-lookup.
    EndB = 13,
    /// RFC 8986 §4.6 — End.DX6: decapsulate and forward to IPv6.
    EndDx6 = 16,
    /// RFC 8986 §4.7 — End.DX4: decapsulate and forward to IPv4.
    EndDx4 = 17,
    /// RFC 8986 §4.8 — End.DT6: decapsulate and table-lookup for IPv6.
    EndDt6 = 18,
    /// RFC 8986 §4.9 — End.DT4: decapsulate and table-lookup for IPv4.
    EndDt4 = 19,
    /// Unknown SRv6 endpoint behavior — captured as the raw 16-bit
    /// code point so unknown behaviors round-trip byte-for-byte.
    Unknown(u16),
}

impl Srv6EndpointBehavior {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::End,
            2 => Self::EndWithPsp,
            3 => Self::EndWithUsP,
            4 => Self::EndWithPspAndUsP,
            5 => Self::EndX,
            6 => Self::EndXWithPsp,
            7 => Self::EndXWithUsP,
            8 => Self::EndXWithPspAndUsP,
            9 => Self::EndT,
            10 => Self::EndTWithPsp,
            11 => Self::EndTWithUsP,
            12 => Self::EndTWithPspAndUsP,
            13 => Self::EndB,
            16 => Self::EndDx6,
            17 => Self::EndDx4,
            18 => Self::EndDt6,
            19 => Self::EndDt4,
            _ => Self::Unknown(v),
        }
    }
    pub fn to_u16(self) -> u16 {
        match self {
            Self::End => 1,
            Self::EndWithPsp => 2,
            Self::EndWithUsP => 3,
            Self::EndWithPspAndUsP => 4,
            Self::EndX => 5,
            Self::EndXWithPsp => 6,
            Self::EndXWithUsP => 7,
            Self::EndXWithPspAndUsP => 8,
            Self::EndT => 9,
            Self::EndTWithPsp => 10,
            Self::EndTWithUsP => 11,
            Self::EndTWithPspAndUsP => 12,
            Self::EndB => 13,
            Self::EndDx6 => 16,
            Self::EndDx4 => 17,
            Self::EndDt6 => 18,
            Self::EndDt4 => 19,
            Self::Unknown(v) => v,
        }
    }
}

/// SRv6 SID Structure (RFC 9514 §8 / RFC 8986 §2). The four length
/// fields (in bits) split an SRv6 SID into its Locator Block,
/// Locator Node, Function, and Argument parts. The sum MUST be less
/// than or equal to 128 per RFC 9514 §8 — the codec enforces this on
/// decode and rejects any structure that overflows the 128-bit SID
/// space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Srv6SidStructure {
    /// SRv6 SID Locator Block length, in bits.
    pub locator_block_len: u8,
    /// SRv6 SID Locator Node length, in bits.
    pub locator_node_len: u8,
    /// SRv6 SID Function length, in bits.
    pub function_len: u8,
    /// SRv6 SID Argument length, in bits.
    pub argument_len: u8,
}

impl Srv6SidStructure {
    /// Returns `true` when the four length fields are consistent
    /// with the 128-bit SRv6 SID constraint (RFC 9514 §8: "the sum
    /// of the LB Length, LN Length, Fun. Length, and Arg. Length MUST
    /// be less than or equal to 128").
    pub fn is_valid(&self) -> bool {
        let sum = self.locator_block_len as u16
            + self.locator_node_len as u16
            + self.function_len as u16
            + self.argument_len as u16;
        sum <= 128
    }
    /// Wire length of the SRv6 SID Structure TLV value (4 bytes,
    /// RFC 9514 §8).
    pub const WIRE_LEN: usize = 4;
}

/// One BGP-LS Attribute TLV (RFC 7752 §3.3 + RFC 9514 §7-§8).
///
/// Each variant maps to a TLV that the codec models explicitly. Any
/// TLV whose type the codec does not recognize is preserved verbatim
/// via the [`Self::Unknown`] variant so a re-encode round-trips
/// byte-for-byte — the same contract the NLRI codec in
/// [`crate::path::bgp_ls`] enforces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BgpLsAttrTlv {
    // ===== Node Attribute TLVs (RFC 7752 §3.3.1) =====
    /// TLV 1024 (RFC 7752 §3.3.1.1). 1-byte node flag bits.
    NodeFlagBits(u8),
    /// TLV 1025 (RFC 7752 §3.3.1.5). Variable-length opaque node
    /// attribute. The codec does not interpret the bytes.
    OpaqueNodeAttribute(Vec<u8>),
    /// TLV 1026 (RFC 7752 §3.3.1.3). Variable-length node name
    /// (symbolic, often a hostname or FQDN).
    NodeName(Vec<u8>),
    /// TLV 1027 (RFC 7752 §3.3.1.2). Variable-length IS-IS area
    /// identifier. Stored raw — multiple instances are permitted.
    IsisAreaIdentifier(Vec<u8>),
    /// TLV 1028 (RFC 5305 §4.3). 4-byte IPv4 Router-ID of the local
    /// node.
    Ipv4RouterIdLocal([u8; 4]),
    /// TLV 1029 (RFC 6119 §4.1). 16-byte IPv6 Router-ID of the local
    /// node.
    Ipv6RouterIdLocal([u8; 16]),
    /// TLV 1038 (RFC 9514 §3.1). 2-byte flags + 2-byte reserved =
    /// 4-byte value.
    Srv6Capabilities { flags: u16, reserved: u16 },

    // ===== Link Attribute TLVs (RFC 7752 §3.3.2, selected) =====
    /// TLV 1088 (RFC 7752 §3.3.2.1). 4-byte admin group (color).
    AdminGroup(u32),
    /// TLV 1089 (RFC 7752 §3.3.2.2). 4-byte IEEE 754 float. The
    /// codec carries the raw 4 bytes so it does not need an `f32`
    /// dependency in the hot path; the embedder interprets.
    MaxLinkBandwidth([u8; 4]),
    /// TLV 1090 (RFC 7752 §3.3.2.2). 4-byte IEEE 754 float, raw
    /// bytes.
    MaxReservableBandwidth([u8; 4]),
    /// TLV 1091 (RFC 7752 §3.3.2.2). 8 × 4-byte IEEE 754 floats (32
    /// bytes total). Stored raw to keep the codec dependency-free.
    UnreservedBandwidth([u8; 32]),
    /// TLV 1092 (RFC 7752 §3.3.2.3). 4-byte TE default metric.
    TeDefaultMetric(u32),
    /// TLV 1093 (RFC 7752 §3.3.2.5). Variable-length link protection
    /// type. Stored raw.
    LinkProtectionType(Vec<u8>),
    /// TLV 1094 (RFC 7752 §3.3.2.4). 1-byte MPLS metric.
    MplsMetric(u8),
    /// TLV 1095 (RFC 7752 §3.3.2.6). Variable-length SRLG list.
    /// Stored raw.
    SharedRiskLinkGroup(Vec<u8>),
    /// TLV 1114 (RFC 7855 §2.1). Variable-length IGP metric (1-3
    /// bytes for OSPF; the codec stores the raw bytes and validates
    /// the length against 1..=4 on decode).
    IgpMetric(Vec<u8>),
    /// TLV 1106 (RFC 9514 §4.1). SRv6 End.X SID TLV — variable
    /// length: 2-byte endpoint behavior + 1-byte flags + 1-byte
    /// algorithm + 1-byte weight + 1-byte reserved + 16-byte SID +
    /// optional sub-TLVs.
    Srv6EndXSid {
        endpoint_behavior: u16,
        flags: u8,
        algorithm: u8,
        weight: u8,
        sid: [u8; 16],
        sub_tlvs: Vec<u8>,
    },
    /// TLV 1107/1108 (RFC 9514 §4.2). SRv6 LAN End.X SID TLV — same
    /// shape as [`Self::Srv6EndXSid`] but with a 6-byte (IS-IS) or
    /// 4-byte (OSPFv3) neighbor ID after the reserved byte. The
    /// codec stores the neighbor ID bytes raw and the protocol in
    /// the variant to keep the model faithful.
    Srv6LanEndXSid {
        is_isis: bool,
        endpoint_behavior: u16,
        flags: u8,
        algorithm: u8,
        weight: u8,
        neighbor_id: Vec<u8>,
        sid: [u8; 16],
        sub_tlvs: Vec<u8>,
    },

    // ===== Prefix Attribute TLVs (RFC 7752 §3.3.3, selected) =====
    /// TLV 1150 (RFC 7752 §3.3.3.1). 1-byte IGP flags.
    IgpFlags(u8),
    /// TLV 1151 (RFC 7752 §3.3.3.2). Variable-length IGP route tag.
    /// Stored raw.
    IgpRouteTag(Vec<u8>),
    /// TLV 1152 (RFC 7752 §3.3.3.3). 4-byte prefix metric.
    PrefixMetric(u32),
    /// TLV 1153 (RFC 7752 §3.3.3.4). Variable-length forwarding
    /// address prefix. Stored raw.
    ForwardingAddressPrefix(Vec<u8>),
    /// TLV 1154 (RFC 7752 §3.3.3.5). Variable-length opaque prefix
    /// attribute. Stored raw.
    OpaquePrefixAttribute(Vec<u8>),
    /// TLV 1155 (RFC 7752 §3.3.3.6). 1-byte prefix attribute flags.
    PrefixAttributeFlags(u8),
    /// TLV 1162 (RFC 9514 §5.1). SRv6 Locator TLV — variable
    /// length: 1-byte flags + 1-byte algorithm + 2-byte reserved +
    /// 4-byte metric + optional sub-TLVs.
    Srv6Locator {
        flags: u8,
        algorithm: u8,
        metric: u32,
        sub_tlvs: Vec<u8>,
    },

    // ===== SRv6 SID Attribute TLVs (RFC 9514 §7-§8) =====
    /// TLV 1250 (RFC 9514 §7.1). SRv6 Endpoint Behavior — 4-byte
    /// value: 2-byte endpoint behavior + 1-byte flags + 1-byte
    /// algorithm. Mandatory in the BGP-LS Attribute associated with
    /// an SRv6 SID NLRI.
    Srv6EndpointBehavior {
        behavior: Srv6EndpointBehavior,
        flags: u8,
        algorithm: u8,
    },
    /// TLV 1251 (RFC 9514 §7.2). SRv6 BGP PeerNode SID — 12-byte
    /// value: 1-byte flags + 1-byte weight + 2-byte reserved +
    /// 4-byte peer AS number + 4-byte peer BGP identifier. Mandatory
    /// in the BGP-LS Attribute for an SRv6 SID NLRI advertised by
    /// BGP for EPE functionality.
    Srv6BgpPeerNodeSid {
        flags: u8,
        weight: u8,
        peer_as: u32,
        peer_bgp_id: u32,
    },
    /// TLV 1252 (RFC 9514 §8). SRv6 SID Structure — 4-byte value:
    /// 1-byte locator-block length + 1-byte locator-node length +
    /// 1-byte function length + 1-byte argument length. The sum
    /// MUST be ≤ 128 (RFC 9514 §8).
    Srv6SidStructure(Srv6SidStructure),

    /// Any TLV the codec does not model. The bytes are preserved
    /// verbatim so a re-encode round-trips byte-for-byte, matching
    /// the contract the NLRI codec enforces.
    Unknown(Tlv),
}

impl BgpLsAttrTlv {
    /// The 16-bit TLV type code for this variant.
    pub fn ty(&self) -> u16 {
        match self {
            Self::NodeFlagBits(_) => tlv_type::NODE_FLAG_BITS,
            Self::OpaqueNodeAttribute(_) => tlv_type::OPAQUE_NODE_ATTRIBUTE,
            Self::NodeName(_) => tlv_type::NODE_NAME,
            Self::IsisAreaIdentifier(_) => tlv_type::ISIS_AREA_IDENTIFIER,
            Self::Ipv4RouterIdLocal(_) => tlv_type::IPV4_ROUTER_ID_LOCAL,
            Self::Ipv6RouterIdLocal(_) => tlv_type::IPV6_ROUTER_ID_LOCAL,
            Self::Srv6Capabilities { .. } => tlv_type::SRV6_CAPABILITIES,
            Self::AdminGroup(_) => tlv_type::ADMIN_GROUP,
            Self::MaxLinkBandwidth(_) => tlv_type::MAX_LINK_BANDWIDTH,
            Self::MaxReservableBandwidth(_) => tlv_type::MAX_RESERVABLE_BANDWIDTH,
            Self::UnreservedBandwidth(_) => tlv_type::UNRESERVED_BANDWIDTH,
            Self::TeDefaultMetric(_) => tlv_type::TE_DEFAULT_METRIC,
            Self::LinkProtectionType(_) => tlv_type::LINK_PROTECTION_TYPE,
            Self::MplsMetric(_) => tlv_type::MPLS_METRIC,
            Self::SharedRiskLinkGroup(_) => tlv_type::SHARED_RISK_LINK_GROUP,
            Self::IgpMetric(_) => tlv_type::IGP_METRIC,
            Self::Srv6EndXSid { .. } => tlv_type::SRV6_END_X_SID,
            Self::Srv6LanEndXSid { is_isis, .. } => {
                if *is_isis {
                    tlv_type::ISIS_SRV6_LAN_END_X_SID
                } else {
                    tlv_type::OSPFV3_SRV6_LAN_END_X_SID
                }
            }
            Self::IgpFlags(_) => tlv_type::IGP_FLAGS,
            Self::IgpRouteTag(_) => tlv_type::IGP_ROUTE_TAG,
            Self::PrefixMetric(_) => tlv_type::PREFIX_METRIC,
            Self::ForwardingAddressPrefix(_) => tlv_type::FORWARDING_ADDRESS_PREFIX,
            Self::OpaquePrefixAttribute(_) => tlv_type::OPAQUE_PREFIX_ATTRIBUTE,
            Self::PrefixAttributeFlags(_) => tlv_type::PREFIX_ATTRIBUTE_FLAGS,
            Self::Srv6Locator { .. } => tlv_type::SRV6_LOCATOR,
            Self::Srv6EndpointBehavior { .. } => tlv_type::SRV6_ENDPOINT_BEHAVIOR,
            Self::Srv6BgpPeerNodeSid { .. } => tlv_type::SRV6_BGP_PEER_NODE_SID,
            Self::Srv6SidStructure(_) => tlv_type::SRV6_SID_STRUCTURE,
            Self::Unknown(t) => t.ty,
        }
    }

    /// Wire length of this TLV's value (excluding the 4-byte TLV
    /// header). Used by the encoder to back-patch the `Length` field
    /// and by callers that need to size a buffer up front.
    pub fn value_len(&self) -> usize {
        match self {
            Self::NodeFlagBits(_) => 1,
            Self::OpaqueNodeAttribute(v) => v.len(),
            Self::NodeName(v) => v.len(),
            Self::IsisAreaIdentifier(v) => v.len(),
            Self::Ipv4RouterIdLocal(_) => 4,
            Self::Ipv6RouterIdLocal(_) => 16,
            Self::Srv6Capabilities { .. } => 4,
            Self::AdminGroup(_) => 4,
            Self::MaxLinkBandwidth(_) => 4,
            Self::MaxReservableBandwidth(_) => 4,
            Self::UnreservedBandwidth(_) => 32,
            Self::TeDefaultMetric(_) => 4,
            Self::LinkProtectionType(v) => v.len(),
            Self::MplsMetric(_) => 1,
            Self::SharedRiskLinkGroup(v) => v.len(),
            Self::IgpMetric(v) => v.len(),
            Self::Srv6EndXSid { sub_tlvs, .. } => 2 + 1 + 1 + 1 + 1 + 16 + sub_tlvs.len(),
            Self::Srv6LanEndXSid {
                neighbor_id,
                sub_tlvs,
                ..
            } => 2 + 1 + 1 + 1 + 1 + neighbor_id.len() + 16 + sub_tlvs.len(),
            Self::IgpFlags(_) => 1,
            Self::IgpRouteTag(v) => v.len(),
            Self::PrefixMetric(_) => 4,
            Self::ForwardingAddressPrefix(v) => v.len(),
            Self::OpaquePrefixAttribute(v) => v.len(),
            Self::PrefixAttributeFlags(_) => 1,
            Self::Srv6Locator { sub_tlvs, .. } => 1 + 1 + 2 + 4 + sub_tlvs.len(),
            Self::Srv6EndpointBehavior { .. } => 4,
            Self::Srv6BgpPeerNodeSid { .. } => 12,
            Self::Srv6SidStructure(_) => Srv6SidStructure::WIRE_LEN,
            Self::Unknown(t) => t.value.len(),
        }
    }

    /// Wire length of the whole TLV (4-byte header + value).
    pub fn wire_len(&self) -> usize {
        4 + self.value_len()
    }

    /// Encode this TLV into `out`. Returns the number of bytes
    /// written or an `EncodeError` when the value will not fit in a
    /// 16-bit `Length` field or the buffer is too small.
    pub fn encode(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let val_len = self.value_len();
        if val_len > u16::MAX as usize {
            return Err(EncodeError::InvalidValue(
                "bgp-ls-attr tlv length > u16::MAX",
            ));
        }
        if out.remaining_mut() < 4 + val_len {
            return Err(EncodeError::BufferFull);
        }
        out.put_u16_be(self.ty());
        out.put_u16_be(val_len as u16);
        self.encode_value(out)?;
        Ok(4 + val_len)
    }

    /// Encode this TLV's value into `out` (the bytes after the
    /// 4-byte TLV header). Used internally by [`Self::encode`] and by
    /// the attribute container's value encoder.
    fn encode_value(&self, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
        match self {
            Self::NodeFlagBits(b) => {
                out.put_u8(*b);
            }
            Self::OpaqueNodeAttribute(v)
            | Self::NodeName(v)
            | Self::IsisAreaIdentifier(v)
            | Self::LinkProtectionType(v)
            | Self::SharedRiskLinkGroup(v)
            | Self::IgpMetric(v)
            | Self::IgpRouteTag(v)
            | Self::ForwardingAddressPrefix(v)
            | Self::OpaquePrefixAttribute(v) => {
                out.put_bytes(v);
            }
            Self::Ipv4RouterIdLocal(b) => {
                out.put_bytes(b);
            }
            Self::Ipv6RouterIdLocal(b) => {
                out.put_bytes(b);
            }
            Self::Srv6Capabilities { flags, reserved } => {
                out.put_u16_be(*flags);
                out.put_u16_be(*reserved);
            }
            Self::AdminGroup(v) => {
                out.put_u32_be(*v);
            }
            Self::MaxLinkBandwidth(b) | Self::MaxReservableBandwidth(b) => {
                out.put_bytes(b);
            }
            Self::UnreservedBandwidth(b) => {
                out.put_bytes(b);
            }
            Self::TeDefaultMetric(v) => {
                out.put_u32_be(*v);
            }
            Self::MplsMetric(b) => {
                out.put_u8(*b);
            }
            Self::Srv6EndXSid {
                endpoint_behavior,
                flags,
                algorithm,
                weight,
                sid,
                sub_tlvs,
            } => {
                out.put_u16_be(*endpoint_behavior);
                out.put_u8(*flags);
                out.put_u8(*algorithm);
                out.put_u8(*weight);
                out.put_u8(0); // reserved
                out.put_bytes(sid);
                out.put_bytes(sub_tlvs);
            }
            Self::Srv6LanEndXSid {
                is_isis: _,
                endpoint_behavior,
                flags,
                algorithm,
                weight,
                neighbor_id,
                sid,
                sub_tlvs,
            } => {
                out.put_u16_be(*endpoint_behavior);
                out.put_u8(*flags);
                out.put_u8(*algorithm);
                out.put_u8(*weight);
                out.put_u8(0); // reserved
                out.put_bytes(neighbor_id);
                out.put_bytes(sid);
                out.put_bytes(sub_tlvs);
            }
            Self::IgpFlags(b) => {
                out.put_u8(*b);
            }
            Self::PrefixMetric(v) => {
                out.put_u32_be(*v);
            }
            Self::PrefixAttributeFlags(b) => {
                out.put_u8(*b);
            }
            Self::Srv6Locator {
                flags,
                algorithm,
                metric,
                sub_tlvs,
            } => {
                out.put_u8(*flags);
                out.put_u8(*algorithm);
                out.put_u16_be(0); // reserved
                out.put_u32_be(*metric);
                out.put_bytes(sub_tlvs);
            }
            Self::Srv6EndpointBehavior {
                behavior,
                flags,
                algorithm,
            } => {
                out.put_u16_be(behavior.to_u16());
                out.put_u8(*flags);
                out.put_u8(*algorithm);
            }
            Self::Srv6BgpPeerNodeSid {
                flags,
                weight,
                peer_as,
                peer_bgp_id,
            } => {
                out.put_u8(*flags);
                out.put_u8(*weight);
                out.put_u16_be(0); // reserved
                out.put_u32_be(*peer_as);
                out.put_u32_be(*peer_bgp_id);
            }
            Self::Srv6SidStructure(s) => {
                out.put_u8(s.locator_block_len);
                out.put_u8(s.locator_node_len);
                out.put_u8(s.function_len);
                out.put_u8(s.argument_len);
            }
            Self::Unknown(t) => {
                out.put_bytes(&t.value);
            }
        }
        Ok(())
    }

    /// Decode one TLV from the raw `Tlv` produced by the attribute
    /// stream parser. Length checks specific to each variant are
    /// enforced here — a wrong-length well-known TLV falls through to
    /// [`Self::Unknown`] so the byte stream still round-trips.
    pub fn decode(t: Tlv) -> Self {
        match t.ty {
            tlv_type::NODE_FLAG_BITS if t.value.len() == 1 => Self::NodeFlagBits(t.value[0]),
            tlv_type::OPAQUE_NODE_ATTRIBUTE => Self::OpaqueNodeAttribute(t.value),
            tlv_type::NODE_NAME => Self::NodeName(t.value),
            tlv_type::ISIS_AREA_IDENTIFIER => Self::IsisAreaIdentifier(t.value),
            tlv_type::IPV4_ROUTER_ID_LOCAL if t.value.len() == 4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(&t.value);
                Self::Ipv4RouterIdLocal(a)
            }
            tlv_type::IPV6_ROUTER_ID_LOCAL if t.value.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&t.value);
                Self::Ipv6RouterIdLocal(a)
            }
            tlv_type::SRV6_CAPABILITIES if t.value.len() == 4 => {
                let flags = u16::from_be_bytes([t.value[0], t.value[1]]);
                let reserved = u16::from_be_bytes([t.value[2], t.value[3]]);
                Self::Srv6Capabilities { flags, reserved }
            }
            tlv_type::ADMIN_GROUP if t.value.len() == 4 => Self::AdminGroup(u32::from_be_bytes([
                t.value[0], t.value[1], t.value[2], t.value[3],
            ])),
            tlv_type::MAX_LINK_BANDWIDTH if t.value.len() == 4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(&t.value);
                Self::MaxLinkBandwidth(a)
            }
            tlv_type::MAX_RESERVABLE_BANDWIDTH if t.value.len() == 4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(&t.value);
                Self::MaxReservableBandwidth(a)
            }
            tlv_type::UNRESERVED_BANDWIDTH if t.value.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&t.value);
                Self::UnreservedBandwidth(a)
            }
            tlv_type::TE_DEFAULT_METRIC if t.value.len() == 4 => {
                Self::TeDefaultMetric(u32::from_be_bytes([
                    t.value[0], t.value[1], t.value[2], t.value[3],
                ]))
            }
            tlv_type::LINK_PROTECTION_TYPE => Self::LinkProtectionType(t.value),
            tlv_type::MPLS_METRIC if t.value.len() == 1 => Self::MplsMetric(t.value[0]),
            tlv_type::SHARED_RISK_LINK_GROUP => Self::SharedRiskLinkGroup(t.value),
            tlv_type::IGP_METRIC if (1..=4).contains(&t.value.len()) => Self::IgpMetric(t.value),
            tlv_type::SRV6_END_X_SID if t.value.len() >= 22 => {
                // 2-byte endpoint behavior + 1-byte flags + 1-byte
                // algorithm + 1-byte weight + 1-byte reserved + 16-byte
                // SID = 22 bytes minimum, plus optional sub-TLVs.
                let endpoint_behavior = u16::from_be_bytes([t.value[0], t.value[1]]);
                let flags = t.value[2];
                let algorithm = t.value[3];
                let weight = t.value[4];
                // t.value[5] is the 1-byte reserved field.
                let mut sid = [0u8; 16];
                sid.copy_from_slice(&t.value[6..22]);
                let sub_tlvs = t.value[22..].to_vec();
                Self::Srv6EndXSid {
                    endpoint_behavior,
                    flags,
                    algorithm,
                    weight,
                    sid,
                    sub_tlvs,
                }
            }
            tlv_type::ISIS_SRV6_LAN_END_X_SID if t.value.len() >= 28 => {
                // 2-byte endpoint behavior + 1-byte flags + 1-byte
                // algorithm + 1-byte weight + 1-byte reserved + 6-byte
                // IS-IS neighbor System-ID + 16-byte SID = 28 bytes
                // minimum, plus optional sub-TLVs.
                let endpoint_behavior = u16::from_be_bytes([t.value[0], t.value[1]]);
                let flags = t.value[2];
                let algorithm = t.value[3];
                let weight = t.value[4];
                // t.value[5] is the 1-byte reserved field.
                let neighbor_id = t.value[6..12].to_vec();
                let mut sid = [0u8; 16];
                sid.copy_from_slice(&t.value[12..28]);
                let sub_tlvs = t.value[28..].to_vec();
                Self::Srv6LanEndXSid {
                    is_isis: true,
                    endpoint_behavior,
                    flags,
                    algorithm,
                    weight,
                    neighbor_id,
                    sid,
                    sub_tlvs,
                }
            }
            tlv_type::OSPFV3_SRV6_LAN_END_X_SID if t.value.len() >= 26 => {
                // 2-byte endpoint behavior + 1-byte flags + 1-byte
                // algorithm + 1-byte weight + 1-byte reserved + 4-byte
                // OSPFv3 Router-ID + 16-byte SID = 26 bytes minimum,
                // plus optional sub-TLVs.
                let endpoint_behavior = u16::from_be_bytes([t.value[0], t.value[1]]);
                let flags = t.value[2];
                let algorithm = t.value[3];
                let weight = t.value[4];
                // t.value[5] is the 1-byte reserved field.
                let neighbor_id = t.value[6..10].to_vec();
                let mut sid = [0u8; 16];
                sid.copy_from_slice(&t.value[10..26]);
                let sub_tlvs = t.value[26..].to_vec();
                Self::Srv6LanEndXSid {
                    is_isis: false,
                    endpoint_behavior,
                    flags,
                    algorithm,
                    weight,
                    neighbor_id,
                    sid,
                    sub_tlvs,
                }
            }
            tlv_type::IGP_FLAGS if t.value.len() == 1 => Self::IgpFlags(t.value[0]),
            tlv_type::IGP_ROUTE_TAG => Self::IgpRouteTag(t.value),
            tlv_type::PREFIX_METRIC if t.value.len() == 4 => {
                Self::PrefixMetric(u32::from_be_bytes([
                    t.value[0], t.value[1], t.value[2], t.value[3],
                ]))
            }
            tlv_type::FORWARDING_ADDRESS_PREFIX => Self::ForwardingAddressPrefix(t.value),
            tlv_type::OPAQUE_PREFIX_ATTRIBUTE => Self::OpaquePrefixAttribute(t.value),
            tlv_type::PREFIX_ATTRIBUTE_FLAGS if t.value.len() == 1 => {
                Self::PrefixAttributeFlags(t.value[0])
            }
            tlv_type::SRV6_LOCATOR if t.value.len() >= 8 => {
                // 1 + 1 + 2 + 4 = 8 minimum; rest is sub-TLVs.
                let flags = t.value[0];
                let algorithm = t.value[1];
                let metric = u32::from_be_bytes([t.value[4], t.value[5], t.value[6], t.value[7]]);
                let sub_tlvs = t.value[8..].to_vec();
                Self::Srv6Locator {
                    flags,
                    algorithm,
                    metric,
                    sub_tlvs,
                }
            }
            tlv_type::SRV6_ENDPOINT_BEHAVIOR if t.value.len() == 4 => {
                let behavior =
                    Srv6EndpointBehavior::from_u16(u16::from_be_bytes([t.value[0], t.value[1]]));
                let flags = t.value[2];
                let algorithm = t.value[3];
                Self::Srv6EndpointBehavior {
                    behavior,
                    flags,
                    algorithm,
                }
            }
            tlv_type::SRV6_BGP_PEER_NODE_SID if t.value.len() == 12 => {
                let flags = t.value[0];
                let weight = t.value[1];
                let peer_as = u32::from_be_bytes([t.value[4], t.value[5], t.value[6], t.value[7]]);
                let peer_bgp_id =
                    u32::from_be_bytes([t.value[8], t.value[9], t.value[10], t.value[11]]);
                Self::Srv6BgpPeerNodeSid {
                    flags,
                    weight,
                    peer_as,
                    peer_bgp_id,
                }
            }
            tlv_type::SRV6_SID_STRUCTURE if t.value.len() == 4 => {
                let s = Srv6SidStructure {
                    locator_block_len: t.value[0],
                    locator_node_len: t.value[1],
                    function_len: t.value[2],
                    argument_len: t.value[3],
                };
                if !s.is_valid() {
                    // RFC 9514 §8: sum of lengths MUST be ≤ 128. A
                    // structure that overflows the 128-bit SID space
                    // is malformed; preserve the bytes verbatim so
                    // the stream still round-trips and let the
                    // attribute-level decoder surface the violation
                    // via the projection's validation pass.
                    return Self::Unknown(t);
                }
                Self::Srv6SidStructure(s)
            }
            _ => Self::Unknown(t),
        }
    }
}

/// A BGP-LS Attribute (RFC 7752 §3.3). The attribute value is a TLV
/// stream; this struct owns the parsed TLV set and round-trips
/// byte-for-byte through [`Self::encode`] / [`Self::decode`].
///
/// The BGP path attribute header (type 29, optional + non-transitive
/// flags) is owned by the caller — this type only models the
/// attribute *value* so it can be attached to any BGP-LS NLRI via
/// the standard [`crate::path::PathAttributes`] surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct BgpLsAttr {
    pub tlvs: Vec<BgpLsAttrTlv>,
}

impl BgpLsAttr {
    pub fn new(tlvs: Vec<BgpLsAttrTlv>) -> Self {
        Self { tlvs }
    }
    /// True when no TLVs are present.
    pub fn is_empty(&self) -> bool {
        self.tlvs.is_empty()
    }
    /// Number of TLVs.
    pub fn len(&self) -> usize {
        self.tlvs.len()
    }
    /// Wire length of the attribute value (the concatenation of all
    /// TLVs, excluding the BGP path attribute header).
    pub fn value_len(&self) -> usize {
        self.tlvs.iter().map(BgpLsAttrTlv::wire_len).sum()
    }
    /// Encode the attribute value (the TLV stream) into `out`.
    /// Returns the number of bytes written.
    pub fn encode_value(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let start = out.position();
        for t in &self.tlvs {
            t.encode(out)?;
        }
        Ok(out.position() - start)
    }
    /// Encode the attribute value into a fresh `Vec<u8>`. Convenience
    /// for callers that want to attach the bytes to a
    /// [`crate::path::PathAttribute`] without managing a `WriteBuf`.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let total = self.value_len();
        let mut v = vec![0u8; total];
        let mut buf = WriteBuf::new(&mut v);
        self.encode_value(&mut buf)?;
        Ok(v)
    }
    /// Decode the attribute value (a TLV stream) from `b`. Returns
    /// `ParseError` on truncation or a length that runs past the
    /// buffer. Unknown TLVs are preserved verbatim — the codec never
    /// rejects a stream on the basis of an unknown TLV type.
    pub fn decode(b: &[u8]) -> Result<Self, ParseError> {
        let mut r = ReadBuf::new(b);
        let mut tlvs = Vec::new();
        while r.remaining() > 0 {
            let t = Tlv::decode(&mut r).ok_or_else(|| ParseError::truncated("bgp-ls-attr.tlv"))?;
            tlvs.push(BgpLsAttrTlv::decode(t));
        }
        Ok(Self { tlvs })
    }
    /// Find the first TLV of a given type, if any. Returns `None`
    /// when the type is absent.
    pub fn find(&self, ty: u16) -> Option<&BgpLsAttrTlv> {
        self.tlvs.iter().find(|t| t.ty() == ty)
    }
    /// Iterate over every TLV matching `ty`. RFC 7752 §3.3 permits
    /// multiple instances of some TLVs (e.g. IS-IS Area Identifier,
    /// SRv6 End.X SID); this iterator is the canonical way to read
    /// them.
    pub fn iter_ty(&self, ty: u16) -> impl Iterator<Item = &BgpLsAttrTlv> {
        self.tlvs.iter().filter(move |t| t.ty() == ty)
    }
}

#[cfg(test)]
#[path = "bgp_ls_attr_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bgp_ls_attr_seed_tests.rs"]
mod seed_tests;
