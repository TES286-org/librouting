//! BGP-LS NLRI codec (RFC 7752 §3.2-§3.3, base for RFC 9552 SRv6 SID NLRI).
//!
//! This module implements Layer 1 (the stateless wire codec) for the BGP-LS
//! Link-State AFI (16388) / SAFI 71 family. It parses and serialises the
//! Node, Link, IPv4 Topology Prefix and IPv6 Topology Prefix NLRI shapes
//! defined by RFC 7752 §3.3, plus the Local/Remote Node Descriptor,
//! Link Descriptor and Prefix Descriptor TLVs (§3.2) and the Node
//! Descriptor sub-TLVs (§3.2.1.4) and Prefix Descriptor sub-TLVs
//! (§3.2.3). Unknown TLVs and sub-TLVs are passed through verbatim — the
//! RFC mandates that an implementation must compare NLRIs byte-for-byte
//! even when it does not understand every sub-TLV, so the codec preserves
//! everything it cannot parse.
//!
//! # Wire shape (RFC 7752 §3.3 Figure 5)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            NLRI Type          |     Total NLRI Length         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! //                  Link-State NLRI (variable)                 //
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The `NLRI Type` and `Total NLRI Length` fields are 16-bit big-endian
//! integers. The `Total NLRI Length` field excludes the 4-byte header
//! itself (RFC 7752 §3.3: "the cumulative length, in octets, of the rest
//! of the NLRI, not including the NLRI Type field or itself"). For the
//! VPN family (SAFI=72), the length includes the 8-byte Route
//! Distinguisher.
//!
//! # Inner TLV framing (RFC 7752 §3.1)
//!
//! Each inner TLV uses the same 4-byte header:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              Type             |             Length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! //                         Value (variable)                   //
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `Type` and `Length` are 16-bit big-endian; `Length` excludes the
//! 4-byte TLV header.
//!
//! # Structure (per RFC 7752 §3.3)
//!
//! - **Node NLRI (Type 1)**: `Protocol-ID(1) | Identifier(8) |
//!   Local Node Descriptor TLV (type 256, wraps sub-TLVs)`.
//! - **Link NLRI (Type 2)**: `Protocol-ID(1) | Identifier(8) |
//!   Local Node Descriptor TLV (256) | Remote Node Descriptor TLV (257)
//!   | Link Descriptor TLV stream (258..=263, bare — no wrapper)`.
//! - **IPv4/IPv6 Prefix NLRI (Types 3/4)**: `Protocol-ID(1) |
//!   Identifier(8) | Local Node Descriptor TLV (256) | Prefix
//!   Descriptor TLV stream (263..=265, bare — no wrapper)`.
//!
//! Local Node Descriptor and Remote Node Descriptor are wrapper TLVs
//! (their value is a sub-TLV stream of 512-516 etc.). Link Descriptor
//! and Prefix Descriptor are bare TLV streams at the same level —
//! matching the BIRD and FRR reference codecs.
//!
//! # Scope
//!
//! This is the codec half of issue #60's work breakdown. The OSPF LSDB
//! → BGP-LS projection (RFC 7752 §3 with SR-MPLS / SRv6 descriptors)
//! and the daemon wiring (`--bgp-ls` flag, capability negotiation) are
//! separate follow-ups. The SRv6 SID NLRI (RFC 9514 §3, NLRI Type 6) is
//! parsed at the framing level only — its inner sub-TLVs (`SRv6 SID
//! Information`, `SRv6 Endpoint Behavior`, `SRv6 SID Structure`) need
//! a follow-up.

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::error::{EncodeError, ParseError};

/// AFI for BGP-LS, per IANA "Address Family Numbers" registry
/// (RFC 7752 §3.1). Re-exported here so the codec is self-contained.
pub const AFI_BGP_LS: u16 = 16388;
/// SAFI for BGP-LS, per IANA "Subsequent Address Family Identifiers
/// (SAFI) Values" registry (RFC 7752 §3.1).
pub const SAFI_BGP_LS: u8 = 71;
/// SAFI for BGP-LS VPN, per RFC 7752 §3.3 Figure 6.
pub const SAFI_BGP_LS_VPN: u8 = 72;

/// NLRI Type values, per RFC 7752 §3.3 Table 1 + RFC 9514 §3 for SRv6 SID.
///
/// The field is u16 on the wire; the assigned values fit in a small
/// range, so an enum keeps the call sites readable while still
/// admitting an `Unknown` variant that carries the raw 16-bit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BgpLsNlriType {
    /// RFC 7752 §3.3 Table 1: Node NLRI.
    Node,
    /// RFC 7752 §3.3 Table 1: Link NLRI.
    Link,
    /// RFC 7752 §3.3 Table 1: IPv4 Topology Prefix NLRI.
    Ipv4Prefix,
    /// RFC 7752 §3.3 Table 1: IPv6 Topology Prefix NLRI.
    Ipv6Prefix,
    /// RFC 9514 §3: SRv6 SID NLRI. The codec parses the framing; the
    /// inner SRv6 descriptor sub-TLVs are deferred to a follow-up.
    Srv6Sid,
    /// Unknown NLRI type — captured as the raw 16-bit code so the NLRI
    /// can still be re-encoded byte-for-byte.
    Unknown(u16),
}

impl BgpLsNlriType {
    /// The 16-bit wire value.
    pub const NODE: u16 = 1;
    pub const LINK: u16 = 2;
    pub const IPV4_PREFIX: u16 = 3;
    pub const IPV6_PREFIX: u16 = 4;
    pub const SRV6_SID: u16 = 6;

    pub fn from_u16(v: u16) -> Self {
        match v {
            Self::NODE => Self::Node,
            Self::LINK => Self::Link,
            Self::IPV4_PREFIX => Self::Ipv4Prefix,
            Self::IPV6_PREFIX => Self::Ipv6Prefix,
            Self::SRV6_SID => Self::Srv6Sid,
            _ => Self::Unknown(v),
        }
    }
    pub fn to_u16(self) -> u16 {
        match self {
            Self::Node => Self::NODE,
            Self::Link => Self::LINK,
            Self::Ipv4Prefix => Self::IPV4_PREFIX,
            Self::Ipv6Prefix => Self::IPV6_PREFIX,
            Self::Srv6Sid => Self::SRV6_SID,
            Self::Unknown(v) => v,
        }
    }
}

/// Protocol-ID, per RFC 7752 §3.3 Table 2.
///
/// Identifies the IGP the NLRI was sourced from; the codec carries it
/// as an opaque byte so that projections can attach the right semantic
/// to an `IGP Router-ID` (a 32-bit OSPF Router-ID or a 6/7-byte IS-IS
/// System-ID) without the codec having to know the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolId {
    IsisLevel1,
    IsisLevel2,
    Ospfv2,
    Direct,
    Static,
    Ospfv3,
    Bgp,
    Unknown(u8),
}

impl ProtocolId {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::IsisLevel1,
            2 => Self::IsisLevel2,
            3 => Self::Ospfv2,
            4 => Self::Direct,
            5 => Self::Static,
            6 => Self::Ospfv3,
            7 => Self::Bgp,
            _ => Self::Unknown(v),
        }
    }
    pub fn to_u8(self) -> u8 {
        match self {
            Self::IsisLevel1 => 1,
            Self::IsisLevel2 => 2,
            Self::Ospfv2 => 3,
            Self::Direct => 4,
            Self::Static => 5,
            Self::Ospfv3 => 6,
            Self::Bgp => 7,
            Self::Unknown(v) => v,
        }
    }
}

/// TLV type code points defined by RFC 7752 §7 Table 13.
///
/// The same code space is shared by:
/// - **Outer TLVs** inside the NLRI value: `LocalNodeDescriptor` (256),
///   `RemoteNodeDescriptor` (257) (§3.2.1.2 / §3.2.1.3). These are
///   *wrapper* TLVs whose value is a sub-TLV stream.
/// - **Bare TLV streams** at the same level as the wrapper TLVs:
///   Link Descriptor sub-TLVs (§3.2.2 Table 5) and Prefix Descriptor
///   sub-TLVs (§3.2.3 Table 6) carry the same code points (258-265)
///   without an additional wrapping TLV.
/// - **Sub-TLVs inside a Node Descriptor**: `As` (512), `BgpLsId` (513),
///   `OspfAreaId` (514), `IgpRouterId` (515) (§3.2.1.4 Table 4).
///
/// The codec never interprets `Multi-Topology ID` (263) content beyond
/// bounds-checking; RFC 7752 §3.2.1.5 describes its layout as
/// `Length = 2 * n` with `n` 2-byte MT-IDs, but the codec leaves
/// unpacking to the projection that owns the topology context.
pub mod tlv_type {
    // Outer wrapper TLVs (§3.2.1.2 / §3.2.1.3) — value is a sub-TLV stream.
    pub const LOCAL_NODE_DESCRIPTOR: u16 = 256;
    pub const REMOTE_NODE_DESCRIPTOR: u16 = 257;

    // Bare-stream TLVs (§3.2.2 Table 5 / §3.2.3 Table 6) — appear
    // either as a Link Descriptor or Prefix Descriptor stream,
    // depending on the parent NLRI type.
    pub const LINK_LOCAL_REMOTE_ID: u16 = 258;
    pub const IPV4_INTERFACE_ADDRESS: u16 = 259;
    pub const IPV4_NEIGHBOR_ADDRESS: u16 = 260;
    pub const IPV6_INTERFACE_ADDRESS: u16 = 261;
    pub const IPV6_NEIGHBOR_ADDRESS: u16 = 262;
    pub const MULTI_TOPOLOGY_ID: u16 = 263;
    pub const OSPF_ROUTE_TYPE: u16 = 264;
    pub const IP_REACHABILITY_INFO: u16 = 265;

    // Node Descriptor sub-TLVs (§3.2.1.4 Table 4) — inside a Node
    // Descriptor wrapper TLV.
    pub const AUTONOMOUS_SYSTEM: u16 = 512;
    pub const BGP_LS_IDENTIFIER: u16 = 513;
    pub const OSPF_AREA_ID: u16 = 514;
    pub const IGP_ROUTER_ID: u16 = 515;
}

/// OSPF Route Type values, per RFC 7752 §3.2.3.1 (Table following the
/// Route Type TLV description). Carried in the 1-byte Value of TLV 264.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OspfRouteType {
    IntraArea,
    InterArea,
    External1,
    External2,
    Nssa1,
    Nssa2,
    Unknown(u8),
}

impl OspfRouteType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::IntraArea,
            2 => Self::InterArea,
            3 => Self::External1,
            4 => Self::External2,
            5 => Self::Nssa1,
            6 => Self::Nssa2,
            _ => Self::Unknown(v),
        }
    }
    pub fn to_u8(self) -> u8 {
        match self {
            Self::IntraArea => 1,
            Self::InterArea => 2,
            Self::External1 => 3,
            Self::External2 => 4,
            Self::Nssa1 => 5,
            Self::Nssa2 => 6,
            Self::Unknown(v) => v,
        }
    }
}

/// One raw TLV inside the BGP-LS TLV stream: 16-bit type, 16-bit
/// length, value bytes.
///
/// The codec works in terms of `Tlv` for any code point it does not
/// need to unpack. The typed views below (`NodeDescriptor`,
/// `LinkDescriptor`, `PrefixDescriptor`) wrap a slice of `Tlv`s and
/// expose the well-known sub-TLVs as Rust fields.
///
/// `Tlv` is the unit of unknown-passthrough: round-tripping a parsed
/// NLRI preserves byte-for-byte equality for every sub-TLV the codec
/// does not model.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tlv {
    pub ty: u16,
    pub value: Vec<u8>,
}

impl Tlv {
    /// Wire length of one TLV: 4-byte header + value length.
    pub fn wire_len(&self) -> usize {
        4 + self.value.len()
    }

    /// Encode this TLV into `out`. Returns the number of bytes written
    /// or an `EncodeError` when the buffer is full. The value length
    /// must fit in a `u16` (max 65535 bytes per TLV).
    pub fn encode(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let len = self.value.len();
        if len > u16::MAX as usize {
            return Err(EncodeError::InvalidValue("bgp-ls tlv length > u16::MAX"));
        }
        if out.remaining_mut() < 4 + len {
            return Err(EncodeError::BufferFull);
        }
        out.put_u16_be(self.ty);
        out.put_u16_be(len as u16);
        out.put_bytes(&self.value);
        Ok(4 + len)
    }

    /// Decode one TLV from `r`. Returns `None` (caller-side) on
    /// truncation; the caller turns that into the appropriate
    /// `ParseError`.
    pub fn decode(r: &mut ReadBuf<'_>) -> Option<Self> {
        let ty = r.get_u16_be()?;
        let len = r.get_u16_be()? as usize;
        let value = r.get_bytes(len)?.to_vec();
        Some(Self { ty, value })
    }
}

/// Decode a TLV stream into a `Vec<Tlv>`. Truncation or a length that
/// runs past the buffer produces a `ParseError` so the caller can
/// reject the whole NLRI.
pub fn decode_tlv_stream(b: &[u8]) -> Result<Vec<Tlv>, ParseError> {
    let mut r = ReadBuf::new(b);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let tlv = Tlv::decode(&mut r).ok_or_else(|| ParseError::truncated("bgp-ls.tlv"))?;
        out.push(tlv);
    }
    Ok(out)
}

/// Encode a slice of `Tlv`s into a contiguous byte buffer.
pub fn encode_tlv_stream(tlvs: &[Tlv]) -> Result<Vec<u8>, EncodeError> {
    let total = tlvs.iter().map(Tlv::wire_len).sum();
    let mut v = Vec::with_capacity(total);
    let mut buf = WriteBuf::new(&mut v);
    for t in tlvs {
        t.encode(&mut buf)?;
    }
    Ok(v)
}

/// A Node Descriptor sub-TLV, per RFC 7752 §3.2.1.4 Table 4.
///
/// The codec parses the four well-known sub-TLVs into typed variants
/// and preserves any other sub-TLV verbatim. `IgpRouterId` is left as
/// raw bytes because its layout depends on the Protocol-ID — see
/// RFC 7752 §3.2.1.4 "IGP Router-ID" for the per-protocol shapes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeDescriptorSubTlv {
    /// TLV 512. 4-byte AS number.
    As(u32),
    /// TLV 513. 4-byte BGP-LS Identifier.
    BgpLsId(u32),
    /// TLV 514. 4-byte OSPF Area-ID.
    OspfAreaId(u32),
    /// TLV 515. Variable-length IGP Router-ID. Stored raw — the
    /// interpretation depends on the NLRI's Protocol-ID.
    IgpRouterId(Vec<u8>),
    /// Any other sub-TLV, preserved verbatim for byte-exact round-trip.
    Unknown(Tlv),
}

impl NodeDescriptorSubTlv {
    /// Wire length of one Node Descriptor sub-TLV (4-byte header +
    /// value).
    pub fn wire_len(&self) -> usize {
        match self {
            Self::As(_) | Self::BgpLsId(_) | Self::OspfAreaId(_) => 4 + 4,
            Self::IgpRouterId(v) => 4 + v.len(),
            Self::Unknown(t) => t.wire_len(),
        }
    }
    pub fn ty(&self) -> u16 {
        match self {
            Self::As(_) => tlv_type::AUTONOMOUS_SYSTEM,
            Self::BgpLsId(_) => tlv_type::BGP_LS_IDENTIFIER,
            Self::OspfAreaId(_) => tlv_type::OSPF_AREA_ID,
            Self::IgpRouterId(_) => tlv_type::IGP_ROUTER_ID,
            Self::Unknown(t) => t.ty,
        }
    }
    pub fn encode_into(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        match self {
            Self::As(v) => encode_fixed(out, tlv_type::AUTONOMOUS_SYSTEM, &v.to_be_bytes()),
            Self::BgpLsId(v) => encode_fixed(out, tlv_type::BGP_LS_IDENTIFIER, &v.to_be_bytes()),
            Self::OspfAreaId(v) => encode_fixed(out, tlv_type::OSPF_AREA_ID, &v.to_be_bytes()),
            Self::IgpRouterId(v) => Tlv {
                ty: tlv_type::IGP_ROUTER_ID,
                value: v.clone(),
            }
            .encode(out),
            Self::Unknown(t) => t.encode(out),
        }
    }
    pub fn decode(t: Tlv) -> Self {
        match t.ty {
            tlv_type::AUTONOMOUS_SYSTEM if t.value.len() == 4 => {
                let v = u32::from_be_bytes([t.value[0], t.value[1], t.value[2], t.value[3]]);
                Self::As(v)
            }
            tlv_type::BGP_LS_IDENTIFIER if t.value.len() == 4 => {
                let v = u32::from_be_bytes([t.value[0], t.value[1], t.value[2], t.value[3]]);
                Self::BgpLsId(v)
            }
            tlv_type::OSPF_AREA_ID if t.value.len() == 4 => {
                let v = u32::from_be_bytes([t.value[0], t.value[1], t.value[2], t.value[3]]);
                Self::OspfAreaId(v)
            }
            tlv_type::IGP_ROUTER_ID => Self::IgpRouterId(t.value),
            _ => Self::Unknown(t),
        }
    }
}

/// A Link Descriptor sub-TLV, per RFC 7752 §3.2.2 Table 5.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinkDescriptorSubTlv {
    /// TLV 258. 8 bytes: 4-byte local + 4-byte remote link ID.
    LinkLocalRemoteId { local: u32, remote: u32 },
    /// TLV 259. 4-byte IPv4 interface address.
    Ipv4InterfaceAddress([u8; 4]),
    /// TLV 260. 4-byte IPv4 neighbor address.
    Ipv4NeighborAddress([u8; 4]),
    /// TLV 261. 16-byte IPv6 interface address (RFC 6119 §4.2).
    Ipv6InterfaceAddress([u8; 16]),
    /// TLV 262. 16-byte IPv6 neighbor address (RFC 6119 §4.3).
    Ipv6NeighborAddress([u8; 16]),
    /// TLV 263. Raw multi-topology IDs (each 2 bytes; RFC 7752 §3.2.1.5).
    MultiTopologyId(Vec<u8>),
    /// Any other sub-TLV, preserved verbatim.
    Unknown(Tlv),
}

impl LinkDescriptorSubTlv {
    /// Wire length of one Link Descriptor sub-TLV (4-byte header + value).
    pub fn wire_len(&self) -> usize {
        match self {
            Self::LinkLocalRemoteId { .. } => 4 + 8,
            Self::Ipv4InterfaceAddress(_) | Self::Ipv4NeighborAddress(_) => 4 + 4,
            Self::Ipv6InterfaceAddress(_) | Self::Ipv6NeighborAddress(_) => 4 + 16,
            Self::MultiTopologyId(v) => 4 + v.len(),
            Self::Unknown(t) => t.wire_len(),
        }
    }
    pub fn ty(&self) -> u16 {
        match self {
            Self::LinkLocalRemoteId { .. } => tlv_type::LINK_LOCAL_REMOTE_ID,
            Self::Ipv4InterfaceAddress(_) => tlv_type::IPV4_INTERFACE_ADDRESS,
            Self::Ipv4NeighborAddress(_) => tlv_type::IPV4_NEIGHBOR_ADDRESS,
            Self::Ipv6InterfaceAddress(_) => tlv_type::IPV6_INTERFACE_ADDRESS,
            Self::Ipv6NeighborAddress(_) => tlv_type::IPV6_NEIGHBOR_ADDRESS,
            Self::MultiTopologyId(_) => tlv_type::MULTI_TOPOLOGY_ID,
            Self::Unknown(t) => t.ty,
        }
    }
    pub fn encode_into(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        match self {
            Self::LinkLocalRemoteId { local, remote } => {
                let mut v = Vec::with_capacity(8);
                v.extend_from_slice(&local.to_be_bytes());
                v.extend_from_slice(&remote.to_be_bytes());
                Tlv {
                    ty: tlv_type::LINK_LOCAL_REMOTE_ID,
                    value: v,
                }
                .encode(out)
            }
            Self::Ipv4InterfaceAddress(b) => {
                encode_fixed(out, tlv_type::IPV4_INTERFACE_ADDRESS, b)
            }
            Self::Ipv4NeighborAddress(b) => {
                encode_fixed(out, tlv_type::IPV4_NEIGHBOR_ADDRESS, b)
            }
            Self::Ipv6InterfaceAddress(b) => {
                encode_fixed(out, tlv_type::IPV6_INTERFACE_ADDRESS, b)
            }
            Self::Ipv6NeighborAddress(b) => {
                encode_fixed(out, tlv_type::IPV6_NEIGHBOR_ADDRESS, b)
            }
            Self::MultiTopologyId(v) => Tlv {
                ty: tlv_type::MULTI_TOPOLOGY_ID,
                value: v.clone(),
            }
            .encode(out),
            Self::Unknown(t) => t.encode(out),
        }
    }
    pub fn decode(t: Tlv) -> Self {
        match t.ty {
            tlv_type::LINK_LOCAL_REMOTE_ID if t.value.len() == 8 => {
                let local = u32::from_be_bytes([
                    t.value[0],
                    t.value[1],
                    t.value[2],
                    t.value[3],
                ]);
                let remote = u32::from_be_bytes([
                    t.value[4],
                    t.value[5],
                    t.value[6],
                    t.value[7],
                ]);
                Self::LinkLocalRemoteId { local, remote }
            }
            tlv_type::IPV4_INTERFACE_ADDRESS if t.value.len() == 4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(&t.value);
                Self::Ipv4InterfaceAddress(a)
            }
            tlv_type::IPV4_NEIGHBOR_ADDRESS if t.value.len() == 4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(&t.value);
                Self::Ipv4NeighborAddress(a)
            }
            tlv_type::IPV6_INTERFACE_ADDRESS if t.value.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&t.value);
                Self::Ipv6InterfaceAddress(a)
            }
            tlv_type::IPV6_NEIGHBOR_ADDRESS if t.value.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&t.value);
                Self::Ipv6NeighborAddress(a)
            }
            tlv_type::MULTI_TOPOLOGY_ID => Self::MultiTopologyId(t.value),
            _ => Self::Unknown(t),
        }
    }
}

/// A Prefix Descriptor sub-TLV, per RFC 7752 §3.2.3 Table 6.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrefixDescriptorSubTlv {
    /// TLV 263. Raw multi-topology IDs (each 2 bytes).
    MultiTopologyId(Vec<u8>),
    /// TLV 264. 1-byte OSPF route type. RFC 7752 §3.2.3.1.
    OspfRouteType(OspfRouteType),
    /// TLV 265. Variable-length IP reachability: 1-byte prefix length
    /// followed by the most-significant octets of the prefix.
    /// Stored raw so the codec does not impose the AFI; the projection
    /// reads the prefix with the family it has in hand.
    IpReachabilityInfo { prefix_len: u8, prefix_bytes: Vec<u8> },
    /// Any other sub-TLV, preserved verbatim.
    Unknown(Tlv),
}

impl PrefixDescriptorSubTlv {
    /// Wire length of one Prefix Descriptor sub-TLV (4-byte header + value).
    pub fn wire_len(&self) -> usize {
        match self {
            Self::MultiTopologyId(v) => 4 + v.len(),
            Self::OspfRouteType(_) => 4 + 1,
            Self::IpReachabilityInfo { prefix_bytes, .. } => 4 + 1 + prefix_bytes.len(),
            Self::Unknown(t) => t.wire_len(),
        }
    }
    pub fn ty(&self) -> u16 {
        match self {
            Self::MultiTopologyId(_) => tlv_type::MULTI_TOPOLOGY_ID,
            Self::OspfRouteType(_) => tlv_type::OSPF_ROUTE_TYPE,
            Self::IpReachabilityInfo { .. } => tlv_type::IP_REACHABILITY_INFO,
            Self::Unknown(t) => t.ty,
        }
    }
    pub fn encode_into(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        match self {
            Self::MultiTopologyId(v) => Tlv {
                ty: tlv_type::MULTI_TOPOLOGY_ID,
                value: v.clone(),
            }
            .encode(out),
            Self::OspfRouteType(r) => encode_fixed(out, tlv_type::OSPF_ROUTE_TYPE, &[r.to_u8()]),
            Self::IpReachabilityInfo {
                prefix_len,
                prefix_bytes,
            } => {
                let mut v = Vec::with_capacity(1 + prefix_bytes.len());
                v.push(*prefix_len);
                v.extend_from_slice(prefix_bytes);
                Tlv {
                    ty: tlv_type::IP_REACHABILITY_INFO,
                    value: v,
                }
                .encode(out)
            }
            Self::Unknown(t) => t.encode(out),
        }
    }
    pub fn decode(t: Tlv) -> Self {
        match t.ty {
            tlv_type::MULTI_TOPOLOGY_ID => Self::MultiTopologyId(t.value),
            tlv_type::OSPF_ROUTE_TYPE if t.value.len() == 1 => {
                Self::OspfRouteType(OspfRouteType::from_u8(t.value[0]))
            }
            tlv_type::IP_REACHABILITY_INFO if !t.value.is_empty() => {
                let prefix_len = t.value[0];
                let prefix_bytes = t.value[1..].to_vec();
                Self::IpReachabilityInfo {
                    prefix_len,
                    prefix_bytes,
                }
            }
            _ => Self::Unknown(t),
        }
    }
}

/// A Node Descriptor (RFC 7752 §3.2.1.4) — the union of sub-TLVs that
/// identify one node (AS, BGP-LS ID, OSPF Area-ID, IGP Router-ID, plus
/// any future / unknown sub-TLVs preserved verbatim).
///
/// Used as the `Local Node Descriptor` and `Remote Node Descriptor`
/// value inside Node/Link/Prefix NLRIs. The codec preserves the
/// sub-TLV order encountered on decode (RFC 7752 §3.2.1.4 mandates
/// ascending order by sub-TLV type on the wire, but the codec does not
/// enforce it — only preserves it so a re-encode round-trips).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeDescriptor {
    pub sub_tlvs: Vec<NodeDescriptorSubTlv>,
}

impl NodeDescriptor {
    pub fn new(sub_tlvs: Vec<NodeDescriptorSubTlv>) -> Self {
        Self { sub_tlvs }
    }
    /// Helper: the 4-byte Autonomous System sub-TLV value, or `None`
    /// when the descriptor does not carry one.
    pub fn as_number(&self) -> Option<u32> {
        self.sub_tlvs.iter().find_map(|s| match s {
            NodeDescriptorSubTlv::As(v) => Some(*v),
            _ => None,
        })
    }
    /// Helper: the 4-byte BGP-LS Identifier sub-TLV value, or `None`.
    pub fn bgp_ls_id(&self) -> Option<u32> {
        self.sub_tlvs.iter().find_map(|s| match s {
            NodeDescriptorSubTlv::BgpLsId(v) => Some(*v),
            _ => None,
        })
    }
    /// Helper: the 4-byte OSPF Area-ID sub-TLV value, or `None`.
    pub fn ospf_area_id(&self) -> Option<u32> {
        self.sub_tlvs.iter().find_map(|s| match s {
            NodeDescriptorSubTlv::OspfAreaId(v) => Some(*v),
            _ => None,
        })
    }
    /// Helper: the raw IGP Router-ID bytes, or `None`. The
    /// interpretation depends on the surrounding NLRI's Protocol-ID —
    /// 4 bytes for OSPFv2/v3 non-pseudonode, 6 bytes for IS-IS
    /// non-pseudonode, 7 for IS-IS pseudonode, 8 for OSPF pseudonode
    /// (RFC 7752 §3.2.1.4 "IGP Router-ID").
    pub fn igp_router_id(&self) -> Option<&[u8]> {
        self.sub_tlvs.iter().find_map(|s| match s {
            NodeDescriptorSubTlv::IgpRouterId(v) => Some(v.as_slice()),
            _ => None,
        })
    }
    /// Wire length of the descriptor's value (i.e. the sum of the
    /// sub-TLV wire lengths, without the outer wrapper TLV header).
    pub fn value_len(&self) -> usize {
        self.sub_tlvs.iter().map(NodeDescriptorSubTlv::wire_len).sum()
    }
    pub fn encode_value(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let start = out.position();
        for s in &self.sub_tlvs {
            s.encode_into(out)?;
        }
        Ok(out.position() - start)
    }
    pub fn decode_value(b: &[u8]) -> Result<Self, ParseError> {
        let tlvs = decode_tlv_stream(b)?;
        Ok(Self {
            sub_tlvs: tlvs.into_iter().map(NodeDescriptorSubTlv::decode).collect(),
        })
    }
}

/// A Link Descriptor (RFC 7752 §3.2.2) — sub-TLVs that identify one
/// half-link among parallel links between two anchor routers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkDescriptor {
    pub sub_tlvs: Vec<LinkDescriptorSubTlv>,
}

impl LinkDescriptor {
    pub fn new(sub_tlvs: Vec<LinkDescriptorSubTlv>) -> Self {
        Self { sub_tlvs }
    }
    /// Wire length of the descriptor (sum of sub-TLV wire lengths).
    pub fn value_len(&self) -> usize {
        self.sub_tlvs.iter().map(LinkDescriptorSubTlv::wire_len).sum()
    }
    pub fn encode_into(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let start = out.position();
        for s in &self.sub_tlvs {
            s.encode_into(out)?;
        }
        Ok(out.position() - start)
    }
    pub fn decode_from(b: &[u8]) -> Result<Self, ParseError> {
        let tlvs = decode_tlv_stream(b)?;
        Ok(Self {
            sub_tlvs: tlvs.into_iter().map(LinkDescriptorSubTlv::decode).collect(),
        })
    }
}

/// A Prefix Descriptor (RFC 7752 §3.2.3) — sub-TLVs that identify one
/// IPv4 or IPv6 prefix originated by a node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrefixDescriptor {
    pub sub_tlvs: Vec<PrefixDescriptorSubTlv>,
}

impl PrefixDescriptor {
    pub fn new(sub_tlvs: Vec<PrefixDescriptorSubTlv>) -> Self {
        Self { sub_tlvs }
    }
    /// Wire length of the descriptor (sum of sub-TLV wire lengths).
    pub fn value_len(&self) -> usize {
        self.sub_tlvs.iter().map(PrefixDescriptorSubTlv::wire_len).sum()
    }
    pub fn encode_into(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let start = out.position();
        for s in &self.sub_tlvs {
            s.encode_into(out)?;
        }
        Ok(out.position() - start)
    }
    pub fn decode_from(b: &[u8]) -> Result<Self, ParseError> {
        let tlvs = decode_tlv_stream(b)?;
        Ok(Self {
            sub_tlvs: tlvs.into_iter().map(PrefixDescriptorSubTlv::decode).collect(),
        })
    }
}

/// A BGP-LS Node NLRI (RFC 7752 §3.3, NLRI Type 1).
///
/// Shape on the wire:
/// ```text
/// Protocol-ID (1) | Identifier (8) | Local Node Descriptor TLV (variable)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeNlri {
    pub protocol_id: ProtocolId,
    pub identifier: u64,
    pub local_node: NodeDescriptor,
}

/// A BGP-LS Link NLRI (RFC 7752 §3.3, NLRI Type 2).
///
/// Shape on the wire:
/// ```text
/// Protocol-ID (1) | Identifier (8) | Local Node Descriptor TLV |
/// Remote Node Descriptor TLV | Link Descriptor TLV stream
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkNlri {
    pub protocol_id: ProtocolId,
    pub identifier: u64,
    pub local_node: NodeDescriptor,
    pub remote_node: NodeDescriptor,
    pub link: LinkDescriptor,
}

/// A BGP-LS IPv4 or IPv6 Topology Prefix NLRI (RFC 7752 §3.3, NLRI Type 3/4).
///
/// The codec stores the family in the [`NlriFamily`] the caller passed
/// in; the IPv4 and IPv6 forms share the same NLRI shape and differ
/// only in the family code advertised in MP_REACH_NLRI / MP_UNREACH_NLRI.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrefixNlri {
    pub protocol_id: ProtocolId,
    pub identifier: u64,
    pub local_node: NodeDescriptor,
    pub prefix: PrefixDescriptor,
}

/// An 8-byte Route Distinguisher (RFC 4364 §4.2) prepended to the
/// NLRI value when the family is BGP-LS VPN (SAFI=72).
pub type RouteDistinguisher = [u8; 8];

/// One BGP-LS NLRI in parsed form. The variant is keyed by the
/// `NLRI Type` field; the optional `route_distinguisher` is `Some`
/// when the surrounding family is BGP-LS VPN (SAFI=72).
///
/// `Unknown` preserves the raw NLRI bytes for any NLRI Type the codec
/// does not model (currently anything other than 1, 2, 3, 4) so a
/// future extension can re-encode without loss.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BgpLsNlri {
    pub route_distinguisher: Option<RouteDistinguisher>,
    pub variant: BgpLsNlriVariant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BgpLsNlriVariant {
    Node(NodeNlri),
    Link(LinkNlri),
    Ipv4Prefix(PrefixNlri),
    Ipv6Prefix(PrefixNlri),
    /// Any NLRI Type the codec does not model (currently NLRI Type 6,
    /// the SRv6 SID NLRI from RFC 9514 §3, plus any future assignment).
    /// The bytes are the NLRI value, i.e. everything after the 4-byte
    /// NLRI header and (if present) the 8-byte Route Distinguisher.
    Unknown {
        nlri_type: BgpLsNlriType,
        bytes: Vec<u8>,
    },
}

impl BgpLsNlri {
    /// Length of the NLRI value (excluding the 4-byte NLRI header and
    /// the optional 8-byte RD). This is what the `Total NLRI Length`
    /// field on the wire carries, minus the 8-byte RD when present.
    fn value_len(&self) -> usize {
        match &self.variant {
            BgpLsNlriVariant::Node(n) => 9 + wrapped_descriptor_len(&n.local_node),
            BgpLsNlriVariant::Link(n) => {
                9 + wrapped_descriptor_len(&n.local_node)
                    + wrapped_descriptor_len(&n.remote_node)
                    + n.link.value_len()
            }
            BgpLsNlriVariant::Ipv4Prefix(n) | BgpLsNlriVariant::Ipv6Prefix(n) => {
                9 + wrapped_descriptor_len(&n.local_node) + n.prefix.value_len()
            }
            BgpLsNlriVariant::Unknown { bytes, .. } => bytes.len(),
        }
    }

    /// Total wire length of this NLRI: 4-byte NLRI header + 8-byte RD
    /// (if present) + NLRI value bytes.
    pub fn wire_len(&self) -> usize {
        let value = self.value_len();
        4 + 8 * self.route_distinguisher.is_some() as usize + value
    }

    /// Encode this NLRI into `out`. Returns the number of bytes
    /// written, or an `EncodeError` when the value will not fit in a
    /// 16-bit `Total NLRI Length` field or the buffer is too small.
    pub fn encode(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let value_len = self.value_len();
        let total_len = value_len + 8 * self.route_distinguisher.is_some() as usize;
        if total_len > u16::MAX as usize {
            return Err(EncodeError::InvalidValue("bgp-ls nlri length > u16::MAX"));
        }
        if out.remaining_mut() < 4 + total_len {
            return Err(EncodeError::BufferFull);
        }
        let nlri_type = match &self.variant {
            BgpLsNlriVariant::Node(_) => BgpLsNlriType::Node,
            BgpLsNlriVariant::Link(_) => BgpLsNlriType::Link,
            BgpLsNlriVariant::Ipv4Prefix(_) => BgpLsNlriType::Ipv4Prefix,
            BgpLsNlriVariant::Ipv6Prefix(_) => BgpLsNlriType::Ipv6Prefix,
            BgpLsNlriVariant::Unknown { nlri_type, .. } => *nlri_type,
        };
        out.put_u16_be(nlri_type.to_u16());
        out.put_u16_be(total_len as u16);
        if let Some(rd) = &self.route_distinguisher {
            out.put_bytes(rd);
        }
        self.encode_value(out)?;
        Ok(4 + total_len)
    }

    /// Encode the NLRI value (everything after the 4-byte NLRI header
    /// and the optional 8-byte RD).
    fn encode_value(&self, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
        match &self.variant {
            BgpLsNlriVariant::Node(n) => {
                out.put_u8(n.protocol_id.to_u8());
                out.put_u64_be(n.identifier);
                encode_wrapped_descriptor(out, tlv_type::LOCAL_NODE_DESCRIPTOR, &n.local_node)?;
            }
            BgpLsNlriVariant::Link(n) => {
                out.put_u8(n.protocol_id.to_u8());
                out.put_u64_be(n.identifier);
                encode_wrapped_descriptor(out, tlv_type::LOCAL_NODE_DESCRIPTOR, &n.local_node)?;
                encode_wrapped_descriptor(
                    out,
                    tlv_type::REMOTE_NODE_DESCRIPTOR,
                    &n.remote_node,
                )?;
                // Link Descriptor: bare TLV stream, no wrapper.
                n.link.encode_into(out)?;
            }
            BgpLsNlriVariant::Ipv4Prefix(n) | BgpLsNlriVariant::Ipv6Prefix(n) => {
                out.put_u8(n.protocol_id.to_u8());
                out.put_u64_be(n.identifier);
                encode_wrapped_descriptor(out, tlv_type::LOCAL_NODE_DESCRIPTOR, &n.local_node)?;
                // Prefix Descriptor: bare TLV stream, no wrapper.
                n.prefix.encode_into(out)?;
            }
            BgpLsNlriVariant::Unknown { bytes, .. } => {
                out.put_bytes(bytes);
            }
        }
        Ok(())
    }

    /// Decode one BGP-LS NLRI from `b`. The `is_vpn` flag toggles the
    /// 8-byte Route Distinguisher prefix (SAFI=72 → true).
    ///
    /// Returns the parsed NLRI and the number of bytes consumed.
    /// Returns `None` on any framing error (truncation, length
    /// mismatch, descriptor TLV missing).
    pub fn decode(is_vpn: bool, b: &[u8]) -> Option<(Self, usize)> {
        if b.len() < 4 {
            return None;
        }
        let nlri_type_raw = u16::from_be_bytes([b[0], b[1]]);
        let total_len = u16::from_be_bytes([b[2], b[3]]) as usize;
        if b.len() < 4 + total_len {
            return None;
        }
        let mut i = 4;
        let route_distinguisher = if is_vpn {
            if b.len() < 4 + 8 {
                return None;
            }
            let mut rd = [0u8; 8];
            rd.copy_from_slice(&b[4..12]);
            i += 8;
            Some(rd)
        } else {
            None
        };
        let value_end = 4 + total_len;
        let value = &b[i..value_end];
        let variant = decode_variant(nlri_type_raw, value)?;
        Some((
            Self {
                route_distinguisher,
                variant,
            },
            value_end,
        ))
    }
}

/// Wire length of a wrapped Node Descriptor TLV: 4-byte outer header +
/// the descriptor's value bytes.
fn wrapped_descriptor_len(d: &NodeDescriptor) -> usize {
    4 + d.value_len()
}

/// Encode a Node Descriptor as an outer wrapper TLV (type 256 or 257)
/// whose value is the descriptor's sub-TLV stream.
///
/// Uses the length-backpatch approach: write type (2 bytes) + reserve 2
/// bytes for the length, then stream the descriptor's sub-TLVs directly
/// into `out`, then backpatch the length. This is the hot-path encode
/// path: zero heap allocations beyond what the sub-TLVs themselves do.
fn encode_wrapped_descriptor(
    out: &mut WriteBuf<'_>,
    ty: u16,
    d: &NodeDescriptor,
) -> Result<(), EncodeError> {
    let value_len = d.value_len();
    if value_len > u16::MAX as usize {
        return Err(EncodeError::InvalidValue(
            "bgp-ls node descriptor sub-tlv stream > u16::MAX",
        ));
    }
    if out.remaining_mut() < 4 + value_len {
        return Err(EncodeError::BufferFull);
    }
    out.put_u16_be(ty);
    out.put_u16_be(value_len as u16);
    d.encode_value(out)?;
    Ok(())
}

fn decode_variant(nlri_type_raw: u16, value: &[u8]) -> Option<BgpLsNlriVariant> {
    let nlri_type = BgpLsNlriType::from_u16(nlri_type_raw);
    match nlri_type {
        BgpLsNlriType::Node => decode_node_nlri_value(value).map(BgpLsNlriVariant::Node),
        BgpLsNlriType::Link => decode_link_nlri_value(value).map(BgpLsNlriVariant::Link),
        BgpLsNlriType::Ipv4Prefix => decode_prefix_nlri_value(value).map(BgpLsNlriVariant::Ipv4Prefix),
        BgpLsNlriType::Ipv6Prefix => decode_prefix_nlri_value(value).map(BgpLsNlriVariant::Ipv6Prefix),
        _ => Some(BgpLsNlriVariant::Unknown {
            nlri_type,
            bytes: value.to_vec(),
        }),
    }
}

fn read_proto_id_and_id(value: &[u8]) -> Option<(ProtocolId, u64)> {
    if value.len() < 9 {
        return None;
    }
    let protocol_id = ProtocolId::from_u8(value[0]);
    let identifier = u64::from_be_bytes([
        value[1], value[2], value[3], value[4], value[5], value[6], value[7], value[8],
    ]);
    Some((protocol_id, identifier))
}

fn decode_node_nlri_value(value: &[u8]) -> Option<NodeNlri> {
    let (protocol_id, identifier) = read_proto_id_and_id(value)?;
    let body = &value[9..];
    let tlvs = decode_tlv_stream(body).ok()?;
    let mut local_node_sub: Vec<NodeDescriptorSubTlv> = Vec::new();
    for t in tlvs {
        match t.ty {
            tlv_type::LOCAL_NODE_DESCRIPTOR => {
                let nd = NodeDescriptor::decode_value(&t.value).ok()?;
                local_node_sub.extend(nd.sub_tlvs);
            }
            // Unknown outer TLV — preserved via the descriptor's
            // `Unknown` variant so a re-encode round-trips.
            _ => local_node_sub.push(NodeDescriptorSubTlv::Unknown(t)),
        }
    }
    Some(NodeNlri {
        protocol_id,
        identifier,
        local_node: NodeDescriptor::new(local_node_sub),
    })
}

fn decode_link_nlri_value(value: &[u8]) -> Option<LinkNlri> {
    let (protocol_id, identifier) = read_proto_id_and_id(value)?;
    let body = &value[9..];
    // Walk the TLV stream and partition it into Local Node Descriptor,
    // Remote Node Descriptor and Link Descriptor by outer TLV type.
    // Local Node Descriptor (256) and Remote Node Descriptor (257) are
    // wrapper TLVs; the remaining TLVs are bare Link Descriptor
    // sub-TLVs (258..=263).
    let mut local_sub: Vec<NodeDescriptorSubTlv> = Vec::new();
    let mut remote_sub: Vec<NodeDescriptorSubTlv> = Vec::new();
    let mut link_sub: Vec<LinkDescriptorSubTlv> = Vec::new();
    let tlvs = decode_tlv_stream(body).ok()?;
    for t in tlvs {
        match t.ty {
            tlv_type::LOCAL_NODE_DESCRIPTOR => {
                let nd = NodeDescriptor::decode_value(&t.value).ok()?;
                local_sub.extend(nd.sub_tlvs);
            }
            tlv_type::REMOTE_NODE_DESCRIPTOR => {
                let nd = NodeDescriptor::decode_value(&t.value).ok()?;
                remote_sub.extend(nd.sub_tlvs);
            }
            // Bare Link Descriptor sub-TLV.
            _ => link_sub.push(LinkDescriptorSubTlv::decode(t)),
        }
    }
    Some(LinkNlri {
        protocol_id,
        identifier,
        local_node: NodeDescriptor::new(local_sub),
        remote_node: NodeDescriptor::new(remote_sub),
        link: LinkDescriptor::new(link_sub),
    })
}

fn decode_prefix_nlri_value(value: &[u8]) -> Option<PrefixNlri> {
    let (protocol_id, identifier) = read_proto_id_and_id(value)?;
    let body = &value[9..];
    let tlvs = decode_tlv_stream(body).ok()?;
    let mut local_sub: Vec<NodeDescriptorSubTlv> = Vec::new();
    let mut prefix_sub: Vec<PrefixDescriptorSubTlv> = Vec::new();
    for t in tlvs {
        match t.ty {
            tlv_type::LOCAL_NODE_DESCRIPTOR => {
                let nd = NodeDescriptor::decode_value(&t.value).ok()?;
                local_sub.extend(nd.sub_tlvs);
            }
            // Bare Prefix Descriptor sub-TLV.
            _ => prefix_sub.push(PrefixDescriptorSubTlv::decode(t)),
        }
    }
    Some(PrefixNlri {
        protocol_id,
        identifier,
        local_node: NodeDescriptor::new(local_sub),
        prefix: PrefixDescriptor::new(prefix_sub),
    })
}

/// Helper: encode a fixed-length TLV (header + raw value bytes).
fn encode_fixed(out: &mut WriteBuf<'_>, ty: u16, value: &[u8]) -> Result<usize, EncodeError> {
    Tlv {
        ty,
        value: value.to_vec(),
    }
    .encode(out)
}

#[cfg(test)]
#[path = "bgp_ls_tests.rs"]
mod tests;
