//! OSPF LSA model (RFC 2328 §A.4 / RFC 5340 §A.4).

use core::fmt;

use lr_core::util::fletcher;

/// Grace-LSA (RFC 3623 for v2 / RFC 5187 for v3): the Opaque-AS-LSA
/// a restarting router floods to announce its planned shutdown and
/// request that neighbours retain its LSAs for a grace period.
pub mod grace;
pub use grace::{
    is_grace_restart_capable, opaque_lsa_id, originate_grace_lsa_v2, unpack_opaque_lsa_id,
    with_grace_restart_capable, GraceLsaBody, GraceReason, GraceTlvType, OPAQUE_TYPE_GRACE,
    OPTIONS_O_BIT,
};

/// RFC 2328 §14: LSAs aged to MaxAge are flushed from the database.
pub use crate::lsdb::MAX_AGE_SECS;

/// LSA header (RFC 2328 §A.4.1 for v2, RFC 5340 §A.4.2 for v3). 20 bytes.
///
/// The two versions differ only in bytes 2-3: v2 has an 8-bit `options`
/// byte followed by an 8-bit LS type; v3 has no options byte and carries
/// the full 16-bit LS type there (e.g. `0x2003` for an inter-area-prefix
/// LSA). We store the type widened to `u16` so v3 types key correctly:
/// for v2 the value is the 8-bit type (1..=11), for v3 the full 16-bit
/// value. `options` is meaningful for v2 only and MUST be 0 for v3
/// headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaHeader {
    /// Age in seconds (top 2 bits are DoNotAge per RFC 4136 — left to caller).
    pub ls_age: u16,
    /// OSPFv2 options byte. For OSPFv3 there is no options field in the
    /// LSA header; keep this 0.
    pub options: u8,
    /// LSA type: OSPFv2 8-bit type (1..=11) or OSPFv3 full 16-bit type
    /// (e.g. 0x2003, 0x4005).
    pub ls_type: u16,
    pub link_state_id: u32,
    pub advertising_router: u32,
    pub ls_sequence_number: u32,
    pub ls_checksum: u16,
    pub length: u16,
}

impl LsaHeader {
    pub const LEN: usize = 20;
}

/// Common LSA key used by the LSDB. `ls_type` is `u16` so OSPFv3 LSAs
/// (whose types are 16-bit, e.g. 0x2003) do not collide with OSPFv2
/// types (1..=11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LsaKey {
    pub ls_type: u16,
    pub link_state_id: u32,
    pub advertising_router: u32,
}

impl From<&LsaHeader> for LsaKey {
    fn from(h: &LsaHeader) -> Self {
        Self {
            ls_type: h.ls_type,
            link_state_id: h.link_state_id,
            advertising_router: h.advertising_router,
        }
    }
}

/// LSA body. We store the body as raw bytes (parsed lazily by callers) for
/// compactness and to avoid premature type-shape commitments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsa {
    pub header: LsaHeader,
    pub body: Vec<u8>,
}

impl Lsa {
    pub fn key(&self) -> LsaKey {
        LsaKey::from(&self.header)
    }

    /// Serialized wire form: the 20-byte header followed by the body.
    /// The header fields (including `length` and `ls_checksum`) are
    /// written exactly as stored — this is a faithful serialization, not
    /// a normalizing one.
    ///
    /// Bytes 2-3 differ by version: OSPFv2 writes `[options][type]`
    /// (type is 8 bits); OSPFv3 writes the full 16-bit type. The two
    /// layouts coincide because v3 types whose high byte is zero (only
    /// the link-local Link-LSA, 0x0008) are emitted through the v2
    /// branch with `options == 0`, producing the same `[0x00][0x08]`
    /// bytes. Types above 0xff can only be OSPFv3 (v2 types are 8-bit),
    /// so the 16-bit branch is unambiguous.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(LsaHeader::LEN + self.body.len());
        v.extend_from_slice(&self.header.ls_age.to_be_bytes());
        if self.header.ls_type > 0xff {
            // OSPFv3: the 16-bit LS type occupies header bytes 2-3.
            v.extend_from_slice(&self.header.ls_type.to_be_bytes());
        } else {
            // OSPFv2 (or OSPFv3 link-local types with a zero high byte):
            // options byte followed by the low byte of the type.
            v.push(self.header.options);
            v.push(self.header.ls_type as u8);
        }
        v.extend_from_slice(&self.header.link_state_id.to_be_bytes());
        v.extend_from_slice(&self.header.advertising_router.to_be_bytes());
        v.extend_from_slice(&self.header.ls_sequence_number.to_be_bytes());
        v.extend_from_slice(&self.header.ls_checksum.to_be_bytes());
        v.extend_from_slice(&self.header.length.to_be_bytes());
        v.extend_from_slice(&self.body);
        v
    }

    /// Fix the `length` field and recompute the RFC 2328 §C.4 checksum.
    /// Call after constructing or mutating an LSA that will be flooded.
    pub fn finalize(&mut self) {
        self.header.length = (LsaHeader::LEN + self.body.len()) as u16;
        let wire = self.to_wire();
        self.header.ls_checksum = fletcher::ospf_lsa_checksum(&wire);
    }

    /// Verify the embedded RFC 2328 §C.4 checksum. Validation of received
    /// LSAs is the embedder's policy (§13); this helper makes it a one-liner.
    pub fn checksum_ok(&self) -> bool {
        let wire = self.to_wire();
        fletcher::ospf_lsa_checksum_ok(&wire)
    }

    /// Build the MaxAge instance that flushes `self` from all databases
    /// (RFC 2328 §14.1: age the LSA to MaxAge and flood). The sequence
    /// number advances so peers accept the flush as newer.
    ///
    /// Returns `None` when the sequence number cannot advance (wrapped
    /// past `MAX_SEQUENCE_NUMBER`, §12.1.2).
    pub fn maxage_flush(&self) -> Option<Lsa> {
        let seq = self.header.ls_sequence_number.checked_add(1)?;
        if seq == 0x8000_0000 {
            // Wrapped past MaxSequence into the reserved value (§12.1.2).
            return None;
        }
        let mut lsa = self.clone();
        lsa.header.ls_age = MAX_AGE_SECS;
        lsa.header.ls_sequence_number = seq;
        lsa.finalize();
        Some(lsa)
    }
}

/// Convert a dotted-quad netmask to a prefix length. Non-contiguous masks
/// count their set bits (lenient, matching common implementations).
pub fn mask_to_prefix_len(mask: u32) -> u8 {
    mask.count_ones() as u8
}

/// Convert a prefix length (0–32) to a dotted-quad netmask. Values above
/// 32 clamp to a full mask.
pub fn prefix_len_to_mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else if len >= 32 {
        u32::MAX
    } else {
        !0u32 << (32 - len)
    }
}

/// One TOS-metric entry of a summary-LSA (RFC 2328 §A.4.3). `metric` holds
/// the 24-bit metric value; the TOS byte distinguishes multiple entries
/// (TOS 0 is the one inter-area routing uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SummaryTosMetric {
    pub tos: u8,
    pub metric: u32,
}

/// Decoded summary-LSA body (RFC 2328 §A.4.3): a network mask followed by
/// one or more TOS-metric entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryLsaBody {
    pub network_mask: u32,
    pub tos_metrics: Vec<SummaryTosMetric>,
}

impl SummaryLsaBody {
    /// The TOS-0 metric — the value inter-area routing consumes. `None`
    /// when the LSA carries no usable entry.
    pub fn tos0_metric(&self) -> Option<u32> {
        self.tos_metrics
            .iter()
            .find(|m| m.tos == 0)
            .map(|m| m.metric)
    }
}

/// Encode a summary-LSA body carrying a single TOS-0 metric.
pub fn encode_summary_lsa_body(network_mask: u32, metric: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&network_mask.to_be_bytes());
    v.push(0); // TOS 0
    v.extend_from_slice(&metric.to_be_bytes()[1..]); // 24-bit metric
    v
}

// ---------------------------------------------------------------------------
// OSPFv3 inter-area-prefix-LSA (RFC 5340 §A.4.5)
// ---------------------------------------------------------------------------

/// OSPFv3 prefix options (RFC 5340 §A.4.1.1). Currently all zero — the
/// library does not set P/V/LA/NU bits; the embedder can OR them in
/// after encoding if needed.
pub type V3PrefixOptions = u8;

/// RFC 7684 §3: PrefixOptions bit definitions. These are the bits
/// inside [`V3PrefixOptions`] (the one-byte prefix-options field that
/// precedes every OSPFv3 prefix in inter-area-prefix, intra-area-
/// prefix, AS-external, NSSA, link-LSA and the new RFC 7684
/// prefix-link-local LSA bodies).
pub mod v3_prefix_options {
    /// Propagate (P) bit — RFC 5340 §A.4.1.1. Set on NSSA external
    /// prefixes that should be translated to AS-external by the
    /// border router (RFC 3101 §2.4).
    pub const P_BIT: u8 = 0x08;
    /// Multicast (MC) bit — RFC 5340 §A.4.1.1. Set when the prefix
    /// should be included in the multicast topology calculation.
    pub const MC_BIT: u8 = 0x04;
    /// Local Address (LA) bit — RFC 5340 §A.4.1.1, clarified by RFC
    /// 7684 §3. Set when the prefix is a local interface address
    /// (the router should install it on an interface, not just route
    /// to it).
    pub const LA_BIT: u8 = 0x02;
    /// No Unicast (NU) bit — RFC 5340 §A.4.1.1. Set when the prefix
    /// should be excluded from the unicast routing calculation.
    pub const NU_BIT: u8 = 0x01;
    /// Address Family (Af) bit — RFC 7684 §3. Set when the prefix
    /// belongs to an address family other than IPv6 unicast (the
    /// default). The Af-bit + a one-byte Address Family ID in the
    /// prefix body extends the prefix to carry non-IPv6-unicast
    /// prefixes.
    pub const AF_BIT: u8 = 0x80;
    /// Route (R) bit — RFC 7684 §3. Set when the prefix should be
    /// included in the routing calculation even when the NU-bit is
    /// also set (the prefix carries reachability info for a specific
    /// purpose, e.g. multicast RPF).
    pub const R_BIT: u8 = 0x10;
    /// All known prefix-option bits (for masking / display).
    pub const ALL_KNOWN: u8 = P_BIT | MC_BIT | LA_BIT | NU_BIT | AF_BIT | R_BIT;
}

/// Encode the body of an OSPFv3 inter-area-prefix-LSA (RFC 5340 §A.4.5).
///
/// The body carries a single prefix with its metric. RFC 5340 §A.4.5:
///
/// ```text
///   0                   1                   2                   3
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |      0        |                  Metric                       |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | PrefixLength  | PrefixOptions |              0                |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                        Address Prefix                         |
/// ```
///
/// - byte 0: reserved, 0
/// - bytes 1-3: 24-bit big-endian metric — capped just below LSInfinity
///   (`0x00ff_ffff`), the reserved "unreachable" value
/// - byte 4: PrefixLength
/// - byte 5: PrefixOptions (0)
/// - bytes 6-7: reserved, 0
/// - bytes 8+: Address Prefix — ceil(PL/8) bytes zero-padded to a 32-bit
///   boundary (RFC 5340 §4.4.3.4: "The prefix is padded out to an even
///   number of 32-bit words"; §A.4.1: `((PL + 31) / 32)` words).
///
/// The link-state ID of the enclosing LSA is an arbitrary 32-bit ID
/// assigned by the ABR (RFC 5340 uses a counter, not the network
/// address, because v3 prefixes are 128 bits wide).
pub fn encode_v3_inter_area_prefix_body(prefix: &lr_core::addr::Prefix, metric: u32) -> Vec<u8> {
    let metric = metric.min(0x00ff_fffe);
    let mut v = Vec::with_capacity(8 + 16);
    // 4-byte metric word with a zero reserved top byte (24-bit metric).
    v.push(0);
    v.extend_from_slice(&metric.to_be_bytes()[1..]);
    v.push(prefix.prefix_len);
    v.push(0); // PrefixOptions — all zero
    v.extend_from_slice(&0u16.to_be_bytes()); // reserved
                                              // Address prefix: ceil(PL/8) bytes, zero-padded to a 32-bit boundary.
    let n = (prefix.prefix_len as usize).div_ceil(8);
    let padded = n.next_multiple_of(4);
    match &prefix.addr {
        lr_core::addr::IpAddr::V4(b) => {
            v.extend_from_slice(&b[..n.min(4)]);
        }
        lr_core::addr::IpAddr::V6(b) => {
            v.extend_from_slice(&b[..n.min(16)]);
        }
    }
    v.resize(v.len() + (padded - n), 0);
    v
}

/// Decoded OSPFv3 inter-area-prefix-LSA body (RFC 5340 §A.4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3InterAreaPrefixBody {
    pub metric: u32,
    pub prefix_len: u8,
    pub prefix_options: u8,
    /// The address prefix, ceil(PL/8) bytes (the trailing 32-bit padding
    /// on the wire is not stored).
    pub prefix_bytes: Vec<u8>,
}

/// Decode the body of an OSPFv3 inter-area-prefix-LSA. Returns `None`
/// when the body is truncated.
pub fn decode_v3_inter_area_prefix_body(body: &[u8]) -> Option<V3InterAreaPrefixBody> {
    if body.len() < 8 {
        return None;
    }
    let metric = u32::from_be_bytes([0, body[1], body[2], body[3]]);
    let prefix_len = body[4];
    let prefix_options = body[5];
    let n = (prefix_len as usize).div_ceil(8);
    let padded = n.next_multiple_of(4);
    if body.len() < 8 + padded {
        return None;
    }
    let prefix_bytes = body[8..8 + n].to_vec();
    Some(V3InterAreaPrefixBody {
        metric,
        prefix_len,
        prefix_options,
        prefix_bytes,
    })
}

impl V3InterAreaPrefixBody {
    /// Reconstruct the prefix as an `IpAddr`. OSPFv3 carries IPv6
    /// prefixes (16 bytes); IPv4-mapped prefixes are decoded as IPv6
    /// (the caller can detect `::ffff:x.x.x.x` if needed).
    pub fn to_prefix(&self) -> Option<lr_core::addr::Prefix> {
        let mut bytes = [0u8; 16];
        let n = self.prefix_bytes.len().min(16);
        bytes[..n].copy_from_slice(&self.prefix_bytes[..n]);
        Some(lr_core::addr::Prefix::new_v6(bytes, self.prefix_len))
    }
}

/// Decode a summary-LSA body. Returns `None` when the body is truncated
/// or shorter than the mandatory mask + first TOS-0 entry.
pub fn decode_summary_lsa_body(body: &[u8]) -> Option<SummaryLsaBody> {
    if body.len() < 8 || !(body.len() - 4).is_multiple_of(4) {
        return None;
    }
    let network_mask = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let mut tos_metrics = Vec::new();
    let mut i = 4;
    while i + 4 <= body.len() {
        let tos = body[i];
        let metric = u32::from_be_bytes([0, body[i + 1], body[i + 2], body[i + 3]]);
        tos_metrics.push(SummaryTosMetric { tos, metric });
        i += 4;
    }
    Some(SummaryLsaBody {
        network_mask,
        tos_metrics,
    })
}

/// Well-known LSA types (RFC 2328 §A.4 for v2; RFC 5340 §A.4 for v3 uses
/// a different numbering).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LsaTypeV2 {
    RouterLsa = 1,
    NetworkLsa = 2,
    SummaryIpLsa = 3,
    SummaryAsbrLsa = 4,
    AsExternalLsa = 5,
    NssaExternalLsa = 7,
    OpaqueLinkLsa = 9,
    OpaqueAreaLsa = 10,
    OpaqueAsLsa = 11,
}

impl LsaTypeV2 {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::RouterLsa,
            2 => Self::NetworkLsa,
            3 => Self::SummaryIpLsa,
            4 => Self::SummaryAsbrLsa,
            5 => Self::AsExternalLsa,
            7 => Self::NssaExternalLsa,
            9 => Self::OpaqueLinkLsa,
            10 => Self::OpaqueAreaLsa,
            11 => Self::OpaqueAsLsa,
            _ => return None,
        })
    }
}

/// OSPFv3 LSA types (RFC 5340 §A.4). The high byte carries the function
/// code; the low byte carries the LSA scope (1=link, 2=area, 3=AS) and
/// the U-bit (0x08).
///
/// In the wire format, v3 LSA types are 16 bits wide but only the low
/// byte carries the function code (the high byte is zero for the
/// standard types). We store them as `u16` so callers can match on the
/// full 0x2003-style values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LsaTypeV3 {
    /// Router-LSA (scope: area). RFC 5340 §A.4.3.
    RouterLsa = 0x2001,
    /// Network-LSA (scope: area). RFC 5340 §A.4.4.
    NetworkLsa = 0x2002,
    /// Inter-Area-Prefix-LSA (scope: area). RFC 5340 §A.4.5.
    /// Equivalent to OSPFv2 type-3 summary-LSA.
    InterAreaPrefixLsa = 0x2003,
    /// Inter-Area-Router-LSA (scope: area). RFC 5340 §A.4.6.
    /// Equivalent to OSPFv2 type-4 summary-ASBR-LSA.
    InterAreaRouterLsa = 0x2004,
    /// AS-External-LSA (scope: AS). RFC 5340 §A.4.7.
    AsExternalLsa = 0x4005,
    /// NSSA-LSA (scope: area). RFC 3101 / RFC 5340.
    NssaLsa = 0x2007,
    /// Link-LSA (scope: link). RFC 5340 §A.4.9.
    LinkLsa = 0x0008,
    /// Intra-Area-Prefix-LSA (scope: area). RFC 5340 §A.4.10.
    IntraAreaPrefixLsa = 0x2009,
    /// OSPFv3 Prefix Link-Local Attributes LSA (scope: AS, function 4).
    /// RFC 7684 §2.1 — carries the link-local address prefix options
    /// (LA bit, Af bit) for inter-area and external prefixes that need
    /// to carry link-local attributes across the AS. The U-bit is 0
    /// (peers that do not recognise the type flood it as if it were
    /// an AS-External-LSA).
    PrefixLinkLocalAsLsa = 0x4004,
}

impl LsaTypeV3 {
    /// Parse a 16-bit LSA type from the wire. Returns `None` for
    /// unrecognized values.
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x2001 => Self::RouterLsa,
            0x2002 => Self::NetworkLsa,
            0x2003 => Self::InterAreaPrefixLsa,
            0x2004 => Self::InterAreaRouterLsa,
            0x4005 => Self::AsExternalLsa,
            0x2007 => Self::NssaLsa,
            0x0008 => Self::LinkLsa,
            0x2009 => Self::IntraAreaPrefixLsa,
            0x4004 => Self::PrefixLinkLocalAsLsa,
            _ => return None,
        })
    }

    /// The low byte (function code) of this 16-bit v3 LSA type. Retained
    /// for callers that only need the function code; the full 16-bit
    /// value (e.g. `0x2003`) is what `LsaHeader::ls_type` carries and
    /// what the wire format uses.
    pub fn function_code(self) -> u8 {
        (self as u16) as u8
    }
}

impl fmt::Display for LsaTypeV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RouterLsa => "Router-LSA(v3)",
            Self::NetworkLsa => "Network-LSA(v3)",
            Self::InterAreaPrefixLsa => "InterArea-Prefix-LSA",
            Self::InterAreaRouterLsa => "InterArea-Router-LSA",
            Self::AsExternalLsa => "AS-External-LSA(v3)",
            Self::NssaLsa => "NSSA-LSA(v3)",
            Self::LinkLsa => "Link-LSA",
            Self::IntraAreaPrefixLsa => "IntraArea-Prefix-LSA",
            Self::PrefixLinkLocalAsLsa => "Prefix-LinkLocal-AS-LSA",
        })
    }
}

/// Router-LSA flags bits (RFC 2328 §A.4.2 diagram; Nt from RFC 3101
/// Appendix B): the flags word is the first 16 bits of the body —
/// `| 0 | Nt | W | V | E | B | 0 |` in the high byte.
pub mod router_lsa_flags {
    /// B-bit: the router is an area border router.
    pub const B: u8 = 0x01;
    /// E-bit: the router is an AS boundary router.
    pub const E: u8 = 0x02;
    /// V-bit: the router is an endpoint of an active virtual link.
    pub const V: u8 = 0x04;
    /// Nt-bit (RFC 3101 Appendix B): the NSSA border router is an
    /// unconditional type-7 translator.
    pub const NT: u8 = 0x10;
}

/// Extract the router-LSA flags byte (RFC 2328 §A.4.2) from a body.
/// Returns `None` for truncated bodies.
pub fn router_lsa_flags_byte(body: &[u8]) -> Option<u8> {
    body.first().copied()
}

/// Router-LSA link types (RFC 2328 §A.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RouterLinkType {
    PointToPoint = 1,
    TransitNetwork = 2,
    StubNetwork = 3,
    VirtualLink = 4,
}

impl RouterLinkType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::PointToPoint,
            2 => Self::TransitNetwork,
            3 => Self::StubNetwork,
            4 => Self::VirtualLink,
            _ => return None,
        })
    }
}

/// One router-LSA link description (RFC 2328 §A.4.2): 12 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterLink {
    pub link_id: u32,
    pub link_data: u32,
    pub link_type: u8,
    pub tos: u8,
    pub metric: u16,
}

/// AS-external LSA entry (RFC 2328 §A.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsExternalEntry {
    pub network_mask: u32,
    pub metric: u32, // top bit is E-bit; 24-bit metric
    pub forwarding_addr: u32,
    pub route_tag: u32,
}

impl AsExternalEntry {
    /// E bit (external metric type 2) per RFC 2328 §2.3.
    pub fn external_type2(&self) -> bool {
        (self.metric & 0x8000_0000) != 0
    }

    pub fn metric_value(&self) -> u32 {
        self.metric & 0x00ff_ffff
    }
}

/// Encode an AS-external LSA body (RFC 2328 §A.4.5): network mask, the
/// E-bit + 24-bit metric packed into one word, forwarding address and
/// external route tag. Always 16 bytes.
pub fn encode_as_external_body(entry: &AsExternalEntry) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&entry.network_mask.to_be_bytes());
    v.extend_from_slice(&(entry.metric & 0x80ff_ffff).to_be_bytes());
    v.extend_from_slice(&entry.forwarding_addr.to_be_bytes());
    v.extend_from_slice(&entry.route_tag.to_be_bytes());
    v
}

/// Decode an AS-external LSA body (RFC 2328 §A.4.5). Returns `None` when
/// the body is not exactly 16 bytes. The E-bit and metric are kept packed
/// in [`AsExternalEntry::metric`] exactly as they appear on the wire.
pub fn decode_as_external_body(body: &[u8]) -> Option<AsExternalEntry> {
    if body.len() != 16 {
        return None;
    }
    Some(AsExternalEntry {
        network_mask: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
        metric: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
        forwarding_addr: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
        route_tag: u32::from_be_bytes([body[12], body[13], body[14], body[15]]),
    })
}

impl fmt::Display for LsaTypeV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RouterLsa => "Router-LSA",
            Self::NetworkLsa => "Network-LSA",
            Self::SummaryIpLsa => "Summary-IP-LSA",
            Self::SummaryAsbrLsa => "Summary-ASBR-LSA",
            Self::AsExternalLsa => "AS-External-LSA",
            Self::NssaExternalLsa => "NSSA-External-LSA",
            Self::OpaqueLinkLsa => "Opaque-Link-LSA",
            Self::OpaqueAreaLsa => "Opaque-Area-LSA",
            Self::OpaqueAsLsa => "Opaque-AS-LSA",
        })
    }
}

// ---------------------------------------------------------------------------
// OSPFv3 Prefix Link-Local Attributes LSA (RFC 7684)
// ---------------------------------------------------------------------------

/// One prefix entry inside a RFC 7684 prefix-link-local LSA body. The
/// `prefix_options` byte carries the [`v3_prefix_options`] bits
/// (including the RFC 7684 Af and R bits). When the Af-bit is set an
/// extra one-byte Address Family ID follows the prefix options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3PrefixLinkLocalEntry {
    pub prefix_len: u8,
    pub prefix_options: u8,
    /// Address Family ID — only present when the Af-bit is set in
    /// `prefix_options`. Stored as `Option<u8>` so the codec emits
    /// the byte only when the Af-bit is on, matching the wire format.
    pub address_family_id: Option<u8>,
    /// The address prefix, ceil(PL/8) bytes, zero-padded to the byte
    /// boundary.
    pub prefix_bytes: Vec<u8>,
}

/// Encode a single RFC 7684 prefix entry: `<prefix_len:1>
/// <prefix_options:1> [<af_id:1> when Af-bit set] <prefix:N>`.
pub fn encode_v3_prefix_link_local_entry(entry: &V3PrefixLinkLocalEntry) -> Vec<u8> {
    let n = (entry.prefix_len as usize).div_ceil(8);
    let af = (entry.prefix_options & v3_prefix_options::AF_BIT) != 0;
    let mut v = Vec::with_capacity(2 + (af as usize) + n);
    v.push(entry.prefix_len);
    v.push(entry.prefix_options);
    if af {
        v.push(entry.address_family_id.unwrap_or(0));
    }
    v.extend_from_slice(&entry.prefix_bytes[..n.min(entry.prefix_bytes.len())]);
    v
}

/// Decode a single RFC 7684 prefix entry from `body` starting at
/// `offset`. Returns `(entry, next_offset)` on success, or `None`
/// when the body is truncated.
pub fn decode_v3_prefix_link_local_entry(
    body: &[u8],
    offset: usize,
) -> Option<(V3PrefixLinkLocalEntry, usize)> {
    if offset + 2 > body.len() {
        return None;
    }
    let prefix_len = body[offset];
    let prefix_options = body[offset + 1];
    let af = (prefix_options & v3_prefix_options::AF_BIT) != 0;
    let mut i = offset + 2;
    let address_family_id = if af {
        if i >= body.len() {
            return None;
        }
        let id = body[i];
        i += 1;
        Some(id)
    } else {
        None
    };
    let n = (prefix_len as usize).div_ceil(8);
    if i + n > body.len() {
        return None;
    }
    let prefix_bytes = body[i..i + n].to_vec();
    Some((
        V3PrefixLinkLocalEntry {
            prefix_len,
            prefix_options,
            address_family_id,
            prefix_bytes,
        },
        i + n,
    ))
}

/// Encode the body of an OSPFv3 prefix-link-local LSA (RFC 7684 §2).
/// The body is a sequence of prefix entries. Callers that need a
/// single prefix can pass a one-element slice.
pub fn encode_v3_prefix_link_local_body(entries: &[V3PrefixLinkLocalEntry]) -> Vec<u8> {
    let mut v = Vec::new();
    for e in entries {
        v.extend_from_slice(&encode_v3_prefix_link_local_entry(e));
    }
    v
}

/// Decode the body of an OSPFv3 prefix-link-local LSA (RFC 7684 §2).
/// Walks the prefix entries until the body is exhausted. Returns
/// `None` when a prefix entry is truncated.
pub fn decode_v3_prefix_link_local_body(body: &[u8]) -> Option<Vec<V3PrefixLinkLocalEntry>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let (entry, next) = decode_v3_prefix_link_local_entry(body, i)?;
        out.push(entry);
        i = next;
    }
    Some(out)
}

#[cfg(test)]
mod v3_prefix_link_local_tests {
    use super::*;

    #[test]
    fn prefix_options_bits_defined() {
        // RFC 5340 §A.4.1.1 bits.
        assert_eq!(v3_prefix_options::P_BIT, 0x08);
        assert_eq!(v3_prefix_options::MC_BIT, 0x04);
        assert_eq!(v3_prefix_options::LA_BIT, 0x02);
        assert_eq!(v3_prefix_options::NU_BIT, 0x01);
        // RFC 7684 §3 new bits.
        assert_eq!(v3_prefix_options::AF_BIT, 0x80);
        assert_eq!(v3_prefix_options::R_BIT, 0x10);
    }

    #[test]
    fn prefix_entry_roundtrip_basic() {
        let entry = V3PrefixLinkLocalEntry {
            prefix_len: 64,
            prefix_options: v3_prefix_options::LA_BIT,
            address_family_id: None,
            prefix_bytes: vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0],
        };
        let wire = encode_v3_prefix_link_local_entry(&entry);
        let (dec, next) = decode_v3_prefix_link_local_entry(&wire, 0).expect("decode");
        assert_eq!(dec, entry);
        assert_eq!(next, wire.len());
    }

    #[test]
    fn prefix_entry_roundtrip_with_af_bit() {
        // Af-bit set → a one-byte Address Family ID follows the
        // prefix options byte.
        let entry = V3PrefixLinkLocalEntry {
            prefix_len: 48,
            prefix_options: v3_prefix_options::AF_BIT | v3_prefix_options::LA_BIT,
            address_family_id: Some(1), // IPv4
            prefix_bytes: vec![0xfe, 0x80, 0, 0, 0, 0],
        };
        let wire = encode_v3_prefix_link_local_entry(&entry);
        assert_eq!(
            wire.len(),
            2 + 1 + 6, // prefix_len + prefix_options + af_id + 6 bytes
            "Af-bit adds one byte after prefix_options"
        );
        let (dec, next) = decode_v3_prefix_link_local_entry(&wire, 0).expect("decode");
        assert_eq!(dec, entry);
        assert_eq!(next, wire.len());
    }

    #[test]
    fn prefix_entry_roundtrip_no_af_bit_omits_af_id() {
        // Af-bit clear → no Address Family ID byte on the wire.
        let entry = V3PrefixLinkLocalEntry {
            prefix_len: 128,
            prefix_options: v3_prefix_options::LA_BIT | v3_prefix_options::NU_BIT,
            address_family_id: None,
            prefix_bytes: (0..16).collect(),
        };
        let wire = encode_v3_prefix_link_local_entry(&entry);
        assert_eq!(wire.len(), 2 + 16, "no Af-bit means no af_id byte");
        let (dec, _) = decode_v3_prefix_link_local_entry(&wire, 0).expect("decode");
        assert_eq!(dec, entry);
    }

    #[test]
    fn prefix_body_roundtrip_multi_entry() {
        let entries = vec![
            V3PrefixLinkLocalEntry {
                prefix_len: 64,
                prefix_options: v3_prefix_options::LA_BIT,
                address_family_id: None,
                prefix_bytes: vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0],
            },
            V3PrefixLinkLocalEntry {
                prefix_len: 128,
                prefix_options: v3_prefix_options::LA_BIT | v3_prefix_options::NU_BIT,
                address_family_id: None,
                prefix_bytes: (0..16).collect(),
            },
            V3PrefixLinkLocalEntry {
                prefix_len: 0,
                prefix_options: 0,
                address_family_id: None,
                prefix_bytes: vec![],
            },
        ];
        let body = encode_v3_prefix_link_local_body(&entries);
        let dec = decode_v3_prefix_link_local_body(&body).expect("decode");
        assert_eq!(dec, entries);
    }

    #[test]
    fn prefix_body_decode_truncated_returns_none() {
        // Truncated at the prefix-options byte.
        assert!(decode_v3_prefix_link_local_entry(&[64], 0).is_none());
        // Truncated in the middle of the prefix bytes.
        let wire = vec![64, v3_prefix_options::LA_BIT]; // prefix_len=64 → 8 bytes, but body has 0
        assert!(decode_v3_prefix_link_local_entry(&wire, 0).is_none());
        // Af-bit set but no af_id byte.
        let wire = vec![64, v3_prefix_options::AF_BIT];
        assert!(decode_v3_prefix_link_local_entry(&wire, 0).is_none());
    }

    #[test]
    fn prefix_body_decode_empty_body() {
        // An empty body decodes to an empty entry list (no prefixes).
        let dec = decode_v3_prefix_link_local_body(&[]).expect("empty body");
        assert!(dec.is_empty());
    }

    #[test]
    fn new_lsa_type_parses_and_displays() {
        let t = LsaTypeV3::from_u16(0x4004).expect("RFC 7684 LSA type");
        assert_eq!(t, LsaTypeV3::PrefixLinkLocalAsLsa);
        assert_eq!(t.function_code(), 0x04);
        assert_eq!(t.to_string(), "Prefix-LinkLocal-AS-LSA");
        // Unknown 16-bit value → None.
        assert!(LsaTypeV3::from_u16(0x9999).is_none());
    }
}
