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

/// LSA header (RFC 2328 §A.4.1). 20 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaHeader {
    /// Age in seconds (top 2 bits are DoNotAge per RFC 4136 — left to caller).
    pub ls_age: u16,
    pub options: u8,
    pub ls_type: u8,
    pub link_state_id: u32,
    pub advertising_router: u32,
    pub ls_sequence_number: u32,
    pub ls_checksum: u16,
    pub length: u16,
}

impl LsaHeader {
    pub const LEN: usize = 20;
}

/// Common LSA key used by the LSDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LsaKey {
    pub ls_type: u8,
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
    pub fn to_wire(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(LsaHeader::LEN + self.body.len());
        v.extend_from_slice(&self.header.ls_age.to_be_bytes());
        v.push(self.header.options);
        v.push(self.header.ls_type);
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

/// Encode the body of an OSPFv3 inter-area-prefix-LSA (RFC 5340 §A.4.5).
///
/// The body carries a single prefix with its metric:
/// - Metric (3 bytes, big-endian) — capped at `0x00ff_ffff`
/// - PrefixLength (1 byte)
/// - PrefixOptions (1 byte)
/// - Address Prefix (ceil(PL/8) bytes, zero-padded)
///
/// The link-state ID of the enclosing LSA is an arbitrary 32-bit ID
/// assigned by the ABR (RFC 5340 uses a counter, not the network
/// address, because v3 prefixes are 128 bits wide).
pub fn encode_v3_inter_area_prefix_body(prefix: &lr_core::addr::Prefix, metric: u32) -> Vec<u8> {
    let metric = metric.min(0x00ff_fffe);
    let mut v = Vec::with_capacity(5 + 16);
    // 3-byte big-endian metric
    v.extend_from_slice(&metric.to_be_bytes()[1..]);
    v.push(prefix.prefix_len);
    v.push(0); // PrefixOptions — all zero
               // Address prefix: ceil(PL/8) bytes, zero-padded to the byte boundary.
    let n = (prefix.prefix_len as usize).div_ceil(8);
    match &prefix.addr {
        lr_core::addr::IpAddr::V4(b) => {
            v.extend_from_slice(&b[..n.min(4)]);
        }
        lr_core::addr::IpAddr::V6(b) => {
            v.extend_from_slice(&b[..n.min(16)]);
        }
    }
    v
}

/// Decoded OSPFv3 inter-area-prefix-LSA body (RFC 5340 §A.4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3InterAreaPrefixBody {
    pub metric: u32,
    pub prefix_len: u8,
    pub prefix_options: u8,
    /// The address prefix, zero-padded to 16 bytes for IPv6 or 4 bytes
    /// for IPv4 (the caller matches on length).
    pub prefix_bytes: Vec<u8>,
}

/// Decode the body of an OSPFv3 inter-area-prefix-LSA. Returns `None`
/// when the body is truncated.
pub fn decode_v3_inter_area_prefix_body(body: &[u8]) -> Option<V3InterAreaPrefixBody> {
    if body.len() < 5 {
        return None;
    }
    let metric = u32::from_be_bytes([0, body[0], body[1], body[2]]);
    let prefix_len = body[3];
    let prefix_options = body[4];
    let n = (prefix_len as usize).div_ceil(8);
    if body.len() < 5 + n {
        return None;
    }
    let prefix_bytes = body[5..5 + n].to_vec();
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
            _ => return None,
        })
    }

    /// The low byte (function code) of this LSA type — the value stored
    /// in the `ls_type` field of the v3 LSA header (which is only 8 bits
    /// wide in the shared header layout, but v3 uses the options byte
    /// to carry the high byte for non-standard types).
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
