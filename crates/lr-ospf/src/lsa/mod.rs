//! OSPF LSA model (RFC 2328 §A.4 / RFC 5340 §A.4).

use core::fmt;

use lr_core::util::fletcher;

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
    if len >= 32 {
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
