//! OSPF LSA model (RFC 2328 §A.4 / RFC 5340 §A.4).

use core::fmt;

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
