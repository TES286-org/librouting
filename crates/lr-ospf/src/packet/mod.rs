//! OSPF versions.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OspfVersion {
    V2 = 2,
    V3 = 3,
}

impl OspfVersion {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            2 => Self::V2,
            3 => Self::V3,
            _ => return None,
        })
    }
}

/// OSPF packet header. v2 and v3 share the same 24-byte structure (v3 has
/// no Auth fields but has Instance ID + 0 in their place).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfHeader {
    pub version: u8,
    pub kind: u8,
    pub length: u16,
    pub router_id: u32,
    pub area_id: u32,
    /// v2: checksum; v3: checksum (computed with pseudo-header).
    pub checksum: u16,
    /// v2: AuType; v3: Instance ID.
    pub au_type_or_instance: u16,
    /// v2: Authentication data; v3: zero.
    pub auth_data: u64,
}

impl OspfHeader {
    pub const LEN: usize = 24;
}

/// OSPF packet type (RFC 2328 §A.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OspfPacketType {
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAck = 5,
}

impl OspfPacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Hello,
            2 => Self::DatabaseDescription,
            3 => Self::LinkStateRequest,
            4 => Self::LinkStateUpdate,
            5 => Self::LinkStateAck,
            _ => return None,
        })
    }
}

impl fmt::Display for OspfPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Hello => "Hello",
            Self::DatabaseDescription => "DBDesc",
            Self::LinkStateRequest => "LS-Request",
            Self::LinkStateUpdate => "LS-Update",
            Self::LinkStateAck => "LS-Ack",
        })
    }
}

/// Top-level OSPF packet envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfPacket {
    pub header: OspfHeader,
    pub body: OspfBody,
}

/// OSPF packet body. Each variant corresponds to one of the 5 packet types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfBody {
    Hello(HelloBody),
    DbDesc(DbDescBody),
    LsRequest(LsRequestBody),
    LsUpdate(LsUpdateBody),
    LsAck(LsAckBody),
    /// Raw bytes for unrecognized or unsupported bodies.
    Raw(Vec<u8>),
}

/// Hello packet body (RFC 2328 §A.3.2 / RFC 5340 §A.3.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloBody {
    pub network_mask: u32, // v2 only
    pub hello_interval: u16,
    pub options: u8,
    pub priority: u8,
    pub dead_interval: u32,
    pub dr: u32,
    pub bdr: u32,
    pub neighbors: Vec<u32>,
}

/// Database Description (RFC 2328 §A.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbDescBody {
    pub mtu: u16,
    pub options: u8,
    pub flags: u8, // bits: I, M, MS
    pub dd_seq: u32,
    pub lsa_headers: Vec<crate::lsa::LsaHeader>,
}

/// LS-Request entry (RFC 2328 §A.3.4): (LS type, LS ID, Adv Router).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsRequestEntry {
    pub ls_type: u8,
    pub ls_id: u32,
    pub adv_router: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsRequestBody {
    pub entries: Vec<LsRequestEntry>,
}

/// LS-Update (RFC 2328 §A.3.5): # of advertisements + list of LSAs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsUpdateBody {
    pub lsa_count: u32,
    pub lsas: Vec<crate::lsa::Lsa>,
}

/// LS-Ack (RFC 2328 §A.3.6): list of LSA headers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsAckBody {
    pub lsa_headers: Vec<crate::lsa::LsaHeader>,
}
