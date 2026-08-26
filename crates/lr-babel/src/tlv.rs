//! Babel TLV envelope (RFC 8966 §4.3).
//!
//! Every TLV is `(type:1, length:1, value:0..)` except `Pad1` which is a
//! single zero byte (no length, no value). Length does NOT include the
//! type+length fields themselves.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TlvType {
    Pad1 = 0,
    PadN = 1,
    AckReq = 2,
    Ack = 3,
    Hello = 4,
    Ihu = 5,
    RouterId = 6,
    NextHop = 7,
    Update = 8,
    RouteRequest = 9,
    SeqnoRequest = 10,
    /// Source-specific Hello (RFC 9079).
    SsHello = 11,
    /// Source-specific IHU (RFC 9079).
    SsIhu = 12,
    /// Source-specific Update (RFC 9079).
    SsUpdate = 13,
    /// Source-specific Route Request (RFC 9079).
    SsRouteRequest = 14,
    /// Source-specific Seqno Request (RFC 9079).
    SsSeqnoRequest = 15,
    /// Optional CRC TLV (RFC 8966 §4.5).
    TlvCrc = 16,
    Other(u8),
}

impl TlvType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Pad1,
            1 => Self::PadN,
            2 => Self::AckReq,
            3 => Self::Ack,
            4 => Self::Hello,
            5 => Self::Ihu,
            6 => Self::RouterId,
            7 => Self::NextHop,
            8 => Self::Update,
            9 => Self::RouteRequest,
            10 => Self::SeqnoRequest,
            11 => Self::SsHello,
            12 => Self::SsIhu,
            13 => Self::SsUpdate,
            14 => Self::SsRouteRequest,
            15 => Self::SsSeqnoRequest,
            16 => Self::TlvCrc,
            _ => Self::Other(v),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Pad1 => 0,
            Self::PadN => 1,
            Self::AckReq => 2,
            Self::Ack => 3,
            Self::Hello => 4,
            Self::Ihu => 5,
            Self::RouterId => 6,
            Self::NextHop => 7,
            Self::Update => 8,
            Self::RouteRequest => 9,
            Self::SeqnoRequest => 10,
            Self::SsHello => 11,
            Self::SsIhu => 12,
            Self::SsUpdate => 13,
            Self::SsRouteRequest => 14,
            Self::SsSeqnoRequest => 15,
            Self::TlvCrc => 16,
            Self::Other(v) => v,
        }
    }
}

impl fmt::Display for TlvType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TlvType({})", self.to_u8())
    }
}

/// A single TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub kind: TlvType,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(kind: TlvType, value: Vec<u8>) -> Self {
        Self { kind, value }
    }
    pub fn pad1() -> Self {
        Self {
            kind: TlvType::Pad1,
            value: Vec::new(),
        }
    }
    pub fn pad_n(n: usize) -> Self {
        Self {
            kind: TlvType::PadN,
            value: vec![0u8; n],
        }
    }
}
