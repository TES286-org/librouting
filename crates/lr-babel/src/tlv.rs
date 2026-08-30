//! Babel TLV envelope (RFC 8966 §4.3).
//!
//! Every TLV is `(type:1, length:1, value:0..)` except `Pad1` which is a
//! single zero byte (no length, no value). Length does NOT include the
//! type+length fields themselves.
//!
//! Type numbers follow the IANA "Babel TLV Types" registry (RFC 8966
//! §4.6): 0–10 are the core TLVs, 11–12 are the RFC 7298 TLVs
//! (superseded by RFC 8967), 13–15 are reserved, and 16–19 are the
//! RFC 8967 cryptographic TLVs (MAC, PC, Challenge Request, Challenge
//! Reply). RFC 9079 adds a Source Prefix **sub-TLV** (type 128) inside
//! Update / Route Request / Seqno Request TLVs — it defines no new
//! top-level TLV types.

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
    /// TS/PC TLV (RFC 7298, superseded by RFC 8967).
    TsPc = 11,
    /// HMAC TLV (RFC 7298, superseded by RFC 8967).
    Hmac = 12,
    /// MAC TLV (RFC 8967 §6.1) — lives in the packet trailer.
    Mac = 16,
    /// Packet Counter TLV (RFC 8967 §6.2).
    Pc = 17,
    /// Challenge Request TLV (RFC 8967 §6.3).
    ChallengeRequest = 18,
    /// Challenge Reply TLV (RFC 8967 §6.4).
    ChallengeReply = 19,
    /// RFC 9079 Source Prefix sub-TLV (mandatory bit 0x80 set).
    SourcePrefixSubTlv = 128,
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
            11 => Self::TsPc,
            12 => Self::Hmac,
            16 => Self::Mac,
            17 => Self::Pc,
            18 => Self::ChallengeRequest,
            19 => Self::ChallengeReply,
            128 => Self::SourcePrefixSubTlv,
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
            Self::TsPc => 11,
            Self::Hmac => 12,
            Self::Mac => 16,
            Self::Pc => 17,
            Self::ChallengeRequest => 18,
            Self::ChallengeReply => 19,
            Self::SourcePrefixSubTlv => 128,
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
