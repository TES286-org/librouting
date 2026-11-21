//! Babel routing protocol library (RFC 8966).
//!
//! Implements the Babel TLV codec, neighbor FSM, route table and source-specific
//! routing (RFC 9079).
//!
//! # Wire codec
//!
//! [`codec::BabelCodec`] implements [`lr_core::codec::Codec`] for
//! [`BabelFrame`] (a packet body containing a sequence of TLVs).
//!
//! # FSM
//!
//! [`neighbor::BabelNeighbor`] tracks per-neighbor history and RTO. The
//! route table lives in [`route::BabelRouteTable`] and uses the feasibility
//! condition from RFC 8966 §3.2.2.
//!
//! # Authentication
//!
//! [`auth`] implements RFC 8967 MAC authentication (HMAC-SHA-256 mandatory
//! plus keyed BLAKE2s-128) with the RFC 9467 relaxed packet-counter
//! verification. [`auth::BabelAuthInterface`] is the stateful entry point;
//! the codec-level `encode_authenticated`/`decode_authenticated_slice`
//! helpers remain for single-key embedders.

#![forbid(unsafe_code)]

pub mod auth;
pub mod codec;
pub mod message;
pub mod metric;
pub mod neighbor;
pub mod route;
pub mod route_cache;
pub mod source;
pub mod tlv;

pub use auth::{
    authenticate_packet, challenge_reply_tlv, challenge_request_tlv, verify_packet,
    BabelAuthAction, BabelAuthConfig, BabelAuthError, BabelAuthInterface, BabelMacAlgorithm,
    BabelMacKey, BabelPacketCounter, BabelPseudoHeader, BabelReplayProtection, BabelVerifyOutcome,
    CounterNonceSource, NonceSource, SystemNonceSource,
};
pub use codec::BabelCodec;
pub use message::*;
pub use neighbor::BabelNeighbor;
pub use route::{BabelRoute, BabelRouteTable, RouteKey};
pub use route_cache::{dest_of, BabelRouteCache, PeerRoute, RouteDest};
pub use source::SourcePrefix;
pub use tlv::{Tlv, TlvType};

/// Babel packet header (RFC 8966 §4.2): magic 42 (0x2A) + version 2 and a
/// 2-octet body length. Packets whose first octet is not 42 or whose second
/// octet is not 2 MUST be silently ignored.
pub const MAGIC: u8 = 0x2A;
pub const VERSION: u8 = 2;
pub const BODY_OFFSET: usize = 4;

/// RFC 8966 §4: a Babel datagram's UDP payload MUST NOT exceed 1500
/// octets. The body (everything after the 4-octet header) is therefore
/// capped at 1496 octets. Embedders building an announcement that
/// exceeds this cap must split it across multiple datagrams — see
/// [`codec::BabelCodec::pack_frames`].
pub const MAX_BODY_LENGTH: usize = 1500 - BODY_OFFSET;

/// One Babel frame = one datagram body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BabelFrame {
    pub body: Vec<Tlv>,
}

impl BabelFrame {
    pub fn new(body: Vec<Tlv>) -> Self {
        Self { body }
    }
    pub fn empty() -> Self {
        Self { body: Vec::new() }
    }
}
