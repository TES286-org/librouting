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

#![forbid(unsafe_code)]

pub mod codec;
pub mod message;
pub mod metric;
pub mod neighbor;
pub mod route;
pub mod source;
pub mod tlv;

pub use codec::BabelCodec;
pub use message::*;
pub use neighbor::BabelNeighbor;
pub use route::{BabelRoute, BabelRouteTable, RouteKey};
pub use source::SourcePrefix;
pub use tlv::{Tlv, TlvType};

/// Babel magic + version header (RFC 8966 §4.1): 0x20 + 0x2 and a body of
/// TLVs. The body may include a CRC TLV at the end (CRC-32C).
pub const MAGIC: u8 = 0x20;
pub const VERSION: u8 = 2;
pub const BODY_OFFSET: usize = 4;

/// One Babel frame = one datagram body.
#[derive(Debug, Clone, PartialEq, Eq)]
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
