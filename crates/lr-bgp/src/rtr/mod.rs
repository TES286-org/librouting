//! RPKI-Router protocol (RTR, RFC 8210) support.
//!
//! * [`pdu`] — the wire layer: the 11-variant PDU enum plus a
//!   framing-aware codec, validated with BIRD-parity strictness.
//! * [`client`] — the router-side state machine (§6-§8): Serial/Reset
//!   Query sequencing, session-ID/serial tracking, version
//!   negotiation (§7), and atomic ROA-table deltas per completed
//!   sync. Transport-agnostic — the embedder owns the socket, the
//!   clock and the live [`crate::roa::RoaTable`].
//!
//! The daemon wiring (TCP transport, `[bgp.rpki]` configuration,
//! hot-swapped ROA table) lives in `lr-cli` and composes the two.

pub mod client;
pub mod pdu;

pub use pdu::{
    decode, encode, encode_vec, RtrDecodeError, RtrErrorCode, RtrPdu, RtrPduType,
    RTR_FLAG_ANNOUNCE, RTR_HEADER_LEN, RTR_PDU_MAX_LEN, RTR_VERSION_0, RTR_VERSION_1,
    RTR_VERSION_2, RTR_VERSION_MAX,
};
