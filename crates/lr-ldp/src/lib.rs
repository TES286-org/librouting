//! LDP — Label Distribution Protocol (RFC 5036).
//!
//! LDP is the signaling protocol that distributes MPLS label bindings
//! (FEC-label mappings) between LSRs, complementing the BGP-LU dataplane
//! in [`lr-mpls`]/`lr-bgp`. Peers discover each other with UDP Hellos
//! (port 646), establish a TCP session (port 646), negotiate session
//! parameters with the Initialization message, and then exchange
//! Address / Label Mapping / Label Withdraw / Label Release messages.
//!
//! Architecture (no I/O in the crate; embedders and the daemon own the
//! sockets, mirroring the `lr-bfd` engine pattern):
//!
//! - [`pdu`] — wire primitives: the 6-byte LDP Identifier, the PDU
//!   header (RFC 5036 §3.1), message and TLV headers (§3.3), and the
//!   message / TLV type registries (§3.5, §3.8).
//! - [`tlv`] — TLV value encodings: FEC (§3.4.1), Generic Label
//!   (§3.4.2.1), Address List (§3.4.3), Hop Count (§3.4.4), Path Vector
//!   (§3.4.5), Status (§3.4.6), Hello Parameters (§3.5.2), Session
//!   Parameters (§3.5.3) and the transport-address / config-sequence /
//!   request-id TLVs. RFC 7552 IPv6 transport addresses are supported.
//! - [`message`] — the eleven LDP messages and the `LdpCodec` framing
//!   (one PDU per decode, `Ok(None)` on truncation).
//! - [`session`] — the RFC 5036 §2.5.4 session initialization state
//!   machine (NON_EXISTENT → INITIALIZED → OPENREC/OPENSENT →
//!   OPERATIONAL) with KeepAlive timers and parameter negotiation.
//! - [`discovery`] — the §3.5.2.1 Hello adjacency bookkeeping (hold
//!   time negotiation, refresh and expiry, targeted-accept policy).
//! - [`mapping`] — the label information base: bindings received from
//!   and advertised to each peer.
//!
//! The engine glue that combines all of the above (and the two-speaker
//! E2E) lands in the follow-up commit of the LDP foundation slice.
//!
//! ## Usage
//!
//! 1. Build an [`LdpPdu`] with the messages to send.
//! 2. Encode with [`LdpCodec`] into an output buffer.
//! 3. Decode received bytes with [`LdpCodec`]; it returns `Ok(None)`
//!    until a complete PDU is buffered.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod discovery;
pub mod mapping;
pub mod message;
pub mod pdu;
pub mod session;
pub mod tlv;

pub use message::{LdpCodec, LdpMessage, LdpPdu, RawMessage};
pub use pdu::{
    AdvertisementMode, LdpId, MessageType, TlvType, DEFAULT_KEEPALIVE_TIME,
    DEFAULT_LINK_HELLO_HOLD, DEFAULT_MAX_PDU_LEN, DEFAULT_TARGETED_HELLO_HOLD, LDP_PORT,
    LDP_VERSION,
};
pub use session::{SessionRole, SessionState};
pub use tlv::{Fec, FecElement, GenericLabel, RawTlv, StatusCode};

/// Re-export `lr-core` address types so embedders can stay on one
/// address vocabulary when working with FECs and transport addresses.
pub use lr_core::addr::IpAddr;
