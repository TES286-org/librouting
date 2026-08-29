//! BGP-4 protocol library.
//!
//! Implements RFC 4271 (BGP-4) message codec, peer FSM, path attributes and
//! capability negotiation. Optional extensions under feature flags:
//!
//! - `asn4` (default) — RFC 4893 4-byte AS
//! - `mp_bgp` (default) — RFC 4760 multiprotocol BGP
//! - `addpath` (default) — RFC 7911 AddPath
//! - `graceful_restart` (default) — RFC 4724
//! - `enhanced_rr` (default) — RFC 7313 enhanced route refresh
//! - `extended_communities` (default) — RFC 4360
//! - `long_lived` — RFC 9494 Long-Lived Graceful Restart
//! - `labeled_unicast` (default) — RFC 8277 BGP labelled unicast (MPLS)
//!
//! # Layer 1: codec
//!
//! [`BgpCodec`] implements [`lr_core::codec::Codec`] for [`BgpMessage`]. Use
//! it standalone to parse BGP wire traffic (e.g. from a pcap).
//!
//! # Layer 2: FSM
//!
//! [`fsm::BgpPeer`] implements [`lr_core::fsm::StateMachine`] with
//! [`fsm::BgpEvent`] / [`fsm::BgpAction`]. The embedder feeds inbound bytes via
//! [`fsm::BgpPeer::feed_bytes`] and drains outbound bytes via
//! [`fsm::BgpPeer::drain_outgoing`].
//!
//! # Layer 3
//!
//! A higher-level router instance lives in `lr-router`.

#![forbid(unsafe_code)]

pub mod advertise;
pub mod best_path;
pub mod capabilities;
pub mod codec;
pub mod error;
pub mod extensions;
pub mod fsm;
pub mod message;
pub mod nlri;
pub mod path;
pub mod peer;
pub mod role;

pub use codec::BgpCodec;
pub use error::{
    BgpCeaseSubcode, BgpErrorCode, BgpHeaderErrorSubcode, BgpNotification, BgpOpenErrorSubcode,
    BgpUpdateErrorSubcode,
};
pub use fsm::{BgpAction, BgpEvent, BgpPeer, BgpState};
pub use message::{BgpHeader, BgpMessage, BgpMessageType};
pub use peer::{MaxPrefixAction, PeerConfig};
