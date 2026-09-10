//! SRv6 data-plane primitives — Segment Routing over IPv6.
//!
//! This crate provides the wire-level primitives every SRv6-aware
//! protocol in librouting needs:
//!
//! - [`Sid`] — a 128-bit SRv6 Segment Identifier (RFC 8754 §3, RFC
//!   8402 §3.2.1). A SID is an IPv6 address split into LOC:FUNCT:ARGS;
//!   the [`locator`] module models the prefix part.
//! - [`Locator`] — an IPv6 prefix owned by a node, advertised by the
//!   IGP so packets destined for any SID under the locator route to
//!   that node (RFC 8754 §3.1).
//! - [`Srh`] — the IPv6 Segment Routing Header codec (RFC 8754 §2).
//!   Encodes/decodes the full wire format: Next Header, Hdr Ext Len,
//!   Routing Type (43), Segments Left, Last Entry, Flags, Tag, the
//!   segment list, and optional TLV bytes.
//! - [`Behavior`] — the RFC 8986 endpoint behavior registry (End,
//!   End.X, End.DX6, End.DT4, End.B6.Encaps.Red, etc.) with the
//!   exact 16-bit IANA wire values.
//!
//! The crate has no I/O, no clock and no platform dependency — it is
//! `no_std`-compatible and shares the `lr-core` conventions (mirrors
//! how `lr-mpls` sits next to the protocol crates).
//!
//! ## Slice 1 scope
//!
//! This is the first SRv6 slice. It delivers the data-plane codec
//! and the type system. Slice 2 (future) will add the control-plane
//! extensions — OSPFv3 SRv6 (RFC 9352), BGP-LS SRv6, BGP SR Policy
//! (RFC 9256 / 9430) — riding on this codec. Slice 3 (future) will
//! add the daemon's `--srv6-locator` / `--srv6-endpoint` CLI and the
//! kernel `seg6`/`seg6local` route mirror in `lr-osroute`.
//!
//! ## Wire layout (RFC 8754 §2)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Next Header   | Hdr Ext Len   | Routing Type  | Segments Left |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Last Entry    |    Flags      |           Tag                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List[0] (16 octets, DA at send)            |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                              ...                              |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod behavior;
pub mod locator;
pub mod sid;
pub mod srh;

pub use behavior::Behavior;
pub use locator::{Locator, LocatorParseError};
pub use sid::{Sid, SidParseError};
pub use srh::{
    Srh, SrhError, FLAG_HMAC as SRH_FLAG_HMAC, FLAG_OAM as SRH_FLAG_OAM,
    MAX_SEGMENTS as SRH_MAX_SEGMENTS, ROUTING_TYPE_SRH as SRH_ROUTING_TYPE, SRH_FIXED_LEN,
    SRH_SEGMENT_LEN,
};
