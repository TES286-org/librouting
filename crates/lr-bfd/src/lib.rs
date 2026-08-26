//! BFD — Bidirectional Forwarding Detection (RFC 5880 / 5881 / 7130 / 8562).
//!
//! BFD is a lightweight hello-protocol that detects forwarding-plane failures
//! between two adjacent routers. Compared to protocol-native hellos (BGP
//! keepalives, OSPF hellos), BFD has:
//!
//! - sub-second detection intervals (typically 50-300ms, can go lower);
//! - low CPU cost (single fixed-size 24-byte or 36-byte packet);
//! - protocol-agnostic — multiple protocols can share one BFD session.
//!
//! Architecture:
//!
//! - [`packet`] — wire codec for the BFD Control packet (RFC 5880 §4.1).
//! - [`session`] — the per-session state machine. RFC 5880 §6 introduces a
//!   4-state machine: `AdminDown → Down → Init → Up` (with `AdminDown` as a
//!   forced-quiet state).
//! - [`auth`] — keyed hash authentication (MD5 / SHA1) per RFC 5880 §4.2 -
//!   §4.4. Optional.
//!
//! ## Usage
//!
//! 1. Allocate a [`session::BfdSession`] with the desired timing parameters.
//! 2. Push inbound bytes via [`session::BfdSession::feed_bytes`].
//! 3. Drain outbound bytes via [`session::BfdSession::drain_outgoing`].
//! 4. Drive the FSM via [`session::BfdSession::tick`] with the current time
//!    so the session can detect dead-time expiry.
//!
//! When the session goes Up, BGP/OSPF/etc. may use the BFD state to fast-
//! detect a peer failure (in lieu of protocol-native keepalives).

#![forbid(unsafe_code)]

pub mod auth;
pub mod packet;
pub mod session;

pub use auth::{AuthKey, AuthSection, AuthType};
pub use packet::{BfdCodec, BfdPacket, Diagnostic, PacketFlags, State};
pub use session::{BfdConfig, BfdSession, BfdSessionEvent, SessionRole};
