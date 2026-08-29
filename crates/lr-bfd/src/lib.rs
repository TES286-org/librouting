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
//! - [`packet`] — wire codec for the BFD Control packet (RFC 5880 §4.1),
//!   including the Poll/Final/Control-Plane-Independent/Auth/Demand/
//!   Multipoint flag bits and the optional Authentication Section.
//! - [`session`] — the per-session state machine. RFC 5880 §6 introduces a
//!   4-state machine: `AdminDown → Down → Init → Up` (with `AdminDown` as a
//!   forced-quiet state), with timing negotiated per RFC 5880 §6.8 and
//!   parameter changes confirmed via Poll/Final sequences (§6.5).
//! - [`auth`] — Simple Password framing plus the keyed-hash section
//!   layouts (RFC 5880 §4.2 - §4.4). Sessions support Simple Password
//!   end-to-end; digests are embedder-supplied.
//!
//! ## Usage
//!
//! 1. Allocate a [`session::BfdSession`] with the desired timing parameters.
//! 2. Push inbound datagrams via [`session::BfdSession::feed_bytes`],
//!    passing the current time so the detection timer is anchored to
//!    packet arrival.
//! 3. Drain outbound bytes via [`session::BfdSession::drain_outgoing`].
//! 4. Drive the FSM via [`session::BfdSession::tick`] with the current
//!    time so the session can detect dead-time expiry and transmit
//!    periodic control packets.
//!
//! When the session goes Up, BGP/OSPF/etc. may use the BFD state to
//! fast-detect a peer failure (in lieu of protocol-native keepalives);
//! when it goes Down, tear the protocol session down immediately.
//! The daemon (`--protocol bgp`, per-peer `bfd = true`) wires this
//! end-to-end; see `docs/examples/bfd_integration.md`.

#![forbid(unsafe_code)]

pub mod auth;
pub mod packet;
pub mod session;

pub use auth::{AuthKey, AuthSection, AuthType};
pub use packet::{BfdCodec, BfdPacket, Diagnostic, PacketFlags, State};
pub use session::{BfdConfig, BfdSession, BfdSessionEvent, SessionRole};
