//! KEEPALIVE message (RFC 4271 §4.4).
//!
//! Bodyless message; represented as a unit struct.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Keepalive;
