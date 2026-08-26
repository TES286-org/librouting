//! Cross-crate events emitted by the router to its embedder.
//!
//! [`Event`] is intentionally small and string-friendly so that the FFI can
//! expose it without leaking Rust types.

use crate::addr::Prefix;
use crate::fsm::TimerId;
use crate::rib::{Route, RouteKey};

#[derive(Debug, Clone)]
pub enum Event {
    /// Peer / neighbor state changed. `peer_state` is a short string like
    /// `"Established"` or `"Full"` or `"2-Way"`.
    PeerStateChange {
        session: u64,
        peer_state: &'static str,
    },
    /// A route was installed into Loc-RIB.
    RouteInstalled(Route),
    /// A route was withdrawn from Loc-RIB.
    RouteWithdrawn(RouteKey),
    /// A timer fired (rare at this level — usually FSMs consume their own).
    TimerFired(TimerId),
    /// Bytes are ready to be sent on a session's transport.
    SendBytes { session: u64, bytes: Vec<u8> },
    /// A protocol error occurred on a session.
    ProtocolError { session: u64, message: String },
    /// A free-form log line (for diagnostics).
    Log(String),
    /// A prefix was advertised.
    PrefixAdvertised(Prefix),
    /// A prefix was retracted.
    PrefixRetracted(Prefix),
}
