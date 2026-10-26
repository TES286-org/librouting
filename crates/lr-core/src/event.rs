//! Cross-crate events emitted by the router to its embedder.
//!
//! [`Event`] is intentionally small and string-friendly so that the FFI can
//! expose it without leaking Rust types.

use crate::addr::Prefix;
use crate::fsm::TimerId;
use crate::nlri::NlriFamily;
use crate::rib::{Route, RouteKey};
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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
    /// A negotiated peer requested that this family be re-advertised
    /// (BGP ROUTE-REFRESH, RFC 2918 §2). Surfaced when a BGP FSM
    /// running under the generic [`crate::fsm::StateMachine`] trait
    /// adapter emits [`lr_bgp::fsm::BgpAction::RouteRefreshRequested`];
    /// router-aware embedders that consume `BgpAction` directly (the
    /// daemon) handle the action through that path and never see this
    /// event. The trait-only adapter maps `BgpAction::RouteRefreshRequested`
    /// here so a trait-only embedder can react to the request — previously
    /// it was silently dropped to `Action::None`, masking the signal.
    RouteRefreshRequested { session: u64, family: NlriFamily },
    /// End-of-RIB marker received for an address family (RFC 4724 §4
    /// for BGP graceful restart). Emitted for an empty UPDATE
    /// (IPv4 unicast) or an UPDATE whose only content is an empty
    /// MP_UNREACH_NLRI (other families). Surfaced when a BGP FSM
    /// running under the generic [`crate::fsm::StateMachine`] trait
    /// adapter emits [`lr_bgp::fsm::BgpAction::EndOfRib`]; router-aware
    /// embedders that consume `BgpAction` directly (the daemon) handle
    /// the action through that path and never see this event. The
    /// trait-only adapter maps `BgpAction::EndOfRib` here so a
    /// trait-only embedder can react to the marker — previously it
    /// was silently dropped to `Action::None`, masking the signal.
    EndOfRib { session: u64, family: NlriFamily },
}
