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

/// Router event surfaced to the embedder.
///
/// `#[non_exhaustive]` allows new event variants (e.g.
/// `RouteRefreshRequested`, `EndOfRib`, `OspfNeighborReset`) to land
/// on `main` between releases without forcing every `match Event { … }`
/// site to grow a new arm at every minor. Embedders that exhaustively
/// match must add a `_ => {}` arm to stay source-compatible.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// An OSPF neighbour was reset by an unrecoverable FSM event
    /// (RFC 2328 §10.6 / §10.9 / §13.7). Surfaced by the OSPF
    /// neighbour FSM in [`lr_ospf::neighbor`] when one of the three
    /// "hard reset" events fires (`Kill`, `SeqMismatch`, `BadLsa`);
    /// the router instance (`lr_router::DefaultRouter`) consumes
    /// the event to record the cause into the session's
    /// [`lr_router::session::SessionStats::last_error`] using the
    /// dedicated [`SessionErrorKind::OspfKill`] /
    /// [`SessionErrorKind::OspfSeqMismatch`] /
    /// [`SessionErrorKind::OspfBadLsa`] variants, so `show
    /// sessions` / `lrctl session <h>` reports the RFC 2328 reason
    /// rather than the generic `Other` the previous fall-through
    /// produced. The FSM does not know its session handle; the
    /// router substitutes the live handle when surfacing the event
    /// (matching `Event::PeerStateChange`).
    ///
    /// The previous shape of this signal was a free-form
    /// [`Event::Log`] line whose text varied per reset kind; an
    /// embedder that wanted to count or classify OSPF resets had to
    /// parse the log string. The structured variant lets embedders
    /// (and the daemon's session-stats surface) react to the cause
    /// directly. The router still synthesises a `RouterEvent::Log`
    /// line for backwards compatibility with embedders that consumed
    /// the log message — the operator-visible log stream is
    /// unchanged.
    OspfNeighborReset {
        /// The advertising router's OSPF Router ID (the LSA header
        /// field the FSM keys on, RFC 2328 §A.3.1).
        router_id: u32,
        /// Which RFC 2328 reset kind fired.
        kind: OspfNeighborResetKind,
    },
}

/// The cause of an OSPF neighbour reset (RFC 2328 §10.6 / §10.9 /
/// §13.7). Surfaced through [`Event::OspfNeighborReset`]; mapped to
/// the matching [`SessionErrorKind`] (lr_router) variant by the
/// router instance.
///
/// `#[non_exhaustive]` allows new variants (e.g. for OSPFv3-specific
/// reset causes) to land on `main` between releases without forcing
/// every `match OspfNeighborResetKind { … }` site to grow a new arm
/// at every minor. Embedders that exhaustively match must add a
/// `_ => {}` arm to stay source-compatible.
///
/// [`SessionErrorKind`]: lr_router::session::SessionErrorKind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum OspfNeighborResetKind {
    /// RFC 2328 §10.6 / §10.1 — adjacency killed (inactivity timer
    /// expiry, Hello parameter mismatch, manual reset). The OSPF
    /// equivalent of BGP `NotificationReceived`: the peer was
    /// reachable but the adjacency cannot come up because of a
    /// mismatch the FSM does not recover from. The neighbour
    /// returns to `Down`.
    Kill = 0,
    /// RFC 2328 §10.9 / Fig. 12 — DBD sequence mismatch in the
    /// exchange states. The exchange FSM restarts the adjacency
    /// negotiation from `ExStart`; the neighbour stays alive. The
    /// restart counter lives in
    /// [`SessionStats::state_transitions`](lr_router::session::SessionStats);
    /// `last_error` records the most recent mismatch rather than
    /// counting every restart.
    SeqMismatch = 1,
    /// RFC 2328 §13.7 / §A.3 — a malformed or inconsistent LSA was
    /// received in an LS-Update or LS-Request (Bad LSA event). The
    /// peer is reset; the offending LSA is dropped from the LSDB
    /// and the adjacency re-floods from `ExStart`.
    BadLsa = 2,
}
