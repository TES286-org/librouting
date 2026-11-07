//! Router events. Embedder polls them via [`crate::RouterInstance::poll_events`].

use lr_core::addr::Prefix;
use lr_core::event::Event;
use lr_core::fsm::TimerId;
use lr_core::rib::{Route, RouteKey};

use crate::session::SessionHandle;
use lr_bgp::MaxPrefixAction;

#[derive(Debug, Clone)]
pub enum RouterEvent {
    PeerStateChange {
        session: SessionHandle,
        state: &'static str,
    },
    RouteInstalled(Route),
    RouteWithdrawn(RouteKey),
    SendBytes {
        session: SessionHandle,
        bytes: Vec<u8>,
    },
    TimerFired(TimerId),
    ProtocolError {
        session: SessionHandle,
        message: String,
    },
    Log(String),
    PrefixAdvertised(Prefix),
    PrefixRetracted(Prefix),
    /// Per-peer maximum-prefix limit exceeded (BIRD `maximum prefix`,
    /// FRR `maximum-prefix`). `count` is the current Adj-RIB-In size;
    /// `limit` is the configured ceiling; `action` is what the router
    /// is doing about it. For `Warn` the session stays up; for
    /// `Teardown`/`Restart` the session is being closed with a
    /// NOTIFICATION CEASE (subcode 1 — "Maximum Number of Prefixes
    /// Reached", RFC 4486 §3/§4).
    MaxPrefixExceeded {
        session: SessionHandle,
        count: u32,
        limit: u32,
        action: MaxPrefixAction,
    },
    /// Early warning that the peer's Adj-RIB-In crossed the configured
    /// threshold percentage of the maximum-prefix limit. Emitted once
    /// per crossing (not per route); the embedder logs it.
    MaxPrefixThreshold {
        session: SessionHandle,
        count: u32,
        limit: u32,
        pct: u8,
    },
}

/// A Grace-LSA was received on an OSPF session — the OSPF graceful
/// restart signal (RFC 3623 §3.1 for OSPFv2, RFC 5187 §2 for OSPFv3):
/// the v2 form is a type-9 opaque-LSA with Opaque Type 3, the v3 form
/// is the dedicated link-scoped LS type 0x000b with the Interface ID as
/// its Link State ID. Surfaced once per *changed* instance (a
/// duplicate — same sequence — emits nothing) through
/// [`crate::RouterInstance::drain_ospf_grace_events`] — a channel of
/// its own so an embedder whose event consumption is delegated to a
/// ticker/mirror thread (the daemon's shape) can still run its
/// helper-mode policy on every instance. `purged` is set when the
/// instance carries MaxAge, signalling the restarting router flushed
/// its Grace-LSA and graceful restart ended (RFC 3623 §3.2 (1)).
/// Grace-LSAs are link-scoped: the router does not install them into
/// the area LSDB nor re-flood them (RFC 5250 §3.1 / RFC 5187 §2.1);
/// this event is the only surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfGraceEvent {
    pub area: u32,
    /// The restarting router (Advertising Router of the LSA).
    pub advertising_router: u32,
    /// Requested grace period, seconds (Grace-LSA TLV 1).
    pub grace_period_secs: u32,
    /// Restart reason (TLV 2): 0 unknown, 1 software restart,
    /// 2 software reload/upgrade, 3 redundant switchover.
    pub reason: u8,
    /// The restarting router's IPv4 interface address on the segment
    /// (TLV 3 with a 4-octet value; the v2 broadcast/NBMA/PtMP
    /// identity), if present.
    pub interface_addr_v4: Option<[u8; 4]>,
    /// The restarting router's IPv6 interface address on the segment
    /// (TLV 3 with a 16-octet value, RFC 5187 §2.2), if present.
    /// Not required for v3 — neighbours are Router-ID identified.
    pub interface_addr_v6: Option<[u8; 16]>,
    /// LS age of the received instance (grace already elapsed).
    pub ls_age_secs: u16,
    /// MaxAge instance: the restart ended, helpers exit (flush).
    pub purged: bool,
}

impl From<Event> for RouterEvent {
    fn from(e: Event) -> Self {
        match e {
            Event::PeerStateChange {
                session,
                peer_state,
            } => Self::PeerStateChange {
                session: SessionHandle(session),
                state: peer_state,
            },
            Event::RouteInstalled(r) => Self::RouteInstalled(r),
            Event::RouteWithdrawn(k) => Self::RouteWithdrawn(k),
            Event::SendBytes { session, bytes } => Self::SendBytes {
                session: SessionHandle(session),
                bytes,
            },
            Event::TimerFired(t) => Self::TimerFired(t),
            Event::ProtocolError { session, message } => Self::ProtocolError {
                session: SessionHandle(session),
                message,
            },
            Event::Log(s) => Self::Log(s),
            Event::PrefixAdvertised(p) => Self::PrefixAdvertised(p),
            Event::PrefixRetracted(p) => Self::PrefixRetracted(p),
            // The trait-only `StateMachine for BgpPeer` adapter surfaces
            // these so a trait-only embedder can react to them. The daemon
            // consumes `BgpAction::RouteRefreshRequested` / `BgpAction::EndOfRib`
            // directly through `BgpPeer::step()` and never reaches this
            // arm — surfacing as a `Log` line keeps the daemon's event
            // stream readable while still leaving a trace for the
            // trait-only path. Embedders that want structured access can
            // match on the source `Event` directly (the trait adapter's
            // output goes through `Action::EmitEvent`).
            Event::RouteRefreshRequested { session, family } => Self::Log(format!(
                "bgp: route-refresh requested by session {session} for afi={} safi={}",
                family.afi, family.safi
            )),
            // RFC 7313 §3.2 BoRR (enhanced route refresh demarcation).
            // Same shape as the RouteRefreshRequested mapping above —
            // the trait-only `StateMachine for BgpPeer` adapter surfaces
            // `Event::BeginOfRouteRefresh` for a trait-only embedder; the
            // daemon consumes `BgpAction::BeginOfRouteRefresh` directly
            // through `BgpPeer::step()` and never reaches this arm.
            // Surfacing as a `Log` line keeps the daemon's event stream
            // readable while still leaving a trace for the trait-only
            // path; embedders that want structured access can match on
            // the source `Event` directly.
            Event::BeginOfRouteRefresh { session, family } => Self::Log(format!(
                "bgp: begin-of-rib (BoRR) received from session {session} for afi={} safi={}",
                family.afi, family.safi
            )),
            Event::EndOfRib { session, family } => Self::Log(format!(
                "bgp: end-of-rib received from session {session} for afi={} safi={}",
                family.afi, family.safi
            )),
            // OSPF neighbour reset (RFC 2328 §10.6 / §10.9 / §13.7).
            // The router's OSPF dispatch path
            // (`instance::mod.rs::feed_input`'s `SessionState::Ospf`
            // arm) handles this variant directly and records the cause
            // into `SessionStats::last_error` via the dedicated
            // `SessionErrorKind::OspfKill`/`OspfSeqMismatch`/`OspfBadLsa`
            // variants. This arm exists so a trait-only embedder that
            // converts an `Event` via `into()` (rather than dispatching
            // inside the router) still gets a readable log line instead
            // of the generic "unknown event variant" fallback below.
            Event::OspfNeighborReset { router_id, kind } => Self::Log(format!(
                "ospf: neighbor {router_id} reset ({})",
                match kind {
                    lr_core::event::OspfNeighborResetKind::Kill => "ospf-kill",
                    lr_core::event::OspfNeighborResetKind::SeqMismatch => "ospf-seq-mismatch",
                    lr_core::event::OspfNeighborResetKind::BadLsa => "ospf-bad-lsa",
                    // `OspfNeighborResetKind` is `#[non_exhaustive]` so
                    // future variants (e.g. OSPFv3-specific reset causes)
                    // compile against this match without forcing a
                    // major bump.
                    _ => "ospf-reset",
                }
            )),
            // `Event` is `#[non_exhaustive]` so future variants can
            // land on `main` without forcing this match to grow an
            // arm at every minor. An unknown event carries no
            // structured data the daemon can act on, so it surfaces
            // as a `Log` line and the embedder can pattern-match on
            // the source `Event` directly if it needs the structured
            // form.
            _ => Self::Log("lr-core: unknown event variant".to_string()),
        }
    }
}

/// Sink trait for embedders that want push-based events.
pub trait EventSink {
    fn on_event(&mut self, ev: &RouterEvent);
}
