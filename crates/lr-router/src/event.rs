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
    /// A Grace-LSA (RFC 3623 / RFC 5187: OSPFv2 type-9 opaque-LSA with
    /// Opaque Type 3, or the OSPFv3 equivalent) was received on an OSPF
    /// session. Emitted once per *changed* instance (a duplicate — same
    /// sequence — emits nothing). `purged` is set when the instance
    /// carries MaxAge, signalling the restarting router flushed its
    /// Grace-LSA and graceful restart ended (RFC 3623 §3.2 (1)).
    /// Grace-LSAs are link-scoped: the router does not install them
    /// into the area LSDB nor re-flood them (RFC 5250 §3.1); the event
    /// is the only surface — embedders run their helper-mode policy on
    /// it.
    OspfGraceLsa {
        area: u32,
        /// The restarting router (Advertising Router of the LSA).
        advertising_router: u32,
        /// Requested grace period, seconds (Grace-LSA TLV 1).
        grace_period_secs: u32,
        /// Restart reason (TLV 2): 0 unknown, 1 software restart,
        /// 2 software reload/upgrade, 3 redundant switchover.
        reason: u8,
        /// The restarting router's IPv4 interface address on the
        /// segment (TLV 3, broadcast/NBMA/PtMP identity), if present.
        interface_addr: Option<[u8; 4]>,
        /// LS age of the received instance (grace already elapsed).
        ls_age_secs: u16,
        /// MaxAge instance: the restart ended, helpers exit (flush).
        purged: bool,
    },
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
        }
    }
}

/// Sink trait for embedders that want push-based events.
pub trait EventSink {
    fn on_event(&mut self, ev: &RouterEvent);
}
