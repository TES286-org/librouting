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
    /// NOTIFICATION CEASE (subcode 8).
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
