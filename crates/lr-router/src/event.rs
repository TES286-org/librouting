//! Router events. Embedder polls them via [`crate::RouterInstance::poll_events`].

use lr_core::addr::Prefix;
use lr_core::event::Event;
use lr_core::fsm::TimerId;
use lr_core::rib::{Route, RouteKey};

use crate::session::SessionHandle;

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
