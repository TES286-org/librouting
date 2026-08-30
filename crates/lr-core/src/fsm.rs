//! Generic finite-state machine engine.
//!
//! Used by `lr-bgp::fsm`, `lr-ospf::neighbor`, `lr-babel::fsm`. Each protocol
//! supplies its own `State`, `Event` and `Action` enums and implements the
//! [`StateMachine`] trait. The engine itself is intentionally minimal — no
//! timers, no I/O. FSMs emit [`Action`]s which the embedder dispatches
//! (sending bytes, arming timers, installing routes, etc.).

use core::fmt;
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Stable identifier for an FSM state (used by `RouterEvent::PeerStateChange`
/// across protocols). 0 = idle / down.
pub type StateId = u32;

/// Generic action vocabulary understood by the embedder. Protocol-specific
/// actions are flattened into this enum so the dispatch loop is uniform.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send a byte slice to the peer transport.
    Send(Vec<u8>),
    /// Request the embedder to arm a timer.
    SetTimer(TimerId, TimerSpec),
    /// Cancel a previously armed timer.
    CancelTimer(TimerId),
    /// Install a route into the local RIB (post-policy).
    InstallRoute(crate::rib::Route),
    /// Withdraw a route from the local RIB. `path_id` is the RFC 7911
    /// Add-Path identifier of the withdrawn path (0 = single-path mode).
    WithdrawRoute {
        key: crate::rib::RouteKey,
        path_id: u32,
    },
    /// Emit a router-level event (state change, log, error).
    EmitEvent(crate::event::Event),
    /// Tear down the session; embedder will close the transport.
    Close,
    /// No-op (used when an event triggers no transition).
    None,
}

/// Logical timer identifier (per FSM instance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(pub u32);

/// Timer specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerSpec {
    /// Fire this many milliseconds from now.
    pub after_ms: u64,
    /// If non-zero, fire periodically every `periodic_ms` afterwards.
    pub periodic_ms: u64,
}

impl TimerSpec {
    pub const fn once(after_ms: u64) -> Self {
        Self {
            after_ms,
            periodic_ms: 0,
        }
    }

    pub const fn periodic(after_ms: u64, periodic_ms: u64) -> Self {
        Self {
            after_ms,
            periodic_ms,
        }
    }
}

/// Finite-state machine trait. The implementation owns its state. `step`
/// consumes an event and returns a list of [`Action`]s to dispatch.
pub trait StateMachine {
    type State: Copy + Eq + fmt::Debug;
    type Event;
    fn state(&self) -> Self::State;
    fn step(&mut self, event: Self::Event) -> Vec<Action>;
    /// Reset to the initial state.
    fn reset(&mut self);
}
