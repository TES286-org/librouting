//! Event polling FFI (ROADMAP-v3 D5.5): `lr_router_poll_events`.
//!
//! Serializes [`RouterEvent`] batches into a fixed-layout C struct
//! array. Transport-oriented events never appear here: `SendBytes`
//! rides the drain-output data plane and `TimerFired` is internal
//! machinery — both are consumed silently during the drain. Events
//! that do not fit the caller's buffer are requeued (front of the
//! queue, order preserved), so polling with a too-small buffer loses
//! nothing.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]).

use lr_router::{RouterEvent, RouterInstance as _};

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{lock_router, lr_router_t};

/// Maximum text length carried in one event (peer-state names, log
/// lines, protocol-error messages). Longer strings are truncated to
/// `LR_EVENT_TEXT_MAX - 1` bytes plus the NUL terminator; the full
/// text stays available through the Rust API.
pub const LR_EVENT_TEXT_MAX: usize = 128;

/// Event kinds serialized by [`lr_router_poll_events`]. Mirrors the
/// [`RouterEvent`] variants an embedder can observe.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum lr_event_kind_t {
    /// A session changed state (`text` holds the state name; the
    /// byte defines `LR_EVENT_PEER_STATE`).
    PeerState = 1,
    /// A route entered the Loc-RIB (prefix + path id).
    RouteInstalled = 2,
    /// A route left the Loc-RIB.
    RouteWithdrawn = 3,
    /// A free-form log line (`text`).
    Log = 4,
    /// A prefix was advertised to a peer.
    PrefixAdvertised = 5,
    /// A prefix was retracted from a peer.
    PrefixRetracted = 6,
    /// A protocol error on a session (`text` holds the message).
    ProtocolError = 7,
    /// The per-peer maximum-prefix limit was exceeded (`count`,
    /// `limit`, `action`).
    MaxPrefixExceeded = 8,
    /// The Adj-RIB-In crossed the maximum-prefix warning threshold
    /// (`count`, `limit`, `pct`).
    MaxPrefixThreshold = 9,
}

/// One serialized router event. Only the fields meaningful for `kind`
/// are populated; the rest are zero. `prefix` carries IPv4 in its
/// first four bytes with `is_ipv6 == 0`, IPv6 in all sixteen with
/// `is_ipv6 == 1`. `text` is NUL-terminated.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_event_t {
    /// Which event this is ([`lr_event_kind_t`], also published as the
    /// `LR_EVENT_*` defines in the header).
    pub kind: i32,
    /// The session the event relates to (0 when none).
    pub session: u64,
    /// The prefix (RouteInstalled / RouteWithdrawn / Prefix* events).
    pub prefix: [u8; 16],
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// 1 when `prefix` carries an IPv6 address.
    pub is_ipv6: u8,
    /// The Add-Path identifier of the installed/withdrawn path.
    pub path_id: u32,
    /// MaxPrefix events: the current Adj-RIB-In size.
    pub count: u32,
    /// MaxPrefix events: the configured ceiling.
    pub limit: u32,
    /// MaxPrefixThreshold: the crossing percentage.
    pub pct: u32,
    /// MaxPrefixExceeded: 0 = warn, 1 = teardown, 2 = restart.
    pub action: i32,
    /// Peer state, log line or error message, NUL-terminated
    /// (truncated at [`LR_EVENT_TEXT_MAX`] bytes).
    pub text: [u8; LR_EVENT_TEXT_MAX],
}

impl lr_event_t {
    fn zeroed(kind: lr_event_kind_t) -> Self {
        Self {
            kind: kind as i32,
            session: 0,
            prefix: [0; 16],
            prefix_len: 0,
            is_ipv6: 0,
            path_id: 0,
            count: 0,
            limit: 0,
            pct: 0,
            action: 0,
            text: [0; LR_EVENT_TEXT_MAX],
        }
    }

    fn set_text(&mut self, s: &str) {
        // Clear first: a reused event struct must never leak a longer
        // previous string past the new NUL (text_of stops at the first
        // NUL, but the raw bytes should not carry stale content either).
        self.text = [0; LR_EVENT_TEXT_MAX];
        let bytes = s.as_bytes();
        let n = bytes.len().min(LR_EVENT_TEXT_MAX - 1);
        self.text[..n].copy_from_slice(&bytes[..n]);
    }

    fn set_prefix(&mut self, p: lr_core::addr::Prefix) {
        match p.addr {
            lr_core::addr::IpAddr::V4(b) => {
                self.prefix[..4].copy_from_slice(&b);
                self.is_ipv6 = 0;
            }
            lr_core::addr::IpAddr::V6(b) => {
                self.prefix = b;
                self.is_ipv6 = 1;
            }
        }
        self.prefix_len = p.prefix_len;
    }
}

/// Serialize one batch of events. Returns the serialized vec (the
/// `SendBytes` / `TimerFired` entries are consumed and dropped) and
/// the remainder that did not fit `cap` (to be requeued).
fn serialize(events: Vec<RouterEvent>, cap: usize) -> (Vec<lr_event_t>, Vec<RouterEvent>) {
    let mut out = Vec::new();
    let mut rest = Vec::new();
    for e in events {
        // Transport-plane events never surface here.
        let item = match &e {
            RouterEvent::SendBytes { .. } => continue,
            RouterEvent::TimerFired(_) => continue,
            RouterEvent::PeerStateChange { session, state } => {
                let mut ev = lr_event_t::zeroed(lr_event_kind_t::PeerState);
                ev.session = session.0;
                ev.set_text(state);
                ev
            }
            RouterEvent::RouteInstalled(route) => {
                let mut ev = lr_event_t::zeroed(lr_event_kind_t::RouteInstalled);
                ev.set_prefix(route.key.prefix);
                ev.path_id = route.path_id;
                ev
            }
            RouterEvent::RouteWithdrawn(key) => {
                let mut ev = lr_event_t::zeroed(lr_event_kind_t::RouteWithdrawn);
                ev.set_prefix(key.prefix);
                ev
            }
            RouterEvent::Log(msg) => {
                let mut ev = lr_event_t::zeroed(lr_event_kind_t::Log);
                ev.set_text(msg);
                ev
            }
            RouterEvent::PrefixAdvertised(p) => {
                let mut ev = lr_event_t::zeroed(lr_event_kind_t::PrefixAdvertised);
                ev.set_prefix(*p);
                ev
            }
            RouterEvent::PrefixRetracted(p) => {
                let mut ev = lr_event_t::zeroed(lr_event_kind_t::PrefixRetracted);
                ev.set_prefix(*p);
                ev
            }
            RouterEvent::ProtocolError { session, message } => {
                let mut ev = lr_event_t::zeroed(lr_event_kind_t::ProtocolError);
                ev.session = session.0;
                ev.set_text(message);
                ev
            }
            RouterEvent::MaxPrefixExceeded {
                session,
                count,
                limit,
                action,
            } => {
                let mut ev = lr_event_t::zeroed(lr_event_kind_t::MaxPrefixExceeded);
                ev.session = session.0;
                ev.count = *count;
                ev.limit = *limit;
                ev.action = max_prefix_action_id(*action);
                ev
            }
            RouterEvent::MaxPrefixThreshold {
                session,
                count,
                limit,
                pct,
            } => {
                let mut ev = lr_event_t::zeroed(lr_event_kind_t::MaxPrefixThreshold);
                ev.session = session.0;
                ev.count = *count;
                ev.limit = *limit;
                ev.pct = u32::from(*pct);
                ev
            }
        };
        if out.len() < cap {
            out.push(item);
        } else {
            rest.push(e);
        }
    }
    (out, rest)
}

fn max_prefix_action_id(action: lr_bgp::MaxPrefixAction) -> i32 {
    use lr_bgp::MaxPrefixAction::*;
    match action {
        Warn => 0,
        Teardown => 1,
        Restart => 2,
    }
}

/// Poll up to `cap` router events into `out` (ROADMAP-v3 D5.5):
/// peer-state changes, route installs/withdrawals, advertisements and
/// retractions, logs, protocol errors and the maximum-prefix signals.
/// Returns the number of events written; 0 means the queue is empty
/// for now. Events beyond the buffer are requeued — nothing is lost,
/// the next call delivers them first. Negative on error.
///
/// Transport-plane events (`SendBytes`, `TimerFired`) are consumed
/// and dropped by the poll: outgoing bytes ride
/// [`crate::handle`]`::drain_output`, timers are internal.
///
/// # Safety
/// `out` must point to `cap` writable `lr_event_t` values when `cap`
/// is positive.
#[no_mangle]
pub unsafe extern "C" fn lr_router_poll_events(
    r: lr_router_t,
    out: *mut lr_event_t,
    cap: i32,
) -> i32 {
    guarded(
        || {
            if cap < 0 {
                set_last_error(format!("negative capacity {cap}"));
                return -3;
            }
            if cap > 0 && out.is_null() {
                return -1;
            }
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            let events = router.poll_events();
            let (serialized, rest) = serialize(events, cap as usize);
            router.requeue_events(rest);
            let n = serialized.len();
            if n > 0 {
                unsafe {
                    std::ptr::copy_nonoverlapping(serialized.as_ptr(), out, n.min(cap as usize));
                }
            }
            n as i32
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(e: &lr_event_t) -> String {
        let n = e
            .text
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(LR_EVENT_TEXT_MAX);
        String::from_utf8_lossy(&e.text[..n]).into_owned()
    }

    #[test]
    fn poll_reports_route_lifecycle() {
        let r = crate::router::lr_router_new();
        let addr = [203u8, 0, 113, 0];
        unsafe { crate::router::lr_router_originate_v4(r, addr.as_ptr(), 24, std::ptr::null()) };
        let mut events = [lr_event_t {
            kind: 0,
            session: 0,
            prefix: [0; 16],
            prefix_len: 0,
            is_ipv6: 0,
            path_id: 0,
            count: 0,
            limit: 0,
            pct: 0,
            action: 0,
            text: [0; LR_EVENT_TEXT_MAX],
        }; 8];
        let n = unsafe { lr_router_poll_events(r, events.as_mut_ptr(), 8) };
        assert!(n >= 1, "at least the RouteInstalled event, got {n}");
        let installed = events[..n as usize]
            .iter()
            .find(|e| e.kind == lr_event_kind_t::RouteInstalled as i32)
            .expect("RouteInstalled event");
        assert_eq!(installed.prefix[..4], [203, 0, 113, 0]);
        assert_eq!(installed.prefix_len, 24);
        assert_eq!(installed.is_ipv6, 0);

        // Withdrawing emits RouteWithdrawn.
        unsafe { crate::router::lr_router_withdraw_v4(r, addr.as_ptr(), 24) };
        let n2 = unsafe { lr_router_poll_events(r, events.as_mut_ptr(), 8) };
        assert!(n2 >= 1);
        assert!(
            events[..n2 as usize]
                .iter()
                .any(|e| e.kind == lr_event_kind_t::RouteWithdrawn as i32),
            "RouteWithdrawn event present"
        );

        // An empty queue reports 0.
        let n3 = unsafe { lr_router_poll_events(r, events.as_mut_ptr(), 8) };
        assert_eq!(n3, 0);
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn poll_requeues_overflow() {
        let r = crate::router::lr_router_new();
        let a = [198u8, 51, 100, 0];
        let b = [203u8, 0, 113, 0];
        unsafe {
            crate::router::lr_router_originate_v4(r, a.as_ptr(), 24, std::ptr::null());
            crate::router::lr_router_originate_v4(r, b.as_ptr(), 24, std::ptr::null());
        }
        // One event slot: the first poll delivers 1, the rest wait.
        let mut slot = [lr_event_t {
            kind: 0,
            session: 0,
            prefix: [0; 16],
            prefix_len: 0,
            is_ipv6: 0,
            path_id: 0,
            count: 0,
            limit: 0,
            pct: 0,
            action: 0,
            text: [0; LR_EVENT_TEXT_MAX],
        }];
        let n1 = unsafe { lr_router_poll_events(r, slot.as_mut_ptr(), 1) };
        assert_eq!(n1, 1, "exactly one event fits");
        let first: [u8; 4] = slot[0].prefix[..4].try_into().unwrap();
        let n2 = unsafe { lr_router_poll_events(r, slot.as_mut_ptr(), 1) };
        assert_eq!(n2, 1, "the requeued remainder arrives next");
        let second: [u8; 4] = slot[0].prefix[..4].try_into().unwrap();
        assert_ne!(first, second, "a different event");
        // Draining to empty.
        loop {
            let n = unsafe { lr_router_poll_events(r, slot.as_mut_ptr(), 1) };
            if n == 0 {
                break;
            }
        }
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn poll_argument_validation() {
        let r = crate::router::lr_router_new();
        // Negative capacity is rejected.
        assert_eq!(
            unsafe { lr_router_poll_events(r, std::ptr::null_mut(), -1) },
            -3
        );
        // A NULL buffer with a positive capacity is rejected.
        assert_eq!(
            unsafe { lr_router_poll_events(r, std::ptr::null_mut(), 4) },
            -1
        );
        // cap == 0 with NULL is fine: nothing to write, drains nothing.
        assert_eq!(
            unsafe { lr_router_poll_events(r, std::ptr::null_mut(), 0) },
            0
        );
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn text_truncation_is_nul_terminated() {
        let mut ev = lr_event_t::zeroed(lr_event_kind_t::Log);
        let long = "x".repeat(LR_EVENT_TEXT_MAX * 2);
        ev.set_text(&long);
        assert_eq!(ev.text[LR_EVENT_TEXT_MAX - 1], 0, "last byte is the NUL");
        assert!(text_of(&ev).len() < LR_EVENT_TEXT_MAX);
        // Short strings are copied whole.
        ev.set_text("Established");
        assert_eq!(text_of(&ev), "Established");
    }
}
