//! Signal handling for `lr-daemon`.
//!
//! Follows the project convention of declaring the libc symbols directly
//! (`extern "C"`) instead of pulling in a libc/nix/signal-hook dependency —
//! `lr-osroute` does the same for sockets and netlink.
//!
//! Unix design:
//!
//! - handlers for SIGHUP / SIGINT / SIGTERM are installed with `signal(2)`;
//!   glibc and musl both give it BSD semantics (no System-V handler reset)
//! - the handler body is async-signal-safe: a single relaxed atomic store,
//!   nothing else
//! - the daemon's I/O loops poll [`take_pending`] at their existing
//!   100–200 ms cadence (accept-poll and read-timeout), so no EINTR
//!   plumbing is required
//!
//! Installing a SIGHUP handler is itself hardening: without one a stray
//! SIGHUP (e.g. a hung-up terminal) would terminate the daemon with the
//! default disposition. Signal numbers (SIGHUP 1, SIGINT 2, SIGTERM 15)
//! are identical across every Unix target this workspace compiles for
//! (Linux, FreeBSD, NetBSD, macOS).
//!
//! On non-Unix platforms the API compiles to inert stubs: no signals
//! exist there and the daemon falls back to platform conventions
//! (Ctrl-C console events on Windows).

#[cfg(unix)]
mod imp {
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

    pub const SIGHUP: i32 = 1;
    pub const SIGINT: i32 = 2;
    pub const SIGTERM: i32 = 15;

    /// Last signal delivered (0 = none). Written only from the handler.
    static PENDING: AtomicI32 = AtomicI32::new(0);

    /// Multi-protocol supervision flag (see [`set_supervised`]).
    static SUPERVISED: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_signal(sig: i32) {
        // Async-signal-safe: one relaxed store, no allocation, no locks.
        PENDING.store(sig, Ordering::Relaxed);
    }

    extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }

    /// Install handlers for SIGHUP, SIGINT and SIGTERM. Idempotent.
    ///
    /// Returns an error naming the first signal that could not be
    /// installed. The daemon treats failure as fatal: running with
    /// default dispositions would let a stray SIGHUP kill the process.
    pub fn init() -> Result<(), i32> {
        for sig in [SIGHUP, SIGINT, SIGTERM] {
            // signal(2) returns the previous handler (never SIG_DFL/IGN
            // here after first install); usize::MAX is SIG_ERR.
            let prev = unsafe { signal(sig, on_signal) };
            if prev == usize::MAX {
                return Err(sig);
            }
        }
        Ok(())
    }

    /// Consume the pending signal, if any. The first caller after
    /// delivery wins; later callers see `None` until another arrives.
    pub fn take_pending() -> Option<i32> {
        let sig = PENDING.swap(0, Ordering::Relaxed);
        match sig {
            0 => None,
            s => Some(s),
        }
    }

    /// Set when the multi-protocol supervisor owns signal dispatch
    /// (rc.3): `take_pending` is a single-consumer swap, so engine
    /// threads (connector loops, session pumps, main loops) must not
    /// consume signals — one stealing thread would hide SIGTERM from
    /// the supervisor. `dispatch_signals` checks this flag and becomes
    /// a no-op for everyone but the supervisor's own dispatch.
    pub fn set_supervised(on: bool) {
        SUPERVISED.store(on, Ordering::Relaxed);
    }

    /// Whether the multi-protocol supervisor owns signal dispatch.
    pub fn supervised() -> bool {
        SUPERVISED.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // Single test: the static PENDING is shared, so separate tests
        // would race under the parallel harness.
        #[test]
        fn pending_signal_roundtrip() {
            // Idle when nothing was delivered (or already consumed).
            let stolen = take_pending();
            assert!(stolen.is_none() || matches!(stolen, Some(SIGHUP | SIGINT | SIGTERM)));

            on_signal(SIGTERM);
            assert_eq!(take_pending(), Some(SIGTERM));
            assert!(take_pending().is_none(), "pending must be consumed once");

            on_signal(SIGHUP);
            assert_eq!(take_pending(), Some(SIGHUP));
        }

        #[test]
        fn install_succeeds_and_survives_reinstall() {
            init().expect("signal handlers install");
            init().expect("idempotent reinstall");
        }
    }
}

#[cfg(not(unix))]
mod imp {
    // No signals on this platform; the daemon's shutdown path relies on
    // console events / external termination instead.

    pub const SIGHUP: i32 = 1;
    pub const SIGINT: i32 = 2;
    pub const SIGTERM: i32 = 15;

    pub fn init() -> Result<(), i32> {
        Ok(())
    }

    pub fn take_pending() -> Option<i32> {
        None
    }

    pub fn set_supervised(_on: bool) {}

    pub fn supervised() -> bool {
        false
    }
}

pub use imp::{init, set_supervised, supervised, take_pending, SIGHUP, SIGINT, SIGTERM};
