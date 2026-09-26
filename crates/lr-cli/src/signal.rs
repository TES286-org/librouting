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
//! On Windows the API is backed by a `SetConsoleCtrlHandler` console
//! control handler: CTRL_C / CTRL_BREAK map to SIGINT, and the
//! console-close / logoff / shutdown events map to SIGTERM with a
//! bounded in-handler wait — Windows tears the process down the moment
//! that handler returns, so the daemon must finish withdrawing its
//! kernel routes before [`mark_shutdown_complete`] releases it.

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

    /// Unix shutdown completion is ordinary process exit — the flag
    /// exists for the Windows console handler only.
    pub fn mark_shutdown_complete() {}

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

#[cfg(windows)]
mod imp {
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::time::{Duration, Instant};

    pub const SIGHUP: i32 = 1;
    pub const SIGINT: i32 = 2;
    pub const SIGTERM: i32 = 15;

    /// Last console control event mapped to a signal (0 = none).
    static PENDING: AtomicI32 = AtomicI32::new(0);

    /// Set by the daemon right before it returns from `main`. The
    /// console-control handler for CTRL_CLOSE / CTRL_LOGOFF /
    /// CTRL_SHUTDOWN waits (bounded) on it: Windows tears the process
    /// down the moment the handler returns, so without the wait the
    /// daemon would die before it can withdraw its kernel routes.
    static SHUTDOWN_COMPLETE: AtomicBool = AtomicBool::new(false);

    /// Multi-protocol supervision flag (see [`set_supervised`]).
    static SUPERVISED: AtomicBool = AtomicBool::new(false);

    // wincon.h console control events.
    const CTRL_C_EVENT: u32 = 0;
    const CTRL_BREAK_EVENT: u32 = 1;
    const CTRL_CLOSE_EVENT: u32 = 2;
    const CTRL_LOGOFF_EVENT: u32 = 5;
    const CTRL_SHUTDOWN_EVENT: u32 = 6;

    /// Windows grants ~5 s for CTRL_CLOSE and ~20 s for CTRL_SHUTDOWN
    /// before hard-killing the process once the handler returns; stay
    /// below both so the graceful path (session Cease + kernel-route
    /// withdrawal) fits inside the budget.
    const HANDLER_GRACE: Duration = Duration::from_secs(4);

    extern "system" fn on_console_ctrl(ctrl: u32) -> i32 {
        let graceful = match ctrl {
            CTRL_C_EVENT | CTRL_BREAK_EVENT => {
                PENDING.store(SIGINT, Ordering::Relaxed);
                // Console stays alive: return immediately and let the
                // daemon's poll loops notice the shutdown flag.
                return 1;
            }
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
                PENDING.store(SIGTERM, Ordering::Relaxed);
                true
            }
            _ => return 0,
        };
        if graceful {
            let deadline = Instant::now() + HANDLER_GRACE;
            while !SHUTDOWN_COMPLETE.load(Ordering::Relaxed) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        1
    }

    extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }

    /// Install the console control handler. Idempotent (the handler is
    /// added once; repeat calls are no-ops at the Win32 level).
    pub fn init() -> Result<(), i32> {
        let rc = unsafe { SetConsoleCtrlHandler(Some(on_console_ctrl), 1) };
        if rc == 0 {
            return Err(SIGINT);
        }
        Ok(())
    }

    /// Consume the pending signal, if any. Same single-consumer swap
    /// contract as the Unix implementation.
    pub fn take_pending() -> Option<i32> {
        let sig = PENDING.swap(0, Ordering::Relaxed);
        match sig {
            0 => None,
            s => Some(s),
        }
    }

    /// Set when the multi-protocol supervisor owns signal dispatch
    /// (same contract as Unix).
    pub fn set_supervised(on: bool) {
        SUPERVISED.store(on, Ordering::Relaxed);
    }

    /// Whether the multi-protocol supervisor owns signal dispatch.
    pub fn supervised() -> bool {
        SUPERVISED.load(Ordering::Relaxed)
    }

    /// Release the CTRL_CLOSE / CTRL_LOGOFF / CTRL_SHUTDOWN handler's
    /// bounded wait — called once, from `main`, after every engine has
    /// flushed its Cease NOTIFICATIONs and the kernel FIB mirror has
    /// withdrawn the routes this daemon installed.
    pub fn mark_shutdown_complete() {
        SHUTDOWN_COMPLETE.store(true, Ordering::Relaxed);
    }
}

/// Targets with neither Unix signals nor a Win32 console (wasm and
/// friends): inert stubs so the daemon still compiles.
#[cfg(not(any(unix, windows)))]
mod imp {
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

    pub fn mark_shutdown_complete() {}
}

pub use imp::{
    init, mark_shutdown_complete, set_supervised, supervised, take_pending, SIGHUP, SIGINT, SIGTERM,
};
