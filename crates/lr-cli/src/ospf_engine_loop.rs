//! OSPF engine event loop — the shared shape the OSPFv2 and OSPFv3
//! daemons run their main loop on (ROADMAP async-I/O item, the last
//! transport surface).
//!
//! Before this module both engine loops were a 50 ms poll-and-sleep:
//! pump every interface socket (a `recv_from` sweep that hit every
//! socket even when nothing was queued), sleep 50 ms, repeat — an
//! inbound packet waited out up to 50 ms of that sleep before the
//! engine processed it.
//!
//! One `mio::Poll` drives every interface transport instead:
//!
//! - each raw socket registers READABLE through `mio::unix::SourceFd`
//!   (the transport owns the fd; the registration borrows it — the
//!   same shape the BFD supervisor's rx sockets use);
//! - a readable event wakes the loop immediately and the next pump
//!   pass picks the packet up — the engine's own pump order is
//!   untouched, so the timer work (elections, dead timers,
//!   retransmissions, Hellos) runs on every pass exactly as before;
//! - the poll timeout stays the pump's own 50 ms cadence: OSPF's
//!   timers are second-granularity and the pump's checks are
//!   `now >= due` comparisons, so the timer behaviour is bit-for-bit
//!   the poll-and-sleep loop's, minus the sleep between passes;
//! - a `mio::Waker` owned by a watcher thread fires on a pending
//!   signal (peeked, never taken — the loop's own `dispatch_signals`
//!   owns the consume) or the daemon's `running` flag clearing, at
//!   the 100 ms cadence every other daemon surface offers, so signal
//!   dispatch and shutdown keep the latency class they had.
//!
//! Non-unix targets keep the poll-and-sleep loop: `SourceFd` has no
//! Windows equivalent, and the OSPF raw transports are Linux-only
//! anyway (the BSD/Windows transports refuse at bind, before the
//! loop). A failed registration (a stub transport's `-1` fd, a
//! `Poll::new` error) also falls back to the poll-and-sleep shape
//! rather than failing the daemon.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// The pump cadence both OSPF engines ran their poll-and-sleep loop
/// at — now the poll timeout ceiling that bounds the worst case
/// between readable events.
pub(super) const PUMP_INTERVAL: Duration = Duration::from_millis(50);

/// The cadence the shutdown watcher peeks signals and `running` at.
const WATCHER_INTERVAL: Duration = Duration::from_millis(100);

/// Run one OSPF engine's main loop until the daemon stops.
///
/// `fds` are the interface transports' raw sockets; `pump` is one
/// engine pass (receive → demux → elections → timers → originate →
/// transmit — the daemon's own pump order). `recv_buf` stays with the
/// caller: the graceful-restart shutdown flood reuses it after the
/// loop.
pub(super) fn run_engine_loop(
    fds: Vec<std::os::fd::RawFd>,
    runtime: &crate::Runtime,
    running: &Arc<AtomicBool>,
    start: &Instant,
    pump: &mut dyn FnMut(u64),
) {
    #[cfg(target_family = "unix")]
    {
        if let Some(mut loop_) = MioEngineLoop::new(fds.clone(), running) {
            loop_.run(runtime, running, start, pump);
            return;
        }
    }
    let _ = (runtime, fds);
    run_poll_sleep(runtime, running, start, pump);
}

/// The poll-and-sleep fallback: the exact loop the engines ran before
/// the event loop (a non-unix target, or a registration failure).
fn run_poll_sleep(
    runtime: &crate::Runtime,
    running: &Arc<AtomicBool>,
    start: &Instant,
    pump: &mut dyn FnMut(u64),
) {
    while running.load(Ordering::Relaxed) {
        crate::dispatch_signals(runtime);
        if !running.load(Ordering::Relaxed) {
            break;
        }
        let now_ms = start.elapsed().as_millis() as u64;
        pump(now_ms);
        thread::sleep(PUMP_INTERVAL);
    }
}

/// The reserved token the shutdown waker fires; interface tokens are
/// indices from 0 upward.
#[cfg(target_family = "unix")]
const WAKER_TOKEN: usize = usize::MAX;

/// The event loop: every interface fd registered READABLE, one waker.
#[cfg(target_family = "unix")]
struct MioEngineLoop {
    poll: mio::Poll,
    events: mio::Events,
}

#[cfg(target_family = "unix")]
impl MioEngineLoop {
    /// Build and register. `None` falls the caller back to the
    /// poll-and-sleep loop.
    fn new(fds: Vec<std::os::fd::RawFd>, running: &Arc<AtomicBool>) -> Option<Self> {
        use mio::unix::SourceFd;

        let poll = mio::Poll::new().ok()?;
        let registry = poll.registry().try_clone().ok()?;
        let waker = mio::Waker::new(&registry, mio::Token(WAKER_TOKEN)).ok()?;
        let waker = Arc::new(waker);
        for (i, fd) in fds.iter().enumerate() {
            let fd = *fd;
            let mut source = SourceFd(&fd);
            if let Err(e) = registry.register(&mut source, mio::Token(i), mio::Interest::READABLE) {
                log_error!(
                    crate::Component::Ospf,
                    "mio register interface socket {i}: {e} — poll-and-sleep fallback"
                );
                return None;
            }
        }
        // The waker watcher: a pending signal (peeked) or the
        // `running` flag clearing wakes the poll within the cadence
        // every daemon surface offers.
        let running = Arc::clone(running);
        let _ = thread::Builder::new()
            .name("lr-ospf-waker".into())
            .spawn(move || {
                while running.load(Ordering::Relaxed) {
                    thread::sleep(WATCHER_INTERVAL);
                    if !running.load(Ordering::Relaxed) || crate::signal::peek_pending() {
                        let _ = waker.wake();
                    }
                }
            });
        Some(Self {
            poll,
            events: mio::Events::with_capacity(64),
        })
    }

    fn run(
        &mut self,
        runtime: &crate::Runtime,
        running: &Arc<AtomicBool>,
        start: &Instant,
        pump: &mut dyn FnMut(u64),
    ) {
        while running.load(Ordering::Relaxed) {
            crate::dispatch_signals(runtime);
            if !running.load(Ordering::Relaxed) {
                break;
            }
            self.events.clear();
            let _ = self.poll.poll(&mut self.events, Some(PUMP_INTERVAL));
            if !running.load(Ordering::Relaxed) {
                break;
            }
            // The pump is the engine's own pass — the readable events
            // (or the timeout ceiling) only decide *when* it runs.
            let now_ms = start.elapsed().as_millis() as u64;
            pump(now_ms);
        }
    }
}
