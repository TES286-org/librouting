//! BGP session reactor — one event loop for every established BGP
//! session (ROADMAP async-I/O item, first slice).
//!
//! Before the reactor, each established BGP session ran on a *thread
//! per socket* whose read timeout (200 ms) was the poll cadence: an
//! idle session woke five times a second to check for bytes that were
//! not there, and the session count a process could hold was bounded
//! by thread stacks and per-thread wakeups — the ROADMAP "Scaling"
//! async-I/O entry names exactly this.
//!
//! The reactor replaces the per-session threads with a single thread
//! that owns a `mio::Poll`:
//!
//! - the listener and the per-peer connectors submit connected
//!   sockets through a channel ([`BgpReactor::submit`]); the
//!   submission wakes the reactor through a `mio::Waker` registered
//!   to a reserved token;
//! - registration starts the session in the router (`start_session` —
//!   the same call the session threads made), flushes the FSM's
//!   initial output (the OPEN) and registers the socket READABLE;
//! - a readable event drives the exact pump order the session thread
//!   used: read the bytes, `feed_input`, `drain_output`, write, then
//!   the router-side close / collision-loss latch check;
//! - a partial write (the socket's send buffer filled mid-UPDATE)
//!   parks the remainder in the slot and adds WRITABLE interest; the
//!   writable event flushes it. The session threads could afford
//!   blocking `write_all` (one stalled peer stalled one session); the
//!   reactor cannot — a stalled write on the reactor thread would
//!   stall every session;
//! - a maintenance sweep every 50 ms of wall time (regardless of how
//!   busy the event stream is) covers the sessions that have no
//!   readable events: BFD Up-to-Down transitions, timer-generated
//!   output (KEEPALIVEs, retransmissions — queued by the ticker
//!   thread's `tick`), and router-side closes (collision resolution).
//!
//! OSPF and Babel transports stay on their own threads for now (the
//! ROADMAP's sequencing: their raw-socket and UDP-plus-multicast
//! shapes wrap differently); the runtime API, the metrics endpoint
//! and the BFD daemon keep their hand-rolled loops. Nothing in the
//! library crates depends on this module — it is an implementation
//! detail of the `lr-daemon` BGP engine.
//!
//! # Teardown semantics
//!
//! The old `run_peer_session` distinguished two teardown paths and
//! the reactor preserves them exactly (RFC 4486 §4.1):
//!
//! - the daemon is shutting down (`running == false`) — the session
//!   is a live one WE are ending, so `shutdown_session` queues the
//!   Cease NOTIFICATION, the final drain flushes it to the wire and
//!   only then the socket closes;
//! - everything else (peer closed, read/write error, BFD down,
//!   router-closed collision loss) — `close_session`; the peer keeps
//!   its RFC 4724/9494 retention window because the close is not
//!   classified as a deliberate goodbye.
//!
//! The completion callback (`on_end`, supplied by the listener or
//! the connector that submitted the session) receives the structured
//! [`SessionEnd`] — the enum form of the strings the pump returned —
//! and owns the bookkeeping the session threads did: the inbound
//! `busy` guard, the live-session counter, and the connector's
//! backoff classification (which previously string-matched
//! `"collision resolution"`; the enum makes that an equality test).

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream as StdTcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use mio::net::TcpStream as MioTcpStream;
use mio::{Events, Interest, Poll, Registry, Token, Waker};

use lr_router::{DefaultRouter, RouterInstance, SessionHandle};

use crate::daemon_bfd::BfdFlags;

/// Reserved token the `mio::Waker` fires. Session tokens are indices
/// into the slot table from 0 upward, so the waker takes the top of
/// the usize range.
const WAKER_TOKEN: Token = Token(usize::MAX);

/// Read buffer per session — the same size the session threads used.
const READ_BUF: usize = 8192;

/// Minimum wall time between maintenance sweeps. Timer-generated
/// output (KEEPALIVEs, retransmissions) is queued by the ticker
/// thread's 50 ms `tick`, so a 50 ms sweep cadence flushes it with at
/// most one tick of latency. A busy event stream never delays the
/// sweep past this interval: the loop checks the clock on every
/// wakeup, event-driven or timeout.
const SWEEP_INTERVAL: Duration = Duration::from_millis(50);

/// `poll` timeout when nothing is readable: the liveness ceiling for
/// the sweep. Readable data wakes the reactor immediately; this only
/// bounds the worst case between events.
const POLL_TIMEOUT: Duration = SWEEP_INTERVAL;

/// Why a session ended — the structured form of the error strings the
/// old session pump returned. The connector's backoff ladder and the
/// listener's error log key off this instead of string matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionEnd {
    /// The peer closed the connection (`read` returned 0).
    PeerClosed,
    /// A transport or FSM-feed error; carries the pump's message
    /// (`"read: …"`, `"write: …"`, `"feed_input: …"`).
    TransportError(String),
    /// A BFD session transitioned Up to Down (RFC 5880 §6.8.4 — the
    /// whole point of `--bfd`).
    BfdDown,
    /// The router closed the session while the TCP connection was
    /// alive (the FSM reached Idle from the router side).
    ClosedByRouter,
    /// The router closed this session as the loser of an RFC 4271
    /// §6.8 connection-collision resolution.
    CollisionLost,
    /// The daemon is shutting down (`running == false`) — the
    /// session-thread equivalent of the pump's `Ok(())`.
    DaemonShutdown,
}

impl SessionEnd {
    /// The operator-facing message — the exact string the session
    /// pump returned for the same condition, so log voices are
    /// unchanged.
    pub(crate) fn message(&self) -> &str {
        match self {
            SessionEnd::PeerClosed => "peer closed connection",
            SessionEnd::TransportError(e) => e.as_str(),
            SessionEnd::BfdDown => "bfd session down",
            SessionEnd::ClosedByRouter => "session closed by the router (FSM Idle)",
            SessionEnd::CollisionLost => "connection lost the RFC 4271 §6.8 collision resolution",
            SessionEnd::DaemonShutdown => "daemon shutdown",
        }
    }

    /// The pump's `Err` equivalent test: every end except the shutdown
    /// is an error-path teardown (`close_session`, not
    /// `shutdown_session`).
    pub(crate) fn is_err_path(&self) -> bool {
        !matches!(self, SessionEnd::DaemonShutdown)
    }
}

/// One live session slot inside the reactor.
struct Slot {
    /// The registered, non-blocking stream.
    stream: MioTcpStream,
    handle: SessionHandle,
    bfd: Option<BfdFlags>,
    /// Last-seen BFD liveness, so only an Up-to-Down *transition*
    /// tears the session (a BFD session that never came up must not
    /// kill BGP — BIRD parity). `None` while there is no BFD binding.
    bfd_up_seen: Option<bool>,
    /// Bytes the socket would not take in one write (send buffer full
    /// mid-UPDATE). Non-empty tail ⇒ the slot also carries WRITABLE
    /// interest; the writable event flushes it.
    pending_out: Vec<u8>,
    /// Next write offset into `pending_out` (a partial flush of a
    /// partial write).
    pending_off: usize,
    /// Bookkeeping the per-session thread owned, run once at teardown:
    /// the listener's busy-guard + live counter, the connector's
    /// completion channel. Taken (moved out) exactly once.
    on_end: Option<Box<dyn FnOnce(SessionEnd) + Send>>,
}

impl Slot {
    /// Queue bytes for the peer; the caller flushes right after and
    /// re-arms interest from [`Slot::interest`].
    fn enqueue(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        // Compact the drained prefix first so the buffer cannot grow
        // unboundedly across many partial flushes.
        if self.pending_off > 0 {
            self.pending_out.drain(..self.pending_off);
            self.pending_off = 0;
        }
        self.pending_out.extend_from_slice(bytes);
    }

    /// Push queued bytes into the socket. Returns `true` when the
    /// queue fully drained (WRITABLE interest can drop), `false` when
    /// bytes remain parked (the send buffer is full — keep WRITABLE).
    /// A hard write error is `Err` — the session ends.
    fn flush(&mut self) -> std::io::Result<bool> {
        while self.pending_off < self.pending_out.len() {
            match self.stream.write(&self.pending_out[self.pending_off..]) {
                // A zero-byte write on a non-blocking socket is a
                // stall, not progress — keep the bytes parked.
                Ok(0) => return Ok(false),
                Ok(n) => self.pending_off += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        self.pending_out.clear();
        self.pending_off = 0;
        Ok(true)
    }

    /// The interest the slot needs right now: READABLE always (the
    /// peer's bytes), WRITABLE only while a partial write is parked.
    fn interest(&self) -> Interest {
        if self.pending_off < self.pending_out.len() {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        }
    }
}

/// A session submission — what the listener and the connectors send
/// through [`BgpReactor::submit`].
struct Submission {
    stream: StdTcpStream,
    handle: SessionHandle,
    bfd: Option<BfdFlags>,
    on_end: Box<dyn FnOnce(SessionEnd) + Send>,
}

/// The reactor handle the daemon holds: a submission channel plus
/// the waker that prods the reactor thread when a submission lands.
/// `Clone` so every connector carries one.
#[derive(Clone)]
pub(crate) struct BgpReactor {
    tx: Sender<Submission>,
    waker: Arc<Waker>,
}

impl BgpReactor {
    /// Start the reactor thread for one daemon. `router` and
    /// `running` are the same `Arc`s the `Runtime` carries, so the
    /// reactor observes the daemon's shutdown exactly like the
    /// session threads did.
    pub(crate) fn spawn(
        router: Arc<RwLock<DefaultRouter>>,
        running: Arc<AtomicBool>,
    ) -> BgpReactor {
        let (tx, rx) = mpsc::channel::<Submission>();
        let poll = Poll::new().expect("mio::Poll::new");
        let registry = poll.registry().try_clone().expect("mio registry clone");
        let waker = Waker::new(&registry, WAKER_TOKEN).expect("mio::Waker::new");
        let waker = Arc::new(waker);
        thread::Builder::new()
            .name("lr-bgp-reactor".into())
            .spawn(move || reactor_main(poll, rx, router, running))
            .expect("spawn lr-bgp-reactor thread");
        BgpReactor { tx, waker }
    }

    /// Submit one established TCP connection for event-driven
    /// pumping. The socket must be fully connected (a listener accept
    /// or a connector dial); the reactor switches it to non-blocking
    /// itself so a submitter can never forget.
    ///
    /// `on_end` runs exactly once, on the reactor thread, when the
    /// session ends (peer close, transport error, BFD down,
    /// router-closed collision loss, or daemon shutdown) — after the
    /// router state is closed and after the socket's final bytes are
    /// flushed. It must be quick (atomics, a channel send): the whole
    /// reactor stalls behind it.
    pub(crate) fn submit(
        &self,
        stream: StdTcpStream,
        handle: SessionHandle,
        bfd: Option<BfdFlags>,
        on_end: Box<dyn FnOnce(SessionEnd) + Send>,
    ) -> Result<(), String> {
        self.tx
            .send(Submission {
                stream,
                handle,
                bfd,
                on_end,
            })
            .map_err(|_| "reactor thread is gone".to_string())?;
        self.waker.wake().map_err(|e| format!("waker: {e}"))
    }
}

/// The reactor thread body: the event loop, the slot table, the
/// maintenance sweep and the shutdown pass. One thread drives every
/// session.
fn reactor_main(
    mut poll: Poll,
    rx: Receiver<Submission>,
    router: Arc<RwLock<DefaultRouter>>,
    running: Arc<AtomicBool>,
) {
    let registry: Registry = poll.registry().try_clone().expect("mio registry clone");
    let mut events = Events::with_capacity(1024);
    // Slot table: index == mio Token. Torn-down slots leave holes the
    // free list recycles, so tokens stay dense.
    let mut slots: Vec<Option<Slot>> = Vec::new();
    let mut free: Vec<usize> = Vec::new();
    let mut last_sweep = Instant::now() - SWEEP_INTERVAL;
    let mut read_buf = [0u8; READ_BUF];

    loop {
        // Level-triggered readiness: a readable session keeps
        // reporting until its buffer drains, a parked write keeps
        // reporting WRITABLE until flushed and de-registered.
        // EINTR-style poll errors simply re-loop.
        let _ = poll.poll(&mut events, Some(POLL_TIMEOUT));

        // Waker first: a listener or connector handed us sockets. The
        // registrations are processed before the event pass — the
        // submission is itself the event.
        for event in events.iter() {
            if event.token() == WAKER_TOKEN {
                while let Ok(sub) = rx.try_recv() {
                    register(
                        &mut slots,
                        &mut free,
                        &registry,
                        &router,
                        sub,
                        &mut read_buf,
                    );
                }
            }
        }

        // Readable / writable events for live sessions, in the pump's
        // per-iteration order.
        for event in events.iter() {
            let token = event.token();
            if token == WAKER_TOKEN {
                continue;
            }
            let index = token.0;
            let Some(slot) = slots[index].as_mut() else {
                // A stale token: the slot was torn down between the
                // event being queued and this pass. mio stops a
                // deregistered fd's events after the deregister, so
                // this window is one iteration wide at most.
                continue;
            };
            if let Some(end) = check_bfd_transition(slot) {
                teardown(&mut slots, &mut free, &registry, &router, index, end);
                continue;
            }
            if event.is_readable() {
                if let PumpOutcome::End(end) = pump_readable(slot, &router, &mut read_buf) {
                    teardown(&mut slots, &mut free, &registry, &router, index, end);
                    continue;
                }
            }
            if event.is_writable() {
                match slot.flush() {
                    Ok(true) => {}
                    Ok(false) => {}
                    Err(e) => {
                        // A hard write failure ends the session — the
                        // peer is unreachable at the transport level.
                        teardown(
                            &mut slots,
                            &mut free,
                            &registry,
                            &router,
                            index,
                            SessionEnd::TransportError(format!("write: {e}")),
                        );
                        continue;
                    }
                }
            }
            // Re-arm interest: a partial write parked this round adds
            // WRITABLE; a completed flush drops it.
            let interest = slot.interest();
            let _ = registry.reregister(&mut slot.stream, Token(index), interest);
        }

        // Maintenance sweep — at most one per SWEEP_INTERVAL of wall
        // time, event-driven or timeout, so a busy event stream never
        // starves it. Covers the sessions without events: BFD
        // transitions, timer-generated output, router-side closes.
        if last_sweep.elapsed() >= SWEEP_INTERVAL {
            last_sweep = Instant::now();
            sweep(&mut slots, &mut free, &registry, &router);
        }

        // Daemon shutdown: tear every live session down with the
        // Cease path (shutdown_session) so the peers see the RFC 4486
        // §4.1 notification, then exit the loop. The completion
        // callbacks release the live-session counter the daemon's
        // shutdown grace window waits on.
        if !running.load(Ordering::Relaxed) {
            for index in (0..slots.len()).rev() {
                if slots[index].is_some() {
                    teardown(
                        &mut slots,
                        &mut free,
                        &registry,
                        &router,
                        index,
                        SessionEnd::DaemonShutdown,
                    );
                }
            }
            break;
        }
    }
}

/// Outcome of one readable-event pump pass over a slot.
enum PumpOutcome {
    Continue,
    End(SessionEnd),
}

/// Register a submitted session: start it in the router, flush the
/// FSM's initial output (the OPEN), insert the slot and arm READABLE
/// interest. A `start_session` failure mirrors the old session
/// thread's early `?` return: the completion runs with the error and
/// the socket closes without a session.
fn register(
    slots: &mut Vec<Option<Slot>>,
    free: &mut Vec<usize>,
    registry: &Registry,
    router: &Arc<RwLock<DefaultRouter>>,
    sub: Submission,
    read_buf: &mut [u8],
) {
    let _ = read_buf; // registration reads nothing; kept for shape parity
    let Submission {
        stream,
        handle,
        bfd,
        on_end,
    } = sub;

    // The reactor owns the non-blocking switch so a submitter can
    // never forget it.
    let _ = stream.set_nonblocking(true);
    let mio_stream = MioTcpStream::from_std(stream);

    // start_session, then the initial drain — the same order the old
    // session thread ran before its first pump iteration.
    let out = {
        let mut r = router.write().unwrap();
        if let Err(e) = r.start_session(handle) {
            // The old path: run_peer_session's `?` returned the error
            // before any pump work — no close call ran at all (the
            // session was never started; the connector retries and
            // calls start_session again on the next dial). Match it
            // exactly: close the socket, report, return.
            let msg = format!("start_session: {e}");
            let _ = mio_stream.shutdown(std::net::Shutdown::Both);
            on_end(SessionEnd::TransportError(msg));
            return;
        }
        r.drain_output(handle)
    };

    let index = match free.pop() {
        Some(i) => i, // freed slots are already `None`
        None => {
            slots.push(None);
            slots.len() - 1
        }
    };
    let mut slot = Slot {
        stream: mio_stream,
        handle,
        bfd,
        bfd_up_seen: None,
        pending_out: Vec::new(),
        pending_off: 0,
        on_end: Some(on_end),
    };
    // BFD baseline: seed the last-seen liveness so only a *transition*
    // tears the session later (the first check must not see `None →
    // false` as a transition).
    slot.bfd_up_seen = slot.bfd.as_ref().map(|f| f.up.load(Ordering::Relaxed));
    slot.enqueue(&out);
    match slot.flush() {
        Ok(_) => {}
        Err(e) => {
            // The OPEN could not be written — the transport is dead
            // before the session ever ran. Teardown through the slot
            // so the completion and close path run exactly once.
            slots[index] = Some(slot);
            teardown(
                slots,
                free,
                registry,
                router,
                index,
                SessionEnd::TransportError(format!("write: {e}")),
            );
            return;
        }
    }
    let interest = slot.interest();
    if let Err(e) = registry.register(&mut slot.stream, Token(index), interest) {
        slots[index] = Some(slot);
        teardown(
            slots,
            free,
            registry,
            router,
            index,
            SessionEnd::TransportError(format!("mio register: {e}")),
        );
        return;
    }
    slots[index] = Some(slot);
}

/// Read everything the kernel holds for the session, feed the FSM,
/// drain the router's output and write it to the peer. Mirrors the
/// per-iteration body of the old session pump (minus the signal
/// dispatch, which the daemon's main thread owns).
fn pump_readable(
    slot: &mut Slot,
    router: &Arc<RwLock<DefaultRouter>>,
    read_buf: &mut [u8],
) -> PumpOutcome {
    // 1. Read peer bytes → feed_input. Loop until WouldBlock so the
    //    readable event drains the kernel buffer fully.
    loop {
        match slot.stream.read(read_buf) {
            Ok(0) => return PumpOutcome::End(SessionEnd::PeerClosed),
            Ok(n) => {
                let mut r = router.write().unwrap();
                if let Err(e) = r.feed_input(slot.handle, &read_buf[..n]) {
                    return PumpOutcome::End(SessionEnd::TransportError(format!(
                        "feed_input: {e}"
                    )));
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => return PumpOutcome::End(SessionEnd::TransportError(format!("read: {e}"))),
        }
    }

    // 2. Drain router output → write to peer, and check the
    //    router-side close / collision latch — one write-lock
    //    acquisition, the pump's step order.
    let (out, closed, lost) = {
        let mut r = router.write().unwrap();
        let out = r.drain_output(slot.handle);
        let closed = r.session_peer_state(slot.handle) == Some("Idle");
        let lost = if closed {
            r.take_collision_lost(slot.handle)
        } else {
            false
        };
        (out, closed, lost)
    };
    slot.enqueue(&out);
    if let Err(e) = slot.flush() {
        return PumpOutcome::End(SessionEnd::TransportError(format!("write: {e}")));
    }
    if closed {
        return PumpOutcome::End(if lost {
            SessionEnd::CollisionLost
        } else {
            SessionEnd::ClosedByRouter
        });
    }
    PumpOutcome::Continue
}

/// Check the BFD Up-to-Down transition for a slot. `Some(end)` means
/// the session must tear down now.
fn check_bfd_transition(slot: &mut Slot) -> Option<SessionEnd> {
    let flags = slot.bfd.as_ref()?;
    let up = flags.up.load(Ordering::Relaxed);
    let seen = slot.bfd_up_seen;
    slot.bfd_up_seen = Some(up);
    if seen == Some(true) && !up {
        return Some(SessionEnd::BfdDown);
    }
    None
}

/// One maintenance pass over every live slot: BFD transitions,
/// timer-generated output flush, router-side closes. One write-lock
/// acquisition per slot for the drain (matching the pump's cadence);
/// writes happen after the lock releases.
fn sweep(
    slots: &mut [Option<Slot>],
    free: &mut Vec<usize>,
    registry: &Registry,
    router: &Arc<RwLock<DefaultRouter>>,
) {
    for index in 0..slots.len() {
        let Some(slot) = slots[index].as_mut() else {
            continue;
        };
        if let Some(end) = check_bfd_transition(slot) {
            teardown(slots, free, registry, router, index, end);
            continue;
        }
        let (out, closed, lost) = {
            let mut r = router.write().unwrap();
            let out = r.drain_output(slot.handle);
            let closed = r.session_peer_state(slot.handle) == Some("Idle");
            let lost = if closed {
                r.take_collision_lost(slot.handle)
            } else {
                false
            };
            (out, closed, lost)
        };
        slot.enqueue(&out);
        match slot.flush() {
            Ok(_) => {}
            Err(e) => {
                teardown(
                    slots,
                    free,
                    registry,
                    router,
                    index,
                    SessionEnd::TransportError(format!("write: {e}")),
                );
                continue;
            }
        }
        // Re-arm interest: a partial write parked this round.
        let interest = slot.interest();
        let _ = registry.reregister(&mut slot.stream, Token(index), interest);
        if closed {
            teardown(
                slots,
                free,
                registry,
                router,
                index,
                if lost {
                    SessionEnd::CollisionLost
                } else {
                    SessionEnd::ClosedByRouter
                },
            );
        }
    }
}

/// Tear one session down — the reactor's transcription of
/// `run_peer_session`'s exit path. `reason` selects the RFC 4486
/// §4.1 classification: only the daemon shutdown gets the
/// `shutdown_session` Cease queue; every other end is a
/// `close_session`, so a crash is not reclassified as a deliberate
/// goodbye (which would cost the peer its RFC 4724/9494 retention
/// window).
///
/// The final drain + write flushes whatever the router still holds
/// for the session (the Cease NOTIFICATION on the shutdown path)
/// before the socket closes. The completion callback runs last, off
/// the router lock.
fn teardown(
    slots: &mut [Option<Slot>],
    free: &mut Vec<usize>,
    registry: &Registry,
    router: &Arc<RwLock<DefaultRouter>>,
    index: usize,
    reason: SessionEnd,
) {
    let Some(mut slot) = slots[index].take() else {
        return;
    };
    free.push(index);

    // Final router pass: classify the close, drain the last bytes.
    let out = {
        let mut r = router.write().unwrap();
        if reason.is_err_path() {
            r.close_session(slot.handle);
        } else {
            r.shutdown_session(slot.handle);
        }
        r.drain_output(slot.handle)
    };

    // Deregister before the socket goes away so no stale token fires
    // on the next poll.
    let _ = registry.deregister(&mut slot.stream);

    // Best-effort flush of the final bytes (the Cease on the shutdown
    // path; a queued NOTIFICATION on an error path). Non-blocking
    // write — the socket is about to close either way.
    if !out.is_empty() {
        let _ = slot.stream.write_all(&out);
    }
    let _ = slot.stream.shutdown(std::net::Shutdown::Both);
    drop(slot.stream);

    if let Some(on_end) = slot.on_end.take() {
        on_end(reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::{Asn, RouterId};
    use lr_router::SessionConfig;
    use std::sync::mpsc::Receiver;

    /// A connected loopback TCP pair (the "peer" end plus the socket
    /// the reactor will own). Works on every platform — no BGP peer
    /// needed, just transport semantics.
    fn loopback_pair() -> (StdTcpStream, StdTcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = StdTcpStream::connect(addr).unwrap();
        let server = listener.accept().unwrap().0;
        (client, server)
    }

    /// One BGP session in a fresh router, ready to be started.
    fn bgp_session(router: &mut DefaultRouter) -> SessionHandle {
        router
            .add_session(SessionConfig::bgp(
                Asn(64512),
                Asn(64513),
                RouterId::from_v4([10, 0, 0, 1]),
            ))
            .unwrap()
    }

    /// The pump's exact message strings — the connector's backoff
    /// classification previously string-matched the collision marker,
    /// and the log voices must stay unchanged.
    #[test]
    fn session_end_messages_match_the_pump_strings() {
        assert_eq!(SessionEnd::PeerClosed.message(), "peer closed connection");
        assert_eq!(
            SessionEnd::TransportError("read: x".into()).message(),
            "read: x"
        );
        assert_eq!(SessionEnd::BfdDown.message(), "bfd session down");
        assert_eq!(
            SessionEnd::ClosedByRouter.message(),
            "session closed by the router (FSM Idle)"
        );
        assert_eq!(
            SessionEnd::CollisionLost.message(),
            "connection lost the RFC 4271 §6.8 collision resolution"
        );
    }

    /// Only the daemon shutdown takes the non-error teardown path —
    /// every other end is a `close_session`, preserving the peer's
    /// RFC 4724/9494 retention window.
    #[test]
    fn only_shutdown_is_the_err_free_path() {
        assert!(!SessionEnd::DaemonShutdown.is_err_path());
        assert!(SessionEnd::PeerClosed.is_err_path());
        assert!(SessionEnd::BfdDown.is_err_path());
        assert!(SessionEnd::ClosedByRouter.is_err_path());
        assert!(SessionEnd::CollisionLost.is_err_path());
        assert!(SessionEnd::TransportError("x".into()).is_err_path());
    }

    /// `enqueue` compacts the drained prefix so a long-lived partial
    /// write cannot grow the buffer unboundedly.
    #[test]
    fn enqueue_compacts_the_drained_prefix() {
        let (_client, server) = loopback_pair();
        server.set_nonblocking(true).unwrap();
        let stream = MioTcpStream::from_std(server);
        let mut slot = Slot {
            stream,
            handle: SessionHandle(1),
            bfd: None,
            bfd_up_seen: None,
            pending_out: vec![1u8; 10],
            pending_off: 5,
            on_end: None,
        };
        // 5 of 10 bytes already flushed; 3 new bytes arrive.
        slot.enqueue(&[7, 7, 7]);
        assert_eq!(slot.pending_off, 0, "offset reset by compaction");
        assert_eq!(
            slot.pending_out,
            vec![1, 1, 1, 1, 1, 7, 7, 7],
            "buffer is [drained tail, new bytes]"
        );
        // Empty enqueue is a no-op (the drain_output fast path).
        slot.enqueue(&[]);
        assert_eq!(slot.pending_out.len(), 8);
    }

    /// A parked write holds WRITABLE interest; a drained queue holds
    /// only READABLE.
    #[test]
    fn interest_tracks_the_parked_write() {
        let (_client, server) = loopback_pair();
        server.set_nonblocking(true).unwrap();
        let stream = MioTcpStream::from_std(server);
        let mut slot = Slot {
            stream,
            handle: SessionHandle(1),
            bfd: None,
            bfd_up_seen: None,
            pending_out: Vec::new(),
            pending_off: 0,
            on_end: None,
        };
        assert_eq!(slot.interest(), Interest::READABLE);
        slot.pending_out = vec![1u8; 4];
        slot.pending_off = 2;
        assert_eq!(slot.interest(), Interest::READABLE | Interest::WRITABLE);
    }

    /// Full path: submit a session, the peer closes its end, the
    /// reactor reports `PeerClosed` through the completion callback.
    #[test]
    fn peer_close_ends_the_session() {
        let router = Arc::new(RwLock::new(DefaultRouter::new()));
        let running = Arc::new(AtomicBool::new(true));
        let handle = bgp_session(&mut router.write().unwrap());

        let (client, server) = loopback_pair();
        let reactor = BgpReactor::spawn(Arc::clone(&router), Arc::clone(&running));
        let (tx, rx) = mpsc::channel();
        reactor
            .submit(
                server,
                handle,
                None,
                Box::new(move |end| {
                    tx.send(end).unwrap();
                }),
            )
            .unwrap();
        // The peer hangs up immediately.
        drop(client);
        let end = recv_end(rx);
        assert_eq!(end, SessionEnd::PeerClosed);
        running.store(false, Ordering::Relaxed);
    }

    /// Daemon shutdown: the reactor tears the live session down with
    /// the `shutdown_session` Cease path and reports
    /// `DaemonShutdown` — the pump's `Ok(())` equivalent.
    #[test]
    fn daemon_shutdown_tears_the_session_down_with_cease() {
        let router = Arc::new(RwLock::new(DefaultRouter::new()));
        let running = Arc::new(AtomicBool::new(true));
        let handle = bgp_session(&mut router.write().unwrap());

        let (_client, server) = loopback_pair();
        let reactor = BgpReactor::spawn(Arc::clone(&router), Arc::clone(&running));
        let (tx, rx) = mpsc::channel();
        reactor
            .submit(
                server,
                handle,
                None,
                Box::new(move |end| {
                    tx.send(end).unwrap();
                }),
            )
            .unwrap();
        // The peer stays connected (its socket stays open).
        running.store(false, Ordering::Relaxed);
        let end = recv_end(rx);
        assert_eq!(end, SessionEnd::DaemonShutdown);
    }

    fn recv_end(rx: Receiver<SessionEnd>) -> SessionEnd {
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the completion callback fired")
    }
}
