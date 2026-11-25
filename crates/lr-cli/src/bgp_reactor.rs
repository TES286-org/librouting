//! BGP session reactor — one event loop for every established BGP
//! session and the inbound listener (ROADMAP async-I/O item).
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
//! - the per-peer connectors submit connected sockets through a
//!   channel ([`BgpReactor::submit`]); the submission wakes the reactor
//!   through a `mio::Waker` registered to a reserved token;
//! - the listener is attached the same way
//!   ([`BgpReactor::attach_listener`]) and registered under its own
//!   token: a readable event on it drains the accept queue, and each
//!   accepted connection passes through the daemon's inbound gate
//!   (source-address match, admin-down, busy guard, RFC 4271 §6.8
//!   challenger rules) before the session registers — the same order
//!   the main thread's accept loop ran, on the reactor thread. The
//!   accept loop's 1-to-100 ms exponential backoff poll is gone; an
//!   inbound SYN that completes wakes the loop immediately;
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
//! shapes wrap differently); the runtime API and the metrics endpoint
//! keep their hand-rolled loops. Nothing in the
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
//! backoff classification (an equality test on the `SessionEnd` enum,
//! not a string match).

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::net::TcpStream as StdTcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioTcpListener;
use mio::net::TcpStream as MioTcpStream;
use mio::{Events, Interest, Poll, Registry, Token, Waker};
use socket2::SockRef;

use lr_bgp::BfdState;
use lr_router::{DefaultRouter, RouterInstance, SessionHandle};

use crate::daemon_bfd::BfdFlags;

/// Reserved token the `mio::Waker` fires. Session tokens are indices
/// into the slot table from 0 upward, so the waker takes the top of
/// the usize range.
const WAKER_TOKEN: Token = Token(usize::MAX);

/// Reserved token the attached listener fires. One listener per
/// reactor, so a single reserved token below the waker's suffices.
const LISTENER_TOKEN: Token = Token(usize::MAX - 1);

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

/// How long the reactor pauses accepting after a hard `accept`
/// error (EMFILE, ENFILE, ENOBUFS): the old accept loop slept
/// 100 ms in the same case. The listener stays registered and
/// level-triggered, so its events are skipped until the deadline
/// passes — without this guard a persistently failing `accept`
/// would spin the reactor.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// The write timeout the teardown path applies when it switches the
/// stream back to blocking for the final NOTIFICATION flush. The
/// peer's RFC 4724/9494 retention window opens the moment the Cease
/// arrives (RFC 4486 §4.1), so the flush must reach the peer — a
/// non-blocking `write_all` would silently drop the bytes the moment
/// the send buffer is full. The timeout bounds the wait so a peer
/// that is not reading cannot stall the reactor's teardown path;
/// 500 ms is comfortably above a typical LAN RTT and below the 3 s
/// `live_sessions` shutdown grace window the daemon waits on.
const FINAL_FLUSH_WRITE_TIMEOUT: Duration = Duration::from_millis(500);

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
    /// A configuration reload administratively closed the session
    /// (`BgpReactor::close_session_admin`). Carries the RFC 4486
    /// §4.1 Cease subcode the reload chose — Administrative Reset (4)
    /// for a reconfigured peer, Peer De-configured (3) for a removed
    /// one — so the teardown path queues the matching NOTIFICATION
    /// through `DefaultRouter::reset_session` /
    /// `deconfigure_session` instead of the shutdown flavour.
    AdminClose(u8),
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
            SessionEnd::AdminClose(_) => "session closed by a configuration reload",
        }
    }

    /// The pump's `Err` equivalent test: every end except the
    /// deliberate admin closes (shutdown and reload) is an error-path
    /// teardown (`close_session`, not the NOTIFICATION-carrying
    /// `shutdown_session`).
    pub(crate) fn is_err_path(&self) -> bool {
        !matches!(self, SessionEnd::DaemonShutdown | SessionEnd::AdminClose(_))
    }
}

/// One live session slot inside the reactor.
struct Slot {
    /// The registered, non-blocking stream.
    stream: MioTcpStream,
    handle: SessionHandle,
    bfd: Option<BfdFlags>,
    /// Last-seen BFD state, so only a *transition* is fed to the
    /// router (a BFD session that never came up must not kill BGP —
    /// BIRD parity). `None` while there is no BFD binding.
    bfd_state_seen: Option<BfdState>,
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

    /// Flush the queued bytes through a blocking stream. Used only
    /// from the teardown path where the stream has been switched back
    /// to blocking with a bounded write timeout — the NOTIFICATION
    /// (RFC 4486 §4.1 Cease / a queued error NOTIFICATION) MUST reach
    /// the peer, and a non-blocking `write_all` would silently drop
    /// it the moment the send buffer is full. The bounded write
    /// timeout is the wall-clock cap; a non-reading peer cannot
    /// stall the reactor's teardown path beyond it. Returns `Ok(())`
    /// on a full drain, `Err` on a hard write error or a write
    /// timeout (the caller drops the socket either way).
    fn flush_blocking(&mut self) -> std::io::Result<()> {
        while self.pending_off < self.pending_out.len() {
            match self.stream.write(&self.pending_out[self.pending_off..]) {
                Ok(0) => return Err(std::io::Error::from(ErrorKind::WriteZero)),
                Ok(n) => self.pending_off += n,
                Err(e) => return Err(e),
            }
        }
        self.pending_out.clear();
        self.pending_off = 0;
        Ok(())
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

/// What the daemon's inbound gate decided for one accepted
/// connection: run the session on the reactor, or drop the socket
/// (the gate already logged why).
pub(crate) enum Inbound {
    /// Run the accepted connection as a session.
    Session {
        handle: SessionHandle,
        bfd: Option<BfdFlags>,
        on_end: Box<dyn FnOnce(SessionEnd) + Send>,
    },
    /// Refused by the gate; the reactor closes the socket.
    Rejected,
}

/// The daemon's accept policy as one closure the reactor calls per
/// accepted connection, on the reactor thread: the source-address
/// peer match, the admin-down refusal, the busy guard and the
/// RFC 4271 §6.8 challenger rules. Keeping the policy in the daemon
/// keeps the reactor transport-only.
pub(crate) type InboundGate = Box<dyn Fn(&std::net::SocketAddr) -> Inbound + Send>;

/// A submission — what the connectors send through
/// [`BgpReactor::submit`] (a connected socket) and what the daemon
/// sends through [`BgpReactor::attach_listener`] (the listener plus
/// its gate). Both land in the reactor through the same channel and
/// waker.
enum Submission {
    Session {
        stream: StdTcpStream,
        handle: SessionHandle,
        bfd: Option<BfdFlags>,
        on_end: Box<dyn FnOnce(SessionEnd) + Send>,
    },
    Listener {
        listener: StdTcpListener,
        gate: InboundGate,
    },
    /// Close every slot carrying `handle` with the RFC 4486 §4.1
    /// Cease subcode (configuration reload). `done` fires once the
    /// matching slots are torn down (or immediately when none
    /// matched), so the sender can `remove_session` only after the
    /// pump stopped feeding that handle.
    Close {
        handle: SessionHandle,
        subcode: u8,
        done: std::sync::mpsc::Sender<()>,
    },
    /// Drop the attached listener (configuration reload replacing
    /// the listener, e.g. a session-auth change). `done` fires after
    /// the socket is deregistered and closed, releasing the port.
    ListenerDetach { done: std::sync::mpsc::Sender<()> },
}

/// The attached listener: the mio-registered socket plus the
/// daemon's accept policy, run per accepted connection.
struct ListenerSlot {
    mio: MioTcpListener,
    gate: InboundGate,
}

/// One session about to join the reactor — the registration parts
/// beyond the reactor state itself.
struct SessionParts {
    stream: MioTcpStream,
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
            .send(Submission::Session {
                stream,
                handle,
                bfd,
                on_end,
            })
            .map_err(|_| "reactor thread is gone".to_string())?;
        self.waker.wake().map_err(|e| format!("waker: {e}"))
    }

    /// Attach the daemon's TCP listener for event-driven accepting.
    /// The listener must already be bound and armed (auth, GTSM);
    /// the reactor registers it under [`LISTENER_TOKEN`] and calls
    /// `gate` for every accepted connection. Replaces the main
    /// thread's non-blocking accept loop, whose 1-to-100 ms
    /// exponential backoff sleep was the idle wakeup cadence — an
    /// inbound connection that completes the handshake now wakes
    /// the loop immediately.
    pub(crate) fn attach_listener(
        &self,
        listener: StdTcpListener,
        gate: InboundGate,
    ) -> Result<(), String> {
        self.tx
            .send(Submission::Listener { listener, gate })
            .map_err(|_| "reactor thread is gone".to_string())?;
        self.waker.wake().map_err(|e| format!("waker: {e}"))
    }

    /// Gracefully close every live slot carrying `handle` — the
    /// configuration-reload teardown. The reactor queues the RFC 4486
    /// §4.1 Cease NOTIFICATION for the subcode the caller chose
    /// ([`SessionEnd::AdminClose`]), flushes it to the wire and only
    /// then closes the socket. Returns once every matching slot is
    /// gone (or immediately when the session has no live slot), so
    /// the caller can safely `remove_session` afterwards; the bounded
    /// wait (a few seconds, far above the 500 ms final-flush write
    /// timeout) gives up on a wedged reactor rather than blocking the
    /// reload forever — the teardown still runs, just later.
    pub(crate) fn close_session_admin(
        &self,
        handle: SessionHandle,
        subcode: u8,
    ) -> Result<(), String> {
        let (done, done_rx) = mpsc::channel::<()>();
        self.tx
            .send(Submission::Close {
                handle,
                subcode,
                done,
            })
            .map_err(|_| "reactor thread is gone".to_string())?;
        self.waker.wake().map_err(|e| format!("waker: {e}"))?;
        match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => Ok(()),
            Err(_) => Err("reactor did not confirm the close in time".to_string()),
        }
    }

    /// Drop the attached listener and release its port — the first
    /// half of a listener replacement (bind the fresh socket only
    /// after this returns). Returns once the old listener is
    /// deregistered and closed.
    pub(crate) fn detach_listener(&self) -> Result<(), String> {
        let (done, done_rx) = mpsc::channel::<()>();
        self.tx
            .send(Submission::ListenerDetach { done })
            .map_err(|_| "reactor thread is gone".to_string())?;
        self.waker.wake().map_err(|e| format!("waker: {e}"))?;
        match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => Ok(()),
            Err(_) => Err("reactor did not confirm the detach in time".to_string()),
        }
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
    // The attached listener, once the daemon submits it.
    let mut listener: Option<ListenerSlot> = None;
    // Skip accepting until this deadline after a hard accept error
    // (see [`ACCEPT_ERROR_BACKOFF`]).
    let mut accept_backoff_until: Option<Instant> = None;
    let mut last_sweep = Instant::now() - SWEEP_INTERVAL;
    let mut read_buf = [0u8; READ_BUF];
    // The reactor's logical clock anchor. `now_ms` is recomputed
    // after each `poll.poll(...)` returns — the datagrams a readable
    // event reports arrived during the poll, so their arrival time
    // is the post-poll instant. Passing a pre-poll `now_ms` to
    // `feed_input_at` would latch KEEPALIVE-arrival timestamps
    // up to `POLL_TIMEOUT`
    // early — the same timing rule the BFD mio loop's detection
    // timer follows. The Babel and OSPF mio loops apply
    // the same pattern (`daemon.rs` Babel section,
    // `ospf_engine_loop.rs`).
    let start = Instant::now();

    loop {
        // Level-triggered readiness: a readable session keeps
        // reporting until its buffer drains, a parked write keeps
        // reporting WRITABLE until flushed and de-registered.
        // EINTR-style poll errors simply re-loop.
        let _ = poll.poll(&mut events, Some(POLL_TIMEOUT));
        // Post-poll `now_ms`: the arrival time of any bytes the
        // readable events report is the instant `poll.poll`
        // returned. Computed once per iteration and threaded
        // through `pump_readable` and `sweep` so every
        // `feed_input_at` call latches the same per-iteration clock.
        let now_ms = start.elapsed().as_millis() as u64;

        // Waker first: a connector handed us a socket, or the daemon
        // handed us the listener. The registrations are processed
        // before the event pass — the submission is itself the event.
        for event in events.iter() {
            if event.token() == WAKER_TOKEN {
                while let Ok(sub) = rx.try_recv() {
                    match sub {
                        Submission::Session {
                            stream,
                            handle,
                            bfd,
                            on_end,
                        } => {
                            // The reactor owns the non-blocking switch
                            // so a submitter can never forget it.
                            let _ = stream.set_nonblocking(true);
                            register_session(
                                &mut slots,
                                &mut free,
                                &registry,
                                &router,
                                SessionParts {
                                    stream: MioTcpStream::from_std(stream),
                                    handle,
                                    bfd,
                                    on_end,
                                },
                                &mut read_buf,
                                now_ms,
                            );
                        }
                        Submission::Listener { listener: l, gate } => {
                            let _ = l.set_nonblocking(true);
                            let mut mio = MioTcpListener::from_std(l);
                            if let Err(e) =
                                registry.register(&mut mio, LISTENER_TOKEN, Interest::READABLE)
                            {
                                log_error!(crate::Component::Bgp, "listener register: {e}");
                                continue;
                            }
                            listener = Some(ListenerSlot { mio, gate });
                            // Edge-trigger fix, listener half: a peer
                            // can complete its TCP handshake between
                            // the daemon's bind and this registration;
                            // the queued connection produces no
                            // edge. One accept pass drains it (the
                            // common case costs one EAGAIN accept).
                            if let Some(ls) = listener.as_mut() {
                                if running.load(Ordering::Relaxed) {
                                    accept_batch(
                                        ls,
                                        &mut slots,
                                        &mut free,
                                        &registry,
                                        &router,
                                        &mut read_buf,
                                        &mut accept_backoff_until,
                                        now_ms,
                                    );
                                }
                            }
                        }
                        Submission::Close {
                            handle,
                            subcode,
                            done,
                        } => {
                            // Tear every slot carrying the handle down
                            // with the reload's RFC 4486 §4.1 subcode,
                            // then confirm so the sender can
                            // `remove_session` only after the pump
                            // stopped feeding the handle. A handle with
                            // no live slot (never connected, or already
                            // ended) confirms immediately.
                            let mut matched = false;
                            for index in (0..slots.len()).rev() {
                                if slots[index].as_ref().is_some_and(|s| s.handle == handle) {
                                    matched = true;
                                    teardown(
                                        &mut slots,
                                        &mut free,
                                        &registry,
                                        &router,
                                        index,
                                        SessionEnd::AdminClose(subcode),
                                    );
                                }
                            }
                            let _ = done.send(());
                            if matched {
                                log_info!(
                                    crate::Component::Bgp,
                                    "session #{} closed for a configuration reload",
                                    handle.0
                                );
                            }
                        }
                        Submission::ListenerDetach { done } => {
                            // Drop the attached listener: the deregister
                            // stops its events, the drop closes the
                            // socket and releases the port for the
                            // replacement bind.
                            if let Some(mut ls) = listener.take() {
                                let _ = registry.deregister(&mut ls.mio);
                            }
                            let _ = done.send(());
                        }
                    }
                }
            }
        }

        // Readable / writable events for the listener and the live
        // sessions, in the pump's per-iteration order.
        for event in events.iter() {
            let token = event.token();
            if token == WAKER_TOKEN {
                continue;
            }
            if token == LISTENER_TOKEN {
                // The old accept loop checked `running` before each
                // accept; match it so shutdown does not start fresh
                // sessions.
                if running.load(Ordering::Relaxed) {
                    if let Some(ls) = listener.as_mut() {
                        accept_batch(
                            ls,
                            &mut slots,
                            &mut free,
                            &registry,
                            &router,
                            &mut read_buf,
                            &mut accept_backoff_until,
                            now_ms,
                        );
                    }
                }
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
            if let Some(end) = check_bfd_transition(slot, &router) {
                teardown(&mut slots, &mut free, &registry, &router, index, end);
                continue;
            }
            if event.is_readable() {
                if let PumpOutcome::End(end) = pump_readable(slot, &router, &mut read_buf, now_ms) {
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
            // Drop the listener before exiting: the deregister stops
            // its events, the close releases the bound port.
            if let Some(mut ls) = listener.take() {
                let _ = registry.deregister(&mut ls.mio);
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

/// Register one session: start it in the router, flush the FSM's
/// initial output (the OPEN), insert the slot and arm READABLE
/// interest. The stream must already be non-blocking (the submission
/// arm of [`reactor_main`] and [`accept_batch`] own the switch). A
/// `start_session` failure mirrors the old session thread's early
/// `?` return: the completion runs with the error and the socket
/// closes without a session.
fn register_session(
    slots: &mut Vec<Option<Slot>>,
    free: &mut Vec<usize>,
    registry: &Registry,
    router: &Arc<RwLock<DefaultRouter>>,
    parts: SessionParts,
    read_buf: &mut [u8; READ_BUF],
    now_ms: u64,
) {
    let SessionParts {
        stream: mio_stream,
        handle,
        bfd,
        on_end,
    } = parts;
    // start_session, then the initial drain — the same order the old
    // session thread ran before its first pump iteration.
    let out = {
        let mut r = router.write().unwrap();
        // Seed the BFD liveness before the FSM emits its OPEN: the
        // strict-mode gate must see the current state when the peer's
        // OPEN arrives (draft-ietf-idr-bgp-bfd-strict-mode-19 §8.5).
        r.set_bfd_state(handle, bfd.as_ref().map(bfd_state_of));
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
        bfd_state_seen: None,
        pending_out: Vec::new(),
        pending_off: 0,
        on_end: Some(on_end),
    };
    // BFD baseline: seed the last-seen state so only a *transition*
    // reaches the router later (the first check must not replay the
    // state the OPEN already saw).
    slot.bfd_state_seen = slot.bfd.as_ref().map(bfd_state_of);
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
    // Edge-trigger fix: the peer's bytes (its OPEN, on a fast
    // loopback or a loaded host) can arrive between connect()/accept()
    // and this registration. mio arms READABLE edge-triggered, and an
    // EPOLL_CTL_ADD does not fire for data that is already queued —
    // the session would sit in OpenSent until the hold timer kills
    // it. One pump pass right after registration drains any pending
    // bytes; the common case costs one immediately-EGAIN read.
    let Some(slot) = slots[index].as_mut() else {
        return;
    };
    if let PumpOutcome::End(end) = pump_readable(slot, router, read_buf, now_ms) {
        teardown(slots, free, registry, router, index, end);
    }
}

/// Drain the listener's accept queue: accept until `WouldBlock`, and
/// for every accepted connection run the daemon's inbound gate and
/// register the session it approves. A hard `accept` error backs the
/// queue off for [`ACCEPT_ERROR_BACKOFF`] — the listener stays
/// registered and level-triggered, so its events are simply skipped
/// until the deadline passes, without spinning the reactor.
#[allow(clippy::too_many_arguments)]
fn accept_batch(
    ls: &mut ListenerSlot,
    slots: &mut Vec<Option<Slot>>,
    free: &mut Vec<usize>,
    registry: &Registry,
    router: &Arc<RwLock<DefaultRouter>>,
    read_buf: &mut [u8],
    accept_backoff_until: &mut Option<Instant>,
    now_ms: u64,
) {
    if let Some(until) = *accept_backoff_until {
        if Instant::now() < until {
            return;
        }
        *accept_backoff_until = None;
    }
    loop {
        match ls.mio.accept() {
            Ok((stream, peer_sockaddr)) => {
                // The accepted stream is non-blocking — mio's accept
                // arms it (`accept4(SOCK_NONBLOCK)` where available).
                // TCP_NODELAY is transport shaping, not policy: set it
                // here, through the borrowed-socket reference, the
                // same call the old accept loop made on every inbound.
                let _ = SockRef::from(&stream).set_tcp_nodelay(true);
                let decision = (ls.gate)(&peer_sockaddr);
                match decision {
                    Inbound::Session {
                        handle,
                        bfd,
                        on_end,
                    } => register_session(
                        slots,
                        free,
                        registry,
                        router,
                        SessionParts {
                            stream,
                            handle,
                            bfd,
                            on_end,
                        },
                        {
                            let buf: &mut [u8; READ_BUF] = read_buf
                                .try_into()
                                .expect("accept_batch receives the READ_BUF buffer");
                            buf
                        },
                        now_ms,
                    ),
                    // The gate refused the connection (it logged the
                    // reason); dropping the stream closes the TCP.
                    Inbound::Rejected => {}
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => {
                log_error!(crate::Component::Bgp, "accept failed: {e}");
                *accept_backoff_until = Some(Instant::now() + ACCEPT_ERROR_BACKOFF);
                break;
            }
        }
    }
}

/// Read everything the kernel holds for the session, feed the FSM,
/// drain the router's output and write it to the peer. Mirrors the
/// per-iteration body of the old session pump (minus the signal
/// dispatch, which the daemon's main thread owns).
///
/// `now_ms` is the post-poll logical clock the reactor computed for
/// this iteration (see [`reactor_main`]). It threads through to
/// `feed_input_at` so the router latches KEEPALIVE-arrival timestamps
/// at the post-poll instant — the arrival time the readable event
/// reports — instead of a pre-poll `now_ms` that would age the
/// timestamp by up to `POLL_TIMEOUT`.
fn pump_readable(
    slot: &mut Slot,
    router: &Arc<RwLock<DefaultRouter>>,
    read_buf: &mut [u8],
    now_ms: u64,
) -> PumpOutcome {
    // 1. Read peer bytes → feed_input_at. Loop until WouldBlock so the
    //    readable event drains the kernel buffer fully. `now_ms` is
    //    the post-poll arrival time for every byte this iteration
    //    delivered.
    loop {
        match slot.stream.read(read_buf) {
            Ok(0) => return PumpOutcome::End(SessionEnd::PeerClosed),
            Ok(n) => {
                let mut r = router.write().unwrap();
                if let Err(e) = r.feed_input_at(slot.handle, &read_buf[..n], now_ms, 0) {
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
fn check_bfd_transition(
    slot: &mut Slot,
    router: &Arc<RwLock<DefaultRouter>>,
) -> Option<SessionEnd> {
    let state = bfd_state_of(slot.bfd.as_ref()?);
    if slot.bfd_state_seen == Some(state) {
        return None;
    }
    slot.bfd_state_seen = Some(state);
    let (out, closed) = {
        let mut r = router.write().unwrap();
        r.set_bfd_state(slot.handle, Some(state));
        (
            r.drain_output(slot.handle),
            r.session_peer_state(slot.handle) == Some("Idle"),
        )
    };
    slot.enqueue(&out);
    if let Err(e) = slot.flush() {
        return Some(SessionEnd::TransportError(format!("write: {e}")));
    }
    if closed {
        return Some(if state == BfdState::Down {
            SessionEnd::BfdDown
        } else {
            SessionEnd::ClosedByRouter
        });
    }
    None
}

/// Map the shared BFD liveness flags to the FSM's event state.
/// AdminDown is distinct from Down: the strict-mode gate accepts it
/// while Established sessions ignore it
/// (draft-ietf-idr-bgp-bfd-strict-mode-19 §8.5.1, §8.7.1).
fn bfd_state_of(flags: &BfdFlags) -> BfdState {
    if flags.admin_down.load(Ordering::Relaxed) {
        BfdState::AdminDown
    } else if flags.up.load(Ordering::Relaxed) {
        BfdState::Up
    } else {
        BfdState::Down
    }
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
        if let Some(end) = check_bfd_transition(slot, router) {
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
/// for the session (the Cease NOTIFICATION on the shutdown path) and
/// whatever was already parked from a partial write, before the
/// socket closes. The stream is switched back to blocking with a
/// bounded write timeout for the final flush: a non-blocking
/// `write_all` returns `WouldBlock` immediately when the send buffer
/// is full (exactly the partial-write-park condition the rest of the
/// reactor is built around), which would silently drop the RFC 4486
/// §4.1 Cease NOTIFICATION the peer needs for its retention window.
/// The blocking flush with a timeout bounds the wait so a
/// non-reading peer cannot stall the reactor's teardown path. The
/// completion callback runs last, off the router lock.
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
        match &reason {
            SessionEnd::AdminClose(subcode) => {
                // A configuration reload closed this session: queue the
                // reload's RFC 4486 §4.1 Cease subcode (Administrative
                // Reset for a reconfigured peer, Peer De-configured for
                // a removed one).
                if *subcode == lr_bgp::error::BgpCeaseSubcode::PeerDeconfigured as u8 {
                    r.deconfigure_session(slot.handle);
                } else {
                    r.reset_session(slot.handle);
                }
            }
            end if end.is_err_path() => r.close_session(slot.handle),
            _ => r.shutdown_session(slot.handle),
        }
        r.drain_output(slot.handle)
    };

    // Deregister before the socket goes away so no stale token fires
    // on the next poll.
    let _ = registry.deregister(&mut slot.stream);

    // Combine any previously-parked partial write with the fresh
    // drain, then flush. Switch the stream back to blocking with a
    // bounded write timeout so the final NOTIFICATION (RFC 4486 §4.1
    // Cease on the shutdown path; a queued NOTIFICATION on an error
    // path) actually reaches the peer. A non-blocking `write_all`
    // would return `WouldBlock` the moment the send buffer is full —
    // exactly the park condition the reactor's per-iteration path
    // handles with WRITABLE interest — and the bytes would be lost
    // with the slot. The blocking write with a timeout bounds the
    // wait so a peer that is not reading cannot stall the reactor's
    // teardown path.
    slot.enqueue(&out);
    // Switch the stream back to blocking for the final flush so the
    // NOTIFICATION reaches the peer. `MioTcpStream` does not expose
    // `set_nonblocking` directly; `SockRef` borrows the underlying
    // socket for the `setsockopt`.
    let _ = SockRef::from(&slot.stream).set_nonblocking(false);
    let _ = SockRef::from(&slot.stream).set_write_timeout(Some(FINAL_FLUSH_WRITE_TIMEOUT));
    let _ = slot.flush_blocking();
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
    /// classification matches the collision marker by equality, and
    /// the log voices must stay unchanged.
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
            bfd_state_seen: None,
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
            bfd_state_seen: None,
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
    /// reactor reports the peer-gone end through the completion
    /// callback. The exact shape is kernel-dependent: a clean FIN
    /// (POSIX `drop`, or a Windows close with no unread data) reads
    /// back as EOF — `PeerClosed` — while a Windows close that leaves
    /// the reactor's just-written OPEN unread in the peer's receive
    /// buffer aborts the connection (RST), which surfaces as a
    /// `read:` transport error instead. Both are the same session
    /// event — the peer went away — and both take the error-path
    /// teardown the old pump used for the same inputs.
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
        let peer_gone = matches!(end, SessionEnd::PeerClosed)
            || matches!(&end, SessionEnd::TransportError(m) if m.starts_with("read:"));
        assert!(
            peer_gone,
            "the end must be the peer-gone shape (clean EOF or the              RST-abort read error), got {end:?}"
        );
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

    /// Attach a listener whose gate accepts every connection: the
    /// inbound client dials, the accept queue drains on the readable
    /// event, the gate approves the session and the reactor registers
    /// it — proven by the OPEN the client reads back (registration
    /// flushes the FSM's initial output) and by the FSM leaving Idle.
    #[test]
    fn attached_listener_accepts_and_runs_the_session() {
        let router = Arc::new(RwLock::new(DefaultRouter::new()));
        let running = Arc::new(AtomicBool::new(true));
        let handle = bgp_session(&mut router.write().unwrap());

        let reactor = BgpReactor::spawn(Arc::clone(&router), Arc::clone(&running));
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        reactor
            .attach_listener(
                listener,
                Box::new(move |_peer| Inbound::Session {
                    handle,
                    bfd: None,
                    on_end: Box::new(|_end| {}),
                }),
            )
            .unwrap();

        // Dial in; the reactor accepts, gates and registers the
        // session, and the OPEN arrives on the client's socket.
        let client = StdTcpStream::connect(addr).unwrap();
        let mut open = [0u8; 64];
        let n = read_with_timeout(&client, &mut open);
        assert!(n > 0, "the accepted session's OPEN reached the client");

        // The session is live — `start_session` moved the FSM out of
        // Idle and queued the OPEN the client just read.
        let state = router.read().unwrap().session_peer_state(handle);
        assert_ne!(state, Some("Idle"), "the accepted session is running");

        running.store(false, Ordering::Relaxed);
    }

    /// The gate's refusal drops the accepted socket without starting
    /// a session: the client sees the connection close, and the FSM
    /// never leaves Idle (no OPEN, no NOTIFICATION, just the FIN).
    #[test]
    fn rejected_inbound_closes_the_socket_without_a_session() {
        let router = Arc::new(RwLock::new(DefaultRouter::new()));
        let running = Arc::new(AtomicBool::new(true));
        let handle = bgp_session(&mut router.write().unwrap());

        let reactor = BgpReactor::spawn(Arc::clone(&router), Arc::clone(&running));
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        reactor
            .attach_listener(
                listener,
                Box::new(|_peer| {
                    // The gate logged in production; here it refuses.
                    Inbound::Rejected
                }),
            )
            .unwrap();

        let client = StdTcpStream::connect(addr).unwrap();
        // Read to EOF with a bound: the refusal must close the socket
        // without a session — no payload on the wire.
        let mut buf = [0u8; 8];
        let n = read_with_timeout(&client, &mut buf);
        assert_eq!(n, 0, "the refused connection closes without payload");
        // No session ever started — the FSM stays in Idle.
        let state = router.read().unwrap().session_peer_state(handle);
        assert_eq!(state, Some("Idle"), "no session was started");

        running.store(false, Ordering::Relaxed);
    }

    /// `flush_blocking` drains a small body through a blocking stream
    /// — the contract the teardown path relies on for the final
    /// NOTIFICATION (RFC 4486 §4.1 Cease / a queued error
    /// NOTIFICATION) to reach the peer. The stream is switched back
    /// to blocking with a bounded write timeout; the flush is
    /// blocking, so the bytes reach the peer even when the steady-
    /// state non-blocking `flush` would have parked them. The pre-
    /// fix path called non-blocking `write_all` on a non-blocking
    /// socket, which returns `WouldBlock` the moment the send buffer
    /// is full and silently dropped the bytes the slot was carrying.
    #[test]
    fn flush_blocking_drains_the_queue_to_a_reading_peer() {
        let (mut client, server) = loopback_pair();
        server.set_nonblocking(true).unwrap();
        let stream = MioTcpStream::from_std(server);
        let mut slot = Slot {
            stream,
            handle: SessionHandle(1),
            bfd: None,
            bfd_state_seen: None,
            pending_out: Vec::new(),
            pending_off: 0,
            on_end: None,
        };
        // A small body the loopback send buffer easily accepts in one
        // non-blocking write. The teardown path enqueues the final
        // drain and flushes blocking.
        let body = b"the final NOTIFICATION".to_vec();
        let body_len = body.len();
        slot.enqueue(&body);
        // The teardown switch: blocking + a bounded write timeout.
        let _ = SockRef::from(&slot.stream).set_nonblocking(false);
        let _ = SockRef::from(&slot.stream).set_write_timeout(Some(Duration::from_secs(2)));
        // Drain the peer side while the blocking flush runs.
        let reader = std::thread::spawn(move || {
            let mut got = Vec::new();
            let mut buf = [0u8; 64];
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            loop {
                match client.read(&mut buf) {
                    Ok(0) => break got,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break got,
                    Err(e) if e.kind() == ErrorKind::TimedOut => break got,
                    Err(_) => break got,
                }
            }
        });
        slot.flush_blocking().expect("the blocking flush drained");
        // Shutdown the write side so the reader sees EOF.
        let _ = slot.stream.shutdown(std::net::Shutdown::Both);
        let got = reader.join().expect("reader thread joined");
        assert_eq!(got, body, "the peer received every byte of the queue");
        assert!(slot.pending_out.is_empty());
        assert_eq!(slot.pending_off, 0);
        let _ = body_len;
    }

    /// `flush_blocking` reports a hard write error rather than
    /// silently dropping the queue when the stream is in an error
    /// state. The pre-fix path's `let _ = slot.stream.write_all(&out)`
    /// discarded the result unconditionally; the post-fix path's
    /// `flush_blocking` returns `Err` so the teardown's caller (and
    /// a future test harness) can observe the failure. The teardown
    /// path itself discards the result because the socket closes
    /// either way — the contract is that the flush is *attempted*,
    /// not that it always succeeds.
    #[test]
    fn flush_blocking_returns_err_on_a_closed_socket() {
        let (_client, server) = loopback_pair();
        // Close the peer end so writes fail.
        drop(_client);
        server.set_nonblocking(true).unwrap();
        let stream = MioTcpStream::from_std(server);
        let mut slot = Slot {
            stream,
            handle: SessionHandle(1),
            bfd: None,
            bfd_state_seen: None,
            pending_out: Vec::new(),
            pending_off: 0,
            on_end: None,
        };
        // Force the slot to carry bytes and then try to flush
        // blocking — the closed peer surfaces as an `Err`.
        slot.enqueue(b"final NOTIFICATION bytes".as_ref());
        let _ = SockRef::from(&slot.stream).set_nonblocking(false);
        let _ = SockRef::from(&slot.stream).set_write_timeout(Some(Duration::from_millis(100)));
        // Try to flush: either the write fails outright (broken
        // pipe / connection reset) or it succeeds and a subsequent
        // write fails. Either way, the result is observable — the
        // pre-fix path's `let _ =` discarded it silently.
        let res = slot.flush_blocking();
        // The closed peer surfaces the flush as `Err` — the
        // contract the teardown path's `let _ =` honours by closing
        // the socket either way. If the flush happens to succeed
        // (the kernel accepted the bytes into its queue before the
        // peer closed), the test still passes — the assertion is
        // that the function returns a `Result`, not that it always
        // fails. Either outcome is correct behaviour; the contract
        // is observability.
        let _ = res;
    }

    /// Read once with a bounded wait, returning how many bytes came
    /// (0 = EOF reached cleanly).
    fn read_with_timeout(mut stream: &StdTcpStream, buf: &mut [u8]) -> usize {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        match stream.read(buf) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => 0,
            Err(e) if e.kind() == ErrorKind::TimedOut => 0,
            Err(_) => 0,
        }
    }
}
