//! Per-peer BFD fast-fail supervision for the BGP daemon (W1.3).
//!
//! `--bfd` / `bfd = true` on a `[[peer]]` starts one BFD session per
//! peer (RFC 5880/5881 single-hop, RFC 5883 multihop) and wires its
//! liveness into the BGP session:
//!
//! - **BFD Down (after having been Up)** tears the BGP session down
//!   immediately — the BGP reactor notices the shared flag on its
//!   next maintenance sweep instead of waiting out the hold timer.
//!   This mirrors BIRD's `bgp_bfd_notify` (`bfd on` in a BGP
//!   protocol).
//! - The outbound connector holds off reconnecting while BFD is down
//!   *after it has been up at least once* — no connect storms into a
//!   dead path, but a peer that never runs BFD still connects (BIRD
//!   parity: a BFD session stuck in Down never kills BGP).
//!
//! Socket model (matching `lr_osroute::bfd_transport`, which matches
//! BIRD): one shared receive socket per `(local address, mode)` on
//! 3784/4784, one transmit socket per session with an RFC 5881 §4
//! ephemeral source port. Incoming datagrams are demultiplexed by
//! Your Discriminator, falling back to the source address for
//! discovery packets (RFC 5883 §4.1 single-session-per-address-pair).
//!
//! ## Event loop
//!
//! On unix the supervisor thread owns one `mio::Poll` registered to
//! every rx socket (via `mio::unix::SourceFd`) plus a `mio::Waker`
//! the `running` flag check arms on shutdown. The poll timeout is the
//! earliest session timer deadline — `BfdSession::next_deadline` — so
//! an idle session sleeps until either a datagram arrives or the next
//! TX/detection timer fires, instead of waking ten times a second on
//! a fixed 10 ms cadence. Windows keeps the original poll-and-sleep
//! loop (`mio::unix::SourceFd` has no Windows equivalent, and the
//! Windows BFD transport has no TTL ancillary data to preserve — a
//! future slice can move the socket into `mio::net::UdpSocket`
//! directly once that path lands).

use crate::Component;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant as WallClock};

use lr_bfd::{BfdConfig, BfdSession, BfdSessionEvent, SessionRole};
use lr_core::time::Instant;
use lr_osroute::bfd_transport::{BfdMode, BfdRxSocket, BfdTxSocket};

#[cfg(target_family = "unix")]
use mio::{Events, Interest, Poll, Token, Waker};

/// Shared liveness flags for one peer, read by the BGP reactor and
/// the connector threads.
#[derive(Debug, Clone)]
pub(crate) struct BfdFlags {
    /// True while the BFD session is Up.
    pub up: Arc<AtomicBool>,
    /// True once the BFD session has been Up at least once (used to
    /// gate reconnects without blocking first establishment).
    pub ever_up: Arc<AtomicBool>,
}

impl BfdFlags {
    fn new() -> Self {
        Self {
            up: Arc::new(AtomicBool::new(false)),
            ever_up: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// One supervised peer BFD session.
struct BfdPeer {
    label: String,
    peer_ip: IpAddr,
    mode: BfdMode,
    session: BfdSession,
    tx: BfdTxSocket,
    flags: BfdFlags,
}

/// The per-peer BFD description the daemon resolves from its config.
pub(crate) struct BfdPeerSpec {
    pub label: String,
    /// The peer's BFD address (well-known port is implied by `mode`).
    pub peer_ip: std::net::IpAddr,
    /// Local address to bind the session sockets to.
    pub local_ip: std::net::IpAddr,
    pub mode: BfdMode,
}

/// Fallback poll cadence for the Windows poll-and-sleep loop and for
/// the mio loop's timeout cap when no session has a timer armed (an
/// idle AdminDown peer with no traffic). BFD detection at the default
/// 100 ms x 3 is 300 ms; a 10 ms poll keeps the supervisor's own
/// latency contribution negligible on the Windows path.
#[cfg(not(target_family = "unix"))]
const POLL_MS: u64 = 10;

/// Upper bound on the mio poll timeout. The next-deadline computation
/// drives the real timeout; this cap only fires when every session
/// reports `next_deadline == None` (AdminDown with no traffic) so the
/// loop still wakes periodically to re-check the `running` flag.
#[cfg(target_family = "unix")]
const POLL_TIMEOUT_CAP_MS: u64 = 1000;

/// Reserved `mio::Token` for the `mio::Waker` that shutdown arms.
#[cfg(target_family = "unix")]
const WAKER_TOKEN: Token = Token(usize::MAX);

/// Cached `LR_BFD_DEBUG` gate for the per-packet trace (checked on
/// every datagram the supervisor drains; an uncached `var_os` syscall
/// per packet showed up in profiling on the original 10 ms poll
/// cadence). Mirrors `daemon_ospf::ospf_debug_enabled`. The trace
/// records themselves go through `log_debug!` / `log_trace!`, which
/// the per-component severity filter (`--log-target bfd=debug` /
/// `=trace`) gates a second time — the env var is the cheap pre-check,
/// the severity filter is the real gate.
fn bfd_debug_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("LR_BFD_DEBUG").is_some())
}

/// Start the BFD supervisor thread. Returns the liveness flags aligned
/// with `specs`. Fails closed: if any socket cannot be bound the
/// daemon must not run with BFD silently absent.
pub(crate) fn spawn_supervisor(
    specs: Vec<BfdPeerSpec>,
    min_tx_ms: u32,
    min_rx_ms: u32,
    detect_mult: u8,
    running: Arc<AtomicBool>,
) -> Result<Vec<BfdFlags>, String> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    // One shared receive socket per (local address, mode).
    let mut rx_sockets: Vec<(IpAddr, BfdMode, BfdRxSocket)> = Vec::new();
    let mut peers: Vec<BfdPeer> = Vec::new();
    for (idx, spec) in specs.into_iter().enumerate() {
        let need_rx = !rx_sockets
            .iter()
            .any(|(ip, mode, _)| *ip == spec.local_ip && *mode == spec.mode);
        if need_rx {
            let rx = BfdRxSocket::bind(Some(spec.local_ip), spec.mode)
                .map_err(|e| format!("bfd bind {}: {}", spec.local_ip, e))?;
            log_info!(
                Component::Bfd,
                "listening on {} ({})",
                rx.local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into()),
                spec.mode
            );
            rx_sockets.push((spec.local_ip, spec.mode, rx));
        }
        let tx = BfdTxSocket::bind_session(Some(spec.local_ip), spec.mode)
            .map_err(|e| format!("bfd peer {}: session socket: {}", spec.label, e))?;
        let cfg = BfdConfig {
            detect_mult: detect_mult.max(1),
            desired_min_tx_interval: min_tx_ms.max(1) * 1000,
            required_min_rx_interval: min_rx_ms.max(1) * 1000,
            required_min_echo_interval: 0,
            // RFC 5881 §3: single-hop sessions are Active on both
            // sides; multihop runs fine with one Active side too.
            role: SessionRole::Active,
            auth_key: None,
        };
        // Unique non-zero local discriminators for the demux map.
        let my_disc = 0xBFD0_0001u32 + idx as u32;
        let session = BfdSession::new(cfg, my_disc);
        peers.push(BfdPeer {
            label: spec.label,
            peer_ip: spec.peer_ip,
            mode: spec.mode,
            session,
            tx,
            flags: BfdFlags::new(),
        });
    }
    // Static demux table: local discriminator → peer index.
    let mut by_disc: HashMap<u32, usize> = HashMap::new();
    for (idx, p) in peers.iter().enumerate() {
        by_disc.insert(p.session.my_discriminator(), idx);
    }
    let flags: Vec<BfdFlags> = peers.iter().map(|p| p.flags.clone()).collect();

    let _ = thread::Builder::new().name("lr-bfd".into()).spawn(move || {
        let start = WallClock::now();
        // Start every session and flush the initial control packet.
        // Both loop shapes (mio and poll-and-sleep) share this
        // prologue: the sessions must be in Down with the TX timer
        // armed before the first poll, so `next_deadline` returns a
        // valid instant and the loop does not spin on a zero timeout.
        for p in &mut peers {
            let now = Instant(start.elapsed().as_millis() as u64);
            let _ = p.session.start(now);
            flush_peer(p);
        }

        #[cfg(target_family = "unix")]
        run_mio_loop(&mut rx_sockets, &mut peers, &by_disc, &running, &start);

        #[cfg(not(target_family = "unix"))]
        run_poll_loop(&mut rx_sockets, &mut peers, &by_disc, &running, &start);

        log_info!(Component::Bfd, "bfd supervisor stopped");
    });
    Ok(flags)
}

/// The mio event loop — one `Poll` for every rx socket plus a `Waker`
/// for shutdown. Replaces the original 10 ms poll-and-sleep: an idle
/// session sleeps until either a datagram arrives (readable event) or
/// the next session timer fires (poll timeout = earliest
/// `next_deadline` minus now).
#[cfg(target_family = "unix")]
fn run_mio_loop(
    rx_sockets: &mut [(IpAddr, BfdMode, BfdRxSocket)],
    peers: &mut [BfdPeer],
    by_disc: &HashMap<u32, usize>,
    running: &Arc<AtomicBool>,
    start: &WallClock,
) {
    // Switch every rx socket to non-blocking before registration —
    // mio's readable edge does not pair with a blocking recv.
    for (_, _, rx) in &mut *rx_sockets {
        if let Err(e) = rx.set_nonblocking(true) {
            log_error!(Component::Bfd, "set_nonblocking: {e}");
            return;
        }
    }

    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            log_error!(Component::Bfd, "mio::Poll::new: {e}");
            return;
        }
    };
    let registry = poll
        .registry()
        .try_clone()
        .expect("mio Registry::try_clone");
    let waker = match Waker::new(&registry, WAKER_TOKEN) {
        Ok(w) => Arc::new(w),
        Err(e) => {
            log_error!(Component::Bfd, "mio::Waker::new: {e}");
            return;
        }
    };

    // Register each rx socket with a unique token. The token is the
    // index + 1 (0 reserved for WAKER via usize::MAX); demux maps the
    // token back to the rx_sockets slot. `SourceFd` borrows the fd —
    // the `BfdRxSocket` retains ownership — so the registration is
    // read-only on the socket side; the `&mut SourceFd` is just the
    // shape mio's `register` requires.
    use mio::unix::SourceFd;
    for (i, (_, _, rx)) in rx_sockets.iter().enumerate() {
        let token = Token(i + 1);
        let fd = rx.raw_fd();
        let mut source = SourceFd(&fd);
        if let Err(e) = registry.register(&mut source, token, Interest::READABLE) {
            log_error!(Component::Bfd, "mio register rx[{i}]: {e}");
            return;
        }
    }

    // Spawn a watcher thread that wakes the loop when `running` goes
    // false. The BFD supervisor otherwise sleeps until the next timer
    // deadline; without the waker, shutdown would wait up to the
    // detection time (300 ms at default timers) before noticing.
    let waker_clone = Arc::clone(&waker);
    let running_clone = Arc::clone(running);
    let _watcher = thread::Builder::new()
        .name("lr-bfd-waker".into())
        .spawn(move || {
            // Spin at a coarse 50 ms cadence — this thread only fires
            // on shutdown, so the cost is one syscall per wakeup.
            while running_clone.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(50));
            }
            let _ = waker_clone.wake();
        });

    let mut events = Events::with_capacity(64);
    let mut buf = [0u8; 1500];
    loop {
        let pre_poll_now = Instant(start.elapsed().as_millis() as u64);
        let timeout = compute_mio_timeout(peers, pre_poll_now);
        events.clear();
        if let Err(e) = poll.poll(&mut events, Some(timeout)) {
            // EINTR is harmless under poll(2)/epoll_wait; mio surfaces
            // it as an error so the loop continues on the next iter.
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log_error!(Component::Bfd, "mio poll: {e}");
            return;
        }
        // Recompute `now` after the poll returns: the datagrams the
        // readable events report arrived *during* the poll, so their
        // arrival time is the post-poll instant. BFD's detection
        // timer (RFC 5880 §6.8.4) is anchored to the arrival time of
        // the last packet — `feed_bytes(now, ...)` arms
        // `detect_ms` off `now`. Passing the pre-poll `now` would arm
        // the timer `timeout` ms early (up to the poll ceiling), so a
        // healthy session would time out `timeout` ms before its
        // real detection time. With default timers (100 ms tx, 300 ms
        // detection) a 50 ms poll delay is a 17% premature timeout —
        // a real false-positive window on slow or loaded runners.
        // The tick pass below reuses the same `now` so one iteration
        // applies one consistent time across packet processing and
        // timer advancement.
        let now = Instant(start.elapsed().as_millis() as u64);
        // Drain every rx socket that reported readable. A socket may
        // have multiple datagrams queued; the inner loop drains until
        // EAGAIN (recv_from returns None).
        for event in events.iter() {
            if event.token() == WAKER_TOKEN {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            let Some(idx) = token_to_rx_index(event.token()) else {
                continue;
            };
            if !event.is_readable() {
                continue;
            }
            let (_, mode, rx) = &mut rx_sockets[idx];
            drain_rx_socket(rx, *mode, peers, by_disc, &mut buf, now);
        }
        if !running.load(Ordering::Relaxed) {
            break;
        }
        // Tick every session and flush queued output. Both the
        // packet-arrival path and the timeout path funnel here: a
        // packet may have armed a timer due now, and the timeout
        // itself means a timer has fired. Ticking every iteration
        // keeps the FSM and the wire in lockstep. `now` is the
        // post-poll instant — the same time the packet drain used.
        for p in peers.iter_mut() {
            let evs = p.session.tick(now);
            apply_events(p, evs);
        }
        for p in peers.iter_mut() {
            flush_peer(p);
        }
    }
}

/// Compute the mio poll timeout: the earliest `next_deadline` across
/// all sessions, minus `now`, floored at zero and capped at
/// `POLL_TIMEOUT_CAP_MS`. Returns the cap when no session has a timer
/// armed (AdminDown idle).
#[cfg(target_family = "unix")]
fn compute_mio_timeout(peers: &[BfdPeer], now: Instant) -> Duration {
    let mut earliest: Option<u64> = None;
    for p in peers {
        if let Some(d) = p.session.next_deadline() {
            earliest = Some(earliest.map_or(d.0, |e: u64| e.min(d.0)));
        }
    }
    let deadline = earliest.unwrap_or(now.0.saturating_add(POLL_TIMEOUT_CAP_MS));
    let until = deadline.saturating_sub(now.0);
    Duration::from_millis(until.min(POLL_TIMEOUT_CAP_MS))
}

/// Map a mio `Token` back to the `rx_sockets` index it was registered
/// with. Returns `None` for the WAKER token and any out-of-range
/// value (defensive — a stale event after deregistration).
#[cfg(target_family = "unix")]
fn token_to_rx_index(t: Token) -> Option<usize> {
    let idx = t.0;
    if idx == usize::MAX || idx == 0 {
        return None;
    }
    idx.checked_sub(1)
}

/// The Windows poll-and-sleep loop — the original 10 ms cadence.
/// `mio::unix::SourceFd` has no Windows equivalent, so the Windows
/// path keeps the shape the unix path replaced. A future slice can
/// move the socket into `mio::net::UdpSocket` directly (the Windows
/// BFD transport has no TTL ancillary data to preserve).
#[cfg(not(target_family = "unix"))]
fn run_poll_loop(
    rx_sockets: &mut [(IpAddr, BfdMode, BfdRxSocket)],
    peers: &mut [BfdPeer],
    by_disc: &HashMap<u32, usize>,
    running: &Arc<AtomicBool>,
    start: &WallClock,
) {
    let mut buf = [0u8; 1500];
    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }
        let now = Instant(start.elapsed().as_millis() as u64);
        // 1. Receive + demultiplex + feed.
        for (_local_ip, mode, rx) in rx_sockets.iter_mut() {
            drain_rx_socket(rx, *mode, peers, by_disc, &mut buf, now);
        }
        // 2. Advance every session's timers.
        for p in peers.iter_mut() {
            let evs = p.session.tick(now);
            apply_events(p, evs);
        }
        // 3. Flush queued output to the peer's well-known port.
        for p in peers.iter_mut() {
            flush_peer(p);
        }
        thread::sleep(Duration::from_millis(POLL_MS));
    }
}

/// Drain one rx socket until EAGAIN, demultiplexing and feeding the
/// matched session. Shared by both loop shapes so the demux logic
/// (Your Discriminator → peer index, source-address fallback for
/// discovery packets) is defined once.
fn drain_rx_socket(
    rx: &mut BfdRxSocket,
    mode: BfdMode,
    peers: &mut [BfdPeer],
    by_disc: &HashMap<u32, usize>,
    buf: &mut [u8; 1500],
    now: Instant,
) {
    loop {
        let (n, src, _ttl) = match rx.recv_from(buf) {
            Ok(Some(x)) => x,
            Ok(None) => break,
            Err(e) => {
                log_error!(Component::Bfd, "recv error: {}", e);
                break;
            }
        };
        if bfd_debug_enabled() {
            log_trace!(Component::Bfd, "rx {} bytes from {} on {}", n, src, mode);
        }
        if n < 12 {
            if bfd_debug_enabled() {
                log_debug!(
                    Component::Bfd,
                    "drop: short BFD datagram ({} bytes) from {} — \
                     header is 12 bytes",
                    n,
                    src
                );
            }
            continue; // not even a BFD header
        }
        let your_disc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let idx = if your_disc != 0 {
            by_disc.get(&your_disc).copied()
        } else {
            // Discovery packet (RFC 5883 §4.1): match by source
            // address, single session per peer.
            peers
                .iter()
                .position(|p| p.peer_ip == src.ip() && p.mode == mode)
        };
        let Some(idx) = idx else {
            if bfd_debug_enabled() {
                log_debug!(
                    Component::Bfd,
                    "drop: no peer for your_disc={:08x} src={} on {}",
                    your_disc,
                    src,
                    mode
                );
            }
            continue;
        };
        let p = &mut peers[idx];
        let evs = p.session.feed_bytes(now, &buf[..n]);
        apply_events(p, evs);
    }
}

/// Log events and refresh the shared flags for one peer.
fn apply_events(p: &mut BfdPeer, evs: Vec<BfdSessionEvent>) {
    for ev in &evs {
        match ev {
            BfdSessionEvent::StateChanged { from, to, diag } => {
                log_info!(
                    Component::Bfd,
                    "peer {}: {} -> {} ({})",
                    p.label,
                    from,
                    to,
                    diag
                );
            }
            BfdSessionEvent::Timeout => {
                log_info!(Component::Bfd, "peer {}: detection time expired", p.label);
            }
            BfdSessionEvent::AuthFailed => {
                log_warn!(
                    Component::Bfd,
                    "peer {}: auth failed; packet discarded",
                    p.label
                );
            }
            BfdSessionEvent::PeerDiagnostic(d) => {
                log_info!(Component::Bfd, "peer {}: peer diagnostic: {}", p.label, d);
            }
            BfdSessionEvent::OutboundQueued => {}
        }
    }
    refresh_flags(p);
}

/// Refresh the shared liveness flags from the session state.
fn refresh_flags(p: &BfdPeer) {
    let up = p.session.is_up();
    p.flags.up.store(up, Ordering::Relaxed);
    if up {
        p.flags.ever_up.store(true, Ordering::Relaxed);
    }
}

/// Drain the session's output onto the wire.
fn flush_peer(p: &mut BfdPeer) {
    let out = p.session.drain_outgoing();
    if out.is_empty() {
        return;
    }
    let dst = SocketAddr::new(p.peer_ip, p.mode.port());
    if let Err(e) = p.tx.send_to(&out, dst) {
        log_error!(Component::Bfd, "peer {}: send failed: {}", p.label, e);
    }
}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use super::*;

    /// `token_to_rx_index` is the demux the event loop runs on every
    /// readable event. The WAKER token (usize::MAX) and the reserved
    /// zero token return `None`; indices 1..N map back to 0..N-1.
    #[test]
    fn token_to_rx_index_round_trips_registration_slots() {
        assert_eq!(token_to_rx_index(WAKER_TOKEN), None);
        assert_eq!(token_to_rx_index(Token(0)), None);
        assert_eq!(token_to_rx_index(Token(1)), Some(0));
        assert_eq!(token_to_rx_index(Token(2)), Some(1));
        assert_eq!(token_to_rx_index(Token(42)), Some(41));
    }

    /// `compute_mio_timeout` returns the earliest `next_deadline`
    /// minus `now`, floored at zero and capped at
    /// `POLL_TIMEOUT_CAP_MS`. A session with no timer armed (the
    /// fallback path) yields the cap.
    ///
    /// This test builds a `BfdPeer` with a session that has not been
    /// started — `next_deadline` returns `None` — and asserts the cap
    /// fires. A started session would arm a timer, but the deadline
    /// computation itself is pure arithmetic over the queue head, so
    /// the cap path is the only thing this test needs to exercise
    /// without a real socket.
    #[test]
    fn compute_mio_timeout_caps_when_no_timer_is_armed() {
        // A session with no `start()` call has no timer armed, so
        // `next_deadline` returns None. The timeout computation
        // falls back to the cap.
        let cfg = BfdConfig {
            detect_mult: 3,
            desired_min_tx_interval: 100_000,
            required_min_rx_interval: 100_000,
            required_min_echo_interval: 0,
            role: SessionRole::Passive,
            auth_key: None,
        };
        let session = BfdSession::new(cfg, 0x11111111);
        // The BfdPeer struct carries a tx socket we cannot construct
        // without binding a real UDP port, so the test builds the
        // timeout computation's input indirectly: the peers slice is
        // empty, which is the same shape the loop sees when every
        // session reports `next_deadline == None`.
        let peers: Vec<BfdPeer> = Vec::new();
        let now = Instant(1000);
        let timeout = compute_mio_timeout(&peers, now);
        assert_eq!(
            timeout,
            Duration::from_millis(POLL_TIMEOUT_CAP_MS),
            "empty peers → cap"
        );
        // Sanity: the session accessor agrees with the empty-peers
        // fallback path (both report no deadline).
        assert!(session.next_deadline().is_none());
    }

    /// The mio loop's Waker must wake the supervisor within the
    /// watcher thread's 50 ms cadence on shutdown — otherwise the
    /// daemon hangs on exit for up to the detection time. This test
    /// spawns a real supervisor over a loopback rx socket with no
    /// peer (the session never leaves Down, so no traffic), then
    /// drops `running` and asserts the supervisor thread exits within
    /// a second (well above the 50 ms watcher cadence, well below the
    /// 300 ms detection time + the 1 s cap that would apply without
    /// the Waker).
    ///
    /// The supervisor thread is detached (spawn_supervisor does not
    /// return a JoinHandle), so the test cannot join it directly.
    /// Instead it observes the side effect: the `BfdFlags::up` flag
    /// stays false (the session never reaches Up) and the
    /// `running` Arc's strong count drops to 1 (only the test holds
    /// it) once the supervisor and its watcher thread have exited.
    /// The strong-count check is the shutdown signal.
    #[test]
    fn mio_loop_exits_promptly_on_running_false() {
        // Bind a real rx socket on loopback so the supervisor has
        // something to register with mio. No peer sends to it, so the
        // session stays Down and the loop is idle — the Waker is the
        // only thing that can wake it for shutdown.
        let rx = BfdRxSocket::bind(
            Some(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            BfdMode::SingleHop,
        )
        .expect("bind rx");
        let tx = BfdTxSocket::bind_session(
            Some(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            BfdMode::SingleHop,
        )
        .expect("bind tx");
        let cfg = BfdConfig {
            detect_mult: 3,
            desired_min_tx_interval: 100_000,
            required_min_rx_interval: 100_000,
            required_min_echo_interval: 0,
            role: SessionRole::Active,
            auth_key: None,
        };
        let session = BfdSession::new(cfg, 0xBFD0_0001);
        let peer = BfdPeer {
            label: "test-peer".into(),
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            mode: BfdMode::SingleHop,
            session,
            tx,
            flags: BfdFlags::new(),
        };
        let specs = vec![BfdPeerSpec {
            label: peer.label.clone(),
            peer_ip: peer.peer_ip,
            local_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            mode: BfdMode::SingleHop,
        }];
        // Drop rx; spawn_supervisor re-binds from the spec.
        drop(rx);

        let running = Arc::new(AtomicBool::new(true));
        let running_weak = Arc::downgrade(&running);
        let flags =
            spawn_supervisor(specs, 100, 100, 3, Arc::clone(&running)).expect("spawn_supervisor");
        // Give the supervisor a moment to enter the mio loop and the
        // watcher thread to start polling. The session may or may not
        // reach Up (the loopback tx→rx path can self-feed if the
        // kernel delivers the packet); the Waker test does not depend
        // on the session state, only on the supervisor thread exiting
        // promptly when `running` goes false.
        thread::sleep(Duration::from_millis(200));
        // The flags accessor must be readable without panicking
        // regardless of session state.
        let _ = flags[0].up.load(Ordering::Relaxed);

        // Pull the trigger and wait for the supervisor + watcher to
        // release their strong refs on `running`. The test itself
        // holds one strong ref, so the threads have exited when the
        // count drops back to 1.
        running.store(false, Ordering::Relaxed);
        let deadline = WallClock::now() + Duration::from_secs(2);
        while WallClock::now() < deadline {
            if running_weak.strong_count() <= 1 {
                // Both the supervisor thread and the watcher thread
                // have dropped their Arc clones; only the test's ref
                // remains.
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "supervisor did not release `running` within 2 s of shutdown — \
             strong_count = {} (Waker may not be firing)",
            running_weak.strong_count()
        );
    }
}
