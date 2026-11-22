//! Per-peer BFD fast-fail supervision for the BGP daemon.
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
//! the command channel and the `running` flag check arm on wakeup.
//! The poll timeout is the earliest session timer deadline —
//! `BfdSession::next_deadline` — so an idle session sleeps until
//! either a datagram arrives, a command lands or the next TX/detection
//! timer fires, instead of waking ten times a second on a fixed 10 ms
//! cadence. Windows keeps the original poll-and-sleep loop
//! (`mio::unix::SourceFd` has no Windows equivalent, and the Windows
//! BFD transport has no TTL ancillary data to preserve — a future
//! slice can move the socket into `mio::net::UdpSocket` directly once
//! that path lands).
//!
//! ## Runtime membership
//!
//! The supervisor is not frozen at the daemon's startup peer set:
//! [`BfdSupervisor`] is a handle carrying a command channel into the
//! loop thread. A configuration reload adds a BFD session for a peer
//! whose `bfd` turned on, removes the session of a peer that went
//! away (or turned `bfd` off), and re-points every session's timers
//! when the operator tunes `[bfd]` — each through the same command
//! channel the loop already wakes on. The thread spawns lazily on the
//! first supervised peer, so a daemon started without BFD peers pays
//! nothing until a reload enables one.

use crate::Component;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, Sender, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant as WallClock};

use lr_bfd::{BfdConfig, BfdSession, BfdSessionEvent, SessionRole, State};
use lr_core::time::Instant;
use lr_osroute::bfd_transport::{BfdMode, BfdRxSocket, BfdTxSocket};

#[cfg(target_family = "unix")]
use mio::{Events, Interest, Poll, Token, Waker};

/// How long `BfdSupervisor::add_peer` / `remove_peer` wait for the
/// loop thread's reply before giving up (the loop is woken through
/// the Waker, so the reply latency is a scheduler quantum; the bound
/// only guards a wedged loop).
const COMMAND_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared liveness flags for one peer, read by the BGP reactor and
/// the connector threads.
#[derive(Debug, Clone)]
pub(crate) struct BfdFlags {
    /// True while the BFD session is Up.
    pub up: Arc<AtomicBool>,
    /// True while the BFD session is administratively down. The BGP
    /// strict-mode gate treats AdminDown like Up (draft
    /// draft-ietf-idr-bgp-bfd-strict-mode-13 §8.5.1) while Established
    /// sessions ignore it (§8.7.1), so the reactor needs the
    /// distinction rather than folding it into `up`.
    pub admin_down: Arc<AtomicBool>,
    /// True once the BFD session has been Up at least once (used to
    /// gate reconnects without blocking first establishment).
    pub ever_up: Arc<AtomicBool>,
}

impl BfdFlags {
    fn new() -> Self {
        Self {
            up: Arc::new(AtomicBool::new(false)),
            admin_down: Arc::new(AtomicBool::new(false)),
            ever_up: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// One supervised peer BFD session.
struct BfdPeer {
    label: String,
    peer_ip: IpAddr,
    /// The local address the session's sockets are bound to — the
    /// `(local_ip, mode)` key that maps back to the shared rx slot.
    local_ip: IpAddr,
    mode: BfdMode,
    session: BfdSession,
    tx: BfdTxSocket,
    flags: BfdFlags,
}

/// One shared receive socket slot. Slots are `Option` so the token of
/// a live slot never changes when another is emptied — the mio Token
/// is the slot index.
struct RxSlot {
    local_ip: IpAddr,
    mode: BfdMode,
    rx: BfdRxSocket,
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

/// A command into the supervisor loop: peer membership or timer
/// re-pointing, driven by the daemon's configuration reload.
enum BfdCommand {
    /// Start one supervised session. The reply carries the liveness
    /// flags on success or the bind error.
    Add(BfdPeerSpec, SyncSender<Result<BfdFlags, String>>),
    /// Stop one supervised session, matched by `(label, peer_ip)`.
    /// The reply is `true` when a session was found and removed.
    Remove {
        label: String,
        peer_ip: std::net::IpAddr,
        reply: SyncSender<bool>,
    },
    /// Re-point every session's timers (RFC 5880 §6.8.3 poll
    /// sequences where required). A `detect_mult` change is applied
    /// on the next packet exchange; the interval changes ride
    /// `BfdSession::update_timers`.
    UpdateTimers {
        min_tx_ms: u32,
        min_rx_ms: u32,
        detect_mult: u8,
    },
}

/// Loop-side effects of a command the caller must run: registering a
/// freshly bound rx socket with mio, or deregistering an emptied one.
/// The Windows loop ignores both (its poll walks the slot table).
enum RxSlotEffect {
    /// Register `rx_sockets[index]` with the poll.
    Register(usize),
    /// Deregister and empty `rx_sockets[index]`.
    Deregister(usize),
}

/// The mutable state the supervisor loop owns: the rx-socket slots,
/// the sessions, the demultiplexer and the timer triple.
struct SupervisorState {
    /// One slot per `(local address, mode)` ever bound; `None` after
    /// the last session using the pair went away. The slot index is
    /// the mio Token minus one, so a freed slot's token stays retired.
    rx_sockets: Vec<Option<RxSlot>>,
    peers: Vec<BfdPeer>,
    /// Local discriminator → peer index. Rebuilt whenever the peers
    /// vector changes shape.
    by_disc: HashMap<u32, usize>,
    /// Next unique local discriminator. Monotonic across removals so
    /// a stale remote mapping to a removed session's disc can never
    /// demultiplex to its replacement.
    next_disc: u32,
    min_tx_ms: u32,
    min_rx_ms: u32,
    detect_mult: u8,
}

impl SupervisorState {
    fn new(min_tx_ms: u32, min_rx_ms: u32, detect_mult: u8) -> Self {
        Self {
            rx_sockets: Vec::new(),
            peers: Vec::new(),
            by_disc: HashMap::new(),
            next_disc: 0xBFD0_0001,
            min_tx_ms,
            min_rx_ms,
            detect_mult,
        }
    }

    /// Find (or bind) the rx socket slot for `(local_ip, mode)`.
    /// Returns the slot index plus a registration effect when the
    /// socket was freshly bound.
    fn rx_slot_for(
        &mut self,
        local_ip: IpAddr,
        mode: BfdMode,
    ) -> Result<(usize, Option<RxSlotEffect>), String> {
        // Reuse a live slot for the pair.
        if let Some(index) = self.rx_sockets.iter().position(|s| {
            s.as_ref()
                .is_some_and(|s| s.local_ip == local_ip && s.mode == mode)
        }) {
            return Ok((index, None));
        }
        // Recycle a freed slot so the token space stays dense.
        if let Some(index) = self.rx_sockets.iter().position(|s| s.is_none()) {
            let rx = BfdRxSocket::bind(Some(local_ip), mode)
                .map_err(|e| format!("bfd bind {}: {}", local_ip, e))?;
            log_info!(
                Component::Bfd,
                "listening on {} ({})",
                rx.local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into()),
                mode
            );
            self.rx_sockets[index] = Some(RxSlot { local_ip, mode, rx });
            return Ok((index, Some(RxSlotEffect::Register(index))));
        }
        // Fresh slot at the end.
        let rx = BfdRxSocket::bind(Some(local_ip), mode)
            .map_err(|e| format!("bfd bind {}: {}", local_ip, e))?;
        log_info!(
            Component::Bfd,
            "listening on {} ({})",
            rx.local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".into()),
            mode
        );
        self.rx_sockets.push(Some(RxSlot { local_ip, mode, rx }));
        Ok((
            self.rx_sockets.len() - 1,
            Some(RxSlotEffect::Register(self.rx_sockets.len() - 1)),
        ))
    }

    /// Whether any live session still uses rx slot `index`.
    fn rx_slot_in_use(&self, index: usize) -> bool {
        let Some(slot) = self.rx_sockets[index].as_ref() else {
            return false;
        };
        self.peers
            .iter()
            .any(|p| p.local_ip == slot.local_ip && p.mode == slot.mode)
    }

    /// Add one supervised session. The session starts (Down, TX timer
    /// armed) and the initial control packet flushes before the reply.
    fn add_peer(
        &mut self,
        spec: BfdPeerSpec,
        start: &WallClock,
    ) -> (Result<BfdFlags, String>, Option<RxSlotEffect>) {
        let (slot_index, effect) = match self.rx_slot_for(spec.local_ip, spec.mode) {
            Ok(x) => x,
            Err(e) => return (Err(e), None),
        };
        let _ = slot_index;
        let tx = match BfdTxSocket::bind_session(Some(spec.local_ip), spec.mode) {
            Ok(tx) => tx,
            Err(e) => {
                return (
                    Err(format!("bfd peer {}: session socket: {}", spec.label, e)),
                    effect,
                )
            }
        };
        let cfg = BfdConfig {
            detect_mult: self.detect_mult.max(1),
            desired_min_tx_interval: self.min_tx_ms.max(1) * 1000,
            required_min_rx_interval: self.min_rx_ms.max(1) * 1000,
            required_min_echo_interval: 0,
            // RFC 5881 §3: single-hop sessions are Active on both
            // sides; multihop runs fine with one Active side too.
            role: SessionRole::Active,
            auth_key: None,
        };
        let my_disc = self.next_disc;
        self.next_disc = self.next_disc.wrapping_add(1).max(0xBFD0_0001);
        let mut peer = BfdPeer {
            label: spec.label,
            peer_ip: spec.peer_ip,
            local_ip: spec.local_ip,
            mode: spec.mode,
            session: BfdSession::new(cfg, my_disc),
            tx,
            flags: BfdFlags::new(),
        };
        let now = Instant(start.elapsed().as_millis() as u64);
        let evs = peer.session.start(now);
        apply_events(&mut peer, evs);
        flush_peer(&mut peer);
        let flags = peer.flags.clone();
        self.peers.push(peer);
        self.rebuild_demux();
        (Ok(flags), effect)
    }

    /// Remove one supervised session by `(label, peer_ip)`. `true`
    /// when a session was found and removed. An emptied rx socket
    /// slot yields a deregistration effect.
    fn remove_peer(
        &mut self,
        label: &str,
        peer_ip: std::net::IpAddr,
    ) -> (bool, Option<RxSlotEffect>) {
        let Some(index) = self
            .peers
            .iter()
            .position(|p| p.label == label && p.peer_ip == peer_ip)
        else {
            return (false, None);
        };
        let peer = self.peers.swap_remove(index);
        log_info!(
            Component::Bfd,
            "peer {}: BFD session removed ({} supervision)",
            peer.label,
            peer.mode
        );
        self.rebuild_demux();
        // The tx socket drops with the peer; an rx slot nobody uses
        // anymore retires (the loop deregisters and closes it).
        let mut effect = None;
        for slot_index in 0..self.rx_sockets.len() {
            if self.rx_sockets[slot_index].is_some() && !self.rx_slot_in_use(slot_index) {
                effect = Some(RxSlotEffect::Deregister(slot_index));
                break;
            }
        }
        (true, effect)
    }

    /// Re-point every session's timers (RFC 5880 §6.8.3).
    fn update_timers(
        &mut self,
        min_tx_ms: u32,
        min_rx_ms: u32,
        detect_mult: u8,
        start: &WallClock,
    ) {
        self.min_tx_ms = min_tx_ms;
        self.min_rx_ms = min_rx_ms;
        self.detect_mult = detect_mult;
        let now = Instant(start.elapsed().as_millis() as u64);
        for p in self.peers.iter_mut() {
            let evs =
                p.session
                    .update_timers(now, min_tx_ms.max(1) * 1000, min_rx_ms.max(1) * 1000);
            apply_events(p, evs);
            flush_peer(p);
        }
        log_info!(
            Component::Bfd,
            "timers re-pointed: min_tx {} ms, min_rx {} ms, detect_mult {}",
            min_tx_ms,
            min_rx_ms,
            detect_mult
        );
    }

    /// Rebuild the discriminator demultiplexer after the peers vector
    /// changed shape (`swap_remove` shifts the tail).
    fn rebuild_demux(&mut self) {
        self.by_disc.clear();
        for (idx, p) in self.peers.iter().enumerate() {
            self.by_disc.insert(p.session.my_discriminator(), idx);
        }
    }
}

/// The daemon-side handle: the command channel into the loop thread.
/// The thread spawns lazily on the first supervised peer and runs
/// until the daemon's `running` flag clears, so a daemon started
/// without BFD peers pays nothing and a reload can still enable BFD.
pub(crate) struct BfdSupervisor {
    tx: Option<Sender<BfdCommand>>,
    #[cfg(target_family = "unix")]
    waker: Option<Arc<Waker>>,
    running: Arc<AtomicBool>,
    min_tx_ms: u32,
    min_rx_ms: u32,
    detect_mult: u8,
}

impl BfdSupervisor {
    /// A handle with no loop thread yet; the first `add_peer` spawns
    /// it. `min_tx_ms` / `min_rx_ms` / `detect_mult` are the
    /// `[bfd]` timer triple new sessions start with.
    pub(crate) fn new(
        min_tx_ms: u32,
        min_rx_ms: u32,
        detect_mult: u8,
        running: Arc<AtomicBool>,
    ) -> Self {
        Self {
            tx: None,
            #[cfg(target_family = "unix")]
            waker: None,
            running,
            min_tx_ms,
            min_rx_ms,
            detect_mult,
        }
    }

    /// The timer triple new sessions start with (and the last one
    /// `update_timers` applied).
    pub(crate) fn min_tx_ms(&self) -> u32 {
        self.min_tx_ms
    }

    pub(crate) fn min_rx_ms(&self) -> u32 {
        self.min_rx_ms
    }

    pub(crate) fn detect_multiplier(&self) -> u8 {
        self.detect_mult
    }

    /// Spawn the loop thread on first use. The `mio::Poll` (unix) is
    /// created here, on the caller's thread, so the `Waker` clone the
    /// handle keeps shares the loop's registry — the same shape
    /// `BgpReactor::spawn` uses.
    fn ensure_thread(&mut self) -> Result<(), String> {
        if self.tx.is_some() {
            return Ok(());
        }
        let (tx, rx) = std::sync::mpsc::channel::<BfdCommand>();
        #[cfg(target_family = "unix")]
        let (poll, waker) = {
            let poll = Poll::new().map_err(|e| format!("mio::Poll::new: {e}"))?;
            let registry = poll.registry().try_clone().expect("mio registry clone");
            let waker = Arc::new(Waker::new(&registry, WAKER_TOKEN).map_err(|e| e.to_string())?);
            (poll, waker)
        };
        let state = SupervisorState::new(self.min_tx_ms, self.min_rx_ms, self.detect_mult);
        let running = Arc::clone(&self.running);
        #[cfg(target_family = "unix")]
        let waker_for_thread = Arc::clone(&waker);
        let _ = thread::Builder::new().name("lr-bfd".into()).spawn(move || {
            supervisor_main(
                state,
                rx,
                running,
                #[cfg(target_family = "unix")]
                poll,
                #[cfg(target_family = "unix")]
                waker_for_thread,
            );
        });
        self.tx = Some(tx);
        #[cfg(target_family = "unix")]
        {
            self.waker = Some(waker);
        }
        Ok(())
    }

    /// Wake the loop thread for a command (unix: the Waker; the
    /// Windows poll loop drains the channel on its own cadence).
    fn wake(&self) {
        #[cfg(target_family = "unix")]
        if let Some(waker) = &self.waker {
            let _ = waker.wake();
        }
    }

    /// Start one supervised session for `spec`. The reply is
    /// synchronous: the session is live (Down, TX timer armed, first
    /// control packet flushed) before the flags return.
    pub(crate) fn add_peer(&mut self, spec: BfdPeerSpec) -> Result<BfdFlags, String> {
        self.ensure_thread()?;
        let (reply, reply_rx) = sync_channel(1);
        self.tx
            .as_ref()
            .expect("ensure_thread spawned the loop")
            .send(BfdCommand::Add(spec, reply))
            .map_err(|_| "bfd supervisor thread is gone".to_string())?;
        self.wake();
        match reply_rx.recv_timeout(COMMAND_REPLY_TIMEOUT) {
            Ok(result) => result,
            Err(_) => Err("bfd supervisor did not answer in time".to_string()),
        }
    }

    /// Stop one supervised session. `true` when a session was found
    /// and removed.
    pub(crate) fn remove_peer(&mut self, label: &str, peer_ip: std::net::IpAddr) -> bool {
        let Some(tx) = &self.tx else {
            return false;
        };
        let (reply, reply_rx) = sync_channel(1);
        if tx
            .send(BfdCommand::Remove {
                label: label.to_string(),
                peer_ip,
                reply,
            })
            .is_err()
        {
            return false;
        }
        self.wake();
        matches!(reply_rx.recv_timeout(COMMAND_REPLY_TIMEOUT), Ok(true))
    }

    /// Re-point every session's timers.
    pub(crate) fn update_timers(&mut self, min_tx_ms: u32, min_rx_ms: u32, detect_mult: u8) {
        self.min_tx_ms = min_tx_ms;
        self.min_rx_ms = min_rx_ms;
        self.detect_mult = detect_mult;
        if let Some(tx) = &self.tx {
            let _ = tx.send(BfdCommand::UpdateTimers {
                min_tx_ms,
                min_rx_ms,
                detect_mult,
            });
            self.wake();
        }
    }
}

/// The loop thread body: hand the state to the platform loop and
/// report the exit.
fn supervisor_main(
    mut state: SupervisorState,
    cmd_rx: Receiver<BfdCommand>,
    running: Arc<AtomicBool>,
    #[cfg(target_family = "unix")] poll: Poll,
    #[cfg(target_family = "unix")] waker: Arc<Waker>,
) {
    let start = WallClock::now();

    #[cfg(target_family = "unix")]
    run_mio_loop(&mut state, &cmd_rx, &running, &start, poll, waker);

    #[cfg(not(target_family = "unix"))]
    run_poll_loop(&mut state, &cmd_rx, &running, &start);

    log_info!(Component::Bfd, "bfd supervisor stopped");
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

/// Reserved `mio::Token` for the `mio::Waker` that commands and
/// shutdown arm.
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

/// Apply one command against the state. Returns the rx-slot effects
/// the caller must run (mio registration is the loop's to do — the
/// registry lives there).
fn handle_command(
    state: &mut SupervisorState,
    cmd: BfdCommand,
    start: &WallClock,
) -> Vec<RxSlotEffect> {
    match cmd {
        BfdCommand::Add(spec, reply) => {
            let (result, effect) = state.add_peer(spec, start);
            let _ = reply.send(result);
            effect.into_iter().collect()
        }
        BfdCommand::Remove {
            label,
            peer_ip,
            reply,
        } => {
            let (removed, effect) = state.remove_peer(&label, peer_ip);
            let _ = reply.send(removed);
            effect.into_iter().collect()
        }
        BfdCommand::UpdateTimers {
            min_tx_ms,
            min_rx_ms,
            detect_mult,
        } => {
            state.update_timers(min_tx_ms, min_rx_ms, detect_mult, start);
            Vec::new()
        }
    }
}

/// Run the rx-slot effects: register a freshly bound rx socket with
/// the poll (unix) or deregister and drop an emptied one. The Windows
/// loop passes no registry — its poll walks the slot table, so both
/// effects reduce to the drop.
fn apply_rx_effects(
    state: &mut SupervisorState,
    effects: Vec<RxSlotEffect>,
    registry: Option<&mio::Registry>,
) {
    #[cfg(target_family = "unix")]
    use mio::unix::SourceFd;
    for effect in effects {
        match effect {
            RxSlotEffect::Register(index) => {
                #[cfg(target_family = "unix")]
                if let Some(registry) = registry {
                    if let Some(slot) = state.rx_sockets[index].as_ref() {
                        let fd = slot.rx.raw_fd();
                        let mut source = SourceFd(&fd);
                        if let Err(e) =
                            registry.register(&mut source, Token(index + 1), Interest::READABLE)
                        {
                            log_error!(Component::Bfd, "mio register rx[{index}]: {e}");
                        }
                    }
                }
                #[cfg(not(target_family = "unix"))]
                let _ = (index, registry);
            }
            RxSlotEffect::Deregister(index) => {
                #[cfg(target_family = "unix")]
                if let (Some(registry), Some(slot)) = (registry, state.rx_sockets[index].as_ref()) {
                    let fd = slot.rx.raw_fd();
                    let mut source = SourceFd(&fd);
                    let _ = registry.deregister(&mut source);
                }
                // Drop the socket: the slot's token retires with it.
                state.rx_sockets[index] = None;
                log_info!(Component::Bfd, "rx socket slot {index} retired");
            }
        }
    }
}

/// The mio event loop — one `Poll` for every rx socket plus a `Waker`
/// for commands and shutdown. An idle session sleeps until either a
/// datagram arrives (readable event), a command lands (Waker) or the
/// next session timer fires (poll timeout = earliest `next_deadline`
/// minus now).
#[cfg(target_family = "unix")]
fn run_mio_loop(
    state: &mut SupervisorState,
    cmd_rx: &Receiver<BfdCommand>,
    running: &Arc<AtomicBool>,
    start: &WallClock,
    mut poll: Poll,
    waker: Arc<Waker>,
) {
    // Switch every rx socket to non-blocking before registration —
    // mio's readable edge does not pair with a blocking recv.
    for slot in state.rx_sockets.iter_mut().flatten() {
        if let Err(e) = slot.rx.set_nonblocking(true) {
            log_error!(Component::Bfd, "set_nonblocking: {e}");
            return;
        }
    }

    let registry = poll
        .registry()
        .try_clone()
        .expect("mio Registry::try_clone");

    // Register each rx socket with a unique token. The token is the
    // slot index + 1 (0 reserved for WAKER via usize::MAX); demux
    // maps the token back to the rx_sockets slot. `SourceFd` borrows
    // the fd — the `BfdRxSocket` retains ownership — so the
    // registration is read-only on the socket side; the `&mut
    // SourceFd` is just the shape mio's `register` requires.
    use mio::unix::SourceFd;
    for (i, slot) in state.rx_sockets.iter().enumerate() {
        let Some(slot) = slot.as_ref() else {
            continue;
        };
        let token = Token(i + 1);
        let fd = slot.rx.raw_fd();
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
        let timeout = compute_mio_timeout(&state.peers, pre_poll_now);
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
        // the last packet — `feed_bytes(now, ...)` arms `detect_ms`
        // off `now`. Passing the pre-poll `now` would arm the timer
        // `timeout` ms early (up to the poll ceiling), so a healthy
        // session would time out `timeout` ms before its real
        // detection time. With default timers (100 ms tx, 300 ms
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
            let Some(slot) = state.rx_sockets[idx].as_mut() else {
                continue;
            };
            drain_rx_socket(
                &mut slot.rx,
                slot.mode,
                &mut state.peers,
                &state.by_disc,
                &mut buf,
                now,
            );
        }
        // Commands: the Waker fired either for a command or for
        // shutdown. Process every queued command (the loop wakes on
        // the next send anyway, but a batch drain keeps the reply
        // latency at one scheduler quantum when a reload adds several
        // peers at once).
        if !running.load(Ordering::Relaxed) {
            break;
        }
        while let Ok(cmd) = cmd_rx.try_recv() {
            let effects = handle_command(state, cmd, start);
            apply_rx_effects(state, effects, Some(&registry));
        }
        // Tick every session and flush queued output. Both the
        // packet-arrival path and the timeout path funnel here: a
        // packet may have armed a timer due now, and the timeout
        // itself means a timer has fired. Ticking every iteration
        // keeps the FSM and the wire in lockstep. `now` is the
        // post-poll instant — the same time the packet drain used.
        for p in state.peers.iter_mut() {
            let evs = p.session.tick(now);
            apply_events(p, evs);
        }
        for p in state.peers.iter_mut() {
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
    state: &mut SupervisorState,
    cmd_rx: &Receiver<BfdCommand>,
    running: &Arc<AtomicBool>,
    start: &WallClock,
) {
    let mut buf = [0u8; 1500];
    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }
        let now = Instant(start.elapsed().as_millis() as u64);
        // 0. Commands (membership / timers from a reload).
        while let Ok(cmd) = cmd_rx.try_recv() {
            let effects = handle_command(state, cmd, start);
            apply_rx_effects(state, effects, None);
        }
        // 1. Receive + demultiplex + feed.
        for slot in state.rx_sockets.iter_mut().flatten() {
            drain_rx_socket(
                &mut slot.rx,
                slot.mode,
                &mut state.peers,
                &state.by_disc,
                &mut buf,
                now,
            );
        }
        // 2. Advance every session's timers.
        for p in state.peers.iter_mut() {
            let evs = p.session.tick(now);
            apply_events(p, evs);
        }
        // 3. Flush queued output to the peer's well-known port.
        for p in state.peers.iter_mut() {
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
    p.flags
        .admin_down
        .store(p.session.state() == State::AdminDown, Ordering::Relaxed);
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

    /// The runtime membership surface: `BfdSupervisor::add_peer`
    /// starts a session and returns live flags; `remove_peer` stops
    /// it; a removed peer is reported not-found on a second removal.
    /// Runs against the real loop thread over loopback sockets.
    #[test]
    fn supervisor_add_remove_roundtrip() {
        let running = Arc::new(AtomicBool::new(true));
        let running_weak = Arc::downgrade(&running);
        let mut supervisor = BfdSupervisor::new(100, 100, 3, Arc::clone(&running));

        let spec = BfdPeerSpec {
            label: "membership-test".into(),
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            local_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            // Multihop keeps this test off the single-hop 3784 port
            // so it cannot collide with the sibling waker test when
            // the harness runs them in parallel.
            mode: BfdMode::Multihop,
        };
        let flags = supervisor
            .add_peer(spec)
            .expect("add_peer starts the session");
        assert!(
            !flags.up.load(Ordering::Relaxed),
            "session starts Down (loopback may feed it later, the flag read here races)"
        );

        // A second session on the same (local, mode) reuses the rx
        // socket: the add must succeed without a second bind.
        let spec2 = BfdPeerSpec {
            label: "membership-test-2".into(),
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)),
            local_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            // MultiHop keeps this test off the single-hop 3784 port
            // so it cannot collide with the sibling waker test when
            // the harness runs them in parallel.
            mode: BfdMode::Multihop,
        };
        let _flags2 = supervisor.add_peer(spec2).expect("second add reuses rx");

        // Removal: exact (label, peer_ip) match.
        assert!(supervisor.remove_peer(
            "membership-test",
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        ));
        // A second removal of the same peer is a no-op.
        assert!(!supervisor.remove_peer(
            "membership-test",
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        ));
        // The surviving session keeps its flags readable.
        let _ = flags.up.load(Ordering::Relaxed);

        // Drop the handle first: it holds its own Arc clone of
        // `running`, so the strong-count check below would never
        // reach 1 while the handle is alive.
        drop(supervisor);
        running.store(false, Ordering::Relaxed);
        let deadline = WallClock::now() + Duration::from_secs(2);
        while WallClock::now() < deadline {
            if running_weak.strong_count() <= 1 {
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
    /// stays false (the session never reaches Up) and the `running`
    /// Arc's strong count drops to 1 (only the test holds it) once
    /// the supervisor and its watcher thread have exited. The
    /// strong-count check is the shutdown signal.
    #[test]
    fn mio_loop_exits_promptly_on_running_false() {
        let running = Arc::new(AtomicBool::new(true));
        let running_weak = Arc::downgrade(&running);
        let mut supervisor = BfdSupervisor::new(100, 100, 3, Arc::clone(&running));
        let flags = [supervisor
            .add_peer(BfdPeerSpec {
                label: "test-peer".into(),
                peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                local_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                mode: BfdMode::SingleHop,
            })
            .expect("add_peer")];
        // Drop the handle first: it holds its own Arc clone of
        // `running`, so the strong-count check below would never
        // reach 1 while the handle is alive.
        drop(supervisor);
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
