//! Per-peer BFD fast-fail supervision for the BGP daemon (W1.3).
//!
//! `--bfd` / `bfd = true` on a `[[peer]]` starts one BFD session per
//! peer (RFC 5880/5881 single-hop, RFC 5883 multihop) and wires its
//! liveness into the BGP session:
//!
//! - **BFD Down (after having been Up)** tears the BGP session down
//!   immediately — the pump threads notice the shared flag within one
//!   read timeout instead of waiting out the hold timer. This mirrors
//!   BIRD's `bgp_bfd_notify` (`bfd on` in a BGP protocol).
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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant as WallClock};

use lr_bfd::{BfdConfig, BfdSession, BfdSessionEvent, SessionRole};
use lr_core::time::Instant;
use lr_osroute::bfd_transport::{BfdMode, BfdRxSocket, BfdTxSocket};

/// Shared liveness flags for one peer, read by the BGP session and
/// connector threads.
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

/// Poll cadence of the supervisor thread. BFD detection at the
/// default 100ms x 3 is 300ms; a 10ms poll keeps the supervisor's own
/// latency contribution negligible.
const POLL_MS: u64 = 10;

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
    let mut flags_out = Vec::new();
    for (idx, spec) in specs.into_iter().enumerate() {
        let need_rx = !rx_sockets
            .iter()
            .any(|(ip, mode, _)| *ip == spec.local_ip && *mode == spec.mode);
        if need_rx {
            let rx = BfdRxSocket::bind(Some(spec.local_ip), spec.mode)
                .map_err(|e| format!("bfd bind {}: {}", spec.local_ip, e))?;
            println!(
                "daemon: bfd: listening on {} ({})",
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
    flags_out.extend(flags.iter().cloned());

    let _ = thread::Builder::new().name("lr-bfd".into()).spawn(move || {
        let start = WallClock::now();
        for p in &mut peers {
            let now = Instant(start.elapsed().as_millis() as u64);
            let _ = p.session.start(now);
            flush_peer(p);
        }
        let mut buf = [0u8; 1500];
        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }
            let now = Instant(start.elapsed().as_millis() as u64);
            // 1. Receive + demultiplex + feed.
            for (_local_ip, mode, rx) in rx_sockets.iter_mut() {
                loop {
                    let (n, src, _ttl) = match rx.recv_from(&mut buf) {
                        Ok(Some(x)) => x,
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("daemon: bfd: recv error: {}", e);
                            break;
                        }
                    };
                    if n < 12 {
                        continue; // not even a BFD header
                    }
                    let your_disc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                    let idx = if your_disc != 0 {
                        by_disc.get(&your_disc).copied()
                    } else {
                        // Discovery packet (RFC 5883 §4.1): match by
                        // source address, single session per peer.
                        peers
                            .iter()
                            .position(|p| p.peer_ip == src.ip() && p.mode == *mode)
                    };
                    let Some(idx) = idx else { continue };
                    let p = &mut peers[idx];
                    let evs = p.session.feed_bytes(now, &buf[..n]);
                    apply_events(p, evs);
                }
            }
            // 2. Advance every session's timers.
            for p in &mut peers {
                let evs = p.session.tick(now);
                apply_events(p, evs);
            }
            // 3. Flush queued output to the peer's well-known port.
            for p in &mut peers {
                flush_peer(p);
            }
            thread::sleep(Duration::from_millis(POLL_MS));
        }
        println!("daemon: bfd supervisor stopped");
    });
    Ok(flags_out)
}

/// Log events and refresh the shared flags for one peer.
fn apply_events(p: &mut BfdPeer, evs: Vec<BfdSessionEvent>) {
    for ev in &evs {
        match ev {
            BfdSessionEvent::StateChanged { from, to, diag } => {
                println!(
                    "daemon: bfd: peer {}: {} -> {} ({})",
                    p.label, from, to, diag
                );
            }
            BfdSessionEvent::Timeout => {
                println!("daemon: bfd: peer {}: detection time expired", p.label);
            }
            BfdSessionEvent::AuthFailed => {
                eprintln!(
                    "daemon: bfd: peer {}: auth failed; packet discarded",
                    p.label
                );
            }
            BfdSessionEvent::PeerDiagnostic(d) => {
                println!("daemon: bfd: peer {}: peer diagnostic: {}", p.label, d);
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
        eprintln!("daemon: bfd: peer {}: send failed: {}", p.label, e);
    }
}
