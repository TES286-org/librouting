//! RPKI-RTR cache client thread — `lr-daemon`'s transport layer for
//! `lr_bgp::rtr::client::RtrClient` (RFC 8210, ROADMAP-v3 D2.4).
//!
//! The library side is transport-agnostic: `RtrClient` owns the
//! protocol and emits `ClientStep`s; this module is the "embedder"
//! the rtr docs talk about — it owns the TCP connection, the clock
//! and the live `lr_bgp::RoaStore`. One thread per configured cache:
//!
//! * connect / reconnect with the §6 retry backoff,
//! * `on_connect()` on every established connection (§8.1),
//! * decode + `on_pdu()` for inbound bytes (framing-aware),
//! * `poll()` applies the §6 refresh + expiry timers while idle,
//! * every completed sync's delta batch applies atomically to the
//!   `RoaStore`,
//! * on data expiry (§6) the RTR-sourced ROAs are withdrawn and the
//!   session resets — a stale serial is worse than none,
//! * SIGHUP reload swaps the cache address through the control
//!   channel ([`RpkiCommand::Reconnect`]).
//!
//! Operational visibility: [`RpkiHandle::status_line`] renders the
//! one-line status the runtime API `status` command appends after its
//! fixed fields (the FRR `show bgp rpki` analogue in miniature).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use lr_bgp::rtr::client::ClientStep;
use lr_bgp::rtr::{self, RtrPdu};
use lr_bgp::{RoaStore, RtrClient};

/// Connected-socket read timeout: bounds how long one `read` blocks
/// before the loop falls through to `poll()` — the refresh and expiry
/// timers must run even when the cache goes quiet.
const READ_TIMEOUT_MS: u64 = 500;

/// Idle sleep between poll passes when the socket is quiet. Small
/// enough that a Serial Notify (or a shutdown) is noticed promptly,
/// long enough that an idle thread does not spin.
const IDLE_SLEEP_MS: u64 = 250;

/// Sleep slices during the reconnect backoff: shutdown and reload
/// commands are noticed within one slice.
const BACKOFF_SLICE_MS: u64 = 100;

/// TCP connect timeout per resolved address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on back-to-back reads per loop pass: a bulk sync
/// drains fast (64 × 8 KiB per pass). Against a slow-drip cache the
/// worst case is 64 × the read timeout before the control channel is
/// re-checked, so the burst loop also breaks early when a control
/// command is pending.
const READ_BURST: usize = 64;

/// One command from the daemon's control plane (the SIGHUP reload
/// path) to the RTR thread. Shutdown is deliberately absent — the
/// daemon's shared `running` flag stops the thread.
pub(crate) enum RpkiCommand {
    /// Drop the transport and re-sync. With a new address the session
    /// memory is reset too (the old cache's serial is meaningless);
    /// with the same address the remembered `(session, serial)`
    /// survives and the next sync is incremental (RFC 8210 §8.1).
    /// The intervals are the freshly validated §6 timers from the
    /// reloaded config (they pre-date the first End of Data of the
    /// new session, so a v1+ cache still overrides them).
    Reconnect {
        cache: String,
        refresh_interval: u32,
        retry_interval: u32,
        expire_interval: u32,
    },
}

/// Outcome of draining the control channel.
enum Control {
    /// Nothing pending — keep doing what the loop was doing.
    Continue,
    /// A Reconnect was processed — skip any backoff in progress and
    /// return to the loop head (it reconnects immediately).
    Interrupt,
}

/// A point-in-time snapshot of the RTR thread, rendered for the
/// runtime API `status` command. Plain data — the API thread never
/// touches the RTR thread itself.
#[derive(Debug, Clone)]
pub(crate) struct RpkiStatus {
    pub cache: String,
    pub connected: bool,
    pub version: u8,
    pub phase: &'static str,
    pub session_id: Option<u16>,
    pub serial: Option<u32>,
    pub static_roas: usize,
    pub rtr_roas: usize,
    pub roas: usize,
    pub refresh_interval: u32,
    pub retry_interval: u32,
    pub expire_interval: u32,
    pub last_sync_age_s: Option<u64>,
}

impl RpkiStatus {
    /// The one-line `status` output. Keys are `key=value` pairs so the
    /// API stays grep-friendly and forward-compatible (new keys never
    /// break existing parsers).
    pub fn status_line(&self) -> String {
        let session = self
            .session_id
            .map(|s| format!("0x{s:04x}"))
            .unwrap_or_else(|| "-".to_string());
        let serial = self
            .serial
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());
        let age = self
            .last_sync_age_s
            .map(|a| format!("{a}s"))
            .unwrap_or_else(|| "-".to_string());
        format!(
            "rpki: cache={} state={} version={} phase={} session={} serial={} \
             roas={} (static={} rtr={}) refresh={}s retry={}s expire={}s last-sync={}",
            self.cache,
            if self.connected { "connected" } else { "down" },
            self.version,
            self.phase,
            session,
            serial,
            self.roas,
            self.static_roas,
            self.rtr_roas,
            self.refresh_interval,
            self.retry_interval,
            self.expire_interval,
            age,
        )
    }
}

/// The handle the daemon keeps: status for the API thread, control
/// for the reload path. `Clone` shares the same underlying state.
#[derive(Clone)]
pub(crate) struct RpkiHandle {
    status: Arc<Mutex<RpkiStatus>>,
    control: Sender<RpkiCommand>,
}

impl RpkiHandle {
    /// The configured cache address last seen by the client thread.
    pub(crate) fn cache(&self) -> String {
        self.status.lock().unwrap().cache.clone()
    }

    /// The rendered `status` line for the runtime API.
    pub(crate) fn status_line(&self) -> String {
        self.status.lock().unwrap().status_line()
    }

    /// Ask the thread to drop the transport and re-sync (the reload
    /// path) with the freshly validated intervals. Returns the log
    /// line describing what was requested.
    pub(crate) fn reconnect(
        &self,
        cache: String,
        refresh_interval: u32,
        retry_interval: u32,
        expire_interval: u32,
    ) -> String {
        match self.control.send(RpkiCommand::Reconnect {
            cache,
            refresh_interval,
            retry_interval,
            expire_interval,
        }) {
            Ok(()) => "rpki: reconnect requested".to_string(),
            Err(_) => "rpki: client thread is gone (no reconnect possible)".to_string(),
        }
    }
}

/// Spawn the RTR client thread. `store` is shared with the filter
/// contexts (import hooks see ROAs appear and disappear without any
/// recompilation); `running` is the daemon's shutdown flag.
pub(crate) fn spawn_rpki(
    store: Arc<RoaStore>,
    cache: String,
    refresh_interval: u32,
    retry_interval: u32,
    expire_interval: u32,
    running: Arc<AtomicBool>,
) -> RpkiHandle {
    let status = Arc::new(Mutex::new(RpkiStatus {
        cache: cache.clone(),
        connected: false,
        version: rtr::RTR_VERSION_MAX,
        phase: "awaiting-reset",
        session_id: None,
        serial: None,
        static_roas: store.static_len(),
        rtr_roas: 0,
        roas: store.len(),
        refresh_interval,
        retry_interval,
        expire_interval,
        last_sync_age_s: None,
    }));
    let (tx, rx) = mpsc::channel::<RpkiCommand>();
    let handle = RpkiHandle {
        status: Arc::clone(&status),
        control: tx,
    };
    let thread_status = Arc::clone(&status);
    let spawned = thread::Builder::new()
        .name("lr-rpki-rtr".to_string())
        .spawn(move || {
            let mut state = RpkiLoop {
                store,
                running,
                control: rx,
                status: thread_status,
                cache,
                client: RtrClient::new(),
                stream: None,
                buf: Vec::new(),
                start: Instant::now(),
                last_sync: None,
            };
            state
                .client
                .set_intervals(refresh_interval, retry_interval, expire_interval);
            state.run();
        });
    if let Err(e) = spawned {
        // Thread spawn failure is fatal at daemon scale (the same
        // posture as the ticker / BFD threads): fail loudly, not
        // silently-without-RPKI.
        panic!("rpki: cannot spawn client thread: {e}");
    }
    handle
}

/// The per-thread state machine.
struct RpkiLoop {
    store: Arc<RoaStore>,
    running: Arc<AtomicBool>,
    control: Receiver<RpkiCommand>,
    status: Arc<Mutex<RpkiStatus>>,
    cache: String,
    client: RtrClient,
    stream: Option<TcpStream>,
    /// Partially received PDU bytes (framing-aware decode drains it).
    buf: Vec<u8>,
    start: Instant,
    last_sync: Option<Instant>,
}

impl RpkiLoop {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn run(&mut self) {
        println!("rpki: client thread started (cache {})", self.cache);
        loop {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }
            // Control plane first: a reload may swap the cache under us.
            match self.drain_control() {
                Control::Interrupt => continue,
                Control::Continue => {}
            }
            if !self.running.load(Ordering::Relaxed) {
                break;
            }
            // Establish the transport when down.
            if self.stream.is_none() && !self.connect() {
                // connect() already slept the retry backoff (or an
                // Interrupt came in — either way, re-evaluate).
                continue;
            }
            if !self.read_available() {
                continue;
            }
            if !self.poll_timers() {
                self.sleep_backoff();
                continue;
            }
            // Quiet, healthy socket: brief idle sleep so the loop does
            // not spin while the cache stays silent.
            if self.stream.is_some() {
                thread::sleep(Duration::from_millis(IDLE_SLEEP_MS));
            }
        }
        println!("rpki: client thread stopping");
        self.refresh_status();
    }

    /// Drain one control command.
    fn drain_control(&mut self) -> Control {
        // One command per drain: the outer loop re-enters here every
        // few hundred milliseconds at most, so a queued reload batch
        // drains quickly without a self-recursive loop here.
        if let Ok(RpkiCommand::Reconnect {
            cache,
            refresh_interval,
            retry_interval,
            expire_interval,
        }) = self.control.try_recv()
        {
            self.handle_reconnect(cache, refresh_interval, retry_interval, expire_interval);
            return Control::Interrupt;
        }
        Control::Continue
    }

    /// Apply one Reconnect command (the §8.2 cache-change / §8.1
    /// refresh semantics shared by the loop head and the burst path).
    fn handle_reconnect(
        &mut self,
        cache: String,
        refresh_interval: u32,
        retry_interval: u32,
        expire_interval: u32,
    ) {
        let cache_changed = cache != self.cache;
        if cache_changed {
            println!("rpki: cache changed {} -> {}", self.cache, cache);
            self.cache = cache;
            // The old cache's session/serial are meaningless against a
            // new one (§8.2): reset to a cold-start client carrying
            // the reloaded intervals, and withdraw the old cache's
            // records immediately — they are no longer authoritative.
            self.client = RtrClient::new();
            self.client
                .set_intervals(refresh_interval, retry_interval, expire_interval);
            self.store.clear_rtr();
        } else {
            println!(
                "rpki: reconnecting to {} for a refresh (intervals {}/{}s)",
                self.cache, refresh_interval, retry_interval
            );
            // Same cache: the remembered session survives, but the
            // reloaded intervals govern until the next End of Data.
            self.client
                .set_intervals(refresh_interval, retry_interval, expire_interval);
        }
        // The last sync refers to data that either left with the old
        // cache or is about to be re-verified — stop ageing it.
        self.last_sync = None;
        // Dropping the stream makes the next iteration reconnect;
        // `on_connect()` then sends the §8.1 query (a Serial Query
        // with the remembered session when the cache did not change,
        // a Reset Query when it did).
        self.stream = None;
        self.buf.clear();
        self.refresh_status();
    }

    /// Connect to the current cache. On failure logs and sleeps the
    /// retry backoff (interruptible). Returns whether a connection
    /// was established.
    fn connect(&mut self) -> bool {
        match self.try_connect() {
            Ok(stream) => {
                println!("rpki: connected to {}", self.cache);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
                let _ = stream.set_nodelay(true);
                self.stream = Some(stream);
                self.buf.clear();
                let query = self.client.on_connect();
                self.send(&query);
                self.refresh_status();
                true
            }
            Err(e) => {
                println!(
                    "rpki: connect to {} failed: {} (retry in {}s)",
                    self.cache,
                    e,
                    self.client.intervals().1
                );
                self.refresh_status();
                self.sleep_backoff();
                false
            }
        }
    }

    /// Resolve and try every address (hostnames resolve here, at
    /// connect time — the cache may come up after the daemon does).
    fn try_connect(&self) -> Result<TcpStream, String> {
        let addrs: Vec<_> = self
            .cache
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {}: {e}", self.cache))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("no addresses for {}", self.cache));
        }
        let mut last = "no addresses resolved".to_string();
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(s) => return Ok(s),
                Err(e) => last = format!("{addr}: {e}"),
            }
        }
        Err(last)
    }

    /// Read whatever arrived and run the decoded PDUs through the
    /// client. Returns `false` when the loop should continue from the
    /// top (transport down, backoff slept or pending).
    fn read_available(&mut self) -> bool {
        let mut chunk = [0u8; 8192];
        for _ in 0..READ_BURST {
            // A reload command pending behind a trickle must not wait
            // out the whole burst: consume it through the normal
            // control path (drops the transport / updates intervals)
            // and let the outer loop reconnect immediately.
            if let Ok(RpkiCommand::Reconnect {
                cache,
                refresh_interval,
                retry_interval,
                expire_interval,
            }) = self.control.try_recv()
            {
                self.handle_reconnect(cache, refresh_interval, retry_interval, expire_interval);
                return false;
            }
            let Some(stream) = self.stream.as_mut() else {
                return false;
            };
            match stream.read(&mut chunk) {
                Ok(0) => {
                    println!("rpki: cache {} closed the connection", self.cache);
                    self.disconnect();
                    self.sleep_backoff();
                    return false;
                }
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    if !self.drain_decode() {
                        // The transport is already down (drop / expiry /
                        // write failure inside a step); wait out the
                        // retry backoff before reconnecting.
                        self.sleep_backoff();
                        return false;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    self.refresh_status();
                    return true;
                }
                Err(e) => {
                    println!("rpki: read from {} failed: {}", self.cache, e);
                    self.disconnect();
                    self.sleep_backoff();
                    return false;
                }
            }
        }
        self.refresh_status();
        true
    }

    /// Decode every complete PDU in the buffer and feed the client.
    /// Returns `false` when the transport was dropped.
    fn drain_decode(&mut self) -> bool {
        loop {
            match rtr::decode(&self.buf) {
                Ok(Some((version, pdu, consumed))) => {
                    self.buf.drain(..consumed);
                    let now = self.now_ms();
                    let step = self.client.on_pdu(version, &pdu, now);
                    if !self.apply_step(&step, Some(&pdu)) {
                        return false;
                    }
                }
                Ok(None) => return true,
                Err(e) => {
                    // A malformed PDU means a broken or malicious
                    // cache: reset the session and re-sync from
                    // scratch after the retry backoff.
                    println!("rpki: malformed PDU from {}: {}", self.cache, e);
                    self.reset_client();
                    self.disconnect();
                    return false;
                }
            }
        }
    }

    /// Apply one client step: transmit, apply ROA deltas, log, honor
    /// the drop/expiry flags. `pdu` is the PDU that produced the step
    /// (for logging), if any. Returns `false` when the transport was
    /// dropped (the caller sleeps the retry backoff).
    fn apply_step(&mut self, step: &ClientStep, pdu: Option<&RtrPdu>) -> bool {
        for log in &step.logs {
            println!("rpki: {log}");
        }
        if !step.roa_deltas.is_empty() {
            self.store.apply_rtr_deltas(&step.roa_deltas);
        }
        if step.synced {
            self.last_sync = Some(Instant::now());
            println!(
                "rpki: sync complete (session 0x{:04x} serial {} roas {})",
                self.client.session_id().unwrap_or(0),
                self.client.serial().unwrap_or(0),
                self.store.len()
            );
            // A sync is the one event operational visibility waits for
            // (the API status line must reflect it immediately, not
            // after the next read timeout) — and it happens once per
            // sync, so this is not on the per-PDU hot path.
            self.refresh_status();
        }
        if !step.send.is_empty() && !self.send(&step.send) {
            return false;
        }
        if step.expired {
            // RFC 8210 §6: data past the expire interval MUST NOT be
            // used. Withdraw the cache-sourced records and reset the
            // session — the next sync starts from scratch. The last
            // sync age now refers to withdrawn data: stop ageing it.
            println!(
                "rpki: data expired ({}s without a sync) — withdrawing cache ROAs",
                self.client.intervals().2
            );
            self.last_sync = None;
            self.store.clear_rtr();
            self.reset_client();
            self.disconnect();
            return false;
        }
        if step.drop {
            match pdu {
                Some(p) => println!("rpki: client dropped the session after {p:?}"),
                None => println!("rpki: client dropped the session"),
            }
            self.disconnect();
            return false;
        }
        true
    }

    /// Run the client's timer step (refresh Serial Query, expiry).
    /// Returns `false` when the transport was dropped.
    fn poll_timers(&mut self) -> bool {
        let now = self.now_ms();
        let step = self.client.poll(now);
        if step.send.is_empty() && step.logs.is_empty() && !step.expired {
            return true;
        }
        self.apply_step(&step, None)
    }

    /// Write bytes to the transport. A failure drops the connection
    /// (the caller reconnects after the backoff).
    fn send(&mut self, bytes: &[u8]) -> bool {
        let Some(stream) = self.stream.as_mut() else {
            return false;
        };
        match stream.write_all(bytes).and_then(|()| stream.flush()) {
            Ok(()) => true,
            Err(e) => {
                println!("rpki: write to {} failed: {}", self.cache, e);
                self.disconnect();
                false
            }
        }
    }

    /// Close the transport (idempotent).
    fn disconnect(&mut self) {
        self.stream = None;
        self.buf.clear();
        self.refresh_status();
    }

    /// Cold-start the protocol state machine, preserving the
    /// configured intervals (cache change, data expiry, malformed
    /// PDU).
    fn reset_client(&mut self) {
        let (refresh, retry, expire) = self.client.intervals();
        self.client = RtrClient::new();
        self.client.set_intervals(refresh, retry, expire);
    }

    /// The §6 retry backoff, sliced so shutdown and reload commands
    /// interrupt promptly.
    fn sleep_backoff(&mut self) {
        let total = Duration::from_secs(u64::from(self.client.intervals().1));
        let mut remaining = total;
        while !remaining.is_zero() && self.running.load(Ordering::Relaxed) {
            if matches!(self.drain_control(), Control::Interrupt) {
                return;
            }
            // Cached data must expire while the transport is disconnected.
            self.poll_timers();
            let chunk = remaining.min(Duration::from_millis(BACKOFF_SLICE_MS));
            thread::sleep(chunk);
            remaining = remaining.saturating_sub(chunk);
        }
    }

    fn refresh_status(&mut self) {
        let (refresh, retry, expire) = self.client.intervals();
        let mut st = self.status.lock().unwrap();
        st.cache = self.cache.clone();
        st.connected = self.stream.is_some();
        st.version = self.client.version();
        st.phase = self.client.phase_name();
        st.session_id = self.client.session_id();
        st.serial = self.client.serial();
        st.static_roas = self.store.static_len();
        st.rtr_roas = self.store.rtr_len();
        st.roas = self.store.len();
        st.refresh_interval = refresh;
        st.retry_interval = retry;
        st.expire_interval = expire;
        st.last_sync_age_s = self.last_sync.map(|t| t.elapsed().as_secs());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;

    fn disconnected_state(age: Duration) -> RpkiLoop {
        let mut builder = lr_bgp::RoaTableBuilder::new();
        builder.add("198.51.100.0/24", None, 64513).unwrap();
        let store = Arc::new(RoaStore::from_table(builder.build()));
        let mut client = RtrClient::new();
        client.on_connect();
        for pdu in [
            RtrPdu::CacheResponse { session_id: 1 },
            RtrPdu::Ipv4Prefix {
                announce: true,
                prefix: Prefix::new_v4([192, 0, 2, 0], 24),
                max_length: 24,
                asn: 64512,
            },
            RtrPdu::EndOfData {
                session_id: 1,
                serial: 1,
                refresh_interval: Some(60),
                retry_interval: Some(1),
                expire_interval: Some(120),
            },
        ] {
            let step = client.on_pdu(rtr::RTR_VERSION_MAX, &pdu, 0);
            store.apply_rtr_deltas(&step.roa_deltas);
        }
        assert_eq!(store.rtr_len(), 1);
        let (_, control) = mpsc::channel();
        RpkiLoop {
            store,
            running: Arc::new(AtomicBool::new(true)),
            control,
            status: Arc::new(Mutex::new(RpkiStatus {
                cache: "127.0.0.1:1".into(),
                connected: false,
                version: rtr::RTR_VERSION_MAX,
                phase: "synced",
                session_id: Some(1),
                serial: Some(1),
                static_roas: 1,
                rtr_roas: 1,
                roas: 2,
                refresh_interval: 60,
                retry_interval: 1,
                expire_interval: 120,
                last_sync_age_s: Some(age.as_secs()),
            })),
            cache: "127.0.0.1:1".into(),
            client,
            stream: None,
            buf: Vec::new(),
            start: Instant::now() - age,
            last_sync: Some(Instant::now() - age),
        }
    }

    #[test]
    fn reconnect_backoff_expires_cache_roas_and_preserves_static_roas() {
        let mut state = disconnected_state(Duration::from_secs(121));
        state.sleep_backoff();
        assert_eq!(state.store.rtr_len(), 0, "offline cache data must expire");
        assert_eq!(state.store.static_len(), 1);
        assert_eq!(
            state.client.serial(),
            None,
            "reconnect must use a reset query"
        );
        assert!(state.last_sync.is_none());
        assert_eq!(state.status.lock().unwrap().rtr_roas, 0);
    }

    #[test]
    fn reconnect_backoff_retains_unexpired_cache_roas() {
        let mut state = disconnected_state(Duration::from_secs(61));
        state.sleep_backoff();
        assert_eq!(state.store.rtr_len(), 1);
        assert_eq!(state.store.static_len(), 1);
        assert_eq!(state.client.serial(), Some(1));
    }
}
