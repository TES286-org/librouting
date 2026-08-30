//! `lr-daemon --protocol ospf` — OSPFv2 daemon mode.
//!
//! The OSPF counterpart of the BGP/Babel daemon modes: the router
//! pipeline ([`DefaultRouter`]) owns the protocol logic (neighbor FSMs,
//! per-area LSDBs, flooding, SPF), and this module owns everything the
//! poll-driven core leaves to the embedder:
//!
//! - **Transport** — one raw `IPPROTO_OSPF` socket per configured
//!   interface ([`lr_osroute::ospf_transport`]), multicasting to
//!   224.0.0.5 (RFC 2328 §A.1).
//! - **Hello origination** — one Hello per interface per
//!   `hello_interval`, listing the router-ids heard recently so peers
//!   advance their neighbor FSMs to 2-Way (§9.5.4).
//! - **Router-LSA origination** — the router's own Router-LSA per area
//!   (§12.4.1): one stub link per interface address plus one p2p link
//!   per Full adjacency. Re-originated when adjacencies come or go; the
//!   LSDB's `refresh_due` drives the 1800 s periodic refresh.
//! - **Neighbor discovery** — sessions are created on demand, keyed by
//!   `(area, router-id)`: the first packet from an unknown router gets
//!   a fresh session; the dead timer (`dead_interval` without a
//!   packet) tears it down again. One *anchor* session per area exists
//!   purely to register the area (and its type) with the router and to
//!   accept self-originated LSAs; its output never reaches the wire.
//!
//! ```text
//!   ┌────────────────────────────────────────────────────────────┐
//!   │ lr-daemon --protocol ospf                                   │
//!   │                                                             │
//!   │  eth0 (area 0)      eth1 (area 1)          ticker thread    │
//!   │ ┌────────────┐    ┌────────────┐          ┌──────────────┐  │
//!   │ │ raw :89    │    │ raw :89    │   tick   │ LSA refresh  │  │
//!   │ │ 224.0.0.5  │    │ 224.0.0.5  │ ───────► │ aging(MaxAge)│  │
//!   │ └─────┬──────┘    └─────┬──────┘          └──────────────┘  │
//!   │  recv │  send          │                   events → log/FIB  │
//!   │       ▼                ▼                                    │
//!   │  feed_input / drain_output  ⇄  DefaultRouter                │
//!   │  (per-(area,rid) sessions)     (LSDB per area, SPF, RIB)    │
//!   │  Hello builder + Router-LSA originator                      │
//!   └────────────────────────────────────────────────────────────┘
//! ```
//!
//! Limitations (see docs/STATUS.md): OSPFv2 only; DR election is not
//! run (segments are treated as p2p — DR/BDR stay 0.0.0.0, which
//! interops with peers configured p2p); DBD/LSR exchange is the
//! simplified auto-advance of the router core; authentication is not
//! wired into the daemon yet.

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lr_core::addr::RouterId;
use lr_core::error::EncodeError;
use lr_ospf::codec::OspfCodec;
use lr_ospf::lsa::Lsa;
use lr_ospf::origination::{
    finalize_v2_packet, originate_router_lsa, v2_packet_checksum_ok, RouterLsaLink,
};
use lr_ospf::packet::{HelloBody, LsUpdateBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType};
use lr_osroute::ospf_transport::{
    interface_v4_addrs, prefix_mask, InterfaceV4Addr, OspfV2Transport,
};
use lr_router::{DefaultRouter, RouterEvent, RouterInstance, SessionConfig, SessionHandle};

use crate::daemon_config::{area_label, DaemonConfig, OspfAreaSpec, OspfIfSpec};

/// Default metric of the summary-default injected into stub/NSSA areas
/// when `stub_metric` is not configured (matches the interface cost
/// default).
const DEFAULT_STUB_METRIC: u32 = 10;

/// Loop cadence: also the dead-timer / hello-timer granularity.
const LOOP_INTERVAL_MS: u64 = 50;

/// Cached `LR_OSPF_DEBUG` gate for the wire trace (checked per packet;
/// a raw var_os syscall each time showed up in profiling).
fn ospf_debug_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("LR_OSPF_DEBUG").is_some())
}

/// Delay before an adjacency-driven Router-LSA re-origination:
/// receivers throttle new LSA instances by MinLSArrival (RFC 2328
/// §14, 1 s) — the exchange may have delivered the previous instance
/// moments earlier.
const REORIGINATE_DELAY_MS: u64 = 1_500;

/// One configured interface, resolved against the running kernel.
struct OspfInterface {
    name: String,
    area: u32,
    cost: u16,
    /// Interface MTU advertised in DBDs (RFC 2328 §10.6).
    mtu: u16,
    hello_interval: u16,
    dead_interval: u32,
    priority: u8,
    /// IPv4 addresses (primary + secondary) for stub links + the Hello
    /// network mask.
    addrs: Vec<InterfaceV4Addr>,
    transport: OspfV2Transport,
    /// Last Hello we sent on this interface (ms since daemon start).
    last_hello_ms: u64,
    /// Router-ids heard on this interface → last-heard timestamp (ms).
    /// Drives the Hello neighbor list and the dead timer.
    heard: BTreeMap<u32, u64>,
}

/// One dynamic neighbor session, keyed by `(area, router-id)` in
/// [`OspfDaemon::neighbors`].
struct Neighbor {
    handle: SessionHandle,
    /// Interface the neighbor was first heard on — outbound LSUs are
    /// transmitted there.
    ifindex: u32,
    established: bool,
}

/// Daemon-wide state (the router is shared with the ticker/API threads).
struct OspfDaemon {
    router: Arc<Mutex<DefaultRouter>>,
    interfaces: Vec<OspfInterface>,
    neighbors: BTreeMap<(u32, u32), Neighbor>,
    /// Router-LSA re-originations scheduled for the future (area → due
    /// ms). RFC 2328 §14 MinLSArrival: receivers reject a new instance
    /// of an LSA within ~1 s of the previous one, so adjacency-driven
    /// re-origination (new p2p links) must be spaced from the instance
    /// the exchange just delivered — mirroring the calc-cycle delay
    /// BIRD/FRR naturally have.
    pending_reorig: BTreeMap<u32, u64>,
    /// Area → anchor session (registers the area, accepts
    /// self-originated LSAs; output never reaches the wire).
    anchors: BTreeMap<u32, SessionHandle>,
    /// Area → sequence number of our current Router-LSA instance.
    lsa_seq: BTreeMap<u32, u32>,
    router_id: RouterId,
}

/// Entry point from `daemon.rs`.
pub(super) fn run_ospf_daemon(cfg: &DaemonConfig, rid: RouterId) -> ExitCode {
    if cfg.user.is_some() || cfg.group.is_some() {
        eprintln!(
            "daemon: --user/--group are not supported with --protocol ospf yet \
             (raw sockets are opened before the drop would happen)"
        );
        return ExitCode::from(2);
    }
    if cfg.ospf_interfaces.is_empty() {
        eprintln!(
            "daemon: --protocol ospf needs at least one interface \
             (--ospf-interface NAME or [[ospf.interface]] tables)"
        );
        return ExitCode::from(2);
    }
    // ---- Resolve interfaces against the kernel. ----
    let mut interfaces: Vec<OspfInterface> = Vec::new();
    for spec in &cfg.ospf_interfaces {
        match resolve_interface(cfg, spec) {
            Ok(iface) => {
                println!(
                    "daemon: ospf interface {} area {} — {} address(es), cost {}, \
                     hello {}s dead {}s",
                    iface.name,
                    area_label(iface.area),
                    iface.addrs.len(),
                    iface.cost,
                    iface.hello_interval,
                    iface.dead_interval
                );
                interfaces.push(iface);
            }
            Err(e) => {
                eprintln!("daemon: ospf interface {}: {}", spec.label(), e);
                return ExitCode::from(1);
            }
        }
    }
    let mut daemon = OspfDaemon {
        router: Arc::new(Mutex::new(DefaultRouter::new())),
        interfaces,
        neighbors: BTreeMap::new(),
        pending_reorig: BTreeMap::new(),
        anchors: BTreeMap::new(),
        lsa_seq: BTreeMap::new(),
        router_id: rid,
    };
    // ---- Router: one anchor session per area + area types. ----
    let daemon_iface_mtu = daemon.interfaces.first().map(|i| i.mtu).unwrap_or(1500);
    {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.lock().unwrap();
        for area in daemon.interfaces.iter().map(|i| i.area) {
            if daemon.anchors.contains_key(&area) {
                continue;
            }
            match router
                .add_session(SessionConfig::ospfv2(rid, area).with_ospf_mtu(daemon_iface_mtu))
            {
                Ok(h) => {
                    daemon.anchors.insert(area, h);
                }
                Err(e) => {
                    eprintln!("daemon: ospf add_session area {}: {}", area_label(area), e);
                    return ExitCode::from(1);
                }
            }
        }
        for area_spec in &cfg.ospf_areas {
            let Some(area) = area_spec.id else {
                continue; // finalize() already rejected this
            };
            if !daemon.anchors.contains_key(&area) {
                continue; // declared area without interfaces — nothing to type
            }
            if let Some(kind) = area_kind(area_spec) {
                if !router.ospf_set_area_type(area, kind) {
                    eprintln!(
                        "daemon: warning: could not set area {} type {:?}",
                        area_label(area),
                        area_spec.kind
                    );
                }
            }
        }
    }
    // ---- Signal handling + runtime API + ticker. ----
    if let Err(sig) = crate::signal::init() {
        eprintln!("daemon: cannot install signal handlers (signal {})", sig);
        return ExitCode::from(1);
    }
    let running = Arc::new(AtomicBool::new(true));
    let runtime = Arc::new(crate::Runtime {
        reload: Arc::new(|| {
            // OSPF reload is not wired yet (interface set changes need
            // LSA re-origination + session moves); report it loudly
            // instead of pretending to apply.
            vec![
                "ospf: configuration reload is not supported yet; shutdown still works".to_string(),
            ]
        }),
        router: Arc::clone(&daemon.router),
        running: Arc::clone(&running),
    });
    if let Err(e) = crate::spawn_api(cfg, &runtime) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }
    // The ticker drives tick() (LSA refresh + MaxAge aging) and mirrors
    // Loc-RIB events into the kernel FIB when asked to.
    crate::spawn_ticker(&runtime, cfg.install_kernel, Arc::new(AtomicUsize::new(0)));

    // ---- Initial Router-LSA per area. ----
    {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.lock().unwrap();
        let areas: Vec<u32> = daemon.anchors.keys().copied().collect();
        for area in areas {
            daemon.reoriginate_area(&mut router, area);
        }
    }

    // ---- Main loop. ----
    let start = std::time::Instant::now();
    let mut recv_buf = [0u8; 65535];
    println!(
        "daemon: ospf main loop started ({} interface(s))",
        daemon.interfaces.len()
    );
    while running.load(Ordering::Relaxed) {
        crate::dispatch_signals(&runtime);
        if !running.load(Ordering::Relaxed) {
            break;
        }
        let now_ms = start.elapsed().as_millis() as u64;
        daemon.pump(&mut recv_buf, now_ms);
        std::thread::sleep(Duration::from_millis(LOOP_INTERVAL_MS));
    }
    // Graceful shutdown: close every session so the router emits the
    // down events, then let the ticker drain them.
    {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.lock().unwrap();
        for n in daemon.neighbors.values() {
            router.close_session(n.handle);
        }
        for anchor in daemon.anchors.values() {
            router.close_session(*anchor);
        }
        for ev in router.poll_events() {
            log_event(&ev);
        }
    }
    println!("daemon: ospf shutdown complete");
    ExitCode::SUCCESS
}

/// Resolve one configured interface into runtime state: addresses from
/// the kernel, timers from the config (per-interface → global → RFC
/// defaults), and the raw transport bound to the device.
fn resolve_interface(cfg: &DaemonConfig, spec: &OspfIfSpec) -> Result<OspfInterface, String> {
    let name = spec.label().to_string();
    let addrs = interface_v4_addrs(&name).map_err(|e| e.to_string())?;
    if addrs.is_empty() {
        // The transport works on unnumbered links, but without an
        // address there is no stub link and no Hello mask.
        return Err(format!("no IPv4 address on {}", name));
    }
    let transport = OspfV2Transport::bind(&name, false).map_err(|e| {
        if e.is_permission_denied() {
            format!(
                "{} (raw OSPF sockets need root or a user/network namespace \
                 — e.g. unshare -Urn)",
                e
            )
        } else {
            e.to_string()
        }
    })?;
    // The main loop polls every interface each pass — blocking sockets
    // would deadlock it (the Babel daemon does the same for UDP).
    transport
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking on {}: {}", name, e))?;
    let iface_mtu = transport.mtu().unwrap_or(1500);
    let hello = spec
        .hello_interval
        .unwrap_or(cfg.ospf_hello_interval)
        .max(1);
    let dead = spec
        .dead_interval
        .unwrap_or(cfg.ospf_dead_interval)
        .max(u32::from(hello));
    Ok(OspfInterface {
        name,
        area: spec.area.unwrap_or(cfg.ospf_area),
        cost: spec.cost.unwrap_or(10),
        mtu: iface_mtu,
        hello_interval: hello,
        dead_interval: dead,
        priority: spec.priority.unwrap_or(1),
        addrs,
        transport,
        last_hello_ms: 0,
        heard: BTreeMap::new(),
    })
}

/// Map a configured area table onto the router's area-type enum.
fn area_kind(spec: &OspfAreaSpec) -> Option<lr_router::OspfAreaType> {
    use lr_router::OspfAreaType;
    let metric = spec.stub_metric.unwrap_or(DEFAULT_STUB_METRIC);
    match (spec.kind.as_deref(), spec.no_summary.unwrap_or(false)) {
        (Some("stub"), false) => Some(OspfAreaType::stub(metric)),
        (Some("stub"), true) => Some(OspfAreaType::stub_no_summary(metric)),
        (Some("nssa"), false) => Some(OspfAreaType::nssa(metric)),
        (Some("nssa"), true) => Some(OspfAreaType::nssa_no_summary(metric)),
        _ => None,
    }
}

impl OspfDaemon {
    /// One main-loop pass: receive, demultiplex, track neighbors, check
    /// adjacency transitions and the dead timer, originate Hellos,
    /// drain and transmit.
    fn pump(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        self.pump_inbound(recv_buf, now_ms);
        self.pump_adjacency(now_ms);
        self.pump_dead_timer(now_ms);
        self.pump_reoriginate(now_ms);
        self.pump_hellos(now_ms);
        self.pump_outbound();
    }

    /// Receive every pending datagram and feed it into the matching
    /// neighbor session, creating sessions for unknown routers.
    fn pump_inbound(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        // Collect: (ifindex, interface area, datagram bytes).
        let mut datagrams: Vec<(u32, u32, Vec<u8>)> = Vec::new();
        for iface in &self.interfaces {
            loop {
                match iface.transport.recv_from(recv_buf) {
                    Ok(Some((n, _src))) => {
                        // Linux raw sockets deliver the full IP datagram;
                        // strip the header so the router's OSPF codec
                        // sees a bare packet.
                        if let Some(ospf) = strip_ipv4_header(&recv_buf[..n]) {
                            if ospf_debug_enabled() {
                                eprintln!(
                                    "dbg-recv kind={} len={} rid={:08x}",
                                    ospf.get(1).copied().unwrap_or(0),
                                    u16::from_be_bytes([ospf[2], ospf[3]]),
                                    u32::from_be_bytes([ospf[4], ospf[5], ospf[6], ospf[7]])
                                );
                            }
                            datagrams.push((iface.transport.ifindex(), iface.area, ospf.to_vec()));
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("daemon: ospf recv {}: {}", iface.name, e);
                        break;
                    }
                }
            }
        }
        // Demux: parse the fixed header, keep only packets for this
        // interface's area from other routers with a valid checksum.
        let mut accepted: Vec<(u32, u32, u32, usize, u16)> = Vec::new(); // (ifindex, area, rid, idx, mtu)
        for (idx, (ifindex, iface_area, bytes)) in datagrams.iter().enumerate() {
            let Some((rid, area, len)) = demux_header(bytes) else {
                if ospf_debug_enabled() {
                    eprintln!("dbg-drop demux");
                }
                continue;
            };
            if area != *iface_area {
                continue; // foreign area on this interface
            }
            if rid == self.router_id.as_u32() {
                continue; // our own multicast (loopback)
            }
            if !v2_packet_checksum_ok(&bytes[..len as usize]) {
                if ospf_debug_enabled() {
                    eprintln!(
                        "dbg-drop checksum kind={} len={}",
                        bytes.get(1).copied().unwrap_or(0),
                        len
                    );
                }
                continue; // corrupt — BIRD/FRR would drop it too
            }
            let mtu = self
                .interfaces
                .iter()
                .find(|i| i.transport.ifindex() == *ifindex)
                .map(|i| i.mtu)
                .unwrap_or(1500);
            accepted.push((*ifindex, area, rid, idx, mtu));
        }
        if accepted.is_empty() {
            return;
        }
        let mut new_neighbors: Vec<(u32, u32, u32)> = Vec::new(); // (ifindex, area, rid)
        {
            let router_arc = Arc::clone(&self.router);
            let mut router = router_arc.lock().unwrap();
            for (ifindex, area, rid, idx, mtu) in accepted {
                if let Some(iface) = self
                    .interfaces
                    .iter_mut()
                    .find(|i| i.transport.ifindex() == ifindex)
                {
                    iface.heard.insert(rid, now_ms);
                }
                let key = (area, rid);
                if !self.neighbors.contains_key(&key) {
                    match router
                        .add_session(SessionConfig::ospfv2(self.router_id, area).with_ospf_mtu(mtu))
                    {
                        Ok(h) => {
                            self.neighbors.insert(
                                key,
                                Neighbor {
                                    handle: h,
                                    ifindex,
                                    established: false,
                                },
                            );
                            new_neighbors.push((ifindex, area, rid));
                        }
                        Err(e) => {
                            eprintln!("daemon: ospf add_session: {}", e);
                            continue;
                        }
                    }
                }
                let handle = self.neighbors[&key].handle;
                if let Err(e) = router.feed_input(handle, &datagrams[idx].2) {
                    eprintln!("daemon: ospf feed_input: {}", e);
                }
            }
            for ev in router.poll_events() {
                log_event(&ev);
            }
        }
        for (ifindex, area, rid) in new_neighbors {
            println!(
                "daemon: ospf neighbor {} discovered (area {}, iface {})",
                fmt_rid(rid),
                area_label(area),
                self.iface_name(ifindex)
            );
        }
    }

    /// Watch for sessions reaching Full — each one adds a p2p link to
    /// the area's Router-LSA (RFC 2328 §12.4.1).
    fn pump_adjacency(&mut self, now_ms: u64) {
        let mut newly_full: Vec<(u32, u32)> = Vec::new(); // (area, rid)
        {
            let router_arc = Arc::clone(&self.router);
            let router = router_arc.lock().unwrap();
            let summaries = router.session_summaries();
            let mut changed_areas: Vec<u32> = Vec::new();
            for ((area, rid), n) in self.neighbors.iter_mut() {
                let est = summaries
                    .iter()
                    .any(|s| s.handle == n.handle && s.established);
                if est && !n.established {
                    n.established = true;
                    changed_areas.push(*area);
                    newly_full.push((*area, *rid));
                }
            }
            for area in changed_areas {
                self.schedule_reoriginate(area, now_ms);
            }
        }
        for (area, rid) in newly_full {
            println!(
                "daemon: ospf neighbor {} Full (area {})",
                fmt_rid(rid),
                area_label(area)
            );
        }
    }

    /// Schedule a Router-LSA re-origination for `area` at
    /// now + MinLSArrival (+ slack).
    fn schedule_reoriginate(&mut self, area: u32, now_ms: u64) {
        let due = now_ms + REORIGINATE_DELAY_MS;
        let prev = self.pending_reorig.insert(area, due);
        if prev.is_none() {
            println!(
                "daemon: ospf area {} Router-LSA re-origination scheduled",
                area_label(area)
            );
        }
    }

    /// Fire due re-originations.
    fn pump_reoriginate(&mut self, now_ms: u64) {
        let due: Vec<u32> = self
            .pending_reorig
            .iter()
            .filter(|(_, &d)| now_ms >= d)
            .map(|(&a, _)| a)
            .collect();
        if due.is_empty() {
            return;
        }
        let router_arc = Arc::clone(&self.router);
        let mut router = router_arc.lock().unwrap();
        for area in due {
            self.pending_reorig.remove(&area);
            self.reoriginate_area(&mut router, area);
        }
    }

    /// Tear down sessions whose router went silent for the interface's
    /// dead interval (RFC 2328 §10.2 inactivity timer).
    fn pump_dead_timer(&mut self, now_ms: u64) {
        let mut expired: Vec<(u32, u32)> = Vec::new(); // (area, rid)
        for iface in &mut self.interfaces {
            let dead_ms = u64::from(iface.dead_interval) * 1000;
            let gone: Vec<u32> = iface
                .heard
                .iter()
                .filter(|(_, &t)| now_ms.saturating_sub(t) > dead_ms)
                .map(|(rid, _)| *rid)
                .collect();
            for rid in gone {
                iface.heard.remove(&rid);
                expired.push((iface.area, rid));
            }
        }
        if expired.is_empty() {
            return;
        }
        let router_arc = Arc::clone(&self.router);
        let mut router = router_arc.lock().unwrap();
        for (area, rid) in expired {
            if let Some(n) = self.neighbors.remove(&(area, rid)) {
                router.close_session(n.handle);
                println!(
                    "daemon: ospf neighbor {} dead (area {}) — session closed",
                    fmt_rid(rid),
                    area_label(area)
                );
            }
        }
        for ev in router.poll_events() {
            log_event(&ev);
        }
        // The p2p links to the dead routers are gone from the LSA.
        drop(router);
        let areas: Vec<u32> = self.anchors.keys().copied().collect();
        for area in areas {
            self.schedule_reoriginate(area, now_ms);
        }
    }

    /// Send one Hello per interface whose interval elapsed, listing the
    /// router-ids heard inside the dead window (RFC 2328 §A.3.2).
    /// Debug-gated wire trace of an outbound packet stream.
    #[allow(dead_code)]
    fn dbg_send_trace(bytes: &[u8]) {
        if std::env::var_os("LR_OSPF_DEBUG").is_none() {
            return;
        }
        let mut off = 0usize;
        while off + 24 <= bytes.len() {
            let len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
            if off + len > bytes.len() {
                break;
            }
            eprintln!(
                "dbg-send kind={} len={} rid={:08x}",
                bytes[off + 1],
                len,
                u32::from_be_bytes([
                    bytes[off + 4],
                    bytes[off + 5],
                    bytes[off + 6],
                    bytes[off + 7]
                ])
            );
            off += len;
        }
    }

    fn pump_hellos(&mut self, now_ms: u64) {
        for iface in self.interfaces.iter_mut() {
            let interval_ms = u64::from(iface.hello_interval) * 1000;
            if now_ms.saturating_sub(iface.last_hello_ms) < interval_ms {
                continue;
            }
            iface.last_hello_ms = now_ms;
            let dead_ms = u64::from(iface.dead_interval) * 1000;
            let neighbors: Vec<u32> = iface
                .heard
                .iter()
                .filter(|(_, &t)| now_ms.saturating_sub(t) <= dead_ms)
                .map(|(rid, _)| *rid)
                .collect();
            let mask = iface
                .addrs
                .first()
                .map(|a| prefix_mask(a.prefix_len))
                .unwrap_or(0xffff_ffff);
            let (rid, area, hello, dead, priority) = (
                self.router_id,
                iface.area,
                iface.hello_interval,
                iface.dead_interval,
                iface.priority,
            );
            let mut bytes = match build_hello(rid, area, mask, hello, dead, priority, neighbors) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("daemon: ospf hello encode: {}", e);
                    continue;
                }
            };
            finalize_v2_packet(&mut bytes);
            Self::dbg_send_trace(&bytes);
            if let Err(e) = iface.transport.send_multicast(&bytes) {
                eprintln!("daemon: ospf hello send {}: {}", iface.name, e);
            }
        }
    }

    /// Drain neighbor sessions (transmit on the interface the neighbor
    /// was heard on) and anchors (discard — no wire neighbor).
    ///
    /// The drained stream can hold several back-to-back packets (an
    /// LSR plus its LSU answer, an LSAck plus a flood, ...) — each one
    /// MUST ride its own IP datagram: one OSPF packet per datagram is
    /// how every implementation parses the protocol, and trailing
    /// bytes of a concatenated send are silently ignored by BIRD/FRR.
    fn pump_outbound(&mut self) {
        let mut outbound: Vec<(u32, Vec<u8>)> = Vec::new(); // (ifindex, datagram)
        {
            let router_arc = Arc::clone(&self.router);
            let mut router = router_arc.lock().unwrap();
            for n in self.neighbors.values() {
                let stream = router.drain_output(n.handle);
                if stream.is_empty() {
                    continue;
                }
                // The router finalizes the RFC 2328 §A.1 checksum on every
                // OSPFv2 packet it emits (feed_input, tick exchange, flood).
                // Finalizing again would zero the checksum — the second pass
                // folds the already-set field and recomputes a wrong value.
                let mut off = 0usize;
                while off + lr_ospf::packet::OspfHeader::LEN <= stream.len() {
                    let len = u16::from_be_bytes([stream[off + 2], stream[off + 3]]) as usize;
                    if len < lr_ospf::packet::OspfHeader::LEN || off + len > stream.len() {
                        break; // malformed tail
                    }
                    outbound.push((n.ifindex, stream[off..off + len].to_vec()));
                    off += len;
                }
            }
            for anchor in self.anchors.values() {
                let _ = router.drain_output(*anchor); // discard
            }
        }
        for (ifindex, bytes) in outbound {
            if let Some(iface) = self
                .interfaces
                .iter()
                .find(|i| i.transport.ifindex() == ifindex)
            {
                Self::dbg_send_trace(&bytes);
                if let Err(e) = iface.transport.send_multicast(&bytes) {
                    eprintln!("daemon: ospf send {}: {}", iface.name, e);
                }
            }
        }
    }

    /// Build, install and flood our Router-LSA for `area`: stub links
    /// for every interface address of the area plus p2p links for every
    /// Full adjacency heard on the area's interfaces. The LSA enters
    /// the area LSDB through the anchor session, which floods it to the
    /// neighbor sessions (RFC 2328 §12.4.1 + §13.3).
    fn reoriginate_area(&mut self, router: &mut DefaultRouter, area: u32) {
        let mut links: Vec<RouterLsaLink> = Vec::new();
        for iface in &self.interfaces {
            if iface.area != area {
                continue;
            }
            for addr in &iface.addrs {
                links.push(RouterLsaLink::Stub {
                    network: u32::from(addr.network()),
                    mask: prefix_mask(addr.prefix_len),
                    metric: iface.cost,
                });
            }
            let local = iface.addrs.first().map(|a| u32::from(a.addr)).unwrap_or(0);
            for (&(n_area, rid), n) in &self.neighbors {
                if n_area == area && n.established && iface.heard.contains_key(&rid) {
                    links.push(RouterLsaLink::PointToPoint {
                        neighbor: rid,
                        local_addr: local,
                        metric: iface.cost,
                    });
                }
            }
        }
        let prev = self.lsa_seq.get(&area).copied();
        let Some(lsa) = originate_router_lsa(self.router_id.as_u32(), &links, prev) else {
            eprintln!(
                "daemon: ospf router-LSA sequence space exhausted for area {}",
                area_label(area)
            );
            return;
        };
        self.lsa_seq.insert(area, lsa.header.ls_sequence_number);
        let Some(&anchor) = self.anchors.get(&area) else {
            return;
        };
        let packet = self_lsu(self.router_id, area, vec![lsa]);
        match OspfCodec::v2().encode_vec(&packet) {
            Ok(mut bytes) => {
                finalize_v2_packet(&mut bytes);
                if let Err(e) = router.feed_input(anchor, &bytes) {
                    eprintln!("daemon: ospf self-origination feed: {}", e);
                }
            }
            Err(e) => eprintln!("daemon: ospf router-LSA encode: {}", e),
        }
    }

    fn iface_name(&self, ifindex: u32) -> &str {
        self.interfaces
            .iter()
            .find(|i| i.transport.ifindex() == ifindex)
            .map(|i| i.name.as_str())
            .unwrap_or("?")
    }
}

/// A self-originated LS-Update carrying `lsas` (RFC 2328 §A.3.5).
fn self_lsu(rid: RouterId, area: u32, lsas: Vec<Lsa>) -> OspfPacket {
    OspfPacket {
        header: OspfHeader {
            version: 2,
            kind: OspfPacketType::LinkStateUpdate as u8,
            length: 0,
            router_id: rid.as_u32(),
            area_id: area,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: OspfBody::LsUpdate(LsUpdateBody {
            lsa_count: lsas.len() as u32,
            lsas,
        }),
    }
}

/// Strip the IPv4 header of a raw-socket datagram, verifying that it
/// carries OSPF (protocol 89). Returns the OSPF packet bytes.
fn strip_ipv4_header(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 20 {
        return None;
    }
    if bytes[0] >> 4 != 4 {
        return None; // not IPv4
    }
    let ihl = (bytes[0] & 0x0f) as usize * 4;
    if ihl < 20 || bytes.len() < ihl {
        return None;
    }
    if bytes[9] != 89 {
        return None; // not OSPF
    }
    Some(&bytes[ihl..])
}

/// Extract `(router-id, area, length)` from a raw OSPFv2 datagram
/// without a full decode. Returns `None` for short or non-v2 packets.
fn demux_header(bytes: &[u8]) -> Option<(u32, u32, u16)> {
    if bytes.len() < OspfHeader::LEN {
        return None;
    }
    if bytes[0] != 2 {
        return None;
    }
    let len = u16::from_be_bytes([bytes[2], bytes[3]]);
    if (len as usize) < OspfHeader::LEN || (len as usize) > bytes.len() {
        return None;
    }
    let rid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let area = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    Some((rid, area, len))
}

/// Encode one Hello packet (RFC 2328 §A.3.2).
fn build_hello(
    rid: RouterId,
    area: u32,
    mask: u32,
    hello_interval: u16,
    dead_interval: u32,
    priority: u8,
    neighbors: Vec<u32>,
) -> Result<Vec<u8>, EncodeError> {
    let packet = OspfPacket {
        header: OspfHeader {
            version: 2,
            kind: OspfPacketType::Hello as u8,
            length: 0,
            router_id: rid.as_u32(),
            area_id: area,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: OspfBody::Hello(HelloBody {
            network_mask: mask,
            hello_interval,
            options: 0x02, // E-bit
            priority,
            dead_interval,
            dr: 0,
            bdr: 0,
            neighbors,
        }),
    };
    OspfCodec::v2().encode_vec(&packet)
}

fn fmt_rid(rid: u32) -> String {
    RouterId::from_u32(rid).to_string()
}

fn log_event(ev: &RouterEvent) {
    match ev {
        RouterEvent::PeerStateChange { session, state } => {
            println!("daemon: session #{} → {}", session.0, state);
        }
        RouterEvent::RouteInstalled(r) => {
            println!(
                "daemon: route installed {} via {}",
                r.key.prefix,
                r.next_hop
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "(none)".into())
            );
        }
        RouterEvent::RouteWithdrawn(k) => {
            println!("daemon: route withdrawn {}", k.prefix);
        }
        RouterEvent::Log(msg) => println!("daemon: {}", msg),
        RouterEvent::ProtocolError { session, message } => {
            eprintln!("daemon: session #{} error: {}", session.0, message)
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ipv4_header_extracts_ospf() {
        let pkt = build_hello(
            RouterId::from_u32(0x0a00_0001),
            7,
            0xffff_ff00,
            10,
            40,
            1,
            vec![],
        )
        .unwrap();
        // Simulate a raw-socket datagram: 20-byte IP header (protocol 89)
        // in front of the OSPF packet.
        let mut dg = vec![0u8; 20];
        dg[0] = 0x45; // IPv4, IHL 5
        dg[9] = 89; // OSPF
        dg.extend_from_slice(&pkt);
        let stripped = strip_ipv4_header(&dg).unwrap();
        assert_eq!(stripped, &pkt[..]);
        // Non-OSPF protocol, wrong version, truncated → None.
        let mut other = dg.clone();
        other[9] = 6; // TCP
        assert!(strip_ipv4_header(&other).is_none());
        let mut v6 = dg.clone();
        v6[0] = 0x65;
        assert!(strip_ipv4_header(&v6).is_none());
        assert!(strip_ipv4_header(&dg[..12]).is_none());
    }

    #[test]
    fn demux_header_parses_and_rejects() {
        let pkt = build_hello(
            RouterId::from_u32(0x0a00_0001),
            7,
            0xffff_ff00,
            10,
            40,
            1,
            vec![0x0a00_0002],
        )
        .unwrap();
        let (rid, area, len) = demux_header(&pkt).unwrap();
        assert_eq!(rid, 0x0a00_0001);
        assert_eq!(area, 7);
        assert_eq!(len as usize, pkt.len());
        // Short / wrong version / bad length → None.
        assert!(demux_header(&pkt[..20]).is_none());
        let mut v3 = pkt.clone();
        v3[0] = 3;
        assert!(demux_header(&v3).is_none());
        let mut bad_len = pkt.clone();
        bad_len[3] = 0xff; // length > buffer
        assert!(demux_header(&bad_len).is_none());
    }

    #[test]
    fn area_kind_mapping() {
        use lr_router::OspfAreaType;
        let mut spec = OspfAreaSpec {
            id: Some(1),
            kind: Some("stub".into()),
            no_summary: Some(false),
            stub_metric: Some(42),
        };
        assert_eq!(area_kind(&spec), Some(OspfAreaType::stub(42)));
        spec.no_summary = Some(true);
        assert_eq!(area_kind(&spec), Some(OspfAreaType::stub_no_summary(42)));
        spec.kind = Some("nssa".into());
        assert_eq!(area_kind(&spec), Some(OspfAreaType::nssa_no_summary(42)));
        spec.no_summary = Some(false);
        spec.stub_metric = None;
        assert_eq!(
            area_kind(&spec),
            Some(OspfAreaType::nssa(DEFAULT_STUB_METRIC))
        );
        // normal / unset → no router call needed.
        spec.kind = None;
        assert_eq!(area_kind(&spec), None);
        spec.kind = Some("normal".into());
        assert_eq!(area_kind(&spec), None);
    }
}
