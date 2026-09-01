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
//! Limitations (see docs/STATUS.md): OSPFv2 only; authentication is not
//! wired into the daemon yet. Broadcast segments (RFC 2328 §9.4) run
//! the full DR/BDR election — Hello DR/BDR fields (§A.3.2), the §10.4
//! adjacency gate, §12.4.1.2 transit links and §12.4.2 Network-LSAs —
//! behind the per-interface `network_type = "broadcast"` switch; p2p
//! remains the default so existing labs are unaffected.

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lr_core::addr::RouterId;
use lr_core::error::EncodeError;
use lr_ospf::codec::OspfCodec;
use lr_ospf::interface::{elect as dr_elect, Elector, IfState};
use lr_ospf::lsa::Lsa;
use lr_ospf::origination::{
    finalize_v2_packet, originate_network_lsa, originate_router_lsa, v2_packet_checksum_ok,
    RouterLsaLink,
};
use lr_ospf::packet::{HelloBody, LsUpdateBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType};
use lr_osroute::ospf_transport::{
    interface_v4_addrs, prefix_mask, InterfaceV4Addr, OspfV2Transport,
};
use lr_router::{
    DefaultRouter, OspfNetworkType, RouterEvent, RouterInstance, SessionConfig, SessionHandle,
};

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
    /// RFC 2328 §9.1 network type — `Broadcast` runs the DR/BDR
    /// election, `PointToPoint` (the default) adjacencies with every
    /// bidirectional neighbor.
    network_type: OspfNetworkType,
    /// Elected DR/BDR as IP interface addresses (§A.3.2; 0 = none).
    dr: u32,
    bdr: u32,
    /// This router's own router-id (the election tie-break input).
    router_id: u32,
    /// Interface FSM state (§9.4): `Waiting` until the wait timer or
    /// BackupSeen, then DR/Backup/DR-Other from the election.
    if_state: IfState,
    /// When the §9.3 WaitTimer fires (ms since daemon start;
    /// RouterDeadInterval after interface-up). 0 = not waiting.
    wait_deadline_ms: u64,
    /// Set when a neighbor started/stopped declaring itself DR/BDR or
    /// its priority changed (§10.3 NeighborChange) or the bidirectional
    /// set changed — the next pump re-runs the election.
    election_dirty: bool,
    /// IPv4 addresses (primary + secondary) for stub links + the Hello
    /// network mask.
    addrs: Vec<InterfaceV4Addr>,
    transport: OspfV2Transport,
    /// Last Hello we sent on this interface (ms since daemon start).
    last_hello_ms: u64,
    /// Router-ids heard on this interface, parsed from their Hellos.
    /// Drives the Hello neighbor list, the dead timer and the election.
    heard: BTreeMap<u32, HeardNeighbor>,
    /// Sequence number of our current Network-LSA for this segment
    /// (§12.4.2 — only originated when we are the DR), and whether one
    /// is currently active (needs flushing when we cease to be DR).
    net_lsa_seq: Option<u32>,
    net_lsa_active: bool,
}

/// One neighbor heard on an interface (RFC 2328 §10.5 Hello state).
#[derive(Debug, Clone, Copy)]
struct HeardNeighbor {
    /// The neighbor's IP interface address on the segment (source of
    /// its Hellos) — the election identity (§A.3.2 DR/BDR wire form).
    ip: u32,
    priority: u8,
    /// The DR/BDR the neighbor claims in its Hellos (IP addresses).
    stated_dr: u32,
    stated_bdr: u32,
    /// Last heard (ms since daemon start).
    last_ms: u64,
    /// The neighbor lists our router-id — bidirectional (state ≥ 2-Way
    /// per §10.1), i.e. eligible for the §9.4 election input.
    bidirectional: bool,
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
            Ok(mut iface) => {
                iface.router_id = rid.as_u32();
                println!(
                    "daemon: ospf interface {} area {} — {} address(es), cost {}, \
                     hello {}s dead {}s, {} (priority {}, state {})",
                    iface.name,
                    area_label(iface.area),
                    iface.addrs.len(),
                    iface.cost,
                    iface.hello_interval,
                    iface.dead_interval,
                    match iface.network_type {
                        OspfNetworkType::PointToPoint => "point-to-point",
                        OspfNetworkType::Broadcast => "broadcast",
                    },
                    iface.priority,
                    iface.if_state.name(),
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
        status_lines: Arc::new(Vec::new),
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
    // RFC 2328 §9.1 network type. The default stays point-to-point (the
    // historical lr behavior); `network_type = "broadcast"` opts the
    // segment into the §9.4 DR/BDR election.
    let network_type = match spec.network_type.as_deref() {
        None | Some("p2p") | Some("point-to-point") | Some("") => OspfNetworkType::PointToPoint,
        Some("broadcast") => OspfNetworkType::Broadcast,
        Some(other) => {
            return Err(format!(
                "unknown network_type '{other}' (use \"p2p\" or \"broadcast\")"
            ))
        }
    };
    Ok(OspfInterface {
        name,
        area: spec.area.unwrap_or(cfg.ospf_area),
        cost: spec.cost.unwrap_or(10),
        mtu: iface_mtu,
        hello_interval: hello,
        dead_interval: dead,
        priority: spec.priority.unwrap_or(1),
        network_type,
        dr: 0,
        bdr: 0,
        router_id: 0,
        // §9.3: broadcast interfaces come up in Waiting and wait
        // RouterDeadInterval before electing (p2p has no DR election;
        // priority-0 routers skip Waiting per §9.4 — they are never
        // eligible, BIRD goes straight to DR-Other too).
        if_state: if network_type == OspfNetworkType::Broadcast && spec.priority.unwrap_or(1) > 0
        {
            IfState::Waiting
        } else {
            IfState::DrOther
        },
        wait_deadline_ms: if network_type == OspfNetworkType::Broadcast
            && spec.priority.unwrap_or(1) > 0
        {
            // §9.3: the WaitTimer runs RouterDeadInterval from ifup.
            // The main-loop clock starts right after resolve, so the
            // deadline is the dead interval itself.
            u64::from(dead) * 1000
        } else {
            0
        },
        election_dirty: false,
        addrs,
        transport,
        last_hello_ms: 0,
        heard: BTreeMap::new(),
        net_lsa_seq: None,
        net_lsa_active: false,
    })
}

impl OspfInterface {
    /// §10.5: fold one received Hello into the interface's neighbor
    /// table. Flags the interface election-dirty when the neighbor
    /// started/stopped declaring itself DR/BDR or its priority changed
    /// (§10.3 NeighborChange), or when bidirectionality is first
    /// established (the §9.4 elector set grew).
    fn track_hello(&mut self, rid: u32, ip: u32, body: &HelloBody, our_rid: u32, now_ms: u64) {
        let bidirectional = body.neighbors.contains(&our_rid);
        let became_bidirectional = match self.heard.get(&rid) {
            Some(prev) => {
                // §10.3 NeighborChange: transitions of the neighbor's
                // own DR/BDR claims or its priority (BIRD hello.c
                // parity — only declare-transitions matter, not every
                // claim value change).
                if prev.priority != body.priority
                    || (prev.stated_dr == prev.ip) != (body.dr == ip)
                    || (prev.stated_bdr == prev.ip) != (body.bdr == ip)
                {
                    self.election_dirty = true;
                }
                bidirectional && !prev.bidirectional
            }
            None => bidirectional,
        };
        if became_bidirectional {
            self.election_dirty = true;
        }
        self.heard.insert(
            rid,
            HeardNeighbor {
                ip,
                priority: body.priority,
                stated_dr: body.dr,
                stated_bdr: body.bdr,
                last_ms: now_ms,
                bidirectional,
            },
        );
    }
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
    /// One main-loop pass: receive, demultiplex, track neighbors, run
    /// the DR election, check adjacency transitions and the dead timer,
    /// originate Hellos, drain and transmit.
    fn pump(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        self.pump_inbound(recv_buf, now_ms);
        self.pump_election(now_ms);
        self.pump_adjacency(now_ms);
        self.pump_dead_timer(now_ms);
        self.pump_reoriginate(now_ms);
        self.pump_hellos(now_ms);
        self.pump_outbound();
    }

    /// Receive every pending datagram and feed it into the matching
    /// neighbor session, creating sessions for unknown routers.
    /// Hellos additionally update the per-interface neighbor table
    /// (§10.5) that drives the DR/BDR election.
    fn pump_inbound(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        // Collect: (ifindex, interface area, datagram bytes).
        let mut datagrams: Vec<(u32, u32, Vec<u8>)> = Vec::new();
        for iface in &mut self.interfaces {
            loop {
                match iface.transport.recv_from(recv_buf) {
                    Ok(Some((n, src))) => {
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
                            // §10.5: parse Hellos for the interface's
                            // neighbor table (election + Hello lists).
                            // Only same-area Hellos from other routers
                            // update the table (§10.5 drops mismatched
                            // area/our-own packets silently).
                            if ospf.len() >= 12
                                && ospf.get(1).copied() == Some(OspfPacketType::Hello as u8)
                            {
                                let hello_rid =
                                    u32::from_be_bytes([ospf[4], ospf[5], ospf[6], ospf[7]]);
                                let hello_area =
                                    u32::from_be_bytes([ospf[8], ospf[9], ospf[10], ospf[11]]);
                                if hello_rid != self.router_id.as_u32() && hello_area == iface.area
                                {
                                    if let Some(body) = parse_hello_body(ospf) {
                                        iface.track_hello(
                                            hello_rid,
                                            u32::from(src),
                                            &body,
                                            self.router_id.as_u32(),
                                            now_ms,
                                        );
                                    }
                                }
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
                let key = (area, rid);
                if !self.neighbors.contains_key(&key) {
                    // Broadcast segments carry the network type and the
                    // segment identities into the session: §10.4 gates
                    // adjacency on the elected DR/BDR, identified by IP
                    // interface address (§A.3.2).
                    let cfg_build = self
                        .interfaces
                        .iter()
                        .find(|i| i.transport.ifindex() == ifindex)
                        .map(|iface| {
                            let cfg = SessionConfig::ospfv2(self.router_id, area)
                                .with_ospf_mtu(mtu)
                                .with_ospf_network_type(iface.network_type);
                            let our_ip = iface.addrs.first().map(|a| u32::from(a.addr));
                            let peer_ip = iface.heard.get(&rid).map(|h| h.ip);
                            let cfg = match our_ip {
                                Some(ip) => cfg.with_ospf_interface_ip(ip),
                                None => cfg,
                            };
                            match peer_ip {
                                Some(ip) => cfg.with_ospf_neighbor_ip(ip),
                                None => cfg,
                            }
                        })
                        .unwrap_or_else(|| SessionConfig::ospfv2(self.router_id, area));
                    match router.add_session(cfg_build) {
                        Ok(h) => {
                            // Push the current election result so a
                            // session joining mid-life adopts the
                            // segment's DR/BDR immediately.
                            let (dr, bdr) = self
                                .interfaces
                                .iter()
                                .find(|i| i.transport.ifindex() == ifindex)
                                .map(|i| (i.dr, i.bdr))
                                .unwrap_or((0, 0));
                            let _ = router.set_ospf_dr_state(h, dr, bdr);
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

    /// Drive the interface state machine and the DR/BDR election on
    /// broadcast segments (RFC 2328 §9.3, §9.4). p2p interfaces never
    /// elect (§9.4 does not apply) and are skipped.
    fn pump_election(&mut self, now_ms: u64) {
        let mut changed_areas: Vec<u32> = Vec::new();
        for iface in &mut self.interfaces {
            if iface.network_type != OspfNetworkType::Broadcast {
                continue;
            }
            let fire = match iface.if_state {
                IfState::Waiting => {
                    // §9.3 BackupSeen: a bidirectional neighbor declared
                    // itself BDR, or declared itself DR with no BDR —
                    // track_hello flags both by dirtying the interface.
                    iface.election_dirty
                        || (iface.wait_deadline_ms != 0 && now_ms >= iface.wait_deadline_ms)
                }
                IfState::DrOther | IfState::Backup | IfState::Dr => {
                    // §9.3 NeighborChange: the DR/BDR relationship of a
                    // neighbor (or the bidirectional set) changed.
                    iface.election_dirty
                }
                _ => false,
            };
            if fire {
                iface.wait_deadline_ms = 0;
                iface.election_dirty = false;
                if Self::run_election(iface, &mut self.neighbors, &self.router, now_ms) {
                    // The transit-link set (§12.4.1.2) and the
                    // Network-LSA membership (§12.4.2) may have changed.
                    if !changed_areas.contains(&iface.area) {
                        changed_areas.push(iface.area);
                    }
                }
            }
        }
        let now = now_ms;
        for area in changed_areas {
            self.schedule_reoriginate(area, now);
        }
    }

    /// One §9.4 election round on `iface`: the elector list is the
    /// bidirectional neighbors heard within the dead window plus this
    /// router itself. The result lands in the Hello DR/BDR fields
    /// (§A.3.2) and is pushed into every session on the segment, whose
    /// §10.4 adjacency gate the router re-runs (§9.4 step 7).
    ///
    /// Returns whether the elected pair (or our role) changed.
    fn run_election(
        iface: &mut OspfInterface,
        neighbors: &mut BTreeMap<(u32, u32), Neighbor>,
        router: &Mutex<DefaultRouter>,
        now_ms: u64,
    ) -> bool {
        let self_ip = iface.addrs.first().map(|a| u32::from(a.addr)).unwrap_or(0);
        let dead_ms = u64::from(iface.dead_interval) * 1000;
        let mut electors: Vec<Elector> = iface
            .heard
            .iter()
            .filter(|(_, h)| h.bidirectional && now_ms.saturating_sub(h.last_ms) <= dead_ms)
            .map(|(&rid, h)| Elector {
                router_id: rid,
                ip: h.ip,
                priority: h.priority,
                stated_dr: h.stated_dr,
                stated_bdr: h.stated_bdr,
            })
            .collect();
        // Router X itself is on the list (§9.4), claiming its current
        // view of the segment.
        electors.push(Elector {
            router_id: iface.router_id,
            ip: self_ip,
            priority: iface.priority,
            stated_dr: iface.dr,
            stated_bdr: iface.bdr,
        });
        let (dr, bdr) = dr_elect(&electors, self_ip);
        let changed = dr != iface.dr || bdr != iface.bdr;
        iface.dr = dr;
        iface.bdr = bdr;
        // §9.4 step 5: derive our interface state from the result.
        let next_state = if self_ip != 0 && self_ip == dr {
            IfState::Dr
        } else if self_ip != 0 && self_ip == bdr {
            IfState::Backup
        } else {
            IfState::DrOther
        };
        let role_changed = next_state != iface.if_state;
        iface.if_state = next_state;
        // §9.4 step 7: the AdjOK? event on every neighbor — pushed via
        // set_ospf_dr_state, which re-runs the §10.4 decision per
        // session (advance to ExStart or demote to 2-Way).
        let mut router = router.lock().unwrap();
        for ((area, _rid), n) in neighbors.iter_mut() {
            if *area != iface.area || n.ifindex != iface.transport.ifindex() {
                continue;
            }
            match router.set_ospf_dr_state(n.handle, dr, bdr) {
                Ok(_) => {}
                Err(e) => eprintln!("daemon: ospf dr state: {}", e),
            }
        }
        if changed || role_changed {
            println!(
                "daemon: ospf iface {} elected DR {} / BDR {} — we are {}",
                iface.name,
                fmt_rid(dr),
                fmt_rid(bdr),
                iface.if_state.name()
            );
        }
        changed || role_changed
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
                .filter(|(_, h)| now_ms.saturating_sub(h.last_ms) > dead_ms)
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
            // The bidirectional elector set shrank (§9.3 NeighborChange)
            // and the dead router leaves the Hello list.
            let gone_ifindex = self.neighbors.get(&(area, rid)).map(|n| n.ifindex);
            if let Some(ifindex) = gone_ifindex {
                if let Some(iface) = self
                    .interfaces
                    .iter_mut()
                    .find(|i| i.transport.ifindex() == ifindex)
                {
                    iface.heard.remove(&rid);
                    iface.election_dirty = true;
                }
            }
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
                .filter(|(_, h)| now_ms.saturating_sub(h.last_ms) <= dead_ms)
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
            // §A.3.2: the Hello carries the elected DR/BDR by their IP
            // interface addresses (0.0.0.0 while none is elected —
            // e.g. during the §9.3 Waiting window).
            let wire = HelloWire {
                network_mask: mask,
                hello_interval: hello,
                dead_interval: dead,
                priority,
                dr: iface.dr,
                bdr: iface.bdr,
            };
            let mut bytes = match build_hello(rid, area, &wire, neighbors) {
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

    /// Build, install and flood our Router-LSA for `area` (RFC 2328
    /// §12.4.1) plus — where we are the elected Designated Router of a
    /// broadcast segment with at least one Full adjacency — the
    /// segment's Network-LSA (§12.4.2). The LSAs enter the area LSDB
    /// through the anchor session, which floods them to the neighbor
    /// sessions (§13.3).
    fn reoriginate_area(&mut self, router: &mut DefaultRouter, area: u32) {
        let mut links: Vec<RouterLsaLink> = Vec::new();
        let mut network_lsas: Vec<Lsa> = Vec::new();
        for iface in &mut self.interfaces {
            if iface.area != area {
                continue;
            }
            let local = iface.addrs.first().map(|a| u32::from(a.addr)).unwrap_or(0);
            let established: Vec<u32> = self
                .neighbors
                .iter()
                .filter(|(&(n_area, rid), n)| {
                    n_area == area
                        && n.ifindex == iface.transport.ifindex()
                        && n.established
                        && iface.heard.contains_key(&rid)
                })
                .map(|(&(_, rid), _)| rid)
                .collect();
            match iface.network_type {
                OspfNetworkType::PointToPoint => {
                    for addr in &iface.addrs {
                        links.push(RouterLsaLink::Stub {
                            network: u32::from(addr.network()),
                            mask: prefix_mask(addr.prefix_len),
                            metric: iface.cost,
                        });
                    }
                    for rid in &established {
                        links.push(RouterLsaLink::PointToPoint {
                            neighbor: *rid,
                            local_addr: local,
                            metric: iface.cost,
                        });
                    }
                }
                OspfNetworkType::Broadcast => {
                    // §12.4.1.2: Waiting (or no DR elected yet) —
                    // describe the segment as a stub network. Once a DR
                    // exists and we are fully adjacent to it (or we are
                    // the DR with at least one adjacency), the transit
                    // link replaces the stub link.
                    let waiting = iface.if_state == IfState::Waiting || iface.dr == 0;
                    // The neighbor whose interface address equals the
                    // elected DR, translated back to a router-id.
                    let dr_rid = if iface.dr == 0 {
                        None
                    } else {
                        iface
                            .heard
                            .iter()
                            .find(|(_, h)| h.ip == iface.dr)
                            .map(|(rid, _)| *rid)
                    };
                    let dr_established = if iface.dr == local {
                        // We are the DR ourselves.
                        !established.is_empty()
                    } else {
                        dr_rid
                            .map(|rid| established.contains(&rid))
                            .unwrap_or(false)
                    };
                    if waiting || !dr_established {
                        for addr in &iface.addrs {
                            links.push(RouterLsaLink::Stub {
                                network: u32::from(addr.network()),
                                mask: prefix_mask(addr.prefix_len),
                                metric: iface.cost,
                            });
                        }
                    } else {
                        // §12.4.1.2: transit link with Link ID = the DR's
                        // interface address (our own when we are the DR)
                        // and Link Data = our interface address.
                        links.push(RouterLsaLink::Transit {
                            dr_addr: iface.dr,
                            local_addr: local,
                            metric: iface.cost,
                        });
                    }
                    // §12.4.2: as the DR with at least one Full
                    // adjacency, originate the Network-LSA listing every
                    // fully adjacent router (ourselves included).
                    let we_are_dr = iface.if_state == IfState::Dr && iface.dr == local;
                    if we_are_dr && !established.is_empty() {
                        let mut attached = vec![self.router_id.as_u32()];
                        attached.extend_from_slice(&established);
                        let mask = iface
                            .addrs
                            .first()
                            .map(|a| prefix_mask(a.prefix_len))
                            .unwrap_or(0xffff_ffff);
                        match originate_network_lsa(
                            self.router_id.as_u32(),
                            local,
                            mask,
                            &attached,
                            iface.net_lsa_seq,
                        ) {
                            Some(lsa) => {
                                iface.net_lsa_seq = Some(lsa.header.ls_sequence_number);
                                iface.net_lsa_active = true;
                                network_lsas.push(lsa);
                            }
                            None => eprintln!(
                                "daemon: ospf network-LSA sequence space exhausted on {}",
                                iface.name
                            ),
                        }
                    } else if iface.net_lsa_active {
                        // §12.4.2: a former DR flushes the Network-LSA it
                        // originated (§14.1 MaxAge reflood).
                        if let Some(seq) = iface.net_lsa_seq {
                            if let Some(mut lsa) = originate_network_lsa(
                                self.router_id.as_u32(),
                                local,
                                prefix_mask(
                                    iface.addrs.first().map(|a| a.prefix_len).unwrap_or(24),
                                ),
                                &[self.router_id.as_u32()],
                                Some(seq),
                            ) {
                                lsa.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
                                lsa.finalize();
                                network_lsas.push(lsa);
                            }
                        }
                        iface.net_lsa_active = false;
                    }
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
        let mut all_lsas = vec![lsa];
        all_lsas.extend(network_lsas);
        let packet = self_lsu(self.router_id, area, all_lsas);
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

/// One Hello packet's wire-level knobs (RFC 2328 §A.3.2) — grouped so
/// the builder stays readable.
struct HelloWire {
    network_mask: u32,
    hello_interval: u16,
    dead_interval: u32,
    priority: u8,
    /// The elected DR/BDR by IP interface address (0.0.0.0 = none).
    dr: u32,
    bdr: u32,
}

/// Encode one Hello packet (RFC 2328 §A.3.2).
fn build_hello(
    rid: RouterId,
    area: u32,
    wire: &HelloWire,
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
            network_mask: wire.network_mask,
            hello_interval: wire.hello_interval,
            options: 0x02, // E-bit
            priority: wire.priority,
            dead_interval: wire.dead_interval,
            dr: wire.dr,
            bdr: wire.bdr,
            neighbors,
        }),
    };
    OspfCodec::v2().encode_vec(&packet)
}

/// Decode a received OSPFv2 Hello body (§A.3.2) for the neighbor
/// table. Returns `None` for short, non-v2 or non-Hello packets.
fn parse_hello_body(bytes: &[u8]) -> Option<HelloBody> {
    match OspfCodec::v2().decode_slice(bytes).ok()?? {
        OspfPacket {
            body: OspfBody::Hello(body),
            ..
        } => Some(body),
        _ => None,
    }
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
            &HelloWire {
                network_mask: 0xffff_ff00,
                hello_interval: 10,
                dead_interval: 40,
                priority: 1,
                dr: 0,
                bdr: 0,
            },
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
            &HelloWire {
                network_mask: 0xffff_ff00,
                hello_interval: 10,
                dead_interval: 40,
                priority: 1,
                dr: 0,
                bdr: 0,
            },
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
