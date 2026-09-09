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
use lr_ospf::gr::{HelperCheck, HelperEntry, RestartTracker};
use lr_ospf::interface::{elect as dr_elect, Elector, IfState};
use lr_ospf::lsa::grace::{GraceLsaBody, GraceReason};
use lr_ospf::lsa::Lsa;
use lr_ospf::lsa::{
    opaque_lsa_id, originate_sr_prefix_lsa, originate_sr_ri_lsa, OPAQUE_TYPE_EXT_PREFIX,
    OPAQUE_TYPE_RI,
};
use lr_ospf::origination::{
    finalize_v2_packet, originate_network_lsa, originate_router_lsa, v2_packet_checksum_ok,
    RouterLsaLink,
};
use lr_ospf::packet::{HelloBody, LsUpdateBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType};
use lr_ospf::spf::decode_router_links;
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

/// Grace-LSA retransmissions during the graceful-shutdown flood
/// (RFC 3623 §2.1: "retransmit the grace-LSAs until they are
/// acknowledged"; the flood path is fire-and-forget, so a bounded
/// repeat covers the ack-less gap) and their spacing.
const GRACE_FLOOD_REPEATS: usize = 5;
const GRACE_FLOOD_INTERVAL_MS: u64 = 1_000;

/// How often the graceful-shutdown flood services the protocol
/// between rounds (see `pump_grace_quiet`): a small slice keeps the
/// ACK latency for a peer's in-flight LSA refresh well under one
/// flood round, so the very next Grace-LSA instance re-runs the
/// peer's RFC 3623 §3.1 helper checks against a drained LS
/// retransmission list.
const GRACE_PUMP_SLICE_MS: u64 = 50;

/// A Grace-LSA sequence base that survives the restart: derived from
/// the wallclock (seconds since the Unix epoch) so the flush the
/// restarting router sends after recovery is always *newer* than the
/// instances the helpers hold from before the restart. The signed
/// sequence space of RFC 2328 §12.1.2 starts at 0x80000001 and the
/// epoch (~1.7e9) fits inside the 0x80000001..0xffffffff window, so
/// `INITIAL + unix` is a valid, monotonically increasing base for a
/// single router's Grace-LSA lineage. (BIRD notes the same
/// non-volatile-storage gap — "We should get end of grace period
/// from non-volatile storage" — and uses the configured time; the
/// clock-derived lineage needs no storage at all.)
fn grace_sequence_base() -> u32 {
    const INITIAL: u32 = 0x8000_0001;
    let unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let unix = (unix_ms / 1_000).min(u32::MAX as u64 - u64::from(INITIAL)) as u32;
    INITIAL.wrapping_add(unix)
}

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
    /// RFC 3623 §3 helper state for this neighbour: while active the
    /// dead timer holds off removing the session and the Router-LSA
    /// keeps advertising the adjacency as if Full.
    helper: HelperEntry,
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
    /// RFC 3623 §3 helper policy (from the config; helpers are on by
    /// default, matching BIRD `AWARE` / FRR's helper default).
    gr_helper_enabled: bool,
    /// FRR `supported_grace_time`: the grace ceiling this router
    /// honours (longer requests are clamped, not refused).
    gr_helper_cap: u32,
    /// The configured grace period (seconds) — advertised in the
    /// shutdown Grace-LSAs and persisted to the state file.
    gr_grace_period: u32,
    /// Monotonic floor for this router's Grace-LSA sequence lineage:
    /// every originated instance is strictly newer than the floor,
    /// which is seeded from the state file across restarts. Keeps a
    /// post-flush shutdown (or a restart) from ever sending an
    /// older-sequence instance that receivers would dedup or drop.
    gr_seq_floor: u32,
    /// Where the graceful-restart state (deadline + grace period)
    /// survives the restart. `--ospf-gr-state-file`, defaulting to
    /// `<api-socket>.gr` when the runtime API socket is configured;
    /// `None` means restarts cannot resume recovery (helpers still
    /// work — the restarted router just re-syncs without §2
    /// origination suppression).
    gr_state_file: Option<String>,
    /// RFC 3623 §2 graceful-restart recovery, per area: each tracker
    /// holds that area's pre-restart adjacency set and latches its
    /// §2.2 outcome. Non-empty only while the daemon (re)started with
    /// `graceful_restart` enabled and recovery has not finished; live
    /// trackers suppress topology-LSA origination (§2 (1)).
    gr_recovery: BTreeMap<u32, RestartTracker>,
    /// Area → topology version at the last pump pass — the §3.2 (3)
    /// change detector that exits helpers.
    gr_topology: BTreeMap<u32, u64>,
    /// RFC 8667: this router's SRGB (base, range) when Segment Routing
    /// is configured. `None` = the node originates no SR LSAs.
    sr_srgb: Option<(u32, u32)>,
    /// RFC 8667: the locally originated prefix SIDs (one Extended
    /// Prefix Opaque LSA each).
    sr_sids: Vec<SrSidConfig>,
    /// (area, link_state_id) → last originated sequence number for our
    /// SR LSAs (RI Opaque Type 4 + Extended Prefix Opaque Type 7). The
    /// LSDB instance is the floor, mirroring the Router-LSA rule.
    sr_seq: BTreeMap<(u32, u32), u32>,
    /// Snapshot of the graceful-restart state for the runtime API
    /// `status` command (shared with the API thread).
    gr_status: Arc<std::sync::Mutex<Vec<String>>>,
    router_id: RouterId,
}

/// One configured prefix SID (RFC 8667 §6): the prefix, its SID index
/// into the SRGB, whether it is a node segment (RFC 7684 §6 N-flag)
/// and the stable Opaque ID slot its Extended Prefix Opaque LSA uses.
#[derive(Debug, Clone)]
struct SrSidConfig {
    prefix: [u8; 4],
    prefix_len: u8,
    sid: u32,
    node: bool,
    opaque_index: u32,
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
        gr_helper_enabled: cfg.ospf_gr_helper,
        gr_helper_cap: cfg.ospf_helper_grace_cap,
        gr_grace_period: cfg.ospf_grace_period,
        gr_seq_floor: 0,
        gr_state_file: cfg
            .ospf_gr_state_file
            .clone()
            .or_else(|| cfg.api_socket.as_ref().map(|s| format!("{s}.gr"))),
        gr_recovery: BTreeMap::new(),
        gr_topology: BTreeMap::new(),
        sr_srgb: cfg.ospf_srgb_base.zip(cfg.ospf_srgb_range),
        sr_sids: {
            let mut sids = Vec::new();
            for (idx, spec) in cfg.ospf_prefix_sids.iter().enumerate() {
                let Some(prefix) = spec
                    .prefix
                    .as_deref()
                    .and_then(|p| p.parse::<lr_core::addr::Prefix>().ok())
                else {
                    continue; // finalize() already rejected this
                };
                let lr_core::addr::IpAddr::V4(octets) = prefix.addr else {
                    continue;
                };
                sids.push(SrSidConfig {
                    prefix: octets,
                    prefix_len: prefix.prefix_len,
                    sid: spec.sid.unwrap_or(0),
                    node: spec.node.unwrap_or(false),
                    // Stable per-config-order slot: re-origination
                    // keeps the same (advertising router, opaque ID)
                    // key, so a SID change refreshes its own LSA.
                    opaque_index: (idx + 1) as u32,
                });
            }
            sids
        },
        sr_seq: BTreeMap::new(),
        gr_status: Arc::new(std::sync::Mutex::new(Vec::new())),
        router_id: rid,
    };
    // RFC 3623 §2: recovery is *resumed*, not assumed — the state
    // file written by the pre-restart process carries the grace
    // deadline. A fresh start (no file, or a deadline already past)
    // runs normal OSPF; a resume keeps topology-LSA origination
    // suppressed until §2.2 exits (every pre-restart adjacency Full,
    // an inconsistent LSA, or the grace timeout).
    if cfg.ospf_graceful_restart {
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut remaining: Option<u64> = None;
        match daemon.gr_state_file.as_deref().map(std::fs::read_to_string) {
            Some(Ok(text)) => {
                let mut parts = text.split_whitespace();
                let (deadline, period, floor) = (
                    parts.next().and_then(|d| d.parse::<u64>().ok()),
                    parts.next().and_then(|p| p.parse::<u32>().ok()),
                    parts.next().and_then(|s| s.parse::<u32>().ok()),
                );
                match (deadline, period) {
                    (Some(deadline), Some(period)) if deadline > now_unix_ms => {
                        println!(
                            "daemon: ospf graceful restart recovery started \
                             (grace period {period}s, resuming a restart)"
                        );
                        remaining = Some(deadline - now_unix_ms);
                        // The pre-restart process's Grace-LSA sequence
                        // floor: every instance we send from here on is
                        // strictly newer than the ones the helpers hold.
                        if let Some(floor) = floor {
                            daemon.gr_seq_floor = daemon.gr_seq_floor.max(floor);
                        }
                        // The trackers run on the main-loop clock; the
                        // remaining wallclock seconds translate 1:1.
                        let remaining_secs = u32::try_from((deadline - now_unix_ms) / 1_000)
                            .unwrap_or(1)
                            .max(1);
                        for area in daemon.interfaces.iter().map(|i| i.area) {
                            daemon
                                .gr_recovery
                                .entry(area)
                                .or_insert_with(|| RestartTracker::new(remaining_secs, 0));
                        }
                    }
                    _ => {
                        // Expired or malformed: remove so a later
                        // graceful shutdown rewrites it cleanly.
                        let _ = daemon.gr_state_file.as_deref().map(std::fs::remove_file);
                        println!("daemon: ospf graceful restart state expired — fresh start");
                    }
                }
            }
            _ => {
                println!(
                    "daemon: ospf graceful restart enabled (no prior grace state — fresh start)"
                );
            }
        }
        let _ = remaining;
    }
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
        status_lines: {
            let snapshot = Arc::clone(&daemon.gr_status);
            Arc::new(move || snapshot.lock().map(|s| s.clone()).unwrap_or_default())
        },
    });
    if let Err(e) = crate::spawn_api(cfg, &runtime) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }
    // The ticker drives tick() (LSA refresh + MaxAge aging) and mirrors
    // Loc-RIB events into the kernel FIB when asked to.
    crate::spawn_ticker(&runtime, cfg.install_kernel, Arc::new(AtomicUsize::new(0)));

    // ---- Initial Router-LSA per area. ----
    // RFC 3623 §2 (1): suppressed while graceful-restart recovery is
    // live — the pre-restart instances (re-received from the helping
    // neighbours) keep describing the topology until §2.2 exits.
    if daemon.gr_recovery.is_empty() {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.lock().unwrap();
        let areas: Vec<u32> = daemon.anchors.keys().copied().collect();
        for area in areas {
            daemon.reoriginate_area(&mut router, area);
            // RFC 8667: the SR RI + Extended Prefix LSAs ride the same
            // startup pass (SR-disabled daemons originate nothing).
            daemon.reoriginate_sr(&mut router, area);
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
    // Graceful shutdown. With graceful restart enabled (RFC 3623 §2.1)
    // the teardown is replaced: originate a Grace-LSA per interface
    // (retransmitted a few times — the flood path has no acks) and
    // exit *without* closing sessions, so no Loc-RIB withdrawals fire
    // and the kernel FIB the forwarding plane relies on survives the
    // restart. Between flood rounds the daemon keeps servicing the
    // protocol (see `graceful_shutdown_flood`) so peers whose LSA
    // refresh is still un-ACKed can drain their retransmission lists
    // and engage helper mode on a later round. Without it: close every
    // session so the router emits the down events, then let the ticker
    // drain them.
    if cfg.ospf_graceful_restart {
        daemon.graceful_shutdown_flood(&mut recv_buf, &start);
        let period = lr_ospf::gr::clamp_grace_period(cfg.ospf_grace_period);
        println!(
            "daemon: ospf graceful shutdown complete (neighbours asked to retain LSAs for {period}s)"
        );
        return ExitCode::SUCCESS;
    }
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
        if_state: if network_type == OspfNetworkType::Broadcast && spec.priority.unwrap_or(1) > 0 {
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
        self.pump_gr(now_ms);
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
                                    helper: HelperEntry::default(),
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
            let events = router.poll_events();
            self.handle_router_events(events, now_ms);
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
    /// now + MinLSArrival (+ slack). No-op while graceful-restart
    /// recovery is live: RFC 3623 §2 (1) — the pre-restart LSAs the
    /// helpers retained keep describing the topology until §2.2
    /// exits recovery (the exit path re-origination is driven
    /// directly, not through here).
    fn schedule_reoriginate(&mut self, area: u32, now_ms: u64) {
        if self.gr_recovery.contains_key(&area) {
            return;
        }
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
            // The SR LSAs ride the same re-origination cycle so a
            // (re)formed adjacency always sees them (RFC 8667 §7:
            // extended LSAs flood like any area-scoped LSA).
            self.reoriginate_sr(&mut router, area);
        }
    }

    /// Tear down sessions whose router went silent for the interface's
    /// dead interval (RFC 2328 §10.2 inactivity timer). Neighbours in
    /// graceful-restart helper mode (RFC 3623 §3) are exempt: their
    /// sessions, `heard` entries and advertised adjacencies are
    /// retained for the grace period; the helper exits re-evaluate.
    fn pump_dead_timer(&mut self, now_ms: u64) {
        let mut expired: Vec<(u32, u32)> = Vec::new(); // (area, rid)
                                                       // RFC 3623 §3 retention set, computed up front so the interface
                                                       // loop below can stay a plain mutable walk.
        let retained: std::collections::BTreeSet<(u32, u32)> = self
            .neighbors
            .iter()
            .filter(|(_, n)| n.helper.is_active())
            .map(|((area, rid), _)| (*area, *rid))
            .collect();
        for iface in &mut self.interfaces {
            let dead_ms = u64::from(iface.dead_interval) * 1000;
            let gone: Vec<u32> = iface
                .heard
                .iter()
                .filter(|(rid, h)| {
                    now_ms.saturating_sub(h.last_ms) > dead_ms
                        && !retained.contains(&(iface.area, **rid))
                })
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
        let events = router.poll_events();
        self.handle_router_events(events, now_ms);
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
                        // The transit link describes the connection to
                        // the transit network itself (its prefix is
                        // recovered from the Network-LSA). Secondary
                        // addresses on the interface are separate
                        // attached networks — they stay stub links
                        // (BIRD models them as one broadcast interface
                        // per address; FRR keeps one oi per connected
                        // prefix — both keep the extra prefixes routed).
                        let primary_net = iface
                            .addrs
                            .first()
                            .map(|a| u32::from(a.network()))
                            .unwrap_or(0);
                        for addr in &iface.addrs {
                            if u32::from(addr.network()) != primary_net {
                                links.push(RouterLsaLink::Stub {
                                    network: u32::from(addr.network()),
                                    mask: prefix_mask(addr.prefix_len),
                                    metric: iface.cost,
                                });
                            }
                        }
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
        // Sequence floor: the helpers may hold instances of our LSAs
        // with higher sequences than this process ever originated
        // (received back during graceful restart). The pre-restart
        // instance in the area LSDB (if any) is the floor — a fresh
        // 0x80000001 would be older than what every neighbour holds
        // and silently ignored (RFC 2328 §12.1.2 signed comparison).
        let lsdb_prev =
            router.ospf_area_lsa(area, 1, self.router_id.as_u32(), self.router_id.as_u32());
        let lsdb_seq = lsdb_prev.as_ref().map(|l| l.header.ls_sequence_number);
        let prev = match (self.lsa_seq.get(&area).copied(), lsdb_seq) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
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

    // -----------------------------------------------------------------
    // RFC 8667 Segment Routing: RI + Extended Prefix Opaque LSAs
    // -----------------------------------------------------------------

    /// Originate (or re-originate) the SR LSAs into `area`: the
    /// area-scoped Router Information LSA carrying the SRGB
    /// (RFC 8667 §3) plus one Extended Prefix Opaque LSA per configured
    /// prefix SID (RFC 8667 §6). Follows the Router-LSA self-
    /// origination path exactly: the LSDB instance is the sequence
    /// floor (§12.1.2) and the LSU rides the anchor session so the
    /// router floods it to every neighbour. SR-disabled daemons
    /// originate nothing (no config → no LSA → no behaviour change).
    fn reoriginate_sr(&mut self, router: &mut DefaultRouter, area: u32) {
        let Some((base, range)) = self.sr_srgb else {
            return;
        };
        let Some(&anchor) = self.anchors.get(&area) else {
            return;
        };
        let rid = self.router_id.as_u32();
        let mut lsas: Vec<Lsa> = Vec::new();
        // Router Information LSA (Opaque Type 4, Opaque ID 0).
        let ri_lsid = opaque_lsa_id(OPAQUE_TYPE_RI, 0);
        let prev = self.sr_prev_seq(router, area, ri_lsid);
        if let Some(lsa) = originate_sr_ri_lsa(rid, base, range, prev) {
            self.sr_seq
                .insert((area, ri_lsid), lsa.header.ls_sequence_number);
            lsas.push(lsa);
        }
        // One Extended Prefix Opaque LSA per configured SID (Opaque
        // Type 7; the Opaque ID is the config slot, stable across
        // re-origination so a change refreshes only its own LSA).
        for cfg in &self.sr_sids {
            let lsid = opaque_lsa_id(OPAQUE_TYPE_EXT_PREFIX, cfg.opaque_index);
            let prev = self.sr_prev_seq(router, area, lsid);
            let advert = lr_ospf::lsa::SrPrefixAdvert {
                // §6: an advertised prefix in the router's own area is
                // intra-area; the N-flag marks a node segment.
                route_type: 1,
                flags: if cfg.node { 0x40 } else { 0x00 },
                prefix: cfg.prefix,
                prefix_len: cfg.prefix_len,
                // PHP by default (FRR's default): NP/E/V/L clear.
                sid_flags: 0,
                sid: cfg.sid,
                algorithm: 0,
            };
            if let Some(lsa) = originate_sr_prefix_lsa(rid, &advert, cfg.opaque_index, prev) {
                self.sr_seq
                    .insert((area, lsid), lsa.header.ls_sequence_number);
                lsas.push(lsa);
            }
        }
        if lsas.is_empty() {
            return;
        }
        let packet = self_lsu(self.router_id, area, lsas);
        match OspfCodec::v2().encode_vec(&packet) {
            Ok(mut bytes) => {
                finalize_v2_packet(&mut bytes);
                if let Err(e) = router.feed_input(anchor, &bytes) {
                    eprintln!("daemon: ospf sr self-origination feed: {}", e);
                }
            }
            Err(e) => eprintln!("daemon: ospf sr LSA encode: {}", e),
        }
    }

    /// The sequence floor for one of our SR LSAs: the newest of our
    /// last originated instance and the one the area LSDB holds (a
    /// received-back or pre-restart instance — RFC 2328 §12.1.2 signed
    /// comparison; a fresh 0x80000001 would be silently older).
    fn sr_prev_seq(&self, router: &DefaultRouter, area: u32, lsid: u32) -> Option<u32> {
        let lsdb_seq = router
            .ospf_area_lsa(area, 10, self.router_id.as_u32(), lsid)
            .map(|l| l.header.ls_sequence_number);
        let own = self.sr_seq.get(&(area, lsid)).copied();
        match (own, lsdb_seq) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    // -----------------------------------------------------------------
    // RFC 3623 graceful restart: helper mode + restarting-recovery
    // -----------------------------------------------------------------

    /// Route polled router events: Grace-LSA events drive the §3
    /// helper state machines, everything else is logged as before.
    fn handle_router_events(&mut self, events: Vec<RouterEvent>, now_ms: u64) {
        for ev in events {
            match ev {
                RouterEvent::OspfGraceLsa {
                    area,
                    advertising_router,
                    grace_period_secs,
                    reason,
                    interface_addr,
                    ls_age_secs,
                    purged,
                } => self.on_grace_lsa_event(
                    area,
                    advertising_router,
                    grace_period_secs,
                    reason,
                    interface_addr,
                    ls_age_secs,
                    purged,
                    now_ms,
                ),
                other => log_event(&other),
            }
        }
    }

    /// One received Grace-LSA (the router already decoded + deduped
    /// it). RFC 3623 §3.1: on a flush (MaxAge) exit helper mode; on a
    /// fresh instance run the entry checks against the neighbour
    /// session and the configured policy.
    #[allow(clippy::too_many_arguments)]
    fn on_grace_lsa_event(
        &mut self,
        area: u32,
        advertising_router: u32,
        grace_period_secs: u32,
        reason: u8,
        interface_addr: Option<[u8; 4]>,
        ls_age_secs: u16,
        purged: bool,
        now_ms: u64,
    ) {
        // §3.1 neighbour identity: on broadcast segments the Grace-LSA
        // body's IP interface address identifies the restarting
        // neighbour (its Hellos may not have been heard since); on p2p
        // (and as a fallback) the Advertising Router does.
        let rid = interface_addr
            .and_then(|a| {
                let addr = u32::from_be_bytes(a);
                self.interfaces
                    .iter()
                    .find(|i| i.area == area && i.heard.values().any(|h| h.ip == addr))
                    .and_then(|i| {
                        i.heard
                            .iter()
                            .find(|(_, h)| h.ip == addr)
                            .map(|(rid, _)| *rid)
                    })
            })
            .unwrap_or(advertising_router);
        let Some(n) = self.neighbors.get_mut(&(area, rid)) else {
            if !purged {
                println!(
                    "daemon: ospf grace-LSA from {} (area {}): no session, not helping \
                     (RFC 3623 3.1 (1) — neighbour not Full)",
                    fmt_rid(advertising_router),
                    area_label(area)
                );
            }
            return;
        };
        if purged {
            if let Some(exit) = n.helper.on_flush() {
                println!(
                    "daemon: ospf neighbor {} (area {}): helper mode exited — {}",
                    fmt_rid(rid),
                    area_label(area),
                    exit.reason()
                );
                self.after_helper_exit(area, rid, now_ms);
            }
            return;
        }
        let body = GraceLsaBody {
            grace_period: grace_period_secs,
            reason: GraceReason::from_u8(reason),
            ipv4_address: interface_addr,
            ipv6_address: None,
        };
        let neighbor_full = n.established;
        let check = HelperCheck {
            neighbor_full,
            helper_enabled: self.gr_helper_enabled,
            supported_grace_cap_secs: self.gr_helper_cap,
            self_restarting: self.gr_recovery.contains_key(&area),
            lsa: &body,
            lsa_age_secs: ls_age_secs,
            now_ms,
        };
        let transition = n.helper.on_grace_lsa(check);
        match transition {
            lr_ospf::gr::HelperTransition::Entered { .. } => {
                println!(
                    "daemon: ospf neighbor {} (area {}): helper mode entered (grace {}s, \
                     reason {}) — adjacency and LSAs retained",
                    fmt_rid(rid),
                    area_label(area),
                    grace_period_secs,
                    match reason {
                        1 => "software restart",
                        2 => "software reload/upgrade",
                        3 => "redundant switchover",
                        _ => "unknown",
                    }
                );
            }
            lr_ospf::gr::HelperTransition::Refreshed { .. } => {}
            lr_ospf::gr::HelperTransition::Refused(why) => {
                println!(
                    "daemon: ospf neighbor {} (area {}): not helping — {}",
                    fmt_rid(rid),
                    area_label(area),
                    why.reason()
                );
            }
        }
    }

    /// Re-evaluate a neighbour after its helper relationship ended
    /// (§3.2): re-run the DR election inputs, re-originate the area's
    /// Router-LSA (the retained adjacency drops unless the neighbour
    /// is really back), and reap the session if it stayed silent
    /// past the dead interval.
    fn after_helper_exit(&mut self, area: u32, rid: u32, now_ms: u64) {
        if let Some(ifindex) = self.neighbors.get(&(area, rid)).map(|n| n.ifindex) {
            if let Some(iface) = self
                .interfaces
                .iter_mut()
                .find(|i| i.transport.ifindex() == ifindex)
            {
                iface.election_dirty = true;
            }
        }
        // Reap a neighbour that is still silent: without the helper
        // retention the dead timer would have removed it already.
        let still_quiet = self
            .interfaces
            .iter()
            .find(|i| {
                i.area == area
                    && self
                        .neighbors
                        .get(&(area, rid))
                        .is_some_and(|n| n.ifindex == i.transport.ifindex())
            })
            .and_then(|i| i.heard.get(&rid))
            .is_some_and(|h| {
                let dead_ms = u64::from(
                    self.interfaces
                        .iter()
                        .find(|i| i.area == area)
                        .map(|i| i.dead_interval)
                        .unwrap_or(40),
                ) * 1_000;
                now_ms.saturating_sub(h.last_ms) > dead_ms
            });
        if still_quiet {
            if let Some(n) = self.neighbors.remove(&(area, rid)) {
                let router_arc = Arc::clone(&self.router);
                let mut router = router_arc.lock().unwrap();
                router.close_session(n.handle);
                println!(
                    "daemon: ospf neighbor {} dead (area {}) — session closed",
                    fmt_rid(rid),
                    area_label(area)
                );
                let events = router.poll_events();
                drop(router);
                self.handle_router_events(events, now_ms);
            }
            if let Some(iface) = self
                .interfaces
                .iter_mut()
                .find(|i| i.area == area && i.heard.contains_key(&rid))
            {
                iface.heard.remove(&rid);
                iface.election_dirty = true;
            }
        }
        self.schedule_reoriginate(area, now_ms);
    }

    /// One pump pass of the graceful-restart machines: the §3.2 (3)
    /// topology-change exits for helpers, the §3.2 (2) grace timeouts,
    /// and the §2.2 recovery evaluation for the restarting side.
    fn pump_gr(&mut self, now_ms: u64) {
        let mut helper_exits: Vec<(u32, u32, lr_ospf::gr::HelperExit)> = Vec::new();
        let mut gr_recovery_done: Option<lr_ospf::gr::RestartOutcome> = None;
        {
            let router_arc = Arc::clone(&self.router);
            let router = router_arc.lock().unwrap();

            // §3.2 (3): topology changes terminate helpers. Per area,
            // the poll-side counterpart of BIRD's LSDB-change walk
            // (area granularity: a p2p lab's area maps 1:1 to a
            // segment; the flooding-allowed refinement of §3.2 (3)b
            // is future work).
            for area in self.anchors.keys().copied().collect::<Vec<u32>>() {
                let version = router.ospf_area_topology_version(area).unwrap_or(0);
                let known = self.gr_topology.get(&area).copied();
                match known {
                    None => {
                        // First observation after startup — no change yet.
                        self.gr_topology.insert(area, version);
                        continue;
                    }
                    Some(v) if v != version => {
                        self.gr_topology.insert(area, version);
                        for ((n_area, rid), n) in self.neighbors.iter_mut() {
                            if *n_area == area && n.helper.is_active() {
                                if let Some(exit) = n.helper.on_topology_change() {
                                    helper_exits.push((*n_area, *rid, exit));
                                }
                            }
                        }
                    }
                    Some(_) => {}
                }
            }
            // §3.2 (2): grace-period deadlines.
            for ((area, rid), n) in self.neighbors.iter_mut() {
                if let Some(exit) = n.helper.poll(now_ms) {
                    helper_exits.push((*area, *rid, exit));
                }
            }

            // §2.2: the restarting side. Feed adjacency observations,
            // verify back-links, poll the outcome.
            if !self.gr_recovery.is_empty() {
                let our_rid = self.router_id.as_u32();
                let areas: Vec<u32> = self.gr_recovery.keys().copied().collect();
                for area in areas {
                    let Some(tracker) = self.gr_recovery.get_mut(&area) else {
                        continue;
                    };
                    // Seed the pre-restart adjacency set once our old
                    // Router-LSA (re-received from a helper through
                    // database exchange) shows up in the LSDB.
                    if let Some(lsa) = router.ospf_area_lsa(area, 1, our_rid, our_rid) {
                        let p2p: Vec<u32> = decode_router_links(&lsa.body)
                            .into_iter()
                            .filter(|l| l.link_type == 1)
                            .map(|l| l.link_id)
                            .collect();
                        tracker.set_pre_restart_adjacencies(p2p);
                    }
                    // §2.2 (1) yardstick: every listed adjacency Full.
                    let listed: Vec<u32> = tracker.adjacency_ids().collect();
                    for rid in listed {
                        let full = self.neighbors.get(&(area, rid)).map(|n| n.established);
                        tracker.observe_adjacency(rid, full);
                        // §2.2 (2): back-link verification — a Full
                        // neighbour whose router-LSA no longer links
                        // to us means it never helped (or stopped).
                        if full == Some(true) {
                            if let Some(their) = router.ospf_area_lsa(area, 1, rid, rid) {
                                let links = decode_router_links(&their.body);
                                let back = links
                                    .iter()
                                    .any(|l| l.link_type == 1 && l.link_id == our_rid)
                                    || links.iter().any(|l| l.link_type == 2 && l.link_id != 0);
                                if !back {
                                    tracker.mark_inconsistent();
                                }
                            }
                        }
                    }
                    if let Some(outcome) = tracker.poll(now_ms) {
                        if outcome != lr_ospf::gr::RestartOutcome::AdjacenciesRestablished {
                            gr_recovery_done = Some(outcome);
                        }
                    }
                }
                // Global §2.2 (1): recovery succeeds when every area's
                // tracker reports all adjacencies back.
                if gr_recovery_done.is_none()
                    && !self.gr_recovery.is_empty()
                    && self.gr_recovery.values_mut().all(|t| {
                        t.poll(now_ms).is_some_and(|o| {
                            o == lr_ospf::gr::RestartOutcome::AdjacenciesRestablished
                        })
                    })
                {
                    gr_recovery_done = Some(lr_ospf::gr::RestartOutcome::AdjacenciesRestablished);
                }
            }
        }
        for (area, rid, exit) in helper_exits {
            println!(
                "daemon: ospf neighbor {} (area {}): helper mode exited — {}",
                fmt_rid(rid),
                area_label(area),
                exit.reason()
            );
            self.after_helper_exit(area, rid, now_ms);
        }
        if let Some(outcome) = gr_recovery_done {
            self.exit_gr_recovery(outcome, now_ms);
        }
        self.refresh_gr_status();
    }

    /// §2.3: leave graceful restart (success or failure): flush the
    /// Grace-LSAs this router originated (helpers exit on the MaxAge
    /// instance), re-enable origination and re-originate the
    /// Router-/Network-LSAs from current state.
    fn exit_gr_recovery(&mut self, outcome: lr_ospf::gr::RestartOutcome, now_ms: u64) {
        let areas: Vec<u32> = self.gr_recovery.keys().copied().collect();
        println!(
            "daemon: ospf graceful restart recovery ended — {}",
            outcome.reason()
        );
        self.gr_recovery.clear();
        if let Some(state) = self.gr_state_file.as_deref() {
            let _ = std::fs::remove_file(state);
        }
        // §2.3 (6): flush the Grace-LSAs — the MaxAge instances tell
        // the helpers the restart finished (§3.2 (1)).
        self.send_grace_lsas(true);
        // §2.3 (1)/(2): re-originate the Router-/Network-LSAs from
        // current state — via the scheduled path so MinLSArrival
        // (RFC 2328 §14) paces the instance the exchange just
        // delivered. The sequence floor comes from the retained
        // pre-restart LSAs inside reoriginate_area.
        for area in areas {
            self.schedule_reoriginate(area, now_ms);
        }
        // A topology-observing restart exit refreshes the helper-side
        // snapshot so our own re-origination does not read as a
        // topology change (helpers for other routers on this box).
        {
            let router_arc = Arc::clone(&self.router);
            let router = router_arc.lock().unwrap();
            for area in self.anchors.keys() {
                if let Some(v) = router.ospf_area_topology_version(*area) {
                    self.gr_topology.insert(*area, v);
                }
            }
        }
    }

    /// Build and (re)transmit the Grace-LSA of every interface inside
    /// one LS-Update per interface, directly on the transport (the
    /// restarting router speaks before any adjacency exists; §2.1).
    /// `flush` selects the §2.3 MaxAge flush form instead of the
    /// shutdown announcement.
    fn send_grace_lsas(&mut self, flush: bool) {
        let period_hint = lr_ospf::gr::clamp_grace_period(self.gr_grace_period);
        let our_rid = self.router_id.as_u32();
        // Sequence derivation: strictly newer than every instance this
        // router ever sent — the wallclock base (which grows across
        // restarts) OR the persisted floor + 1, whichever is larger.
        // Each originated LSA advances the floor, so a flush followed
        // by another shutdown (or a restart) can never emit an
        // older/equal instance.
        let mut floor = self.gr_seq_floor;
        for iface in &mut self.interfaces {
            let local = iface.addrs.first().map(|a| u32::from(a.addr)).unwrap_or(0);
            let body = if flush {
                // §2.3 (6): the flush carries no meaningful state.
                GraceLsaBody {
                    grace_period: 0,
                    reason: GraceReason::Unknown,
                    ipv4_address: None,
                    ipv6_address: None,
                }
            } else {
                GraceLsaBody {
                    grace_period: period_hint,
                    reason: GraceReason::SoftwareRestart,
                    ipv4_address: local.to_be_bytes().into(),
                    ipv6_address: None,
                }
            };
            let seq = grace_sequence_base().max(floor.wrapping_add(1));
            floor = seq;
            let Some(lsa) = lr_ospf::lsa::grace::originate_grace_lsa_v2(
                our_rid,
                &body,
                Some(seq.wrapping_sub(1)),
            ) else {
                continue;
            };
            let mut lsa = lsa;
            if flush {
                lsa.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
                lsa.finalize();
            }
            let packet = self_lsu(self.router_id, iface.area, vec![lsa]);
            match OspfCodec::v2().encode_vec(&packet) {
                Ok(mut bytes) => {
                    finalize_v2_packet(&mut bytes);
                    if let Err(e) = iface.transport.send_multicast(&bytes) {
                        eprintln!("daemon: ospf grace-LSA send {}: {}", iface.name, e);
                    }
                    // RFC 2328 §13.5 direct flooding: every
                    // bidirectional neighbour on this interface also
                    // gets a unicast copy — the helper election must
                    // not hinge on one multicast surviving a loaded
                    // scheduler (RFC 3623 §2.1: retransmit until
                    // received).
                    let heard: Vec<u32> = iface
                        .heard
                        .values()
                        .filter(|n| n.bidirectional)
                        .map(|n| n.ip)
                        .collect();
                    for ip in heard {
                        let dst = core::net::Ipv4Addr::from(ip);
                        if let Err(e) = iface.transport.send_unicast(dst, &bytes) {
                            eprintln!("daemon: ospf grace-LSA unicast {}: {}", dst, e);
                        }
                    }
                }
                Err(e) => eprintln!("daemon: ospf grace-LSA encode: {}", e),
            }
        }
        self.gr_seq_floor = floor;
    }

    /// The §2.1 shutdown flood: send the Grace-LSAs on every
    /// interface, retransmitting a bounded number of times (the
    /// flood path is fire-and-forget; BIRD performs ack-tracked
    /// reliable flooding, we approximate with repeats). Also persists
    /// the grace state file so the restarted process knows to enter
    /// recovery (deadline, grace period) — the non-volatile-storage
    /// note of RFC 3623 §2.1 / BIRD's ospf.c.
    fn graceful_shutdown_flood(&mut self, recv_buf: &mut [u8], start: &std::time::Instant) {
        let period = lr_ospf::gr::clamp_grace_period(self.gr_grace_period);
        for attempt in 0..GRACE_FLOOD_REPEATS {
            self.send_grace_lsas(false);
            if attempt + 1 < GRACE_FLOOD_REPEATS {
                let next_round =
                    std::time::Instant::now() + Duration::from_millis(GRACE_FLOOD_INTERVAL_MS);
                // Service the protocol while the flood window runs:
                // a peer that just re-originated its Router-LSA (the
                // post-Full refresh) has it on its LS retransmission
                // list for us, and RFC 3623 §3.1 (2) makes it refuse
                // helper mode until the ACK arrives. Pumping input
                // between rounds sends that ACK, keeps our Hellos
                // flowing so the peer's neighbour state stays Full
                // (§3.1 (1)), and lets the next round's fresh
                // Grace-LSA instance re-run the helper checks.
                while std::time::Instant::now() < next_round {
                    let now_ms = start.elapsed().as_millis() as u64;
                    self.pump_grace_quiet(recv_buf, now_ms);
                    std::thread::sleep(Duration::from_millis(GRACE_PUMP_SLICE_MS));
                }
            }
        }
        // Persist the grace state AFTER the flood so the sequence
        // floor covers every instance just sent (the deadline runs
        // from the shutdown moment).
        let deadline_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            + u64::from(period) * 1_000;
        if let Some(state) = &self.gr_state_file {
            let line = format!("{deadline_unix_ms} {period} {}\n", self.gr_seq_floor);
            if let Err(e) = std::fs::write(state, line) {
                eprintln!("daemon: ospf grace state write {state}: {e}");
            }
        }
    }

    /// Minimal protocol servicing during the graceful-shutdown flood
    /// window: receive (so in-flight peer LSAs get ACKed by the session
    /// machinery), Hellos (keep the peer's view of us Full, RFC 3623
    /// §3.1 (1)), outbound. Everything that mutates the pre-restart
    /// topology — re-origination, DR election, adjacency teardown — is
    /// deliberately skipped: §2.1 wants the router's LSAs frozen while
    /// the Grace-LSAs are announced and acknowledged.
    fn pump_grace_quiet(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        self.pump_inbound(recv_buf, now_ms);
        self.pump_hellos(now_ms);
        self.pump_outbound();
    }

    /// Refresh the runtime-API status snapshot (cheap: a small vec).
    fn refresh_gr_status(&self) {
        let mut lines = Vec::new();
        if let Some((_, tracker)) = self.gr_recovery.first_key_value() {
            lines.push(format!(
                "ospf graceful restart: recovering (grace until +{}s)",
                tracker.grace_deadline_ms().saturating_sub(0) / 1_000
            ));
        }
        let helpers: Vec<String> = self
            .neighbors
            .iter()
            .filter(|(_, n)| n.helper.is_active())
            .map(|((area, rid), n)| {
                format!(
                    "  helper {} (area {}, {}s grace left)",
                    fmt_rid(*rid),
                    area_label(*area),
                    n.helper.grace_deadline_ms().saturating_sub(0) / 1_000
                )
            })
            .collect();
        if !helpers.is_empty() {
            lines.push("ospf graceful restart helpers:".to_string());
            lines.extend(helpers);
        }
        if let Ok(mut s) = self.gr_status.lock() {
            *s = lines;
        }
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
