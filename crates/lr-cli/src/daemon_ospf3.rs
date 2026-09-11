//! `lr-daemon --protocol ospf` with `[ospf] version = "v3"` — OSPFv3
//! daemon mode (RFC 5340).
//!
//! The v3 counterpart of [`daemon_ospf`](crate::daemon_ospf): the same
//! poll-driven split (the [`DefaultRouter`] pipeline owns the neighbor
//! FSMs, per-area LSDBs, flooding and SPF; this module owns everything
//! the embedder must supply), with the v3 specifics:
//!
//! - **Transport** — one raw IPv6 socket per configured interface
//!   ([`lr_osroute::ospf_transport::OspfV6Transport`]), multicasting to
//!   ff02::5 (RFC 5340 §4.2.1). No interface address is required: the
//!   source is the link-local address (`interface_v6_addrs`), which the
//!   daemon also advertises in its Link-LSA (§4.4.3.4).
//! - **Interface IDs** — the kernel ifindex (FRR convention). The
//!   neighbor's Interface ID comes from its Hello's Interface ID field,
//!   which is exactly what our Router-LSA's p2p link descriptions need
//!   (§A.4.3).
//! - **Self-origination** — a Router-LSA per area (p2p links per Full
//!   adjacency, or the RFC 5340 §4.4.3.2 transit links on broadcast
//!   segments), a Link-LSA per interface (the §4.4.3.4 MUST, carrying
//!   the link-local address and the interface's global prefixes), and
//!   the Intra-Area-Prefix-LSAs attaching the global prefixes to the
//!   Router-LSA (§4.4.3.5) — plus, as the elected DR of a broadcast
//!   segment, the Network-LSA (§4.4.3.3) and the network-referenced
//!   Intra-Area-Prefix-LSA carrying the segment's prefixes.
//! - **Broadcast segments** — `network_type = "broadcast"` runs the
//!   RFC 5340 §4.1.2 interface FSM over the RFC 2328 §9.4 election
//!   (Router-ID identity, [`lr_ospf::interface::elect_v3`]): Waiting
//!   → DR/BDR/DR-Other, Hello DR/BDR fields (§A.3.2), the §10.4
//!   adjacency gate pushed through `set_ospf_dr_state`, the §12.4.2
//!   (v3 §4.4.3.3) Network-LSA lifecycle and the §4.4.3.5
//!   network-referenced prefix split (the DR advertises the segment's
//!   prefixes; transit-reported interfaces stay out of the router's
//!   own Intra-Area-Prefix-LSA).
//! - **Checksum egress** — every packet's IPv6 upper-layer checksum is
//!   finalized with the pseudo-header (source link-local, destination
//!   ff02::5) right before the sendto (RFC 5340 §A.3.1); receive-side
//!   verification is skipped like FRR's ospf6d.
//! - **Next-hop bookkeeping for the kernel** — the link-local →
//!   interface mapping learned from Hello sources feeds
//!   [`crate::v6_nexthop_oifs`], so the kernel mirror can attach the
//!   RTA_OIF a link-local gateway needs.
//!
//! Scope of slice 1 was point-to-point segments only; broadcast
//! segments (DR election, Network-LSAs, network-referenced
//! Intra-Area-Prefix-LSAs) are the current slice. No graceful restart
//! (RFC 5187 is a later slice). Slice 3 adds the RFC 9513 SRv6
//! surface: with `[[ospf.srv6_locator]]` configuration the daemon
//! originates the area-scoped Router Information LSA (the SRv6
//! Capabilities, SR-Algorithm and Node MSD TLVs, RFC 9513 §2-§4) and
//! the SRv6 Locator LSA (§7, with the §8 End SID and the optional §10
//! SID Structure) alongside the topology LSAs, and `[ospf]
//! srv6_receive` opens the §5 locator-reception gate on the router
//! pipeline.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lr_core::addr::{IpAddr, RouterId};
use lr_ospf::codec::OspfCodec;
use lr_ospf::interface::{elect_v3, IfState, V3Elector};
use lr_ospf::lsa::srv6::{locator_route_type, msd_type, NodeMsd};
use lr_ospf::lsa::v3::{
    originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_network_lsa,
    originate_v3_router_lsa, V3LinkLsaBody, V3Prefix, LINK_TYPE_POINTTOPOINT, LINK_TYPE_TRANSIT,
    LS_TYPE_LINK, LS_TYPE_NETWORK, LS_TYPE_ROUTER, ROUTER_BIT_E, ROUTER_BIT_V6,
};
use lr_ospf::lsa::{
    originate_v3_srv6_locator_lsa, originate_v3_srv6_ri_lsa, Srv6EndSidSubTlv, Srv6LocatorTlv,
    Srv6SidStructure, PREFIX_OPT_AC, PREFIX_OPT_LA, PREFIX_OPT_NU, SRV6_CAP_O_FLAG,
};
use lr_ospf::origination::finalize_v3_packet;
use lr_ospf::packet::{HelloBody, OspfBody, OspfPacketType, OSPF_V3_OPTIONS_DEFAULT};
use lr_osroute::ospf_transport::{interface_v6_addrs, OspfV6Transport};
use lr_router::{
    DefaultRouter, OspfNetworkType, RouterInstance, SessionConfig, SessionHandle,
};

use crate::daemon_config::{area_label, DaemonConfig, OspfIfSpec};

/// Loop cadence: also the dead-timer / hello-timer granularity.
const LOOP_INTERVAL_MS: u64 = 50;

/// Delay before an adjacency-driven Router-LSA re-origination:
/// receivers throttle new LSA instances by MinLSArrival (RFC 2328
/// §14, 1 s) — mirrored from the v2 daemon.
const REORIGINATE_DELAY_MS: u64 = 1_500;

/// RFC 2328 §14.1 (extended to v3 by §4.4.3): self-originated LSAs are
/// refreshed before they reach half MaxAge — the v2 default cadence.
const LS_REFRESH_MS: u64 = 1_800_000;

/// The v3-extended Debug wire trace (`LR_OSPF_DEBUG`): walk a packet
/// stream and print kind/length/router-id per frame.
fn dbg_send_trace(bytes: &[u8]) {
    if std::env::var_os("LR_OSPF_DEBUG").is_none() {
        return;
    }
    let mut off = 0usize;
    while off + lr_ospf::packet::OspfHeader::LEN_V3 <= bytes.len() {
        let len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
        if len < lr_ospf::packet::OspfHeader::LEN_V3 || off + len > bytes.len() {
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

/// One configured v3 interface, resolved against the running kernel.
struct Ospf3Interface {
    name: String,
    area: u32,
    cost: u16,
    /// Interface MTU advertised in DBDs.
    mtu: u16,
    hello_interval: u16,
    dead_interval: u32,
    /// The kernel ifindex — our OSPFv3 Interface ID on this link
    /// (FRR convention, and the value the kernel mirror needs).
    interface_id: u32,
    /// Our link-local source address on the link (the value peers use
    /// as their next hop toward us).
    link_local: Ipv6Addr,
    /// Global IPv6 prefixes configured on the interface — the stub
    /// prefixes the Link-LSA and Intra-Area-Prefix-LSA advertise.
    prefixes: Vec<(Ipv6Addr, u8)>,
    transport: OspfV6Transport,
    /// Last Hello we sent (ms since daemon start).
    last_hello_ms: u64,
    /// Router-ids heard on this interface (from their Hellos).
    heard: BTreeMap<u32, HeardNeighbor>,
    /// RFC 2328 §9.1 network type: p2p (default) or broadcast. Only
    /// broadcast segments run the §9.4 DR/BDR election (RFC 5340
    /// §4.1.2 keeps the v2 election on Router-ID identity).
    network_type: OspfNetworkType,
    /// Router Priority advertised in Hellos (§A.3.2; 0 = never DR/BDR).
    priority: u8,
    /// Interface FSM state (§9.1): Waiting until the WaitTimer or
    /// BackupSeen, then DR/Backup/DR-Other from the election. p2p
    /// interfaces stay PointToPoint.
    if_state: IfState,
    /// Elected DR — its Router ID (the v3 §10.4 identity; 0 = none).
    dr: u32,
    /// Elected Backup Designated Router (Router ID; 0 = none).
    bdr: u32,
    /// When the §9.3 WaitTimer fires (ms since daemon start).
    wait_deadline_ms: u64,
    /// Set when a received Hello changes the election input (a
    /// neighbor became bidirectional, or its DR/BDR declarations or
    /// priority changed — §9.3 NeighborChange); the next pump
    /// re-runs the election.
    election_dirty: bool,
    /// Sequence number of our current Network-LSA for this segment
    /// (§4.4.3.3) and whether one is live in the area LSDB.
    net_lsa_seq: Option<u32>,
    net_lsa_active: bool,
    /// Sequence number of our current network-referenced
    /// Intra-Area-Prefix-LSA (§4.4.3.5) and whether one is live.
    net_iap_seq: Option<u32>,
    net_iap_active: bool,
}

/// One neighbor heard on an interface. The v3-specific datum is the
/// neighbor's Interface ID on the shared link, from its Hello's
/// Interface ID field — the Neighbor Interface ID of our p2p link
/// description (§A.4.3) and the key to its Link-LSA. On broadcast
/// segments the Hello's DR/BDR fields (Router IDs, §A.3.2) and the
/// Router Priority feed the §9.4 election.
#[derive(Debug, Clone, Copy)]
struct HeardNeighbor {
    /// The neighbor's Interface ID on this link.
    interface_id: u32,
    priority: u8,
    /// The neighbor's link-local address (the Hello's source).
    link_local: Ipv6Addr,
    last_ms: u64,
    /// The neighbor lists our router-id (state ≥ 2-Way, §10.1).
    bidirectional: bool,
    /// The DR the neighbor claims in its Hellos (Router ID; 0 = none).
    stated_dr: u32,
    /// The BDR the neighbor claims in its Hellos (Router ID).
    stated_bdr: u32,
}

/// One dynamic neighbor session, keyed `(area, router-id)`.
struct Neighbor {
    handle: SessionHandle,
    ifindex: u32,
    established: bool,
}

struct Ospf3Daemon {
    router: Arc<Mutex<DefaultRouter>>,
    interfaces: Vec<Ospf3Interface>,
    neighbors: BTreeMap<(u32, u32), Neighbor>,
    /// Router-LSA re-origination due times (area → ms), MinLSArrival
    /// spaced like the v2 daemon.
    pending_reorig: BTreeMap<u32, u64>,
    /// Area → anchor session (registers the area; self-origination
    /// rides it, output discarded).
    anchors: BTreeMap<u32, SessionHandle>,
    /// Per-LSA sequence floors: area → Router-LSA, (area, ifindex) →
    /// Link-LSA, (area, ls_id) → Intra-Area-Prefix-LSA, area →
    /// SRv6 Router-Information-LSA, area → SRv6 Locator-LSA.
    router_lsa_seq: BTreeMap<u32, u32>,
    link_lsa_seq: BTreeMap<(u32, u32), u32>,
    iap_lsa_seq: BTreeMap<(u32, u32), u32>,
    ri_lsa_seq: BTreeMap<u32, u32>,
    srv6_lsa_seq: BTreeMap<u32, u32>,
    /// Last self-origination per area (ms) — the §14.1 refresh cadence.
    last_orig_ms: BTreeMap<u32, u64>,
    /// RFC 9513 origination state (`None` = SRv6 off — the daemon stays
    /// byte-identical to a pre-SRv6 one).
    srv6: Option<Srv6Origination>,
    router_id: RouterId,
    /// Snapshot for the runtime API `status` command.
    status: Arc<Mutex<Vec<String>>>,
}

/// The resolved RFC 9513 origination state: what `reoriginate_area`
/// advertises in every configured area. Built once from the validated
/// config (§7.1 locators resolved to wire TLVs with their §8 End SIDs).
struct Srv6Origination {
    /// SRv6 Capabilities TLV flags (RFC 9513 §2; the O-flag).
    capabilities: u16,
    /// SR-Algorithm TLV values (RFC 8665 §3.1): the distinct locator
    /// algorithms, ascending.
    algorithms: Vec<u8>,
    /// Node MSD TLV pairs (RFC 8476 §2), MSD-type order 41/42/44/45.
    msds: Vec<NodeMsd>,
    /// The §7.1 Locator TLVs, one per configured locator.
    locators: Vec<Srv6LocatorTlv>,
}

impl Srv6Origination {
    /// Resolve the validated `[[ospf.srv6_locator]]` configuration into
    /// the origination state. Parse failures cannot happen (finalize
    /// rejected them) but are handled fail-soft: the offending locator
    /// is dropped with a log line, never a panic.
    fn from_config(cfg: &DaemonConfig) -> Self {
        let capabilities = if cfg.ospf_srv6_o_flag {
            SRV6_CAP_O_FLAG
        } else {
            0
        };
        let mut algorithms = std::collections::BTreeSet::new();
        let mut locators = Vec::new();
        for spec in &cfg.ospf_srv6_locators {
            let Some(text) = spec.prefix.as_deref() else {
                continue; // finalize() already rejected this
            };
            let Ok(prefix) = text.parse::<lr_core::addr::Prefix>() else {
                continue;
            };
            let lr_core::addr::IpAddr::V6(octets) = prefix.addr else {
                continue;
            };
            // §7.1: the locator prefix is advertised with the host
            // bits zeroed (the crate's Prefix keeps them that way).
            let algorithm = spec.algorithm.unwrap_or(0);
            algorithms.insert(algorithm);
            // §8: the End SID value defaults to the locator prefix
            // itself (the RFC 8986 End behavior on the locator).
            let sid = match spec.sid.as_deref() {
                Some(text) => match text.parse::<lr_core::addr::IpAddr>() {
                    Ok(IpAddr::V6(octets)) => octets,
                    _ => {
                        eprintln!("daemon: ospf3 srv6 locator {text}: bad sid, locator skipped");
                        continue;
                    }
                },
                None => octets,
            };
            let structure = match (
                spec.block_len,
                spec.node_len,
                spec.function_len,
                spec.argument_len,
            ) {
                (Some(lb), Some(ln), Some(f), Some(a)) => Some(Srv6SidStructure {
                    lb_len: lb,
                    ln_len: ln,
                    func_len: f,
                    arg_len: a,
                }),
                _ => None,
            };
            locators.push(Srv6LocatorTlv {
                route_type: locator_route_type::INTRA_AREA,
                algorithm,
                locator_len: prefix.prefix_len,
                options: if spec.anycast.unwrap_or(false) {
                    PREFIX_OPT_AC
                } else {
                    0
                },
                metric: spec.metric.unwrap_or(0),
                prefix: octets,
                end_sids: vec![Srv6EndSidSubTlv {
                    flags: 0,
                    behavior: spec.behavior.unwrap_or(1), // 1 = End
                    sid,
                    structure,
                }],
                fwd_addr: None,
                route_tag: None,
            });
        }
        let mut msds = Vec::new();
        for (msd, value) in [
            (msd_type::SRH_MAX_SL, cfg.ospf_srv6_max_sl),
            (msd_type::SRH_MAX_END_POP, cfg.ospf_srv6_max_end_pop),
            (msd_type::SRH_MAX_H_ENCAPS, cfg.ospf_srv6_max_h_encaps),
            (msd_type::SRH_MAX_END_D, cfg.ospf_srv6_max_end_d),
        ] {
            if let Some(v) = value {
                msds.push((msd, v));
            }
        }
        Self {
            capabilities,
            algorithms: algorithms.into_iter().collect(),
            msds,
            locators,
        }
    }

    /// The origination gate: SRv6 state exists only when locators are
    /// configured — reception alone never turns a daemon into an
    /// SRv6 originator (fail-closed default).
    fn maybe_from_config(cfg: &DaemonConfig) -> Option<Self> {
        (!cfg.ospf_srv6_locators.is_empty()).then(|| Self::from_config(cfg))
    }
}

/// `lr-daemon --protocol ospf` with `[ospf] version = "v3"`.
pub fn run_ospf3_daemon(cfg: &DaemonConfig, rid: RouterId) -> ExitCode {
    if cfg.ospf_interfaces.is_empty() {
        eprintln!(
            "daemon: --protocol ospf needs at least one interface \
             (--ospf-interface NAME or [[ospf.interface]] tables)"
        );
        return ExitCode::from(2);
    }
    let mut interfaces: Vec<Ospf3Interface> = Vec::new();
    for spec in &cfg.ospf_interfaces {
        match resolve_interface(cfg, spec) {
            Ok(iface) => {
                println!(
                    "daemon: ospf3 interface {} area {} — ifindex {} (interface id), \
                     link-local {}, {} global prefix(es), cost {}, hello {}s dead {}s, {}",
                    iface.name,
                    area_label(iface.area),
                    iface.interface_id,
                    iface.link_local,
                    iface.prefixes.len(),
                    iface.cost,
                    iface.hello_interval,
                    iface.dead_interval,
                    match iface.network_type {
                        OspfNetworkType::PointToPoint => "point-to-point",
                        OspfNetworkType::Broadcast => "broadcast",
                    },
                );
                interfaces.push(iface);
            }
            Err(e) => {
                eprintln!("daemon: ospf interface {}: {}", spec.label(), e);
                return ExitCode::from(1);
            }
        }
    }
    let mut daemon = Ospf3Daemon {
        router: Arc::new(Mutex::new(DefaultRouter::new())),
        interfaces,
        neighbors: BTreeMap::new(),
        pending_reorig: BTreeMap::new(),
        anchors: BTreeMap::new(),
        router_lsa_seq: BTreeMap::new(),
        link_lsa_seq: BTreeMap::new(),
        iap_lsa_seq: BTreeMap::new(),
        ri_lsa_seq: BTreeMap::new(),
        srv6_lsa_seq: BTreeMap::new(),
        last_orig_ms: BTreeMap::new(),
        srv6: Srv6Origination::maybe_from_config(cfg),
        router_id: rid,
        status: Arc::new(Mutex::new(Vec::new())),
    };
    if let Some(s) = &daemon.srv6 {
        println!(
            "daemon: ospf3 SRv6 origination on — {} locator(s), algorithms {:?}, \
             o-flag {}, {} MSD limit(s)",
            s.locators.len(),
            s.algorithms,
            if cfg.ospf_srv6_o_flag { "on" } else { "off" },
            s.msds.len(),
        );
    }
    // ---- Router: one anchor session per area (v3). ----
    let iface_mtu = daemon.interfaces.first().map(|i| i.mtu).unwrap_or(1500);
    {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.lock().unwrap();
        if cfg.ospf_srv6_receive {
            // RFC 9513 §5 reception: project learned Locator LSAs into
            // the per-node SRv6 database and install the §5 locator
            // routes (fail-closed off by default, like `sr_receive`).
            router.set_ospf_srv6_receive(true);
        }
        for area in daemon.interfaces.iter().map(|i| i.area) {
            if daemon.anchors.contains_key(&area) {
                continue;
            }
            match router.add_session(SessionConfig::ospfv3(rid, area).with_ospf_mtu(iface_mtu)) {
                Ok(h) => {
                    daemon.anchors.insert(area, h);
                }
                Err(e) => {
                    eprintln!("daemon: ospf add_session area {}: {}", area_label(area), e);
                    return ExitCode::from(1);
                }
            }
        }
    }
    // ---- Signals + runtime API + ticker. ----
    if let Err(sig) = crate::signal::init() {
        eprintln!("daemon: cannot install signal handlers (signal {})", sig);
        return ExitCode::from(1);
    }
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let runtime = Arc::new(crate::Runtime {
        reload: Arc::new(|| {
            vec![
                "ospf3: configuration reload is not supported yet; shutdown still works"
                    .to_string(),
            ]
        }),
        router: Arc::clone(&daemon.router),
        running: Arc::clone(&running),
        status_lines: {
            let status = Arc::clone(&daemon.status);
            let router = Arc::clone(&daemon.router);
            Arc::new(move || {
                let mut lines = status.lock().map(|s| s.clone()).unwrap_or_default();
                if let Ok(router) = router.lock() {
                    for s in router.session_summaries() {
                        lines.push(format!(
                            "ospf3 session #{} kind={} state={}",
                            s.handle.0, s.kind, s.state
                        ));
                    }
                }
                lines
            })
        },
    });
    if let Err(e) = crate::spawn_api(cfg, &runtime) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }
    crate::spawn_ticker(
        &runtime,
        cfg.install_kernel,
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    );

    // ---- Initial self-origination per area. ----
    {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.lock().unwrap();
        let areas: Vec<u32> = daemon.anchors.keys().copied().collect();
        for area in areas {
            daemon.reoriginate_area(&mut router, area, 0);
        }
    }

    // ---- Main loop. ----
    let start = std::time::Instant::now();
    let mut recv_buf = [0u8; 65535];
    println!(
        "daemon: ospf3 main loop started ({} interface(s))",
        daemon.interfaces.len()
    );
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        crate::dispatch_signals(&runtime);
        if !running.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let now_ms = start.elapsed().as_millis() as u64;
        daemon.pump(&mut recv_buf, now_ms);
        std::thread::sleep(Duration::from_millis(LOOP_INTERVAL_MS));
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
            crate::daemon_ospf::log_event(&ev);
        }
    }
    println!("daemon: ospf3 shutdown complete");
    ExitCode::SUCCESS
}

/// Resolve one configured interface for v3: the IPv6 raw transport, the
/// link-local source address and the global prefixes. No IPv4 address
/// is needed (RFC 5340 §3.1: OSPFv3 runs per-link, not per-subnet).
fn resolve_interface(cfg: &DaemonConfig, spec: &OspfIfSpec) -> Result<Ospf3Interface, String> {
    let name = spec.label().to_string();
    let v6addrs = interface_v6_addrs(&name).map_err(|e| e.to_string())?;
    let link_local = v6addrs
        .iter()
        .find(|a| a.is_link_local())
        .map(|a| a.addr)
        .ok_or_else(|| format!("no IPv6 link-local address on {name}"))?;
    let prefixes: Vec<(Ipv6Addr, u8)> = v6addrs
        .iter()
        .filter(|a| !a.is_link_local())
        .map(|a| (a.addr, a.prefix_len))
        .collect();
    let transport = OspfV6Transport::bind(&name, false).map_err(|e| {
        if e.is_permission_denied() {
            format!(
                "{e} (raw OSPF sockets need root or a user/network namespace \
                 — e.g. unshare -Urn)"
            )
        } else {
            e.to_string()
        }
    })?;
    transport
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking on {name}: {e}"))?;
    let iface_mtu = transport.mtu().unwrap_or(1500);
    let hello = spec
        .hello_interval
        .unwrap_or(cfg.ospf_hello_interval)
        .max(1);
    let dead = spec
        .dead_interval
        .unwrap_or(cfg.ospf_dead_interval)
        .max(u32::from(hello));
    // RFC 2328 §9.1 network type (the §9.4 election applies only on
    // broadcast segments; RFC 5340 §4.1.2 keeps the v2 algorithm).
    let network_type = match spec.network_type.as_deref() {
        None | Some("p2p") | Some("point-to-point") | Some("") => OspfNetworkType::PointToPoint,
        Some("broadcast") => OspfNetworkType::Broadcast,
        Some(other) => {
            return Err(format!(
                "unknown network_type '{other}' (use \"p2p\" or \"broadcast\")"
            ))
        }
    };
    let priority = spec.priority.unwrap_or(1);
    let interface_id = transport.ifindex();
    Ok(Ospf3Interface {
        name,
        area: spec.area.unwrap_or(cfg.ospf_area),
        cost: spec.cost.unwrap_or(10),
        mtu: iface_mtu,
        hello_interval: hello,
        dead_interval: dead,
        interface_id,
        link_local,
        prefixes,
        transport,
        last_hello_ms: 0,
        heard: BTreeMap::new(),
        network_type,
        priority,
        // §9.3: broadcast interfaces come up in Waiting and wait
        // RouterDeadInterval before electing (p2p has no election;
        // priority-0 routers skip Waiting per §9.4 — never eligible,
        // BIRD/FRR go straight to DR-Other too).
        if_state: if network_type == OspfNetworkType::Broadcast && priority > 0 {
            IfState::Waiting
        } else {
            IfState::DrOther
        },
        dr: 0,
        bdr: 0,
        // §9.3: the WaitTimer runs RouterDeadInterval from ifup. The
        // main-loop clock starts right after resolve, so the deadline
        // is the dead interval itself.
        wait_deadline_ms: if network_type == OspfNetworkType::Broadcast && priority > 0 {
            u64::from(dead) * 1000
        } else {
            0
        },
        election_dirty: false,
        net_lsa_seq: None,
        net_lsa_active: false,
        net_iap_seq: None,
        net_iap_active: false,
    })
}

impl Ospf3Interface {
    /// §10.5: fold one received Hello into the interface's neighbor
    /// table. The v3 identity inputs are the neighbor's Interface ID
    /// (Hello Interface ID field) and its link-local source address.
    /// On broadcast segments the Hello's DR/BDR claims (Router IDs)
    /// and Router Priority feed the §9.4 election: the interface is
    /// flagged election-dirty when the neighbor became bidirectional
    /// (the elector set grew) or its DR/BDR declarations or priority
    /// changed (§9.3 NeighborChange — BIRD hello.c parity: only
    /// declare-transitions matter, not every claim value change).
    fn track_hello(
        &mut self,
        rid: u32,
        link_local: Ipv6Addr,
        body: &HelloBody,
        our_rid: u32,
        now_ms: u64,
    ) {
        let bidirectional = body.neighbors.contains(&our_rid);
        let became_bidirectional = match self.heard.get(&rid) {
            Some(prev) => {
                if self.network_type == OspfNetworkType::Broadcast
                    && (prev.priority != body.priority
                        || (prev.stated_dr == rid) != (body.dr == rid)
                        || (prev.stated_bdr == rid) != (body.bdr == rid))
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
        let entry = self.heard.entry(rid).or_insert(HeardNeighbor {
            interface_id: body.network_mask, // v3: Interface ID slot
            priority: body.priority,
            link_local,
            last_ms: now_ms,
            bidirectional,
            stated_dr: body.dr,
            stated_bdr: body.bdr,
        });
        entry.interface_id = body.network_mask;
        entry.priority = body.priority;
        entry.link_local = link_local;
        entry.last_ms = now_ms;
        entry.bidirectional = bidirectional;
        entry.stated_dr = body.dr;
        entry.stated_bdr = body.bdr;
    }
}

impl Ospf3Daemon {
    fn pump(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        self.pump_inbound(recv_buf, now_ms);
        self.pump_election(now_ms);
        self.pump_adjacency(now_ms);
        self.pump_dead_timer(now_ms);
        self.pump_reoriginate(now_ms);
        self.pump_hellos(now_ms);
        self.pump_outbound();
    }

    /// Drive the interface FSM and the DR/BDR election on broadcast
    /// segments (RFC 2328 §9.3/§9.4 over the RFC 5340 §4.1.2
    /// Router-ID identity). p2p interfaces never elect (§9.4 does not
    /// apply) and are skipped.
    fn pump_election(&mut self, now_ms: u64) {
        let mut changed_areas: Vec<u32> = Vec::new();
        let self_rid = self.router_id.as_u32();
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
                if Self::run_election(iface, &mut self.neighbors, &self.router, self_rid, now_ms)
                {
                    // The transit-link set (§4.4.3.2) and the
                    // Network-LSA membership (§4.4.3.3) may have
                    // changed.
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
    /// router itself, keyed by Router IDs (the RFC 5340 §4.1.2
    /// identity). The result lands in the Hello DR/BDR fields (§A.3.2)
    /// and is pushed into every session on the segment, whose §10.4
    /// adjacency gate the router re-runs (§9.4 step 7).
    ///
    /// Returns whether the elected pair (or our role) changed.
    fn run_election(
        iface: &mut Ospf3Interface,
        neighbors: &mut BTreeMap<(u32, u32), Neighbor>,
        router: &Mutex<DefaultRouter>,
        self_rid: u32,
        now_ms: u64,
    ) -> bool {
        let dead_ms = u64::from(iface.dead_interval) * 1000;
        let mut electors: Vec<V3Elector> = iface
            .heard
            .iter()
            .filter(|(_, h)| h.bidirectional && now_ms.saturating_sub(h.last_ms) <= dead_ms)
            .map(|(&rid, h)| V3Elector {
                router_id: rid,
                priority: h.priority,
                stated_dr: h.stated_dr,
                stated_bdr: h.stated_bdr,
            })
            .collect();
        // Router X itself is on the list (§9.4), claiming its current
        // view of the segment.
        electors.push(V3Elector {
            router_id: self_rid,
            priority: iface.priority,
            stated_dr: iface.dr,
            stated_bdr: iface.bdr,
        });
        let (dr, bdr) = elect_v3(&electors, self_rid);
        let changed = dr != iface.dr || bdr != iface.bdr;
        iface.dr = dr;
        iface.bdr = bdr;
        // §9.4 step 5: derive our interface state from the result.
        let next_state = if self_rid == dr {
            IfState::Dr
        } else if self_rid == bdr {
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
            if *area != iface.area || n.ifindex != iface.interface_id {
                continue;
            }
            match router.set_ospf_dr_state(n.handle, dr, bdr) {
                Ok(_) => {}
                Err(e) => eprintln!("daemon: ospf3 dr state: {}", e),
            }
        }
        if changed || role_changed {
            println!(
                "daemon: ospf3 iface {} elected DR {} / BDR {} — we are {}",
                iface.name,
                fmt_rid(dr),
                fmt_rid(bdr),
                iface.if_state.name()
            );
        }
        changed || role_changed
    }

    /// Receive every pending datagram and feed it into the matching
    /// neighbor session, creating sessions for unknown routers. v6 raw
    /// sockets deliver the OSPF packet without the IPv6 header, and
    /// receive-side checksum verification is skipped (FRR ospf6d
    /// parity — the RFC 5340 §4.2.2 checks the daemon enforces are
    /// version, area and source identity).
    fn pump_inbound(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        let mut datagrams: Vec<(u32, u32, Vec<u8>, Ipv6Addr)> = Vec::new();
        for iface in &mut self.interfaces {
            loop {
                match iface.transport.recv_from(recv_buf) {
                    Ok(Some((n, src))) => {
                        let ospf = &recv_buf[..n];
                        if ospf.len() < lr_ospf::packet::OspfHeader::LEN_V3 {
                            continue;
                        }
                        if ospf_debug_enabled() {
                            eprintln!(
                                "dbg-recv kind={} len={} rid={:08x} src={}",
                                ospf.get(1).copied().unwrap_or(0),
                                u16::from_be_bytes([ospf[2], ospf[3]]),
                                u32::from_be_bytes([ospf[4], ospf[5], ospf[6], ospf[7]]),
                                src
                            );
                        }
                        if ospf.get(1).copied() == Some(OspfPacketType::Hello as u8)
                            && ospf.len() >= 12
                        {
                            let hello_rid =
                                u32::from_be_bytes([ospf[4], ospf[5], ospf[6], ospf[7]]);
                            let hello_area =
                                u32::from_be_bytes([ospf[8], ospf[9], ospf[10], ospf[11]]);
                            if hello_rid != self.router_id.as_u32() && hello_area == iface.area {
                                if let Some(body) = parse_hello_body_v3(ospf) {
                                    iface.track_hello(
                                        hello_rid,
                                        src,
                                        &body,
                                        self.router_id.as_u32(),
                                        now_ms,
                                    );
                                    // The neighbor's link-local rides its
                                    // interface: register it for the
                                    // kernel mirror's RTA_OIF lookups.
                                    crate::v6_nexthop_oifs()
                                        .lock()
                                        .map(|mut m| {
                                            m.insert(IpAddr::V6(src.octets()), iface.interface_id)
                                        })
                                        .ok();
                                }
                            }
                        }
                        datagrams.push((iface.interface_id, iface.area, ospf.to_vec(), src));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("daemon: ospf recv {}: {}", iface.name, e);
                        break;
                    }
                }
            }
        }
        let mut accepted: Vec<(u32, u32, u32, usize, u16)> = Vec::new();
        for (idx, (interface_id, iface_area, bytes, _src)) in datagrams.iter().enumerate() {
            let Some((rid, area, _len)) = demux_header(bytes) else {
                continue;
            };
            if area != *iface_area || rid == self.router_id.as_u32() {
                continue;
            }
            let mtu = self
                .interfaces
                .iter()
                .find(|i| i.interface_id == *interface_id)
                .map(|i| i.mtu)
                .unwrap_or(1500);
            accepted.push((*interface_id, area, rid, idx, mtu));
        }
        if accepted.is_empty() {
            return;
        }
        let router_arc = Arc::clone(&self.router);
        let mut router = router_arc.lock().unwrap();
        for (interface_id, area, rid, idx, mtu) in accepted {
            let key = (area, rid);
            if !self.neighbors.contains_key(&key) {
                // Broadcast segments carry the network type and the
                // segment identities into the session: §10.4 gates
                // adjacency on the elected DR/BDR, identified by
                // Router ID (RFC 5340 §4.1.2 — the v3 Hello's DR/BDR
                // fields are Router IDs, §A.3.2).
                let cfg_build = self
                    .interfaces
                    .iter()
                    .find(|i| i.interface_id == interface_id)
                    .map(|iface| {
                        let cfg = SessionConfig::ospfv3(self.router_id, area)
                            .with_ospf_mtu(mtu)
                            .with_ospf_network_type(iface.network_type);
                        match iface.network_type {
                            OspfNetworkType::Broadcast => cfg
                                .with_ospf_interface_ip(self.router_id.as_u32())
                                .with_ospf_neighbor_ip(rid),
                            OspfNetworkType::PointToPoint => cfg,
                        }
                    })
                    .unwrap_or_else(|| SessionConfig::ospfv3(self.router_id, area));
                match router.add_session(cfg_build) {
                    Ok(h) => {
                        // Push the current election result so a session
                        // joining mid-life adopts the segment's DR/BDR
                        // immediately (the v2 daemon pattern).
                        if let Some(iface) = self
                            .interfaces
                            .iter()
                            .find(|i| i.interface_id == interface_id)
                        {
                            if iface.network_type == OspfNetworkType::Broadcast {
                                let _ = router.set_ospf_dr_state(h, iface.dr, iface.bdr);
                            }
                        }
                        self.neighbors.insert(
                            key,
                            Neighbor {
                                handle: h,
                                ifindex: interface_id,
                                established: false,
                            },
                        );
                        println!(
                            "daemon: ospf3 neighbor {} discovered (area {}, iface {})",
                            fmt_rid(rid),
                            area_label(area),
                            self.interfaces
                                .iter()
                                .find(|i| i.interface_id == interface_id)
                                .map(|i| i.name.as_str())
                                .unwrap_or("?")
                        );
                    }
                    Err(e) => {
                        eprintln!("daemon: ospf3 add_session: {e}");
                        continue;
                    }
                }
            }
            let handle = self.neighbors[&key].handle;
            if let Err(e) = router.feed_input(handle, &datagrams[idx].2) {
                eprintln!("daemon: ospf3 feed_input: {e}");
            }
        }
        // Events are consumed (logged + kernel-mirrored) solely by the
        // ticker thread — the daemon would race it here and steal
        // RouteInstalled events before the mirror sees them.
    }

    /// Track Full transitions via session summaries (the v2 pattern)
    /// and schedule Router-LSA re-origination for the affected areas.
    fn pump_adjacency(&mut self, now_ms: u64) {
        let mut newly_full: Vec<(u32, u32)> = Vec::new();
        let mut changed_areas: Vec<u32> = Vec::new();
        {
            let router_arc = Arc::clone(&self.router);
            let router = router_arc.lock().unwrap();
            let summaries = router.session_summaries();
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
        }
        for area in changed_areas {
            self.schedule_reoriginate(area, now_ms);
        }
        for (area, rid) in newly_full {
            println!(
                "daemon: ospf3 neighbor {} Full (area {})",
                fmt_rid(rid),
                area_label(area)
            );
        }
    }

    /// Tear sessions down after RouterDeadInterval without a packet.
    fn pump_dead_timer(&mut self, now_ms: u64) {
        let mut expired: Vec<(u32, u32)> = Vec::new();
        // Broadcast interfaces that lost a heard neighbor: the
        // bidirectional elector set shrank (§9.3 NeighborChange).
        let mut election_dirty_ifaces: Vec<u32> = Vec::new();
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
                if iface.network_type == OspfNetworkType::Broadcast {
                    election_dirty_ifaces.push(iface.interface_id);
                }
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
                    "daemon: ospf3 neighbor {} dead (area {}) — session closed",
                    fmt_rid(rid),
                    area_label(area)
                );
            }
        }
        drop(router);
        for iface in &mut self.interfaces {
            if election_dirty_ifaces.contains(&iface.interface_id) {
                iface.election_dirty = true;
            }
        }
        let areas: Vec<u32> = self.anchors.keys().copied().collect();
        for area in areas {
            self.schedule_reoriginate(area, now_ms);
        }
    }

    /// Re-originate the Router-LSA when scheduled (adjacency changes)
    /// or when the §14.1 refresh cadence elapses.
    fn pump_reoriginate(&mut self, now_ms: u64) {
        let mut due: Vec<(u32, u64)> = self
            .pending_reorig
            .iter()
            .filter(|(_, t)| **t <= now_ms)
            .map(|(a, t)| (*a, *t))
            .collect();
        for area in self.anchors.keys() {
            let needs_refresh = self
                .last_orig_ms
                .get(area)
                .map(|t| now_ms.saturating_sub(*t) >= LS_REFRESH_MS)
                .unwrap_or(false);
            if needs_refresh {
                due.push((*area, now_ms));
            }
        }
        if due.is_empty() {
            return;
        }
        due.sort_by_key(|(_, t)| *t);
        let areas: Vec<u32> = due.into_iter().map(|(a, _)| a).collect();
        let router_arc = Arc::clone(&self.router);
        let mut router = router_arc.lock().unwrap();
        for area in areas {
            self.pending_reorig.remove(&area);
            self.reoriginate_area(&mut router, area, now_ms);
        }
    }

    fn schedule_reoriginate(&mut self, area: u32, now_ms: u64) {
        let due = now_ms + REORIGINATE_DELAY_MS;
        self.pending_reorig
            .entry(area)
            .and_modify(|t| *t = (*t).min(due))
            .or_insert(due);
    }

    /// Send one v3 Hello per interface whose interval elapsed,
    /// listing the router-ids heard inside the dead window (§A.3.2).
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
            let hello = HelloBody {
                // v3: the network-mask slot carries the Interface ID.
                network_mask: iface.interface_id,
                hello_interval: iface.hello_interval,
                options: OSPF_V3_OPTIONS_DEFAULT,
                priority: iface.priority,
                dead_interval: iface.dead_interval.min(u32::from(u16::MAX)),
                // p2p segments elect no DR (§9.4 does not apply); on
                // broadcast segments the fields carry the elected
                // Router IDs (§A.3.2, RFC 5340 §4.1.2).
                dr: if iface.network_type == OspfNetworkType::Broadcast {
                    iface.dr
                } else {
                    0
                },
                bdr: if iface.network_type == OspfNetworkType::Broadcast {
                    iface.bdr
                } else {
                    0
                },
                neighbors,
            };
            let pkt = lr_ospf::packet::OspfPacket {
                header: lr_ospf::packet::OspfHeader {
                    version: lr_ospf::packet::OspfVersion::V3 as u8,
                    kind: OspfPacketType::Hello as u8,
                    length: 0,
                    router_id: self.router_id.as_u32(),
                    area_id: iface.area,
                    checksum: 0,
                    au_type_or_instance: 0,
                    auth_data: 0,
                },
                body: OspfBody::Hello(hello),
            };
            let mut bytes = match OspfCodec::v3().encode_vec(&pkt) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("daemon: ospf3 hello encode: {e}");
                    continue;
                }
            };
            finalize_v3_packet(&mut bytes, &iface.link_local.octets(), &MULTICAST_ALL_SPF);
            dbg_send_trace(&bytes);
            if let Err(e) = iface.transport.send_multicast(&bytes) {
                eprintln!("daemon: ospf3 hello send {}: {}", iface.name, e);
            }
        }
    }

    /// Drain neighbor sessions and send every packet as its own
    /// datagram, checksum finalized for the pseudo-header this
    /// interface actually uses (source link-local, destination
    /// ff02::5). Anchor output is discarded (no wire neighbor).
    fn pump_outbound(&mut self) {
        let mut outbound: Vec<(u32, Vec<u8>)> = Vec::new();
        {
            let router_arc = Arc::clone(&self.router);
            let mut router = router_arc.lock().unwrap();
            for n in self.neighbors.values() {
                let stream = router.drain_output(n.handle);
                if stream.is_empty() {
                    continue;
                }
                let mut off = 0usize;
                while off + lr_ospf::packet::OspfHeader::LEN_V3 <= stream.len() {
                    let len = u16::from_be_bytes([stream[off + 2], stream[off + 3]]) as usize;
                    if len < lr_ospf::packet::OspfHeader::LEN_V3 || off + len > stream.len() {
                        break;
                    }
                    outbound.push((n.ifindex, stream[off..off + len].to_vec()));
                    off += len;
                }
            }
            for anchor in self.anchors.values() {
                let _ = router.drain_output(*anchor);
            }
        }
        for (interface_id, mut bytes) in outbound {
            let Some(iface) = self
                .interfaces
                .iter_mut()
                .find(|i| i.interface_id == interface_id)
            else {
                continue;
            };
            finalize_v3_packet(&mut bytes, &iface.link_local.octets(), &MULTICAST_ALL_SPF);
            dbg_send_trace(&bytes);
            if let Err(e) = iface.transport.send_multicast(&bytes) {
                eprintln!("daemon: ospf3 send {}: {}", iface.name, e);
            }
        }
    }

    /// Originate the area's self-described LSAs and feed them to the
    /// anchor session so the router floods them to every neighbor:
    /// the Router-LSA (one p2p link per Full adjacency), a Link-LSA
    /// per interface (the §4.4.3.4 MUST) and one Intra-Area-Prefix-LSA
    /// carrying the global prefixes attached to the Router-LSA.
    fn reoriginate_area(&mut self, router: &mut DefaultRouter, area: u32, now_ms: u64) {
        let mut lsas: Vec<lr_ospf::lsa::Lsa> = Vec::new();
        // Per-interface Link-LSAs (always) and p2p links (Full only).
        for iface in &self.interfaces {
            if iface.area != area {
                continue;
            }
            let prefixes: Vec<V3Prefix> = iface
                .prefixes
                .iter()
                .map(|(addr, len)| {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&addr.octets());
                    V3Prefix {
                        prefix_len: *len,
                        options: 0,
                        metric: 0,
                        addr: octets,
                    }
                })
                .collect();
            let key = (area, iface.interface_id);
            let seq = self.link_lsa_seq.get(&key).copied();
            match originate_v3_link_lsa(
                self.router_id.as_u32(),
                iface.interface_id,
                1,
                OSPF_V3_OPTIONS_DEFAULT,
                iface.link_local.octets(),
                prefixes,
                seq,
            ) {
                Some(lsa) => {
                    self.link_lsa_seq.insert(key, lsa.header.ls_sequence_number);
                    lsas.push(lsa);
                }
                None => eprintln!(
                    "daemon: ospf3 link-LSA sequence space exhausted on {}",
                    iface.name
                ),
            }
        }
        // Router-LSA links + the broadcast segment LSA set (§4.4.3.2
        // transit links, §4.4.3.3 Network-LSA, §4.4.3.5 network IAP).
        let mut links: Vec<lr_ospf::lsa::v3::V3RouterLink> = Vec::new();
        // Interfaces described as transit links: their global prefixes
        // ride the DR's network-referenced Intra-Area-Prefix-LSA, not
        // our router-referenced one (§4.4.3.5).
        let mut transit_reported: BTreeMap<u32, ()> = BTreeMap::new();
        for iface in &mut self.interfaces {
            if iface.area != area {
                continue;
            }
            let established: Vec<u32> = self
                .neighbors
                .iter()
                .filter(|((n_area, _rid), n)| {
                    *n_area == area && n.ifindex == iface.interface_id && n.established
                })
                .map(|(&(_, rid), _)| rid)
                .collect();
            match iface.network_type {
                OspfNetworkType::PointToPoint => {
                    for rid in &established {
                        let neighbor_interface_id =
                            iface.heard.get(rid).map(|h| h.interface_id).unwrap_or(0);
                        links.push(lr_ospf::lsa::v3::V3RouterLink {
                            link_type: LINK_TYPE_POINTTOPOINT,
                            metric: iface.cost,
                            interface_id: iface.interface_id,
                            neighbor_interface_id,
                            neighbor_router_id: *rid,
                        });
                    }
                }
                OspfNetworkType::Broadcast => {
                    // FRR ospf6d `ospf6_router_lsa_originate` parity: a
                    // broadcast interface is described only as a
                    // transit link, and only when this router is the
                    // DR with at least one Full adjacency, or is fully
                    // adjacent with the elected DR. Otherwise the
                    // interface is not transit yet and stays out of
                    // the Router-LSA (adjacencies cannot form before a
                    // DR exists — §10.4 gates on the elected pair).
                    let we_are_dr =
                        iface.if_state == IfState::Dr && iface.dr == self.router_id.as_u32();
                    let dr_reachable = !we_are_dr
                        && iface.dr != 0
                        && established.contains(&iface.dr)
                        && iface
                            .heard
                            .get(&iface.dr)
                            .map(|h| h.interface_id)
                            .is_some();
                    let describe = (we_are_dr && !established.is_empty()) || dr_reachable;
                    if describe {
                        let (neighbor_interface_id, neighbor_router_id) = if we_are_dr {
                            // The DR describes itself: the network vertex's
                            // neighbor fields are its own (FRR keeps the
                            // self-referential shape, §A.4.3 type 2).
                            (iface.interface_id, self.router_id.as_u32())
                        } else {
                            (
                                iface
                                    .heard
                                    .get(&iface.dr)
                                    .map(|h| h.interface_id)
                                    .unwrap_or(0),
                                iface.dr,
                            )
                        };
                        links.push(lr_ospf::lsa::v3::V3RouterLink {
                            link_type: LINK_TYPE_TRANSIT,
                            metric: iface.cost,
                            interface_id: iface.interface_id,
                            neighbor_interface_id,
                            neighbor_router_id,
                        });
                        transit_reported.insert(iface.interface_id, ());
                    }
                    // §4.4.3.3: as the DR with at least one Full
                    // adjacency, originate the Network-LSA listing
                    // every fully adjacent router (ourselves included)
                    // with the Options OR'd from the fully adjacent
                    // neighbors' Link-LSAs. Anything else flushes the
                    // instance we may still hold (§14.1 MaxAge).
                    if we_are_dr && !established.is_empty() {
                        let mut options = OSPF_V3_OPTIONS_DEFAULT;
                        for rid in &established {
                            let Some(h) = iface.heard.get(rid) else {
                                continue;
                            };
                            if let Some(llsa) = router.ospf_area_lsa(
                                area,
                                LS_TYPE_LINK,
                                h.interface_id,
                                *rid,
                            ) {
                                if let Some(body) = V3LinkLsaBody::decode(&llsa.body) {
                                    options |= body.options;
                                }
                            }
                        }
                        let mut attached = vec![self.router_id.as_u32()];
                        attached.extend_from_slice(&established);
                        match originate_v3_network_lsa(
                            self.router_id.as_u32(),
                            iface.interface_id,
                            options,
                            &attached,
                            iface.net_lsa_seq,
                        ) {
                            Some(lsa) => {
                                iface.net_lsa_seq = Some(lsa.header.ls_sequence_number);
                                iface.net_lsa_active = true;
                                lsas.push(lsa);
                            }
                            None => eprintln!(
                                "daemon: ospf3 network-LSA sequence space exhausted on {}",
                                iface.name
                            ),
                        }
                    } else if iface.net_lsa_active {
                        // A former DR flushes the Network-LSA it
                        // originated (§14.1 MaxAge reflood, the v2
                        // daemon pattern).
                        if let Some(seq) = iface.net_lsa_seq {
                            if let Some(mut lsa) = originate_v3_network_lsa(
                                self.router_id.as_u32(),
                                iface.interface_id,
                                OSPF_V3_OPTIONS_DEFAULT,
                                &[self.router_id.as_u32()],
                                Some(seq),
                            ) {
                                lsa.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
                                lsa.finalize();
                                lsas.push(lsa);
                            }
                        }
                        iface.net_lsa_active = false;
                        iface.net_lsa_seq = None;
                    }
                }
            }
        }
        // RFC 5340 §4.8: a router is V6-capable; E reflects the area's
        // external capability (regular areas only in slice 1 — the
        // finalizer rejects stub/NSSA v3 areas via the v2 policy path).
        let bits = ROUTER_BIT_E | ROUTER_BIT_V6;
        let seq = self.router_lsa_seq.get(&area).copied().or_else(|| {
            router
                .ospf_area_lsa(area, LS_TYPE_ROUTER, 0, self.router_id.as_u32())
                .map(|l| l.header.ls_sequence_number)
        });
        match originate_v3_router_lsa(
            self.router_id.as_u32(),
            bits,
            OSPF_V3_OPTIONS_DEFAULT,
            &links,
            seq,
        ) {
            Some(lsa) => {
                self.router_lsa_seq
                    .insert(area, lsa.header.ls_sequence_number);
                // One Intra-Area-Prefix-LSA attaching every global
                // prefix to our Router-LSA (§4.4.3.5; skip when the
                // interfaces carry no global addresses). Interfaces
                // reported as transit links are skipped: their
                // prefixes ride the DR's network-referenced
                // Intra-Area-Prefix-LSA instead (§4.4.3.5 — "prefixes
                // that will be included in the intra-area-prefix-LSA
                // for the link are skipped").
                let mut prefixes: Vec<V3Prefix> = Vec::new();
                for iface in &self.interfaces {
                    if iface.area != area || transit_reported.contains_key(&iface.interface_id) {
                        continue;
                    }
                    for (addr, len) in &iface.prefixes {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&addr.octets());
                        prefixes.push(V3Prefix {
                            prefix_len: *len,
                            options: 0,
                            metric: 0,
                            addr: octets,
                        });
                    }
                }
                if !prefixes.is_empty() {
                    let iap_key = (area, 1u32);
                    let iap_seq = self.iap_lsa_seq.get(&iap_key).copied();
                    if let Some(iap) = originate_v3_intra_area_prefix_lsa(
                        self.router_id.as_u32(),
                        1,
                        LS_TYPE_ROUTER,
                        0,
                        self.router_id.as_u32(),
                        prefixes,
                        iap_seq,
                    ) {
                        self.iap_lsa_seq
                            .insert(iap_key, iap.header.ls_sequence_number);
                        lsas.push(iap);
                    }
                }
                lsas.push(lsa);
            }
            None => {
                eprintln!(
                    "daemon: ospf3 router-LSA sequence space exhausted for area {}",
                    area_label(area)
                );
                return;
            }
        }
        // §4.4.3.5, the DR half: on every broadcast segment where this
        // router is the DR, originate the network-referenced
        // Intra-Area-Prefix-LSA carrying the segment's prefixes — the
        // union of the Link-LSA prefixes of every fully adjacent
        // neighbor (ourselves included), NU/LA-marked prefixes and
        // link-locals excluded, duplicates merged with their options
        // OR'd together. A former DR flushes its instance.
        for iface in &mut self.interfaces {
            if iface.area != area || iface.network_type != OspfNetworkType::Broadcast {
                continue;
            }
            let we_are_dr = iface.if_state == IfState::Dr && iface.dr == self.router_id.as_u32();
            let has_full = self.neighbors.iter().any(|((n_area, _), n)| {
                *n_area == area && n.ifindex == iface.interface_id && n.established
            });
            if we_are_dr && has_full {
                // Dedup keyed (prefix length, address) → OR'd options
                // (§4.4.3.5). BTreeMap keeps the wire order stable.
                let mut merged: BTreeMap<(u8, [u8; 16]), u8> = BTreeMap::new();
                let mut collect = |prefixes: &[V3Prefix]| {
                    for p in prefixes {
                        // §A.4.1: NU- and LA-marked prefixes are not
                        // copied; link-locals are never advertised.
                        if p.options & (PREFIX_OPT_NU | PREFIX_OPT_LA) != 0 {
                            continue;
                        }
                        if p.addr[0] == 0xfe && (p.addr[1] & 0xc0) == 0x80 {
                            continue;
                        }
                        merged
                            .entry((p.prefix_len, p.addr))
                            .and_modify(|o| *o |= p.options)
                            .or_insert(p.options);
                    }
                };
                let mut own: Vec<V3Prefix> = Vec::new();
                for (addr, len) in &iface.prefixes {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&addr.octets());
                    own.push(V3Prefix {
                        prefix_len: *len,
                        options: 0,
                        metric: 0,
                        addr: octets,
                    });
                }
                collect(&own);
                for ((n_area, rid), n) in self.neighbors.iter() {
                    if *n_area != area || n.ifindex != iface.interface_id || !n.established {
                        continue;
                    }
                    let Some(h) = iface.heard.get(rid) else {
                        continue;
                    };
                    if let Some(llsa) =
                        router.ospf_area_lsa(area, LS_TYPE_LINK, h.interface_id, *rid)
                    {
                        if let Some(body) = V3LinkLsaBody::decode(&llsa.body) {
                            collect(&body.prefixes);
                        }
                    }
                }
                let prefixes: Vec<V3Prefix> = merged
                    .into_iter()
                    .map(|((prefix_len, addr), options)| V3Prefix {
                        prefix_len,
                        options,
                        metric: 0,
                        addr,
                    })
                    .collect();
                // Network-referenced IAPs use a distinct Link State ID
                // space from the router-referenced one (§4.4.3.5: "a
                // router may originate several Intra-Area-Prefix-LSAs
                // per area, disambiguated by the Link State ID"). The
                // ifindex with a marker bit keeps per-segment instances
                // apart from the router-referenced LS ID 1.
                let iap_key = (area, iface.interface_id | 1 << 31);
                let iap_seq = self.iap_lsa_seq.get(&iap_key).copied();
                if let Some(iap) = originate_v3_intra_area_prefix_lsa(
                    self.router_id.as_u32(),
                    iap_key.1,
                    LS_TYPE_NETWORK,
                    iface.interface_id,
                    self.router_id.as_u32(),
                    prefixes,
                    iap_seq,
                ) {
                    self.iap_lsa_seq
                        .insert(iap_key, iap.header.ls_sequence_number);
                    iface.net_iap_seq = Some(iap.header.ls_sequence_number);
                    iface.net_iap_active = true;
                    lsas.push(iap);
                }
            } else if iface.net_iap_active {
                // No longer the DR (or no Full adjacency left): flush
                // the network-referenced IAP — the new DR advertises
                // the segment's prefixes (§4.4.3.5).
                if let Some(seq) = iface.net_iap_seq {
                    if let Some(mut lsa) = originate_v3_intra_area_prefix_lsa(
                        self.router_id.as_u32(),
                        iface.interface_id | 1 << 31,
                        LS_TYPE_NETWORK,
                        iface.interface_id,
                        self.router_id.as_u32(),
                        Vec::new(),
                        Some(seq),
                    ) {
                        lsa.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
                        lsa.finalize();
                        lsas.push(lsa);
                    }
                }
                iface.net_iap_active = false;
                iface.net_iap_seq = None;
            }
        }
        self.last_orig_ms.insert(area, now_ms);
        // RFC 9513 slice 3: the SRv6 Router Information LSA (§2-§4,
        // instance ID 0) and the Locator LSA (§7, all locators, Link
        // State ID 1) ride the same LSU as the topology LSAs, so a
        // locator change refreshes through the normal re-origination
        // and §14.1 cadences.
        if let Some(s) = &self.srv6 {
            let ri_seq = self.ri_lsa_seq.get(&area).copied();
            match originate_v3_srv6_ri_lsa(
                self.router_id.as_u32(),
                s.capabilities,
                &s.algorithms,
                &s.msds,
                ri_seq,
            ) {
                Some(ri) => {
                    self.ri_lsa_seq.insert(area, ri.header.ls_sequence_number);
                    lsas.push(ri);
                }
                None => eprintln!(
                    "daemon: ospf3 SRv6 RI-LSA sequence space exhausted for area {}",
                    area_label(area)
                ),
            }
            let loc_seq = self.srv6_lsa_seq.get(&area).copied();
            match originate_v3_srv6_locator_lsa(self.router_id.as_u32(), 1, &s.locators, loc_seq) {
                Some(loc_lsa) => {
                    self.srv6_lsa_seq
                        .insert(area, loc_lsa.header.ls_sequence_number);
                    lsas.push(loc_lsa);
                }
                None => eprintln!(
                    "daemon: ospf3 SRv6 Locator-LSA sequence space exhausted for area {}",
                    area_label(area)
                ),
            }
        }
        let Some(&anchor) = self.anchors.get(&area) else {
            return;
        };
        let packet = lr_ospf::packet::OspfPacket {
            header: lr_ospf::packet::OspfHeader {
                version: lr_ospf::packet::OspfVersion::V3 as u8,
                kind: OspfPacketType::LinkStateUpdate as u8,
                length: 0,
                router_id: self.router_id.as_u32(),
                area_id: area,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::LsUpdate(lr_ospf::packet::LsUpdateBody {
                lsa_count: lsas.len() as u32,
                lsas,
            }),
        };
        match OspfCodec::v3().encode_vec(&packet) {
            Ok(bytes) => {
                if let Err(e) = router.feed_input(anchor, &bytes) {
                    eprintln!("daemon: ospf3 self-origination feed: {e}");
                }
            }
            Err(e) => eprintln!("daemon: ospf3 self-origination encode: {e}"),
        }
    }
}

/// The multicast destination every v3 packet uses (slice 1 floods and
/// Hellos are multicast-only): ff02::5, AllSPFRouters.
use lr_osroute::ospf_transport::ALL_SPF_ROUTERS_V6 as MULTICAST_ALL_SPF;

/// The cached `LR_OSPF_DEBUG` gate for the wire trace.
fn ospf_debug_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("LR_OSPF_DEBUG").is_some())
}

/// Decode a received OSPFv3 Hello body (§A.3.2). Returns `None` for
/// short, non-v3 or non-Hello packets.
fn parse_hello_body_v3(bytes: &[u8]) -> Option<HelloBody> {
    match OspfCodec::v3().decode_slice(bytes).ok()?? {
        lr_ospf::packet::OspfPacket {
            body: OspfBody::Hello(body),
            ..
        } => Some(body),
        _ => None,
    }
}

/// Parse the fixed 16-byte v3 header for demux: (router-id, area, length).
fn demux_header(bytes: &[u8]) -> Option<(u32, u32, u16)> {
    if bytes.len() < lr_ospf::packet::OspfHeader::LEN_V3 {
        return None;
    }
    if bytes[0] != 3 {
        return None; // only v3 on the v6 transport
    }
    let len = u16::from_be_bytes([bytes[2], bytes[3]]);
    if bytes.len() < usize::from(len) {
        return None;
    }
    Some((
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        len,
    ))
}

fn fmt_rid(rid: u32) -> String {
    RouterId::from_u32(rid).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_config::{DaemonConfig, OspfSrv6LocatorSpec};

    fn locator_spec(prefix: &str) -> OspfSrv6LocatorSpec {
        OspfSrv6LocatorSpec {
            prefix: Some(prefix.to_string()),
            ..Default::default()
        }
    }

    fn v6_octets(text: &str) -> [u8; 16] {
        match text.parse::<IpAddr>().expect("valid v6") {
            IpAddr::V6(o) => o,
            _ => panic!("not v6"),
        }
    }

    #[test]
    fn srv6_off_without_locators() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        cfg.ospf_srv6_receive = true;
        // Reception alone does not turn origination on: the daemon
        // carries SRv6 state only when locators are configured.
        assert!(Srv6Origination::maybe_from_config(&cfg).is_none());
        cfg.ospf_srv6_locators = vec![locator_spec("2001:db8:a:1::/48")];
        assert!(Srv6Origination::maybe_from_config(&cfg).is_some());
    }

    #[test]
    fn srv6_origination_defaults() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        cfg.ospf_srv6_locators = vec![locator_spec("2001:db8:a:1::/48")];
        let s = Srv6Origination::from_config(&cfg);
        // No O-flag by default; algorithm 0 derived from the locator.
        assert_eq!(s.capabilities, 0);
        assert_eq!(s.algorithms, vec![0]);
        assert!(s.msds.is_empty());
        assert_eq!(s.locators.len(), 1);
        let loc = &s.locators[0];
        assert_eq!(loc.route_type, locator_route_type::INTRA_AREA);
        assert_eq!(loc.algorithm, 0);
        assert_eq!(loc.locator_len, 48);
        assert_eq!(loc.options, 0);
        assert_eq!(loc.metric, 0);
        assert_eq!(loc.prefix, v6_octets("2001:db8:a:1::"));
        // The End SID defaults to the locator prefix, behavior End,
        // no SID Structure sub-TLV.
        assert_eq!(loc.end_sids.len(), 1);
        let sid = &loc.end_sids[0];
        assert_eq!(sid.behavior, 1);
        assert_eq!(sid.sid, v6_octets("2001:db8:a:1::"));
        assert!(sid.structure.is_none());
        // The encoded TLV round-trips through the slice-2 decoder.
        let mut wire = Vec::new();
        loc.encode(&mut wire);
        let (decoded, _) = Srv6LocatorTlv::decode(&wire, 0).expect("decodable");
        assert_eq!(&decoded, loc);
    }

    #[test]
    fn srv6_origination_full_attributes() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        cfg.ospf_srv6_o_flag = true;
        cfg.ospf_srv6_max_sl = Some(8);
        cfg.ospf_srv6_max_end_d = Some(6);
        cfg.ospf_srv6_locators = vec![
            OspfSrv6LocatorSpec {
                prefix: Some("2001:db8:a:1::/64".to_string()),
                algorithm: Some(128), // flexible-algorithm space
                metric: Some(30),
                anycast: Some(true),
                sid: Some("2001:db8:a:1:f00d::".to_string()),
                behavior: Some(1),
                block_len: Some(32),
                node_len: Some(16),
                function_len: Some(16),
                argument_len: Some(0),
            },
            locator_spec("2001:db8:a:2::/64"),
        ];
        let s = Srv6Origination::from_config(&cfg);
        assert_eq!(s.capabilities, SRV6_CAP_O_FLAG);
        // Distinct algorithms, ascending (BTreeSet order).
        assert_eq!(s.algorithms, vec![0, 128]);
        // MSD pairs in the 41/42/44/45 wire order, only the configured ones.
        assert_eq!(
            s.msds,
            vec![(msd_type::SRH_MAX_SL, 8), (msd_type::SRH_MAX_END_D, 6)]
        );
        assert_eq!(s.locators.len(), 2);
        let first = &s.locators[0];
        assert_eq!(first.options, PREFIX_OPT_AC);
        assert_eq!(first.metric, 30);
        assert_eq!(first.end_sids[0].sid, v6_octets("2001:db8:a:1:f00d::"));
        assert_eq!(
            first.end_sids[0].structure,
            Some(Srv6SidStructure {
                lb_len: 32,
                ln_len: 16,
                func_len: 16,
                arg_len: 0,
            })
        );
        // The full TLV round-trips through the slice-2 decoder.
        let mut wire = Vec::new();
        first.encode(&mut wire);
        let (decoded, _) = Srv6LocatorTlv::decode(&wire, 0).expect("decodable");
        assert_eq!(&decoded, first);
    }
}
