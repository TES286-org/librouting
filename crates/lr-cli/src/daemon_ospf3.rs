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
//! - **Self-origination** — a Router-LSA per area (one p2p link per
//!   Full adjacency), a Link-LSA per interface (the RFC 5340 §4.4.3.4
//!   MUST, carrying the link-local address and the interface's global
//!   prefixes), and one Intra-Area-Prefix-LSA per area attaching the
//!   global prefixes to the Router-LSA (§4.4.3.5).
//! - **Checksum egress** — every packet's IPv6 upper-layer checksum is
//!   finalized with the pseudo-header (source link-local, destination
//!   ff02::5) right before the sendto (RFC 5340 §A.3.1); receive-side
//!   verification is skipped like FRR's ospf6d.
//! - **Next-hop bookkeeping for the kernel** — the link-local →
//!   interface mapping learned from Hello sources feeds
//!   [`crate::v6_nexthop_oifs`], so the kernel mirror can attach the
//!   RTA_OIF a link-local gateway needs.
//!
//! Scope of slice 1 (see docs/STATUS.md): point-to-point segments only
//! (broadcast/DR election, inter-area summaries and AS externals are
//! later slices), no graceful restart, no SR — the config finalizer
//! rejects those combinations outright.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lr_core::addr::{IpAddr, RouterId};
use lr_ospf::codec::OspfCodec;
use lr_ospf::lsa::v3::{
    originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_router_lsa, V3Prefix,
    LINK_TYPE_POINTTOPOINT, LS_TYPE_ROUTER, ROUTER_BIT_E, ROUTER_BIT_V6,
};
use lr_ospf::origination::finalize_v3_packet;
use lr_ospf::packet::{HelloBody, OspfBody, OspfPacketType, OSPF_V3_OPTIONS_DEFAULT};
use lr_osroute::ospf_transport::{interface_v6_addrs, OspfV6Transport};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

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
}

/// One neighbor heard on an interface. The v3-specific datum is the
/// neighbor's Interface ID on the shared link, from its Hello's
/// Interface ID field — the Neighbor Interface ID of our p2p link
/// description (§A.4.3) and the key to its Link-LSA.
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
    /// Link-LSA, (area, ls_id) → Intra-Area-Prefix-LSA.
    router_lsa_seq: BTreeMap<u32, u32>,
    link_lsa_seq: BTreeMap<(u32, u32), u32>,
    iap_lsa_seq: BTreeMap<(u32, u32), u32>,
    /// Last self-origination per area (ms) — the §14.1 refresh cadence.
    last_orig_ms: BTreeMap<u32, u64>,
    router_id: RouterId,
    /// Snapshot for the runtime API `status` command.
    status: Arc<Mutex<Vec<String>>>,
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
                     link-local {}, {} global prefix(es), cost {}, hello {}s dead {}s",
                    iface.name,
                    area_label(iface.area),
                    iface.interface_id,
                    iface.link_local,
                    iface.prefixes.len(),
                    iface.cost,
                    iface.hello_interval,
                    iface.dead_interval,
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
        last_orig_ms: BTreeMap::new(),
        router_id: rid,
        status: Arc::new(Mutex::new(Vec::new())),
    };
    // ---- Router: one anchor session per area (v3). ----
    let iface_mtu = daemon.interfaces.first().map(|i| i.mtu).unwrap_or(1500);
    {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.lock().unwrap();
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
    // Slice 1 is p2p-only; the finalizer already rejects "broadcast".
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
    })
}

impl Ospf3Interface {
    /// §10.5: fold one received Hello into the interface's neighbor
    /// table. The v3 identity inputs are the neighbor's Interface ID
    /// (Hello Interface ID field) and its link-local source address.
    fn track_hello(
        &mut self,
        rid: u32,
        link_local: Ipv6Addr,
        body: &HelloBody,
        our_rid: u32,
        now_ms: u64,
    ) {
        let bidirectional = body.neighbors.contains(&our_rid);
        let entry = self.heard.entry(rid).or_insert(HeardNeighbor {
            interface_id: body.network_mask, // v3: Interface ID slot
            priority: body.priority,
            link_local,
            last_ms: now_ms,
            bidirectional,
        });
        entry.interface_id = body.network_mask;
        entry.priority = body.priority;
        entry.link_local = link_local;
        entry.last_ms = now_ms;
        entry.bidirectional = bidirectional;
        let _ = bidirectional; // p2p segments have no election to dirty
    }
}

impl Ospf3Daemon {
    fn pump(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        self.pump_inbound(recv_buf, now_ms);
        self.pump_adjacency(now_ms);
        self.pump_dead_timer(now_ms);
        self.pump_reoriginate(now_ms);
        self.pump_hellos(now_ms);
        self.pump_outbound();
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
                let cfg = SessionConfig::ospfv3(self.router_id, area).with_ospf_mtu(mtu);
                match router.add_session(cfg) {
                    Ok(h) => {
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
                priority: 1,
                dead_interval: iface.dead_interval.min(u32::from(u16::MAX)),
                // p2p segments elect no DR (§9.4 does not apply).
                dr: 0,
                bdr: 0,
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
        // Router-LSA: one p2p link per Full adjacency.
        let mut links: Vec<lr_ospf::lsa::v3::V3RouterLink> = Vec::new();
        for iface in &self.interfaces {
            if iface.area != area {
                continue;
            }
            for ((n_area, rid), n) in self.neighbors.iter() {
                if *n_area != area || n.ifindex != iface.interface_id || !n.established {
                    continue;
                }
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
                // interfaces carry no global addresses).
                let mut prefixes: Vec<V3Prefix> = Vec::new();
                for iface in &self.interfaces {
                    if iface.area != area {
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
        self.last_orig_ms.insert(area, now_ms);
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
