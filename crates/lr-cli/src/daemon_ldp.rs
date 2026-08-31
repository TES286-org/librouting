//! `lr-daemon --protocol ldp` — LDP daemon mode (RFC 5036).
//!
//! The LDP counterpart of the BGP/Babel/OSPF daemon modes: the
//! [`LdpEngine`] owns the protocol logic (§3.5.2 discovery, §2.5.4
//! session FSM, label bookkeeping), and this module owns everything the
//! engine leaves to the embedder:
//!
//! - **UDP discovery transport** — one socket per address family on
//!   the LDP port (§3.10.1: 646), joined to the all-routers multicast
//!   group of that family (224.0.0.2 / ff02::2) on every configured
//!   interface. Link Hellos are originated per interface every
//!   hold-time third (§3.5.2.1) with multicast TTL/hop-limit 1 and the
//!   interface's primary address as the source; targeted Hellos ride
//!   the same socket as ordinary unicast. RFC 7552 §5.1 applies to the
//!   IPv6 side: link Hellos go to ff02::2 from a link-local source with
//!   hop limit 255, and received ones are checked for it (GTSM).
//! - **TCP session transport** — a listener on the LDP port (passive
//!   role) plus active connections driven by the engine's
//!   `EstablishTransport` events (§2.5.2 transport-address comparison
//!   within the RFC 7552 §6.1.1 chosen family). The listener is a
//!   dual-stack IPv6 socket (IPV6_V6ONLY = 0) when the speaker has an
//!   IPv6 transport address, so one socket serves both families.
//! - **Local bindings** — the configured `[[ldp.bind]]` FEC-label
//!   pairs are advertised downstream-unsolicited to every peer that
//!   becomes operational (and re-advertised on each new session, since
//!   the engine sends mappings only to peers that were operational at
//!   advertise time).
//!
//! ```text
//!   ┌─────────────────────────────────────────────────────┐
//!   │ lr-daemon --protocol ldp                             │
//!   │                                                      │
//!   │  UDP :646                        TCP :646            │
//!   │ ┌───────────────────────┐   ┌────────────────────┐  │
//!   │ │ link Hellos 224.0.0.2 │   │ listener (passive) │  │
//!   │ │ TTL 1, per interface  │   │ + active connects  │  │
//!   │ │ targeted Hellos       │   │ (EstablishTransport)│ │
//!   │ └──────────┬────────────┘   └─────────┬──────────┘  │
//!   │            │ feed_udp                 │ feed_tcp    │
//!   │        ┌───┴──────────────────────────┴───┐         │
//!   │        │            LdpEngine             │         │
//!   │        │  discovery + sessions + LIB      │         │
//!   │        └──────────────────────────────────┘         │
//!   │   events → log (+ API status counters)              │
//!   └─────────────────────────────────────────────────────┘
//! ```
//!
//! Kernel MPLS installation of learned bindings is future work (the
//! BGP-LU dataplane mirror covers that role today).

use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use lr_core::addr::{IpAddr, Prefix, RouterId};
use lr_core::time::Instant;
use lr_ldp::engine::{EngineEvent, LdpEngine, LdpEngineConfig};
use lr_ldp::session::SessionDownReason;
use lr_ldp::{GenericLabel, LdpId};
use lr_osroute::bfd_transport::{arm_ttl_rx, recv_from_with_ttl, BfdTransportError};
use lr_osroute::ospf_transport::{
    ifindex_of, interface_v4_addrs, interface_v6_addrs, InterfaceV6Addr,
};
use lr_router::DefaultRouter;

use crate::daemon_config::DaemonConfig;

/// Loop cadence: also the hello/keepalive timer granularity. LDP timers
/// are seconds-scale, so 100 ms keeps the loop cheap while staying
/// precise against 2 s test keepalives.
const LOOP_INTERVAL_MS: u64 = 100;

/// IPv4 all-routers multicast group — the link Hello destination
/// (RFC 5036 §3.5.2).
const ALL_ROUTERS_V4: [u8; 4] = [224, 0, 0, 2];

/// IPv6 link-local all-routers multicast group — the IPv6 link Hello
/// destination (RFC 7552 §5.1: ff02::2, hop limit 255, link-local
/// source).
const ALL_ROUTERS_V6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

/// Parse an address literal (`A.B.C.D`, `2001:db8::1`, `[::1]`).
fn parse_addr(s: &str) -> Option<IpAddr> {
    use std::str::FromStr;
    let trimmed = s.trim_start_matches('[').trim_end_matches(']');
    IpAddr::from_str(trimmed).ok()
}

/// Map a v4-mapped IPv6 address (`::ffff:a.b.c.d` — what a dual-stack
/// socket reports for IPv4 endpoints) back to plain IPv4.
fn normalize_v6(v6: std::net::Ipv6Addr) -> IpAddr {
    match v6.octets() {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => IpAddr::V4([a, b, c, d]),
        octets => IpAddr::V6(octets),
    }
}

/// One discovery interface, resolved against the running kernel.
struct LdpInterface {
    name: String,
    /// Addresses (primary first) used as the multicast membership and
    /// per-interface Hello source.
    addrs: Vec<std::net::Ipv4Addr>,
    /// Last IPv4 link Hello on this interface (ms since daemon start).
    last_hello_ms: u64,
    /// Kernel interface index (IPV6_MULTICAST_IF scoping).
    ifindex: u32,
    /// IPv6 addresses (RFC 7552 §6.1 rule 5: global unicast first).
    v6_addrs: Vec<InterfaceV6Addr>,
    /// Last IPv6 link Hello on this interface (ms since daemon start).
    last_v6_hello_ms: u64,
}

/// Counters shared with the runtime API `status` view.
struct LdpCounters {
    adjacencies: AtomicUsize,
    sessions: AtomicUsize,
    mappings_learned: AtomicUsize,
    mappings_withdrawn: AtomicUsize,
}

impl LdpCounters {
    fn new() -> Self {
        Self {
            adjacencies: AtomicUsize::new(0),
            sessions: AtomicUsize::new(0),
            mappings_learned: AtomicUsize::new(0),
            mappings_withdrawn: AtomicUsize::new(0),
        }
    }
}

/// Daemon-wide transport state (the engine drives everything else).
struct LdpDaemon {
    engine: LdpEngine,
    /// Sending endpoint (socket2: per-send IP_MULTICAST_IF / TTL).
    udp_tx: Socket,
    /// Receiving endpoint (same UDP socket, duplicated fd).
    udp_rx: UdpSocket,
    /// IPv6 discovery endpoints (RFC 7552); `None` on a v4-only
    /// speaker or when the kernel lacks IPv6.
    udp_tx_v6: Option<Socket>,
    udp_rx_v6: Option<UdpSocket>,
    listener: TcpListener,
    interfaces: Vec<LdpInterface>,
    conns: HashMap<u64, TcpStream>,
    next_conn: u64,
    /// The configured local bindings, re-advertised on every new
    /// session (the engine only sends mappings to peers that were
    /// operational when advertise_mapping ran).
    binds: Vec<(Prefix, GenericLabel)>,
    /// Peers that reached Operational — iterated on graceful shutdown.
    peers_up: BTreeSet<LdpId>,
    /// Per-targeted-peer UDP/TCP port overrides (`ADDR:PORT` form);
    /// destinations absent from the map use the local LDP port.
    peer_ports: HashMap<IpAddr, u16>,
    counters: Arc<LdpCounters>,
    port: u16,
}

/// Entry point from `daemon.rs`.
pub(super) fn run_ldp_daemon(cfg: &DaemonConfig, rid: RouterId) -> ExitCode {
    let port = cfg.ldp_port;
    let local_id = LdpId::new(rid.to_v4_bytes(), 0);

    // ---- Resolve discovery interfaces against the kernel. ----
    let mut interfaces: Vec<LdpInterface> = Vec::new();
    for spec in &cfg.ldp_interfaces {
        let name = spec.label().to_string();
        let addrs = match interface_v4_addrs(&name) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("daemon: ldp interface {}: {}", name, e);
                return ExitCode::from(1);
            }
        };
        if addrs.is_empty() {
            eprintln!("daemon: ldp interface {}: no IPv4 address", name);
            return ExitCode::from(1);
        }
        let ifindex = ifindex_of(&name).unwrap_or_default();
        let v6_addrs = interface_v6_addrs(&name).unwrap_or_default();
        let v6_globals = v6_addrs.iter().filter(|a| a.is_global_unicast()).count();
        println!(
            "daemon: ldp interface {} — discovery on {} ({} address(es), IPv6: {} global, {} link-local)",
            name,
            std::net::Ipv4Addr::from(ALL_ROUTERS_V4),
            addrs.len(),
            v6_globals,
            v6_addrs.iter().filter(|a| a.is_link_local()).count()
        );
        interfaces.push(LdpInterface {
            name,
            addrs: addrs.into_iter().map(|a| a.addr).collect(),
            last_hello_ms: 0,
            ifindex,
            v6_addrs,
            last_v6_hello_ms: 0,
        });
    }

    // ---- Transport address: explicit, else the first interface's
    // primary address (the TCP endpoint peers connect back to). ----
    let transport: IpAddr = match cfg.ldp_transport.as_deref() {
        Some(t) => match IpAddr::from_str(t) {
            Ok(a) => a,
            Err(_) => {
                eprintln!("daemon: invalid ldp transport address: {}", t);
                return ExitCode::from(2);
            }
        },
        None => {
            match interfaces.first().and_then(|i| i.addrs.first()) {
                Some(a) => IpAddr::V4(a.octets()),
                None => {
                    // Targeted-only deployments must name the transport
                    // address explicitly.
                    eprintln!("daemon: --protocol ldp without interfaces needs --ldp-transport");
                    return ExitCode::from(2);
                }
            }
        }
    };

    // ---- UDP discovery sockets (one per address family). ----
    let (udp_tx, udp_rx) = match bind_ldp_udp(port, &interfaces) {
        Ok(u) => u,
        Err(e) => {
            eprintln!(
                "daemon: ldp UDP bind :{} failed: {} (port < 1024 needs root \
                 or a user/network namespace; use --ldp-port to override)",
                port, e
            );
            return ExitCode::from(1);
        }
    };
    let (udp_tx_v6, udp_rx_v6) = match bind_ldp_udp_v6(port, &interfaces) {
        Ok(u) => u,
        Err(e) => {
            eprintln!(
                "daemon: ldp IPv6 UDP bind :{} failed: {} (continuing IPv4-only)",
                port, e
            );
            (None, None)
        }
    };

    // ---- TCP session listener: dual-stack (IPV6_V6ONLY=0) when the
    // speaker has an IPv6 transport address, so one socket serves
    // both families; otherwise plain IPv4. ----
    let dual_stack = udp_tx_v6.is_some();
    let listener = if dual_stack {
        match TcpListener::bind(("::", port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("daemon: ldp TCP bind [::]:{} failed: {}", port, e);
                return ExitCode::from(1);
            }
        }
    } else {
        match TcpListener::bind(("0.0.0.0", port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("daemon: ldp TCP bind :{} failed: {}", port, e);
                return ExitCode::from(1);
            }
        }
    };
    if let Err(e) = listener.set_nonblocking(true) {
        eprintln!("daemon: ldp listener nonblocking: {}", e);
        return ExitCode::from(1);
    }

    // ---- Engine. ----
    let mut engine_cfg = LdpEngineConfig::new(local_id, transport);
    engine_cfg.keepalive_time = cfg.ldp_keepalive_time;
    engine_cfg.link_hello_hold = cfg.ldp_link_hold;
    engine_cfg.targeted_hello_hold = cfg.ldp_targeted_hold;
    // Targeted peers: `ADDR`, `ADDR:PORT` or `[V6]:PORT`. The engine
    // deals in addresses; a port override means that peer runs its LDP
    // transport on a different port (asymmetric deployments on shared
    // hosts) — Hellos and the TCP connect go there instead of the
    // local port.
    let mut targeted_addrs: Vec<IpAddr> = Vec::new();
    let mut peer_ports: HashMap<IpAddr, u16> = HashMap::new();
    for peer in &cfg.ldp_targeted {
        let Some(spec) = peer.address.as_deref() else {
            continue; // finalize() already rejected this
        };
        let bad = || format!("daemon: invalid ldp targeted peer '{spec}'");
        let Some((addr_part, port_part)) = crate::daemon_config::parse_targeted_spec(spec) else {
            eprintln!("{}", bad());
            return ExitCode::from(2);
        };
        targeted_addrs.push(addr_part);
        if let Some(port) = port_part {
            peer_ports.insert(addr_part, port);
        }
        println!("daemon: ldp targeted peer {}", peer.label());
    }
    engine_cfg.targeted_peers = targeted_addrs;

    // RFC 7552 §6.1 rule 5: the IPv6 transport address is a global
    // unicast address — explicit, else the first interface GUA.
    let v6_transport: Option<IpAddr> = match cfg.ldp_transport_v6.as_deref() {
        Some(t) => match parse_addr(t) {
            Some(a) => Some(a),
            None => {
                eprintln!("daemon: invalid ldp transport-v6 address: {}", t);
                return ExitCode::from(2);
            }
        },
        None => interfaces
            .iter()
            .flat_map(|i| i.v6_addrs.iter())
            .find(|a| a.is_global_unicast())
            .map(|a| IpAddr::V6(a.addr.octets())),
    };
    if let Some(v6) = v6_transport {
        println!("daemon: ldp IPv6 transport {}", v6);
    }
    engine_cfg.transport_addr_v6 = v6_transport;
    engine_cfg.prefer_ipv6 = cfg.ldp_prefer_ipv6;

    // Address-message contents (§3.5.5.1 + RFC 7552 §7.1): interface
    // addresses of both families; the engine scopes per peer.
    let mut interface_ips: Vec<IpAddr> = interfaces
        .iter()
        .flat_map(|i| i.addrs.iter())
        .map(|a| IpAddr::V4(a.octets()))
        .collect();
    interface_ips.extend(
        interfaces
            .iter()
            .flat_map(|i| i.v6_addrs.iter())
            .filter(|a| a.is_global_unicast())
            .map(|a| IpAddr::V6(a.addr.octets())),
    );
    interface_ips.sort();
    interface_ips.dedup();
    interface_ips.push(transport);
    engine_cfg.interface_addresses = interface_ips;
    let engine = LdpEngine::new(engine_cfg);

    // ---- Local bindings. ----
    let mut binds: Vec<(Prefix, GenericLabel)> = Vec::new();
    for bind in &cfg.ldp_binds {
        let Some(p) = bind.prefix.as_deref() else {
            continue; // finalize() already rejected this
        };
        match Prefix::from_str(p) {
            Ok(prefix) => binds.push((prefix, GenericLabel(bind.label))),
            Err(e) => {
                eprintln!("daemon: ldp bind {}: {}", p, e);
                return ExitCode::from(1);
            }
        }
    }
    for (prefix, label) in &binds {
        println!("daemon: ldp binding {} label {}", prefix, label.0);
    }

    // Privileged work is done (both sockets bound): honor the privilege
    // drop before the loop touches any network input.
    if let Err(e) = crate::do_privdrop(cfg) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }

    // ---- Runtime API + signals. ----
    let router = Arc::new(Mutex::new(DefaultRouter::new()));
    let counters = Arc::new(LdpCounters::new());
    let running = Arc::new(AtomicBool::new(true));
    let runtime = Arc::new(crate::Runtime {
        reload: Arc::new(|| {
            vec!["ldp: configuration reload is not supported yet; shutdown still works".to_string()]
        }),
        router: Arc::clone(&router),
        running: Arc::clone(&running),
        status_lines: Arc::new({
            let counters = Arc::clone(&counters);
            move || {
                vec![
                    format!(
                        "ldp-adjacencies {}",
                        counters.adjacencies.load(Ordering::Relaxed)
                    ),
                    format!("ldp-sessions {}", counters.sessions.load(Ordering::Relaxed)),
                    format!(
                        "ldp-mappings-learned {}",
                        counters.mappings_learned.load(Ordering::Relaxed)
                    ),
                    format!(
                        "ldp-mappings-withdrawn {}",
                        counters.mappings_withdrawn.load(Ordering::Relaxed)
                    ),
                ]
            }
        }),
    });
    if let Err(sig) = crate::signal::init() {
        eprintln!("daemon: cannot install signal handlers (signal {})", sig);
        return ExitCode::from(1);
    }
    if let Err(e) = crate::spawn_api(cfg, &runtime) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }

    let mut daemon = LdpDaemon {
        engine,
        udp_tx,
        udp_rx,
        udp_tx_v6,
        udp_rx_v6,
        listener,
        interfaces,
        conns: HashMap::new(),
        next_conn: 1,
        binds,
        peers_up: BTreeSet::new(),
        peer_ports,
        counters,
        port,
    };

    // ---- Main loop. ----
    let start = std::time::Instant::now();
    println!(
        "daemon: ldp main loop started (transport {}, {} interface(s), {} targeted peer(s))",
        transport,
        daemon.interfaces.len(),
        cfg.ldp_targeted.len()
    );
    while running.load(Ordering::Relaxed) {
        crate::dispatch_signals(&runtime);
        if !running.load(Ordering::Relaxed) {
            break;
        }
        let now_ms = start.elapsed().as_millis() as u64;
        let now = Instant::from_millis(now_ms);
        daemon.pump(now_ms, now);
        std::thread::sleep(Duration::from_millis(LOOP_INTERVAL_MS));
    }

    // Graceful shutdown: targeted Shutdown to every live session, then
    // deliver the queued bytes before the sockets go away.
    let now = Instant::from_millis(start.elapsed().as_millis() as u64);
    daemon.shutdown(now);
    println!("daemon: ldp shutdown complete");
    ExitCode::SUCCESS
}

/// Bind the UDP discovery socket: one wildcard socket on the LDP port,
/// joined to the all-routers group on every interface. Multicast loop
/// is disabled so a speaker never feeds its own Hellos back into the
/// engine (the engine keys adjacencies by UDP source address, and a
/// looped-back Hello would masquerade as a foreign peer). Returns the
/// sending endpoint (socket2 — per-send multicast egress selection)
/// and a duplicated receiving endpoint (std I/O surface).
fn bind_ldp_udp(port: u16, interfaces: &[LdpInterface]) -> std::io::Result<(Socket, UdpSocket)> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    let bind_addr = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port));
    sock.bind(&bind_addr.into())?;
    let group = std::net::Ipv4Addr::from(ALL_ROUTERS_V4);
    for iface in interfaces {
        // Join through every address: multi-addressed interfaces then
        // accept link discovery on each subnet.
        for addr in &iface.addrs {
            if let Err(e) = sock.join_multicast_v4(&group, addr) {
                eprintln!(
                    "daemon: ldp multicast join {} on {}: {} (link discovery \
                     may not receive Hellos on this interface)",
                    group, iface.name, e
                );
            }
        }
    }
    sock.set_multicast_loop_v4(false)?;
    let rx: UdpSocket = sock.try_clone()?.into();
    rx.set_nonblocking(true)?;
    Ok((sock, rx))
}

/// Bind the IPv6 UDP discovery socket (RFC 7552 §5.1): one socket on
/// the LDP port, joined to ff02::2 on every interface that has IPv6
/// addresses, multicast loop disabled, and the received hop limit
/// requested as an ancillary message for the §5.1 GTSM-style check.
/// Returns `None`-pair when the system has no IPv6 support.
fn bind_ldp_udp_v6(
    port: u16,
    interfaces: &[LdpInterface],
) -> std::io::Result<(Option<Socket>, Option<UdpSocket>)> {
    if !interfaces.iter().any(|i| !i.v6_addrs.is_empty()) {
        return Ok((None, None));
    }
    let sock = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => return Ok((None, None)),
        Err(e) => return Err(e),
    };
    // Only protocol constants socket2 does not expose:
    const IPPROTO_IPV6: i32 = 41;
    const IPV6_MULTICAST_IF: i32 = 17;
    const IPV6_MULTICAST_LOOP: i32 = 19;
    const IPV6_JOIN_GROUP: i32 = 12;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    let bind_addr = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
    sock.bind(&bind_addr.into())?;
    // The dual-stack TCP listener relies on V6ONLY=0; keep the UDP
    // socket IPv6-only so the v4 socket stays the sole v4 endpoint.
    unsafe {
        setsockopt_int(sock.as_raw_fd(), IPPROTO_IPV6, 26, 0); // IPV6_V6ONLY = 26
    }
    let group = std::net::Ipv6Addr::from(ALL_ROUTERS_V6);
    for iface in interfaces {
        if iface.v6_addrs.is_empty() || iface.ifindex == 0 {
            continue;
        }
        // ipv6_mreq { ipv6mr_multiaddr, ipv6mr_interface }.
        let mreq = Ipv6Mreq {
            multiaddr: group.octets(),
            interface: iface.ifindex,
        };
        let rc = unsafe {
            setsockopt(
                sock.as_raw_fd(),
                IPPROTO_IPV6,
                IPV6_JOIN_GROUP,
                &mreq as *const Ipv6Mreq as *const core::ffi::c_void,
                core::mem::size_of::<Ipv6Mreq>() as u32,
            )
        };
        if rc < 0 {
            eprintln!(
                "daemon: ldp IPv6 multicast join ff02::2 on {}: {} (link discovery \
                 may not receive Hellos on this interface)",
                iface.name,
                std::io::Error::last_os_error()
            );
        }
    }
    unsafe {
        setsockopt_int(sock.as_raw_fd(), IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 0);
        setsockopt_int(sock.as_raw_fd(), IPPROTO_IPV6, IPV6_MULTICAST_IF, 0);
    }
    let rx: UdpSocket = sock.try_clone()?.into();
    rx.set_nonblocking(true)?;
    // §5.1: check the hop limit of received link Hellos — the kernel
    // attaches it as an ancillary message.
    let _ = arm_ttl_rx(&rx, true);
    Ok((Some(sock), Some(rx)))
}

/// Raw `setsockopt` for an integer socket option (the handful of
/// IPV6 options socket2 does not model).
///
/// # Safety
/// `fd` must be a valid socket file descriptor.
unsafe fn setsockopt_int(fd: i32, level: i32, optname: i32, value: i32) {
    let rc = unsafe {
        setsockopt(
            fd,
            level,
            optname,
            &value as *const i32 as *const core::ffi::c_void,
            4,
        )
    };
    let _ = rc;
}

#[repr(C)]
struct Ipv6Mreq {
    multiaddr: [u8; 16],
    interface: u32,
}

extern "C" {
    fn setsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *const core::ffi::c_void,
        optlen: u32,
    ) -> i32;
}

impl LdpDaemon {
    /// One main-loop pass: receive, originate, tick, log, transmit.
    fn pump(&mut self, now_ms: u64, now: Instant) {
        self.pump_udp(now);
        self.pump_tcp(now);
        self.pump_link_hellos(now_ms);
        self.engine.tick(now);
        self.handle_events(now);
        self.flush_tcp();
        self.flush_udp();
    }

    /// Feed every pending UDP datagram into the engine (both address
    /// families). IPv6 datagrams arrive with their hop limit and get
    /// the RFC 7552 §5.1 GTSM check: a link Hello (link-local source —
    /// §5.2 reserves link-local for link discovery) MUST carry hop
    /// limit 255 and is dropped otherwise.
    fn pump_udp(&mut self, now: Instant) {
        let mut buf = [0u8; 65535];
        loop {
            match self.udp_rx.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let from_ip = match from.ip() {
                        std::net::IpAddr::V4(v4) => IpAddr::V4(v4.octets()),
                        std::net::IpAddr::V6(v6) => normalize_v6(v6),
                    };
                    self.engine.feed_udp(now, from_ip, &buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("daemon: ldp udp recv: {}", e);
                    break;
                }
            }
        }
        let Some(rx_v6) = self.udp_rx_v6.as_ref() else {
            return;
        };
        loop {
            match recv_from_with_ttl(rx_v6, &mut buf) {
                Ok(Some((n, from, hop_limit))) => {
                    let from_ip = match from.ip() {
                        std::net::IpAddr::V4(v4) => IpAddr::V4(v4.octets()),
                        std::net::IpAddr::V6(v6) => normalize_v6(v6),
                    };
                    // §5.2: link-local sources only ever carry link
                    // Hellos, and §5.1 requires hop limit 255 on them.
                    let link_local = match from.ip() {
                        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
                        _ => false,
                    };
                    if link_local && hop_limit != Some(255) {
                        eprintln!(
                            "daemon: ldp dropped IPv6 Hello from {} (hop limit {:?} != 255, RFC 7552 §5.1)",
                            from.ip(),
                            hop_limit
                        );
                        continue;
                    }
                    self.engine.feed_udp(now, from_ip, &buf[..n]);
                }
                Ok(None) => break,
                Err(BfdTransportError::Os { errno: 11, .. }) => break, // EAGAIN
                Err(e) => {
                    eprintln!("daemon: ldp udp6 recv: {}", e);
                    break;
                }
            }
        }
    }

    /// Accept passive connections, read active ones, detect closures.
    fn pump_tcp(&mut self, now: Instant) {
        while let Ok((stream, _peer)) = self.listener.accept() {
            let _ = stream.set_nonblocking(true);
            // The accepted socket's local address fixes the session's
            // address family (RFC 7552 §7.1); normalize v4-mapped
            // endpoints back to IPv4.
            let local = stream
                .local_addr()
                .map(|a| match a.ip() {
                    std::net::IpAddr::V4(v4) => IpAddr::V4(v4.octets()),
                    std::net::IpAddr::V6(v6) => normalize_v6(v6),
                })
                .unwrap_or(IpAddr::V4([0, 0, 0, 0]));
            let conn = self.next_conn;
            self.next_conn += 1;
            self.conns.insert(conn, stream);
            self.engine.on_accepted(conn, local);
        }
        let conns: Vec<u64> = self.conns.keys().copied().collect();
        for conn in conns {
            let mut dead = false;
            let mut buf = [0u8; 65535];
            if let Some(stream) = self.conns.get_mut(&conn) {
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            dead = true;
                            break;
                        }
                        Ok(n) => self.engine.feed_tcp(now, conn, &buf[..n]),
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::Interrupted =>
                        {
                            break
                        }
                        Err(_) => {
                            dead = true;
                            break;
                        }
                    }
                }
            }
            if dead {
                if let Some(stream) = self.conns.remove(&conn) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
                self.engine.on_closed(now, conn);
            }
        }
    }

    /// Originate link Hellos on every interface whose hold-time third
    /// has elapsed (§3.5.2.1). Each interface's Hello is transmitted
    /// with the interface as the multicast egress so the source address
    /// (and thus the adjacency) is per-link; TTL 1 keeps the discovery
    /// datagram link-local. A dual-stack interface originates both
    /// families (RFC 7552 §5: "the LSR MUST periodically transmit both
    /// IPv6 and IPv4 LDP Link Hellos ... using the same LDP
    /// Identifier").
    fn pump_link_hellos(&mut self, now_ms: u64) {
        let hold_ms = u64::from(self.engine.config().link_hello_hold) * 1000;
        let interval = (hold_ms / 3).max(1);
        let due: Vec<usize> = self
            .interfaces
            .iter()
            .enumerate()
            .filter(|(_, i)| now_ms.saturating_sub(i.last_hello_ms) >= interval)
            .map(|(idx, _)| idx)
            .collect();
        let has_v6 = self.udp_tx_v6.is_some() && self.engine.config().transport_addr_v6.is_some();
        for idx in due {
            self.engine.send_link_hello(IpAddr::V4(ALL_ROUTERS_V4));
            let datagrams = self.engine.drain_udp();
            let iface = &self.interfaces[idx];
            for (dest, bytes) in datagrams {
                self.transmit(iface, &dest, &bytes);
            }
            let (v6_empty, ifindex) = (
                &self.interfaces[idx].v6_addrs.is_empty(),
                self.interfaces[idx].ifindex,
            );
            self.interfaces[idx].last_hello_ms = now_ms;
            // The IPv6 link Hello of the same cadence (§5: transmit
            // both families on a dual-stack interface).
            if has_v6 && !v6_empty && ifindex != 0 {
                self.engine.send_link_hello(IpAddr::V6(ALL_ROUTERS_V6));
                let datagrams = self.engine.drain_udp();
                let iface = &self.interfaces[idx];
                for (dest, bytes) in datagrams {
                    self.transmit_v6(iface, &dest, &bytes);
                }
                self.interfaces[idx].last_v6_hello_ms = now_ms;
            }
        }
    }

    /// Send one datagram: multicast destinations egress the interface
    /// (TTL 1), unicast destinations follow the routing table (targeted
    /// Hellos to remote peers).
    fn transmit(&self, iface: &LdpInterface, dest: &IpAddr, bytes: &[u8]) {
        let std_dest = crate::to_std_ip(*dest);
        let sock_addr = std::net::SocketAddr::from((std_dest, self.port));
        if std_dest.is_multicast() {
            // IP_MULTICAST_IF selects the egress; the kernel picks the
            // interface's primary address as the Hello source.
            if let Some(primary) = iface.addrs.first() {
                let _ = self.udp_tx.set_multicast_if_v4(primary);
            }
            let _ = self.udp_tx.set_multicast_ttl_v4(1);
        }
        let _ = self.udp_tx.send_to(bytes, &sock_addr.into());
    }

    /// IPv6 twin of [`transmit`](Self::transmit): multicast egress is
    /// selected per interface with IPV6_MULTICAST_IF and the hop limit
    /// of a link Hello is 1 (link-local scope); the hop limit of a
    /// unicast targeted Hello follows the default (RFC 7552 §5.1
    /// requires 255 only on link Hellos, which are multicast).
    fn transmit_v6(&self, iface: &LdpInterface, dest: &IpAddr, bytes: &[u8]) {
        const IPPROTO_IPV6: i32 = 41;
        const IPV6_MULTICAST_IF: i32 = 17;
        const IPV6_MULTICAST_HOPS: i32 = 18;
        let Some(tx) = self.udp_tx_v6.as_ref() else {
            return;
        };
        let std_dest = crate::to_std_ip(*dest);
        let sock_addr = std::net::SocketAddr::from((std_dest, self.port));
        if std_dest.is_multicast() {
            // SAFETY: plain integer setsockopt on a valid socket.
            unsafe {
                setsockopt_int(
                    tx.as_raw_fd(),
                    IPPROTO_IPV6,
                    IPV6_MULTICAST_IF,
                    iface.ifindex as i32,
                )
            };
            unsafe { setsockopt_int(tx.as_raw_fd(), IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 1) };
        }
        let _ = tx.send_to(bytes, &sock_addr.into());
    }

    /// Surface engine events: log, track counters, drive the transport
    /// (active connects on EstablishTransport; re-advertise bindings on
    /// SessionUp) and the shutdown path.
    fn handle_events(&mut self, now: Instant) {
        let events = self.engine.take_events();
        for ev in events {
            match ev {
                EngineEvent::AdjacencyUp(a) => {
                    println!(
                        "ldp: adjacency up peer {} kind {:?} source {} hold {:?}",
                        a.peer_id, a.kind, a.source, a.hold_time
                    );
                    self.counters
                        .adjacencies
                        .store(self.engine.adjacencies().len(), Ordering::Relaxed);
                }
                EngineEvent::AdjacencyDown { peer_id, kind, .. } => {
                    println!("ldp: adjacency down peer {} kind {:?}", peer_id, kind);
                    self.counters
                        .adjacencies
                        .store(self.engine.adjacencies().len(), Ordering::Relaxed);
                }
                EngineEvent::TargetedHelloRequested { source, .. } => {
                    println!("ldp: targeted hello requested from {} — responding", source);
                }
                EngineEvent::HelloDiscarded {
                    peer_id,
                    source,
                    reason,
                } => {
                    println!(
                        "ldp: discarded Hello from {} (peer {}): {}",
                        source, peer_id, reason
                    );
                }
                EngineEvent::EstablishTransport {
                    peer_id,
                    transport_addr,
                } => {
                    self.connect_peer(now, peer_id, transport_addr);
                }
                EngineEvent::SessionUp {
                    peer_id, params, ..
                } => {
                    println!(
                        "ldp: session up peer {} keepalive {}s max-pdu {}",
                        peer_id, params.keepalive_time, params.max_pdu_len
                    );
                    self.peers_up.insert(peer_id);
                    self.counters
                        .sessions
                        .store(self.peers_up.len(), Ordering::Relaxed);
                    // §3.5.9 (DU): push the local LIB to the freshly
                    // operational peer (existing peers receive a
                    // harmless re-announcement).
                    for (prefix, label) in self.binds.clone() {
                        self.engine.advertise_mapping(prefix, label);
                    }
                }
                EngineEvent::SessionDown { peer_id, reason } => {
                    println!(
                        "ldp: session down peer {} ({})",
                        peer_id,
                        down_reason_label(reason)
                    );
                    self.peers_up.remove(&peer_id);
                    self.counters
                        .sessions
                        .store(self.peers_up.len(), Ordering::Relaxed);
                }
                EngineEvent::CloseConnection(conn) => {
                    // Deliver any queued bytes (fatal Notification)
                    // before the FIN.
                    self.flush_tcp();
                    if let Some(stream) = self.conns.remove(&conn) {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                    }
                }
                EngineEvent::MappingLearned {
                    peer_id,
                    prefix,
                    label,
                } => {
                    println!(
                        "ldp: mapping learned {} label {} from {}",
                        prefix, label.0, peer_id
                    );
                    self.counters
                        .mappings_learned
                        .fetch_add(1, Ordering::Relaxed);
                }
                EngineEvent::MappingWithdrawn { peer_id, prefixes } => {
                    for prefix in &prefixes {
                        println!("ldp: mapping withdrawn {} from {}", prefix, peer_id);
                    }
                    self.counters
                        .mappings_withdrawn
                        .fetch_add(prefixes.len(), Ordering::Relaxed);
                }
                EngineEvent::MappingReleased { peer_id, prefix } => {
                    println!("ldp: mapping released {} by {}", prefix, peer_id);
                }
                EngineEvent::AddressReceived { peer_id, addresses } => {
                    let addrs: Vec<String> =
                        addresses.addresses.iter().map(|a| a.to_string()).collect();
                    println!("ldp: addresses from {}: {}", peer_id, addrs.join(","));
                }
                EngineEvent::NotificationReceived { peer_id, status } => {
                    println!(
                        "ldp: notification from {} status 0x{:08x}",
                        peer_id, status.code.0
                    );
                }
                EngineEvent::UnknownMessage { peer_id, message } => {
                    println!(
                        "ldp: unknown message type 0x{:04x} from {} (ignored, U=1)",
                        message.msg_type & 0x7fff,
                        peer_id
                    );
                }
            }
        }
    }

    /// Active role: open the TCP session transport to the peer's
    /// advertised transport address (§2.5.2). Failures return the peer
    /// to the engine so the next Hello retries.
    fn connect_peer(&mut self, now: Instant, peer_id: LdpId, transport_addr: IpAddr) {
        let std_addr = crate::to_std_ip(transport_addr);
        let port = self
            .peer_ports
            .get(&transport_addr)
            .copied()
            .unwrap_or(self.port);
        match TcpStream::connect_timeout(
            &std::net::SocketAddr::from((std_addr, port)),
            Duration::from_secs(5),
        ) {
            Ok(stream) => {
                let _ = stream.set_nonblocking(true);
                let conn = self.next_conn;
                self.next_conn += 1;
                self.conns.insert(conn, stream);
                self.engine.on_connected(now, conn, peer_id);
                println!("ldp: connected to {} for peer {}", std_addr, peer_id);
            }
            Err(e) => {
                println!("ldp: connect to {} failed: {} (will retry)", std_addr, e);
                self.engine.on_connect_failed(peer_id);
            }
        }
    }

    /// Write every queued TCP payload to its connection.
    fn flush_tcp(&mut self) {
        for (conn, bytes) in self.engine.drain_tcp_all() {
            if let Some(stream) = self.conns.get_mut(&conn) {
                let _ = stream.write_all(&bytes);
            }
        }
    }

    /// Transmit anything still queued (targeted Hellos from tick()).
    /// No interface is given: these follow the routing table; the port
    /// is the peer's override when configured, else the local LDP port.
    fn flush_udp(&mut self) {
        for (dest, bytes) in self.engine.drain_udp() {
            let std_dest = crate::to_std_ip(dest);
            let port = self.peer_ports.get(&dest).copied().unwrap_or(self.port);
            let sock_addr = std::net::SocketAddr::from((std_dest, port));
            let _ = self.udp_tx.send_to(&bytes, &sock_addr.into());
        }
    }

    /// Graceful shutdown: targeted Shutdown to every operational peer
    /// (§3.5.1.2.1.4), deliver the notifications, close the sockets.
    fn shutdown(&mut self, now: Instant) {
        let peers: Vec<LdpId> = std::mem::take(&mut self.peers_up).into_iter().collect();
        for peer in peers {
            self.engine.shutdown_peer(now, peer);
        }
        self.flush_tcp();
        self.conns.clear();
    }
}

/// Readable label for a session-down reason (log + operator parity
/// with the engine's §2.5.4 teardown causes).
fn down_reason_label(reason: SessionDownReason) -> &'static str {
    match reason {
        SessionDownReason::PeerNotification(_) => "notification from peer",
        SessionDownReason::KeepAliveExpired => "keepalive expired",
        SessionDownReason::TransportClosed => "transport closed",
        SessionDownReason::ProtocolError => "protocol error",
        SessionDownReason::ParameterMismatch => "parameter mismatch",
        SessionDownReason::LocalShutdown => "local shutdown",
    }
}
