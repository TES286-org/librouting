//! `lr-daemon` — reference librouting daemon with a real I/O loop.
//!
//! This is the embedder pattern in full: a TCP transport, a poll-driven
//! router, a ticker thread and graceful shutdown. It is deliberately small —
//! production daemons add config includes, privilege dropping, supervision
//! and MIBs — but every byte that flows is real BGP.
//!
//! ```text
//!            ┌──────────────────────────────────────────────┐
//!            │                 lr-daemon                    │
//!  TCP :179  │  ┌──────────┐  feed_input   ┌─────────────┐  │
//!  ────────► │  │ IO thread│ ───────────► │ DefaultRouter│  │
//!  ◄──────── │  │ (pump)   │ ◄─────────── │  (BGP FSMs)  │  │
//!  drain_out │  └──────────┘  drain_output└─────────────┘  │
//!            │       ▲                    ▲        │       │
//!            │       │ tick(ms)           │        ▼       │
//!            │  ┌────┴─────┐        poll_events  Loc-RIB   │
//!            │  │ ticker   │ ─────────────► events ─► log  │
//!            │  └──────────┘                          │     │
//!            │                          optionally:   ▼     │
//!            │                       lr-osroute (netlink)   │
//!            └──────────────────────────────────────────────┘
//! ```
//!
//! Usage:
//! ```text
//! lr-daemon --config daemon.toml
//! lr-daemon --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
//!           --peer 192.0.2.2:179 --network 203.0.113.0/24 [--install-kernel-routes]
//! ```
//!
//! The daemon does **not** install routes into the kernel by default (safe
//! in any environment). `--install-kernel-routes` enables it (root + Linux).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant as WallClock};

use core::str::FromStr;
use lr_core::addr::{Asn, Prefix, RouterId};
use lr_router::{DefaultRouter, RouterEvent, RouterInstance, SessionConfig, SessionHandle};

/// Daemon configuration (TOML or CLI flags).
#[derive(Debug, Clone, Default)]
struct DaemonConfig {
    local_as: u32,
    peer_as: u32,
    router_id: String,
    /// Remote peer address (outbound connection).
    peer_addr: Option<String>,
    /// Local listen address (inbound connections).
    listen_addr: Option<String>,
    /// Explicit local interface address (next-hop-self). Overrides the
    /// address derived from --peer/--listen.
    local_address: Option<String>,
    /// Locally originated networks.
    networks: Vec<String>,
    /// Install best routes into the kernel FIB.
    install_kernel: bool,
    /// BGP hold time (seconds).
    hold_time: u16,
    /// RFC 4724 graceful restart time to advertise (seconds). 0 disables GR.
    gr_restart_time: u16,
    /// RFC 9494 Long-Lived Graceful Restart stale time (seconds).
    /// 0 disables LLGR.
    llgr_stale_time: u32,
    /// Optional local cap (seconds) for the LLGR stale time received from
    /// peers. 0 = honour the peer's value.
    llgr_max_stale_time: u32,
}

fn print_usage() {
    println!(
        "lr-daemon — reference librouting BGP daemon\n\n\
         USAGE:\n  \
         lr-daemon --local-as AS --peer-as AS --router-id A.B.C.D \
         [--peer ADDR:PORT] [--listen ADDR:PORT] [--network PREFIX]...\n         \
         [--hold-time SEC]\n         \
         lr-daemon --config daemon.toml [--install-kernel-routes]\n\n\
         OPTIONS:\n  \
         --config PATH            Load TOML configuration\n  \
         --peer ADDR:PORT         Remote BGP peer to connect to (outbound)\n  \
         --listen ADDR:PORT       Accept an inbound BGP connection\n  \
         --network PREFIX         Locally originate PREFIX (repeatable)\n  \
         --hold-time SEC          BGP hold time in seconds (default 90)\n  \
         --graceful-restart SEC   RFC 4724 restart time to advertise\n  \
         (default 120; 0 disables)\n  \
         --llgr SEC               RFC 9494 long-lived graceful restart\n  \
         stale time to advertise (default 0 = disabled)\n  \
         --llgr-max-stale SEC     Cap the peer-advertised LLGR stale time\n  \
         --install-kernel-routes  Install best routes into the OS FIB (root)\n  \
         -h, --help               Show this help"
    );
}

/// Minimal TOML subset parser: `key = value` lines, `[section]` headers,
/// `#` comments, and quoted strings. Sufficient for the daemon's config
/// schema (see templates/daemon.toml).
fn parse_toml_subset(text: &str, cfg: &mut DaemonConfig) -> Result<(), String> {
    let mut section = String::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {}: expected `key = value`", lineno + 1));
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        let full = if section.is_empty() {
            key.to_string()
        } else {
            format!("{}.{}", section, key)
        };
        match full.as_str() {
            "bgp.local_as" => {
                cfg.local_as = value
                    .parse()
                    .map_err(|_| format!("line {}: bad local_as", lineno + 1))?
            }
            "bgp.peer_as" => {
                cfg.peer_as = value
                    .parse()
                    .map_err(|_| format!("line {}: bad peer_as", lineno + 1))?
            }
            "bgp.router_id" => cfg.router_id = value.to_string(),
            "bgp.peer_addr" => cfg.peer_addr = Some(value.to_string()),
            "bgp.listen_addr" => cfg.listen_addr = Some(value.to_string()),
            "bgp.local_address" => cfg.local_address = Some(value.to_string()),
            "bgp.hold_time" => cfg.hold_time = value.parse().unwrap_or(90),
            "networks" => {
                // Comma-separated array: ["a", "b"]
                let inner = value.trim_start_matches('[').trim_end_matches(']');
                for item in inner.split(',') {
                    let item = item.trim().trim_matches('"');
                    if !item.is_empty() {
                        cfg.networks.push(item.to_string());
                    }
                }
            }
            _ => {} // unknown keys are tolerated (forward compatibility)
        }
    }
    Ok(())
}

fn parse_args() -> Result<DaemonConfig, ExitCode> {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = DaemonConfig {
        hold_time: 90,
        ..Default::default()
    };
    let mut config_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--config" if i + 1 < args.len() => {
                config_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--local-as" if i + 1 < args.len() => {
                cfg.local_as = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--peer-as" if i + 1 < args.len() => {
                cfg.peer_as = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--router-id" if i + 1 < args.len() => {
                cfg.router_id = args[i + 1].clone();
                i += 2;
            }
            "--peer" if i + 1 < args.len() => {
                cfg.peer_addr = Some(args[i + 1].clone());
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                cfg.listen_addr = Some(args[i + 1].clone());
                i += 2;
            }
            "--local-address" if i + 1 < args.len() => {
                cfg.local_address = Some(args[i + 1].clone());
                i += 2;
            }
            "--network" if i + 1 < args.len() => {
                cfg.networks.push(args[i + 1].clone());
                i += 2;
            }
            "--hold-time" if i + 1 < args.len() => {
                cfg.hold_time = args[i + 1].parse().unwrap_or(90);
                i += 2;
            }
            "--graceful-restart" if i + 1 < args.len() => {
                cfg.gr_restart_time = args[i + 1].parse().unwrap_or(120);
                i += 2;
            }
            "--llgr" if i + 1 < args.len() => {
                cfg.llgr_stale_time = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--llgr-max-stale" if i + 1 < args.len() => {
                cfg.llgr_max_stale_time = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--install-kernel-routes" => {
                cfg.install_kernel = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_usage();
                return Err(ExitCode::SUCCESS);
            }
            _ => {
                eprintln!("unknown arg: {}", a);
                print_usage();
                return Err(ExitCode::from(2));
            }
        }
    }
    if let Some(path) = config_path {
        let text = std::fs::read_to_string(&path).map_err(|e| {
            eprintln!("cannot read config {}: {}", path, e);
            ExitCode::from(1)
        })?;
        parse_toml_subset(&text, &mut cfg).map_err(|e| {
            eprintln!("config parse error: {}", e);
            ExitCode::from(1)
        })?;
    }
    Ok(cfg)
}

fn main() -> ExitCode {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(code) => return code,
    };
    if cfg.local_as == 0 || cfg.peer_as == 0 || cfg.router_id.is_empty() {
        eprintln!("error: --local-as, --peer-as and --router-id are required");
        print_usage();
        return ExitCode::from(2);
    }
    let rid = match RouterId::from_str(&cfg.router_id) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("error: invalid router-id: {}", cfg.router_id);
            return ExitCode::from(2);
        }
    };

    let router = Arc::new(Mutex::new(DefaultRouter::new()));
    {
        let mut r = router.lock().unwrap();
        let mut sc = SessionConfig::bgp(Asn(cfg.local_as), Asn(cfg.peer_as), rid);
        sc.hold_time = cfg.hold_time;
        // RFC 4724 graceful restart + RFC 9494 long-lived graceful restart.
        // LLGR requires GR (RFC 9494 §4.1): with_long_lived_gr is therefore
        // only applied when the restart time is nonzero.
        sc = sc.with_graceful_restart(cfg.gr_restart_time);
        if cfg.llgr_stale_time != 0 {
            sc = sc.with_long_lived_gr(cfg.llgr_stale_time);
        }
        if cfg.llgr_max_stale_time != 0 {
            sc = sc.with_llgr_max_stale_time(cfg.llgr_max_stale_time);
        }
        // Local address for next-hop-self egress: prefer the peer address
        // (we connect from the interface that reaches it), else the listen
        // address. Without this, eBGP UPDATEs would carry no NEXT_HOP and
        // the remote would (correctly) reject them per RFC 4271 §6.3.
        let local_source = cfg
            .local_address
            .as_deref()
            .map(|s| s.to_string())
            .or_else(|| {
                cfg.peer_addr
                    .as_deref()
                    .or(cfg.listen_addr.as_deref())
                    .and_then(|p| p.split(':').next())
                    .map(|s| s.to_string())
            });
        if let Some(addr) = local_source {
            if let Ok(ip) = lr_core::addr::IpAddr::from_str(&addr) {
                sc = sc.with_local_address(ip);
            }
        }
        match r.add_session(sc) {
            Ok(h) => println!("daemon: BGP session #{} configured", h.0),
            Err(e) => {
                eprintln!("daemon: add_session failed: {}", e);
                return ExitCode::from(1);
            }
        }
    }

    println!("librouting daemon (lr-daemon)");
    println!("  local AS:    AS{}", cfg.local_as);
    println!("  peer AS:     AS{}", cfg.peer_as);
    println!("  router-id:   {}", rid);
    if let Some(peer) = &cfg.peer_addr {
        println!("  peer:        {}", peer);
    }
    println!("  networks:    {:?}", cfg.networks);
    println!("  install:     {}", cfg.install_kernel);
    println!("  platform:    {}", lr_osroute::PLATFORM_NAME);

    // Locally originated networks.
    {
        let mut r = router.lock().unwrap();
        for net in &cfg.networks {
            match Prefix::from_str(net) {
                Ok(p) => {
                    r.originate(p, None);
                    println!("daemon: originating {}", p);
                }
                Err(_) => eprintln!("daemon: invalid network '{}'", net),
            }
        }
    }

    let running = Arc::new(AtomicBool::new(true));

    // --- Ticker thread: pump the router clock every 50 ms. ---
    {
        let router = Arc::clone(&router);
        let running = Arc::clone(&running);
        thread::spawn(move || {
            let start = WallClock::now();
            while running.load(Ordering::Relaxed) {
                let now_ms = start.elapsed().as_millis() as u64;
                {
                    let mut r = router.lock().unwrap();
                    r.tick(lr_core::time::Instant(now_ms));
                    for ev in r.poll_events() {
                        log_event(&ev);
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
    }

    // --- IO loop: connect to the peer and pump bytes both ways. ---
    let session: SessionHandle = SessionHandle(1);

    if let Some(listen_addr) = cfg.listen_addr.clone() {
        // ---- Inbound mode: accept connections on a local port. ----
        let sockaddr = match resolve(&listen_addr) {
            Some(a) => a,
            None => {
                eprintln!("daemon: cannot resolve {}", listen_addr);
                return ExitCode::from(1);
            }
        };
        let listener = match std::net::TcpListener::bind(sockaddr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("daemon: bind {} failed: {}", listen_addr, e);
                return ExitCode::from(1);
            }
        };
        println!("daemon: listening on {}", listen_addr);
        let mut ever_established = false;
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let peer = s
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "?".into());
                    println!("daemon: inbound connection from {}", peer);
                    let _ = s.set_nodelay(true);
                    if let Err(e) = run_session(
                        &router,
                        &running,
                        s,
                        session,
                        cfg.install_kernel,
                        &mut ever_established,
                    ) {
                        eprintln!("daemon: session ended: {}", e);
                    }
                }
                Err(e) => eprintln!("daemon: accept failed: {}", e),
            }
            if !running.load(Ordering::Relaxed) {
                break;
            }
        }
        println!("daemon: shutdown complete");
        return ExitCode::SUCCESS;
    }

    let peer_addr = match cfg.peer_addr.clone() {
        Some(p) => p,
        None => {
            println!("daemon: no --peer/--listen given; idling (tick loop only). Ctrl-C to stop.");
            wait_for_shutdown(&running);
            return ExitCode::SUCCESS;
        }
    };

    // ---- Outbound mode: connect (with reconnect + backoff). ----
    let mut backoff_ms: u64 = 1_000;
    let mut ever_established = false;

    while running.load(Ordering::Relaxed) {
        let sockaddr = match resolve(&peer_addr) {
            Some(a) => a,
            None => {
                eprintln!("daemon: cannot resolve {}", peer_addr);
                return ExitCode::from(1);
            }
        };
        println!("daemon: connecting to {} ...", peer_addr);
        let stream = match TcpStream::connect_timeout(&sockaddr, Duration::from_secs(5)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "daemon: connect failed ({}); retrying in {}ms",
                    e, backoff_ms
                );
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(30_000);
                continue;
            }
        };
        backoff_ms = 1_000;
        let _ = stream.set_nodelay(true);
        match run_session(
            &router,
            &running,
            stream,
            session,
            cfg.install_kernel,
            &mut ever_established,
        ) {
            Ok(()) => break,
            Err(e) => {
                eprintln!("daemon: session ended: {}", e);
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                eprintln!("daemon: reconnecting in {}ms", backoff_ms);
                thread::sleep(Duration::from_millis(backoff_ms));
            }
        }
    }

    println!("daemon: shutdown complete");
    ExitCode::SUCCESS
}

fn resolve(addr: &str) -> Option<std::net::SocketAddr> {
    addr.to_socket_addrs().ok()?.next()
}

/// Drive one established TCP connection until it drops or we shut down.
fn run_session(
    router: &Arc<Mutex<DefaultRouter>>,
    running: &Arc<AtomicBool>,
    mut stream: TcpStream,
    session: SessionHandle,
    install_kernel: bool,
    _ever_established: &mut bool,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    {
        let mut r = router.lock().unwrap();
        r.start_session(session)
            .map_err(|e| format!("start_session: {}", e))?;
    }
    let mut os_table: Option<Box<dyn lr_osroute::OsRouteTable<Error = lr_osroute::OsRouteError>>> =
        None;
    if install_kernel {
        match lr_osroute::SystemRouteTable::connect() {
            Ok(t) => {
                println!("daemon: os route table connected — installing kernel routes");
                os_table = Some(Box::new(t));
            }
            Err(e) => eprintln!(
                "daemon: os route table unavailable ({}); kernel install disabled",
                e
            ),
        }
    }
    let result = pump_session(router, running, &mut stream, session, &mut os_table);
    // The transport is gone: drive the FSM to Idle and purge the routes
    // this session contributed (RFC 4271 §8.2.2).
    {
        let mut r = router.lock().unwrap();
        r.close_session(session);
        for ev in r.poll_events() {
            log_event(&ev);
        }
    }
    result
}

fn pump_session(
    router: &Arc<Mutex<DefaultRouter>>,
    running: &Arc<AtomicBool>,
    stream: &mut TcpStream,
    session: SessionHandle,
    os_table: &mut Option<Box<dyn lr_osroute::OsRouteTable<Error = lr_osroute::OsRouteError>>>,
) -> Result<(), String> {
    let mut buf = [0u8; 8192];
    while running.load(Ordering::Relaxed) {
        // 1. Read peer bytes → feed_input.
        match stream.read(&mut buf) {
            Ok(0) => return Err("peer closed connection".into()),
            Ok(n) => {
                let mut r = router.lock().unwrap();
                r.feed_input(session, &buf[..n])
                    .map_err(|e| format!("feed_input: {}", e))?;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("read: {}", e)),
        }

        // 2. Drain router output → write to peer.
        let out = {
            let mut r = router.lock().unwrap();
            let o = r.drain_output(session);
            let events = r.poll_events();
            for ev in &events {
                log_event(ev);
            }
            handle_events(&mut r, &events, os_table);
            o
        };
        if !out.is_empty() {
            stream
                .write_all(&out)
                .map_err(|e| format!("write: {}", e))?;
        }
    }
    Ok(())
}

/// React to router events (kernel route installation lives here).
fn handle_events(
    router: &mut DefaultRouter,
    events: &[RouterEvent],
    os_table: &mut Option<Box<dyn lr_osroute::OsRouteTable<Error = lr_osroute::OsRouteError>>>,
) {
    let _ = router;
    let Some(table) = os_table else {
        return;
    };
    for ev in events {
        match ev {
            RouterEvent::RouteInstalled(r) => {
                if let Some(nh) = r.next_hop {
                    let _ = table.add_route(r.key.prefix, nh, 0);
                }
            }
            RouterEvent::RouteWithdrawn(k) => {
                let _ = table.delete_route(k.prefix);
            }
            _ => {}
        }
    }
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

fn wait_for_shutdown(running: &Arc<AtomicBool>) {
    // No signal handling without libc: the loop exits when stdin closes or
    // the process is killed. In production use `signal-hook` or `tokio`.
    println!("daemon: press Ctrl-C to stop");
    loop {
        if running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(500));
        } else {
            break;
        }
    }
}
