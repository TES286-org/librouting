//! `lr-daemon` — reference librouting daemon with a real I/O loop.
//!
//! This is the embedder pattern in full: TCP transports, a poll-driven
//! router, a ticker thread and graceful shutdown. Multi-peer is first
//! class: one connector thread per outbound `[[peer]]`, a listener that
//! accepts concurrent inbound sessions (matched to configured peers by
//! source address), and a single event consumer so Loc-RIB ordering is
//! preserved across sessions.
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
//!            │  └──────────┘                 + kernel FIB   │
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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant as WallClock};

use core::str::FromStr;
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_osroute::gtsm::Gtsm;
use lr_osroute::tcp_auth::{TcpAoAlgorithm, TcpAoKey, TcpAuth};
use lr_router::{DefaultRouter, RouterEvent, RouterInstance, SessionConfig, SessionHandle};

mod api;
mod daemon_config;
mod daemon_policy;
mod privdrop;
mod signal;

use daemon_config::{DaemonConfig, PeerSpec};

fn print_usage() {
    println!(
        "lr-daemon — reference librouting BGP daemon\n\n\
         USAGE:\n  \
         lr-daemon --local-as AS --peer-as AS --router-id A.B.C.D \
         [--peer ADDR:PORT]... [--listen ADDR:PORT] [--network PREFIX]...\n         \
         [--hold-time SEC]\n         \
         lr-daemon --config daemon.toml [--install-kernel-routes]\n\n\
         OPTIONS:\n  \
         --config PATH            Load TOML configuration\n  \
         --peer ADDR:PORT         Remote BGP peer to connect to (repeatable;\n  \
         all peers share --peer-as; per-peer settings need [[peer]])\n  \
         --listen ADDR:PORT       Accept inbound BGP connections\n  \
         --network PREFIX         Locally originate PREFIX (repeatable)\n  \
         --hold-time SEC          BGP hold time in seconds (default 90)\n  \
         --graceful-restart SEC   RFC 4724 restart time to advertise\n  \
         (default 120; 0 disables)\n  \
         --llgr SEC               RFC 9494 long-lived graceful restart\n  \
         stale time (0 disables)\n  \
         --llgr-max-stale SEC     Cap the peer-advertised LLGR stale time\n  \
         --md5-key SECRET         RFC 2385 TCP MD5 session auth\n  \
         --tcp-ao-key ID:SECRET   RFC 5925 TCP-AO key (repeatable)\n  \
         --tcp-ao-alg ALG         hmac-sha1 (default) or cmac-aes\n  \
         --tcp-ao-maclen BYTES    TCP-AO MAC length (0 = default)\n  \
         --add-path               Advertise RFC 7911 Add-Path\n  \
         --add-path-max N         Paths per prefix kept (default 6)\n  \
         --mp-family NAME         Extra MP-BGP family (repeatable;\n  \
         ipv4-unicast | ipv6-unicast)\n  \
         --extended-next-hop      RFC 5549 IPv4-over-IPv6 next-hops\n  \
         --local-address ADDR     Source address for next-hop-self\n  \
         --local-address-v6 ADDR  IPv6 source for v6 NLRI / ENH egress\n  \
         --gtsm [N]               RFC 5082 TTL security (bare = 1 hop)\n  \
         --max-prefixes N         Per-peer maximum-prefix limit\n  \
         --max-prefix-action A    warn (default) | teardown | restart\n  \
         --max-prefix-threshold P Early-warning percentage (default 75)\n  \
         --protocol PROTO         bgp (default) | babel\n  \
         --babel-group ADDR       Babel multicast group (ff02::1:6)\n  \
         --babel-port PORT        Babel UDP port (6696)\n  \
         --install-kernel-routes  Install best routes into the kernel FIB\n  \
         --user NAME              Drop privileges after binding\n  \
         --group NAME             Privilege-drop group\n  \
         --api-socket PATH        Unix-socket runtime API\n  \
         Multi-peer configuration uses [[peer]] tables in the TOML config\n  \
         (see templates/daemon.toml): per-peer remote/address, peer_as,\n  \
         auth, GTSM, maximum-prefix, Add-Path and family settings,\n  \
         inheriting the [bgp] globals when omitted."
    );
}

fn main() -> ExitCode {
    let mut cfg = match daemon_config::parse_args() {
        Ok(c) => c,
        Err(code) => {
            if code == ExitCode::SUCCESS || code == ExitCode::from(2) {
                print_usage();
            }
            return code;
        }
    };
    cfg.finalize();
    if cfg.local_as == 0 || cfg.router_id.is_empty() {
        eprintln!("error: --local-as and --router-id are required");
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
    // Babel mode: short-circuit the BGP session setup and run the
    // Babel UDP transport loop instead.
    if cfg.protocol == "babel" {
        return run_babel_daemon(&cfg);
    }
    // Signal handling must precede everything that could receive one:
    // without a SIGHUP handler the default disposition would terminate
    // the daemon on a hung-up terminal.
    if let Err(sig) = signal::init() {
        eprintln!("daemon: cannot install signal handlers (signal {})", sig);
        return ExitCode::from(1);
    }
    if cfg.user.is_some() && cfg.install_kernel {
        eprintln!(
            "daemon: warning: --user with --install-kernel-routes: \
             kernel installs may be denied after the privilege drop"
        );
    }
    run_bgp_daemon(&cfg, rid)
}

/// One configured BGP peer: its router session, transport security and
/// the busy flag serialising inbound connections on the session.
struct PeerEntry {
    spec: PeerSpec,
    handle: SessionHandle,
    auth: TcpAuth,
    gtsm: Gtsm,
    /// True while a transport thread owns this session — prevents two
    /// concurrent connections racing one FSM.
    busy: Arc<AtomicBool>,
}

impl PeerEntry {
    fn label(&self) -> &str {
        self.spec.label()
    }
}

fn run_bgp_daemon(cfg: &DaemonConfig, rid: RouterId) -> ExitCode {
    let router = Arc::new(Mutex::new(DefaultRouter::new()));

    // ---- Build one router session per configured peer. ----
    let mut entries: Vec<PeerEntry> = Vec::new();
    {
        let mut r = router.lock().unwrap();
        // RFC 7911 Add-Path: cap how many paths per prefix survive the
        // decision process (and reach Add-Path peers). Router-global.
        r.set_add_path_max_paths(cfg.add_path_max_paths.max(1) as usize);
        for spec in &cfg.peers {
            if cfg.explicit_peers && !spec.is_outbound() && !spec.is_inbound() {
                eprintln!(
                    "daemon: peer {}: 'remote' or 'address' is required",
                    spec.label()
                );
                return ExitCode::from(2);
            }
            if spec.is_outbound() && spec.is_inbound() {
                eprintln!(
                    "daemon: peer {}: 'remote' and 'address' together are not \
                     supported yet (RFC 4271 §6.8 collision detection is \
                     future work); configure one direction",
                    spec.label()
                );
                return ExitCode::from(2);
            }
            if cfg.effective_peer_as(spec) == 0 {
                eprintln!(
                    "daemon: peer {}: no peer AS configured (set peer_as or \
                     the global --peer-as)",
                    spec.label()
                );
                return ExitCode::from(2);
            }
            if spec.is_inbound() && cfg.listen_addr.is_none() {
                eprintln!(
                    "daemon: peer {}: inbound peers require --listen",
                    spec.label()
                );
                return ExitCode::from(2);
            }
            let auth = match build_peer_tcp_auth(cfg, spec) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("error: peer {}: {}", spec.label(), e);
                    return ExitCode::from(2);
                }
            };
            let gtsm = build_peer_gtsm(cfg, spec);
            let sc = build_session_config(cfg, spec, rid);
            // eBGP without a source address: egress keeps the received
            // NEXT_HOP, which peers usually reject — warn loudly.
            if cfg.effective_peer_as(spec) != cfg.local_as
                && sc.local_address.is_none()
                && spec.is_outbound()
            {
                eprintln!(
                    "daemon: peer {}: warning: no local_address; eBGP \
                     egress will keep the received NEXT_HOP (peers often \
                     reject these UPDATEs)",
                    spec.label()
                );
            }
            match r.add_session(sc) {
                Ok(h) => entries.push(PeerEntry {
                    spec: spec.clone(),
                    handle: h,
                    auth,
                    gtsm,
                    busy: Arc::new(AtomicBool::new(false)),
                }),
                Err(e) => {
                    eprintln!("daemon: peer {}: add_session failed: {}", spec.label(), e);
                    return ExitCode::from(1);
                }
            }
        }
    }

    // ---- Policy (route-maps / lists from the TOML config). ----
    // Registered before any session comes up so the initial table
    // dump already flows through per-peer import/export policy.
    let has_policy_bindings = cfg
        .peers
        .iter()
        .any(|p| p.import.is_some() || p.export.is_some());
    if has_policy_bindings || !cfg.route_maps.is_empty() {
        let mut policy_set = match daemon_policy::build_policy_set(cfg) {
            Ok(set) => set,
            Err(e) => return daemon_policy::policy_error(e),
        };
        if let Err(e) = daemon_policy::bind_peer_policies(cfg, &mut policy_set, |idx| {
            entries.get(idx).map(|e| e.handle.0).unwrap_or(u64::MAX)
        }) {
            return daemon_policy::policy_error(e);
        }
        let hooks = policy_set.hooks();
        let bound_imports = cfg.peers.iter().filter(|p| p.import.is_some()).count();
        let bound_exports = cfg.peers.iter().filter(|p| p.export.is_some()).count();
        {
            let mut r = router.lock().unwrap();
            r.hooks_mut().import.push(Box::new(hooks.clone()));
            r.hooks_mut().export.push(Box::new(hooks));
        }
        println!(
            "  policy:      {} route-maps, {} import / {} export bindings",
            cfg.route_maps.len(),
            bound_imports,
            bound_exports
        );
    }

    // ---- Banner. ----
    println!("librouting daemon (lr-daemon)");
    println!("  local AS:    AS{}", cfg.local_as);
    println!("  router-id:   {}", rid);
    println!("  peers:       {}", entries.len());
    for e in &entries {
        println!(
            "    #{} {} AS{} ({})",
            e.handle.0,
            e.label(),
            cfg.effective_peer_as(&e.spec),
            if e.spec.is_outbound() {
                "outbound"
            } else if e.spec.is_inbound() {
                "inbound"
            } else {
                "any"
            }
        );
    }
    println!("  networks:    {:?}", cfg.networks);
    println!("  install:     {}", cfg.install_kernel);
    println!("  platform:    {}", lr_osroute::PLATFORM_NAME);

    // Locally originated networks. The string list is kept around so
    // reloads can diff old vs new (SIGHUP / runtime API `reload`).
    let current_networks = Arc::new(Mutex::new(cfg.networks.clone()));
    {
        let mut r = router.lock().unwrap();
        for net in &cfg.networks {
            match Prefix::from_str(net) {
                Ok(p) => {
                    let (p, family) = originate_family_for(p);
                    r.originate_family(p, family, None);
                    println!("daemon: originating {}", p);
                }
                Err(_) => eprintln!("daemon: invalid network '{}'", net),
            }
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let live_sessions = Arc::new(AtomicUsize::new(0));
    let runtime = Arc::new(Runtime {
        reload: Arc::new({
            let router = Arc::clone(&router);
            let current_networks = Arc::clone(&current_networks);
            let config_path = cfg.config_path.clone();
            move || reload_config(config_path.as_deref(), &router, &current_networks)
        }),
        router,
        running: Arc::clone(&running),
    });

    // --- Ticker thread: pump the router clock every 50 ms. It is the
    // single consumer of router events — logging and (optional) kernel
    // route installation happen here, never on the I/O threads, so the
    // Loc-RIB event order cannot be shuffled across sessions. ---
    spawn_ticker(&runtime, cfg.install_kernel, Arc::clone(&live_sessions));

    // ---- Listener (inbound), if configured. ----
    // Legacy mode (no [[peer]] tables, a single peer): the listener
    // accepts any connection on session #1, and `--listen` wins over
    // `--peer` exactly as the historical daemon did. Explicit mode:
    // inbound connections are matched to peers by source address.
    let strict_inbound = cfg.explicit_peers || cfg.peers.len() > 1;
    let mut listener: Option<std::net::TcpListener> = None;
    if let Some(listen_addr) = cfg.listen_addr.clone() {
        let sockaddr = match resolve(&listen_addr) {
            Some(a) => a,
            None => {
                eprintln!("daemon: cannot resolve {}", listen_addr);
                return ExitCode::from(1);
            }
        };
        let l = match std::net::TcpListener::bind(sockaddr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("daemon: bind {} failed: {}", listen_addr, e);
                return ExitCode::from(1);
            }
        };
        println!("daemon: listening on {}", listen_addr);
        // Fail closed: if session authentication is configured but cannot
        // be armed on the listener (missing kernel support, bad key), stop
        // instead of accepting unauthenticated connections. All inbound
        // peers must share one auth configuration — heterogeneous
        // listener keys are future work.
        let inbound_auth = match listener_auth(cfg, &entries) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("daemon: session auth arming failed: {}", e);
                return ExitCode::from(1);
            }
        };
        if let Err(e) = lr_osroute::tcp_auth::arm_listener(&l, &inbound_auth) {
            eprintln!("daemon: session auth arming failed: {}", e);
            return ExitCode::from(1);
        }
        if !inbound_auth.is_none() {
            println!("daemon: session auth armed ({})", inbound_auth.describe());
        }
        // RFC 5082 GTSM: arm the listener with the min-TTL filter. Fail
        // closed when the kernel does not support IP_MINTTL — running
        // without the filter would defeat the purpose of configuring GTSM.
        // Like auth, the filter is listener-wide.
        let inbound_gtsm = listener_gtsm(cfg, &entries);
        if !inbound_gtsm.is_disabled() {
            if let Err(e) = lr_osroute::gtsm::arm_listener_gtsm(&l, &inbound_gtsm) {
                eprintln!("daemon: GTSM arming failed: {}", e);
                return ExitCode::from(1);
            }
            println!("daemon: GTSM armed ({})", inbound_gtsm);
        }
        if let Err(e) = l.set_nonblocking(true) {
            eprintln!("daemon: cannot set listener non-blocking: {}", e);
            return ExitCode::from(1);
        }
        listener = Some(l);
    }

    // Privileged work is done: drop root before touching any network
    // input, then create the management socket as the reduced user.
    if let Err(e) = do_privdrop(cfg) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }
    if let Err(e) = spawn_api(cfg, &runtime) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }

    // ---- Outbound connectors: one thread per remote peer. ----
    // Legacy listen precedence: with a single peer and --listen, the
    // historical daemon ignored --peer entirely (listen mode wins).
    let legacy_listen_only = !strict_inbound && listener.is_some();
    if !legacy_listen_only {
        for entry in &entries {
            if entry.spec.is_outbound() {
                spawn_connector(&runtime, entry, Arc::clone(&live_sessions));
            }
        }
    }

    // ---- Main thread: run the accept loop, or idle until shutdown. ----
    if let Some(listener) = listener {
        let mut poll_idle = Duration::from_millis(100);
        loop {
            dispatch_signals(&runtime);
            if !running.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((s, peer_sockaddr)) => {
                    let peer = peer_sockaddr.to_string();
                    println!("daemon: inbound connection from {}", peer);
                    let _ = s.set_nodelay(true);
                    let entry = if strict_inbound {
                        match match_inbound_peer(&entries, peer_sockaddr.ip()) {
                            Ok(e) => e,
                            Err(reason) => {
                                eprintln!(
                                    "daemon: inbound connection from {} rejected: {}",
                                    peer, reason
                                );
                                continue;
                            }
                        }
                    } else {
                        // Historical accept-any: session #1.
                        &entries[0]
                    };
                    if entry.busy.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "daemon: peer {} already has an active session; \
                             dropping inbound connection from {}",
                            entry.label(),
                            peer
                        );
                        continue;
                    }
                    let rt = Arc::clone(&runtime);
                    let busy = Arc::clone(&entry.busy);
                    let live = Arc::clone(&live_sessions);
                    let handle = entry.handle;
                    live.fetch_add(1, Ordering::Relaxed);
                    let spawned = thread::Builder::new()
                        .name(format!("lr-session-{}", handle.0))
                        .spawn(move || {
                            if let Err(e) = run_peer_session(rt, s, handle) {
                                eprintln!("daemon: session #{} ended: {}", handle.0, e);
                            }
                            busy.store(false, Ordering::Relaxed);
                            live.fetch_sub(1, Ordering::Relaxed);
                        });
                    if spawned.is_err() {
                        // Thread spawn failed: undo the guards so the
                        // peer is not wedged busy forever.
                        entry.busy.store(false, Ordering::Relaxed);
                        live_sessions.fetch_sub(1, Ordering::Relaxed);
                    }
                    poll_idle = Duration::from_millis(1);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(poll_idle);
                    poll_idle = (poll_idle * 2).min(Duration::from_millis(100));
                }
                Err(e) => {
                    eprintln!("daemon: accept failed: {}", e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    } else if entries.iter().any(|e| e.spec.is_outbound()) {
        // Connectors own the I/O; the main thread just supervises.
        wait_for_shutdown(&runtime);
    } else {
        println!("daemon: no --peer/--listen given; idling (tick loop only)");
        wait_for_shutdown(&runtime);
    }

    // Give live session threads a bounded grace period to flush their
    // close NOTIFICATIONs (RFC 4271 §6.4) before the process exits.
    let deadline = WallClock::now() + Duration::from_secs(3);
    while live_sessions.load(Ordering::Relaxed) > 0 && WallClock::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    println!("daemon: shutdown complete");
    ExitCode::SUCCESS
}

/// Build the `SessionConfig` for one peer, resolving all per-peer
/// overrides against the `[bgp]` globals.
fn build_session_config(g: &DaemonConfig, p: &PeerSpec, rid: RouterId) -> SessionConfig {
    let mut sc = SessionConfig::bgp(Asn(g.local_as), Asn(g.effective_peer_as(p)), rid);
    sc.hold_time = p.hold_time.unwrap_or(g.hold_time);
    if p.add_path.unwrap_or(g.add_path) {
        sc = sc.with_add_path();
    }
    // RFC 4760 MP-BGP: build the family list from the effective config.
    // Empty keeps the SessionConfig::bgp() default (IPv4 unicast),
    // preserving the historical daemon behaviour. `ipv4-unicast` and
    // `ipv6-unicast` are recognised; unknown names are logged and dropped.
    let families_cfg = p.mp_families.as_ref().unwrap_or(&g.mp_families);
    if !families_cfg.is_empty() {
        let mut families = Vec::new();
        for name in families_cfg {
            match name.as_str() {
                "ipv4-unicast" => families.push(NlriFamily::IPV4_UNICAST),
                "ipv6-unicast" => families.push(NlriFamily::IPV6_UNICAST),
                other => eprintln!(
                    "daemon: peer {}: unknown mp_family '{}' (skipped)",
                    p.label(),
                    other
                ),
            }
        }
        if !families.is_empty() {
            sc = sc.with_mp_families(families);
        }
    }
    // RFC 5549 Extended Next-Hop. Advertise the canonical (1,1,2) tuple
    // so an IPv6 transport can carry IPv4 NLRI without an IPv4 next-hop.
    if p.extended_next_hop.unwrap_or(g.extended_next_hop) {
        sc = sc.with_extended_next_hop();
    }
    // Per-peer maximum-prefix (BIRD `maximum prefix`, FRR
    // `maximum-prefix`).
    if let Some(limit) = p.max_prefixes.or(g.max_prefixes) {
        let action = match p
            .max_prefix_action
            .as_deref()
            .unwrap_or(g.max_prefix_action.as_str())
        {
            "teardown" => lr_bgp::MaxPrefixAction::Teardown,
            "restart" => lr_bgp::MaxPrefixAction::Restart,
            _ => lr_bgp::MaxPrefixAction::Warn,
        };
        sc = sc
            .with_maximum_prefix(limit, action)
            .with_maximum_prefix_threshold(
                p.max_prefix_threshold.unwrap_or(g.max_prefix_threshold),
            );
    }
    // RFC 4724 graceful restart + RFC 9494 long-lived graceful restart.
    // LLGR requires GR (RFC 9494 §4.1): with_long_lived_gr is therefore
    // only applied when the restart time is nonzero.
    sc = sc.with_graceful_restart(p.gr_restart_time.unwrap_or(g.gr_restart_time));
    let llgr = p.llgr_stale_time.unwrap_or(g.llgr_stale_time);
    if llgr != 0 {
        sc = sc.with_long_lived_gr(llgr);
    }
    let llgr_cap = p.llgr_max_stale_time.unwrap_or(g.llgr_max_stale_time);
    if llgr_cap != 0 {
        sc = sc.with_llgr_max_stale_time(llgr_cap);
    }
    // Local address for next-hop-self egress. The IPv4 source derives
    // from the peer's local_address / the global --local-address / the
    // listener's IP. Without a relevant source we leave the session's
    // local_address unset and rely on the route's existing NEXT_HOP
    // (correct for iBGP; eBGP without a source skips rewrite).
    if let Some(ip) = peer_local_address(g, p) {
        sc = sc.with_local_address(ip);
    }
    // When the IPv6 source differs from the IPv4 one (the common case
    // for dual-stack hosts), prefer it for IPv6 / ENH egress: when the
    // transport is IPv6 it is the right next-hop-self for any family
    // this session speaks; with ENH the peer resolves IPv4 NLRI over
    // the v6 next-hop even on a v4 transport.
    let v6_source = p.local_address_v6.as_ref().or(g.local_address_v6.as_ref());
    if let Some(v6) = v6_source {
        if let Ok(ip) = IpAddr::from_str(v6) {
            if matches!(ip, IpAddr::V6(_)) {
                // The session transport: the remote address for outbound
                // peers, the listener for inbound/legacy ones.
                let transport = p.remote.as_deref().or(g.listen_addr.as_deref());
                let transport_is_v6 = transport
                    .and_then(transport_ip)
                    .map(|ip| matches!(ip, IpAddr::V6(_)))
                    .unwrap_or(false);
                if transport_is_v6 || p.extended_next_hop.unwrap_or(g.extended_next_hop) {
                    sc = sc.with_local_address(ip);
                }
            }
        } else {
            eprintln!(
                "daemon: peer {}: invalid local_address_v6 '{}'",
                p.label(),
                v6
            );
        }
    }
    sc
}

/// Per-peer transport authentication (RFC 2385 / RFC 5925). MD5 and
/// TCP-AO are mutually exclusive (the kernel forbids mixing them on one
/// socket anyway).
fn build_peer_tcp_auth(g: &DaemonConfig, p: &PeerSpec) -> Result<TcpAuth, String> {
    let md5 = p.md5_key.as_ref().or(g.md5_key.as_ref());
    let ao_keys = p
        .tcp_ao_keys
        .clone()
        .unwrap_or_else(|| g.tcp_ao_keys.clone());
    if let Some(md5) = md5 {
        if !ao_keys.is_empty() {
            return Err("--md5-key and --tcp-ao-key are mutually exclusive".to_string());
        }
        return TcpAuth::md5(md5.as_bytes().to_vec()).map_err(|e| format!("bad md5 key: {e}"));
    }
    if ao_keys.is_empty() {
        return Ok(TcpAuth::None);
    }
    let algorithm_name = p
        .tcp_ao_algorithm
        .clone()
        .unwrap_or_else(|| g.tcp_ao_algorithm.clone());
    let algorithm = TcpAoAlgorithm::parse(&algorithm_name).ok_or_else(|| {
        format!("unknown tcp-ao-alg '{algorithm_name}' (use hmac-sha1 or cmac-aes)")
    })?;
    let maclen = p.tcp_ao_maclen.unwrap_or(g.tcp_ao_maclen);
    let mut keys = Vec::with_capacity(ao_keys.len());
    for raw in &ao_keys {
        // Format: "id:secret" — the id is used as both SendID and RecvID.
        let (id, secret) = raw
            .split_once(':')
            .ok_or_else(|| format!("bad tcp-ao-key '{raw}': expected ID:SECRET (e.g. 1:alpha)"))?;
        let id: u8 = id
            .trim()
            .parse()
            .map_err(|_| format!("bad tcp-ao-key '{raw}': ID must be 0-255"))?;
        keys.push(
            TcpAoKey::symmetric(id, secret.as_bytes().to_vec())
                .map_err(|e| format!("bad tcp-ao-key '{raw}': {e}"))?,
        );
    }
    TcpAuth::tcp_ao(keys, algorithm, maclen).map_err(|e| format!("bad tcp-ao configuration: {e}"))
}

/// Per-peer RFC 5082 GTSM configuration.
fn build_peer_gtsm(g: &DaemonConfig, p: &PeerSpec) -> Gtsm {
    match p.gtsm_hops.or(g.gtsm_hops) {
        None => Gtsm::default(),
        Some(1) => Gtsm::single_hop(),
        Some(hops) => Gtsm::multihop(hops),
    }
}

/// The auth configuration a shared listener must be armed with: every
/// inbound-capable peer's auth, which must all be identical (hetero-
/// geneous listener keys are future work). Legacy mode arms the single
/// peer's configuration exactly as the historical daemon did.
fn listener_auth(g: &DaemonConfig, entries: &[PeerEntry]) -> Result<TcpAuth, String> {
    let strict = g.explicit_peers || g.peers.len() > 1;
    let inbound: Vec<&PeerEntry> = if strict {
        entries.iter().filter(|e| e.spec.is_inbound()).collect()
    } else {
        entries.iter().take(1).collect() // legacy: the single peer
    };
    if inbound.is_empty() {
        return Ok(TcpAuth::None);
    }
    let first = inbound[0].auth.clone();
    for e in &inbound[1..] {
        if e.auth != first {
            return Err(format!(
                "peers {} and {} configure different session auth; a \
                 shared listener supports one key set (configure identical \
                 auth for all inbound peers)",
                inbound[0].label(),
                e.label()
            ));
        }
    }
    Ok(first)
}

/// The GTSM filter for the shared listener (same rules as
/// [`listener_auth`]).
fn listener_gtsm(g: &DaemonConfig, entries: &[PeerEntry]) -> Gtsm {
    let strict = g.explicit_peers || g.peers.len() > 1;
    let inbound: Vec<&PeerEntry> = if strict {
        entries.iter().filter(|e| e.spec.is_inbound()).collect()
    } else {
        entries.iter().take(1).collect()
    };
    inbound.first().map(|e| e.gtsm).unwrap_or_default()
}

/// Resolve the effective source address for next-hop-self egress of
/// `peer`. Explicit peers derive from the listener only (deriving from
/// the *peer's* address would advertise the peer's IP as next-hop);
/// the legacy single peer keeps the historical derivation order.
fn peer_local_address(g: &DaemonConfig, p: &PeerSpec) -> Option<IpAddr> {
    let configured = p.local_address.as_ref().or(g.local_address.as_ref());
    if let Some(s) = configured {
        if let Ok(ip) = IpAddr::from_str(s) {
            return Some(ip);
        }
        // The configured string might be a `host:port` form (legacy).
        if let Some(ip) = transport_ip(s) {
            return Some(ip);
        }
        return None;
    }
    if g.explicit_peers {
        g.listen_addr.as_deref().and_then(transport_ip)
    } else {
        g.peer_addr
            .as_deref()
            .or(g.listen_addr.as_deref())
            .and_then(transport_ip)
    }
}

/// Match an inbound connection's source address to a configured peer
/// (explicit mode). Exactly one peer must claim the address.
fn match_inbound_peer(entries: &[PeerEntry], src: std::net::IpAddr) -> Result<&PeerEntry, String> {
    let src = match src {
        std::net::IpAddr::V4(v4) => IpAddr::V4(v4.octets()),
        std::net::IpAddr::V6(v6) => IpAddr::V6(v6.octets()),
    };
    let mut found: Option<&PeerEntry> = None;
    for e in entries {
        let Some(expected) = expected_peer_ip(&e.spec) else {
            continue;
        };
        if expected == src {
            if found.is_some() {
                return Err(format!("address {} is claimed by more than one peer", src));
            }
            found = Some(e);
        }
    }
    found.ok_or_else(|| format!("no configured peer matches {}", src))
}

/// The IP an inbound connection from this peer is expected to carry:
/// the explicit `address`, else the host part of `remote`.
fn expected_peer_ip(spec: &PeerSpec) -> Option<IpAddr> {
    spec.address
        .as_deref()
        .or(spec.remote.as_deref())
        .and_then(transport_ip)
}

/// Connect with the appropriate transport security:
/// - TCP auth (MD5/AO) + GTSM: connect_auth creates the socket and
///   signs the SYN; GTSM's outbound TTL is set on the returned
///   TcpStream via set_ttl. The min-TTL filter is listener-side only.
/// - GTSM only: connect_gtsm creates the socket with TTL set.
/// - Neither: plain connect.
///
/// The Err payload marks kernel-unsupported auth as fatal for this peer
/// (fail closed: the key was configured, running without it is worse
/// than not running the session).
fn connect_secure(
    sockaddr: std::net::SocketAddr,
    auth: &TcpAuth,
    gtsm: &Gtsm,
) -> Result<TcpStream, (String, bool)> {
    if !auth.is_none() {
        match lr_osroute::tcp_auth::connect_auth(sockaddr, auth, Duration::from_secs(5)) {
            Ok(s) => {
                if !gtsm.is_disabled() {
                    let _ = s.set_ttl(gtsm.outbound_ttl as u32);
                }
                Ok(s)
            }
            Err(e) => {
                if e.is_kernel_unsupported() {
                    Err((format!("session auth not supported by kernel: {e}"), true))
                } else {
                    Err((format!("{e}"), false))
                }
            }
        }
    } else if !gtsm.is_disabled() {
        match lr_osroute::gtsm::connect_gtsm(sockaddr, gtsm, Duration::from_secs(5)) {
            Ok(s) => Ok(s),
            Err(e) => {
                if e.is_kernel_unsupported() {
                    Err((format!("GTSM not supported by kernel: {e}"), true))
                } else {
                    Err((format!("{e}"), false))
                }
            }
        }
    } else {
        TcpStream::connect_timeout(&sockaddr, Duration::from_secs(5))
            .map_err(|e| (format!("{e}"), false))
    }
}

/// One outbound peer: connect, run the session until it drops, back
/// off, repeat — for the lifetime of the daemon.
fn spawn_connector(rt: &Arc<Runtime>, entry: &PeerEntry, live: Arc<AtomicUsize>) {
    let rt = Arc::clone(rt);
    let remote = entry.spec.remote.clone().expect("outbound peer has remote");
    let auth = entry.auth.clone();
    let gtsm = entry.gtsm;
    let handle = entry.handle;
    let label = entry.spec.label().to_string();
    let _ = thread::Builder::new()
        .name(format!("lr-connect-{}", label))
        .spawn(move || {
            let mut backoff_ms: u64 = 1_000;
            while rt.running.load(Ordering::Relaxed) {
                dispatch_signals(&rt);
                if !rt.running.load(Ordering::Relaxed) {
                    break;
                }
                let sockaddr = match resolve(&remote) {
                    Some(a) => a,
                    None => {
                        eprintln!("daemon: peer {}: cannot resolve {}", label, remote);
                        return;
                    }
                };
                println!("daemon: peer {}: connecting to {} ...", label, remote);
                match connect_secure(sockaddr, &auth, &gtsm) {
                    Ok(stream) => {
                        backoff_ms = 1_000;
                        let _ = stream.set_nodelay(true);
                        live.fetch_add(1, Ordering::Relaxed);
                        let result = run_peer_session(Arc::clone(&rt), stream, handle);
                        live.fetch_sub(1, Ordering::Relaxed);
                        if let Err(e) = result {
                            eprintln!("daemon: peer {}: session ended: {}", label, e);
                        }
                        if !rt.running.load(Ordering::Relaxed) {
                            break;
                        }
                        eprintln!("daemon: peer {}: reconnecting in {}ms", label, backoff_ms);
                        sleep_interruptible(&rt, Duration::from_millis(backoff_ms));
                        backoff_ms = (backoff_ms * 2).min(30_000);
                    }
                    Err((e, fatal)) => {
                        if fatal {
                            eprintln!("daemon: peer {}: {}", label, e);
                            return;
                        }
                        eprintln!(
                            "daemon: peer {}: connect failed ({}); retrying in {}ms",
                            label, e, backoff_ms
                        );
                        sleep_interruptible(&rt, Duration::from_millis(backoff_ms));
                        backoff_ms = (backoff_ms * 2).min(30_000);
                    }
                }
            }
        });
}

/// Drive one established TCP connection until it drops or we shut down.
fn run_peer_session(
    rt: Arc<Runtime>,
    mut stream: TcpStream,
    session: SessionHandle,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    {
        let mut r = rt.router.lock().unwrap();
        r.start_session(session)
            .map_err(|e| format!("start_session: {}", e))?;
    }
    let result = pump_session(&rt, &mut stream, session);
    // The transport is gone: drive the FSM to Idle and purge the routes
    // this session contributed (RFC 4271 §8.2.2). Event consumers (the
    // ticker thread) observe the resulting events.
    {
        let mut r = rt.router.lock().unwrap();
        r.close_session(session);
        // RFC 4271 §6.4: close a live session with a NOTIFICATION
        // (CEASE) rather than a bare FIN — close_session queues it, so
        // drain and flush it to the wire before the socket goes away.
        let out = r.drain_output(session);
        if !out.is_empty() {
            let _ = stream.write_all(&out);
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
    result
}

fn pump_session(
    rt: &Arc<Runtime>,
    stream: &mut TcpStream,
    session: SessionHandle,
) -> Result<(), String> {
    let router = &rt.router;
    let mut buf = [0u8; 8192];
    while rt.running.load(Ordering::Relaxed) {
        // Signals first: a shutdown must tear the session down cleanly
        // even while the peer is idle, and a reload can change what we
        // originate mid-session.
        dispatch_signals(rt);
        if !rt.running.load(Ordering::Relaxed) {
            break;
        }

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
            r.drain_output(session)
        };
        if !out.is_empty() {
            stream
                .write_all(&out)
                .map_err(|e| format!("write: {}", e))?;
        }
    }
    Ok(())
}

/// The ticker thread: sole consumer of router events. Drives the router
/// clock every 50 ms, logs every event, and (when enabled) mirrors the
/// Loc-RIB into the kernel FIB. Keeping event consumption on one thread
/// preserves Loc-RIB ordering across concurrently pumped sessions.
/// During shutdown it keeps draining until the live session threads
/// have flushed their close NOTIFICATIONs, so withdrawal events (and
/// their kernel route deletions) are not lost.
fn spawn_ticker(rt: &Arc<Runtime>, install_kernel: bool, live: Arc<AtomicUsize>) {
    let rt = Arc::clone(rt);
    thread::Builder::new()
        .name("lr-ticker".into())
        .spawn(move || {
            let mut os_table: Option<
                Box<dyn lr_osroute::OsRouteTable<Error = lr_osroute::OsRouteError>>,
            > = None;
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
            let start = WallClock::now();
            loop {
                let shutting_down = !rt.running.load(Ordering::Relaxed);
                if shutting_down && live.load(Ordering::Relaxed) == 0 {
                    break;
                }
                let now_ms = start.elapsed().as_millis() as u64;
                {
                    let mut r = rt.router.lock().unwrap();
                    r.tick(lr_core::time::Instant(now_ms));
                    let events = r.poll_events();
                    for ev in &events {
                        log_event(ev);
                    }
                    install_kernel_routes(&mut os_table, &events);
                }
                if shutting_down {
                    // Bounded shutdown cadence: the main thread exits the
                    // process after its grace period regardless.
                    thread::sleep(Duration::from_millis(10));
                } else {
                    thread::sleep(Duration::from_millis(50));
                }
            }
            // Final drain: the last events queued by closing sessions.
            {
                let mut r = rt.router.lock().unwrap();
                let events = r.poll_events();
                for ev in &events {
                    log_event(ev);
                }
                install_kernel_routes(&mut os_table, &events);
            }
        })
        .expect("spawn ticker thread");
}

/// Mirror Loc-RIB events into the kernel FIB (best-effort: a failed
/// install is logged by rtnetlink itself and retried on the next event).
fn install_kernel_routes(
    table: &mut Option<Box<dyn lr_osroute::OsRouteTable<Error = lr_osroute::OsRouteError>>>,
    events: &[RouterEvent],
) {
    let Some(table) = table else {
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

/// Babel daemon mode: run the Babel protocol over UDP on an IPv6
/// link-local address. This is the BIRD `babel` protocol equivalent —
/// Babel uses UDP multicast on port 6696, not TCP like BGP.
fn run_babel_daemon(cfg: &DaemonConfig) -> ExitCode {
    use std::net::UdpSocket;

    // Babel runs on IPv6 link-local by default (RFC 8966 §2.1). The
    // local address must be a link-local IPv6 address with a scope ID.
    let local_addr = cfg.local_address.as_deref().or(cfg.listen_addr.as_deref());
    let local_addr = match local_addr {
        Some(a) => a,
        None => {
            eprintln!("daemon: --protocol babel requires --local-address (IPv6 link-local)");
            return ExitCode::from(2);
        }
    };
    // Parse the local address. Accept both `fe80::1%eth0` and
    // `[fe80::1%eth0]:6696` forms.
    let local_ip: std::net::Ipv6Addr = match local_addr.parse() {
        Ok(ip) => ip,
        Err(_) => {
            // Try bracketed form.
            let trimmed = local_addr.trim_start_matches('[').trim_end_matches(']');
            match trimmed.split(':').next().unwrap_or("").parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("daemon: invalid IPv6 local address: {}", local_addr);
                    return ExitCode::from(2);
                }
            }
        }
    };
    let port = cfg.babel_port;
    let bind_addr = std::net::SocketAddr::new(std::net::IpAddr::V6(local_ip), port);
    let sock = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("daemon: babel bind {} failed: {}", bind_addr, e);
            return ExitCode::from(1);
        }
    };
    println!("daemon: babel listening on {}", bind_addr);

    // Join the Babel multicast group (ff02::1:6, RFC 8966 §2.1).
    let group: std::net::Ipv6Addr = cfg
        .babel_group
        .as_deref()
        .unwrap_or("ff02::1:6")
        .parse()
        .unwrap_or_else(|_| "ff02::1:6".parse().unwrap());
    // The interface index is derived from the scope ID of the bind
    // address. `Ipv6Addr` does not carry a scope ID, so we use 0
    // (the default interface) when the address has no scope.
    if let Err(e) = sock.join_multicast_v6(&group, 0) {
        eprintln!("daemon: babel multicast join failed: {}", e);
        // Non-fatal: the daemon can still receive unicast.
    }
    // Set the multicast hop limit to 255 (Babel requirement, RFC 8966
    // §2.1: "The hop limit MUST be set to 255").
    let _ = sock.set_multicast_loop_v6(false);
    let _ = sock.set_ttl(255);

    // Set up the router with a Babel session.
    let router = Arc::new(Mutex::new(DefaultRouter::new()));
    let babel_local = lr_core::addr::IpAddr::V6(local_ip.octets());
    let sc = SessionConfig::babel(babel_local);
    let h = {
        let mut r = router.lock().unwrap();
        match r.add_session(sc) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("daemon: babel add_session failed: {}", e);
                return ExitCode::from(1);
            }
        }
    };
    {
        let mut r = router.lock().unwrap();
        r.start_session(h).unwrap();
    }

    // Signal handling.
    if let Err(sig) = signal::init() {
        eprintln!("daemon: cannot install signal handlers (signal {})", sig);
        return ExitCode::from(1);
    }

    let running = Arc::new(AtomicBool::new(true));
    let runtime = Arc::new(Runtime {
        reload: Arc::new({
            let router = Arc::clone(&router);
            move || reload_config(None, &router, &Arc::new(Mutex::new(Vec::new())))
        }),
        router: Arc::clone(&router),
        running: Arc::clone(&running),
    });
    if let Err(e) = spawn_api(cfg, &runtime) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }

    // Ticker thread.
    {
        let router = Arc::clone(&runtime.router);
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

    // Non-blocking read loop.
    let _ = sock.set_nonblocking(true);
    let mut buf = [0u8; 65535];
    while running.load(Ordering::Relaxed) {
        dispatch_signals(&runtime);
        if !running.load(Ordering::Relaxed) {
            break;
        }
        // Read inbound.
        match sock.recv_from(&mut buf) {
            Ok((n, _peer)) => {
                let mut r = router.lock().unwrap();
                let _ = r.feed_input(h, &buf[..n]);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("daemon: babel recv failed: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
        // Drain outbound.
        let out = {
            let mut r = router.lock().unwrap();
            r.drain_output(h)
        };
        if !out.is_empty() {
            // Send to the Babel multicast group.
            let dest = std::net::SocketAddr::new(std::net::IpAddr::V6(group), port);
            let _ = sock.send_to(&out, dest);
        }
    }
    println!("daemon: babel shutdown complete");
    ExitCode::SUCCESS
}

fn resolve(addr: &str) -> Option<std::net::SocketAddr> {
    // `to_socket_addrs` accepts both `host:port` and `[v6]:port` (incl.
    // scope ids like `[fe80::1%eth0]:179`). Try the verbatim form first;
    // for bare IPv6 hosts without brackets, attempt `[host]:179` so a
    // user passing `--peer fe80::1%eth0` still gets a usable address.
    if let Ok(mut it) = addr.to_socket_addrs() {
        if let Some(a) = it.next() {
            return Some(a);
        }
    }
    if !addr.starts_with('[') && addr.contains("::") {
        let bracketed = format!("[{}]", addr);
        if let Some(port) = bracketed.rfind(']') {
            let host = &bracketed[1..port];
            // Default to BGP port 179 when no port was specified.
            let port_str = if bracketed[port..].starts_with("]:") {
                &bracketed[port + 2..]
            } else {
                "179"
            };
            if let Ok(port) = port_str.parse::<u16>() {
                use std::net::Ipv6Addr;
                if let Ok(v6) = host.parse::<Ipv6Addr>() {
                    return Some(std::net::SocketAddr::new(v6.into(), port));
                }
            }
        }
    }
    None
}

/// Extract the IP component of a `host:port` or `[v6]:port` string.
/// Returns `None` when the address cannot be parsed — the caller treats
/// this as "no derivable local address" and falls back to other sources.
fn transport_ip(addr: &str) -> Option<IpAddr> {
    // Bracketed IPv6 form: `[v6]:port` or `[v6]`.
    if addr.starts_with('[') {
        let end = addr.find(']')?;
        let host = &addr[1..end];
        return IpAddr::from_str(host).ok();
    }
    // Plain `host:port` — last colon separates port (IPv4 or hostname).
    // For a bare IPv6 without brackets this is ambiguous; the resolve()
    // helper handles that path separately.
    if let Some(idx) = addr.rfind(':') {
        let host = &addr[..idx];
        return IpAddr::from_str(host).ok();
    }
    IpAddr::from_str(addr).ok()
}

/// Pick the NLRI family for a `--network` prefix based on its address
/// family. IPv4 prefixes → IPv4 unicast (the historical default); IPv6
/// prefixes → IPv6 unicast (requires `--mp-family ipv6-unicast` on the
/// session, otherwise the peer will reject the UPDATE).
fn originate_family_for(p: Prefix) -> (Prefix, NlriFamily) {
    let family = match p.addr {
        IpAddr::V4(_) => NlriFamily::IPV4_UNICAST,
        IpAddr::V6(_) => NlriFamily::IPV6_UNICAST,
    };
    (p, family)
}

/// Shared daemon state threaded through the I/O loops.
struct Runtime {
    router: Arc<Mutex<DefaultRouter>>,
    running: Arc<AtomicBool>,
    /// Re-apply the configuration file (SIGHUP / API `reload`).
    reload: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
}

/// Act on every pending signal. SIGTERM/SIGINT trigger a graceful stop
/// (sessions are closed with a NOTIFICATION before the FIN); SIGHUP
/// reloads the configuration file. Safe to call from any thread —
/// exactly one caller wins the atomic take.
fn dispatch_signals(rt: &Runtime) {
    while let Some(sig) = signal::take_pending() {
        match sig {
            signal::SIGTERM | signal::SIGINT => {
                println!("daemon: signal {} received — shutting down", sig);
                rt.running.store(false, Ordering::Relaxed);
            }
            signal::SIGHUP => {
                println!("daemon: SIGHUP received — reloading configuration");
                for line in (rt.reload)() {
                    println!("daemon: {}", line);
                }
            }
            _ => {}
        }
    }
}

/// Sleep in small slices so signals (shutdown / reload) are noticed
/// within ~100 ms even during long reconnect backoffs.
fn sleep_interruptible(rt: &Runtime, total: Duration) {
    let mut remaining = total;
    while !remaining.is_zero() && rt.running.load(Ordering::Relaxed) {
        let chunk = remaining.min(Duration::from_millis(100));
        thread::sleep(chunk);
        remaining -= chunk;
        dispatch_signals(rt);
    }
}

/// Drop privileges when `--user` is configured; a no-op otherwise.
/// A failed drop is fatal — never continue as root by accident.
fn do_privdrop(cfg: &DaemonConfig) -> Result<(), String> {
    if let Some(user) = &cfg.user {
        privdrop::drop_privileges(user, cfg.group.as_deref())?;
        println!("daemon: privileges dropped ({})", privdrop::identity());
    }
    Ok(())
}

/// Start the runtime API socket when `--api-socket` is configured.
/// Creation failure is fatal: the operator asked for a management plane;
/// running without it silently is not an option.
fn spawn_api(cfg: &DaemonConfig, rt: &Arc<Runtime>) -> Result<(), String> {
    let Some(path) = &cfg.api_socket else {
        return Ok(());
    };
    let ctx = api::ApiContext {
        info: api::DaemonInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            local_as: cfg.local_as,
            peer_as: cfg.peer_as,
            router_id: cfg.router_id.clone(),
            config_path: cfg.config_path.clone(),
        },
        router: Arc::clone(&rt.router),
        running: Arc::clone(&rt.running),
        reload: Box::new({
            let rt = Arc::clone(rt);
            move || (rt.reload)()
        }),
    };
    api::spawn(path, ctx)
        .map(|p| println!("daemon: runtime API on {}", p))
        .map_err(|e| format!("runtime API: {e}"))
}

/// Re-apply the configuration file: diff the `networks` list against the
/// currently originated set and apply add/remove. Identity and transport
/// auth changes cannot be applied to a live session — they are reported
/// so the operator knows a restart is required. A parse or I/O error
/// keeps the current configuration running (reload must never crash or
/// half-apply).
fn reload_config(
    path: Option<&str>,
    router: &Arc<Mutex<DefaultRouter>>,
    current_networks: &Arc<Mutex<Vec<String>>>,
) -> Vec<String> {
    let Some(path) = path else {
        return vec!["reload: no config file in use; nothing to reload".into()];
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            return vec![format!(
                "reload: cannot read {}: {} (keeping current config)",
                path, e
            )]
        }
    };
    let mut fresh = DaemonConfig::default();
    if let Err(e) = daemon_config::parse_toml_subset(&text, &mut fresh) {
        return vec![format!("reload: {} (keeping current config)", e)];
    }
    let mut lines: Vec<String> = fresh
        .warnings
        .iter()
        .map(|w| format!("reload: config warning: {}", w))
        .collect();

    let old = current_networks.lock().unwrap().clone();
    let new = fresh.networks.clone();
    {
        let mut r = router.lock().unwrap();
        for net in new.iter().filter(|n| !old.contains(n)) {
            match Prefix::from_str(net) {
                Ok(p) => {
                    let (p, family) = originate_family_for(p);
                    r.originate_family(p, family, None);
                    lines.push(format!("reload: originating {}", p));
                }
                Err(_) => lines.push(format!("reload: invalid network '{}' skipped", net)),
            }
        }
        for net in old.iter().filter(|n| !new.contains(n)) {
            if let Ok(p) = Prefix::from_str(net) {
                let (p, family) = originate_family_for(p);
                let key = lr_core::rib::RouteKey::new(p, family);
                r.unoriginate(&key);
                lines.push(format!("reload: unoriginating {}", p));
            }
        }
    }
    *current_networks.lock().unwrap() = new;
    if lines.is_empty() {
        lines.push("reload: no network changes".into());
    }
    lines.push("reload: note: AS, router-id, peer and auth changes require a restart".into());
    lines
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

fn wait_for_shutdown(rt: &Runtime) {
    println!("daemon: waiting for SIGTERM / SIGINT");
    while rt.running.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
        dispatch_signals(rt);
    }
}
