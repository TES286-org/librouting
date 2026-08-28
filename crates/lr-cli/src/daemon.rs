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
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_osroute::tcp_auth::{TcpAoAlgorithm, TcpAoKey, TcpAuth};
use lr_router::{DefaultRouter, RouterEvent, RouterInstance, SessionConfig, SessionHandle};

mod api;
mod privdrop;
mod signal;

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
    /// RFC 2385 TCP MD5 shared secret for the BGP session.
    md5_key: Option<String>,
    /// RFC 5925 TCP-AO keys as "id:secret" pairs (id = KeyID, used as
    /// both SendID and RecvID in the reference daemon).
    tcp_ao_keys: Vec<String>,
    /// TCP-AO MAC algorithm ("hmac-sha1" or "cmac-aes").
    tcp_ao_algorithm: String,
    /// TCP-AO MAC length in bytes (0 = algorithm default).
    tcp_ao_maclen: u8,
    /// Drop privileges to this user (name or uid) after binding.
    user: Option<String>,
    /// Drop privileges to this group (name or gid); default: the user's
    /// login group.
    group: Option<String>,
    /// Runtime API socket path (Unix domain socket, 0600).
    api_socket: Option<String>,
    /// Configuration file the daemon was started with (reload source).
    config_path: Option<String>,
    /// RFC 7911 Add-Path: advertise the capability (send + receive) for
    /// the session's families. Requires peer support to take effect.
    add_path: bool,
    /// RFC 7911: how many paths per prefix the decision process keeps in
    /// Loc-RIB and advertises to Add-Path peers.
    add_path_max_paths: u32,
    /// RFC 4760 MP-BGP families advertised in OPEN, beyond the default
    /// IPv4 unicast. Each entry is a name (`ipv4-unicast`, `ipv6-unicast`).
    /// Empty defaults to IPv4 unicast only (the historical daemon default).
    mp_families: Vec<String>,
    /// RFC 5549 Extended Next-Hop: advertise the (1,1,2) tuple so IPv4
    /// NLRI can be resolved over an IPv6 next-hop. Requires peer support.
    extended_next_hop: bool,
    /// Local IPv6 source address for next-hop-self egress over IPv6 NLRI
    /// or RFC 5549 ENH. Falls back to the IPv4 `local_address` field when
    /// unset and the session is IPv4.
    local_address_v6: Option<String>,
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
         --md5-key SECRET         RFC 2385 TCP MD5 session authentication\n  \
         --tcp-ao-key ID:SECRET   RFC 5925 TCP-AO key (repeatable; first key\n  \
         is Current/RNext; Linux 6.7+)\n  \
         --tcp-ao-alg NAME        TCP-AO MAC algorithm: hmac-sha1 (default)\n  \
         or cmac-aes\n  \
         --tcp-ao-maclen N        TCP-AO MAC length in bytes (default 12)\n  \
         --install-kernel-routes  Install best routes into the OS FIB (root)\n  \
         --user USER|UID          Drop privileges to USER after binding\n  \
         (Unix; default group: the user's login group)\n  \
         --group GROUP|GID        Override the privilege-drop group\n  \
         --api-socket PATH        Runtime API on a Unix stream socket\n  \
         (status / sessions / routes / reload / shutdown)\n  \
         --mp-family NAME         MP-BGP family to advertise (repeatable;\n  \
         ipv4-unicast, ipv6-unicast). Default: ipv4-unicast only.\n  \
         --extended-next-hop      Advertise RFC 5549 (1,1,2) — IPv4 NLRI over\n  \
         an IPv6 next-hop. Requires --mp-family ipv6-unicast or a v6 transport.\n  \
         --local-address-v6 ADDR  Local IPv6 source for next-hop-self / ENH egress\n  \
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
            "bgp.add_path" => cfg.add_path = value == "true",
            "bgp.add_path_max_paths" => cfg.add_path_max_paths = value.parse().unwrap_or(6),
            "bgp.extended_next_hop" => cfg.extended_next_hop = value == "true",
            "bgp.local_address_v6" => cfg.local_address_v6 = Some(value.to_string()),
            "bgp.mp_families" => {
                // Comma-separated array: ["ipv4-unicast", "ipv6-unicast"]
                let inner = value.trim_start_matches('[').trim_end_matches(']');
                for item in inner.split(',') {
                    let item = item.trim().trim_matches('"');
                    if !item.is_empty() {
                        cfg.mp_families.push(item.to_string());
                    }
                }
            }
            "bgp.md5_key" => cfg.md5_key = Some(value.to_string()),
            "bgp.tcp_ao_keys" => {
                // Comma-separated array: ["1:secret", "2:other"]
                let inner = value.trim_start_matches('[').trim_end_matches(']');
                for item in inner.split(',') {
                    let item = item.trim().trim_matches('"');
                    if !item.is_empty() {
                        cfg.tcp_ao_keys.push(item.to_string());
                    }
                }
            }
            "bgp.tcp_ao_algorithm" => cfg.tcp_ao_algorithm = value.to_string(),
            "bgp.tcp_ao_maclen" => cfg.tcp_ao_maclen = value.parse().unwrap_or(0),
            "user" => cfg.user = Some(value.to_string()),
            "group" => cfg.group = Some(value.to_string()),
            "api_socket" => cfg.api_socket = Some(value.to_string()),
            "networks" | "bgp.networks" => {
                // Comma-separated array: ["a", "b"] (top-level `networks`
                // or inside [bgp] — the shipped template uses the latter).
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
        tcp_ao_algorithm: "hmac-sha1".to_string(),
        add_path_max_paths: 6,
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
            "--md5-key" if i + 1 < args.len() => {
                cfg.md5_key = Some(args[i + 1].clone());
                i += 2;
            }
            "--tcp-ao-key" if i + 1 < args.len() => {
                cfg.tcp_ao_keys.push(args[i + 1].clone());
                i += 2;
            }
            "--tcp-ao-alg" if i + 1 < args.len() => {
                cfg.tcp_ao_algorithm = args[i + 1].clone();
                i += 2;
            }
            "--tcp-ao-maclen" if i + 1 < args.len() => {
                cfg.tcp_ao_maclen = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--install-kernel-routes" => {
                cfg.install_kernel = true;
                i += 1;
            }
            "--add-path" => {
                cfg.add_path = true;
                i += 1;
            }
            "--add-path-max" if i + 1 < args.len() => {
                cfg.add_path_max_paths = args[i + 1].parse().unwrap_or(6);
                i += 2;
            }
            "--mp-family" if i + 1 < args.len() => {
                cfg.mp_families.push(args[i + 1].clone());
                i += 2;
            }
            "--extended-next-hop" => {
                cfg.extended_next_hop = true;
                i += 1;
            }
            "--local-address-v6" if i + 1 < args.len() => {
                cfg.local_address_v6 = Some(args[i + 1].clone());
                i += 2;
            }
            "--user" if i + 1 < args.len() => {
                cfg.user = Some(args[i + 1].clone());
                i += 2;
            }
            "--group" if i + 1 < args.len() => {
                cfg.group = Some(args[i + 1].clone());
                i += 2;
            }
            "--api-socket" if i + 1 < args.len() => {
                cfg.api_socket = Some(args[i + 1].clone());
                i += 2;
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
        // Remember the file so `status` can show it and SIGHUP / `reload`
        // can re-apply it.
        cfg.config_path = Some(path);
    }
    Ok(cfg)
}

/// Builds the transport authentication configuration from CLI flags / TOML.
/// MD5 and TCP-AO are mutually exclusive (the kernel forbids mixing them
/// on one socket anyway: `TCP_AO_INFO.ao_required` fails with EKEYREJECTED
/// when MD5 keys are present).
fn build_tcp_auth(cfg: &DaemonConfig) -> Result<TcpAuth, String> {
    if let Some(md5) = &cfg.md5_key {
        if !cfg.tcp_ao_keys.is_empty() {
            return Err("--md5-key and --tcp-ao-key are mutually exclusive".to_string());
        }
        return TcpAuth::md5(md5.as_bytes().to_vec()).map_err(|e| format!("bad --md5-key: {e}"));
    }
    if cfg.tcp_ao_keys.is_empty() {
        return Ok(TcpAuth::None);
    }
    let algorithm = TcpAoAlgorithm::parse(&cfg.tcp_ao_algorithm).ok_or_else(|| {
        format!(
            "unknown --tcp-ao-alg '{}' (use hmac-sha1 or cmac-aes)",
            cfg.tcp_ao_algorithm
        )
    })?;
    let mut keys = Vec::with_capacity(cfg.tcp_ao_keys.len());
    for raw in &cfg.tcp_ao_keys {
        // Format: "id:secret" — the id is used as both SendID and RecvID.
        let (id, secret) = raw.split_once(':').ok_or_else(|| {
            format!("bad --tcp-ao-key '{raw}': expected ID:SECRET (e.g. 1:alpha)")
        })?;
        let id: u8 = id
            .trim()
            .parse()
            .map_err(|_| format!("bad --tcp-ao-key '{raw}': ID must be 0-255"))?;
        keys.push(
            TcpAoKey::symmetric(id, secret.as_bytes().to_vec())
                .map_err(|e| format!("bad --tcp-ao-key '{raw}': {e}"))?,
        );
    }
    TcpAuth::tcp_ao(keys, algorithm, cfg.tcp_ao_maclen)
        .map_err(|e| format!("bad tcp-ao configuration: {e}"))
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
    // Transport authentication (RFC 2385 / RFC 5925). MD5 and TCP-AO are
    // mutually exclusive — a single TcpAuth value carries the choice.
    let tcp_auth = match build_tcp_auth(&cfg) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::from(2);
        }
    };
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

    let router = Arc::new(Mutex::new(DefaultRouter::new()));
    {
        let mut r = router.lock().unwrap();
        // RFC 7911 Add-Path: cap how many paths per prefix survive the
        // decision process (and reach Add-Path peers).
        r.set_add_path_max_paths(cfg.add_path_max_paths.max(1) as usize);
        let mut sc = SessionConfig::bgp(Asn(cfg.local_as), Asn(cfg.peer_as), rid);
        sc.hold_time = cfg.hold_time;
        if cfg.add_path {
            sc = sc.with_add_path();
        }
        // RFC 4760 MP-BGP: build the family list from --mp-family entries.
        // Empty config keeps the SessionConfig::bgp() default (IPv4 unicast),
        // preserving the historical daemon behaviour. `ipv4-unicast` and
        // `ipv6-unicast` are recognised; unknown names are logged and dropped.
        if !cfg.mp_families.is_empty() {
            let mut families = Vec::new();
            for name in &cfg.mp_families {
                match name.as_str() {
                    "ipv4-unicast" => families.push(NlriFamily::IPV4_UNICAST),
                    "ipv6-unicast" => families.push(NlriFamily::IPV6_UNICAST),
                    other => eprintln!("daemon: unknown --mp-family '{}' (skipped)", other),
                }
            }
            if !families.is_empty() {
                sc = sc.with_mp_families(families);
            }
        }
        // RFC 5549 Extended Next-Hop. Advertise the canonical (1,1,2) tuple
        // so an IPv6 transport can carry IPv4 NLRI without an IPv4 next-hop.
        if cfg.extended_next_hop {
            sc = sc.with_extended_next_hop();
        }
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
        // Local address for next-hop-self egress. The IPv4 source derives
        // from --local-address or the peer/listen socket's IP; the IPv6
        // source (for IPv6 NLRI / RFC 5549 ENH egress) is taken verbatim
        // from --local-address-v6. Without a relevant source we leave the
        // session's local_address unset and rely on the route's existing
        // NEXT_HOP (correct for iBGP; eBGP without a source skips rewrite).
        if let Some(ip) = parse_local_address(&cfg.local_address, &cfg.peer_addr, &cfg.listen_addr)
        {
            sc = sc.with_local_address(ip);
        }
        // When the IPv6 source differs from the IPv4 one (the common case
        // for dual-stack hosts), prefer it for IPv6 / ENH egress. The
        // router layer accepts only one local_address today, so we pick
        // the v6 source when the configured transport is IPv6 — otherwise
        // the v4 source above already covers IPv4 NLRI.
        if let Some(v6) = &cfg.local_address_v6 {
            if let Ok(ip) = IpAddr::from_str(v6) {
                if matches!(ip, IpAddr::V6(_)) {
                    // When the transport is IPv6 (peer_addr or listen_addr
                    // resolves to a v6 socket), the v6 source is the right
                    // next-hop-self for any family this session speaks.
                    let transport_is_v6 = cfg
                        .peer_addr
                        .as_deref()
                        .or(cfg.listen_addr.as_deref())
                        .and_then(transport_ip)
                        .map(|ip| matches!(ip, IpAddr::V6(_)))
                        .unwrap_or(false);
                    if transport_is_v6 {
                        sc = sc.with_local_address(ip);
                    } else if cfg.extended_next_hop {
                        // ENH egress needs the v6 source even when the
                        // transport is v4 — the peer resolves IPv4 NLRI
                        // over the v6 next-hop.
                        sc = sc.with_local_address(ip);
                    }
                }
            } else {
                eprintln!("daemon: invalid --local-address-v6 '{}'", v6);
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
    if cfg.add_path {
        println!(
            "  add-path:    enabled (max {} paths/prefix)",
            cfg.add_path_max_paths.max(1)
        );
    }
    println!("  auth:        {}", tcp_auth.describe());
    println!("  platform:    {}", lr_osroute::PLATFORM_NAME);

    // Locally originated networks. The string list is kept around so
    // reloads can diff old vs new (SIGHUP / runtime API `reload`).
    let current_networks = Arc::new(Mutex::new(cfg.networks.clone()));
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

    // --- Ticker thread: pump the router clock every 50 ms. ---
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
        // Fail closed: if session authentication is configured but cannot
        // be armed on the listener (missing kernel support, bad key), stop
        // instead of accepting unauthenticated connections.
        if let Err(e) = lr_osroute::tcp_auth::arm_listener(&listener, &tcp_auth) {
            eprintln!("daemon: session auth arming failed: {}", e);
            return ExitCode::from(1);
        }
        if !tcp_auth.is_none() {
            println!("daemon: session auth armed ({})", tcp_auth.describe());
        }
        // Privileged work is done: drop root before touching any network
        // input, then create the management socket as the reduced user.
        if let Err(e) = do_privdrop(&cfg) {
            eprintln!("daemon: {}", e);
            return ExitCode::from(1);
        }
        if let Err(e) = spawn_api(&cfg, &runtime) {
            eprintln!("daemon: {}", e);
            return ExitCode::from(1);
        }
        // Non-blocking accept: the poll cadence is what lets the main
        // thread notice SIGTERM/SIGINT (graceful stop) and SIGHUP
        // (reload) while idle between connections.
        if let Err(e) = listener.set_nonblocking(true) {
            eprintln!("daemon: cannot set listener non-blocking: {}", e);
            return ExitCode::from(1);
        }
        loop {
            dispatch_signals(&runtime);
            if !running.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((s, _)) => {
                    let peer = s
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "?".into());
                    println!("daemon: inbound connection from {}", peer);
                    let _ = s.set_nodelay(true);
                    if let Err(e) = run_session(&runtime, s, session, cfg.install_kernel) {
                        eprintln!("daemon: session ended: {}", e);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    eprintln!("daemon: accept failed: {}", e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        println!("daemon: shutdown complete");
        return ExitCode::SUCCESS;
    }

    let peer_addr = match cfg.peer_addr.clone() {
        Some(p) => p,
        None => {
            // Idle mode: no sockets beyond the management plane.
            if let Err(e) = do_privdrop(&cfg) {
                eprintln!("daemon: {}", e);
                return ExitCode::from(1);
            }
            if let Err(e) = spawn_api(&cfg, &runtime) {
                eprintln!("daemon: {}", e);
                return ExitCode::from(1);
            }
            println!("daemon: no --peer/--listen given; idling (tick loop only)");
            wait_for_shutdown(&runtime);
            return ExitCode::SUCCESS;
        }
    };

    // ---- Outbound mode: connect (with reconnect + backoff). ----
    // No privileged resource is needed (ephemeral source port; auth keys
    // are plain setsockopt) — drop before the first connect attempt.
    if let Err(e) = do_privdrop(&cfg) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }
    if let Err(e) = spawn_api(&cfg, &runtime) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }
    let mut backoff_ms: u64 = 1_000;

    while running.load(Ordering::Relaxed) {
        dispatch_signals(&runtime);
        if !running.load(Ordering::Relaxed) {
            break;
        }
        let sockaddr = match resolve(&peer_addr) {
            Some(a) => a,
            None => {
                eprintln!("daemon: cannot resolve {}", peer_addr);
                return ExitCode::from(1);
            }
        };
        println!("daemon: connecting to {} ...", peer_addr);
        // With authentication configured the raw-socket path installs the
        // keys before connect(2) so the SYN itself is signed (RFC 2385
        // §2 / RFC 5925 §3.1).
        let stream =
            match lr_osroute::tcp_auth::connect_auth(sockaddr, &tcp_auth, Duration::from_secs(5)) {
                Ok(s) => s,
                Err(e) => {
                    if e.is_kernel_unsupported() {
                        // Permanent condition (e.g. TCP-AO on Linux < 6.7):
                        // retrying cannot help, fail closed.
                        eprintln!("daemon: session auth not supported by kernel: {}", e);
                        return ExitCode::from(1);
                    }
                    eprintln!(
                        "daemon: connect failed ({}); retrying in {}ms",
                        e, backoff_ms
                    );
                    sleep_interruptible(&runtime, Duration::from_millis(backoff_ms));
                    backoff_ms = (backoff_ms * 2).min(30_000);
                    continue;
                }
            };
        backoff_ms = 1_000;
        let _ = stream.set_nodelay(true);
        match run_session(&runtime, stream, session, cfg.install_kernel) {
            Ok(()) => break,
            Err(e) => {
                eprintln!("daemon: session ended: {}", e);
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                eprintln!("daemon: reconnecting in {}ms", backoff_ms);
                sleep_interruptible(&runtime, Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(30_000);
            }
        }
    }

    println!("daemon: shutdown complete");
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

/// Resolve the configured local source address for next-hop-self.
/// Priority: explicit `--local-address` → derived from peer/listen addr.
/// Returns `None` when nothing usable was configured.
fn parse_local_address(
    configured: &Option<String>,
    peer_addr: &Option<String>,
    listen_addr: &Option<String>,
) -> Option<IpAddr> {
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
    peer_addr
        .as_deref()
        .or(listen_addr.as_deref())
        .and_then(transport_ip)
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
/// reloads the configuration file.
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
    if let Err(e) = parse_toml_subset(&text, &mut fresh) {
        return vec![format!("reload: {} (keeping current config)", e)];
    }

    let old = current_networks.lock().unwrap().clone();
    let new = fresh.networks.clone();
    let mut lines = Vec::new();
    {
        let mut r = router.lock().unwrap();
        for net in new.iter().filter(|n| !old.contains(n)) {
            match Prefix::from_str(net) {
                Ok(p) => {
                    r.originate(p, None);
                    lines.push(format!("reload: originating {}", p));
                }
                Err(_) => lines.push(format!("reload: invalid network '{}' skipped", net)),
            }
        }
        for net in old.iter().filter(|n| !new.contains(n)) {
            if let Ok(p) = Prefix::from_str(net) {
                let key = lr_core::rib::RouteKey::new(p, lr_core::nlri::NlriFamily::IPV4_UNICAST);
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

/// Drive one established TCP connection until it drops or we shut down.
fn run_session(
    rt: &Runtime,
    mut stream: TcpStream,
    session: SessionHandle,
    install_kernel: bool,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    {
        let mut r = rt.router.lock().unwrap();
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
    let result = pump_session(rt, &mut stream, session, &mut os_table);
    // The transport is gone: drive the FSM to Idle and purge the routes
    // this session contributed (RFC 4271 §8.2.2).
    {
        let mut r = rt.router.lock().unwrap();
        r.close_session(session);
        for ev in r.poll_events() {
            log_event(&ev);
        }
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
    rt: &Runtime,
    stream: &mut TcpStream,
    session: SessionHandle,
    os_table: &mut Option<Box<dyn lr_osroute::OsRouteTable<Error = lr_osroute::OsRouteError>>>,
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

fn wait_for_shutdown(rt: &Runtime) {
    println!("daemon: waiting for SIGTERM / SIGINT");
    while rt.running.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
        dispatch_signals(rt);
    }
    println!("daemon: shutdown complete");
}
