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
use daemon_multi::{EngineHost, EngineReport};
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_osroute::gtsm::Gtsm;
use lr_osroute::tcp_auth::{TcpAoAlgorithm, TcpAoKey, TcpAuth};
use lr_router::{DefaultRouter, RouterEvent, RouterInstance, SessionConfig, SessionHandle};
#[cfg(target_os = "linux")]
use std::collections::HashMap;

mod api;
mod compat;
mod daemon_bfd;
mod daemon_config;
mod daemon_ldp;
mod daemon_multi;
mod daemon_ospf;
mod daemon_ospf3;
mod daemon_policy;
mod daemon_rpki;
mod privdrop;
mod signal;
mod translate;
mod yang;

use daemon_bfd::BfdFlags;
use daemon_config::{DaemonConfig, PeerSpec};

fn print_usage() {
    println!(
        "lr-daemon — reference librouting BGP daemon\n\n\
         USAGE:\n  \
         lr-daemon --local-as AS --peer-as AS --router-id A.B.C.D \
         [--peer ADDR:PORT]... [--listen ADDR:PORT] [--network PREFIX]...\n         \
         [--hold-time SEC]\n         \
         lr-daemon --config daemon.toml [--install-kernel-routes]\n         \
         lr-daemon --config bird.conf|frr.conf (the dialect is\n         \
         auto-detected; --config-dialect bird|frr|toml forces one)\n         \
         lr-daemon translate <bird|frr> <config-file>\n\n\
         lr-daemon yang render <config-file> [--model babel|keychain|all]\n\n\
         SUBCOMMANDS:\n  \
         translate bird|frr FILE  Best-effort conversion of a BIRD 2 or\n  \
         FRR BGP config into lr daemon TOML (unmappable lines are kept\n  \
         as `# UNMAPPED:` comments; review before use)\n  \
         yang render FILE   Render the Babel subset of a daemon TOML\n  \
         config as XML instance data for the YANG models in yang/\n  \
         (RFC 9647 ietf-babel, RFC 8177 ietf-key-chain; NETCONF-style\n  \
         <config> wrapper with --model all, the default)\n\n\
         OPTIONS:\n  \
         --config PATH            Load configuration; the dialect (lr\n  \
         TOML, BIRD 2, FRR) is auto-detected, so a BIRD or FRR file\n  \
         runs directly in the compatible form (see docs/COMPAT.md)\n  \
         --config-dialect D       Force the config dialect: bird | frr |\n  \
         toml (BIRD/FRR files support the lr: comment directives as\n  \
         the lr-specific extension channel)\n  \
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
         --rpki-cache ADDR:PORT   RPKI-RTR cache (RFC 8210, TCP 8282);\n  \
         spawns the RTR client thread and syncs ROAs into the live\n  \
         table (see also [bgp.rpki] in the TOML config)\n  \
         --rpki-refresh SEC       Initial refresh interval (default 3600;\n  \
         a v1+ cache overrides from End-of-Data)\n  \
         --rpki-retry SEC         Initial retry interval (default 600)\n  \
         --rpki-expire SEC        Initial expire interval (default 7200;\n  \
         on expiry the RTR-sourced ROAs are withdrawn)\n  \
         --max-prefixes N         Per-peer maximum-prefix limit\n  \
         --max-prefix-action A    warn (default) | teardown | restart\n  \
         --max-prefix-threshold P Early-warning percentage (default 75)\n  \
         --ebgp-policy MODE       rfc8212 (default) | accept-all — default\n  \
         eBGP route behavior for peers without import/export\n  \
         route-maps (RFC 8212: deny-in/deny-out vs legacy accept)\n  \
         --enforce-first-as        Reject eBGP UPDATEs whose leftmost AS_PATH\n  \
         AS is not the peer's AS (FRR `bgp enforce-first-as`)\n  \
         --no-enforce-first-as     Disable the check (default)\n  \
         --bestpath-compare-routerid  Use lowest BGP IDENTIFIER as the\n  \
         best-path tiebreaker (RFC 5004 deterministic, default)\n  \
         --no-bestpath-compare-routerid  Fall back to oldest-route-wins\n  \
         (FRR default)\n  \
         --default-ipv4-unicast  Activate IPv4 unicast for every peer by\n  \
         default (FRR `bgp default ipv4-unicast`, the default)\n  \
         --no-default-ipv4-unicast  Require explicit per-peer activation\n  \
         (FRR `no bgp default ipv4-unicast`)\n  \
         --allow-local-as [N]     Admit the local AS in a received AS_PATH\n  \
         up to N times (FRR `allowas-in N`; default N=1)\n  \
         --allowas-any            Admit any number of local AS in the\n  \
         AS_PATH (FRR `allowas-any`)\n  \
         --soft-reconfig-inbound  Retain the pre-policy Adj-RIB-In for\n  \
         every peer (FRR `soft-reconfiguration inbound`)\n  \
         --no-soft-reconfig-inbound  Disable pre-policy retention (default)\n  \
         --bfd                    BFD fast-fail for the peer(s) (RFC 5880/\n  \
         5881): a BFD Down tears the BGP session immediately\n  \
         --bfd-multihop           RFC 5883 multihop BFD (UDP 4784, no TTL\n  \
         255 check)\n  \
         --bfd-min-tx-ms MS       BFD transmit interval (default 100)\n  \
         --bfd-min-rx-ms MS       BFD receive interval (default 100)\n  \
         --bfd-multiplier N       BFD detection multiplier (default 3)\n  \
         --protocol PROTO         One protocol or a set (repeatable, comma-\n  \
                                  separated): bgp (default) | babel | ospf |\n  \
                                  bmp | ldp. bgp, ospf and babel combine in\n  \
                                  one process (--protocol bgp,ospf,babel)\n  \
         --babel-group ADDR       Babel multicast group (ff02::1:6 v6, 224.0.0.111 v4)\n  \
         --babel-port PORT        Babel UDP port (6696)\n  \
         --babel-key SECRET       RFC 8967 MAC key (repeatable; one MAC per\n  \
                                  key per datagram, key-rotation safe)\n  \
         --babel-accept-unauthenticated\n  \
                                  RFC 8967 5 incremental deployment: sign\n  \
                                  outgoing but accept unsigned inbound\n  \
         --babel-no-pc-split      RFC 9467 3.1: single PC field instead of\n  \
                                  the recommended unicast/multicast split\n  \
         --babel-pc-window N      RFC 9467 3.2 window verification (0 = off)\n  \
         --ospf-interface NAME    OSPF interface (repeatable; needs root\n  \
         or a user/network namespace)\n  \
         --ospf-area ID           Area for --ospf-interface (default 0;\n  \
         integer or dotted quad)\n  \
         --ospf-hello-interval S  OSPF hello interval (default 10)\n  \
         --ospf-dead-interval S   OSPF dead interval (default 40)\n  \
         --ldp-transport ADDR     LDP transport address advertised in\n  \
                                  Hellos (default: first interface addr)\n  \
         --ldp-port PORT          LDP UDP/TCP port (646)\n  \
         --ldp-keepalive SEC      Session KeepAlive Time (default 15)\n  \
         --ldp-link-hold SEC      Link Hello hold time (default 15)\n  \
         --ldp-targeted-hold SEC  Targeted Hello hold time (default 45)\n  \
         --ldp-interface NAME     LDP link-discovery interface (repeatable)\n  \
         --ldp-targeted ADDR      Extended-discovery peer (repeatable)\n  \
         --ldp-bind PFX[=LABEL]   Advertise FEC binding (repeatable;\n  \
                                  LABEL auto-allocates from 16)\n  \
         --bmp-target ADDR:PORT  Mirror Peer Up/Down + Route Monitoring\n  \
         to a BMP monitoring station (RFC 7854)\n  \
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
    // `lr-daemon translate <dialect> <file>` — the W5.1 config
    // converter rides the daemon binary so it can reuse the daemon's
    // config schema (and round-trip test against the real parser).
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() >= 2 && argv[1] == "translate" {
        return translate::translate(&argv[2..]);
    }
    // `lr-daemon yang render <file>` — the W3.8 YANG surface rides the
    // daemon binary for the same reason: it renders the real config
    // schema into RFC 9647 / RFC 8177 XML instance data.
    if argv.len() >= 2 && argv[1] == "yang" {
        return yang::cmd_yang(&argv[2..]);
    }
    let mut cfg = match daemon_config::parse_args() {
        Ok(c) => c,
        Err(code) => {
            if code == ExitCode::SUCCESS || code == ExitCode::from(2) {
                print_usage();
            }
            return code;
        }
    };
    if let Err(e) = cfg.finalize() {
        eprintln!("error: {}", e);
        return ExitCode::from(2);
    }
    // rc.3: the protocol surface is a set. Fail closed on a typo'd or
    // degenerate value instead of silently running BGP (an all-comma
    // value names nothing).
    let protocol_set = cfg.protocol_set();
    if !cfg.protocol.split(',').any(|name| !name.trim().is_empty()) {
        eprintln!(
            "error: unknown --protocol '{}' (bgp | babel | ospf | bmp | ldp)",
            cfg.protocol
        );
        return ExitCode::from(2);
    }
    for name in &protocol_set {
        if !matches!(name.as_str(), "bgp" | "babel" | "ospf" | "bmp" | "ldp") {
            eprintln!(
                "error: unknown --protocol '{}' (bgp | babel | ospf | bmp | ldp)",
                name
            );
            return ExitCode::from(2);
        }
    }
    // Multi-protocol combinations (rc.3): bgp, ospf and babel run in
    // one process through the shared-router supervisor. bmp and ldp
    // stay standalone-only — fail closed instead of silently ignoring
    // the combination.
    if protocol_set.len() > 1 {
        for name in &protocol_set {
            if !matches!(name.as_str(), "bgp" | "ospf" | "babel") {
                eprintln!(
                    "error: --protocol {} cannot run in a combination \
                     (only bgp, ospf and babel combine)",
                    name
                );
                return ExitCode::from(2);
            }
        }
        // Every combination includes bgp or ospf, which need the
        // router-id (Babel alone is a single engine — classic path).
        if cfg.router_id.is_empty() {
            eprintln!("error: --router-id is required");
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
        if protocol_set.iter().any(|p| p == "bgp") && cfg.local_as == 0 {
            eprintln!("error: --local-as is required for the bgp engine");
            print_usage();
            return ExitCode::from(2);
        }
        return daemon_multi::run_multi_daemon(&cfg, rid, &protocol_set);
    }
    // Babel mode: short-circuit the BGP session setup and run the
    // Babel UDP transport loop instead. Babel derives its router-id from
    // the local address (RFC 8966 §3.3) — --router-id is not used.
    if protocol_set.first().is_some_and(|p| p == "babel") {
        return run_babel_daemon(&cfg, None);
    }
    if cfg.router_id.is_empty() {
        eprintln!("error: --router-id is required");
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
    // OSPF mode: raw-socket transport, dynamic per-neighbor sessions.
    if protocol_set.first().is_some_and(|p| p == "ospf") {
        if cfg.ospf_version == "v3" {
            return daemon_ospf3::run_ospf3_daemon(&cfg, rid, None);
        }
        return daemon_ospf::run_ospf_daemon(&cfg, rid, None);
    }
    // LDP mode: UDP discovery + TCP session transport around LdpEngine.
    if protocol_set.first().is_some_and(|p| p == "ldp") {
        return daemon_ldp::run_ldp_daemon(&cfg, rid);
    }
    // BMP collector mode: accept monitoring sessions from routers.
    if protocol_set.first().is_some_and(|p| p == "bmp") {
        return run_bmp_collector(&cfg, rid);
    }
    // BGP additionally needs the local AS.
    if cfg.local_as == 0 {
        eprintln!("error: --local-as is required");
        print_usage();
        return ExitCode::from(2);
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
    run_bgp_daemon(&cfg, rid, None)
}

/// One configured BGP peer: its router session(s), transport security
/// and the busy flag serialising inbound connections on the session.
struct PeerEntry {
    spec: PeerSpec,
    /// Primary session. For bidirectional peers (both `remote` and
    /// `address`) this carries the OUTBOUND transport (locally
    /// initiated); unidirectional peers use it for their single
    /// direction.
    handle: SessionHandle,
    /// RFC 4271 §6.8 challenger session for bidirectional peers: the
    /// session the accept loop binds inbound transports to, so an
    /// inbound connection can coexist with the outbound one while the
    /// router resolves the collision. `None` = single-transport peer.
    handle_in: Option<SessionHandle>,
    auth: TcpAuth,
    gtsm: Gtsm,
    /// BFD liveness flags when the peer runs `bfd = true`.
    bfd: Option<BfdFlags>,
    /// True while a transport thread owns this session — prevents two
    /// concurrent connections racing one FSM.
    busy: Arc<AtomicBool>,
    /// Set once the outbound transport has LOST a §6.8 collision (the
    /// connector's session was closed by the router's resolver). Until
    /// this latches, the connector always dials: the §6.8 convention
    /// needs the higher-BGP-Identifier speaker's first dial to happen —
    /// suppressing it would turn "higher ID wins" into "first dial
    /// wins". After a loss, holding off while the sibling (the
    /// surviving pair) is Established prevents endless
    /// dial-into-Established-winner churn (every retry would only earn
    /// another Cease/7).
    outbound_lost_collision: Arc<AtomicBool>,
}

impl PeerEntry {
    fn label(&self) -> &str {
        self.spec.label()
    }
}

/// Run the BGP engine. `host = None` is the classic standalone
/// daemon (own router, own running flag, own ticker, own API socket,
/// own privilege drop); `Some(host)` plugs it into the multi-protocol
/// supervisor (rc.3) — the supervisor supplies the shared router,
/// running flag, ticker and API socket, and the engine waits on the
/// startup gate between its binds and its main loop.
fn run_bgp_daemon(cfg: &DaemonConfig, rid: RouterId, host: Option<EngineHost>) -> ExitCode {
    // The shared router when embedded (the supervisor created it and
    // the other engines add their sessions to the same instance).
    let router = match &host {
        Some(h) => Arc::clone(&h.runtime.router),
        None => Arc::new(Mutex::new(DefaultRouter::new())),
    };

    // Optional BMP egress (RFC 7854): mirror Peer Up/Down + Route
    // Monitoring to a monitoring station. The sink is called from
    // inside the router lock, so bytes travel over a channel to a
    // dedicated sender thread (connect + reconnect + backoff).
    if let Some(target) = cfg.bmp_target.as_deref() {
        match spawn_bmp_sender(target, &router) {
            Ok(()) => println!("daemon: bmp mirroring to {}", target),
            Err(e) => {
                eprintln!("daemon: bmp target {}: {}", target, e);
                return ExitCode::from(1);
            }
        }
    }

    // ---- Build one router session per configured peer. ----
    let mut entries: Vec<PeerEntry> = Vec::new();
    {
        let mut r = router.lock().unwrap();
        // RFC 7911 Add-Path: cap how many paths per prefix survive the
        // decision process (and reach Add-Path peers). Router-global.
        r.set_add_path_max_paths(cfg.add_path_max_paths.max(1) as usize);
        // RFC 8212 default eBGP route behaviors: deny-in/deny-out for
        // external peers without explicit policy ("rfc8212", the
        // default) or the RFC 4271 accept-all deviation the RFC
        // permits (§3 / Appendix A "insecure-mode").
        let rfc8212 = cfg.ebgp_policy != "accept-all";
        r.set_ebgp_requires_policy(rfc8212);
        // FRR `bgp enforce-first-as` (W2.2): drop eBGP UPDATEs whose
        // leftmost AS_PATH sequence segment's first AS is not the
        // peer's AS. Off by default (FRR `no bgp enforce-first-as`).
        r.set_enforce_first_as(cfg.enforce_first_as);
        // FRR `bgp bestpath compare-routerid` (W2.2): the best-path
        // tiebreaker is the lowest BGP IDENTIFIER (RFC 5004
        // deterministic) when on, or oldest-route-wins when off.
        r.best_path_config_mut().deterministic_router_id = cfg.bestpath_compare_routerid;
        for spec in &cfg.peers {
            if cfg.explicit_peers && !spec.is_outbound() && !spec.is_inbound() {
                eprintln!(
                    "daemon: peer {}: 'remote' or 'address' is required",
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
            // RFC 4271 §6.8: a bidirectional peer (both `remote` and
            // `address`) gets TWO identical sessions in one collision
            // group — the outbound transport runs on the primary
            // (locally initiated), inbound connections land on the
            // challenger (remotely initiated) and the router resolves
            // the collision when the OPENs arrive, closing the loser
            // with a Cease / Connection Collision Resolution
            // NOTIFICATION. Single-direction peers carry no group and
            // never collide.
            let bidirectional = spec.is_outbound() && spec.is_inbound();
            let group = (entries.len() + 1) as u64;
            let mut sc_out = sc.clone();
            let mut sc_in: Option<SessionConfig> = None;
            if bidirectional {
                sc_out.collision_group = Some(group);
                sc_out.locally_initiated = true;
                let mut c = sc.clone();
                c.collision_group = Some(group);
                c.locally_initiated = false;
                sc_in = Some(c);
            }
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
            match r.add_session(sc_out) {
                Ok(h) => {
                    // RFC 4271 §6.8 challenger for bidirectional peers.
                    let handle_in = match sc_in {
                        Some(c) => match r.add_session(c) {
                            Ok(h2) => Some(h2),
                            Err(e) => {
                                eprintln!(
                                    "daemon: peer {}: add_session (collision \
                                     challenger) failed: {}",
                                    spec.label(),
                                    e
                                );
                                return ExitCode::from(1);
                            }
                        },
                        None => None,
                    };
                    let handles = core::iter::once(h).chain(handle_in);
                    for hh in handles {
                        // RFC 8212 §3: declare the policy presence of this
                        // peer so the router knows which directions carry
                        // an explicit route-map. External peers missing a
                        // direction get the default deny (with an
                        // Appendix-A-style warning so the incomplete
                        // configuration is visible at startup).
                        if let Err(e) =
                            r.set_session_policy(hh, spec.import.is_some(), spec.export.is_some())
                        {
                            eprintln!("daemon: peer {}: {}", spec.label(), e);
                            return ExitCode::from(1);
                        }
                        // W6.3 exchange-plane (feature `exchange-plane`):
                        // activate the record plane for peers that opted
                        // in. Fail closed on a feature-less binary, on a
                        // missing key block, or on a bad key — never run
                        // half-configured.
                        #[cfg(feature = "exchange-plane")]
                        if spec.exchange_plane.unwrap_or(cfg.exchange_plane) {
                            if let Err(e) = wire_exchange_plane(&mut r, hh, cfg, spec) {
                                eprintln!("daemon: peer {}: {}", spec.label(), e);
                                return ExitCode::from(2);
                            }
                        }
                    }
                    #[cfg(not(feature = "exchange-plane"))]
                    {
                        let xp_requested = spec.exchange_plane.unwrap_or(cfg.exchange_plane)
                            || !cfg.exchange_plane_keys.is_empty();
                        if xp_requested {
                            eprintln!(
                                "daemon: peer {}: exchange_plane requested but this binary \
                                 was built without the exchange-plane feature",
                                spec.label()
                            );
                            return ExitCode::from(2);
                        }
                    }
                    if rfc8212 && cfg.effective_peer_as(spec) != cfg.local_as {
                        if spec.import.is_none() {
                            eprintln!(
                                "daemon: peer {}: warning: no import route-map; discarding \
                                 received routes (RFC 8212)",
                                spec.label()
                            );
                        }
                        if spec.export.is_none() {
                            eprintln!(
                                "daemon: peer {}: warning: no export route-map; announcing \
                                 nothing (RFC 8212)",
                                spec.label()
                            );
                        }
                    }
                    if let Some(h2) = handle_in {
                        println!(
                            "daemon: peer {}: bidirectional (remote + address); \
                             collision resolution per RFC 4271 §6.8 on sessions \
                             #{} / #{}",
                            spec.label(),
                            h.0,
                            h2.0
                        );
                    }
                    entries.push(PeerEntry {
                        spec: spec.clone(),
                        handle: h,
                        handle_in,
                        auth,
                        gtsm,
                        bfd: None,
                        busy: Arc::new(AtomicBool::new(false)),
                        outbound_lost_collision: Arc::new(AtomicBool::new(false)),
                    })
                }
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
    let has_filter_bindings = cfg
        .peers
        .iter()
        .any(|p| p.import_filter.is_some() || p.export_filter.is_some());
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

    // ---- ROA / RFC 6811 prefix-origin validation ----
    // Build the table even when `roa_validate` is off so the filter
    // DSL's `roa.state` accessor still works. The table lives in a
    // shared `RoaStore` (ROADMAP-v3 D2.3): the static [[roa]] entries
    // seed the store's config layer and the RTR client thread (below,
    // D2.4) applies cache syncs on top — the filter contexts see both
    // through one snapshot handle.
    let roa_table = match daemon_policy::build_roa_table(cfg) {
        Ok(t) => t,
        Err(e) => return daemon_policy::policy_error(e),
    };
    let roa_store = std::sync::Arc::new(lr_bgp::RoaStore::from_table(roa_table));
    if !roa_store.is_empty() {
        println!(
            "  roa:         {} entries, validate={} (action: {})",
            roa_store.len(),
            cfg.roa_validate,
            cfg.roa_invalid_action
        );
    }
    if let Some(cache) = &cfg.rpki.cache {
        println!(
            "  rpki:        cache {} (refresh {}s, retry {}s, expire {}s)",
            cache,
            cfg.rpki
                .refresh_interval
                .unwrap_or(lr_bgp::rtr::client::DEFAULT_REFRESH_INTERVAL),
            cfg.rpki
                .retry_interval
                .unwrap_or(lr_bgp::rtr::client::DEFAULT_RETRY_INTERVAL),
            cfg.rpki
                .expire_interval
                .unwrap_or(lr_bgp::rtr::client::DEFAULT_EXPIRE_INTERVAL)
        );
    }
    if cfg.roa_validate && !roa_store.is_empty() {
        // Install a built-in import hook that drops Invalid routes
        // (or warns + accepts them) before the user-supplied chain.
        // Implemented as a tiny DSL filter so the same code path
        // runs as user-supplied filters.
        let body = match cfg.roa_invalid_action.as_str() {
            "reject" => "if roa.state == \"invalid\" then { reject; } accept;",
            "warn" => "accept;",
            "accept" => "accept;",
            _ => "accept;",
        };
        match lr_policy::filter::compile("__roa_validate", body) {
            Ok(f) => {
                let ctx = std::sync::Arc::new(daemon_policy::DaemonFilterContext::new(
                    std::sync::Arc::clone(&roa_store),
                ));
                let hook = daemon_policy::FilterImportHook { filter: f, ctx };
                let mut r = router.lock().unwrap();
                r.hooks_mut().import.push(Box::new(hook));
            }
            Err(e) => {
                eprintln!("daemon: internal ROA filter compile error: {e}");
            }
        }
    }

    // ---- BIRD-like filter DSL ([[filter]] tables). ----
    if has_filter_bindings || !cfg.filters.is_empty() {
        let filters = match daemon_policy::build_filters(cfg) {
            Ok(f) => f,
            Err(e) => return daemon_policy::policy_error(e),
        };
        let ctx = std::sync::Arc::new(daemon_policy::DaemonFilterContext::new(
            std::sync::Arc::clone(&roa_store),
        ));
        let mut bound_import_filters = 0usize;
        let mut bound_export_filters = 0usize;
        // Index filters by name for O(1) lookup during peer binding.
        let by_name: std::collections::BTreeMap<&str, &lr_policy::filter::Filter> =
            filters.iter().map(|(n, f)| (n.as_str(), f)).collect();
        for (idx, peer) in cfg.peers.iter().enumerate() {
            let Some(session) = entries.get(idx) else {
                continue;
            };
            if let Some(name) = &peer.import_filter {
                let Some(f) = by_name.get(name.as_str()) else {
                    return daemon_policy::policy_error(format!(
                        "peer {}: unknown filter '{name}'",
                        peer.label()
                    ));
                };
                let hook = daemon_policy::FilterImportHook {
                    filter: (*f).clone(),
                    ctx: std::sync::Arc::clone(&ctx),
                };
                let _ = session.handle.0;
                {
                    let mut r = router.lock().unwrap();
                    r.hooks_mut().import.push(Box::new(hook));
                }
                bound_import_filters += 1;
            }
            if let Some(name) = &peer.export_filter {
                let Some(f) = by_name.get(name.as_str()) else {
                    return daemon_policy::policy_error(format!(
                        "peer {}: unknown filter '{name}'",
                        peer.label()
                    ));
                };
                let hook = daemon_policy::FilterExportHook {
                    filter: (*f).clone(),
                    ctx: std::sync::Arc::clone(&ctx),
                };
                {
                    let mut r = router.lock().unwrap();
                    r.hooks_mut().export.push(Box::new(hook));
                }
                bound_export_filters += 1;
            }
        }
        println!(
            "  filters:     {} compiled, {} import / {} export bindings",
            filters.len(),
            bound_import_filters,
            bound_export_filters
        );
    }

    // ---- RFC 8326 Graceful Session Shutdown (always-on for BGP). ----
    // The community (`GRACEFUL_SHUTDOWN` / `0xFFFF:0000`) is honoured
    // on the *export* side: any route that carries it has its
    // LOCAL_PREF set to zero before advertisement, so receivers prefer
    // alternatives before the session actually goes down. RFC 8326
    // §3.1 specifies this as a SHOULD, so the hook is installed by
    // default whenever BGP is in the protocol set. Embedders that
    // want a different policy can replace the hook chain.
    //
    // The hook is destination-agnostic and idempotent; running it
    // twice on the same route is a no-op (the second pass finds
    // LOCAL_PREF already at 0).
    if cfg.runs_protocol("bgp") {
        let mut r = router.lock().unwrap();
        r.hooks_mut()
            .export
            .push(Box::new(lr_policy::hooks::GracefulShutdownExportHook::new()));
        println!("  rfc8326:      graceful-shutdown export hook installed");
    }

    // ---- RFC 2439 Route Flap Damping (opt-in via [damping]). ----
    // The damping crate shipped in rc.3 as dead code — wiring it into
    // the daemon import chain is ROADMAP-v3 D4.3. Off by default:
    // RFC 7196 §3 documents that RFC 2439 defaults are harmful on
    // Internet-facing eBGP, so the operator must explicitly opt in
    // with `[damping] enabled = true`. When enabled, the daemon
    // installs a `DampingImportHook` on the import chain and spawns
    // a decay ticker thread that periodically calls
    // `DampingTable::decay_all` so suppressed prefixes re-emerge
    // as the figure-of-merit decays below the reuse threshold.
    if cfg.damping.enabled {
        let table = std::sync::Arc::new(std::sync::Mutex::new(lr_damping::DampingTable::new(
            cfg.damping.config.clone(),
        )));
        let hook = lr_policy::hooks::DampingImportHook::new(std::sync::Arc::clone(&table));
        {
            let mut r = router.lock().unwrap();
            r.hooks_mut().import.push(Box::new(hook));
        }
        // Spawn the decay ticker thread. The thread holds a weak-ish
        // reference (an `Arc`) to the damping table and runs for the
        // lifetime of the process — the daemon does not currently
        // expose a "stop damping" knob, so a SIGHUP-driven config
        // reload cannot unset damping mid-run (a known limitation,
        // documented in ROADMAP-v3 D4.3 follow-up).
        let decay_interval_s = cfg.damping.config.decay_interval_s;
        std::thread::Builder::new()
            .name("lr-damping-decay".into())
            .spawn(move || {
                // RFC 2439 §4.2: decay once per `decay_interval_s`.
                // The first tick fires after one interval so we do
                // not decay a freshly-started table (which would be a
                // no-op anyway — the FoM is 0 everywhere).
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(decay_interval_s));
                    let Ok(mut table) = table.lock() else {
                        // Mutex poisoned — another thread panicked
                        // while holding the lock. The damping table
                        // is now in an unknown state; the safest thing
                        // is to stop decaying (suppressed prefixes
                        // will stay suppressed until the daemon is
                        // restarted).
                        break;
                    };
                    let _now_s = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let reactivated = table.decay_all(_now_s);
                    for prefix in &reactivated {
                        // The router's import hook chain has no
                        // "please re-import this prefix" API — the
                        // next re-announce from the peer will
                        // naturally flow through the import hook
                        // (and pass, since `is_suppressed(prefix)`
                        // is now false). Until then, the prefix
                        // stays out of Adj-RIB-In. Log the
                        // reactivation so the operator can correlate.
                        eprintln!(
                            "damping: prefix {} reactivated (FoM decayed below reuse threshold)",
                            prefix
                        );
                    }
                }
            })
            .expect("spawn damping decay thread");
        println!(
            "  rfc2439:      route flap damping enabled (suppress={}, reuse={}, decay={}s)",
            cfg.damping.config.suppress_threshold,
            cfg.damping.config.reuse_threshold,
            cfg.damping.config.decay_interval_s,
        );
    }

    // ---- Banner. ----
    // The multi-protocol supervisor already printed the process banner
    // (protocol set, router-id, install, platform); the engine banner
    // then carries only the BGP-specific lines.
    if host.is_none() {
        println!("librouting daemon (lr-daemon)");
    }
    println!("  bgp engine: local AS AS{}", cfg.local_as);
    println!("  router-id:   {}", rid);
    println!(
        "  ebgp policy: {}",
        if cfg.ebgp_policy == "accept-all" {
            "accept-all (RFC 8212 insecure-mode)"
        } else {
            "rfc8212 (default deny-in/deny-out)"
        }
    );
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
    println!(
        "  ebgp:        policy={} enforce_first_as={} compare_routerid={}",
        cfg.ebgp_policy, cfg.enforce_first_as, cfg.bestpath_compare_routerid
    );
    println!("  ipv4-unicast: default={}", cfg.default_ipv4_unicast);
    let allowas_label = if cfg.allow_local_as == u32::MAX {
        "any".to_string()
    } else {
        cfg.allow_local_as.to_string()
    };
    println!("  allow-local-as: {}", allowas_label);
    println!("  soft-reconfig-in: {}", cfg.soft_reconfig_inbound);
    {
        // W6.3 exchange-plane posture at startup (feature `exchange-plane`
        // builds only; a feature-less binary fails earlier on the flag).
        let xp = cfg.exchange_plane || cfg.peers.iter().any(|p| p.exchange_plane == Some(true));
        println!(
            "  exchange-plane: {}{}",
            if xp { "on" } else { "off" },
            if cfg.exchange_plane_keys.is_empty() {
                String::new()
            } else {
                format!(" ({} key(s))", cfg.exchange_plane_keys.len())
            }
        );
    }
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
                    let nh = originate_next_hop(cfg, family);
                    r.originate_family(p, family, nh);
                    println!("daemon: originating {}", p);
                }
                Err(_) => eprintln!("daemon: invalid network '{}'", net),
            }
        }
        // RFC 8277 labelled networks: each entry is "<prefix> <labels>"
        // where labels is a comma-separated list of 20-bit values. The
        // family is derived from the prefix (v4 → IPV4_LABELED_UNICAST,
        // v6 → IPV6_LABELED_UNICAST). Requires `mp-family
        // ipv4-labeled-unicast` (or v6) on the peer to be advertised.
        for entry in &cfg.labeled_networks {
            match parse_labeled_network(entry) {
                Ok((p, labels)) => {
                    let family = match p.addr {
                        IpAddr::V4(_) => NlriFamily::IPV4_LABELED_UNICAST,
                        IpAddr::V6(_) => NlriFamily::IPV6_LABELED_UNICAST,
                    };
                    let nh = originate_next_hop(cfg, family);
                    r.originate_labeled(p, family, labels, nh);
                    println!("daemon: originating labelled {}", p);
                }
                Err(msg) => eprintln!("daemon: invalid labeled_network '{}': {}", entry, msg),
            }
        }
    }

    let running = match &host {
        Some(h) => Arc::clone(&h.runtime.running),
        None => Arc::new(AtomicBool::new(true)),
    };
    // The supervisor's shared ticker waits on this counter at shutdown
    // when the BGP engine is embedded; standalone owns both sides.
    let live_sessions = match &host {
        Some(h) => Arc::clone(&h.live_sessions),
        None => Arc::new(AtomicUsize::new(0)),
    };

    // ---- BFD fast-fail supervisor (RFC 5880/5881/5883, W1.3). ----
    // One session per `bfd = true` peer; a BFD Down tears the BGP
    // session immediately instead of waiting out the hold timer.
    // Fails closed: configured BFD that cannot bind is fatal.
    {
        let mut specs = Vec::new();
        for entry in &entries {
            if !cfg.effective_bfd(&entry.spec) {
                continue;
            }
            let Some(peer_ip) = expected_peer_ip(&entry.spec) else {
                eprintln!(
                    "daemon: peer {}: bfd requires a resolvable peer address \
                     ('remote' host or 'address')",
                    entry.label()
                );
                return ExitCode::from(2);
            };
            let Some(local_ip) = peer_local_address(cfg, &entry.spec) else {
                eprintln!(
                    "daemon: peer {}: bfd requires a local address \
                     (--local-address / local_address)",
                    entry.label()
                );
                return ExitCode::from(2);
            };
            let mode = if cfg.effective_bfd_multihop(&entry.spec) {
                lr_osroute::bfd_transport::BfdMode::Multihop
            } else {
                lr_osroute::bfd_transport::BfdMode::SingleHop
            };
            specs.push(daemon_bfd::BfdPeerSpec {
                label: entry.label().to_string(),
                peer_ip: to_std_ip(peer_ip),
                local_ip: to_std_ip(local_ip),
                mode,
            });
        }
        if !specs.is_empty() {
            println!(
                "daemon: bfd: {} session(s), min tx {} ms, min rx {} ms, multiplier {}",
                specs.len(),
                cfg.bfd_min_tx_ms,
                cfg.bfd_min_rx_ms,
                cfg.bfd_multiplier
            );
            let flags = match daemon_bfd::spawn_supervisor(
                specs,
                cfg.bfd_min_tx_ms,
                cfg.bfd_min_rx_ms,
                cfg.bfd_multiplier,
                Arc::clone(&running),
            ) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("daemon: {}", e);
                    return ExitCode::from(1);
                }
            };
            // specs were built in entry order; assign back by position.
            let mut flag_iter = flags.into_iter();
            for entry in &mut entries {
                if cfg.effective_bfd(&entry.spec) {
                    entry.bfd = flag_iter.next();
                }
            }
        }
    }

    // ---- Runtime: standalone builds its own (reload over its own
    // router, empty status lines); an embedded engine shares the
    // supervisor's runtime — one running flag, one reload closure, one
    // status registry for the whole combination.
    // RPKI-RTR cache client ([bgp.rpki], RFC 8210 — ROADMAP-v3 D2.4):
    // one thread per configured cache, syncing ROA deltas into the
    // shared store. The handle is created before the runtime so the
    // API `status` command can render the live state; the thread uses
    // the same running flag as the rest of the daemon.
    let rpki = cfg.rpki.cache.as_ref().map(|cache| {
        daemon_rpki::spawn_rpki(
            std::sync::Arc::clone(&roa_store),
            cache.clone(),
            cfg.rpki
                .refresh_interval
                .unwrap_or(lr_bgp::rtr::client::DEFAULT_REFRESH_INTERVAL),
            cfg.rpki
                .retry_interval
                .unwrap_or(lr_bgp::rtr::client::DEFAULT_RETRY_INTERVAL),
            cfg.rpki
                .expire_interval
                .unwrap_or(lr_bgp::rtr::client::DEFAULT_EXPIRE_INTERVAL),
            Arc::clone(&running),
        )
    });
    let runtime = match &host {
        Some(h) => Arc::clone(&h.runtime),
        None => Arc::new(Runtime {
            reload: Arc::new({
                let router = Arc::clone(&router);
                let current_networks = Arc::clone(&current_networks);
                let config_path = cfg.config_path.clone();
                let config_dialect = cfg.config_dialect.clone();
                move || {
                    reload_config(
                        config_path.as_deref(),
                        config_dialect.as_deref(),
                        &router,
                        &current_networks,
                    )
                }
            }),
            router,
            running: Arc::clone(&running),
            status_lines: Arc::new({
                let rpki = rpki.clone();
                move || match &rpki {
                    Some(h) => vec![h.status_line()],
                    None => Vec::new(),
                }
            }),
        }),
    };

    // --- Ticker thread: pump the router clock every 50 ms. It is the
    // single consumer of router events — logging and (optional) kernel
    // route installation happen here, never on the I/O threads, so the
    // Loc-RIB event order cannot be shuffled across sessions. ---
    // Embedded: the supervisor already spawned one shared ticker (and
    // fed it our live-session counter via the host).
    if host.is_none() {
        spawn_ticker(&runtime, cfg.install_kernel, Arc::clone(&live_sessions));
    }

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

    // Privileged work is done (the listener, BFD raw sockets and any
    // TCP-MD5/GTSM arming happened above). Standalone: drop root, then
    // create the management socket as the reduced user. Embedded: the
    // same two steps happen in the supervisor — report readiness and
    // block on the startup gate so every engine binds before the drop
    // and no connector dials before the API socket exists.
    match host {
        None => {
            if let Err(e) = do_privdrop(cfg) {
                eprintln!("daemon: {}", e);
                return ExitCode::from(1);
            }
            if let Err(e) = spawn_api(cfg, &runtime) {
                eprintln!("daemon: {}", e);
                return ExitCode::from(1);
            }
        }
        Some(h) => {
            let _ = h.report.send(EngineReport::Started);
            if h.gate.wait().is_err() {
                // A sibling engine failed startup; the supervisor
                // already reported it and returns that engine's code.
                println!("daemon: bgp engine startup aborted");
                return ExitCode::SUCCESS;
            }
        }
    }

    // ---- Outbound connectors: one thread per remote peer. ----
    // Legacy listen precedence: with a single peer and --listen, the
    // historical daemon ignored --peer entirely (listen mode wins).
    let legacy_listen_only = !strict_inbound && listener.is_some();
    if !legacy_listen_only {
        for entry in &entries {
            if entry.spec.is_outbound() {
                spawn_connector(&runtime, entry, cfg, Arc::clone(&live_sessions));
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
                    // RFC 4271 §6.8: a bidirectional peer's inbound
                    // connections run on the challenger session so they
                    // can coexist with the outbound transport while the
                    // router resolves the collision.
                    let handle = entry.handle_in.unwrap_or(entry.handle);
                    let rt = Arc::clone(&runtime);
                    let busy = Arc::clone(&entry.busy);
                    let live = Arc::clone(&live_sessions);
                    let bfd = entry.bfd.clone();
                    live.fetch_add(1, Ordering::Relaxed);
                    let spawned = thread::Builder::new()
                        .name(format!("lr-session-{}", handle.0))
                        .spawn(move || {
                            if let Err(e) = run_peer_session(rt, s, handle, bfd) {
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
    // Recognised names: `ipv4-unicast`, `ipv6-unicast`,
    // `ipv4-labeled-unicast` (RFC 8277), `ipv6-labeled-unicast`
    // (RFC 8277); unknown names are logged and dropped.
    //
    // FRR `bgp default ipv4-unicast` (W2.1): when on (the default —
    // matches FRR and BIRD's MP-BGP capability requirement), ensure
    // IPV4_UNICAST is in the family list so the MP-BGP capability
    // advertises it (BIRD 2 refuses the session without a matching
    // capability). When off, IPV4_UNICAST must be added explicitly to
    // the peer's `mp_families` to be advertised and processed — the
    // FRR `no bgp default ipv4-unicast` posture. The router's FSM
    // additionally gates legacy-section IPv4 NLRI on the same flag
    // (see `PeerConfig::ipv4_unicast_active`).
    let effective_default_ipv4 = p.default_ipv4_unicast.unwrap_or(g.default_ipv4_unicast);
    let families_cfg = p.mp_families.as_ref().unwrap_or(&g.mp_families);
    let mut families = Vec::new();
    for name in families_cfg {
        match name.as_str() {
            "ipv4-unicast" => families.push(NlriFamily::IPV4_UNICAST),
            "ipv6-unicast" => families.push(NlriFamily::IPV6_UNICAST),
            "ipv4-labeled-unicast" => families.push(NlriFamily::IPV4_LABELED_UNICAST),
            "ipv6-labeled-unicast" => families.push(NlriFamily::IPV6_LABELED_UNICAST),
            other => eprintln!(
                "daemon: peer {}: unknown mp_family '{}' (skipped)",
                p.label(),
                other
            ),
        }
    }
    if effective_default_ipv4 && !families.contains(&NlriFamily::IPV4_UNICAST) {
        // Implicit IPv4 unicast (RFC 4271 default + BIRD capability
        // requirement). Insert at the front so explicit families
        // listed by the operator stay in their original order.
        families.insert(0, NlriFamily::IPV4_UNICAST);
    }
    // Always override — even when families is empty, this clears the
    // SessionConfig::bgp() default `[IPV4_UNICAST]` so a
    // `default_ipv4_unicast = false` peer with no configured families
    // does not advertise IPv4 unicast (matches FRR).
    sc = sc.with_mp_families(families);
    // Stash the effective default_ipv4_unicast on the SessionConfig
    // so add_session propagates it to PeerConfig — the FSM gates
    // IPv4 NLRI processing on this flag.
    sc.default_ipv4_unicast = effective_default_ipv4;
    // FRR `neighbor X allowas-in N` / BIRD `allow local as` (W2.3):
    // per-peer override of the router-wide default. add_session
    // propagates it to PeerConfig so the router's per-peer AS-loop
    // tolerance check sees it.
    sc.local_as_tolerance = p.allow_local_as.unwrap_or(g.allow_local_as);
    // FRR `neighbor X soft-reconfiguration inbound` (W2.4): per-peer
    // override of the router-wide default. add_session propagates it
    // to PeerConfig so import_route knows to retain the raw received
    // route in the pre-policy RIB.
    sc.soft_reconfig_inbound = p.soft_reconfig_inbound.unwrap_or(g.soft_reconfig_inbound);
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

/// W6.3 exchange-plane (feature `exchange-plane`): parse one
/// `"id:secret"` key pair. HMAC-SHA256 is the prototype's only
/// algorithm (design §8); ids share the TCP-AO range (1..=65535).
#[cfg(feature = "exchange-plane")]
fn parse_exchange_key(
    spec_str: &str,
) -> Result<lr_bgp::extensions::exchange_plane::ExchangeKey, String> {
    use lr_bgp::extensions::exchange_plane::ExchangeKey;
    let (id_str, secret) = spec_str
        .split_once(':')
        .ok_or_else(|| format!("expected 'id:secret', got '{}'", spec_str))?;
    let id: u16 = id_str
        .parse()
        .map_err(|_| format!("bad key id '{}' (expected 0..=65535)", id_str))?;
    if secret.is_empty() {
        return Err("empty key secret".to_string());
    }
    Ok(ExchangeKey::hmac_sha256(id, secret.as_bytes().to_vec()))
}

/// W6.3 exchange-plane (feature `exchange-plane`): the canonical
/// description of one route-map's effective filter/action set — the
/// map's entries plus the definitions of the lists they reference.
/// The SipHash-2-4 digest over the sorted lines is the policy-intent
/// record's fingerprint (design §5.2): two sessions reporting the same
/// digest announce the same effective filter, and a digest change
/// between one sender's consecutive records signals a policy edit.
#[cfg(feature = "exchange-plane")]
fn canonical_policy_lines(cfg: &DaemonConfig, map_name: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut entries: Vec<&crate::daemon_policy::RouteMapSpec> = cfg
        .route_maps
        .iter()
        .filter(|r| r.name == map_name)
        .collect();
    entries.sort_by_key(|r| r.entry);
    for e in entries {
        lines.push(format!(
            "map {} entry {} {}",
            e.name,
            e.entry,
            if e.permit.unwrap_or(true) {
                "permit"
            } else {
                "deny"
            }
        ));
        if let Some(m) = &e.match_prefix {
            lines.push(format!("match-prefix {}", m));
            for pl in &cfg.prefix_lists {
                if &pl.name == m {
                    lines.push(format!(
                        "prefix-list {} {} ge={} le={} {}",
                        pl.name,
                        pl.prefix,
                        pl.ge.unwrap_or(0),
                        pl.le.unwrap_or(0),
                        if pl.permit.unwrap_or(true) {
                            "permit"
                        } else {
                            "deny"
                        }
                    ));
                }
            }
        }
        if let Some(m) = &e.match_as_path {
            lines.push(format!("match-as-path {}", m));
            for l in &cfg.as_path_lists {
                if &l.name == m {
                    lines.push(format!(
                        "as-path-list {} {} {}",
                        l.name,
                        l.pattern,
                        if l.permit.unwrap_or(true) {
                            "permit"
                        } else {
                            "deny"
                        }
                    ));
                }
            }
        }
        if let Some(m) = &e.match_community {
            lines.push(format!("match-community {}", m));
            for l in &cfg.community_lists {
                if &l.name == m {
                    lines.push(format!(
                        "community-list {} {:?} {}",
                        l.name,
                        {
                            let mut c = l.communities.clone();
                            c.sort();
                            c
                        },
                        if l.permit.unwrap_or(true) {
                            "permit"
                        } else {
                            "deny"
                        }
                    ));
                }
            }
        }
        if let Some(v) = e.set_local_pref {
            lines.push(format!("set local-pref {}", v));
        }
        if let Some(v) = e.set_med {
            lines.push(format!("set med {}", v));
        }
        if let Some(v) = e.set_metric {
            lines.push(format!("set metric {}", v));
        }
        if let Some(v) = &e.set_next_hop {
            lines.push(format!("set next-hop {}", v));
        }
        if let Some(v) = &e.prepend {
            lines.push(format!("set as-path prepend {}", v));
        }
        if let Some(v) = &e.add_community {
            lines.push(format!("set community {}", v));
        }
    }
    lines.sort();
    lines
}

/// W6.3 exchange-plane (feature `exchange-plane`): SipHash-2-4 over the
/// canonical policy description, keyed with the per-boot nonce (the
/// design's "keyed per session from the capability nonce" — the nonce
/// is per boot + per OPEN instance in this prototype, which is enough
/// for the digest's actual use: change detection between one sender's
/// consecutive records).
#[cfg(feature = "exchange-plane")]
fn exchange_plane_policy_digest(
    cfg: &DaemonConfig,
    spec: &PeerSpec,
    import: bool,
    nonce: &[u8; 8],
) -> Option<[u8; 8]> {
    use siphasher::sip::SipHasher;
    use std::hash::Hasher;

    let map_name = if import {
        spec.import.as_deref()?
    } else {
        spec.export.as_deref()?
    };
    let lines = canonical_policy_lines(cfg, map_name);
    let k0 = u64::from_be_bytes(*nonce);
    let mut hasher = SipHasher::new_with_keys(k0, !k0);
    for line in &lines {
        hasher.write(line.as_bytes());
        hasher.write(&[0]);
    }
    let h = hasher.finish();
    Some(h.to_be_bytes())
}

/// W6.3 exchange-plane (feature `exchange-plane`): build the per-session
/// plane configuration and attach it to the router session. The local
/// OPEN nonce mixes the per-boot nonce with the FSM's per-instance OPEN
/// counter (the nonce is a session-instance tag, not a secret).
#[cfg(feature = "exchange-plane")]
fn wire_exchange_plane(
    r: &mut lr_router::DefaultRouter,
    h: lr_router::SessionHandle,
    g: &DaemonConfig,
    p: &PeerSpec,
) -> Result<(), String> {
    use lr_bgp::extensions::exchange_plane::{ExchangePlaneConfig, ROLE_UNSET};

    if g.exchange_plane_keys.is_empty() {
        return Err(
            "exchange_plane needs at least one key (--exchange-plane-key id:secret \
             or [bgp] exchange_plane_keys)"
                .to_string(),
        );
    }
    let mut keys = Vec::new();
    for k in &g.exchange_plane_keys {
        keys.push(parse_exchange_key(k)?);
    }
    // Per-boot random nonce (uniqueness across daemon restarts comes
    // from here; uniqueness across session instances from the FSM's
    // OPEN counter mixed in at each OPEN).
    let mut nonce = [0u8; 8];
    {
        use lr_babel::NonceSource;
        lr_babel::SystemNonceSource::new().fill(&mut nonce);
    }
    let mut xp = ExchangePlaneConfig::new(nonce);
    xp.keys = keys;
    // Policy intent (design §5.2): lr's daemon does not configure RFC
    // 9234 roles yet, so the claim is ROLE_UNSET; the digests fingerprint
    // the effective import/export filter sets when a route-map is bound.
    xp.policy_role = Some(ROLE_UNSET);
    xp.policy_import_digest = exchange_plane_policy_digest(g, p, true, &nonce);
    xp.policy_export_digest = exchange_plane_policy_digest(g, p, false, &nonce);
    r.set_session_exchange_plane(h, xp)
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
/// - Neither: plain connect — bound to `local` when configured so the
///   peer sees the configured source address.
///
/// Source binding does not yet combine with TCP auth (connect_auth
/// creates its own socket); that combination is future work.
///
/// The Err payload marks kernel-unsupported auth as fatal for this peer
/// (fail closed: the key was configured, running without it is worse
/// than not running the session).
fn connect_secure(
    sockaddr: std::net::SocketAddr,
    local: Option<std::net::SocketAddr>,
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
    } else if let Some(local) = local {
        match lr_osroute::tcp_bind::connect_bound(local, sockaddr, Duration::from_secs(5)) {
            Ok(s) => Ok(s),
            // `local_address` is primarily a next-hop-self value and
            // may name an address the host does not own (192.0.2.x in
            // lab configs); fall back to the kernel's source choice
            // exactly as before the bind existed.
            Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
                TcpStream::connect_timeout(&sockaddr, Duration::from_secs(5))
                    .map_err(|e2| (format!("{e2}"), false))
            }
            Err(e) => Err((format!("{e}"), false)),
        }
    } else {
        TcpStream::connect_timeout(&sockaddr, Duration::from_secs(5))
            .map_err(|e| (format!("{e}"), false))
    }
}

/// One outbound peer: connect, run the session until it drops, back
/// off, repeat — for the lifetime of the daemon.
fn spawn_connector(
    rt: &Arc<Runtime>,
    entry: &PeerEntry,
    cfg: &DaemonConfig,
    live: Arc<AtomicUsize>,
) {
    let rt = Arc::clone(rt);
    let remote = entry.spec.remote.clone().expect("outbound peer has remote");
    let auth = entry.auth.clone();
    let gtsm = entry.gtsm;
    let handle = entry.handle;
    // RFC 4271 §6.8 churn guard: a bidirectional peer's inbound session
    // suppresses fresh outbound attempts only after this outbound
    // transport has actually LOST a collision — until then the §6.8
    // convention needs the dial to happen (the higher-BGP-Identifier
    // speaker's initiated connection must get its chance to win).
    let sibling_in = entry.handle_in;
    let lost_once = Arc::clone(&entry.outbound_lost_collision);
    let label = entry.spec.label().to_string();
    let bfd = entry.bfd.clone();
    // Source the connection from the configured local address when
    // one exists (port 0 = ephemeral).
    let local =
        peer_local_address(cfg, &entry.spec).map(|ip| std::net::SocketAddr::new(to_std_ip(ip), 0));
    let _ = thread::Builder::new()
        .name(format!("lr-connect-{}", label))
        .spawn(move || {
            let mut backoff_ms: u64 = 1_000;
            while rt.running.load(Ordering::Relaxed) {
                dispatch_signals(&rt);
                if !rt.running.load(Ordering::Relaxed) {
                    break;
                }
                // BFD hold-off (after the session has been Up at least
                // once): don't connect into a path BFD has declared
                // dead — and don't grow the backoff while waiting.
                if let Some(bfd) = &bfd {
                    if bfd.ever_up.load(Ordering::Relaxed) && !bfd.up.load(Ordering::Relaxed) {
                        sleep_interruptible(&rt, Duration::from_millis(200));
                        continue;
                    }
                }
                // RFC 4271 §6.8 churn guard: the sibling inbound session
                // is Established AND this transport already lost a
                // collision — stay passive until the winner goes away.
                if let Some(hin) = sibling_in {
                    let hold_off = lost_once.load(Ordering::Relaxed)
                        && rt
                            .router
                            .lock()
                            .unwrap()
                            .session_peer_state(hin)
                            .map(|s| s == "Established")
                            .unwrap_or(false);
                    if hold_off {
                        sleep_interruptible(&rt, Duration::from_millis(500));
                        continue;
                    }
                }
                let sockaddr = match resolve(&remote) {
                    Some(a) => a,
                    None => {
                        eprintln!("daemon: peer {}: cannot resolve {}", label, remote);
                        return;
                    }
                };
                println!("daemon: peer {}: connecting to {} ...", label, remote);
                match connect_secure(sockaddr, local, &auth, &gtsm) {
                    Ok(stream) => {
                        backoff_ms = 1_000;
                        let _ = stream.set_nodelay(true);
                        live.fetch_add(1, Ordering::Relaxed);
                        let result = run_peer_session(Arc::clone(&rt), stream, handle, bfd.clone());
                        live.fetch_sub(1, Ordering::Relaxed);
                        if let Err(e) = result {
                            // Latch a §6.8 collision loss so the churn guard
                            // above engages (see PeerEntry docs).
                            if e.contains("collision resolution") {
                                lost_once.store(true, Ordering::Relaxed);
                            }
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
    bfd: Option<BfdFlags>,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    {
        let mut r = rt.router.lock().unwrap();
        r.start_session(session)
            .map_err(|e| format!("start_session: {}", e))?;
    }
    let result = pump_session(&rt, &mut stream, session, bfd);
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
    bfd: Option<BfdFlags>,
) -> Result<(), String> {
    let router = &rt.router;
    let mut buf = [0u8; 8192];
    // BFD fast-fail: remember the last-seen liveness so only an
    // Up -> Down *transition* tears the session (a BFD session that
    // never came up must not kill BGP — BIRD parity).
    let mut bfd_up_seen = bfd.as_ref().map(|f| f.up.load(Ordering::Relaxed));
    while rt.running.load(Ordering::Relaxed) {
        // Signals first: a shutdown must tear the session down cleanly
        // even while the peer is idle, and a reload can change what we
        // originate mid-session.
        dispatch_signals(rt);
        if !rt.running.load(Ordering::Relaxed) {
            break;
        }

        // BFD Up -> Down: the path died; tear the session down now
        // instead of waiting out the hold timer (RFC 5880 §6.8.4,
        // the whole point of `--bfd`).
        if let Some(flags) = &bfd {
            let up = flags.up.load(Ordering::Relaxed);
            if bfd_up_seen == Some(true) && !up {
                return Err("bfd session down".into());
            }
            bfd_up_seen = Some(up);
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
        let (out, closed_by_router) = {
            let mut r = router.lock().unwrap();
            let out = r.drain_output(session);
            // RFC 4271 §6.8: the router may have just closed this
            // session while the TCP connection is still alive — this
            // transport lost the collision and the Cease / Connection
            // Collision Resolution NOTIFICATION is part of `out`. Flush
            // it below, then unwind so the socket closes.
            let closed = r.session_peer_state(session) == Some("Idle");
            (out, closed)
        };
        if !out.is_empty() {
            stream
                .write_all(&out)
                .map_err(|e| format!("write: {}", e))?;
        }
        if closed_by_router {
            return Err("connection lost the RFC 4271 §6.8 collision resolution".into());
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
fn spawn_ticker(
    rt: &Arc<Runtime>,
    install_kernel: bool,
    live: Arc<AtomicUsize>,
) -> thread::JoinHandle<()> {
    let rt = Arc::clone(rt);
    thread::Builder::new()
        .name("lr-ticker".into())
        .spawn(move || {
            let mut mirror = KernelMirror::new(install_kernel);
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
                    mirror.apply(&events);
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
                mirror.apply(&events);
            }
        })
        .expect("spawn ticker thread")
}

/// The private `lr-bgp` attribute tag that carries an RFC 8277 label
/// stack through the Loc-RIB (never transmitted on the wire).
const LR_MPLS_LABEL_STACK_TAG: u8 = 255; // pinned to AttrType::LrMplsLabelStack by a test

/// Link-local IPv6 next hops learned from protocol traffic, mapped to
/// the outgoing interface index (OSPFv3 daemon writes as it hears
/// peers; the kernel mirror reads at install time). A link-local
/// gateway is only routable *through* a specific interface — the
/// kernel refuses RTM_NEWROUTE with a link-local RTA_GATEWAY and no
/// RTA_OIF (EINVAL) — so the mirror consults this registry instead of
/// the per-route ifindex (which plain `Route`s do not carry).
pub(crate) static V6_NEXTHOP_OIFS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<IpAddr, u32>>,
> = std::sync::OnceLock::new();

pub(crate) fn v6_nexthop_oifs() -> &'static std::sync::Mutex<std::collections::BTreeMap<IpAddr, u32>>
{
    V6_NEXTHOP_OIFS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

/// Linux loopback is always ifindex 1 inside a network namespace: the
/// loopback device registers at netns creation before any other device.
/// The LSP tail (pop, no via) needs that device for local delivery.
#[cfg(target_os = "linux")]
pub(crate) const LO_IF_INDEX: u32 = 1;

/// What the kernel dataplane should do for a Loc-RIB best route
/// (RFC 8277 BGP-LU → Linux MPLS, W3-extra.3).
#[derive(Debug, Clone, PartialEq, Eq)]
enum LspDecision {
    /// LSP **tail**: a locally originated labelled route carries the
    /// label remote peers use to reach the prefix — install the AF_MPLS
    /// pop route (in-label → `lo`, local delivery; PHP-style tails
    /// originate implicit-null instead and never take this branch).
    PopLocal(lr_mpls::Label),
    /// LSP **head**: a peer-advertised labelled route — install the
    /// encap route pushing `stack` toward the BGP next hop, so locally
    /// generated / forwarded IP traffic enters the LSP.
    Push(lr_mpls::LabelStack),
    /// Nothing labelled: plain IP install (or nothing).
    Plain,
}

/// Classify a best route for the LSP mirror. Pure — no I/O.
///
/// The label stack rides the private `LrMplsLabelStack` attribute the
/// protocol layer attaches to BGP-LU routes (both originated and
/// received). An implicit-null top label (3, RFC 3032 §2.1) means
/// penultimate-hop popping: the head must NOT push, plain forwarding is
/// correct. Received routes without a resolvable next hop are left
/// alone — there is nothing to point the encap route at.
fn lsp_decision(route: &lr_core::rib::Route) -> LspDecision {
    let Some(attr) = route
        .attributes
        .get(lr_core::attr::AttrTag(LR_MPLS_LABEL_STACK_TAG))
    else {
        return LspDecision::Plain;
    };
    let Ok(stack) = lr_mpls::LabelStack::decode_4octet(&attr.value) else {
        return LspDecision::Plain;
    };
    let Some(top) = stack.labels().first() else {
        return LspDecision::Plain;
    };
    if top.value == lr_mpls::Label::IMPLICIT_NULL.value {
        return LspDecision::Plain; // PHP: forward unlabeled
    }
    if route.origin.proto == 2 {
        // Locally originated: this node is the LSP tail.
        return LspDecision::PopLocal(lr_mpls::Label::new_value(top.value));
    }
    if route.next_hop.is_some() {
        return LspDecision::Push(stack);
    }
    LspDecision::Plain
}

/// Mirrors Loc-RIB best routes into the kernel: the plain IP FIB (best
/// effort, failures retried on the next event) and — when the kernel
/// has MPLS routing enabled (Linux `mpls_router`) — the RFC 8277 LSP
/// endpoints for labelled routes: a pop route per locally originated
/// label (tail) and an encap route per received labelled prefix (head).
/// Withdrawals reverse both halves.
struct KernelMirror {
    ip_table: Option<Box<dyn lr_osroute::OsRouteTable<Error = lr_osroute::OsRouteError>>>,
    /// Locally originated in-labels currently installed, keyed by
    /// prefix — `RouteWithdrawn` carries only the key, so the tail half
    /// needs this side table to know which label to delete.
    #[cfg(target_os = "linux")]
    tails: HashMap<Prefix, lr_mpls::Label>,
    #[cfg(target_os = "linux")]
    mpls: Option<lr_osroute::mpls_route::MplsNetlink>,
}

impl KernelMirror {
    fn new(install_kernel: bool) -> Self {
        let mut ip_table = None;
        #[cfg(target_os = "linux")]
        let mut mpls = None;
        if install_kernel {
            match lr_osroute::SystemRouteTable::connect() {
                Ok(t) => {
                    println!("daemon: os route table connected — installing kernel routes");
                    ip_table = Some(Box::new(t)
                        as Box<dyn lr_osroute::OsRouteTable<Error = lr_osroute::OsRouteError>>);
                }
                Err(e) => eprintln!(
                    "daemon: os route table unavailable ({}); kernel install disabled",
                    e
                ),
            }
            #[cfg(target_os = "linux")]
            match lr_osroute::mpls_route::MplsNetlink::connect() {
                Ok(t) => {
                    println!("daemon: mpls route table connected — installing BGP-LU LSPs");
                    mpls = Some(t);
                }
                Err(e) => eprintln!(
                    "daemon: mpls route table unavailable ({}); LSP install disabled",
                    e
                ),
            }
        }
        Self {
            ip_table,
            #[cfg(target_os = "linux")]
            tails: HashMap::new(),
            #[cfg(target_os = "linux")]
            mpls,
        }
    }

    fn apply(&mut self, events: &[RouterEvent]) {
        for ev in events {
            match ev {
                RouterEvent::RouteInstalled(r) => {
                    // Classify on every platform (pure); the netlink
                    // half of the mirror exists only on Linux, where
                    // `mirrored` marks a route whose LSP took over the
                    // prefix (no plain-IP fallback needed).
                    #[allow(unused_mut)]
                    let mut mirrored = false;
                    match lsp_decision(r) {
                        #[cfg(target_os = "linux")]
                        LspDecision::PopLocal(label) => {
                            if let Some(mpls) = self.mpls.as_mut() {
                                let lsp = lr_osroute::mpls_route::MplsRoute::pop_local(
                                    label,
                                    LO_IF_INDEX,
                                );
                                match mpls.add_route(&lsp) {
                                    Ok(()) => {
                                        println!(
                                            "lsp: in-label {} -> pop (local delivery) for {}",
                                            label.value, r.key.prefix
                                        );
                                        self.tails.insert(r.key.prefix, label);
                                        mirrored = true;
                                    }
                                    Err(e) => eprintln!(
                                        "lsp: pop install for {} failed: {}",
                                        r.key.prefix, e
                                    ),
                                }
                            }
                            // Tail routes carry no next hop, so the
                            // plain fallback below is a no-op for them.
                        }
                        #[cfg(not(target_os = "linux"))]
                        LspDecision::PopLocal(_) => {
                            // Tail routes carry no next hop: nothing to
                            // install off-Linux.
                        }
                        #[cfg(target_os = "linux")]
                        LspDecision::Push(stack) => {
                            if let (Some(mpls), Some(nh)) = (self.mpls.as_mut(), r.next_hop) {
                                match mpls.add_encap_route(&r.key.prefix, &stack, nh, 0) {
                                    Ok(()) => {
                                        println!(
                                            "lsp: {} encap mpls [{}] via {}",
                                            r.key.prefix,
                                            stack
                                                .labels()
                                                .iter()
                                                .map(|l| l.value.to_string())
                                                .collect::<Vec<_>>()
                                                .join(","),
                                            nh
                                        );
                                        mirrored = true;
                                    }
                                    Err(e) => eprintln!(
                                        "lsp: encap install for {} failed ({}); \
                                         falling back to plain",
                                        r.key.prefix, e
                                    ),
                                }
                            }
                            // Failed encap: fall through to the plain
                            // install for reachability.
                        }
                        #[cfg(not(target_os = "linux"))]
                        LspDecision::Push(_) => {
                            // No netlink mirror off-Linux: the plain-IP
                            // fallback below keeps the prefix reachable.
                        }
                        LspDecision::Plain => {}
                    }
                    // Plain IP fallback: for unlabelled routes, and for
                    // labelled routes when MPLS is unavailable or the
                    // encap install failed (reachability first, labels
                    // second — BIRD behaves the same way).
                    if !mirrored {
                        if let Some(nh) = r.next_hop {
                            // A link-local gateway only works with its
                            // outgoing interface (netlink EINVAL
                            // otherwise); the protocol daemons register
                            // the mapping as they learn peers.
                            let oif = match nh {
                                IpAddr::V6(a) if a[..2] == [0xfe, 0x80] => v6_nexthop_oifs()
                                    .lock()
                                    .ok()
                                    .and_then(|m| m.get(&nh).copied())
                                    .unwrap_or(0),
                                _ => 0,
                            };
                            if let Some(table) = self.ip_table.as_mut() {
                                if let Err(e) = table.add_route(r.key.prefix, nh, oif) {
                                    eprintln!(
                                        "mirror: route install failed for {} via {} oif {}: {}",
                                        r.key.prefix, nh, oif, e
                                    );
                                }
                            }
                        }
                    }
                }
                RouterEvent::RouteWithdrawn(k) => {
                    #[cfg(target_os = "linux")]
                    if let Some(label) = self.tails.remove(&k.prefix) {
                        if let Some(mpls) = self.mpls.as_mut() {
                            if let Err(e) = mpls.delete_route(label) {
                                eprintln!(
                                    "lsp: pop removal for label {} failed: {}",
                                    label.value, e
                                );
                            }
                        }
                    }
                    if let Some(table) = self.ip_table.as_mut() {
                        let _ = table.delete_route(k.prefix);
                    }
                }
                _ => {}
            }
        }
    }
}

/// BMP collector mode (`--protocol bmp --listen ADDR:PORT`): the
/// monitoring-station side of RFC 7854 — accept BMP sessions from
/// routers (BIRD's `protocol bmp`, FRR's bmpbgpd), decode Peer Up/Down
/// and Route Monitoring, and mirror the observed prefixes into the
/// Loc-RIB so the runtime API (`routes`, `mrt <path>`) serves them like
/// any other source. One thread per BMP connection; BGP UPDATEs are
/// decoded with the `lr-bgp` codec (the 19-byte header included) and
/// withdrawals retract the corresponding entries.
///
/// Scope note: the Loc-RIB keys routes by prefix, so a prefix monitored
/// through several peers keeps the last-received path — the collector
/// is an operational view, not a full Adj-RIB-In replay (W5.3's
/// wire-parity harness will build that).
fn run_bmp_collector(cfg: &DaemonConfig, rid: RouterId) -> ExitCode {
    use std::net::TcpListener;

    let Some(listen) = cfg.listen_addr.as_deref() else {
        eprintln!("daemon: --protocol bmp requires --listen ADDR:PORT");
        return ExitCode::from(2);
    };
    let addr = match resolve(listen) {
        Some(a) => a,
        None => {
            eprintln!("daemon: invalid --listen address: {}", listen);
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("daemon: bmp bind {} failed: {}", addr, e);
            return ExitCode::from(1);
        }
    };
    println!("daemon: bmp collector listening on {}", addr);
    if let Err(sig) = signal::init() {
        eprintln!("daemon: cannot install signal handlers (signal {})", sig);
        return ExitCode::from(1);
    }
    let running = Arc::new(AtomicBool::new(true));
    let router = Arc::new(Mutex::new(DefaultRouter::new()));
    let runtime = Arc::new(Runtime {
        reload: Arc::new(|| vec!["bmp: configuration reload is not supported".to_string()]),
        router: Arc::clone(&router),
        running: Arc::clone(&running),
        status_lines: Arc::new(Vec::new),
    });
    if let Err(e) = spawn_api(cfg, &runtime) {
        eprintln!("daemon: {}", e);
        return ExitCode::from(1);
    }
    let _ = rid;
    // Ticker: drains the events the originate/unoriginate calls emit.
    {
        let rt = Arc::clone(&runtime);
        thread::Builder::new()
            .name("lr-ticker".into())
            .spawn(move || {
                let start = WallClock::now();
                loop {
                    if !rt.running.load(Ordering::Relaxed) {
                        break;
                    }
                    let now_ms = start.elapsed().as_millis() as u64;
                    {
                        let mut r = rt.router.lock().unwrap();
                        r.tick(lr_core::time::Instant(now_ms));
                        for ev in r.poll_events() {
                            log_event(&ev);
                        }
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            })
            .expect("spawn ticker thread");
    }
    listener
        .set_nonblocking(true)
        .map_err(|e| {
            eprintln!("daemon: bmp listener nonblocking: {}", e);
            ExitCode::from(1)
        })
        .unwrap();
    while running.load(Ordering::Relaxed) {
        dispatch_signals(&runtime);
        match listener.accept() {
            Ok((stream, peer)) => {
                println!("daemon: bmp station connected from {}", peer);
                let router = Arc::clone(&router);
                let running = Arc::clone(&running);
                thread::Builder::new()
                    .name("lr-bmp-station".into())
                    .spawn(move || serve_bmp_station(stream, &router, &running))
                    .expect("spawn bmp station thread");
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("daemon: bmp accept: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    println!("daemon: bmp collector shutdown complete");
    ExitCode::SUCCESS
}

/// Serve one connected BMP station until it disconnects or the daemon
/// stops. Decoded Route Monitoring messages install routes into the
/// shared router; Peer Up/Down are logged.
fn serve_bmp_station(
    mut stream: std::net::TcpStream,
    router: &Arc<Mutex<DefaultRouter>>,
    running: &Arc<AtomicBool>,
) {
    use lr_bmp::BmpCodec;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let mut bmp = BmpCodec::new();
    let mut bgp = lr_bgp::BgpCodec::new();
    let mut buf = [0u8; 65535];
    // Locally originated keys per prefix, so withdrawals can retract.
    let mut installed: std::collections::BTreeMap<lr_core::addr::Prefix, lr_core::rib::RouteKey> =
        std::collections::BTreeMap::new();
    while running.load(Ordering::Relaxed) {
        let n = match stream.read(&mut buf) {
            Ok(0) => break, // station disconnected
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                eprintln!("daemon: bmp station read: {}", e);
                break;
            }
        };
        // One read can carry several BMP messages: feed the bytes
        // once, then drain every complete buffered message.
        bmp.feed(&buf[..n]);
        loop {
            let message = match bmp.next_message() {
                Ok(Some(m)) => m,
                Ok(None) => break,
                Err(e) => {
                    eprintln!("daemon: bmp decode: {}", e);
                    break;
                }
            };
            handle_bmp_message(&message, &mut bgp, router, &mut installed);
        }
    }
    println!("daemon: bmp station disconnected");
}

/// Apply one decoded BMP message.
fn handle_bmp_message(
    message: &lr_bmp::BmpMessage,
    bgp: &mut lr_bgp::BgpCodec,
    router: &Arc<Mutex<DefaultRouter>>,
    installed: &mut std::collections::BTreeMap<lr_core::addr::Prefix, lr_core::rib::RouteKey>,
) {
    use lr_bmp::BmpMsgType;
    use lr_core::codec::Decoder;
    let peer_desc = message
        .peer
        .as_ref()
        .map(|p| format!("peer as={} bgp-id={}", p.peer_as, fmt_bgp_id(p.peer_bgp_id)))
        .unwrap_or_else(|| "station".to_string());
    match message.header.msg_type {
        BmpMsgType::RouteMonitoring => {
            // Payload: a complete BGP UPDATE (marker included).
            let mut r = lr_core::buf::ReadBuf::new(&message.payload);
            let update = match bgp.decode(&mut r) {
                Ok(Some(lr_bgp::message::BgpMessage::Update(u))) => u,
                Ok(Some(other)) => {
                    // KEEPALIVE / OPEN echoes inside monitoring are legal
                    // but carry no routes.
                    let _ = other;
                    return;
                }
                Ok(None) => return,
                Err(e) => {
                    eprintln!("daemon: bmp monitored update decode: {}", e);
                    return;
                }
            };
            let mut r = router.lock().unwrap();
            for w in &update.withdrawn {
                if let Some(key) = installed.remove(&w.prefix) {
                    r.unoriginate(&key);
                }
            }
            for n in &update.nlri {
                let next_hop = update.attributes.next_hop().map(|nh| nh.to_ip());
                let key = r.originate_with_attributes(
                    n.prefix,
                    lr_core::nlri::NlriFamily::IPV4_UNICAST,
                    next_hop,
                    update.attributes.clone().into(),
                );
                installed.insert(n.prefix, key);
                println!(
                    "daemon: bmp route {} via {} ({})",
                    n.prefix,
                    next_hop
                        .map(|nh| nh.to_string())
                        .unwrap_or_else(|| "(none)".into()),
                    peer_desc
                );
            }
        }
        BmpMsgType::PeerUp => {
            println!("daemon: bmp peer up ({})", peer_desc);
        }
        BmpMsgType::PeerDown => {
            println!("daemon: bmp peer down ({})", peer_desc);
        }
        BmpMsgType::Initiation => {
            println!("daemon: bmp station initiated ({})", peer_desc);
        }
        BmpMsgType::Termination => {
            println!("daemon: bmp station terminating ({})", peer_desc);
        }
        _ => {}
    }
}

/// Format a BGP identifier as a dotted quad (shared log helper).
fn fmt_bgp_id(id: u32) -> String {
    std::net::Ipv4Addr::from(id).to_string()
}

/// Build the RFC 8967 authentication interface from the `[babel]` config:
/// one [`lr_babel::BabelAuthInterface`] when keys are configured, `None`
/// otherwise (unsigned transport, the historical behaviour).
fn build_babel_auth_interface(cfg: &DaemonConfig) -> Option<lr_babel::BabelAuthInterface> {
    if cfg.babel_keys.is_empty() {
        return None;
    }
    let mut keys: Vec<lr_babel::BabelMacKey> = Vec::new();
    for spec in &cfg.babel_keys {
        let Some(secret) = &spec.secret else {
            eprintln!("daemon: [[babel.key]] without 'secret' (fail closed)");
            return None;
        };
        let algorithm = spec
            .algorithm
            .as_deref()
            .and_then(lr_babel::BabelMacAlgorithm::from_name)
            .unwrap_or(lr_babel::BabelMacAlgorithm::HmacSha256);
        keys.push(lr_babel::BabelMacKey {
            algorithm,
            secret: secret.clone().into_bytes(),
        });
    }
    let first = keys.remove(0);
    let mut acfg = lr_babel::BabelAuthConfig::new(first);
    acfg.keys.extend(keys);
    acfg.accept_unauthenticated = cfg.babel_accept_unauthenticated;
    acfg.split_unicast_multicast = cfg.babel_split_unicast_multicast;
    acfg.pc_window = if cfg.babel_pc_window > 0 {
        Some(cfg.babel_pc_window)
    } else {
        None
    };
    let mut nonce = lr_babel::SystemNonceSource::new();
    // The outbound Index must be fresh (RFC 8967 §3.1): draw it from the
    // OS-entropy nonce source.
    use lr_babel::NonceSource;
    let mut index = [0u8; 8];
    nonce.fill(&mut index);
    match lr_babel::BabelAuthInterface::new(acfg, index.to_vec(), 0, Box::new(nonce)) {
        Ok(iface) => Some(iface),
        Err(e) => {
            eprintln!("daemon: babel auth config rejected: {} (fail closed)", e);
            None
        }
    }
}

fn lr_ip(addr: std::net::IpAddr) -> lr_core::addr::IpAddr {
    match addr {
        std::net::IpAddr::V4(v4) => lr_core::addr::IpAddr::V4(v4.octets()),
        std::net::IpAddr::V6(v6) => lr_core::addr::IpAddr::V6(v6.octets()),
    }
}

/// Babel daemon mode: run the Babel protocol over UDP (RFC 8966 §4) on an
/// IPv6 link-local address or an IPv4 local address. Without keys this is
/// the unsigned transport. With `[[babel.key]]` / `--babel-key`, every
/// datagram carries one MAC TLV per configured key and inbound datagrams go
/// through the full RFC 8967 §4.3 state machine (MAC test, PC verification,
/// Challenge Request/Reply resynchronization, RFC 9467 §3.1 unicast/
/// multicast PC split).
///
/// Authenticated transport uses two sockets so the destination class of
/// each datagram is exact (RFC 9467 §3.1 picks PCm vs PCu by destination):
/// a unicast socket bound to the local address and a multicast socket bound
/// to the group address. Challenge traffic is unicast to the peer, per
/// RFC 8967 §4.3.1.1/§4.3.1.2.
/// Run the Babel engine. `host = None` is the classic standalone
/// daemon; `Some(host)` plugs it into the multi-protocol supervisor
/// (rc.3) — see [`run_bgp_daemon`] for the split.
fn run_babel_daemon(cfg: &DaemonConfig, host: Option<EngineHost>) -> ExitCode {
    // ---- local address (IPv6 link-local with %scope, or IPv4) ----
    // When `[[babel.interface]]` blocks exist, resolve them against
    // the system's interfaces first so the daemon can pick the first
    // match's address as the bind source.
    let mut resolved_iface_name: Option<String> = None;
    if !cfg.babel_interfaces.is_empty() {
        match lr_osroute::ospf_transport::list_interfaces() {
            Ok(ifaces) => {
                println!(
                    "daemon: babel {} interface pattern(s) configured; enumerating {} system interface(s)",
                    cfg.babel_interfaces.len(),
                    ifaces.len()
                );
                for spec in &cfg.babel_interfaces {
                    let pat = spec.name.as_deref().unwrap_or("");
                    let matched: Vec<&lr_osroute::ospf_transport::InterfaceEntry> = ifaces
                        .iter()
                        .filter(|i| crate::daemon_config::glob_match(pat, &i.name))
                        .collect();
                    if matched.is_empty() {
                        println!(
                            "daemon: babel interface pattern '{}' matched 0 interfaces",
                            pat
                        );
                    } else {
                        println!(
                            "daemon: babel interface pattern '{}' matched {} interface(s): {}",
                            pat,
                            matched.len(),
                            matched
                                .iter()
                                .map(|i| i.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                        if resolved_iface_name.is_none() {
                            resolved_iface_name = Some(matched[0].name.clone());
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "daemon: babel interface enumeration unavailable ({}); ignoring [[babel.interface]] blocks",
                    e
                );
            }
        }
    }
    // Pick the bind address: explicit --local-address wins; otherwise
    // fall back to the first matched [[babel.interface]]'s address.
    let local_str = cfg.local_address.as_deref().or(cfg.listen_addr.as_deref());
    let local_str = if let Some(local_str) = local_str {
        local_str.to_string()
    } else if let Some(iface_name) = &resolved_iface_name {
        match lr_osroute::ospf_transport::list_interfaces() {
            Ok(ifaces) => {
                let iface = ifaces.iter().find(|i| &i.name == iface_name);
                let picked = iface.and_then(|i| {
                    if let Some(v4) = i.v4.first() {
                        Some(std::net::IpAddr::V4(*v4))
                    } else {
                        // Pick the first non-link-local IPv6, or fall
                        // back to the first IPv6 (often link-local).
                        i.v6.iter()
                            .find(|v| !(v.octets()[0] == 0xfe && (v.octets()[1] & 0xc0) == 0x80))
                            .map(|v| std::net::IpAddr::V6(*v))
                            .or_else(|| i.v6.first().map(|v| std::net::IpAddr::V6(*v)))
                    }
                });
                match picked {
                    Some(ip) => {
                        println!(
                            "daemon: babel using interface {} address {} as bind source",
                            iface_name, ip
                        );
                        ip.to_string()
                    }
                    None => {
                        eprintln!(
                            "daemon: babel interface {} has no usable address; specify --local-address",
                            iface_name
                        );
                        return ExitCode::from(2);
                    }
                }
            }
            Err(e) => {
                eprintln!("daemon: babel interface enumeration failed: {}", e);
                return ExitCode::from(2);
            }
        }
    } else {
        eprintln!("daemon: --protocol babel requires --local-address (IPv6 link-local or IPv4) or a [[babel.interface]] block matching a system interface");
        return ExitCode::from(2);
    };
    let local_str = local_str.as_str();
    // Accept `fe80::1%eth0`, `[fe80::1%eth0]:6696`, and bare IPv4.
    let bare = local_str
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or(local_str);
    let (addr_part, scope_part) = bare.split_once('%').unwrap_or((bare, ""));
    let scope_id: u32 = scope_part.parse().unwrap_or(0);
    let local: std::net::IpAddr = match addr_part.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("daemon: invalid babel local address: {}", local_str);
            return ExitCode::from(2);
        }
    };
    if local.is_unspecified() {
        eprintln!("daemon: babel local address must be a real interface address");
        return ExitCode::from(2);
    }
    let port = cfg.babel_port;

    // ---- multicast group (family must match the local address) ----
    let default_group = if local.is_ipv4() {
        "224.0.0.111"
    } else {
        "ff02::1:6"
    };
    let group: std::net::IpAddr = match cfg.babel_group.as_deref().unwrap_or(default_group).parse()
    {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("daemon: invalid babel group address");
            return ExitCode::from(2);
        }
    };
    if group.is_ipv4() != local.is_ipv4() {
        eprintln!("daemon: babel group and local address families differ");
        return ExitCode::from(2);
    }

    // ---- authentication ----
    let mut auth = build_babel_auth_interface(cfg);
    if let Some(iface) = &auth {
        let algorithms: Vec<&str> = iface
            .config()
            .keys
            .iter()
            .map(|k| k.algorithm.as_str())
            .collect();
        println!(
            "daemon: babel MAC auth enabled ({} key(s): {}), RFC 9467 split {}, window {}",
            algorithms.len(),
            algorithms.join(","),
            if cfg.babel_split_unicast_multicast {
                "on"
            } else {
                "off"
            },
            cfg.babel_pc_window
        );
    }

    // ---- sockets ----
    // Unicast socket: bound to the local address. In unsigned mode this is
    // also the multicast receiver (historical behaviour).
    let uc_bind = match local {
        std::net::IpAddr::V4(v4) => std::net::SocketAddr::from((v4, port)),
        std::net::IpAddr::V6(v6) => {
            std::net::SocketAddr::V6(std::net::SocketAddrV6::new(v6, port, 0, scope_id))
        }
    };
    let uc = match bind_babel_socket(uc_bind, true) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("daemon: babel bind {} failed: {}", uc_bind, e);
            return ExitCode::from(1);
        }
    };
    let _ = uc.set_ttl(255);
    let _ = uc.set_multicast_loop_v6(true);

    // Multicast socket: bound to the group address so every received
    // datagram's destination class is exact (RFC 9467 §3.1) — a socket
    // bound to a unicast address does not receive multicast on Linux.
    // The interface is mandatory for the membership join: v6 uses the
    // %scope ifindex, v4 the local address as the membership interface.
    let mc_bind = match group {
        std::net::IpAddr::V4(v4) => std::net::SocketAddr::from((v4, port)),
        std::net::IpAddr::V6(v6) => {
            std::net::SocketAddr::V6(std::net::SocketAddrV6::new(v6, port, 0, scope_id))
        }
    };
    let mc = match bind_babel_socket(mc_bind, true) {
        Ok(s) => {
            let joined = match (group, local) {
                (std::net::IpAddr::V4(g), std::net::IpAddr::V4(l)) => {
                    s.join_multicast_v4(&g, &l).is_ok()
                }
                (std::net::IpAddr::V6(g), _) => s.join_multicast_v6(&g, scope_id).is_ok(),
                _ => false,
            };
            if !joined {
                eprintln!("daemon: babel multicast join failed (group {})", group);
                // Non-fatal: unicast traffic still works.
            }
            Some(s)
        }
        Err(e) => {
            eprintln!("daemon: babel multicast bind {} failed: {}", mc_bind, e);
            return ExitCode::from(1);
        }
    };
    println!("daemon: babel listening on {} (group {})", uc_bind, group);

    // Set up the router with a Babel session. Embedded: the supervisor's
    // shared router (every engine's sessions live in one instance).
    let router = match &host {
        Some(h) => Arc::clone(&h.runtime.router),
        None => Arc::new(Mutex::new(DefaultRouter::new())),
    };
    let babel_local = lr_ip(local);
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
    // Locally originated networks enter the Loc-RIB and are announced as
    // Babel Updates (RFC 8966 §3.7) on the periodic announcement tick.
    {
        let mut r = router.lock().unwrap();
        for net in &cfg.networks {
            match Prefix::from_str(net) {
                Ok(p) => {
                    let (p, family) = originate_family_for(p);
                    let nh = originate_next_hop(cfg, family).or(Some(lr_ip(local)));
                    let _key = r.originate_family(p, family, nh);
                    println!("daemon: originating {}", p);
                }
                Err(_) => eprintln!("daemon: invalid network '{}'", net),
            }
        }
    }

    // Signal handling (idempotent — the multi-protocol supervisor
    // already installed the handlers; re-registering the same static
    // handler is harmless).
    if let Err(sig) = signal::init() {
        eprintln!("daemon: cannot install signal handlers (signal {})", sig);
        return ExitCode::from(1);
    }

    // Standalone: own running flag, own runtime, own API socket and
    // ticker. Embedded: the supervisor's shared runtime (one running
    // flag, one reload closure, one status registry, one ticker), and
    // a startup gate between the UDP binds above and the main loop.
    let runtime = match &host {
        Some(h) => Arc::clone(&h.runtime),
        None => Arc::new(Runtime {
            reload: Arc::new({
                let router = Arc::clone(&router);
                move || reload_config(None, None, &router, &Arc::new(Mutex::new(Vec::new())))
            }),
            router: Arc::clone(&router),
            running: Arc::new(AtomicBool::new(true)),
            status_lines: Arc::new(Vec::new),
        }),
    };
    let running = Arc::clone(&runtime.running);
    match &host {
        None => {
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
        }
        Some(h) => {
            // Embedded: report the binds, wait for the supervisor's
            // release (privilege drop + API socket happen in between).
            let _ = h.report.send(EngineReport::Started);
            if h.gate.wait().is_err() {
                println!("daemon: babel engine startup aborted");
                return ExitCode::SUCCESS;
            }
        }
    }

    let mc_sock = mc.as_ref();
    let _ = uc.set_nonblocking(true);
    if let Some(s) = mc_sock {
        let _ = s.set_nonblocking(true);
    }
    let mut buf = [0u8; 65535];
    let mut last_gc_ms: u64 = 0;
    let mut dropped: u64 = 0;
    let start = WallClock::now();
    // Periodic announcement state: RFC 8966 §3.4 Hellos keep the adjacency
    // alive; §3.7 Updates advertise the Loc-RIB (originated networks and
    // non-Babel routes — split horizon keeps babel-learned routes from
    // echoing back).
    let mut boot_nonce = lr_babel::SystemNonceSource::new();
    use lr_babel::NonceSource;
    let mut boot_bytes = [0u8; 8];
    boot_nonce.fill(&mut boot_bytes);
    let babel_router_id = babel_router_id_for(local, boot_bytes);
    let mut babel_seqno: u16 = 0;
    let mut last_announce_ms: u64 = 0;
    // Busyness for the idle sleep below: receiving a datagram, sending
    // the periodic announcement or draining router output counts; an
    // idle pass sleeps 10 ms instead of spinning the core (the loop is
    // otherwise a non-blocking busy-spin — the only sub-second timer
    // is the 1 s Hello interval).
    let mut busy: bool;

    while running.load(Ordering::Relaxed) {
        dispatch_signals(&runtime);
        if !running.load(Ordering::Relaxed) {
            break;
        }
        busy = false;
        let now_ms = start.elapsed().as_millis() as u64;

        // Periodic announcement (Hello + Router-Id + Next-Hop + Updates).
        if now_ms >= last_announce_ms + BABEL_HELLO_INTERVAL_MS {
            last_announce_ms = now_ms;
            busy = true;
            babel_seqno = babel_seqno.wrapping_add(1);
            let announce = {
                let r = router.lock().unwrap();
                build_babel_announcement(&r, local, babel_router_id, babel_seqno)
            };
            let dest = match group {
                std::net::IpAddr::V4(g) => std::net::SocketAddr::from((g, port)),
                std::net::IpAddr::V6(g) => {
                    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(g, port, 0, scope_id))
                }
            };
            let payload = match &mut auth {
                Some(iface) => {
                    let ph = lr_babel::BabelPseudoHeader {
                        source: lr_ip(local),
                        source_port: port,
                        destination: lr_ip(group),
                        destination_port: port,
                    };
                    match iface.authenticate_packet(&announce, ph) {
                        Ok(signed) => signed,
                        Err(e) => {
                            eprintln!("daemon: babel authenticate failed: {}", e);
                            continue;
                        }
                    }
                }
                None => announce,
            };
            let _ = uc.send_to(&payload, dest);
        }

        // Receive inbound. Two paths in authenticated mode: multicast
        // (exact group destination) and unicast (exact local destination).
        for (sock, is_multicast) in std::iter::once((&uc, false)).chain(mc_sock.map(|s| (s, true)))
        {
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, peer)) => {
                        busy = true;
                        if n == 0 {
                            continue;
                        }
                        // RFC 8966 §4.1: the source port MUST be the Babel
                        // port; our own datagrams are skipped (multicast
                        // loop is on so same-host links deliver them).
                        if peer.port() != port || peer.ip() == local {
                            continue;
                        }
                        let dest = if is_multicast { group } else { local };
                        let ph = lr_babel::BabelPseudoHeader {
                            source: lr_ip(peer.ip()),
                            source_port: peer.port(),
                            destination: lr_ip(dest),
                            destination_port: port,
                        };
                        let mut r = router.lock().unwrap();
                        match &mut auth {
                            Some(iface) => {
                                let out = iface.verify(&buf[..n], ph, now_ms);
                                for action in out.actions {
                                    if let Some(pkt) = build_challenge_packet(
                                        iface,
                                        &action,
                                        local,
                                        peer.ip(),
                                        port,
                                    ) {
                                        let dst = match peer {
                                            std::net::SocketAddr::V6(v6) => {
                                                std::net::SocketAddr::V6(
                                                    std::net::SocketAddrV6::new(
                                                        *v6.ip(),
                                                        port,
                                                        0,
                                                        v6.scope_id(),
                                                    ),
                                                )
                                            }
                                            std::net::SocketAddr::V4(v4) => {
                                                std::net::SocketAddr::from((*v4.ip(), port))
                                            }
                                        };
                                        let _ = uc.send_to(&pkt, dst);
                                    }
                                }
                                match out.accepted {
                                    Some(plain) => {
                                        let _ = r.feed_input(h, &plain);
                                    }
                                    None => dropped += 1,
                                }
                            }
                            None => {
                                let _ = r.feed_input(h, &buf[..n]);
                            }
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }

        // Periodic neighbour-state expiry (RFC 8967 §4.4).
        if auth.is_some() && now_ms >= last_gc_ms + 5_000 {
            last_gc_ms = now_ms;
            if let Some(iface) = &mut auth {
                let _ = iface.gc(now_ms);
            }
        }

        // Drain outbound and send it as an authenticated multicast (or
        // plain in unsigned mode) via the unicast socket: the bound local
        // address is the datagram source the peers' pseudo-headers see.
        let out = {
            let mut r = router.lock().unwrap();
            r.drain_output(h)
        };
        if !out.is_empty() {
            busy = true;
            let dest = match group {
                std::net::IpAddr::V4(g) => std::net::SocketAddr::from((g, port)),
                std::net::IpAddr::V6(g) => {
                    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(g, port, 0, scope_id))
                }
            };
            let payload = match &mut auth {
                Some(iface) => {
                    let ph = lr_babel::BabelPseudoHeader {
                        source: lr_ip(local),
                        source_port: port,
                        destination: lr_ip(group),
                        destination_port: port,
                    };
                    match iface.authenticate_packet(&out, ph) {
                        Ok(signed) => signed,
                        Err(e) => {
                            eprintln!("daemon: babel authenticate failed: {}", e);
                            continue;
                        }
                    }
                }
                None => out,
            };
            let _ = uc.send_to(&payload, dest);
        }

        // Idle pass: sleep instead of spinning (see `busy` above).
        if !busy {
            thread::sleep(Duration::from_millis(10));
        }
    }
    if dropped > 0 {
        println!(
            "daemon: babel dropped {} unauthenticated/replayed datagrams",
            dropped
        );
    }
    println!("daemon: babel shutdown complete");
    ExitCode::SUCCESS
}

/// Babel Hello interval for the daemon transport (RFC 8966 §3.4; the
/// interval is advertised to peers who derive their hold time from it).
const BABEL_HELLO_INTERVAL_MS: u64 = 1000;

/// Bind one Babel UDP socket. `reuse` sets SO_REUSEADDR, which several
/// Babel speakers on one host need to share the multicast group address
/// and port (RFC 8966 §4: every speaker binds the same port).
fn bind_babel_socket(
    addr: std::net::SocketAddr,
    reuse: bool,
) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = match addr {
        std::net::SocketAddr::V4(_) => Domain::IPV4,
        std::net::SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if reuse {
        sock.set_reuse_address(true)?;
    }
    sock.set_nonblocking(false)?;
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// Router-Id for the babel transport: the local address identifies the
/// speaker, and per-boot random octets make every daemon instance a fresh
/// Babel source (RFC 8966 §3.3 router ids must be unique in the routing
/// domain; §3.7.1 sources are keyed by router-id, so a restart must not
/// re-emit stale-looking sequence numbers under the old source key).
fn babel_router_id_for(local: std::net::IpAddr, boot: [u8; 8]) -> [u8; 8] {
    let mut id = [0u8; 8];
    match local {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            id[..4].copy_from_slice(&o);
            id[4..].copy_from_slice(&boot[4..8]);
        }
        std::net::IpAddr::V6(_) => {
            id.copy_from_slice(&boot);
        }
    }
    id
}

/// Build one periodic announcement datagram: Hello + Router-Id + Next-Hop +
/// Updates for every Loc-RIB route that was not learned over this Babel
/// session (split horizon).
///
/// The frame is returned WITHOUT the MAC trailer; the caller authenticates
/// it when keys are configured.
fn build_babel_announcement(
    router: &DefaultRouter,
    local: std::net::IpAddr,
    router_id: [u8; 8],
    seqno: u16,
) -> Vec<u8> {
    use lr_babel::message::{Hello, NextHop, RouterId as RouterIdTlv, Update};
    use lr_babel::tlv::{Tlv, TlvType};

    let mut frame = lr_babel::BabelFrame::empty();
    // §3.4: Hello with the advertised interval in centiseconds.
    frame.body.push(Tlv::new(
        TlvType::Hello,
        Hello::new(seqno, (BABEL_HELLO_INTERVAL_MS / 10) as u16)
            .encode()
            .to_vec(),
    ));
    // §4.6.7 Router-Id — must precede the Updates that depend on it.
    frame.body.push(Tlv::new(
        TlvType::RouterId,
        RouterIdTlv { id: router_id }.encode().to_vec(),
    ));
    // §4.6.8 Next-Hop per address family, before the Updates using it.
    let nh_ae: u8 = if local.is_ipv4() { 1 } else { 2 };
    frame.body.push(Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: nh_ae,
            address: lr_ip(local),
        }
        .encode(),
    ));

    // Updates: every Loc-RIB best route that did not come from Babel.
    // Metric 96 mirrors babeld's default wired-link cost; infinity (0xFFFF)
    // is never sent here (withdrawals happen by prefix disappearance).
    const ADVERTISED_METRIC: u16 = 96;
    const UPDATE_INTERVAL_CS: u16 = 300;
    let snapshot = router.rib_snapshot();
    for route in snapshot {
        if route.protocol == lr_core::rib::Protocol::Babel {
            continue;
        }
        let prefix = &route.key.prefix;
        let (ae, octets): (u8, Vec<u8>) = match prefix.addr {
            lr_core::addr::IpAddr::V4(v4) => (1, v4.to_vec()),
            lr_core::addr::IpAddr::V6(v6) => (2, v6.to_vec()),
        };
        let used = (prefix.prefix_len as usize).div_ceil(8).min(octets.len());
        frame.body.push(Tlv::new(
            TlvType::Update,
            Update {
                ae,
                flags: 0,
                prefix_len: prefix.prefix_len,
                omitted: 0,
                interval_cs: UPDATE_INTERVAL_CS,
                seqno,
                metric: ADVERTISED_METRIC,
                prefix: octets[..used].to_vec(),
                src_prefix_len: 0,
                src_prefix: Vec::new(),
            }
            .encode(),
        ));
    }
    lr_babel::BabelCodec::new()
        .encode_vec(&frame)
        .unwrap_or_default()
}

/// Build one authenticated unicast control datagram (Challenge Request or
/// Challenge Reply) to `peer` — RFC 8967 §4.3.1.1/§4.3.1.2 require these to
/// be sent promptly to the peer's unicast address, MAC-protected like any
/// other packet. The pseudo-header source is the local (bound) address.
fn build_challenge_packet(
    iface: &mut lr_babel::BabelAuthInterface,
    action: &lr_babel::BabelAuthAction,
    local: std::net::IpAddr,
    peer: std::net::IpAddr,
    port: u16,
) -> Option<Vec<u8>> {
    let mut frame = lr_babel::BabelFrame::empty();
    match action {
        lr_babel::BabelAuthAction::SendChallengeRequest(n) => {
            frame.body.push(lr_babel::challenge_request_tlv(n));
        }
        lr_babel::BabelAuthAction::SendChallengeReply(n) => {
            frame.body.push(lr_babel::challenge_reply_tlv(n));
        }
    }
    let raw = lr_babel::BabelCodec::new().encode_vec(&frame).ok()?;
    let ph = lr_babel::BabelPseudoHeader {
        source: lr_ip(local),
        source_port: port,
        destination: lr_ip(peer),
        destination_port: port,
    };
    iface.authenticate_packet(&raw, ph).ok()
}

/// Spawn the BMP sender thread: connects to `target` (host:port) and
/// forwards every BMP message the router emits. Reconnects with
/// backoff; messages produced while disconnected are dropped (BMP is
/// best-effort monitoring).
fn spawn_bmp_sender(target: &str, router: &Arc<Mutex<DefaultRouter>>) -> Result<(), String> {
    use std::sync::mpsc;
    let addr = resolve(target).ok_or_else(|| format!("invalid address: {target}"))?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    {
        let mut r = router.lock().unwrap();
        r.set_bmp_sink(move |bytes| {
            // Channel send is non-blocking enough for the router lock;
            // unbounded queueing under a stuck collector is bounded by
            // dropping when the receiver is gone.
            let _ = tx.send(bytes.to_vec());
        });
    }
    thread::Builder::new()
        .name("lr-bmp-sender".into())
        .spawn(move || {
            let mut backoff_ms = 500u64;
            loop {
                match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                    Ok(mut stream) => {
                        println!("daemon: bmp station {} connected", addr);
                        backoff_ms = 500; // a good connect resets the timer
                        let mut station_alive = true;
                        while let Ok(bytes) = rx.recv() {
                            use std::io::Write;
                            if stream.write_all(&bytes).is_err() {
                                station_alive = false;
                                break;
                            }
                        }
                        if !station_alive {
                            continue; // station dropped — reconnect
                        }
                        // recv() only fails when the sink is dropped,
                        // i.e. the router is gone: exit.
                        return;
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(backoff_ms));
                        backoff_ms = (backoff_ms * 2).min(10_000);
                    }
                }
            }
        })
        .map_err(|e| format!("spawn bmp sender: {e}"))?;
    Ok(())
}

/// Write the Loc-RIB as an RFC 6396 TABLE_DUMP_V2 dump (one peer index
/// table + one RIB record per prefix). Peers come from the session
/// summaries (BGP-learned routes reference their session's peer); local,
/// OSPF and Babel routes reference the synthetic local peer 0, exactly
/// how BIRD's `protocol mrt` represents non-BGP sources. Returns the
/// number of RIB records written.
/// Unix-only: the runtime API that drives it is Unix-gated.
#[cfg(unix)]
/// Write the Loc-RIB as an RFC 6396 TABLE_DUMP_V2 dump.
///
/// `routes` and `summaries` are caller-provided snapshots so the file I/O
/// (which can block on a slow or hung filesystem) never runs while the
/// router lock is held.
pub(crate) fn write_mrt_rib_dump(
    routes: &[lr_core::rib::Route],
    summaries: &[lr_router::SessionSummary],
    router_id: lr_core::addr::RouterId,
    path: &str,
) -> Result<usize, String> {
    use lr_core::rib::Protocol;
    use lr_mrt::{MrtRibDump, PeerEntry, RibEntry, RibTable};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut dump = MrtRibDump::new(router_id.as_u32(), "loc-rib");
    // Peer 0: the synthetic local source (BIRD convention: ::, AS 0).
    dump.add_peer(PeerEntry {
        bgp_id: 0,
        ip: lr_core::addr::IpAddr::V6([0; 16]),
        asn: lr_core::addr::Asn(0),
    });
    // One peer per BGP session that contributed at least one route.
    let mut session_peer: std::collections::BTreeMap<u64, u16> = std::collections::BTreeMap::new();
    for s in summaries {
        if s.kind != "bgp" {
            continue;
        }
        if !routes
            .iter()
            .any(|r| r.origin.peer == s.handle.0 && r.protocol == Protocol::Bgp)
        {
            continue;
        }
        let index = dump.add_peer(PeerEntry {
            bgp_id: s.peer_bgp_id.map(|id| id.as_u32()).unwrap_or(0),
            // The session summary carries the peer's BGP identifier but
            // not its transport address; the ID in dotted-quad form is
            // the conventional stand-in.
            ip: lr_core::addr::IpAddr::V4(
                s.peer_bgp_id.map(|id| id.to_v4_bytes()).unwrap_or([0; 4]),
            ),
            asn: lr_core::addr::Asn(s.peer_as.0),
        });
        session_peer.insert(s.handle.0, index);
    }
    // Flatten into prefix-keyed entries, then split plain / add-path.
    let mut by_prefix: std::collections::BTreeMap<lr_core::addr::Prefix, Vec<RibEntry>> =
        std::collections::BTreeMap::new();
    for r in routes {
        let entry = RibEntry {
            peer_index: match (r.protocol, session_peer.get(&r.origin.peer)) {
                (Protocol::Bgp, Some(idx)) => *idx,
                _ => 0,
            },
            originated_time: now,
            path_id: r.path_id,
            attributes: lr_mrt::encode_attributes(&r.attributes),
        };
        by_prefix.entry(r.key.prefix).or_default().push(entry);
    }
    let mut records = 0usize;
    for (prefix, entries) in by_prefix {
        for add_path in [false, true] {
            let entries: Vec<RibEntry> = entries
                .iter()
                .filter(|e| (e.path_id != 0) == add_path)
                .cloned()
                .collect();
            if entries.is_empty() {
                continue;
            }
            dump.add_table(RibTable {
                sequence: records as u32,
                prefix,
                add_path,
                entries,
            });
            records += 1;
        }
    }
    let bytes = dump.encode(now).map_err(|e| format!("mrt encode: {}", e))?;
    std::fs::write(path, bytes).map_err(|e| format!("mrt write {path}: {e}"))?;
    Ok(records)
}

/// Convert an `lr_core` address into its `std::net` counterpart
/// (for sockets and transport modules).
fn to_std_ip(ip: IpAddr) -> std::net::IpAddr {
    match ip {
        IpAddr::V4(o) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(o)),
        IpAddr::V6(o) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)),
    }
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

/// Parse a labelled-network entry of the form `"<prefix> <labels>"` where
/// `labels` is a comma-separated list of 20-bit values. Used by both
/// `--labeled-network` and the `labeled_networks` TOML key.
fn parse_labeled_network(spec: &str) -> Result<(Prefix, lr_mpls::LabelStack), String> {
    let mut parts = spec.split_whitespace();
    let prefix_str = parts
        .next()
        .ok_or_else(|| "expected '<prefix> <label>[,<label>...]': missing prefix".to_string())?;
    let labels_str = parts
        .next()
        .ok_or_else(|| "expected '<prefix> <label>[,<label>...]': missing labels".to_string())?;
    let prefix = Prefix::from_str(prefix_str).map_err(|e| format!("invalid prefix: {}", e))?;
    let mut labels = Vec::new();
    for tok in labels_str.split(',') {
        let v: u32 = tok
            .trim()
            .parse()
            .map_err(|_| format!("invalid label value '{}'", tok))?;
        if !lr_mpls::Label::is_valid_value(v) {
            return Err(format!("label value {} exceeds the 20-bit range", v));
        }
        labels.push(lr_mpls::Label::new(v));
    }
    if labels.is_empty() {
        return Err("at least one label is required".to_string());
    }
    Ok((prefix, lr_mpls::LabelStack::from_vec(labels)))
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

/// The next-hop a locally originated route should carry: the family-
/// matching local source address. Keeps the Loc-RIB route
/// self-describing (the `routes` API and MRT dumps show it), lets
/// kernel FIB installs work, and gives iBGP egress a NEXT_HOP to
/// preserve — an UPDATE without the attribute is discarded by the
/// peer (RFC 4271 §6.3).
fn originate_next_hop(cfg: &DaemonConfig, family: NlriFamily) -> Option<IpAddr> {
    match family {
        NlriFamily::IPV4_UNICAST => {
            cfg.local_address
                .as_deref()
                .and_then(|a| match IpAddr::from_str(a) {
                    Ok(IpAddr::V4(_)) => Some(IpAddr::from_str(a).unwrap()),
                    _ => None,
                })
        }
        NlriFamily::IPV6_UNICAST => cfg
            .local_address_v6
            .as_deref()
            .or(cfg.local_address.as_deref())
            .and_then(|a| match IpAddr::from_str(a) {
                Ok(IpAddr::V6(_)) => Some(IpAddr::from_str(a).unwrap()),
                _ => None,
            }),
        _ => None,
    }
}

/// Shared daemon state threaded through the I/O loops.
struct Runtime {
    router: Arc<Mutex<DefaultRouter>>,
    running: Arc<AtomicBool>,
    /// Re-apply the configuration file (SIGHUP / API `reload`).
    reload: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
    /// Protocol-specific extra `status` lines for the runtime API
    /// (e.g. LDP counters). Empty for the BGP/Babel/OSPF/BMP modes.
    status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
}

/// Act on every pending signal. SIGTERM/SIGINT trigger a graceful stop
/// (sessions are closed with a NOTIFICATION before the FIN); SIGHUP
/// reloads the configuration file. Safe to call from any thread —
/// exactly one caller wins the atomic take.
///
/// In multi-protocol mode this is a no-op on every thread except the
/// supervisor: [`signal::set_supervised`] marks the supervisor as the
/// sole consumer, so engine threads (connectors, session pumps, main
/// loops) cannot steal the shutdown signal from it.
fn dispatch_signals(rt: &Runtime) {
    if signal::supervised() {
        return;
    }
    dispatch_pending_signals(rt);
}

/// Consume and act on pending signals unconditionally — the
/// multi-protocol supervisor's dispatch (engines go through the
/// [`dispatch_signals`] guard above).
fn dispatch_pending_signals(rt: &Runtime) {
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
        status_lines: Box::new({
            let rt = Arc::clone(rt);
            move || (rt.status_lines)()
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
    dialect: Option<&str>,
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
    // The reload goes through the same dialect path as startup: a
    // config loaded from a BIRD/FRR file re-parses as BIRD/FRR, so a
    // compat-mode daemon does not break on SIGHUP.
    let forced = match dialect {
        Some("bird") => Some(crate::compat::Dialect::Bird),
        Some("frr") => Some(crate::compat::Dialect::Frr),
        Some("toml") | None => Some(crate::compat::Dialect::Toml),
        Some(other) => {
            return vec![format!(
                "reload: unknown config dialect '{}' (keeping current config)",
                other
            )]
        }
    };
    if let Err(e) = crate::compat::load_config_text(&text, forced, &mut fresh) {
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
                    let nh = originate_next_hop(&fresh, family);
                    r.originate_family(p, family, nh);
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

#[cfg(test)]
mod lsp_tests {
    use super::*;

    /// The private tag is a magic byte by necessity (const context);
    /// this pins it to the lr-bgp definition so a renumbering breaks
    /// the build's tests, not the dataplane.
    #[test]
    fn label_stack_tag_matches_lr_bgp() {
        assert_eq!(
            LR_MPLS_LABEL_STACK_TAG,
            lr_bgp::path::AttrType::LrMplsLabelStack.to_u8()
        );
    }

    /// Build a best route shaped like the router pipeline emits it:
    /// `proto` 2 = locally originated, anything else = peer-learned.
    fn route(
        origin_proto: u32,
        next_hop: Option<IpAddr>,
        stack: Option<&lr_mpls::LabelStack>,
    ) -> lr_core::rib::Route {
        let mut attrs = lr_core::attr::Attributes::new();
        if let Some(s) = stack {
            attrs.insert(lr_core::attr::Attribute {
                tag: lr_core::attr::AttrTag(LR_MPLS_LABEL_STACK_TAG),
                flags: 0x20, // optional (matches PathAttribute::set_label_stack)
                value: s.encode_4octet(),
            });
        }
        lr_core::rib::Route {
            key: lr_core::rib::RouteKey::new(
                "198.51.100.0/24".parse().unwrap(),
                NlriFamily::IPV4_LABELED_UNICAST,
            ),
            origin: lr_core::rib::RouteOrigin {
                proto: origin_proto,
                peer: 0,
            },
            protocol: lr_core::rib::Protocol::Bgp,
            preference: lr_core::rib::Preference::new(
                lr_core::rib::Protocol::Bgp.default_admin_distance(),
                0,
            ),
            next_hop,
            attributes: attrs,
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    #[test]
    fn plain_when_no_label_stack() {
        let r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), None);
        assert_eq!(lsp_decision(&r), LspDecision::Plain);
    }

    #[test]
    fn push_for_received_labelled_route() {
        let stack = lr_mpls::LabelStack::from_values([100]);
        let r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), Some(&stack));
        assert_eq!(lsp_decision(&r), LspDecision::Push(stack));
    }

    #[test]
    fn pop_local_for_originated_labelled_route() {
        let stack = lr_mpls::LabelStack::from_values([100]);
        let r = route(2, None, Some(&stack));
        assert_eq!(
            lsp_decision(&r),
            LspDecision::PopLocal(lr_mpls::Label::new_value(100))
        );
    }

    #[test]
    fn plain_for_implicit_null_top_label() {
        // PHP: the tail advertises implicit null, the head must not push.
        let stack = lr_mpls::LabelStack::from_values([lr_mpls::Label::IMPLICIT_NULL.value]);
        let r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), Some(&stack));
        assert_eq!(lsp_decision(&r), LspDecision::Plain);
    }

    #[test]
    fn plain_when_received_route_has_no_next_hop() {
        let stack = lr_mpls::LabelStack::from_values([100]);
        let r = route(0, None, Some(&stack));
        assert_eq!(lsp_decision(&r), LspDecision::Plain);
    }

    #[test]
    fn garbled_stack_attribute_is_ignored() {
        let mut r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), None);
        r.attributes.insert(lr_core::attr::Attribute {
            tag: lr_core::attr::AttrTag(LR_MPLS_LABEL_STACK_TAG),
            flags: 0x20,
            value: vec![0xff; 3], // not a multiple of 4 → decode failure
        });
        assert_eq!(lsp_decision(&r), LspDecision::Plain);
    }

    #[test]
    fn multi_label_stack_round_trips() {
        let stack = lr_mpls::LabelStack::from_values([100, 200]);
        let r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), Some(&stack));
        match lsp_decision(&r) {
            LspDecision::Push(s) => {
                assert_eq!(
                    s.labels().iter().map(|l| l.value).collect::<Vec<_>>(),
                    [100, 200]
                );
            }
            other => panic!("expected Push, got {:?}", other),
        }
    }
}
