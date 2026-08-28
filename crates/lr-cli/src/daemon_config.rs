//! Configuration model for `lr-daemon`: globals (the historical
//! single-peer CLI flags / `[bgp]` TOML section) plus explicit
//! `[[peer]]` tables for multi-peer deployments.
//!
//! Inheritance rule: every `[[peer]]` field left unset inherits the
//! corresponding global. The legacy single-peer keys (`--peer`,
//! `bgp.peer_addr`) are synthesised into one implicit peer so old
//! configs behave exactly as before.

use std::process::ExitCode;

/// Per-peer settings — one `[[peer]]` TOML table (or one `--peer` CLI
/// flag). `None` fields inherit the `[bgp]` globals.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PeerSpec {
    /// Human-readable label used in logs (defaults to remote/address).
    pub name: Option<String>,
    /// Remote `host:port` to connect to (outbound peer). Mutually
    /// exclusive with `address` until RFC 4271 §6.8 collision detection
    /// is implemented.
    pub remote: Option<String>,
    /// Expected source IP of inbound connections (listen-only peer).
    pub address: Option<String>,
    /// Peer AS; `0` = inherit the global `peer_as`.
    pub peer_as: u32,

    // --- per-peer overrides (None/empty = inherit the global value) ---
    pub hold_time: Option<u16>,
    /// RFC 4724 graceful restart time (seconds).
    pub gr_restart_time: Option<u16>,
    /// RFC 9494 LLGR stale time (seconds).
    pub llgr_stale_time: Option<u32>,
    /// Local cap on the peer-advertised LLGR stale time (seconds).
    pub llgr_max_stale_time: Option<u32>,
    /// Source address for next-hop-self egress.
    pub local_address: Option<String>,
    /// IPv6 source address for IPv6 NLRI / RFC 5549 ENH egress.
    pub local_address_v6: Option<String>,
    /// RFC 2385 TCP MD5 shared secret.
    pub md5_key: Option<String>,
    /// RFC 5925 TCP-AO keys as `id:secret` pairs.
    pub tcp_ao_keys: Option<Vec<String>>,
    pub tcp_ao_algorithm: Option<String>,
    pub tcp_ao_maclen: Option<u8>,
    /// RFC 7911 Add-Path capability.
    pub add_path: Option<bool>,
    pub add_path_max_paths: Option<u32>,
    /// RFC 4760 MP-BGP families beyond the default IPv4 unicast.
    pub mp_families: Option<Vec<String>>,
    /// RFC 5549 Extended Next-Hop.
    pub extended_next_hop: Option<bool>,
    /// RFC 5082 GTSM hop count (`Some(1)` = single-hop TTL security).
    pub gtsm_hops: Option<u8>,
    /// Per-peer maximum-prefix limit.
    pub max_prefixes: Option<u32>,
    pub max_prefix_action: Option<String>,
    pub max_prefix_threshold: Option<u8>,
}

impl PeerSpec {
    /// Short description for log lines: the explicit name, else the
    /// remote address, else the expected inbound address.
    pub fn label(&self) -> &str {
        self.name
            .as_deref()
            .or(self.remote.as_deref())
            .or(self.address.as_deref())
            .unwrap_or("(unnamed)")
    }

    /// True when the peer can accept inbound connections (an expected
    /// source address is configured).
    pub fn is_inbound(&self) -> bool {
        self.address.is_some()
    }

    /// True when the daemon should connect out to this peer.
    pub fn is_outbound(&self) -> bool {
        self.remote.is_some()
    }
}

/// Daemon configuration (TOML or CLI flags). The historical fields are
/// the globals every `PeerSpec` inherits from; `peers` carries the
/// explicit per-peer entries.
#[derive(Debug, Clone, Default)]
pub(crate) struct DaemonConfig {
    pub local_as: u32,
    pub peer_as: u32,
    pub router_id: String,
    /// Legacy single-peer remote address (`bgp.peer_addr` in TOML).
    pub peer_addr: Option<String>,
    /// Local listen address (inbound connections).
    pub listen_addr: Option<String>,
    /// Explicit local interface address (next-hop-self).
    pub local_address: Option<String>,
    /// Locally originated networks.
    pub networks: Vec<String>,
    /// Install best routes into the kernel FIB.
    pub install_kernel: bool,
    /// BGP hold time (seconds).
    pub hold_time: u16,
    /// RFC 4724 graceful restart time to advertise (seconds). 0 disables.
    pub gr_restart_time: u16,
    /// RFC 9494 Long-Lived Graceful Restart stale time (seconds).
    pub llgr_stale_time: u32,
    /// Optional local cap (seconds) for the received LLGR stale time.
    pub llgr_max_stale_time: u32,
    /// RFC 2385 TCP MD5 shared secret for the BGP session.
    pub md5_key: Option<String>,
    /// RFC 5925 TCP-AO keys as "id:secret" pairs.
    pub tcp_ao_keys: Vec<String>,
    /// TCP-AO MAC algorithm ("hmac-sha1" or "cmac-aes").
    pub tcp_ao_algorithm: String,
    /// TCP-AO MAC length in bytes (0 = algorithm default).
    pub tcp_ao_maclen: u8,
    /// Drop privileges to this user (name or uid) after binding.
    pub user: Option<String>,
    /// Drop privileges to this group (name or gid).
    pub group: Option<String>,
    /// Runtime API socket path (Unix domain socket, 0600).
    pub api_socket: Option<String>,
    /// Configuration file the daemon was started with (reload source).
    pub config_path: Option<String>,
    /// RFC 7911 Add-Path capability.
    pub add_path: bool,
    /// RFC 7911: how many paths per prefix the decision process keeps.
    pub add_path_max_paths: u32,
    /// RFC 4760 MP-BGP families advertised in OPEN.
    pub mp_families: Vec<String>,
    /// RFC 5549 Extended Next-Hop.
    pub extended_next_hop: bool,
    /// Local IPv6 source address for next-hop-self egress.
    pub local_address_v6: Option<String>,
    /// RFC 5082 GTSM: `None` = disabled; `Some(hops)` = multihop.
    pub gtsm_hops: Option<u8>,
    /// Per-peer maximum-prefix limit. `None` = no limit.
    pub max_prefixes: Option<u32>,
    /// Action when the limit is exceeded: "warn", "teardown", "restart".
    pub max_prefix_action: String,
    /// Early-warning threshold percentage (0..=100). 0 disables.
    pub max_prefix_threshold: u8,
    /// Protocol to run: "bgp" (default) or "babel".
    pub protocol: String,
    /// Babel multicast group address (default: ff02::1:6).
    pub babel_group: Option<String>,
    /// Babel local port (default: 6696).
    pub babel_port: u16,

    /// Explicit `[[peer]]` entries and repeatable `--peer` flags.
    /// Post-parse, [`DaemonConfig::finalize`] also synthesises the
    /// legacy single-peer entry when this is empty.
    pub peers: Vec<PeerSpec>,
    /// True when at least one `[[peer]]` table was parsed — switches
    /// the listener to strict source-address matching instead of the
    /// historical accept-any behaviour.
    pub explicit_peers: bool,
}

impl DaemonConfig {
    /// Field defaults that differ from `Default::default()`.
    pub fn with_defaults() -> Self {
        Self {
            hold_time: 90,
            tcp_ao_algorithm: "hmac-sha1".to_string(),
            add_path_max_paths: 6,
            max_prefix_action: "warn".to_string(),
            max_prefix_threshold: 75,
            protocol: "bgp".to_string(),
            babel_port: 6696,
            ..Default::default()
        }
    }

    /// Apply the legacy-single-peer synthesis after all inputs (CLI +
    /// TOML) are merged: with no explicit peers, the historical
    /// `--peer` / `bgp.peer_addr` (or a bare `--listen`) maps onto one
    /// implicit peer so previous behaviour is preserved exactly.
    pub fn finalize(&mut self) {
        if self.peers.is_empty() && (self.peer_addr.is_some() || self.listen_addr.is_some()) {
            self.peers.push(PeerSpec {
                remote: self.peer_addr.clone(),
                ..Default::default()
            });
        }
    }

    /// Effective peer AS for `peer` (per-peer value or the global).
    pub fn effective_peer_as(&self, peer: &PeerSpec) -> u32 {
        if peer.peer_as != 0 {
            peer.peer_as
        } else {
            self.peer_as
        }
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(value, "true" | "1" | "yes")
}

fn parse_str_array(value: &str) -> Vec<String> {
    let inner = value.trim_start_matches('[').trim_end_matches(']');
    inner
        .split(',')
        .map(|item| item.trim().trim_matches('"').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn parse_gtsm(value: &str) -> Option<u8> {
    if parse_bool(value) || value == "1" {
        Some(1)
    } else {
        value.parse::<u8>().ok()
    }
}

/// Minimal TOML subset parser: `key = value` lines, `[section]` headers,
/// `[[peer]]` array-of-table sections, `#` comments, and quoted strings.
/// Sufficient for the daemon's config schema (see templates/daemon.toml).
pub(crate) fn parse_toml_subset(text: &str, cfg: &mut DaemonConfig) -> Result<(), String> {
    let mut section = String::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Array-of-tables: `[[peer]]` starts a new peer entry.
        if line.starts_with("[[") && line.ends_with("]]") {
            let name = line[2..line.len() - 2].trim();
            if name == "peer" {
                cfg.peers.push(PeerSpec::default());
                cfg.explicit_peers = true;
                section = "peer".to_string();
            } else {
                // Unknown array table: tolerate (forward compatibility),
                // but leave peer context so keys do not leak into one.
                section = format!("unknown-array.{name}");
            }
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
        if section == "peer" {
            let Some(peer) = cfg.peers.last_mut() else {
                return Err(format!("line {}: key outside a [[peer]] table", lineno + 1));
            };
            apply_peer_key(peer, key, value).map_err(|e| format!("line {}: {}", lineno + 1, e))?;
            continue;
        }
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
            "bgp.graceful_restart_time" => {
                cfg.gr_restart_time = value.parse().unwrap_or(120);
            }
            "bgp.llgr_stale_time" => {
                cfg.llgr_stale_time = value.parse().unwrap_or(0);
            }
            "bgp.llgr_max_stale_time" => {
                cfg.llgr_max_stale_time = value.parse().unwrap_or(0);
            }
            "bgp.install_kernel" => cfg.install_kernel = parse_bool(value),
            "bgp.add_path" => cfg.add_path = parse_bool(value),
            "bgp.add_path_max_paths" => cfg.add_path_max_paths = value.parse().unwrap_or(6),
            "bgp.extended_next_hop" => cfg.extended_next_hop = parse_bool(value),
            "bgp.local_address_v6" => cfg.local_address_v6 = Some(value.to_string()),
            "bgp.gtsm" => cfg.gtsm_hops = parse_gtsm(value),
            "bgp.max_prefixes" => {
                cfg.max_prefixes = value.parse::<u32>().ok().filter(|&n| n > 0);
            }
            "bgp.max_prefix_action" => {
                cfg.max_prefix_action = value.to_string();
            }
            "bgp.max_prefix_threshold" => {
                cfg.max_prefix_threshold = value.parse().unwrap_or(75);
            }
            "bgp.mp_families" => cfg.mp_families = parse_str_array(value),
            "bgp.md5_key" => cfg.md5_key = Some(value.to_string()),
            "bgp.tcp_ao_keys" => cfg.tcp_ao_keys = parse_str_array(value),
            "bgp.tcp_ao_algorithm" => cfg.tcp_ao_algorithm = value.to_string(),
            "bgp.tcp_ao_maclen" => cfg.tcp_ao_maclen = value.parse().unwrap_or(0),
            "user" => cfg.user = Some(value.to_string()),
            "group" => cfg.group = Some(value.to_string()),
            "api_socket" => cfg.api_socket = Some(value.to_string()),
            "networks" | "bgp.networks" => cfg.networks = parse_str_array(value),
            _ => {} // unknown keys are tolerated (forward compatibility)
        }
    }
    Ok(())
}

/// Apply one `key = value` pair to the current `[[peer]]` entry.
fn apply_peer_key(peer: &mut PeerSpec, key: &str, value: &str) -> Result<(), String> {
    match key {
        "name" => peer.name = Some(value.to_string()),
        "remote" => peer.remote = Some(value.to_string()),
        "address" => peer.address = Some(value.to_string()),
        "peer_as" => peer.peer_as = value.parse().map_err(|_| "bad peer_as".to_string())?,
        "hold_time" => peer.hold_time = Some(value.parse().map_err(|_| "bad hold_time")?),
        "graceful_restart_time" => {
            peer.gr_restart_time = Some(value.parse().map_err(|_| "bad graceful_restart_time")?)
        }
        "llgr_stale_time" => {
            peer.llgr_stale_time = Some(value.parse().map_err(|_| "bad llgr_stale_time")?)
        }
        "llgr_max_stale_time" => {
            peer.llgr_max_stale_time = Some(value.parse().map_err(|_| "bad llgr_max_stale_time")?)
        }
        "local_address" => peer.local_address = Some(value.to_string()),
        "local_address_v6" => peer.local_address_v6 = Some(value.to_string()),
        "md5_key" => peer.md5_key = Some(value.to_string()),
        "tcp_ao_keys" => peer.tcp_ao_keys = Some(parse_str_array(value)),
        "tcp_ao_algorithm" => peer.tcp_ao_algorithm = Some(value.to_string()),
        "tcp_ao_maclen" => {
            peer.tcp_ao_maclen = Some(value.parse().map_err(|_| "bad tcp_ao_maclen")?)
        }
        "add_path" => peer.add_path = Some(parse_bool(value)),
        "add_path_max_paths" => {
            peer.add_path_max_paths = Some(value.parse().map_err(|_| "bad add_path_max_paths")?)
        }
        "mp_families" => peer.mp_families = Some(parse_str_array(value)),
        "extended_next_hop" => peer.extended_next_hop = Some(parse_bool(value)),
        "gtsm" => peer.gtsm_hops = parse_gtsm(value),
        "max_prefixes" => {
            peer.max_prefixes = value.parse::<u32>().ok().filter(|&n| n > 0);
        }
        "max_prefix_action" => peer.max_prefix_action = Some(value.to_string()),
        "max_prefix_threshold" => {
            peer.max_prefix_threshold = Some(value.parse().map_err(|_| "bad max_prefix_threshold")?)
        }
        _ => {} // unknown keys are tolerated (forward compatibility)
    }
    Ok(())
}

pub(crate) fn parse_args() -> Result<DaemonConfig, ExitCode> {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = DaemonConfig::with_defaults();
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
            // Repeatable: each --peer adds one outbound peer using the
            // global --peer-as (per-peer AS requires a TOML [[peer]]).
            "--peer" if i + 1 < args.len() => {
                cfg.peers.push(PeerSpec {
                    remote: Some(args[i + 1].clone()),
                    ..Default::default()
                });
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
            "--gtsm" => {
                // Bare --gtsm → single-hop (TTL=255). --gtsm N → multihop.
                if i + 1 < args.len() {
                    if let Ok(hops) = args[i + 1].parse::<u8>() {
                        cfg.gtsm_hops = Some(hops);
                        i += 2;
                        continue;
                    }
                }
                cfg.gtsm_hops = Some(1); // single-hop
                i += 1;
            }
            "--max-prefixes" if i + 1 < args.len() => {
                cfg.max_prefixes = args[i + 1].parse::<u32>().ok().filter(|&n| n > 0);
                i += 2;
            }
            "--max-prefix-action" if i + 1 < args.len() => {
                cfg.max_prefix_action = args[i + 1].clone();
                i += 2;
            }
            "--max-prefix-threshold" if i + 1 < args.len() => {
                cfg.max_prefix_threshold = args[i + 1].parse().unwrap_or(75);
                i += 2;
            }
            "--protocol" if i + 1 < args.len() => {
                cfg.protocol = args[i + 1].clone();
                i += 2;
            }
            "--babel-group" if i + 1 < args.len() => {
                cfg.babel_group = Some(args[i + 1].clone());
                i += 2;
            }
            "--babel-port" if i + 1 < args.len() => {
                cfg.babel_port = args[i + 1].parse().unwrap_or(6696);
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
                return Err(ExitCode::SUCCESS);
            }
            _ => {
                eprintln!("unknown arg: {}", a);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_single_peer_is_synthesised() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\npeer_addr = \"192.0.2.2:179\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize();
        assert_eq!(cfg.peers.len(), 1);
        assert!(!cfg.explicit_peers);
        assert_eq!(cfg.peers[0].remote.as_deref(), Some("192.0.2.2:179"));
        assert_eq!(cfg.effective_peer_as(&cfg.peers[0]), 2);
    }

    #[test]
    fn peer_tables_parse_and_inherit() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 65000\npeer_as = 65001\nrouter_id = \"10.0.0.1\"\n\
             listen_addr = \"0.0.0.0:1179\"\n\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\npeer_as = 65002\nmd5_key = \"alpha\"\n\n\
             [[peer]]\naddress = \"192.0.2.3\"\nhold_time = 30\nmax_prefixes = 1000\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize();
        assert!(cfg.explicit_peers);
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.peers[0].remote.as_deref(), Some("192.0.2.2:179"));
        assert!(cfg.peers[0].is_outbound());
        assert_eq!(cfg.effective_peer_as(&cfg.peers[0]), 65002);
        assert_eq!(cfg.peers[0].md5_key.as_deref(), Some("alpha"));
        // Inheritance: peer 2 keeps the global AS, overrides hold_time.
        assert_eq!(cfg.effective_peer_as(&cfg.peers[1]), 65001);
        assert!(cfg.peers[1].is_inbound());
        assert_eq!(cfg.peers[1].hold_time, Some(30));
        assert_eq!(cfg.peers[1].max_prefixes, Some(1000));
    }

    #[test]
    fn previously_ignored_global_keys_now_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             graceful_restart_time = 300\nllgr_stale_time = 3600\n\
             llgr_max_stale_time = 7200\ninstall_kernel = true\n",
            &mut cfg,
        )
        .unwrap();
        assert_eq!(cfg.gr_restart_time, 300);
        assert_eq!(cfg.llgr_stale_time, 3600);
        assert_eq!(cfg.llgr_max_stale_time, 7200);
        assert!(cfg.install_kernel);
    }

    #[test]
    fn peer_arrays_and_gtsm_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[peer]]\nremote = \"192.0.2.2:179\"\ntcp_ao_keys = [\"1:alpha\", \"2:beta\"]\n\
             mp_families = [\"ipv4-unicast\", \"ipv6-unicast\"]\ngtsm = 2\nadd_path = true\n",
            &mut cfg,
        )
        .unwrap();
        let p = &cfg.peers[0];
        assert_eq!(
            p.tcp_ao_keys.as_deref().unwrap(),
            ["1:alpha".to_string(), "2:beta".to_string()].as_slice()
        );
        assert_eq!(
            p.mp_families.as_deref().unwrap(),
            ["ipv4-unicast".to_string(), "ipv6-unicast".to_string()].as_slice()
        );
        assert_eq!(p.gtsm_hops, Some(2));
        assert_eq!(p.add_path, Some(true));
    }

    #[test]
    fn key_outside_peer_table_is_an_error() {
        let mut cfg = DaemonConfig::with_defaults();
        // A [bgp] section key must not leak into a peer entry: flip the
        // section to `peer` without a [[peer]] header.
        let err = parse_toml_subset("[peer]\nremote = \"192.0.2.2:179\"\n", &mut cfg);
        assert!(err.is_err());
    }

    #[test]
    fn empty_peer_entry_is_flagged_by_label() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset("[[peer]]\npeer_as = 65010\n", &mut cfg).unwrap();
        assert_eq!(cfg.peers[0].label(), "(unnamed)");
    }
}
