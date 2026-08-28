//! Configuration model for `lr-daemon`: globals (the historical
//! single-peer CLI flags / `[bgp]` TOML section) plus explicit
//! `[[peer]]` tables for multi-peer deployments.
//!
//! Inheritance rule: every `[[peer]]` field left unset inherits the
//! corresponding global. The legacy single-peer keys (`--peer`,
//! `bgp.peer_addr`) are synthesised into one implicit peer so old
//! configs behave exactly as before.

use std::process::ExitCode;

use crate::daemon_policy::{AsPathListSpec, CommunityListSpec, PrefixListSpec, RouteMapSpec};

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
    /// Name of a `[peer-template.<name>]` this peer extends
    /// (`extends = "<name>"`); per-peer keys override template keys.
    pub extends: Option<String>,
    /// Import route-map name (`import = "..."`).
    pub import: Option<String>,
    /// Export route-map name (`export = "..."`).
    pub export: Option<String>,

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

/// One `[[ospf.area]]` table: area ID plus stub/NSSA policy
/// (RFC 2328 §3.6, RFC 3101). The backbone (area 0) is always normal
/// and needs no declaration.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct OspfAreaSpec {
    /// Area ID: dotted quad (`"0.0.0.1"`) or plain integer (`1`).
    pub id: Option<u32>,
    /// `"normal"` (default) | `"stub"` | `"nssa"`.
    pub kind: Option<String>,
    /// Suppress type-3 summaries — "totally stubby" / totally-NSSA.
    pub no_summary: Option<bool>,
    /// Metric of the default route injected into stub/NSSA areas.
    pub stub_metric: Option<u32>,
}

/// One `[[ospf.interface]]` table (or `--ospf-interface` flag).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct OspfIfSpec {
    /// Kernel interface name (required).
    pub name: Option<String>,
    /// Area ID; unset inherits the global default (area 0).
    pub area: Option<u32>,
    /// Interface cost advertised in Router-LSA links (default 10).
    pub cost: Option<u16>,
    pub hello_interval: Option<u16>,
    pub dead_interval: Option<u32>,
    /// DR election priority (default 1).
    pub priority: Option<u8>,
}

impl OspfIfSpec {
    /// Human-readable label for log lines.
    pub fn label(&self) -> &str {
        self.name.as_deref().unwrap_or("(unnamed)")
    }
}

/// Parse an OSPF area ID: dotted quad (`"0.0.0.1"`) or integer
/// (`"1"`). Both BIRD and FRR accept the two spellings.
pub(crate) fn parse_area_id(value: &str) -> Option<u32> {
    if value.contains('.') {
        let ip: std::net::Ipv4Addr = value.parse().ok()?;
        Some(u32::from(ip))
    } else {
        value.parse().ok()
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
    /// Protocol to run: "bgp" (default), "babel" or "ospf".
    pub protocol: String,
    /// Babel multicast group address (default: ff02::1:6).
    pub babel_group: Option<String>,
    /// Babel local port (default: 6696).
    pub babel_port: u16,

    /// OSPF hello interval default (seconds; RFC 2328 default 10).
    pub ospf_hello_interval: u16,
    /// OSPF dead interval default (seconds; RFC 2328 default 4× hello).
    pub ospf_dead_interval: u32,
    /// Default area for interfaces without one (`--ospf-area`; 0).
    pub ospf_area: u32,
    /// `[[ospf.area]]` tables — non-backbone areas must be declared.
    pub ospf_areas: Vec<OspfAreaSpec>,
    /// `[[ospf.interface]]` tables / `--ospf-interface` flags.
    pub ospf_interfaces: Vec<OspfIfSpec>,

    /// Explicit `[[peer]]` entries and repeatable `--peer` flags.
    /// Post-parse, [`DaemonConfig::finalize`] also synthesises the
    /// legacy single-peer entry when this is empty.
    pub peers: Vec<PeerSpec>,
    /// True when at least one `[[peer]]` table was parsed — switches
    /// the listener to strict source-address matching instead of the
    /// historical accept-any behaviour.
    pub explicit_peers: bool,
    /// Non-fatal configuration problems (unknown keys / sections),
    /// collected during parsing and reported at startup and reload.
    /// Keeping them here (instead of printing directly) makes the
    /// parser unit-testable.
    pub warnings: Vec<String>,

    /// `[[prefix-list]]` tables (see `daemon_policy::PrefixListSpec`).
    pub prefix_lists: Vec<PrefixListSpec>,
    /// `[[as-path-list]]` tables.
    pub as_path_lists: Vec<AsPathListSpec>,
    /// `[[community-list]]` tables.
    pub community_lists: Vec<CommunityListSpec>,
    /// `[[route-map]]` tables — one instance per entry.
    pub route_maps: Vec<RouteMapSpec>,
    /// `[peer-template.<name>]` tables — reusable `[[peer]]` defaults.
    pub peer_templates: std::collections::BTreeMap<String, PeerSpec>,
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
            ospf_hello_interval: 10,
            ospf_dead_interval: 40,
            ospf_area: 0,
            ..Default::default()
        }
    }

    /// Apply the legacy-single-peer synthesis after all inputs (CLI +
    /// TOML) are merged: with no explicit peers, the historical
    /// `--peer` / `bgp.peer_addr` (or a bare `--listen`) maps onto one
    /// implicit peer so previous behaviour is preserved exactly. Then
    /// every `extends = "<template>"` is resolved (least-specific
    /// first; per-peer keys win, template chains supported, cycles
    /// and unknown names are errors — fail closed).
    pub fn finalize(&mut self) -> Result<(), String> {
        if self.peers.is_empty() && (self.peer_addr.is_some() || self.listen_addr.is_some()) {
            self.peers.push(PeerSpec {
                remote: self.peer_addr.clone(),
                ..Default::default()
            });
        }
        for idx in 0..self.peers.len() {
            let mut chain: Vec<String> = Vec::new();
            let mut resolved = self.peers[idx].clone();
            // Walk the extends chain from the peer upward; each level
            // only fills fields the level above left unset.
            while let Some(name) = resolved.extends.clone() {
                if chain.contains(&name) {
                    return Err(format!(
                        "peer {}: extends cycle via '{}'",
                        resolved.label(),
                        name
                    ));
                }
                let template = self.peer_templates.get(&name).cloned().ok_or_else(|| {
                    format!(
                        "peer {}: unknown peer-template '{}'",
                        resolved.label(),
                        name
                    )
                })?;
                chain.push(name);
                resolved.extends = template.extends.clone();
                merge_spec(&mut resolved, &template);
            }
            resolved.extends = None;
            self.peers[idx] = resolved;
        }
        self.finalize_ospf()?;
        Ok(())
    }

    /// Validate and complete the OSPF configuration (only meaningful
    /// with `--protocol ospf`; other protocols get a warning when OSPF
    /// tables are present). Fills interface areas from the global
    /// default and enforces the fail-closed rules: every interface
    /// named, non-backbone areas declared exactly once, valid area
    /// types, the backbone never stub/NSSA.
    fn finalize_ospf(&mut self) -> Result<(), String> {
        if self.ospf_areas.is_empty() && self.ospf_interfaces.is_empty() {
            return Ok(());
        }
        if self.protocol != "ospf" {
            self.warnings.push(format!(
                "OSPF tables present but --protocol is '{}' (ignored)",
                self.protocol
            ));
            return Ok(());
        }
        // Areas: id present, unique, kind valid; backbone stays normal.
        let mut seen = std::collections::BTreeSet::new();
        for area in &self.ospf_areas {
            let Some(id) = area.id else {
                return Err("[[ospf.area]] without 'id'".to_string());
            };
            if !seen.insert(id) {
                return Err(format!("area {} declared twice", area_label(id)));
            }
            match area.kind.as_deref() {
                None | Some("normal") | Some("stub") | Some("nssa") => {}
                Some(other) => {
                    return Err(format!(
                        "area {}: unknown type '{}' (normal | stub | nssa)",
                        area_label(id),
                        other
                    ))
                }
            }
            if id == 0 && matches!(area.kind.as_deref(), Some("stub" | "nssa")) {
                return Err("the OSPF backbone (area 0) cannot be a stub or NSSA area".into());
            }
        }
        // Interfaces: named, area resolved + declared (area 0 implicit).
        let declared = |id: u32| id == 0 || seen.contains(&id);
        for iface in &mut self.ospf_interfaces {
            if iface.name.as_deref().is_none_or(str::is_empty) {
                return Err("[[ospf.interface]] without 'name'".to_string());
            }
            let area = iface.area.unwrap_or(self.ospf_area);
            if !declared(area) {
                return Err(format!(
                    "interface {}: area {} is not declared ([[ospf.area]])",
                    iface.label(),
                    area_label(area)
                ));
            }
            iface.area = Some(area);
        }
        Ok(())
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

/// Area IDs render as dotted quads when they look like one (BIRD/FRR
/// habit); plain small integers stay integers.
pub(crate) fn area_label(id: u32) -> String {
    std::net::Ipv4Addr::from(id).to_string()
}

/// Fill unset fields of `over` from `base` (per-peer key wins).
fn merge_spec(over: &mut PeerSpec, base: &PeerSpec) {
    fn opt<T: Clone>(dst: &mut Option<T>, src: &Option<T>) {
        if dst.is_none() {
            *dst = src.clone();
        }
    }
    opt(&mut over.name, &base.name);
    opt(&mut over.remote, &base.remote);
    opt(&mut over.address, &base.address);
    if over.peer_as == 0 {
        over.peer_as = base.peer_as;
    }
    opt(&mut over.import, &base.import);
    opt(&mut over.export, &base.export);
    opt(&mut over.hold_time, &base.hold_time);
    opt(&mut over.gr_restart_time, &base.gr_restart_time);
    opt(&mut over.llgr_stale_time, &base.llgr_stale_time);
    opt(&mut over.llgr_max_stale_time, &base.llgr_max_stale_time);
    opt(&mut over.local_address, &base.local_address);
    opt(&mut over.local_address_v6, &base.local_address_v6);
    opt(&mut over.md5_key, &base.md5_key);
    if over.tcp_ao_keys.is_none() {
        over.tcp_ao_keys = base.tcp_ao_keys.clone();
    }
    opt(&mut over.tcp_ao_algorithm, &base.tcp_ao_algorithm);
    if over.tcp_ao_maclen.is_none() {
        over.tcp_ao_maclen = base.tcp_ao_maclen;
    }
    if over.add_path.is_none() {
        over.add_path = base.add_path;
    }
    if over.add_path_max_paths.is_none() {
        over.add_path_max_paths = base.add_path_max_paths;
    }
    if over.mp_families.is_none() {
        over.mp_families = base.mp_families.clone();
    }
    if over.extended_next_hop.is_none() {
        over.extended_next_hop = base.extended_next_hop;
    }
    if over.gtsm_hops.is_none() {
        over.gtsm_hops = base.gtsm_hops;
    }
    if over.max_prefixes.is_none() {
        over.max_prefixes = base.max_prefixes;
    }
    opt(&mut over.max_prefix_action, &base.max_prefix_action);
    if over.max_prefix_threshold.is_none() {
        over.max_prefix_threshold = base.max_prefix_threshold;
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
        // Array-of-tables: `[[peer]]` starts a new peer entry; the
        // policy tables accumulate into their spec vectors.
        if line.starts_with("[[") && line.ends_with("]]") {
            let name = line[2..line.len() - 2].trim();
            match name {
                "peer" => {
                    cfg.peers.push(PeerSpec::default());
                    cfg.explicit_peers = true;
                    section = "peer".to_string();
                }
                "prefix-list" => {
                    cfg.prefix_lists.push(PrefixListSpec::default());
                    section = "prefix-list".to_string();
                }
                "as-path-list" => {
                    cfg.as_path_lists.push(AsPathListSpec::default());
                    section = "as-path-list".to_string();
                }
                "community-list" => {
                    cfg.community_lists.push(CommunityListSpec::default());
                    section = "community-list".to_string();
                }
                "route-map" => {
                    cfg.route_maps.push(RouteMapSpec::default());
                    section = "route-map".to_string();
                }
                "ospf.area" => {
                    cfg.ospf_areas.push(OspfAreaSpec::default());
                    section = "ospf.area".to_string();
                }
                "ospf.interface" => {
                    cfg.ospf_interfaces.push(OspfIfSpec::default());
                    section = "ospf.interface".to_string();
                }
                _ => {
                    // Unknown array table: tolerate (forward compatibility),
                    // but leave peer context so keys do not leak into one.
                    cfg.warnings.push(format!(
                        "line {}: unknown table [[{}]] (ignored)",
                        lineno + 1,
                        name
                    ));
                    section = format!("unknown-array.{name}");
                }
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            // [peer-template.<name>] — reusable peer defaults. Keys use
            // the [[peer]] schema; unknown keys are hard errors.
            if let Some(name) = section.strip_prefix("peer-template.") {
                if name.is_empty() || name.contains('.') {
                    return Err(format!(
                        "line {}: bad template section [{}]",
                        lineno + 1,
                        section
                    ));
                }
                cfg.peer_templates.entry(name.to_string()).or_default();
            } else if section != "bgp"
                && section != "ospf"
                && !section.starts_with("unknown-array.")
            {
                cfg.warnings.push(format!(
                    "line {}: unknown section [{}] (ignored)",
                    lineno + 1,
                    section
                ));
            }
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
            if !apply_peer_key(peer, key, value)
                .map_err(|e| format!("line {}: {}", lineno + 1, e))?
            {
                cfg.warnings.push(format!(
                    "line {}: unknown peer key '{}' (ignored)",
                    lineno + 1,
                    key
                ));
            }
            continue;
        }
        if let Some(name) = section.strip_prefix("peer-template.") {
            let Some(template) = cfg.peer_templates.get_mut(name) else {
                return Err(format!("line {}: unknown template", lineno + 1));
            };
            if !apply_peer_key(template, key, value)
                .map_err(|e| format!("line {}: {}", lineno + 1, e))?
            {
                return Err(format!(
                    "line {}: unknown peer-template key '{}' (typo protection)",
                    lineno + 1,
                    key
                ));
            }
            continue;
        }
        // Policy table sections have their own key schemas; unknown
        // keys inside them are hard errors (typo protection for
        // policy the operator expects to be in force — fail closed).
        if apply_policy_key(cfg, &section, key, value)
            .map_err(|e| format!("line {}: {}", lineno + 1, e))?
        {
            continue;
        }
        // OSPF tables and globals: protocol configuration is fail-closed —
        // an unknown key is a typo that could silently alter adjacency
        // behaviour (hello intervals, area types), so it is an error.
        if apply_ospf_key(cfg, &section, key, value)
            .map_err(|e| format!("line {}: {}", lineno + 1, e))?
        {
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
            _ => {
                cfg.warnings.push(format!(
                    "line {}: unknown key '{}' (ignored)",
                    lineno + 1,
                    full
                ));
            }
        }
    }
    Ok(())
}

/// Apply one `key = value` pair to the current policy table
/// (`[[prefix-list]]`, `[[as-path-list]]`, `[[community-list]]`,
/// `[[route-map]]`). Returns `Some(error)` for unknown keys so
/// policy typos fail at parse time instead of silently passing
/// traffic. Returns `None` for sections that are not policy tables
/// (the caller falls through to the global schema).
fn apply_policy_key(
    cfg: &mut DaemonConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<bool, String> {
    match section {
        "prefix-list" => {
            let Some(list) = cfg.prefix_lists.last_mut() else {
                return Err("key outside a [[prefix-list]] table".into());
            };
            match key {
                "name" => list.name = value.to_string(),
                "prefix" => list.prefix = value.to_string(),
                "ge" => list.ge = value.parse().ok(),
                "le" => list.le = value.parse().ok(),
                "permit" => list.permit = Some(parse_bool(value)),
                _ => {
                    return Err(format!(
                        "unknown prefix-list key '{}' (typo protection; policy fails closed)",
                        key
                    ))
                }
            }
        }
        "as-path-list" => {
            let Some(list) = cfg.as_path_lists.last_mut() else {
                return Err("key outside a [[as-path-list]] table".into());
            };
            match key {
                "name" => list.name = value.to_string(),
                "pattern" => list.pattern = value.to_string(),
                "permit" => list.permit = Some(parse_bool(value)),
                _ => {
                    return Err(format!(
                        "unknown as-path-list key '{}' (typo protection; policy fails closed)",
                        key
                    ))
                }
            }
        }
        "community-list" => {
            let Some(list) = cfg.community_lists.last_mut() else {
                return Err("key outside a [[community-list]] table".into());
            };
            match key {
                "name" => list.name = value.to_string(),
                "communities" => list.communities = parse_str_array(value),
                "permit" => list.permit = Some(parse_bool(value)),
                _ => {
                    return Err(format!(
                        "unknown community-list key '{}' (typo protection; policy fails closed)",
                        key
                    ))
                }
            }
        }
        "route-map" => {
            let Some(map) = cfg.route_maps.last_mut() else {
                return Err("key outside a [[route-map]] table".into());
            };
            match key {
                "name" => map.name = value.to_string(),
                "entry" => {
                    map.entry = value
                        .parse()
                        .map_err(|_| format!("bad entry '{}'", value))?
                }
                "match_prefix" => map.match_prefix = Some(value.to_string()),
                "match_as_path" => map.match_as_path = Some(value.to_string()),
                "match_community" => map.match_community = Some(value.to_string()),
                "set_local_pref" => map.set_local_pref = value.parse().ok(),
                "set_med" => map.set_med = value.parse().ok(),
                "set_metric" => map.set_metric = value.parse().ok(),
                "set_next_hop" => map.set_next_hop = Some(value.to_string()),
                "prepend" => map.prepend = Some(value.to_string()),
                "add_community" => map.add_community = Some(value.to_string()),
                "permit" => map.permit = Some(parse_bool(value)),
                _ => {
                    return Err(format!(
                        "unknown route-map key '{}' (typo protection; policy fails closed)",
                        key
                    ))
                }
            }
        }
        // Not a policy section: signal the caller to fall through to
        // the global schema.
        _ => return Ok(false),
    }
    Ok(true)
}

/// Apply one `key = value` pair to the OSPF schema: the `[ospf]`
/// globals plus the `[[ospf.area]]` / `[[ospf.interface]]` tables.
/// Unknown keys are errors (fail closed — see the parser). Returns
/// `Ok(false)` for non-OSPF sections so the caller falls through.
fn apply_ospf_key(
    cfg: &mut DaemonConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<bool, String> {
    match section {
        "ospf" => match key {
            "hello_interval" => {
                cfg.ospf_hello_interval = value
                    .parse()
                    .map_err(|_| format!("bad hello_interval '{value}'"))?;
            }
            "dead_interval" => {
                cfg.ospf_dead_interval = value
                    .parse()
                    .map_err(|_| format!("bad dead_interval '{value}'"))?;
            }
            _ => {
                return Err(format!(
                    "unknown [ospf] key '{key}' (typo protection; OSPF config fails closed)"
                ))
            }
        },
        "ospf.area" => {
            let Some(area) = cfg.ospf_areas.last_mut() else {
                return Err("key outside a [[ospf.area]] table".into());
            };
            match key {
                "id" => {
                    area.id = Some(parse_area_id(value).ok_or_else(|| {
                        format!("bad area id '{value}' (integer or dotted quad)")
                    })?);
                }
                "type" => area.kind = Some(value.to_string()),
                "no_summary" => area.no_summary = Some(parse_bool(value)),
                "stub_metric" => {
                    area.stub_metric = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad stub_metric '{value}'"))?,
                    );
                }
                _ => return Err(format!(
                    "unknown [[ospf.area]] key '{key}' (typo protection; OSPF config fails closed)"
                )),
            }
        }
        "ospf.interface" => {
            let Some(iface) = cfg.ospf_interfaces.last_mut() else {
                return Err("key outside a [[ospf.interface]] table".into());
            };
            match key {
                "name" => iface.name = Some(value.to_string()),
                "area" => {
                    iface.area = Some(
                        parse_area_id(value)
                            .ok_or_else(|| format!("bad area '{value}' (integer or dotted quad)"))?,
                    );
                }
                "cost" => {
                    iface.cost = Some(value.parse().map_err(|_| format!("bad cost '{value}'"))?);
                }
                "hello_interval" => {
                    iface.hello_interval = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad hello_interval '{value}'"))?,
                    );
                }
                "dead_interval" => {
                    iface.dead_interval = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad dead_interval '{value}'"))?,
                    );
                }
                "priority" => {
                    iface.priority = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad priority '{value}'"))?,
                    );
                }
                _ => {
                    return Err(format!(
                        "unknown [[ospf.interface]] key '{key}' (typo protection; OSPF config fails closed)"
                    ))
                }
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Apply one `key = value` pair to the current `[[peer]]` entry.
/// Returns `Ok(false)` when the key is not part of the schema so the
/// caller can surface an unknown-key warning.
fn apply_peer_key(peer: &mut PeerSpec, key: &str, value: &str) -> Result<bool, String> {
    match key {
        "name" => peer.name = Some(value.to_string()),
        "remote" => peer.remote = Some(value.to_string()),
        "address" => peer.address = Some(value.to_string()),
        "peer_as" => peer.peer_as = value.parse().map_err(|_| "bad peer_as".to_string())?,
        "extends" => peer.extends = Some(value.to_string()),
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
        "import" => peer.import = Some(value.to_string()),
        "export" => peer.export = Some(value.to_string()),
        _ => return Ok(false), // unknown key — caller warns
    }
    Ok(true)
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
            // Repeatable: each --ospf-interface adds one interface; its
            // area defaults to --ospf-area (resolved in finalize).
            "--ospf-interface" if i + 1 < args.len() => {
                cfg.ospf_interfaces.push(OspfIfSpec {
                    name: Some(args[i + 1].clone()),
                    ..Default::default()
                });
                i += 2;
            }
            "--ospf-area" if i + 1 < args.len() => {
                match parse_area_id(&args[i + 1]) {
                    Some(id) => cfg.ospf_area = id,
                    None => {
                        eprintln!("invalid area id: {}", args[i + 1]);
                        return Err(ExitCode::from(2));
                    }
                }
                i += 2;
            }
            "--ospf-hello-interval" if i + 1 < args.len() => {
                cfg.ospf_hello_interval = args[i + 1].parse().unwrap_or(10);
                i += 2;
            }
            "--ospf-dead-interval" if i + 1 < args.len() => {
                cfg.ospf_dead_interval = args[i + 1].parse().unwrap_or(40);
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
        for w in &cfg.warnings {
            eprintln!("config warning: {}", w);
        }
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
        cfg.finalize().unwrap();
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
        cfg.finalize().unwrap();
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

    #[test]
    fn unknown_keys_and_sections_warn() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             typo_key = 5\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\npeer_typo = \"x\"\n",
            &mut cfg,
        )
        .unwrap();
        assert_eq!(cfg.warnings.len(), 2, "{:?}", cfg.warnings);
        assert!(cfg.warnings[0].contains("unknown key 'bgp.typo_key'"));
        assert!(cfg.warnings[1].contains("unknown peer key 'peer_typo'"));
    }

    #[test]
    fn unknown_table_headers_warn() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[vendor]]\nfoo = 1\n[logging]\nlevel = \"debug\"\n",
            &mut cfg,
        )
        .unwrap();
        assert_eq!(cfg.warnings.len(), 4, "{:?}", cfg.warnings);
        assert!(cfg.warnings[0].contains("unknown table [[vendor]]"));
        // Keys inside an unknown array table warn too.
        assert!(cfg.warnings[1].contains("unknown key 'unknown-array.vendor.foo'"));
        assert!(cfg.warnings[2].contains("unknown section [logging]"));
        // Keys inside an unknown section warn as unknown keys.
        assert!(cfg.warnings[3].contains("unknown key 'logging.level'"));
    }

    #[test]
    fn clean_config_produces_no_warnings() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "user = \"lr\"\n\n[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             networks = [\"203.0.113.0/24\"]\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\nhold_time = 30\n",
            &mut cfg,
        )
        .unwrap();
        assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    }
    #[test]
    fn peer_templates_inherit_and_override() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 65000\nrouter_id = \"10.0.0.1\"\n\n\
             [peer-template.transit]\npeer_as = 64500\nmd5_key = \"alpha\"\nmax_prefixes = 1000\n\n\
             [[peer]]\nextends = \"transit\"\nremote = \"192.0.2.2:179\"\nmax_prefixes = 2000\n\n\
             [[peer]]\nextends = \"transit\"\nremote = \"192.0.2.3:179\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.peers.len(), 2);
        // Both inherit AS + key; peer 0 overrides the prefix limit.
        assert_eq!(cfg.peers[0].peer_as, 64500);
        assert_eq!(cfg.peers[0].md5_key.as_deref(), Some("alpha"));
        assert_eq!(cfg.peers[0].max_prefixes, Some(2000));
        assert_eq!(cfg.peers[1].max_prefixes, Some(1000));
        // extends is consumed, not carried into the session config.
        assert!(cfg.peers[0].extends.is_none());
    }

    #[test]
    fn template_chains_resolve_least_specific_first() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[peer-template.base]\npeer_as = 64500\nhold_time = 60\n\n\
             [peer-template.fast]\nextends = \"base\"\nhold_time = 10\n\n\
             [[peer]]\nextends = \"fast\"\nremote = \"192.0.2.2:179\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        // 'fast' overrides hold_time; 'base' fills peer_as.
        assert_eq!(cfg.peers[0].hold_time, Some(10));
        assert_eq!(cfg.peers[0].peer_as, 64500);
    }

    #[test]
    fn unknown_template_and_cycles_fail_closed() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[peer]]\nextends = \"ghost\"\nremote = \"192.0.2.2:179\"\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().expect_err("must fail");
        assert!(err.contains("unknown peer-template 'ghost'"), "{err}");

        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[peer-template.a]\nextends = \"b\"\n\n\
             [peer-template.b]\nextends = \"a\"\n\n\
             [[peer]]\nextends = \"a\"\nremote = \"192.0.2.2:179\"\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().expect_err("must fail");
        assert!(err.contains("cycle"), "{err}");
    }

    // ---- OSPF configuration ----

    #[test]
    fn area_ids_parse_both_spellings() {
        assert_eq!(parse_area_id("0"), Some(0));
        assert_eq!(parse_area_id("1"), Some(1));
        assert_eq!(parse_area_id("0.0.0.1"), Some(1));
        assert_eq!(parse_area_id("10.1.0.0"), Some(0x0a01_0000));
        assert_eq!(parse_area_id("x"), None);
        assert_eq!(parse_area_id("1.2.3"), None);
    }

    #[test]
    fn ospf_tables_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset(
            "[ospf]\nhello_interval = 5\ndead_interval = 20\n\n\
             [[ospf.area]]\nid = 1\ntype = \"stub\"\nno_summary = true\nstub_metric = 25\n\n\
             [[ospf.area]]\nid = \"0.0.0.2\"\n\n\
             [[ospf.interface]]\nname = \"eth0\"\narea = 1\ncost = 20\n\n\
             [[ospf.interface]]\nname = \"eth1\"\narea = 2\nhello_interval = 3\ndead_interval = 12\npriority = 5\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.ospf_hello_interval, 5);
        assert_eq!(cfg.ospf_dead_interval, 20);
        assert_eq!(cfg.ospf_areas.len(), 2);
        assert_eq!(cfg.ospf_areas[0].id, Some(1));
        assert_eq!(cfg.ospf_areas[0].kind.as_deref(), Some("stub"));
        assert_eq!(cfg.ospf_areas[0].no_summary, Some(true));
        assert_eq!(cfg.ospf_areas[0].stub_metric, Some(25));
        assert_eq!(cfg.ospf_areas[1].id, Some(2), "dotted-quad id");
        assert_eq!(cfg.ospf_interfaces.len(), 2);
        assert_eq!(cfg.ospf_interfaces[0].name.as_deref(), Some("eth0"));
        assert_eq!(cfg.ospf_interfaces[0].area, Some(1));
        assert_eq!(cfg.ospf_interfaces[0].cost, Some(20));
        assert_eq!(cfg.ospf_interfaces[1].hello_interval, Some(3));
        assert_eq!(cfg.ospf_interfaces[1].dead_interval, Some(12));
        assert_eq!(cfg.ospf_interfaces[1].priority, Some(5));
        assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    }

    #[test]
    fn ospf_interface_area_defaults_to_backbone() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset("[[ospf.interface]]\nname = \"eth0\"\n", &mut cfg).unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.ospf_interfaces[0].area, Some(0));
    }

    #[test]
    fn ospf_undeclared_area_fails_closed() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset(
            "[[ospf.area]]\nid = 1\n\n\
             [[ospf.interface]]\nname = \"eth0\"\narea = 2\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().expect_err("undeclared area must fail");
        assert!(err.contains("not declared"), "{err}");
    }

    #[test]
    fn ospf_unknown_keys_are_errors() {
        for (section, key) in [
            ("[ospf]", "verion"),
            ("[[ospf.area]]", "typ"),
            ("[[ospf.interface]]", "nam"),
        ] {
            let mut cfg = DaemonConfig::with_defaults();
            let err = parse_toml_subset(&format!("{section}\n{key} = 1\n"), &mut cfg);
            let err = err.expect_err("unknown OSPF key must fail");
            assert!(err.contains("typo protection"), "{section}.{key}: {err}");
        }
    }

    #[test]
    fn ospf_backbone_cannot_be_stub() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset("[[ospf.area]]\nid = 0\ntype = \"stub\"\n", &mut cfg).unwrap();
        let err = cfg.finalize().expect_err("stub backbone must fail");
        assert!(err.contains("backbone"), "{err}");
    }

    #[test]
    fn ospf_duplicate_and_missing_area_ids_fail() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset("[[ospf.area]]\nid = 1\n\n[[ospf.area]]\nid = 1\n", &mut cfg).unwrap();
        assert!(cfg.finalize().is_err(), "duplicate area");

        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset("[[ospf.area]]\ntype = \"stub\"\n", &mut cfg).unwrap();
        let err = cfg.finalize().expect_err("missing id must fail");
        assert!(err.contains("without 'id'"), "{err}");
    }

    #[test]
    fn ospf_tables_in_bgp_mode_warn() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset("[[ospf.interface]]\nname = \"eth0\"\n", &mut cfg).unwrap();
        cfg.finalize().unwrap();
        assert!(
            cfg.warnings
                .iter()
                .any(|w| w.contains("OSPF tables present but --protocol")),
            "{:?}",
            cfg.warnings
        );
    }
}
