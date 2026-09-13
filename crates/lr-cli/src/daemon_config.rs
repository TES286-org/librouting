//! Configuration model for `lr-daemon`: globals (the historical
//! single-peer CLI flags / `[bgp]` TOML section) plus explicit
//! `[[peer]]` tables for multi-peer deployments.
//!
//! Inheritance rule: every `[[peer]]` field left unset inherits the
//! corresponding global. The legacy single-peer keys (`--peer`,
//! `bgp.peer_addr`) are synthesised into one implicit peer so old
//! configs behave exactly as before.

use std::process::ExitCode;

use lr_babel::BabelMacAlgorithm;

use crate::daemon_policy::{AsPathListSpec, CommunityListSpec, PrefixListSpec, RouteMapSpec};

/// Per-peer settings — one `[[peer]]` TOML table (or one `--peer` CLI
/// flag). `None` fields inherit the `[bgp]` globals.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PeerSpec {
    /// Human-readable label used in logs (defaults to remote/address).
    pub name: Option<String>,
    /// Remote `host:port` to connect to (outbound peer). Combining
    /// `remote` and `address` on one peer makes it bidirectional: the
    /// daemon connects out AND accepts inbound connections for it,
    /// running the two transports on separate sessions and resolving
    /// them per RFC 4271 §6.8 (the connection initiated by the speaker
    /// with the higher BGP Identifier survives; the loser gets a Cease
    /// / Connection Collision Resolution NOTIFICATION).
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
    /// Import filter DSL name (`import_filter = "..."`). When set the
    /// peer's import path runs the named `[[filter]]` body after the
    /// route-map (if both are set). The route-map is the FRR-style
    /// fast path; the filter DSL is the BIRD-style expressive path.
    pub import_filter: Option<String>,
    /// Export filter DSL name (`export_filter = "..."`).
    pub export_filter: Option<String>,

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
    /// FRR `bgp default ipv4-unicast` (W2.1): per-peer override of the
    /// router-wide default. `None` = inherit the router default.
    pub default_ipv4_unicast: Option<bool>,
    /// FRR `neighbor X allowas-in N` / BIRD `allow local as` (W2.3):
    /// per-peer tolerance for the local AS in a received AS_PATH.
    /// `None` = inherit the router default (0 = reject any).
    /// `0` = reject any occurrence; `N > 0` = admit up to N occurrences
    /// (FRR `allowas-in N`); `u32::MAX` = admit any number (FRR
    /// `allowas-any`).
    pub allow_local_as: Option<u32>,
    /// FRR `neighbor X soft-reconfiguration inbound` (W2.4): per-peer
    /// toggle for pre-policy Adj-RIB-In retention. `None` = inherit
    /// the router default (off).
    pub soft_reconfig_inbound: Option<bool>,
    /// RFC 5549 Extended Next-Hop.
    pub extended_next_hop: Option<bool>,
    /// RFC 5082 GTSM hop count (`Some(1)` = single-hop TTL security).
    pub gtsm_hops: Option<u8>,
    /// Per-peer maximum-prefix limit.
    pub max_prefixes: Option<u32>,
    pub max_prefix_action: Option<String>,
    pub max_prefix_threshold: Option<u8>,
    /// BFD fast-fail for this peer (`bfd = true`, RFC 5880/5881).
    /// `None` inherits the global setting.
    pub bfd: Option<bool>,
    /// BFD multihop mode (RFC 5883 — UDP 4784, no TTL check).
    /// `None` inherits the global setting.
    pub bfd_multihop: Option<bool>,
    /// W6.3 exchange-plane prototype (`exchange_plane = true`): per-peer
    /// override of the router-wide default. `None` inherits the global.
    /// Requires a binary built with the `exchange-plane` feature.
    pub exchange_plane: Option<bool>,
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

/// One `[[ospf.prefix_sid]]` table (RFC 8665 §5): a locally originated
/// prefix advertised with a Segment Routing Prefix-SID.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct OspfPrefixSidSpec {
    /// Prefix (IPv4, required).
    pub prefix: Option<String>,
    /// SID index into the SRGB (required; the label peers derive is
    /// `srgb_base + sid`).
    pub sid: Option<u32>,
    /// RFC 7684 §2.1 N-flag: the prefix identifies the node itself (an
    /// SR-Node / loopback), so peers may treat it as a node segment.
    pub node: Option<bool>,
    /// RFC 8665 §5 NP flag (FRR `no-php-flag`): the penultimate hop
    /// must NOT pop — neighbours one hop away still push
    /// `srgb_base + sid`. Clear by default (PHP, the FRR default).
    pub no_php: Option<bool>,
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
    /// RFC 2328 §9.1 network type: "p2p" (default) or "broadcast".
    /// Broadcast runs the §9.4 DR/BDR election and gates adjacency per
    /// §10.4.
    pub network_type: Option<String>,
    /// RFC 8665 §6: the local adjacency segment this interface
    /// advertises once its adjacency is Full — an absolute SRLB label
    /// (V/L shape). Neighbours steer traffic over the link by pushing
    /// it. Optional; absent = the interface originates no Extended
    /// Link LSA.
    pub adj_sid: Option<u32>,
}

impl OspfIfSpec {
    /// Human-readable label for log lines.
    pub fn label(&self) -> &str {
        self.name.as_deref().unwrap_or("(unnamed)")
    }
}

/// One `[[ospf.mapping_server]]` table (RFC 8665 §4 / RFC 8661 §3.2):
/// the SR Mapping Server role — advertise prefix→SID bindings for
/// prefixes this router does not own. The Extended Prefix Range TLV
/// covers `range_size` consecutive prefixes starting at `prefix`, the
/// first carrying `sid` (later ones shift by their offset).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct OspfMappingServerSpec {
    /// Base prefix of the range (IPv4, required).
    pub prefix: Option<String>,
    /// SID index assigned to the range's first prefix (required).
    pub sid: Option<u32>,
    /// Number of consecutive prefixes covered (default 1; RFC 8665 §4
    /// Range Size).
    pub range_size: Option<u32>,
    /// RFC 8665 §5 NP flag for the range's Prefix-SID (FRR
    /// `no-php-flag` semantics): set to keep the label on the
    /// penultimate hop. Clear by default.
    pub no_php: Option<bool>,
}

/// One `[[ospf.srv6_locator]]` table (RFC 9513 §7-§8, OSPFv3 only): a
/// locally originated SRv6 locator, advertised in a per-area Locator
/// LSA with its End SID. The OSPFv3 counterpart of
/// [`OspfPrefixSidSpec`].
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct OspfSrv6LocatorSpec {
    /// Locator prefix (IPv6, required) — the §7.1 Locator TLV prefix.
    pub prefix: Option<String>,
    /// IGP algorithm the locator is associated with (§7.1; default
    /// 0 = SPF).
    pub algorithm: Option<u8>,
    /// The §7.1 locator metric (default 0).
    pub metric: Option<u32>,
    /// RFC 9513 §6 AC-bit: the locator is anycast (default false).
    pub anycast: Option<bool>,
    /// The §8 End SID value (IPv6 address). Default: the locator
    /// prefix itself with the host bits zeroed (the RFC 8986 End
    /// behavior on the locator prefix).
    pub sid: Option<String>,
    /// RFC 8986 endpoint behavior advertised with the End SID
    /// (§8; default 1 = End).
    pub behavior: Option<u16>,
    /// §10 SID Structure Locator-Block length in bits. The four
    /// lengths are all-or-none; when all are set the §10 sub-TLV rides
    /// the End SID.
    pub block_len: Option<u8>,
    /// §10 Locator-Node length in bits (see `block_len`).
    pub node_len: Option<u8>,
    /// §10 Function length in bits (see `block_len`).
    pub function_len: Option<u8>,
    /// §10 Argument length in bits (see `block_len`).
    pub argument_len: Option<u8>,
}

/// One `[[babel.key]]` table (or `--babel-key` flag): a symmetric MAC
/// key for RFC 8967 Babel authentication.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct BabelKeySpec {
    /// Shared secret (raw string bytes; RFC 8967 §7 recommends 32 octets
    /// chosen randomly — passphrases should go through a KDF upstream).
    pub secret: Option<String>,
    /// `"hmac-sha256"` (default, mandatory to implement) or `"blake2s"`
    /// (keyed BLAKE2s, 16-octet digest).
    pub algorithm: Option<String>,
}

/// One `[[babel.interface]]` table — per-interface Babel parameters
/// (RFC 8966 §A.2). `name` accepts shell-like glob patterns (`*`, `?`,
/// `\`) so the same parameters can apply to a fleet of similar
/// interfaces (`eth*`). The first matching pattern wins, mirroring
/// BIRD's `interface` directive in `proto/babel/config.Y`.
///
/// When no `[[babel.interface]]` block exists the daemon keeps the
/// legacy single-socket path: one Babel session bound to the global
/// `--local-address`. When one or more blocks exist the daemon
/// enumerates the system interfaces, matches each name against the
/// patterns in file order, and uses the first match's parameters
/// for the single Babel session. A future per-interface multi-socket
/// spawning will run one Babel session per matched interface.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct BabelInterfaceSpec {
    /// Kernel interface name or glob pattern (`eth*`, `eth?`).
    pub name: Option<String>,
    /// `"wired"` (default), `"wireless"` or `"tunnel"` (RFC 8966
    /// §A.2 link cost model selection).
    pub kind: Option<String>,
    /// Hello interval in milliseconds (RFC 8966 §3.1; BIRD default
    /// 4000 ms wired, 12000 ms wireless).
    pub hello_interval_ms: Option<u32>,
    /// Update (multicast) interval in milliseconds (RFC 8966 §3.1).
    pub update_interval_ms: Option<u32>,
    /// Receive cost the interface advertises for peers it learns
    /// (RFC 8966 §3.5.2; BIRD default 96 wired, 256 wireless).
    pub rxcost: Option<u16>,
    /// RTT-based cost (RFC 8966 §A.2.4): when RTT exceeds
    /// `rtt_min`, an additional `rtt_cost` is added. Off when 0.
    pub rtt_cost: Option<u16>,
    /// Lower RTT bound (microseconds) below which no RTT cost is
    /// added (RFC 8966 §A.2.4; BIRD default 10 ms).
    pub rtt_min_us: Option<u32>,
    /// Upper RTT bound (microseconds) above which the RTT cost is
    /// applied in full (RFC 8966 §A.2.4; BIRD default 120 ms).
    pub rtt_max_us: Option<u32>,
    /// Per-interface IPv4 next-hop advertised in Babel Updates
    /// (RFC 8966 §3.5.3; defaults to the interface's primary IPv4).
    pub next_hop_ipv4: Option<String>,
    /// Per-interface IPv6 next-hop advertised in Babel Updates
    /// (RFC 8966 §3.5.3; defaults to the interface's link-local).
    pub next_hop_ipv6: Option<String>,
    /// RFC 5549 extended next-hop: advertise IPv4 prefixes over an
    /// IPv6 next-hop on this interface (BIRD `extended next hop yes`).
    pub extended_next_hop: Option<bool>,
    /// Withdraw routes when the interface goes operationally down
    /// (BIRD `check link yes`, default on).
    pub check_link: Option<bool>,
    /// Override the global `[babel] port` for this interface.
    pub port: Option<u16>,
    /// Override the global `[babel] group` for this interface.
    pub group: Option<String>,
}

impl BabelInterfaceSpec {
    /// Human-readable label for log lines.
    pub fn label(&self) -> &str {
        self.name.as_deref().unwrap_or("(unnamed)")
    }
}

/// One `[[roa]]` table — a Route Origin Authorization binding
/// (RFC 6482 §3 / RFC 6811 §2). Loaded at startup into the
/// router-wide [`lr_bgp::RoaTable`] used by the import hook
/// (`[bgp] roa_validate = true`) and the filter DSL's `roa.state`
/// accessor.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct RoaSpec {
    /// Authorized prefix (`"203.0.113.0/24"`), required.
    pub prefix: Option<String>,
    /// Maximum authorized prefix length. Defaults to the prefix
    /// length when unset (exact-prefix authorization). Must be ≥ the
    /// prefix length and ≤ 32 (v4) or 128 (v6).
    pub max_length: Option<u8>,
    /// Authorized origin AS (RFC 6482 §3.2). AS 0 marks a ROA for
    /// the blackhole range (RFC 6483 §4); it does not match any
    /// real AS but still produces `Invalid` for any actual route
    /// under the prefix.
    pub asn: Option<u32>,
}

/// One `[[filter]]` table — a BIRD-like filter body compiled into
/// an [`lr_policy::filter::Filter`] and attachable to peers via
/// `import_filter` / `export_filter`. See `crates/lr-policy/src/filter/`
/// for the DSL grammar (lexer + Pratt parser + evaluator).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct FilterSpec {
    /// Filter name (referenced from `[[peer]] import_filter` /
    /// `export_filter`), required and unique across the config.
    pub name: Option<String>,
    /// DSL body — a string carrying the filter source. TOML
    /// `\"` escapes are processed by the daemon config parser so
    /// the DSL's own string literals (`if proto == \"bgp\"`) reach
    /// the lexer intact.
    pub body: Option<String>,
    /// Optional human-readable description shown by `lr-daemon
    /// --config-dump` for operator sanity. Ignored at compile time.
    pub description: Option<String>,
}

/// One `[[ldp.interface]]` table (or `--ldp-interface` flag): an
/// interface running basic (link) discovery, RFC 5036 §3.5.2.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct LdpIfSpec {
    /// Kernel interface name (required).
    pub name: Option<String>,
}

impl LdpIfSpec {
    /// Human-readable label for log lines.
    pub fn label(&self) -> &str {
        self.name.as_deref().unwrap_or("(unnamed)")
    }
}

/// One `[[ldp.targeted]]` table (or `--ldp-targeted` flag): an
/// extended-discovery peer — periodic targeted Hellos to `address`
/// (RFC 5036 §3.5.2, LDP-over-TCP without a shared link).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct LdpTargetedSpec {
    /// Peer transport address, optionally with a port suffix
    /// (`"10.0.0.2"` or `"10.0.0.2:646"`). Without a port the local
    /// LDP port is used (the standard symmetric deployment).
    pub address: Option<String>,
}

impl LdpTargetedSpec {
    /// Human-readable label for log lines.
    pub fn label(&self) -> &str {
        self.address.as_deref().unwrap_or("(unnamed)")
    }
}

/// One `[[ldp.bind]]` table (or `--ldp-bind` flag): a local FEC-label
/// binding advertised downstream-unsolicited to every operational
/// peer. Explicit (deterministic) label allocation; automatic
/// allocation from a label range is future work.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct LdpBindSpec {
    /// FEC prefix (`"203.0.113.0/24"`), required.
    pub prefix: Option<String>,
    /// MPLS label value, 16..=1048575 (0..=15 are reserved per
    /// RFC 3032 §1.2), required.
    pub label: u32,
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
    /// Locally originated RFC 8277 labelled networks, in the form
    /// `"prefix label1[,label2,...]"`, e.g. `"203.0.113.0/24 100"` or
    /// `"10.0.0.0/8 100,200,3"`. Originated as IPv4 labelled-unicast
    /// (AFI=1, SAFI=4) for IPv4 prefixes and IPv6 labelled-unicast
    /// (AFI=2, SAFI=4) for IPv6 prefixes.
    pub labeled_networks: Vec<String>,
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
    /// Dialect of the config file: `"toml"` (native), `"bird"` or
    /// `"frr"` (compat surface). Set at load time; SIGHUP / API
    /// `reload` re-parse the file through the same dialect path.
    pub config_dialect: Option<String>,
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
    /// BFD fast-fail enabled for peers that do not override
    /// (`--bfd` / `[bgp] bfd`). Sessions run on the RFC 5881 ports and
    /// a BFD Down tears the BGP session immediately instead of
    /// waiting out the hold timer.
    pub bfd_enabled: bool,
    /// BFD multihop default (RFC 5883: UDP 4784, no TTL 255 check).
    pub bfd_multihop: bool,
    /// BFD DesiredMinTxInterval in milliseconds (RFC 5880 §6.8.1).
    pub bfd_min_tx_ms: u32,
    /// BFD RequiredMinRxInterval in milliseconds.
    pub bfd_min_rx_ms: u32,
    /// BFD detection multiplier (packets lost before Down).
    pub bfd_multiplier: u8,
    /// Protocol(s) to run, as a comma-separated list: "bgp" (the
    /// default), "babel", "ospf", "bmp", "ldp" or a combination
    /// like "bgp,ospf". `--protocol` is repeatable and each value may
    /// itself carry several comma-separated names; the TOML
    /// equivalents are `protocol = "bgp,ospf"` and
    /// `protocols = ["bgp", "ospf"]`. See [`DaemonConfig::protocol_set`].
    pub protocol: String,
    /// Babel multicast group address (default: ff02::1:6).
    pub babel_group: Option<String>,
    /// Babel local port (default: 6696).
    pub babel_port: u16,
    /// RFC 8967 MAC keys (`[[babel.key]]` tables / repeatable
    /// `--babel-key`). When non-empty the babel transport signs every
    /// datagram (one MAC TLV per key) and verifies inbound ones with the
    /// full RFC 8967 §4.3 state machine.
    pub babel_keys: Vec<BabelKeySpec>,
    /// RFC 8967 §5 incremental deployment: send authenticated packets but
    /// accept unauthenticated inbound ones (`--babel-accept-unauthenticated`).
    pub babel_accept_unauthenticated: bool,
    /// RFC 9467 §3.1 unicast/multicast PC split (RECOMMENDED, default on;
    /// `--babel-no-pc-split` disables it).
    pub babel_split_unicast_multicast: bool,
    /// RFC 9467 §3.2 window size for PC verification (OPTIONAL; 0 = off).
    pub babel_pc_window: usize,
    /// `[[babel.interface]]` blocks — per-interface Babel parameters
    /// with shell-like name wildcards (RFC 8966 §A.2). When empty
    /// the daemon runs the legacy single-socket path bound to
    /// `--local-address`. When non-empty it enumerates system
    /// interfaces, matches them against the patterns in file order,
    /// and uses the first match's parameters for the single Babel
    /// session. The first matching pattern wins (BIRD `interface`
    /// directive parity).
    pub babel_interfaces: Vec<BabelInterfaceSpec>,
    /// BMP monitoring station to mirror Peer Up/Down + Route Monitoring
    /// to (`--bmp-target host:port` / `[bgp] bmp_target`).
    pub bmp_target: Option<String>,
    /// RFC 8212 default eBGP route behaviors: `"rfc8212"` (default —
    /// deny-in/deny-out for external peers without explicit policy) or
    /// `"accept-all"` (the RFC 4271 default the RFC allows as a
    /// deviation, §3 / Appendix A "insecure-mode").
    pub ebgp_policy: String,
    /// FRR `bgp enforce-first-as` (W2.2): when on, an eBGP UPDATE
    /// whose AS_PATH leftmost sequence segment's first AS is not the
    /// peer's AS is rejected before Adj-RIB-In. Off by default —
    /// matches FRR `no bgp enforce-first-as`.
    pub enforce_first_as: bool,
    /// FRR `bgp bestpath compare-routerid` (W2.2): when on (the
    /// default), the best-path tiebreaker uses the lowest BGP
    /// IDENTIFIER (RFC 5004 deterministic mode). When off, the
    /// oldest-received route wins (FRR's default).
    pub bestpath_compare_routerid: bool,
    /// FRR `bgp default ipv4-unicast` (W2.1): when on (the default —
    /// matches FRR), IPv4 unicast is implicitly active for every BGP
    /// peer even when its `mp_families` does not list it. When off,
    /// IPv4 unicast must be added explicitly to the peer's
    /// `mp_families` (FRR `no bgp default ipv4-unicast` with explicit
    /// `address-family ipv4 unicast` / `neighbor X activate`).
    pub default_ipv4_unicast: bool,
    /// FRR `bgp allow-local-as [N]` (W2.3): router-wide default for the
    /// per-peer `allow_local_as` knob. `0` (the default) rejects any
    /// occurrence of the local AS in a received AS_PATH (RFC 4271
    /// §9.1.2.15). `N > 0` admits up to N occurrences (FRR
    /// `allowas-in N`); `u32::MAX` admits any number (FRR
    /// `allowas-any`). Per-peer overrides via `[peer] allow_local_as`.
    pub allow_local_as: u32,
    /// FRR `bgp soft-reconfiguration inbound` (W2.4): router-wide
    /// default for the per-peer `soft_reconfig_inbound` knob. When
    /// on, the router retains the pre-policy Adj-RIB-In for every BGP
    /// peer — the raw received routes before the import hook chain
    /// runs — so a policy reconfiguration can be applied without
    /// re-fetching from the peer (`clear ip bgp * soft in`). Off by
    /// default (FRR's default; the cost is duplicate RIB memory per
    /// peer). Per-peer overrides via `[peer] soft_reconfig_inbound`.
    pub soft_reconfig_inbound: bool,
    /// W6.3 exchange-plane prototype (`[bgp] exchange_plane`,
    /// `--exchange-plane`): advertise the LRXP capability (code 251) on
    /// every BGP peer and activate the record plane where the peer
    /// negotiates it. Off by default. Requires a binary built with the
    /// `exchange-plane` feature; enabling it on a feature-less binary
    /// is a startup error (fail closed).
    pub exchange_plane: bool,
    /// Exchange-plane record keys as `"id:secret"` pairs
    /// (`[[bgp] exchange_plane_keys]` / repeatable
    /// `--exchange-plane-key`). HMAC-SHA256 (design §8 prototype
    /// trust); the key-id intersection with the peer's advertisement
    /// decides activation, and every negotiated key id stays valid
    /// while rotating (new key id added before the old one removed).
    pub exchange_plane_keys: Vec<String>,

    /// `[[roa]]` tables — Route Origin Authorizations (RFC 6482)
    /// loaded into the router-wide [`lr_bgp::RoaTable`] at startup.
    /// When `roa_validate` is on, every received BGP UPDATE is
    /// validated per RFC 6811 §2; `roa_invalid_action` decides the
    /// `Invalid` outcome. The filter DSL exposes the state via
    /// `roa.state` regardless of `roa_validate` so an explicit
    /// `if roa.state == "invalid" then { reject; }` always works.
    pub roas: Vec<RoaSpec>,
    /// RFC 6811 §2 prefix-origin validation: when on, every received
    /// BGP UPDATE is validated against `[[roa]]` tables at import
    /// time (before the user-supplied import hook chain runs). Off
    /// by default — matches BIRD's opt-in `rpki reload` model.
    pub roa_validate: bool,
    /// Action when a received route is `Invalid` per RFC 6811 §2:
    /// `"reject"` (default — drop the route before Adj-RIB-In),
    /// `"warn"` (accept with a `config warning` log line; the
    /// filter DSL still sees `roa.state == "invalid"`), or
    /// `"accept"` (silent accept — operator who wants RFC 8212
    /// default-accept must use this; otherwise Invalid is rejected).
    pub roa_invalid_action: String,

    /// `[[filter]]` tables — BIRD-like filter bodies attached to
    /// peers via `import_filter` / `export_filter`. Compiled into
    /// [`lr_policy::filter::Filter`] instances at startup and
    /// evaluated against every route through the existing policy
    /// hook chain.
    pub filters: Vec<FilterSpec>,

    /// OSPF protocol version: `"v2"` (default) or `"v3"` (RFC 5340).
    /// One version per daemon process — the two are independent
    /// protocols with separate LSDBs (FRR runs ospfd and ospf6d the
    /// same way).
    pub ospf_version: String,
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
    /// RFC 8665 §3.2: this router's SRGB base label (first label of
    /// the range). Absent until `[ospf] srgb_base` is configured.
    pub ospf_srgb_base: Option<u32>,
    /// RFC 8665 §3.2: SRGB range size (label count).
    pub ospf_srgb_range: Option<u32>,
    /// `[[ospf.prefix_sid]]` tables — locally originated prefixes
    /// advertised with a Prefix-SID in an Extended Prefix Opaque LSA.
    pub ospf_prefix_sids: Vec<OspfPrefixSidSpec>,
    /// `[[ospf.mapping_server]]` tables — the SR Mapping Server role
    /// (RFC 8665 §4): Extended Prefix Range TLVs binding ranges of
    /// prefixes to SID indexes on behalf of their owners.
    pub ospf_mapping_servers: Vec<OspfMappingServerSpec>,
    /// RFC 8665 reception (`[ospf] sr_receive`): project the area LSDB
    /// into a per-node SR database and attach the resolved Prefix-SID
    /// labels (RFC 8660 head end) to the routes they map onto. Off by
    /// default — a router that never enables it stays byte-identical
    /// to a pre-SR one.
    pub ospf_sr_receive: bool,
    /// RFC 9513 §5 reception (`[ospf] srv6_receive`, OSPFv3 only):
    /// project learned Locator LSAs into the per-node SRv6 database
    /// and install the §5 locator routes. Off by default (fail
    /// closed — the `sr_receive` counterpart on the v3 plane).
    pub ospf_srv6_receive: bool,
    /// RFC 9513 §2 (`[ospf] srv6_o_flag`): advertise the RFC 9259
    /// SRH O-flag in the SRv6 Capabilities TLV. Off by default.
    pub ospf_srv6_o_flag: bool,
    /// Node MSD limits advertised in the RI LSA's Node MSD TLV when
    /// set (RFC 8476 §2 carrier, RFC 9352 §4 MSD types).
    pub ospf_srv6_max_sl: Option<u8>,
    /// See `ospf_srv6_max_sl` (SRH Max End Pop, MSD type 42).
    pub ospf_srv6_max_end_pop: Option<u8>,
    /// See `ospf_srv6_max_sl` (SRH Max H.Encaps, MSD type 44).
    pub ospf_srv6_max_h_encaps: Option<u8>,
    /// See `ospf_srv6_max_sl` (SRH Max End D, MSD type 45).
    pub ospf_srv6_max_end_d: Option<u8>,
    /// `[[ospf.srv6_locator]]` tables — locally originated SRv6
    /// locators (RFC 9513 §7), OSPFv3 only.
    pub ospf_srv6_locators: Vec<OspfSrv6LocatorSpec>,
    /// OSPF graceful restart, restarting side (RFC 3623 §2): on
    /// shutdown, originate Grace-LSAs per interface and exit without
    /// the session-close teardown (kernel routes persist); after the
    /// restart, suppress topology-LSA origination until every
    /// pre-restart adjacency is Full again (`--ospf-graceful-restart`).
    pub ospf_graceful_restart: bool,
    /// Grace period offered in the Grace-LSAs (`--ospf-grace-period`,
    /// seconds, 1..=1800 per RFC 3623 §2.1; BIRD/FRR default 120).
    pub ospf_grace_period: u32,
    /// OSPF graceful restart helper mode (RFC 3623 §3, default on —
    /// BIRD `AWARE`/FRR helper default): retain a restarting
    /// neighbour's adjacency and LSAs for the grace period
    /// (`--ospf-no-gr-helper` to refuse).
    pub ospf_gr_helper: bool,
    /// Helper ceiling: the maximum grace period this router will
    /// honour (`--ospf-helper-grace-cap`, seconds; FRR
    /// `supported_grace_time`, default 120 — longer requests are
    /// clamped, not refused).
    pub ospf_helper_grace_cap: u32,
    /// Graceful-restart state file (`--ospf-gr-state-file`,
    /// `[ospf] gr_state_file`): written at graceful shutdown with the
    /// grace deadline, consumed by the restarted process to resume
    /// RFC 3623 §2 recovery. Defaults to `<api-socket>.gr` when the
    /// runtime API socket is configured; absent → restarts re-sync
    /// without the §2 origination suppression.
    pub ospf_gr_state_file: Option<String>,

    /// LDP transport address advertised in Hellos and used for the
    /// TCP session transport (`--ldp-transport`). When unset it
    /// defaults to the first `[[ldp.interface]]` address.
    pub ldp_transport: Option<String>,
    /// IPv6 TCP session transport (`--ldp-transport-v6`, RFC 7552
    /// §6.1 rule 5: a global unicast address). When unset it defaults
    /// to the first global unicast address of the `[[ldp.interface]]`
    /// set; when neither exists the speaker stays IPv4-only.
    pub ldp_transport_v6: Option<String>,
    /// The RFC 7552 §6.1.1 transport-connection preference for
    /// dual-stack peers (the RFC default is LDPoIPv6;
    /// `--ldp-prefer-ipv4` flips it).
    pub ldp_prefer_ipv6: bool,
    /// Mirror the LDP dataplane into the kernel: a pop route per
    /// local binding label and an encap route per learned binding
    /// (Linux `AF_MPLS`, the `install_kernel` counterpart of the
    /// BGP-LU mirror). Off by default.
    pub ldp_install_kernel: bool,
    /// Inclusive bounds of the automatic label allocation range
    /// (RFC 3032 platform-wide range; FRR `mpls label range` parity).
    pub ldp_label_min: u32,
    /// See `ldp_label_min`.
    pub ldp_label_max: u32,
    /// RFC 5036 §3.5.7.1.1 transit-LSR label allocation: allocate one
    /// local label per FEC learned from peers, re-advertise it
    /// upstream and (with `ldp_install_kernel`) mirror the resulting
    /// swap into the kernel MPLS dataplane. Default on — a real LSR
    /// forwards labeled traffic; `[ldp] transit_allocation = false`
    /// (or `--ldp-no-transit`) pins the daemon to the egress/ingress
    /// roles of its explicitly configured bindings only.
    pub ldp_transit_allocation: bool,
    /// RFC 3478 LDP graceful restart (`[ldp] graceful_restart`,
    /// `--ldp-graceful-restart`; off by default — matches FRR's
    /// `mpls ldp graceful-restart`). When on, the Init advertises the
    /// FT Session TLV and an unexpected session failure retains the
    /// failed peer's bindings (marked stale) instead of purging them:
    /// the kernel LSPs keep forwarding while the peer restarts.
    pub ldp_graceful_restart: bool,
    /// Advertised FT Reconnect Timeout in milliseconds (RFC 3478 §2):
    /// how long a peer should keep its forwarding state for our LSPs
    /// when the session with us fails. FRR's default is 15000.
    pub ldp_gr_reconnect_ms: u32,
    /// Advertised Recovery Time in milliseconds (RFC 3478 §2). The
    /// honest default is 0: the daemon does not preserve its MPLS
    /// forwarding state across its own restart (the kernel mirror is
    /// deleted on shutdown), so peers delete their stale bindings for
    /// us on reconnection and relearn from our re-advertisements.
    pub ldp_gr_recovery_ms: u32,
    /// RFC 5036 §2.8 Loop Detection: propose the D bit (PVLim =
    /// `ldp_loop_pv_limit`) in the Init and enforce the §3.4.4.1/A.2.6
    /// Hop Count and Path Vector checks on received Label Mapping and
    /// Label Request messages. Off by default (a per-domain option:
    /// enable on all LSRs in the domain or not at all).
    pub ldp_loop_detection: bool,
    /// Maximum Hop Count accepted on received messages (RFC 5036
    /// §2.8.1 "configured maximum value"; a value of 0 means unknown).
    pub ldp_loop_hc_limit: u8,
    /// Maximum Path Vector length accepted (PVLim proposed in the
    /// Init; RFC 5036 §2.8.2 "maximum allowable length").
    pub ldp_loop_pv_limit: u8,
    /// LDP UDP/TCP port (RFC 5036 §3.10.1: 646; overridable for
    /// multi-instance testing on shared hosts).
    pub ldp_port: u16,
    /// Session KeepAlive Time proposal in seconds (§3.5.3; 15 default).
    pub ldp_keepalive_time: u16,
    /// Link Hello hold time proposal in seconds (§3.5.2.1; 15 default).
    pub ldp_link_hold: u16,
    /// Targeted Hello hold time proposal in seconds (§3.5.2.1; 45
    /// default).
    pub ldp_targeted_hold: u16,
    /// `[[ldp.interface]]` tables / `--ldp-interface` flags (basic
    /// discovery).
    pub ldp_interfaces: Vec<LdpIfSpec>,
    /// `[[ldp.targeted]]` tables / `--ldp-targeted` flags (extended
    /// discovery peers).
    pub ldp_targeted: Vec<LdpTargetedSpec>,
    /// `[[ldp.bind]]` tables / `--ldp-bind` flags: local FEC-label
    /// bindings advertised downstream-unsolicited.
    pub ldp_binds: Vec<LdpBindSpec>,

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
            bfd_min_tx_ms: 100,
            bfd_min_rx_ms: 100,
            bfd_multiplier: 3,
            protocol: "bgp".to_string(),
            babel_port: 6696,
            babel_keys: Vec::new(),
            babel_accept_unauthenticated: false,
            babel_split_unicast_multicast: true,
            babel_pc_window: 0,
            babel_interfaces: Vec::new(),
            ebgp_policy: "rfc8212".to_string(),
            enforce_first_as: false,
            bestpath_compare_routerid: true,
            default_ipv4_unicast: true,
            allow_local_as: 0,
            soft_reconfig_inbound: false,
            exchange_plane: false,
            exchange_plane_keys: Vec::new(),
            roas: Vec::new(),
            roa_validate: false,
            roa_invalid_action: "reject".to_string(),
            filters: Vec::new(),
            ospf_version: "v2".to_string(),
            ospf_hello_interval: 10,
            ospf_dead_interval: 40,
            ospf_area: 0,
            ospf_sr_receive: false,
            ospf_srv6_receive: false,
            ospf_srv6_o_flag: false,
            ospf_graceful_restart: false,
            ospf_grace_period: lr_ospf::gr::DEFAULT_GRACE_PERIOD_SECS,
            ospf_gr_helper: true,
            ospf_helper_grace_cap: lr_ospf::gr::DEFAULT_GRACE_PERIOD_SECS,
            ospf_gr_state_file: None,
            ldp_port: 646,
            ldp_transport_v6: None,
            ldp_prefer_ipv6: true,
            ldp_install_kernel: false,
            ldp_label_min: 16,
            ldp_label_max: 1048575,
            ldp_transit_allocation: true,
            ldp_graceful_restart: false,
            ldp_gr_reconnect_ms: 15000,
            ldp_gr_recovery_ms: 0,
            ldp_loop_detection: false,
            ldp_loop_hc_limit: 32,
            ldp_loop_pv_limit: 32,
            ldp_keepalive_time: 15,
            ldp_link_hold: 15,
            ldp_targeted_hold: 45,
            ..Default::default()
        }
    }

    /// The protocol set this daemon runs (rc.3): the comma-separated
    /// [`Self::protocol`] string splits into an order-preserving,
    /// duplicate-free list of names. At least one name always comes
    /// out (an empty or all-comma value falls back to `bgp`, matching
    /// the historical default).
    ///
    /// Combinations run in one process through the multi-protocol
    /// supervisor (`bgp,ospf`, `bgp,babel`, `ospf,babel`, …); a single
    /// name takes the classic dedicated daemon path. Name validation
    /// is fail-closed and lives with the dispatcher so every entry
    /// point (CLI, TOML, reload diagnostics) shares one message.
    pub fn protocol_set(&self) -> Vec<String> {
        let mut set: Vec<String> = Vec::new();
        for name in self
            .protocol
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            if !set.iter().any(|seen| seen == name) {
                set.push(name.to_string());
            }
        }
        if set.is_empty() {
            set.push("bgp".to_string());
        }
        set
    }

    /// True when the protocol set includes `name`.
    pub fn runs_protocol(&self, name: &str) -> bool {
        self.protocol_set().iter().any(|p| p == name)
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
        self.finalize_ldp()?;
        self.finalize_roa()?;
        self.finalize_filters()?;
        self.finalize_babel_interfaces()?;
        Ok(())
    }

    /// Validate and complete the ROA configuration (RFC 6482 invariants).
    /// Surfaced as a separate step so the daemon can collect every
    /// ROA error before bailing out, instead of failing on the first
    /// malformed entry.
    fn finalize_roa(&mut self) -> Result<(), String> {
        let mut seen: std::collections::BTreeSet<(lr_core::addr::Prefix, u32)> =
            std::collections::BTreeSet::new();
        for spec in &self.roas {
            let Some(prefix_text) = spec.prefix.as_deref() else {
                return Err("[[roa]] without 'prefix'".to_string());
            };
            let prefix: lr_core::addr::Prefix = prefix_text
                .parse()
                .map_err(|_| format!("[[roa]] bad prefix '{prefix_text}'"))?;
            let asn = spec
                .asn
                .ok_or_else(|| format!("[[roa]] {prefix_text} without 'asn' (RFC 6482 §3.2)"))?;
            // The RoaEntry invariant: max_length >= prefix_len and ≤
            // family width. RoaEntry::with_max_length enforces this
            // and produces the canonical error string the daemon
            // surfaces in its startup log.
            let _entry = match spec.max_length {
                Some(ml) => lr_bgp::RoaEntry::with_max_length(prefix, ml, lr_core::addr::Asn(asn))
                    .map_err(|e| format!("[[roa]] {prefix_text}: {e}"))?,
                None => lr_bgp::RoaEntry::exact(prefix, lr_core::addr::Asn(asn)),
            };
            if !seen.insert((prefix, asn)) {
                return Err(format!(
                    "[[roa]] {prefix_text} asn {asn} declared twice (duplicate)"
                ));
            }
        }
        Ok(())
    }

    /// Validate and complete the filter DSL configuration. Each
    /// `[[filter]]` table needs a non-empty `name` and a non-empty
    /// `body`. Names are unique across the config (the peer attachment
    /// references them). The DSL body itself is compiled by
    /// `daemon_policy::build_policy_set` (which delegates to
    /// `lr_policy::filter::Filter::compile`) so every per-filter
    /// syntax error surfaces in one pass.
    fn finalize_filters(&mut self) -> Result<(), String> {
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for spec in &self.filters {
            let Some(name) = spec.name.as_deref() else {
                return Err("[[filter]] without 'name'".to_string());
            };
            if name.is_empty() {
                return Err("[[filter]] with empty 'name'".to_string());
            }
            if !seen.insert(name.to_string()) {
                return Err(format!("[[filter]] name '{name}' declared twice"));
            }
            if spec.body.as_deref().map(str::is_empty).unwrap_or(true) {
                return Err(format!("[[filter]] '{name}' without 'body'"));
            }
        }
        Ok(())
    }

    /// Validate the `[[babel.interface]]` blocks. Each needs a name
    /// (the glob pattern). RTT bounds must satisfy
    /// `rtt_min_us < rtt_max_us` when both are set (RFC 8966 §A.2.4
    /// / BIRD's `RTT MIN must be smaller than MAX` rule). Wildcard
    /// patterns are syntax-checked against the same shell-like
    /// grammar BIRD uses (`*`, `?`, `\`); the actual interface
    /// matching happens at daemon startup in `run_babel_daemon`.
    fn finalize_babel_interfaces(&mut self) -> Result<(), String> {
        for iface in &self.babel_interfaces {
            let Some(name) = iface.name.as_deref() else {
                return Err("[[babel.interface]] without 'name'".to_string());
            };
            if name.is_empty() {
                return Err("[[babel.interface]] with empty 'name'".to_string());
            }
            // Validate the glob pattern is well-formed (no stray
            // backslashes). BIRD's patmatch treats `\` as an escape,
            // so a trailing `\` is a syntax error in the pattern itself.
            if let Err(e) = glob_pattern_validate(name) {
                return Err(format!("[[babel.interface]] bad pattern '{name}': {e}"));
            }
            if let (Some(min), Some(max)) = (iface.rtt_min_us, iface.rtt_max_us) {
                if min >= max {
                    return Err(format!(
                        "[[babel.interface]] {name}: rtt_min ({min}us) must be < rtt_max ({max}us) (RFC 8966 §A.2.4)"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate and complete the OSPF configuration (only meaningful
    /// with `--protocol ospf`; other protocols get a warning when OSPF
    /// tables are present). Fills interface areas from the global
    /// default and enforces the fail-closed rules: every interface
    /// named, non-backbone areas declared exactly once, valid area
    /// types, the backbone never stub/NSSA.
    fn finalize_ospf(&mut self) -> Result<(), String> {
        if self.ospf_areas.is_empty()
            && self.ospf_interfaces.is_empty()
            && self.ospf_prefix_sids.is_empty()
            && self.ospf_srgb_base.is_none()
            && self.ospf_srgb_range.is_none()
            && self.ospf_srv6_locators.is_empty()
            && !self.ospf_srv6_receive
            && !self.ospf_srv6_o_flag
            && self.ospf_srv6_max_sl.is_none()
            && self.ospf_srv6_max_end_pop.is_none()
            && self.ospf_srv6_max_h_encaps.is_none()
            && self.ospf_srv6_max_end_d.is_none()
        {
            return Ok(());
        }
        if !self.runs_protocol("ospf") {
            self.warnings.push(format!(
                "OSPF tables present but the protocol set is '{}' (ignored)",
                self.protocol
            ));
            return Ok(());
        }
        // RFC 5340 §A.3.2: the v3 Hello dead interval is a 16-bit field
        // (half the v2 width), so RouterDeadInterval must fit it.
        if self.ospf_version == "v3" && self.ospf_dead_interval > 65535 {
            return Err(format!(
                "OSPFv3 dead_interval {} exceeds the 16-bit Hello field (max 65535)",
                self.ospf_dead_interval
            ));
        }
        // OSPFv3 daemon: the v2-scoped extensions (SR-MPLS, Adj-SIDs)
        // are not wired — fail closed instead of silently ignoring
        // configured features. Broadcast segments run the RFC 5340
        // §4.1.2 election (Router-ID identity); graceful restart is
        // RFC 5187 (the v3 counterpart of the v2 RFC 3623 surface —
        // same knobs, same state-file semantics).
        if self.ospf_version == "v3" {
            for spec in &self.ospf_interfaces {
                if spec.adj_sid.is_some() {
                    return Err(
                        "OSPFv3 does not support adj_sid (SR is an OSPFv2 extension)".to_string(),
                    );
                }
            }
            if self.ospf_srgb_base.is_some()
                || self.ospf_srgb_range.is_some()
                || !self.ospf_prefix_sids.is_empty()
                || !self.ospf_mapping_servers.is_empty()
            {
                return Err(
                    "OSPFv3 does not support the SR-MPLS configuration (srgb/prefix_sid/mapping_server are OSPFv2 extensions)"
                        .to_string(),
                );
            }
        }
        // SRv6 (RFC 9513) is an OSPFv3-only extension: under v2 the
        // config is rejected outright instead of being ignored.
        if self.ospf_version != "v3"
            && (!self.ospf_srv6_locators.is_empty()
                || self.ospf_srv6_receive
                || self.ospf_srv6_o_flag
                || self.ospf_srv6_max_sl.is_some()
                || self.ospf_srv6_max_end_pop.is_some()
                || self.ospf_srv6_max_h_encaps.is_some()
                || self.ospf_srv6_max_end_d.is_some())
        {
            return Err(
                "SRv6 configuration (srv6_*) is an OSPFv3 extension (RFC 9513); set [ospf] version = \"v3\""
                    .to_string(),
            );
        }
        // Per-locator validation (RFC 9513 §7.1/§8/§10): an IPv6
        // prefix, an End-SID-valid behavior, and an all-or-none §10
        // SID Structure whose lengths sum to ≤ 128 bits. Duplicate
        // locator prefixes are a config bug (they would emit two
        // indistinguishable TLVs) — fail closed.
        let mut seen_locators = std::collections::BTreeSet::new();
        for loc in &self.ospf_srv6_locators {
            let Some(text) = loc.prefix.as_deref() else {
                return Err("[[ospf.srv6_locator]] without 'prefix'".to_string());
            };
            let prefix: lr_core::addr::Prefix = text
                .parse()
                .map_err(|_| format!("srv6_locator: bad prefix '{text}'"))?;
            if matches!(prefix.addr, lr_core::addr::IpAddr::V4(_)) {
                return Err(format!(
                    "srv6_locator: prefix '{text}' must be IPv6 (RFC 9513 §7.1)"
                ));
            }
            if !seen_locators.insert(prefix) {
                return Err(format!("srv6_locator: prefix '{text}' configured twice"));
            }
            if let Some(sid) = loc.sid.as_deref() {
                let sid: lr_core::addr::IpAddr = sid
                    .parse()
                    .map_err(|_| format!("srv6_locator: bad sid '{sid}'"))?;
                if matches!(sid, lr_core::addr::IpAddr::V4(_)) {
                    return Err(format!("srv6_locator: sid '{sid}' must be an IPv6 address"));
                }
            }
            if let Some(b) = loc.behavior {
                if !lr_ospf::lsa::srv6::behavior_valid_for_end_sid(b) {
                    return Err(format!(
                        "srv6_locator: behavior {b} is not valid in an End SID sub-TLV (RFC 9513 §8)"
                    ));
                }
            }
            let lens = [
                loc.block_len,
                loc.node_len,
                loc.function_len,
                loc.argument_len,
            ];
            if lens.iter().any(|l| l.is_some()) && lens.iter().any(|l| l.is_none()) {
                return Err(
                    "srv6_locator: the §10 SID Structure needs all of block_len/node_len/function_len/argument_len (or none)"
                        .to_string(),
                );
            }
            if let [Some(b), Some(n), Some(f), Some(a)] = lens {
                if u32::from(b) + u32::from(n) + u32::from(f) + u32::from(a) > 128 {
                    return Err(format!(
                        "srv6_locator: SID structure {b}+{n}+{f}+{a} exceeds 128 bits (RFC 9513 §10)"
                    ));
                }
            }
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
        // Segment Routing (RFC 8665): prefix SIDs need an SRGB; a
        // base without a range (or vice versa) is a config bug. When
        // only the SRGB is configured (no prefix SIDs yet) it still
        // gets advertised — the node is SR-capable even before it
        // originates SIDs (that is what a future mapping server or
        // Adj-SID slice builds on).
        if (self.ospf_srgb_base.is_some()) != (self.ospf_srgb_range.is_some()) {
            return Err("[ospf] srgb_base and srgb_range must be set together".to_string());
        }
        for spec in &self.ospf_prefix_sids {
            let Some(prefix) = spec.prefix.as_deref().filter(|p| !p.is_empty()) else {
                return Err("[[ospf.prefix_sid]] without 'prefix'".to_string());
            };
            prefix
                .parse::<lr_core::addr::Prefix>()
                .map_err(|_| format!("[[ospf.prefix_sid]] bad prefix '{prefix}'"))?;
            spec.sid
                .ok_or_else(|| format!("[[ospf.prefix_sid]] {prefix} without 'sid'"))?;
        }
        for spec in &self.ospf_mapping_servers {
            let Some(prefix) = spec.prefix.as_deref().filter(|p| !p.is_empty()) else {
                return Err("[[ospf.mapping_server]] without 'prefix'".to_string());
            };
            prefix
                .parse::<lr_core::addr::Prefix>()
                .map_err(|_| format!("[[ospf.mapping_server]] bad prefix '{prefix}'"))?;
            spec.sid
                .ok_or_else(|| format!("[[ospf.mapping_server]] {prefix} without 'sid'"))?;
        }
        if !self.ospf_prefix_sids.is_empty() || !self.ospf_mapping_servers.is_empty() {
            // FRR's default SRGB (16000/8000) applies when the
            // operator configures SIDs without an explicit block.
            let base = self.ospf_srgb_base.unwrap_or(16_000);
            let range = self.ospf_srgb_range.unwrap_or(8_000);
            self.ospf_srgb_base = Some(base);
            self.ospf_srgb_range = Some(range);
            if base + range - 1 > 1_048_575 {
                return Err(format!(
                    "[ospf] srgb_base {base} + srgb_range {range} overflows the MPLS label space"
                ));
            }
            for spec in &self.ospf_prefix_sids {
                let sid = spec.sid.unwrap_or(0);
                if sid >= range {
                    return Err(format!(
                        "[[ospf.prefix_sid]] sid {sid} falls outside the SRGB range 0..={}",
                        range - 1
                    ));
                }
            }
            for spec in &self.ospf_mapping_servers {
                let sid = spec.sid.unwrap_or(0);
                let size = spec.range_size.unwrap_or(1).max(1);
                if size > range || sid >= range || sid + size > range {
                    return Err(format!(
                        "[[ospf.mapping_server]] range sid {sid} + size {size} falls outside \
                         the SRGB range 0..={}",
                        range - 1
                    ));
                }
                // RFC 8665 §4: the Range Size must fit the prefix's
                // address space.
                let parsed = spec
                    .prefix
                    .as_deref()
                    .unwrap_or("")
                    .parse::<lr_core::addr::Prefix>()
                    .map_err(|_| "[[ospf.mapping_server]] bad prefix".to_string())?;
                if parsed.prefix_len > 32 {
                    return Err(format!(
                        "[[ospf.mapping_server]] bad prefix length {}",
                        parsed.prefix_len
                    ));
                }
                let space: u64 = 1u64 << (32 - u32::from(parsed.prefix_len));
                if u64::from(size) > space {
                    return Err(format!(
                        "[[ospf.mapping_server]] range_size {size} exceeds the /{} address space",
                        parsed.prefix_len
                    ));
                }
            }
        }
        for spec in &self.ospf_interfaces {
            // RFC 3032 platform label space; 0..=15 are reserved.
            if let Some(sid) = spec.adj_sid {
                if !(16..=1_048_575).contains(&sid) {
                    return Err(format!(
                        "[[ospf.interface]] adj_sid {sid} outside the MPLS label range 16..=1048575"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate and complete the LDP configuration (only meaningful
    /// with `--protocol ldp`; other protocols get a warning when LDP
    /// tables are present). Fail-closed rules: named interfaces,
    /// addressed targeted peers, valid bind prefixes and labels
    /// (16..=1048575 per RFC 3032 — 0..=15 are reserved), KeepAlive
    /// Time non-zero (§3.5.3), and at least one discovery source
    /// (interface or targeted peer) when the mode runs.
    fn finalize_ldp(&mut self) -> Result<(), String> {
        if self.ldp_interfaces.is_empty()
            && self.ldp_targeted.is_empty()
            && self.ldp_binds.is_empty()
            && self.ldp_transport.is_none()
            && !self.runs_protocol("ldp")
        {
            return Ok(());
        }
        if !self.runs_protocol("ldp") {
            self.warnings.push(format!(
                "LDP tables present but the protocol set is '{}' (ignored)",
                self.protocol
            ));
            return Ok(());
        }
        for iface in &self.ldp_interfaces {
            if iface.name.as_deref().is_none_or(str::is_empty) {
                return Err("[[ldp.interface]] without 'name'".to_string());
            }
        }
        for peer in &self.ldp_targeted {
            let spec = peer.address.as_deref().unwrap_or_default();
            if spec.is_empty() {
                return Err("[[ldp.targeted]] without 'address'".to_string());
            }
            // RFC 7552 §5.2: link-local addresses MUST NOT be used as
            // targeted-Hello source or destination. Reject them at
            // parse time (fail closed) instead of discovering the
            // problem on the wire.
            if let Some((lr_core::addr::IpAddr::V6(octets), _)) = parse_targeted_spec(spec) {
                if (u16::from_be_bytes([octets[0], octets[1]]) & 0xffc0) == 0xfe80 {
                    return Err(format!(
                        "[[ldp.targeted]] {spec}: link-local addresses must not be \
                         used for targeted discovery (RFC 7552 §5.2)"
                    ));
                }
            }
        }
        for bind in &self.ldp_binds {
            let Some(p) = bind.prefix.as_deref() else {
                return Err("[[ldp.bind]] without 'prefix'".to_string());
            };
            if p.parse::<lr_core::addr::Prefix>().is_err() {
                return Err(format!("[[ldp.bind]] invalid prefix '{p}'"));
            }
        }
        let mut seen_prefixes = std::collections::BTreeSet::new();
        for bind in &self.ldp_binds {
            let p = bind.prefix.as_deref().unwrap_or_default();
            if !seen_prefixes.insert(p.to_string()) {
                return Err(format!("[[ldp.bind]] prefix {p} bound twice"));
            }
        }
        // Label allocation: an explicit label must sit in the
        // platform-writable range (16..=1048575 per RFC 3032 §1.2 —
        // 0..=15 are reserved; 0 in the config means "allocate"). Auto
        // labels hand out the first free value inside the configured
        // range ([ldp] label_min..=label_max), skipping explicit ones.
        if self.ldp_label_min < 16
            || self.ldp_label_min > 1048575
            || self.ldp_label_max < 16
            || self.ldp_label_max > 1048575
            || self.ldp_label_min > self.ldp_label_max
        {
            return Err(format!(
                "[ldp] label range {}..={} is invalid (both bounds must be \
                 16..=1048575 and min <= max, RFC 3032 §1.2)",
                self.ldp_label_min, self.ldp_label_max
            ));
        }
        let mut next_auto = self.ldp_label_min;
        for idx in 0..self.ldp_binds.len() {
            if self.ldp_binds[idx].label == 0 {
                while self.ldp_binds.iter().any(|b| b.label == next_auto) {
                    next_auto += 1;
                }
                if next_auto > self.ldp_label_max {
                    return Err(format!(
                        "[ldp] automatic label allocation exhausted the range \
                         {}..={} — add explicit labels or widen it",
                        self.ldp_label_min, self.ldp_label_max
                    ));
                }
                self.ldp_binds[idx].label = next_auto;
            } else if self.ldp_binds[idx].label > 1048575 {
                return Err(format!(
                    "[[ldp.bind]] label {} out of range (16..=1048575, RFC 3032)",
                    self.ldp_binds[idx].label
                ));
            } else if self.ldp_binds[idx].label < 16 {
                return Err(format!(
                    "[[ldp.bind]] label {} is reserved (RFC 3032 §1.2: 0..=15)",
                    self.ldp_binds[idx].label
                ));
            }
        }
        if self.ldp_keepalive_time == 0 {
            return Err("[ldp] keepalive_time must be non-zero (RFC 5036 §3.5.3)".to_string());
        }
        if self.ldp_link_hold == 0 || self.ldp_targeted_hold == 0 {
            return Err("[ldp] hold times must be non-zero (RFC 5036 §3.5.2.1)".to_string());
        }
        if self.ldp_interfaces.is_empty() && self.ldp_targeted.is_empty() {
            return Err(
                "--protocol ldp needs at least one discovery source: an interface \
                 (--ldp-interface / [[ldp.interface]]) or a targeted peer \
                 (--ldp-targeted / [[ldp.targeted]])"
                    .to_string(),
            );
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

    /// BFD fast-fail resolved for one peer (per-peer override of the
    /// `[bgp]` / `--bfd` global).
    pub fn effective_bfd(&self, peer: &PeerSpec) -> bool {
        peer.bfd.unwrap_or(self.bfd_enabled)
    }

    /// BFD mode resolved for one peer.
    pub fn effective_bfd_multihop(&self, peer: &PeerSpec) -> bool {
        peer.bfd_multihop.unwrap_or(self.bfd_multihop)
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
    opt(&mut over.import_filter, &base.import_filter);
    opt(&mut over.export_filter, &base.export_filter);
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
    if over.bfd.is_none() {
        over.bfd = base.bfd;
    }
    if over.bfd_multihop.is_none() {
        over.bfd_multihop = base.bfd_multihop;
    }
    if over.default_ipv4_unicast.is_none() {
        over.default_ipv4_unicast = base.default_ipv4_unicast;
    }
    if over.allow_local_as.is_none() {
        over.allow_local_as = base.allow_local_as;
    }
    if over.soft_reconfig_inbound.is_none() {
        over.soft_reconfig_inbound = base.soft_reconfig_inbound;
    }
    if over.exchange_plane.is_none() {
        over.exchange_plane = base.exchange_plane;
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(value, "true" | "1" | "yes")
}

/// Process TOML `\\`, `\"`, `\n`, `\t`, `\r` escapes in a string
/// value. Used by the filter DSL `body` field (which carries a
/// multi-line DSL program with embedded `\"` for the DSL's own
/// string literals, e.g. `if proto == \"bgp\"`). The caller has
/// already stripped the outer `"` quotes via `trim_matches('"')` —
/// this function only walks the interior, replacing escape sequences.
fn unescape_toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(other) => {
                    // Unknown escape — preserve verbatim (forward
                    // compatibility, like TOML's "unknown escapes are
                    // an error" rule relaxed to "preserve").
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
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
                "ospf.prefix_sid" => {
                    cfg.ospf_prefix_sids.push(OspfPrefixSidSpec::default());
                    section = "ospf.prefix_sid".to_string();
                }
                "ospf.mapping_server" => {
                    cfg.ospf_mapping_servers
                        .push(OspfMappingServerSpec::default());
                    section = "ospf.mapping_server".to_string();
                }
                "ospf.srv6_locator" => {
                    cfg.ospf_srv6_locators.push(OspfSrv6LocatorSpec::default());
                    section = "ospf.srv6_locator".to_string();
                }
                "babel.key" => {
                    cfg.babel_keys.push(BabelKeySpec::default());
                    section = "babel.key".to_string();
                }
                "babel.interface" => {
                    cfg.babel_interfaces.push(BabelInterfaceSpec::default());
                    section = "babel.interface".to_string();
                }
                "roa" => {
                    cfg.roas.push(RoaSpec::default());
                    section = "roa".to_string();
                }
                "filter" => {
                    cfg.filters.push(FilterSpec::default());
                    section = "filter".to_string();
                }
                "ldp.interface" => {
                    cfg.ldp_interfaces.push(LdpIfSpec::default());
                    section = "ldp.interface".to_string();
                }
                "ldp.targeted" => {
                    cfg.ldp_targeted.push(LdpTargetedSpec::default());
                    section = "ldp.targeted".to_string();
                }
                "ldp.bind" => {
                    cfg.ldp_binds.push(LdpBindSpec::default());
                    section = "ldp.bind".to_string();
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
                && section != "babel"
                && section != "ldp"
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
        // Babel tables and globals: protocol configuration is fail-closed —
        // an unknown key is a typo that could silently disable link
        // authentication or alter replay handling.
        if apply_babel_key(cfg, &section, key, value)
            .map_err(|e| format!("line {}: {}", lineno + 1, e))?
        {
            continue;
        }
        // ROA and filter tables: fail-closed like every other
        // protocol surface — a typo'd prefix or filter body silently
        // changes origin validation behaviour.
        if apply_roa_key(cfg, &section, key, value)
            .map_err(|e| format!("line {}: {}", lineno + 1, e))?
        {
            continue;
        }
        if apply_filter_key(cfg, &section, key, value)
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
        // LDP tables and globals: same fail-closed posture — a typo'd
        // hold time or a mis-spelled bind silently changes discovery
        // or label origination.
        if apply_ldp_key(cfg, &section, key, value)
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
            "bgp.bfd" => cfg.bfd_enabled = parse_bool(value),
            "bgp.bfd_multihop" => cfg.bfd_multihop = parse_bool(value),
            "bgp.bfd_min_tx_ms" => {
                cfg.bfd_min_tx_ms = value.parse().unwrap_or(100);
            }
            "bgp.bfd_min_rx_ms" => {
                cfg.bfd_min_rx_ms = value.parse().unwrap_or(100);
            }
            "bgp.bfd_multiplier" => {
                cfg.bfd_multiplier = value.parse().unwrap_or(3);
            }
            "bgp.md5_key" => cfg.md5_key = Some(value.to_string()),
            "bgp.bmp_target" => cfg.bmp_target = Some(value.to_string()),
            "bgp.ebgp_policy" => {
                if value != "rfc8212" && value != "accept-all" {
                    return Err(format!(
                        "line {}: bad ebgp_policy '{}' (expected \"rfc8212\" or \"accept-all\")",
                        lineno + 1,
                        value
                    ));
                }
                cfg.ebgp_policy = value.to_string();
            }
            "bgp.enforce_first_as" => cfg.enforce_first_as = parse_bool(value),
            "bgp.bestpath_compare_routerid" => {
                cfg.bestpath_compare_routerid = parse_bool(value);
            }
            "bgp.default_ipv4_unicast" => cfg.default_ipv4_unicast = parse_bool(value),
            "bgp.allow_local_as" => {
                // Accept "any" / "allowas-any" as the u32::MAX sentinel,
                // integers as N. FRR `allow-local-as [N]` defaults to
                // N=1 when the value is omitted — but a TOML value
                // without an integer would be a syntax error; the
                // daemon accepts `true`/`false` to mean N=1/0 for
                // BIRD `allow local as` parity.
                cfg.allow_local_as = match value.trim() {
                    "any" | "allowas-any" => u32::MAX,
                    "true" => 1,
                    "false" => 0,
                    other => other.parse().map_err(|_| {
                        format!("line {}: bad allow_local_as '{other}' (expected integer N, 'any', or 'true'/'false')", lineno + 1)
                    })?,
                };
            }
            "bgp.soft_reconfig_inbound" => cfg.soft_reconfig_inbound = parse_bool(value),
            "bgp.exchange_plane" => cfg.exchange_plane = parse_bool(value),
            "bgp.exchange_plane_keys" => cfg.exchange_plane_keys = parse_str_array(value),
            "bgp.roa_validate" | "roa_validate" => cfg.roa_validate = parse_bool(value),
            "bgp.roa_invalid_action" | "roa_invalid_action" => {
                if !matches!(value, "reject" | "warn" | "accept") {
                    return Err(format!(
                        "line {}: bad roa_invalid_action '{}' (expected \"reject\" | \"warn\" | \"accept\")",
                        lineno + 1,
                        value
                    ));
                }
                cfg.roa_invalid_action = value.to_string();
            }
            "bgp.tcp_ao_keys" => cfg.tcp_ao_keys = parse_str_array(value),
            "bgp.tcp_ao_algorithm" => cfg.tcp_ao_algorithm = value.to_string(),
            "bgp.tcp_ao_maclen" => cfg.tcp_ao_maclen = value.parse().unwrap_or(0),
            // rc.3 multi-protocol selection. Top-level keys: the
            // string form mirrors the CLI (`protocol = "bgp,ospf"`),
            // the array form reads better in operator configs
            // (`protocols = ["bgp", "ospf"]`). Like every other
            // overlapping key they override the CLI value. Names are
            // validated fail-closed by the dispatcher, not here, so
            // the reload diagnostics name the same error.
            "protocol" => {
                if value.is_empty() {
                    return Err(format!(
                        "line {}: an empty protocol value needs at least one name",
                        lineno + 1
                    ));
                }
                cfg.protocol = value.to_string();
            }
            "protocols" => {
                let list = parse_str_array(value);
                if list.is_empty() {
                    return Err(format!(
                        "line {}: protocols = [...] needs at least one name",
                        lineno + 1
                    ));
                }
                cfg.protocol = list.join(",");
            }
            "user" => cfg.user = Some(value.to_string()),
            "group" => cfg.group = Some(value.to_string()),
            "api_socket" => cfg.api_socket = Some(value.to_string()),
            "networks" | "bgp.networks" => cfg.networks = parse_str_array(value),
            "labeled_networks" | "bgp.labeled_networks" => {
                cfg.labeled_networks = parse_str_array(value)
            }
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
/// Babel `[babel]` globals and `[[babel.key]]` tables. Fail-closed like
/// the OSPF schema: an unknown key may mean authentication silently
/// disabled, so it is a hard error.
/// Returns `Ok(true)` when the key was consumed here, `Ok(false)` to fall
/// through to the next section schema.
fn apply_babel_key(
    cfg: &mut DaemonConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<bool, String> {
    match section {
        "babel" => match key {
            "group" => {
                cfg.babel_group = Some(value.to_string());
            }
            "port" => {
                cfg.babel_port = value
                    .parse()
                    .map_err(|_| format!("bad babel port '{value}'"))?;
            }
            "accept_unauthenticated" => {
                cfg.babel_accept_unauthenticated = parse_bool(value);
            }
            "split_unicast_multicast" => {
                cfg.babel_split_unicast_multicast = parse_bool(value);
            }
            "pc_window" => {
                cfg.babel_pc_window = value
                    .parse()
                    .map_err(|_| format!("bad babel pc_window '{value}'"))?;
            }
            _ => {
                return Err(format!(
                    "unknown [babel] key '{key}' (typo protection; Babel config fails closed)"
                ))
            }
        },
        "babel.key" => {
            let Some(k) = cfg.babel_keys.last_mut() else {
                return Err("key outside a [[babel.key]] table".into());
            };
            match key {
                "secret" => k.secret = Some(value.to_string()),
                "algorithm" => {
                    if BabelMacAlgorithm::from_name(value).is_none() {
                        return Err(format!(
                            "unknown babel key algorithm '{value}' (hmac-sha256 | blake2s)"
                        ));
                    }
                    k.algorithm = Some(value.to_string());
                }
                _ => {
                    return Err(format!(
                        "unknown [[babel.key]] key '{key}' (typo protection; Babel config fails closed)"
                    ))
                }
            }
        }
        "babel.interface" => {
            let Some(iface) = cfg.babel_interfaces.last_mut() else {
                return Err("key outside a [[babel.interface]] table".into());
            };
            match key {
                "name" => iface.name = Some(value.to_string()),
                "type" | "kind" => {
                    let v = value.trim().trim_matches('"');
                    if !matches!(v, "wired" | "wireless" | "tunnel") {
                        return Err(format!(
                            "bad babel interface type '{v}' (use \"wired\" | \"wireless\" | \"tunnel\")"
                        ));
                    }
                    iface.kind = Some(v.to_string());
                }
                "hello_interval_ms" | "hello_interval" => {
                    iface.hello_interval_ms = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad hello_interval '{value}'"))?,
                    );
                }
                "update_interval_ms" | "update_interval" => {
                    iface.update_interval_ms = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad update_interval '{value}'"))?,
                    );
                }
                "rxcost" => {
                    iface.rxcost = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad rxcost '{value}'"))?,
                    );
                }
                "rtt_cost" => {
                    iface.rtt_cost = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad rtt_cost '{value}'"))?,
                    );
                }
                "rtt_min_us" | "rtt_min" => {
                    iface.rtt_min_us = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad rtt_min '{value}'"))?,
                    );
                }
                "rtt_max_us" | "rtt_max" => {
                    iface.rtt_max_us = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad rtt_max '{value}'"))?,
                    );
                }
                "next_hop_ipv4" | "next_hop_v4" => {
                    iface.next_hop_ipv4 = Some(value.to_string());
                }
                "next_hop_ipv6" | "next_hop_v6" => {
                    iface.next_hop_ipv6 = Some(value.to_string());
                }
                "extended_next_hop" => {
                    iface.extended_next_hop = Some(parse_bool(value));
                }
                "check_link" => {
                    iface.check_link = Some(parse_bool(value));
                }
                "port" => {
                    iface.port = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad babel interface port '{value}'"))?,
                    );
                }
                "group" => {
                    iface.group = Some(value.to_string());
                }
                _ => {
                    return Err(format!(
                        "unknown [[babel.interface]] key '{key}' (typo protection; Babel config fails closed)"
                    ))
                }
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Apply one `key = value` pair to the ROA schema: the `[[roa]]`
/// tables. Fail-closed like every other policy surface — a typo'd
/// prefix silently weakens origin validation, so it is a hard error.
/// Returns `Ok(true)` when the key was consumed here, `Ok(false)`
/// to fall through to the next section schema.
fn apply_roa_key(
    cfg: &mut DaemonConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<bool, String> {
    if section != "roa" {
        return Ok(false);
    }
    let Some(roa) = cfg.roas.last_mut() else {
        return Err("key outside a [[roa]] table".into());
    };
    match key {
        "prefix" => {
            let v = value.trim().trim_matches('"');
            if v.parse::<lr_core::addr::Prefix>().is_err() {
                return Err(format!("bad roa prefix '{v}' (expected CIDR)"));
            }
            roa.prefix = Some(v.to_string());
        }
        "max_length" | "max_len" => {
            let n: u8 = value
                .parse()
                .map_err(|_| format!("bad roa max_length '{value}' (0..=128)"))?;
            roa.max_length = Some(n);
        }
        "asn" | "origin_as" => {
            roa.asn = Some(
                value
                    .parse()
                    .map_err(|_| format!("bad roa asn '{value}' (u32)"))?,
            );
        }
        _ => {
            return Err(format!(
                "unknown [[roa]] key '{key}' (typo protection; ROA config fails closed)"
            ))
        }
    }
    Ok(true)
}

/// Apply one `key = value` pair to the filter DSL schema: the
/// `[[filter]]` tables. Fail-closed — a typo'd key on a filter
/// silently changes route handling. Returns `Ok(true)` when
/// consumed, `Ok(false)` to fall through.
fn apply_filter_key(
    cfg: &mut DaemonConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<bool, String> {
    if section != "filter" {
        return Ok(false);
    }
    let Some(filter) = cfg.filters.last_mut() else {
        return Err("key outside a [[filter]] table".into());
    };
    match key {
        "name" => filter.name = Some(value.to_string()),
        // The body is a TOML string with `\"` escapes that the DSL
        // parser expects to see unescaped. unescape_toml_string
        // converts `\"` back to `"` so `if proto == \"bgp\"` reaches
        // the DSL parser as `if proto == "bgp"`.
        "body" => filter.body = Some(unescape_toml_string(value)),
        "description" | "desc" => filter.description = Some(value.to_string()),
        _ => {
            return Err(format!(
                "unknown [[filter]] key '{key}' (typo protection; filter config fails closed)"
            ))
        }
    }
    Ok(true)
}

fn apply_ospf_key(
    cfg: &mut DaemonConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<bool, String> {
    match section {
        "ospf" => match key {
            "version" => {
                let v = match value {
                    "2" | "v2" => "v2",
                    "3" | "v3" => "v3",
                    other => {
                        return Err(format!("bad OSPF version '{other}' (use \"v2\" or \"v3\")"))
                    }
                };
                cfg.ospf_version = v.to_string();
            }
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
            "graceful_restart" => {
                cfg.ospf_graceful_restart = parse_bool(value);
            }
            "grace_period" => {
                let secs: u32 = value
                    .parse()
                    .map_err(|_| format!("bad grace_period '{value}'"))?;
                if !(1..=lr_ospf::gr::MAX_GRACE_PERIOD_SECS).contains(&secs) {
                    return Err(format!(
                        "grace_period {secs} outside RFC 3623 §2.1 range 1..={}",
                        lr_ospf::gr::MAX_GRACE_PERIOD_SECS
                    ));
                }
                cfg.ospf_grace_period = secs;
            }
            "graceful_restart_helper" => {
                cfg.ospf_gr_helper = parse_bool(value);
            }
            "helper_grace_cap" => {
                let secs: u32 = value
                    .parse()
                    .map_err(|_| format!("bad helper_grace_cap '{value}'"))?;
                if !(1..=lr_ospf::gr::MAX_GRACE_PERIOD_SECS).contains(&secs) {
                    return Err(format!(
                        "helper_grace_cap {secs} outside RFC 3623 §2.1 range 1..={}",
                        lr_ospf::gr::MAX_GRACE_PERIOD_SECS
                    ));
                }
                cfg.ospf_helper_grace_cap = secs;
            }
            "gr_state_file" => {
                cfg.ospf_gr_state_file = Some(value.to_string());
            }
            // RFC 8665 §3.2: the Segment Routing Global Base this
            // router advertises in its Router Information LSA. A
            // base without a range (or vice versa) is a config bug —
            // rejected, defaulted together in finalize() instead.
            "srgb_base" => {
                let base: u32 = value
                    .parse()
                    .map_err(|_| format!("bad srgb_base '{value}'"))?;
                if !(16..=1_048_575).contains(&base) {
                    return Err(format!(
                        "srgb_base {base} outside the MPLS label space 16..=1048575"
                    ));
                }
                cfg.ospf_srgb_base = Some(base);
            }
            "srgb_range" => {
                let range: u32 = value
                    .parse()
                    .map_err(|_| format!("bad srgb_range '{value}'"))?;
                if range == 0 {
                    return Err("srgb_range must be non-zero".into());
                }
                cfg.ospf_srgb_range = Some(range);
            }
            // RFC 8665 reception: resolve Prefix-SIDs learned from the
            // LSDB into MPLS labels and let the kernel mirror install
            // the RFC 8660 encap routes. Off by default (fail closed).
            "sr_receive" => {
                cfg.ospf_sr_receive = parse_bool(value);
            }
            // RFC 9513 §5 reception (OSPFv3): project learned Locator
            // LSAs into the per-node SRv6 database and install the §5
            // locator routes. Off by default (fail closed — the
            // `sr_receive` counterpart on the v3 plane).
            "srv6_receive" => {
                cfg.ospf_srv6_receive = parse_bool(value);
            }
            // RFC 9513 §2: advertise the RFC 9259 SRH O-flag in the
            // SRv6 Capabilities TLV (OSPFv3).
            "srv6_o_flag" => {
                cfg.ospf_srv6_o_flag = parse_bool(value);
            }
            // RFC 8476 Node MSD limits (RFC 9352 §4 MSD types 41/42/
            // 44/45), advertised in the v3 RI LSA when set.
            "srv6_max_sl" => {
                cfg.ospf_srv6_max_sl = Some(
                    value
                        .parse()
                        .map_err(|_| format!("bad srv6_max_sl '{value}'"))?,
                );
            }
            "srv6_max_end_pop" => {
                cfg.ospf_srv6_max_end_pop = Some(
                    value
                        .parse()
                        .map_err(|_| format!("bad srv6_max_end_pop '{value}'"))?,
                );
            }
            "srv6_max_h_encaps" => {
                cfg.ospf_srv6_max_h_encaps = Some(
                    value
                        .parse()
                        .map_err(|_| format!("bad srv6_max_h_encaps '{value}'"))?,
                );
            }
            "srv6_max_end_d" => {
                cfg.ospf_srv6_max_end_d = Some(
                    value
                        .parse()
                        .map_err(|_| format!("bad srv6_max_end_d '{value}'"))?,
                );
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
                _ => {
                    return Err(format!(
                    "unknown [[ospf.area]] key '{key}' (typo protection; OSPF config fails closed)"
                ))
                }
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
                "network_type" => {
                    let v = value.trim().trim_matches('"');
                    if !matches!(v, "p2p" | "point-to-point" | "broadcast") {
                        return Err(format!(
                            "bad network_type '{v}' (use \"p2p\" or \"broadcast\")"
                        ));
                    }
                    iface.network_type = Some(v.to_string());
                }
                "adj_sid" => {
                    iface.adj_sid = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad adj_sid '{value}'"))?,
                    );
                }
                _ => {
                    return Err(format!(
                        "unknown [[ospf.interface]] key '{key}' (typo protection; OSPF config fails closed)"
                    ))
                }
            }
        }
        "ospf.mapping_server" => {
            let Some(ms) = cfg.ospf_mapping_servers.last_mut() else {
                return Err("key outside a [[ospf.mapping_server]] table".into());
            };
            match key {
                "prefix" => ms.prefix = Some(value.to_string()),
                "sid" => {
                    ms.sid = Some(value.parse().map_err(|_| format!("bad sid '{value}'"))?);
                }
                "range_size" => {
                    ms.range_size = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad range_size '{value}'"))?,
                    );
                }
                "no_php" => ms.no_php = Some(parse_bool(value)),
                _ => {
                    return Err(format!(
                        "unknown [[ospf.mapping_server]] key '{key}' (typo protection; OSPF config fails closed)"
                    ))
                }
            }
        }
        "ospf.prefix_sid" => {
            let Some(sid) = cfg.ospf_prefix_sids.last_mut() else {
                return Err("key outside a [[ospf.prefix_sid]] table".into());
            };
            match key {
                "prefix" => sid.prefix = Some(value.to_string()),
                "sid" => {
                    sid.sid = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad sid '{value}'"))?,
                    );
                }
                "node" => sid.node = Some(parse_bool(value)),
                "no_php" => sid.no_php = Some(parse_bool(value)),
                _ => {
                    return Err(format!(
                        "unknown [[ospf.prefix_sid]] key '{key}' (typo protection; OSPF config fails closed)"
                    ))
                }
            }
        }
        "ospf.srv6_locator" => {
            let Some(loc) = cfg.ospf_srv6_locators.last_mut() else {
                return Err("key outside a [[ospf.srv6_locator]] table".into());
            };
            match key {
                "prefix" => loc.prefix = Some(value.to_string()),
                "algorithm" => {
                    loc.algorithm = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad algorithm '{value}'"))?,
                    );
                }
                "metric" => {
                    loc.metric = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad metric '{value}'"))?,
                    );
                }
                "anycast" => loc.anycast = Some(parse_bool(value)),
                "sid" => loc.sid = Some(value.to_string()),
                "behavior" => {
                    loc.behavior = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad behavior '{value}'"))?,
                    );
                }
                "block_len" => {
                    loc.block_len = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad block_len '{value}'"))?,
                    );
                }
                "node_len" => {
                    loc.node_len = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad node_len '{value}'"))?,
                    );
                }
                "function_len" => {
                    loc.function_len = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad function_len '{value}'"))?,
                    );
                }
                "argument_len" => {
                    loc.argument_len = Some(
                        value
                            .parse()
                            .map_err(|_| format!("bad argument_len '{value}'"))?,
                    );
                }
                _ => {
                    return Err(format!(
                        "unknown [[ospf.srv6_locator]] key '{key}' (typo protection; OSPF config fails closed)"
                    ))
                }
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Parse a targeted-peer spec (`ADDR`, `ADDR:PORT`, `[V6]:PORT`)
/// into its address and optional port. The bracketed form exists
/// because a bare IPv6 already uses colons; RFC 7552 makes v6 targeted
/// peers a first-class deployment.
pub(crate) fn parse_targeted_spec(spec: &str) -> Option<(lr_core::addr::IpAddr, Option<u16>)> {
    use std::str::FromStr;
    // Bracketed IPv6: `[2001:db8::1]` or `[2001:db8::1]:646`.
    if let Some(rest) = spec.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let addr = lr_core::addr::IpAddr::from_str(inner).ok()?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if after.is_empty() => None,
            _ => return None,
        };
        return Some((addr, port));
    }
    match spec.rsplit_once(':') {
        // `ADDR:PORT` — only when both halves parse; a bare IPv6 has
        // colons but no parseable port after the last one.
        Some((a, p)) => match (lr_core::addr::IpAddr::from_str(a), p.parse::<u16>()) {
            (Ok(addr), Ok(port)) => Some((addr, Some(port))),
            _ => lr_core::addr::IpAddr::from_str(spec)
                .ok()
                .map(|addr| (addr, None)),
        },
        None => lr_core::addr::IpAddr::from_str(spec)
            .ok()
            .map(|addr| (addr, None)),
    }
}

/// Validate a shell-like glob pattern. BIRD's `patmatch`
/// (lib/patmatch.c) accepts `*` (any sequence), `?` (any single
/// character) and `\` (escape next character). A pattern that ends
/// with a dangling `\` is malformed and rejected here — every other
/// byte is accepted.
///
/// This is a syntax-only check; the actual matching is [`glob_match`].
pub(crate) fn glob_pattern_validate(pattern: &str) -> Result<(), String> {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if i + 1 >= bytes.len() {
                return Err("dangling '\\' at end of pattern".to_string());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// Shell-like glob match (`*`, `?`, `\`) — same semantics as BIRD's
/// `patmatch` (lib/patmatch.c, 1998 Martin Mares). `*` matches any
/// (possibly empty) sequence of characters; `?` matches any single
/// character; `\` escapes the next character to make it literal.
///
/// Used by the `[[babel.interface]]` matcher to apply per-interface
/// parameters to a fleet of similar interfaces (`eth*`, `eth?`,
/// `wlp*`, etc.). The matcher is iterative on the `*` recursion —
/// matching `eth*` against `ethernet-extra-long` does not blow the
/// stack.
pub(crate) fn glob_match(pattern: &str, name: &str) -> bool {
    let p = pattern.as_bytes();
    let s = name.as_bytes();
    let mut pi = 0usize;
    let mut si = 0usize;
    let mut star_p: Option<usize> = None;
    let mut star_s: usize = 0;
    while si < s.len() {
        if pi < p.len() {
            match p[pi] {
                b'?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                b'*' => {
                    star_p = Some(pi);
                    star_s = si;
                    pi += 1;
                    continue;
                }
                b'\\' if pi + 1 < p.len() => {
                    if p[pi + 1] == s[si] {
                        pi += 2;
                        si += 1;
                        continue;
                    }
                }
                c if c == s[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }
        // No match — backtrack to the last `*` if we have one.
        if let Some(sp) = star_p {
            pi = sp + 1;
            star_s += 1;
            si = star_s;
        } else {
            return false;
        }
    }
    // Skip trailing `*` in the pattern; everything else must match
    // exactly (no leftover pattern bytes after the input ends).
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Apply one `key = value` pair to the LDP schema: the `[ldp]`
/// globals plus the `[[ldp.interface]]` / `[[ldp.targeted]]` /
/// `[[ldp.bind]]` tables. Unknown keys are errors (fail closed — see
/// the parser). Returns `Ok(false)` for non-LDP sections so the caller
/// falls through.
fn apply_ldp_key(
    cfg: &mut DaemonConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<bool, String> {
    match section {
        "ldp" => match key {
            "transport" => cfg.ldp_transport = Some(value.to_string()),
            "transport_v6" => cfg.ldp_transport_v6 = Some(value.to_string()),
            "prefer_ipv6" => {
                cfg.ldp_prefer_ipv6 = value
                    .parse()
                    .map_err(|_| format!("bad prefer_ipv6 '{value}' (true|false)"))?;
            }
            "install_kernel" => {
                cfg.ldp_install_kernel = value
                    .parse()
                    .map_err(|_| format!("bad install_kernel '{value}' (true|false)"))?;
            }
            "label_min" => {
                cfg.ldp_label_min = value
                    .parse()
                    .map_err(|_| format!("bad label_min '{value}'"))?;
            }
            "label_max" => {
                cfg.ldp_label_max = value
                    .parse()
                    .map_err(|_| format!("bad label_max '{value}'"))?;
            }
            "transit_allocation" => {
                cfg.ldp_transit_allocation = value
                    .parse()
                    .map_err(|_| format!("bad transit_allocation '{value}' (true|false)"))?;
            }
            "graceful_restart" => {
                cfg.ldp_graceful_restart = value
                    .parse()
                    .map_err(|_| format!("bad graceful_restart '{value}' (true|false)"))?;
            }
            "gr_reconnect_ms" => {
                cfg.ldp_gr_reconnect_ms = value
                    .parse()
                    .map_err(|_| format!("bad gr_reconnect_ms '{value}'"))?;
            }
            "gr_recovery_ms" => {
                cfg.ldp_gr_recovery_ms = value
                    .parse()
                    .map_err(|_| format!("bad gr_recovery_ms '{value}'"))?;
            }
            "port" => {
                cfg.ldp_port = value
                    .parse()
                    .map_err(|_| format!("bad ldp port '{value}'"))?;
            }
            "keepalive_time" => {
                cfg.ldp_keepalive_time = value
                    .parse()
                    .map_err(|_| format!("bad keepalive_time '{value}'"))?;
            }
            "link_hold_time" => {
                cfg.ldp_link_hold = value
                    .parse()
                    .map_err(|_| format!("bad link_hold_time '{value}'"))?;
            }
            "targeted_hold_time" => {
                cfg.ldp_targeted_hold = value
                    .parse()
                    .map_err(|_| format!("bad targeted_hold_time '{value}'"))?;
            }
            "loop_detection" => {
                cfg.ldp_loop_detection = value
                    .parse()
                    .map_err(|_| format!("bad loop_detection '{value}' (true|false)"))?;
            }
            "loop_hop_count_limit" => {
                cfg.ldp_loop_hc_limit = value
                    .parse()
                    .map_err(|_| format!("bad loop_hop_count_limit '{value}'"))?;
            }
            "loop_path_vector_limit" => {
                cfg.ldp_loop_pv_limit = value
                    .parse()
                    .map_err(|_| format!("bad loop_path_vector_limit '{value}'"))?;
            }
            _ => {
                return Err(format!(
                    "unknown [ldp] key '{key}' (typo protection; LDP config fails closed)"
                ))
            }
        },
        "ldp.interface" => {
            let Some(iface) = cfg.ldp_interfaces.last_mut() else {
                return Err("key outside a [[ldp.interface]] table".into());
            };
            match key {
                "name" => iface.name = Some(value.to_string()),
                _ => {
                    return Err(format!(
                        "unknown [[ldp.interface]] key '{key}' (typo protection; LDP config fails closed)"
                    ))
                }
            }
        }
        "ldp.targeted" => {
            let Some(peer) = cfg.ldp_targeted.last_mut() else {
                return Err("key outside a [[ldp.targeted]] table".into());
            };
            match key {
                "address" => peer.address = Some(value.to_string()),
                _ => {
                    return Err(format!(
                        "unknown [[ldp.targeted]] key '{key}' (typo protection; LDP config fails closed)"
                    ))
                }
            }
        }
        "ldp.bind" => {
            let Some(bind) = cfg.ldp_binds.last_mut() else {
                return Err("key outside a [[ldp.bind]] table".into());
            };
            match key {
                "prefix" => bind.prefix = Some(value.to_string()),
                "label" => {
                    bind.label = value.parse().map_err(|_| format!("bad label '{value}'"))?;
                }
                _ => {
                    return Err(format!(
                    "unknown [[ldp.bind]] key '{key}' (typo protection; LDP config fails closed)"
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
        "default_ipv4_unicast" => peer.default_ipv4_unicast = Some(parse_bool(value)),
        "allow_local_as" => {
            peer.allow_local_as = Some(match value.trim() {
                "any" | "allowas-any" => u32::MAX,
                "true" => 1,
                "false" => 0,
                other => other.parse().map_err(|_| {
                    format!("bad allow_local_as '{other}' (expected integer N, 'any', or 'true'/'false')")
                })?,
            });
        }
        "soft_reconfig_inbound" => peer.soft_reconfig_inbound = Some(parse_bool(value)),
        "exchange_plane" => peer.exchange_plane = Some(parse_bool(value)),
        "extended_next_hop" => peer.extended_next_hop = Some(parse_bool(value)),
        "gtsm" => peer.gtsm_hops = parse_gtsm(value),
        "max_prefixes" => {
            peer.max_prefixes = value.parse::<u32>().ok().filter(|&n| n > 0);
        }
        "max_prefix_action" => peer.max_prefix_action = Some(value.to_string()),
        "max_prefix_threshold" => {
            peer.max_prefix_threshold = Some(value.parse().map_err(|_| "bad max_prefix_threshold")?)
        }
        "bfd" => peer.bfd = Some(parse_bool(value)),
        "bfd_multihop" => peer.bfd_multihop = Some(parse_bool(value)),
        "import" => peer.import = Some(value.to_string()),
        "export" => peer.export = Some(value.to_string()),
        "import_filter" => peer.import_filter = Some(value.to_string()),
        "export_filter" => peer.export_filter = Some(value.to_string()),
        _ => return Ok(false), // unknown key — caller warns
    }
    Ok(true)
}

pub(crate) fn parse_args() -> Result<DaemonConfig, ExitCode> {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = DaemonConfig::with_defaults();
    let mut config_path: Option<String> = None;
    let mut config_dialect: Option<String> = None;
    // rc.3 multi-protocol: `--protocol` is repeatable and every value
    // may carry a comma-separated list (`--protocol bgp --protocol
    // ospf` ≡ `--protocol bgp,ospf`). The flags accumulate here and
    // merge into `cfg.protocol` below, before the config file load —
    // so a TOML `protocol`/`protocols` key still overrides the CLI,
    // exactly like every other overlapping key.
    let mut protocol_flags: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--config" if i + 1 < args.len() => {
                config_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--config-dialect" if i + 1 < args.len() => {
                match crate::compat::Dialect::from_flag(&args[i + 1]) {
                    Ok(_) => config_dialect = Some(args[i + 1].clone()),
                    Err(e) => {
                        eprintln!("error: {e}");
                        return Err(ExitCode::from(2));
                    }
                }
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
            "--labeled-network" if i + 1 < args.len() => {
                cfg.labeled_networks.push(args[i + 1].clone());
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
            "--bmp-target" if i + 1 < args.len() => {
                cfg.bmp_target = Some(args[i + 1].clone());
                i += 2;
            }
            "--ebgp-policy" if i + 1 < args.len() => {
                let v = args[i + 1].as_str();
                if v != "rfc8212" && v != "accept-all" {
                    // Fail closed: an unknown mode must not silently
                    // fall back to the permissive behaviour.
                    eprintln!("bad --ebgp-policy '{}' (expected rfc8212 or accept-all)", v);
                    return Err(ExitCode::from(2));
                }
                cfg.ebgp_policy = v.to_string();
                i += 2;
            }
            "--enforce-first-as" => {
                cfg.enforce_first_as = true;
                i += 1;
            }
            "--no-enforce-first-as" => {
                cfg.enforce_first_as = false;
                i += 1;
            }
            "--bestpath-compare-routerid" => {
                cfg.bestpath_compare_routerid = true;
                i += 1;
            }
            "--no-bestpath-compare-routerid" => {
                cfg.bestpath_compare_routerid = false;
                i += 1;
            }
            "--default-ipv4-unicast" => {
                cfg.default_ipv4_unicast = true;
                i += 1;
            }
            "--no-default-ipv4-unicast" => {
                cfg.default_ipv4_unicast = false;
                i += 1;
            }
            "--allow-local-as" => {
                // FRR `neighbor X allowas-in` defaults to N=1 when
                // no argument is given.
                let n = match args.get(i + 1) {
                    Some(v) if !v.starts_with("--") => v.parse().unwrap_or(1),
                    _ => 1,
                };
                cfg.allow_local_as = n;
                i += if args
                    .get(i + 1)
                    .map(|v| !v.starts_with("--"))
                    .unwrap_or(false)
                {
                    2
                } else {
                    1
                };
            }
            "--allowas-any" => {
                cfg.allow_local_as = u32::MAX;
                i += 1;
            }
            "--soft-reconfig-inbound" => {
                cfg.soft_reconfig_inbound = true;
                i += 1;
            }
            "--no-soft-reconfig-inbound" => {
                cfg.soft_reconfig_inbound = false;
                i += 1;
            }
            "--exchange-plane" => {
                cfg.exchange_plane = true;
                i += 1;
            }
            "--no-exchange-plane" => {
                cfg.exchange_plane = false;
                i += 1;
            }
            "--exchange-plane-key" if i + 1 < args.len() => {
                cfg.exchange_plane_keys.push(args[i + 1].clone());
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
            "--bfd" => {
                cfg.bfd_enabled = true;
                i += 1;
            }
            "--bfd-multihop" => {
                cfg.bfd_multihop = true;
                i += 1;
            }
            "--bfd-min-tx-ms" if i + 1 < args.len() => {
                cfg.bfd_min_tx_ms = args[i + 1].parse().unwrap_or(100);
                i += 2;
            }
            "--bfd-min-rx-ms" if i + 1 < args.len() => {
                cfg.bfd_min_rx_ms = args[i + 1].parse().unwrap_or(100);
                i += 2;
            }
            "--bfd-multiplier" if i + 1 < args.len() => {
                cfg.bfd_multiplier = args[i + 1].parse().unwrap_or(3);
                i += 2;
            }
            "--protocol" if i + 1 < args.len() => {
                protocol_flags.push(args[i + 1].clone());
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
            "--babel-key" if i + 1 < args.len() => {
                // Repeatable: every flag adds one key. The default algorithm
                // is HMAC-SHA256 (RFC 8967 §4.1 mandatory); TOML
                // `[[babel.key]]` tables allow per-key algorithm selection.
                cfg.babel_keys.push(BabelKeySpec {
                    secret: Some(args[i + 1].clone()),
                    algorithm: None,
                });
                i += 2;
            }
            "--babel-accept-unauthenticated" => {
                cfg.babel_accept_unauthenticated = true;
                i += 1;
            }
            "--babel-no-pc-split" => {
                cfg.babel_split_unicast_multicast = false;
                i += 1;
            }
            "--babel-pc-window" if i + 1 < args.len() => {
                cfg.babel_pc_window = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            // Repeatable: each --ospf-interface adds one interface; its
            "--ospf-version" if i + 1 < args.len() => {
                match args[i + 1].as_str() {
                    "2" | "v2" => cfg.ospf_version = "v2".to_string(),
                    "3" | "v3" => cfg.ospf_version = "v3".to_string(),
                    other => {
                        eprintln!("invalid OSPF version '{other}' (use \"v2\" or \"v3\")");
                        return Err(ExitCode::from(2));
                    }
                }
                i += 2;
            }
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
            // RFC 3623 graceful restart (restarting + helper sides).
            "--ospf-graceful-restart" => {
                cfg.ospf_graceful_restart = true;
                i += 1;
            }
            "--ospf-no-graceful-restart" => {
                cfg.ospf_graceful_restart = false;
                i += 1;
            }
            "--ospf-grace-period" if i + 1 < args.len() => {
                cfg.ospf_grace_period = args[i + 1].parse().unwrap_or(120);
                i += 2;
            }
            "--ospf-no-gr-helper" => {
                cfg.ospf_gr_helper = false;
                i += 1;
            }
            "--ospf-helper-grace-cap" if i + 1 < args.len() => {
                cfg.ospf_helper_grace_cap = args[i + 1].parse().unwrap_or(120);
                i += 2;
            }
            "--ospf-gr-state-file" if i + 1 < args.len() => {
                cfg.ospf_gr_state_file = Some(args[i + 1].clone());
                i += 2;
            }
            // RFC 9513 (OSPFv3 SRv6): a repeatable --ospf-srv6-locator
            // flag configures one locally originated locator; the
            // remaining attributes (algorithm/metric/…) come from
            // [[ospf.srv6_locator]] tables.
            "--ospf-srv6-locator" if i + 1 < args.len() => {
                cfg.ospf_srv6_locators.push(OspfSrv6LocatorSpec {
                    prefix: Some(args[i + 1].clone()),
                    ..Default::default()
                });
                i += 2;
            }
            "--ospf-srv6-receive" => {
                cfg.ospf_srv6_receive = true;
                i += 1;
            }
            "--ospf-srv6-o-flag" => {
                cfg.ospf_srv6_o_flag = true;
                i += 1;
            }
            "--ldp-transport" if i + 1 < args.len() => {
                cfg.ldp_transport = Some(args[i + 1].clone());
                i += 2;
            }
            "--ldp-transport-v6" if i + 1 < args.len() => {
                cfg.ldp_transport_v6 = Some(args[i + 1].clone());
                i += 2;
            }
            "--ldp-prefer-ipv4" => {
                cfg.ldp_prefer_ipv6 = false;
                i += 1;
            }
            "--ldp-loop-detection" => {
                cfg.ldp_loop_detection = true;
                i += 1;
            }
            "--ldp-loop-hc-limit" if i + 1 < args.len() => {
                cfg.ldp_loop_hc_limit = args[i + 1].parse().unwrap_or(32);
                i += 2;
            }
            "--ldp-loop-pv-limit" if i + 1 < args.len() => {
                cfg.ldp_loop_pv_limit = args[i + 1].parse().unwrap_or(32);
                i += 2;
            }
            "--ldp-install-kernel" => {
                cfg.ldp_install_kernel = true;
                i += 1;
            }
            "--ldp-label-min" if i + 1 < args.len() => {
                cfg.ldp_label_min = args[i + 1].parse().unwrap_or(16);
                i += 2;
            }
            "--ldp-label-max" if i + 1 < args.len() => {
                cfg.ldp_label_max = args[i + 1].parse().unwrap_or(1048575);
                i += 2;
            }
            "--ldp-no-transit" => {
                cfg.ldp_transit_allocation = false;
                i += 1;
            }
            "--ldp-graceful-restart" => {
                cfg.ldp_graceful_restart = true;
                i += 1;
            }
            "--ldp-port" if i + 1 < args.len() => {
                cfg.ldp_port = args[i + 1].parse().unwrap_or(646);
                i += 2;
            }
            "--ldp-keepalive" if i + 1 < args.len() => {
                cfg.ldp_keepalive_time = args[i + 1].parse().unwrap_or(15);
                i += 2;
            }
            "--ldp-link-hold" if i + 1 < args.len() => {
                cfg.ldp_link_hold = args[i + 1].parse().unwrap_or(15);
                i += 2;
            }
            "--ldp-targeted-hold" if i + 1 < args.len() => {
                cfg.ldp_targeted_hold = args[i + 1].parse().unwrap_or(45);
                i += 2;
            }
            "--ldp-interface" if i + 1 < args.len() => {
                // Repeatable: every flag adds one basic-discovery
                // interface.
                cfg.ldp_interfaces.push(LdpIfSpec {
                    name: Some(args[i + 1].clone()),
                });
                i += 2;
            }
            "--ldp-targeted" if i + 1 < args.len() => {
                // Repeatable: every flag adds one extended-discovery
                // peer.
                cfg.ldp_targeted.push(LdpTargetedSpec {
                    address: Some(args[i + 1].clone()),
                });
                i += 2;
            }
            "--ldp-bind" if i + 1 < args.len() => {
                // Repeatable `prefix=label` (label optional → auto-pick
                // the next free label from 16).
                let (prefix, label) = match args[i + 1].split_once('=') {
                    Some((p, l)) => match l.parse::<u32>() {
                        Ok(n) => (p.to_string(), n),
                        Err(_) => {
                            eprintln!("invalid --ldp-bind label '{}'", l);
                            return Err(ExitCode::from(2));
                        }
                    },
                    None => (args[i + 1].clone(), 0),
                };
                cfg.ldp_binds.push(LdpBindSpec {
                    prefix: Some(prefix),
                    label,
                });
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
    if !protocol_flags.is_empty() {
        cfg.protocol = protocol_flags.join(",");
    }
    if let Some(path) = config_path {
        let text = std::fs::read_to_string(&path).map_err(|e| {
            eprintln!("cannot read config {}: {}", path, e);
            ExitCode::from(1)
        })?;
        // Dialect resolution: `--config-dialect` forces an
        // interpretation, otherwise the content is recognised (lr
        // TOML, BIRD 2 or FRR). Bird/frr files go through the compat
        // surface (parse → render → the same TOML loader below), so
        // `lr-daemon --config bird.conf` runs the source config
        // directly in the compatible form.
        let forced = match config_dialect.as_deref() {
            Some(f) => match crate::compat::Dialect::from_flag(f) {
                Ok(d) => Some(d),
                Err(e) => {
                    eprintln!("error: {e}");
                    return Err(ExitCode::from(2));
                }
            },
            None => None,
        };
        crate::compat::load_config_text(&text, forced, &mut cfg).map_err(|e| {
            eprintln!("config parse error: {}", e);
            ExitCode::from(1)
        })?;
        if cfg.config_dialect.is_none() {
            cfg.config_dialect = forced
                .map(|d| d.name().to_string())
                .or_else(|| crate::compat::detect_dialect(&text).map(|d| d.name().to_string()));
        }
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
    fn bfd_globals_and_peer_overrides_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             bfd = true\nbfd_min_tx_ms = 150\nbfd_min_rx_ms = 200\n\
             bfd_multiplier = 5\n\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\nbfd = false\n\n\
             [[peer]]\naddress = \"192.0.2.3\"\nbfd = true\nbfd_multihop = true\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert!(cfg.bfd_enabled);
        assert_eq!(cfg.bfd_min_tx_ms, 150);
        assert_eq!(cfg.bfd_min_rx_ms, 200);
        assert_eq!(cfg.bfd_multiplier, 5);
        assert!(!cfg.effective_bfd(&cfg.peers[0])); // opt-out
        assert!(!cfg.effective_bfd_multihop(&cfg.peers[0]));
        // Opt-in with the multihop override (RFC 5883).
        assert!(cfg.effective_bfd(&cfg.peers[1]));
        assert!(cfg.effective_bfd_multihop(&cfg.peers[1]));
    }

    #[test]
    fn bfd_defaults_inherit_from_globals() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nbfd = true\nbfd_multihop = true\n\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        // Peer inherits both globals; timing stays at the defaults.
        assert!(cfg.effective_bfd(&cfg.peers[0]));
        assert!(cfg.effective_bfd_multihop(&cfg.peers[0]));
        assert_eq!(cfg.bfd_min_tx_ms, 100);
        assert_eq!(cfg.bfd_min_rx_ms, 100);
        assert_eq!(cfg.bfd_multiplier, 3);
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
    fn ospf_graceful_restart_keys_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset(
            "[ospf]\ngraceful_restart = true\ngrace_period = 30\n\
             graceful_restart_helper = false\nhelper_grace_cap = 45\n\
             gr_state_file = \"/run/lr/ospf.gr\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert!(cfg.ospf_graceful_restart);
        assert_eq!(cfg.ospf_grace_period, 30);
        assert!(!cfg.ospf_gr_helper);
        assert_eq!(cfg.ospf_helper_grace_cap, 45);
        assert_eq!(cfg.ospf_gr_state_file.as_deref(), Some("/run/lr/ospf.gr"));
    }

    #[test]
    fn ospf_grace_period_out_of_range_is_rejected() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        let err = parse_toml_subset("[ospf]\ngrace_period = 1801\n", &mut cfg).unwrap_err();
        assert!(err.contains("RFC 3623"), "fail-closed error: {err}");
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        assert!(parse_toml_subset("[ospf]\nhelper_grace_cap = 0\n", &mut cfg).is_err());
    }

    #[test]
    fn ospf_srv6_locator_tables_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset(
            "[ospf]\nversion = \"v3\"\nsrv6_receive = true\nsrv6_o_flag = true\n\
             srv6_max_sl = 8\nsrv6_max_end_pop = 4\nsrv6_max_h_encaps = 2\n\
             srv6_max_end_d = 6\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\nalgorithm = 0\n\
             metric = 10\nanycast = true\nsid = \"2001:db8:a:1::1\"\nbehavior = 1\n\
             block_len = 32\nnode_len = 16\nfunction_len = 16\nargument_len = 0\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:2::/64\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert!(cfg.ospf_srv6_receive);
        assert!(cfg.ospf_srv6_o_flag);
        assert_eq!(cfg.ospf_srv6_max_sl, Some(8));
        assert_eq!(cfg.ospf_srv6_max_end_pop, Some(4));
        assert_eq!(cfg.ospf_srv6_max_h_encaps, Some(2));
        assert_eq!(cfg.ospf_srv6_max_end_d, Some(6));
        assert_eq!(cfg.ospf_srv6_locators.len(), 2);
        let first = &cfg.ospf_srv6_locators[0];
        assert_eq!(first.prefix.as_deref(), Some("2001:db8:a:1::/48"));
        assert_eq!(first.algorithm, Some(0));
        assert_eq!(first.metric, Some(10));
        assert_eq!(first.anycast, Some(true));
        assert_eq!(first.sid.as_deref(), Some("2001:db8:a:1::1"));
        assert_eq!(first.behavior, Some(1));
        assert_eq!(first.block_len, Some(32));
        assert_eq!(first.node_len, Some(16));
        assert_eq!(first.function_len, Some(16));
        assert_eq!(first.argument_len, Some(0));
        // Defaults: the second locator keeps the implicit values.
        let second = &cfg.ospf_srv6_locators[1];
        assert_eq!(second.algorithm, None);
        assert_eq!(second.anycast, None);
        assert_eq!(second.behavior, None);
        assert_eq!(second.block_len, None);
    }

    #[test]
    fn ospf_srv6_configuration_is_rejected_under_v2() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset(
            "[ospf]\nversion = \"v2\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("OSPFv3"), "fail-closed error: {err}");
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset("[ospf]\nsrv6_receive = true\n", &mut cfg).unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("OSPFv3"), "fail-closed error: {err}");
    }

    #[test]
    fn ospf_srv6_locator_validation_is_fail_closed() {
        let case = |toml: &str| {
            let mut cfg = DaemonConfig::with_defaults();
            cfg.protocol = "ospf".to_string();
            parse_toml_subset(toml, &mut cfg).unwrap();
            cfg.finalize().unwrap_err()
        };
        // Missing prefix.
        let err = case("[ospf]\nversion = \"v3\"\n\n[[ospf.srv6_locator]]\nanycast = true\n");
        assert!(err.contains("prefix"), "fail-closed error: {err}");
        // IPv4 prefix.
        let err =
            case("[ospf]\nversion = \"v3\"\n\n[[ospf.srv6_locator]]\nprefix = \"10.0.0.0/8\"\n");
        assert!(err.contains("IPv6"), "fail-closed error: {err}");
        // A behavior outside the RFC 9513 §8 End-SID set (End.X = 5 is
        // an E-Router-Link behavior, not an End-SID one).
        let err = case(
            "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\nbehavior = 5\n",
        );
        assert!(err.contains("behavior"), "fail-closed error: {err}");
        // Partial §10 SID Structure.
        let err = case(
            "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\nblock_len = 32\n",
        );
        assert!(err.contains("SID Structure"), "fail-closed error: {err}");
        // §10 lengths above 128 bits.
        let err = case(
            "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\
             block_len = 32\nnode_len = 32\nfunction_len = 32\nargument_len = 40\n",
        );
        assert!(err.contains("128"), "fail-closed error: {err}");
        // Duplicate locator prefix.
        let err = case(
            "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n",
        );
        assert!(err.contains("twice"), "fail-closed error: {err}");
    }

    #[test]
    fn ospf_gr_defaults_match_bird_frr() {
        let cfg = DaemonConfig::with_defaults();
        // BIRD OSPF_DEFAULT_GR_TIME / FRR supported_grace_time: 120 s.
        assert_eq!(cfg.ospf_grace_period, 120);
        assert_eq!(cfg.ospf_helper_grace_cap, 120);
        // Helper mode defaults on (BIRD AWARE / FRR helper default).
        assert!(cfg.ospf_gr_helper);
        assert!(!cfg.ospf_graceful_restart);
        assert!(cfg.ospf_gr_state_file.is_none());
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

    /// RFC 8665 config: SRGB + prefix SIDs parse and finalize; the
    /// FRR-default SRGB (16000/8000) fills in when SIDs are given
    /// without an explicit block; mismatched half-SRGBs and
    /// out-of-range SIDs fail closed.
    #[test]
    fn ospf_segment_routing_config_validates() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[ospf]\nsrgb_base = 20000\nsrgb_range = 4000\n\n\
             [[ospf.prefix_sid]]\nprefix = \"10.0.0.0/24\"\nsid = 100\nnode = true\n\n\
             [[ospf.prefix_sid]]\nprefix = \"10.0.1.0/24\"\nsid = 200\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.ospf_srgb_base, Some(20_000));
        assert_eq!(cfg.ospf_srgb_range, Some(4_000));
        assert_eq!(cfg.ospf_prefix_sids.len(), 2);
        assert_eq!(cfg.ospf_prefix_sids[0].node, Some(true));

        // SIDs without an SRGB get FRR's default block.
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset(
            "[[ospf.prefix_sid]]\nprefix = \"10.0.0.0/24\"\nsid = 5\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.ospf_srgb_base, Some(16_000));
        assert_eq!(cfg.ospf_srgb_range, Some(8_000));

        // Half an SRGB is a config bug.
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset("[ospf]\nsrgb_base = 16000\n", &mut cfg).unwrap();
        let err = cfg.finalize().expect_err("base without range must fail");
        assert!(err.contains("together"), "{err}");

        // SID outside the SRGB fails closed.
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset(
            "[ospf]\nsrgb_base = 16000\nsrgb_range = 100\n\n\
             [[ospf.prefix_sid]]\nprefix = \"10.0.0.0/24\"\nsid = 500\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().expect_err("SID outside SRGB must fail");
        assert!(err.contains("outside the SRGB"), "{err}");
    }

    #[test]
    fn ospf_sr_receive_parses_and_defaults_off() {
        // Default off (fail closed).
        let cfg = DaemonConfig::with_defaults();
        assert!(!cfg.ospf_sr_receive);

        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset("[ospf]\nsr_receive = true\n", &mut cfg).unwrap();
        assert!(cfg.ospf_sr_receive);

        // Unknown keys nearby still fail closed (typo protection).
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        let err = parse_toml_subset("[ospf]\nsr_recieve = true\n", &mut cfg).unwrap_err();
        assert!(err.contains("unknown [ospf] key"), "{err}");
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
                .any(|w| w.contains("OSPF tables present but the protocol set")),
            "{:?}",
            cfg.warnings
        );
    }

    // ---- rc.3 multi-protocol protocol set ----

    #[test]
    fn protocol_set_splits_and_dedupes_in_order() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "bgp,ospf,bgp, babel".to_string();
        assert_eq!(
            cfg.protocol_set(),
            ["bgp".to_string(), "ospf".to_string(), "babel".to_string()].as_slice()
        );
        assert!(cfg.runs_protocol("ospf"));
        assert!(!cfg.runs_protocol("ldp"));
    }

    #[test]
    fn protocol_set_empty_falls_back_to_bgp() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = " , ,".to_string();
        assert_eq!(cfg.protocol_set(), ["bgp".to_string()].as_slice());
        // The historical default survives untouched.
        let plain = DaemonConfig::with_defaults();
        assert_eq!(plain.protocol_set(), ["bgp".to_string()].as_slice());
    }

    #[test]
    fn toml_protocol_and_protocols_keys_parse() {
        // The string form mirrors the CLI: one comma-separated value.
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "bgp".to_string();
        parse_toml_subset("protocol = \"bgp,ospf\"\n", &mut cfg).unwrap();
        assert_eq!(cfg.protocol, "bgp,ospf");
        assert_eq!(cfg.protocol_set().len(), 2);

        // The array form reads better in operator configs.
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset("protocols = [\"babel\", \"ospf\"]\n", &mut cfg).unwrap();
        assert_eq!(cfg.protocol, "babel,ospf");
        assert_eq!(
            cfg.protocol_set(),
            ["babel".to_string(), "ospf".to_string()].as_slice()
        );
    }

    #[test]
    fn toml_empty_protocol_keys_fail_closed() {
        let mut cfg = DaemonConfig::with_defaults();
        let err = parse_toml_subset("protocol = \"\"\n", &mut cfg)
            .expect_err("empty protocol value must fail");
        assert!(err.contains("empty protocol value"), "{err}");

        let mut cfg = DaemonConfig::with_defaults();
        let err = parse_toml_subset("protocols = []\n", &mut cfg)
            .expect_err("empty protocols list must fail");
        assert!(err.contains("needs at least one name"), "{err}");
    }

    #[test]
    fn ospf_tables_with_multi_protocol_set_do_not_warn() {
        // An OSPF table is honoured (not warned about) as soon as the
        // protocol set includes ospf — including combinations.
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "bgp,ospf".to_string();
        parse_toml_subset("[[ospf.area]]\nid = 0\n", &mut cfg).unwrap();
        cfg.finalize().unwrap();
        assert!(
            !cfg.warnings
                .iter()
                .any(|w| w.contains("OSPF tables present")),
            "{:?}",
            cfg.warnings
        );
    }

    // ---- LDP configuration ----

    #[test]
    fn ldp_tables_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ldp".to_string();
        parse_toml_subset(
            "[ldp]\ntransport = \"10.99.1.1\"\nport = 646\nkeepalive_time = 15\n\
             link_hold_time = 15\ntargeted_hold_time = 45\ninstall_kernel = true\n\
             label_min = 100\nlabel_max = 999\n\n\
             [[ldp.interface]]\nname = \"veth0\"\n\n\
             [[ldp.interface]]\nname = \"veth1\"\n\n\
             [[ldp.targeted]]\naddress = \"10.99.1.2\"\n\n\
             [[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 24000\n\n\
             [[ldp.bind]]\nprefix = \"198.51.100.0/24\"\n\n\
             [[ldp.bind]]\nprefix = \"192.0.2.0/24\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.ldp_transport.as_deref(), Some("10.99.1.1"));
        assert!(cfg.ldp_install_kernel);
        assert_eq!(cfg.ldp_label_min, 100);
        assert_eq!(cfg.ldp_label_max, 999);
        assert_eq!(cfg.ldp_port, 646);
        assert_eq!(cfg.ldp_keepalive_time, 15);
        assert_eq!(cfg.ldp_link_hold, 15);
        assert_eq!(cfg.ldp_targeted_hold, 45);
        assert_eq!(cfg.ldp_interfaces.len(), 2);
        assert_eq!(cfg.ldp_interfaces[0].name.as_deref(), Some("veth0"));
        assert_eq!(cfg.ldp_targeted[0].address.as_deref(), Some("10.99.1.2"));
        assert_eq!(cfg.ldp_binds.len(), 3);
        assert_eq!(cfg.ldp_binds[0].prefix.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(cfg.ldp_binds[0].label, 24000);
        // Auto allocation: label 0 picks the first free value inside
        // the configured range, skipping the explicit 24000.
        assert_eq!(cfg.ldp_binds[1].label, 100);
        assert_eq!(cfg.ldp_binds[2].label, 101);
        assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    }

    #[test]
    fn ldp_label_range_validation() {
        // Out-of-bounds bounds.
        for (min, max) in [(15u32, 100u32), (100, 1048576), (500, 100), (0, 1048575)] {
            let mut cfg = DaemonConfig::with_defaults();
            cfg.protocol = "ldp".to_string();
            parse_toml_subset(
                &format!("[ldp]\nlabel_min = {min}\nlabel_max = {max}\n"),
                &mut cfg,
            )
            .unwrap();
            let err = cfg.finalize().expect_err("bad label range must fail");
            assert!(err.contains("label range"), "{min}..{max}: {err}");
        }
    }

    #[test]
    fn ldp_label_range_exhaustion_fails() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ldp".to_string();
        parse_toml_subset(
            "[ldp]\nlabel_min = 16\nlabel_max = 17\n\n\
             [[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 16\n\n\
             [[ldp.bind]]\nprefix = \"198.51.100.0/24\"\nlabel = 17\n\n\
             [[ldp.bind]]\nprefix = \"192.0.2.0/24\"\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().expect_err("exhausted range must fail");
        assert!(err.contains("exhausted"), "{err}");
    }

    #[test]
    fn ldp_targeted_link_local_rejected() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ldp".to_string();
        parse_toml_subset("[[ldp.targeted]]\naddress = \"fe80::1\"\n", &mut cfg).unwrap();
        let err = cfg.finalize().expect_err("link-local targeted must fail");
        assert!(err.contains("link-local"), "{err}");
        // The bracketed v6 form parses and passes for global addresses.
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ldp".to_string();
        parse_toml_subset(
            "[[ldp.targeted]]\naddress = \"[2001:db8::1]:646\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert_eq!(
            cfg.ldp_targeted[0].address.as_deref(),
            Some("[2001:db8::1]:646")
        );
    }

    #[test]
    fn ldp_bracketed_v6_targeted_parses_port() {
        assert_eq!(
            parse_targeted_spec("[2001:db8::1]:646").map(|(a, p)| (a.to_string(), p)),
            Some(("2001:db8::1".to_string(), Some(646)))
        );
        assert_eq!(
            parse_targeted_spec("2001:db8::1").map(|(a, p)| (a.to_string(), p)),
            Some(("2001:db8::1".to_string(), None))
        );
        assert_eq!(
            parse_targeted_spec("10.0.0.1:646").map(|(a, p)| (a.to_string(), p)),
            Some(("10.0.0.1".to_string(), Some(646)))
        );
        assert_eq!(parse_targeted_spec("not-an-address"), None);
    }

    #[test]
    fn ldp_unknown_keys_are_errors() {
        for (section, key) in [
            ("[ldp]", "trasport"),
            ("[[ldp.interface]]", "nam"),
            ("[[ldp.targeted]]", "host"),
            ("[[ldp.bind]]", "lbl"),
        ] {
            let mut cfg = DaemonConfig::with_defaults();
            let err = parse_toml_subset(&format!("{section}\n{key} = 1\n"), &mut cfg);
            let err = err.expect_err("unknown LDP key must fail");
            assert!(err.contains("typo protection"), "{section}.{key}: {err}");
        }
    }

    #[test]
    fn ldp_transit_allocation_defaults_on_and_parses() {
        // Default: transit allocation is on (a real LSR forwards).
        let mut cfg = DaemonConfig::with_defaults();
        assert!(cfg.ldp_transit_allocation);
        parse_toml_subset("[ldp]\ntransit_allocation = false\n", &mut cfg).unwrap();
        assert!(!cfg.ldp_transit_allocation);
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset("[ldp]\ntransit_allocation = true\n", &mut cfg).unwrap();
        assert!(cfg.ldp_transit_allocation);
        // Bad value fails closed.
        let mut cfg = DaemonConfig::with_defaults();
        let err = parse_toml_subset("[ldp]\ntransit_allocation = \"yes\"\n", &mut cfg).unwrap_err();
        assert!(err.contains("transit_allocation"), "{err}");
    }

    #[test]
    fn ldp_reserved_and_oversized_labels_fail() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ldp".to_string();
        parse_toml_subset(
            "[[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 3\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().expect_err("reserved label must fail");
        assert!(err.contains("reserved"), "{err}");

        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ldp".to_string();
        parse_toml_subset(
            "[[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 2000000\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().expect_err("oversized label must fail");
        assert!(err.contains("out of range"), "{err}");
    }

    #[test]
    fn ldp_duplicate_and_invalid_bind_prefixes_fail() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ldp".to_string();
        parse_toml_subset(
            "[[ldp.bind]]\nprefix = \"203.0.113.0/24\"\n\n\
             [[ldp.bind]]\nprefix = \"203.0.113.0/24\"\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().expect_err("duplicate bind must fail");
        assert!(err.contains("twice"), "{err}");

        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ldp".to_string();
        parse_toml_subset("[[ldp.bind]]\nprefix = \"203.0.113.0/33\"\n", &mut cfg).unwrap();
        let err = cfg.finalize().expect_err("invalid prefix must fail");
        assert!(err.contains("invalid prefix"), "{err}");
    }

    #[test]
    fn ldp_zero_keepalive_fails() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ldp".to_string();
        parse_toml_subset("[ldp]\nkeepalive_time = 0\n", &mut cfg).unwrap();
        let err = cfg.finalize().expect_err("zero keepalive must fail");
        assert!(err.contains("non-zero"), "{err}");
    }

    #[test]
    fn ldp_tables_in_bgp_mode_warn() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset("[[ldp.interface]]\nname = \"eth0\"\n", &mut cfg).unwrap();
        cfg.finalize().unwrap();
        assert!(
            cfg.warnings
                .iter()
                .any(|w| w.contains("LDP tables present but the protocol set")),
            "{:?}",
            cfg.warnings
        );
    }

    #[test]
    fn ebgp_policy_default_is_rfc8212_and_values_validate() {
        // Default: RFC 8212 deny-in/deny-out for policy-less external
        // peers (the roadmap mandate; fail-closed posture).
        assert_eq!(DaemonConfig::with_defaults().ebgp_policy, "rfc8212");

        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             ebgp_policy = \"accept-all\"\n",
            &mut cfg,
        )
        .unwrap();
        assert_eq!(cfg.ebgp_policy, "accept-all");

        // Unknown mode is a hard error — never silently permissive.
        let mut bad = DaemonConfig::with_defaults();
        let err = parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             ebgp_policy = \"permissive\"\n",
            &mut bad,
        )
        .unwrap_err();
        assert!(err.contains("bad ebgp_policy 'permissive'"), "{err}");
    }

    #[test]
    fn enforce_first_as_default_off_and_parses() {
        // FRR `bgp enforce-first-as` is off by default; the config
        // flips it on. W2.2.
        assert!(!DaemonConfig::with_defaults().enforce_first_as);
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             enforce_first_as = true\n",
            &mut cfg,
        )
        .unwrap();
        assert!(cfg.enforce_first_as);
    }

    #[test]
    fn bestpath_compare_routerid_default_on_and_parses() {
        // lr ships deterministic_router_id = true (RFC 5004); the
        // config exposes FRR `bgp bestpath compare-routerid` and lets
        // the operator flip it off. W2.2.
        assert!(DaemonConfig::with_defaults().bestpath_compare_routerid);
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             bestpath_compare_routerid = false\n",
            &mut cfg,
        )
        .unwrap();
        assert!(!cfg.bestpath_compare_routerid);
    }

    #[test]
    fn default_ipv4_unicast_default_on_and_parses() {
        // FRR `bgp default ipv4-unicast` defaults to on. W2.1.
        assert!(DaemonConfig::with_defaults().default_ipv4_unicast);
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             default_ipv4_unicast = false\n",
            &mut cfg,
        )
        .unwrap();
        assert!(!cfg.default_ipv4_unicast);
    }

    #[test]
    fn babel_toml_globals_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[babel]\ngroup = \"224.0.0.111\"\nport = 7696\n\
             accept_unauthenticated = true\nsplit_unicast_multicast = false\n\
             pc_window = 128\n",
            &mut cfg,
        )
        .unwrap();
        assert_eq!(cfg.babel_group.as_deref(), Some("224.0.0.111"));
        assert_eq!(cfg.babel_port, 7696);
        assert!(cfg.babel_accept_unauthenticated);
        assert!(!cfg.babel_split_unicast_multicast);
        assert_eq!(cfg.babel_pc_window, 128);
    }

    #[test]
    fn babel_toml_unknown_key_fails_closed() {
        let mut cfg = DaemonConfig::with_defaults();
        let err = parse_toml_subset("[babel]\ntypo = 1\n", &mut cfg);
        assert!(err.is_err(), "{err:?}");
        assert!(err.unwrap_err().contains("unknown [babel] key"));
    }

    #[test]
    fn babel_key_tables_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[babel.key]]\nsecret = \"one\"\n\
             [[babel.key]]\nsecret = \"two\"\nalgorithm = \"blake2s\"\n",
            &mut cfg,
        )
        .unwrap();
        assert_eq!(cfg.babel_keys.len(), 2);
        assert_eq!(cfg.babel_keys[0].secret.as_deref(), Some("one"));
        assert_eq!(cfg.babel_keys[0].algorithm, None);
        assert_eq!(cfg.babel_keys[1].algorithm.as_deref(), Some("blake2s"));
    }

    #[test]
    fn babel_key_unknown_algorithm_fails_closed() {
        let mut cfg = DaemonConfig::with_defaults();
        let err = parse_toml_subset(
            "[[babel.key]]\nsecret = \"x\"\nalgorithm = \"md5\"\n",
            &mut cfg,
        );
        assert!(err.is_err(), "{err:?}");
        assert!(err.unwrap_err().contains("unknown babel key algorithm"));
    }

    #[test]
    fn babel_key_without_secret_is_rejected_at_build() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset("[[babel.key]]\nalgorithm = \"blake2s\"\n", &mut cfg).unwrap();
        // The daemon treats a key without a secret as a fatal
        // configuration error (fail closed): the auth interface is None
        // and the caller must refuse to run.
        let built = {
            let mut ok = true;
            for k in &cfg.babel_keys {
                if k.secret.is_none() {
                    ok = false;
                }
            }
            ok
        };
        assert!(!built);
    }

    #[test]
    fn exchange_plane_globals_and_peers_parse() {
        // Defaults off, no keys.
        let fresh = DaemonConfig::with_defaults();
        assert!(!fresh.exchange_plane);
        assert!(fresh.exchange_plane_keys.is_empty());

        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nlocal_as = 65000\npeer_as = 65001\nrouter_id = \"10.0.0.1\"\n\
             exchange_plane = true\nexchange_plane_keys = [\"1:alpha\", \"2:beta\"]\n\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\nexchange_plane = false\n\n\
             [[peer]]\naddress = \"192.0.2.3\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert!(cfg.exchange_plane);
        assert_eq!(
            cfg.exchange_plane_keys,
            vec!["1:alpha".to_string(), "2:beta".to_string()]
        );
        // Per-peer override beats the global default.
        assert_eq!(cfg.peers[0].exchange_plane, Some(false));
        // Unset inherits (effective value resolved at wiring time).
        assert_eq!(cfg.peers[1].exchange_plane, None);
        // Template inheritance reaches the per-peer knob.
        let base = PeerSpec {
            exchange_plane: Some(true),
            ..Default::default()
        };
        let mut over = PeerSpec::default();
        merge_spec(&mut over, &base);
        assert_eq!(over.exchange_plane, Some(true));
    }

    #[test]
    fn roa_tables_parse_and_finalize() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[roa]]\nprefix = \"203.0.113.0/24\"\nasn = 64512\n\n\
             [[roa]]\nprefix = \"198.51.100.0/24\"\nmax_length = 26\nasn = 64513\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.roas.len(), 2);
        assert_eq!(cfg.roas[0].prefix.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(cfg.roas[0].asn, Some(64512));
        assert_eq!(cfg.roas[0].max_length, None);
        assert_eq!(cfg.roas[1].max_length, Some(26));
    }

    #[test]
    fn roa_finalize_rejects_max_length_below_prefix() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[roa]]\nprefix = \"203.0.113.0/24\"\nmax_length = 23\nasn = 64512\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("max_length"), "{err}");
    }

    #[test]
    fn roa_finalize_rejects_max_length_above_family() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[roa]]\nprefix = \"203.0.113.0/24\"\nmax_length = 33\nasn = 64512\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("family"), "{err}");
    }

    #[test]
    fn roa_finalize_rejects_duplicates() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[roa]]\nprefix = \"203.0.113.0/24\"\nasn = 64512\n\n\
             [[roa]]\nprefix = \"203.0.113.0/24\"\nasn = 64512\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("declared twice"), "{err}");
    }

    #[test]
    fn roa_globals_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[bgp]\nroa_validate = true\nroa_invalid_action = \"warn\"\n",
            &mut cfg,
        )
        .unwrap();
        assert!(cfg.roa_validate);
        assert_eq!(cfg.roa_invalid_action, "warn");
    }

    #[test]
    fn roa_invalid_action_rejects_unknown() {
        let mut cfg = DaemonConfig::with_defaults();
        let err = parse_toml_subset("[bgp]\nroa_invalid_action = \"quarantine\"\n", &mut cfg);
        assert!(err.is_err());
    }

    #[test]
    fn roa_without_prefix_fails() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset("[[roa]]\nasn = 64512\n", &mut cfg).unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("without 'prefix'"), "{err}");
    }

    #[test]
    fn roa_without_asn_fails() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset("[[roa]]\nprefix = \"203.0.113.0/24\"\n", &mut cfg).unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("without 'asn'"), "{err}");
    }

    #[test]
    fn filter_tables_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[filter]]\nname = \"customer-in\"\nbody = \"if net ~ 203.0.113.0/24 then accept; reject;\"\n\
             description = \"drop non-customer prefixes\"\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.filters.len(), 1);
        assert_eq!(cfg.filters[0].name.as_deref(), Some("customer-in"));
        assert!(cfg.filters[0].body.as_deref().unwrap().contains("accept"));
    }

    #[test]
    fn filter_finalize_rejects_duplicate_names() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[filter]]\nname = \"dup\"\nbody = \"accept;\"\n\n\
             [[filter]]\nname = \"dup\"\nbody = \"reject;\"\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("declared twice"), "{err}");
    }

    #[test]
    fn filter_finalize_rejects_empty_body() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset("[[filter]]\nname = \"empty\"\nbody = \"\"\n", &mut cfg).unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("without 'body'"), "{err}");
    }

    #[test]
    fn peer_filter_attachment_parses() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[peer]]\nremote = \"192.0.2.2:179\"\nimport_filter = \"in\"\nexport_filter = \"out\"\n",
            &mut cfg,
        )
        .unwrap();
        assert_eq!(cfg.peers[0].import_filter.as_deref(), Some("in"));
        assert_eq!(cfg.peers[0].export_filter.as_deref(), Some("out"));
    }

    #[test]
    fn babel_interface_tables_parse() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[babel.interface]]\nname = \"eth*\"\ntype = \"wired\"\nrxcost = 96\nhello_interval_ms = 4000\n\n\
             [[babel.interface]]\nname = \"wlan0\"\ntype = \"wireless\"\nrxcost = 256\n",
            &mut cfg,
        )
        .unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.babel_interfaces.len(), 2);
        assert_eq!(cfg.babel_interfaces[0].name.as_deref(), Some("eth*"));
        assert_eq!(cfg.babel_interfaces[0].kind.as_deref(), Some("wired"));
        assert_eq!(cfg.babel_interfaces[0].rxcost, Some(96));
        assert_eq!(cfg.babel_interfaces[1].kind.as_deref(), Some("wireless"));
    }

    #[test]
    fn babel_interface_rejects_bad_type() {
        let mut cfg = DaemonConfig::with_defaults();
        let err = parse_toml_subset(
            "[[babel.interface]]\nname = \"eth0\"\ntype = \"optical\"\n",
            &mut cfg,
        );
        assert!(err.is_err());
    }

    #[test]
    fn babel_interface_rejects_bad_rtt_bounds() {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(
            "[[babel.interface]]\nname = \"eth0\"\nrtt_min = 100\nrtt_max = 100\n",
            &mut cfg,
        )
        .unwrap();
        let err = cfg.finalize().unwrap_err();
        assert!(err.contains("rtt_min"), "{err}");
    }

    #[test]
    fn babel_interface_rejects_dangling_escape() {
        // The validator rejects a trailing `\` (BIRD's patmatch
        // treats `\` as an escape, so a dangling one is malformed).
        assert!(glob_pattern_validate("eth\\").is_err());
        assert!(glob_pattern_validate("eth").is_ok());
        assert!(glob_pattern_validate("eth*").is_ok());
        assert!(glob_pattern_validate("eth?").is_ok());
        assert!(glob_pattern_validate("eth\\0").is_ok());
    }

    #[test]
    fn glob_match_matches_bird_semantics() {
        // Mirrors BIRD's lib/patmatch.c test cases:
        // `*` matches any sequence (including empty),
        // `?` matches exactly one character,
        // `\` escapes the next character.
        assert!(glob_match("eth*", "eth0"));
        assert!(glob_match("eth*", "ethernet-extra-long"));
        assert!(glob_match("eth*", "eth"));
        assert!(!glob_match("eth*", "wlan0"));
        assert!(glob_match("eth?", "eth0"));
        assert!(glob_match("eth?", "eth1"));
        assert!(!glob_match("eth?", "eth"));
        assert!(!glob_match("eth?", "eth01"));
        // Backslash escapes the next character.
        assert!(glob_match("eth\\0", "eth0"));
        assert!(!glob_match("eth\\0", "ethX"));
        // Wildcards combined.
        assert!(glob_match("*0", "eth0"));
        assert!(glob_match("*0", "wlan0"));
        assert!(!glob_match("*0", "wlan1"));
        // Empty pattern matches empty string only.
        assert!(glob_match("", ""));
        assert!(!glob_match("", "eth0"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }
}
