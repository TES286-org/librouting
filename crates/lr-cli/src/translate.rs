//! `lr translate bird|frr <config>` — best-effort conversion of BIRD 2
//! and FRR BGP configurations into librouting daemon TOML (the
//! W5.1 compatibility-layer slice).
//!
//! The converter is deliberately *line-based and shallow*: it maps the
//! shapes operators actually deploy — peers (AS, transport, auth,
//! timers), the router-id/local AS, and the common policy idioms
//! (prefix lists, route-map sequences, import/export none|all).
//! Everything it cannot map faithfully is preserved as an explicit
//! `# UNMAPPED:` comment instead of being silently dropped, and the
//! generated TOML is always loadable by `lr-daemon --config` (verified
//! by a round-trip test through the real parser).
//!
//! Mappings (BIRD 2 / FRR → lr):
//! - `router id` / `bgp router-id` → `[bgp] router_id`
//! - `local as` / `router bgp <as>` → `[bgp] local_as`
//! - `protocol bgp` / `neighbor … remote-as` → `[[peer]]`
//! - `neighbor … as` (BIRD) → `remote` + `peer_as`
//! - `password` / `neighbor … password` → `md5_key`
//! - `local address` / `update-source` → `local_address`
//! - `neighbor … port N` / `local port N` → `remote` ADDR:PORT /
//!   UNMAPPED note (lr has no per-peer listen port)
//! - `hold time` → `hold_time`
//! - `bfd on|off` / `neighbor … bfd` → `bfd`
//! - `import|export none` → a generated deny-all `[[route-map]]`
//! - `import|export all` → nothing: `ebgp_policy = "accept-all"`
//!   already has exactly that meaning (see Policy semantics below)
//! - `route-map NAME permit|deny SEQ` + `match`/`set` clauses →
//!   `[[route-map]]` entries (prefix-list, as-path, community matches;
//!   next-hop, local-pref, MED, prepend, add-community actions)
//! - `bgp as-path access-list` → `[[as-path-list]]`,
//!   `bgp community-list standard` → `[[community-list]]`
//! - `network PREFIX` (FRR) / `route PREFIX` inside `protocol static`
//!   (BIRD) → `networks`
//! - `ip prefix-list … seq … permit|deny` → `[[prefix-list]]` entries
//! - BIRD `ipv4 { … }` / `ipv6 { … }` channels → `mp_families` (+
//!   `default_ipv4_unicast = false` for an ipv6-only peer)
//! - FRR `address-family ipv6 unicast` + `neighbor … activate` →
//!   `mp_families += ipv6-unicast`
//!
//! Policy semantics: BIRD and FRR natively accept every route a peer
//! sends unless a filter says otherwise, which is lr's
//! `ebgp_policy = "accept-all"` mode (RFC 8212 insecure deviation) —
//! the converter always emits it, because the lr daemon's default
//! (rfc8212 deny-by-default) would silently drop routes the source
//! config would have accepted. Explicit maps, including the generated
//! deny-alls for `import none`, are still applied in accept-all mode.
//!
//! Not mapped (no lr equivalent): BIRD `multihop`, `rr client`,
//! FRR `ebgp-multihop`, `shutdown`, VRFs, route reflector/cluster
//! knobs, and anything inside non-BGP protocol stanzas. Lines inside
//! a BGP stanza that have no mapping are kept as `# UNMAPPED:`
//! comments; FRR peers whose `remote-as` never appears are dropped
//! with a note instead of emitting a peer that cannot start.

use std::process::ExitCode;

/// One peer extracted from the source config.
#[derive(Debug, Default, Clone)]
struct PeerOut {
    name: Option<String>,
    remote: Option<String>,
    /// FRR `neighbor … port N` — the port to CONNECT to, merged into
    /// `remote` at render time (ADDR:PORT).
    remote_port: Option<String>,
    peer_as: Option<u32>,
    local_address: Option<String>,
    md5_key: Option<String>,
    hold_time: Option<u32>,
    bfd: Option<bool>,
    default_ipv4_unicast: Option<bool>,
    /// Policy attachment: `import = "name"`.
    import: Option<String>,
    export: Option<String>,
    /// MP-BGP families beyond the daemon's implicit ipv4-unicast
    /// (BIRD channels / FRR `address-family … activate`). Rendered as
    /// the peer's `mp_families` list when non-empty.
    families: Vec<String>,
    /// BIRD channel presence (`ipv4 { … }` / `ipv6 { … }`), the input
    /// to the family mapping above. Always false for FRR peers.
    channel_v4: bool,
    channel_v6: bool,
    /// Source lines with no lr equivalent.
    unmapped: Vec<String>,
}

/// One `[[prefix-list]]` table: (name, seq, permit, prefix, ge, le).
type PrefixListRow = (String, u32, bool, String, Option<u8>, Option<u8>);

/// One `[[route-map]]` entry: FRR's `route-map` block plus its
/// `match`/`set` clauses (lr's schema mirrors the FRR shapes closely
/// enough to map them directly). Clauses without an lr equivalent
/// surface in `unmapped` instead of being dropped silently.
#[derive(Debug)]
struct RouteMapRow {
    name: String,
    entry: u32,
    permit: bool,
    match_prefix: Option<String>,
    match_as_path: Option<String>,
    match_community: Option<String>,
    set_local_pref: Option<u32>,
    set_med: Option<u32>,
    set_next_hop: Option<String>,
    prepend: Option<String>,
    add_community: Option<String>,
    unmapped: Vec<String>,
}

impl RouteMapRow {
    fn new(name: &str, entry: u32, permit: bool) -> Self {
        Self {
            name: name.to_string(),
            entry,
            permit,
            match_prefix: None,
            match_as_path: None,
            match_community: None,
            set_local_pref: None,
            set_med: None,
            set_next_hop: None,
            prepend: None,
            add_community: None,
            unmapped: Vec::new(),
        }
    }
}

/// One `[[as-path-list]]` row: FRR `bgp as-path access-list`.
#[derive(Debug)]
struct AsPathListRow {
    name: String,
    pattern: String,
    permit: bool,
}

/// One `[[community-list]]` row: FRR `bgp community-list standard`.
#[derive(Debug)]
struct CommunityListRow {
    name: String,
    communities: Vec<String>,
    permit: bool,
}

/// The converted configuration before rendering.
#[derive(Debug, Default)]
struct ConfigOut {
    local_as: Option<u32>,
    router_id: Option<String>,
    /// Locally originated prefixes (FRR `network`, BIRD static
    /// `route` inside a static protocol).
    networks: Vec<String>,
    peers: Vec<PeerOut>,
    prefix_lists: Vec<PrefixListRow>,
    as_path_lists: Vec<AsPathListRow>,
    community_lists: Vec<CommunityListRow>,
    route_maps: Vec<RouteMapRow>,
    /// Whole-peer notes rendered near the header (peers dropped
    /// because they can never start, e.g. FRR stubs without a
    /// `remote-as`).
    unmapped_global: Vec<String>,
}

/// Entry point: `lr translate <bird|frr> <file>`.
pub(super) fn translate(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        eprintln!("usage: lr translate <bird|frr> <config-file>");
        return ExitCode::from(2);
    }
    let dialect = args[0].as_str();
    let text = match std::fs::read_to_string(&args[1]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("translate: cannot read {}: {}", args[1], e);
            return ExitCode::from(1);
        }
    };
    let out = match dialect {
        "bird" => translate_bird(&text),
        "frr" => translate_frr(&text),
        other => {
            eprintln!("translate: unknown dialect '{other}' (expected bird or frr)");
            return ExitCode::from(2);
        }
    };
    print!("{}", render(out));
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// BIRD 2 parser
// ---------------------------------------------------------------------------

/// Parse a BIRD 2 config: `router id` plus `protocol bgp <name> { … }`
/// stanzas (one peer each). Stanza boundaries come from whole-line
/// brace counting — BIRD closes channel blocks with `};` and may put
/// the opening brace inline (`ipv4 { … };`) or on its own line, so
/// per-keyword brace arms would leak depth; counting every `{`/`}`
/// on the (comment-stripped) line keeps any nesting shape balanced.
fn translate_bird(text: &str) -> ConfigOut {
    let mut out = ConfigOut::default();
    let mut current: Option<PeerOut> = None;
    let mut depth_in_peer = 0usize;
    // `protocol static <name> { route PREFIX …; }` — the prefixes the
    // operator seeds for origination. lr's `networks` list has the
    // same role in the converted config, so they carry over.
    let mut in_static = false;
    let mut static_depth = 0usize;

    for raw in text.lines() {
        let line = strip_comments(raw);
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();
        if tokens.len() >= 2 && tokens[0] == "protocol" && tokens[1] == "static" {
            in_static = true;
            static_depth = 0;
        }
        match tokens[0] {
            // `route PREFIX [blackhole|via …];` inside a static
            // protocol — the announce intent maps to `networks`.
            "route" if in_static && tokens.len() >= 2 && tokens[1].contains('/') => {
                out.networks.push(clean(tokens[1]).to_string());
            }
            "router" if tokens.len() >= 3 && tokens[1] == "id" => {
                out.router_id = Some(clean(tokens[2]).to_string());
            }
            "protocol" if tokens.len() >= 3 && tokens[1] == "bgp" => {
                if let Some(finished) = current.take() {
                    out.peers.push(finished);
                }
                let name = tokens.get(2).map(|n| n.to_string());
                current = Some(PeerOut {
                    name,
                    ..PeerOut::default()
                });
            }
            // Full `local` clause: `local [address A] [port P] [as ASN]`
            // in any order (the interop configs use `local port P as N`).
            // `port` has no per-peer lr equivalent (the daemon listens
            // on its own global listener) — noted, the AS still maps.
            "local" if current.is_some() && tokens.len() >= 3 => {
                // Walk the clause list first, apply afterwards — keeps
                // the peer borrow out of the local_as update path.
                let mut addr: Option<String> = None;
                let mut port: Option<String> = None;
                let mut asn: Option<String> = None;
                let mut i = 1;
                while i < tokens.len() {
                    match tokens[i] {
                        "as" => {
                            asn = tokens.get(i + 1).map(|v| clean(v).to_string());
                            i += 1;
                        }
                        "address" => {
                            addr = tokens.get(i + 1).map(|v| clean(v).to_string());
                            i += 1;
                        }
                        "port" => {
                            port = tokens.get(i + 1).map(|v| clean(v).to_string());
                            i += 1;
                        }
                        // `local 10.0.0.1 as N` — a bare address first.
                        addr_like if addr.is_none() => addr = Some(clean(addr_like).to_string()),
                        _ => {}
                    }
                    i += 1;
                }
                let peer = current.as_mut().unwrap();
                if let Some(a) = addr {
                    peer.local_address = Some(a);
                }
                if let Some(p) = port {
                    peer.unmapped.push(format!(
                        "local port {p} (lr listens on the daemon's global listener)"
                    ));
                }
                if let Some(a) = asn {
                    apply_bird_local_as(&mut out, peer, &a);
                }
            }
            // `neighbor ADDR [port N] as ASN` — the `as` clause may be
            // preceded by a non-default `port`; lr's `remote` accepts
            // ADDR:PORT. Dynamic-BGP ranges (`neighbor 192.168.0.0/24 …`)
            // have no lr equivalent and are noted instead.
            "neighbor" if current.is_some() && tokens.len() >= 4 && tokens[1..].contains(&"as") => {
                let peer = current.as_mut().unwrap();
                if tokens[1].contains('/') {
                    peer.unmapped.push(line.trim().to_string());
                } else {
                    peer.remote = Some(tokens[1].to_string());
                    let mut port: Option<&str> = None;
                    for i in 2..tokens.len() {
                        match tokens[i] {
                            "port" => port = tokens.get(i + 1).copied(),
                            "as" => {
                                peer.peer_as = tokens
                                    .get(i + 1)
                                    .and_then(|v| v.trim_end_matches(';').parse().ok());
                            }
                            _ => {}
                        }
                    }
                    if let Some(p) = port {
                        peer.remote = Some(format!("{}:{}", tokens[1], p));
                    }
                }
            }
            "password" if tokens.len() >= 2 => {
                if let Some(peer) = current.as_mut() {
                    peer.md5_key = Some(unquote(clean(tokens[1])));
                }
            }
            "multihop" if current.is_some() => {
                if let Some(peer) = current.as_mut() {
                    peer.unmapped.push(line.trim().to_string());
                }
            }
            // Channel openings: `ipv4 { … }` / `ipv6 { … }`. A peer's
            // channel set decides its MP-BGP families (mapped after
            // the loop). An inline body (`ipv4 { import all; };`)
            // cannot be parsed line-wise — kept visible as UNMAPPED.
            "ipv4" | "ipv6" if current.is_some() => {
                let peer = current.as_mut().unwrap();
                if tokens[0] == "ipv4" {
                    peer.channel_v4 = true;
                } else {
                    peer.channel_v6 = true;
                }
                if tokens[1..]
                    .iter()
                    .any(|t| !t.trim_matches(|c| c == '{' || c == '}').is_empty())
                {
                    peer.unmapped.push(line.trim().to_string());
                }
            }
            "hold" if tokens.len() >= 3 && tokens[1] == "time" => {
                if let Some(peer) = current.as_mut() {
                    peer.hold_time = tokens[2].trim_end_matches(';').parse().ok();
                }
            }
            "bfd" if current.is_some() => {
                if let Some(peer) = current.as_mut() {
                    peer.bfd = Some(tokens.get(1).map(|t| *t != "off").unwrap_or(true));
                }
            }
            "import" | "export" if current.is_some() => {
                let dir = tokens[0];
                // Keep the whole filter expression visible in notes
                // (`export filter export_to_lr`, `import where …`).
                let value = tokens[1..]
                    .iter()
                    .map(|t| clean(t))
                    .collect::<Vec<_>>()
                    .join(" ");
                apply_bird_policy(current.as_mut().unwrap(), dir, &value);
            }
            "rr" if tokens.len() >= 2 && tokens[1] == "client" => {
                if let Some(peer) = current.as_mut() {
                    peer.unmapped.push(line.trim().to_string());
                }
            }
            // Anything else inside the BGP stanza has no lr mapping —
            // keep it visible instead of dropping it silently. Lines
            // outside `protocol bgp { … }` (top-level filters, device
            // protocols, includes) are out of scope by design, and
            // bare block punctuation is counted below, not noted.
            _ if current.is_some() && !is_brace_noise(line.trim()) => {
                let peer = current.as_mut().unwrap();
                peer.unmapped.push(line.trim().to_string());
            }
            _ => {}
        }
        // Stanza boundary: the whole-line brace count decides when
        // the opened `protocol bgp { … }` block closes again. Pushing
        // only on a line that closed a brace keeps a brace-less
        // `protocol bgp <name>` opener from ending the stanza early.
        if current.is_some() {
            depth_in_peer += opens;
            if closes > 0 {
                depth_in_peer = depth_in_peer.saturating_sub(closes);
                if depth_in_peer == 0 {
                    if let Some(finished) = current.take() {
                        out.peers.push(finished);
                    }
                }
            }
        }
        // The static protocol's block lifetime, same counting scheme.
        if in_static {
            static_depth += opens;
            if closes > 0 {
                static_depth = static_depth.saturating_sub(closes);
                if static_depth == 0 {
                    in_static = false;
                }
            }
        }
    }
    if let Some(finished) = current.take() {
        out.peers.push(finished);
    }
    // Drop peers that can never start: the daemon refuses a `[[peer]]`
    // without a usable remote/AS, so emitting one would break the
    // "generated TOML is always loadable" guarantee. Degenerate input
    // (e.g. a whole stanza on one line) surfaces here as a note.
    let mut dropped: Vec<String> = Vec::new();
    out.peers.retain(|p| match (&p.remote, p.peer_as) {
        (Some(_), Some(_)) => true,
        _ => {
            dropped.push(format!(
                "protocol bgp {}: incomplete stanza, peer dropped",
                p.name.as_deref().unwrap_or("<unnamed>")
            ));
            false
        }
    });
    out.unmapped_global.extend(dropped);
    // Channels → MP-BGP families. The daemon implicitly activates
    // ipv4-unicast (FRR parity) unless the peer opts out, so:
    // - ipv4-only channel: the default already matches — nothing to do;
    // - ipv4 + ipv6: keep the implicit v4 and list both families;
    // - ipv6 only: opt out of the implicit v4 activation and list v6
    //   (BIRD would never exchange IPv4 NLRI with this peer).
    for peer in &mut out.peers {
        match (peer.channel_v4, peer.channel_v6) {
            (true, true) => {
                peer.families = vec!["ipv4-unicast".into(), "ipv6-unicast".into()];
            }
            (false, true) => {
                peer.default_ipv4_unicast = Some(false);
                peer.families = vec!["ipv6-unicast".into()];
            }
            _ => {}
        }
    }
    out
}

/// A line made purely of block punctuation (`{`, `};`, `}};`, …) —
/// structural noise the brace counter owns, not an unmapped feature.
fn is_brace_noise(line: &str) -> bool {
    !line.is_empty() && line.chars().all(|c| matches!(c, '{' | '}' | ';'))
}

/// A BIRD `local … as ASN` clause. lr carries one global `local_as`;
/// a per-peer divergence cannot map and is noted on the peer.
fn apply_bird_local_as(out: &mut ConfigOut, peer: &mut PeerOut, asn_text: &str) {
    match asn_text.parse::<u32>() {
        Ok(asn) => {
            if out.local_as.is_some() && out.local_as != Some(asn) {
                peer.unmapped
                    .push(format!("local as {asn} (differs from the first peer)"));
            }
            out.local_as.get_or_insert(asn);
        }
        Err(_) => peer.unmapped.push(format!("local as {asn_text}")),
    }
}

/// One BIRD `import|export <value>` line. `none` gets a deny-all
/// route-map (the one policy the source had that must be preserved
/// explicitly); `all` is exactly what `ebgp_policy = "accept-all"`
/// already means, so it attaches nothing; BIRD filter expressions
/// have no lr equivalent — recorded as unmapped.
fn apply_bird_policy(peer: &mut PeerOut, dir: &str, value: &str) {
    // The caller passes only the first argument token: `none`, `all`,
    // or `filter NAME` / `where EXPR` (the unmapped shapes).
    if value == "all" {
        return;
    }
    if value != "none" {
        peer.unmapped.push(format!("{dir} {value}"));
        return;
    }
    let name = format!("translate-{dir}-deny");
    if dir == "import" {
        peer.import = Some(name);
    } else {
        peer.export = Some(name);
    }
}

// ---------------------------------------------------------------------------
// FRR parser
// ---------------------------------------------------------------------------

/// Parse an FRR bgpd config: `router bgp <as>` context plus
/// `neighbor` lines and the policy tables. `address-family` blocks
/// are tracked shallowly (one nesting level, vtysh output shape) so
/// `neighbor … activate` lines land in the right family.
fn translate_frr(text: &str) -> ConfigOut {
    let mut out = ConfigOut::default();
    // `Some("ipv4-unicast")` / `Some("ipv6-unicast")` inside the
    // matching `address-family …` block, `None` in router context.
    let mut af_ctx: Option<String> = None;
    for raw in text.lines() {
        let line = strip_comments(raw);
        let line = line.trim();
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        match tokens[0] {
            "router" if tokens.len() >= 3 && tokens[1] == "bgp" => {
                out.local_as = tokens[2].parse().ok();
            }
            "bgp" if tokens.len() >= 3 && tokens[1] == "router-id" => {
                out.router_id = Some(tokens[2].to_string());
            }
            // `bgp as-path access-list NAME permit|deny PATTERN` —
            // lr's [[as-path-list]] rows.
            "bgp" if tokens.len() >= 6 && tokens[1] == "as-path" && tokens[2] == "access-list" => {
                out.as_path_lists.push(AsPathListRow {
                    name: tokens[3].to_string(),
                    permit: tokens[4] == "permit",
                    // The regex may contain spaces (`_65001 _65002_`)
                    // — keep the tail verbatim.
                    pattern: tokens[5..].join(" "),
                });
            }
            // `bgp community-list standard NAME permit|deny C1 [C2 …]`.
            // `expanded` lists are regexes — no lr equivalent.
            "bgp" if tokens.len() >= 6 && tokens[1] == "community-list" => {
                if tokens[2] == "standard" {
                    if let Some(action_pos) = tokens[4..]
                        .iter()
                        .position(|t| *t == "permit" || *t == "deny")
                    {
                        let action_pos = action_pos + 4;
                        out.community_lists.push(CommunityListRow {
                            name: tokens[3].to_string(),
                            permit: tokens[action_pos] == "permit",
                            communities: tokens[action_pos + 1..]
                                .iter()
                                .map(|t| t.to_string())
                                .collect(),
                        });
                    }
                } else {
                    out.unmapped_global
                        .push(format!("{line} (expanded community lists unsupported)"));
                }
            }
            "ip" if tokens.len() >= 4 && tokens[1] == "prefix-list" => {
                parse_frr_prefix_list(&mut out, line);
            }
            "route-map" if tokens.len() >= 4 => {
                // route-map NAME permit|deny SEQ
                let name = tokens[1];
                let permit = tokens[2] == "permit";
                let entry = tokens.get(3).and_then(|s| s.parse().ok()).unwrap_or(10);
                out.route_maps.push(RouteMapRow::new(name, entry, permit));
            }
            // Route-map clause bodies attach to the entry declared
            // just above (FRR lists the header first).
            "match" if tokens.len() >= 3 => {
                if let Some(last) = out.route_maps.last_mut() {
                    match (tokens[1], tokens.get(2).copied()) {
                        ("ip", Some("address"))
                            if tokens.len() >= 5 && tokens[3] == "prefix-list" =>
                        {
                            last.match_prefix = Some(tokens[4].to_string());
                        }
                        ("as-path", Some(name)) => {
                            last.match_as_path = Some(name.to_string());
                        }
                        ("community", Some(name)) => {
                            last.match_community = Some(name.to_string());
                        }
                        _ => last.unmapped.push(line.to_string()),
                    }
                }
            }
            "set" if tokens.len() >= 3 => {
                if let Some(last) = out.route_maps.last_mut() {
                    match (tokens[1], tokens.get(2).copied()) {
                        ("ip", Some("next-hop")) if tokens.len() >= 4 => {
                            last.set_next_hop = Some(tokens[3].to_string());
                        }
                        ("local-preference", Some(v)) => {
                            last.set_local_pref = v.parse().ok();
                            if last.set_local_pref.is_none() {
                                last.unmapped.push(line.to_string());
                            }
                        }
                        ("metric" | "med", Some(v)) => {
                            last.set_med = v.parse().ok();
                            if last.set_med.is_none() {
                                last.unmapped.push(line.to_string());
                            }
                        }
                        ("as-path", Some("prepend")) if tokens.len() >= 4 => {
                            last.prepend = Some(tokens[3..].join(" "));
                        }
                        ("community", Some(_)) if tokens.len() >= 4 => {
                            if tokens.last() == Some(&"additive") {
                                last.add_community = Some(tokens[2..tokens.len() - 1].join(" "));
                            } else {
                                // FRR replaces the whole community set
                                // without `additive`; lr only adds.
                                last.unmapped.push(format!("{line} (non-additive)"));
                            }
                        }
                        _ => last.unmapped.push(line.to_string()),
                    }
                }
            }
            "address-family" if tokens.len() >= 3 => {
                // `address-family ipv4|ipv6 unicast` (others — vpnv4,
                // l2vpn — carry no lr mapping; their neighbors still
                // resolve through the generic attribute path).
                af_ctx = Some(format!(
                    "{}-{}",
                    tokens[1],
                    tokens.get(2).copied().unwrap_or("")
                ));
            }
            "exit-address-family" => af_ctx = None,
            "network" if tokens.len() >= 2 && tokens[1].contains('/') => {
                // `network PREFIX` (router or address-family context)
                // — locally originated, same as lr's `networks`.
                out.networks.push(tokens[1].to_string());
            }
            "neighbor" if tokens.len() >= 3 => {
                apply_frr_neighbor(&mut out, &tokens[2..], tokens[1], false, af_ctx.as_deref());
            }
            "no" if tokens.len() >= 4 && tokens[1] == "neighbor" => {
                apply_frr_neighbor(&mut out, &tokens[3..], tokens[2], true, af_ctx.as_deref());
            }
            _ => {}
        }
    }
    // Peers whose `remote-as` never appeared: lr would refuse to
    // start them (no usable AS), so drop with a note instead of
    // emitting a broken `[[peer]]`.
    let mut dropped: Vec<String> = Vec::new();
    out.peers.retain(|p| {
        if p.peer_as.is_some() {
            true
        } else {
            dropped.push(format!(
                "neighbor {}: no `remote-as` line found, peer dropped",
                p.remote.as_deref().unwrap_or("<unknown>")
            ));
            false
        }
    });
    out.unmapped_global.extend(dropped);
    // Every policy reference must resolve — the daemon's policy
    // compiler treats unknown names as startup errors (fail closed),
    // so a dangling `match` would make the converted config refuse to
    // boot. Clear unmatched references with a note instead.
    for row in &mut out.route_maps {
        if let Some(name) = row.match_prefix.clone() {
            if !out.prefix_lists.iter().any(|(n, ..)| *n == name) {
                row.unmapped.push(format!(
                    "match ip address prefix-list {name} (no such prefix-list; match dropped)"
                ));
                row.match_prefix = None;
            }
        }
        if let Some(name) = row.match_as_path.clone() {
            if !out.as_path_lists.iter().any(|l| l.name == name) {
                row.unmapped.push(format!(
                    "match as-path {name} (no such as-path access-list; match dropped)"
                ));
                row.match_as_path = None;
            }
        }
        if let Some(name) = row.match_community.clone() {
            if !out.community_lists.iter().any(|l| l.name == name) {
                row.unmapped.push(format!(
                    "match community {name} (no such community-list; match dropped)"
                ));
                row.match_community = None;
            }
        }
    }
    out
}

/// `ip prefix-list NAME [seq N] permit|deny PREFIX [ge G] [le L]`.
fn parse_frr_prefix_list(out: &mut ConfigOut, line: &str) {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    // ip prefix-list NAME ...
    let name = tokens[2].to_string();
    let mut idx = 3;
    let mut seq = 10u32;
    if tokens.get(idx) == Some(&"seq") {
        seq = tokens
            .get(idx + 1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        idx += 2;
    }
    let Some(action) = tokens.get(idx) else {
        return;
    };
    if action != &"permit" && action != &"deny" {
        return;
    }
    let permit = action == &"permit";
    let Some(prefix) = tokens.get(idx + 1) else {
        return;
    };
    let (mut ge, mut le) = (None, None);
    for (i, t) in tokens.iter().enumerate().skip(idx + 2) {
        match *t {
            "ge" => ge = tokens.get(i + 1).and_then(|s| s.parse().ok()),
            "le" => le = tokens.get(i + 1).and_then(|s| s.parse().ok()),
            _ => {}
        }
    }
    out.prefix_lists
        .push((name, seq, permit, prefix.to_string(), ge, le));
}

/// One `neighbor ADDR …` line in the FRR dialect. `tokens` starts at
/// the attribute (`remote-as`, …); `negated` marks a `no neighbor`
/// line; `af` is the enclosing `address-family` context, if any.
///
/// Attribute lines may precede `remote-as` (vtysh accepts any order),
/// so every attribute arm materialises the peer on first reference;
/// stubs without a later `remote-as` are dropped with a note by the
/// caller.
fn apply_frr_neighbor(
    out: &mut ConfigOut,
    tokens: &[&str],
    addr: &str,
    negated: bool,
    af: Option<&str>,
) {
    let addr = addr.to_string();
    let rest: Vec<&str> = tokens.to_vec();
    if negated {
        match rest[0] {
            // `no neighbor ADDR activate` inside `address-family ipv4
            // unicast` is the FRR way of turning implicit IPv4
            // unicast off — lr has the same knob per peer.
            "activate" if af != Some("ipv6-unicast") => {
                if let Some(peer) = peer_for_or_create(out, &addr) {
                    peer.default_ipv4_unicast = Some(false);
                }
            }
            // The v6 twin cannot map onto the same knob (lr keys
            // families off `mp_families`, which only adds) — visible
            // note instead of a silent no-op.
            "activate" => {
                if let Some(peer) = peer_for_or_create(out, &addr) {
                    peer.unmapped
                        .push(format!("no neighbor {addr} activate (ipv6-unicast)"));
                }
            }
            // `no neighbor ADDR shutdown` re-enables a peer — the
            // default state in lr, nothing to emit.
            "shutdown" => {}
            _ => {
                if let Some(peer) = peer_for_or_create(out, &addr) {
                    peer.unmapped
                        .push(format!("no neighbor {addr} {}", rest.join(" ")));
                }
            }
        }
        return;
    }
    match rest[0] {
        "remote-as" => {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                peer.peer_as = rest.get(1).and_then(|s| s.parse().ok());
            }
        }
        "password" => {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                // `password 0 SECRET` (cleartext) maps; type 7 is
                // encrypted and cannot be converted.
                match rest.get(1) {
                    Some(&"0") if rest.len() >= 3 => {
                        peer.md5_key = Some(rest[2..].join(" "));
                    }
                    Some(&"7") => peer
                        .unmapped
                        .push(format!("neighbor {addr} password 7 (encrypted)")),
                    Some(secret) => peer.md5_key = Some(secret.to_string()),
                    None => {}
                }
            }
        }
        "update-source" => {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                peer.local_address = rest.get(1).map(|s| s.to_string());
            }
        }
        // `neighbor ADDR port N` — the TCP port for the active
        // connection; lr keeps it in `remote` as ADDR:PORT. A
        // non-numeric port would produce an unloadable `remote`, so
        // it is noted instead of emitted.
        "port" => {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                match rest.get(1) {
                    Some(p) if p.parse::<u16>().is_ok() => {
                        peer.remote_port = Some(p.to_string());
                    }
                    Some(p) => peer
                        .unmapped
                        .push(format!("neighbor {addr} port {p} (invalid port)")),
                    None => {}
                }
            }
        }
        "ebgp-multihop" => {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                peer.unmapped
                    .push(format!("neighbor {addr} {}", rest.join(" ")));
            }
        }
        "shutdown" => {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                peer.unmapped.push(format!("neighbor {addr} shutdown"));
            }
        }
        "bfd" => {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                peer.bfd = Some(true);
            }
        }
        "route-map" => {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                let (name, dir) = (rest.get(1).copied(), rest.get(2).copied());
                match (name, dir) {
                    (Some(n), Some("in")) => peer.import = Some(n.to_string()),
                    (Some(n), Some("out")) => peer.export = Some(n.to_string()),
                    _ => {}
                }
            }
        }
        "activate" => {
            // IPv4 unicast is active by default in lr (FRR parity).
            // `neighbor ADDR activate` inside `address-family ipv6
            // unicast` adds the v6 family; a bare activate (router
            // context or ipv4) changes nothing.
            if af == Some("ipv6-unicast") {
                if let Some(peer) = peer_for_or_create(out, &addr) {
                    if !peer.families.iter().any(|f| f == "ipv6-unicast") {
                        peer.families.push("ipv6-unicast".to_string());
                    }
                }
            }
        }
        _ => {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                peer.unmapped
                    .push(format!("neighbor {addr} {}", rest.join(" ")));
            }
        }
    }
}

/// Find the peer for `addr`, materialising a stub on first reference
/// (FRR lets attribute lines precede `remote-as`; the stub is dropped
/// with a note by the caller when `remote-as` never arrives).
fn peer_for_or_create<'a>(out: &'a mut ConfigOut, addr: &str) -> Option<&'a mut PeerOut> {
    if out.peers.iter().all(|p| p.remote.as_deref() != Some(addr)) {
        out.peers.push(PeerOut {
            remote: Some(addr.to_string()),
            name: Some(format!("neighbor-{addr}")),
            ..PeerOut::default()
        });
    }
    out.peers
        .iter_mut()
        .find(|p| p.remote.as_deref() == Some(addr))
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render the converted config as lr daemon TOML.
fn render(out: ConfigOut) -> String {
    let mut s = String::new();
    s.push_str("# Generated by `lr translate` — best-effort conversion.\n");
    s.push_str("# Lines the converter could not map are kept as UNMAPPED comments.\n");
    s.push_str("# Review the result before pointing lr-daemon at it.\n");
    for note in &out.unmapped_global {
        s.push_str(&format!("# UNMAPPED: {note}\n"));
    }
    s.push('\n');
    s.push_str("[bgp]\n");
    if let Some(asn) = out.local_as {
        s.push_str(&format!("local_as = {asn}\n"));
    }
    if let Some(rid) = out.router_id {
        s.push_str(&format!("router_id = {}\n", toml_str(&rid)));
    }
    if !out.networks.is_empty() {
        let list = out
            .networks
            .iter()
            .map(|n| toml_str(n))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("networks = [{list}]\n"));
    }
    // BIRD and FRR accept every route a peer sends unless a filter
    // says otherwise — that is lr's `accept-all` mode (the RFC 8212
    // insecure deviation the lr daemon does NOT default to). Per-peer
    // maps, explicit or generated, still apply under accept-all, so
    // `import none` conversions keep their deny-all behaviour.
    s.push_str("ebgp_policy = \"accept-all\"\n");
    s.push('\n');

    // lr prefix-lists evaluate in document order — emit them sorted
    // by their source sequence number.
    let mut prefix_lists = out.prefix_lists.clone();
    prefix_lists.sort_by_key(|(_, seq, _, _, _, _)| *seq);
    for (name, _seq, permit, prefix, ge, le) in &prefix_lists {
        s.push_str("[[prefix-list]]\n");
        s.push_str(&format!("name = {}\n", toml_str(name)));
        s.push_str(&format!("permit = {permit}\n"));
        s.push_str(&format!("prefix = {}\n", toml_str(prefix)));
        if let Some(ge) = ge {
            s.push_str(&format!("ge = {ge}\n"));
        }
        if let Some(le) = le {
            s.push_str(&format!("le = {le}\n"));
        }
        s.push('\n');
    }
    for list in &out.as_path_lists {
        s.push_str("[[as-path-list]]\n");
        s.push_str(&format!("name = {}\n", toml_str(&list.name)));
        s.push_str(&format!("pattern = {}\n", toml_str(&list.pattern)));
        s.push_str(&format!("permit = {}\n\n", list.permit));
    }
    for list in &out.community_lists {
        s.push_str("[[community-list]]\n");
        s.push_str(&format!("name = {}\n", toml_str(&list.name)));
        let communities = list
            .communities
            .iter()
            .map(|c| toml_str(c))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("communities = [{communities}]\n"));
        s.push_str(&format!("permit = {}\n\n", list.permit));
    }
    for row in &out.route_maps {
        s.push_str("[[route-map]]\n");
        s.push_str(&format!("name = {}\n", toml_str(&row.name)));
        s.push_str(&format!("entry = {}\n", row.entry));
        s.push_str(&format!("permit = {}\n", row.permit));
        if let Some(mp) = &row.match_prefix {
            s.push_str(&format!("match_prefix = {}\n", toml_str(mp)));
        }
        if let Some(ap) = &row.match_as_path {
            s.push_str(&format!("match_as_path = {}\n", toml_str(ap)));
        }
        if let Some(cm) = &row.match_community {
            s.push_str(&format!("match_community = {}\n", toml_str(cm)));
        }
        if let Some(v) = row.set_local_pref {
            s.push_str(&format!("set_local_pref = {v}\n"));
        }
        if let Some(v) = row.set_med {
            s.push_str(&format!("set_med = {v}\n"));
        }
        if let Some(v) = &row.set_next_hop {
            s.push_str(&format!("set_next_hop = {}\n", toml_str(v)));
        }
        if let Some(v) = &row.prepend {
            s.push_str(&format!("prepend = {}\n", toml_str(v)));
        }
        if let Some(v) = &row.add_community {
            s.push_str(&format!("add_community = {}\n", toml_str(v)));
        }
        for note in &row.unmapped {
            s.push_str(&format!("# UNMAPPED: {note}\n"));
        }
        s.push('\n');
    }
    // Generated policies: the deny-all route-maps the BIRD
    // `import|export none` mappings reference.
    let generated: Vec<&str> = ["translate-import-deny", "translate-export-deny"]
        .into_iter()
        .filter(|tag| {
            out.peers
                .iter()
                .any(|p| p.import.as_deref() == Some(*tag) || p.export.as_deref() == Some(*tag))
        })
        .collect();
    for tag in generated {
        s.push_str("[[route-map]]\n");
        s.push_str(&format!("name = \"{tag}\"\n"));
        s.push_str("entry = 10\n");
        s.push_str(&format!("permit = {}\n\n", tag.ends_with("permit")));
    }

    for peer in &out.peers {
        s.push_str("[[peer]]\n");
        if let Some(n) = &peer.name {
            s.push_str(&format!("name = {}\n", toml_str(n)));
        }
        if let Some(r) = &peer.remote {
            // FRR `neighbor … port N` appends the connect port.
            match &peer.remote_port {
                Some(p) => s.push_str(&format!("remote = {}\n", toml_str(&format!("{r}:{p}")))),
                None => s.push_str(&format!("remote = {}\n", toml_str(r))),
            }
        }
        if let Some(asn) = peer.peer_as {
            s.push_str(&format!("peer_as = {asn}\n"));
        }
        if let Some(la) = &peer.local_address {
            s.push_str(&format!("local_address = {}\n", toml_str(la)));
        }
        if let Some(k) = &peer.md5_key {
            s.push_str(&format!("md5_key = {}\n", toml_str(k)));
        }
        if let Some(h) = peer.hold_time {
            s.push_str(&format!("hold_time = {h}\n"));
        }
        if let Some(b) = peer.bfd {
            s.push_str(&format!("bfd = {b}\n"));
        }
        if let Some(d) = peer.default_ipv4_unicast {
            s.push_str(&format!("default_ipv4_unicast = {d}\n"));
        }
        if !peer.families.is_empty() {
            let list = peer
                .families
                .iter()
                .map(|f| format!("\"{f}\""))
                .collect::<Vec<_>>()
                .join(", ");
            s.push_str(&format!("mp_families = [{list}]\n"));
        }
        if let Some(i) = &peer.import {
            s.push_str(&format!("import = \"{i}\"\n"));
        }
        if let Some(e) = &peer.export {
            s.push_str(&format!("export = \"{e}\"\n"));
        }
        for u in &peer.unmapped {
            s.push_str(&format!("# UNMAPPED: {u}\n"));
        }
        s.push('\n');
    }
    s
}

/// Drop a trailing `;`, `{` and trailing whitespace.
fn clean(token: &str) -> &str {
    token.trim_end_matches(';').trim_end_matches('{').trim()
}

/// Strip BIRD `#` comments (not inside quotes — configs in the wild
/// do not put `#` in passwords, and the converter is best-effort).
fn strip_comments(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Remove surrounding double quotes.
fn unquote(s: &str) -> String {
    s.trim_matches('"').to_string()
}

/// Render `s` as a TOML basic string (escaping backslashes and
/// quotes so passwords and regex patterns cannot break the output).
fn toml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_config::DaemonConfig;

    fn roundtrip(toml: &str) -> DaemonConfig {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "bgp".to_string();
        crate::daemon_config::parse_toml_subset(toml, &mut cfg).expect("generated TOML must load");
        cfg.finalize().expect("generated TOML must finalize");
        cfg
    }

    #[test]
    fn bird_single_peer() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;

protocol bgp uplink {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
    local address 10.99.1.1;
    password "s3cret";
    hold time 90;
    multihop 2;
    ipv4 {
        import all;
        export all;
    };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.router_id, "10.0.0.1");
        assert_eq!(cfg.local_as, 64512);
        assert_eq!(cfg.peers.len(), 1);
        let peer = &cfg.peers[0];
        assert_eq!(peer.remote.as_deref(), Some("192.168.1.2"));
        assert_eq!(peer.peer_as, 64513);
        assert_eq!(peer.local_address.as_deref(), Some("10.99.1.1"));
        assert_eq!(peer.md5_key.as_deref(), Some("s3cret"));
        assert_eq!(peer.hold_time, Some(90));
        // `import all / export all` is what the emitted
        // `ebgp_policy = "accept-all"` already means: no maps attached.
        assert!(peer.import.is_none() && peer.export.is_none());
        assert!(toml.contains("ebgp_policy = \"accept-all\""));
        // `multihop 2` has no lr equivalent: kept as an UNMAPPED note.
        assert!(toml.contains("# UNMAPPED: multihop 2"));
    }

    #[test]
    fn bird_import_none_gets_deny_all() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;
protocol bgp p1 {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
    ipv4 {
        import none;
        export all;
    };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(
            cfg.peers[0].import.as_deref(),
            Some("translate-import-deny")
        );
        // `export all` needs no map under the emitted accept-all mode.
        assert!(cfg.peers[0].export.is_none());
        assert!(cfg
            .route_maps
            .iter()
            .any(|m| m.name == "translate-import-deny" && m.permit == Some(false)));
        assert!(!cfg
            .route_maps
            .iter()
            .any(|m| m.name.starts_with("translate-export")));
    }

    #[test]
    fn frr_single_peer_with_policy() {
        let toml = render(translate_frr(
            r#"
frr version 10
frr defaults traditional
hostname r1
!
router bgp 64512
 bgp router-id 10.0.0.1
 neighbor 192.168.1.2 remote-as 64513
 neighbor 192.168.1.2 password 0 s3cret
 neighbor 192.168.1.2 update-source 10.99.1.1
 neighbor 192.168.1.2 ebgp-multihop 2
 neighbor 192.168.1.2 route-map FILTER-IN in
 neighbor 192.168.1.2 bfd
!
ip prefix-list ONLY-DEFAULT seq 10 permit 0.0.0.0/0
!
route-map FILTER-IN permit 10
 match ip address prefix-list ONLY-DEFAULT
!
"#,
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.local_as, 64512);
        assert_eq!(cfg.router_id, "10.0.0.1");
        assert_eq!(cfg.peers.len(), 1);
        let peer = &cfg.peers[0];
        assert_eq!(peer.remote.as_deref(), Some("192.168.1.2"));
        assert_eq!(peer.peer_as, 64513);
        assert_eq!(peer.md5_key.as_deref(), Some("s3cret"));
        assert_eq!(peer.local_address.as_deref(), Some("10.99.1.1"));
        assert_eq!(peer.bfd, Some(true));
        assert_eq!(peer.import.as_deref(), Some("FILTER-IN"));
        assert_eq!(cfg.prefix_lists.len(), 1);
        assert_eq!(cfg.route_maps.len(), 1);
        assert_eq!(
            cfg.route_maps[0].match_prefix.as_deref(),
            Some("ONLY-DEFAULT")
        );
        assert!(toml.contains("# UNMAPPED: neighbor 192.168.1.2 ebgp-multihop 2"));
    }

    #[test]
    fn frr_no_activate_maps_to_default_off() {
        let out = translate_frr(
            "router bgp 64512\n neighbor 10.0.0.2 remote-as 64513\n\
             address-family ipv4 unicast\n  no neighbor 10.0.0.2 activate\n",
        );
        assert_eq!(out.peers[0].default_ipv4_unicast, Some(false));
    }

    #[test]
    fn bird_ipv6_only_channel_disables_v4() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;
protocol bgp v6peer {
    local as 64512;
    neighbor 2001:db8::2 as 64513;
    ipv6 {
        import all;
        export all;
    };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        let peer = &cfg.peers[0];
        // BIRD would never exchange IPv4 NLRI with this peer — the
        // implicit v4 activation must be switched off and v6 listed.
        assert_eq!(peer.default_ipv4_unicast, Some(false));
        assert_eq!(
            peer.mp_families.as_deref(),
            Some(["ipv6-unicast".to_string()].as_slice())
        );
    }

    #[test]
    fn bird_dual_channel_lists_both_families() {
        let out = translate_bird(
            r#"
protocol bgp dual {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
    ipv4 { import all; export all; };
    ipv6 { import all; export all; };
}
"#,
        );
        assert_eq!(out.peers[0].families, vec!["ipv4-unicast", "ipv6-unicast"]);
    }

    #[test]
    fn bird_unknown_lines_inside_stanza_become_unmapped() {
        let toml = render(translate_bird(
            r#"
protocol bgp p1 {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
    description "uplink to transit";
    ipv4 {
        import all;
        export all;
        next hop self;
    };
}
"#,
        ));
        // Unmapped content stays visible; brace punctuation does not
        // leak into the notes and the stanza still closes.
        assert!(toml.contains("# UNMAPPED: description \"uplink to transit\";"));
        assert!(toml.contains("# UNMAPPED: next hop self;"));
        assert!(!toml.contains("# UNMAPPED: }"));
        assert!(!toml.contains("# UNMAPPED: {"));
    }

    #[test]
    fn frr_attributes_before_remote_as_survive() {
        let toml = render(translate_frr(
            "router bgp 64512\n\
             neighbor 192.168.1.2 password 0 s3cret\n\
             neighbor 192.168.1.2 update-source 10.99.1.1\n\
             neighbor 192.168.1.2 remote-as 64513\n",
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.peers.len(), 1);
        let peer = &cfg.peers[0];
        assert_eq!(peer.peer_as, 64513);
        assert_eq!(peer.md5_key.as_deref(), Some("s3cret"));
        assert_eq!(peer.local_address.as_deref(), Some("10.99.1.1"));
    }

    #[test]
    fn frr_ipv6_activate_adds_family() {
        let toml = render(translate_frr(
            "router bgp 64512\n\
             neighbor 2001:db8::2 remote-as 64513\n\
             address-family ipv6 unicast\n\
              neighbor 2001:db8::2 activate\n\
             exit-address-family\n",
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(
            cfg.peers[0].mp_families.as_deref(),
            Some(["ipv6-unicast".to_string()].as_slice())
        );
    }

    #[test]
    fn frr_stub_without_remote_as_is_dropped_with_note() {
        let toml = render(translate_frr("router bgp 64512\n neighbor 10.0.0.2 bfd\n"));
        // The peer cannot start without an AS — dropped, with the
        // reason surfaced as a global UNMAPPED comment.
        assert!(
            toml.contains("# UNMAPPED: neighbor 10.0.0.2: no `remote-as` line found, peer dropped")
        );
        assert!(!toml.contains("[[peer]]"));
        assert!(toml.contains("ebgp_policy = \"accept-all\""));
    }

    #[test]
    fn bird_neighbor_and_local_with_ports() {
        // The shape the interop lab actually deploys: non-default
        // ports on both ends of the eBGP session.
        let toml = render(translate_bird(
            r#"
router id 10.0.0.2;
protocol bgp lr {
    local port 17992 as 64513;
    neighbor 127.0.0.1 port 17990 as 64512;
    multihop 2;
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.local_as, 64513);
        assert_eq!(cfg.peers.len(), 1);
        let peer = &cfg.peers[0];
        // The connect port rides `remote` as ADDR:PORT; the local
        // listen port has no per-peer lr equivalent (noted instead).
        assert_eq!(peer.remote.as_deref(), Some("127.0.0.1:17990"));
        assert_eq!(peer.peer_as, 64512);
        assert!(toml
            .contains("# UNMAPPED: local port 17992 (lr listens on the daemon's global listener)"));
        assert!(toml.contains("# UNMAPPED: export filter export_to_lr"));
    }

    #[test]
    fn frr_neighbor_port_merges_into_remote() {
        let toml = render(translate_frr(
            "router bgp 64512\n\
             neighbor 127.0.0.1 remote-as 64513\n\
             neighbor 127.0.0.1 port 17990\n",
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.peers[0].remote.as_deref(), Some("127.0.0.1:17990"));
    }

    #[test]
    fn frr_network_and_route_map_set_clauses() {
        let toml = render(translate_frr(
            "router bgp 64512\n\
             neighbor 192.168.1.2 remote-as 64513\n\
             address-family ipv4 unicast\n\
              network 198.51.100.0/24\n\
             exit-address-family\n\
             route-map SET-OUT permit 10\n\
              set ip next-hop 192.0.2.20\n\
              set local-preference 200\n\
              set metric 50\n\
              set as-path prepend 65001 65001\n\
              set community 65000:1 additive\n\
             !\n",
        ));
        let cfg = roundtrip(&toml);
        // FRR `network` = lr `networks` (locally originated).
        assert_eq!(cfg.networks, vec!["198.51.100.0/24".to_string()]);
        let map = &cfg.route_maps[0];
        assert_eq!(map.set_next_hop.as_deref(), Some("192.0.2.20"));
        assert_eq!(map.set_local_pref, Some(200));
        assert_eq!(map.set_med, Some(50));
        assert_eq!(map.prepend.as_deref(), Some("65001 65001"));
        assert_eq!(map.add_community.as_deref(), Some("65000:1"));
    }

    #[test]
    fn frr_as_path_and_community_lists_resolve() {
        let toml = render(translate_frr(
            "router bgp 64512\n\
             neighbor 192.168.1.2 remote-as 64513\n\
             bgp as-path access-list ONLY-OURS permit ^65001$\n\
             bgp community-list standard TRUSTED permit 65000:42\n\
             route-map POLICY permit 10\n\
              match as-path ONLY-OURS\n\
              match community TRUSTED\n\
             !\n",
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.as_path_lists.len(), 1);
        assert_eq!(cfg.as_path_lists[0].pattern, "^65001$");
        assert_eq!(cfg.community_lists.len(), 1);
        assert_eq!(
            cfg.community_lists[0].communities,
            vec!["65000:42".to_string()]
        );
        assert_eq!(
            cfg.route_maps[0].match_as_path.as_deref(),
            Some("ONLY-OURS")
        );
        assert_eq!(
            cfg.route_maps[0].match_community.as_deref(),
            Some("TRUSTED")
        );
    }

    #[test]
    fn frr_dangling_match_is_noted_and_cleared() {
        let toml = render(translate_frr(
            "router bgp 64512\n\
             neighbor 192.168.1.2 remote-as 64513\n\
             route-map POLICY permit 10\n\
              match as-path GHOST\n\
             !\n",
        ));
        // The daemon's policy compiler fails startup on unknown list
        // names — the reference is dropped with a visible note so the
        // generated TOML still loads.
        assert!(toml.contains("no such as-path access-list"));
        assert!(!toml.contains("match_as_path"));
    }

    #[test]
    fn bird_static_routes_become_networks() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;
protocol static static_routes {
    ipv4;
    route 198.51.100.0/24 blackhole;
    route 203.0.113.0/24 via 10.0.0.9;
}
protocol bgp p1 {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
}
"#,
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(
            cfg.networks,
            vec!["198.51.100.0/24".to_string(), "203.0.113.0/24".to_string()]
        );
    }
}
