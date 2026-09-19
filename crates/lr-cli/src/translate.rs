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
//! - BIRD `filter NAME { … }` / `function NAME(…) { … }` → `[[filter]]`
//!   bodies in the lr filter DSL (ROADMAP-v3 D14.1, fail-closed: a
//!   filter with any unfaithfully-translatable construct is not
//!   emitted and the offending constructs are reported; see
//!   `translate_bird_filter.rs` for the verified operator/attribute
//!   mapping)
//! - BIRD `import|export filter NAME` / `import where EXPR` →
//!   `import_filter` / `export_filter` peer wiring (`where` becomes a
//!   generated `bird-<dir>-<peer>` filter)
//! - BIRD `roa table NAME { roa …; }` → `[[roa]]` entries; the
//!   single-table `roa_check(t) = ROA_*` idiom → `roa.state` string
//!   comparisons
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
//! Dialect defaults are applied so the output runs with the source
//! implementation's semantics: an FRR config keeps FRR's
//! `bgp enforce-first-as` default (on), BIRD keeps it off.
//!
//! lr-specific extensions: `lr:` comment directives ride along in both
//! dialects (`# lr: …` in BIRD and FRR, `! lr: …` also accepted in
//! FRR) and map onto the daemon's TOML schema — see `LrDirective`.
//! Inside a BIRD `protocol bgp` block a directive scopes to that
//! peer; in FRR the `# lr: neighbor ADDR …` form scopes to a peer.
//! Directives are invisible to the reference implementations, so a
//! config carrying them still loads in real BIRD / FRR.
//!
//! Not mapped (no lr equivalent): BIRD `multihop`, `rr client`,
//! FRR `ebgp-multihop`, `shutdown`, VRFs, route reflector/cluster
//! knobs, and anything inside non-BGP protocol stanzas. Non-BGP
//! routing protocols (`protocol ospf …`, `router ospf`, …) are
//! reported as ignored — the converter covers the BGP control plane.
//! Lines inside a BGP stanza that have no mapping are kept as
//! `# UNMAPPED:` comments; FRR peers whose `remote-as` never appears
//! are dropped with a note instead of emitting a peer that cannot
//! start.

use std::process::ExitCode;

use crate::daemon_config::BabelInterfaceSpec;
use crate::translate_bird_filter::{self, BirdFilterSource, FilterRow, RoaRow};

/// One lr-specific `lr:` comment directive: `key` (normalised to
/// snake_case) plus its optional value (the whitespace-joined
/// remainder, quotes stripped). Resolved against the TOML schema at
/// render time by [`directive_toml`]; unknown keys or bad values
/// surface as visible notes instead of being applied.
#[derive(Debug, Clone)]
struct LrDirective {
    key: String,
    value: Option<String>,
}

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
    /// Policy attachment: `import = "name"` (route-map).
    import: Option<String>,
    export: Option<String>,
    /// Filter DSL attachments (BIRD `import filter NAME`):
    /// `import_filter = "name"`.
    import_filter: Option<String>,
    export_filter: Option<String>,
    /// MP-BGP families beyond the daemon's implicit ipv4-unicast
    /// (BIRD channels / FRR `address-family … activate`). Rendered as
    /// the peer's `mp_families` list when non-empty.
    families: Vec<String>,
    /// BIRD channel presence (`ipv4 { … }` / `ipv6 { … }`), the input
    /// to the family mapping above. Always false for FRR peers.
    channel_v4: bool,
    channel_v6: bool,
    /// lr TCP-AO keys attached via `lr: tcp-ao-key ID:SECRET`
    /// directives (the dialects have no TCP-AO syntax).
    tcp_ao_keys: Vec<String>,
    /// `lr:` directives scoped to this peer (inside the BIRD BGP
    /// stanza / FRR `neighbor ADDR` form).
    ext: Vec<LrDirective>,
    /// Source lines with no lr equivalent.
    unmapped: Vec<String>,
}

/// One `[[prefix-list]]` table: (name, seq, permit, prefix, ge, le).
type PrefixListRow = (String, u32, bool, String, Option<u8>, Option<u8>);

/// A pending BIRD `import|export filter NAME` / `… where EXPR`
/// attachment, resolved after the whole file is scanned (BIRD lets
/// filters be defined after the protocol that uses them).
struct PendingFilter {
    peer: String,
    dir: &'static str,
    target: PendingTarget,
}

enum PendingTarget {
    /// `filter NAME` — a named top-level filter.
    Named(String),
    /// `where EXPR` — an inline expression.
    Where(String),
}

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

/// The converted configuration before rendering. Visible to `compat`
/// so the native-run surface can reuse the parse/render pipeline.
#[derive(Debug, Default)]
pub(super) struct ConfigOut {
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
    /// BIRD filters translated into lr filter DSL bodies (D14.1).
    filters: Vec<FilterRow>,
    /// ROA entries captured from BIRD `roa table` blocks.
    roas: Vec<RoaRow>,
    /// BIRD filters that could not be translated faithfully:
    /// `(bird name, notes)` — rendered as UNMAPPED.
    failed_filters: Vec<(String, Vec<String>)>,
    /// BIRD `protocol babel` interface blocks (D14.2): the spec plus
    /// the per-interface unmapped notes.
    babel_ifaces: Vec<(BabelInterfaceSpec, Vec<String>)>,
    /// Whole-peer notes rendered near the header (peers dropped
    /// because they can never start, e.g. FRR stubs without a
    /// `remote-as`).
    unmapped_global: Vec<String>,
    /// `lr:` directives at global scope (outside any BGP stanza).
    ext_global: Vec<LrDirective>,
    /// Non-BGP routing protocols seen in the source config — reported
    /// as ignored (the converter covers the BGP control plane).
    /// Read by `compat` to surface them as operator warnings.
    pub(super) ignored_protocols: Vec<String>,
    /// Dialect-specific default that differs from lr's: FRR runs with
    /// `bgp enforce-first-as` on, so an FRR config keeps that.
    enforce_first_as: Option<bool>,
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
    // Non-BGP protocols are reported even in the standalone converter —
    // a silent omission here would look like lost routing config.
    for proto in &out.ignored_protocols {
        eprintln!(
            "translate: note: `{proto}` ignored — the compat surface runs the BGP control plane only"
        );
    }
    print!("{}", render(out));
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Native-run surface (compat mode) — used by crate::compat
// ---------------------------------------------------------------------------

/// Parse a BIRD 2 config into the intermediate form. `pub(super)` so
/// `compat` can run the same parse the converter uses, then feed the
/// rendered TOML straight into the daemon's loader.
pub(super) fn parse_bird_config(text: &str) -> ConfigOut {
    translate_bird(text)
}

/// Parse an FRR config into the intermediate form (see
/// [`parse_bird_config`]).
pub(super) fn parse_frr_config(text: &str) -> ConfigOut {
    translate_frr(text)
}

/// Render the intermediate form as daemon TOML (see
/// [`parse_bird_config`]).
pub(super) fn render_config(out: ConfigOut) -> String {
    render(out)
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
    // D14.1 captures: BIRD top-level `filter` / `function` /
    // `roa table` blocks and `define` constants. Filter attachment is
    // deferred — BIRD lets a filter be defined after the protocol
    // that uses it.
    let mut capture: Option<BirdCapture> = None;
    let mut defines: Vec<(String, String)> = Vec::new();
    let mut functions: Vec<(String, String)> = Vec::new();
    let mut filters: Vec<(String, Vec<String>)> = Vec::new();
    let mut roa_tables: Vec<Vec<RoaRow>> = Vec::new();
    let mut pending: Vec<PendingFilter> = Vec::new();

    for raw in text.lines() {
        let line = strip_comments(raw);
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();

        // An active capture swallows its body lines whole — they
        // belong to the filter text, not to the peer scan below.
        if let Some(cap) = capture.as_mut() {
            if cap.feed(line, opens, closes) {
                let cap = capture.take().expect("checked above");
                match cap.kind {
                    BirdCaptureKind::Filter(name) => {
                        filters.push((name, extract_block_body(&cap.text)));
                    }
                    BirdCaptureKind::Function(name) => functions.push((name, cap.text)),
                    BirdCaptureKind::RoaTable => roa_tables.push(cap.rows),
                    BirdCaptureKind::Babel(mut proto) => {
                        let proto = &mut *proto;
                        finish_babel_iface(proto);
                        // Protocol-level `next hop` statements may
                        // appear after the interface blocks — backfill
                        // every interface still lacking one.
                        for (spec, _) in &mut proto.ifaces {
                            if spec.next_hop_ipv4.is_none() {
                                spec.next_hop_ipv4 = proto.next_hop_v4.clone();
                            }
                            if spec.next_hop_ipv6.is_none() {
                                spec.next_hop_ipv6 = proto.next_hop_v6.clone();
                            }
                        }
                        // lr runs one protocol per daemon instance: the
                        // Babel interface parameters carry over, and the
                        // operator picks the protocol with the top-level
                        // `protocol = "babel"` key.
                        out.unmapped_global.push(
                            "protocol babel: lr runs one protocol per daemon instance —                              set the top-level `protocol = \"babel\"` key to activate Babel                              (the BGP peers above need their own instance)"
                                .to_string(),
                        );
                        for note in proto.iface_notes.drain(..) {
                            out.unmapped_global.push(format!("protocol babel: {note}"));
                        }
                        out.babel_ifaces.append(&mut proto.ifaces);
                    }
                }
            }
            continue;
        }

        // `lr:` directives live in comments that strip_comments would
        // eat — scan the raw line first, but never inside captured
        // bodies (a directive there is BIRD filter text, not lr
        // config). Inside `protocol bgp` a directive scopes to that
        // peer, outside it is global.
        if let Some(d) = extract_lr_directive(raw, "#") {
            match current.as_mut() {
                Some(peer) => attach_peer_directive(peer, d),
                None => out.ext_global.push(d),
            }
        }
        if tokens.is_empty() {
            continue;
        }
        // Capture starts (top level only — BIRD has no filters inside
        // protocol stanzas).
        if current.is_none() {
            match tokens[0] {
                "filter" if tokens.len() >= 2 && line.contains('{') => {
                    let name = tokens[1].trim_end_matches('{').to_string();
                    capture = Some(BirdCapture::new(
                        BirdCaptureKind::Filter(name),
                        line,
                        opens,
                        closes,
                    ));
                    continue;
                }
                "function" if tokens.len() >= 2 => {
                    let name = tokens[1].split('(').next().unwrap_or("").to_string();
                    capture = Some(BirdCapture::new(
                        BirdCaptureKind::Function(name),
                        line,
                        opens,
                        closes,
                    ));
                    continue;
                }
                "roa" if tokens.len() >= 3 && tokens[1] == "table" => {
                    if line.contains('{') {
                        capture = Some(BirdCapture::new(
                            BirdCaptureKind::RoaTable,
                            line,
                            opens,
                            closes,
                        ));
                    } else {
                        // `roa table t4;` — an empty table (populated
                        // via RTR in BIRD; lr's [[roa]] stays empty and
                        // the roa_check mapping still knows it exists).
                        roa_tables.push(Vec::new());
                    }
                    continue;
                }
                "define" if tokens.len() >= 4 && tokens[2] == "=" => {
                    // `define NAME = value;` — parsed from the line so
                    // quoted values keep their inner spaces.
                    if let Some((name, value)) = parse_bird_define(line) {
                        defines.push((name, value));
                    }
                    continue;
                }
                "protocol" if tokens.len() >= 3 && tokens[1] == "babel" => {
                    // D14.2: `protocol babel NAME { interface …; }` —
                    // per-interface parameter capture (RFC 8966 §A.2).
                    capture = Some(BirdCapture::new(
                        BirdCaptureKind::Babel(Box::default()),
                        line,
                        opens,
                        closes,
                    ));
                    continue;
                }
                _ => {}
            }
        }
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
            // Non-BGP routing protocols are reported as ignored instead
            // of vanishing silently — the converter covers the BGP
            // control plane (Babel's interface parameters are the one
            // exception, handled by its own capture below). `protocol
            // device` is BIRD housekeeping with no routing meaning:
            // skipped without a note.
            "protocol" if tokens.len() >= 3 && tokens[1] != "static" && tokens[1] != "babel" => {
                if tokens[1] != "device" {
                    out.ignored_protocols.push(format!(
                        "protocol {} {}",
                        tokens[1],
                        tokens
                            .get(2)
                            .map(|n| n.trim_end_matches(['{', ';']))
                            .unwrap_or("")
                    ));
                }
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
            // the loop). Inline bodies (`ipv4 { import all; };`) split
            // on `;` and run the same statement mapping; the shapes
            // that still do not map stay visible per statement.
            "ipv4" | "ipv6" if current.is_some() => {
                let peer = current.as_mut().unwrap();
                if tokens[0] == "ipv4" {
                    peer.channel_v4 = true;
                } else {
                    peer.channel_v6 = true;
                }
                let has_content = tokens[1..]
                    .iter()
                    .any(|t| !t.trim_matches(|c| c == '{' || c == '}').is_empty());
                if has_content {
                    let start = line.find('{').map(|i| i + 1).unwrap_or(0);
                    let end = line.rfind('}').unwrap_or(line.len());
                    let peer_name = peer.name.clone().unwrap_or_else(|| "peer".to_string());
                    for stmt in line[start..end].split(';') {
                        let stmt = stmt.trim();
                        if stmt.is_empty() {
                            continue;
                        }
                        if stmt.starts_with("import") || stmt.starts_with("export") {
                            let dir: &'static str = if stmt.starts_with("import") {
                                "import"
                            } else {
                                "export"
                            };
                            let value = stmt
                                .split_whitespace()
                                .skip(1)
                                .map(clean)
                                .collect::<Vec<_>>()
                                .join(" ");
                            apply_bird_import_export(&peer_name, peer, dir, &value, &mut pending);
                        } else {
                            peer.unmapped.push(stmt.to_string());
                        }
                    }
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
                let dir: &'static str = if tokens[0] == "import" {
                    "import"
                } else {
                    "export"
                };
                // Keep the whole filter expression visible in notes
                // (`export filter export_to_lr`, `import where …`).
                let value = tokens[1..]
                    .iter()
                    .map(|t| clean(t))
                    .collect::<Vec<_>>()
                    .join(" ");
                let peer_name = current
                    .as_ref()
                    .expect("arm guard")
                    .name
                    .clone()
                    .unwrap_or_else(|| "peer".to_string());
                apply_bird_import_export(
                    &peer_name,
                    current.as_mut().unwrap(),
                    dir,
                    &value,
                    &mut pending,
                );
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
    // D14.1: translate the captured filter set, then resolve the
    // deferred `import|export filter NAME` / `where EXPR` attachments.
    let src = BirdFilterSource {
        defines,
        functions,
        filters,
        roa_tables,
    };
    let (translated, roa_rows) = translate_bird_filter::translate(&src);
    out.filters = translated.ok;
    out.failed_filters = translated.failed;
    out.roas = roa_rows;
    for p in pending {
        let peer = match out
            .peers
            .iter_mut()
            .find(|peer| peer.name.as_deref() == Some(&p.peer))
        {
            Some(peer) => peer,
            None => continue,
        };
        let filter_slot = if p.dir == "import" {
            &mut peer.import_filter
        } else {
            &mut peer.export_filter
        };
        match &p.target {
            PendingTarget::Named(name) => {
                if out.filters.iter().any(|f| &f.name == name) {
                    *filter_slot = Some(name.clone());
                } else {
                    let notes = out
                        .failed_filters
                        .iter()
                        .filter(|(n, _)| n == name)
                        .flat_map(|(_, notes)| notes.iter())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; ");
                    let reason = if notes.is_empty() {
                        "filter is not defined in the source config".to_string()
                    } else {
                        notes
                    };
                    peer.unmapped.push(format!(
                        "{} filter {name}: filter NOT attached — {reason}",
                        p.dir
                    ));
                }
            }
            PendingTarget::Where(expr) => {
                match translate_bird_filter::translate_where(expr, &src) {
                    Ok(body) => {
                        let name = format!("bird-{}-{}", p.dir, p.peer);
                        let name = unique_filter_name(&out.filters, &name);
                        out.filters.push(FilterRow {
                            name: name.clone(),
                            body,
                        });
                        *filter_slot = Some(name);
                    }
                    Err(notes) => {
                        peer.unmapped.push(format!(
                            "{} where {expr}: filter NOT attached — {}",
                            p.dir,
                            notes.join("; ")
                        ));
                    }
                }
            }
        }
    }
    out
}

/// Ensure generated `where` filter names stay unique across peers.
fn unique_filter_name(existing: &[FilterRow], base: &str) -> String {
    let mut candidate = base.to_string();
    let mut n = 1;
    while existing.iter().any(|f| f.name == candidate) {
        n += 1;
        candidate = format!("{base}-{n}");
    }
    candidate
}

/// One top-level BIRD block capture (`filter`, `function`,
/// `roa table`): brace-counted text accumulation.
struct BirdCapture {
    kind: BirdCaptureKind,
    text: String,
    depth: isize,
    seen_brace: bool,
    rows: Vec<RoaRow>,
}

enum BirdCaptureKind {
    Filter(String),
    Function(String),
    RoaTable,
    /// `protocol babel NAME` — interface-block parsing state plus
    /// protocol-level next hops. Boxed: by far the largest variant.
    Babel(Box<BabelProtoCapture>),
}

/// State accumulated while scanning a `protocol babel` stanza.
#[derive(Default)]
struct BabelProtoCapture {
    /// Name of the `interface "…" { … }` block being captured
    /// (`None` while at protocol level).
    iface: Option<BabelInterfaceSpec>,
    iface_notes: Vec<String>,
    /// Protocol-level `next hop ipv4|ipv6` defaults applied to every
    /// interface at close time.
    next_hop_v4: Option<String>,
    next_hop_v6: Option<String>,
    /// Per-interface rows finished so far.
    ifaces: Vec<(BabelInterfaceSpec, Vec<String>)>,
}

impl BirdCapture {
    /// Start a capture from the header line (its braces count too —
    /// a single-line stanza closes immediately).
    fn new(kind: BirdCaptureKind, header: &str, opens: usize, closes: usize) -> Self {
        let mut cap = Self {
            kind,
            text: String::new(),
            depth: 0,
            seen_brace: false,
            rows: Vec::new(),
        };
        cap.absorb(header, opens, closes);
        cap
    }

    fn absorb(&mut self, line: &str, opens: usize, closes: usize) {
        self.text.push_str(line);
        self.text.push('\n');
        self.depth += opens as isize - closes as isize;
        if self.text.contains('{') {
            self.seen_brace = true;
        }
        match &mut self.kind {
            BirdCaptureKind::RoaTable => {
                if let Some(row) = parse_roa_line(line) {
                    self.rows.push(row);
                }
            }
            BirdCaptureKind::Babel(proto) => absorb_babel_line(proto, line),
            _ => {}
        }
    }

    /// Absorb one body line; true when the block just closed.
    fn feed(&mut self, line: &str, opens: usize, closes: usize) -> bool {
        self.absorb(line, opens, closes);
        self.seen_brace && self.depth <= 0
    }
}

/// One line inside a `protocol babel` stanza: interface-block
/// bookkeeping plus the parameter statements that map onto
/// [`BabelInterfaceSpec`] (D14.2, RFC 8966 §A.2).
fn absorb_babel_line(proto: &mut BabelProtoCapture, line: &str) {
    let trimmed = line.trim();
    let mut tokens = trimmed.split_whitespace();
    let t0 = tokens.next().unwrap_or("");
    // Interface block lifecycle: `interface "eth0" {` opens a block
    // (closed by the matching `};` line), a bare `interface "wg*";`
    // is complete immediately, and the stanza-level `}` that closes
    // the protocol itself arrives at depth 0 (handled by the caller).
    if t0 == "interface" && !trimmed.starts_with('}') {
        // Close any open interface block first.
        finish_babel_iface(proto);
        let raw_name = trimmed.split('"').nth(1).unwrap_or_default().to_string();
        let spec = BabelInterfaceSpec {
            name: Some(raw_name),
            ..BabelInterfaceSpec::default()
        };
        if trimmed.ends_with(';') {
            // Bare form: no parameter block, complete as-is.
            let mut spec = spec;
            if spec.next_hop_ipv4.is_none() {
                spec.next_hop_ipv4 = proto.next_hop_v4.clone();
            }
            if spec.next_hop_ipv6.is_none() {
                spec.next_hop_ipv6 = proto.next_hop_v6.clone();
            }
            proto.ifaces.push((spec, Vec::new()));
            return;
        }
        proto.iface = Some(spec);
        proto.iface_notes = Vec::new();
        return;
    }
    // A pure close line ends the open interface block.
    if proto.iface.is_some() && is_brace_noise(trimmed) {
        finish_babel_iface(proto);
        return;
    }
    if proto.iface.is_none() {
        // Protocol-level statements.
        match t0 {
            "next" if trimmed.contains("hop ipv4 ") => {
                proto.next_hop_v4 = Some(
                    trimmed
                        .split("hop ipv4 ")
                        .nth(1)
                        .unwrap_or("")
                        .trim_end_matches(';')
                        .trim()
                        .to_string(),
                );
            }
            "next" if trimmed.contains("hop ipv6 ") => {
                proto.next_hop_v6 = Some(
                    trimmed
                        .split("hop ipv6 ")
                        .nth(1)
                        .unwrap_or("")
                        .trim_end_matches(';')
                        .trim()
                        .to_string(),
                );
            }
            // Protocol-level keys/other statements: keep visible.
            t if !t.is_empty() && !is_brace_noise(trimmed) => {
                proto.iface_notes.push(format!(
                    "protocol-level babel statement `{t}` — lr carries it per [[babel.interface]]"
                ));
            }
            _ => {}
        }
        return;
    }
    // Inside an interface block: map the parameter statements.
    let Some(spec) = proto.iface.as_mut() else {
        return;
    };
    let mut words = trimmed.split_whitespace();
    let t0 = words.next().unwrap_or("");
    match t0 {
        "type" => {
            let kind = words.next().unwrap_or("").trim_end_matches(';');
            spec.kind = Some(kind.to_string());
        }
        "rxcost" => {
            spec.rxcost = words
                .next()
                .and_then(|v| v.trim_end_matches(';').parse().ok());
        }
        "rtt" => match words.next() {
            Some("cost") => {
                spec.rtt_cost = words
                    .next()
                    .and_then(|v| v.trim_end_matches(';').parse().ok());
            }
            // `rtt min 10 ms;` / `rtt max 120 ms;` — value and unit
            // are separate words (bare numbers are seconds in BIRD).
            Some("min") => {
                let v = words.next().unwrap_or("");
                let unit = words.next().unwrap_or("s");
                spec.rtt_min_us = parse_time_ms(&format!("{v} {}", unit.trim_end_matches(';')))
                    .map(|ms| ms * 1000);
            }
            Some("max") => {
                let v = words.next().unwrap_or("");
                let unit = words.next().unwrap_or("s");
                spec.rtt_max_us = parse_time_ms(&format!("{v} {}", unit.trim_end_matches(';')))
                    .map(|ms| ms * 1000);
            }
            _ => {}
        },
        "hello" if trimmed.contains("interval") => {
            // `hello interval 4 s;` / `hello interval 4000 ms;`
            let after = trimmed.split("interval").nth(1).unwrap_or("");
            let mut it = after.split_whitespace();
            let value = it.next().unwrap_or("");
            let unit = it.next().unwrap_or("s");
            spec.hello_interval_ms =
                parse_time_ms(&format!("{value} {}", unit.trim_end_matches(';')));
        }
        "update" if trimmed.contains("interval") => {
            let after = trimmed.split("interval").nth(1).unwrap_or("");
            let mut it = after.split_whitespace();
            let value = it.next().unwrap_or("");
            let unit = it.next().unwrap_or("s");
            spec.update_interval_ms =
                parse_time_ms(&format!("{value} {}", unit.trim_end_matches(';')));
        }
        "check" if trimmed.contains("link") => {
            spec.check_link = Some(trimmed.contains("yes"));
        }
        "extended" if trimmed.contains("next hop") => {
            spec.extended_next_hop = Some(trimmed.contains("yes"));
        }
        "port" => {
            spec.port = words
                .next()
                .and_then(|v| v.trim_end_matches(';').parse().ok());
        }
        t if !t.is_empty() && !is_brace_noise(trimmed) => {
            proto.iface_notes.push(format!(
                "babel interface parameter `{t}` — no lr equivalent"
            ));
        }
        _ => {}
    }
}

/// Close the open interface block (if any), applying the protocol
/// level next-hop defaults.
fn finish_babel_iface(proto: &mut BabelProtoCapture) {
    if let Some(mut spec) = proto.iface.take() {
        let notes = std::mem::take(&mut proto.iface_notes);
        if spec.next_hop_ipv4.is_none() {
            spec.next_hop_ipv4 = proto.next_hop_v4.clone();
        }
        if spec.next_hop_ipv6.is_none() {
            spec.next_hop_ipv6 = proto.next_hop_v6.clone();
        }
        proto.ifaces.push((spec, notes));
    }
}

/// Parse a BIRD babel time value (`4`, `4 s`, `4000 ms`) into
/// milliseconds. Bare numbers are seconds (BIRD's babel time default).
fn parse_time_ms(text: &str) -> Option<u32> {
    let text = text.trim().trim_end_matches(';');
    if let Some(ms) = text.strip_suffix("ms") {
        return ms.trim().parse().ok();
    }
    let secs: f64 = text.trim_end_matches('s').trim().parse().ok()?;
    Some((secs * 1000.0).round() as u32)
}

/// The text between the first `{` and the matching final `}` — the
/// filter body the translator works on, trimmed per line.
fn extract_block_body(text: &str) -> Vec<String> {
    let start = text.find('{').map(|i| i + 1).unwrap_or(0);
    let end = text.rfind('}').unwrap_or(text.len());
    text[start..end]
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

/// `define NAME = value;` — name plus the verbatim value text
/// (quotes preserved, trailing `;` stripped).
fn parse_bird_define(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("define")?.trim_start();
    let eq = rest.find('=')?;
    let name = rest[..eq].trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let value = rest[eq + 1..].trim();
    let value = value.strip_suffix(';').unwrap_or(value).trim();
    Some((name.to_string(), value.to_string()))
}

/// One `roa <prefix> [max <n>] as <asn>;` entry inside a
/// `roa table { … }` block.
fn parse_roa_line(line: &str) -> Option<RoaRow> {
    let rest = line.trim().strip_prefix("roa")?.trim_start();
    if rest.starts_with("table") {
        return None;
    }
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    let prefix = tokens[0].to_string();
    let mut max_length = None;
    let mut asn = None;
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i] {
            "max" => {
                max_length = tokens.get(i + 1).and_then(|v| v.parse().ok());
                i += 2;
            }
            "as" => {
                asn = tokens
                    .get(i + 1)
                    .and_then(|v| v.trim_end_matches(';').parse().ok());
                i += 2;
            }
            _ => i += 1,
        }
    }
    asn.map(|asn| RoaRow {
        prefix,
        max_length,
        asn,
    })
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

/// One BIRD `import|export VALUE` statement — from a channel block
/// line or an inline channel body. `all` / `none` map immediately
/// (see [`apply_bird_policy`]); `filter NAME` / `where EXPR` defer to
/// the post-scan resolution (BIRD lets filters be defined after the
/// protocol that uses them).
fn apply_bird_import_export(
    peer_name: &str,
    peer: &mut PeerOut,
    dir: &'static str,
    value: &str,
    pending: &mut Vec<PendingFilter>,
) {
    if let Some(rest) = value.strip_prefix("filter ") {
        if rest.trim().starts_with('{') {
            peer.unmapped.push(format!(
                "{dir} filter {{ … }} (inline filter block) — use a named top-level filter"
            ));
        } else {
            pending.push(PendingFilter {
                peer: peer_name.to_string(),
                dir,
                target: PendingTarget::Named(rest.trim().to_string()),
            });
        }
        return;
    }
    if let Some(rest) = value.strip_prefix("where ") {
        pending.push(PendingFilter {
            peer: peer_name.to_string(),
            dir,
            target: PendingTarget::Where(rest.trim().to_string()),
        });
        return;
    }
    apply_bird_policy(peer, dir, value);
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
        // FRR directive scan: `# lr: KEY [VALUE]` / `! lr: …` are
        // global; `# lr: neighbor ADDR KEY [VALUE]` scopes to that
        // peer (FRR has no stanza braces to inherit scope from).
        if let Some(body) = lr_marker_body(raw, "#!") {
            let tokens: Vec<&str> = body.split_whitespace().collect();
            if tokens.len() >= 2 && tokens[0].trim_end_matches(';') == "neighbor" {
                let addr = tokens[1];
                let d = parse_lr_body(&tokens[2..].join(" "));
                if d.key.is_empty() {
                    out.unmapped_global
                        .push(format!("lr: neighbor {addr} — no directive given"));
                } else if let Some(peer) = peer_for_or_create(&mut out, addr) {
                    attach_peer_directive(peer, d);
                }
            } else {
                out.ext_global.push(parse_lr_body(&body));
            }
        }
        let line = strip_comments(raw);
        let line = line.trim();
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        match tokens[0] {
            "router" if tokens.len() >= 3 && tokens[1] == "bgp" => {
                out.local_as = tokens[2].parse().ok();
                // FRR's documented default: `bgp enforce-first-as` is
                // ON. The native run keeps the source implementation's
                // semantics, so the rendered config turns it on too.
                out.enforce_first_as = Some(true);
            }
            // Non-BGP routing protocols (`router ospf`, `router isis`,
            // …) are reported as ignored instead of vanishing
            // silently — the converter covers the BGP control plane.
            "router" if tokens.len() >= 2 => {
                out.ignored_protocols.push(format!("router {}", tokens[1]));
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
    // `remote-as` may ride anywhere on the line — FRR's own output
    // gives it a dedicated line, but hand-written configs combine it
    // with the other attributes (`neighbor A port P remote-as N`).
    // Extract it first so the per-attribute dispatch below only owns
    // the rest; the leading-token arm stays for the common shape.
    for (i, t) in rest.iter().enumerate().skip(1) {
        if *t == "remote-as" {
            if let Some(peer) = peer_for_or_create(out, &addr) {
                peer.peer_as = rest.get(i + 1).and_then(|s| s.parse().ok());
            }
        }
    }
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
    for proto in &out.ignored_protocols {
        s.push_str(&format!(
            "# UNMAPPED: {proto} — the lr compat surface runs the BGP control plane only\n"
        ));
    }
    // Global `lr:` directives that map onto top-level (bare) TOML keys
    // must precede the `[bgp]` header — inside it they would parse as
    // `bgp.api_socket` and be rejected as unknown.
    let mut bgp_ext: Vec<(String, String)> = Vec::new();
    for d in &out.ext_global {
        match directive_toml(d, DirScope::Global) {
            Ok((k, v)) if matches!(k.as_str(), "api_socket" | "user" | "group") => {
                s.push_str(&format!("{k} = {v}\n"));
            }
            Ok((k, v)) => bgp_ext.push((k, v)),
            Err(note) => s.push_str(&format!("# UNMAPPED: {note}\n")),
        }
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
    if out.enforce_first_as == Some(true) {
        // Dialect default: FRR runs `bgp enforce-first-as` on, BIRD
        // has no such check. Emitted only when the source dialect
        // differs from the lr default (off).
        s.push_str("enforce_first_as = true\n");
    }
    // Remaining global `lr:` directives land in the [bgp] section.
    for (k, v) in &bgp_ext {
        s.push_str(&format!("{k} = {v}\n"));
    }
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
    // BIRD `roa table` entries carry over as `[[roa]]` rows — the
    // translated filters' `roa.state` checks and the daemon's
    // `roa_validate` both read the same store.
    for row in &out.roas {
        s.push_str("[[roa]]\n");
        s.push_str(&format!("prefix = {}\n", toml_str(&row.prefix)));
        if let Some(ml) = row.max_length {
            s.push_str(&format!("max_length = {ml}\n"));
        }
        s.push_str(&format!("asn = {}\n\n", row.asn));
    }
    // BIRD `protocol babel` interface parameters (D14.2).
    for (spec, notes) in &out.babel_ifaces {
        s.push_str("[[babel.interface]]\n");
        if let Some(n) = &spec.name {
            s.push_str(&format!("name = {}\n", toml_str(n)));
        }
        if let Some(k) = &spec.kind {
            s.push_str(&format!("kind = {}\n", toml_str(k)));
        }
        if let Some(v) = spec.hello_interval_ms {
            s.push_str(&format!("hello_interval_ms = {v}\n"));
        }
        if let Some(v) = spec.update_interval_ms {
            s.push_str(&format!("update_interval_ms = {v}\n"));
        }
        if let Some(v) = spec.rxcost {
            s.push_str(&format!("rxcost = {v}\n"));
        }
        if let Some(v) = spec.rtt_cost {
            s.push_str(&format!("rtt_cost = {v}\n"));
        }
        if let Some(v) = spec.rtt_min_us {
            s.push_str(&format!("rtt_min_us = {v}\n"));
        }
        if let Some(v) = spec.rtt_max_us {
            s.push_str(&format!("rtt_max_us = {v}\n"));
        }
        if let Some(v) = &spec.next_hop_ipv4 {
            s.push_str(&format!("next_hop_ipv4 = {}\n", toml_str(v)));
        }
        if let Some(v) = &spec.next_hop_ipv6 {
            s.push_str(&format!("next_hop_ipv6 = {}\n", toml_str(v)));
        }
        if let Some(v) = spec.extended_next_hop {
            s.push_str(&format!("extended_next_hop = {v}\n"));
        }
        if let Some(v) = spec.check_link {
            s.push_str(&format!("check_link = {v}\n"));
        }
        if let Some(v) = spec.port {
            s.push_str(&format!("port = {v}\n"));
        }
        for n in notes {
            s.push_str(&format!("# UNMAPPED: {n}\n"));
        }
        s.push('\n');
    }
    // Translated BIRD filters. The lr DSL is whitespace-insensitive,
    // so the multi-line body collapses onto one TOML string line.
    for f in &out.filters {
        s.push_str("[[filter]]\n");
        s.push_str(&format!("name = {}\n", toml_str(&f.name)));
        let one_line = f.body.replace('\n', " ");
        s.push_str(&format!("body = {}\n\n", toml_str(&one_line)));
    }
    // Filters that could not be translated faithfully stay visible —
    // silently re-filtering a route policy is worse than a gap.
    for (name, notes) in &out.failed_filters {
        s.push_str(&format!(
            "# UNMAPPED: filter {name} not translated — {}\n",
            notes.join("; ")
        ));
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
        if !peer.tcp_ao_keys.is_empty() {
            let list = peer
                .tcp_ao_keys
                .iter()
                .map(|k| toml_str(k))
                .collect::<Vec<_>>()
                .join(", ");
            s.push_str(&format!("tcp_ao_keys = [{list}]\n"));
        }
        // Peer-scoped `lr:` directives resolve against the [[peer]]
        // schema; unknown keys or bad values stay visible as notes.
        for d in &peer.ext {
            match directive_toml(d, DirScope::Peer) {
                Ok((k, v)) => s.push_str(&format!("{k} = {v}\n")),
                Err(note) => s.push_str(&format!("# UNMAPPED: {note}\n")),
            }
        }
        if let Some(i) = &peer.import {
            s.push_str(&format!("import = \"{i}\"\n"));
        }
        if let Some(e) = &peer.export {
            s.push_str(&format!("export = \"{e}\"\n"));
        }
        if let Some(i) = &peer.import_filter {
            s.push_str(&format!("import_filter = {}\n", toml_str(i)));
        }
        if let Some(e) = &peer.export_filter {
            s.push_str(&format!("export_filter = {}\n", toml_str(e)));
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

// ---------------------------------------------------------------------------
// lr: comment directives (the lr-specific extension channel)
// ---------------------------------------------------------------------------

/// Return the directive body after the `lr:` marker, if the raw line
/// carries one. `comment_chars` is the dialect's comment introducers:
/// `#` for BIRD, `#` and `!` for FRR. A directive may ride on its own
/// comment line or trail real code (`ipv4 { # lr: add-path`); the
/// caller keeps parsing the code part. Trailing `;` is tolerated so
/// BIRD-styled `# lr: gtsm 2;` reads naturally.
fn lr_marker_body(raw: &str, comment_chars: &str) -> Option<String> {
    let start = raw.find(|c| comment_chars.contains(c))?;
    let comment = raw[start + 1..].trim_start();
    let rest = comment.strip_prefix("lr:")?;
    let body = rest.trim();
    if body.is_empty() {
        None
    } else {
        Some(body.to_string())
    }
}

/// Split a directive body into its normalised key (snake_case) and
/// optional value (whitespace-joined remainder, quotes stripped).
/// Both `key value` and `key = value` spellings are accepted — the
/// latter is what operators coming from the TOML schema write
/// naturally. A bare `=` separator is stripped, `key=` with no value
/// keeps the empty value (surfaced as "needs a value" at render).
fn parse_lr_body(body: &str) -> LrDirective {
    let body = body.trim();
    let (key_part, value_part) = match body.find('=') {
        Some(i) if i > 0 => (body[..i].trim(), Some(body[i + 1..].trim())),
        _ => (body, None),
    };
    let key = key_part
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches(';')
        .to_lowercase()
        .replace('-', "_");
    let value_raw = match value_part {
        Some(v) => v.to_string(),
        None => key_part
            .split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" "),
    };
    let value = if value_raw.is_empty() {
        None
    } else {
        Some(unquote(value_raw.trim_end_matches(';').trim()))
    };
    LrDirective { key, value }
}

/// BIRD-side extraction: stanza scope decides global vs peer.
fn extract_lr_directive(raw: &str, comment_chars: &str) -> Option<LrDirective> {
    lr_marker_body(raw, comment_chars).map(|body| parse_lr_body(&body))
}

/// Attach a peer-scoped directive: list-shaped ones (`mp-family`,
/// `tcp-ao-key`) fold into the peer's arrays immediately; scalar ones
/// resolve against the peer TOML schema at render time. Unknown keys
/// surface as UNMAPPED notes at render — never silently dropped.
fn attach_peer_directive(peer: &mut PeerOut, d: LrDirective) {
    match fold_peer_list_directive(peer, &d) {
        Ok(()) => {}
        Err(_) => peer.ext.push(d),
    }
}

/// Where a directive was found — decides the TOML schema it resolves
/// against (the `[bgp]`/top-level globals vs the `[[peer]]` table).
#[derive(Clone, Copy, PartialEq)]
enum DirScope {
    Global,
    Peer,
}

/// Resolve one directive to a `(toml key, toml value literal)` pair.
/// List-shaped directives (`mp-family`, `tcp-ao-key`) are NOT handled
/// here — the callers fold them into the peer's existing arrays.
/// `Err` carries a human-readable note that the callers render as an
/// UNMAPPED comment instead of applying the directive.
fn directive_toml(d: &LrDirective, scope: DirScope) -> Result<(String, String), String> {
    use DirScope::*;
    let val = d.value.as_deref();
    // Bool-shaped: bare directive means true; "true"/"false" accepted.
    let bool_val = |v: Option<&str>| -> Result<String, String> {
        match v {
            None => Ok("true".into()),
            Some("true") => Ok("true".into()),
            Some("false") => Ok("false".into()),
            Some(other) => Err(format!("lr: bad bool value '{other}' for {}", d.key)),
        }
    };
    // Number-shaped: parse + range check, so a typo never lands in
    // the TOML as an unloadable or silently-wrong value.
    let num_val = |v: Option<&str>, min: i64, max: i64| -> Result<String, String> {
        match v.and_then(|s| s.parse::<i64>().ok()) {
            Some(n) if (min..=max).contains(&n) => Ok(n.to_string()),
            _ => Err(format!(
                "lr: bad value '{}' for {} (expected integer {}..={})",
                val.unwrap_or(""),
                d.key,
                min,
                max
            )),
        }
    };
    let str_val = |v: Option<&str>| -> Result<String, String> {
        v.map(toml_str)
            .ok_or_else(|| format!("lr: {} needs a value", d.key))
    };
    match (scope, d.key.as_str()) {
        // ---- globals ----
        (Global, "install_kernel") => Ok(("install_kernel".into(), bool_val(val)?)),
        (Global, "api_socket") => Ok(("api_socket".into(), str_val(val)?)),
        (Global, "user") => Ok(("user".into(), str_val(val)?)),
        (Global, "group") => Ok(("group".into(), str_val(val)?)),
        (Global, "listen") => Ok(("listen_addr".into(), str_val(val)?)),
        (Global, "bmp_target") => Ok(("bmp_target".into(), str_val(val)?)),
        (Global, "graceful_restart") => {
            Ok(("graceful_restart_time".into(), num_val(val, 0, 4095)?))
        }
        (Global, "llgr") => Ok(("llgr_stale_time".into(), num_val(val, 0, 65535)?)),
        (Global, "llgr_max_stale") => Ok(("llgr_max_stale_time".into(), num_val(val, 0, 65535)?)),
        (Global, "add_path") => Ok(("add_path".into(), bool_val(val)?)),
        (Global, "add_path_max") => Ok(("add_path_max_paths".into(), num_val(val, 1, 255)?)),
        (Global, "max_prefixes") => Ok(("max_prefixes".into(), num_val(val, 1, u32::MAX as i64)?)),
        (Global, "max_prefix_action") => {
            let s = val.ok_or_else(|| format!("lr: {} needs a value", d.key))?;
            if !matches!(s, "warn" | "teardown" | "restart") {
                return Err(format!(
                    "lr: bad max_prefix_action '{s}' (warn|teardown|restart)"
                ));
            }
            Ok(("max_prefix_action".into(), toml_str(s)))
        }
        (Global, "gtsm") => match val {
            None => Ok(("gtsm".into(), "true".into())),
            Some(n) => Ok(("gtsm".into(), num_val(Some(n), 1, 255)?)),
        },
        (Global, "ebgp_policy") => {
            let s = val.ok_or_else(|| format!("lr: {} needs a value", d.key))?;
            if s != "rfc8212" && s != "accept-all" {
                return Err(format!("lr: bad ebgp_policy '{s}' (rfc8212|accept-all)"));
            }
            Ok(("ebgp_policy".into(), toml_str(s)))
        }
        (Global, "soft_reconfig_inbound") => Ok(("soft_reconfig_inbound".into(), bool_val(val)?)),
        // ---- per-peer ----
        (Peer, "add_path") => Ok(("add_path".into(), bool_val(val)?)),
        (Peer, "add_path_max") => Ok(("add_path_max_paths".into(), num_val(val, 1, 255)?)),
        (Peer, "max_prefixes") => Ok(("max_prefixes".into(), num_val(val, 1, u32::MAX as i64)?)),
        (Peer, "max_prefix_action") => {
            let s = val.ok_or_else(|| format!("lr: {} needs a value", d.key))?;
            if !matches!(s, "warn" | "teardown" | "restart") {
                return Err(format!(
                    "lr: bad max_prefix_action '{s}' (warn|teardown|restart)"
                ));
            }
            Ok(("max_prefix_action".into(), toml_str(s)))
        }
        (Peer, "max_prefix_threshold") => {
            Ok(("max_prefix_threshold".into(), num_val(val, 0, 100)?))
        }
        (Peer, "gtsm") => match val {
            None => Ok(("gtsm".into(), "true".into())),
            Some(n) => Ok(("gtsm".into(), num_val(Some(n), 1, 255)?)),
        },
        (Peer, "extended_next_hop") => Ok(("extended_next_hop".into(), bool_val(val)?)),
        (Peer, "allow_local_as") => match val {
            None => Ok(("allow_local_as".into(), "1".into())),
            Some("any") => Ok(("allow_local_as".into(), "\"any\"".into())),
            Some(n) => Ok((
                "allow_local_as".into(),
                num_val(Some(n), 0, u32::MAX as i64)?,
            )),
        },
        (Peer, "local_address") => Ok(("local_address".into(), str_val(val)?)),
        (Peer, "soft_reconfig_inbound") => Ok(("soft_reconfig_inbound".into(), bool_val(val)?)),
        _ => Err(format!(
            "lr: unknown {} directive '{}' (see docs/COMPAT.md for the vocabulary)",
            match scope {
                Global => "global",
                Peer => "peer",
            },
            d.key
        )),
    }
}

/// Apply the list-shaped peer directives that fold into existing
/// `PeerOut` arrays (`mp-family` → `families`, `tcp-ao-key` →
/// `tcp_ao_keys`). Returns an error note when the directive is not
/// list-shaped here or the value is not a known family.
fn fold_peer_list_directive(peer: &mut PeerOut, d: &LrDirective) -> Result<(), String> {
    match d.key.as_str() {
        "mp_family" => {
            let f = d
                .value
                .as_deref()
                .ok_or_else(|| "lr: mp-family needs a family name".to_string())?;
            if f != "ipv4-unicast" && f != "ipv6-unicast" {
                return Err(format!(
                    "lr: unknown mp-family '{f}' (ipv4-unicast|ipv6-unicast)"
                ));
            }
            if !peer.families.iter().any(|x| x == f) {
                peer.families.push(f.to_string());
            }
            Ok(())
        }
        "tcp_ao_key" => {
            let k = d
                .value
                .as_deref()
                .ok_or_else(|| "lr: tcp-ao-key needs ID:SECRET".to_string())?;
            // Fail obviously-broken keys (no id prefix) early.
            if !k.contains(':') {
                return Err(format!("lr: tcp-ao-key '{k}' is not ID:SECRET"));
            }
            peer.tcp_ao_keys.push(k.to_string());
            Ok(())
        }
        _ => Err(format!("lr: directive '{}' not list-shaped", d.key)),
    }
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

    /// `remote-as` combined with other attributes on one line — the
    /// e2e compat test surfaced this hand-written shape, where the
    /// old first-token-only dispatch silently dropped the peer AS.
    #[test]
    fn frr_combined_neighbor_line_keeps_remote_as() {
        let out = translate_frr("router bgp 64512\n neighbor 10.0.0.2 port 1179 remote-as 64513\n");
        assert_eq!(out.peers.len(), 1);
        assert_eq!(out.peers[0].peer_as, Some(64513));
        assert_eq!(out.peers[0].remote.as_deref(), Some("10.0.0.2"));
        assert_eq!(out.peers[0].remote_port.as_deref(), Some("1179"));
    }

    /// FRR dialect defaults: `router bgp` implies FRR's documented
    /// `bgp enforce-first-as` default (on); BIRD keeps lr's default (off).
    #[test]
    fn frr_enforce_first_as_default_is_on() {
        let out = translate_frr("router bgp 64512\n neighbor 10.0.0.2 remote-as 64513\n");
        assert_eq!(out.enforce_first_as, Some(true));
        let bird = translate_bird("router id 10.0.0.1\n");
        assert_eq!(bird.enforce_first_as, None);
    }

    /// Both `key value` and `key = value` directive spellings work —
    /// the latter is the natural TOML-shaped habit.
    #[test]
    fn directives_accept_assignment_form() {
        let mut cfg = crate::daemon_config::DaemonConfig::with_defaults();
        crate::compat::load_config_text(
            "router bgp 64512\n\
             neighbor 10.0.0.2 remote-as 64513\n\
             # lr: graceful_restart = 240\n\
             # lr: install-kernel\n",
            Some(crate::compat::Dialect::Frr),
            None,
            &mut cfg,
        )
        .unwrap();
        assert_eq!(cfg.gr_restart_time, 240);
        assert!(cfg.install_kernel);
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

    // ---- D14.1: BIRD filter translation through the public path ----

    #[test]
    fn bird_named_filter_translates_and_attaches() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;

filter export_only_cust {
    if net ~ [ 10.0.0.0/8{16,24}, 192.0.2.0/24 ] then {
        bgp_local_pref := 200;
        bgp_path.prepend(64512);
        accept;
    }
    reject;
}

protocol bgp uplink {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 {
        import all;
        export filter export_only_cust;
    };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        // The filter body landed as a [[filter]] table and compiled
        // at finalize time (roundtrip would have failed otherwise).
        assert_eq!(cfg.filters.len(), 1);
        assert_eq!(cfg.filters[0].name.as_deref(), Some("export_only_cust"));
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("bgp.local_pref = 200"));
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("bgp.as_path.prepend(64512)"));
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("10.0.0.0/8{16,24}"));
        assert!(!cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("bgp_path"));
        // The peer references it.
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(
            cfg.peers[0].export_filter.as_deref(),
            Some("export_only_cust")
        );
    }

    #[test]
    fn bird_where_expression_becomes_generated_filter() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;
protocol bgp uplink {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 { import where net ~ 10.0.0.0/8; export all; };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.filters.len(), 1);
        assert_eq!(cfg.filters[0].name.as_deref(), Some("bird-import-uplink"));
        // `import where EXPR` = accept iff EXPR.
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .starts_with("if net ~ 10.0.0.0/8 then accept; reject;"));
        assert_eq!(
            cfg.peers[0].import_filter.as_deref(),
            Some("bird-import-uplink")
        );
    }

    #[test]
    fn bird_unfaithful_filter_is_not_attached() {
        // `proto` compares the BIRD instance name — no faithful lr
        // translation exists, so the filter must NOT attach.
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;
filter from_customer {
    if proto = "cust_bgp" then accept;
    reject;
}
protocol bgp cust {
    local as 64512;
    neighbor 192.0.2.9 as 64513;
    ipv4 { import filter from_customer; export all; };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        assert!(cfg.filters.is_empty(), "unfaithful filter must not emit");
        assert!(toml.contains(
            "filter from_customer: filter NOT attached — BIRD route attribute or statement `proto`"
        ));
        assert_eq!(cfg.peers[0].import_filter, None);
    }

    #[test]
    fn bird_roa_table_and_roa_check_translate() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;
roa table roa_v4 {
    roa 198.51.100.0/24 max 24 as 64513;
    roa 203.0.113.0/24 as 65000;
}
filter roa_guard {
    if roa_check(roa_v4) = ROA_INVALID then reject;
    if roa_check(roa_v4) = ROA_UNKNOWN then accept;
    reject;
}
protocol bgp uplink {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 { import filter roa_guard; export all; };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.roas.len(), 2);
        assert_eq!(cfg.roas[0].prefix.as_deref(), Some("198.51.100.0/24"));
        assert_eq!(cfg.roas[0].max_length, Some(24));
        assert_eq!(cfg.roas[0].asn, Some(64513));
        assert_eq!(cfg.roas[1].max_length, None);
        assert_eq!(cfg.roas[1].asn, Some(65000));
        assert_eq!(cfg.filters.len(), 1);
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("roa.state == \"invalid\""));
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("roa.state == \"not-found\""));
        assert!(!cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("roa_check"));
        assert_eq!(cfg.peers[0].import_filter.as_deref(), Some("roa_guard"));
    }

    #[test]
    fn bird_defines_substitute_into_filters() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;
define MY_AS = 64512;
define CUST_NETS = [ 10.0.0.0/8, 192.0.2.0/24 ];
filter tag_cust {
    if net ~ CUST_NETS then {
        bgp_path.prepend(MY_AS);
        accept;
    }
    reject;
}
protocol bgp uplink {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 { export filter tag_cust; import all; };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.filters.len(), 1);
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("bgp.as_path.prepend(64512)"));
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("[ 10.0.0.0/8, 192.0.2.0/24 ]"));
        assert!(!cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("CUST_NETS"));
        assert!(!cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("MY_AS"));
    }

    #[test]
    fn bird_function_used_by_filter_is_embedded() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;
function set_pref(int p) {
    bgp_local_pref := p;
    return true;
}
filter export_up {
    if net ~ 10.0.0.0/8 then {
        set_pref(200);
        accept;
    }
    reject;
}
protocol bgp uplink {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 { export filter export_up; import all; };
}
"#,
        ));
        let cfg = roundtrip(&toml);
        assert_eq!(cfg.filters.len(), 1);
        // The function declaration precedes the body and survives
        // compilation (roundtrip finalizes the filter).
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .starts_with("function set_pref(p)"));
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("set_pref(200);"));
        assert!(cfg.filters[0]
            .body
            .as_deref()
            .unwrap_or("")
            .contains("bgp.local_pref = p;"));
    }

    #[test]
    fn bird_babel_protocol_maps_interfaces() {
        let toml = render(translate_bird(
            r#"
router id 10.0.0.1;
protocol babel babel_core {
    interface "eth0" {
        type wired;
        rxcost 8;
        hello interval 4 s;
        update interval 30 s;
        rtt cost 42;
        rtt min 10 ms;
        rtt max 120 ms;
        check link yes;
    };
    interface "wg*";
    next hop ipv4 192.0.2.1;
    next hop ipv6 2001:db8::1;
}
protocol bgp uplink {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
}
"#,
        ));
        let cfg = roundtrip(&toml);
        // The BGP peer still converts; the Babel interfaces carry over
        // as [[babel.interface]] tables.
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.babel_interfaces.len(), 2);
        let eth0 = &cfg.babel_interfaces[0];
        assert_eq!(eth0.name.as_deref(), Some("eth0"));
        assert_eq!(eth0.kind.as_deref(), Some("wired"));
        assert_eq!(eth0.rxcost, Some(8));
        assert_eq!(eth0.hello_interval_ms, Some(4000));
        assert_eq!(eth0.update_interval_ms, Some(30000));
        assert_eq!(eth0.rtt_cost, Some(42));
        assert_eq!(eth0.rtt_min_us, Some(10_000));
        assert_eq!(eth0.rtt_max_us, Some(120_000));
        assert_eq!(eth0.check_link, Some(true));
        // Protocol-level next hops apply to interfaces without their own.
        assert_eq!(eth0.next_hop_ipv4.as_deref(), Some("192.0.2.1"));
        assert_eq!(eth0.next_hop_ipv6.as_deref(), Some("2001:db8::1"));
        // The bare interface inherits the protocol-level next hops only.
        let wg = &cfg.babel_interfaces[1];
        assert_eq!(wg.name.as_deref(), Some("wg*"));
        assert_eq!(wg.kind, None);
        assert_eq!(wg.next_hop_ipv4.as_deref(), Some("192.0.2.1"));
        // lr runs one protocol per daemon instance — the converter
        // says so instead of silently switching the protocol key.
        assert!(toml.contains("lr runs one protocol per daemon instance"));
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
        // The filter is referenced but never defined in the source —
        // reported, and nothing attaches.
        assert!(toml.contains(
            "# UNMAPPED: export filter export_to_lr: filter NOT attached — filter is not defined"
        ));
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
