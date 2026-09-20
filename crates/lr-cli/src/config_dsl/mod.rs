//! The native `.lr` configuration DSL (ROADMAP-v3 D16 Phase 2,
//! GitHub #18).
//!
//! Layout:
//!
//! - [`lexer`] — tokens for the grammar specified in
//!   `docs/config_dsl_grammar.md`;
//! - [`parser`] — recursive descent that lowers every statement into
//!   [`crate::daemon_config::apply_config_key`], the dispatch the TOML
//!   subset parser also drives, so both frontends share one fail-closed
//!   key schema and one typed IR ([`DaemonConfig`]).
//!
//! The frontend is strict where TOML is tolerant: unknown block names
//! are errors (a brand-new dialect has no legacy files to keep
//! loadable), while the per-key schema — including its fail-closed
//! typo protection — is literally the same code for both frontends.

mod emit;
mod lexer;
mod parser;

use std::path::Path;

use crate::daemon_config::DaemonConfig;

/// Render a finalized-or-raw [`DaemonConfig`] IR into a `.lr`
/// program (the `lr-daemon config to-dsl` backend). See
/// [`emit`] for the determinism / fail-loud / round-trip contract.
pub(crate) fn to_dsl(cfg: &DaemonConfig) -> Result<String, String> {
    emit::to_dsl(cfg)
}

/// Parse `.lr` configuration `text` into `cfg`.
///
/// `source` identifies the file for diagnostics and include
/// resolution: `Some((display_name, path))` for real files, `None`
/// for inline snippets (includes then resolve against the process
/// working directory, which only tests do).
pub(crate) fn parse_dsl_text(
    text: &str,
    source: Option<(&str, &Path)>,
    cfg: &mut DaemonConfig,
) -> Result<(), String> {
    parser::parse_dsl_text(text, source, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_config::DaemonConfig;

    fn parse(text: &str) -> Result<DaemonConfig, String> {
        let mut cfg = DaemonConfig::default();
        parse_dsl_text(text, None, &mut cfg)?;
        Ok(cfg)
    }

    #[test]
    fn parses_the_grammar_doc_example() {
        let cfg = parse(
            r#"
protocol bgp;
bgp {
    local_as 64512;
    peer_as 64513;
    router_id 10.0.0.1;
    peer_addr 192.0.2.2:179;
    local_address 192.0.2.1;
    hold_time 90s;
    graceful_restart_time 2m;
    networks [203.0.113.0/24, 198.51.100.0/24];
    install_kernel true;
}
"#,
        )
        .unwrap();
        assert_eq!(cfg.protocol, "bgp");
        assert_eq!(cfg.local_as, 64512);
        assert_eq!(cfg.peer_as, 64513);
        assert_eq!(cfg.router_id, "10.0.0.1");
        assert_eq!(cfg.peer_addr.as_deref(), Some("192.0.2.2:179"));
        assert_eq!(cfg.local_address.as_deref(), Some("192.0.2.1"));
        assert_eq!(cfg.hold_time, 90);
        assert_eq!(cfg.gr_restart_time, 120);
        assert_eq!(cfg.networks, vec!["203.0.113.0/24", "198.51.100.0/24"]);
        assert!(cfg.install_kernel);
    }

    #[test]
    fn parses_policy_bank_and_peer_identity() {
        let cfg = parse(
            r#"
peer "core-1" {
    remote 192.0.2.2:179;
    peer_as 65010;
    hold_time 30s;
    max_prefixes 100k;
}
prefix-list customer-space {
    prefix 203.0.113.0/24;
}
route-map to-customer {
    entry 10;
    match_prefix customer-space;
    permit true;
}
"#,
        )
        .unwrap();
        assert!(cfg.explicit_peers);
        assert_eq!(cfg.peers.len(), 1);
        let peer = &cfg.peers[0];
        assert_eq!(peer.name.as_deref(), Some("core-1"));
        assert_eq!(peer.remote.as_deref(), Some("192.0.2.2:179"));
        assert_eq!(peer.peer_as, 65010);
        assert_eq!(peer.hold_time, Some(30));
        assert_eq!(peer.max_prefixes, Some(100_000));
        assert_eq!(cfg.prefix_lists.len(), 1);
        assert_eq!(cfg.prefix_lists[0].name, "customer-space");
        assert_eq!(cfg.route_maps.len(), 1);
        assert_eq!(cfg.route_maps[0].entry, 10);
    }

    #[test]
    fn filter_body_is_verbatim_between_braces() {
        let body = "\n    if net ~ [10.0.0.0/8+] then accept;\n    # brace in comment: }\n    else reject;\n";
        let text = format!("filter customer-in {{{body}}}");
        let cfg = parse(&text).unwrap();
        assert_eq!(cfg.filters.len(), 1);
        assert_eq!(cfg.filters[0].name.as_deref(), Some("customer-in"));
        assert_eq!(cfg.filters[0].body.as_deref(), Some(body));
    }

    #[test]
    fn filter_body_survives_nested_braces_and_strings() {
        let body = "\n    if proto = \"weird } brace\" then accept; # } too\n";
        let text = format!("filter f{{{body}}}");
        let cfg = parse(&text).unwrap();
        assert_eq!(cfg.filters[0].body.as_deref(), Some(body));
    }

    #[test]
    fn unit_suffixes_expand_by_key() {
        let cfg = parse(
            r#"
bgp {
    hold_time 90s;
    graceful_restart_time 2m;
    llgr_stale_time 1h;
    bfd_min_rx_ms 300ms;
    max_prefixes 100k;
    add_path_max_paths 2M;
}
peer "p" {
    hold_time 1m;
    max_prefixes 1k;
}
"#,
        )
        .unwrap();
        assert_eq!(cfg.hold_time, 90);
        assert_eq!(cfg.gr_restart_time, 120);
        assert_eq!(cfg.llgr_stale_time, 3600);
        assert_eq!(cfg.bfd_min_rx_ms, 300);
        assert_eq!(cfg.max_prefixes, Some(100_000));
        assert_eq!(cfg.add_path_max_paths, 2_000_000);
        assert_eq!(cfg.peers[0].hold_time, Some(60));
        assert_eq!(cfg.peers[0].max_prefixes, Some(1000));
    }

    #[test]
    fn unit_suffixes_are_whitelisted_per_key() {
        // max_prefixes takes k/M — not seconds.
        let err = parse("bgp { max_prefixes 90s; }").unwrap_err();
        assert!(err.contains("unit not valid"), "{err}");
        // hold_time takes seconds — not k.
        let err = parse("bgp { hold_time 5k; }").unwrap_err();
        assert!(err.contains("unit not valid"), "{err}");
        // A non-duration key refuses suffixes entirely.
        let err = parse("bgp { router_id 10s; }").unwrap_err();
        assert!(err.contains("does not take a unit suffix"), "{err}");
    }

    #[test]
    fn hello_interval_units_differ_per_section() {
        let cfg = parse(
            r#"
ospf {
    hello_interval 10s;
    interface "eth0" {
        hello_interval 5s;
    }
}
babel {
    interface "eth1" {
        hello_interval 4s;
        rtt_min 5ms;
    }
}
"#,
        )
        .unwrap();
        assert_eq!(cfg.ospf_hello_interval, 10);
        assert_eq!(cfg.ospf_interfaces[0].hello_interval, Some(5));
        // Babel interface hello_interval is milliseconds (RFC 8966).
        assert_eq!(cfg.babel_interfaces[0].hello_interval_ms, Some(4000));
        assert_eq!(cfg.babel_interfaces[0].rtt_min_us, Some(5000));
    }

    #[test]
    fn unknown_blocks_fail_closed() {
        let err = parse("mystery { key 1; }").unwrap_err();
        assert!(err.contains("unknown block 'mystery'"), "{err}");
        // Sub-blocks are parent-scoped: rpki lives under bgp only.
        let err = parse("ospf { rpki { cache \"x\"; } }").unwrap_err();
        assert!(err.contains("not a valid block inside 'ospf'"), "{err}");
        // Top-level blocks cannot nest arbitrarily.
        let err = parse("peer \"p\" { area 1 { } }").unwrap_err();
        assert!(err.contains("not a valid block inside 'peer'"), "{err}");
    }

    #[test]
    fn unknown_key_posture_matches_the_toml_frontend() {
        // Protocol/policy sections fail closed (typo protection).
        let err = parse("ospf { hold_time_typo 30; }").unwrap_err();
        assert!(err.contains("unknown [ospf] key"), "{err}");
        // [bgp] and top level tolerate unknown keys with a warning
        // (forward compatibility), exactly like the TOML frontend.
        let cfg = parse("bgp { hold_time_typo 30; }").unwrap();
        assert!(cfg
            .warnings
            .iter()
            .any(|w| w.contains("unknown key 'bgp.hold_time_typo'")),);
        let cfg = parse("peer \"p\" { as_not_number 65010; }").unwrap();
        assert!(cfg.warnings.iter().any(|w| w.contains("unknown peer key")),);
    }

    #[test]
    fn syntax_errors_carry_positions() {
        let err = parse("bgp {\n    hold_time 90\n}").unwrap_err();
        assert!(err.starts_with("inline:"), "{err}");
        assert!(err.contains("expected ';'"), "{err}");
        let err = parse("bgp { hold_time 90; ").unwrap_err();
        assert!(err.contains("unexpected end of file inside 'bgp'"), "{err}");
        let err = parse("filter f { if net then accept;").unwrap_err();
        assert!(err.contains("unterminated filter body"), "{err}");
    }

    #[test]
    fn repeated_blocks_merge_like_repeated_toml_tables() {
        let cfg = parse(
            r#"
bgp { hold_time 60s; }
bgp { hold_time 90s; peer_as 65000; }
"#,
        )
        .unwrap();
        assert_eq!(cfg.hold_time, 90);
        assert_eq!(cfg.peer_as, 65000);
    }

    #[test]
    fn includes_splice_into_the_current_context() {
        let dir = std::env::temp_dir().join(format!("lr-dsl-include-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("snippet.lr"), "hold_time 45s;\npeer_as 65001;\n").unwrap();
        let main = dir.join("main.lr");
        std::fs::write(&main, "bgp {\n  include \"snippet.lr\";\n}\n").unwrap();
        let text = std::fs::read_to_string(&main).unwrap();
        let mut cfg = DaemonConfig::default();
        parse_dsl_text(&text, Some(("main.lr", &main)), &mut cfg).unwrap();
        assert_eq!(cfg.hold_time, 45);
        assert_eq!(cfg.peer_as, 65001);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn include_cycles_fail_closed() {
        let dir = std::env::temp_dir().join(format!("lr-dsl-cycle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.lr"), "include \"b.lr\";\n").unwrap();
        std::fs::write(dir.join("b.lr"), "include \"a.lr\";\n").unwrap();
        let main = dir.join("a.lr");
        let text = std::fs::read_to_string(&main).unwrap();
        let mut cfg = DaemonConfig::default();
        let err = parse_dsl_text(&text, Some(("a.lr", &main)), &mut cfg).unwrap_err();
        assert!(err.contains("include cycle"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn include_diagnostics_name_the_included_file() {
        let dir = std::env::temp_dir().join(format!("lr-dsl-diag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bad.lr"), "mystery { }\n").unwrap();
        let main = dir.join("main.lr");
        std::fs::write(&main, "include \"bad.lr\";\n").unwrap();
        let text = std::fs::read_to_string(&main).unwrap();
        let mut cfg = DaemonConfig::default();
        let err = parse_dsl_text(&text, Some(("main.lr", &main)), &mut cfg).unwrap_err();
        assert!(err.contains("bad.lr"), "{err}");
        assert!(err.contains("unknown block"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn glob_include_splices_every_match_in_sorted_order() {
        let dir = std::env::temp_dir().join(format!("lr-dsl-glob-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Three peer files: a, b, c. The glob `peers/*.lr` must
        // splice all three in lexicographic order so the peer list
        // ends up deterministic regardless of filesystem readdir
        // order (readdir order is unspecified on most platforms).
        let peers = dir.join("peers");
        std::fs::create_dir_all(&peers).unwrap();
        std::fs::write(peers.join("a.lr"), "peer \"a\" { remote 192.0.2.1:179; }\n").unwrap();
        std::fs::write(peers.join("b.lr"), "peer \"b\" { remote 192.0.2.2:179; }\n").unwrap();
        std::fs::write(peers.join("c.lr"), "peer \"c\" { remote 192.0.2.3:179; }\n").unwrap();
        // A non-matching file (wrong extension) must be ignored.
        std::fs::write(
            peers.join("d.txt"),
            "peer \"d\" { remote 192.0.2.4:179; }\n",
        )
        .unwrap();
        let main = dir.join("main.lr");
        std::fs::write(&main, "include \"peers/*.lr\";\n").unwrap();
        let text = std::fs::read_to_string(&main).unwrap();
        let mut cfg = DaemonConfig::default();
        parse_dsl_text(&text, Some(("main.lr", &main)), &mut cfg).unwrap();
        assert_eq!(cfg.peers.len(), 3, "expected 3 peers, got {:?}", cfg.peers);
        // Sorted lexicographically: a, b, c.
        assert_eq!(cfg.peers[0].name.as_deref(), Some("a"));
        assert_eq!(cfg.peers[1].name.as_deref(), Some("b"));
        assert_eq!(cfg.peers[2].name.as_deref(), Some("c"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn glob_include_with_no_matches_warns_but_does_not_fail() {
        let dir = std::env::temp_dir().join(format!("lr-dsl-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let peers = dir.join("peers");
        std::fs::create_dir_all(&peers).unwrap();
        let main = dir.join("main.lr");
        std::fs::write(&main, "include \"peers/*.lr\";\n").unwrap();
        let text = std::fs::read_to_string(&main).unwrap();
        let mut cfg = DaemonConfig::default();
        parse_dsl_text(&text, Some(("main.lr", &main)), &mut cfg).unwrap();
        // No peers were loaded — the daemon should still start.
        assert!(cfg.peers.is_empty(), "no peers should be loaded");
        // The warning surfaces through the config's warning channel.
        assert!(
            cfg.warnings.iter().any(|w| w.contains("matched 0 files")),
            "warnings: {:?}",
            cfg.warnings
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn glob_include_in_a_subblock_splices_into_the_block() {
        // `include` splices into the current context (BIRD semantics);
        // a glob include inside a `bgp { ... }` block contributes its
        // files' contents to that block.
        let dir = std::env::temp_dir().join(format!("lr-dsl-glob-bg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fragments = dir.join("fragments");
        std::fs::create_dir_all(&fragments).unwrap();
        std::fs::write(fragments.join("a.lr"), "local_as 64512;\n").unwrap();
        std::fs::write(fragments.join("b.lr"), "peer_as 64513;\n").unwrap();
        let main = dir.join("main.lr");
        std::fs::write(&main, "bgp {\n  include \"fragments/*.lr\";\n}\n").unwrap();
        let text = std::fs::read_to_string(&main).unwrap();
        let mut cfg = DaemonConfig::default();
        parse_dsl_text(&text, Some(("main.lr", &main)), &mut cfg).unwrap();
        assert_eq!(cfg.local_as, 64512);
        assert_eq!(cfg.peer_as, 64513);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn peer_templates_take_their_name_from_the_header() {
        let cfg = parse(
            r#"
peer-template "rr-client" {
    default_ipv4_unicast true;
    hold_time 30s;
}
peer "edge-1" {
    extends rr-client;
    remote 192.0.2.9:179;
}
"#,
        )
        .unwrap();
        assert!(cfg.peer_templates.contains_key("rr-client"));
        assert_eq!(cfg.peers[0].extends.as_deref(), Some("rr-client"));
    }

    #[test]
    fn static_route_blocks_parse_in_dsl() {
        let cfg = parse(
            r#"
static {
    route "203.0.113.0/24" {
        next_hop "198.51.100.1";
        metric 10;
    }
    route "10.0.0.0/8" {
        next_hop "blackhole";
    }
}
"#,
        )
        .unwrap();
        assert_eq!(cfg.static_routes.len(), 2);
        assert_eq!(
            cfg.static_routes[0].prefix.as_deref(),
            Some("203.0.113.0/24")
        );
        assert_eq!(
            cfg.static_routes[0].next_hop.as_deref(),
            Some("198.51.100.1")
        );
        assert_eq!(cfg.static_routes[0].metric, Some(10));
        // The blackhole keyword is normalised to None at parse time.
        assert_eq!(cfg.static_routes[1].next_hop, None);
    }
}
