use super::*;

#[test]
fn inline_comments_strip_outside_strings_only() {
    assert_eq!(strip_inline_comment("entry = 20 # trailing"), "entry = 20 ");
    assert_eq!(strip_inline_comment("[bgp] # header comment"), "[bgp] ");
    assert_eq!(
        strip_inline_comment("md5_key = \"a#b\""),
        "md5_key = \"a#b\""
    );
    // An escaped quote keeps the string open, so the hash stays data.
    assert_eq!(
        strip_inline_comment("name = \"a\\\"#b\" # real comment"),
        "name = \"a\\\"#b\" "
    );
    assert_eq!(strip_inline_comment("no comment here"), "no comment here");
}

#[test]
fn inline_comment_on_value_line_parses() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
            "[[route-map]]\nname = \"rm\" \nentry = 20      # everything else stays internal\npermit = false\n",
            &mut cfg,
        )
        .unwrap();
    assert_eq!(cfg.route_maps.len(), 1);
    assert_eq!(cfg.route_maps[0].entry, 20);
    assert_eq!(cfg.route_maps[0].permit, Some(false));
}

// --------------------------------------------------------------
// Issue #18 Phase 1 — the IR-equality golden tests. A TOML config
// and its future DSL translation are semantically equivalent iff
// they parse to equal `DaemonConfig`s; these tests pin the
// equality contract the DSL migration (Phase 2+) is validated
// against, plus the shipped template as the standing golden file.
// --------------------------------------------------------------

/// Parsing is a pure function of the text: the same file produces
/// the same IR on every parse, so a golden IR comparison is stable
/// across runs and processes.
#[test]
fn ir_parse_is_deterministic() {
    let text = include_str!("../../../templates/daemon.toml");
    let mut first = DaemonConfig::default();
    let mut second = DaemonConfig::default();
    parse_toml_subset(text, &mut first).unwrap();
    parse_toml_subset(text, &mut second).unwrap();
    first.finalize().unwrap();
    second.finalize().unwrap();
    assert_eq!(first, second);
}

/// Frontend freedom does not change the IR: the two spellings the
/// TOML subset defines for the top-level protocol set key
/// (`protocol = "a,b"` mirroring the CLI, `protocols = ["a", "b"]`
/// as the native list) and key order inside a table (TOML tables
/// are unordered mappings) resolve to equal IRs.
#[test]
fn ir_semantically_equal_variants_are_equal() {
    let mut string_form = DaemonConfig::with_defaults();
    parse_toml_subset("protocol = \"bgp,ospf\"\n", &mut string_form).unwrap();
    assert!(
        string_form.warnings.is_empty(),
        "warnings: {:?}",
        string_form.warnings
    );
    let mut list_form = DaemonConfig::with_defaults();
    parse_toml_subset("protocols = [\"bgp\", \"ospf\"]\n", &mut list_form).unwrap();
    assert_eq!(string_form, list_form);

    let mut forward = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp]\nlocal_as = 65000\npeer_as = 65001\nrouter_id = \"10.0.0.1\"\n",
        &mut forward,
    )
    .unwrap();
    let mut reversed = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp]\nrouter_id = \"10.0.0.1\"\npeer_as = 65001\nlocal_as = 65000\n",
        &mut reversed,
    )
    .unwrap();
    assert_eq!(forward, reversed);
}

/// Equality is content, not shape: one differing field makes the
/// IRs unequal (guards against a PartialEq that accidentally
/// compares equal), while the order of `[[peer]]` entries is
/// semantic — peers are matched and listed by index, so a
/// reordering is a different configuration.
#[test]
fn ir_distinguishes_different_configs() {
    let mut a = DaemonConfig::with_defaults();
    parse_toml_subset("[bgp]\nlocal_as = 65000\n", &mut a).unwrap();
    let mut b = DaemonConfig::with_defaults();
    parse_toml_subset("[bgp]\nlocal_as = 65001\n", &mut b).unwrap();
    assert_ne!(a, b);

    let mut first = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\npeer_as = 10\n\n\
             [[peer]]\nremote = \"192.0.2.3:179\"\npeer_as = 11\n",
        &mut first,
    )
    .unwrap();
    let mut swapped = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\n\
             [[peer]]\nremote = \"192.0.2.3:179\"\npeer_as = 11\n\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\npeer_as = 10\n",
        &mut swapped,
    )
    .unwrap();
    assert_ne!(first, swapped);
}

/// The shipped template is the standing golden file: a structured
/// walk of the IR it must resolve to. Doubles as the fast
/// unit-level guard for the schema the template documents.
#[test]
fn shipped_template_resolves_to_expected_ir() {
    let text = include_str!("../../../templates/daemon.toml");
    let mut cfg = DaemonConfig::default();
    parse_toml_subset(text, &mut cfg).unwrap();
    cfg.finalize().unwrap();

    assert_eq!(cfg.local_as, 64512);
    assert_eq!(cfg.peer_as, 64513);
    assert_eq!(cfg.router_id, "10.0.0.1");
    assert_eq!(cfg.hold_time, 90);
    assert_eq!(cfg.gr_restart_time, 120);
    assert_eq!(cfg.local_address.as_deref(), Some("192.0.2.1"));
    assert_eq!(cfg.networks, vec!["203.0.113.0/24".to_string()]);
    // The legacy single-peer shape: no [[peer]] tables, so the
    // peer_addr key synthesises one peer at finalize.
    assert!(!cfg.explicit_peers);
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].remote.as_deref(), Some("192.0.2.2:179"));
    // The policy bank: one prefix-list feeding two route-map
    // entries of the same map name.
    assert_eq!(cfg.prefix_lists.len(), 1);
    assert_eq!(cfg.prefix_lists[0].name, "customer-space");
    assert_eq!(cfg.route_maps.len(), 2);
    assert!(cfg.route_maps.iter().all(|rm| rm.name == "to-customer"));
    assert_eq!(cfg.route_maps[0].entry, 10);
    assert_eq!(cfg.route_maps[0].permit, Some(true));
    assert_eq!(cfg.route_maps[1].entry, 20);
    assert_eq!(cfg.route_maps[1].permit, Some(false));
    // Nothing in the shipped template triggers a warning.
    assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
}

/// The DSL-first twin (`templates/daemon.lr`, Phase 3) walks the
/// same golden IR through the native-DSL frontend: the .lr file
/// documents the identical active configuration, so both templates
/// must resolve to the same warnings-free `DaemonConfig`.
#[test]
fn shipped_lr_template_resolves_to_expected_ir() {
    let text = include_str!("../../../templates/daemon.lr");
    let mut cfg = DaemonConfig::default();
    crate::config_dsl::parse_dsl_text(text, None, &mut cfg).unwrap();
    cfg.finalize().unwrap();

    assert_eq!(cfg.local_as, 64512);
    assert_eq!(cfg.peer_as, 64513);
    assert_eq!(cfg.router_id, "10.0.0.1");
    assert_eq!(cfg.hold_time, 90);
    assert_eq!(cfg.gr_restart_time, 120);
    assert_eq!(cfg.local_address.as_deref(), Some("192.0.2.1"));
    assert_eq!(cfg.networks, vec!["203.0.113.0/24".to_string()]);
    // Unit suffixes expanded: `hold_time 90s` / `graceful_restart_time
    // 120s` carry the same numbers as the TOML template's raw fields.
    assert!(!cfg.explicit_peers);
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].remote.as_deref(), Some("192.0.2.2:179"));
    assert_eq!(cfg.prefix_lists.len(), 1);
    assert_eq!(cfg.prefix_lists[0].name, "customer-space");
    assert_eq!(cfg.route_maps.len(), 2);
    assert!(cfg.route_maps.iter().all(|rm| rm.name == "to-customer"));
    assert_eq!(cfg.route_maps[0].entry, 10);
    assert_eq!(cfg.route_maps[0].permit, Some(true));
    assert_eq!(cfg.route_maps[1].entry, 20);
    assert_eq!(cfg.route_maps[1].permit, Some(false));
    assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
}

/// The golden cross-frontend property, pinned on the shipped pair:
/// `templates/daemon.lr` documents exactly the configuration
/// `templates/daemon.toml` carries, so the two frontends must
/// produce equal IRs — before and after finalize. This is the
/// standing guarantee that makes the template pair a safe
/// migration target for `config to-dsl` users.
#[test]
fn shipped_templates_match_across_frontends() {
    let toml_text = include_str!("../../../templates/daemon.toml");
    let lr_text = include_str!("../../../templates/daemon.lr");

    let mut toml_cfg = DaemonConfig::default();
    parse_toml_subset(toml_text, &mut toml_cfg).unwrap();
    let mut lr_cfg = DaemonConfig::default();
    crate::config_dsl::parse_dsl_text(lr_text, None, &mut lr_cfg).unwrap();
    assert_eq!(toml_cfg, lr_cfg, "pre-finalize IRs must be equal");
    assert!(toml_cfg.warnings.is_empty());
    assert!(lr_cfg.warnings.is_empty());

    toml_cfg.finalize().unwrap();
    lr_cfg.finalize().unwrap();
    assert_eq!(toml_cfg, lr_cfg, "post-finalize IRs must be equal");
}

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

/// `max_prefix_restart_time` parses at the `[bgp]` global scope and the
/// `[[peer]]` per-peer scope, and a peer without it inherits the global
/// value (FRR `bgp maximum-prefix restart <secs>` / BIRD `restart time`).
#[test]
fn max_prefix_restart_time_parses_and_inherits() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp]\nlocal_as = 65000\npeer_as = 65001\nrouter_id = \"10.0.0.1\"\n\
             max_prefix_restart_time = 30\n\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\nmax_prefix_restart_time = 60\n\n\
             [[peer]]\nremote = \"192.0.2.3:179\"\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize().unwrap();
    assert_eq!(cfg.max_prefix_restart_time, 30, "global [bgp] key");
    assert_eq!(
        cfg.peers[0].max_prefix_restart_time,
        Some(60),
        "per-peer override"
    );
    // The peer without an explicit value leaves the slot `None`; the
    // daemon builder resolves it against the global default at session
    // build time (`p.max_prefix_restart_time.unwrap_or(g.…)`), the same
    // contract as `max_prefix_threshold`.
    assert_eq!(
        cfg.peers[1].max_prefix_restart_time, None,
        "unset per-peer slot stays None until the daemon builder resolves it"
    );
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
        "[[vendor]]\nfoo = 1\n[mystery]\nlevel = \"debug\"\n",
        &mut cfg,
    )
    .unwrap();
    assert_eq!(cfg.warnings.len(), 4, "{:?}", cfg.warnings);
    assert!(cfg.warnings[0].contains("unknown table [[vendor]]"));
    // Keys inside an unknown array table warn too.
    assert!(cfg.warnings[1].contains("unknown key 'unknown-array.vendor.foo'"));
    assert!(cfg.warnings[2].contains("unknown section [mystery]"));
    // Keys inside an unknown section warn as unknown keys.
    assert!(cfg.warnings[3].contains("unknown key 'mystery.level'"));
}

#[test]
fn logging_section_parses_keys() {
    // The `[logging]` section is a recognised first-class block:
    // its keys land in `cfg.logging`, not in the warnings vector.
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[logging]\nlevel = \"debug\"\nformat = \"json\"\n\
             color = \"on\"\nfile = \"/tmp/lr.log\"\n\
             targets = [\"bgp=trace\", \"ospf=warn\"]\n",
        &mut cfg,
    )
    .unwrap();
    assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    assert_eq!(cfg.logging.level, "debug");
    assert_eq!(cfg.logging.format, "json");
    assert_eq!(cfg.logging.color, "on");
    assert_eq!(cfg.logging.file.as_deref(), Some("/tmp/lr.log"));
    assert_eq!(cfg.logging.targets, vec!["bgp=trace", "ospf=warn"]);
    // Finalise converts to the runtime form without errors.
    let rt = cfg.logging.finalise().unwrap();
    assert_eq!(rt.default_level, crate::daemon_logger::Severity::Debug);
    assert_eq!(rt.format, crate::daemon_logger::LogFormat::Json);
    assert_eq!(rt.color, crate::daemon_logger::ColorMode::On);
    assert_eq!(
        rt.level_for(crate::daemon_logger::Component::Bgp),
        crate::daemon_logger::Severity::Trace
    );
}

#[test]
fn logging_section_fail_closed_on_typo() {
    // A typo'd level is a hard error, not a warning.
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset("[logging]\nlevel = \"verbose\"\n", &mut cfg).unwrap_err();
    assert!(err.contains("bad logging level"), "{err}");

    // A typo'd format is a hard error too.
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset("[logging]\nformat = \"xml\"\n", &mut cfg).unwrap_err();
    assert!(err.contains("bad logging format"), "{err}");

    // An unknown key in [logging] fails closed (typo protection).
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset("[logging]\nverbosity = 5\n", &mut cfg).unwrap_err();
    assert!(err.contains("unknown [logging] key"), "{err}");
}

#[test]
fn safety_section_parses_keys() {
    // The `[safety]` section is a recognised first-class block
    // (issue #46). Its keys land in `cfg.safety`, not in the
    // warnings vector.
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[safety]\n\
             enabled = true\n\
             reject_as_loop = false\n\
             max_as_path_loops = 5\n\
             reject_martian_v4 = false\n\
             as_loop_exceptions = [\"65000\", \"65001\"]\n\
             martian_exceptions = [\"169.254.0.0/16\"]\n",
        &mut cfg,
    )
    .unwrap();
    assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    assert_eq!(cfg.safety.enabled, Some(true));
    assert_eq!(cfg.safety.reject_as_loop, Some(false));
    assert_eq!(cfg.safety.max_as_path_loops, Some(5));
    assert_eq!(cfg.safety.reject_martian_v4, Some(false));
    assert_eq!(cfg.safety.as_loop_exceptions, vec!["65000", "65001"]);
    assert_eq!(cfg.safety.martian_exceptions, vec!["169.254.0.0/16"]);
    // Finalise converts to the runtime form without errors.
    let rt = cfg.safety.finalise().unwrap();
    assert!(rt.enabled);
    assert!(!rt.reject_as_loop);
    assert_eq!(rt.max_as_path_loops, 5);
    assert!(!rt.reject_martian_v4);
    assert!(rt.reject_martian_v6); // untouched — still the default
    assert_eq!(rt.as_loop_exceptions.len(), 2);
    assert_eq!(rt.as_loop_exceptions[0].0, 65000);
    assert_eq!(rt.martian_exceptions.len(), 1);
}

#[test]
fn safety_section_fail_closed_on_typo() {
    // An unknown key in [safety] fails closed.
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset("[safety]\nverbosity = 5\n", &mut cfg).unwrap_err();
    assert!(err.contains("unknown [safety] key"), "{err}");

    // A bad boolean fails.
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset("[safety]\nenabled = maybe\n", &mut cfg).unwrap_err();
    assert!(err.contains("bad enabled"), "{err}");

    // A non-numeric max_as_path_loops fails.
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset("[safety]\nmax_as_path_loops = \"lots\"\n", &mut cfg).unwrap_err();
    assert!(err.contains("bad max_as_path_loops"), "{err}");

    // Finalise rejects a bad ASN in as_loop_exceptions.
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[safety]\nas_loop_exceptions = [\"not-a-number\"]\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.safety.finalise().unwrap_err();
    assert!(err.contains("bad safety as_loop_exceptions"), "{err}");

    // Finalise rejects a bad CIDR in martian_exceptions.
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[safety]\nmartian_exceptions = [\"not-a-prefix\"]\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.safety.finalise().unwrap_err();
    assert!(err.contains("bad safety martian_exceptions"), "{err}");
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
    // The RFC 8362 Extended-LSA knob is OSPFv3-only too.
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    parse_toml_subset("[ospf]\nextended_lsas = true\n", &mut cfg).unwrap();
    let err = cfg.finalize().unwrap_err();
    assert!(err.contains("OSPFv3"), "fail-closed error: {err}");
}

#[test]
fn ospf_extended_lsas_parses_under_v3() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    parse_toml_subset("[ospf]\nversion = \"v3\"\nextended_lsas = true\n", &mut cfg).unwrap();
    cfg.finalize().unwrap();
    assert!(cfg.ospf_extended_lsas);
    // Default off — a v3 config without the knob stays legacy.
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    parse_toml_subset("[ospf]\nversion = \"v3\"\n", &mut cfg).unwrap();
    cfg.finalize().unwrap();
    assert!(!cfg.ospf_extended_lsas);
}

#[test]
fn ospf_srv6_end_x_validation_is_fail_closed() {
    let case = |toml: &str| {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        parse_toml_subset(toml, &mut cfg).unwrap();
        cfg.finalize().unwrap_err()
    };
    // §9 containment: a SID outside every locator is refused.
    let err = case(
        "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.interface]]\nname = \"eth0\"\nsrv6_end_x = \"2001:db8:dead::1\"\n",
    );
    assert!(err.contains("outside"), "fail-closed error: {err}");
    // §9.2: the LAN form needs a broadcast segment, at most /96
    // (the neighbor Router-ID fills the low 32 bits), and a base
    // inside a locator.
    let err = case(
        "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.interface]]\nname = \"eth0\"\nsrv6_end_x_lan = \"2001:db8:a:1:ffff::/96\"\n",
    );
    assert!(
        err.contains("needs network_type \"broadcast\""),
        "fail-closed error: {err}"
    );
    let err = case(
        "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.interface]]\nname = \"eth0\"\nnetwork_type = \"broadcast\"\n\
             srv6_end_x_lan = \"2001:db8:a:1:ffff::/112\"\n",
    );
    assert!(err.contains("at most /96"), "fail-closed error: {err}");
    let err = case(
        "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.interface]]\nname = \"eth0\"\nnetwork_type = \"broadcast\"\n\
             srv6_end_x_lan = \"2001:db8:dead:ffff::/96\"\n",
    );
    assert!(err.contains("outside"), "fail-closed error: {err}");
    let err = case(
        "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.interface]]\nname = \"eth0\"\nnetwork_type = \"broadcast\"\n\
             srv6_end_x_lan = \"10.0.0.0/8\"\n",
    );
    assert!(
        err.contains("must be an IPv6 prefix"),
        "fail-closed error: {err}"
    );
    // A non-IPv6 SID is refused at the parse site.
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    let err = parse_toml_subset(
        "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.interface]]\nname = \"eth0\"\nsrv6_end_x = \"10.0.0.1\"\n",
        &mut cfg,
    )
    .unwrap_err();
    assert!(err.contains("bad srv6_end_x"), "fail-closed error: {err}");
    // A non-prefix LAN base is refused at the parse site.
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    let err = parse_toml_subset(
        "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.interface]]\nname = \"eth0\"\nnetwork_type = \"broadcast\"\n\
             srv6_end_x_lan = \"not-a-prefix\"\n",
        &mut cfg,
    )
    .unwrap_err();
    assert!(
        err.contains("bad srv6_end_x_lan"),
        "fail-closed error: {err}"
    );
    // A SID inside the locator passes — on p2p (the §9.1 p2p
    // adjacency) and on broadcast (the §9.1 DR adjacency) alike,
    // and the LAN base beside it.
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    parse_toml_subset(
        "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.interface]]\nname = \"lo\"\nsrv6_end_x = \"2001:db8:a:1::100\"\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize().unwrap();
    assert_eq!(
        cfg.ospf_interfaces[0].srv6_end_x.as_deref(),
        Some("2001:db8:a:1::100")
    );
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    parse_toml_subset(
        "[ospf]\nversion = \"v3\"\n\n\
             [[ospf.srv6_locator]]\nprefix = \"2001:db8:a:1::/48\"\n\n\
             [[ospf.interface]]\nname = \"eth0\"\nnetwork_type = \"broadcast\"\n\
             srv6_end_x = \"2001:db8:a:1::100\"\n\
             srv6_end_x_lan = \"2001:db8:a:1:ffff::/96\"\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize().unwrap();
    assert_eq!(
        cfg.ospf_interfaces[0].srv6_end_x_lan.as_deref(),
        Some("2001:db8:a:1:ffff::/96")
    );
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
    let err = case("[ospf]\nversion = \"v3\"\n\n[[ospf.srv6_locator]]\nprefix = \"10.0.0.0/8\"\n");
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

/// `[ospf] area = N` is the config-file counterpart of `--ospf-area`:
/// the default area an interface without an explicit one falls back
/// to (issue #41 §5). It feeds `cfg.ospf_area`, the same field the
/// CLI flag writes, so the two frontends cannot drift.
#[test]
fn ospf_section_area_key_sets_default_area() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    parse_toml_subset(
        "[ospf]\narea = 1\n\n\
             [[ospf.area]]\nid = 1\n\n\
             [[ospf.interface]]\nname = \"eth0\"\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize().unwrap();
    assert_eq!(cfg.ospf_area, 1, "the [ospf] area key feeds the default");
    assert_eq!(
        cfg.ospf_interfaces[0].area,
        Some(1),
        "an interface without an explicit area picks the [ospf] default"
    );
    assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
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
fn graceful_shutdown_default_on_and_parses() {
    // RFC 8326 honouring is a SHOULD on the receive side, so the
    // daemon ships it enabled; `[bgp] graceful_shutdown = false`
    // opts out of all three surfaces (sender hook, receiver hook,
    // best-path step).
    assert!(DaemonConfig::with_defaults().graceful_shutdown);
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp]\nlocal_as = 1\npeer_as = 2\nrouter_id = \"10.0.0.1\"\n\
             graceful_shutdown = false\n",
        &mut cfg,
    )
    .unwrap();
    assert!(!cfg.graceful_shutdown);
}

#[test]
fn graceful_shutdown_per_peer_override_parses_and_inherits() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp]\nlocal_as = 65000\npeer_as = 65001\nrouter_id = \"10.0.0.1\"\n\n\
             [[peer]]\nremote = \"192.0.2.2:179\"\ngraceful_shutdown = false\n\n\
             [[peer]]\nremote = \"192.0.2.3:179\"\ngraceful_shutdown = true\n\n\
             [[peer]]\nremote = \"192.0.2.4:179\"\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize().unwrap();
    assert_eq!(cfg.peers[0].graceful_shutdown, Some(false));
    assert_eq!(cfg.peers[1].graceful_shutdown, Some(true));
    // Inheritance: the third peer carries no override (None).
    assert_eq!(cfg.peers[2].graceful_shutdown, None);
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
fn babel_key_interface_scope_parses() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[[babel.interface]]\nname = \"veth*\"\n\
             [[babel.interface]]\nname = \"lan*\"\n\
             [[babel.key]]\nsecret = \"global\"\n\
             [[babel.key]]\nsecret = \"link\"\ninterface = \"veth*\"\n\
             [[babel.key]]\nsecret = \"lan\"\nalgorithm = \"blake2s\"\ninterface = \"lan0\"\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize().unwrap();
    assert_eq!(cfg.babel_keys.len(), 3);
    assert_eq!(cfg.babel_keys[0].interface, None);
    assert_eq!(cfg.babel_keys[1].interface.as_deref(), Some("veth*"));
    // A literal interface name is a valid (wildcard-free) pattern.
    assert_eq!(cfg.babel_keys[2].interface.as_deref(), Some("lan0"));
}

#[test]
fn babel_key_interface_scope_rejects_bad_pattern() {
    // TOML `interface = "eth\"` decodes to a pattern with a dangling
    // backslash — the same patmatch syntax error [[babel.interface]]
    // rejects (the subset parser only quote-trims values, so the
    // backslash reaches the pattern verbatim).
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(
        "[[babel.interface]]\nname = \"eth*\"\n\
             [[babel.key]]\nsecret = \"x\"\ninterface = \"eth\\\"\n",
        &mut cfg,
    );
    assert!(err.is_err(), "{err:?}");
    assert!(err
        .unwrap_err()
        .contains("bad [[babel.key]] interface pattern"));
}

#[test]
fn babel_key_interface_scope_unknown_key_fails_closed() {
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(
        "[[babel.key]]\nsecret = \"x\"\niface = \"eth0\"\n",
        &mut cfg,
    );
    assert!(err.is_err(), "{err:?}");
    assert!(err.unwrap_err().contains("unknown [[babel.key]] key"));
}

#[test]
fn babel_key_interface_scope_must_overlap_an_interface_block() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[[babel.interface]]\nname = \"eth*\"\n\
             [[babel.key]]\nsecret = \"x\"\ninterface = \"wlan*\"\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.finalize().unwrap_err();
    assert!(
        err.contains("matches no [[babel.interface]] block"),
        "{err}"
    );
}

#[test]
fn babel_key_interface_scope_without_interface_blocks_rejected() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[[babel.key]]\nsecret = \"x\"\ninterface = \"eth0\"\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.finalize().unwrap_err();
    assert!(err.contains("no [[babel.interface]] blocks"), "{err}");
}

#[test]
fn babel_key_literal_scope_narrower_than_block_passes() {
    // A literal key scope (veth0) inside a broader interface block
    // pattern (veth*) overlaps in exactly one direction — legal.
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[[babel.interface]]\nname = \"veth*\"\n\
             [[babel.key]]\nsecret = \"x\"\ninterface = \"veth0\"\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize().unwrap();
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
fn static_routes_parse_and_finalize() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
            "[[static.route]]\nprefix = \"203.0.113.0/24\"\nnext_hop = \"198.51.100.1\"\nmetric = 10\n\n\
             [[static.route]]\nprefix = \"2001:db8:1::/48\"\nnext_hop = \"2001:db8:2::1\"\n\n\
             [[static.route]]\nprefix = \"10.0.0.0/8\"\nnext_hop = \"blackhole\"\n",
            &mut cfg,
        )
        .unwrap();
    cfg.finalize().unwrap();
    assert_eq!(cfg.static_routes.len(), 3);
    assert_eq!(
        cfg.static_routes[0].prefix.as_deref(),
        Some("203.0.113.0/24")
    );
    assert_eq!(
        cfg.static_routes[0].next_hop.as_deref(),
        Some("198.51.100.1")
    );
    assert_eq!(cfg.static_routes[0].metric, Some(10));
    // The blackhole keyword is normalised to None.
    assert_eq!(cfg.static_routes[2].next_hop, None);
}

#[test]
fn static_routes_reject_missing_prefix() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset("[[static.route]]\nnext_hop = \"198.51.100.1\"\n", &mut cfg).unwrap();
    let err = cfg.finalize().unwrap_err();
    assert!(err.contains("without 'prefix'"), "{err}");
}

#[test]
fn static_routes_reject_family_mismatch() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[[static.route]]\nprefix = \"203.0.113.0/24\"\nnext_hop = \"2001:db8::1\"\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.finalize().unwrap_err();
    assert!(err.contains("family mismatch"), "{err}");
}

#[test]
fn static_routes_reject_bad_next_hop() {
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(
        "[[static.route]]\nprefix = \"203.0.113.0/24\"\nnext_hop = \"not-an-ip\"\n",
        &mut cfg,
    )
    .unwrap_err();
    assert!(err.contains("bad static route next_hop"), "{err}");
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

// ==== [damping] table parsing (ROADMAP-v3 D4.3) ====

#[test]
fn damping_defaults_to_disabled() {
    // Without a [damping] section the config stays at the
    // DampingSpec::default() (enabled = false). Critical for
    // RFC 7196 §3: damping defaults are harmful on
    // Internet-facing eBGP, so the operator must opt in
    // explicitly.
    let cfg = DaemonConfig::with_defaults();
    assert!(!cfg.damping.enabled);
}

#[test]
fn damping_enabled_flag_parses() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset("[damping]\nenabled = true\n", &mut cfg).unwrap();
    assert!(cfg.damping.enabled);
    // The tunables inherit lr_damping::DampingConfig::default()
    // when only `enabled` is set.
    assert_eq!(cfg.damping.config.suppress_threshold, 2000);
    assert_eq!(cfg.damping.config.reuse_threshold, 750);
    assert_eq!(cfg.damping.config.decay_interval_s, 30);
}

#[test]
fn damping_tunables_parse() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[damping]\nenabled = true\nsuppress_threshold = 4000\nreuse_threshold = 1500\n\
             decay_interval_s = 15\ndecay_factor_active = 0.95\n",
        &mut cfg,
    )
    .unwrap();
    assert_eq!(cfg.damping.config.suppress_threshold, 4000);
    assert_eq!(cfg.damping.config.reuse_threshold, 1500);
    assert_eq!(cfg.damping.config.decay_interval_s, 15);
    assert!((cfg.damping.config.decay_factor_active - 0.95).abs() < 1e-9);
}

#[test]
fn damping_unknown_key_fails_closed() {
    // Typo protection: a misspelled threshold silently changes
    // flap-suppression behaviour, so unknown keys are hard
    // errors.
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset("[damping]\nsuppress_treshold = 4000\n", &mut cfg).unwrap_err();
    assert!(
        err.contains("unknown [damping] key 'suppress_treshold'"),
        "error should name the bad key: {err}"
    );
}

#[test]
fn damping_bad_threshold_value_fails() {
    let mut cfg = DaemonConfig::with_defaults();
    let err =
        parse_toml_subset("[damping]\nsuppress_threshold = \"lots\"\n", &mut cfg).unwrap_err();
    assert!(
        err.contains("invalid u32 for damping.suppress_threshold"),
        "error should explain the type mismatch: {err}"
    );
}

// ==== [bgp.rpki] table parsing (ROADMAP-v3 D2.4) ====

#[test]
fn rpki_defaults_to_disabled() {
    // Without a [bgp.rpki] section no RTR client thread starts —
    // validation runs on the static [[roa]] table only.
    let cfg = DaemonConfig::with_defaults();
    assert_eq!(cfg.rpki.cache, None);
    assert_eq!(cfg.rpki.refresh_interval, None);
    assert_eq!(cfg.rpki.retry_interval, None);
    assert_eq!(cfg.rpki.expire_interval, None);
}

#[test]
fn rpki_table_parses() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp.rpki]\ncache = \"rpki.example.net:8282\"\nrefresh_interval = 600\n\
             retry_interval = 120\nexpire_interval = 1440\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize().unwrap();
    assert_eq!(cfg.rpki.cache.as_deref(), Some("rpki.example.net:8282"));
    assert_eq!(cfg.rpki.refresh_interval, Some(600));
    assert_eq!(cfg.rpki.retry_interval, Some(120));
    assert_eq!(cfg.rpki.expire_interval, Some(1440));
}

#[test]
fn rpki_v6_bracketed_cache_parses() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset("[bgp.rpki]\ncache = \"[2001:db8::1]:8282\"\n", &mut cfg).unwrap();
    cfg.finalize().unwrap();
    assert_eq!(cfg.rpki.cache.as_deref(), Some("[2001:db8::1]:8282"));
}

#[test]
fn rpki_cache_requires_port() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset("[bgp.rpki]\ncache = \"rpki.example.net\"\n", &mut cfg).unwrap();
    let err = cfg.finalize().expect_err("cache without port must fail");
    assert!(err.contains("lacks a port"), "unexpected error: {err}");
}

#[test]
fn rpki_cache_bad_port_fails() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset("[bgp.rpki]\ncache = \"rpki.example.net:rtr\"\n", &mut cfg).unwrap();
    let err = cfg.finalize().expect_err("non-numeric port must fail");
    assert!(err.contains("bad port"), "unexpected error: {err}");
}

#[test]
fn rpki_zero_interval_rejected() {
    // RFC 8210 §6 intervals are positive — a zero would spin the
    // client loop hot or disable expiry outright.
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp.rpki]\ncache = \"1.2.3.4:8282\"\nretry_interval = 0\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.finalize().expect_err("zero interval must fail");
    assert!(
        err.contains("retry_interval must be non-zero"),
        "unexpected error: {err}"
    );
}

#[test]
fn rpki_unknown_key_fails_closed() {
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset("[bgp.rpki]\ncache_host = \"1.2.3.4\"\n", &mut cfg).unwrap_err();
    assert!(
        err.contains("unknown [bgp.rpki] key 'cache_host'"),
        "error should name the bad key: {err}"
    );
}

// ---- [[redistribute]] / [[aggregate]] (ROADMAP-v3 D4.1/D4.2) ----

#[test]
fn redistribute_table_parses() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp]\nlocal_as = 65000\nrouter_id = \"10.0.0.1\"\n\n\
             [[redistribute]]\nsource = \"ospf\"\ntarget = \"bgp\"\nmetric = 100\ntag = 65000\n\
             allow = [\"10.0.0.0/8\", \"192.168.0.0/16\"]\n",
        &mut cfg,
    )
    .unwrap();
    assert_eq!(cfg.redistributes.len(), 1);
    let spec = &cfg.redistributes[0];
    assert_eq!(spec.source.as_deref(), Some("ospf"));
    assert_eq!(spec.target.as_deref(), Some("bgp"));
    assert_eq!(spec.metric, Some(100));
    assert_eq!(spec.tag, Some(65000));
    assert_eq!(spec.allow, vec!["10.0.0.0/8", "192.168.0.0/16"]);
}

#[test]
fn redistribute_finalize_accepts_bgp_to_bgp_pipe() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "protocol = \"bgp\"\n[bgp]\nlocal_as = 65000\nrouter_id = \"10.0.0.1\"\n\n\
             [[redistribute]]\nsource = \"bgp\"\ntarget = \"bgp\"\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize()
        .expect("bgp->bgp re-origination pipe is a supported shape");
}

#[test]
fn redistribute_finalize_rejects_engine_not_in_protocol_set() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "protocol = \"bgp\"\n[bgp]\nlocal_as = 65000\nrouter_id = \"10.0.0.1\"\n\n\
             [[redistribute]]\nsource = \"babel\"\ntarget = \"bgp\"\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg
        .finalize()
        .expect_err("babel source without the babel engine");
    assert!(
        err.contains("does not run the babel engine"),
        "unexpected error: {err}"
    );
}

#[test]
fn redistribute_finalize_rejects_unsupported_target() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "protocol = \"bgp,babel\"\n[bgp]\nlocal_as = 65000\nrouter_id = \"10.0.0.1\"\n\n\
             [[redistribute]]\nsource = \"babel\"\ntarget = \"babel\"\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.finalize().expect_err("babel is not a supported target");
    assert!(
        err.contains("target 'babel' is not supported"),
        "unexpected error: {err}"
    );
}

#[test]
fn redistribute_finalize_rejects_static_source() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "protocol = \"bgp\"\n[bgp]\nlocal_as = 65000\nrouter_id = \"10.0.0.1\"\n\n\
             [[redistribute]]\nsource = \"static\"\ntarget = \"bgp\"\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.finalize().expect_err("static has no injection surface");
    assert!(
        err.contains("no daemon injection surface"),
        "unexpected error: {err}"
    );
}

#[test]
fn redistribute_missing_source_fails() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset("[[redistribute]]\ntarget = \"bgp\"\n", &mut cfg).unwrap();
    let err = cfg.finalize().expect_err("missing source");
    assert!(err.contains("without 'source'"), "unexpected error: {err}");
}

#[test]
fn redistribute_unknown_key_fails_closed() {
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(
        "[[redistribute]]\nsource = \"bgp\"\ntarget = \"ospf\"\nmetrik = 5\n",
        &mut cfg,
    )
    .unwrap_err();
    assert!(
        err.contains("unknown [[redistribute]] key 'metrik'"),
        "error should name the bad key: {err}"
    );
}

#[test]
fn redistribute_bad_allow_prefix_fails() {
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(
        "[[redistribute]]\nsource = \"bgp\"\ntarget = \"ospf\"\nallow = [\"10.0.0.0/44\"]\n",
        &mut cfg,
    )
    .unwrap_err();
    assert!(
        err.contains("bad redistribute allow prefix"),
        "unexpected error: {err}"
    );
}

#[test]
fn redistribute_duplicate_pipe_fails() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "protocol = \"bgp\"\n[bgp]\nlocal_as = 65000\nrouter_id = \"10.0.0.1\"\n\n\
             [[redistribute]]\nsource = \"bgp\"\ntarget = \"bgp\"\n\n\
             [[redistribute]]\nsource = \"bgp\"\ntarget = \"bgp\"\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.finalize().expect_err("duplicate pipe");
    assert!(
        err.contains("bgp -> bgp declared twice"),
        "unexpected error: {err}"
    );
}

#[test]
fn aggregate_table_parses_and_finalizes() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[bgp]\nlocal_as = 65000\nrouter_id = \"10.0.0.1\"\n\n\
             [[aggregate]]\nprefix = \"198.51.100.0/23\"\n\n\
             [[aggregate]]\nprefix = \"2001:db8::/32\"\n",
        &mut cfg,
    )
    .unwrap();
    cfg.finalize().unwrap();
    assert_eq!(cfg.aggregates.len(), 2);
    assert_eq!(cfg.aggregates[0].prefix.as_deref(), Some("198.51.100.0/23"));
}

#[test]
fn aggregate_missing_prefix_fails() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset("[[aggregate]]\n", &mut cfg).unwrap();
    let err = cfg.finalize().expect_err("missing prefix");
    assert!(err.contains("without 'prefix'"), "unexpected error: {err}");
}

#[test]
fn aggregate_unknown_key_fails_closed() {
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(
        "[[aggregate]]\nprefix = \"198.51.100.0/23\"\nsummary_only = true\n",
        &mut cfg,
    )
    .unwrap_err();
    assert!(
        err.contains("unknown [[aggregate]] key 'summary_only'"),
        "error should name the bad key: {err}"
    );
}

#[test]
fn aggregate_duplicate_prefix_fails() {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(
        "[[aggregate]]\nprefix = \"198.51.100.0/23\"\n\n\
             [[aggregate]]\nprefix = \"198.51.100.0/23\"\n",
        &mut cfg,
    )
    .unwrap();
    let err = cfg.finalize().expect_err("duplicate aggregate");
    assert!(err.contains("declared twice"), "unexpected error: {err}");
}

#[test]
fn deprecation_notice_keys_on_the_resolved_dialect() {
    // Only the TOML subset is inside its deprecation window.
    let notice = deprecation_notice(Some("toml")).expect("toml is deprecated");
    assert!(notice.contains("to-dsl"), "notice: {notice}");
    assert!(notice.contains("1.x"), "notice: {notice}");
    assert!(notice.contains("2.0"), "notice: {notice}");
    // The migration target and the adoption dialects are quiet.
    for d in [Some("lr"), Some("bird"), Some("frr"), None, Some("")] {
        assert!(
            deprecation_notice(d).is_none(),
            "unexpected deprecation notice for {d:?}"
        );
    }
}
