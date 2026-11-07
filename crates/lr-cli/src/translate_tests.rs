use super::*;
use crate::daemon_config::DaemonConfig;

fn roundtrip(toml: &str) -> DaemonConfig {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "bgp".to_string();
    crate::daemon_config::parse_toml_subset(toml, &mut cfg).expect("generated TOML must load");
    cfg.finalize().expect("generated TOML must finalize");
    cfg
}

/// Round-trip a translation through the daemon loader with the OSPF
/// protocol flag set, so the OSPF tables are validated by `finalize`
/// instead of warned about. Mirrors [`roundtrip`] for the OSPF path.
fn roundtrip_ospf(toml: &str) -> DaemonConfig {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
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

/// FRR `neighbor X shutdown` — the peer is administratively down.
/// Maps onto the per-peer `shutdown = true` key (RFC 4486 §3 +
/// RFC 8203 §2); the daemon's connector stays passive and the
/// listener refuses inbound SYNs from this peer's address.
#[test]
fn frr_neighbor_shutdown_maps_to_peer_shutdown_true() {
    let toml = render(translate_frr(
        "router bgp 64512\n bgp router-id 10.0.0.1\n\
         neighbor 10.0.0.2 remote-as 64513\n\
         neighbor 10.0.0.2 shutdown\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].shutdown, Some(true));
    assert!(toml.contains("shutdown = true"));
    // No UNMAPPED note — the line is fully mapped now.
    assert!(!toml.contains("# UNMAPPED: neighbor 10.0.0.2 shutdown"));
}

/// FRR `no neighbor X shutdown` — the explicit un-shutdown form
/// (RFC 4486 §3 — re-enable a peer that was administratively down).
/// Maps onto `shutdown = false` so the operator's explicit
/// re-enable survives a `lr translate` round-trip (a future reload
/// that flips the source back to `neighbor X shutdown` lands as
/// `true` rather than the implicit `None`).
#[test]
fn frr_no_neighbor_shutdown_maps_to_peer_shutdown_false() {
    let toml = render(translate_frr(
        "router bgp 64512\n bgp router-id 10.0.0.1\n\
         neighbor 10.0.0.2 remote-as 64513\n\
         no neighbor 10.0.0.2 shutdown\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].shutdown, Some(false));
    assert!(toml.contains("shutdown = false"));
}

/// FRR `neighbor X shutdown message MSG...` (RFC 8203 §2 shutdown
/// communication) — the message is accepted but not modelled, and
/// the converter still maps the `shutdown` flag. The message
/// qualifier is silently stripped (a follow-up can surface it as a
/// `lr:` directive).
#[test]
fn frr_neighbor_shutdown_with_message_still_maps() {
    let out = translate_frr(
        "router bgp 64512\n bgp router-id 10.0.0.1\n\
         neighbor 10.0.0.2 remote-as 64513\n\
         neighbor 10.0.0.2 shutdown message \"maintenance window\"\n",
    );
    assert_eq!(out.peers.len(), 1);
    assert_eq!(out.peers[0].shutdown, Some(true));
}

/// A peer without `neighbor X shutdown` carries `shutdown = None`
/// (the default) — the daemon treats the peer as up.
#[test]
fn frr_peer_without_shutdown_defaults_to_none() {
    let out = translate_frr(
        "router bgp 64512\n bgp router-id 10.0.0.1\n\
         neighbor 10.0.0.2 remote-as 64513\n",
    );
    assert_eq!(out.peers.len(), 1);
    assert_eq!(out.peers[0].shutdown, None);
}

/// BIRD `disabled;` (the bare form, which BIRD treats as `yes`) —
/// the peer is administratively down. Maps onto `shutdown = true`
/// in the rendered TOML.
#[test]
fn bird_disabled_bare_maps_to_peer_shutdown_true() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;
protocol bgp p1 {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
    disabled;
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].shutdown, Some(true));
    assert!(toml.contains("shutdown = true"));
}

/// BIRD `disabled yes;` — the explicit form. Same mapping as the
/// bare form: `shutdown = true`.
#[test]
fn bird_disabled_yes_maps_to_peer_shutdown_true() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;
protocol bgp p1 {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
    disabled yes;
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.peers[0].shutdown, Some(true));
}

/// BIRD `disabled no;` — the explicit un-shutdown (lr's default).
/// Maps onto `shutdown = false` so the operator's explicit
/// re-enable survives the round-trip.
#[test]
fn bird_disabled_no_maps_to_peer_shutdown_false() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;
protocol bgp p1 {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
    disabled no;
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.peers[0].shutdown, Some(false));
    assert!(toml.contains("shutdown = false"));
}

/// BIRD `disabled "reason string";` (RFC 8203 shutdown
/// communication) — the message is accepted but not modelled, and
/// the converter still maps the `shutdown` flag.
#[test]
fn bird_disabled_with_reason_string_still_maps() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;
protocol bgp p1 {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
    disabled "maintenance window";
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.peers[0].shutdown, Some(true));
}

/// A BIRD BGP stanza without `disabled` carries `shutdown = None`
/// (the default) — the daemon treats the peer as up.
#[test]
fn bird_peer_without_disabled_defaults_to_none() {
    let out = translate_bird(
        r#"
router id 10.0.0.1;
protocol bgp p1 {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
}
"#,
    );
    assert_eq!(out.peers.len(), 1);
    assert_eq!(out.peers[0].shutdown, None);
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
    assert!(toml.contains("# UNMAPPED: neighbor 10.0.0.2: no `remote-as` line found, peer dropped"));
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
    assert!(
        toml.contains("# UNMAPPED: local port 17992 (lr listens on the daemon's global listener)")
    );
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

// ---------------------------------------------------------------------------
// OSPF translation (BIRD `protocol ospf` and FRR `router ospf` /
// `interface IFNAME` blocks) — RFC 2328 §C / RFC 5340 §A.4.
// ---------------------------------------------------------------------------

#[test]
fn bird_ospf_protocol_maps_areas_and_interfaces() {
    // The shape the BIRD-users mailing list actually deploys: an area
    // block with one or more interface blocks inside, each carrying
    // the common RFC 2328 §C.1 parameters.
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;
protocol ospf my_ospf {
    area 0.0.0.0 {
        interface "eth0" {
            cost 10;
            hello 5;
            dead interval 20;
            priority 100;
            type broadcast;
        };
        interface "eth1" {
            type pointopoint;
        };
    };
    area 0.0.0.1 {
        stub yes;
        summary no;
        default cost 25;
        interface "eth2";
    };
}
protocol bgp p1 {
    local as 64512;
    neighbor 192.168.1.2 as 64513;
}
"#,
    ));
    let cfg = roundtrip_ospf(&toml);
    // The BGP peer still converts.
    assert_eq!(cfg.peers.len(), 1);
    // Two areas: 0.0.0.0 (backbone) and 0.0.0.1 (stub, no-summary).
    assert_eq!(cfg.ospf_areas.len(), 2);
    assert_eq!(cfg.ospf_areas[0].id, Some(0));
    assert_eq!(cfg.ospf_areas[0].kind, None, "backbone stays normal");
    assert_eq!(cfg.ospf_areas[1].id, Some(1));
    assert_eq!(cfg.ospf_areas[1].kind.as_deref(), Some("stub"));
    assert_eq!(cfg.ospf_areas[1].no_summary, Some(true));
    assert_eq!(cfg.ospf_areas[1].stub_metric, Some(25));
    // Three interfaces across the two areas.
    assert_eq!(cfg.ospf_interfaces.len(), 3);
    let eth0 = &cfg.ospf_interfaces[0];
    assert_eq!(eth0.name.as_deref(), Some("eth0"));
    assert_eq!(eth0.area, Some(0));
    assert_eq!(eth0.cost, Some(10));
    assert_eq!(eth0.hello_interval, Some(5));
    assert_eq!(eth0.dead_interval, Some(20));
    assert_eq!(eth0.priority, Some(100));
    assert_eq!(eth0.network_type.as_deref(), Some("broadcast"));
    let eth1 = &cfg.ospf_interfaces[1];
    assert_eq!(eth1.name.as_deref(), Some("eth1"));
    assert_eq!(eth1.area, Some(0));
    assert_eq!(eth1.network_type.as_deref(), Some("p2p"));
    let eth2 = &cfg.ospf_interfaces[2];
    assert_eq!(eth2.name.as_deref(), Some("eth2"));
    assert_eq!(eth2.area, Some(1));
    // The converter says so instead of silently switching the
    // protocol key — same shape as the Babel note.
    assert!(toml.contains("lr runs one protocol per daemon instance"));
}

#[test]
fn bird_ospf_dead_count_becomes_unmapped_note() {
    // BIRD's legacy `dead count N;` (dead interval = N * hello) has
    // no direct lr equivalent — lr uses an explicit `dead_interval`
    // in seconds. The converter notes the gap instead of dropping it.
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;
protocol ospf my_ospf {
    area 0 {
        interface "eth0" {
            hello 10;
            dead count 4;
        };
    };
}
"#,
    ));
    assert!(toml.contains("dead count"));
    assert!(toml.contains("lr uses dead_interval"));
    // The hello parameter still converts.
    let cfg = roundtrip_ospf(&toml);
    assert_eq!(cfg.ospf_interfaces[0].hello_interval, Some(10));
}

#[test]
fn bird_ospf_unmapped_interface_parameters_stay_visible() {
    // retransmit, transmit delay, wait, authentication, password —
    // all noted per-interface so the operator sees the gap.
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;
protocol ospf my_ospf {
    area 0 {
        interface "eth0" {
            retransmit 5;
            transmit delay 1;
            wait 40;
            authentication cryptographic;
            password "abc";
        };
    };
}
"#,
    ));
    assert!(toml.contains("retransmit"));
    assert!(toml.contains("transmit delay"));
    assert!(toml.contains("wait"));
    assert!(toml.contains("authentication"));
    assert!(toml.contains("password"));
}

#[test]
fn bird_ospf_protocol_level_statement_is_noted() {
    // `rfc1583 yes;` has no lr equivalent — noted at protocol level.
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;
protocol ospf my_ospf {
    rfc1583 yes;
    area 0 { interface "eth0"; };
}
"#,
    ));
    assert!(toml.contains("protocol-level ospf statement `rfc1583`"));
}

#[test]
fn frr_ospf_router_block_maps_areas_and_router_id() {
    // FRR `router ospf` with area policy + `router-id`, plus a
    // top-level `interface IFNAME` block with `ip ospf …` directives.
    let toml = render(translate_frr(
        "router ospf\n\
         router-id 1.1.1.1\n\
         area 0.0.0.1 stub no-summary\n\
         area 0.0.0.1 default-cost 25\n\
         area 0.0.0.2 nssa\n\
         !\n\
         interface eth0\n\
         ip ospf cost 10\n\
         ip ospf hello-interval 5\n\
         ip ospf dead-interval 20\n\
         ip ospf priority 100\n\
         ip ospf network broadcast\n\
         ip ospf area 0\n\
         !\n\
         interface eth1\n\
         ip ospf network point-to-point\n\
         ip ospf area 1\n\
         !\n\
         router bgp 64512\n\
         neighbor 192.0.2.2 remote-as 64513\n",
    ));
    let cfg = roundtrip_ospf(&toml);
    // The router-id carries over (FRR form: bare `router-id` inside
    // `router ospf`).
    assert_eq!(cfg.router_id.as_str(), "1.1.1.1");
    // Two areas: 0.0.0.1 stub no-summary with default-cost, 0.0.0.2
    // nssa.
    assert_eq!(cfg.ospf_areas.len(), 2);
    assert_eq!(cfg.ospf_areas[0].id, Some(1));
    assert_eq!(cfg.ospf_areas[0].kind.as_deref(), Some("stub"));
    assert_eq!(cfg.ospf_areas[0].no_summary, Some(true));
    assert_eq!(cfg.ospf_areas[0].stub_metric, Some(25));
    assert_eq!(cfg.ospf_areas[1].id, Some(2));
    assert_eq!(cfg.ospf_areas[1].kind.as_deref(), Some("nssa"));
    // Two interfaces with their per-interface parameters.
    assert_eq!(cfg.ospf_interfaces.len(), 2);
    let eth0 = &cfg.ospf_interfaces[0];
    assert_eq!(eth0.name.as_deref(), Some("eth0"));
    assert_eq!(eth0.area, Some(0));
    assert_eq!(eth0.cost, Some(10));
    assert_eq!(eth0.hello_interval, Some(5));
    assert_eq!(eth0.dead_interval, Some(20));
    assert_eq!(eth0.priority, Some(100));
    assert_eq!(eth0.network_type.as_deref(), Some("broadcast"));
    let eth1 = &cfg.ospf_interfaces[1];
    assert_eq!(eth1.name.as_deref(), Some("eth1"));
    assert_eq!(eth1.area, Some(1));
    assert_eq!(eth1.network_type.as_deref(), Some("p2p"));
    // The BGP peer still converts alongside the OSPF config.
    assert_eq!(cfg.peers.len(), 1);
}

#[test]
fn frr_ospf_network_area_is_noted_as_unmapped() {
    // FRR `network PREFIX area N` cannot map mechanically (lr keys
    // interfaces by name); the converter notes the gap with a hint
    // instead of silently dropping.
    let toml = render(translate_frr(
        "router ospf\n\
         network 10.0.0.0/24 area 0\n\
         !\n",
    ));
    assert!(toml.contains("network 10.0.0.0/24 area 0"));
    assert!(toml.contains("map the matching interface manually"));
}

#[test]
fn frr_ospf_interface_without_ospf_directives_produces_no_row() {
    // A plain `interface IFNAME` block with only `ip address …` lines
    // should not produce an empty `[[ospf.interface]]` table.
    let toml = render(translate_frr(
        "interface eth0\n\
         ip address 10.0.0.1/24\n\
         no ip ospf\n\
         !\n",
    ));
    assert!(
        !toml.contains("[[ospf.interface]]"),
        "plain interface block must not produce an OSPF row: {toml}"
    );
}

#[test]
fn frr_ospf_unmapped_area_options_are_noted() {
    // `area N range PREFIX` and `area N export-list NAME` have no lr
    // equivalent — noted on the area row.
    let toml = render(translate_frr(
        "router ospf\n\
         area 0.0.0.1 range 10.0.0.0/8\n\
         area 0.0.0.1 export-list OUT\n\
         !\n",
    ));
    assert!(toml.contains("area 1 range 10.0.0.0/8"));
    assert!(toml.contains("no area-range knob"));
    assert!(toml.contains("area 1 export-list"));
    assert!(toml.contains("no area-list knob"));
}

#[test]
fn frr_ospfv3_router_block_emits_version_note() {
    // `router ospfv3` should produce the v3-specific note telling the
    // operator to set `ospf_version = "v3"`.
    let toml = render(translate_frr(
        "router ospfv3\n\
         router-id 1.1.1.1\n\
         !\n",
    ));
    assert!(toml.contains("ospf_version"));
    assert!(toml.contains("v3"));
}

#[test]
fn frr_ospfv3_router_id_maps() {
    // `ospfv3 router-id A.B.C.D` inside `router ospfv3` maps onto the
    // same `router_id` field the v2 `ospf router-id` form fills.
    let toml = render(translate_frr(
        "router ospfv3\n\
         ospfv3 router-id 10.0.0.7\n\
         !\n",
    ));
    let cfg = roundtrip_ospf(&toml);
    assert_eq!(cfg.router_id, "10.0.0.7");
}

#[test]
fn frr_ospfv3_interface_directives_map() {
    // The `ospfv3 cost|hello-interval|dead-interval|priority|network|
    // area N` directives inside an `interface IFNAME` block map onto
    // the same `[[ospf.interface]]` row the v2 `ip ospf …` directives
    // produce (RFC 5340 §A.4, FRR `ospf6d`).
    let toml = render(translate_frr(
        "router ospfv3\n\
         ospfv3 router-id 10.0.0.1\n\
         area 1 stub\n\
         !\n\
         interface eth0\n\
         ospfv3 cost 10\n\
         ospfv3 hello-interval 5\n\
         ospfv3 dead-interval 20\n\
         ospfv3 priority 100\n\
         ospfv3 network broadcast\n\
         ospfv3 area 1\n\
         !\n\
         interface eth1\n\
         ospfv3 network point-to-point\n\
         ospfv3 area 1\n\
         !\n",
    ));
    let cfg = roundtrip_ospf(&toml);
    assert_eq!(cfg.router_id, "10.0.0.1");
    assert_eq!(cfg.ospf_interfaces.len(), 2);
    let eth0 = &cfg.ospf_interfaces[0];
    assert_eq!(eth0.name.as_deref(), Some("eth0"));
    assert_eq!(eth0.area, Some(1));
    assert_eq!(eth0.cost, Some(10));
    assert_eq!(eth0.hello_interval, Some(5));
    assert_eq!(eth0.dead_interval, Some(20));
    assert_eq!(eth0.priority, Some(100));
    assert_eq!(eth0.network_type.as_deref(), Some("broadcast"));
    let eth1 = &cfg.ospf_interfaces[1];
    assert_eq!(eth1.name.as_deref(), Some("eth1"));
    assert_eq!(eth1.area, Some(1));
    assert_eq!(eth1.network_type.as_deref(), Some("p2p"));
}

#[test]
fn frr_ospfv3_instance_id_is_noted() {
    // `ospfv3 instance-id N` has no lr equivalent (lr's OSPFv3 daemon
    // does not carry a per-interface instance ID); the converter notes
    // the gap on the matching `[[ospf.interface]]` row instead of
    // silently dropping it.
    let toml = render(translate_frr(
        "router ospfv3\n\
         area 1 stub\n\
         !\n\
         interface eth0\n\
         ospfv3 area 1\n\
         ospfv3 instance-id 7\n\
         !\n",
    ));
    assert!(toml.contains("ospfv3 instance-id"));
    assert!(toml.contains("no lr equivalent"));
}

#[test]
fn frr_ospfv3_prefixed_area_policy_maps() {
    // `ospfv3 area N stub|nssa|default-cost M` inside `router ospfv3`
    // — the v3 spelling of the area policy. Same shape as the bare v2
    // `area N …` form; routes through the same handler.
    let toml = render(translate_frr(
        "router ospfv3\n\
         ospfv3 router-id 10.0.0.1\n\
         ospfv3 area 2 stub no-summary\n\
         ospfv3 area 2 default-cost 25\n\
         !\n",
    ));
    let cfg = roundtrip_ospf(&toml);
    assert_eq!(cfg.router_id, "10.0.0.1");
    assert_eq!(cfg.ospf_areas.len(), 1);
    assert_eq!(cfg.ospf_areas[0].id, Some(2));
    assert_eq!(cfg.ospf_areas[0].kind.as_deref(), Some("stub"));
    assert_eq!(cfg.ospf_areas[0].no_summary, Some(true));
    assert_eq!(cfg.ospf_areas[0].stub_metric, Some(25));
}

#[test]
fn frr_ospfv3_network_area_is_noted_as_unmapped() {
    // `ospfv3 network PREFIX area N` (the v3 spelling of the v2 `network
    // PREFIX area N`) cannot map mechanically — lr keys interfaces by
    // name, not prefix (same gap as v2). The converter notes the gap
    // with a hint instead of silently dropping.
    let toml = render(translate_frr(
        "router ospfv3\n\
         ospfv3 network 2001:db8::/32 area 2\n\
         !\n",
    ));
    assert!(toml.contains("ospfv3 network 2001:db8::/32 area 2"));
    assert!(toml.contains("map the matching interface manually"));
}

#[test]
fn frr_ospfv3_router_level_unknown_directive_is_noted() {
    // `ospfv3 abr-type …`, `ospfv3 log-adjacency-changes`, … have no lr
    // equivalent. The converter surfaces the gap as an UNMAPPED note
    // instead of silently dropping the directive.
    let toml = render(translate_frr(
        "router ospfv3\n\
         ospfv3 abr-type shortcut\n\
         ospfv3 log-adjacency-changes\n\
         !\n",
    ));
    assert!(toml.contains("ospfv3 abr-type shortcut"));
    assert!(toml.contains("no lr equivalent (FRR OSPFv3 router-level directive)"));
}

#[test]
fn frr_ospfv3_interface_directives_work_outside_router_ospfv3() {
    // FRR accepts `ospfv3 cost …` inside a top-level `interface IFNAME`
    // block — the block does not have to be nested inside `router
    // ospfv3`. The converter routes these the same way as the nested
    // form (matches the v2 `ip ospf …` behaviour, which also works at
    // top-level interface blocks).
    let toml = render(translate_frr(
        "interface eth0\n\
         ospfv3 cost 5\n\
         !\n",
    ));
    assert!(toml.contains("[[ospf.interface]]"));
    assert!(toml.contains("name = \"eth0\""));
    assert!(toml.contains("cost = 5"));
}

#[test]
fn bird_ospf_nssa_area_maps_kind() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;
protocol ospf my_ospf {
    area 0.0.0.5 {
        nssa yes;
        default cost 10;
        interface "eth0";
    };
}
"#,
    ));
    let cfg = roundtrip_ospf(&toml);
    assert_eq!(cfg.ospf_areas[0].id, Some(5));
    assert_eq!(cfg.ospf_areas[0].kind.as_deref(), Some("nssa"));
    assert_eq!(cfg.ospf_areas[0].stub_metric, Some(10));
}

// ---- FRR address-family state: aggregate-address & redistribute ----

#[test]
fn frr_aggregate_address_maps_to_aggregate_table() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             bgp router-id 10.0.0.1\n\
             address-family ipv4 unicast\n\
              aggregate-address 192.0.2.0/24\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.aggregates.len(), 1);
    assert_eq!(cfg.aggregates[0].prefix.as_deref(), Some("192.0.2.0/24"));
}

#[test]
fn frr_aggregate_address_summary_only_carries_through() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              aggregate-address 192.0.2.0/24 summary-only\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.aggregates.len(), 1);
    assert_eq!(cfg.aggregates[0].prefix.as_deref(), Some("192.0.2.0/24"));
    assert!(
        cfg.aggregates[0].summary_only,
        "summary-only must round-trip to the [[aggregate]] summary_only key"
    );
    assert!(
        !cfg.aggregates[0].as_set,
        "summary-only alone must not set as_set"
    );
    assert!(
        toml.contains("summary_only = true"),
        "rendered TOML must carry summary_only = true"
    );
    assert!(
        !toml.contains("# UNMAPPED: aggregate-address 192.0.2.0/24 — summary-only"),
        "summary-only is no longer unmapped"
    );
}

#[test]
fn frr_aggregate_address_as_set_carries_through() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              aggregate-address 192.0.2.0/24 as-set\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.aggregates.len(), 1);
    assert_eq!(cfg.aggregates[0].prefix.as_deref(), Some("192.0.2.0/24"));
    assert!(
        cfg.aggregates[0].as_set,
        "as-set must round-trip to the [[aggregate]] as_set key"
    );
    assert!(
        !cfg.aggregates[0].summary_only,
        "as-set alone must not set summary_only"
    );
    assert!(
        toml.contains("as_set = true"),
        "rendered TOML must carry as_set = true"
    );
    assert!(
        !toml.contains("# UNMAPPED: aggregate-address 192.0.2.0/24 — as-set"),
        "as-set is no longer unmapped"
    );
}

#[test]
fn frr_aggregate_address_summary_only_and_as_set_combine() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              aggregate-address 192.0.2.0/24 summary-only as-set\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.aggregates.len(), 1);
    assert_eq!(cfg.aggregates[0].prefix.as_deref(), Some("192.0.2.0/24"));
    assert!(cfg.aggregates[0].summary_only);
    assert!(cfg.aggregates[0].as_set);
    assert!(toml.contains("summary_only = true"));
    assert!(toml.contains("as_set = true"));
}

#[test]
fn frr_aggregate_address_route_map_carries_unmapped_note() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              aggregate-address 192.0.2.0/24 as-set route-map RM-AGG\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.aggregates.len(), 1);
    assert_eq!(cfg.aggregates[0].prefix.as_deref(), Some("192.0.2.0/24"));
    assert!(cfg.aggregates[0].as_set);
    // `route-map NAME` carries an unmapped note — lr's [[aggregate]]
    // has no per-aggregate route-map surface today.
    assert!(
        toml.contains("route-map RM-AGG — lr's [[aggregate]] has no per-aggregate attribute hook"),
        "route-map NAME must surface its own UNMAPPED note"
    );
    // The summary-only/as-set qualifiers are mapped (no UNMAPPED note
    // for them); only the route-map is unmapped.
    assert!(
        !toml.contains("# UNMAPPED: aggregate-address 192.0.2.0/24 — as-set"),
        "as-set is no longer unmapped; only route-map is"
    );
}

#[test]
fn frr_aggregate_address_outside_router_bgp_is_dropped() {
    // `aggregate-address` outside `router bgp` (e.g. at the top level)
    // is a config error in FRR. The converter must not emit a
    // [[aggregate]] row from such a line — silently dropping it
    // matches the catch-all for other top-level noise.
    let out = translate_frr("aggregate-address 192.0.2.0/24\n");
    assert!(out.aggregates.is_empty());
}

#[test]
fn frr_redistribute_ospf_into_bgp_emits_pipe_and_engines() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute ospf metric 100\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    let rd = &cfg.redistributes[0];
    assert_eq!(rd.source.as_deref(), Some("ospf"));
    assert_eq!(rd.target.as_deref(), Some("bgp"));
    assert_eq!(rd.metric, Some(100));
    // The pipe needs the ospf engine running — the converter emits
    // `protocols = ["bgp", "ospf"]` so finalize accepts the pipe.
    assert!(
        toml.contains("protocols = [\"bgp\", \"ospf\"]"),
        "expected protocols line for the ospf engine, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_babel_into_bgp_emits_babel_engine() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute babel\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert_eq!(cfg.redistributes[0].source.as_deref(), Some("babel"));
    assert_eq!(cfg.redistributes[0].target.as_deref(), Some("bgp"));
    assert!(
        toml.contains("protocols = [\"bgp\", \"babel\"]"),
        "expected protocols line for the babel engine, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_bgp_into_bgp_no_extra_engine() {
    // A bgp→bgp pipe (FRR's `redistribute bgp` inside `router bgp`)
    // re-originates BGP routes as locally-originated — lr supports it
    // without an extra engine, so no `protocols = [...]` line.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute bgp\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert_eq!(cfg.redistributes[0].source.as_deref(), Some("bgp"));
    assert_eq!(cfg.redistributes[0].target.as_deref(), Some("bgp"));
    assert!(
        !toml.contains("protocols = "),
        "bgp→bgp pipe must not emit a protocols line"
    );
}

#[test]
fn frr_redistribute_connected_maps_to_connected_source() {
    // FRR `redistribute connected` (in `router bgp` → address-family
    // ipv4 unicast) now maps onto lr's `[[redistribute]] source =
    // "connected" target = "bgp"` pipe — the daemon enumerates
    // kernel interface network prefixes at startup via
    // `install_connected` and pushes them through any matching
    // pipe (BIRD `redistribute direct` / FRR `redistribute connected`
    // parity). Previously this was unmapped because the daemon had
    // no `install_connected` surface.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute connected\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(
        cfg.redistributes.len(),
        1,
        "connected source must produce exactly one [[redistribute]] row, got: {toml}"
    );
    assert_eq!(cfg.redistributes[0].source.as_deref(), Some("connected"));
    assert_eq!(cfg.redistributes[0].target.as_deref(), Some("bgp"));
}

#[test]
fn frr_redistribute_static_maps_to_static_source() {
    // FRR `redistribute static` (in `router bgp` → address-family
    // ipv4 unicast) now maps onto lr's `[[redistribute]] source =
    // "static" target = "bgp"` pipe — the daemon installs
    // operator-configured `[[static.route]]` entries via
    // `install_static` and pushes them through any matching pipe
    // (BIRD `redistribute static` / FRR `redistribute static` parity).
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute static\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(
        cfg.redistributes.len(),
        1,
        "static source must produce exactly one [[redistribute]] row, got: {toml}"
    );
    assert_eq!(cfg.redistributes[0].source.as_deref(), Some("static"));
    assert_eq!(cfg.redistributes[0].target.as_deref(), Some("bgp"));
}

#[test]
fn frr_redistribute_kernel_is_still_unmapped() {
    // FRR `redistribute kernel` (the kernel RIB — routes installed
    // by another daemon or by `ip route add`) is a distinct concept
    // that lr does not have an injection surface for; the converter
    // still leaves it as an unmapped note so the operator sees the
    // gap and converts manually (e.g. by adding `[[static.route]]`
    // entries for the routes they would have had the kernel feed in).
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute kernel\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert!(
        cfg.redistributes.is_empty(),
        "kernel source must not produce a [[redistribute]] row"
    );
    assert!(
        toml.contains("no daemon injection surface for source 'kernel'"),
        "expected unmapped note for kernel, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_route_map_is_unmapped() {
    // A `redistribute … route-map NAME` whose NAME is not defined
    // anywhere in the source config: the resolver cannot look the
    // route-map up, so it carries an unmapped note that says so
    // (and the redistribute row still lands — with an empty allow
    // list, which means "redistribute everything").
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute ospf route-map RM-REDIST\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert_eq!(cfg.redistributes[0].source.as_deref(), Some("ospf"));
    assert!(
        toml.contains("route-map RM-REDIST not defined"),
        "expected route-map-not-defined note, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_route_map_translates_to_allow_list() {
    // The happy path: `redistribute connected route-map RM-REDIST`
    // where RM-REDIST is a single permit entry whose only match is
    // `match ip address prefix-list PL-ALLOWED`, and PL-ALLOWED is a
    // pure all-permit prefix-list whose every row carries `le 32`
    // (i.e. "any prefix inside this network"). The FRR semantics is
    // exactly `RedistributionPipe::matches`'s bit-level containment
    // check, so the converter copies the prefixes onto the pipe's
    // `allow` list. FRR permits the prefix-list to be defined after
    // the `redistribute` line (forward reference) — the resolver
    // runs only after the whole file has been scanned.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute connected route-map RM-REDIST\n\
             exit-address-family\n\
             !\n\
             route-map RM-REDIST permit 10\n\
              match ip address prefix-list PL-ALLOWED\n\
             !\n\
             ip prefix-list PL-ALLOWED permit 10.0.0.0/8 le 32\n\
             ip prefix-list PL-ALLOWED permit 192.168.0.0/16 le 32\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    let rd = &cfg.redistributes[0];
    assert_eq!(rd.source.as_deref(), Some("connected"));
    assert_eq!(rd.target.as_deref(), Some("bgp"));
    assert_eq!(
        rd.allow,
        vec!["10.0.0.0/8", "192.168.0.0/16"],
        "route-map RM-REDIST must translate to allow list with both prefix-list entries"
    );
    // No `# UNMAPPED:` line should mention RM-REDIST on the happy
    // path (the route-map definition itself legitimately contains
    // RM-REDIST, but it is not an unmapped note). The header comment
    // about UNMAPPED comments does not count.
    let unmapped_mentions_rm = toml
        .lines()
        .filter(|l| l.starts_with("# UNMAPPED:"))
        .any(|l| l.contains("RM-REDIST"));
    assert!(
        !unmapped_mentions_rm,
        "no unmapped note for RM-REDIST on the happy path, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_route_map_translates_v6_le_128() {
    // IPv6 variant of the happy path: `le 128` is the v6 containment
    // marker (any prefix inside the network). The resolver must pick
    // the family's max plen, not a hard-coded 32.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv6 unicast\n\
              redistribute connected route-map RM-V6\n\
             exit-address-family\n\
             !\n\
             route-map RM-V6 permit 10\n\
              match ip address prefix-list PL-V6\n\
             !\n\
             ipv6 prefix-list PL-V6 permit 2001:db8::/32 le 128\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert_eq!(
        cfg.redistributes[0].allow,
        vec!["2001:db8::/32"],
        "v6 route-map with le 128 must translate to allow list"
    );
}

#[test]
fn frr_redistribute_route_map_with_deny_entry_is_unmapped() {
    // A route-map with a `deny` entry cannot be flattened onto the
    // pipe's `allow` list (allow is a pure union of permit prefixes,
    // with no exclusion mechanism). The converter emits an unmapped
    // note describing the gap and leaves the allow list empty.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute ospf route-map RM-DENY\n\
             exit-address-family\n\
             !\n\
             route-map RM-DENY deny 10\n\
              match ip address prefix-list PL-ALLOWED\n\
             !\n\
             ip prefix-list PL-ALLOWED permit 10.0.0.0/8 le 32\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert!(
        cfg.redistributes[0].allow.is_empty(),
        "deny route-map must NOT populate allow list"
    );
    assert!(
        toml.contains("route-map RM-DENY cannot be translated") && toml.contains("deny entries"),
        "expected deny-entry unmapped note, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_route_map_with_set_clauses_is_unmapped() {
    // A route-map with set clauses (local-preference, MED, next-hop,
    // prepend, community) carries attribute-rewrite semantics that
    // `allow` cannot express; the converter notes the gap.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute ospf route-map RM-SET\n\
             exit-address-family\n\
             !\n\
             route-map RM-SET permit 10\n\
              match ip address prefix-list PL-ALLOWED\n\
              set local-preference 200\n\
             !\n\
             ip prefix-list PL-ALLOWED permit 10.0.0.0/8 le 32\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert!(cfg.redistributes[0].allow.is_empty());
    assert!(
        toml.contains("route-map RM-SET cannot be translated") && toml.contains("set clauses"),
        "expected set-clauses unmapped note, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_route_map_with_ge_qualifier_is_unmapped() {
    // FRR's `permit PREFIX ge G` is a stricter-than-containment match
    // (prefix length >= G AND inside the network). Flattening it onto
    // `allow` (which is pure containment) would silently admit more
    // routes, so the converter refuses the translation and notes the
    // gap.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute ospf route-map RM-GE\n\
             exit-address-family\n\
             !\n\
             route-map RM-GE permit 10\n\
              match ip address prefix-list PL-GE\n\
             !\n\
             ip prefix-list PL-GE permit 10.0.0.0/8 ge 16 le 32\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert!(
        cfg.redistributes[0].allow.is_empty(),
        "ge-qualified prefix-list must NOT populate allow list"
    );
    assert!(
        toml.contains("prefix-list PL-GE has ge/le qualifier"),
        "expected ge-qualifier unmapped note, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_route_map_with_exact_match_is_unmapped() {
    // FRR's bare `permit PREFIX` (no `le`) is exact-match (ge=plen,
    // le=plen), which is stricter than `allow`'s containment. The
    // converter refuses the translation to avoid silently widening
    // the match.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute ospf route-map RM-EXACT\n\
             exit-address-family\n\
             !\n\
             route-map RM-EXACT permit 10\n\
              match ip address prefix-list PL-EXACT\n\
             !\n\
             ip prefix-list PL-EXACT permit 10.0.0.0/8\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert!(
        cfg.redistributes[0].allow.is_empty(),
        "exact-match prefix-list must NOT populate allow list"
    );
    assert!(
        toml.contains("prefix-list PL-EXACT has ge/le qualifier"),
        "expected exact-match unmapped note, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_route_map_with_prefix_list_deny_is_unmapped() {
    // A prefix-list with a `deny` entry cannot be flattened onto the
    // pipe's `allow` list (allow has no exclusion mechanism).
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute ospf route-map RM-PL-DENY\n\
             exit-address-family\n\
             !\n\
             route-map RM-PL-DENY permit 10\n\
              match ip address prefix-list PL-MIXED\n\
             !\n\
             ip prefix-list PL-MIXED permit 10.0.0.0/8 le 32\n\
             ip prefix-list PL-MIXED deny 10.1.0.0/16 le 32\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert!(
        cfg.redistributes[0].allow.is_empty(),
        "prefix-list with deny entries must NOT populate allow list"
    );
    assert!(
        toml.contains("prefix-list PL-MIXED has deny entries"),
        "expected prefix-list-deny unmapped note, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_route_map_undefined_prefix_list_is_unmapped() {
    // A route-map references a prefix-list that is never defined.
    // The existing route-map reference-validation pass clears the
    // dangling `match_prefix` (pushing an unmapped note onto the
    // route-map row), and our resolver then sees the route-map has
    // no `match_prefix` (and an unmapped clause) — both surface as
    // reasons in the redistribute's unmapped note.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute ospf route-map RM-UNDEF\n\
             exit-address-family\n\
             !\n\
             route-map RM-UNDEF permit 10\n\
              match ip address prefix-list PL-NEVER\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert!(
        cfg.redistributes[0].allow.is_empty(),
        "route-map referencing an undefined prefix-list must NOT populate allow list"
    );
    assert!(
        toml.contains("route-map RM-UNDEF cannot be translated")
            && toml.contains("no such prefix-list"),
        "expected undefined-prefix-list unmapped note, got:\n{toml}"
    );
}

#[test]
fn frr_redistribute_route_map_multiple_entries_merge() {
    // A route-map with multiple permit entries, each referencing a
    // different prefix-list, merges all the prefixes onto the pipe's
    // allow list (deduplicated). This mirrors FRR's "any matching
    // permit entry allows the route" semantics.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute connected route-map RM-MULTI\n\
             exit-address-family\n\
             !\n\
             route-map RM-MULTI permit 10\n\
              match ip address prefix-list PL-A\n\
             route-map RM-MULTI permit 20\n\
              match ip address prefix-list PL-B\n\
             !\n\
             ip prefix-list PL-A permit 10.0.0.0/8 le 32\n\
             ip prefix-list PL-B permit 192.168.0.0/16 le 32\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    let mut allow = cfg.redistributes[0].allow.clone();
    allow.sort();
    assert_eq!(
        allow,
        vec!["10.0.0.0/8", "192.168.0.0/16"],
        "multiple permit entries must merge their prefix-lists onto allow"
    );
}

#[test]
fn frr_redistribute_route_map_deduplicates_prefixes() {
    // The same prefix may legitimately appear in multiple prefix-list
    // rows or in two different prefix-lists referenced by the same
    // route-map. `allow` is a set-membership check, so the dedup
    // keeps the rendered TOML clean and avoids a confusing double
    // entry in the daemon config.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute connected route-map RM-DUP\n\
             exit-address-family\n\
             !\n\
             route-map RM-DUP permit 10\n\
              match ip address prefix-list PL-DUP\n\
             !\n\
             ip prefix-list PL-DUP permit 10.0.0.0/8 le 32\n\
             ip prefix-list PL-DUP permit 10.0.0.0/8 le 32\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert_eq!(
        cfg.redistributes[0].allow,
        vec!["10.0.0.0/8"],
        "duplicated prefix-list rows must collapse to one allow entry"
    );
}

#[test]
fn frr_redistribute_route_map_preserves_metric() {
    // `metric M` and `route-map NAME` are independent qualifiers on
    // the same `redistribute` line: the metric override carries
    // through unchanged while the route-map is resolved onto the
    // allow list. Round-trip both through the daemon parser.
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              redistribute connected metric 100 route-map RM-METRIC\n\
             exit-address-family\n\
             !\n\
             route-map RM-METRIC permit 10\n\
              match ip address prefix-list PL-ALLOWED\n\
             !\n\
             ip prefix-list PL-ALLOWED permit 10.0.0.0/8 le 32\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    let rd = &cfg.redistributes[0];
    assert_eq!(rd.metric, Some(100), "metric override carries through");
    assert_eq!(
        rd.allow,
        vec!["10.0.0.0/8"],
        "route-map translates to allow"
    );
}

#[test]
fn frr_redistribute_route_map_into_ospf_target_translates() {
    // The route-map translation works for OSPF targets too — the
    // resolver is target-agnostic (it only inspects the route-map
    // and prefix-list tables).
    let toml = render(translate_frr(
        "router ospf\n\
             redistribute bgp route-map RM-INTO-OSPF\n\
             !\n\
             route-map RM-INTO-OSPF permit 10\n\
              match ip address prefix-list PL-ALLOWED\n\
             !\n\
             ip prefix-list PL-ALLOWED permit 10.0.0.0/8 le 32\n",
    ));
    let cfg = roundtrip_ospf(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    let rd = &cfg.redistributes[0];
    assert_eq!(rd.source.as_deref(), Some("bgp"));
    assert_eq!(rd.target.as_deref(), Some("ospf"));
    assert_eq!(rd.allow, vec!["10.0.0.0/8"]);
}

#[test]
fn frr_redistribute_into_ospf_targets_ospf() {
    let toml = render(translate_frr(
        "router ospf\n\
             redistribute bgp metric 50\n\
             !\n",
    ));
    // OSPF target — round-trip with protocol=ospf (per corpus
    // convention) but the converter still emits the bgp engine in
    // the protocols list.
    let cfg = roundtrip_ospf(&toml);
    assert_eq!(cfg.redistributes.len(), 1);
    assert_eq!(cfg.redistributes[0].source.as_deref(), Some("bgp"));
    assert_eq!(cfg.redistributes[0].target.as_deref(), Some("ospf"));
    assert_eq!(cfg.redistributes[0].metric, Some(50));
    // The pipe needs both bgp (source) and ospf (target) engines.
    // The order is converter-internal; both names must appear.
    assert!(
        toml.contains("\"bgp\"") && toml.contains("\"ospf\""),
        "expected protocols line listing both bgp and ospf engines, got:\n{toml}"
    );
}

#[test]
fn frr_no_redistribute_is_silently_consumed() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              no redistribute ospf\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert!(
        cfg.redistributes.is_empty(),
        "no redistribute must not produce a [[redistribute]] row"
    );
    assert!(
        !toml.to_lowercase().contains("no redistribute"),
        "no redistribute line must not appear in the rendered TOML"
    );
}

#[test]
fn frr_no_bgp_ebgp_requires_policy_is_silently_consumed() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             no bgp ebgp-requires-policy\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    // lr always emits `ebgp_policy = "accept-all"` (the converter's
    // baseline), which is exactly what `no bgp ebgp-requires-policy`
    // asks for. The FRR directive must not appear as an UNMAPPED
    // note — that would be noise.
    assert!(
        !toml.to_lowercase().contains("ebgp-requires-policy"),
        "no bgp ebgp-requires-policy must not appear in rendered TOML, got:\n{toml}"
    );
    assert_eq!(cfg.local_as, 64512, "router bgp N must still set local_as");
}

#[test]
fn frr_network_with_route_map_keeps_prefix_noting_route_map() {
    let toml = render(translate_frr(
        "router bgp 64512\n\
             address-family ipv4 unicast\n\
              network 203.0.113.0/24 route-map RM-NET\n\
             exit-address-family\n\
             !\n",
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.networks, vec!["203.0.113.0/24".to_string()]);
    assert!(
        toml.contains("network 203.0.113.0/24 route-map RM-NET"),
        "expected unmapped note for the route-map, got:\n{toml}"
    );
}

// ---- RFC 4271 §5.1.6 + RFC 4456 §8: BIRD attribute renames ----

/// BIRD's `bgp_atomic_aggregate`, `bgp_originator_id` and
/// `bgp_cluster_list` attributes rename to lr's dotted spellings and
/// the body compiles in the lr filter DSL. The three arms mirror the
/// canonical route-reflector loop-detection idioms: reject routes
/// whose CLUSTER_LIST contains the local cluster id, reject routes
/// whose ORIGINATOR_ID is the local BGP identifier, and optionally
/// reject ATOMIC_AGGREGATE routes.
#[test]
fn bird_filter_renames_rr_loop_attributes() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;

filter import_rr {
    if defined(bgp_cluster_list) && 10.0.0.1 ~ bgp_cluster_list then reject;
    if bgp_originator_id = 10.0.0.1 then reject;
    if bgp_atomic_aggregate then reject;
    accept;
}

protocol bgp rr_client {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 {
        import filter import_rr;
        export all;
    };
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.filters.len(), 1);
    let body = cfg.filters[0].body.as_deref().unwrap_or("");
    // BIRD spelling is gone.
    assert!(!body.contains("bgp_atomic_aggregate"));
    assert!(!body.contains("bgp_originator_id"));
    assert!(!body.contains("bgp_cluster_list"));
    // lr spelling is present.
    assert!(body.contains("bgp.atomic_aggregate"), "body: {body}");
    assert!(body.contains("bgp.originator_id"), "body: {body}");
    assert!(body.contains("bgp.cluster_list"), "body: {body}");
    // BIRD `=` for equality swapped to lr `==`.
    assert!(
        body.contains("bgp.originator_id == 10.0.0.1"),
        "body: {body}"
    );
    // `defined()` and `~` survive verbatim — they share spelling
    // between BIRD and lr.
    assert!(body.contains("defined(bgp.cluster_list)"), "body: {body}");
    assert!(body.contains("10.0.0.1 ~ bgp.cluster_list"), "body: {body}");
}

// ---- RFC 9234 §3.1: BIRD attribute rename for OTC ----

/// BIRD's `bgp_otc` attribute renames to lr's `bgp.otc` and the body
/// compiles in the lr filter DSL. The two arms mirror the canonical
/// RFC 9234 leak-detection idioms: reject routes that carry OTC on
/// import from a peer/provider (the route is "customer-only" and
/// must not transit upstream), and `defined(bgp_otc)` to distinguish
/// "absent" from "set to zero".
#[test]
fn bird_filter_renames_otc_attribute() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;

filter import_otc {
    if defined(bgp_otc) && bgp_otc != 0 then reject;
    if bgp_otc = 0 then accept;
    reject;
}

protocol bgp customer {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 {
        import filter import_otc;
        export all;
    };
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.filters.len(), 1);
    let body = cfg.filters[0].body.as_deref().unwrap_or("");
    // BIRD spelling is gone.
    assert!(!body.contains("bgp_otc"), "body: {body}");
    // lr spelling is present.
    assert!(body.contains("bgp.otc"), "body: {body}");
    // BIRD `=` for equality swapped to lr `==`.
    assert!(body.contains("bgp.otc == 0"), "body: {body}");
    assert!(body.contains("bgp.otc != 0"), "body: {body}");
    // `defined()` survives verbatim — it shares spelling between
    // BIRD and lr.
    assert!(body.contains("defined(bgp.otc)"), "body: {body}");
}

/// RFC 7311 AIGP metric-comparison idioms: prefer lower-metric paths
/// and `defined(bgp_aigp)` to distinguish "absent" from "set to zero".
#[test]
fn bird_filter_renames_aigp_attribute() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;

filter import_aigp {
    if defined(bgp_aigp) && bgp_aigp < 100 then accept;
    if bgp_aigp = 0 then accept;
    reject;
}

protocol bgp customer {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 {
        import filter import_aigp;
        export all;
    };
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.filters.len(), 1);
    let body = cfg.filters[0].body.as_deref().unwrap_or("");
    // BIRD spelling is gone.
    assert!(!body.contains("bgp_aigp"), "body: {body}");
    // lr spelling is present.
    assert!(body.contains("bgp.aigp"), "body: {body}");
    // BIRD `=` for equality swapped to lr `==`.
    assert!(body.contains("bgp.aigp == 0"), "body: {body}");
    assert!(body.contains("bgp.aigp < 100"), "body: {body}");
    // `defined()` survives verbatim — it shares spelling between
    // BIRD and lr.
    assert!(body.contains("defined(bgp.aigp)"), "body: {body}");
}

// ---- RFC 4271 §5.1.7: BIRD attribute rename for AGGREGATOR ----

/// BIRD's `bgp_aggregator` attribute renames to lr's
/// `bgp.aggregator.asn` and the body compiles in the lr filter DSL.
/// The canonical BIRD idiom is `defined(bgp_aggregator)` ("was this
/// route aggregated?"); the rename maps it to
/// `defined(bgp.aggregator.asn)`, which is faithful because the AS
/// and speaker are present together or absent together. A bare
/// comparison on the aggregator value (`bgp_aggregator = 0`) maps to
/// the AS-number component.
#[test]
fn bird_filter_renames_aggregator_attribute() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;

filter import_aggregator {
    if defined(bgp_aggregator) then accept;
    if bgp_aggregator = 0 then accept;
    reject;
}

protocol bgp customer {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 {
        import filter import_aggregator;
        export all;
    };
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.filters.len(), 1);
    let body = cfg.filters[0].body.as_deref().unwrap_or("");
    // BIRD spelling is gone.
    assert!(!body.contains("bgp_aggregator"), "body: {body}");
    // lr spelling is present — the canonical probe for `defined()`.
    assert!(body.contains("bgp.aggregator.asn"), "body: {body}");
    // BIRD `=` for equality swapped to lr `==`.
    assert!(body.contains("bgp.aggregator.asn == 0"), "body: {body}");
    // `defined()` survives verbatim — it shares spelling between
    // BIRD and lr.
    assert!(body.contains("defined(bgp.aggregator.asn)"), "body: {body}");
}

// ---- RFC 6514 §5: BIRD attribute rename for PMSI Tunnel ----

/// BIRD's `bgp_pmsi_tunnel` attribute renames to lr's
/// `bgp.pmsi_tunnel` and the body compiles in the lr filter DSL.
/// The canonical BIRD idiom is `defined(bgp_pmsi_tunnel)` ("does
/// the route carry a PMSI Tunnel binding — i.e. is it an MVPN
/// A-D route?"); the rename maps it to `defined(bgp.pmsi_tunnel)`,
/// which is faithful because BIRD exposes the attribute as an
/// opaque bytestring (`EAF_TYPE_OPAQUE` + `T_ENUM_EMPTY`) and lr's
/// DSL mirrors that surface as a read-only `Bool` field.
#[test]
fn bird_filter_renames_pmsi_tunnel_attribute() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;

filter import_pmsi {
    if defined(bgp_pmsi_tunnel) then reject;
    if !defined(bgp_pmsi_tunnel) then accept;
    reject;
}

protocol bgp customer {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 {
        import filter import_pmsi;
        export all;
    };
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.filters.len(), 1);
    let body = cfg.filters[0].body.as_deref().unwrap_or("");
    // BIRD spelling is gone.
    assert!(!body.contains("bgp_pmsi_tunnel"), "body: {body}");
    // lr spelling is present.
    assert!(body.contains("bgp.pmsi_tunnel"), "body: {body}");
    // `defined()` survives verbatim — it shares spelling between
    // BIRD and lr.
    assert!(body.contains("defined(bgp.pmsi_tunnel)"), "body: {body}");
    assert!(body.contains("!defined(bgp.pmsi_tunnel)"), "body: {body}");
}

// ---- RFC 4456 §3 + §10: route-reflector wiring (BIRD + FRR) ----

/// BIRD's `rr client;` directive (RFC 4456 §3) maps onto the per-peer
/// `route_reflector_client = true` TOML key. Without it the converter
/// would push the line to `# UNMAPPED:`, forcing the operator to
/// hand-migrate every RR-client peer; with it a BIRD config carrying
/// the directive runs unchanged.
#[test]
fn bird_rr_client_maps_to_peer_route_reflector_client() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;

protocol bgp rr_client_a {
    local as 64512;
    neighbor 192.0.2.2 as 64512;
    rr client;
    ipv4 {
        import all;
        export all;
    };
}

protocol bgp non_client {
    local as 64512;
    neighbor 192.0.2.3 as 64512;
    ipv4 {
        import all;
        export all;
    };
}
"#,
    ));
    let cfg = roundtrip(&toml);
    // The first peer (rr_client_a) carries the directive; the
    // second (non_client) does not. Both peers should round-trip.
    assert_eq!(cfg.peers.len(), 2);
    let rr = cfg
        .peers
        .iter()
        .find(|p| p.name.as_deref() == Some("rr_client_a"))
        .expect("rr_client_a peer survived round-trip");
    assert_eq!(
        rr.route_reflector_client,
        Some(true),
        "rr client maps to route_reflector_client = true"
    );
    let non = cfg
        .peers
        .iter()
        .find(|p| p.name.as_deref() == Some("non_client"))
        .expect("non_client peer survived round-trip");
    assert_eq!(
        non.route_reflector_client, None,
        "no rr client = no route_reflector_client key"
    );
    // The rendered TOML must carry the key for the RR client peer
    // and not carry it for the non-client peer.
    assert!(
        toml.contains("route_reflector_client = true"),
        "expected `route_reflector_client = true` in rendered TOML:\n{toml}"
    );
    // The unmapped list must NOT keep the original `rr client;`
    // line as a fallback note — the directive mapped successfully.
    assert!(
        !toml.contains("# UNMAPPED: rr client"),
        "rr client should not appear as UNMAPPED:\n{toml}"
    );
}

/// BIRD's `route reflector cluster_id A.B.C.D;` (RFC 4456 §10) maps
/// onto the router-wide `[bgp] route_reflector_cluster_id` key. The
/// directive appears inside a `protocol bgp` stanza in BIRD, but lr
/// keys it off the `[bgp]` global — last write wins when the source
/// has multiple RR-client peers, mirroring BIRD's own router-wide
/// effective cluster id. `cluster_id 0.0.0.0` is BIRD's spelling for
/// "use the local router id", which is lr's default fall-through too;
/// it is silently dropped so the generated config stays minimal.
#[test]
fn bird_route_reflector_cluster_id_maps_to_global() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;

protocol bgp rr_client_a {
    local as 64512;
    neighbor 192.0.2.2 as 64512;
    rr client;
    route reflector cluster_id 10.0.0.254;
    ipv4 {
        import all;
        export all;
    };
}
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(
        cfg.route_reflector_cluster_id.as_deref(),
        Some("10.0.0.254"),
        "route reflector cluster_id maps to [bgp] route_reflector_cluster_id"
    );
    assert!(
        toml.contains("route_reflector_cluster_id = \"10.0.0.254\""),
        "expected `route_reflector_cluster_id = \"10.0.0.254\"` in rendered TOML:\n{toml}"
    );
}

#[test]
fn bird_route_reflector_cluster_id_zero_drops_silently() {
    let toml = render(translate_bird(
        r#"
router id 10.0.0.1;

protocol bgp rr_client_a {
    local as 64512;
    neighbor 192.0.2.2 as 64512;
    rr client;
    route reflector cluster_id 0.0.0.0;
    ipv4 {
        import all;
        export all;
    };
}
"#,
    ));
    let cfg = roundtrip(&toml);
    // 0.0.0.0 is BIRD's "fall back to the local router id" spelling,
    // which is also lr's default — no key needs to be emitted.
    assert_eq!(
        cfg.route_reflector_cluster_id, None,
        "cluster_id 0.0.0.0 must not be emitted as a TOML key"
    );
    assert!(
        !toml.contains("route_reflector_cluster_id"),
        "expected no `route_reflector_cluster_id` key in rendered TOML:\n{toml}"
    );
}

/// FRR's `bgp cluster-id A.B.C.D` (RFC 4456 §10) maps onto the
/// router-wide `[bgp] route_reflector_cluster_id` key. The integer
/// form FRR also accepts (`bgp cluster-id 16843009`) does not map —
/// lr keeps the IPv4-dotted-quad spelling and surfaces the original
/// line as `# UNMAPPED:` so the operator can convert it manually.
#[test]
fn frr_bgp_cluster_id_maps_to_global() {
    let toml = render(translate_frr(
        r#"
router bgp 64512
 bgp router-id 10.0.0.1
 bgp cluster-id 10.0.0.254
 neighbor 192.0.2.2 remote-as 64512
!
 address-family ipv4 unicast
  neighbor 192.0.2.2 route-reflector-client
 exit-address-family
!
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(
        cfg.route_reflector_cluster_id.as_deref(),
        Some("10.0.0.254"),
        "FRR bgp cluster-id maps to [bgp] route_reflector_cluster_id"
    );
    assert!(
        toml.contains("route_reflector_cluster_id = \"10.0.0.254\""),
        "expected `route_reflector_cluster_id = \"10.0.0.254\"` in rendered TOML:\n{toml}"
    );
}

#[test]
fn frr_bgp_cluster_id_integer_form_is_unmapped() {
    let toml = render(translate_frr(
        r#"
router bgp 64512
 bgp router-id 10.0.0.1
 bgp cluster-id 16843009
 neighbor 192.0.2.2 remote-as 64512
!
"#,
    ));
    // The integer form (1.1.1.1 in dotted-quad) does not parse as
    // `ClusterId` (the parser requires an IPv4 dotted-quad), so the
    // converter surfaces the original line as `# UNMAPPED:` instead
    // of silently producing a config the daemon would refuse to
    // load. The rendered TOML must not carry `route_reflector_cluster_id`.
    assert!(
        toml.contains("integer cluster-id form not mapped"),
        "expected an UNMAPPED note for the integer cluster id:\n{toml}"
    );
    assert!(
        !toml.contains("route_reflector_cluster_id"),
        "expected no `route_reflector_cluster_id` key for integer form:\n{toml}"
    );
}

/// FRR's `neighbor ADDR route-reflector-client` (RFC 4456 §3), which
/// FRR only allows inside an `address-family` block, maps onto the
/// per-peer `route_reflector_client = true` TOML key. Without it the
/// directive would land in `# UNMAPPED:` like the `bgp cluster-id`
/// integer form above; with it an FRR config carrying the directive
/// runs unchanged.
#[test]
fn frr_neighbor_route_reflector_client_maps_per_peer() {
    let toml = render(translate_frr(
        r#"
router bgp 64512
 bgp router-id 10.0.0.1
 bgp cluster-id 10.0.0.254
 neighbor 192.0.2.2 remote-as 64512
 neighbor 192.0.2.3 remote-as 64512
!
 address-family ipv4 unicast
  neighbor 192.0.2.2 route-reflector-client
 exit-address-family
!
"#,
    ));
    let cfg = roundtrip(&toml);
    assert_eq!(cfg.peers.len(), 2);
    let rr = cfg
        .peers
        .iter()
        .find(|p| p.remote.as_deref() == Some("192.0.2.2"))
        .expect("RR client peer survived round-trip");
    assert_eq!(
        rr.route_reflector_client,
        Some(true),
        "neighbor X route-reflector-client maps to route_reflector_client = true"
    );
    let non = cfg
        .peers
        .iter()
        .find(|p| p.remote.as_deref() == Some("192.0.2.3"))
        .expect("non-client peer survived round-trip");
    assert_eq!(
        non.route_reflector_client, None,
        "peer without route-reflector-client stays unset"
    );
    // The rendered TOML must carry the key for the RR client peer
    // and not carry an UNMAPPED note for the directive.
    assert!(
        toml.contains("route_reflector_client = true"),
        "expected `route_reflector_client = true` in rendered TOML:\n{toml}"
    );
    assert!(
        !toml.contains("# UNMAPPED: neighbor 192.0.2.2 route-reflector-client"),
        "route-reflector-client should not appear as UNMAPPED:\n{toml}"
    );
}
