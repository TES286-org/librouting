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
