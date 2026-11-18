use super::*;
use crate::config_dsl::parse_dsl_text;
use crate::daemon_config::parse_toml_subset;

/// The round-trip property: parse TOML, render `.lr`, parse the
/// `.lr`, compare IRs byte-for-byte (`PartialEq`).
fn round_trip(toml: &str) -> (DaemonConfig, DaemonConfig) {
    let mut first = DaemonConfig::default();
    parse_toml_subset(toml, &mut first).expect("toml parses");
    let dsl = to_dsl(&first).expect("converts");
    let mut second = DaemonConfig::default();
    parse_dsl_text(&dsl, None, &mut second).expect("dsl parses");
    (first, second)
}

#[test]
fn round_trips_a_multi_protocol_config() {
    let toml = r#"
protocol = "bgp,ospf"
user = "lr"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
hold_time = 30
gtsm = 1
max_prefixes = 5000
networks = ["203.0.113.0/24"]
[[peer]]
name = "core-1"
remote = "192.0.2.2:179"
peer_as = 65010
import_filter = "in"
[[filter]]
name = "in"
body = "if net ~ [10.0.0.0/8+] then accept;\nelse reject;"
[ospf]
hello_interval = 10
[[ospf.interface]]
name = "eth0"
cost = 10
"#;
    let (first, second) = round_trip(toml);
    assert_eq!(first, second);
}

#[test]
fn round_trips_the_shipped_template() {
    let toml = std::fs::read_to_string("../../templates/daemon.toml").expect("template exists");
    let (first, second) = round_trip(&toml);
    assert_eq!(first, second);
}

#[test]
fn refuses_configs_with_parse_warnings() {
    let mut cfg = DaemonConfig::default();
    parse_toml_subset("[mystery]\nx = 1\n", &mut cfg).unwrap();
    let err = to_dsl(&cfg).unwrap_err();
    assert!(err.contains("refusing to convert"), "{err}");
}

#[test]
fn refuses_filters_with_descriptions() {
    let mut cfg = DaemonConfig::default();
    parse_toml_subset(
        "[[filter]]\nname = \"f\"\nbody = \"accept;\"\ndescription = \"why\"\n",
        &mut cfg,
    )
    .unwrap();
    let err = to_dsl(&cfg).unwrap_err();
    assert!(err.contains("description"), "{err}");
}

// ---- issue #92 (defects.txt L75): [[bgp.network_route_map]] DSL round-trip ----

/// A TOML config with `[[bgp.network_route_map]]` round-trips through
/// the `.lr` DSL — the DSL emitter produces a
/// `bgp.network_route_map { prefix = …; route_map = … }` block and
/// the DSL parser reads it back into the same IR.
#[test]
fn round_trips_bgp_network_route_map_table() {
    let toml = r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
networks = ["203.0.113.0/24"]

[[route-map]]
name = "mark"
entry = 10
set_local_pref = 250
permit = true

[[bgp.network_route_map]]
prefix = "203.0.113.0/24"
route_map = "mark"
"#;
    let (first, second) = round_trip(toml);
    assert_eq!(first, second);
    assert_eq!(first.network_route_maps.len(), 1);
    assert_eq!(
        first.network_route_maps[0].prefix.as_deref(),
        Some("203.0.113.0/24")
    );
    assert_eq!(
        first.network_route_maps[0].route_map.as_deref(),
        Some("mark")
    );
}

/// Multiple `[[bgp.network_route_map]]` entries round-trip
/// independently — each maps to one `bgp.network_route_map` block in
/// the DSL and one row in the IR. Pins the array-table shape
/// (the DSL emitter writes one block per entry; the parser pushes
/// one NetworkRouteMapSpec per block).
#[test]
fn round_trips_multiple_bgp_network_route_map_tables() {
    let toml = r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
networks = ["203.0.113.0/24", "198.51.100.0/24"]

[[route-map]]
name = "mark1"
entry = 10
permit = true

[[route-map]]
name = "mark2"
entry = 10
permit = true

[[bgp.network_route_map]]
prefix = "203.0.113.0/24"
route_map = "mark1"

[[bgp.network_route_map]]
prefix = "198.51.100.0/24"
route_map = "mark2"
"#;
    let (first, second) = round_trip(toml);
    assert_eq!(first, second);
    assert_eq!(first.network_route_maps.len(), 2);
}

// ---- [shutdown] and [bgp.peer_health] have a DSL spelling ----

/// A drain configuration survives `to-dsl` instead of being dropped:
/// the emitted `shutdown { … }` block re-parses to the same IR.
#[test]
fn round_trips_shutdown_drain() {
    let toml = r#"
[shutdown]
mode = "drain"
drain_rate_per_sec = 25
drain_max_wait_secs = 120
"#;
    let (first, second) = round_trip(toml);
    assert_eq!(first, second);
    assert_eq!(first.shutdown_mode, "drain");
    assert_eq!(first.shutdown_drain_rate_per_sec, 25);
    assert_eq!(first.shutdown_drain_max_wait_secs, 120);
}

/// `[bgp.peer_health]` lowers to a nested `bgp { peer-health { … } }`
/// block and round-trips, including the tuning keys.
#[test]
fn round_trips_peer_health_table() {
    let toml = r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"

[bgp.peer_health]
rollout = "limited"
short_window_s = 10
baseline_window_s = 600
soft_degraded = 5
"#;
    let (first, second) = round_trip(toml);
    assert_eq!(first, second);
    assert!(first.peer_health.is_enabled());
    assert_eq!(first.peer_health.rollout, "limited");
    assert_eq!(first.peer_health.config.short_window.window_s, 10);
    assert_eq!(first.peer_health.config.baseline_window_s, 600);
    assert_eq!(first.peer_health.config.global_budgets.soft_degraded, 5);
}

// ---- issue #101: `[[filter_function]]` DSL round-trip ----

/// A TOML config with `[[filter_function]]` round-trips through the
/// `.lr` DSL — the emitter renders a `filter-function "name" { … }`
/// block and the DSL parser reads it back into the same IR. The
/// shared-function preamble path was previously broken in the DSL
/// (the `enter_array` dispatch had no `filter_function` arm), so the
/// DSL form of this block failed at parse time. This test pins the
/// round-trip so the regression cannot return.
#[test]
fn round_trips_filter_function_table() {
    let toml = r#"
[[filter_function]]
name = "tag_customer"
params = ["lp"]
body = "bgp.local_pref = lp; return true;"

[[filter_function]]
name = "classify"
param = "lp"
return_type = "int"
body = "if lp >= 200 then return 300; return 100;"

[[filter]]
name = "in"
body = "tag_customer(classify(200)); accept;"
"#;
    let (first, second) = round_trip(toml);
    assert_eq!(first, second);
    assert_eq!(first.filter_functions.len(), 2);
    assert_eq!(
        first.filter_functions[0].name.as_deref(),
        Some("tag_customer")
    );
    assert_eq!(first.filter_functions[0].params, vec!["lp".to_string()]);
    assert_eq!(
        first.filter_functions[0].body.as_deref(),
        Some("bgp.local_pref = lp; return true;")
    );
    assert_eq!(first.filter_functions[1].name.as_deref(), Some("classify"));
    assert_eq!(first.filter_functions[1].params, vec!["lp".to_string()]);
    assert_eq!(
        first.filter_functions[1].return_type.as_deref(),
        Some("int")
    );
}

/// A filter body that uses IPv6 prefixes whose hextets are all
/// decimal must round-trip too. The DSL lexer previously
/// mis-classified these as community pairs (see the lexer regression
/// tests in `crates/lr-policy/src/filter/lexer.rs`); this test pins
/// the IR-level round-trip so the same defect cannot return through
/// the config pipeline.
#[test]
fn round_trips_filter_body_with_decimal_only_ipv6() {
    let toml = r#"
[[filter]]
name = "v6"
body = "if net ~ [2001:1::/32, 2606:4700:4700::1111/64] then accept; reject;"
"#;
    let (first, second) = round_trip(toml);
    assert_eq!(first, second);
    assert_eq!(first.filters.len(), 1);
    assert_eq!(first.filters[0].name.as_deref(), Some("v6"));
    assert_eq!(
        first.filters[0].body.as_deref(),
        Some("if net ~ [2001:1::/32, 2606:4700:4700::1111/64] then accept; reject;")
    );
}
