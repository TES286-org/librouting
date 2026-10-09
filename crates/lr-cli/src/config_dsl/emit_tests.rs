
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
