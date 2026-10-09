use super::*;
use crate::config_dsl::parse_dsl_text;
use crate::daemon_config::parse_toml_subset;

/// Every key of every section, in one file. If the converter
/// misses a field or renders a key wrong, this round-trip fails
/// with a field-level diff — it is the completeness oracle for
/// the whole schema.
#[test]
fn round_trips_every_key_of_every_section() {
    let toml = r#"
# --- top level ---
protocol = "bgp,ospf"
user = "lr"
group = "netops"
api_socket = "/run/lr/api.sock"
metrics_addr = "127.0.0.1:9640"
networks = ["203.0.113.0/24"]
labeled_networks = ["198.51.100.0/24"]
roa_validate = true
roa_invalid_action = "warn"

# --- [bgp]: the full schema ---
[bgp]
local_as = 64512
peer_as = 64513
router_id = "10.0.0.1"
peer_addr = "192.0.2.2:179"
listen_addr = "0.0.0.0:179"
local_address = "192.0.2.1"
hold_time = 45
graceful_restart_time = 100
llgr_stale_time = 200
llgr_max_stale_time = 300
md5_key = "s3cret"
tcp_ao_keys = ["ao-key-1"]
tcp_ao_algorithm = "hmac-sha1"
tcp_ao_maclen = 12
install_kernel = true
add_path = true
add_path_max_paths = 8
mp_families = ["ipv4-unicast", "ipv6-unicast"]
extended_next_hop = true
local_address_v6 = "2001:db8::1"
gtsm = 1
max_prefixes = 5000
max_prefix_action = "restart"
max_prefix_threshold = 80
bfd = true
bfd_multihop = true
bfd_min_tx_ms = 500
bfd_min_rx_ms = 500
bfd_multiplier = 4
bmp_target = "127.0.0.1:5000"
ebgp_policy = "accept-all"
enforce_first_as = true
bestpath_compare_routerid = true
default_ipv4_unicast = true
allow_local_as = 3
soft_reconfig_inbound = true
exchange_plane = true
exchange_plane_keys = ["secret-a"]
graceful_shutdown = true

[bgp.rpki]
cache = "rtr.example.net:3323"
refresh_interval = 300
retry_interval = 30
expire_interval = 3600

# --- peers and templates ---
[[peer]]
name = "core-1"
remote = "192.0.2.2:179"
address = "192.0.2.9"
peer_as = 65010
extends = "rr-client"
import = "to-customer"
export = "to-customer"
import_filter = "in"
export_filter = "in"
hold_time = 30
graceful_restart_time = 90
llgr_stale_time = 100
llgr_max_stale_time = 200
local_address = "192.0.2.1"
local_address_v6 = "2001:db8::1"
md5_key = "peer-secret"
tcp_ao_keys = ["ao-key-1"]
tcp_ao_algorithm = "hmac-sha1"
tcp_ao_maclen = 12
add_path = true
add_path_max_paths = 4
mp_families = ["ipv4-unicast"]
default_ipv4_unicast = true
allow_local_as = 1
soft_reconfig_inbound = true
extended_next_hop = true
gtsm = 1
max_prefixes = 1000
max_prefix_action = "shutdown"
max_prefix_threshold = 70
bfd = true
bfd_multihop = false
exchange_plane = true
graceful_shutdown = true

[peer-template.rr-client]
remote = "192.0.2.20:179"
peer_as = 65100
hold_time = 20
add_path = false
mp_families = ["ipv4-unicast"]

# --- policy bank ---
[[prefix-list]]
name = "customer"
prefix = "203.0.113.0/24"
permit = true
ge = 24
le = 32

[[as-path-list]]
name = "as-customer"
pattern = "65010"
permit = false

[[community-list]]
name = "comm-customer"
communities = ["65010:1", "65010:2"]
permit = true

[[route-map]]
name = "to-customer"
entry = 10
match_prefix = "customer"
match_as_path = "as-customer"
match_community = "comm-customer"
permit = true
set_local_pref = 200
set_med = 50
set_metric = 100
set_next_hop = "192.0.2.1"
prepend = "65000 65000"
add_community = "65000:100"

[[filter]]
name = "in"
body = "if net ~ [10.0.0.0/8+] then accept;\n# braces } and \"quotes\" survive\nelse reject;"

# --- roa / redistribution / aggregation ---
[[roa]]
prefix = "203.0.113.0/24"
max_len = 24
origin_as = 65010

[[redistribute]]
source = "ospf"
target = "bgp"
metric = 100
tag = 65000
allow = ["10.0.0.0/8"]

[[aggregate]]
prefix = "10.0.0.0/8"

# --- ospf: full schema ---
[ospf]
version = "v2"
hello_interval = 15
dead_interval = 60
graceful_restart = true
grace_period = 90
graceful_restart_helper = true
helper_grace_cap = 100
gr_state_file = "/var/lib/lr/ospf-gr.state"
srgb_base = 16000
srgb_range = 1000
sr_receive = true
srv6_receive = true
srv6_o_flag = true
extended_lsas = true
srv6_max_sl = 8
srv6_max_end_pop = 1
srv6_max_h_encaps = 1
srv6_max_end_d = 1

[[ospf.area]]
id = 1
type = "stub"
no_summary = true
stub_metric = 100

[[ospf.interface]]
name = "eth0"
area = 1
cost = 10
hello_interval = 10
dead_interval = 40
priority = 2
network_type = "broadcast"
adj_sid = 100
srv6_end_x = "2001:db8:aa::"
srv6_end_x_lan = "2001:db8:ab::/96"

[[ospf.prefix_sid]]
prefix = "10.0.0.0/8"
sid = 200
node = true
no_php = true

[[ospf.mapping_server]]
prefix = "10.1.0.0/16"
sid = 300
range_size = 4
no_php = false

[[ospf.srv6_locator]]
prefix = "2001:db8:ab::/48"
algorithm = 0
metric = 10
anycast = false
sid = "D::"
behavior = 4
block_len = 32
node_len = 16
function_len = 0
argument_len = 0

# --- babel: full schema ---
[babel]
group = "lab"
port = 6696
accept_unauthenticated = true
split_unicast_multicast = true
pc_window = 120

[[babel.key]]
secret = "babel-secret"
algorithm = "blake2s"
interface = "eth*"

[[babel.interface]]
name = "eth1"
type = "wired"
hello_interval_ms = 4000
update_interval_ms = 16000
rxcost = 96
rtt_cost = 200
rtt_min_us = 1000
rtt_max_us = 2000
next_hop_ipv4 = "192.0.2.30"
next_hop_ipv6 = "2001:db8::30"
extended_next_hop = true
check_link = true
port = 6697
group = "lab"

# --- ldp: full schema ---
[ldp]
transport = "192.0.2.1"
transport_v6 = "2001:db8::1"
prefer_ipv6 = true
install_kernel = true
label_min = 200
label_max = 5000
transit_allocation = true
graceful_restart = true
gr_reconnect_ms = 10000
gr_recovery_ms = 20000
port = 646
keepalive_time = 30
link_hold_time = 20
targeted_hold_time = 45
loop_detection = true
loop_hop_count_limit = 5
loop_path_vector_limit = 10

[[ldp.interface]]
name = "eth0"

[[ldp.targeted]]
address = "192.0.2.9"

[[ldp.bind]]
prefix = "10.0.0.0/8"
label = 1000

# --- damping ---
[damping]
enabled = true
additive_incr = 2000
suppress_threshold = 3000
reuse_threshold = 800
upper_limit = 60001
decay_interval_s = 20
decay_factor_active = 0.95
decay_factor_withdrawn = 0.6
"#;
    let mut first = DaemonConfig::default();
    parse_toml_subset(toml, &mut first).expect("kitchen-sink TOML parses");
    assert!(
        first.warnings.is_empty(),
        "fixture must parse clean: {:?}",
        first.warnings
    );
    let dsl = to_dsl(&first).expect("converts");
    let mut second = DaemonConfig::default();
    parse_dsl_text(&dsl, None, &mut second).expect("rendered DSL parses");
    assert_eq!(first, second, "IR must survive TOML → DSL → IR");
}
