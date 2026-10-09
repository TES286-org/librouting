# `lr-daemon` flag and configuration reference

This is the exhaustive reference for the `lr-daemon` command line and
its configuration file. Every flag below is a `match` arm in
`daemon_config::parse_args`; every configuration key is a `match` arm in
`daemon_config::apply_config_key` or one of the per-section appliers it
dispatches to. Read it when you need a default, the exact spelling of a
key, or the name of the config equivalent of a flag.

The narrative guide is [lr-daemon.md](lr-daemon.md); the `.lr` grammar
is [config_dsl_grammar.md](config_dsl_grammar.md); the commented
reference config is [`templates/daemon.lr`](../templates/daemon.lr).

## Invocation

```text
lr-daemon [flags]
lr-daemon translate <bird|frr> <config-file>
lr-daemon yang render <config-file> [--model babel|keychain|all]
lr-daemon config check   [--dialect lr|toml|bird|frr] <config-file>
lr-daemon config to-dsl  [--dialect lr|toml|bird|frr] <config-file>
```

There is no `-c`; the short form does not exist. Config files are loaded
with `--config PATH`.

Exit codes differ per subcommand, which matters in scripts:

| Invocation | 0 | 1 | 2 |
| --- | --- | --- | --- |
| daemon | Graceful stop, `--help` | Config load failed, engine or session setup failed, signal handler install failed | Usage error, bad flag value, failed `finalize`, missing `--local-as` / `--router-id`, unknown `--protocol` |
| `config check` | File is valid (even with warnings) | Load or `finalize` failed | Usage, unknown option, missing file argument |
| `config to-dsl` | `.lr` program on stdout | Load failed, or conversion refused | Usage, unknown option, missing file argument |
| `yang render` | XML on stdout, or `nothing to render` | — | Every failure: usage, unreadable file, parse error, render error |
| `translate` | Converted config on stdout | File could not be read | Usage, missing argument, unknown dialect |

`yang render` is the odd one out: unlike `config check` and
`config to-dsl` it uses exit 2 for a config it cannot render, and it
accepts only the TOML subset — there is no `--dialect` and no `.lr`
input.

A daemon that stops because a sibling engine died in a protocol
combination returns that engine's exit code; an engine aborted *by* a
sibling returns 0 so the supervisor's code wins.

## Configuration dialects

`--config PATH` loads one file. The dialect is recognised from the
content; `--config-dialect` forces one and accepts `bird`, `frr`, `toml`
and `lr`. The daemon's own usage banner lists only `bird | frr | toml`,
but `lr` is accepted and is what an unstamped `.lr` file resolves to.
The resolved dialect is stamped into the config and reused by `SIGHUP`
and the API `reload`, so a compat-mode daemon keeps re-parsing the same
way. See [COMPAT.md](COMPAT.md) for the BIRD/FRR mapping surface.

The TOML subset is deprecated: loading one prints
`config deprecation: the TOML configuration dialect is deprecated - …`
to stderr, and the same notice rides every reload.

## Flags

### General

| Flag | Config equivalent | Notes |
| --- | --- | --- |
| `--config PATH` | — | The file to load |
| `--config-dialect D` | — | `bird`, `frr`, `toml`, `lr` |
| `--protocol PROTO` | `protocol`, `protocols` | Repeatable, comma-separated |
| `--install-kernel-routes` | `[bgp] install_kernel` | Install best routes into the FIB |
| `--user NAME` | `user` | Name or uid; drop after binding |
| `--group NAME` | `group` | Name or gid |
| `--api-socket PATH` | `api_socket` | Unix socket, chmod 0600 |
| `--metrics-addr ADDR` | `metrics_addr` | TCP address for `/metrics` |
| `-h`, `--help` | — | Usage banner, exit 0 |

### BGP identity and peers

| Flag | Config equivalent | Default | Notes |
| --- | --- | --- | --- |
| `--local-as AS` | `[bgp] local_as` | — | Required for BGP |
| `--peer-as AS` | `[bgp] peer_as` | — | Shared by every `--peer` |
| `--router-id A.B.C.D` | `[bgp] router_id` | — | Required except in Babel-only mode |
| `--peer ADDR:PORT` | `[[peer]] remote` | — | Repeatable; outbound only |
| `--listen ADDR:PORT` | `[bgp] listen_addr` | — | Required for inbound peers |
| `--local-address ADDR` | `[bgp] local_address` | — | Source for next-hop-self |
| `--local-address-v6 ADDR` | `[bgp] local_address_v6` | — | IPv6 source for v6/ENH egress |
| `--network PREFIX` | `[bgp] networks` | — | Repeatable |
| `--labeled-network SPEC` | `[bgp] labeled_networks` | — | `"prefix label[,label]"` |
| `--mp-family NAME` | `[bgp] mp_families` | — | Repeatable; four family names |

The recognised `--mp-family` names are `ipv4-unicast`, `ipv6-unicast`,
`ipv4-labeled-unicast` and `ipv6-labeled-unicast`; an unknown name is
logged as `daemon: peer <name>: unknown mp_family '<x>' (skipped)`.

### BGP timers, auth and hardening

| Flag | Config equivalent | Default | Notes |
| --- | --- | --- | --- |
| `--hold-time SEC` | `[bgp] hold_time` | 90 | 0 disables keepalives |
| `--graceful-restart SEC` | `[bgp] graceful_restart_time` | 0 | Off unless set |
| `--llgr SEC` | `[bgp] llgr_stale_time` | 0 | RFC 9494; needs GR |
| `--llgr-max-stale SEC` | `[bgp] llgr_max_stale_time` | 0 | Cap on the peer's value |
| `--md5-key SECRET` | `[bgp] md5_key` | — | RFC 2385 |
| `--tcp-ao-key ID:SECRET` | `[bgp] tcp_ao_keys` | — | Repeatable; RFC 5925 |
| `--tcp-ao-alg ALG` | `[bgp] tcp_ao_algorithm` | `hmac-sha1` | Or `cmac-aes` |
| `--tcp-ao-maclen N` | `[bgp] tcp_ao_maclen` | 0 | 0 = algorithm default |
| `--gtsm [N]` | `[bgp] gtsm` | off | Bare = 1 hop; RFC 5082 |
| `--add-path` | `[bgp] add_path` | off | RFC 7911 |
| `--add-path-max N` | `[bgp] add_path_max_paths` | 6 | Paths per prefix |
| `--extended-next-hop` | `[bgp] extended_next_hop` | off | RFC 5549 |
| `--bmp-target ADDR:PORT` | `[bgp] bmp_target` | — | RFC 7854 station |

The graceful-restart field default is 0, so the daemon advertises no
restart time unless `--graceful-restart` or `graceful_restart_time` sets
one — the shipped `templates/daemon.lr` sets 120. The `120` in the
flag's parser is only the fallback for an unparseable argument.

### BGP policy and limits

| Flag | Config equivalent | Default | Notes |
| --- | --- | --- | --- |
| `--ebgp-policy MODE` | `[bgp] ebgp_policy` | `rfc8212` | Or `accept-all` |
| `--enforce-first-as` | `[bgp] enforce_first_as` | off | FRR parity |
| `--no-enforce-first-as` | `[bgp] enforce_first_as` | off | |
| `--bestpath-compare-routerid` | `[bgp] bestpath_compare_routerid` | on | RFC 5004 |
| `--no-bestpath-compare-routerid` | `[bgp] bestpath_compare_routerid` | | Oldest-route-wins |
| `--default-ipv4-unicast` | `[bgp] default_ipv4_unicast` | on | FRR parity |
| `--no-default-ipv4-unicast` | `[bgp] default_ipv4_unicast` | | Explicit activation |
| `--allow-local-as [N]` | `[bgp] allow_local_as` | 0 | Bare = N=1 |
| `--allowas-any` | `[bgp] allow_local_as` | 0 | Sets `u32::MAX` |
| `--soft-reconfig-inbound` | `[bgp] soft_reconfig_inbound` | off | Retains pre-policy Adj-RIB-In |
| `--no-soft-reconfig-inbound` | `[bgp] soft_reconfig_inbound` | off | |
| `--max-prefixes N` | `[bgp] max_prefixes` | none | 0 = no limit |
| `--max-prefix-action A` | `[bgp] max_prefix_action` | `warn` | `warn`, `teardown`, `restart` |
| `--max-prefix-threshold P` | `[bgp] max_prefix_threshold` | 75 | Percent |

`warn` only logs; a session is torn down only with `--max-prefix-action
teardown` or `restart`. The daemon does not validate the action string —
anything that is not `teardown` or `restart` is treated as `warn`.

### BFD

| Flag | Config equivalent | Default | Notes |
| --- | --- | --- | --- |
| `--bfd` | `[bgp] bfd` | off | RFC 5880/5881 |
| `--bfd-multihop` | `[bgp] bfd_multihop` | off | RFC 5883, UDP 4784 |
| `--bfd-min-tx-ms MS` | `[bgp] bfd_min_tx_ms` | 100 | |
| `--bfd-min-rx-ms MS` | `[bgp] bfd_min_rx_ms` | 100 | |
| `--bfd-multiplier N` | `[bgp] bfd_multiplier` | 3 | |

### Babel

| Flag | Config equivalent | Default | Notes |
| --- | --- | --- | --- |
| `--babel-group ADDR` | `[babel] group` | family default | `ff02::1:6`, `224.0.0.111` |
| `--babel-port PORT` | `[babel] port` | 6696 | |
| `--babel-key SECRET` | `[[babel.key]] secret` | — | Repeatable; RFC 8967 |
| `--babel-accept-unauthenticated` | `[babel] accept_unauthenticated` | off | RFC 8967 §5 |
| `--babel-no-pc-split` | `[babel] split_unicast_multicast` | on | Clears it |
| `--babel-pc-window N` | `[babel] pc_window` | 0 | RFC 9467 §3.2 |

### OSPF

| Flag | Config equivalent | Default | Notes |
| --- | --- | --- | --- |
| `--ospf-version V` | `[ospf] version` | `v2` | `v2`/`2`, `v3`/`3` |
| `--ospf-interface NAME` | `[[ospf.interface]] name` | — | Repeatable |
| `--ospf-area ID` | — | 0 | Integer or dotted quad |
| `--ospf-hello-interval S` | `[ospf] hello_interval` | 10 | |
| `--ospf-dead-interval S` | `[ospf] dead_interval` | 40 | |

`--ospf-area` sets the default area for interfaces that do not name one.
It has no configuration-file counterpart: the `[ospf]` schema has no
`area` key, so a file must set `area` on each `[[ospf.interface]]`.

### OSPF graceful restart

| Flag | Config equivalent | Default | Notes |
| --- | --- | --- | --- |
| `--ospf-graceful-restart` | `[ospf] graceful_restart` | off | RFC 3623, RFC 5187 |
| `--ospf-no-graceful-restart` | `[ospf] graceful_restart` | off | |
| `--ospf-grace-period S` | `[ospf] grace_period` | 120 | 1..=1800 |
| `--ospf-no-gr-helper` | `[ospf] graceful_restart_helper` | on | Clears it |
| `--ospf-helper-grace-cap S` | `[ospf] helper_grace_cap` | 120 | 1..=1800 |
| `--ospf-gr-state-file PATH` | `[ospf] gr_state_file` | `<api-socket>.gr` | |

### OSPF Segment Routing and SRv6

| Flag | Config equivalent | Notes |
| --- | --- | --- |
| `--ospf-srv6-locator PREFIX` | `[[ospf.srv6_locator]] prefix` | Repeatable; v3 only |
| `--ospf-srv6-receive` | `[ospf] srv6_receive` | RFC 9513 §5 |
| `--ospf-srv6-o-flag` | `[ospf] srv6_o_flag` | RFC 9259 O-flag |
| `--ospf-extended-lsas` | `[ospf] extended_lsas` | RFC 8362, v3 only |

There are no flags for the SR-MPLS or MSD knobs. `srgb_base`,
`srgb_range`, `sr_receive`, `adj_sid`, `prefix_sid`,
`mapping_server`, `srv6_max_sl`, `srv6_max_end_pop`,
`srv6_max_h_encaps` and `srv6_max_end_d` are configuration keys only.

### RPKI

| Flag | Config equivalent | Default | Notes |
| --- | --- | --- | --- |
| `--rpki-cache ADDR:PORT` | `[bgp.rpki] cache` | off | RFC 8210, TCP 8282 |
| `--rpki-refresh SEC` | `[bgp.rpki] refresh_interval` | 3600 | Non-zero |
| `--rpki-retry SEC` | `[bgp.rpki] retry_interval` | 600 | Non-zero |
| `--rpki-expire SEC` | `[bgp.rpki] expire_interval` | 7200 | Non-zero |

### LDP

| Flag | Config equivalent | Default | Notes |
| --- | --- | --- | --- |
| `--ldp-transport ADDR` | `[ldp] transport` | first interface | Advertised in Hellos |
| `--ldp-transport-v6 ADDR` | `[ldp] transport_v6` | first global v6 | RFC 7552 §6.1 |
| `--ldp-prefer-ipv4` | `[ldp] prefer_ipv6` | v6 preferred | Clears it |
| `--ldp-port PORT` | `[ldp] port` | 646 | |
| `--ldp-keepalive SEC` | `[ldp] keepalive_time` | 15 | |
| `--ldp-link-hold SEC` | `[ldp] link_hold_time` | 15 | |
| `--ldp-targeted-hold SEC` | `[ldp] targeted_hold_time` | 45 | |
| `--ldp-interface NAME` | `[[ldp.interface]] name` | — | Repeatable |
| `--ldp-targeted ADDR` | `[[ldp.targeted]] address` | — | Repeatable |
| `--ldp-bind PFX[=LABEL]` | `[[ldp.bind]] prefix`/`label` | — | Repeatable |
| `--ldp-install-kernel` | `[ldp] install_kernel` | off | Linux `AF_MPLS` |
| `--ldp-label-min N` | `[ldp] label_min` | 16 | |
| `--ldp-label-max N` | `[ldp] label_max` | 1048575 | |
| `--ldp-no-transit` | `[ldp] transit_allocation` | on | Clears it |
| `--ldp-graceful-restart` | `[ldp] graceful_restart` | off | RFC 3478 |
| `--ldp-loop-detection` | `[ldp] loop_detection` | off | RFC 5036 §2.8 |
| `--ldp-loop-hc-limit N` | `[ldp] loop_hop_count_limit` | 32 | |
| `--ldp-loop-pv-limit N` | `[ldp] loop_path_vector_limit` | 32 | |

`--ldp-bind` without `=LABEL` stores label 0, which the `[[ldp.bind]]`
schema reads as "allocate one": the daemon hands out the first free
value in `[ldp] label_min..=label_max`, 16 upwards by default.

`--ldp-graceful-restart` has no `gr_reconnect_ms` / `gr_recovery_ms`
flags; those two are configuration keys only.

### Exchange plane

| Flag | Config equivalent | Notes |
| --- | --- | --- |
| `--exchange-plane` | `[bgp] exchange_plane` | Needs the `exchange-plane` feature |
| `--no-exchange-plane` | `[bgp] exchange_plane` | |
| `--exchange-plane-key ID:SECRET` | `[bgp] exchange_plane_keys` | Repeatable |

Requesting the exchange plane on a binary built without the feature is a
startup error, exit 2. See
[research/EXCHANGE-PLANE.md](research/EXCHANGE-PLANE.md).

### Shutdown (issue #53)

| Flag | Config equivalent | Notes |
| --- | --- | --- |
| `--shutdown-mode MODE` | `[shutdown] mode` | `immediate` (default) \| `drain` |
| `--shutdown-drain-rate N` | `[shutdown] drain_rate_per_sec` | Withdrawals per second in drain mode (default 50) |
| `--shutdown-drain-max-wait S` | `[shutdown] drain_max_wait_secs` | Drain hard ceiling in seconds (default 600) |

The `drain` mode minimises the network-wide update rate during a
maintenance exit: stop accepting new routes (a `DrainModeImportHook`
at the front of the import chain drops every inbound UPDATE while
the drain is in progress), walk the Loc-RIB's locally-originated
routes (statics + BGP-originated + aggregates) at the configured
rate, then exit when the queue is empty or the deadline elapses.
The existing RFC 8326 community-based graceful-shutdown hooks are
orthogonal: they govern one peer's per-session maintenance posture,
the drain governs the whole daemon's exit posture.

A drain is triggered on a live daemon through `lrctl shutdown drain`
(or the runtime API `shutdown drain` line command); `lrctl shutdown
status` polls the lifecycle (`running | draining | drained`);
`lrctl shutdown abort` cancels a drain in progress (best-effort —
the worker notices on its next iteration, mirroring the POSIX signal
contract; the state flips back to `running`, the gate clears, the
daemon stays alive). Immediate mode (the default) refuses `shutdown
drain` and `shutdown abort` with a clear "drain not configured"
diagnostic so the operator cannot accidentally trigger a no-op.
`finalize` rejects a zero drain rate or zero max-wait in drain mode
(a drain that cannot make progress would never terminate, and an
unbounded drain would hang the daemon on a wedged peer).

The drain is wired into every daemon mode: BGP standalone, the
multi-protocol supervisor, and the standalone OSPF / OSPFv3 / LDP
engines. The runtime API dispatch is identical on Unix and Windows
(named pipes mirror the Unix domain socket path verbatim), so
`lrctl shutdown drain|status|abort` works on both platforms.

## Configuration keys

A key with no table above it is top-level. Array tables (`[[name]]`)
accumulate one entry each; single tables (`[name]`) set globals.

Sections are named below with their TOML spelling. The `.lr` DSL carries
the same key set but spells the blocks itself, and a few names differ:
`ospf { area … }`, `ospf { interface … }`, `ospf { prefix-sid … }`,
`ospf { mapping-server … }`, `ospf { srv6-locator … }`,
`static { route "…" { … } }`, `babel { key { … } }`,
`babel { interface … }`, `ldp { interface|targeted|bind … }`,
`bgp { rpki { … } }`, `peer "name" { … }`, `peer-template "name" { … }`
and `filter name { … }`. See
[config_dsl_grammar.md](config_dsl_grammar.md).

### Top level

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `protocol` | string | `bgp` | `"bgp,ospf"` form |
| `protocols` | array | `bgp` | `["bgp", "ospf"]` form |
| `user` | string | — | Name or uid |
| `group` | string | — | Name or gid |
| `api_socket` | string | — | Unix socket path |
| `metrics_addr` | string | — | Prometheus TCP address |
| `networks` | array | — | Also accepted as `bgp.networks` |
| `labeled_networks` | array | — | Also `bgp.labeled_networks` |
| `roa_validate` | bool | false | Also `bgp.roa_validate` |
| `roa_invalid_action` | enum | `reject` | Also `bgp.roa_invalid_action` |

These keys carry no section prefix. `local_as`, `peer_as` and
`router_id` written without `[bgp]` are unknown keys and produce a
warning, not a value.

### `[bgp]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `local_as` | int | — | Required |
| `peer_as` | int | — | Legacy single-peer |
| `router_id` | string | — | Dotted quad |
| `peer_addr` | string | — | Legacy single-peer remote |
| `listen_addr` | string | — | Inbound listener |
| `local_address` | string | — | next-hop-self source |
| `local_address_v6` | string | — | |
| `networks` | array | — | |
| `labeled_networks` | array | — | |
| `install_kernel` | bool | false | |
| `hold_time` | int | 90 | Seconds |
| `graceful_restart_time` | int | 0 | Seconds |
| `llgr_stale_time` | int | 0 | Seconds |
| `llgr_max_stale_time` | int | 0 | Seconds |
| `md5_key` | string | — | |
| `tcp_ao_keys` | array | — | `"id:secret"` |
| `tcp_ao_algorithm` | string | `hmac-sha1` | |
| `tcp_ao_maclen` | int | 0 | Bytes |
| `bmp_target` | string | — | `host:port` |
| `ebgp_policy` | enum | `rfc8212` | Or `accept-all` |
| `enforce_first_as` | bool | false | |
| `bestpath_compare_routerid` | bool | true | |
| `graceful_shutdown` | bool | true | RFC 8326 |
| `default_ipv4_unicast` | bool | true | |
| `allow_local_as` | int/word | 0 | `N`, `any`, `true`, `false` |
| `soft_reconfig_inbound` | bool | false | |
| `exchange_plane` | bool | false | Feature-gated |
| `exchange_plane_keys` | array | — | `"id:secret"` |
| `add_path` | bool | false | |
| `add_path_max_paths` | int | 6 | |
| `mp_families` | array | — | Four family names |
| `extended_next_hop` | bool | false | |
| `gtsm` | int/bool | off | `true`/`1`/`yes` = one hop |
| `max_prefixes` | int | none | 0 = no limit |
| `max_prefix_action` | enum | `warn` | |
| `max_prefix_threshold` | int | 75 | Percent |
| `bfd` | bool | false | |
| `bfd_multihop` | bool | false | |
| `bfd_min_tx_ms` | int | 100 | |
| `bfd_min_rx_ms` | int | 100 | |
| `bfd_multiplier` | int | 3 | |
| `roa_validate` | bool | false | |
| `roa_invalid_action` | enum | `reject` | `warn`, `accept` |

### `[[peer]]` and `[peer-template.<name>]`

Both tables share one schema through `apply_peer_key`, with one
difference: an unknown key inside `[[peer]]` is a warning, inside a
template it is a hard error. A peer with `remote` dials out; one with
`address` accepts inbound connections from that source IP.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | remote/address | Log and metrics label |
| `remote` | string | — | `host:port` to dial |
| `address` | string | — | Expected inbound source IP |
| `peer_as` | int | global | 0 = inherit |
| `extends` | string | — | Peer template name |
| `import` | string | — | Route-map name |
| `export` | string | — | Route-map name |
| `import_filter` | string | — | `[[filter]]` name |
| `export_filter` | string | — | `[[filter]]` name |
| `hold_time` | int | global | Seconds |
| `graceful_restart_time` | int | global | Seconds |
| `llgr_stale_time` | int | global | Seconds |
| `llgr_max_stale_time` | int | global | Seconds |
| `local_address` | string | global | |
| `local_address_v6` | string | global | |
| `md5_key` | string | global | |
| `tcp_ao_keys` | array | global | |
| `tcp_ao_algorithm` | string | global | |
| `tcp_ao_maclen` | int | global | |
| `add_path` | bool | global | |
| `add_path_max_paths` | int | global | |
| `mp_families` | array | global | |
| `default_ipv4_unicast` | bool | global | |
| `allow_local_as` | int/word | global | |
| `soft_reconfig_inbound` | bool | global | |
| `exchange_plane` | bool | global | |
| `graceful_shutdown` | bool | global | `false` exempts the peer |
| `extended_next_hop` | bool | global | |
| `gtsm` | int | global | |
| `max_prefixes` | int | global | |
| `max_prefix_action` | enum | global | |
| `max_prefix_threshold` | int | global | |
| `bfd` | bool | global | |
| `bfd_multihop` | bool | global | |

Every field left unset inherits the `[bgp]` global of the same name, so
a peer can be as short as `remote "192.0.2.2:179"`. `extends` chains are
resolved least-specific first; a cycle or an unknown template name fails
`finalize`.

### `[ospf]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `version` | enum | `v2` | `v2`/`2`, `v3`/`3` |
| `hello_interval` | int | 10 | Seconds |
| `dead_interval` | int | 40 | Seconds |
| `graceful_restart` | bool | false | RFC 3623 / RFC 5187 |
| `grace_period` | int | 120 | 1..=1800 |
| `graceful_restart_helper` | bool | true | |
| `helper_grace_cap` | int | 120 | 1..=1800 |
| `gr_state_file` | string | — | Grace deadline file |
| `srgb_base` | int | 16000 | 16..=1048575 with `srgb_range` |
| `srgb_range` | int | 8000 | Non-zero; paired with `srgb_base` |
| `sr_receive` | bool | false | RFC 8665 reception |
| `srv6_receive` | bool | false | RFC 9513 §5, v3 only |
| `srv6_o_flag` | bool | false | v3 only |
| `extended_lsas` | bool | false | RFC 8362, v3 only |
| `srv6_max_sl` | int | — | Node MSD, v3 only |
| `srv6_max_end_pop` | int | — | MSD type 42 |
| `srv6_max_h_encaps` | int | — | MSD type 44 |
| `srv6_max_end_d` | int | — | MSD type 45 |

The SRGB defaults (16000/8000, FRR's) are applied at `finalize` when a
`[[ospf.prefix_sid]]` or `[[ospf.mapping_server]]` exists without an
explicit block. Under `version = "v3"` the SR-MPLS keys and `adj_sid`
are rejected, and under `v2` every `srv6_*` key, `extended_lsas` and
the interface End.X SIDs are rejected.

### `[[ospf.area]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `id` | int/quad | — | Required; `0.0.0.1` or `1` |
| `type` | enum | `normal` | `stub`, `nssa` |
| `no_summary` | bool | false | Totally stubby / totally NSSA |
| `stub_metric` | int | 10 | Default route metric |

Area 0 is always normal and needs no declaration; a non-backbone area an
interface references must be declared. Each id may appear once.

### `[[ospf.interface]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | — | Required kernel interface |
| `area` | int/quad | 0 | Must be declared |
| `cost` | int | 10 | Router-LSA link cost |
| `hello_interval` | int | global | Seconds |
| `dead_interval` | int | global | Seconds |
| `priority` | int | 1 | DR election |
| `network_type` | enum | `p2p` | Or `broadcast` |
| `adj_sid` | int | — | RFC 8665 §6, v2; 16..=1048575 |
| `srv6_end_x` | string | — | RFC 9513 §9.1, v3 |
| `srv6_end_x_lan` | string | — | §9.2, broadcast, ≤ /96 |

`broadcast` runs the RFC 2328 §9.4 DR/BDR election. `srv6_end_x` must
fall inside one of the router's `[[ospf.srv6_locator]]` prefixes, and
`srv6_end_x_lan` needs `network_type = "broadcast"` — both are checked
at `finalize`.

### `[[ospf.prefix_sid]]`

| Key | Type | Notes |
| --- | --- | --- |
| `prefix` | string | Required IPv4 CIDR |
| `sid` | int | Required index into the SRGB |
| `node` | bool | RFC 7684 §2.1 N-flag |
| `no_php` | bool | RFC 8665 §5 NP flag |

### `[[ospf.mapping_server]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `prefix` | string | — | Required range base |
| `sid` | int | — | Required first SID |
| `range_size` | int | 1 | Consecutive prefixes |
| `no_php` | bool | false | NP flag for the range |

`sid + range_size` must fit the SRGB and the prefix's address space, and
the prefix must be IPv4.

### `[[ospf.srv6_locator]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `prefix` | string | — | Required IPv6 CIDR |
| `algorithm` | int | 0 | IGP algorithm |
| `metric` | int | 0 | Locator metric |
| `anycast` | bool | false | RFC 9513 §6 AC-bit |
| `sid` | string | prefix/0 | End SID address |
| `behavior` | int | 1 | End SID sub-TLV behavior |
| `block_len` | int | — | §10, all four or none |
| `node_len` | int | — | §10 |
| `function_len` | int | — | §10 |
| `argument_len` | int | — | §10 |

The four §10 lengths are all-or-none and must sum to at most 128. A
behavior that is not valid inside an End SID sub-TLV is a `finalize`
error. Duplicate locator prefixes are rejected.

### `[babel]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `group` | string | family default | `ff02::1:6`, `224.0.0.111` |
| `port` | int | 6696 | |
| `accept_unauthenticated` | bool | false | RFC 8967 §5 |
| `split_unicast_multicast` | bool | true | RFC 9467 §3.1 |
| `pc_window` | int | 0 | RFC 9467 §3.2; 0 = off |
| `import_filter` | string | — | `[[filter]]` name |
| `export_filter` | string | — | `[[filter]]` name |

### `[[babel.key]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `secret` | string | — | Required; RFC 8967 secret |
| `algorithm` | enum | `hmac-sha256` | Or `blake2s` |
| `interface` | string | all | Glob pattern |

An `interface` pattern must overlap at least one
`[[babel.interface]]` block, and declaring one with no interface blocks
at all is a `finalize` error — a typo there would silently disable
authentication on the intended interface.

### `[[babel.interface]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | — | Required; glob allowed |
| `type`, `kind` | enum | `wired` | `wireless`, `tunnel` |
| `hello_interval_ms`, `hello_interval` | int | 1000 | Milliseconds |
| `update_interval_ms`, `update_interval` | int | 3 × hello | Milliseconds |
| `rxcost` | int | 96 | |
| `rtt_cost` | int | 0 / 96 | 96 on a `tunnel` interface |
| `rtt_min_us`, `rtt_min` | int | 10000 | Microseconds |
| `rtt_max_us`, `rtt_max` | int | 120000 | Microseconds |
| `next_hop_ipv4`, `next_hop_v4` | string | interface | |
| `next_hop_ipv6`, `next_hop_v6` | string | link-local | |
| `extended_next_hop` | bool | false | RFC 5549 |
| `check_link` | bool | true | BIRD `check link` |
| `port` | int | `[babel] port` | Per-interface override |
| `group` | string | `[babel] group` | Per-interface override |

The first matching pattern in file order wins, mirroring BIRD's
`interface` directive. `rtt_min_us` must be below `rtt_max_us` when both
are set. The daemon currently applies the matched parameters to its one
Babel session rather than spawning one per matched interface.

### `[ldp]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `transport` | string | first interface | Hello transport address |
| `transport_v6` | string | first global v6 | RFC 7552 §6.1 |
| `prefer_ipv6` | bool | true | RFC 7552 §6.1.1 |
| `install_kernel` | bool | false | Linux `AF_MPLS` mirror |
| `label_min` | int | 16 | Auto-allocation range |
| `label_max` | int | 1048575 | |
| `transit_allocation` | bool | true | RFC 5036 §3.5.7.1.1 |
| `graceful_restart` | bool | false | RFC 3478 |
| `gr_reconnect_ms` | int | 15000 | FT Reconnect Timeout |
| `gr_recovery_ms` | int | 0 | Recovery Time |
| `port` | int | 646 | UDP and TCP |
| `keepalive_time` | int | 15 | Seconds |
| `link_hold_time` | int | 15 | Seconds |
| `targeted_hold_time` | int | 45 | Seconds |
| `loop_detection` | bool | false | RFC 5036 §2.8 |
| `loop_hop_count_limit` | int | 32 | §2.8.1 |
| `loop_path_vector_limit` | int | 32 | §2.8.2 |

`finalize` requires at least one discovery source — an interface or a
targeted peer — when the LDP mode runs.

### `[[ldp.interface]]`

| Key | Type | Notes |
| --- | --- | --- |
| `name` | string | Required; basic discovery |

### `[[ldp.targeted]]`

| Key | Type | Notes |
| --- | --- | --- |
| `address` | string | Required; `ADDR` or `[v6]:PORT` |

### `[[ldp.bind]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `prefix` | string | — | Required FEC; unique |
| `label` | int | 0 | 0 = auto-allocate; else 16..=1048575 |

A targeted peer's address must not be link-local (RFC 7552 §5.2), and
`keepalive_time` and both hold times must be non-zero.

### `[damping]`

Route flap damping (RFC 2439) is off by default. The thresholds and the
factor are dimensionless figure-of-merit values, not seconds; only
`decay_interval_s` is a time.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | bool | false | Installs the hook and the decay ticker |
| `additive_incr` | int | 1000 | Penalty per flap |
| `suppress_threshold` | int | 2000 | FoM that suppresses |
| `reuse_threshold` | int | 750 | FoM that reactivates |
| `upper_limit` | int | 60000 | FoM ceiling |
| `decay_interval_s` | int | 30 | Seconds between decays |
| `decay_factor_active` | float | 0.97 | Per interval, active route |
| `decay_factor_withdrawn` | float | 0.5 | Per interval, withdrawn |

### `[bgp.rpki]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `cache` | string | off | `host:port`; unbracketed IPv6 rejected |
| `refresh_interval` | int | 3600 | Seconds, non-zero |
| `retry_interval` | int | 600 | Seconds, non-zero |
| `expire_interval` | int | 7200 | Seconds, non-zero |

The intervals are the initial RFC 8210 §6 timers; a v1+ cache overrides
them from every End-of-Data PDU.

### `[[roa]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `prefix` | string | — | Required CIDR |
| `max_length`, `max_len` | int | prefix length | Must be ≥ the length |
| `asn`, `origin_as` | int | — | Required; RFC 6482 §3.2 |

A `(prefix, asn)` pair may appear once. `asn = 0` marks a blackhole ROA.

### `[[filter]]`

| Key | Type | Notes |
| --- | --- | --- |
| `name` | string | Required, unique, referenced by `import_filter` |
| `body` | string | Required filter DSL source |
| `description`, `desc` | string | Operator note; blocks `config to-dsl` |

### `[[prefix-list]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | — | Referenced by a route-map |
| `prefix` | string | — | CIDR |
| `ge` | int | prefix length | |
| `le` | int | 255 | |
| `permit` | bool | true | |

### `[[as-path-list]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | — | |
| `pattern` | string | — | AS-path regex |
| `permit` | bool | true | |

### `[[community-list]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | — | |
| `communities` | array | — | `asn:value`, decimal, or a name |
| `permit` | bool | true | |

Each entry is `asn:value`, a plain decimal `u32`, or one of the
well-known names `no-export`, `no-advertise`, `no-peer`, `llgr-stale`
and `no-llgr`.

### `[[route-map]]`

One table per entry. Entries of one map apply in ascending `entry`, ties
in file order, matching FRR `route-map NAME permit N` instances. A
missing `permit` continues to the next entry.

| Key | Type | Notes |
| --- | --- | --- |
| `name` | string | Referenced by a peer's `import`/`export` |
| `entry` | int | Ordering key |
| `match_prefix` | string | Prefix-list name |
| `match_as_path` | string | AS-path-list name |
| `match_community` | string | Community-list name |
| `set_local_pref` | int | |
| `set_med` | int | |
| `set_metric` | int | |
| `set_next_hop` | string | |
| `prepend` | string | Space-separated AS numbers |
| `add_community` | string | One or more `asn:value` |
| `permit` | bool | Verdict; absent = continue |

### `[[static.route]]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `prefix` | string | — | Required; v4 or v6 |
| `next_hop`, `via`, `gateway` | string | blackhole | Or `blackhole`/`Null0` |
| `metric` | int | 0 | Within the static protocol |
| `tag` | int | — | Propagated by redistribution |

A prefix/next-hop family mismatch is a `finalize` error.

### `[[redistribute]]`

| Key | Type | Notes |
| --- | --- | --- |
| `source` | string | Required: `bgp`, `ospf`, `ospf3`, `babel` |
| `target` | string | Required: `bgp`, `ospf`, `ospf3` |
| `metric` | int | Fixed override; absent = inherit |
| `tag` | int | OSPF external route tag |
| `allow` | array | CIDR allow-list; empty = all |

`static` and `connected` are rejected as sources. The pipe must match
the configured protocol set and the OSPF version, and a `(source,
target)` pair may appear once.

### `[[aggregate]]`

| Key | Type | Notes |
| --- | --- | --- |
| `prefix` | string | Required CIDR; once per config |

### `[shutdown]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `mode` | `"immediate"` \| `"drain"` | `"immediate"` | The new `drain` mode stops accepting new routes, walks the Loc-RIB at `drain_rate_per_sec`, then exits when empty or after `drain_max_wait_secs` |
| `drain_rate_per_sec` | u32 | `50` | Must be `> 0` in drain mode |
| `drain_max_wait_secs` | u32 | `600` | Must be `> 0` in drain mode |

`[shutdown]` keys live in their own table; the dotted form
(`shutdown.mode = "drain"` at the top level) also parses. The block
is fail-closed — a typo'd value or an unsupported `mode` string
stops the daemon at config load with a clear error message. See
the [Shutdown (issue #53)](#shutdown-issue-53) flag table for the
CLI equivalents and the operational semantics.

## Unknown keys: warnings versus errors

The parser is fail-closed on structure and, mostly, on keys. The
tolerance is narrow:

| Where | Unknown key |
| --- | --- |
| root, `[bgp]` | `config warning: line N: unknown key '…' (ignored)` |
| `[[peer]]` | `config warning: line N: unknown peer key '…' (ignored)` |
| `[peer-template.<name>]` | Hard error |
| `[ospf]`, `[[ospf.*]]` | Hard error |
| `[babel]`, `[[babel.*]]` | Hard error |
| `[ldp]`, `[[ldp.*]]` | Hard error |
| `[damping]`, `[bgp.rpki]`, `[shutdown]` | Hard error |
| `[[roa]]`, `[[filter]]`, `[[prefix-list]]`, `[[as-path-list]]`, `[[community-list]]`, `[[route-map]]`, `[[static.route]]`, `[[redistribute]]`, `[[aggregate]]` | Hard error |
| An unknown `[[table]]` or `[section]` name | `config warning: line N: unknown table/section … (ignored)` |

So a typo in the root or `[bgp]` schema is a warning, while a typo in a
protocol or policy table stops the daemon. Warnings are collected in
`DaemonConfig::warnings` and printed at startup, on `config check`, and
on every reload as `reload: config warning: …`.

## Migrating a TOML config to `.lr`

```sh
lr-daemon config to-dsl daemon.toml > daemon.lr
lr-daemon config check daemon.lr
```

`config to-dsl` is deterministic: blocks and keys come out in schema
order, `peer-template` blocks in name order, unset fields omitted. It
works on the pre-`finalize` IR, so peer templates survive as templates
instead of being flattened into peers. It is the migration tool, so it
prints no deprecation notice.

It refuses rather than emitting a file that means less than its input,
and exits 1:

- Any config that produced parse warnings —

  `refusing to convert: the config produced <n> parse warning(s) that
  the DSL cannot represent faithfully (first: <warning>)`

  Since unknown keys in the root and `[bgp]` schema are warnings, a file
  relying on that tolerance cannot be converted until the keys are
  fixed or removed.

- A `[[filter]]` with a `description` —

  `refusing to convert: filter '<name>' carries a description, which the
  DSL cannot represent yet (drop it or keep that filter's TOML file)`

- A `[[filter]]` with no `body` —

  `refusing to convert: filter '<name>' has no body — the DSL has no
  spelling for a body-less filter`

A load failure exits 1 with `config to-dsl: <path>: <error>`. Bad usage
exits 2. `round-trip` is the contract: `parse(TOML) → to-dsl →
parse(lr)` produces an equal `DaemonConfig`, so a successful conversion
can be verified with `config check` on the result.
