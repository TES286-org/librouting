# Daemon knob compatibility matrix

Read this page when you are configuring a behaviour knob and need to
know its name on every surface: the native `.lr` DSL, the TOML subset,
the `lr-daemon` command line, the C ABI and the Go/Python bindings.

The Rust API is the column of record — each row names the method on
`DefaultRouter` (or the config field) that the other columns set.

| Knob | Rust API | DSL | TOML | CLI | C ABI | Go / Python |
| --- | --- | --- | --- | --- | --- | --- |
| maximum-prefix | `with_maximum_prefix`, `with_maximum_prefix_threshold` | `max_prefixes`, `max_prefix_action`, `max_prefix_threshold` | `bgp.max_prefixes`, `bgp.max_prefix_action`, `bgp.max_prefix_threshold` | `--max-prefixes`, `--max-prefix-action`, `--max-prefix-threshold` | — | — |
| RFC 8212 eBGP policy | `set_ebgp_requires_policy`, `set_session_policy` | `ebgp_policy` | `bgp.ebgp_policy` | `--ebgp-policy` | `lr_router_set_ebgp_requires_policy`, `lr_router_set_session_policy` | `SetEbgpRequiresPolicy`, `SetSessionPolicy` / `set_ebgp_requires_policy`, `set_session_policy` |
| default IPv4 unicast | `set_session_default_ipv4_unicast`, `PeerConfig::default_ipv4_unicast` | `default_ipv4_unicast` | `bgp.default_ipv4_unicast`, peer override | `--default-ipv4-unicast`, `--no-default-ipv4-unicast` | `lr_router_set_default_ipv4_unicast` | `SetDefaultIPv4Unicast` / `set_default_ipv4_unicast` |
| allow local AS | `set_session_local_as_tolerance`, `PeerConfig::local_as_tolerance` | `allow_local_as` | `bgp.allow_local_as`, peer override | `--allow-local-as N`, `--allowas-any` | `lr_router_set_local_as_tolerance` | `SetLocalAsTolerance` / `set_local_as_tolerance` |
| soft reconfiguration inbound | `set_session_soft_reconfig_inbound`, `soft_reconfig_inbound` | `soft_reconfig_inbound` | `bgp.soft_reconfig_inbound`, peer override | `--soft-reconfig-inbound`, `--no-soft-reconfig-inbound` | `lr_router_set_soft_reconfig_inbound`, `lr_router_soft_reconfig_inbound` | `SetSoftReconfigInbound`, `SoftReconfigInbound` / `set_soft_reconfig_inbound`, `soft_reconfig_inbound` |
| enforce first AS | `set_enforce_first_as` | `enforce_first_as` | `bgp.enforce_first_as` | `--enforce-first-as`, `--no-enforce-first-as` | `lr_router_set_enforce_first_as` | `SetEnforceFirstAs` / `set_enforce_first_as` |
| bestpath compare router-id | `best_path_config_mut().deterministic_router_id` | `bestpath_compare_routerid` | `bgp.bestpath_compare_routerid` | `--bestpath-compare-routerid`, `--no-bestpath-compare-routerid` | — | — |
| GTSM | `lr_osroute::gtsm::Gtsm` | `gtsm` | `bgp.gtsm` | `--gtsm [N]` | — | — |
| labelled unicast origination | `originate_labeled` | `labeled_networks` | `bgp.labeled_networks` | `--labeled-network "PREFIX LABEL"` | — | — |
| exchange plane | `set_session_exchange_plane` | `exchange_plane`, `exchange_plane_keys` | `bgp.exchange_plane`, `bgp.exchange_plane_keys`, peer override | `--exchange-plane`, `--no-exchange-plane`, `--exchange-plane-key` | — | — |

Notes that the table cannot carry:

- `best_path_config_mut().deterministic_router_id` defaults to `true`,
  which is the inverse of FRR's `bgp bestpath compare-routerid`: true
  means lowest router ID wins (RFC 5004), false means oldest route wins.
- The library defaults are off for RFC 8212 and enforce-first-as. The
  shipped daemon enables RFC 8212 and fails closed on an unknown
  `ebgp_policy` value.
- `--gtsm` with no argument is single-hop (TTL 255); `--gtsm N` is
  multihop. Each peer may override it in its own block.
- A `—` cell means the surface has no setter. The knob is still
  available from Rust, and from the daemon if the DSL/TOML/CLI column is
  filled in.
- Features gate three rows: the exchange plane needs `exchange-plane`,
  and the labelled-unicast row needs `labeled_unicast`, which both
  `lr-bgp` and `lr-router` enable by default.

The daemon grammar for the DSL and the TOML subset is in
[`../config_dsl_grammar.md`](../config_dsl_grammar.md); the file
format itself is described in [`../lr-cli.md`](../lr-cli.md).

## RFCs

- RFC 8212 §1/§3 — eBGP policy scope and the fail-closed default.
- RFC 4271 §9.1.2.15 — the AS-loop check `allow_local_as` relaxes.
- RFC 5082 — GTSM hop counts.
- RFC 8277 — labelled-unicast NLRI.

## See also

- [`bgp.md`](bgp.md) — the Rust behaviour behind each row.
- [`router.md`](router.md) — sessions and the event loop.
- [`README.md`](README.md) — feature flags and error handling.
