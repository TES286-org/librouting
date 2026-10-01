# Examples

Scenario walkthroughs. Each page names the goal, shows the
configuration, says what the daemon or the library does with it, and
gives the command that proves it worked. They do not depend on each
other.

Read the page that matches your task. Vocabulary and the configuration
grammar live in [`../config_dsl_grammar.md`](../config_dsl_grammar.md)
and [`../filter_dsl_grammar.md`](../filter_dsl_grammar.md).

## BGP

| Example | RFC | What it covers |
| ------- | --- | -------------- |
| [`bgp_route_reflector.md`](bgp_route_reflector.md) | RFC 4456 | Route reflection — ORIGINATOR_ID, CLUSTER_LIST |
| [`bgp_route_server.md`](bgp_route_server.md) | RFC 7947 | IX route server — transparent AS_PATH, per-client policy |
| [`bgp_confederation.md`](bgp_confederation.md) | RFC 6793 | Confederations — AS_CONFED_SEQUENCE, AS_CONFED_SET |
| [`bgp_roles_otc.md`](bgp_roles_otc.md) | RFC 9234 | Roles and the OTC attribute on egress and ingress |
| [`bgp_labeled_unicast.md`](bgp_labeled_unicast.md) | RFC 8277 | BGP-LU into the Linux MPLS table |
| [`bfd_integration.md`](bfd_integration.md) | RFC 5880 | BFD-driven fast failure detection |
| [`filter_dsl_roa.md`](filter_dsl_roa.md) | RFC 6811 | Filter DSL plus ROA origin validation |

## OSPF

| Example | RFC | What it covers |
| ------- | --- | -------------- |
| [`ospf_abr_nssa.md`](ospf_abr_nssa.md) | RFC 2328, RFC 3101 | ABR summaries; NSSA type-7 to type-5 translation |
| [`ospfv3_srv6.md`](ospfv3_srv6.md) | RFC 9513 | SRv6 locator origination, End and End.X SIDs |

## Babel

| Example | RFC | What it covers |
| ------- | --- | -------------- |
| [`babel_multi_nic.md`](babel_multi_nic.md) | RFC 8966 | Per-interface parameters, selected by glob |
| [`babel_source_specific.md`](babel_source_specific.md) | RFC 9079 | Source-prefix routes |

## LDP

| Example | RFC | What it covers |
| ------- | --- | -------------- |
| [`ldp_basic.md`](ldp_basic.md) | RFC 5036 | Discovery, session, label bindings, MPLS install |

## OS integration

| Example | What it covers |
| ------- | -------------- |
| [`os_integration.md`](os_integration.md) | Kernel route installation and the `OsRouteTable` trait |

## Conventions

- A `Cargo.toml` snippet writes the crate version as `<version>`. That
  value is `[workspace.package] version` in the workspace `Cargo.toml`.
- Rust snippets name the same types and calls the daemon in
  `crates/lr-cli/` and the cross-crate tests in `crates/lr-tests/tests/`
  use. A snippet that is a fragment rather than a program says so.
- A `.lr` snippet is a fragment: it assumes the surrounding block from
  [`templates/daemon.lr`](../../templates/daemon.lr). Every key named
  here is accepted by `crates/lr-cli/src/daemon_config.rs`.
