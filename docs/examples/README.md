# Examples

Per-scenario walkthroughs. Each example is a self-contained
description of one deployment pattern: the protocol feature it
exercises, the configuration that drives it, and the verification
that proves it works.

## BGP

| Example | RFC | What it covers |
| ------- | --- | -------------- |
| [`bgp_route_reflector.md`](bgp_route_reflector.md) | RFC 4456 | iBGP route-reflector cluster — `ORIGINATOR_ID` + `CLUSTER_LIST` |
| [`bgp_route_server.md`](bgp_route_server.md) | RFC 7947 | IX route-server mode — transparent AS_PATH / NEXT_HOP, per-client filters |
| [`bgp_confederation.md`](bgp_confederation.md) | RFC 6793 | BGP confederations — `AS_CONFED_SEQUENCE` / `AS_CONFED_SET` |
| [`bgp_roles_otc.md`](bgp_roles_otc.md) | RFC 9234 | BGP roles + the OTC attribute — valley-free advertisement enforcement |
| [`bgp_labeled_unicast.md`](bgp_labeled_unicast.md) | RFC 8277 | BGP-LU → MPLS dataplane — label-stack attribute, LSP head/tail install |
| [`bfd_integration.md`](bfd_integration.md) | RFC 5880 | BFD-driven sub-second BGP failure detection |
| [`filter_dsl_roa.md`](filter_dsl_roa.md) | RFC 6811 | BIRD-like filter DSL + ROA prefix-origin validation |

## OSPF

| Example | RFC | What it covers |
| ------- | --- | -------------- |
| [`ospf_abr_nssa.md`](ospf_abr_nssa.md) | RFC 2328 / RFC 3101 | ABR summary-LSA origination + NSSA area type-7 ↔ type-5 translation |
| [`ospfv3_srv6.md`](ospfv3_srv6.md) | RFC 9513 | OSPFv3 SRv6 — locator LSA origination, End SID, kernel `seg6local` install |

## Babel

| Example | RFC | What it covers |
| ------- | --- | -------------- |
| [`babel_multi_nic.md`](babel_multi_nic.md) | RFC 8966 §A.2 | Multi-interface Babel with shell glob patterns |
| [`babel_source_specific.md`](babel_source_specific.md) | RFC 9079 | Source-specific routing — source-prefix TLV + kernel `src` route |

## LDP

| Example | RFC | What it covers |
| ------- | --- | -------------- |
| [`ldp_basic.md`](ldp_basic.md) | RFC 5036 | LDP label distribution — discovery, session, label-binding exchange, kernel MPLS install |

## OS integration

| Example | What it covers |
| ------- | -------------- |
| [`os_integration.md`](os_integration.md) | Linux rtnetlink route-table mirror — install/withdraw hooks, FIB sync |

## Conventions

- Version pins in `Cargo.toml` snippets inside these examples match
  the workspace version in `Cargo.toml` (`[workspace.package] version`).
  Bump them in lockstep when the workspace version moves.
- Code snippets are adapted from the cross-crate integration tests in
  `crates/lr-tests/tests/` — every snippet mirrors code that compiles
  and runs in this repository.
