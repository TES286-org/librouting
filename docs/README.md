# librouting documentation index

Start here. The documentation set is organized by audience: embedders
writing Rust, operators running the daemon, and contributors extending
the protocol crates.

## Orientation

| Document                                         | Audience                | Contents                                                         |
| ------------------------------------------------ | ----------------------- | ---------------------------------------------------------------- |
| [`../README.md`](../README.md)       | everyone                | Project overview, crate map, quick-start daemon example          |
| [`tutorial.md`](tutorial.md)         | newcomers               | Book-style tutorial: wire decode → two FSMs → the router pipeline |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | contributors, embedders | Layering, RIB pipeline diagram, extension points, testing layout |
| [`STATUS.md`](STATUS.md)             | everyone                | Implemented-vs-missing gap analysis + roadmap state summary      |
| [`ROADMAP.md`](ROADMAP.md)           | contributors            | Roadmap v2 workstream landing log: design decisions, evidence    |
| [`ROADMAP-v3.md`](ROADMAP-v3.md)     | contributors            | Roadmap v3 — 15 maturity directions (Babel multi-session, RPKI-RTR, Filter DSL parity, FFI, fuzz/bench, supply-chain, perf, docs, BGP-LS, E-LSA, `lrctl`, …) |
| [`RFC_MAP.md`](RFC_MAP.md)           | contributors            | RFC-by-RFC coverage table with crate paths                       |
| [`RELEASE-PLAN.md`](RELEASE-PLAN.md) | maintainers, embedders  | Semver policy, 1.0 freeze criteria, release flow, post-1.0 governance |

## Embedding the library

| Document                                         | Contents                                                                                     |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| [`API.md`](API.md)                               | Public API tour, layer by layer, with code snippets                                          |
| [`filter_dsl_grammar.md`](filter_dsl_grammar.md) | Formal EBNF grammar for the BIRD-like filter DSL — every example pinned by `crates/lr-policy/tests/grammar_corpus.rs` |
| [`ffi_design.md`](ffi_design.md)               | FFI design: panic barrier contract, `lr_bytes_t` ownership model, cbindgen pipeline, opaque-handle pattern, why OSPF/Babel/LDP are not yet exposed |
| [`bindings/`](bindings/)                         | Per-language guides with complete, verified programs (Go / Python / C / C++)                  |
| [`scaffolding/README.md`](scaffolding/README.md) | Generating starter projects from `templates/` (analyzer, RR, BFD, OS integration)            |
| [`examples/`](examples/)                         | Per-scenario walkthroughs: route reflector, confederation, route server, BFD, OS integration, LDP, BGP-LU, OSPFv3 SRv6 |

## Running the daemon

| Document                   | Contents                                                             |
| -------------------------- | -------------------------------------------------------------------- |
| `templates/daemon.lr`      | Fully commented reference configuration, native DSL (every key explained); `templates/daemon.toml` is the TOML twin |
| [`lr-cli.md`](lr-cli.md)   | CLI user guide — every `lr` and `lr-daemon` subcommand, flag and example |
| [`lr-cli-internals.md`](lr-cli-internals.md) | CLI internals — module layout, run paths, extension patterns |
| [`RUNBOOK.md`](RUNBOOK.md) | Operations runbook: lifecycle, runtime API, troubleshooting FAQ      |
| [`COMPAT.md`](COMPAT.md)   | Running BIRD 2 / FRR configs natively: dialects, defaults, `lr:` extensions |
| [`PARITY.md`](PARITY.md)   | Behaviour knobs vs. BIRD 2 / FRR 10: RFC latitude, defaults, mapping |
| [`INTEROP.md`](INTEROP.md) | Interop lab against BIRD / FRR: what is verified, how to run locally |

## Platform porting

| Document                                 | Contents                                                                                                        |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| [`OS-INTEGRATION.md`](OS-INTEGRATION.md) | Kernel route-table backends (Linux rtnetlink, BSD route(4), Windows IP Helper), layout tables, porting a new OS |

## Research

| Document                                          | Contents                                                                                      |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| [`research/BGP-DEFECTS.md`](research/BGP-DEFECTS.md) | BGP's protocol-inherent defects: mechanisms, primary evidence, standard mitigations, lr status |
| [`research/EXCHANGE-PLANE.md`](research/EXCHANGE-PLANE.md) | Capability-negotiated private exchange plane design: feasibility hints, policy intent, provenance proofs |
| [`research/E-LSA-DESIGN.md`](research/E-LSA-DESIGN.md) | RFC 8362 Extended-LSA implementation plan: function codes, TLV framing, SPF integration, End.X SID sub-TLV, three-slice breakdown |

## Standing rules

1. Every landed feature updates `STATUS.md` (capability tables) and
   `RFC_MAP.md` in the same series of commits; the workstream
   narrative lands in `ROADMAP.md` (enforced at review).
2. `API.md` gains a section whenever a new public API surface appears.
3. Documents are English-only; keep lines under ~80 characters.

## Contributor and security docs (repo root)

| Document                              | Contents                                                          |
| ------------------------------------- | ----------------------------------------------------------------- |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | PR checklist, commit message format, test layers, RFC pinning procedure |
| [`../SECURITY.md`](../SECURITY.md)    | Vulnerability reporting, 90-day embargo, threat model             |
| [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | Contributor Covenant 2.0                                  |
| [`../CHANGELOG.md`](../CHANGELOG.md)  | Consumer-facing version history (Keep a Changelog format)         |
| [`../deny.toml`](../deny.toml)        | `cargo-deny` config — advisories, licenses, bans, sources         |
