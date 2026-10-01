# librouting documentation

Start here. The documentation set is organised by what you are
trying to do, not by who you are — most readers wear several hats.

The workspace version lives in `Cargo.toml`
(`[workspace.package] version`); that file is the source of truth.
The public Rust API and the C ABI are frozen for the 1.0 cut — see
[`RELEASE-PLAN.md`](RELEASE-PLAN.md) §2.8 for the remaining freeze
criteria. For the AI-agent / contributor quick-start, see
[`../AGENTS.md`](../AGENTS.md).

## Getting started

| Document                                 | What it covers                                          |
| ---------------------------------------- | ------------------------------------------------------- |
| [`../README.md`](../README.md)           | Project overview, quick start, crate map                |
| [`tutorial.md`](tutorial.md)             | Book-style walk: wire → two FSMs → the router pipeline  |
| [`../AGENTS.md`](../AGENTS.md)           | Project state, build/test commands, conventions         |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | PR checklist, commit message format, test layers       |

## Embedding the library (Rust)

| Document                                         | What it covers                                          |
| ------------------------------------------------ | ------------------------------------------------------- |
| [`API.md`](API.md)                               | Public API tour, layer by layer, with code snippets     |
| [`ARCHITECTURE.md`](ARCHITECTURE.md)             | Layering, RIB pipeline, extension points                |
| [`filter_dsl_grammar.md`](filter_dsl_grammar.md) | Formal grammar for the BIRD-like filter DSL              |
| [`config_dsl_grammar.md`](config_dsl_grammar.md) | Grammar for the native `.lr` configuration DSL           |
| [`examples/`](examples/)                         | Per-scenario walkthroughs (RR, confederation, RS, BFD …) |

## Embedding (C / C++ / Go / Python)

| Document                                         | What it covers                                          |
| ------------------------------------------------ | ------------------------------------------------------- |
| [`bindings/`](bindings/)                         | Per-language guides with complete, verified programs    |
| [`ffi_design.md`](ffi_design.md)                 | FFI design: panic barrier, `lr_bytes_t`, cbindgen, handles |
| [`scaffolding/README.md`](scaffolding/README.md) | Generating starter projects from `templates/`           |

## Running the daemon

| Document                                     | What it covers                                          |
| -------------------------------------------- | ------------------------------------------------------- |
| `templates/daemon.lr`                        | Fully commented reference config (native DSL)            |
| `templates/daemon.toml`                      | Deprecated TOML twin (supported through 1.x)              |
| [`lr-cli.md`](lr-cli.md)                     | CLI user guide — `lr`, `lr-daemon`, `lrctl` subcommands  |
| [`RUNBOOK.md`](RUNBOOK.md)                   | Operations runbook: lifecycle, runtime API, troubleshooting |
| [`COMPAT.md`](COMPAT.md)                     | Running BIRD 2 / FRR 10 configs natively                 |
| [`PARITY.md`](PARITY.md)                     | Behaviour knobs vs BIRD 2 / FRR 10                        |

## Protocol coverage

| Document                                 | What it covers                                          |
| ---------------------------------------- | ------------------------------------------------------- |
| [`STATUS.md`](STATUS.md)                 | Implemented-vs-missing gap analysis                      |
| [`RFC_MAP.md`](RFC_MAP.md)               | RFC-by-RFC coverage table with crate paths               |
| [`INTEROP.md`](INTEROP.md)               | Interop lab against BIRD / FRR: what is verified         |

## Platform porting

| Document                                 | What it covers                                          |
| ---------------------------------------- | ------------------------------------------------------- |
| [`OS-INTEGRATION.md`](OS-INTEGRATION.md) | Kernel backends (Linux / BSD / Windows), porting guide   |

## Internals

| Document                                                 | What it covers                                          |
| -------------------------------------------------------- | ------------------------------------------------------- |
| [`lr-cli-internals.md`](lr-cli-internals.md)             | CLI internals: module layout, run paths, extension patterns |
| [`ARCHITECTURE.md`](ARCHITECTURE.md)                     | Layering, RIB pipeline, extension points                |
| [`ffi_design.md`](ffi_design.md)                         | FFI design + panic-barrier contract                     |

## Releases and roadmap

| Document                                 | What it covers                                          |
| ---------------------------------------- | ------------------------------------------------------- |
| [`RELEASE-PLAN.md`](RELEASE-PLAN.md)     | Semver policy, 1.0 freeze criteria, release flow        |
| [`ROADMAP.md`](ROADMAP.md)               | Roadmap v2 workstream landing log (audit trail)         |
| [`ROADMAP-v3.md`](ROADMAP-v3.md)         | Roadmap v3 — 15 maturity directions (forward-looking)    |

## Research

| Document                                                   | What it covers                                          |
| ---------------------------------------------------------- | ------------------------------------------------------- |
| [`research/BGP-DEFECTS.md`](research/BGP-DEFECTS.md)       | BGP's protocol-inherent defects and mitigations         |
| [`research/EXCHANGE-PLANE.md`](research/EXCHANGE-PLANE.md) | Capability-negotiated private exchange plane design      |
| [`research/E-LSA-DESIGN.md`](research/E-LSA-DESIGN.md)     | RFC 8362 Extended-LSA implementation plan                |

## Repo-level docs

| Document                                         | What it covers                                          |
| ------------------------------------------------ | ------------------------------------------------------- |
| [`../AGENTS.md`](../AGENTS.md)                   | AI-agent + contributor quick-start                     |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md)       | PR checklist, commit format, test layers                |
| [`../SECURITY.md`](../SECURITY.md)               | Vulnerability reporting, embargo, threat model          |
| [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | Contributor Covenant 2.0                                 |
| [`../CHANGELOG.md`](../CHANGELOG.md)             | Consumer-facing version history (Keep a Changelog)       |
| [`../deny.toml`](../deny.toml)                   | `cargo-deny` config — advisories, licenses, bans        |

## Standing rules

1. Every landed feature updates [`STATUS.md`](STATUS.md) (capability
   tables) and [`RFC_MAP.md`](RFC_MAP.md) in the same series of
   commits; the workstream narrative lands in [`ROADMAP.md`](ROADMAP.md)
   or [`ROADMAP-v3.md`](ROADMAP-v3.md) (enforced at review).
2. [`API.md`](API.md) gains a section whenever a new public API surface
   appears.
3. Documents are English-only; wrap long lines around 80 characters.
4. Do not stamp a hard-coded version into prose — point to
   `Cargo.toml` instead. Hard-coded version stamps go stale the
   moment the next release lands.
5. Do not maintain a list of open GitHub issues in a doc — the issues
   page is the canonical list.
