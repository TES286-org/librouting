# librouting documentation

Start here. Each document below names the reader it is for, so pick the
row that matches what you are doing right now.

The workspace version lives in `[workspace.package] version` in
`../Cargo.toml`; that file is the source of truth. The public Rust API
and the C ABI are frozen for the 1.0 cut —
[`RELEASE-PLAN.md`](RELEASE-PLAN.md) has the policy. If you are
contributing code or documents, read [`../CONTRIBUTING.md`](../CONTRIBUTING.md)
and [`STYLE.md`](STYLE.md) first.

## Getting started

| Document | For |
| --- | --- |
| [`../README.md`](../README.md) | What the project is, and a five-minute quick start |
| [`tutorial.md`](tutorial.md) | Building a working BGP speaker from the library, step by step |
| [`../AGENTS.md`](../AGENTS.md) | Orientation: project state, layout, build commands |

## Embedding the library (Rust)

| Document | For |
| --- | --- |
| [`api/`](api/) | Every public type, grouped by crate, with examples |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How the crates fit together, the RIB pipeline, the extension points |
| [`filter_dsl_grammar.md`](filter_dsl_grammar.md) | Writing policy in the BIRD-like filter language |
| [`config_dsl_grammar.md`](config_dsl_grammar.md) | The native `.lr` configuration language |
| [`examples/`](examples/) | One document per scenario: route reflectors, confederations, BFD, SRv6, MPLS |

## Embedding from C, C++, Go or Python

| Document | For |
| --- | --- |
| [`bindings/`](bindings/) | Per-language guides, each with a complete program |
| [`ffi_design.md`](ffi_design.md) | What the C ABI guarantees and why it is shaped this way |
| [`scaffolding/README.md`](scaffolding/README.md) | Starting a project from `templates/` |

## Running the daemon

| Document | For |
| --- | --- |
| [`lr-daemon.md`](lr-daemon.md) | The daemon user guide: sessions, protocols, lifecycle |
| [`lr-daemon-reference.md`](lr-daemon-reference.md) | Every flag and configuration key |
| [`lr-cli.md`](lr-cli.md) | The `lr` inspection CLI and the `lrctl` operational CLI |
| [`RUNBOOK.md`](RUNBOOK.md) | Day-2 operations: runtime API, metrics, troubleshooting |
| `../templates/daemon.lr` | The fully commented reference configuration |
| [`COMPAT.md`](COMPAT.md) | Running a BIRD 2 or FRR 10 configuration file unchanged |
| [`PARITY.md`](PARITY.md) | Where lr behaves differently from BIRD and FRR, and how to change it |

## Protocol coverage

| Document | For |
| --- | --- |
| [`STATUS.md`](STATUS.md) | What is implemented and what is not |
| [`RFC_MAP.md`](RFC_MAP.md) | RFC-by-RFC coverage, with the crate and module |
| [`INTEROP.md`](INTEROP.md) | The interop lab against BIRD, FRR and a second lr-daemon |
| [`../CHANGELOG.md`](../CHANGELOG.md) | What changed, per release |

## Platform porting

| Document | For |
| --- | --- |
| [`OS-INTEGRATION.md`](OS-INTEGRATION.md) | The kernel backends and how to write another one |

## Internals

| Document | For |
| --- | --- |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | The layer model, the RIB pipeline, the hook contracts |
| [`lr-cli-internals.md`](lr-cli-internals.md) | Inside the binaries: module layout and run paths |
| [`ffi_design.md`](ffi_design.md) | The C ABI's panic barrier, ownership model and handles |

## Releases and plans

| Document | For |
| --- | --- |
| [`RELEASE-PLAN.md`](RELEASE-PLAN.md) | Semver policy, the 1.0 freeze criteria, the release flow |
| [`ROADMAP.md`](ROADMAP.md) | Open work, grouped by theme |
| [`research/`](research/) | Design notes: BGP's inherent defects, the LRXP exchange plane |

## Repository documents

| Document | For |
| --- | --- |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | The checklist every change has to satisfy |
| [`../AGENTS.md`](../AGENTS.md) | Orientation for AI agents |
| [`STYLE.md`](STYLE.md) | How to write these documents |
| [`../SECURITY.md`](../SECURITY.md) | Reporting a vulnerability, and the threat model |
| [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | Contributor Covenant |
| [`../deny.toml`](../deny.toml) | `cargo-deny` configuration |

## Standing rules

1. A landed feature updates [`STATUS.md`](STATUS.md) and
   [`RFC_MAP.md`](RFC_MAP.md) in the same series of commits. New public
   API also updates [`api/`](api/).
2. Documents follow [`STYLE.md`](STYLE.md), and `tests/lint_docs.sh`
   enforces the mechanical half of it in CI.
3. Every interop lab is listed in [`INTEROP.md`](INTEROP.md);
   `tests/lint_interop_doc.sh` enforces that in CI.
4. A document carries no version number, date, commit hash or count.
   Point at the file that holds the fact instead.
5. Open issues belong on the issues page, not in a document here.
