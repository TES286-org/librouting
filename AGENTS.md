# AGENTS.md — orientation for AI contributors

This is the short map for an AI agent (or a human who wants the same
thing) working in `librouting`. [`CONTRIBUTING.md`](CONTRIBUTING.md) is
the canonical contributor checklist — commit format, code review,
testing layers. [`docs/STYLE.md`](docs/STYLE.md) is the documentation
contract. When this file and another disagree, the other file wins; file
an issue.

The project is a platform-independent BGP / OSPF / Babel routing protocol
library in Rust, at parity with BIRD 2 and FRR 10, with C / C++ / Go /
Python bindings.

**The code is the source of truth.** Documentation lags. Read the code
before trusting any claim in a doc, including this one.

## 1. Project state

The workspace version is `[workspace.package] version` in
[`Cargo.toml`](Cargo.toml). That file is the only place a version is
written down.

The project is at 1.0 and in its stability window: the public Rust API and
the C ABI are frozen, so a breaking change ships as a major-version bump
(see [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md) §4). The `abi-freeze`
CI job enforces the C half mechanically — the headers may only grow
relative to the baseline tag. [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md)
§4 has the post-1.0 governance rules and §4.4 lists the out-of-scope items.

Coverage is at parity with BIRD 2 and FRR 10 for everything in scope.
[`docs/STATUS.md`](docs/STATUS.md) is the gap analysis and
[`docs/RFC_MAP.md`](docs/RFC_MAP.md) the RFC-by-RFC table.

Open work is listed in [`docs/ROADMAP.md`](docs/ROADMAP.md). Open issues
are at <https://github.com/TES286-org/librouting/issues> — that page is
the canonical list, so do not copy it into a document.

## 2. Workspace layout

```text
librouting/
├── Cargo.toml              workspace members, shared package metadata
├── rust-toolchain.toml     toolchain + components; MSRV lives in Cargo.toml
├── deny.toml               cargo-deny: advisories, licenses, bans, sources
├── crates/                 the library, one crate per concern
│   ├── lr-core/            addresses, codec traits, generic FSM, RIB traits
│   ├── lr-bgp/             BGP codec, FSM, best-path, roles, extensions
│   ├── lr-ospf/            OSPFv2/v3 codec, LSAs, LSDB, SPF, neighbor FSM
│   ├── lr-babel/           Babel codec, TLVs, neighbor FSM, route table
│   ├── lr-ldp/             LDP codec and state machines
│   ├── lr-mpls/            MPLS label and label-stack codec
│   ├── lr-srv6/            SRv6 SID, locator, behavior
│   ├── lr-rib/             Adj-RIB-In/Out, Loc-RIB, selection, merging
│   ├── lr-policy/          route-maps, lists, hooks, safety net, filter DSL
│   ├── lr-router/          router instance, sessions, scheduler, events
│   ├── lr-bfd/             BFD codec and session FSM
│   ├── lr-bmp/             BMP codec and sink
│   ├── lr-mrt/             MRT dump format
│   ├── lr-damping/         route flap damping
│   ├── lr-osroute/         OS route-table backends and transports
│   ├── lr-ffi/             C ABI; cbindgen writes include/lr_ffi.h
│   ├── lr-cli/             the lr, lr-daemon and lrctl binaries
│   └── lr-tests/           cross-crate integration tests
├── bindings/               lr-go (cgo) and lr-python (cffi)
├── include/                lr_ffi.h and the C++ RAII wrapper
├── templates/              daemon.lr reference config, daemon.toml, scaffolding
├── tests/interop/          bash labs against BIRD, FRR and a second lr-daemon
├── tests/vm/               QEMU harness for kernel-gated tests
├── docs/                   the documentation set; see docs/README.md
├── fuzz/                   cargo-fuzz targets
├── yang/                   standards-track YANG models
└── .github/workflows/      ci.yml, nightly.yml, release.yml, docker.yml,
                            windows-fib-probe.yml; dependabot.yml alongside
```

Every protocol crate has the same three layers: a stateless wire codec, a
peer FSM over a transport abstraction, and an orchestrator that owns
sessions and the RIB. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) has
the picture and the extension points.

The RIB pipeline, end to end: inbound bytes → FSM → safety net → import
hooks → Adj-RIB-In → reselect → Loc-RIB → export hooks → egress rules →
Adj-RIB-Out → outbound bytes.

## 3. Build and test

Commands run from the repository root.

```sh
cargo build --workspace --all-features
cargo test --workspace --all-features

# The CI gates.
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Documentation gates.
tests/lint_docs.sh
tests/lint_interop_doc.sh

# Regenerate the C header after touching the FFI surface.
cargo build --release -p lr-ffi

# One interop lab; it skips cleanly when BIRD or FRR is absent.
./tests/interop/two_daemon.sh
```

`.github/workflows/ci.yml` is the canonical list of build dependencies
and of which job runs what.

A full `target/` is large. If disk is tight, set `CARGO_INCREMENTAL=0`
and clean per crate with `cargo clean -p <crate>`.

## 4. Conventions worth repeating

These are the ones an agent gets wrong most often. The full list is in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

- **Cite the RFC section** when implementing or extending one, in the doc
  comment and in the commit message: `RFC 8966 §A.2.4`.
- **Prefer first-hand references** over documentation: the RFC text
  (<https://www.rfc-editor.org/rfc/rfcNNNN.txt>), the BIRD source
  (<https://gitlab.nic.cz/labs/bird.git>), the FRR source
  (<https://github.com/FRRouting/frr.git>), the Linux kernel source.
- **English only**, in code, comments, documents and commit messages.
- **No `println!` or `dbg!`** in committed code — use `tracing`.
- **When a location has several valid implementations, choose the
  fastest.** The filter DSL bytecode VM, RIB selection and the codec
  decode loops are the hot paths. Benchmarks are criterion benches in
  `crates/*/benches/`; put the measured delta in the commit message.
- **A new wire codec needs a fuzz target or proptest strategy.**
- **Documents follow [`docs/STYLE.md`](docs/STYLE.md).** No version
  stamps, dates, commit hashes or counts in prose.

## 5. Environment recovery

The environment may be reset between sessions.

```sh
# Toolchain, if missing.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"

# Working copy, if gone.
git clone https://github.com/TES286-org/librouting.git
cd librouting
git pull --ff-only

# Baseline.
cargo build --workspace --all-features
cargo test --workspace --all-features
```

Missing tools: `cargo install cbindgen`, `cargo install cargo-nextest`,
`cargo install cargo-deny`, and `apt-get install bird2 frr` for the
interop labs.

## 6. Where to look first

| Task | Start here |
| --- | --- |
| Understand the layering | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| See what exists and what does not | [`docs/STATUS.md`](docs/STATUS.md) |
| Find the next block of work | [`docs/ROADMAP.md`](docs/ROADMAP.md) |
| Embed the library | [`docs/tutorial.md`](docs/tutorial.md), [`docs/api/`](docs/api/) |
| Run the daemon | [`docs/lr-daemon.md`](docs/lr-daemon.md), [`docs/RUNBOOK.md`](docs/RUNBOOK.md) |
| Embed from C / C++ / Go / Python | [`docs/bindings/`](docs/bindings/), [`docs/ffi_design.md`](docs/ffi_design.md) |
| Verify against BIRD or FRR | [`docs/INTEROP.md`](docs/INTEROP.md), `tests/interop/` |
| Write a filter | [`docs/filter_dsl_grammar.md`](docs/filter_dsl_grammar.md) |
| Port to a new OS | [`docs/OS-INTEGRATION.md`](docs/OS-INTEGRATION.md) |
| Cut a release | [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md) |
| Write a document | [`docs/STYLE.md`](docs/STYLE.md) |

`git log` for a file is the best narrative of why it looks the way it
does. When in doubt, read the code.
