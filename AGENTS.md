# AGENTS.md — guidance for AI contributors

This document orients AI agents (and human contributors who want the
same concise map) to the current state of `librouting` and the
constraints a contribution must satisfy to land. It is the operational
counterpart to [`CONTRIBUTING.md`](CONTRIBUTING.md) (which covers the
human-facing PR checklist) and [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md)
(which covers the semver + release policy). When this document and
another disagree, the other document is authoritative; file an issue.

The project's overall goal is a platform-independent BGP / OSPF / Babel
routing protocol library in Rust, at parity with BIRD 2 and FRR 10,
with C / C++ / Go / Python bindings. The canonical source of truth is
the **code**; documentation may lag. Always read the code before
trusting a doc claim.

---

## 1. Project state (as of v1.0.0-rc.4)

The workspace is at **`1.0.0-rc.4`** (`[workspace.package] version`
in `Cargo.toml`). The public Rust API (Tier 1) and the C ABI (Tier 2)
are **frozen** for the 1.0 cut — a breaking change is a major-version
bump, no exceptions. See `docs/RELEASE-PLAN.md` §2.8 for the remaining
1.0.0 freeze criteria (one week of clean CI on Linux + macOS + Windows,
no open `release-blocker` issues).

**Protocol coverage** is at parity with BIRD 2 + FRR 10 for everything
in scope (BGP, OSPFv2/v3, Babel, LDP, BFD, BMP, MRT). The only
deliberately-out-of-scope item is BGPsec. See `docs/STATUS.md` for the
honest gap analysis and `docs/RFC_MAP.md` for the RFC-by-RFC coverage
table.

**Open roadmap directions** (post-1.0, tracked in `docs/ROADMAP-v3.md`):

- D8.2 — per-AFI RIB sharding (perf)
- D8.3 — async I/O migration (`mio` / `tokio` event loop)
- D10.2/D10.3/D10.4 — RFC 5666 (EPE), BGP-LS, SR Policy
- D11 — BGP-LS (RFC 7752 + RFC 9552)
- D14.7 — external BIRD/FRR conversion corpus
- D15 — multi-threaded RIB + lock-free event bus

**Open GitHub issues** of note: #19 (DSL performance — ongoing), #20
(publish to package managers — future), #26 (this doc-reorg task).

---

## 2. Workspace layout

```
librouting/
├── Cargo.toml              # workspace + [workspace.package] + [workspace.dependencies]
├── Cargo.lock              # committed; regenerated on version bumps
├── rust-toolchain.toml     # stable + rustfmt + clippy; MSRV 1.88
├── deny.toml               # cargo-deny config (advisories, licenses, bans, sources)
├── crates/                 # 18 crates, all version.workspace = true
│   ├── lr-core/            # shared primitives (addr, codec, rib, fsm, timer, event, attr)
│   ├── lr-bgp/             # BGP codec + FSM + best-path + roles + extensions
│   ├── lr-ospf/            # OSPFv2/v3 codec + LSAs + LSDB + SPF + neighbor FSM
│   ├── lr-babel/           # Babel codec + TLVs + neighbor + route + auth
│   ├── lr-rib/             # Adj-RIB-In/Out, Loc-RIB, selection, merging
│   ├── lr-policy/          # route-maps, prefix-lists, AS-path filters, hooks, safety net, filter DSL
│   ├── lr-router/          # DefaultRouter orchestrator (Layer 3)
│   ├── lr-bfd/             # BFD (RFC 5880) codec + session FSM
│   ├── lr-bmp/             # BMP (RFC 7854) codec + sink
│   ├── lr-mrt/             # MRT (RFC 6396) dump format
│   ├── lr-damping/         # route flap damping (RFC 2439)
│   ├── lr-osroute/         # OS route-table backends (Linux/BSD/Windows) + transports
│   ├── lr-mpls/            # MPLS label + label-stack codec (RFC 3032)
│   ├── lr-srv6/            # SRv6 SID + locator + behavior
│   ├── lr-ldp/            # LDP (RFC 5036) codec + state machines
│   ├── lr-ffi/             # C ABI (cbindgen-generated header → include/lr_ffi.h)
│   ├── lr-cli/             # lr + lr-daemon + lrctl binaries
│   └── lr-tests/           # cross-crate integration tests
├── bindings/               # lr-go (cgo) + lr-python (cffi)
├── include/                # lr_ffi.h (C) + librouting.hpp (C++ RAII wrapper)
├── templates/               # daemon.lr (native DSL reference) + daemon.toml (TOML twin, deprecated) + scaffolding
├── tests/interop/           # 54 bash interop scripts (BIRD + FRR)
├── docs/                    # documentation set (see docs/README.md)
├── fuzz/                    # cargo-fuzz targets (bgp_decode, filter_parser, roa_validate)
├── yang/                    # standards-track YANG models
└── .github/workflows/       # ci.yml + nightly.yml + release.yml + docker.yml
```

**Three-layer API** (every protocol crate follows this):

| Layer | What                              | Example              |
| ----- | --------------------------------- | -------------------- |
| 1     | Stateless wire codec             | `BgpCodec`, `BfdCodec` |
| 2     | Peer FSM + transport abstraction | `BgpPeer::step`      |
| 3     | Orchestrator (sessions + RIB)     | `DefaultRouter`      |

**RIB pipeline**: inbound bytes → FSM → SafetyNet → ImportHooks →
AdjRibIn → reselect (BestPath) → LocRib → ExportHooks → egress rules
→ AdjRibOut → outbound bytes. See `docs/ARCHITECTURE.md` for the
diagram and extension points.

---

## 3. Build + test commands

All commands run from the repo root. Rust stable is the toolchain
(`rust-toolchain.toml`); MSRV is 1.88.

```sh
# Build everything (dev profile).
cargo build --workspace --all-features

# Full test suite (unit + integration + doc-tests).
cargo test --workspace --all-features

# Format check + lint (CI gate, -D warnings).
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Release build (mirrors the release.yml workflow).
cargo build --workspace --release --all-features
cargo build --release -p lr-ffi      # regenerates include/lr_ffi.h via cbindgen

# FFI harness (C + C++ + Go + Python) — run after `cargo build --release -p lr-ffi`.
cc -Iinclude tests/ffi/harness.c -Ltarget/release -llr_ffi -o /tmp/lr_harness
LD_LIBRARY_PATH=target/release /tmp/lr_harness

# One interop script (skip gracefully if bird/frr not installed).
./tests/interop/two_daemon.sh

# Fuzz (nightly CI runs these).
cargo +nightly fuzz run bgp_decode
```

**Environment note**: the workspace is large (~8 GB target/ after a
full build). If disk is tight, run `CARGO_INCREMENTAL=0` and clean
between big test runs: `cargo clean -p <crate>` removes only that
crate's artifacts.

**Four test layers** (prefer the layer that proves the most with the
least code):

1. **Unit tests** — in-crate `#[cfg(test)] mod tests`. Fast, deterministic.
2. **Integration tests** — `crates/*/tests/*.rs`. Cross-crate, daemon
   end-to-end against itself.
3. **Interop tests** — `tests/interop/*.sh`. Bash scripts spawning
   `lr-daemon` against BIRD 2 / FRR 10 (reference-daemon scripts are
   Linux-only) or against a second `lr-daemon` (the library-based
   scripts — `two_daemon.sh`, `labeled_unicast.sh`,
   `bgp_kernel_install.sh` — are portable and run on the macOS and
   Windows interop CI jobs too). All skip gracefully when the
   reference daemon is absent.
4. **Kernel-gated tests** — `#[ignore]`'d tests needing root +
   specific kernel modules (TCP-AO, MPLS, SRv6). Run in the
   `tests/vm/run_vm.sh` QEMU harness in the nightly job.

---

## 4. Conventions a contribution must satisfy

### 4.1 Commit messages — Conventional Commits

```
type(scope): imperative summary under 72 chars

Body: explain *why*. Reference issues (#123), RFCs (RFC 8966 §A.2.4),
or prior commits (abcdef0) when relevant.
```

- `type`: `feat` | `fix` | `refactor` | `perf` | `docs` | `test` |
  `chore` | `build` | `ci` | `style` | `revert`
- `scope`: a crate name without the `lr-` prefix (`bgp`, `ospf`,
  `policy`, `router`, `ffi`, `cli`, `core`, `rib`, `bfd`, `bmp`,
  `mrt`, `damping`, `osroute`, `mpls`, `srv6`, `ldp`, `tests`),
  `bindings`, `docs`, `ci`, `release`, or `deps`.

Prefer **small, self-contained commits** — each commit builds and passes
tests. 5 small commits beat 1 megacommit for bisecting regressions.

### 4.2 Code style

- **Rust stable + MSRV 1.88.** Do not introduce a crate requiring a
  newer toolchain without bumping the MSRV in `rust-toolchain.toml`.
- `cargo fmt --all -- --check` clean. No `#[allow(...)]` unless the
  justification is in the commit message and the lint is named.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  clean.
- No `println!` / `dbg!` in committed code — use `tracing`.
- **English only** in all files (code, comments, docs, commit messages).
- Doc comments cite the RFC section when implementing or extending one:
  `RFC 8966 §A.2.4 — RTT measurement TLV`.

### 4.3 Public API stability (frozen at rc.4)

Three tiers with different stability contracts (see
`docs/RELEASE-PLAN.md` §1):

| Tier | Surface | Stability |
| --- | --- | --- |
| 1 | `pub` items in `lr-core`, `lr-bgp`, `lr-ospf`, `lr-babel`, `lr-ldp`, `lr-bfd`, `lr-rib`, `lr-policy`, `lr-router`, `lr-damping`, `lr-mpls`, `lr-mrt`, `lr-bmp`, `lr-srv6`, `lr-osroute` | Semver-tracked. Breaking change = minor (pre-1.0) / major (post-1.0) bump. |
| 2 | C ABI (`lr-ffi`, `include/lr_ffi.h`, `include/librouting.hpp`) | **ABI-stable.** A breaking ABI change is a major version bump *even pre-1.0*. `lr_abi_version()` bumped in lockstep. |
| 3 | `lr-daemon` CLI flags + config schema (`.lr` DSL + TOML subset) + `--api-socket` line protocol | Documented stability. Flag rename = minor bump + deprecated alias for one minor cycle. |

When touching the FFI surface: regenerate `include/lr_ffi.h` via
`cargo build -p lr-ffi` (cbindgen runs from `build.rs`), and sync the
Go / Python / C++ bindings.

### 4.4 RFC pinning

When you implement or extend an RFC:

1. Add a row to `docs/RFC_MAP.md` (RFC number, crate path, one-line
   description).
2. Update the capability table in `docs/STATUS.md`.
3. Cite the RFC section in doc comments and the commit message.

### 4.5 First-hand references

When implementing or verifying protocol behaviour, prefer first-hand
sources over documentation:

- **RFCs** — the canonical protocol specification. Fetch from
  `https://www.rfc-editor.org/rfc/rfcNNNN.txt`.
- **BIRD source** — `https://gitlab.nic.cz/labs/bird.git` (or a mirror).
  The `proto/bgp/` and `proto/ospf/` directories are the reference
  implementation librouting is verified against.
- **FRR source** — `https://github.com/FRRouting/frr.git`. The
  `bgpd/`, `ospfd/`, `ospf6d/`, `ldpd/` directories.
- **Linux kernel** — `net/ipv4/`, `net/ipv6/`, `net/mpls/` for the
  dataplane backends (rtnetlink, seg6, AF_MPLS).

When a doc claim and the code disagree, the code wins. File an issue
or fix the doc in the same PR.

### 4.6 Performance

When a location has multiple valid implementations, choose the
performance-optimal one. The filter DSL bytecode VM is a hot path
(GitHub issue #19 is the ongoing perf workstream); the RIB selection
and the codec decode loops are the other two. Benchmarks live in
`crates/*/benches/` (criterion); run with `cargo bench -p <crate>`.
Document a measured delta in the commit message when landing a perf
change.

---

## 5. Git workflow

1. **Sync before starting**: `git pull --ff-only`.
2. **Branch off `main`**: `feat/babel-multi-session`,
   `fix/proto-field-bird-name`, `docs/roadmap-v3`.
3. **Small, self-contained commits** (see §4.1).
4. **Open a PR against `main`.** CI must be green before review.
5. **Review checklist** (see `CONTRIBUTING.md` §"Code review checklist"):
   - `cargo fmt --all -- --check` clean.
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
   - `cargo test --workspace --all-features` green (kernel-gated tests
     may be `#[ignore]`'d — explain why in the commit message).
   - New public API → doc comment + `docs/API.md` entry.
   - New protocol feature → `docs/STATUS.md` capability row +
     `docs/RFC_MAP.md` entry.
   - New wire codec → fuzz target or proptest strategy.
   - FFI surface touched → header regenerated + bindings synced.
6. **Push to `origin/main`** only after the PR is approved + CI green.

**Credentials**: never commit secrets. The repo uses a GitHub PAT for
automation; it lives in the environment, not in the repo.

---

## 6. Environment recovery

The development environment may be reset between sessions. Recovery
steps:

```sh
# 1. Rust toolchain (if missing).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile default
source "$HOME/.cargo/env"

# 2. Clone (if the working copy is gone).
git clone https://github.com/TES286-org/librouting.git
cd librouting
git pull --ff-only   # sync to origin/main

# 3. Verify baseline.
cargo build --workspace --all-features
cargo test --workspace --all-features
```

If a tool is missing (`cbindgen`, `cargo-tarpaulin`, `bird2`, `frr`),
install it: `cargo install cbindgen` / `cargo install cargo-tarpaulin`
/ `apt-get install bird2 frr`. The CI workflow (`ci.yml`) is the
canonical list of build dependencies.

---

## 7. Where to look first

| Task | Start here |
| --- | --- |
| Understand the layering | `docs/ARCHITECTURE.md` |
| See what exists vs. missing | `docs/STATUS.md` |
| Find the next block of work | `docs/ROADMAP-v3.md` |
| Embed the library (Rust) | `docs/API.md` + `docs/tutorial.md` |
| Run the daemon | `docs/lr-cli.md` + `docs/RUNBOOK.md` + `templates/daemon.lr` |
| Embed (C / C++ / Go / Python) | `docs/bindings/{c,cpp,go,python}.md` + `docs/ffi_design.md` |
| Verify against BIRD / FRR | `docs/INTEROP.md` + `tests/interop/*.sh` |
| Cut a release | `docs/RELEASE-PLAN.md` |
| Write a filter | `docs/filter_dsl_grammar.md` + `docs/examples/filter_dsl_roa.md` |
| Port to a new OS | `docs/OS-INTEGRATION.md` |

When in doubt, read the code. The `git log` for a file is the best
narrative of why it is the way it is.
