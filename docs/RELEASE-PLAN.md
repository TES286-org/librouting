# librouting Release Plan — toward 1.0.0 and beyond

This document is the canonical reference for the librouting
versioning policy, the API-freeze criteria gating the move from
0.x to 1.0, the release flow itself, and the post-1.0 governance
rules. It is the source of truth that the `.github/workflows/release.yml`
workflow and the `STATUS.md` roadmap summary both defer to.

The current state of the project against these criteria is captured
in [`STATUS.md`](STATUS.md); this document defines the criteria
themselves.

---

## 1. Semver policy

librouting follows [Cargo's semver interpretation](https://doc.rust-lang.org/cargo/reference/semver.html)
in the strict form the Rust ecosystem expects of a library:

| Change                                                    | Bump            |
| --------------------------------------------------------- | --------------- |
| Breaking change to a public Rust API (signature, type, trait, behaviour contract) | **minor** before 1.0, **major** after 1.0 |
| New public API (function, type, trait)                    | **minor**       |
| New feature flag, new protocol crate, new daemon flag     | **minor**       |
| Bug fix that does not change a documented public contract | **patch**       |
| Wire-format / RFC-correctness fix that changes which messages are accepted | **minor** (the old behaviour was a defect; this is the fix) |
| MSRV bump (minimum supported Rust version)               | **minor**, documented in the release notes |

The workspace `version` lives under `[workspace.package]` in
`Cargo.toml`. A bump is one PR — every crate shares the version
number, every `lr-X = { path = …, version = "0.1.0" }` line in
`[workspace.dependencies]` shares the bump.

### What is "public API" in librouting

The librouting public API has **three tiers**, each with a
different stability contract:

| Tier | Surface | Stability contract |
| --- | --- | --- |
| **1 — Rust library API** | `lr-core`, `lr-bgp`, `lr-ospf`, `lr-babel`, `lr-ldp`, `lr-bfd`, `lr-rib`, `lr-policy`, `lr-router`, `lr-damping`, `lr-mpls`, `lr-mrt`, `lr-bmp`, `lr-srv6`, `lr-osroute` — `pub` items reached from the crate root | Semver-tracked. Breaking changes are gated by a minor (pre-1.0) / major (post-1.0) bump and a release-notes entry. |
| **2 — C ABI** (`lr-ffi`) | `include/lr_ffi.h`, `include/librouting.hpp` — the `lr_*` symbols exported from `lr-ffi` and the `lr_router_t` / `lr_bytes_t` types | **ABI-stable.** A breaking ABI change is a major version bump *even pre-1.0*, because embedders (Go / Python / C / C++) compile against the published header. The `lr_abi_version()` accessor is bumped in lockstep. |
| **3 — Daemon flag + config surface** | `lr-daemon` CLI flags, the config schema (native `.lr` DSL in `templates/daemon.lr` + the TOML subset twin), the `lr:` extension directives, the `--api-socket` line protocol | **Documented stability.** A flag can be renamed only across a minor bump and must be supported as a deprecated alias for at least one minor cycle. The `--api-socket` line protocol's existing commands are stable; new commands are additive. |

### What is **not** public API

- Internal modules reached only via `pub(crate)` or `pub(in …)`
  are not part of the public API; they may change freely.
- `tests/`, `templates/`, `docs/`, `yang/` are not part of the
  public API — they are reference material that ships alongside the
  library.
- The exchange-plane prototype (`--features exchange-plane`) is
  explicitly experimental; its wire format rides IANA experimental
  code points pending an RFC 7120 early allocation. A 1.0 cut
  **does not** freeze the exchange-plane surface.

---

## 2. Pre-1.0 freeze criteria — when can we cut 1.0.0?

A `1.0.0` tag is appropriate once **all** of the following are
true. They are written so an outside reviewer can verify each one
without taking the maintainers' word for it.

### 2.1. RFC coverage at feature parity with the reference implementations

The capability tables in [`STATUS.md`](STATUS.md) must show ✅ for
every RFC the project considers in-scope at parity with BIRD 2.17.x
and FRR 10.x. The deliberately-out-of-scope items (currently only
BGPsec) must be enumerated as ❌ with rationale — no silent gaps.

### 2.2. Cross-vendor interop verified in CI

Every protocol crate that ships a peer FSM must have at least one
`tests/interop/*.sh` lab that exchanges real traffic with a
reference implementation (BIRD / FRR / a real OSPFv3 daemon) in
both directions. The interop matrix in [`INTEROP.md`](INTEROP.md)
must be the live `tests/interop/` directory listing, not a curated
subset.

### 2.3. Wire-level parity harness green

`lr parity-replay` must reproduce, byte-for-byte on the Loc-RIB, the
output of the reference implementation given the same captured wire
stream — for at least one capture per protocol family (BGP, OSPFv2,
OSPFv3, Babel, LDP). The documented normalizations in
[`PARITY.md`](PARITY.md) are allowed; anything else is a defect.

### 2.4. Cross-platform CI green

The CI matrix in `.github/workflows/ci.yml` must cover:

- **Linux** (Ubuntu LTS, 22.04 and the latest LTS in flight) —
  the full interop suite + kernel-gated tests.
- **macOS** (Apple Silicon, `macos-14`) — `cargo build --workspace`,
  `cargo test --workspace`, `cargo clippy -D warnings`. Intel macOS
  is covered by cross-compilation to `x86_64-apple-darwin` from the
  Apple Silicon runner (GitHub Actions retired the Intel `macos-13`
  pool in 2025); the `lr-osroute` BSD backend is shared between Intel
  and Apple Silicon macOS, so the cross-build covers the Intel path.
- **Windows** (x86_64, MSVC toolchain) — `cargo build --workspace`,
  `cargo test --workspace`, `cargo clippy -D warnings`.

All three must be green on `main` at the cut commit.

### 2.5. ABI version pinned

`lr_core::ABI_VERSION` and the C ABI accessor `lr_abi_version()`
must be bumped to a documented value, and the `lr-ffi` C header
(`include/lr_ffi.h`) and C++ wrapper (`include/librouting.hpp`)
must be regenerated from the same `cargo build -p lr-ffi` run as
the published binaries.

### 2.6. Documentation set complete

The following must all exist, be reviewed, and reference live code
(not aspirational features):

- `README.md` — project overview + quick-start
- `docs/README.md` — document index
- `docs/tutorial.md` — book-style tutorial (3 chapters, every
  snippet pinned by `crates/lr-tests/tests/tutorial_snippets.rs`)
- `docs/ARCHITECTURE.md` — layering + RIB pipeline + testing layout
- `docs/API.md` — public Rust API tour, layer by layer
- `docs/lr-cli.md` — CLI user guide
- `docs/lr-cli-internals.md` — CLI internals / extension patterns
- `docs/RUNBOOK.md` — daemon lifecycle + runtime API + troubleshooting
- `docs/COMPAT.md` — BIRD / FRR compat layer
- `docs/PARITY.md` — behaviour knobs side-by-side
- `docs/INTEROP.md` — interop matrix + local reproduction
- `docs/RFC_MAP.md` — RFC-by-RFC coverage table
- `docs/STATUS.md` — implemented-vs-missing gap analysis
- `docs/ROADMAP.md` — workstream landing log
- `docs/RELEASE-PLAN.md` — this document
- `docs/OS-INTEGRATION.md` — kernel backends per OS
- `docs/bindings/{c,cpp,go,python}.md` — per-language embedding guides
- `docs/examples/*.md` — per-scenario walkthroughs
- `docs/research/*.md` — research notes (BGP defects, exchange plane)
- `templates/daemon.lr` — fully-commented reference configuration (native DSL; `daemon.toml` is the compat twin)
- `templates/README.md` — scaffolding templates
- `yang/*.yang` — standards-track YANG models

### 2.7. Pre-1.0 release-notes audit

A single PR (the "1.0 cut" PR) must:

- Update `Cargo.toml` to `version = "1.0.0"` (workspace).
- Bump `lr_core::ABI_VERSION` to the documented 1.0 value.
- Regenerate `include/lr_ffi.h` and `include/librouting.hpp`.
- Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --workspace --all-features` against the cut commit on
  Linux, macOS and Windows.
- Write the 1.0 release notes enumerating the protocol coverage
  surface, the interop verification, and the deliberately-out-of-scope
  items.

### 2.8. Current status against these criteria

As of HEAD (`v1.0.0-rc.4`), the picture is:

- ✅ 2.1 — RFC coverage at parity for everything in scope; only
  BGPsec is ❌ and is documented out of scope.
- ✅ 2.2 — Cross-vendor interop in CI (BIRD 2 + FRR 10) for BGP,
  OSPFv2/v3, Babel, LDP, BFD, BMP, MRT, parity.
- ✅ 2.3 — Wire-level parity harness (`lr parity-replay` +
  `tests/interop/parity.sh`) green on `main`.
- ✅ 2.4 — Cross-platform CI green on Linux (Ubuntu 22.04 + 24.04),
  macOS (Apple Silicon, macos-14) and Windows (2022). The matrix
  has been green on every push since the Phase 4 series landed.
- ✅ 2.5 — `lr_abi_version()` exists (`ABI_VERSION = 1`); the 1.0
  cut PR will confirm the value is still 1 (no ABI break since
  rc.1) or bump it if a late change requires one.
- ✅ 2.6 — Documentation set is complete.
- 🟡 2.7 — The 1.0 cut PR is the next release-event. The criteria
  it must satisfy are enumerated below.

**When can we cut 1.0.0?**

A `1.0.0` tag is appropriate once **all** of the following are
true on `main`:

1. **No open `release-blocker` issues.** Every GitHub issue labelled
   `release-blocker` is closed or re-labelled. Issues #19 (DSL
   performance) and #20 (publish to package managers) are
   `enhancement`, not blockers — they do not gate the freeze.
2. **One full week of clean CI on all three platforms** (Linux,
   macOS, Windows) on the commit that will be tagged. The rc.4
   release is the start of this week; if CI stays green through
   2026-09-26 on `main`, the 1.0 cut can proceed.
3. **No breaking-change commits since the last `-rc`.** The public
   Rust API (Tier 1) and the C ABI (Tier 2) must be byte-identical
   to rc.4. If a breaking change is needed, it ships as rc.5 and
   the clock restarts.
4. **The `release.yml` workflow produces all 6 assets** (4 archives
   + 2 standalone headers) on the rc.4 tag without manual
   intervention — this is verified by the rc.4 release itself.
5. **The community validation window.** At least one downstream
   embedder (or the maintainer's own integration test) confirms the
   rc.4 artifacts link + run against a real BIRD / FRR peer. The
   `tests/interop/` suite is the in-repo proxy; an external report
   is the community signal.

If all five are true, the 1.0 cut PR:

1. Updates `Cargo.toml` to `version = "1.0.0"` (workspace).
2. Confirms `ABI_VERSION` is still 1 (or bumps it with a
   `BREAKING CHANGE:` entry).
3. Regenerates `include/lr_ffi.h` and `include/librouting.hpp`.
4. Runs `cargo fmt`, `cargo clippy --all-targets --all-features
   -- -D warnings`, `cargo test --workspace --all-features` on
   Linux, macOS and Windows.
5. Writes the 1.0 release notes enumerating the protocol coverage
   surface, the interop verification, and the
   deliberately-out-of-scope items.
6. Tags `v1.0.0` and pushes; `release.yml` builds the final
   artifacts.

**Target window**: a `1.0.0` cut is appropriate once rc.4 has been
on `main` for one full week of clean CI on Linux + macOS + Windows
(target: 2026-09-26) and no `release-blocker` issue is open. The
next Phase 3 items (BGP-LS, BGP SR Policy, D8.2 RIB sharding, D15
multi-threaded RIB) are **post-1.0 work** — they extend the surface
but do not block the freeze, because the surface they extend is
already at parity with BIRD and FRR for the protocols they touch.

---

## 3. Release flow

### 3.1. Pre-release checks

Before tagging, on a clean checkout of `main`:

```sh
# Format + lint (every platform).
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

# Full workspace test (Linux).
cargo test --workspace --all-features

# Build the release artifacts (mirrors the CI workflow).
cargo build --workspace --release --all-features
cargo build --release -p lr-ffi
```

The maintainer then runs the same shape on macOS and Windows (the
CI matrix already does this on push; the pre-release check is
belt-and-braces against a runner-cache hit).

### 3.2. Tagging

```sh
# Bump Cargo.toml's workspace version (one PR per release).
#   0.1.0 → 0.2.0 (minor)
#   0.2.0 → 0.2.1 (patch)
#   1.0.0 → 1.0.1 (patch)
#   1.0.1 → 1.1.0 (minor)
#   …
git commit -m "release: vX.Y.Z"
git tag -a vX.Y.Z -m "librouting vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

The tag push triggers `.github/workflows/release.yml`:

1. **Build matrix** — Linux x86_64, macOS Intel, macOS Apple Silicon,
   Windows x86_64 each build `lr-ffi` in release mode and stage the
   shared library + the static archive (where emitted) + the C / C++
   headers into a tarball (or `.zip` on Windows).
2. **Publish job** — downloads all four build artifacts, flattens
   them with the standalone headers, and creates a **draft** GitHub
   Release with auto-generated commit-diff release notes and a
   boilerplate body linking back to this document.

The release stays **draft** until the maintainer reviews the
release notes, fills in the **Breaking changes** / **New features**
/ **Fixes** sections from the commit log, and publishes.

### 3.3. After publish

- Update `docs/STATUS.md` and `docs/ROADMAP.md` with a "Released
  vX.Y.Z on YYYY-MM-DD" entry pointing back at the release.
- Open issues for any follow-up TODOs the release uncovered.
- If the release is a major bump (1.0.0, 2.0.0, …), announce on the
  project's channel and update the README compatibility matrix.

### 3.4. Hotfix flow

A patch release off a backport branch:

```sh
git checkout -b release/vX.Y.x vX.Y.Z
# cherry-pick the fix(es)
git cherry-pick <fix-commit>
# bump Cargo.toml to vX.Y.(Z+1)
git commit -am "release: vX.Y.(Z+1)"
git tag -a vX.Y.(Z+1) -m "librouting vX.Y.(Z+1)"
git push origin release/vX.Y.x
git push origin vX.Y.(Z+1)
```

The same `release.yml` runs on the tag push; the draft release is
the same shape.

---

## 4. Post-1.0 governance

### 4.1. Stability window

Once `1.0.0` is tagged, the **public Rust API** and the **C ABI**
enter their stability window. The rules in §1 apply in their strict
form: a breaking change to either is a major-version bump, no
exceptions for "we know better now."

### 4.2. Deprecation policy

A public API that is being replaced may be marked `#[deprecated]`
with a note pointing at the replacement. A deprecated API stays
for at least **one minor cycle** (e.g. deprecated in 1.1, removed
in 1.2 or 2.0). A daemon flag renamed under the same policy gets a
deprecated alias that prints a one-line warning on startup.

### 4.3. New protocol crates

A new protocol crate (e.g. a future `lr-isis`) lands as a new
minor version (1.x.0). It must come with:

- A `STATUS.md` capability table for the new crate.
- An `RFC_MAP.md` entry per RFC implemented.
- At least one `tests/interop/*.sh` lab against a reference
  implementation.
- A `docs/bindings/`-style embedding guide if the crate exposes a
  new public API beyond what the existing crates already cover.

### 4.4. Out-of-scope items

Items currently documented out of scope (BGPsec, NBMA / point-to-
multipoint OSPF interface types, OSPFv3 virtual links) stay out
of scope unless a contributor opens an issue with a concrete
deployment scenario. Reopening any of them is a minor version bump
and a `STATUS.md` capability-table entry; the freeze does not
apply to the new surface, only to the existing one.

---

## 5. Compatibility matrix

The reference implementations librouting is verified against:

| Reference | Version       | Where (CI)                          |
| ---------- | ------------- | ----------------------------------- |
| BIRD       | 2.x (Ubuntu LTS package + 2.17.x) | `tests/interop/bird*.sh`, `compat_bird.sh` |
| FRR        | 10.x (and 8.1 on Ubuntu 22.04 runners) | `tests/interop/frr*.sh`, `compat_frr.sh`, `ldp_frr*.sh`, `ospf*_frr*.sh` |
| libyang    | (interop lab) | `tests/interop/yang.sh`             |
| Linux      | 5.10+ (Ubuntu LTS), 6.8 (ubuntu-24.04) | kernel-gated tests, `tests/vm/run_vm.sh` |

A BIRD or FRR major version bump that introduces a behaviour
change is a `PARITY.md` update + (if the change is observable on
the wire) an interop lab refresh. The version range is documented
in [`PARITY.md`](PARITY.md); this document only commits to "CI
runs against the latest Ubuntu LTS package + a maintained recent
release."

---

## 6. Release event log

| Tag           | Date          | Notes                                                                                              |
| ------------- | ------------- | -------------------------------------------------------------------------------------------------- |
| v1.0.0-rc.1   | 2026-09-11    | API-freeze pre-release. All §2 freeze criteria verified on commit `1cc6f5d`. CI 11/11 jobs green (Ubuntu, macOS Apple Silicon, Windows, 3 cross-builds, MSRV, Coverage, interop BIRD+FRR, interop-auth TCP-AO). Nightly 2/2 green (Miri, QEMU VM harness). The 1-week clean-CI wait (§2.8) skipped per the user's instruction: functionality is complete (at parity with BIRD 2 + FRR 10, only BGPsec out of scope) and the recent commit history is docs + CI + small fixes (no protocol code changes). Released as a pre-release rather than the final 1.0.0 to test the never-exercised `release.yml` workflow end-to-end and signal API freeze to the community. 6 assets: librouting-{linux-x86_64.tar.gz, macos-x86_64.tar.gz, macos-aarch64.tar.gz, windows-x86_64.zip} + lr_ffi.h + librouting.hpp. |
| v1.0.0-rc.2   | 2026-09-11    | Adds the `lr` + `lr-daemon` CLI binaries to each per-OS archive. rc.1 archives contained only the shared library and headers; the CLI binaries were built by `cargo build --workspace` but not staged. The `release.yml` matrix gained `lr_bin` and `lrd_bin` entries (`lr` / `lr-daemon` on Unix, `lr.exe` / `lr-daemon.exe` on Windows) and the staging steps copy them into the archive alongside the shared library. Each archive now contains: the shared library, the static archive (where emitted), the two CLI binaries, and the headers. Release workflow 5/5 jobs green. Same 6 standalone assets (4 archives + 2 headers) — the archives are now richer. |
| v1.0.0-rc.3   | 2026-09-12    | Multi-protocol daemon: one lr-daemon process runs a combination of bgp, ospf and babel (`--protocol bgp,ospf`, TOML `protocols = [...]`) through a shared-router supervisor — one Loc-RIB, one ticker, one API socket, one thread per engine, gated startup (binds → privdrop → release) and fail-closed combinations. Ships the lr-router cross-protocol Loc-RIB merge (admin-distance ordering with withdrawal fallback, direct contributions never evicted by BGP re-ranking, no implicit redistribution into BGP — pipes stay opt-in) plus the Babel idle-spin fix. API unchanged (daemon-layer + router internals only) — bindings need no regeneration. Coverage: 8 new unit tests, 4 new e2e tests, the multi_protocol.sh BIRD interop lab (lr bgp,ospf ↔ BIRD ospf+bgp) wired into CI. |
| v1.0.0-rc.4   | 2026-09-19    | Config DSL migration (issue #18 Phases 0–4) + filter VM hardening (issue #19 P6 + P7). Ships the native `.lr` configuration DSL (`templates/daemon.lr`), `lr-daemon config check`, `lr-daemon config to-dsl`, positioned filter diagnostics (byte `Span` on every token / AST node / error, in both the interpreter and the bytecode VM, with a caret snippet rendered by the daemon and `lrctl filter compile`), the TOML deprecation window, filter VM instruction fusion (`BranchFieldIntCmp` — `vm_if_local_pref` ~66 → ~28 ns, −57 %), the lazy span read + function-body span bug fix (P7), RFC 8326 graceful session shutdown (receive + send + per-peer exempt), and OSPFv3 Extended-LSA + SRv6 End.X (RFC 8362 + RFC 9513 §9.1/§9.2). Public Rust API + C ABI unchanged since rc.3 — no breaking changes. 174 commits, 1891 tests pass (was 1733 at rc.3). 7 new interop labs wired into CI. |
| (pending)     | (post-rc.4)   | Final 1.0.0 cut — see §2.8 for the freeze criteria.                                              |

The tag history is the canonical release record; this table is the
human-readable index.
