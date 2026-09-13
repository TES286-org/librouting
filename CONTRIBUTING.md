# Contributing to librouting

Thanks for considering a contribution. librouting is a
platform-independent BGP / OSPF / Babel routing library written in
Rust, with C / C++ / Go / Python bindings; this document is the
single checklist every change must satisfy before it lands.

## Quick start

```bash
git clone https://github.com/TES286-org/librouting.git
cd librouting
cargo build --workspace --all-features
cargo test --workspace --all-features
```

CI uses Rust stable. The Minimum Supported Rust Version is pinned in
[`rust-toolchain.toml`](../rust-toolchain.toml) (currently stable;
MSRV 1.88 is enforced by the `msrv` job in
[ci.yml](../.github/workflows/ci.yml)). Do not introduce a crate that
requires a newer toolchain without bumping the MSRV in lockstep.

## How to land a change

1. **Open an issue first for non-trivial work.** Protocol
   correctness, public-API changes, or any item in
   [`docs/ROADMAP-v3.md`](ROADMAP-v3.md) benefits from a written
   design discussion before code is written. Trivial fixes
   (typo, missing test, clippy lint) can go straight to a PR.
2. **Branch off `main`.** Use a descriptive name:
   `feat/babel-multi-session`, `fix/proto-field-bird-name`,
   `docs/roadmap-v3`.
3. **Small, self-contained commits.** Each commit should build and
   pass tests. Prefer 5 small commits over 1 large one — bisecting a
   regression against 5 commits is cheap; against 1 megacommit it is
   impossible.
4. **Every commit message follows the Conventional Commits form**
   (see below).
5. **Open a PR against `main`.** CI must be green before review.

## Commit message format

Conventional Commits — `type(scope): summary`:

```
type(scope): imperative summary under 72 chars

Body: explain *why* this change is needed. Wrap at 80. Reference
issues (#123), RFCs (RFC 8966 §A.2.4), or prior commits (abcdef0)
when relevant.

Footer for breaking changes or sign-offs:
BREAKING CHANGE: explain what the consumer must update.
```

Recognised `type` values:

| Type     | Use for                                                        |
| -------- | -------------------------------------------------------------- |
| `feat`   | New user-visible feature or capability                         |
| `fix`   | Bug fix                                                        |
| `refactor` | Code restructuring with no behaviour change                |
| `perf`  | Performance improvement (also: add a benchmark in the commit) |
| `docs`  | Documentation only                                             |
| `test`  | Tests only (regression test, proptest, fuzz target, bench)    |
| `chore` | Tooling, CI, deps, refactor without user-visible impact       |
| `build` | Build system, Cargo.toml, build.rs                            |
| `ci`    | CI workflow changes                                            |
| `style` | Whitespace, formatting, import order                          |
| `revert`| Reverts a prior commit                                         |

Recognised `scope` values: a crate name without the `lr-` prefix
(`bgp`, `ospf`, `babel`, `policy`, `router`, `ffi`, `cli`, `core`,
`rib`, `bfd`, `bmp`, `mrt`, `damping`, `osroute`, `mpls`, `srv6`,
`ldp`, `tests`), `bindings`, `docs`, `ci`, `release`, or `deps`.

Examples:

```
feat(babel): per-interface socket pair and session
fix(policy): proto field returns BIRD-style lowercase name
docs(roadmap): add ROADMAP-v3 — 15 maturity directions
test(bgp): RFC 4271 Appendix A decode vectors
chore(deps): bump bytes from 1.10 to 1.11
```

## Code review checklist

Before requesting review, every PR must satisfy:

- [ ] `cargo fmt --all -- --check` is clean.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` is
      clean. Do not silence lints with `#[allow(...)]` unless the
      justification is in the commit message and the lint is named.
- [ ] `cargo test --workspace --all-features` is green. If a test
      is `#[ignore]`'d (e.g. kernel-gated interop), explain why in
      the commit message.
- [ ] If you added a public API, it has a doc comment and an entry
      in [`docs/API.md`](API.md).
- [ ] If you added a protocol feature, [`docs/STATUS.md`](STATUS.md)
      capability table is updated and [`docs/RFC_MAP.md`](RFC_MAP.md)
      has the RFC pinning.
- [ ] If you added a wire codec, you added a fuzz target or proptest
      strategy (see [`docs/ROADMAP-v3.md`](ROADMAP-v3.md) D6).
- [ ] If you touched the FFI surface, the C header was regenerated
      (`cbindgen` runs from `build.rs`) and the Go / Python / C++
      bindings are synced.
- [ ] Commit messages follow Conventional Commits.
- [ ] No `println!` / `dbg!` left in committed code — use `tracing`.

## Testing strategy

librouting has four test layers:

1. **Unit tests** — in-crate `#[cfg(test)] mod tests` blocks. Every
   public function has one. Fast, deterministic, run on every push.
2. **Integration tests** — `crates/*/tests/*.rs`. Cross-crate
   scenarios that exercise the daemon end-to-end against itself.
3. **Interop tests** — `tests/interop/*.sh`. Bash scripts that
   spawn `lr-daemon` against a reference daemon (BIRD 2, FRR 10) on
   loopback TCP / UDP / raw sockets and verify routes propagate in
   both directions. Run by the `interop` job in CI on Linux only.
4. **Kernel-gated tests** — `#[ignore]`'d tests that need root +
   specific kernel modules (TCP-AO, MPLS, SRv6). Run in the
   `tests/vm/run_vm.sh` QEMU harness in the `nightly` job.

When you add a feature, prefer the layer that proves the most with
the least code: a unit test for a codec, an integration test for a
daemon wiring change, an interop test for a protocol-level
behaviour.

## Adding a new crate

If your work needs a new crate (rare — discuss first):

1. Add it under `crates/lr-<name>/`.
2. Add it to `[workspace].members` in the root `Cargo.toml`.
3. Use the `lr-core` / `lr-bgp` / etc. `Cargo.toml` as a template —
   the package metadata block (version, license, authors, repo) is
   shared via `[workspace.package]` and inherited with
   `edition.workspace = true`.
4. Add the crate to [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) and
   the layering table in [`README.md`](../README.md).

## Adding a new RFC pin

When you implement or extend an RFC:

1. Add a row to [`docs/RFC_MAP.md`](RFC_MAP.md) with the RFC number,
   the crate path, and a one-line description.
2. Update the capability table in [`docs/STATUS.md`](STATUS.md).
3. Cite the RFC section in the doc comments and in the commit
   message. Example: `RFC 8966 §A.2.4 — RTT measurement TLV`.

## Release flow

Releases are tag-driven. See [`docs/RELEASE-PLAN.md`](RELEASE-PLAN.md)
for the semver policy, the 1.0 freeze criteria, and the post-1.0
governance rules. In short:

* Push a `v*` tag → [`release.yml`](../.github/workflows/release.yml)
  builds per-platform archives and uploads them to a draft GitHub
  Release.
* The release is published manually after a human reviews the draft.
* Every release ships the same artifacts the CI matrix built: the
  shared library, the headers, and the `lr` + `lr-daemon` binaries.

## License

By contributing, you agree that your contributions are licensed under
the same dual `MIT OR Apache-2.0` license as the rest of the project
(see [`LICENSE-MIT`](../LICENSE-MIT) and the Apache-2.0 reference at
the top of every crate's `Cargo.toml`).
