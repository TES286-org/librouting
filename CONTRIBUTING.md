# Contributing to librouting

This is the checklist every change has to satisfy before it lands. It is
the canonical contributor guide; [`AGENTS.md`](AGENTS.md) is the shorter
orientation for AI agents and points back here.

## Quick start

```sh
git clone https://github.com/TES286-org/librouting.git
cd librouting
cargo build --workspace --all-features
cargo test --workspace --all-features
```

The toolchain and the minimum supported Rust version are pinned in
[`rust-toolchain.toml`](rust-toolchain.toml) and
`[workspace.package] rust-version` in [`Cargo.toml`](Cargo.toml) — check
those files rather than trusting a number written in prose. Do not
introduce a dependency that needs a newer toolchain without bumping the
MSRV in the same change.

## How to land a change

1. **Open an issue first for anything non-trivial.** Protocol
   correctness, public API changes, and anything already listed in
   [`docs/ROADMAP.md`](docs/ROADMAP.md) benefit from a written design
   discussion before code. Typo fixes, a missing test and a clippy lint
   can go straight to a pull request.
2. **Branch off `main`**, with a descriptive name:
   `feat/babel-multi-session`, `fix/proto-field-bird-name`,
   `docs/roadmap-v3`.
3. **Keep commits small and self-contained.** Each one should build and
   pass tests. Five small commits beat one large one, because a
   regression can be bisected.
4. **Open a pull request against `main`.** CI has to be green before
   review.

## Commit messages

Conventional Commits — `type(scope): summary`, imperative, under 72
characters:

```text
type(scope): imperative summary under 72 chars

Body: explain why the change is needed. Wrap at 80 columns. Reference
the RFC section (RFC 8966 §A.2.4), the issue, or the prior commit when
it helps.

BREAKING CHANGE: only when a consumer has to change something.
```

| Type | Use for |
| --- | --- |
| `feat` | New user-visible feature or capability |
| `fix` | Bug fix |
| `refactor` | Restructuring with no behaviour change |
| `perf` | Performance work — include the measured delta |
| `docs` | Documentation only |
| `test` | Tests only |
| `chore` | Tooling, dependencies, non-user-visible cleanup |
| `build` | Build system, `Cargo.toml`, `build.rs` |
| `ci` | CI workflow changes |
| `style` | Whitespace, formatting, import order |
| `revert` | Reverts a prior commit |

Recognised scopes: a crate name without the `lr-` prefix (`bgp`, `ospf`,
`babel`, `ldp`, `core`, `rib`, `policy`, `router`, `bfd`, `bmp`, `mrt`,
`damping`, `osroute`, `mpls`, `srv6`, `ffi`, `cli`, `tests`), or
`bindings`, `docs`, `ci`, `release`, `deps`.

## Code review checklist

- [ ] `cargo fmt --all -- --check` is clean.
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
      is clean. Do not silence a lint with `#[allow(...)]` unless the
      lint is named and the justification is in the commit message.
- [ ] `cargo test --workspace --all-features` is green. An `#[ignore]`d
      test (kernel-gated interop, for example) needs a reason in the
      commit message.
- [ ] A new public item has a doc comment and a section in
      [`docs/api/`](docs/api/).
- [ ] A new protocol feature updates the capability table in
      [`docs/STATUS.md`](docs/STATUS.md) and adds its RFC to
      [`docs/RFC_MAP.md`](docs/RFC_MAP.md).
- [ ] A new wire codec has a fuzz target or a proptest strategy.
      The targets live in `fuzz/fuzz_targets/`.
- [ ] Touching the FFI surface means regenerating the C header
      (`cbindgen` runs from `crates/lr-ffi/build.rs`) and syncing the Go,
      Python and C++ bindings.
- [ ] Commit messages follow the format above.
- [ ] No `println!` or `dbg!` in committed code — use `tracing`.
- [ ] Documents follow [`docs/STYLE.md`](docs/STYLE.md), and
      `tests/lint_docs.sh` passes.

## Testing

Four layers, cheapest first. Prefer the layer that proves the most with
the least code.

1. **Unit tests** — `#[cfg(test)] mod tests` inside a crate. Fast and
   deterministic. New public functions need one; codecs need one per
   wire form.
2. **Integration tests** — `crates/*/tests/*.rs`. Cross-crate scenarios
   that drive the daemon's own pipeline end to end.
3. **Interop tests** — `tests/interop/*.sh`. Bash scripts that run
   `lr-daemon` against a reference daemon, or against a second
   `lr-daemon` where no reference is available. They skip cleanly when
   the reference binary is missing. Every script has to be listed in
   [`docs/INTEROP.md`](docs/INTEROP.md); `tests/lint_interop_doc.sh`
   enforces it.
4. **Kernel-gated tests** — `#[ignore]`d tests that need root and a
   kernel feature (TCP-AO, MPLS, SRv6). `tests/vm/run_vm.sh` runs them
   in a QEMU guest during the nightly job.

## Adding a crate

New crates are rare — discuss it in an issue first.

1. Add it under `crates/lr-<name>/`.
2. Add it to `members` in the root [`Cargo.toml`](Cargo.toml).
3. Copy the package metadata block from an existing crate: version,
   license and repository are inherited from `[workspace.package]`.
4. Add it to the crate table in [`README.md`](README.md) and to the
   layering picture in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Adding an RFC

When you implement or extend an RFC:

1. Add a row to [`docs/RFC_MAP.md`](docs/RFC_MAP.md): the RFC number,
   the `lr-crate::module` path, and what it implements.
2. Update the capability table in [`docs/STATUS.md`](docs/STATUS.md).
3. Cite the section in the doc comment and in the commit message —
   `RFC 8966 §A.2.4 — RTT measurement TLV`.

## Release flow

Releases are tag-driven; the semver policy and the freeze rules are in
[`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md).

- Pushing a `v*` tag runs [`release.yml`](.github/workflows/release.yml),
  which builds the per-platform archives and uploads them to a draft
  GitHub release. The release is published after a human reviews it.
- Every release ships the same artifacts: the shared library, the C and
  C++ headers, and the `lr`, `lr-daemon` and `lrctl` binaries.

## License

Contributions are licensed under the same dual `MIT OR Apache-2.0`
license as the project. The MIT text is in
[`LICENSE-MIT`](LICENSE-MIT); the Apache-2.0 reference is in the
`license` field of every crate's `Cargo.toml`.
