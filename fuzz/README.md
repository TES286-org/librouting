# cargo-fuzz targets

`fuzz/` is a standalone Cargo workspace (it is not a member of the
librouting workspace) holding the sanitizer-driven fuzz targets. They
complement the property tests in `crates/lr-policy/tests/proptest.rs`: those
run inside `cargo test` and assert structural invariants, while these run
under `cargo +nightly fuzz` with AddressSanitizer and LibFuzzer's
coverage-guided input generation and assert one contract — the codec or
parser under test must not panic or exhibit undefined behaviour on arbitrary
input.

Read this page to run a target or to add one.

The targets are `bgp_decode` (`BgpCodec::decode_slice`), `filter_parser`
(`lr_policy::filter::compile`) and `roa_validate` (`RoaTableBuilder::add`
plus `RoaTable::validate`).

## Layout

| Path | Contents |
| --- | --- |
| `fuzz/Cargo.toml` | The fuzz workspace; one `[[bin]]` per target |
| `fuzz/fuzz_targets/` | One file per target |
| `fuzz/seeds/` | Committed starting inputs, one directory per target |

`fuzz/corpus/`, `fuzz/artifacts/` and `fuzz/coverage/` are generated at run
time and ignored by the root `.gitignore`, so a fresh checkout starts from
`fuzz/seeds/` alone.

## Running locally

```bash
# Install the subcommand (one-time).
cargo +nightly install cargo-fuzz --locked

# Seed fuzz/corpus/<target>/ from the committed inputs (one-time per
# checkout): cargo-fuzz reads fuzz/corpus/<target>/ at run time.
for t in bgp_decode filter_parser roa_validate; do
  mkdir -p "fuzz/corpus/$t"
  cp "fuzz/seeds/$t/"* "fuzz/corpus/$t/"
done

# One target.
cargo +nightly fuzz run bgp_decode -- -max_total_time=60
```

## CI

`.github/workflows/nightly.yml` runs each target for five minutes and
uploads `fuzz/artifacts/` as an artifact. The job is non-blocking: a crash
does not fail the build.

## Adding a target

1. Add `fuzz/fuzz_targets/<name>.rs` with the `#![no_main]` +
   `fuzz_target!(...)` boilerplate (`bgp_decode.rs` is the canonical shape).
2. Add the matching `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Add a step to the fuzz job in `.github/workflows/nightly.yml`.
