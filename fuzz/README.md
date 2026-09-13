# cargo-fuzz targets for librouting (ROADMAP-v3 D6.4)

The `fuzz/` workspace houses the long-running, sanitizer-driven fuzz
targets that complement the property tests in `crates/*/tests/proptest.rs`.
Property tests run inside `cargo test` and assert structural invariants
(prefix lattice, parser purity, codec contract); fuzz targets run under
`cargo +nightly fuzz` with AddressSanitizer + LibFuzzer's coverage-guided
input generation, and assert the *security* contract: **the codec / parser
must never panic, never abort, never exhibit undefined behaviour on
arbitrary input**.

## Layout

```
fuzz/
├── Cargo.toml                  # fuzz workspace, depends on in-tree lr-* crates
├── README.md
├── fuzz_targets/
│   ├── bgp_decode.rs           # BgpCodec::decode_slice  — wire input
│   ├── filter_parser.rs        # filter DSL compile()    — operator config
│   └── roa_validate.rs         # RoaTableBuilder::add + validate — RPKI cache input
└── seeds/                      # hand-picked starting corpus
    ├── bgp_decode/             # minimal KEEPALIVE / OPEN / UPDATE / truncated / bad-marker
    ├── filter_parser/          # accept / reject / if-local-pref / prefix-set / garbage
    └── roa_validate/           # empty table + single exact-match
```

The `fuzz/corpus/` and `fuzz/artifacts/` directories are generated at
run time and `.gitignore`d — they hold the auto-grown corpus and any
crash artifacts the fuzzer discovers. Seeds under `fuzz/seeds/` are
committed so anyone running `cargo +nightly fuzz run` starts from a
meaningful initial coverage point instead of an empty corpus.

## Running locally

```bash
# Install the cargo-fuzz subcommand (one-time).
cargo +nightly install cargo-fuzz --locked

# Seed the corpus from the committed hand-picked inputs (one-time
# per checkout). cargo-fuzz reads fuzz/corpus/<target>/ at run
# time, so a fresh checkout has no corpus until you copy seeds in.
for t in bgp_decode filter_parser roa_validate; do
  mkdir -p "fuzz/corpus/$t"
  cp "fuzz/seeds/$t/"* "fuzz/corpus/$t/"
done

# Run one target for 60 seconds.
cargo +nightly fuzz run bgp_decode -- -max_total_time=60

# Run all targets in a loop (recommended for nightly CI).
for t in bgp_decode filter_parser roa_validate; do
  cargo +nightly fuzz run "$t" -- -max_total_time=300
done
```

## CI integration

The nightly workflow (`.github/workflows/nightly.yml`) runs each
target for 5 minutes under `cargo +nightly fuzz`. Fuzzing is
non-blocking on PRs — a regression is filed as an issue, not a CI
failure, because the corpus growth can take days to surface a bug
that the build itself cannot detect.

## Adding a new target

1. Add a new file under `fuzz/fuzz_targets/<name>.rs` with the
   `#![no_main]` + `fuzz_target!(...)` boilerplate (see
   `bgp_decode.rs` for the canonical shape).
2. Add a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Add a CI step in `.github/workflows/nightly.yml` mirroring the
   existing fuzz jobs.

## Coverage scope

The current three targets cover the highest-risk input surfaces
(network wire + operator config + RPKI cache). The remaining ROADMAP
targets — `ospf_decode`, `babel_decode`, `ldp_decode`, `bfd_decode`,
`bmp_decode`, `mrt_decode` — follow the same pattern and will be
added as those crates' codecs stabilise.
