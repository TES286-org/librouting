# Conversion corpus

Golden-file regression net for `lr-daemon translate bird|frr`. Every
`.conf` file in `bird/` or `frr/` is a real-world BIRD 2 or FRR
configuration covering one shape the converter maps today; the matching
`.expected.toml` file is the exact TOML the converter emits, committed
to the repository. A new dialect quirk adds a corpus case (input +
expected) instead of a bespoke assertion.

## Layout

```
tests/corpus/
  bird/                 # BIRD 2 dialect inputs
    <case>.conf         # a representative BIRD config
    <case>.expected.toml# the converter's exact output
  frr/                  # FRR dialect inputs
    <case>.conf
    <case>.expected.toml
```

## The contract

- Every `.expected.toml` is the byte-for-byte output of
  `lr-daemon translate <dialect> <case>.conf` (stdout only).
- Every `.expected.toml` round-trips through the daemon loader
  (`parse_toml_subset` + `finalize`) — the generated TOML is always
  loadable.
- `# UNMAPPED:` comments mark lines the converter cannot map. They are
  part of the contract: a line that has no lr equivalent (e.g. BIRD
  `multihop`, FRR `network PREFIX area N`) stays visible instead of
  being silently dropped. A line that *would* change behaviour if
  dropped is a bug, not a corpus case.

## Running the gate

Two harnesses check the corpus, sharing the same data files:

1. **In-crate unit test** (`crates/lr-cli/src/corpus_tests.rs`,
   reached as `translate::corpus_tests`): drives the converter
   functions directly. Runs on every platform in `cargo nextest` /
   `cargo test`.
   ```
   cargo test -p lr-cli --bin lr-daemon translate::corpus_tests
   ```

2. **End-to-end shell gate** (`tests/interop/translate_corpus.sh`):
   drives the real `lr-daemon translate` CLI binary. Runs in the Linux
   `Interop (BIRD + FRR)` CI job (the "interop gate").
   ```
   ./tests/interop/translate_corpus.sh
   ```

## Regenerating after an intentional converter change

Both harnesses honour `LR_CORPUS_UPDATE=1` — set it to rewrite every
`.expected.toml` from the current converter output instead of
diffing:

```
LR_CORPUS_UPDATE=1 cargo test -p lr-cli --bin lr-daemon translate::corpus_tests
# or, for the CLI binary path:
LR_CORPUS_UPDATE=1 ./tests/interop/translate_corpus.sh
```

Review the diff of the regenerated files before committing — a
surprising change in a `.expected.toml` is the signal the converter
regressed (or improved) in a way the corpus did not intend.

## Adding a case

1. Pick a shape the converter maps (or should map) — a real BIRD or
   FRR idiom from a first-hand source (RFC, BIRD manual, FRR user
   guide).
2. Add `<case>.conf` under `bird/` or `frr/`.
3. Generate the expected output:
   `LR_CORPUS_UPDATE=1 cargo test -p lr-cli --bin lr-daemon translate::corpus_tests`
4. Review `<case>.expected.toml`: every `# UNMAPPED:` line should be
   a genuine gap (no lr equivalent), not a line that changes behaviour
   if dropped. If it is the latter, fix the converter and regenerate.
5. Commit the pair together.
