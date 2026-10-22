#!/usr/bin/env bash
# Conversion-corpus gate for `lr-daemon translate bird|frr`.
#
# The corpus under tests/corpus/{bird,frr}/ pairs every real-world
# BIRD or FRR `.conf` with the exact `.expected.toml` the converter
# emits. This script is the end-to-end half of the corpus gate: it
# drives the real `lr-daemon translate` CLI binary (the in-crate
# `translate::corpus_tests` unit test drives the same converter
# functions directly and runs on every platform in `cargo test`).
#
# A mismatch fails with a unified diff so the regression is obvious.
# Run `LR_CORPUS_UPDATE=1 ./tests/interop/translate_corpus.sh` to
# regenerate the `.expected.toml` files after an intentional converter
# change (the unit test honours the same env var).
#
# No reference daemon (BIRD/FRR) is needed — this is a pure converter
# gate — so it runs on every CI runner that has a Rust toolchain.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=$(./tests/interop/_lr_daemon.sh 2>/dev/null || true)
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "SKIP: lr-daemon binary not found (run \`cargo build -p lr-cli\` first)"
    exit 0
fi

CORPUS=tests/corpus
UPDATE=${LR_CORPUS_UPDATE:-0}
fail=0
checked=0

run_case() {
    local dialect="$1" conf="$2"
    local expected
    expected="${conf%.conf}.expected.toml"
    checked=$((checked + 1))
    local actual
    actual=$("$BIN" translate "$dialect" "$conf" 2>/dev/null || true)
    if [ "$UPDATE" = "1" ]; then
        printf '%s\n' "$actual" >"$expected"
        return
    fi
    if [ ! -f "$expected" ]; then
        echo "FAIL: $conf — missing $expected (run with LR_CORPUS_UPDATE=1)"
        fail=1
        return
    fi
    local exp
    exp=$(cat "$expected")
    if [ "$actual" != "$exp" ]; then
        echo "FAIL: $conf — converter output differs from $expected"
        diff -u "$expected" <(printf '%s\n' "$actual") || true
        fail=1
        return
    fi
    echo "PASS: $dialect $(basename "$conf")"
}

for dialect in bird frr; do
    dir="$CORPUS/$dialect"
    [ -d "$dir" ] || continue
    for conf in "$dir"/*.conf; do
        [ -f "$conf" ] || continue
        run_case "$dialect" "$conf"
    done
done

if [ "$UPDATE" = "1" ]; then
    echo "corpus: regenerated $checked .expected.toml file(s)"
    exit 0
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "corpus gate FAILED ($checked case(s) checked)"
    exit 1
fi
echo "corpus gate OK: $checked case(s) match their .expected.toml"
