#!/usr/bin/env bash
# Guard: every interop lab in tests/interop/ must be documented in
# docs/INTEROP.md, and every script the document mentions must exist.
#
# docs/RELEASE-PLAN.md §2.2 requires the interop matrix in INTEROP.md
# to be the *live* tests/interop/ directory listing, not a curated
# subset. This guard makes that requirement machine-checked: when a
# new lab lands without a documentation row, CI (and this script)
# fails with the exact list of undocumented labs.
#
# Shared helper libraries (leading underscore, e.g. `_lib.sh`) are
# infrastructure, not labs: they must be referenced in the document's
# "Shared helpers" note instead. This script checks that they are
# mentioned somewhere in docs/INTEROP.md too, so nothing in the
# directory is silent.
#
# Dependencies: bash, GNU coreutils, GNU grep — nothing else. It must
# run on a bare GitHub-hosted runner (no ripgrep there).
#
# Usage: tests/lint_interop_doc.sh   (from the repository root)

set -euo pipefail
cd "$(dirname "$0")/.."

DOC=docs/INTEROP.md
fail=0

missing_doc() {
    # Labs on disk that docs/INTEROP.md never references. The
    # basename is matched as a whole word, so `ldp.sh` does not
    # false-positive on `ldp_frr.sh` (the `_` is a word character,
    # which kills the `\b` boundary) and a row may use either the
    # bare name or the full `tests/interop/…` path.
    local s
    for s in tests/interop/*.sh; do
        local base
        base=$(basename "$s")
        if ! grep -Eq "\b${base//./\\.}\b" "$DOC"; then
            echo "UNDOCUMENTED LAB: tests/interop/$base"
            fail=1
        fi
    done
}

missing_file() {
    # Scripts referenced by the document that no longer exist
    # (stale rows are as misleading as missing rows).
    local p
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        if [ ! -f "$p" ]; then
            echo "STALE DOC ROW: $p is documented but does not exist"
            fail=1
        fi
    done < <(grep -oE 'tests/interop/[A-Za-z0-9_]+\.sh' "$DOC" | sort -u)
}

missing_doc
missing_file

if [ "$fail" -ne 0 ]; then
    echo
    echo "docs/INTEROP.md and tests/interop/ have diverged."
    echo "Add a matrix row for each new lab (or delete the stale row);"
    echo "see docs/INTEROP.md 'Extending the suite'."
    exit 1
fi
echo "interop doc lint ok: every lab under tests/interop/ is documented in $DOC"
