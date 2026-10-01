#!/usr/bin/env bash
# Guard: the documentation set must stay readable and honest.
#
# docs/STYLE.md is the contract this script enforces mechanically:
#
#   1. prose is wrapped at 80 columns (fenced code and tables are exempt,
#      and so is a line whose overflow is a single unbreakable token)
#   2. no tab characters
#   3. no trailing whitespace
#   4. every relative Markdown link resolves to a file that exists
#   5. no hard-coded release stamp in prose — point at Cargo.toml instead
#   6. exactly one level-1 heading per file
#
# Dependencies: bash, awk, grep, sed, sort. A bare GitHub-hosted runner
# has all of them; deliberately no ripgrep (same constraint as
# tests/lint_interop_doc.sh).
#
# Usage: tests/lint_docs.sh   (from the repository root)

set -euo pipefail
cd "$(dirname "$0")/.."

# C collation keeps awk byte-oriented, which is what the UTF-8 column
# count below relies on.
export LC_ALL=C

MAX_COLUMNS=80

# Rule 5 does not apply here: these documents exist to talk about
# versions and releases, so a version string in them is the subject,
# not a stale copy of the workspace version.
VERSION_ALLOWLIST=" CHANGELOG.md docs/RELEASE-PLAN.md "

fail=0

mapfile -t FILES < <(git ls-files '*.md')
# A file deleted in the working tree but not yet staged is still in the
# index. Checking it would fail on a missing file rather than on its
# contents, so skip it; `git status` is where that state belongs.
PRESENT=()
for f in "${FILES[@]}"; do
    [ -f "$f" ] && PRESENT+=("$f")
done
FILES=("${PRESENT[@]}")
if [ "${#FILES[@]}" -eq 0 ]; then
    echo "no tracked Markdown files found" >&2
    exit 1
fi

# --- rules 1-3: layout -------------------------------------------------
# Continuation bytes (0x80-0xBF) are stripped before the column count so
# a multi-byte character counts as the one column a reader sees.
check_layout() {
    local f
    for f in "${FILES[@]}"; do
        awk -v file="$f" -v max="$MAX_COLUMNS" '
            BEGIN { fence = 0; h1 = 0 }
            /^[[:space:]]*(```|~~~)/ { fence = !fence; next }
            fence { next }
            /^# / { h1++ }
            /^[[:space:]]*\|/ { next }
            /^[[:space:]]*[+][-=]/ { next }
            # An indented code block cannot be wrapped either. A nested
            # list item is indented the same way but starts with a
            # marker, so it is still checked.
            /^    / && !/^[[:space:]]*([-*+]|[0-9]+[.)])[[:space:]]/ { next }
            {
                if ($0 ~ /[ \t]+$/) {
                    printf "%s:%d: trailing whitespace\n", file, FNR
                }
                if (index($0, "\t") > 0) {
                    printf "%s:%d: tab character\n", file, FNR
                }
                line = $0
                gsub(/[\200-\277]/, "", line)
                if (length(line) > max) {
                    # A line whose overflow contains no space cannot be
                    # wrapped without breaking a token (a long URL, a
                    # deeply nested path); wrapping is not the fix there.
                    if (substr(line, max + 1) ~ / /) {
                        printf "%s:%d: prose line is %d columns, the limit is %d\n", \
                            file, FNR, length(line), max
                    }
                }
            }
            END {
                if (h1 != 1) {
                    printf "%s: %d level-1 headings, expected exactly 1\n", file, h1
                }
            }
        ' "$f"
    done
}

# --- rule 4: links -----------------------------------------------------
# Resolution happens with cd into the linking file's directory, so `..`
# and nested directories need no path algebra.
check_links() {
    local f dir target
    for f in "${FILES[@]}"; do
        dir=$(dirname "$f")
        while IFS= read -r target; do
            [ -n "$target" ] || continue
            case "$target" in
                http://* | https://* | mailto:* | '#'*) continue ;;
            esac
            target=${target%%#*}
            [ -n "$target" ] || continue
            if ! (cd "$dir" && [ -e "$target" ]); then
                printf "%s: dead link -> %s\n" "$f" "$target"
            fi
        done < <(grep -oE '\]\([^()[:space:]]+\)' "$f" | sed -e 's/^](//' -e 's/)$//' | sort -u)
    done
}

# --- rule 5: release stamps -------------------------------------------
# Two shapes are stamped into prose and go stale the moment the next tag
# lands: a pre-release stamp (`-rc.5`) and the literal current workspace
# version. Everything else that looks version-like in these documents is
# a legitimate literal — an IP address, an OSPF area, an RFC section.
#
# `§9.1.2` is stripped first: section citations are not versions, and
# not every document writes them with a section sign.
check_version_stamps() {
    local f ver ver_re
    ver=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
    [ -n "$ver" ] || {
        echo "cannot read [workspace.package] version from Cargo.toml" >&2
        exit 1
    }
    ver_re=$(printf '%s' "$ver" | sed 's/\./[.]/g')

    for f in "${FILES[@]}"; do
        case "$VERSION_ALLOWLIST" in
            *" $f "*) continue ;;
        esac
        awk -v file="$f" -v ver_re="$ver_re" '
            function boundary(text, at, len,   pre, post) {
                pre = (at > 1) ? substr(text, at - 1, 1) : ""
                post = substr(text, at + len, 1)
                return (pre !~ /[0-9.]/) && (post !~ /[0-9.]/)
            }
            {
                line = $0
                gsub(/§[A-Za-z0-9.]+/, "", line)
                if (match(line, /-rc\.[0-9]+/)) {
                    printf "%s:%d: pre-release stamp \"%s\" — point at Cargo.toml instead\n", \
                        file, FNR, substr(line, RSTART, RLENGTH)
                }
                rest = line
                while (match(rest, ver_re)) {
                    if (boundary(rest, RSTART, RLENGTH)) {
                        printf "%s:%d: workspace version \"%s\" — point at Cargo.toml instead\n", \
                            file, FNR, substr(rest, RSTART, RLENGTH)
                        break
                    }
                    rest = substr(rest, RSTART + RLENGTH)
                }
            }
        ' "$f"
    done
}

run_rule() {
    local out
    out=$("$1")
    if [ -n "$out" ]; then
        printf '%s\n' "$out"
        fail=1
    fi
}

run_rule check_layout
run_rule check_links
run_rule check_version_stamps

if [ "$fail" -ne 0 ]; then
    echo
    echo "The documentation set violates docs/STYLE.md (reasons above)."
    exit 1
fi

echo "docs lint ok: ${#FILES[@]} Markdown files are wrapped, link-clean and stamp-free"
