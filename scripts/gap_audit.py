#!/usr/bin/env python3
"""Audit C ABI coverage vs Rust pub API.

For each protocol crate (lr-bgp, lr-ospf, lr-babel, lr-ldp, lr-bfd, lr-bmp,
lr-mpls, lr-mrt, lr-srv6, lr-policy, lr-rib, lr-osroute, lr-router,
lr-damping, lr-core), collect the set of `pub fn` names defined in
`crates/<crate>/src/**/*.rs` (excluding `_tests.rs` / `tests/` files),
then check what fraction is mirrored by an `lr_*` C ABI entry point in
`crates/lr-ffi/src/**/*.rs`.

A pub fn name maps loosely to an `lr_<crate_short>_<fn_name_snake>` ABI
name; we count coverage by substring match (the FFI often wraps with
context prefixes). The goal is to surface crates with large remaining
gaps, not to be exact."""

from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES_DIR = ROOT / "crates"
FFI_DIR = CRATES_DIR / "lr-ffi" / "src"

PROTOCOL_CRATES = [
    "lr-bgp",
    "lr-ospf",
    "lr-babel",
    "lr-ldp",
    "lr-bfd",
    "lr-bmp",
    "lr-mpls",
    "lr-mrt",
    "lr-srv6",
    "lr-policy",
    "lr-rib",
    "lr-osroute",
    "lr-router",
    "lr-damping",
    "lr-core",
]

PUB_UNSAFE_FN_RE = re.compile(
    r"^\s*pub\s+(?:unsafe\s+)?(?:async\s+)?fn\s+([a-zA-Z0-9_]+)\b", re.MULTILINE
)
EXTERN_FN_RE = re.compile(r'\bextern\s+"C"\s+fn\s+([a-zA-Z0-9_]+)\b', re.MULTILINE)


def collect_pub_fns(crate_dir: Path) -> set[str]:
    """Collect non-test pub fn names from `crates/<crate>/src/`."""
    out: set[str] = set()
    if not crate_dir.exists():
        return out
    for path in sorted(crate_dir.rglob("*.rs")):
        # Skip test files.
        rel = path.relative_to(crate_dir)
        if any(p == "tests" for p in rel.parts):
            continue
        if rel.name.endswith("_tests.rs") or rel.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8")
        for m in PUB_UNSAFE_FN_RE.finditer(text):
            name = m.group(1)
            if name.startswith("test_"):
                continue
            out.add(name)
    return out


def collect_ffi_symbols() -> set[str]:
    """Collect all `extern "C" fn` names from `crates/lr-ffi/src/`."""
    out: set[str] = set()
    for path in sorted(FFI_DIR.rglob("*.rs")):
        rel = path.relative_to(FFI_DIR)
        if rel.name.endswith("_tests.rs") or rel.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8")
        for m in EXTERN_FN_RE.finditer(text):
            out.add(m.group(1))
    return out


def crate_short(name: str) -> str:
    return name.removeprefix("lr-").replace("-", "_")


def main() -> int:
    ffi_syms = collect_ffi_symbols()
    print(f"Total C ABI extern \"C\" fns: {len(ffi_syms)}")
    print()
    rows = []
    for crate in PROTOCOL_CRATES:
        pub_fns = collect_pub_fns(CRATES_DIR / crate / "src")
        if not pub_fns:
            continue
        short = crate_short(crate)
        covered = 0
        missing = []
        for fn in sorted(pub_fns):
            needle = fn.lower()
            # Permissive: any FFI symbol whose tail segment matches.
            hit = any(
                (f"lr_{short}_" in sym and sym.endswith(f"_{needle}"))
                or sym == f"lr_{short}_{needle}"
                or sym == f"lr_{needle}"
                or (f"lr_{short}_" in sym and needle in sym.split("lr_" + short + "_")[-1])
                for sym in ffi_syms
            )
            if hit:
                covered += 1
            else:
                missing.append(fn)
        total = len(pub_fns)
        pct = (covered / total * 100.0) if total else 100.0
        rows.append((crate, total, covered, pct, missing))
    rows.sort(key=lambda r: r[3])
    print(f"{'crate':<14} {'pub':>6} {'covered':>8} {'%':>6}  missing (top 20)")
    for crate, total, covered, pct, missing in rows:
        head = ", ".join(missing[:20]) if missing else ""
        more = f" (+{len(missing) - 20} more)" if len(missing) > 20 else ""
        print(f"{crate:<14} {total:>6} {covered:>8} {pct:>5.1f}%  {head}{more}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
