#!/usr/bin/env python3
"""Audit which C ABI (lr_*) entry points are covered by each binding.

Surfaces:
- C ABI:        include/lr_ffi.h           (every `lr_*` symbol name)
- C++ wrapper:  include/librouting.hpp     (every `lr_*` symbol name)
- Python cdef:  bindings/lr-python/src/librouting/_ffi.py
- Go cgo:       bindings/lr-go/librouting.go
- Rust pub API: crates/lr-ffi/src/*.rs     (extern "C" fn names — same as C ABI)

Goal: surface the *missing* symbols in each binding layer.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
C_ABI = ROOT / "include" / "lr_ffi.h"
CPP = ROOT / "include" / "librouting.hpp"
PY_FFI = ROOT / "bindings" / "lr-python" / "src" / "librouting" / "_ffi.py"
GO = ROOT / "bindings" / "lr-go" / "librouting.go"


# Match function-name tokens that begin with `lr_`. We capture
# `lr_xxx_yyy_zzz` even if the return type is split across lines.
LR_SYM = re.compile(r"\blr_([A-Za-z0-9_]+)\b")

# Match a C-style function declaration like
#   `lr_xxx_t lr_xxx_yyy(args);`
# or  `void lr_xxx_yyy(args);`
# ignoring return-type tokens (which may be `lr_xxx_t` themselves).
# We anchor on a `(` immediately following the captured identifier.
DECL_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_ *]*\blr_([A-Za-z0-9_]+)\s*\(",
    re.MULTILINE,
)


def collect_c_abi() -> set[str]:
    """Return the set of `lr_*` function names declared in lr_ffi.h."""
    text = C_ABI.read_text(encoding="utf-8")
    decls = set()
    for m in DECL_RE.finditer(text):
        decls.add("lr_" + m.group(1))
    return decls


def _collect_decl_or_call(path: Path) -> set[str]:
    """Collect every `lr_*` token used as a *call* or *declaration* in
    `path`. We take the union of (a) declarations (`... lr_xxx(`) and
    (b) calls (`lr_xxx(`) — the same surface, but exclude bare type
    references (`lr_xxx_t var;`) and bare struct-member references."""
    if not path.exists():
        return set()
    text = path.read_text(encoding="utf-8")
    out: set[str] = set()
    # Both declarations and calls end with `(`.
    for m in re.finditer(r"\blr_([A-Za-z0-9_]+)\s*\(", text):
        out.add("lr_" + m.group(1))
    return out


def collect_cpp() -> set[str]:
    return _collect_decl_or_call(CPP)


def collect_python() -> set[str]:
    return _collect_decl_or_call(PY_FFI)


def collect_go() -> set[str]:
    return _collect_decl_or_call(GO)


def categorise(syms: set[str]) -> dict[str, list[str]]:
    """Group symbols by their 'subject' (the part after `lr_` and before
    the next `_` cluster that identifies the crate/object)."""
    out: dict[str, list[str]] = {}
    for s in sorted(syms):
        # subject heuristic: lr_<subject>_<verb>; subject is the first
        # identifier chunk following `lr_` plus optionally a sub-chunk
        # (e.g. `lr_bgp_peer_new` -> subject `bgp_peer`).
        rest = s.removeprefix("lr_")
        parts = rest.split("_")
        if len(parts) >= 2 and parts[0] in {
            "bgp", "babel", "bfd", "ospf", "ldp", "bmp", "mpls", "mrt",
            "srv6", "policy", "rib", "osroute", "router", "damping",
            "core", "filter", "route", "attributes", "session",
            "event", "best", "ip", "nlri", "prefix", "as", "ext",
            "large", "community", "max",
        }:
            subject = "_".join(parts[:2])
        else:
            subject = parts[0]
        out.setdefault(subject, []).append(s)
    return out


def main() -> int:
    c_abi = collect_c_abi()
    cpp = collect_cpp()
    py = collect_python()
    go = collect_go()

    print(f"C ABI declares:      {len(c_abi):>5}")
    print(f"C++ wrapper covers:  {len(cpp & c_abi):>5}  (extra: {len(cpp - c_abi)})")
    print(f"Python cdef covers:  {len(py & c_abi):>5}  (extra: {len(py - c_abi)})")
    print(f"Go cgo covers:        {len(go & c_abi):>5}  (extra: {len(go - c_abi)})")
    print()

    for name, layer in (("C++", cpp), ("Python", py), ("Go", go)):
        missing = c_abi - layer
        print(f"=== {name} missing ({len(missing)} of {len(c_abi)}) ===")
        by_subj = categorise(missing)
        for subj in sorted(by_subj, key=lambda s: -len(by_subj[s])):
            print(f"  {subj:<14} ({len(by_subj[subj]):>3}): {', '.join(by_subj[subj][:8])}"
                  + (f"  +{len(by_subj[subj]) - 8} more" if len(by_subj[subj]) > 8 else ""))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
