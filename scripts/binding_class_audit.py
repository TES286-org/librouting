#!/usr/bin/env python3
"""Audit which C ABI methods are NOT covered by the hand-written
binding classes for each opaque handle.

For each opaque handle ``lr_X_t`` in the C ABI:
- Python: look for a hand-written class named ``X`` (CamelCase) in any
  module under ``bindings/lr-python/src/librouting/`` (excluding
  ``generated.py``); for each C ABI method ``lr_X_<verb>``, check if
  the class defines a method named ``<verb>`` (snake_case preserved).
- Go: look for a Go type named ``X`` (CamelCase) in any .go file
  (excluding ``generated.go``); for each C ABI method, check if the
  type has a method named ``<Verb>`` (CamelCase).
- C++: look for a class in ``include/librouting.hpp`` outside the
  ``namespace gen`` block.

The script reports, for each binding, the list of (handle, method)
pairs that are NOT covered by a hand-written class. The generated
thin wrappers are intentionally excluded — they always cover the C
ABI surface; the audit is about the *idiomatic* layer.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ABI = ROOT / "scripts" / "abi.json"
PY_DIR = ROOT / "bindings" / "lr-python" / "src" / "librouting"
GO_DIR = ROOT / "bindings" / "lr-go"
CPP = ROOT / "include" / "librouting.hpp"


def to_camel(handle: str) -> str:
    """lr_route_t -> Route, lr_bgp_path_attrs_t -> BgpPathAttrs."""
    base = handle
    if base.startswith("lr_"):
        base = base[3:]
    if base.endswith("_t"):
        base = base[:-2]
    elif base.endswith("_handle"):
        base = base[: -len("_handle")]
    parts = base.split("_")
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def method_verb(fn_name: str, handle: str) -> str:
    """``lr_route_set_med`` -> ``set_med`` (strip handle prefix)."""
    stem = handle
    if stem.startswith("lr_"):
        stem = stem[3:]
    if stem.endswith("_t"):
        stem = stem[:-2]
    elif stem.endswith("_handle"):
        stem = stem[: -len("_handle")]
    prefix = "lr_" + stem + "_"
    if fn_name.startswith(prefix):
        return fn_name[len(prefix):]
    return fn_name[3:]  # strip lr_


def collect_python_methods() -> dict[str, set[str]]:
    """Return {class_name: {method_names}} for every hand-written
    Python class (excluding generated.py)."""
    out: dict[str, set[str]] = {}
    for path in sorted(PY_DIR.glob("*.py")):
        if path.name == "generated.py":
            continue
        text = path.read_text(encoding="utf-8")
        # Find class definitions
        for cls_m in re.finditer(r"^class\s+(\w+)\b", text, re.MULTILINE):
            cls = cls_m.group(1)
            # Find methods within this class (between this class and the
            # next class definition or end of file)
            start = cls_m.end()
            nxt = re.search(r"^class\s+\w+\b", text[start:], re.MULTILINE)
            end = start + nxt.start() if nxt else len(text)
            body = text[start:end]
            methods: set[str] = set()
            for m in re.finditer(r"^\s+def\s+(\w+)\b", body, re.MULTILINE):
                methods.add(m.group(1))
            # Also expose the cdef-style direct calls
            for m in re.finditer(r"\blr_\w+\b\s*\(", body):
                pass
            out.setdefault(cls, set()).update(methods)
    return out


def collect_go_methods() -> dict[str, set[str]]:
    """Return {type_name: {method_names}} for every hand-written Go
    type (excluding generated.go)."""
    out: dict[str, set[str]] = {}
    for path in sorted(GO_DIR.glob("*.go")):
        if path.name == "generated.go":
            continue
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8")
        # Find type definitions: `type X struct {` or `type X SomeType`
        for tm in re.finditer(r"^type\s+(\w+)\b", text, re.MULTILINE):
            tname = tm.group(1)
            # Find receiver methods: `func (r *X) Method(...)` or `func (r X) Method(...)`
            methods: set[str] = set()
            pat = re.compile(r"^func\s+\([^)]*\*?\s*" + re.escape(tname) + r"\s*\)\s+(\w+)\b", re.MULTILINE)
            for m in pat.finditer(text):
                methods.add(m.group(1))
            out.setdefault(tname, set()).update(methods)
    return out


def collect_cpp_methods() -> dict[str, set[str]]:
    """Return {class_name: {method_names}} for every hand-written C++
    class (outside the `namespace gen` block)."""
    out: dict[str, set[str]] = {}
    text = CPP.read_text(encoding="utf-8")
    # Strip the namespace gen block
    gen_match = re.search(r"namespace\s+gen\s*\{.*?\n\}\s*//\s*namespace\s+gen", text, re.DOTALL)
    hand_text = text
    if gen_match:
        hand_text = text[: gen_match.start()] + text[gen_match.end():]
    # Find class definitions: `class X {` or `class X : ... {`
    for cls_m in re.finditer(r"^class\s+(\w+)\b", hand_text, re.MULTILINE):
        cls = cls_m.group(1)
        start = cls_m.end()
        # Find the next class or end of file
        nxt = re.search(r"^class\s+\w+\b|^\}\s*;\s*$", hand_text[start:], re.MULTILINE)
        end = start + nxt.start() if nxt else len(hand_text)
        body = hand_text[start:end]
        methods: set[str] = set()
        # Method declarations: `ret-type Method(...)`
        # Simplified: any identifier followed by ( that's not a type
        for m in re.finditer(r"^\s+(?:inline\s+)?[A-Za-z_][\w\s\*&:<>]*?\b(\w+)\s*\(", body, re.MULTILINE):
            methods.add(m.group(1))
        out.setdefault(cls, set()).update(methods)
    return out


def main() -> int:
    abi = json.loads(ABI.read_text(encoding="utf-8"))
    py_methods = collect_python_methods()
    go_methods = collect_go_methods()
    cpp_methods = collect_cpp_methods()

    print(f"Python classes: {len(py_methods)}")
    print(f"Go types:       {len(go_methods)}")
    print(f"C++ classes:    {len(cpp_methods)}")
    print()

    # For each opaque handle, list methods NOT covered by hand-written class
    for label, methods_map in (("Python", py_methods), ("Go", go_methods), ("C++", cpp_methods)):
        print(f"=== {label} binding — methods on opaque handles NOT covered by hand-written class ===")
        total_missing = 0
        for handle in sorted(abi["opaque_types"]):
            cls = to_camel(handle)
            fns = abi["by_handle"].get(handle, [])
            # Skip free / array_free / vec_free
            real_fns = [f for f in fns
                        if not f["name"].endswith("_free")
                        and not f["name"].endswith("_array_free")
                        and not f["name"].endswith("_vec_free")]
            hand_methods = methods_map.get(cls, set())
            missing = []
            for f in real_fns:
                verb = method_verb(f["name"], handle)
                if verb in ("new", "try_new"):
                    continue  # constructor
                # Map snake_case verb to CamelCase for Go
                camel_verb = "".join(p[:1].upper() + p[1:] for p in verb.split("_") if p)
                if label == "Go":
                    if camel_verb in hand_methods or verb in hand_methods:
                        continue
                else:
                    if verb in hand_methods or camel_verb in hand_methods:
                        continue
                missing.append(verb)
            if missing:
                print(f"  {cls:<28} ({len(missing):>3}): {', '.join(missing[:8])}"
                      + (f"  +{len(missing) - 8} more" if len(missing) > 8 else ""))
                total_missing += len(missing)
        print(f"  Total missing for {label}: {total_missing}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
