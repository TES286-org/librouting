#!/usr/bin/env python3
"""Generate idiomatic Go wrapper additions for hand-written Go types that
are missing C ABI methods.

For each opaque handle in the C ABI, find the corresponding hand-written
Go type and identify C ABI methods that are NOT exposed either as a
method OR called inside another method's body. Emit idiomatic Go
wrappers in a new file ``bindings/lr-go/extras.go``.

The generator is conservative — methods with callback parameters, opaque
output arrays, or value-struct returns are skipped (a human can hand-write
them).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ABI = ROOT / "scripts" / "abi.json"
GO_DIR = ROOT / "bindings" / "lr-go"
GO_EXTRAS = GO_DIR / "extras.go"


def to_camel(handle: str) -> str:
    base = handle
    if base.startswith("lr_"):
        base = base[3:]
    if base.endswith("_t"):
        base = base[:-2]
    elif base.endswith("_handle"):
        base = base[: -len("_handle")]
    parts = base.split("_")
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def to_camel_lower(s: str) -> str:
    """Convert snake_case to camelCase."""
    parts = s.split("_")
    if not parts:
        return s
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:] if p)


def method_verb(fn_name: str, handle: str) -> str:
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
    return fn_name[3:]


def go_param_name(p: dict, idx: int) -> str:
    name = p.get("name") or f"a{idx}"
    # Go keywords / built-ins
    if name in ("type", "func", "map", "chan", "interface", "struct",
                "range", "import", "package", "var", "const", "go",
                "select", "case", "default", "switch", "defer", "fallthrough",
                "break", "continue", "return", "if", "else", "for",
                "len", "cap", "new", "make", "delete", "copy", "append"):
        name = name + "_"
    return name


def collect_go_classes() -> dict[str, tuple[set[str], set[str]]]:
    """Return {type_name: (methods_set, c_symbols_used_set)}.

    Scans every non-test .go file EXCEPT generated.go and extras.go for
    hand-written types and their methods. Go allows methods to be in
    any file of the same package, so we scan ALL files for methods on
    each type, not just the file where the type is defined.

    For the auto-gen layer (generated.go) we ALSO scan it to know which
    methods are already declared there (so we don't emit a duplicate in
    extras.go).
    """
    out: dict[str, tuple[set[str], set[str]]] = {}
    # First, scan generated.go to collect every method already declared
    # there (so we don't duplicate them in extras.go).
    generated_methods: set[tuple[str, str]] = set()
    gen_path = GO_DIR / "generated.go"
    if gen_path.exists():
        text = gen_path.read_text(encoding="utf-8")
        for m in re.finditer(r"^func\s+\((\w+)\s+\*?(\w+)\)\s+(\w+)\b", text, re.MULTILINE):
            generated_methods.add((m.group(2), m.group(3)))

    # Collect every hand-written type name and its struct fields
    type_names: set[str] = set()
    type_fields: dict[str, set[str]] = {}
    for path in sorted(GO_DIR.glob("*.go")):
        if path.name in ("generated.go", "extras.go"):
            continue
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8")
        for tm in re.finditer(r"^type\s+(\w+)\s+struct\s*\{([^}]*)\}", text, re.MULTILINE | re.DOTALL):
            tname = tm.group(1)
            type_names.add(tname)
            fields = set(re.findall(r"^\s*(\w+)\s+", tm.group(2), re.MULTILINE))
            type_fields[tname] = fields
        # Also handle type aliases / non-struct types
        for tm in re.finditer(r"^type\s+(\w+)\s+(?!struct\b)", text, re.MULTILINE):
            tname = tm.group(1)
            type_names.add(tname)
            type_fields.setdefault(tname, set())

    # Only treat a type as a handle wrapper if it has a `ptr` field
    # (the convention used by every hand-written handle wrapper in this
    # package). Plain value-struct types like BabelRoute (with public
    # fields Key/Seqno/Metric/...) are NOT handle wrappers and should
    # not get extra methods that call `r.ptr`.
    handle_types: set[str] = {t for t in type_names if "ptr" in type_fields.get(t, set())}

    # For each type, scan every hand-written .go file for methods on it
    for tname in sorted(type_names):
        if tname not in handle_types:
            continue  # not a handle wrapper — skip
        methods: set[str] = set()
        syms: set[str] = set()
        pat = re.compile(r"^func\s+\((\w+)\s+\*?" + re.escape(tname) + r"\)\s+(\w+)\b", re.MULTILINE)
        for path in sorted(GO_DIR.glob("*.go")):
            if path.name in ("generated.go", "extras.go"):
                continue
            if path.name.endswith("_test.go"):
                continue
            text = path.read_text(encoding="utf-8")
            for m in pat.finditer(text):
                methods.add(m.group(2))
                start = m.end()
                nxt = re.search(r"^\}", text[start:], re.MULTILINE)
                end = start + nxt.start() if nxt else len(text)
                body = text[start:end]
                syms.update(re.findall(r"\blr_(\w+)\b", body))
        # Also include methods declared in generated.go for this type
        for (gt, gm) in generated_methods:
            if gt == tname:
                methods.add(gm)
        out[tname] = (methods, syms)
    return out


def classify_param(p: dict) -> str:
    if "raw" in p:
        return "skip"
    ptype = p.get("type", "").strip()
    if "const char *" in ptype or ptype.startswith("const char *"):
        return "string"
    if "char" in ptype and "*" in ptype:
        return "skip"
    if ptype.endswith("*"):
        base = ptype[:-1].strip()
        if base in ("uint8_t", "uint16_t", "uint32_t", "uint64_t",
                    "int8_t", "int16_t", "int32_t", "int64_t",
                    "bool", "size_t", "uintptr_t"):
            return "out_prim"
        return "skip"
    if ptype in ("uint8_t", "uint16_t", "uint32_t", "uint64_t",
                 "int8_t", "int16_t", "int32_t", "int64_t",
                 "bool", "size_t", "uintptr_t"):
        return "prim"
    if ptype.startswith("struct "):
        return "value_struct"
    if ptype.endswith("_t"):
        return "handle"
    return "skip"


def classify_return(ret: str) -> str:
    ret = ret.strip()
    if ret == "void":
        return "void"
    if ret in ("int32_t", "int64_t", "int16_t", "int8_t"):
        return "rc_int"
    if ret in ("uint8_t", "uint16_t", "uint32_t", "uint64_t", "size_t", "uintptr_t"):
        return "rc_uint"
    if ret == "bool":
        return "bool"
    if ret == "char *" or ret.startswith("const char *"):
        return "string"
    if ret.endswith("_t") and not ret.startswith("struct "):
        return "handle"
    if ret.startswith("struct "):
        return "value_struct"
    if ret.endswith("*"):
        return "unknown"
    return "unknown"


def go_c_type(t: str) -> str:
    """Map an lr_ffi.h C type to a cgo C type."""
    return "C." + t.strip()


def render_go_method(type_name: str, handle: str, fn: dict) -> str | None:
    name = fn["name"]
    verb = method_verb(name, handle)
    if verb in ("new", "try_new", "destroy", "free", "array_free", "vec_free"):
        return None
    if verb.startswith("array_") or verb.startswith("vec_"):
        return None

    params = fn["params"]
    if not params or "raw" in params[0]:
        return None
    if params[0].get("type", "") != handle:
        return None

    ret_kind = classify_return(fn["return_type"])
    if ret_kind in ("value_struct", "handle", "unknown"):
        return None

    # Skip methods that likely return multi-byte arrays via uint8_t*
    UNSAFE_OUT_NAME_HINTS = ("addr", "address", "router_id", "routerid",
                              "mac", "next_hop", "nexthop", "speaker",
                              "cluster_id", "originator", "sa_id",
                              "bytes", "digest", "secret", "key")
    if any(h in name for h in UNSAFE_OUT_NAME_HINTS):
        return None

    # Detect array-output patterns (out pointer + cap)
    for i, p in enumerate(params):
        if i == 0:
            continue
        kind = classify_param(p)
        if kind == "out_prim":
            if i + 1 < len(params):
                next_p = params[i + 1]
                next_ptype = next_p.get("type", "").strip()
                next_pname = (next_p.get("name") or "").lower()
                if not next_ptype.endswith("*") and any(h == next_pname or h in next_pname
                                                       for h in ("cap", "count", "len", "max")):
                    return None

    # Build Go method
    go_params: list[str] = []
    call_args: list[str] = ["r.ptr"]
    body_pre: list[str] = []
    out_vars: list[tuple[str, str]] = []  # (name, ctype)

    for i, p in enumerate(params[1:], start=1):
        kind = classify_param(p)
        pname = go_param_name(p, i)
        ptype = p.get("type", "").strip()
        if kind == "skip":
            return None
        elif kind == "prim":
            go_params.append(f"{pname} {go_c_type(ptype)}")
            if ptype == "bool":
                call_args.append(f"C.uint8_t(0)")
                # actually, the caller will pass a C.uint8_t directly
                # since we declared the param as C.uint8_t; no conversion
                call_args[-1] = pname
            else:
                call_args.append(pname)
        elif kind == "out_prim":
            base = ptype[:-1].strip()
            local = f"out{i}"
            out_vars.append((local, base))
            body_pre.append(f"\tvar {local} C.{base}")
            call_args.append(f"&{local}")
        elif kind == "string":
            # const char * - Go string param
            go_params.append(f"{pname} string")
            body_pre.append(f"\t_c{i} := C.CString({pname})")
            body_pre.append(f"\tdefer C.free(unsafe.Pointer(_c{i}))")
            call_args.append(f"_c{i}")
        elif kind == "handle":
            return None
        elif kind == "value_struct":
            return None
        else:
            return None

    # Render body
    body: list[str] = []
    body.extend(body_pre)
    method_name = "".join(p[:1].upper() + p[1:] for p in verb.split("_") if p)

    # Receiver
    recv = "r"
    sig_params = ", ".join(go_params) if go_params else ""
    sig = f"func ({recv} *{type_name}) {method_name}({sig_params})"

    # Determine return type
    ret = fn["return_type"].strip()
    if ret_kind == "void":
        if out_vars:
            ret_types = ", ".join(f"C.{v[1]}" for v in out_vars)
            sig += f" ({ret_types}, error)"
        else:
            sig += " error"
        body.append(f"\trc := C.{name}({', '.join(call_args)})")
        body.append(f"\tif rc != 0 {{")
        body.append(f"\t\treturn " + (", ".join(f"0" for _ in out_vars) + (", " if out_vars else "") + f"fmt.Errorf(\"{name}: %s (rc=%d)\", LastError(), int(rc))"))
        body.append(f"\t}}")
        if out_vars:
            ret_vals = ", ".join(f"{v[0]}" for v in out_vars)
            body.append(f"\treturn {ret_vals}, nil")
        else:
            body.append(f"\treturn nil")
    elif ret_kind == "rc_int":
        if out_vars:
            ret_types = ", ".join(f"C.{v[1]}" for v in out_vars)
            sig += f" ({ret_types}, error)"
        else:
            sig += " (int32, error)"
        body.append(f"\trc := C.{name}({', '.join(call_args)})")
        body.append(f"\tif rc < 0 {{")
        body.append(f"\t\treturn " + (", ".join(f"0" for _ in out_vars) + (", " if out_vars else "") + f"fmt.Errorf(\"{name}: %s (rc=%d)\", LastError(), int(rc))"))
        body.append(f"\t}}")
        if out_vars:
            ret_vals = ", ".join(f"{v[0]}" for v in out_vars)
            body.append(f"\treturn {ret_vals}, nil")
        else:
            body.append(f"\treturn int32(rc), nil")
    elif ret_kind == "rc_uint":
        if out_vars:
            ret_types = ", ".join(f"C.{v[1]}" for v in out_vars)
            sig += f" ({ret_types}, error)"
        else:
            sig += " (uint64, error)"
        body = []
        body.extend(body_pre)
        body.append(f"\trc := C.{name}({', '.join(call_args)})")
        if out_vars:
            ret_vals = ", ".join(f"{v[0]}" for v in out_vars)
            body.append(f"\treturn {ret_vals}, uint64(rc), nil")
        else:
            body.append(f"\treturn uint64(rc), nil")
    elif ret_kind == "bool":
        sig += " (bool, error)"
        body.append(f"\trc := C.{name}({', '.join(call_args)})")
        body.append(f"\tif rc < 0 {{")
        body.append(f"\t\treturn false, fmt.Errorf(\"{name}: %s (rc=%d)\", LastError(), int(rc))")
        body.append(f"\t}}")
        body.append(f"\treturn rc != 0, nil")
    elif ret_kind == "string":
        sig += " (string, error)"
        body.append(f"\tp := C.{name}({', '.join(call_args)})")
        body.append(f"\tif p == nil {{")
        body.append(f"\t\treturn \"\", nil")
        body.append(f"\t}}")
        body.append(f"\treturn C.GoString(p), nil")
    else:
        return None

    # Doc comment
    doc = f"// {method_name} is an auto-generated wrapper for ``{name}``.\n"
    return doc + sig + " {\n" + "\n".join(body) + "\n}"


def main() -> int:
    abi = json.loads(ABI.read_text(encoding="utf-8"))
    go_classes = collect_go_classes()

    header = """// Code generated by scripts/gen_methods_extras_go.py — DO NOT EDIT MANUALLY.
// Re-run: python3 scripts/gen_methods_extras_go.py

package librouting

/*
#include <stdlib.h>
#include "lr_ffi.h"
*/
import "C"

// This file patches the hand-written Go types with idiomatic wrappers
// for C ABI methods not exposed by the hand-written layer. Methods with
// callback parameters, opaque output arrays, or value-struct returns
// are intentionally skipped — a human can hand-write them.
"""

    methods_by_type: dict[str, list[str]] = {}
    n_classes = 0
    n_methods = 0
    n_skipped = 0

    for handle in sorted(abi["opaque_types"]):
        type_name = to_camel(handle)
        if type_name not in go_classes:
            continue
        methods_defined, syms_used = go_classes[type_name]

        emitted: list[str] = []
        for fn in abi["by_handle"].get(handle, []):
            verb = method_verb(fn["name"], handle)
            method_name = "".join(p[:1].upper() + p[1:] for p in verb.split("_") if p)
            if method_name in methods_defined:
                continue
            if fn["name"][3:] in syms_used:
                continue
            src = render_go_method(type_name, handle, fn)
            if src is None:
                n_skipped += 1
                continue
            emitted.append(src)
            n_methods += 1
        if not emitted:
            continue
        methods_by_type[type_name] = emitted
        n_classes += 1

    # Detect if any emitted method uses fmt or unsafe
    all_src = "\n".join("\n".join(v) for v in methods_by_type.values())
    needs_fmt = "fmt." in all_src
    needs_unsafe = "unsafe." in all_src

    import_lines = ['import (']
    if needs_fmt:
        import_lines.append('\t"fmt"')
    if needs_unsafe:
        import_lines.append('\t"unsafe"')
    import_lines.append(')')

    header_with_imports = header
    if needs_fmt or needs_unsafe:
        header_with_imports = header + "\n" + "\n".join(import_lines) + "\n"

    out_lines = [header_with_imports.rstrip()]
    out_lines.append("")
    for type_name in sorted(methods_by_type):
        out_lines.append(f"// ---- {type_name} ----")
        out_lines.append("")
        for src in methods_by_type[type_name]:
            out_lines.append(src)
            out_lines.append("")

    content = "\n".join(out_lines) + "\n"
    GO_EXTRAS.write_text(content, encoding="utf-8")
    print(f"Go extras:")
    print(f"  classes patched: {n_classes}")
    print(f"  methods emitted:  {n_methods}")
    print(f"  methods skipped:  {n_skipped}")
    print(f"  wrote {GO_EXTRAS} ({len(content)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
