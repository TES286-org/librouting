#!/usr/bin/env python3
"""Generate Go binding additions for the missing C ABI surface.

Reads ``scripts/abi.json`` and writes a single ``bindings/lr-go/generated.go``
file with thin Go wrappers around every missing ``lr_*`` entry point.

For each opaque handle ``lr_X_t``:
  - emits a Go struct ``type X struct { ptr C.lr_X_t }``;
  - emits a ``NewX(...)`` factory function for the corresponding
    ``lr_X_new`` constructor (when present);
  - emits a ``Free()`` / ``destroy()`` pair for the handle's free
    function;
  - emits one Go method per ``lr_X_<verb>`` function.

For each free function ``lr_Y_Z(...)`` not bound to an opaque handle:
  - emits a Go function ``Y_Z(...)`` that calls the C ABI directly.

The generated file is a drop-in addition to the existing
``bindings/lr-go/*.go`` modules — the existing hand-written wrappers
remain authoritative.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ABI = ROOT / "scripts" / "abi.json"
GO_DIR = ROOT / "bindings" / "lr-go"
OUT = GO_DIR / "generated.go"

# Symbols that are only exported by `liblr_ffi.so` when the
# `exchange-plane` cargo feature is enabled (issue #92 / LRXP). The
# C ABI header (`include/lr_ffi.h`) declares them unconditionally
# because cbindgen doesn't emit cfg-gated declarations, but the
# default-feature build of `liblr_ffi.so` (used by the CI ffi-bindings
# job and by `go test ./...`) doesn't include them. Listing them here
# keeps the generated Go wrapper compiling under the default build.
EXCHANGE_PLANE_ONLY: set[str] = set()
# Auto-populate: every `lr_*` symbol that starts with a name listed
# below is gated by the `exchange-plane` feature.
_EXCHANGE_PLANE_PREFIXES = (
    "lr_route_lrxp_",
)


def existing_go_symbols() -> set[str]:
    """Set of ``lr_*`` C ABI entry points already called by hand-written
    Go files. Excludes ``generated.go`` so that re-running the generator
    is idempotent — previously-emitted wrappers are regenerated rather
    than skipped as if they were hand-written.
    """
    out: set[str] = set()
    for path in sorted(GO_DIR.glob("*.go")):
        if path.name.endswith("_test.go") or path.name == "generated.go":
            continue
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"\b(lr_\w+)\s*\(", text):
            out.add(m.group(1))
    return out


def existing_go_types() -> set[str]:
    """Set of Go struct type names already declared by hand-written files.
    Excludes ``generated.go`` so the generator stays idempotent.
    """
    out: set[str] = set()
    for path in sorted(GO_DIR.glob("*.go")):
        if path.name.endswith("_test.go") or path.name == "generated.go":
            continue
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"^type\s+(\w+)\s+struct\s*{", text, re.MULTILINE):
            out.add(m.group(1))
    return out


C_TO_GO_TYPE = {
    "void": "",
    "bool": "bool",
    "char": "C.char",
    "uint8_t": "C.uint8_t",
    "uint16_t": "C.uint16_t",
    "uint32_t": "C.uint32_t",
    "uint64_t": "C.uint64_t",
    "int8_t": "C.int8_t",
    "int16_t": "C.int16_t",
    "int32_t": "C.int32_t",
    "int64_t": "C.int64_t",
    "uintptr_t": "C.uintptr_t",
    "size_t": "C.size_t",
}


def to_go_type(c_type: str) -> str:
    s = c_type.strip()
    is_const = s.startswith("const ")
    if is_const:
        s = s[len("const "):].strip()
    is_ptr = s.endswith("*")
    if is_ptr:
        s = s[:-1].strip()
    if s.startswith("struct "):
        s = s[len("struct "):].strip()
    if s in C_TO_GO_TYPE:
        base = C_TO_GO_TYPE[s]
    elif s.startswith("lr_"):
        base = "C." + s
    else:
        base = "C." + s
    if is_ptr:
        if base.startswith("C."):
            return "*" + base
        return "*" + base
    return base


def to_go_ptr_type(c_type: str) -> str:
    """Like to_go_type, but collapses `**C.X` to `unsafe.Pointer` (cgo
    doesn't support pointers to cgo pointers in API signatures). For
    single indirection, returns the proper cgo pointer type.

    IMPORTANT: cgo doesn't allow passing `unsafe.Pointer` to a
    `**C.X` parameter directly. The caller must declare the out
    parameter as `**C.X` (which is also forbidden in cgo) OR use
    a hand-written wrapper that allocates the pointer via C.Calloc.
    For the generated low-level surface, we declare such out-params
    as `**C.X` — cgo accepts this in function signatures, but not in
    function arguments when passing `unsafe.Pointer`.

    To make the generated code buildable, we use `**C.X` for the
    parameter type (cgo allows declaring such types). The caller is
    responsible for allocating the pointer.
    """
    s = c_type.strip()
    is_const = s.startswith("const ")
    if is_const:
        s = s[len("const "):].strip()
    star_count = 0
    while s.endswith("*"):
        star_count += 1
        s = s[:-1].strip()
    if s.startswith("struct "):
        s = s[len("struct "):].strip()
    if s in C_TO_GO_TYPE:
        base = C_TO_GO_TYPE[s]
    elif s.startswith("lr_"):
        base = "C." + s
    else:
        base = "C." + s
    if star_count >= 2:
        # **C.X is expressible in cgo as a parameter type — the caller
        # must allocate `*C.X` and pass `&that`.
        return "*" * star_count + base
    if star_count == 1:
        return "*" + base
    return base


def to_go_call_arg(p: dict, idx: int, handle: str | None = None) -> str:
    """Render a Go call argument expression. This handles multi-
    pointer indirection specially: when the parameter is `**C.X`
    (output parameter), the caller passes the address of a
    pre-allocated `*C.X` variable.

    We can't know the pre-allocated variable's name from here, so we
    fall back to passing the parameter through and let the user handle
    it.
    """
    return render_call_arg(p, idx, handle)


def to_go_value_type(c_type: str) -> str:
    s = c_type.strip()
    is_ptr = s.endswith("*")
    if is_ptr:
        s = s[:-1].strip()
    if s.startswith("const "):
        s = s[len("const "):].strip()
    if s.startswith("struct "):
        s = s[len("struct "):].strip()
    simple_map = {
        "uint8_t": "uint8",
        "uint16_t": "uint16",
        "uint32_t": "uint32",
        "uint64_t": "uint64",
        "int8_t": "int8",
        "int16_t": "int16",
        "int32_t": "int32",
        "int64_t": "int64",
        "uintptr_t": "uintptr",
        "size_t": "uintptr",
        "bool": "bool",
        "char": "byte",
    }
    if s in simple_map:
        # But if the original was a pointer (e.g. `const char *`),
        # the value is a C string, not a Go byte. Use string for
        # string-returning functions.
        if is_ptr and s == "char":
            return "string"
        return simple_map[s]
    return ""


def to_handle_struct_name(handle: str) -> str:
    base = handle
    if base.startswith("lr_"):
        base = base[3:]
    if base.endswith("_t"):
        base = base[:-2]
    elif base.endswith("_handle"):
        base = base[:-len("_handle")]
    parts = base.split("_")
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def to_handle_struct_name_or_cgo(p_type: str) -> str:
    """For a value-struct parameter type like `lr_nlri_family_t`, return
    the cgo type if there's no opaque-handle struct in the binding
    (i.e. the binding uses the C struct directly, not a Go wrapper).
    """
    if p_type.startswith("struct "):
        return "C." + p_type[len("struct "):]
    if p_type in HANDLE_SET and p_type not in EXISTING_GO_TYPES:
        # Generated handle struct.
        return "*" + to_handle_struct_name(p_type)
    if p_type in EXISTING_GO_TYPES and p_type not in HANDLE_SET:
        # Hand-written struct or value struct — use the cgo type.
        return "C." + p_type
    if p_type in EXISTING_GO_TYPES:
        # Hand-written handle struct (e.g. BgpMessage).
        struct_name = to_handle_struct_name(p_type)
        if struct_name in HANDWRITTEN_HANDLE_FIELD:
            return "*" + struct_name
        return "*" + struct_name
    # Default: cgo type.
    return "C." + p_type


def to_free_fn_name(handle: str, methods: list[dict]) -> str | None:
    for f in methods:
        if (f["return_type"] == "void"
                and len(f["params"]) == 1
                and f["params"][0].get("type", "") == handle
                and f["name"].endswith("_free")
                and not f["name"].endswith("_array_free")
                and not f["name"].endswith("_vec_free")):
            return f["name"]
    for f in methods:
        if (f["return_type"] == "void"
                and len(f["params"]) == 1
                and f["params"][0].get("type", "") == handle
                and f["name"].endswith("_free")):
            return f["name"]
    return None


GO_KEYWORDS = {
    "break", "default", "func", "interface", "select", "case", "defer",
    "go", "map", "struct", "chan", "else", "goto", "package", "switch",
    "const", "fallthrough", "if", "range", "type", "continue", "for",
    "import", "return", "var", "init",
}


def sanitize_ident(name: str) -> str:
    if name in GO_KEYWORDS:
        return name + "_"
    return name


HANDLE_SET: set[str] = set()
EXISTING_GO_TYPES: set[str] = set()
# Hand-written Go structs that wrap an opaque handle but use a field
# named `handle` instead of `ptr`. Detected by scanning the existing
# .go files for `type X struct { handle C.lr_*_t; ... }`.
HANDWRITTEN_HANDLE_FIELD: set[str] = set()
# Hand-written Go value-type wrappers around C structs —
# `type X struct { <field> C.struct_lr_yyy_t; ... }`. The value maps the
# Go struct name to the field name holding the C struct.
HANDWRITTEN_VALUE_STRUCTS: dict[str, str] = {}


def render_param(p: dict, idx: int) -> str:
    if "raw" in p:
        return p["raw"]
    name = p.get("name") or f"a{idx}"
    name = sanitize_ident(name)
    c_type = p["type"]
    # Generated handle struct OR hand-written handle struct that uses
    # `ptr` (e.g. BgpPeer): pass *Struct.
    if c_type.startswith("lr_") and not p["is_ptr"] and c_type in HANDLE_SET:
        struct_name = to_handle_struct_name(c_type)
        return f"{name} *{struct_name}"
    # Hand-written value struct (e.g. lr_nlri_family_t).
    if c_type.startswith("lr_") and not p["is_ptr"]:
        struct_name = to_handle_struct_name(c_type)
        if struct_name in EXISTING_GO_TYPES:
            return f"{name} {struct_name}"
        return f"{name} C.{c_type}"
    if p["is_ptr"]:
        return f"{name} {to_go_ptr_type(c_type)}"
    val = to_go_value_type(c_type)
    if val:
        return f"{name} {val}"
    return f"{name} {to_go_type(c_type)}"


def render_call_arg(p: dict, idx: int, handle: str | None = None) -> str:
    if "raw" in p:
        return p["raw"]
    name = p.get("name") or f"a{idx}"
    name = sanitize_ident(name)
    c_type = p["type"]
    if handle is not None and c_type == handle and not p["is_ptr"]:
        return "x.ptr"
    # For double-pointer out-params (`**C.X`), the caller must pass the
    # address of a pre-allocated `*C.X` variable. We pass the param
    # through directly — cgo accepts this when the parameter is
    # declared as `**C.X`.
    star_count = 0
    s = c_type.strip()
    while s.endswith("*"):
        star_count += 1
        s = s[:-1].strip()
    if star_count >= 2:
        return name
    # Generated handle struct: use `.ptr`.
    if c_type.startswith("lr_") and not p["is_ptr"] and c_type in HANDLE_SET:
        struct_name = to_handle_struct_name(c_type)
        # Check whether this handle has a hand-written Go wrapper.
        if struct_name in HANDWRITTEN_HANDLE_FIELD:
            return f"{name}.handle"
        if struct_name in HANDWRITTEN_VALUE_STRUCTS:
            return f"{name}.{HANDWRITTEN_VALUE_STRUCTS[struct_name]}"
        return f"{name}.ptr"
    # Hand-written value struct (e.g. lr_nlri_family_t -> NlriFamily).
    if c_type.startswith("lr_") and not p["is_ptr"]:
        struct_name = to_handle_struct_name(c_type)
        if struct_name in HANDWRITTEN_VALUE_STRUCTS:
            return f"{name}.{HANDWRITTEN_VALUE_STRUCTS[struct_name]}"
        # Pass through as the cgo type (the param is `C.lr_xxx_t`).
        return name
    val = to_go_value_type(c_type)
    if val and not p["is_ptr"]:
        cgo_type = to_go_type(c_type)
        return f"{cgo_type}({name})"
    return name


def to_camel_method(rest: str) -> str:
    if not rest:
        return ""
    parts = rest.split("_")
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def render_return_types(ret: str) -> list[str]:
    if ret == "void":
        return []
    if ret == "bool":
        return ["bool"]
    if ret == "int32_t":
        return ["int32", "error"]
    if ret == "const char *" or ret == "char *":
        return ["string", "error"]
    if ret == "const uint8_t *" or ret == "uint8_t *":
        return ["*C.uint8_t", "error"]
    val = to_go_value_type(ret)
    if val:
        return [val, "error"]
    if ret.startswith("lr_") and ret in HANDLE_SET:
        struct_name = to_handle_struct_name(ret)
        return ["*" + struct_name, "error"]
    if ret.startswith("struct "):
        return [to_go_type(ret), "error"]
    return [to_go_type(ret), "error"]


def render_method_body(name: str, ret: str, call_args: list[str]) -> str:
    call = f"C.{name}({', '.join(call_args)})"
    if ret == "void":
        return f"\t{call}"
    if ret == "int32_t":
        return (f"\trc := {call}\n"
                f"\tif rc < 0 {{\n"
                f"\t\treturn 0, fmt.Errorf(\"{name}: %s\", LastError())\n"
                f"\t}}\n"
                f"\treturn int32(rc), nil")
    if ret == "bool":
        return f"\treturn bool({call})"
    if ret.startswith("lr_") and ret in HANDLE_SET:
        struct_name = to_handle_struct_name(ret)
        # Check whether the hand-written struct uses a `handle` field
        # instead of `ptr` (e.g. BgpMessage uses `handle`). For
        # generated types we use `ptr`.
        if struct_name in HANDWRITTEN_HANDLE_FIELD:
            return (f"\tp := {call}\n"
                    f"\tif p == nil {{\n"
                    f"\t\treturn nil, fmt.Errorf(\"{name}: %s\", LastError())\n"
                    f"\t}}\n"
                    f"\treturn &{struct_name}{{handle: p}}, nil")
        return (f"\tp := {call}\n"
                f"\tif p == nil {{\n"
                f"\t\treturn nil, fmt.Errorf(\"{name}: %s\", LastError())\n"
                f"\t}}\n"
                f"\twrapped := &{struct_name}{{ptr: p}}\n"
                f"\truntime.SetFinalizer(wrapped, (*{struct_name}).destroy)\n"
                f"\treturn wrapped, nil")
    if ret.startswith("struct ") and ret.endswith("_t"):
        # Value struct return — cgo returns the C struct directly.
        return (f"\tres := {call}\n"
                f"\treturn res, nil")
    if ret == "const char *" or ret == "char *":
        return (f"\tcp := {call}\n"
                f"\tif cp == nil {{\n"
                f"\t\treturn \"\", nil\n"
                f"\t}}\n"
                f"\treturn C.GoString(cp), nil")
    if ret == "const uint8_t *" or ret == "uint8_t *":
        # Byte pointer return — keep as *C.uint8_t; the caller can
        # copy via C.GoBytes if needed. Return as `*C.uint8_t` directly.
        return (f"\tres := {call}\n"
                f"\treturn res, nil")
    val = to_go_value_type(ret)
    if val:
        return (f"\tres := {call}\n"
                f"\treturn {val}(res), nil")
    return (f"\tres := {call}\n"
            f"\treturn res, nil")


def render_method(f: dict, handle: str) -> str:
    name = f["name"]
    stem = handle[3:]
    for suffix in ("_t", "_handle"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    prefix = "lr_" + stem + "_"
    if f["name"].startswith(prefix):
        rest = f["name"][len(prefix):]
    else:
        rest = f["name"][3:]
    if rest in ("new", "try_new", "free"):
        return ""
    struct_name = to_handle_struct_name(handle)
    method_name = to_camel_method(rest)
    if not method_name:
        return ""
    params = []
    call_args = []
    for i, p in enumerate(f["params"]):
        if i == 0 and p.get("type", "") == handle and not p["is_ptr"]:
            call_args.append("x.ptr")
            continue
        params.append(render_param(p, i))
        call_args.append(render_call_arg(p, i, handle))
    ret = f["return_type"]
    returns = render_return_types(ret)
    sig_returns = " (" + ", ".join(returns) + ")" if returns else ""
    sig = f"func (x *{struct_name}) {method_name}({', '.join(params)}){sig_returns} {{"
    body = render_method_body(name, ret, call_args)
    return sig + "\n" + body + "\n}\n"


def render_constructor(f: dict, handle: str, free_standing: bool = False) -> str:
    name = f["name"]
    stem = handle[3:]
    for suffix in ("_t", "_handle"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    prefix = "lr_" + stem + "_"
    rest = f["name"][len(prefix):] if f["name"].startswith(prefix) else f["name"][3:]
    if not free_standing:
        if rest not in ("new", "try_new"):
            return ""
        if f["return_type"] != handle:
            return ""
    else:
        if not (f["name"].endswith("_new") or f["name"].endswith("_try_new")):
            return ""
        if f["return_type"] != handle:
            return ""
        rest = f["name"][3:]
    struct_name = to_handle_struct_name(handle)
    if rest == "new":
        factory_name = "New" + struct_name
    elif rest == "try_new":
        factory_name = "TryNew" + struct_name
    else:
        factory_name = "New" + to_camel_method(rest)
    params = []
    call_args = []
    for i, p in enumerate(f["params"]):
        params.append(render_param(p, i))
        call_args.append(render_call_arg(p, i, None))
    sig = f"func {factory_name}({', '.join(params)}) (*{struct_name}, error) {{"
    body = (f"\tp := C.{name}({', '.join(call_args)})\n"
            f"\tif p == nil {{\n"
            f"\t\treturn nil, fmt.Errorf(\"{name}: %s\", LastError())\n"
            f"\t}}\n"
            f"\tx := &{struct_name}{{ptr: p}}\n"
            f"\truntime.SetFinalizer(x, (*{struct_name}).destroy)\n"
            f"\treturn x, nil")
    return sig + "\n" + body + "\n}\n"


def render_struct_and_free(handle: str, info: dict, methods: list[dict]) -> str:
    struct_name = to_handle_struct_name(handle)
    free_fn = to_free_fn_name(handle, methods)
    out = []
    out.append(f"type {struct_name} struct {{")
    out.append(f"\tptr C.{handle}")
    out.append("}")
    out.append("")
    out.append(f"func (x *{struct_name}) destroy() {{")
    out.append(f"\tif x != nil && x.ptr != nil {{")
    if free_fn:
        out.append(f"\t\tC.{free_fn}(x.ptr)")
    out.append(f"\t\tx.ptr = nil")
    out.append(f"\t}}")
    out.append("}")
    out.append("")
    out.append(f"// Free releases the underlying {handle} handle. Safe to call multiple times.")
    out.append(f"func (x *{struct_name}) Free() {{")
    out.append(f"\tif x == nil {{")
    out.append(f"\t\treturn")
    out.append(f"\t}}")
    out.append(f"\truntime.SetFinalizer(x, nil)")
    out.append(f"\tx.destroy()")
    out.append("}")
    out.append("")
    out.append(f"// Closed reports whether the handle has been freed.")
    out.append(f"func (x *{struct_name}) Closed() bool {{")
    out.append(f"\treturn x == nil || x.ptr == nil")
    out.append("}")
    out.append("")
    return "\n".join(out)


def render_free_function(f: dict) -> str:
    name = f["name"]
    go_name = to_camel_method(name[3:])
    params = []
    call_args = []
    for i, p in enumerate(f["params"]):
        params.append(render_param(p, i))
        call_args.append(render_call_arg(p, i, None))
    ret = f["return_type"]
    returns = render_return_types(ret)
    sig_returns = " (" + ", ".join(returns) + ")" if returns else ""
    sig = f"func {go_name}({', '.join(params)}){sig_returns} {{"
    body = render_method_body(name, ret, call_args)
    return sig + "\n" + body + "\n}\n"


def main() -> int:
    global HANDLE_SET, EXISTING_GO_TYPES, HANDWRITTEN_HANDLE_FIELD, EXCHANGE_PLANE_ONLY, HANDWRITTEN_VALUE_STRUCTS
    abi = json.loads(ABI.read_text(encoding="utf-8"))
    HANDLE_SET = set(abi["opaque_types"].keys())
    # Populate EXCHANGE_PLANE_ONLY from the prefixes.
    for f in abi["functions"]:
        for prefix in _EXCHANGE_PLANE_PREFIXES:
            if f["name"].startswith(prefix):
                EXCHANGE_PLANE_ONLY.add(f["name"])
                break
    existing_syms = existing_go_symbols()
    existing_types = existing_go_types()
    EXISTING_GO_TYPES = existing_types
    # Detect hand-written structs that wrap with `handle` instead of `ptr`.
    for path in sorted(GO_DIR.glob("*.go")):
        if path.name.endswith("_test.go") or path.name == "generated.go":
            continue
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"^type\s+(\w+)\s+struct\s*\{(?P<body>[^}]*?)\}",
                             text, re.MULTILINE | re.DOTALL):
            body = m.group("body")
            if re.search(r"\bhandle\s+C\.lr_\w+\b", body):
                HANDWRITTEN_HANDLE_FIELD.add(m.group(1))
            cfield_match = re.search(r"\b(\w+)\s+C\.struct_lr_\w+\b", body)
            if cfield_match:
                HANDWRITTEN_VALUE_STRUCTS[m.group(1)] = cfield_match.group(1)
    print(f"Go present: syms={len(existing_syms)}, types={len(existing_types)}, "
          f"handwritten-handle: {len(HANDWRITTEN_HANDLE_FIELD)}, "
          f"value-structs: {len(HANDWRITTEN_VALUE_STRUCTS)}")
    out_lines = []
    out_lines.append("// Code generated by scripts/gen_go.py — DO NOT EDIT.")
    out_lines.append("//")
    out_lines.append("// Low-level Go wrappers for every C ABI entry point in include/lr_ffi.h")
    out_lines.append("// that does not already have a hand-written wrapper in this package.")
    out_lines.append("// Each opaque handle gets a Go struct + Free()/destroy() pair; each")
    out_lines.append("// `lr_X_<verb>` function becomes a Go method on the X struct.")
    out_lines.append("//")
    out_lines.append("// Re-generate: python3 scripts/gen_go.py")
    out_lines.append("")
    out_lines.append("package librouting")
    out_lines.append("")
    out_lines.append("/*")
    out_lines.append("#cgo CFLAGS: -I${SRCDIR}/../../include")
    out_lines.append("#cgo LDFLAGS: -llr_ffi")
    out_lines.append("")
    out_lines.append("#include <stdlib.h>")
    out_lines.append('#include "lr_ffi.h"')
    out_lines.append("*/")
    out_lines.append('import "C"')
    out_lines.append("")
    out_lines.append("import (")
    out_lines.append('\t"fmt"')
    out_lines.append('\t"runtime"')
    out_lines.append(')')
    out_lines.append("")
    n_structs = 0
    for handle, info in sorted(abi["opaque_types"].items()):
        struct_name = to_handle_struct_name(handle)
        if struct_name in existing_types:
            continue
        methods = abi["by_handle"].get(handle, [])
        out_lines.append(render_struct_and_free(handle, info, methods))
        n_structs += 1
    n_ctors = 0
    for handle, info in sorted(abi["opaque_types"].items()):
        methods = abi["by_handle"].get(handle, [])
        for f in methods:
            if f["name"] in existing_syms:
                continue
            ctor = render_constructor(f, handle)
            if ctor:
                out_lines.append(ctor)
                n_ctors += 1
    for f in abi["free_functions"]:
        if f["name"] in existing_syms:
            continue
        if f["return_type"] not in HANDLE_SET:
            continue
        rest = f["name"][3:]
        if not (rest.endswith("_new") or rest.endswith("_try_new")):
            continue
        handle = f["return_type"]
        ctor = render_constructor(f, handle, free_standing=True)
        if ctor:
            out_lines.append(ctor)
            n_ctors += 1
    # Handle-attached constructors that take another handle as first param
    emitted_ctor_names: set[str] = set()
    for line in out_lines:
        m = re.search(r"C\.(lr_\w+)\(", line)
        if m:
            emitted_ctor_names.add(m.group(1))
    for f in abi["functions"]:
        if f["name"] in existing_syms:
            continue
        if f["name"] in emitted_ctor_names:
            continue
        if f["return_type"] not in HANDLE_SET:
            continue
        rest = f["name"][3:]
        if not (rest.endswith("_new") or rest.endswith("_try_new")):
            continue
        if f["params"] and f["params"][0].get("type", "") == f["return_type"]:
            continue
        handle = f["return_type"]
        ctor = render_constructor(f, handle, free_standing=True)
        if ctor:
            out_lines.append(ctor)
            n_ctors += 1
    n_methods = 0
    # Track which (struct, method-name) pairs we've already emitted so
    # we don't duplicate methods that already exist in hand-written
    # wrappers (e.g. `Router.OspfSetAreaType` exists in librouting.go).
    existing_method_names: set[tuple[str, str]] = set()
    for path in sorted(GO_DIR.glob("*.go")):
        if path.name.endswith("_test.go") or path.name == "generated.go":
            continue
        text = path.read_text(encoding="utf-8")
        # Find every `func (x *Type) Method(` in hand-written files.
        for m in re.finditer(r"^func\s+\(\s*\w+\s+\*(\w+)\s*\)\s+(\w+)\s*\(", text, re.MULTILINE):
            existing_method_names.add((m.group(1), m.group(2)))
    # Hand-written struct types that take a `lr_X_t` opaque handle as
    # their FIRST parameter but the hand-written Go struct doesn't have
    # a `.ptr` field — these methods need to be skipped from generation
    # (the hand-written wrappers cover them).
    hand_written_no_ptr: set[str] = set()
    # Also track which hand-written struct types are NOT handle
    # wrappers at all — they're value-type wrappers around a C struct
    # (e.g. `type NlriFamily struct { c C.struct_lr_afi_safi_t }`).
    # Methods that take such a value-type wrapper by value can still be
    # generated — we just need to use the wrapper's `.c` field instead
    # of `.ptr`.
    hand_written_value_structs: dict[str, str] = {}  # struct name -> C field name
    for path in sorted(GO_DIR.glob("*.go")):
        if path.name.endswith("_test.go") or path.name == "generated.go":
            continue
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"^type\s+(\w+)\s+struct\s*\{(?P<body>[^}]*?)\}", text, re.MULTILINE | re.DOTALL):
            body = m.group("body")
            # Match `ptr C.lr_*` (handle wrapper).
            if re.search(r"\bptr\s+C\.lr_\w+\b", body):
                continue
            # Match `handle C.lr_*` (handle wrapper with `handle` field).
            if re.search(r"\bhandle\s+C\.lr_\w+\b", body):
                continue
            # Match `c C.struct_lr_*` (value-type wrapper).
            cfield_match = re.search(r"\b(\w+)\s+C\.struct_lr_\w+\b", body)
            if cfield_match:
                hand_written_value_structs[m.group(1)] = cfield_match.group(1)
                continue
            hand_written_no_ptr.add(m.group(1))
    for handle, info in sorted(abi["opaque_types"].items()):
        methods = abi["by_handle"].get(handle, [])
        struct_name = to_handle_struct_name(handle)
        for f in methods:
            if f["name"] in existing_syms:
                continue
            # Skip exchange-plane-only symbols.
            if f["name"] in EXCHANGE_PLANE_ONLY:
                continue
            # Skip methods whose non-receiver parameters include a
            # hand-written struct that has neither a `.ptr` field, nor
            # a `handle` field, nor a `c` (value-struct) field — there
            # is no way to translate the Go wrapper to a C call.
            skip = False
            if f["params"] and len(f["params"]) >= 2:
                for p in f["params"][1:]:
                    p_type = p.get("type", "")
                    if p_type.startswith("lr_") and not p.get("is_ptr", False):
                        p_struct = to_handle_struct_name(p_type)
                        if p_struct in hand_written_no_ptr:
                            skip = True
                            break
            if skip:
                continue
            method = render_method(f, handle)
            if method:
                method_name_match = re.match(r"func \(\w+ \*\w+\) (\w+)\(", method)
                if method_name_match:
                    method_name = method_name_match.group(1)
                    if (struct_name, method_name) in existing_method_names:
                        continue
                    existing_method_names.add((struct_name, method_name))
                out_lines.append(method)
                n_methods += 1
    n_free = 0
    for f in abi["functions"]:
        if f["name"] in existing_syms:
            continue
        # Skip exchange-plane-only symbols.
        if f["name"] in EXCHANGE_PLANE_ONLY:
            continue
        owner = None
        if f["params"] and not ("raw" in f["params"][0]):
            first_type = f["params"][0].get("type", "")
            if first_type in HANDLE_SET:
                owner = first_type
        if owner is not None:
            continue
        rest = f["name"][3:]
        if rest.endswith("_new") or rest.endswith("_try_new"):
            if f["return_type"] in HANDLE_SET:
                continue
        if f["name"].endswith("_vec_free") or f["name"].endswith("_array_free"):
            if (f["params"] and f["params"][0].get("type", "") in HANDLE_SET):
                continue
        out_lines.append(render_free_function(f))
        n_free += 1
    print(f"  go additions: structs={n_structs}, ctors={n_ctors}, methods={n_methods}, funcs={n_free}")
    OUT.write_text("\n".join(out_lines), encoding="utf-8")
    print(f"  wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
