#!/usr/bin/env python3
"""Generate idiomatic wrapper additions for hand-written binding classes
that are missing C ABI methods.

For each opaque handle in the C ABI, find the corresponding hand-written
class (Python/Go/C++) and identify C ABI methods that are NOT exposed
either as a class method OR called inside another method's body. Emit
idiomatic wrappers for those methods.

Output:
- Python: ``bindings/lr-python/src/librouting/_extras.py`` — patches
  the hand-written classes via ``setattr`` at import time.

The generator is conservative: when a method's signature is too complex
to emit a safe wrapper (callbacks, void* user_data, output arrays of
opaque handles, value-struct returns), the method is skipped and
reported in the script's stdout so a human can hand-write it later.

Re-run: ``python3 scripts/gen_methods_extras.py``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ABI = ROOT / "scripts" / "abi.json"
PY_DIR = ROOT / "bindings" / "lr-python" / "src" / "librouting"
PY_EXTRAS = PY_DIR / "_extras.py"

# --- helpers ---

PY_KEYWORDS = {
    "import", "from", "class", "global", "lambda", "and", "or",
    "not", "is", "in", "as", "if", "else", "elif", "while", "for",
    "try", "except", "finally", "with", "return", "yield", "raise",
    "pass", "break", "continue", "del",
}


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


def py_param_name(p: dict, idx: int) -> str:
    name = p.get("name") or f"a{idx}"
    if name in PY_KEYWORDS:
        name = name + "_"
    return name


# --- audit existing classes ---

def collect_python_classes() -> dict[str, set[str]]:
    """Return {class_name: (method_names_set, c_symbols_used_set)}."""
    out: dict[str, tuple[set[str], set[str]]] = {}
    for path in sorted(PY_DIR.glob("*.py")):
        if path.name in ("generated.py", "_extras.py"):
            continue
        text = path.read_text(encoding="utf-8")
        for cls_m in re.finditer(r"^class\s+(\w+)\b", text, re.MULTILINE):
            cls = cls_m.group(1)
            start = cls_m.end()
            nxt = re.search(r"^class\s+\w+\b", text[start:], re.MULTILINE)
            end = start + nxt.start() if nxt else len(text)
            body = text[start:end]
            methods = set(re.findall(r"^\s+def\s+(\w+)\b", body, re.MULTILINE))
            syms = set(re.findall(r"\blr_(\w+)\b", body))
            out[cls] = (methods, syms)
    return out


# --- method classification ---

def classify_return(ret: str) -> str:
    """Return one of: 'void', 'rc_int', 'rc_uint', 'bool', 'string', 'handle', 'value_struct', 'unknown'."""
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
        return "handle"  # opaque handle return
    if ret.startswith("struct "):
        return "value_struct"
    if ret.endswith("*"):
        return "unknown"
    return "unknown"


def classify_param(p: dict) -> str:
    """Return one of: 'self_handle', 'prim', 'out_prim', 'string', 'bytes',
    'handle', 'value_struct', 'skip'."""
    if "raw" in p:
        return "skip"
    ptype = p.get("type", "").strip()
    if "const char *" in ptype or ptype.startswith("const char *"):
        return "string"  # input string (UTF-8)
    if "char" in ptype and "*" in ptype:
        # `char *` without `const` is a potential output buffer; skip
        return "skip"
    if ptype.endswith("*"):
        base = ptype[:-1].strip()
        if base in ("uint8_t", "uint16_t", "uint32_t", "uint64_t",
                    "int8_t", "int16_t", "int32_t", "int64_t",
                    "bool", "size_t", "uintptr_t"):
            return "out_prim"
        return "skip"  # opaque pointer or struct pointer
    if ptype in ("uint8_t", "uint16_t", "uint32_t", "uint64_t",
                 "int8_t", "int16_t", "int32_t", "int64_t",
                 "bool", "size_t", "uintptr_t"):
        return "prim"
    if ptype.startswith("struct "):
        return "value_struct"
    if ptype.endswith("_t"):
        return "handle"
    return "skip"


def render_python_method(cls_name: str, handle: str, fn: dict) -> str | None:
    """Render a Python method that wraps fn. Returns None if too complex."""
    name = fn["name"]
    verb = method_verb(name, handle)
    if verb in ("new", "try_new", "destroy", "free", "array_free", "vec_free"):
        return None
    if verb.startswith("array_") or verb.startswith("vec_"):
        return None

    # First param must be the handle (self)
    params = fn["params"]
    if not params or "raw" in params[0]:
        return None
    if params[0].get("type", "") != handle:
        return None

    ret_kind = classify_return(fn["return_type"])
    if ret_kind in ("value_struct", "handle", "unknown"):
        return None  # too complex for now

    # Heuristic: methods that return multi-byte arrays via a uint8_t*
    # out parameter are unsafe to auto-wrap (we'd only read the first
    # byte). Skip methods whose name suggests an address / router-id /
    # bytes output. These need hand-written wrappers that allocate the
    # right buffer size.
    UNSAFE_OUT_NAME_HINTS = ("addr", "address", "router_id", "routerid",
                              "mac", "next_hop", "nexthop", "speaker",
                              "cluster_id", "originator", "sa_id",
                              "bytes", "digest", "secret", "key")
    if any(h in name for h in UNSAFE_OUT_NAME_HINTS):
        return None

    # Inspect the rest of the params
    py_params: list[str] = ["self"]
    call_args: list[str] = ["self._ptr"]
    body_pre: list[str] = []
    out_vars: list[tuple[str, str]] = []  # (py_local, cdef_type)

    # Detect array-output patterns: a `*` parameter followed by a
    # capacity parameter (`cap`, `count`, `len`, `max_count`, etc.) is
    # an array output, not a single-value output. Skip these — they
    # need a hand-written wrapper that allocates the right buffer size.
    # The capacity parameter is a NON-pointer primitive (just `uintptr_t
    # cap`), so we only flag pairs where the next param is a primitive
    # (not another pointer).
    param_pairs = list(enumerate(params[1:], start=1))
    for i, p in param_pairs:
        kind = classify_param(p)
        if kind == "out_prim":
            # Check if the next parameter is a capacity hint (a NON-pointer
            # primitive named cap/count/len/max_*).
            if i + 1 < len(params):
                next_p = params[i + 1]
                next_ptype = next_p.get("type", "").strip()
                next_pname = (next_p.get("name") or "").lower()
                # Capacity hints are non-pointer primitives
                if not next_ptype.endswith("*") and any(h == next_pname or h in next_pname
                                                       for h in ("cap", "count", "len", "max")):
                    return None  # array output — skip

    for i, p in param_pairs:
        kind = classify_param(p)
        pname = py_param_name(p, i)
        ptype = p.get("type", "").strip()
        if kind == "skip":
            return None
        elif kind == "prim":
            py_params.append(pname)
            if ptype == "bool":
                call_args.append(f"1 if {pname} else 0")
            else:
                call_args.append(pname)
        elif kind == "out_prim":
            base = ptype[:-1].strip()
            cdef_t = base
            local = f"_out{i}"
            out_vars.append((local, cdef_t))
            body_pre.append(f"    {local} = ffi.new(\"{cdef_t} *\")")
            call_args.append(local)
        elif kind == "string":
            py_params.append(f"{pname}: str")
            body_pre.append(f"    _b{i} = {pname}.encode('utf-8') if isinstance({pname}, str) else {pname}")
            call_args.append(f"_b{i}")
        elif kind == "handle":
            # Passing another handle — skip for now (complex)
            return None
        elif kind == "value_struct":
            # Passing a value struct — skip (complex)
            return None
        elif kind == "bytes":
            # bytes input — complex
            return None

    # Build the call
    call_expr = f"get_lib().{name}({', '.join(call_args)})"
    body: list[str] = []
    body.extend(body_pre)

    if ret_kind == "void":
        body.append(f"    rc = {call_expr}")
        body.append(f"    if rc != 0:")
        body.append(f"        raise LrError(f\"{name} failed (rc={{rc}}): {{last_error()}}\")")
        if out_vars:
            outs = ", ".join(f"int({v[0]}[0])" if v[1].startswith(("int", "uint"))
                            else f"{v[0]}[0]"
                            for v in out_vars)
            body.append(f"    return ({outs})" if len(out_vars) > 1 else f"    return {outs}")
    elif ret_kind == "rc_int":
        body.append(f"    rc = {call_expr}")
        body.append(f"    if rc < 0:")
        body.append(f"        raise LrError(f\"{name} failed (rc={{rc}}): {{last_error()}}\")")
        if out_vars:
            outs = ", ".join(f"int({v[0]}[0])" for v in out_vars)
            body.append(f"    return ({outs})" if len(out_vars) > 1 else f"    return {outs}")
        else:
            body.append(f"    return int(rc)")
    elif ret_kind == "rc_uint":
        body.append(f"    rc = {call_expr}")
        body.append(f"    return int(rc)")
        if out_vars:
            outs = ", ".join(f"int({v[0]}[0])" for v in out_vars)
            body.append(f"    return ({outs})" if len(out_vars) > 1 else f"    return {outs}")
    elif ret_kind == "bool":
        # C ABI bool is returned as i32: < 0 = error, 0 = false, 1 = true
        body.append(f"    rc = {call_expr}")
        body.append(f"    if rc < 0:")
        body.append(f"        raise LrError(f\"{name} failed (rc={{rc}}): {{last_error()}}\")")
        body.append(f"    return bool(rc)")
    elif ret_kind == "string":
        body.append(f"    _p = {call_expr}")
        body.append(f"    if _p == ffi.NULL:")
        body.append(f"        return None")
        body.append(f"    return ffi.string(_p).decode('utf-8', errors='replace')")

    # Indent body inside a `def ...:` block
    py_params_str = ", ".join(py_params)
    sig = f"def _impl_{cls_name.lower()}_{verb}({py_params_str}):"
    doc = f"    \"\"\"Auto-generated wrapper for ``{name}``. See ``include/lr_ffi.h``.\"\"\""
    return sig + "\n" + doc + "\n" + "\n".join(body)


def main() -> int:
    abi = json.loads(ABI.read_text(encoding="utf-8"))
    py_classes = collect_python_classes()

    lines: list[str] = []
    lines.append('"""Auto-generated idiomatic wrappers for C ABI methods not covered')
    lines.append("by the hand-written Python classes.")
    lines.append("")
    lines.append("Produced by ``scripts/gen_methods_extras.py`` from ``include/lr_ffi.h``.")
    lines.append("Re-run: ``python3 scripts/gen_methods_extras.py``.")
    lines.append("")
    lines.append("Each function patches the corresponding hand-written class via")
    lines.append("``setattr`` at import time. The generator is conservative — methods")
    lines.append("with callback parameters, opaque output arrays, or value-struct")
    lines.append("returns are skipped (a human can hand-write them).")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("from ._ffi import ffi, get_lib, last_error")
    lines.append("from .router import LrError")
    lines.append("")
    lines.append("")

    # Build a lookup of class -> module name for the patches
    cls_to_module: dict[str, str] = {}
    for path in sorted(PY_DIR.glob("*.py")):
        if path.name in ("generated.py", "_extras.py", "_ffi.py", "__init__.py"):
            continue
        text = path.read_text(encoding="utf-8")
        for cls_m in re.finditer(r"^class\s+(\w+)\b", text, re.MULTILINE):
            cls_to_module[cls_m.group(1)] = path.stem

    n_classes = 0
    n_methods = 0
    n_skipped = 0

    # For each hand-written class, generate method patches
    for handle in sorted(abi["opaque_types"]):
        cls = to_camel(handle)
        if cls not in py_classes:
            continue
        methods_defined, syms_used = py_classes[cls]
        module_name = cls_to_module.get(cls)
        if not module_name:
            continue

        emitted: list[tuple[str, str]] = []  # (verb, src)
        for fn in abi["by_handle"].get(handle, []):
            verb = method_verb(fn["name"], handle)
            if verb in methods_defined:
                continue
            # Skip if the C ABI function is called inside any existing method
            if fn["name"][3:] in syms_used:
                continue
            src = render_python_method(cls, handle, fn)
            if src is None:
                n_skipped += 1
                continue
            emitted.append((verb, src))
            n_methods += 1
        if not emitted:
            continue
        n_classes += 1
        lines.append(f"# ---- {cls} (handle: {handle}, module: {module_name}) ----")
        lines.append("")
        for verb, src in emitted:
            lines.append(src)
            lines.append("")
            lines.append(f"setattr(_import_{module_name.replace('.', '_').lower()}.{cls}, \"{verb}\", _impl_{cls.lower()}_{verb})")
            lines.append("")
        lines.append("")

    # Now build the _import_<module> lookups at the top
    # We need to import each module that has patches
    modules_needed = set()
    for handle in sorted(abi["opaque_types"]):
        cls = to_camel(handle)
        if cls not in py_classes:
            continue
        methods_defined, syms_used = py_classes[cls]
        for fn in abi["by_handle"].get(handle, []):
            verb = method_verb(fn["name"], handle)
            if verb in methods_defined:
                continue
            if fn["name"][3:] in syms_used:
                continue
            src = render_python_method(cls, handle, fn)
            if src is None:
                continue
            module_name = cls_to_module.get(cls)
            modules_needed.add(module_name)

    # Build the final file: header + imports + patches
    final_lines = []
    final_lines.append('"""Auto-generated idiomatic wrappers for C ABI methods not covered')
    final_lines.append("by the hand-written Python classes.")
    final_lines.append("")
    final_lines.append("Produced by ``scripts/gen_methods_extras.py`` from ``include/lr_ffi.h``.")
    final_lines.append("Re-run: ``python3 scripts/gen_methods_extras.py``.")
    final_lines.append("")
    final_lines.append("Each function patches the corresponding hand-written class via")
    final_lines.append("``setattr`` at import time. The generator is conservative — methods")
    final_lines.append("with callback parameters, opaque output arrays, or value-struct")
    final_lines.append("returns are skipped (a human can hand-write them).")
    final_lines.append('"""')
    final_lines.append("")
    final_lines.append("from __future__ import annotations")
    final_lines.append("")
    final_lines.append("from ._ffi import ffi, get_lib, last_error")
    final_lines.append("from .router import LrError")
    for m in sorted(modules_needed):
        final_lines.append(f"from . import {m} as _import_{m.replace('.', '_').lower()}")
    final_lines.append("")
    final_lines.append("")

    # Now re-emit the patches but using the imported modules
    n_classes = 0
    n_methods = 0
    for handle in sorted(abi["opaque_types"]):
        cls = to_camel(handle)
        if cls not in py_classes:
            continue
        methods_defined, syms_used = py_classes[cls]
        module_name = cls_to_module.get(cls)
        if not module_name:
            continue

        emitted: list[tuple[str, str]] = []
        for fn in abi["by_handle"].get(handle, []):
            verb = method_verb(fn["name"], handle)
            if verb in methods_defined:
                continue
            if fn["name"][3:] in syms_used:
                continue
            src = render_python_method(cls, handle, fn)
            if src is None:
                continue
            emitted.append((verb, src))
            n_methods += 1
        if not emitted:
            continue
        n_classes += 1
        final_lines.append(f"# ---- {cls} (handle: {handle}, module: {module_name}) ----")
        final_lines.append("")
        for verb, src in emitted:
            final_lines.append(src)
            final_lines.append("")
            final_lines.append(
                f"setattr(_import_{module_name.replace('.', '_').lower()}.{cls}, \"{verb}\", "
                f"_impl_{cls.lower()}_{verb})"
            )
            final_lines.append("")

    content = "\n".join(final_lines) + "\n"
    PY_EXTRAS.write_text(content, encoding="utf-8")
    print(f"Python extras:")
    print(f"  classes patched: {n_classes}")
    print(f"  methods emitted:  {n_methods}")
    print(f"  wrote {PY_EXTRAS} ({len(content)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
