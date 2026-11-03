#!/usr/bin/env python3
"""Generate Python binding additions for the missing C ABI surface.

Reads ``scripts/abi.json`` (produced by ``abi_parse.py``), inspects the
existing ``bindings/lr-python/src/librouting/_ffi.py`` cdef text, and emits:

* a single cdef block containing every missing opaque typedef, value
  struct, and function declaration — appended to ``_HEADER`` inside
  ``_ffi.py``;
* a new module ``bindings/lr-python/src/librouting/generated.py`` with
  thin low-level wrapper classes for every opaque handle that does not
  already have a hand-written Python class.

The generated layer is intentionally mechanical: each method is a
thin pass-through to ``get_lib().lr_<name>(...)``. Idiomatic Python
wrappers (``BgpPathAttrs``, ``Router``, …) sit on top.

The script is idempotent: re-running it produces the same output.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ABI = ROOT / "scripts" / "abi.json"
FFI = ROOT / "bindings" / "lr-python" / "src" / "librouting" / "_ffi.py"
GENERATED = ROOT / "bindings" / "lr-python" / "src" / "librouting" / "generated.py"

GEN_BEGIN = "/* GENERATED ADDITIONS - do not edit by hand."
GEN_END = "   Re-run: python3 scripts/gen_python.py */"


def existing_python_cdef() -> str:
    text = FFI.read_text(encoding="utf-8")
    m = re.search(r'_HEADER\s*=\s*r"""(.*?)"""', text, re.DOTALL)
    if not m:
        raise RuntimeError("cannot find _HEADER in _ffi.py")
    return m.group(1)


def existing_python_symbols(cdef: str) -> set[str]:
    out = set()
    for m in re.finditer(r"\b(lr_\w+)\s*\(", cdef):
        out.add(m.group(1))
    return out


def existing_python_opaques(cdef: str) -> set[str]:
    out = set()
    for m in re.finditer(r"typedef struct (Opaque\w+) \*(lr_\w+);", cdef):
        out.add(m.group(2))
    return out


def existing_python_structs(cdef: str) -> set[str]:
    out = set()
    for m in re.finditer(r"typedef struct \w+ \{[^}]*\}\s*(lr_\w+_t);", cdef, re.DOTALL):
        out.add(m.group(1))
    for m in re.finditer(r"^\s*struct\s+(lr_\w+_t)\s*\{", cdef, re.MULTILINE):
        out.add(m.group(1))
    return out


def existing_python_classes() -> set[str]:
    out: set[str] = set()
    for path in (ROOT / "bindings" / "lr-python" / "src" / "librouting").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"^class\s+(\w+)\b", text, re.MULTILINE):
            out.add(m.group(1))
    return out


def render_opaque(handle: str, info: dict) -> str:
    if "alias_of" in info:
        return f"typedef {info['alias_of']} {handle};"
    return f"typedef struct {info['c_struct']} {info['c_struct']};\ntypedef struct {info['c_struct']} *{handle};"


def render_struct(handle: str, info: dict) -> str:
    if "alias_of" in info:
        return f"typedef struct {info['alias_of']} {handle};"
    lines = [f"typedef struct {info['c_struct']} {{"]
    for f in info["fields"]:
        if f["array"] is not None:
            lines.append(f"    {f['type']} {f['name']}[{f['array']}];")
        else:
            lines.append(f"    {f['type']} {f['name']};")
    lines.append(f"}} {handle};")
    return "\n".join(lines)


def render_function(f: dict) -> str:
    ret = f["return_type"]
    name = f["name"]
    params = []
    for p in f["params"]:
        if "raw" in p:
            params.append(p["raw"])
            continue
        params.append(f"{p['type']} {p['name']}")
    if not params:
        return f"{ret} {name}(void);"
    if len(params) <= 2:
        return f"{ret} {name}({', '.join(params)});"
    return f"{ret} {name}(\n    " + ",\n    ".join(params) + "\n);"


def render_cdef(abi: dict, present_opaques: set[str], present_structs: set[str],
                present_syms: set[str]) -> str:
    out_lines: list[str] = []
    out_lines.append("/* GENERATED ADDITIONS - do not edit by hand.")
    out_lines.append("   Source: scripts/gen_python.py + scripts/abi.json")
    out_lines.append("   Re-run: python3 scripts/gen_python.py */")
    out_lines.append("")
    added_opaque = 0
    for h, info in sorted(abi["opaque_types"].items()):
        if h in present_opaques:
            continue
        out_lines.append(render_opaque(h, info))
        added_opaque += 1
    added_struct = 0
    for h, info in sorted(abi["value_structs"].items()):
        if h in present_structs:
            continue
        out_lines.append(render_struct(h, info))
        added_struct += 1
    added_func = 0
    for f in abi["functions"]:
        if f["name"] in present_syms:
            continue
        out_lines.append(render_function(f))
        added_func += 1
    print(f"  cdef additions: opaques={added_opaque}, structs={added_struct}, funcs={added_func}")
    return "\n".join(out_lines)


def to_camel(handle: str) -> str:
    base = handle
    if base.startswith("lr_"):
        base = base[3:]
    if base.endswith("_t"):
        base = base[:-2]
    elif base.endswith("_handle"):
        base = base[:-len("_handle")]
    parts = base.split("_")
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def render_method(f: dict, class_handle: str | None) -> str:
    name = f["name"]
    if class_handle:
        stem = class_handle[3:]
        for suffix in ("_t", "_handle"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        prefix = "lr_" + stem + "_"
        if name.startswith(prefix):
            method_name = name[len(prefix):]
        else:
            method_name = name[3:]
    else:
        method_name = name[3:]
    py_keywords = {
        "import", "from", "class", "global", "lambda", "and", "or",
        "not", "is", "in", "as", "if", "else", "elif", "while", "for",
        "try", "except", "finally", "with", "return", "yield", "raise",
        "pass", "break", "continue", "del",
    }
    if method_name in py_keywords:
        method_name = method_name + "_"

    py_params: list[str] = []
    if class_handle:
        py_params.append("self")
    skip_first = bool(class_handle)
    call_args: list[str] = []
    for i, p in enumerate(f["params"]):
        if "raw" in p:
            continue
        if skip_first and i == 0 and p["type"].endswith(class_handle):
            call_args.append("self._ptr")
            continue
        pname = p.get("name") or f"a{i}"
        if pname in py_keywords:
            pname = pname + "_"
        py_params.append(pname)
        call_args.append(pname)

    body_lines: list[str] = []
    ret = f["return_type"]
    call_expr = f"_lib.{name}({', '.join(call_args)})"
    is_handle_ret = (
        ret.endswith("_t") and not ret.startswith("uint") and
        not ret.startswith("int") and not ret.startswith("char") and
        not ret.startswith("void") and not ret.startswith("bool") and
        not ret.startswith("struct") and not ret.startswith("uintptr") and
        not ret.startswith("size") and "*" not in ret
    )
    is_value_struct_ret = ret.startswith("struct ") and ret.endswith("_t")
    if ret == "void":
        body_lines.append(f"    {call_expr}")
    elif is_handle_ret:
        cls = to_camel(ret)
        body_lines.append(f"    p = {call_expr}")
        body_lines.append(f"    if not p:")
        body_lines.append(f"        raise LrError(last_error())")
        body_lines.append(f"    return {cls}.__wrap__(p)")
    elif ret in {"int32_t", "int64_t", "int16_t", "int8_t", "uint8_t",
                  "uint16_t", "uint32_t", "uint64_t", "uintptr_t"}:
        if ret == "int32_t":
            body_lines.append(f"    rc = {call_expr}")
            body_lines.append(f"    if rc < 0:")
            body_lines.append(f"        raise LrError(last_error())")
            body_lines.append(f"    return rc")
        else:
            body_lines.append(f"    return {call_expr}")
    elif ret == "bool":
        body_lines.append(f"    return bool({call_expr})")
    elif is_value_struct_ret:
        body_lines.append(f"    return {call_expr}")
    else:
        body_lines.append(f"    return {call_expr}")

    if class_handle:
        sig = f"    def {method_name}({', '.join(py_params)}):"
        body_indent = "        "
    else:
        sig = f"def {method_name}({', '.join(py_params)}):"
        body_indent = "    "

    body_lines = [body_indent + line[4:] if line.startswith("    ") else (body_indent + line if line.strip() else line)
                  for line in body_lines]
    doc = f"{body_indent}\"\"\"Low-level wrapper for ``{name}``. See ``include/lr_ffi.h``.\"\"\""
    return sig + "\n" + doc + "\n" + "\n".join(body_lines)


def render_class(handle: str, info: dict, methods: list[dict],
                 existing_classes: set[str]) -> str:
    cls_name = to_camel(handle)
    if cls_name in existing_classes:
        return ""
    lines: list[str] = []
    lines.append("")
    lines.append(f"class {cls_name}:")
    lines.append(f"    \"\"\"Low-level RAII wrapper around ``{handle}``.")
    lines.append(f"")
    lines.append(f"    Generated; prefer the hand-written wrappers in the other modules when they exist.")
    lines.append(f"    \"\"\"")
    lines.append("")
    lines.append(f"    __slots__ = (\"_ptr\",)")
    lines.append("")
    lines.append(f"    def __init__(self, ptr):")
    lines.append(f"        self._ptr = ptr")
    lines.append("")
    lines.append(f"    @classmethod")
    lines.append(f"    def __wrap__(cls, ptr):")
    lines.append(f"        \"\"\"Wrap an existing C handle without taking ownership of construction.")
    lines.append(f"        The handle is still freed by ``__del__``.\"\"\"")
    lines.append(f"        return cls(ptr)")
    lines.append("")

    # Find free function
    free_sym = None
    for f in methods:
        if (f["return_type"] == "void"
                and len(f["params"]) == 1
                and f["params"][0].get("type", "") == handle
                and f["name"].endswith("_free")
                and not f["name"].endswith("_array_free")
                and not f["name"].endswith("_vec_free")):
            free_sym = f["name"]
            break
    # Fallback: vec/array free with single handle.
    if free_sym is None:
        for f in methods:
            if (f["return_type"] == "void"
                    and len(f["params"]) == 1
                    and f["params"][0].get("type", "") == handle
                    and f["name"].endswith("_free")):
                free_sym = f["name"]
                break

    if free_sym is not None:
        lines.append("    def free(self) -> None:")
        lines.append(f"        \"\"\"Release the underlying ``{handle}`` handle.\"\"\"")
        lines.append("        if getattr(self, \"_ptr\", None) is not None and self._ptr != ffi.NULL:")
        lines.append(f"            _lib.{free_sym}(self._ptr)")
        lines.append("            self._ptr = None")
        lines.append("")
        lines.append("    def __del__(self):")
        lines.append("        try:")
        lines.append("            self.free()")
        lines.append("        except Exception:")
        lines.append("            pass")
        lines.append("")
    else:
        lines.append("    def __del__(self):")
        lines.append("        pass")
        lines.append("")

    lines.append("    @property")
    lines.append("    def ptr(self):")
    lines.append("        \"\"\"Return the raw CFFI pointer for direct C ABI access.\"\"\"")
    lines.append("        return self._ptr")
    lines.append("")

    added = 0
    stem = handle[3:]
    for suffix in ("_t", "_handle"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    prefix = "lr_" + stem + "_"
    py_keywords = {
        "import", "from", "class", "global", "lambda", "and", "or",
        "not", "is", "in", "as", "if", "else", "elif", "while", "for",
        "try", "except", "finally", "with", "return", "yield", "raise",
        "pass", "break", "continue", "del",
    }
    # First, constructors: function name is `<prefix>new` or `<prefix>try_new`,
    # returns the handle, first param is NOT the handle.
    for f in methods:
        if not f["name"].startswith(prefix):
            continue
        rest = f["name"][len(prefix):]
        if rest not in ("new", "try_new"):
            continue
        if f["return_type"] != handle:
            continue
        ctor_params = ["cls"]
        call_args = []
        for i, p in enumerate(f["params"]):
            if "raw" in p:
                continue
            pname = p.get("name") or f"a{i}"
            if pname in py_keywords:
                pname = pname + "_"
            ctor_params.append(pname)
            call_args.append(pname)
        sig = f"    @classmethod\n    def new({', '.join(ctor_params)}):"
        doc = f"        \"\"\"Construct a new ``{handle}``. Throws ``LrError`` on failure.\"\"\""
        body = [f"        p = _lib.{f['name']}({', '.join(call_args)})",
                "        if not p:",
                "            raise LrError(last_error())",
                "        return cls(p)"]
        lines.append(sig)
        lines.append(doc)
        lines.extend(body)
        lines.append("")
        added += 1
    # Then, regular methods.
    for f in methods:
        if not f["params"]:
            continue
        if "raw" in f["params"][0]:
            continue
        first_type = f["params"][0].get("type", "")
        if first_type != handle:
            continue
        if free_sym is not None and f["name"] == free_sym:
            continue
        if not f["name"].startswith(prefix):
            continue
        rest = f["name"][len(prefix):]
        if rest in ("new", "try_new"):
            continue
        if rest in ("array_free", "vec_free"):
            continue
        lines.append(render_method(f, handle))
        lines.append("")
        added += 1
    return "\n".join(lines)


def render_generated_module(abi: dict, existing_classes: set[str]) -> str:
    lines: list[str] = []
    lines.append('"""Auto-generated low-level Python wrappers for the C ABI.')
    lines.append("")
    lines.append("Produced by ``scripts/gen_python.py`` from ``include/lr_ffi.h``.")
    lines.append("Each class is a thin RAII wrapper around an opaque C handle;")
    lines.append("methods are 1:1 pass-throughs to the corresponding ``lr_*`` entry points.")
    lines.append("Prefer the hand-written wrappers in the other modules when they exist.")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("from ._ffi import ffi, get_lib, last_error")
    lines.append("from .router import LrError")
    lines.append("")
    lines.append("_lib = get_lib()")
    lines.append("")
    n_classes = 0
    n_methods = 0
    n_free = 0
    for handle, info in sorted(abi["opaque_types"].items()):
        methods = abi["by_handle"].get(handle, [])
        rendered = render_class(handle, info, methods, existing_classes)
        if rendered:
            lines.append(rendered)
            n_classes += 1
            n_methods += sum(1 for f in methods
                             if f["params"] and f["params"][0].get("type") == handle
                             and f["name"] != f"lr_{handle[3:-2]}_free"
                             and not f["name"].endswith("_array_free")
                             and not f["name"].endswith("_vec_free"))
    for f in abi["free_functions"]:
        if f["params"] and "raw" in f["params"][0]:
            continue
        lines.append(render_method(f, None))
        lines.append("")
        n_free += 1
    print(f"  generated classes:    {n_classes}")
    print(f"  generated methods:     {n_methods}")
    print(f"  generated free funcs:  {n_free}")
    return "\n".join(lines)


def patch_ffi(abi: dict) -> None:
    text = FFI.read_text(encoding="utf-8")
    m = re.search(r'(_HEADER\s*=\s*r"""(.*?)""")', text, re.DOTALL)
    if not m:
        raise RuntimeError("cannot find _HEADER")
    cdef = m.group(2)
    pat = re.compile(re.escape(GEN_BEGIN) + r".*?" + re.escape(GEN_END) + r"\s*", re.DOTALL)
    cdef_clean = pat.sub("", cdef)
    present_opaques = existing_python_opaques(cdef_clean)
    present_structs = existing_python_structs(cdef_clean)
    present_syms = existing_python_symbols(cdef_clean)
    print("Python present: opaques={}, structs={}, syms={}".format(
        len(present_opaques), len(present_structs), len(present_syms)))
    addition = render_cdef(abi, present_opaques, present_structs, present_syms)
    new_cdef = cdef_clean + "\n" + addition + "\n"
    new_text = text.replace(m.group(2), new_cdef, 1)
    if "def last_error()" not in new_text:
        helper = '''

def last_error() -> str:
    """Return the thread-local last-error message from the C ABI."""
    cstr = get_lib().lr_last_error()
    if cstr == ffi.NULL:
        return ""
    return ffi.string(cstr).decode("utf-8", errors="replace")
'''
        new_text = new_text + helper
    if new_text == text:
        print("  _ffi.py unchanged (already up to date)")
    else:
        FFI.write_text(new_text, encoding="utf-8")
        print(f"  patched {FFI}")


def main() -> int:
    abi = json.loads(ABI.read_text(encoding="utf-8"))
    print("Patching _ffi.py …")
    patch_ffi(abi)
    print("Rendering generated.py …")
    existing_classes = existing_python_classes()
    body = render_generated_module(abi, existing_classes)
    GENERATED.write_text(body, encoding="utf-8")
    print(f"  wrote {GENERATED} ({len(body)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
