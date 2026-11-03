#!/usr/bin/env python3
"""Generate C++ binding additions for the missing C ABI surface.

Reads ``scripts/abi.json`` and appends to ``include/librouting.hpp`` a
``namespace gen`` block with one ``inline`` wrapper per missing
``lr_*`` entry point. Each opaque handle gets an ``using XHandle =
std::unique_ptr<OpaqueX, XDeleter>`` RAII typedef.

The generated layer is mechanical and intentionally minimal — it
mirrors the C ABI 1:1 with C++ types (``std::uint32_t`` etc.). The
hand-written wrappers above (``Router``, ``Bytes``, ``make_router`` …)
sit on top.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ABI = ROOT / "scripts" / "abi.json"
HPP = ROOT / "include" / "librouting.hpp"

GEN_BEGIN = "// ===== GENERATED ADDITIONS - do not edit by hand. ====="
GEN_END = "// ===== END GENERATED ADDITIONS ====="


def existing_cpp_symbols() -> set[str]:
    text = HPP.read_text(encoding="utf-8")
    return set(re.findall(r"\b(lr_\w+)\s*\(", text))


def existing_cpp_typedefs() -> set[str]:
    text = HPP.read_text(encoding="utf-8")
    handles = set()
    for m in re.finditer(r"using\s+(\w+Handle)\s*=\s*std::unique_ptr<(Opaque\w+),\s*detail::(\w+)>", text):
        handles.add(m.group(1))
    return handles


def existing_cpp_deleters() -> set[str]:
    text = HPP.read_text(encoding="utf-8")
    return set(re.findall(r"struct\s+(\w+Deleter)\s*{", text))


C_TO_CPP_TYPE = {
    "void": "void",
    "bool": "bool",
    "char": "char",
    "uint8_t": "std::uint8_t",
    "uint16_t": "std::uint16_t",
    "uint32_t": "std::uint32_t",
    "uint64_t": "std::uint64_t",
    "int8_t": "std::int8_t",
    "int16_t": "std::int16_t",
    "int32_t": "std::int32_t",
    "int64_t": "std::int64_t",
    "uintptr_t": "std::uintptr_t",
    "size_t": "std::size_t",
}


def to_cpp_type(c_type: str) -> str:
    s = c_type.strip()
    is_const = s.startswith("const ")
    if is_const:
        s = s[len("const "):].strip()
    is_ptr = s.endswith("*")
    if is_ptr:
        s = s[:-1].strip()
    base = C_TO_CPP_TYPE.get(s, s)
    out = base
    if is_ptr:
        out = out + "*"
    if is_const:
        out = "const " + out
    return out


def to_handle_class_name(handle: str) -> str:
    base = handle
    if base.startswith("lr_"):
        base = base[3:]
    if base.endswith("_t"):
        base = base[:-2]
    elif base.endswith("_handle"):
        base = base[:-len("_handle")]
    parts = base.split("_")
    return "".join(p[:1].upper() + p[1:] for p in parts if p) + "Handle"


def to_deleter_name(handle: str) -> str:
    base = handle
    if base.startswith("lr_"):
        base = base[3:]
    if base.endswith("_t"):
        base = base[:-2]
    elif base.endswith("_handle"):
        base = base[:-len("_handle")]
    parts = base.split("_")
    return "".join(p[:1].upper() + p[1:] for p in parts if p) + "Deleter"


def to_free_fn_name(handle: str, methods: list[dict]) -> str | None:
    for f in methods:
        if f["return_type"] != "void":
            continue
        if f["name"].endswith("_array_free") or f["name"].endswith("_vec_free"):
            continue
        if len(f["params"]) != 1:
            continue
        if f["params"][0].get("type", "") != handle:
            continue
        if not f["name"].endswith("_free"):
            continue
        return f["name"]
    for f in methods:
        if f["return_type"] != "void":
            continue
        if not f["name"].endswith("_free"):
            continue
        if len(f["params"]) != 1:
            continue
        if f["params"][0].get("type", "") != handle:
            continue
        return f["name"]
    return None


def render_param(p: dict, idx: int) -> str:
    if "raw" in p:
        return p["raw"]
    name = p.get("name") or f"a{idx}"
    return f"{to_cpp_type(p['type'])} {name}"


def render_free_function(f: dict) -> str:
    name = f["name"]
    cpp_name = name[3:]
    ret = to_cpp_type(f["return_type"])
    params = [render_param(p, i) for i, p in enumerate(f["params"])]
    args = [p.get("name") or f"a{i}" for i, p in enumerate(f["params"]) if "raw" not in p]
    if not params:
        sig = f"inline {ret} {cpp_name}()"
    else:
        sig = f"inline {ret} {cpp_name}({', '.join(params)})"
    if ret == "void":
        body = f"    {name}({', '.join(args)});"
    elif ret == "std::int32_t":
        body = (f"    std::int32_t rc = {name}({', '.join(args)});\n"
                f"    if (rc < 0) throw Error(std::string(\"{name} failed: \") + (lr_last_error() ? lr_last_error() : \"unknown\"));\n"
                f"    return rc;")
    else:
        body = f"    return {name}({', '.join(args)});"
    return f"{sig} {{\n{body}\n}}\n"


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
    if rest in ("new", "try_new"):
        return ""
    if rest == "free":
        return ""
    ret = to_cpp_type(f["return_type"])
    params = [render_param(p, i) for i, p in enumerate(f["params"])]
    handle_name = to_handle_class_name(handle)
    if params and len(f["params"]) > 0 and f["params"][0].get("type", "") == handle:
        params[0] = f"{handle_name} const& h"
    args = []
    for i, p in enumerate(f["params"]):
        if "raw" in p:
            continue
        if i == 0 and p.get("type", "") == handle:
            args.append("h.get()")
            continue
        args.append(p.get("name") or f"a{i}")
    if not params:
        sig = f"inline {ret} {rest}()"
    else:
        sig = f"inline {ret} {rest}({', '.join(params)})"
    if ret == "void":
        body = f"    {name}({', '.join(args)});"
    elif ret == "std::int32_t":
        body = (f"    std::int32_t rc = {name}({', '.join(args)});\n"
                f"    if (rc < 0) throw Error(std::string(\"{name} failed: \") + (lr_last_error() ? lr_last_error() : \"unknown\"));\n"
                f"    return rc;")
    else:
        body = f"    return {name}({', '.join(args)});"
    return f"{sig} {{\n{body}\n}}\n"


def render_constructor(f: dict, handle: str) -> str:
    name = f["name"]
    stem = handle[3:]
    for suffix in ("_t", "_handle"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    prefix = "lr_" + stem + "_"
    rest = f["name"][len(prefix):]
    if rest not in ("new", "try_new"):
        return ""
    if f["return_type"] != handle:
        return ""
    ret = to_handle_class_name(handle)
    params = [render_param(p, i) for i, p in enumerate(f["params"])]
    args = [p.get("name") or f"a{i}" for i, p in enumerate(f["params"]) if "raw" not in p]
    factory_suffix = rest
    if not params:
        sig = f"inline {ret} make_{stem.replace('_', '')}_{factory_suffix}()"
    else:
        sig = f"inline {ret} make_{stem.replace('_', '')}_{factory_suffix}({', '.join(params)})"
    body = (f"    auto p = {name}({', '.join(args)});\n"
            f"    if (!p) throw Error(std::string(\"{name} returned null\"));\n"
            f"    return {ret}(p);")
    return f"{sig} {{\n{body}\n}}\n"


def render_deleter_and_handle(handle: str, info: dict, methods: list[dict]) -> str:
    handle_class = to_handle_class_name(handle)
    deleter_name = to_deleter_name(handle)
    free_fn = to_free_fn_name(handle, methods)
    opaque_name = info["c_struct"]
    lines = []
    if free_fn is not None:
        lines.append(f"struct {deleter_name} {{")
        lines.append(f"    void operator()({handle} h) const noexcept {{ if (h) {free_fn}(h); }}")
        lines.append("};")
    else:
        lines.append(f"struct {deleter_name} {{")
        lines.append(f"    void operator()({handle} /*h*/) const noexcept {{ /* no free — owned by parent */ }}")
        lines.append("};")
    lines.append(f"using {handle_class} = std::unique_ptr<{opaque_name}, {deleter_name}>;")
    return "\n".join(lines)


def patch_hpp(abi: dict) -> None:
    text = HPP.read_text(encoding="utf-8")
    pat = re.compile(re.escape(GEN_BEGIN) + r".*?" + re.escape(GEN_END) + r"\s*", re.DOTALL)
    text_clean = pat.sub("", text)
    ns_close = text_clean.rfind("} // namespace librouting")
    if ns_close < 0:
        insertion_point = len(text_clean)
    else:
        insertion_point = ns_close
    present_syms = existing_cpp_symbols()
    present_typedefs = existing_cpp_typedefs()
    present_deleters = existing_cpp_deleters()
    print(f"CPP present: syms={len(present_syms)}, typedefs={len(present_typedefs)}, deleters={len(present_deleters)}")
    out_lines = [GEN_BEGIN, ""]
    out_lines.append("namespace gen {")
    out_lines.append("")
    out_lines.append("using ::librouting::Error;")
    out_lines.append("")
    n_typedefs = 0
    n_deleters = 0
    for handle, info in sorted(abi["opaque_types"].items()):
        out_lines.append(render_deleter_and_handle(handle, info, abi["by_handle"].get(handle, [])))
        out_lines.append("")
        n_deleters += 1
        n_typedefs += 1
    n_funcs = 0
    for f in abi["functions"]:
        if f["name"] in present_syms:
            continue
        owner = None
        rest = f["name"][3:]
        for plen in range(1, len(rest.split("_")) + 1):
            candidate = "lr_" + "_".join(rest.split("_")[:plen]) + "_t"
            if candidate in abi["opaque_types"]:
                owner = candidate
        if owner is not None and f["return_type"] == owner and f["name"].endswith("_new"):
            continue
        if owner is not None and f["params"] and f["params"][0].get("type", "") == owner:
            stem = owner[3:]
            for suffix in ("_t", "_handle"):
                if stem.endswith(suffix):
                    stem = stem[: -len(suffix)]
                    break
            prefix = "lr_" + stem + "_"
            if f["name"].startswith(prefix):
                rest = f["name"][len(prefix):]
                if rest in ("new", "try_new", "free"):
                    continue
                continue
        out_lines.append(render_free_function(f))
        n_funcs += 1
    n_ctors = 0
    for handle, info in sorted(abi["opaque_types"].items()):
        methods = abi["by_handle"].get(handle, [])
        stem = handle[3:]
        for suffix in ("_t", "_handle"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        prefix = "lr_" + stem + "_"
        for f in methods:
            if not f["name"].startswith(prefix):
                continue
            ctor = render_constructor(f, handle)
            if ctor:
                out_lines.append(ctor)
                n_ctors += 1
    # Also emit free-standing constructors: functions in
    # `free_functions` that return an opaque handle and end with `_new`.
    for f in abi["free_functions"]:
        if f["name"] in present_syms:
            continue
        if f["return_type"] not in abi["opaque_types"]:
            continue
        if not (f["name"].endswith("_new") or f["name"].endswith("_try_new")):
            continue
        handle = f["return_type"]
        stem = handle[3:]
        for suffix in ("_t", "_handle"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        # We need a custom constructor name since the function doesn't
        # match the standard `<prefix>new` pattern.
        ret = to_handle_class_name(handle)
        params = [render_param(p, i) for i, p in enumerate(f["params"])]
        args = [p.get("name") or f"a{i}" for i, p in enumerate(f["params"]) if "raw" not in p]
        # Use the function's own name (without lr_) as the factory suffix.
        factory_suffix = f["name"][3:].replace("_", "")
        if not params:
            sig = f"inline {ret} make_{factory_suffix}()"
        else:
            sig = f"inline {ret} make_{factory_suffix}({', '.join(params)})"
        body = (f"    auto p = {f['name']}({', '.join(args)});\n"
                f"    if (!p) throw Error(std::string(\"{f['name']} returned null\"));\n"
                f"    return {ret}(p);")
        out_lines.append(f"{sig} {{\n{body}\n}}\n")
        n_ctors += 1
    n_methods = 0
    for handle, info in sorted(abi["opaque_types"].items()):
        methods = abi["by_handle"].get(handle, [])
        for f in methods:
            if f["name"] in present_syms:
                continue
            if not f["params"] or f["params"][0].get("type", "") != handle:
                continue
            method = render_method(f, handle)
            if method:
                out_lines.append(method)
                n_methods += 1
    out_lines.append("} // namespace gen")
    out_lines.append("")
    out_lines.append(GEN_END)
    addition = "\n".join(out_lines)
    print(f"  c++ additions: typedefs={n_typedefs}, deleters={n_deleters}, ctors={n_ctors}, methods={n_methods}, funcs={n_funcs}")
    new_text = (text_clean[:insertion_point].rstrip()
                + "\n\n" + addition + "\n\n"
                + text_clean[insertion_point:].lstrip("\n"))
    HPP.write_text(new_text, encoding="utf-8")
    print(f"  patched {HPP}")


def main() -> int:
    abi = json.loads(ABI.read_text(encoding="utf-8"))
    patch_hpp(abi)
    return 0


if __name__ == "__main__":
    sys.exit(main())
