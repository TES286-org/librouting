#!/usr/bin/env python3
"""Parse ``include/lr_ffi.h`` into a structured, machine-readable JSON.

The parser is deliberately tolerant: cbindgen output is well-formed C, but
we want to extract:

* every opaque handle typedef (``typedef struct OpaqueX *lr_xxx_t``)
* every value struct typedef (``typedef struct { ... } lr_xxx_t``)
* every ``#define`` constant
* every enum and its values
* every function declaration (return type, name, ordered parameter list)

The output is consumed by the binding generators in this directory.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "include" / "lr_ffi.h"
OUT = ROOT / "scripts" / "abi.json"


OPAQUE_TYPEDEF = re.compile(
    r"^typedef struct Opaque(\w+) \*(lr_\w+);",
    re.MULTILINE,
)
ALIAS_TYPEDEF = re.compile(
    r"^typedef\s+(lr_\w+)\s+(lr_\w+)\s*;",
    re.MULTILINE,
)
VALUE_STRUCT_ALIAS = re.compile(
    r"^typedef struct\s+(lr_\w+_t)\s+(lr_\w+);",
    re.MULTILINE,
)
VALUE_STRUCT_TYPEDEF = re.compile(
    r"^typedef struct (\w+) \{(?P<body>[^}]*)\}\s*lr_(\w+)_t;",
    re.MULTILINE,
)
DEFINE_CONST = re.compile(
    r"^#define\s+(LR_\w+)\s+(\S+)",
    re.MULTILINE,
)
ENUM_BLOCK = re.compile(
    r"^enum class\s+(\w+)\s*:\s*(\w+)\s*\{(?P<body>.*?)\};",
    re.MULTILINE | re.DOTALL,
)
ENUM_VALUE = re.compile(r"(\w+)\s*(?:=\s*([^,]+))?\s*,?")


def _strip_comments(text: str) -> str:
    """Remove /* */ and // comments. Keeps newlines so line numbers in
    error messages still roughly correspond to the original."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"),
                  text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def _split_top_level(s: str, sep: str = ",") -> list[str]:
    """Split a comma-separated list at top level (not inside braces)."""
    parts: list[str] = []
    depth = 0
    cur = ""
    for ch in s:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def parse_param(p: str) -> dict:
    p = p.strip()
    if not p:
        return {}
    m = re.match(r"^(?P<type>.+?)(?P<name>\b[A-Za-z_]\w*)\s*$", p)
    if not m:
        return {"raw": p}
    full_type = m.group("type").strip()
    name = m.group("name")
    is_const = "const" in full_type.split()
    is_ptr = "*" in full_type
    is_struct = "struct " in full_type
    pointee = None
    if is_ptr:
        pointee = full_type.replace("const", "").replace("struct ", "").replace("*", "").strip()
    out = {
        "name": name,
        "type": full_type,
        "is_const": is_const,
        "is_ptr": is_ptr,
        "is_struct": is_struct,
    }
    if pointee is not None:
        out["pointee"] = pointee
    return out


def parse_function_decl(decl: str) -> dict:
    decl = decl.strip().rstrip(";").strip()
    m = re.match(r"^(?P<ret>.+?)\b(?P<name>lr_\w+)\s*\((?P<args>.*)\)\s*$",
                 decl, re.DOTALL)
    if not m:
        raise ValueError(f"cannot parse: {decl!r}")
    ret = m.group("ret").strip()
    name = m.group("name")
    args = m.group("args").strip()
    if args == "void" or args == "":
        params = []
    else:
        params = [parse_param(p) for p in _split_top_level(args)]
    return {
        "name": name,
        "return_type": ret,
        "params": params,
    }


def collect_function_decls(text: str) -> list[dict]:
    text = _strip_comments(text)
    decls = []
    seen_names: set[str] = set()
    depth = 0
    cur = ""
    for ch in text:
        if ch == "{":
            depth += 1
            cur += ch
            continue
        if ch == "}":
            depth -= 1
            cur += ch
            continue
        if ch == ";" and depth == 0:
            cur += ch
            stmt = cur.strip()
            cur = ""
            if not stmt:
                continue
            if stmt.startswith("typedef"):
                continue
            if stmt.startswith("#"):
                continue
            if stmt.startswith("enum class") or stmt.startswith("enum "):
                continue
            if stmt.startswith("struct ") and "(" not in stmt:
                continue
            if "lr_" not in stmt:
                continue
            if "(" not in stmt:
                continue
            if not re.search(r"\blr_\w+\s*\(", stmt):
                continue
            try:
                decl = parse_function_decl(stmt)
            except ValueError:
                continue
            if decl["name"] in seen_names:
                continue
            seen_names.add(decl["name"])
            decls.append(decl)
        else:
            cur += ch
    return decls


def collect_opaque_typedefs(text: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for m in OPAQUE_TYPEDEF.finditer(text):
        out[m.group(2)] = {
            "c_struct": "Opaque" + m.group(1),
            "handle_name": m.group(2),
        }
    for m in ALIAS_TYPEDEF.finditer(text):
        target = m.group(1)
        alias = m.group(2)
        if target in out and alias not in out:
            out[alias] = {
                "c_struct": out[target]["c_struct"],
                "handle_name": alias,
                "alias_of": target,
            }
    return out


def _is_opaque_marker_struct(body: str) -> bool:
    body = body.strip()
    return bool(re.match(r"^uint8_t\s+_private\s*\[\d+\]\s*;?\s*$", body))


def collect_value_structs(text: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for m in VALUE_STRUCT_TYPEDEF.finditer(text):
        body = m.group("body")
        if _is_opaque_marker_struct(body):
            continue
        handle = "lr_" + m.group(3) + "_t"
        clean_body = re.sub(r"/\*.*?\*/", " ", body, flags=re.DOTALL)
        clean_body = re.sub(r"//[^\n]*", " ", clean_body)
        fields = []
        for field_line in clean_body.split(";"):
            field_line = field_line.strip()
            if not field_line:
                continue
            fm = re.match(
                r"^(?P<type>[A-Za-z_][A-Za-z0-9_ *\[\]]+?)\s*\b(?P<name>\w+)(?:\[(?P<n>\d+)\])?\s*$",
                field_line, re.DOTALL)
            if not fm:
                continue
            ftype = fm.group("type").strip()
            fname = fm.group("name")
            arr = fm.group("n")
            fields.append({
                "name": fname,
                "type": ftype,
                "array": int(arr) if arr is not None else None,
            })
        out[handle] = {
            "c_struct": m.group(1),
            "fields": fields,
        }
    for m in VALUE_STRUCT_ALIAS.finditer(text):
        target = m.group(1)
        alias = m.group(2)
        if target in out and alias not in out:
            out[alias] = {
                "c_struct": out[target]["c_struct"],
                "fields": out[target]["fields"],
                "alias_of": target,
            }
    return out


def collect_defines(text: str) -> list[dict]:
    out = []
    for m in DEFINE_CONST.finditer(text):
        out.append({"name": m.group(1), "value": m.group(2).strip()})
    return out


def collect_enums(text: str) -> list[dict]:
    out = []
    for m in ENUM_BLOCK.finditer(text):
        name = m.group(1)
        base = m.group(2)
        body = m.group("body")
        values = []
        body = re.sub(r"//.*", "", body)
        for piece in _split_top_level(body):
            piece = piece.strip()
            if not piece:
                continue
            em = re.match(r"^(?P<name>\w+)\s*(?:=\s*(?P<val>[^,]+?))?\s*$",
                          piece)
            if not em:
                continue
            values.append({
                "name": em.group("name"),
                "value": em.group("val"),
            })
        out.append({"name": name, "base": base, "values": values})
    return out


def main() -> int:
    text = HEADER.read_text(encoding="utf-8")
    cleaned = _strip_comments(text)
    funcs = collect_function_decls(text)
    opaques = collect_opaque_typedefs(text)
    structs = collect_value_structs(text)
    defines = collect_defines(cleaned)
    enums = collect_enums(cleaned)

    by_handle: dict[str, list[dict]] = {}
    free: list[dict] = []
    for f in funcs:
        name = f["name"]
        rest = name.removeprefix("lr_")
        owner = None
        if f["params"] and not ("raw" in f["params"][0]):
            first_type = f["params"][0].get("type", "")
            if first_type in opaques:
                owner = first_type
        if owner is None:
            for plen in range(1, len(rest.split("_")) + 1):
                candidate = "_".join(rest.split("_")[:plen])
                if "lr_" + candidate + "_t" in opaques or "lr_" + candidate + "_t" in structs:
                    owner = "lr_" + candidate + "_t"
        if owner is None:
            free.append(f)
        else:
            by_handle.setdefault(owner, []).append(f)

    out = {
        "functions": funcs,
        "opaque_types": opaques,
        "value_structs": structs,
        "defines": defines,
        "enums": enums,
        "by_handle": by_handle,
        "free_functions": free,
    }
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote {OUT}")
    print(f"  functions:     {len(funcs)}")
    print(f"  opaque types:  {len(opaques)}")
    print(f"  value structs: {len(structs)}")
    print(f"  defines:       {len(defines)}")
    print(f"  enums:         {len(enums)}")
    print(f"  by-handle:     {len(by_handle)}")
    print(f"  free:          {len(free)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
