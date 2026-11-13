#!/usr/bin/env python3
"""Remove the lr_roa_store_replace_static_from_text C ABI declaration
from the CFFI header snippet in bindings/lr-python/src/librouting/_ffi.py
and remove the function + define entries from scripts/abi.json.

This is a follow-up to issue #100: the replace_static_from_text FFI
surface is removed because the jq/awk transform feature is now a
daemon-internal concern, not a library API.
"""
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

def strip_ffi_decl() -> None:
    p = REPO / "bindings/lr-python/src/librouting/_ffi.py"
    text = p.read_text()
    # The declaration block looks like:
    #   int32_t lr_roa_store_replace_static_from_text(
    #       lr_roa_store_t s,
    #       const uint8_t *text,
    #       uintptr_t len,
    #       uint8_t format);
    pattern = re.compile(
        r"\n\s*int32_t lr_roa_store_replace_static_from_text\(\s*\n"
        r"\s*lr_roa_store_t s,\s*\n"
        r"\s*const uint8_t \*text,\s*\n"
        r"\s*uintptr_t len,\s*\n"
        r"\s*uint8_t format\);\s*\n",
        re.MULTILINE,
    )
    new = pattern.sub("\n", text)
    if new == text:
        print("WARN: _ffi.py pattern did not match", file=sys.stderr)
    else:
        p.write_text(new)
        print(f"stripped {p}: {len(text) - len(new)} bytes")

def strip_abi_json() -> None:
    p = REPO / "scripts/abi.json"
    data = json.loads(p.read_text())
    # Remove from functions list
    before_f = len(data.get("functions", []))
    data["functions"] = [
        f for f in data.get("functions", [])
        if f.get("name") != "lr_roa_store_replace_static_from_text"
    ]
    after_f = len(data["functions"])
    # Remove from by_handle.lr_roa_store_t
    if "by_handle" in data and "lr_roa_store_t" in data["by_handle"]:
        before_h = len(data["by_handle"]["lr_roa_store_t"])
        data["by_handle"]["lr_roa_store_t"] = [
            f for f in data["by_handle"]["lr_roa_store_t"]
            if f.get("name") != "lr_roa_store_replace_static_from_text"
        ]
        after_h = len(data["by_handle"]["lr_roa_store_t"])
        print(f"by_handle.lr_roa_store_t: {before_h} -> {after_h}")
    print(f"functions: {before_f} -> {after_f}")
    # Remove the four LR_ROA_FORMAT_* defines
    before_d = len(data.get("defines", []))
    data["defines"] = [
        d for d in data.get("defines", [])
        if d.get("name") not in (
            "LR_ROA_FORMAT_NATIVE",
            "LR_ROA_FORMAT_BIRD",
            "LR_ROA_FORMAT_JSON",
            "LR_ROA_FORMAT_CSV",
        )
    ]
    after_d = len(data["defines"])
    print(f"defines: {before_d} -> {after_d}")
    p.write_text(json.dumps(data, indent=2) + "\n")
    print(f"wrote {p}")

if __name__ == "__main__":
    strip_ffi_decl()
    strip_abi_json()
