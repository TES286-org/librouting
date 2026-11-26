#!/usr/bin/env python3
"""Cross-check the cbindgen header against the Rust export surface.

`abi_freeze_check.py` compares two header versions; `abi_coverage.py`
compares symbol *names* across binding layers. Neither answers the
question that actually bit the C ABI: "does the header contain every
constant and function the Rust crate exports, with a value cbindgen
could evaluate?"

cbindgen silently drops or mangles exports in two known ways:

* a ``pub extern "C" fn`` whose signature carries a by-value array
  (``[u8; 4]``) never reaches the header;
* a ``pub const`` whose value references another crate's item (or a
  cross-crate enum cast) is emitted as a bare identifier
  (``#define LR_BMP_VERSION VERSION``) or dropped entirely when the
  same name is defined twice.

This script walks the Rust sources for ``#[no_mangle] pub extern "C"``
functions and ``pub const LR_*`` items, walks the header for
declarations and ``#define``s, and reports every mismatch:

* functions exported from Rust but missing from the header;
* constants exported from Rust but missing from the header;
* ``#define``s whose value is a bare identifier (an unevaluated
  cross-crate reference);
* Rust-level duplicate names (two modules exporting the same
  ``pub const``), which make header emission order-dependent.

Exit code 1 on any finding. Run from the repository root:
``python3 scripts/abi_export_check.py``
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FFI_SRC = ROOT / "crates" / "lr-ffi" / "src"
HEADER = ROOT / "include" / "lr_ffi.h"

# `pub extern "C" fn name(` or `pub unsafe extern "C" fn name(`.
RUST_FN = re.compile(
    r"pub\s+(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+(lr_\w+)\s*\(",
)
# `pub const NAME: type = VALUE;` — value captured up to the semicolon.
RUST_CONST = re.compile(
    r"pub\s+const\s+(LR_\w+)\s*:\s*([\w:]+)\s*=\s*([^;]+);",
)
# A by-value array parameter inside a Rust signature.
RUST_ARRAY_PARAM = re.compile(r":\s*\[\w+;\s*\d+\]")

# Header function declaration: any `lr_name(` occurrence — comments
# are stripped first so doc references do not count. The capture
# excludes the `lr_` prefix, so it is re-attached when building the
# symbol set (the Rust walk yields full names).
HEADER_FN = re.compile(r"\blr_(\w+)\s*\(")
# Header constant: `#define LR_NAME <value>`.
HEADER_DEFINE = re.compile(r"^#define\s+(LR_\w+)\s+(.+?)\s*$", re.MULTILINE)


def strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def rust_exports() -> tuple[dict[str, dict], dict[str, list[dict]]]:
    """Collect exported functions and constants from the FFI crate."""
    functions: dict[str, dict] = {}
    constants: dict[str, list[dict]] = {}
    for path in sorted(FFI_SRC.glob("*.rs")):
        text = path.read_text(encoding="utf-8")
        # Only the non-test portion counts as the export surface: the
        # `#[cfg(test)] mod tests` blocks at the bottom of each file
        # stay out of the walk.
        body = re.split(r"\n#\[cfg\(test\)\]", text, maxsplit=1)[0]
        for m in RUST_FN.finditer(body):
            name = m.group(1)
            # Grab the full signature (up to the opening brace).
            tail = body[m.end():m.end() + 2000]
            sig = tail.split("{", 1)[0]
            functions[name] = {
                "file": path.name,
                "array_param": bool(RUST_ARRAY_PARAM.search(sig)),
            }
        for m in RUST_CONST.finditer(body):
            constants.setdefault(m.group(1), []).append(
                {
                    "file": path.name,
                    "type": m.group(2),
                    "value": m.group(3).strip(),
                }
            )
    return functions, constants


def header_symbols() -> tuple[set[str], dict[str, str]]:
    """Collect declared function names and #define constants."""
    text = strip_comments(HEADER.read_text(encoding="utf-8"))
    functions = {"lr_" + m.group(1) for m in HEADER_FN.finditer(text)}
    defines = {m.group(1): m.group(2) for m in HEADER_DEFINE.finditer(text)}
    return functions, defines


def main() -> int:
    rust_fns, rust_consts = rust_exports()
    header_fns, header_defines = header_symbols()

    problems: list[str] = []

    # 1. Functions exported from Rust but absent from the header.
    for name, info in sorted(rust_fns.items()):
        if name not in header_fns:
            why = (
                " (by-value array parameter — cbindgen drops it)"
                if info["array_param"]
                else ""
            )
            problems.append(
                f"function `{name}` exported from {info['file']} is missing"
                f" from {HEADER.name}{why}"
            )

    # 2. Constants exported from Rust but absent from the header.
    for name, defs in sorted(rust_consts.items()):
        if name not in header_defines:
            problems.append(
                f"constant `{name}` exported from {defs[0]['file']} is"
                f" missing from {HEADER.name}"
            )

    # 3. Rust-level duplicate names: header emission becomes
    #    order-dependent, and cbindgen may drop both.
    for name, defs in sorted(rust_consts.items()):
        if len(defs) > 1:
            values = {d["value"] for d in defs}
            files = ", ".join(sorted({d["file"] for d in defs}))
            detail = (
                "conflicting values" if len(values) > 1 else "identical values"
            )
            problems.append(
                f"constant `{name}` defined in multiple modules ({files};"
                f" {detail}: "
                + " vs ".join(f"`{v}`" for v in sorted(values))
                + ") — keep one definition"
            )

    # 4. #defines whose value is a bare identifier: an unevaluated
    #    cross-crate reference no C compiler can resolve.
    raw_header = HEADER.read_text(encoding="utf-8")
    for name, value in sorted(header_defines.items()):
        if re.fullmatch(r"[A-Za-z_]\w*", value) and not value.startswith("0x"):
            # A bare identifier is only meaningful if it is a macro
            # defined elsewhere in the same header.
            if f"#define {value} " not in raw_header:
                problems.append(
                    f"#define {name} {value} — the value is an undefined"
                    " bare identifier (a cross-crate constant cbindgen"
                    " could not evaluate)"
                )

    if problems:
        print(f"ABI export check found {len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(
        f"ABI export check clean: {len(rust_fns)} exported functions and"
        f" {len(rust_consts)} constants all present and evaluable in"
        f" {HEADER.name}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
