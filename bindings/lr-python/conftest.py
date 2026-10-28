"""Pytest bootstrap for the librouting Python binding test suite.

Adds ``bindings/lr-python/src`` to ``sys.path`` so the test modules
can ``import librouting`` without each one repeating the path
manipulation that ``test_librouting.py`` historically carried inline
(``sys.path.insert(0, str(_ROOT / "bindings" / "lr-python" / "src"))``).

Also locates the workspace's built ``liblr_ffi.so`` and exports it
through the ``LIBROUTING_LIB`` environment variable when the caller
has not — the same fallback ``test_librouting.py`` performed inline,
now shared by every test module in ``bindings/lr-python/tests/`` so
``test_bfd.py`` and ``test_mpls.py`` no longer have to duplicate it.
"""

from __future__ import annotations

import os
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_SRC = _HERE / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Walk up to the workspace root (the directory containing Cargo.toml)
# so the test modules can locate the built shared library when the
# caller did not set LIBROUTING_LIB explicitly.
_ROOT = _HERE
for _ in range(8):
    if (_ROOT / "Cargo.toml").exists():
        break
    _ROOT = _ROOT.parent

if not os.environ.get("LIBROUTING_LIB"):
    for candidate in (
        _ROOT / "target" / "release" / "liblr_ffi.so",
        _ROOT / "target" / "release" / "liblr_ffi.dylib",
        _ROOT / "target" / "debug" / "liblr_ffi.so",
        _ROOT / "target" / "debug" / "liblr_ffi.dylib",
    ):
        if candidate.exists():
            os.environ["LIBROUTING_LIB"] = str(candidate)
            break
