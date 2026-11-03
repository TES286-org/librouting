"""Pytest smoke suite for the auto-generated ``librouting.generated`` module.

The previous round of the FFI bindings parity work (issue #92) added a
mechanical auto-gen layer in ``bindings/lr-python/src/librouting/generated.py``
covering every ``lr_*`` C ABI entry point that did not already have a
hand-written Python wrapper. The auto-gen layer had no test coverage of
its own — this module closes that gap:

- ``test_generated_module_imports`` — the module loads cleanly.
- ``test_generated_module_does_not_shadow_last_error`` — the
  ``last_error`` symbol imported from ``_ffi`` is the string-decoding
  helper, NOT a thin pass-through to ``_lib.lr_last_error()`` that
  would return a raw ``char *`` cdata.
- ``test_every_class_has_raii_lifecycle`` — every generated class
  exposes ``__slots__``, ``__init__(ptr)``, ``__wrap__``, ``__del__``,
  and the ``ptr`` property.
- ``test_every_constructor_round_trips`` — every generated class
  that has a ``new`` classmethod can be constructed with sensible
  default-argument values; the returned object holds a non-NULL
  pointer; ``free`` clears the pointer; calling ``free`` a second
  time and ``__del__`` after ``free`` are safe no-ops. Constructors
  that reject the defaults (e.g. BabelMacKey with algorithm 0) must
  surface a real ``LrError`` carrying a Python ``str`` message, not
  a ``<cdata 'char *' 0x...>`` repr.
- ``test_lerror_carries_real_message`` — when a generated constructor
  fails (BabelMacKey with an unknown algorithm id 0), the resulting
  ``LrError`` carries the actual C-side error string.
- ``test_generated_classes_do_not_collide_with_hand_written`` — no
  class name appears in both the generated module and a hand-written
  module (the generator skips existing classes).

The defaults used by ``test_every_constructor_round_trips`` come from
the C ABI signatures in ``scripts/abi.json`` — every scalar defaults
to 0, every ``const uint8_t *`` / ``const char *`` defaults to ``b''``
(which CFFI maps to a zero-length buffer). The test skips constructors
whose first non-receiver parameter is an opaque handle (those need a
complex dependency and are exercised by the hand-written tests).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from librouting._ffi import ffi
from librouting._ffi import last_error as _ffi_last_error
from librouting import generated as gen
from librouting.router import LrError

_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_ABI = json.loads((_ROOT / "scripts" / "abi.json").read_text(encoding="utf-8"))
_FUNCS_BY_NAME = {f["name"]: f for f in _ABI["functions"]}
_GEN_SRC = (_ROOT / "bindings" / "lr-python" / "src" / "librouting" / "generated.py").read_text(encoding="utf-8")

_CLASS_RE = re.compile(r"^class (\w+):", re.MULTILINE)
_CLASS_NAMES = [m.group(1) for m in _CLASS_RE.finditer(_GEN_SRC)]


def _camel_to_handle(cls_name: str) -> str:
    parts = re.findall(r"[A-Z][^A-Z]*", cls_name)
    snake = "_".join(p.lower() for p in parts)
    return f"lr_{snake}_t"


def _constructor_signature(cls_name: str) -> tuple[str, list[dict]] | None:
    """Return (c_fn_name, params) for the class's ``new`` constructor, or None."""
    handle = _camel_to_handle(cls_name)
    new_sym = f"lr_{handle[3:-2]}_new"
    if new_sym in _FUNCS_BY_NAME:
        return new_sym, _FUNCS_BY_NAME[new_sym]["params"]
    return None


def _default_arg(c_type: str) -> object:
    """Sensible default value for a C ABI parameter type."""
    if c_type.endswith("*"):
        # Pointer-typed param: pass empty bytes (CFFI maps to zero-length buffer).
        if c_type.startswith("const uint8_t") or c_type.startswith("const char"):
            return b""
        return ffi.NULL
    if c_type in (
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t",
        "uintptr_t", "size_t",
    ):
        return 0
    if c_type == "bool":
        return False
    return None  # unknown — caller should skip


def _is_handle_param(p: dict) -> bool:
    t = p.get("type", "")
    return t.startswith("lr_") and t.endswith("_t")


# ---------------------------------------------------------------------------
# Module-level invariants
# ---------------------------------------------------------------------------


def test_generated_module_imports():
    """The generated module loads cleanly and exposes at least 50 classes."""
    assert hasattr(gen, "_lib"), "generated module should expose _lib"
    assert hasattr(gen, "LrError"), "generated module imports LrError"
    assert len(_CLASS_NAMES) >= 50, (
        f"expected at least 50 generated classes, got {len(_CLASS_NAMES)}"
    )


def test_generated_module_does_not_shadow_last_error():
    """``last_error`` in the generated module must be the ``_ffi.last_error``
    helper that decodes the C string, not a thin pass-through that would
    return a raw ``char *`` cdata (which would wrap as a useless
    ``<cdata 'char *' 0x...>`` repr)."""
    assert gen.last_error is _ffi_last_error, (
        "gen.last_error must be the imported _ffi.last_error helper; "
        "if this fails, gen_python.py emitted a shadowing wrapper for "
        "lr_last_error (regression)."
    )


def test_lerror_carries_real_message():
    """An LrError raised from a generated constructor must carry a real
    Python string message, not a <cdata 'char *' 0x...> repr."""
    # BabelMacKey with algorithm 0 is rejected by the C ABI:
    # "unknown Babel MAC algorithm id 0".
    with pytest.raises(LrError) as excinfo:
        gen.BabelMacKey.new(0, b"\x01\x02\x03", 3)
    msg = excinfo.value.args[0]
    assert isinstance(msg, str), (
        f"LrError.args[0] must be str, got {type(msg).__name__}: {msg!r}"
    )
    assert "unknown Babel MAC algorithm" in msg, (
        f"LrError message must mention the rejected algorithm; got: {msg!r}"
    )


def test_generated_classes_do_not_collide_with_hand_written():
    """No class name appears in both the generated module and a hand-written
    module — the generator's existing_python_classes() filter excludes
    hand-written names, so a collision would indicate a generator bug."""
    hand_written = set()
    src_dir = _ROOT / "bindings" / "lr-python" / "src" / "librouting"
    for path in sorted(src_dir.glob("*.py")):
        if path.name == "generated.py":
            continue
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"^class\s+(\w+)\b", text, re.MULTILINE):
            hand_written.add(m.group(1))
    overlap = hand_written & set(_CLASS_NAMES)
    assert not overlap, (
        f"Class names appear in both hand-written and generated modules: {overlap}"
    )


# ---------------------------------------------------------------------------
# Per-class invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cls_name", _CLASS_NAMES)
def test_every_class_has_raii_lifecycle(cls_name):
    """Every generated class has the RAII lifecycle methods/properties that
    the auto-gen template emits: __slots__, __init__, __wrap__, __del__,
    and the ptr property. Classes whose handle has a recognized free
    function also expose ``free``."""
    cls = getattr(gen, cls_name)
    assert hasattr(cls, "__slots__"), f"{cls_name} missing __slots__"
    assert "_ptr" in cls.__slots__, f"{cls_name} __slots__ missing _ptr"
    assert hasattr(cls, "__init__"), f"{cls_name} missing __init__"
    assert hasattr(cls, "__wrap__"), f"{cls_name} missing __wrap__"
    assert hasattr(cls, "__del__"), f"{cls_name} missing __del__"
    assert hasattr(cls, "ptr"), f"{cls_name} missing ptr property"
    # __wrap__ must return an instance without calling __init__
    inst = cls.__wrap__(ffi.NULL)
    assert isinstance(inst, cls), f"{cls_name}.__wrap__ returned {type(inst)}"
    # __del__ must be safe on a NULL handle (no-op)
    inst.__del__()


@pytest.mark.parametrize("cls_name", _CLASS_NAMES)
def test_every_constructor_round_trips(cls_name):
    """Every generated class with a ``new`` classmethod can be constructed
    with sensible defaults, holds a non-NULL pointer after construction,
    and the ``free`` method clears the pointer. Constructors that reject
    the defaults must surface a real LrError with a str message."""
    sig = _constructor_signature(cls_name)
    if sig is None:
        pytest.skip(f"{cls_name} has no constructor")
    new_sym, params = sig

    # Determine Python args from the C signature. Skip the test if any
    # parameter is an opaque handle (those need a complex dependency).
    args = []
    for p in params:
        if "raw" in p:
            continue
        if _is_handle_param(p):
            pytest.skip(f"{cls_name} constructor needs handle arg {p.get('name')}")
        v = _default_arg(p.get("type", ""))
        if v is None:
            pytest.skip(f"{cls_name} constructor has unknown arg type {p.get('type')}")
        args.append(v)

    cls = getattr(gen, cls_name)
    try:
        inst = cls.new(*args)
    except LrError as e:
        # The C ABI rejected the default args (e.g. BabelMacKey with
        # algorithm 0). That's fine — the wrapper correctly surfaced the
        # error. Just verify the error message is a real string.
        assert isinstance(e.args[0], str), (
            f"{cls_name}.new raised LrError with non-str args: {e.args!r}"
        )
        return

    # The constructor must have returned an instance with a non-NULL ptr.
    assert isinstance(inst, cls), f"{cls_name}.new returned {type(inst)}"
    assert inst.ptr != ffi.NULL, f"{cls_name}.new returned a NULL handle"

    # If the class exposes free(), calling it must clear the ptr.
    if hasattr(inst, "free"):
        inst.free()
        assert inst.ptr is None or inst.ptr == ffi.NULL, (
            f"{cls_name}.free() did not clear the ptr: {inst.ptr!r}"
        )
        # Calling free() a second time must be safe (no-op).
        inst.free()

    # __del__ after free() must be safe (no-op).
    inst.__del__()


def test_every_no_constructor_class_is_importable():
    """Sanity check for classes without a constructor: just verify
    they're importable and have the RAII lifecycle. Tests one
    representative (the first no-constructor class)."""
    no_ctor = []
    for cls_name in _CLASS_NAMES:
        if _constructor_signature(cls_name) is None:
            no_ctor.append(cls_name)
    if not no_ctor:
        pytest.skip("every generated class has a constructor")
    # Pick the first no-constructor class
    cls_name = no_ctor[0]
    cls = getattr(gen, cls_name)
    inst = cls.__wrap__(ffi.NULL)
    assert inst.ptr == ffi.NULL
    inst.__del__()  # safe on NULL
