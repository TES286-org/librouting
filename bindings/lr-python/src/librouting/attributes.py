"""Generic ordered attribute set — mirrors ``lr_core::attr::Attributes``.

The :class:`Attributes` container is the generic typed-attribute carrier
that backs every ``Route::attributes`` field. BGP path attributes
(RFC 4271 §5.1) live in it under their IANA wire tag, OSPF/Babel
extra-metadata live in it under private tags, and the policy filter
DSL reads/writes through the typed readers. This module exposes the
C ABI surface (:mod:`crates.lr_ffi.src.attributes`) so a Python
embedder can build, populate, read and round-trip an attribute set
without dropping down to the raw CFFI surface.

The :func:`apply_set_checked` function mirrors
``lr_policy::action::apply_set_checked``: it applies one
:class:`SetAction` to a :class:`~librouting.policy.Route` and returns
the fail-closed verdict (``ApplySetError``). The four BGP-specific
SetActions return ``REQUIRES_BGP_FEATURE`` when the underlying
``lr-policy`` crate is built without the ``bgp`` feature.
"""

from __future__ import annotations

from ._ffi import ffi, get_lib
from .router import LrError, last_error

__all__ = [
    "Attributes",
    "ApplySetError",
    "apply_set_checked",
    "apply_set_error_name",
    # SetAction discriminants (mirror LR_SET_*).
    "SET_LOCAL_PREF",
    "SET_MED",
    "SET_NEXT_HOP",
    "SET_PREPEND_AS",
    "SET_ADD_COMMUNITY",
    "SET_METRIC",
    "SET_TAG",
    # ApplySetError discriminants (mirror LR_APPLY_SET_ERROR_*).
    "APPLY_SET_ERROR_OK",
    "APPLY_SET_ERROR_LOCAL_PREF_NO_BGP",
    "APPLY_SET_ERROR_MED_NO_BGP",
    "APPLY_SET_ERROR_PREPEND_AS_NO_BGP",
    "APPLY_SET_ERROR_ADD_COMMUNITY_NO_BGP",
    "APPLY_SET_ERROR_NOT_WIRED",
    "APPLY_SET_ERROR_UNKNOWN",
]

# SetAction discriminants (LR_SET_*). Mirrors the constants defined in
# crates/lr-ffi/src/policy_objects.rs and bindings/lr-python policy.py —
# re-exported here so a single ``from librouting.attributes import *``
# gives embedders everything they need to drive apply_set_checked.
SET_LOCAL_PREF = 0
SET_MED = 1
SET_NEXT_HOP = 2
SET_PREPEND_AS = 3
SET_ADD_COMMUNITY = 4
SET_METRIC = 5
SET_TAG = 6

# ApplySetError discriminants (LR_APPLY_SET_ERROR_*). Mirrors the
# constants defined in crates/lr-ffi/src/policy_batch.rs. The OK case
# is 0; the four ``*_NO_BGP`` cases correspond to the four BGP-specific
# SetActions when the lr-policy crate is built without the ``bgp``
# feature (fail-closed).
APPLY_SET_ERROR_OK = 0
APPLY_SET_ERROR_LOCAL_PREF_NO_BGP = 1
APPLY_SET_ERROR_MED_NO_BGP = 2
APPLY_SET_ERROR_PREPEND_AS_NO_BGP = 3
APPLY_SET_ERROR_ADD_COMMUNITY_NO_BGP = 4
APPLY_SET_ERROR_NOT_WIRED = 5
APPLY_SET_ERROR_UNKNOWN = 6


class ApplySetError(Exception):
    """Raised by :func:`apply_set_checked` when the action cannot be
    applied. The string form carries the C ABI's error name (e.g.
    ``"SetLocalPref needs bgp feature"``). Inspect :attr:`code` for the
    raw ``LR_APPLY_SET_ERROR_*`` discriminant."""

    def __init__(self, code: int):
        self.code = int(code)
        super().__init__(apply_set_error_name(self.code))


def apply_set_error_name(code: int) -> str:
    """Look up the ``ApplySetError`` discriminant name. Mirrors
    ``lr_apply_set_error_name`` in the C ABI."""
    ptr = get_lib().lr_apply_set_error_name(int(code))
    if ptr == ffi.NULL:
        return f"unknown ApplySetError code {code}"
    return ffi.string(ptr).decode("utf-8", errors="replace")


def apply_set_checked(route, set_kind: int, arg1: int = 0, arg2: int = 0, arg3: int = 0) -> None:
    """Apply a ``SetAction`` to ``route`` via the fail-closed
    ``apply_set_checked`` surface. Mirrors
    ``lr_policy::action::apply_set_checked``.

    Parameters
    ----------
    route:
        A :class:`~librouting.policy.Route` instance. The action is
        applied in-place to the route's attribute set.
    set_kind:
        One of ``SET_LOCAL_PREF`` / ``SET_MED`` / ``SET_NEXT_HOP`` /
        ``SET_PREPEND_AS`` / ``SET_ADD_COMMUNITY`` / ``SET_METRIC`` /
        ``SET_TAG``.
    arg1, arg2, arg3:
        Per-action payload. The shape follows the Rust
        ``SetAction`` variant:

        - ``SET_LOCAL_PREF``: ``arg1 = value`` (u32)
        - ``SET_MED``: ``arg1 = value`` (u32)
        - ``SET_PREPEND_AS``: ``arg1 = asn`` (u32)
        - ``SET_ADD_COMMUNITY``: ``arg1 = asn`` (u32), ``arg2 = local`` (u16)
        - ``SET_METRIC``: ``arg1 = value`` (u32)
        - ``SET_TAG``: ``arg1 = tag`` (u32)

    Raises
    ------
    ApplySetError
        When the action cannot be applied (e.g. a BGP-specific action
        against a no-``bgp`` build of lr-policy).
    """
    code = get_lib().lr_apply_set_checked(
        route._ptr, int(set_kind), int(arg1), int(arg2), int(arg3)
    )
    if code != APPLY_SET_ERROR_OK:
        raise ApplySetError(code)


class Attributes:
    """An owned generic attribute-set handle.

    Wraps the boxed ``lr_core::attr::Attributes`` so a Python embedder
    can build, populate and read a typed-attribute container using the
    same surface the Rust crate exposes. The container is a BTreeMap
    keyed by 8-bit tag — insertion replaces any existing entry for the
    same tag, iteration order is ascending by tag.
    """

    def __init__(self, _ptr=None):
        if _ptr is None:
            ptr = get_lib().lr_attributes_new()
            if ptr == ffi.NULL:
                raise LrError(f"lr_attributes_new: {last_error()}")
            self._ptr = ptr
        else:
            self._ptr = _ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None:
            get_lib().lr_attributes_free(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def __len__(self) -> int:
        return int(get_lib().lr_attributes_len(self._ptr))

    def __bool__(self) -> bool:
        return self.__len__() > 0

    def is_empty(self) -> bool:
        """True when the set holds no attributes."""
        return bool(get_lib().lr_attributes_is_empty(self._ptr))

    def insert(self, tag: int, flags: int, value: bytes) -> None:
        """Insert / replace one attribute by tag. ``value`` is the raw
        attribute payload (any bytes-like object; empty bytes insert
        the tag with no payload)."""
        v = bytes(value)
        n = len(v)
        rc = get_lib().lr_attributes_insert(
            self._ptr, int(tag), int(flags),
            ffi.from_buffer("uint8_t[]", v) if n else ffi.NULL,
            n,
        )
        if rc != 0:
            raise LrError(f"lr_attributes_insert failed (rc={rc}): {last_error()}")

    def get(self, tag: int) -> tuple[int, bytes] | None:
        """Read one attribute by tag. Returns ``(flags, value_bytes)``
        when present, ``None`` when the tag is absent. Allocates a
        Python-side buffer big enough for the value — for the typed
        fast paths use :meth:`get_u32_be` / :meth:`get_u64_be` /
        :meth:`get_u8` instead."""
        flags = ffi.new("uint8_t*")
        # Two-pass: discover the length, then read it.
        n = get_lib().lr_attributes_get(self._ptr, int(tag), flags, ffi.NULL, 0)
        if n < 0:
            # -1 LR_ERR_NULL (null handle / out pointer) — impossible
            # here because we always pass a valid handle and a real
            # flags pointer. -2 LR_ERR_INVALID_HANDLE means absent.
            return None
        n = int(n)
        if n == 0:
            return (int(flags[0]), b"")
        buf = ffi.new(f"uint8_t[{n}]")
        got = get_lib().lr_attributes_get(self._ptr, int(tag), flags, buf, n)
        if got < 0:
            return None
        return (int(flags[0]), bytes(buf[0:int(got)]))

    def get_u32_be(self, tag: int) -> int:
        """Read a 4-byte big-endian unsigned integer attribute.
        Returns 0 when the tag is absent or the value is not exactly
        4 bytes long — use :meth:`get` when the distinction matters."""
        return int(get_lib().lr_attributes_get_u32_be(self._ptr, int(tag)))

    def get_u64_be(self, tag: int) -> int:
        """Read an 8-byte big-endian unsigned integer attribute.
        Returns 0 when the tag is absent or the value is not exactly
        8 bytes long."""
        return int(get_lib().lr_attributes_get_u64_be(self._ptr, int(tag)))

    def get_u8(self, tag: int) -> int:
        """Read a 1-byte unsigned integer attribute. Returns 0 when
        the tag is absent."""
        return int(get_lib().lr_attributes_get_u8(self._ptr, int(tag)))

    def remove(self, tag: int) -> bool:
        """Remove one attribute by tag. Returns ``True`` when the
        attribute was present (and is now removed), ``False`` when it
        was not in the set."""
        rc = get_lib().lr_attributes_remove(self._ptr, int(tag))
        if rc < 0:
            raise LrError(f"lr_attributes_remove failed (rc={rc}): {last_error()}")
        return bool(rc)

    def at(self, index: int) -> tuple[int, int, bytes] | None:
        """Read one attribute by index. Returns ``(tag, flags,
        value_bytes)`` when the index is in range, ``None`` otherwise.
        Iteration order is ascending by tag (BTreeMap order)."""
        tag = ffi.new("uint8_t*")
        flags = ffi.new("uint8_t*")
        # Discover length first.
        n = get_lib().lr_attributes_at(
            self._ptr, int(index), tag, flags, ffi.NULL, 0
        )
        if n < 0:
            return None
        n = int(n)
        if n == 0:
            return (int(tag[0]), int(flags[0]), b"")
        buf = ffi.new(f"uint8_t[{n}]")
        got = get_lib().lr_attributes_at(
            self._ptr, int(index), tag, flags, buf, n
        )
        if got < 0:
            return None
        return (int(tag[0]), int(flags[0]), bytes(buf[0:int(got)]))

    def __iter__(self):
        """Yield ``(tag, flags, value_bytes)`` for every attribute in
        ascending tag order."""
        n = self.__len__()
        for i in range(n):
            entry = self.at(i)
            if entry is None:
                break
            yield entry
