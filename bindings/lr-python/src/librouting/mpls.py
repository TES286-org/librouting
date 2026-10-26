"""MPLS label and label-stack codec (RFC 3032 §2.1, RFC 8277 §2.2/§2.3).

Mirrors the public Rust API of ``lr_mpls::{Label, LabelStack}`` and
the C ABI surface in ``lr_ffi.h`` (``lr_mpls_*``). Resources are
released via ``__del__`` finalizers — a Python-side equivalent of
the Go runtime.SetFinalizer and the C++ RAII wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ._ffi import ffi, get_lib, alloc_bytes, free_bytes, copy_bytes
from .router import LrError, last_error


@dataclass(frozen=True)
class LabelSpec:
    """A fully-specified label ``(value, tc, ttl)``.

    Used by :meth:`LabelStack.from_labels` to build a stack from a flat
    list of label specs without round-tripping through individual
    :class:`Label` handles. Mirrors the C ``lr_mpls_label_spec_t``.
    """

    value: int
    tc: int = 0
    ttl: int = 0


def _check_rc(rc: int, what: str) -> None:
    if rc != 0:
        raise LrError(f"{what} failed (rc={rc}): {last_error()}")


class Label:
    """A single MPLS label value with its Traffic-Class and TTL fields
    (RFC 3032 §2.1).

    The bottom-of-stack bit is NOT stored on a Label — it is positional
    (1 only on the last entry of a stack) and is therefore owned by
    the :class:`LabelStack` container.
    """

    def __init__(self, value: int, *, checked: bool = False) -> None:
        """Construct a Label with default TC=0 and TTL=64.

        ``checked=True`` validates that ``value`` fits in the 20-bit
        label range (RFC 3032 §2.1); an out-of-range value raises
        :class:`LrError`.
        """
        if checked:
            ptr = get_lib().lr_mpls_label_new_checked(value)
            if ptr == ffi.NULL:
                raise LrError(
                    f"lr_mpls_label_new_checked failed: {last_error()}"
                )
        else:
            ptr = get_lib().lr_mpls_label_new(value)
            if ptr == ffi.NULL:
                raise LrError("lr_mpls_label_new returned NULL")
        self._ptr = ptr

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying handle. Safe to call multiple times."""
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_mpls_label_free(ptr)
            self._ptr = None

    def __enter__(self) -> "Label":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # The builder-style ``with_tc`` / ``with_ttl`` consume the
    # receiver in Rust; the FFI surface mirrors that by transferring
    # ownership (the input handle is freed). On the Python side we
    # hide the transfer inside these methods so the receiver's
    # ``_ptr`` is nulled out — the Python object becomes invalid, the
    # returned Label owns the new handle.

    def with_tc(self, tc: int) -> "Label":
        """Return a NEW Label with the Traffic Class set to the lower
        3 bits of ``tc`` (RFC 5462). The receiver is consumed and freed.
        """
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("Label.with_tc: handle already closed")
        old = self._ptr
        self._ptr = None
        out = get_lib().lr_mpls_label_with_tc(old, tc)
        if out == ffi.NULL:
            raise LrError(f"lr_mpls_label_with_tc failed: {last_error()}")
        wrapped = Label.__new__(Label)
        wrapped._ptr = out
        return wrapped

    def with_ttl(self, ttl: int) -> "Label":
        """Return a NEW Label with the TTL set. The receiver is consumed."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("Label.with_ttl: handle already closed")
        old = self._ptr
        self._ptr = None
        out = get_lib().lr_mpls_label_with_ttl(old, ttl)
        if out == ffi.NULL:
            raise LrError(f"lr_mpls_label_with_ttl failed: {last_error()}")
        wrapped = Label.__new__(Label)
        wrapped._ptr = out
        return wrapped

    @property
    def value(self) -> int:
        """The 20-bit label value."""
        return int(get_lib().lr_mpls_label_value(self._ptr))

    @property
    def tc(self) -> int:
        """The 3-bit Traffic Class."""
        return int(get_lib().lr_mpls_label_tc(self._ptr))

    @property
    def ttl(self) -> int:
        """The 8-bit TTL."""
        return int(get_lib().lr_mpls_label_ttl(self._ptr))

    @property
    def is_reserved(self) -> bool:
        """True when the label value is in the reserved range 0–15."""
        return bool(get_lib().lr_mpls_label_is_reserved(self._ptr))

    def encode_3octet(self, bottom: bool = False) -> bytes:
        """Encode as a single 3-octet NLRI entry (RFC 8277 §2.2/§2.3:
        ``Label(20) | Rsrv(3) | S(1)``, no TTL and no TC field).

        ``bottom`` sets the S bit.
        """
        out = ffi.new("uint8_t[3]")
        rc = get_lib().lr_mpls_label_encode_3octet(
            self._ptr, 1 if bottom else 0, out
        )
        _check_rc(rc, "lr_mpls_label_encode_3octet")
        return bytes(ffi.buffer(out, 3))

    def encode_4octet(self, bottom: bool = False) -> bytes:
        """Encode as a single 4-octet wire entry (RFC 3032 §2.1:
        label + TC + S + TTL).
        """
        out = ffi.new("uint8_t[4]")
        rc = get_lib().lr_mpls_label_encode_4octet(
            self._ptr, 1 if bottom else 0, out
        )
        _check_rc(rc, "lr_mpls_label_encode_4octet")
        return bytes(ffi.buffer(out, 4))


class LabelStack:
    """An ordered MPLS label stack (RFC 3032 §2.1).

    The first element of the list is the *top* of the stack — the
    label that is examined first when a labelled packet arrives. The
    bottom-of-stack bit is set automatically on the last entry when
    encoding and is stripped when decoding.
    """

    def __init__(self) -> None:
        """Construct an empty stack. Useful as a builder starting point;
        not a valid wire value (an MPLS frame must carry at least one
        label).
        """
        ptr = get_lib().lr_mpls_label_stack_new()
        if ptr == ffi.NULL:
            raise LrError("lr_mpls_label_stack_new returned NULL")
        self._ptr = ptr

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying handle. Safe to call multiple times."""
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_mpls_label_stack_free(ptr)
            self._ptr = None

    def __enter__(self) -> "LabelStack":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def from_values(cls, values: List[int]) -> "LabelStack":
        """Build a stack from a list of label values (TC=0, TTL=64)."""
        s = cls()
        if not values:
            return s
        arr = ffi.new(f"uint32_t[{len(values)}]", values)
        ptr = get_lib().lr_mpls_label_stack_from_values(arr, len(values))
        if ptr == ffi.NULL:
            raise LrError(f"lr_mpls_label_stack_from_values: {last_error()}")
        # Replace the empty stack we just allocated with the populated one.
        get_lib().lr_mpls_label_stack_free(s._ptr)
        s._ptr = ptr
        return s

    @classmethod
    def from_labels(cls, labels: List[LabelSpec]) -> "LabelStack":
        """Build a stack from a list of fully-specified labels."""
        s = cls()
        if not labels:
            return s
        arr = ffi.new(f"struct lr_mpls_label_spec_t[{len(labels)}]")
        for i, l in enumerate(labels):
            arr[i].value = l.value
            arr[i].tc = l.tc
            arr[i].ttl = l.ttl
        ptr = get_lib().lr_mpls_label_stack_from_labels(arr, len(labels))
        if ptr == ffi.NULL:
            raise LrError(f"lr_mpls_label_stack_from_labels: {last_error()}")
        get_lib().lr_mpls_label_stack_free(s._ptr)
        s._ptr = ptr
        return s

    @classmethod
    def decode_4octet(cls, data: bytes) -> "LabelStack":
        """Decode the 4-octet-per-entry wire form (RFC 3032 §2.1).
        The S bit must mark the bottom entry only.
        """
        if not data:
            raise LrError("LabelStack.decode_4octet: empty input")
        out = ffi.new("lr_mpls_label_stack_t*")
        rc = get_lib().lr_mpls_label_stack_decode_4octet(
            data, len(data), out
        )
        _check_rc(rc, "lr_mpls_label_stack_decode_4octet")
        if out[0] == ffi.NULL:
            raise LrError(
                f"lr_mpls_label_stack_decode_4octet: {last_error()}"
            )
        s = cls.__new__(LabelStack)
        s._ptr = out[0]
        return s

    @classmethod
    def decode_3octet(cls, data: bytes) -> "LabelStack":
        """Decode the 3-octet-per-entry NLRI form (RFC 8277 §2.2/§2.3).
        TTL is not carried in this form and defaults to 0.
        """
        if not data:
            raise LrError("LabelStack.decode_3octet: empty input")
        out = ffi.new("lr_mpls_label_stack_t*")
        rc = get_lib().lr_mpls_label_stack_decode_3octet(
            data, len(data), out
        )
        _check_rc(rc, "lr_mpls_label_stack_decode_3octet")
        if out[0] == ffi.NULL:
            raise LrError(
                f"lr_mpls_label_stack_decode_3octet: {last_error()}"
            )
        s = cls.__new__(LabelStack)
        s._ptr = out[0]
        return s

    def __len__(self) -> int:
        return int(get_lib().lr_mpls_label_stack_len(self._ptr))

    def is_empty(self) -> bool:
        return bool(get_lib().lr_mpls_label_stack_is_empty(self._ptr))

    def at(self, index: int) -> LabelSpec:
        """Return the label at ``index`` as a fully-specified spec.

        Raises :class:`LrError` when the index is out of range.
        """
        v = ffi.new("uint32_t*")
        tc = ffi.new("uint8_t*")
        ttl = ffi.new("uint8_t*")
        rc = get_lib().lr_mpls_label_stack_at(self._ptr, index, v, tc, ttl)
        _check_rc(rc, "lr_mpls_label_stack_at")
        return LabelSpec(value=int(v[0]), tc=int(tc[0]), ttl=int(ttl[0]))

    def labels(self) -> List[LabelSpec]:
        """Return the full list of label specs in stack order (top first)."""
        return [self.at(i) for i in range(len(self))]

    def push(self, label: Label) -> None:
        """Push a label onto the top of the stack. The label handle is
        consumed and freed.
        """
        if label._ptr is None or label._ptr == ffi.NULL:
            raise LrError("LabelStack.push: label already closed")
        ptr = label._ptr
        label._ptr = None
        rc = get_lib().lr_mpls_label_stack_push(self._ptr, ptr)
        _check_rc(rc, "lr_mpls_label_stack_push")

    def push_bottom(self, label: Label) -> None:
        """Push a label onto the bottom of the stack. The label handle is
        consumed and freed.
        """
        if label._ptr is None or label._ptr == ffi.NULL:
            raise LrError("LabelStack.push_bottom: label already closed")
        ptr = label._ptr
        label._ptr = None
        rc = get_lib().lr_mpls_label_stack_push_bottom(self._ptr, ptr)
        _check_rc(rc, "lr_mpls_label_stack_push_bottom")

    def pop(self) -> bool:
        """Pop the top label. Returns True when a label was popped, False
        when the stack was already empty.
        """
        rc = get_lib().lr_mpls_label_stack_pop(self._ptr)
        if rc < 0:
            raise LrError(
                f"lr_mpls_label_stack_pop failed (rc={rc}): {last_error()}"
            )
        return rc == 1

    def encode_4octet(self) -> bytes:
        """Encode the stack as the 4-octet-per-entry wire form (RFC 3032
        §2.1). The S bit is set on the last entry.
        """
        b = alloc_bytes()
        rc = get_lib().lr_mpls_label_stack_encode_4octet(self._ptr, b)
        _check_rc(rc, "lr_mpls_label_stack_encode_4octet")
        try:
            return copy_bytes(b)
        finally:
            free_bytes(b)

    def encode_3octet(self) -> bytes:
        """Encode the stack as the 3-octet-per-entry NLRI form (RFC 8277
        §2.2/§2.3).
        """
        b = alloc_bytes()
        rc = get_lib().lr_mpls_label_stack_encode_3octet(self._ptr, b)
        _check_rc(rc, "lr_mpls_label_stack_encode_3octet")
        try:
            return copy_bytes(b)
        finally:
            free_bytes(b)
