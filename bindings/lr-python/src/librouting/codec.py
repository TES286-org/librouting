"""Layer-1 codec helpers."""

from __future__ import annotations

from ._ffi import ffi, get_lib, alloc_bytes, free_bytes, copy_bytes
from .router import LrError, last_error


def _run_decode(fn, data: bytes) -> bytes:
    if not data:
        raise LrError("empty data")
    b = alloc_bytes()
    rc = fn(data, len(data), b)
    if rc != 0:
        raise LrError(f"decode failed (rc={rc}): {last_error()}")
    try:
        return copy_bytes(b)
    finally:
        free_bytes(b)


def _run_encode(fn) -> bytes:
    b = alloc_bytes()
    rc = fn(b)
    if rc != 0:
        raise LrError(f"encode failed (rc={rc}): {last_error()}")
    try:
        return copy_bytes(b)
    finally:
        free_bytes(b)


def encode_keepalive() -> bytes:
    return _run_encode(get_lib().lr_bgp_encode_keepalive)


def decode_bgp(data: bytes) -> bytes:
    return _run_decode(get_lib().lr_bgp_decode, data)


def decode_ospf_v2(data: bytes) -> bytes:
    return _run_decode(get_lib().lr_ospf_decode_v2, data)


def decode_babel(data: bytes) -> bytes:
    return _run_decode(get_lib().lr_babel_decode, data)
