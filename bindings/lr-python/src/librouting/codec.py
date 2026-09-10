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


def encode_srv6_srh(sids: bytes) -> bytes:
    """Encode an SRv6 Segment Routing Header (RFC 8754 §2).

    ``sids`` is a flat byte string of ``n * 16`` bytes — each 16-byte
    block is one SID, in traversal order (the first SID becomes the
    destination address at the sender). The function returns the
    on-wire SRH bytes (8-octet fixed header + segment list).
    """
    if len(sids) % 16 != 0:
        raise LrError(f"SIDs length must be a multiple of 16, got {len(sids)}")
    b = alloc_bytes()
    rc = get_lib().lr_srv6_encode_srh(sids, len(sids), b)
    if rc != 0:
        raise LrError(f"SRH encode failed (rc={rc}): {last_error()}")
    try:
        return copy_bytes(b)
    finally:
        free_bytes(b)


def decode_srv6_srh(data: bytes) -> bytes:
    """Decode an SRv6 SRH (RFC 8754 §2) into its segment list.

    Returns the concatenation of the segment list (16 bytes per SID)
    followed by any TLV bytes present in the SRH.
    """
    return _run_decode(get_lib().lr_srv6_decode_srh, data)
