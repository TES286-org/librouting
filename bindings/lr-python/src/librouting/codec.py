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

def encode_open(my_as: int, hold_time: int, bgp_id: str, as4: bool = True) -> bytes:
    """Encode a BGP OPEN message (RFC 4271 §4.2).

    With ``as4`` set (the default — what BIRD/FRR speak today) the
    RFC 6793 four-octet-AS capability (code 65) is appended; an AS
    above 65535 then travels as AS_TRANS (23456) in the 16-bit
    field. Hold time must be 0 or >= 3.
    """
    parts = bgp_id.split(".")
    if len(parts) != 4:
        raise LrError(f"invalid BGP identifier: {bgp_id}")
    try:
        addr = bytes(int(p) for p in parts)
    except ValueError as e:
        raise LrError(f"invalid BGP identifier: {bgp_id}") from e
    b = alloc_bytes()
    rc = get_lib().lr_bgp_encode_open(
        my_as, hold_time, addr, 1 if as4 else 0, b
    )
    if rc != 0:
        raise LrError(f"encode_open failed (rc={rc}): {last_error()}")
    try:
        return copy_bytes(b)
    finally:
        free_bytes(b)


def encode_notification(code: int, subcode: int, data: bytes = b"") -> bytes:
    """Encode a BGP NOTIFICATION message (RFC 4271 §4.5)."""
    b = alloc_bytes()
    rc = get_lib().lr_bgp_encode_notification(
        code, subcode, data if data else ffi.NULL, len(data), b
    )
    if rc != 0:
        raise LrError(f"encode_notification failed (rc={rc}): {last_error()}")
    try:
        return copy_bytes(b)
    finally:
        free_bytes(b)


def _prefix_specs_to_c(prefixes: list[str]):
    import ipaddress
    out = ffi.new("lr_prefix_t[]", len(prefixes))
    for i, text in enumerate(prefixes):
        net = ipaddress.ip_network(text, strict=False)
        packed = net.network_address.packed
        if net.version == 4:
            out[i].addr[0:4] = packed
            out[i].is_ipv6 = 0
        else:
            out[i].addr[0:16] = packed
            out[i].is_ipv6 = 1
        out[i].prefix_len = net.prefixlen
    return out


def encode_update_withdraw_v4(prefixes: list[str]) -> bytes:
    """Encode a withdraw-only UPDATE (RFC 4271 §4.3): every listed
    IPv4 prefix goes into the withdrawn-routes section. IPv6 entries
    are rejected (the legacy NLRI section carries IPv4 only)."""
    arr = _prefix_specs_to_c(prefixes)
    b = alloc_bytes()
    rc = get_lib().lr_bgp_encode_update_withdraw_v4(
        arr if len(prefixes) else ffi.NULL, len(prefixes), b
    )
    if rc != 0:
        raise LrError(f"encode_update_withdraw_v4 failed (rc={rc}): {last_error()}")
    try:
        return copy_bytes(b)
    finally:
        free_bytes(b)


def encode_update_announce_v4(prefixes: list[str], next_hop: str,
                              as_path: list[int] | None = None,
                              origin: int = 0, as4: bool = True) -> bytes:
    """Encode an announcement UPDATE (RFC 4271 §4.3): ORIGIN +
    AS_PATH + NEXT_HOP attributes and the IPv4 NLRI.

    ``origin`` selects the ORIGIN value (0=IGP, 1=EGP, 2=INCOMPLETE);
    ``as_path`` is an AS_SEQUENCE in wire order (the origin AS first;
    ``None`` for a locally originated route); with ``as4`` set the
    segments use the RFC 6793 four-octet encoding."""
    import ipaddress
    parts = next_hop.split(".")
    if len(parts) != 4:
        raise LrError(f"invalid next-hop: {next_hop}")
    try:
        nh = bytes(int(p) for p in parts)
    except ValueError as e:
        raise LrError(f"invalid next-hop: {next_hop}") from e
    arr = _prefix_specs_to_c(prefixes)
    path_arr = ffi.new("uint32_t[]", as_path or [])
    b = alloc_bytes()
    rc = get_lib().lr_bgp_encode_update_announce_v4(
        arr if len(prefixes) else ffi.NULL, len(prefixes),
        nh, path_arr if as_path else ffi.NULL, len(as_path or []),
        origin, 1 if as4 else 0, b,
    )
    if rc != 0:
        raise LrError(f"encode_update_announce_v4 failed (rc={rc}): {last_error()}")
    try:
        return copy_bytes(b)
    finally:
        free_bytes(b)
