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


# ---- BGP message inspection (parsed-form readers) ----
#
# `decode_bgp` (above) returns the canonical re-encoded bytes — useful
# for differential checks but not for reading a message's fields. The
# `BgpMessage` class below wraps the opaque `lr_bgp_message_t` handle
# and exposes the variant fields, mirroring `lr_bgp::BgpMessage`:
# OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH.

# BGP message type codes (RFC 4271 §4.1 + RFC 2918).
BGP_MSG_OPEN = 1
BGP_MSG_UPDATE = 2
BGP_MSG_NOTIFICATION = 3
BGP_MSG_KEEPALIVE = 4
BGP_MSG_ROUTE_REFRESH = 5

# Route-Refresh subtype (RFC 7313 §3.2).
BGP_RR_SUBTYPE_NORMAL = 0
BGP_RR_SUBTYPE_BORR = 1
BGP_RR_SUBTYPE_EORR = 2


class BgpMessage:
    """Owned BGP-message handle (a boxed `lr_bgp::BgpMessage`).

    Decode wire bytes once via :py:meth:`decode`, then read the
    variant fields with the ``open_*`` / ``notification_*`` /
    ``route_refresh_*`` / ``update_*`` accessors. The handle is freed
    automatically when the wrapper is garbage-collected.
    """

    __slots__ = ("_handle",)

    def __init__(self, handle) -> None:
        # `handle` is a cffi-owned `lr_bgp_message_t` (a pointer).
        # NULL is rejected at decode time so we never wrap one.
        self._handle = handle

    def __del__(self) -> None:
        # Free is safe on NULL but should never be called twice on a
        # live handle. The wrapper is single-owner by construction.
        h = getattr(self, "_handle", None)
        if h is not None:
            try:
                get_lib().lr_bgp_message_free(h)
            except Exception:
                pass
            self._handle = None

    def __enter__(self) -> "BgpMessage":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        """Free the underlying handle. Safe to call more than once."""
        if self._handle is not None:
            get_lib().lr_bgp_message_free(self._handle)
            self._handle = None

    @classmethod
    def decode(cls, data: bytes) -> "BgpMessage":
        """Decode one BGP message from ``data`` and return an owned
        handle. Raises :class:`LrError` on a decode failure (the
        underlying last-error string is preserved in the message)."""
        if not data:
            raise LrError("decode: empty data")
        h = get_lib().lr_bgp_decode_message(data, len(data))
        if h == ffi.NULL:
            raise LrError(f"lr_bgp_decode_message failed: {last_error()}")
        return cls(h)

    def _require(self) -> "lr_bgp_message_t":  # type: ignore[name-defined]
        if self._handle is None:
            raise LrError("BgpMessage: handle already closed")
        return self._handle

    def kind(self) -> int:
        """BGP message type code (1..5, see ``BGP_MSG_*``)."""
        out = ffi.new("uint8_t *")
        rc = get_lib().lr_bgp_message_type(self._require(), out)
        if rc != 0:
            raise LrError(f"lr_bgp_message_type failed (rc={rc}): {last_error()}")
        return out[0]

    # -- OPEN readers (RFC 4271 §4.2) --

    def open_version(self) -> int:
        out = ffi.new("uint8_t *")
        rc = get_lib().lr_bgp_message_open_version(self._require(), out)
        if rc != 0:
            raise LrError(f"open_version failed (rc={rc}): {last_error()}")
        return out[0]

    def open_my_as(self) -> int:
        """Sender AS. When the OPEN carries the RFC 6793 four-octet-AS
        capability, the real 32-bit AS is unwrapped from the
        capability; otherwise the 16-bit ``my_as`` field is returned."""
        out = ffi.new("uint32_t *")
        rc = get_lib().lr_bgp_message_open_my_as(self._require(), out)
        if rc != 0:
            raise LrError(f"open_my_as failed (rc={rc}): {last_error()}")
        return out[0]

    def open_hold_time(self) -> int:
        out = ffi.new("uint16_t *")
        rc = get_lib().lr_bgp_message_open_hold_time(self._require(), out)
        if rc != 0:
            raise LrError(f"open_hold_time failed (rc={rc}): {last_error()}")
        return out[0]

    def open_bgp_id(self) -> bytes:
        out = ffi.new("uint8_t[4]")
        rc = get_lib().lr_bgp_message_open_bgp_id(self._require(), out)
        if rc != 0:
            raise LrError(f"open_bgp_id failed (rc={rc}): {last_error()}")
        return bytes(ffi.buffer(out, 4))

    def open_param_count(self) -> int:
        return int(get_lib().lr_bgp_message_open_param_count(self._require()))

    def open_param_at(self, idx: int) -> tuple[int, bytes]:
        """Read the optional parameter at ``idx``: returns
        ``(param_type, value_bytes)``. ``param_type`` is 2 for the
        RFC 5492 capabilities parameter; ``value_bytes`` is the raw
        capability payload (a sequence of
        ``(code:1, length:1, value:length)`` triples)."""
        ptype = ffi.new("uint8_t *")
        pvalue = alloc_bytes()
        rc = get_lib().lr_bgp_message_open_param_at(
            self._require(), idx, ptype, pvalue
        )
        if rc != 0:
            raise LrError(f"open_param_at({idx}) failed (rc={rc}): {last_error()}")
        try:
            return ptype[0], copy_bytes(pvalue)
        finally:
            free_bytes(pvalue)

    def open_params(self) -> list[tuple[int, bytes]]:
        """Walk every optional parameter."""
        return [self.open_param_at(i) for i in range(self.open_param_count())]

    # -- NOTIFICATION readers (RFC 4271 §4.5) --

    def notification_code(self) -> int:
        out = ffi.new("uint8_t *")
        rc = get_lib().lr_bgp_message_notification_code(self._require(), out)
        if rc != 0:
            raise LrError(f"notification_code failed (rc={rc}): {last_error()}")
        return out[0]

    def notification_subcode(self) -> int:
        out = ffi.new("uint8_t *")
        rc = get_lib().lr_bgp_message_notification_subcode(self._require(), out)
        if rc != 0:
            raise LrError(f"notification_subcode failed (rc={rc}): {last_error()}")
        return out[0]

    def notification_data(self) -> bytes:
        out = alloc_bytes()
        rc = get_lib().lr_bgp_message_notification_data(self._require(), out)
        if rc != 0:
            raise LrError(f"notification_data failed (rc={rc}): {last_error()}")
        try:
            return copy_bytes(out)
        finally:
            free_bytes(out)

    # -- ROUTE-REFRESH readers (RFC 2918 + RFC 7313) --

    def route_refresh_afi(self) -> int:
        out = ffi.new("uint16_t *")
        rc = get_lib().lr_bgp_message_route_refresh_afi(self._require(), out)
        if rc != 0:
            raise LrError(f"route_refresh_afi failed (rc={rc}): {last_error()}")
        return out[0]

    def route_refresh_safi(self) -> int:
        out = ffi.new("uint8_t *")
        rc = get_lib().lr_bgp_message_route_refresh_safi(self._require(), out)
        if rc != 0:
            raise LrError(f"route_refresh_safi failed (rc={rc}): {last_error()}")
        return out[0]

    def route_refresh_subtype(self) -> int:
        out = ffi.new("uint8_t *")
        rc = get_lib().lr_bgp_message_route_refresh_subtype(self._require(), out)
        if rc != 0:
            raise LrError(f"route_refresh_subtype failed (rc={rc}): {last_error()}")
        return out[0]

    # -- UPDATE readers (RFC 4271 §4.3) --

    def update_withdrawn_count(self) -> int:
        return int(get_lib().lr_bgp_message_update_withdrawn_count(self._require()))

    def update_nlri_count(self) -> int:
        return int(get_lib().lr_bgp_message_update_nlri_count(self._require()))

    def update_attr_count(self) -> int:
        return int(get_lib().lr_bgp_message_update_attr_count(self._require()))

    def update_withdrawn_at(self, idx: int) -> tuple[bytes, int]:
        """Read the withdrawn route at ``idx`` as ``(addr_bytes,
        prefix_len)``. ``addr_bytes`` is 4 bytes for IPv4 (or 16 for
        IPv6, though the legacy NLRI section carries IPv4 only)."""
        p = ffi.new("struct lr_prefix_t *")
        rc = get_lib().lr_bgp_message_update_withdrawn_at(self._require(), idx, p)
        if rc != 0:
            raise LrError(f"update_withdrawn_at({idx}) failed (rc={rc}): {last_error()}")
        if p.is_ipv6:
            return bytes(p.addr[0:16]), p.prefix_len
        return bytes(p.addr[0:4]), p.prefix_len

    def update_nlri_at(self, idx: int) -> tuple[bytes, int]:
        """Read the NLRI entry at ``idx``."""
        p = ffi.new("struct lr_prefix_t *")
        rc = get_lib().lr_bgp_message_update_nlri_at(self._require(), idx, p)
        if rc != 0:
            raise LrError(f"update_nlri_at({idx}) failed (rc={rc}): {last_error()}")
        if p.is_ipv6:
            return bytes(p.addr[0:16]), p.prefix_len
        return bytes(p.addr[0:4]), p.prefix_len

    def update_attr_at(self, idx: int) -> tuple[int, int, bytes]:
        """Read the path attribute at ``idx`` as ``(attr_type, flags,
        value_bytes)``. The flags byte is RFC 4271 §5.1 + RFC 9072 §2:
        bit 7 optional, bit 6 transitive, bit 5 partial, bit 4
        extended-length."""
        atype = ffi.new("uint8_t *")
        aflags = ffi.new("uint8_t *")
        avalue = alloc_bytes()
        rc = get_lib().lr_bgp_message_update_attr_at(
            self._require(), idx, atype, aflags, avalue
        )
        if rc != 0:
            raise LrError(f"update_attr_at({idx}) failed (rc={rc}): {last_error()}")
        try:
            return atype[0], aflags[0], copy_bytes(avalue)
        finally:
            free_bytes(avalue)

    def update_attrs(self) -> list[tuple[int, int, bytes]]:
        """Walk every path attribute."""
        return [self.update_attr_at(i) for i in range(self.update_attr_count())]
