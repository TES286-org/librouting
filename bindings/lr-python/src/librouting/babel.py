"""Babel routing protocol — frame codec, route table, neighbor FSM, auth.

Mirrors the Rust crate ``lr_babel`` (RFC 8966 — the Babel routing
protocol; plus RFC 8967 — the HMAC authentication extension). The
module layers Python classes on top of the C ABI in
``crates/lr-ffi/src/babel*.rs`` so an embedder can:

* build a Babel frame from scratch (``BabelFrame`` + ``Tlv``),
* decode a received frame and walk its TLVs,
* drive a route table (``BabelRouteTable``) — insert / withdraw /
  expire / lookup / iterate (RFC 8966 §3.5),
* feed a neighbor FSM (``BabelNeighbor``) Hello / IHU TLVs and read
  the RTT estimate,
* construct MAC keys + pseudo-headers + replay-protection state
  (RFC 8967) for the authenticated codec.

The Python class hierarchy mirrors the Rust module split:

    lr_babel::BabelFrame            -> BabelFrame
    lr_babel::tlv::Tlv              -> Tlv
    lr_babel::codec::BabelCodec     -> BabelCodec
    lr_babel::route::BabelRoute     -> BabelRoute (dataclass)
    lr_babel::route::RouteKey       -> RouteKey (dataclass)
    lr_babel::route::BabelRouteTable-> BabelRouteTable
    lr_babel::neighbor::BabelNeighbor -> BabelNeighbor
    lr_babel::auth::BabelMacKey     -> MacKey
    lr_babel::auth::BabelPseudoHeader -> PseudoHeader
    lr_babel::auth::BabelPacketCounter -> PacketCounter
    lr_babel::auth::BabelReplayProtection -> ReplayProtection
    lr_babel::message::Hello / Ihu / AckReq / Ack / NextHop /
                 RouterId / RouteRequest / SeqnoRequest -> Hello / Ihu / ...
    lr_babel::metric::rtt_penalty / route_metric / feasible ->
        rtt_penalty / route_metric_sum / feasible (free functions)

Resources are released via ``__del__`` finalizers — the Python-side
equivalent of the Go runtime.SetFinalizer and the C++ RAII wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence, Tuple

from ._ffi import ffi, get_lib
from .router import LrError, last_error


# ---- Error / return-code constants (mirror lr_ffi.h after_includes) ----

LR_ERR_OK = 0
LR_ERR_NULL = -1
LR_ERR_INVALID_HANDLE = -2
LR_ERR_BAD_UTF8 = -3
LR_ERR_PANIC = -4
LR_ERR_CODEC = -5
LR_ERR_OTHER = -6


def _check_rc(rc: int, what: str) -> None:
    if rc < 0:
        raise LrError(f"{what} failed (rc={rc}): {last_error()}")


# ---- TLV type constants (RFC 8966 §4.4 — Table 1) ----

TLV_PAD1 = 0
TLV_PADN = 1
TLV_ACK_REQ = 2
TLV_ACK = 3
TLV_HELLO = 4
TLV_IHU = 5
TLV_ROUTER_ID = 6
TLV_NEXT_HOP = 7
TLV_UPDATE = 8
TLV_ROUTE_REQUEST = 9
TLV_SEQNO_REQUEST = 10
TLV_TSPC = 11
TLV_HMAC = 12
TLV_UNSUPPORTED = 255

# Address Encoding (AE) — RFC 8966 §4.4.4 + RFC 8967 §4.1
AE_WILDCARD = 0
AE_IPV4 = 1
AE_IPV6 = 2
AE_IPV6_LINK_LOCAL = 3

# MAC algorithm constants — mirror `BabelMacAlgorithm` in lr_babel::auth.
MAC_HMAC_SHA256 = 1
MAC_BLAKE2S128 = 2


# ---- Helpers to convert 4 / 16-byte addresses into Python bytes ----

def _addr_to_py(buf, is_ipv6: bool) -> bytes:
    """Read an address from a 16-byte buffer. For IPv4, the C ABI
    writes the 4-byte address into the last 4 bytes (the IPv4-mapped
    IPv6 layout used by lr_babel_route_key_*_addr / lr_babel_route_next_hop)."""
    if is_ipv6:
        return bytes(buf[i] for i in range(16))
    return bytes(buf[12 + i] for i in range(4))


def _addr_ptr(addr: bytes):
    """Build a pointer to a contiguous address buffer. For IPv4, the
    C ABI reads the 4 raw bytes (the first 4 bytes of the pointer's
    target). For IPv6, the 16 raw bytes. The returned pointer is a
    fresh cffi buffer that the caller keeps a reference to for the
    duration of the C call."""
    if len(addr) not in (4, 16):
        raise LrError("address must be 4 or 16 bytes")
    buf = ffi.new(f"uint8_t[{len(addr)}]")
    for i, b in enumerate(addr):
        buf[i] = b
    return buf


def _addr_buf(size: int) -> ffi.CData:
    """Allocate a zero-initialized 16-byte buffer for the read path
    (lr_babel_route_key_*_addr / lr_babel_route_next_hop)."""
    return ffi.new("uint8_t[16]")


# =========================================================================
# Tlv — RFC 8966 §4.4 — the atomic unit of a Babel frame body.
# =========================================================================


class Tlv:
    """A single Babel TLV — the atomic unit of a Babel frame body
    (RFC 8966 §4.4). The handle owns a Rust ``Tlv`` and is freed by
    ``__del__`` / ``close``. The constructor variants mirror the
    Rust ``Tlv::new`` / ``Tlv::pad1`` / ``Tlv::pad_n``."""

    __slots__ = ("_t", "_freed")

    def __init__(self, _t, _owned: bool = True):
        self._t = _t
        self._freed = False if _owned else True

    @classmethod
    def new(cls, kind: int, value: bytes = b"") -> "Tlv":
        v = bytes(value)
        t = get_lib().lr_babel_tlv_new(int(kind), v, len(v))
        if t == ffi.NULL:
            raise LrError(f"Tlv.new failed: {last_error()}")
        return cls(t)

    @classmethod
    def pad1(cls) -> "Tlv":
        return cls(get_lib().lr_babel_tlv_pad1())

    @classmethod
    def pad_n(cls, n: int = 0) -> "Tlv":
        return cls(get_lib().lr_babel_tlv_pad_n(int(n)))

    @property
    def kind(self) -> int:
        return int(get_lib().lr_babel_tlv_kind(self._t))

    @property
    def value(self) -> bytes:
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_tlv_value(self._t, b)
        _check_rc(rc, "Tlv.value")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def close(self) -> None:
        if not self._freed and getattr(self, "_t", None) is not None:
            get_lib().lr_babel_tlv_free(self._t)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "Tlv":
        return self

    def __exit__(self, *_):
        self.close()


# ---- TLV type enum helpers (mirror lr_babel::tlv::TlvType) ----

def tlv_type_to_u8(kind: int) -> int:
    """Convert a high-level TLV kind enum value to its wire byte
    (RFC 8966 §4.4 — Table 1). Identity — kept for ABI symmetry
    with ``tlv_type_from_u8``."""
    return int(get_lib().lr_babel_tlv_type_to_u8(int(kind)))


def tlv_type_from_u8(wire: int) -> int:
    """Convert a wire TLV type byte back to the high-level enum value."""
    return int(get_lib().lr_babel_tlv_type_from_u8(int(wire)))


def tlv_type_name(wire: int) -> str:
    """Human-readable name for a wire TLV type byte (RFC 8966 §4.4 — Table 1)."""
    s = get_lib().lr_babel_tlv_type_name(int(wire))
    if s == ffi.NULL:
        return ""
    return ffi.string(s).decode("utf-8", errors="replace")


# =========================================================================
# BabelFrame — RFC 8966 §4.1 — the Babel protocol frame body.
# =========================================================================


class BabelFrame:
    """A Babel protocol frame body (RFC 8966 §4.1) — a flat list of TLVs.

    The handle owns a Rust ``BabelFrame`` and is freed by ``__del__``
    / ``close``. Construct empty, from a flat list of ``Tlv`` handles,
    or from a raw wire buffer via the module-level ``decode_frame``
    helper."""

    __slots__ = ("_f", "_freed")

    def __init__(self, _f, _owned: bool = True):
        self._f = _f
        self._freed = False if _owned else True

    @classmethod
    def empty(cls) -> "BabelFrame":
        return cls(get_lib().lr_babel_frame_new_empty())

    @classmethod
    def from_tlvs(cls, tlvs: Sequence[Tlv]) -> "BabelFrame":
        # cffi's `new(type*, init)` builds a contiguous C array.
        if not tlvs:
            return cls(get_lib().lr_babel_frame_new_from_tlvs(ffi.NULL, 0))
        arr_t = ffi.typeof(f"lr_babel_tlv_t[{len(tlvs)}]")
        arr = ffi.new(arr_t)
        for i, t in enumerate(tlvs):
            arr[i] = t._t
            # The frame takes ownership of the TLV handle. Mark each
            # input Tlv as "freed" so its __del__ does not double-free.
            t._freed = True
        return cls(get_lib().lr_babel_frame_new_from_tlvs(arr, len(tlvs)))

    def push_tlv(self, tlv: Tlv) -> None:
        """Append one TLV (consumes the ``Tlv`` handle — do not reuse
        the Python object after this call)."""
        rc = get_lib().lr_babel_frame_push_tlv(self._f, tlv._t)
        _check_rc(rc, "BabelFrame.push_tlv")
        tlv._freed = True

    @property
    def tlv_count(self) -> int:
        return int(get_lib().lr_babel_frame_tlv_count(self._f))

    def tlv_type_at(self, index: int) -> int:
        n = self.tlv_count
        if index < 0 or index >= n:
            raise IndexError(f"TLV index {index} out of range (count={n})")
        return int(get_lib().lr_babel_frame_tlv_type_at(self._f, index))

    def tlv_value_at(self, index: int) -> bytes:
        n = self.tlv_count
        if index < 0 or index >= n:
            raise IndexError(f"TLV index {index} out of range (count={n})")
        length = int(get_lib().lr_babel_frame_tlv_value_len_at(self._f, index))
        if length == 0:
            return b""
        out = ffi.new(f"uint8_t[{length}]")
        copied = get_lib().lr_babel_frame_tlv_value_at(self._f, index, out, length)
        if copied == 0:
            return b""
        return bytes(out[i] for i in range(int(copied)))

    def iter_tlvs(self) -> Iterator[Tuple[int, bytes]]:
        """Iterate the frame's TLVs as ``(kind, value_bytes)`` tuples.
        The bytes are copied out of the borrowed C buffer."""
        for i in range(self.tlv_count):
            yield (self.tlv_type_at(i), self.tlv_value_at(i))

    def encode(self) -> bytes:
        """Encode the frame to its on-the-wire representation
        (RFC 8966 §4.2 — the magic + body fields)."""
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_encode_frame(self._f, b)
        _check_rc(rc, "BabelFrame.encode")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def close(self) -> None:
        if not self._freed and getattr(self, "_f", None) is not None:
            get_lib().lr_babel_frame_free(self._f)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "BabelFrame":
        return self

    def __exit__(self, *_):
        self.close()


def decode_frame(data: bytes) -> BabelFrame:
    """Decode a raw Babel wire frame into a ``BabelFrame`` (RFC 8966
    §4.2 — magic + body fields). The caller owns the returned frame
    and must free it via ``close`` / the GC."""
    if not isinstance(data, (bytes, bytearray)):
        raise LrError("decode_frame expects bytes")
    out = ffi.new("lr_babel_frame_t*")
    rc = get_lib().lr_babel_decode_frame(bytes(data), len(data), out)
    _check_rc(rc, "decode_frame")
    if out[0] == ffi.NULL:
        raise LrError(f"decode_frame returned NULL out: {last_error()}")
    return BabelFrame(out[0])


# =========================================================================
# BabelCodec — RFC 8966 §4.3 — the streaming codec for frames + auth.
# =========================================================================


class BabelCodec:
    """A streaming codec for Babel frames (RFC 8966 §4.3) and the
    authenticated codec extension (RFC 8967 §3). The handle owns a
    Rust ``BabelCodec`` and is freed by ``__del__`` / ``close``."""

    __slots__ = ("_c", "_freed")

    def __init__(self, _c):
        self._c = _c
        self._freed = False

    @classmethod
    def new(cls) -> "BabelCodec":
        return cls(get_lib().lr_babel_codec_new())

    def decode_slice(self, data: bytes) -> Optional[BabelFrame]:
        """Feed one wire slice; returns a ``BabelFrame`` when the
        accumulated bytes yield a complete frame, ``None`` when more
        bytes are needed."""
        out = ffi.new("lr_babel_frame_t*")
        rc = get_lib().lr_babel_codec_decode_slice(self._c, bytes(data), len(data), out)
        _check_rc(rc, "BabelCodec.decode_slice")
        if out[0] == ffi.NULL:
            return None
        return BabelFrame(out[0])

    def encode_vec(self, frame: BabelFrame) -> bytes:
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_codec_encode_vec(self._c, frame._f, b)
        _check_rc(rc, "BabelCodec.encode_vec")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def decode_authenticated_slice(self, data: bytes, pseudo_header: "PseudoHeader") -> bytes:
        """Decode an authenticated Babel frame slice (RFC 8967 §3).
        Returns the inner (de-encapsulated) frame bytes."""
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_codec_decode_authenticated_slice(
            self._c, bytes(data), len(data), pseudo_header._p, b
        )
        _check_rc(rc, "BabelCodec.decode_authenticated_slice")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def encode_authenticated(self, frame: BabelFrame, pseudo_header: "PseudoHeader",
                             keys: Sequence["MacKey"]) -> bytes:
        """Encode an authenticated Babel frame (RFC 8967 §3). The
        resulting bytes carry the original TLVs plus one HMAC TLV per
        key, in the order the keys were supplied."""
        if not keys:
            arr = ffi.NULL
            n = 0
        else:
            arr_t = ffi.typeof(f"lr_babel_mac_key_t[{len(keys)}]")
            arr = ffi.new(arr_t)
            for i, k in enumerate(keys):
                arr[i] = k._k
            n = len(keys)
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_codec_encode_authenticated(
            self._c, frame._f, pseudo_header._p, arr, n, b
        )
        _check_rc(rc, "BabelCodec.encode_authenticated")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def close(self) -> None:
        if not self._freed and getattr(self, "_c", None) is not None:
            get_lib().lr_babel_codec_free(self._c)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "BabelCodec":
        return self

    def __exit__(self, *_):
        self.close()


# =========================================================================
# RouteKey + BabelRoute — RFC 8966 §3.2 — the per-destination route key
# and the route entry (seqno + metric + next-hop + feasible/installed flags).
# =========================================================================


@dataclass(frozen=True)
class BabelRouteKey:
    """A Babel route key (RFC 8966 §3.1): destination prefix + optional
    source prefix (RFC 8966 §3.1, source-specific routing) + the
    8-byte router identifier of the source.

    The destination / source prefixes are stored as ``(addr, prefix_len)``
    tuples where ``addr`` is the 4 (IPv4) or 16 (IPv6) raw bytes.
    ``source`` is ``None`` for a non-source-specific route.
    """

    destination: Tuple[bytes, int]
    source: Optional[Tuple[bytes, int]]
    router_id: bytes  # 8 bytes

    @property
    def is_source_specific(self) -> bool:
        return self.source is not None


@dataclass(frozen=True)
class BabelRoute:
    """A Babel route entry (RFC 8966 §3.2): the route's key + seqno +
    metric + next-hop + feasibility + install flags. Frozen so the
    dataclass can be safely hashed when used as a dict key."""

    key: BabelRouteKey
    seqno: int
    metric: int
    next_hop: bytes  # 4 (IPv4) or 16 (IPv6) bytes
    feasible: bool
    installed: bool

    @property
    def is_ipv6(self) -> bool:
        return len(self.next_hop) == 16


def _route_key_to_c(k: BabelRouteKey):
    """Build an ``lr_babel_route_key_t`` handle from a Python
    ``BabelRouteKey``. The handle is owned by the caller and must be
    freed via ``lr_babel_route_key_free``."""
    dest_addr, dest_plen = k.destination
    if k.source is None:
        src_present = 0
        src_is_ipv6 = 0
        src_addr_ptr = ffi.NULL
        src_plen = 0
    else:
        src_addr, src_plen = k.source
        src_present = 1
        src_is_ipv6 = 1 if len(src_addr) == 16 else 0
        src_addr_ptr = _addr_ptr(src_addr)
    if len(dest_addr) not in (4, 16):
        raise LrError("destination address must be 4 or 16 bytes")
    dest_is_ipv6 = 1 if len(dest_addr) == 16 else 0
    dest_addr_ptr = _addr_ptr(dest_addr)
    if len(k.router_id) != 8:
        raise LrError("router_id must be exactly 8 bytes")
    rid = ffi.new("uint8_t[8]")
    for i, b in enumerate(k.router_id):
        rid[i] = b
    h = get_lib().lr_babel_route_key_new(
        dest_is_ipv6, dest_addr_ptr, dest_plen,
        src_present, src_is_ipv6, src_addr_ptr, src_plen,
        rid,
    )
    if h == ffi.NULL:
        raise LrError(f"BabelRouteKey build failed: {last_error()}")
    return h


def _route_key_from_c(h) -> BabelRouteKey:
    """Read a ``BabelRouteKey`` from a borrowed handle. Does NOT free the
    handle (the table retains ownership)."""
    is_v6 = bool(get_lib().lr_babel_route_key_destination_is_ipv6(h))
    out = ffi.new("uint8_t[16]")
    rc = get_lib().lr_babel_route_key_destination_addr(h, out)
    _check_rc(rc, "BabelRouteKey.destination_addr")
    dest_addr = _addr_to_py(out, is_v6)
    dest_plen = int(get_lib().lr_babel_route_key_destination_prefix_len(h))
    src_present = bool(get_lib().lr_babel_route_key_source_present(h))
    if src_present:
        src_is_v6 = bool(get_lib().lr_babel_route_key_source_is_ipv6(h))
        sout = ffi.new("uint8_t[16]")
        rc = get_lib().lr_babel_route_key_source_addr(h, sout)
        _check_rc(rc, "BabelRouteKey.source_addr")
        src_addr = _addr_to_py(sout, src_is_v6)
        src_plen = int(get_lib().lr_babel_route_key_source_prefix_len(h))
        source = (src_addr, src_plen)
    else:
        source = None
    rid = ffi.new("uint8_t[8]")
    rc = get_lib().lr_babel_route_key_router_id(h, rid)
    _check_rc(rc, "BabelRouteKey.router_id")
    router_id = bytes(rid[i] for i in range(8))
    return BabelRouteKey(
        destination=(dest_addr, dest_plen),
        source=source,
        router_id=router_id,
    )


def _route_from_c(h) -> BabelRoute:
    """Read a ``BabelRoute`` from a borrowed handle. Does NOT free the
    handle (the table retains ownership when borrowed via get/iter)."""
    key_h = get_lib().lr_babel_route_borrow_key(h)
    if key_h == ffi.NULL:
        raise LrError("BabelRoute.borrow_key failed: key handle was NULL")
    key = _route_key_from_c(key_h)
    seqno = int(get_lib().lr_babel_route_seqno(h))
    metric = int(get_lib().lr_babel_route_metric(h))
    is_v6 = bool(get_lib().lr_babel_route_next_hop_is_ipv6(h))
    out = ffi.new("uint8_t[16]")
    rc = get_lib().lr_babel_route_next_hop(h, out)
    _check_rc(rc, "BabelRoute.next_hop")
    next_hop = _addr_to_py(out, is_v6)
    feasible = bool(get_lib().lr_babel_route_feasible(h))
    installed = bool(get_lib().lr_babel_route_installed(h))
    return BabelRoute(
        key=key,
        seqno=seqno,
        metric=metric,
        next_hop=next_hop,
        feasible=feasible,
        installed=installed,
    )


def _route_to_c(r: BabelRoute):
    """Build an owned ``lr_babel_route_t`` handle from a Python
    ``BabelRoute``. The handle is owned by the caller and must be
    freed via ``lr_babel_route_free``."""
    key_h = _route_key_to_c(r.key)
    if len(r.next_hop) not in (4, 16):
        raise LrError("next_hop must be 4 or 16 bytes")
    next_hop_is_ipv6 = 1 if len(r.next_hop) == 16 else 0
    nh = _addr_ptr(r.next_hop)
    h = get_lib().lr_babel_route_new(
        key_h,
        r.seqno,
        r.metric,
        next_hop_is_ipv6,
        nh,
        1 if r.feasible else 0,
        1 if r.installed else 0,
    )
    get_lib().lr_babel_route_key_free(key_h)
    if h == ffi.NULL:
        raise LrError(f"BabelRoute build failed: {last_error()}")
    return h


# =========================================================================
# BabelRouteTable — RFC 8966 §3.5 — the per-neighbor route store.
# =========================================================================


class BabelRouteTable:
    """A per-neighbor Babel route table (RFC 8966 §3.5). Routes are
    keyed by ``BabelRouteKey``; the table tracks feasibility state per
    destination and returns the lowest-metric feasible route per
    destination via ``best_routes``. Mirrors
    ``lr_babel::route::BabelRouteTable``."""

    __slots__ = ("_t", "_freed")

    def __init__(self, _t):
        self._t = _t
        self._freed = False

    @classmethod
    def new(cls) -> "BabelRouteTable":
        return cls(get_lib().lr_babel_route_table_new())

    def __len__(self) -> int:
        return int(get_lib().lr_babel_route_table_len(self._t))

    def is_empty(self) -> bool:
        return bool(get_lib().lr_babel_route_table_is_empty(self._t))

    def insert(self, route: BabelRoute, *, interval_cs: int = 0, now_ms: int = 0) -> None:
        """Insert (or refresh) a route. When ``interval_cs`` and
        ``now_ms`` are non-zero, the route's hold-deadline is pushed
        out by ``hold_ms(interval_cs)`` (RFC 8966 §3.2.5)."""
        h = _route_to_c(route)
        try:
            if interval_cs == 0 and now_ms == 0:
                rc = get_lib().lr_babel_route_table_insert(self._t, h)
            else:
                rc = get_lib().lr_babel_route_table_insert_timed(
                    self._t, h, int(interval_cs), int(now_ms)
                )
            _check_rc(rc, "BabelRouteTable.insert")
        finally:
            get_lib().lr_babel_route_free(h)

    def withdraw(self, key: BabelRouteKey) -> None:
        h = _route_key_to_c(key)
        try:
            rc = get_lib().lr_babel_route_table_withdraw(self._t, h)
            _check_rc(rc, "BabelRouteTable.withdraw")
        finally:
            get_lib().lr_babel_route_key_free(h)

    def expire(self, now_ms: int) -> int:
        """Expire routes whose re-announcement hold time lapsed (RFC
        8966 §3.2.5). Returns the number of routes withdrawn."""
        return int(get_lib().lr_babel_route_table_expire(self._t, int(now_ms)))

    def contains(self, key: BabelRouteKey) -> bool:
        h = _route_key_to_c(key)
        try:
            return bool(get_lib().lr_babel_route_table_contains(self._t, h))
        finally:
            get_lib().lr_babel_route_key_free(h)

    def get(self, key: BabelRouteKey) -> Optional[BabelRoute]:
        """Look up the route stored under ``key``. Returns ``None``
        when the key is not present. The returned ``BabelRoute`` is a
        snapshot copied out of the table — the table's internal
        storage is not pinned."""
        h = _route_key_to_c(key)
        try:
            r = get_lib().lr_babel_route_table_get(self._t, h)
            if r == ffi.NULL:
                return None
            return _route_from_c(r)
        finally:
            get_lib().lr_babel_route_key_free(h)

    def best_routes_count(self) -> int:
        return int(get_lib().lr_babel_route_table_best_routes_count(self._t))

    def iter_all(self) -> Iterator[BabelRoute]:
        """Iterate every route in the table in ``BTreeMap<BabelRouteKey, _>``
        order (deterministic). Yields snapshots copied out of the
        table; mutation during iteration is not safe."""
        collected: List[BabelRoute] = []

        def _cb(route_ptr, _user):
            try:
                collected.append(_route_from_c(route_ptr))
            except Exception:
                return -1
            return 0

        cb = ffi.callback("lr_babel_route_iter_cb")(_cb)
        rc = get_lib().lr_babel_route_table_iter(self._t, cb, ffi.NULL)
        _check_rc(rc, "BabelRouteTable.iter_all")
        for r in collected:
            yield r

    def iter_best(self) -> Iterator[BabelRoute]:
        """Iterate the best (lowest-metric feasible) route per
        destination (RFC 8966 §3.5 — the routes eligible for FIB
        install). Yields snapshots copied out of the table."""
        collected: List[BabelRoute] = []

        def _cb(route_ptr, _user):
            try:
                collected.append(_route_from_c(route_ptr))
            except Exception:
                return -1
            return 0

        cb = ffi.callback("lr_babel_route_iter_cb")(_cb)
        rc = get_lib().lr_babel_route_table_best_routes_iter(self._t, cb, ffi.NULL)
        _check_rc(rc, "BabelRouteTable.iter_best")
        for r in collected:
            yield r

    def close(self) -> None:
        if not self._freed and getattr(self, "_t", None) is not None:
            get_lib().lr_babel_route_table_free(self._t)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "BabelRouteTable":
        return self

    def __exit__(self, *_):
        self.close()


def _ffi_callback(typ: str):
    """Decorator that wraps a Python callable as a cffi callback.
    Kept for backwards-compatibility; new code uses ``ffi.callback``
    inline so the closure's local variable keeps the cdata alive."""
    def deco(fn):
        return ffi.callback(typ)(fn)
    return deco


# =========================================================================
# BabelNeighbor — RFC 8966 §3.4 — the per-neighbor FSM (Hello/IHU feed).
# =========================================================================


class BabelNeighbor:
    """A Babel neighbor FSM (RFC 8966 §3.4) — feeds Hello / IHU TLVs,
    tracks the neighbor's rxcost and the round-trip-time estimate
    (RFC 8966 §3.4.3 — the RTT is valid for ``RTT_VALIDITY_MS`` after
    the last timestamped Hello/IHU pair)."""

    __slots__ = ("_n", "_freed")

    def __init__(self, _n):
        self._n = _n
        self._freed = False

    @classmethod
    def new(cls, address: bytes, now_ms: int = 0) -> "BabelNeighbor":
        if len(address) == 4:
            v4 = ffi.new("uint8_t[4]")
            for i, b in enumerate(address):
                v4[i] = b
            v6 = ffi.NULL
        elif len(address) == 16:
            v4 = ffi.NULL
            v6 = ffi.new("uint8_t[16]")
            for i, b in enumerate(address):
                v6[i] = b
        else:
            raise LrError("address must be 4 or 16 bytes")
        h = get_lib().lr_babel_neighbor_new(v4, v6, int(now_ms))
        if h == ffi.NULL:
            raise LrError(f"BabelNeighbor.new failed: {last_error()}")
        return cls(h)

    def hello(self, seqno: int, interval_cs: int, now_ms: int) -> None:
        rc = get_lib().lr_babel_neighbor_hello(self._n, int(seqno), int(interval_cs), int(now_ms))
        _check_rc(rc, "BabelNeighbor.hello")

    def ihu(self, rxcost: int, interval_cs: int, now_ms: int) -> None:
        rc = get_lib().lr_babel_neighbor_ihu(self._n, int(rxcost), int(interval_cs), int(now_ms))
        _check_rc(rc, "BabelNeighbor.ihu")

    def rtt_us(self, now_ms: int) -> int:
        return int(get_lib().lr_babel_neighbor_rtt_us(self._n, int(now_ms)))

    def rtt_valid(self, now_ms: int) -> bool:
        return bool(get_lib().lr_babel_neighbor_rtt_valid(self._n, int(now_ms)))

    def close(self) -> None:
        if not self._freed and getattr(self, "_n", None) is not None:
            get_lib().lr_babel_neighbor_free(self._n)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "BabelNeighbor":
        return self

    def __exit__(self, *_):
        self.close()


# =========================================================================
# Auth helpers — RFC 8967 — MAC keys, pseudo-headers, replay protection.
# =========================================================================


class MacKey:
    """A Babel MAC key (RFC 8967 §2.1) — algorithm + secret bytes."""

    __slots__ = ("_k", "_freed")

    def __init__(self, _k):
        self._k = _k
        self._freed = False

    @classmethod
    def new(cls, secret: bytes, algorithm: int = MAC_HMAC_SHA256) -> "MacKey":
        s = bytes(secret)
        h = get_lib().lr_babel_mac_key_new(int(algorithm), s, len(s))
        if h == ffi.NULL:
            raise LrError(f"MacKey build failed: {last_error()}")
        return cls(h)

    @classmethod
    def hmac_sha256(cls, secret: bytes) -> "MacKey":
        return cls._from_algo(get_lib().lr_babel_mac_key_hmac_sha256, secret)

    @classmethod
    def blake2s128(cls, secret: bytes) -> "MacKey":
        return cls._from_algo(get_lib().lr_babel_mac_key_blake2s128, secret)

    @classmethod
    def _from_algo(cls, fn, secret: bytes) -> "MacKey":
        s = bytes(secret)
        h = fn(s, len(s))
        if h == ffi.NULL:
            raise LrError(f"MacKey build failed: {last_error()}")
        return cls(h)

    @property
    def algorithm(self) -> int:
        return int(get_lib().lr_babel_mac_key_algorithm(self._k))

    @property
    def digest_len(self) -> int:
        return int(get_lib().lr_babel_mac_key_digest_len(self._k))

    @property
    def secret_len(self) -> int:
        return int(get_lib().lr_babel_mac_key_secret_len(self._k))

    @property
    def secret(self) -> bytes:
        n = self.secret_len
        if n == 0:
            return b""
        out = ffi.new(f"uint8_t[{n}]")
        rc = get_lib().lr_babel_mac_key_secret_copy(self._k, out, n)
        _check_rc(rc, "MacKey.secret")
        return bytes(out[i] for i in range(n))

    def close(self) -> None:
        if not self._freed and getattr(self, "_k", None) is not None:
            get_lib().lr_babel_mac_key_free(self._k)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "MacKey":
        return self

    def __exit__(self, *_):
        self.close()


class PseudoHeader:
    """A Babel pseudo-header (RFC 8967 §4.2) — the address-family
    + src/dst address + src/dst port tuple hashed into the MAC."""

    __slots__ = ("_p", "_freed")

    def __init__(self, _p):
        self._p = _p
        self._freed = False

    @classmethod
    def new_v4(cls, src: bytes, dst: bytes, src_port: int, dst_port: int) -> "PseudoHeader":
        return cls._build(get_lib().lr_babel_pseudo_header_new_v4, src, dst, src_port, dst_port)

    @classmethod
    def new_v6(cls, src: bytes, dst: bytes, src_port: int, dst_port: int) -> "PseudoHeader":
        return cls._build(get_lib().lr_babel_pseudo_header_new_v6, src, dst, src_port, dst_port)

    @classmethod
    def _build(cls, fn, src: bytes, dst: bytes, src_port: int, dst_port: int) -> "PseudoHeader":
        if len(src) != 4 and len(src) != 16:
            raise LrError("src must be 4 or 16 bytes")
        if len(dst) != 4 and len(dst) != 16:
            raise LrError("dst must be 4 or 16 bytes")
        if len(src) != len(dst):
            raise LrError("src and dst must both be 4 or both be 16 bytes")
        s = ffi.new(f"uint8_t[{len(src)}]")
        for i, b in enumerate(src):
            s[i] = b
        d = ffi.new(f"uint8_t[{len(dst)}]")
        for i, b in enumerate(dst):
            d[i] = b
        # The C ABI order is (src_ptr, src_port, dst_ptr, dst_port).
        h = fn(s, int(src_port), d, int(dst_port))
        if h == ffi.NULL:
            raise LrError(f"PseudoHeader build failed: {last_error()}")
        return cls(h)

    def encode(self) -> bytes:
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_pseudo_header_encode(self._p, b)
        _check_rc(rc, "PseudoHeader.encode")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def close(self) -> None:
        if not self._freed and getattr(self, "_p", None) is not None:
            get_lib().lr_babel_pseudo_header_free(self._p)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "PseudoHeader":
        return self

    def __exit__(self, *_):
        self.close()


class PacketCounter:
    """A per-source packet counter (RFC 8967 §3.2) — used by the
    nonce source to produce monotonically-increasing indices."""

    __slots__ = ("_c", "_freed")

    def __init__(self, _c):
        self._c = _c
        self._freed = False

    @classmethod
    def new(cls, index: bytes, initial: int = 0) -> "PacketCounter":
        i = bytes(index)
        idx = ffi.new(f"uint8_t[{max(len(i), 1)}]")
        for j, b in enumerate(i):
            idx[j] = b
        h = get_lib().lr_babel_packet_counter_new(idx, len(i), int(initial))
        if h == ffi.NULL:
            raise LrError(f"PacketCounter build failed: {last_error()}")
        return cls(h)

    @property
    def counter(self) -> int:
        return int(get_lib().lr_babel_packet_counter_peek_counter(self._c))

    @property
    def index_len(self) -> int:
        return int(get_lib().lr_babel_packet_counter_peek_index_len(self._c))

    @property
    def index(self) -> bytes:
        n = self.index_len
        if n == 0:
            return b""
        out = ffi.new(f"uint8_t[{n}]")
        rc = get_lib().lr_babel_packet_counter_peek_index_copy(self._c, out, n)
        _check_rc(rc, "PacketCounter.index")
        return bytes(out[i] for i in range(n))

    def close(self) -> None:
        if not self._freed and getattr(self, "_c", None) is not None:
            get_lib().lr_babel_packet_counter_free(self._c)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "PacketCounter":
        return self

    def __exit__(self, *_):
        self.close()


class ReplayProtection:
    """Replay-protection state for the inbound direction (RFC 8967
    §3.3) — tracks the highest counter value seen so far per index."""

    __slots__ = ("_r", "_freed")

    def __init__(self, _r):
        self._r = _r
        self._freed = False

    @classmethod
    def new(cls) -> "ReplayProtection":
        return cls(get_lib().lr_babel_replay_protection_new())

    def accept(self, index: bytes, counter: int) -> bool:
        """Accept a packet with the given index + counter. Returns
        ``True`` when the counter is strictly greater than the
        previously-accepted counter for this index, ``False`` when
        it is a replay (counter <= previously accepted)."""
        i = bytes(index)
        idx = ffi.new(f"uint8_t[{max(len(i), 1)}]")
        for j, b in enumerate(i):
            idx[j] = b
        rc = get_lib().lr_babel_replay_protection_accept(self._r, idx, len(i), int(counter))
        if rc < 0:
            raise LrError(f"ReplayProtection.accept failed (rc={rc}): {last_error()}")
        return bool(rc)

    def close(self) -> None:
        if not self._freed and getattr(self, "_r", None) is not None:
            get_lib().lr_babel_replay_protection_free(self._r)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "ReplayProtection":
        return self

    def __exit__(self, *_):
        self.close()


# =========================================================================
# Babel message constructors — RFC 8966 §4.4 — individual TLV builders
# with structured fields. Each is a thin RAII handle that knows how to
# encode itself to its on-the-wire form.
# =========================================================================


class Hello:
    """A Hello TLV (RFC 8966 §3.4.1 + §4.4.5) — seqno + interval +
    unicast flag + optional timestamp (RFC 8966 §3.4.3)."""

    __slots__ = ("_h", "_freed")

    def __init__(self, _h):
        self._h = _h
        self._freed = False

    @classmethod
    def new(cls, seqno: int, interval_cs: int) -> "Hello":
        return cls(get_lib().lr_babel_hello_new(int(seqno), int(interval_cs)))

    def set_unicast(self, on: bool) -> None:
        rc = get_lib().lr_babel_hello_set_unicast(self._h, 1 if on else 0)
        _check_rc(rc, "Hello.set_unicast")

    @property
    def seqno(self) -> int:
        return int(get_lib().lr_babel_hello_seqno(self._h))

    @property
    def interval_cs(self) -> int:
        return int(get_lib().lr_babel_hello_interval_cs(self._h))

    @property
    def flags(self) -> int:
        return int(get_lib().lr_babel_hello_flags(self._h))

    @property
    def timestamp(self) -> Optional[int]:
        out = ffi.new("uint32_t*")
        rc = get_lib().lr_babel_hello_timestamp(self._h, out)
        if rc < 0:
            return None
        return int(out[0])

    def encode(self) -> bytes:
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_hello_encode(self._h, b)
        _check_rc(rc, "Hello.encode")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def close(self) -> None:
        if not self._freed and getattr(self, "_h", None) is not None:
            get_lib().lr_babel_hello_free(self._h)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "Hello":
        return self

    def __exit__(self, *_):
        self.close()


class Ihu:
    """An IHU (I Heard You) TLV (RFC 8966 §3.4.2 + §4.4.6) — ae +
    rxcost + interval + address."""

    __slots__ = ("_h", "_freed")

    def __init__(self, _h):
        self._h = _h
        self._freed = False

    @classmethod
    def new(cls, rxcost: int, interval_cs: int) -> "Ihu":
        return cls(get_lib().lr_babel_ihu_new(int(rxcost), int(interval_cs)))

    @property
    def ae(self) -> int:
        return int(get_lib().lr_babel_ihu_ae(self._h))

    @property
    def rxcost(self) -> int:
        return int(get_lib().lr_babel_ihu_rxcost(self._h))

    @property
    def interval_cs(self) -> int:
        return int(get_lib().lr_babel_ihu_interval_cs(self._h))

    @property
    def address(self) -> Optional[bytes]:
        out = ffi.new("uint8_t[16]")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_babel_ihu_address(self._h, out, present)
        _check_rc(rc, "Ihu.address")
        if int(present[0]) == 0:
            return None
        is_v6 = self.ae == AE_IPV6 or self.ae == AE_IPV6_LINK_LOCAL
        if is_v6:
            return bytes(out[i] for i in range(16))
        return bytes(out[i] for i in range(4))

    def encode(self) -> bytes:
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_ihu_encode(self._h, b)
        _check_rc(rc, "Ihu.encode")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def close(self) -> None:
        if not self._freed and getattr(self, "_h", None) is not None:
            get_lib().lr_babel_ihu_free(self._h)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "Ihu":
        return self

    def __exit__(self, *_):
        self.close()


class AckReq:
    """An Acknowledgment Request TLV (RFC 8966 §3.3 + §4.4.7) —
    nonce + interval."""

    __slots__ = ("_a", "_freed")

    def __init__(self, _a):
        self._a = _a
        self._freed = False

    @classmethod
    def new(cls, nonce: int, interval_cs: int) -> "AckReq":
        return cls(get_lib().lr_babel_ack_req_new(int(nonce), int(interval_cs)))

    @property
    def nonce(self) -> int:
        return int(get_lib().lr_babel_ack_req_nonce(self._a))

    @property
    def interval_cs(self) -> int:
        return int(get_lib().lr_babel_ack_req_interval_cs(self._a))

    def close(self) -> None:
        if not self._freed and getattr(self, "_a", None) is not None:
            get_lib().lr_babel_ack_req_free(self._a)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "AckReq":
        return self

    def __exit__(self, *_):
        self.close()


class Ack:
    """An Acknowledgment TLV (RFC 8966 §3.3 + §4.4.8) — the
    16-bit opaque value the responder echoes back from the AckReq."""

    __slots__ = ("_a", "_freed")

    def __init__(self, _a):
        self._a = _a
        self._freed = False

    @classmethod
    def new(cls, opaque: int) -> "Ack":
        return cls(get_lib().lr_babel_ack_new(int(opaque)))

    @property
    def opaque(self) -> int:
        return int(get_lib().lr_babel_ack_opaque(self._a))

    def encode(self) -> bytes:
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_ack_encode(self._a, b)
        _check_rc(rc, "Ack.encode")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def close(self) -> None:
        if not self._freed and getattr(self, "_a", None) is not None:
            get_lib().lr_babel_ack_free(self._a)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "Ack":
        return self

    def __exit__(self, *_):
        self.close()


class NextHop:
    """A Next Hop TLV (RFC 8966 §4.4.9) — AE + address. Carries the
    next-hop address for the *following* Update TLVs in the same
    frame."""

    __slots__ = ("_n", "_freed")

    def __init__(self, _n):
        self._n = _n
        self._freed = False

    @classmethod
    def new(cls, address: bytes) -> "NextHop":
        if len(address) == 4:
            return cls(get_lib().lr_babel_next_hop_new_v4(_copy_to_c(address, 4)))
        if len(address) == 16:
            return cls(get_lib().lr_babel_next_hop_new_v6(_copy_to_c(address, 16)))
        raise LrError("address must be 4 or 16 bytes")

    @property
    def ae(self) -> int:
        return int(get_lib().lr_babel_next_hop_ae(self._n))

    @property
    def address(self) -> bytes:
        out = ffi.new("uint8_t[16]")
        n = get_lib().lr_babel_next_hop_address(self._n, out, 16)
        n = int(n)
        if n == 0:
            return b""
        # For IPv4, the C ABI writes the 4-byte address into the
        # FIRST 4 bytes of out (not the IPv4-mapped IPv6 layout).
        return bytes(out[i] for i in range(n))

    def encode(self) -> bytes:
        b = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_babel_next_hop_encode(self._n, b)
        _check_rc(rc, "NextHop.encode")
        n = int(get_lib().lr_bytes_len(b))
        if n == 0:
            get_lib().lr_bytes_free(b)
            return b""
        ptr = get_lib().lr_bytes_ptr(b)
        out = ffi.buffer(ptr, n)[:]
        get_lib().lr_bytes_free(b)
        return out

    def close(self) -> None:
        if not self._freed and getattr(self, "_n", None) is not None:
            get_lib().lr_babel_next_hop_free(self._n)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "NextHop":
        return self

    def __exit__(self, *_):
        self.close()


class RouterId:
    """A Router-Id TLV (RFC 8966 §4.4.10) — the 8-byte router
    identifier in effect for the *following* Update TLVs in the same
    frame."""

    __slots__ = ("_r", "_freed")

    def __init__(self, _r):
        self._r = _r
        self._freed = False

    @classmethod
    def new(cls, router_id: bytes) -> "RouterId":
        if len(router_id) != 8:
            raise LrError("router_id must be exactly 8 bytes")
        rid = _copy_to_c(router_id, 8)
        return cls(get_lib().lr_babel_router_id_new(rid))

    @property
    def bytes_(self) -> bytes:
        # The C ABI copies 10 bytes out (2 reserved + 8 router_id).
        out = ffi.new("uint8_t[10]")
        rc = get_lib().lr_babel_router_id_bytes(self._r, out)
        _check_rc(rc, "RouterId.bytes")
        # The router_id occupies bytes 2..10 (RFC 8966 §4.4.10 — the
        # first 2 bytes are reserved/zero).
        return bytes(out[i] for i in range(2, 10))

    def close(self) -> None:
        if not self._freed and getattr(self, "_r", None) is not None:
            get_lib().lr_babel_router_id_free(self._r)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "RouterId":
        return self

    def __exit__(self, *_):
        self.close()


class RouteRequest:
    """A Route Request TLV (RFC 8966 §3.3.1 + §4.4.11). The wildcard
    form requests every destination the peer knows."""

    __slots__ = ("_r", "_freed")

    def __init__(self, _r):
        self._r = _r
        self._freed = False

    @classmethod
    def new_wildcard(cls) -> "RouteRequest":
        return cls(get_lib().lr_babel_route_request_new_wildcard())

    def close(self) -> None:
        if not self._freed and getattr(self, "_r", None) is not None:
            get_lib().lr_babel_route_request_free(self._r)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "RouteRequest":
        return self

    def __exit__(self, *_):
        self.close()


class SeqnoRequest:
    """A Seqno Request TLV (RFC 8966 §3.3.2 + §4.4.12) — asks the
    peer to re-announce a specific (prefix, seqno) tuple. The
    hop-count limits propagation through the mesh."""

    __slots__ = ("_r", "_freed")

    def __init__(self, _r):
        self._r = _r
        self._freed = False

    @classmethod
    def new(cls, prefix: bytes, prefix_len: int, seqno: int,
            router_id: bytes, hop_count: int = 255) -> "SeqnoRequest":
        """Build a Seqno Request for the given ``prefix`` (4 or 16
        bytes), the requested ``seqno``, the 8-byte ``router_id`` of
        the requesting router, and the ``hop_count`` (default 255 —
        the maximum TTL)."""
        if len(prefix) == 4:
            v4 = _addr_ptr(prefix)
            v6 = ffi.NULL
        elif len(prefix) == 16:
            v4 = ffi.NULL
            v6 = _addr_ptr(prefix)
        else:
            raise LrError("prefix must be 4 or 16 bytes")
        if len(router_id) != 8:
            raise LrError("router_id must be exactly 8 bytes")
        rid = ffi.new("uint8_t[8]")
        for i, b in enumerate(router_id):
            rid[i] = b
        h = get_lib().lr_babel_seqno_request_new(
            v4, v6, int(prefix_len), int(seqno), rid, int(hop_count)
        )
        if h == ffi.NULL:
            raise LrError(f"SeqnoRequest build failed: {last_error()}")
        return cls(h)

    def close(self) -> None:
        if not self._freed and getattr(self, "_r", None) is not None:
            get_lib().lr_babel_seqno_request_free(self._r)
            self._freed = True

    def __del__(self):
        self.close()

    def __enter__(self) -> "SeqnoRequest":
        return self

    def __exit__(self, *_):
        self.close()


# =========================================================================
# Free functions — metric helpers (RFC 8966 §A.2.4 / §3.1 / §3.2.2).
# =========================================================================


def rtt_penalty(rtt_us: int, rtt_min_us: int, rtt_max_us: int, max_penalty: int) -> int:
    """The RTT-based extra link cost (RFC 8966 §A.2.4, BABEL-RTT): a
    linear ramp from 0 at ``rtt_min_us`` to ``max_penalty`` at
    ``rtt_max_us``, clamped at ``max_penalty`` above it. A
    ``max_penalty == 0`` disables the feature."""
    return int(get_lib().lr_babel_rtt_penalty(int(rtt_us), int(rtt_min_us),
                                              int(rtt_max_us), int(max_penalty)))


def route_metric_sum(link_metrics: Sequence[int]) -> int:
    """Sum a list of per-link metric values (RFC 8966 §3.1 — the
    total route metric is the sum of the link costs along the path)."""
    if not link_metrics:
        return 0
    arr = ffi.new(f"uint32_t[{len(link_metrics)}]")
    for i, m in enumerate(link_metrics):
        arr[i] = int(m)
    return int(get_lib().lr_babel_route_metric_sum(arr, len(link_metrics)))


def feasible(route_seqno: int, route_metric: int,
             feasible_seqno: int, feasible_metric: int) -> bool:
    """The Babel feasibility condition (RFC 8966 §3.2.2): a route is
    feasible iff its (seqno, metric) pair is strictly better than
    the current best-known feasible metric for the same source."""
    return bool(get_lib().lr_babel_feasible(int(route_seqno), int(route_metric),
                                             int(feasible_seqno), int(feasible_metric)))


# ---- internal helper used by NextHop / RouterId ----

def _copy_to_c(src: bytes, n: int):
    if len(src) != n:
        raise LrError(f"expected {n} bytes, got {len(src)}")
    out = ffi.new(f"uint8_t[{n}]")
    for i, b in enumerate(src):
        out[i] = b
    return out
