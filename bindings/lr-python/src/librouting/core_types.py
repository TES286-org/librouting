"""Foundational lr-core value types — IpAddr, CorePrefix, Asn,
RouterId, Instant, Duration, Preference, Protocol, RouteKey,
NlriFamily, plus the ReadBuf / WriteBuf / TimerQueue / MemoryConn
owned handles and the CRC/Fletcher utility functions.

Mirrors ``crates/lr-core/src/addr.rs`` (``IpAddr``, ``Prefix``,
``Asn``, ``RouterId``), ``crates/lr-core/src/rib.rs`` (``Protocol``,
``RouteKey``, ``Preference``, ``RouteOrigin``),
``crates/lr-core/src/nlri.rs`` (``NlriFamily``),
``crates/lr-core/src/buf.rs`` (``ReadBuf``, ``WriteBuf``),
``crates/lr-core/src/timer.rs`` (``TimerQueue``, ``TimerSpec``),
``crates/lr-core/src/checksum.rs`` (CRC/Fletcher utilities) and the
``MemoryConn`` test transport in ``crates/lr-ffi/src/memory_conn.rs``.

The repr-C structs returned by the C ABI are passed by value where the
ABI does so (``lr_ip_addr_t`` is 17 bytes + padding; ``lr_asn_t`` /
``lr_router_id_t`` / ``lr_preference_t`` are 4-8 bytes) and as opaque
``cdata`` handles when the ABI boxes them (``IpAddr *``,
``lr_read_buf_t``, ``lr_write_buf_t``, ``lr_timer_queue_t``,
``lr_memory_conn_t``).

The Python class hierarchy mirrors the Rust module split:

    lr_core::addr::IpAddr         -> IpAddr
    lr_core::addr::Prefix         -> CorePrefix
    lr_core::addr::Asn            -> Asn
    lr_core::addr::RouterId       -> RouterId
    lr_core::rib::Protocol        -> Protocol (constants + helpers)
    lr_core::rib::RouteKey        -> RouteKey
    lr_core::rib::Preference       -> Preference
    lr_core::nlri::NlriFamily     -> NlriFamily
    lr_core::buf::ReadBuf         -> ReadBuf
    lr_core::buf::WriteBuf        -> WriteBuf
    lr_core::timer::TimerQueue    -> TimerQueue
    lr_core::timer::TimerSpec     -> TimerSpec
    lr_core::checksum::crc16_arc  -> crc16_arc
    lr_core::checksum::crc32c    -> crc32c
    lr_core::checksum::fletcher32 -> fletcher32
    lr_core::time::Instant        -> Instant (free functions)
    lr_core::time::Duration       -> Duration (free functions)
    lr_ffi::memory_conn::MemoryConn -> MemoryConn

Owned resources are released via ``__del__`` finalizers — the
Python-side equivalent of the Go runtime.SetFinalizer and the C++
RAII wrapper. Plain value types (``IpAddr``, ``Asn``, etc.) are
dataclass-style and hold their ``cdata`` inline; they do not need
finalizers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from ._ffi import ffi, get_lib
from .router import LrError, last_error


# ---- Protocol constants (mirror lr_ffi.h LR_PROTOCOL_*) ----
#
# These mirror the C ABI's `LR_PROTOCOL_*` enum:
#   LR_PROTOCOL_BGP       = 0
#   LR_PROTOCOL_OSPFV2    = 1
#   LR_PROTOCOL_OSPFV3    = 2
#   LR_PROTOCOL_BABEL     = 3
#   LR_PROTOCOL_STATIC    = 4
#   LR_PROTOCOL_CONNECTED = 5
#   LR_PROTOCOL_OTHER     = 6
#
# For backwards compatibility the existing ``PROTO_BGP`` /
# ``PROTO_OSPF`` / ``PROTO_OSPF3`` / ``PROTO_BABEL`` / ``PROTO_STATIC``
# / ``PROTO_CONNECTED`` names (defined in :mod:`librouting.router`)
# remain the canonical Python names; this module re-exports them and
# adds the only C ABI constant they did not cover — ``PROTO_OTHER``
# (a.k.a. ``LR_PROTOCOL_OTHER``).

from .router import (
    PROTO_BGP,
    PROTO_OSPF,
    PROTO_OSPF3,
    PROTO_BABEL,
    PROTO_STATIC,
    PROTO_CONNECTED,
)

PROTO_OTHER = 6


def _check_rc(rc: int, what: str) -> None:
    """Raise LrError on a non-zero rc unless the rc is a positive
    count (used by the ABI for array sizes / counters). Negative rc
    is always an error."""
    if rc < 0:
        raise LrError(f"{what}: {last_error()} (rc={rc})")


def _check_rc_zero(rc: int, what: str) -> None:
    """Raise on rc != 0. Use this for setters that return 0 on
    success and a negative LR_ERR_* code otherwise."""
    if rc != 0:
        raise LrError(f"{what}: {last_error()} (rc={rc})")


# ---- IpAddr (RFC 4291 / RFC 4001) ----


@dataclass
class IpAddr:
    """IPv4 or IPv6 address.

    The C ABI represents it as ``lr_ip_addr_t`` (1-byte ``is_ipv6`` +
    16-byte ``octets``); IPv4 occupies the last 4 octets in the
    IPv4-mapped IPv6 form (``::ffff:a.b.c.d``). This class owns its
    ``cdata`` and is cheap to copy — no heap allocation, no
    finalizer."""

    cdata: object  # ffi.new("lr_ip_addr_t*")

    @classmethod
    def from_v4_bytes(cls, octets: bytes) -> "IpAddr":
        if len(octets) != 4:
            raise ValueError(f"IPv4 address requires 4 bytes, got {len(octets)}")
        buf = ffi.new("uint8_t[]", list(octets))
        c = get_lib().lr_ip_addr_v4(buf)
        return cls(cdata=c)

    @classmethod
    def from_v6_bytes(cls, octets: bytes) -> "IpAddr":
        if len(octets) != 16:
            raise ValueError(f"IPv6 address requires 16 bytes, got {len(octets)}")
        buf = ffi.new("uint8_t[]", list(octets))
        c = get_lib().lr_ip_addr_v6(buf)
        return cls(cdata=c)

    @classmethod
    def from_bytes(cls, octets: bytes) -> "IpAddr":
        if len(octets) == 4:
            return cls.from_v4_bytes(octets)
        if len(octets) == 16:
            return cls.from_v6_bytes(octets)
        raise ValueError(f"IP address requires 4 or 16 bytes, got {len(octets)}")

    @classmethod
    def from_str(cls, s: str) -> "IpAddr":
        """Parse the standard textual form (``a.b.c.d`` or
        ``xxxx:xxxx:...``)."""
        import ipaddress

        a = ipaddress.ip_address(s)
        return cls.from_bytes(a.packed)

    @property
    def is_ipv4(self) -> bool:
        return bool(get_lib().lr_ip_addr_is_ipv4(self.cdata))

    @property
    def is_ipv6(self) -> bool:
        return bool(get_lib().lr_ip_addr_is_ipv6(self.cdata))

    @property
    def is_unspecified(self) -> bool:
        return bool(get_lib().lr_ip_addr_is_unspecified(self.cdata))

    @property
    def is_multicast(self) -> bool:
        return bool(get_lib().lr_ip_addr_is_multicast(self.cdata))

    def octets(self) -> bytes:
        """Return the address as 4 (V4) or 16 (V6) bytes."""
        cap = 16
        buf = ffi.new("uint8_t[]", cap)
        n = get_lib().lr_ip_addr_octets(self.cdata, buf, cap)
        return bytes(buf[0:n])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IpAddr):
            return NotImplemented
        return self.octets() == other.octets()

    def __hash__(self) -> int:
        return hash(self.octets())

    def __str__(self) -> str:
        import ipaddress

        if self.is_ipv4:
            return str(ipaddress.IPv4Address(self.octets()))
        return str(ipaddress.IPv6Address(self.octets()))

    def __repr__(self) -> str:
        return f"IpAddr({self})"


class BoxedIpAddr:
    """Boxed ``IpAddr *`` handle (the C ABI's second IpAddr surface,
    ``lr_ip_addr_from_v4_bytes`` etc). Returned by
    ``lr_ip_addr_to_ipv4_mapped``; freed via ``lr_ip_addr_free``."""

    __slots__ = ("_ptr", "_freed")

    def __init__(self, ptr) -> None:
        self._ptr = ptr
        self._freed = False

    def __del__(self) -> None:
        self._close()

    def _close(self) -> None:
        if not self._freed and self._ptr is not None:
            get_lib().lr_ip_addr_free(self._ptr)
            self._freed = True

    def close(self) -> None:
        """Release the boxed handle explicitly."""
        self._close()

    @classmethod
    def from_v4_bytes(cls, octets: bytes) -> "BoxedIpAddr":
        if len(octets) != 4:
            raise ValueError(f"IPv4 address requires 4 bytes, got {len(octets)}")
        buf = ffi.new("uint8_t[]", list(octets))
        p = get_lib().lr_ip_addr_from_v4_bytes(buf)
        if p == ffi.NULL:
            raise LrError("lr_ip_addr_from_v4_bytes returned null")
        return cls(p)

    @classmethod
    def from_v6_bytes(cls, octets: bytes) -> "BoxedIpAddr":
        if len(octets) != 16:
            raise ValueError(f"IPv6 address requires 16 bytes, got {len(octets)}")
        buf = ffi.new("uint8_t[]", list(octets))
        p = get_lib().lr_ip_addr_from_v6_bytes(buf)
        if p == ffi.NULL:
            raise LrError("lr_ip_addr_from_v6_bytes returned null")
        return cls(p)

    @classmethod
    def from_bytes(cls, octets: bytes) -> "BoxedIpAddr":
        if len(octets) == 4:
            return cls.from_v4_bytes(octets)
        if len(octets) == 16:
            return cls.from_v6_bytes(octets)
        raise ValueError(f"IP address requires 4 or 16 bytes, got {len(octets)}")

    @property
    def is_ipv4_mapped_ipv6(self) -> bool:
        return bool(get_lib().lr_ip_addr_is_ipv4_mapped_ipv6(self._ptr))

    def to_ipv4_mapped(self) -> Optional["BoxedIpAddr"]:
        """Convert IPv4 to its IPv4-mapped IPv6 form (``::ffff:a.b.c.d``).
        Returns ``None`` when the input is already IPv6 (no fresh
        allocation is needed)."""
        p = get_lib().lr_ip_addr_to_ipv4_mapped(self._ptr)
        if p == ffi.NULL:
            return None
        return BoxedIpAddr(p)


# ---- CorePrefix (RFC 4632 / RFC 4291) ----


@dataclass
class CorePrefix:
    """IP prefix (RFC 4632 §3.1)."""

    cdata: object  # ffi.new("lr_core_prefix_t*")

    @classmethod
    def v4(cls, octets: bytes, prefix_len: int) -> "CorePrefix":
        if len(octets) != 4:
            raise ValueError(f"IPv4 prefix address requires 4 bytes, got {len(octets)}")
        if not 0 <= prefix_len <= 32:
            raise ValueError(f"IPv4 prefix_len out of range: {prefix_len}")
        buf = ffi.new("uint8_t[]", list(octets))
        c = get_lib().lr_core_prefix_v4(buf, prefix_len)
        return cls(cdata=c)

    @classmethod
    def v6(cls, octets: bytes, prefix_len: int) -> "CorePrefix":
        if len(octets) != 16:
            raise ValueError(f"IPv6 prefix address requires 16 bytes, got {len(octets)}")
        if not 0 <= prefix_len <= 128:
            raise ValueError(f"IPv6 prefix_len out of range: {prefix_len}")
        buf = ffi.new("uint8_t[]", list(octets))
        c = get_lib().lr_core_prefix_v6(buf, prefix_len)
        return cls(cdata=c)

    @classmethod
    def from_str(cls, s: str) -> "CorePrefix":
        import ipaddress

        net = ipaddress.ip_network(s, strict=False)
        return cls.v4(net.network_address.packed, net.prefixlen) \
            if isinstance(net, ipaddress.IPv4Network) \
            else cls.v6(net.network_address.packed, net.prefixlen)

    @property
    def is_ipv4(self) -> bool:
        return bool(get_lib().lr_core_prefix_is_ipv4(self.cdata))

    @property
    def is_ipv6(self) -> bool:
        return bool(get_lib().lr_core_prefix_is_ipv6(self.cdata))

    @property
    def prefix_len(self) -> int:
        return int(self.cdata.prefix_len)

    def addr(self) -> IpAddr:
        """Return the address part as an IpAddr."""
        c = get_lib().lr_ip_addr_v4(ffi.NULL)  # safe no-op produces default
        # Copy the addr field into a new lr_ip_addr_t
        out = ffi.new("lr_ip_addr_t*")
        out.is_ipv6 = self.cdata.addr.is_ipv6
        for i in range(16):
            out.octets[i] = self.cdata.addr.octets[i]
        return IpAddr(cdata=out[0])

    def contains(self, addr: IpAddr) -> bool:
        return bool(get_lib().lr_core_prefix_contains(self.cdata, addr.cdata))

    def contains_prefix(self, inner: "CorePrefix") -> bool:
        return bool(get_lib().lr_core_prefix_contains_prefix(self.cdata, inner.cdata))

    def network(self) -> IpAddr:
        """Compute the network address (host bits zeroed)."""
        out = ffi.new("lr_ip_addr_t*")
        rc = get_lib().lr_core_prefix_network(self.cdata, out)
        _check_rc_zero(rc, "lr_core_prefix_network")
        return IpAddr(cdata=out[0])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CorePrefix):
            return NotImplemented
        return (self.is_ipv4 == other.is_ipv4
                and self.prefix_len == other.prefix_len
                and self.addr().octets() == other.addr().octets())

    def __hash__(self) -> int:
        return hash((self.is_ipv4, self.prefix_len, self.addr().octets()))

    def __str__(self) -> str:
        return f"{self.addr()}/{self.prefix_len}"

    def __repr__(self) -> str:
        return f"CorePrefix({self})"


# ---- Asn (RFC 6996 / RFC 6793) ----


@dataclass
class Asn:
    """Autonomous System Number (RFC 6996)."""

    cdata: object  # ffi.new("lr_asn_t*")

    @classmethod
    def new(cls, value: int) -> "Asn":
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"ASN out of u32 range: {value}")
        c = get_lib().lr_asn_new(value)
        return cls(cdata=c)

    @property
    def value(self) -> int:
        return int(self.cdata.value)

    @property
    def is_private(self) -> bool:
        """True for RFC 6996 private ranges (64512..=65534 or
        4200000000..=4294967294)."""
        return bool(get_lib().lr_asn_is_private(self.cdata))

    @property
    def is_as_trans(self) -> bool:
        """True for AS_TRANS (23456, RFC 6793 §4.2.3 — the placeholder
        for 4-byte ASes on a 2-byte session)."""
        return bool(get_lib().lr_asn_is_as_trans(self.cdata))

    @property
    def is_as23456(self) -> bool:
        """Alias for ``is_as_trans`` (named after the actual AS value)."""
        return bool(get_lib().lr_asn_is_as23456(self.cdata))

    def as_u32(self) -> int:
        return get_lib().lr_asn_as_u32(self.value)

    def as_u16(self) -> int:
        """16-bit AS value, or 0 when the value does not fit (RFC 4893
        AS_TRANS upgrade path)."""
        return get_lib().lr_asn_as_u16(self.value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Asn):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __int__(self) -> int:
        return self.value

    def __repr__(self) -> str:
        return f"Asn({self.value})"


# ---- RouterId ----


@dataclass
class RouterId:
    """OSPF/BGP Router ID — a 32-bit value usually rendered as
    ``a.b.c.d``."""

    cdata: object  # ffi.new("lr_router_id_t*")

    @classmethod
    def from_u32(cls, value: int) -> "RouterId":
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"RouterId out of u32 range: {value}")
        c = get_lib().lr_router_id_from_u32(value)
        return cls(cdata=c)

    @classmethod
    def from_v4(cls, octets: bytes) -> "RouterId":
        if len(octets) != 4:
            raise ValueError(f"RouterId from_v4 requires 4 bytes, got {len(octets)}")
        buf = ffi.new("uint8_t[]", list(octets))
        c = get_lib().lr_router_id_from_v4(buf)
        return cls(cdata=c)

    @property
    def value(self) -> int:
        return int(self.cdata.value)

    def to_v4_bytes(self) -> bytes:
        out = ffi.new("uint8_t[4]")
        rc = get_lib().lr_router_id_to_v4_bytes(self.cdata, out)
        _check_rc_zero(rc, "lr_router_id_to_v4_bytes")
        return bytes(out[0:4])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RouterId):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __int__(self) -> int:
        return self.value

    def __str__(self) -> str:
        b = self.to_v4_bytes()
        return ".".join(str(x) for x in b)

    def __repr__(self) -> str:
        return f"RouterId({self})"


# ---- Protocol helpers ----


def protocol_bird_name(proto: int) -> str:
    """Read the BIRD-style name of a ``PROTO_*`` constant
    (e.g. ``"bgp"``, ``"ospf"``)."""
    cap = 32
    buf = ffi.new("char[]", cap)
    n = get_lib().lr_protocol_bird_name(proto, buf, cap)
    if n == 0:
        return ""
    return ffi.string(buf, n).decode("utf-8")


def protocol_default_admin_distance(proto: int) -> int:
    """Default administrative distance for a ``PROTO_*`` constant
    (e.g. 20 for BGP eBGP, 110 for OSPF)."""
    return int(get_lib().lr_protocol_default_admin_distance(proto))


# ---- Instant / Duration (free functions; the C ABI represents
#      them as plain u64 milliseconds) ----


def instant_from_millis(millis: int) -> int:
    return int(get_lib().lr_instant_from_millis(millis))


def instant_from_secs(secs: int) -> int:
    return int(get_lib().lr_instant_from_secs(secs))


def instant_as_millis(instant: int) -> int:
    return int(get_lib().lr_instant_as_millis(instant))


def instant_as_secs(instant: int) -> int:
    return int(get_lib().lr_instant_as_secs(instant))


def instant_saturating_sub(earlier: int, later: int) -> int:
    """``max(0, later - earlier)`` in milliseconds."""
    return int(get_lib().lr_instant_saturating_sub(earlier, later))


def instant_checked_add(instant: int, duration_ms: int) -> int:
    """``instant + duration_ms`` with overflow check (returns the
    new instant on success, raises on overflow)."""
    return int(get_lib().lr_instant_checked_add(instant, duration_ms))


def instant_checked_sub(instant: int, other: int) -> Optional[int]:
    """``instant - other`` with underflow check. Returns ``None`` when
    the subtraction would underflow (the C ABI returns
    ``LR_ERR_INVALID_HANDLE`` for that case)."""
    LR_ERR_INVALID_HANDLE = -2
    out = ffi.new("uint64_t*")
    rc = get_lib().lr_instant_checked_sub(instant, other, out)
    if rc == LR_ERR_INVALID_HANDLE:
        return None
    _check_rc_zero(rc, "lr_instant_checked_sub")
    return int(out[0])


def duration_from_millis(millis: int) -> int:
    return int(get_lib().lr_duration_from_millis(millis))


def duration_from_secs(secs: int) -> int:
    return int(get_lib().lr_duration_from_secs(secs))


def duration_as_millis(duration_ms: int) -> int:
    return int(get_lib().lr_duration_as_millis(duration_ms))


def duration_as_secs(duration_ms: int) -> int:
    return int(get_lib().lr_duration_as_secs(duration_ms))


def duration_checked_add(a: int, b: int) -> int:
    return int(get_lib().lr_duration_checked_add(a, b))


# ---- RouteKey ----


# ---- RawRouteKey (direct lr_route_key_t wrapper) ----
#
# The user-friendly ``librouting.RouteKey`` (in ``rib.py``) is the
# Pythonic dataclass form; this class is the low-level direct
# wrapper around the C ABI's ``lr_route_key_t`` and the
# ``lr_route_key_new`` / ``lr_route_key_with_source`` constructors.
# Most Python embedders want the high-level form.


@dataclass
class RawRouteKey:
    """Direct wrapper around ``lr_route_key_t``.

    Most Python embedders want :class:`librouting.RouteKey` (the
    Pythonic dataclass in :mod:`librouting.rib`); this class exists
    for parity with the C ABI ``lr_route_key_new`` /
    ``lr_route_key_with_source`` constructors."""

    cdata: object  # ffi.new("lr_route_key_t*")

    @classmethod
    def new(cls, prefix: CorePrefix, afi_safi: int) -> "RawRouteKey":
        if not 0 <= afi_safi <= 0xFFFF:
            raise ValueError(f"afi_safi out of u16 range: {afi_safi}")
        out = ffi.new("lr_route_key_t*")
        rc = get_lib().lr_route_key_new(prefix.cdata, afi_safi, out)
        _check_rc_zero(rc, "lr_route_key_new")
        return cls(cdata=out)

    @classmethod
    def with_source(cls, prefix: CorePrefix, afi_safi: int,
                    source: CorePrefix) -> "RawRouteKey":
        out = ffi.new("lr_route_key_t*")
        rc = get_lib().lr_route_key_with_source(prefix.cdata, afi_safi,
                                                 source.cdata, out)
        _check_rc_zero(rc, "lr_route_key_with_source")
        return cls(cdata=out)

    @property
    def prefix(self) -> CorePrefix:
        c = ffi.new("lr_core_prefix_t*")
        c.addr.is_ipv6 = self.cdata.prefix.addr.is_ipv6
        for i in range(16):
            c.addr.octets[i] = self.cdata.prefix.addr.octets[i]
        c.prefix_len = self.cdata.prefix.prefix_len
        return CorePrefix(cdata=c[0])

    @property
    def afi_safi(self) -> int:
        return int(self.cdata.afi_safi)

    @property
    def has_source(self) -> bool:
        return bool(self.cdata.has_source)

    @property
    def source_prefix(self) -> Optional[CorePrefix]:
        if not self.has_source:
            return None
        c = ffi.new("lr_core_prefix_t*")
        c.addr.is_ipv6 = self.cdata.source_prefix.addr.is_ipv6
        for i in range(16):
            c.addr.octets[i] = self.cdata.source_prefix.addr.octets[i]
        c.prefix_len = self.cdata.source_prefix.prefix_len
        return CorePrefix(cdata=c[0])


# ---- Preference ----


@dataclass
class Preference:
    """Administrative distance + metric pair (RFC 4271 §9)."""

    admin_distance: int
    metric: int

    @classmethod
    def new(cls, admin_distance: int, metric: int) -> "Preference":
        c = get_lib().lr_preference_new(admin_distance, metric)
        return cls(admin_distance=int(c.admin_distance),
                   metric=int(c.metric))


# ---- NlriFamily (RFC 4760) ----


@dataclass
class NlriFamily:
    """AFI + SAFI pair (RFC 4760). Stored as a 16-bit AFI + 8-bit
    SAFI in ``lr_afi_safi_t`` (alias ``lr_nlri_family_t``)."""

    cdata: object  # ffi.new("lr_nlri_family_t*")

    @property
    def afi(self) -> int:
        return int(self.cdata.afi)

    @property
    def safi(self) -> int:
        return int(self.cdata.safi)

    @property
    def is_ipv4(self) -> bool:
        return bool(get_lib().lr_nlri_family_is_ipv4(self.cdata[0]))

    @property
    def is_ipv6(self) -> bool:
        return bool(get_lib().lr_nlri_family_is_ipv6(self.cdata[0]))

    @property
    def is_labeled_unicast(self) -> bool:
        return bool(get_lib().lr_nlri_family_is_labeled_unicast(self.cdata[0]))

    @property
    def is_bgp_ls(self) -> bool:
        return bool(get_lib().lr_nlri_family_is_bgp_ls(self.cdata[0]))

    @property
    def is_bgp_ls_vpn(self) -> bool:
        return bool(get_lib().lr_nlri_family_is_bgp_ls_vpn(self.cdata[0]))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NlriFamily):
            return NotImplemented
        return self.afi == other.afi and self.safi == other.safi

    def __hash__(self) -> int:
        return hash((self.afi, self.safi))

    def __repr__(self) -> str:
        return f"NlriFamily(afi={self.afi}, safi={self.safi})"


def _nlri_family_call(ctor) -> NlriFamily:
    """Call a `lr_nlri_family_*` constructor returning a
    `lr_nlri_family_t` by value, wrap the result."""
    c = ctor()
    # c is a lr_afi_safi_t; copy into a stable cdata
    out = ffi.new("lr_nlri_family_t*")
    out.afi = c.afi
    out.safi = c.safi
    return NlriFamily(cdata=out)


def nlri_family_ipv4_unicast() -> NlriFamily:
    return _nlri_family_call(get_lib().lr_nlri_family_ipv4_unicast)


def nlri_family_ipv6_unicast() -> NlriFamily:
    return _nlri_family_call(get_lib().lr_nlri_family_ipv6_unicast)


def nlri_family_ipv4_multicast() -> NlriFamily:
    return _nlri_family_call(get_lib().lr_nlri_family_ipv4_multicast)


def nlri_family_ipv4_mpls_vpn() -> NlriFamily:
    return _nlri_family_call(get_lib().lr_nlri_family_ipv4_mpls_vpn)


def nlri_family_ipv6_mpls_vpn() -> NlriFamily:
    return _nlri_family_call(get_lib().lr_nlri_family_ipv6_mpls_vpn)


def nlri_family_ipv4_labeled_unicast() -> NlriFamily:
    return _nlri_family_call(get_lib().lr_nlri_family_ipv4_labeled_unicast)


def nlri_family_ipv6_labeled_unicast() -> NlriFamily:
    return _nlri_family_call(get_lib().lr_nlri_family_ipv6_labeled_unicast)


def nlri_family_bgp_ls() -> NlriFamily:
    return _nlri_family_call(get_lib().lr_nlri_family_bgp_ls)


def nlri_family_bgp_ls_vpn() -> NlriFamily:
    return _nlri_family_call(get_lib().lr_nlri_family_bgp_ls_vpn)


def nlri_family_from_addr(addr: BoxedIpAddr) -> NlriFamily:
    """Derive the family for a boxed IpAddr — V4 -> (1, 1), V6 -> (2, 1)."""
    out = ffi.new("lr_nlri_family_t*")
    rc = get_lib().lr_nlri_family_from_addr(addr._ptr, out)
    _check_rc_zero(rc, "lr_nlri_family_from_addr")
    return NlriFamily(cdata=out)


# ---- CRC / Fletcher / OSPF LSA checksum utilities ----


def crc16_arc(data: bytes) -> int:
    """RFC 1952 CRC-16/ARC over ``data``."""
    if not data:
        return int(get_lib().lr_crc16_arc(ffi.NULL, 0))
    buf = ffi.from_buffer(data) if len(data) > 0 else ffi.NULL
    return int(get_lib().lr_crc16_arc(buf, len(data)))


def crc32c(data: bytes) -> int:
    """RFC 3748 CRC-32C/Castagnoli over ``data``."""
    if not data:
        return int(get_lib().lr_crc32c(ffi.NULL, 0))
    buf = ffi.from_buffer(data)
    return int(get_lib().lr_crc32c(buf, len(data)))


def fletcher32(data: bytes) -> int:
    """Generic Fletcher-32 (RFC 2328 §C.4 / RFC 905 §A.3)."""
    if not data:
        return int(get_lib().lr_fletcher32(ffi.NULL, 0))
    buf = ffi.from_buffer(data)
    return int(get_lib().lr_fletcher32(buf, len(data)))


def ospf_lsa_checksum(lsa: bytes) -> int:
    """RFC 2328 §C.4 LSA checksum (Fletcher-16 over the LSA body)."""
    if len(lsa) < 20:
        return 0
    buf = ffi.from_buffer(lsa)
    return int(get_lib().lr_ospf_lsa_checksum(buf, len(lsa)))


def ospf_lsa_checksum_ok(lsa: bytes) -> bool:
    """True when the LSA's embedded checksum (offset 16-17) matches
    the computed Fletcher-16."""
    if len(lsa) < 20:
        return False
    buf = ffi.from_buffer(lsa)
    return bool(get_lib().lr_ospf_lsa_checksum_ok(buf, len(lsa)))


# ---- ReadBuf / WriteBuf ----


class ReadBuf:
    """Owned readable byte buffer with a position cursor (mirrors
    ``lr_core::buf::ReadBuf``)."""

    __slots__ = ("_ptr", "_freed", "_keepalive")

    def __init__(self, ptr, keepalive=None) -> None:
        self._ptr = ptr
        self._freed = False
        # The C ABI copies the data, so we can drop `keepalive` after
        # construction. We retain it only when the caller passes a
        # borrowed buffer.
        self._keepalive = keepalive

    def __del__(self) -> None:
        self._close()

    def _close(self) -> None:
        if not self._freed and self._ptr is not None:
            get_lib().lr_read_buf_free(self._ptr)
            self._freed = True

    def close(self) -> None:
        self._close()

    @classmethod
    def new(cls, data: bytes) -> "ReadBuf":
        if not data:
            p = get_lib().lr_read_buf_new(ffi.NULL, 0)
        else:
            buf = ffi.from_buffer(data)
            p = get_lib().lr_read_buf_new(buf, len(data))
        if p == ffi.NULL:
            raise LrError("lr_read_buf_new returned null")
        return cls(p)

    @property
    def remaining(self) -> int:
        return int(get_lib().lr_read_buf_remaining(self._ptr))

    @property
    def position(self) -> int:
        return int(get_lib().lr_read_buf_position(self._ptr))

    def advance(self, n: int) -> None:
        rc = get_lib().lr_read_buf_advance(self._ptr, n)
        _check_rc_zero(rc, "lr_read_buf_advance")

    def peek_u8(self) -> Optional[int]:
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_read_buf_peek_u8(self._ptr, out)
        if rc == 1:
            return None
        _check_rc_zero(rc, "lr_read_buf_peek_u8")
        return int(out[0])

    def get_u8(self) -> Optional[int]:
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_read_buf_get_u8(self._ptr, out)
        if rc == 1:
            return None
        _check_rc_zero(rc, "lr_read_buf_get_u8")
        return int(out[0])

    def get_u16_be(self) -> Optional[int]:
        out = ffi.new("uint16_t*")
        rc = get_lib().lr_read_buf_get_u16_be(self._ptr, out)
        if rc == 1:
            return None
        _check_rc_zero(rc, "lr_read_buf_get_u16_be")
        return int(out[0])

    def get_u32_be(self) -> Optional[int]:
        out = ffi.new("uint32_t*")
        rc = get_lib().lr_read_buf_get_u32_be(self._ptr, out)
        if rc == 1:
            return None
        _check_rc_zero(rc, "lr_read_buf_get_u32_be")
        return int(out[0])

    def get_u64_be(self) -> Optional[int]:
        out = ffi.new("uint64_t*")
        rc = get_lib().lr_read_buf_get_u64_be(self._ptr, out)
        if rc == 1:
            return None
        _check_rc_zero(rc, "lr_read_buf_get_u64_be")
        return int(out[0])

    def get_bytes(self, n: int) -> Optional[bytes]:
        out = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_read_buf_get_bytes(self._ptr, n, out)
        if rc == 1:
            return None
        _check_rc_zero(rc, "lr_read_buf_get_bytes")
        try:
            ptr = get_lib().lr_bytes_ptr(out)
            ln = get_lib().lr_bytes_len(out)
            return bytes(ffi.buffer(ptr, ln)) if ln else b""
        finally:
            get_lib().lr_bytes_free(out)

    def chunk(self) -> bytes:
        """Borrow the remaining bytes as a snapshot (does not advance)."""
        out = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_read_buf_chunk(self._ptr, out)
        _check_rc_zero(rc, "lr_read_buf_chunk")
        try:
            ptr = get_lib().lr_bytes_ptr(out)
            ln = get_lib().lr_bytes_len(out)
            return bytes(ffi.buffer(ptr, ln)) if ln else b""
        finally:
            get_lib().lr_bytes_free(out)


class WriteBuf:
    """Owned writable byte buffer (mirrors ``lr_core::buf::WriteBuf``)."""

    __slots__ = ("_ptr", "_freed")

    def __init__(self, ptr) -> None:
        self._ptr = ptr
        self._freed = False

    def __del__(self) -> None:
        self._close()

    def _close(self) -> None:
        if not self._freed and self._ptr is not None:
            get_lib().lr_write_buf_free(self._ptr)
            self._freed = True

    def close(self) -> None:
        self._close()

    @classmethod
    def new(cls, cap: int = 0) -> "WriteBuf":
        p = get_lib().lr_write_buf_new(cap)
        if p == ffi.NULL:
            raise LrError("lr_write_buf_new returned null")
        return cls(p)

    @property
    def position(self) -> int:
        return int(get_lib().lr_write_buf_position(self._ptr))

    @property
    def remaining_mut(self) -> int:
        return int(get_lib().lr_write_buf_remaining_mut(self._ptr))

    @property
    def capacity(self) -> int:
        return int(get_lib().lr_write_buf_capacity(self._ptr))

    def put_u8(self, v: int) -> None:
        rc = get_lib().lr_write_buf_put_u8(self._ptr, v & 0xFF)
        _check_rc_zero(rc, "lr_write_buf_put_u8")

    def put_bytes(self, b: bytes) -> None:
        if not b:
            rc = get_lib().lr_write_buf_put_bytes(self._ptr, ffi.NULL, 0)
        else:
            buf = ffi.from_buffer(b)
            rc = get_lib().lr_write_buf_put_bytes(self._ptr, buf, len(b))
        _check_rc_zero(rc, "lr_write_buf_put_bytes")

    def put_u16_be(self, v: int) -> None:
        rc = get_lib().lr_write_buf_put_u16_be(self._ptr, v & 0xFFFF)
        _check_rc_zero(rc, "lr_write_buf_put_u16_be")

    def put_u32_be(self, v: int) -> None:
        rc = get_lib().lr_write_buf_put_u32_be(self._ptr, v & 0xFFFFFFFF)
        _check_rc_zero(rc, "lr_write_buf_put_u32_be")

    def put_u64_be(self, v: int) -> None:
        rc = get_lib().lr_write_buf_put_u64_be(self._ptr, v & 0xFFFFFFFFFFFFFFFF)
        _check_rc_zero(rc, "lr_write_buf_put_u64_be")

    def patch(self, at: int, data: bytes) -> None:
        """Back-patch ``len(data)`` bytes at offset ``at``. The
        buffer must already contain at least ``at + len(data)`` bytes
        (write ahead, patch behind)."""
        if not data:
            rc = get_lib().lr_write_buf_patch(self._ptr, at, ffi.NULL, 0)
        else:
            buf = ffi.from_buffer(data)
            rc = get_lib().lr_write_buf_patch(self._ptr, at, buf, len(data))
        _check_rc_zero(rc, "lr_write_buf_patch")

    def reserve(self, additional: int) -> None:
        rc = get_lib().lr_write_buf_reserve(self._ptr, additional)
        _check_rc_zero(rc, "lr_write_buf_reserve")

    def written(self) -> bytes:
        """Take a snapshot of the bytes written so far (does not
        reset the buffer)."""
        out = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_write_buf_written(self._ptr, out)
        _check_rc_zero(rc, "lr_write_buf_written")
        try:
            ptr = get_lib().lr_bytes_ptr(out)
            ln = get_lib().lr_bytes_len(out)
            return bytes(ffi.buffer(ptr, ln)) if ln else b""
        finally:
            get_lib().lr_bytes_free(out)

    def take_bytes(self) -> bytes:
        """Take the bytes written so far and reset the buffer to empty."""
        out = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_write_buf_take_bytes(self._ptr, out)
        _check_rc_zero(rc, "lr_write_buf_take_bytes")
        try:
            ptr = get_lib().lr_bytes_ptr(out)
            ln = get_lib().lr_bytes_len(out)
            return bytes(ffi.buffer(ptr, ln)) if ln else b""
        finally:
            get_lib().lr_bytes_free(out)


# ---- TimerQueue / TimerSpec ----


@dataclass
class TimerSpec:
    after_ms: int
    periodic_ms: int

    @classmethod
    def once(cls, after_ms: int) -> "TimerSpec":
        c = get_lib().lr_timer_spec_once(after_ms)
        return cls(after_ms=int(c.after_ms), periodic_ms=int(c.periodic_ms))

    @classmethod
    def periodic(cls, after_ms: int, periodic_ms: int) -> "TimerSpec":
        c = get_lib().lr_timer_spec_periodic(after_ms, periodic_ms)
        return cls(after_ms=int(c.after_ms), periodic_ms=int(c.periodic_ms))

    def to_c(self):
        c = ffi.new("lr_timer_spec_t*")
        c.after_ms = self.after_ms
        c.periodic_ms = self.periodic_ms
        return c[0]


class TimerQueue:
    """Ordered timer queue with a single-fire / periodic arm + cancel
    surface (mirrors ``lr_core::timer::TimerQueue``)."""

    __slots__ = ("_ptr", "_freed")

    def __init__(self, ptr) -> None:
        self._ptr = ptr
        self._freed = False

    def __del__(self) -> None:
        self._close()

    def _close(self) -> None:
        if not self._freed and self._ptr is not None:
            get_lib().lr_timer_queue_free(self._ptr)
            self._freed = True

    def close(self) -> None:
        self._close()

    @classmethod
    def new(cls) -> "TimerQueue":
        p = get_lib().lr_timer_queue_new()
        if p == ffi.NULL:
            raise LrError("lr_timer_queue_new returned null")
        return cls(p)

    def arm(self, now_ms: int, id: int, spec: TimerSpec) -> None:
        rc = get_lib().lr_timer_queue_arm(self._ptr, now_ms, id, spec.to_c())
        _check_rc_zero(rc, "lr_timer_queue_arm")

    def cancel(self, id: int) -> None:
        rc = get_lib().lr_timer_queue_cancel(self._ptr, id)
        _check_rc_zero(rc, "lr_timer_queue_cancel")

    def cancel_all(self) -> None:
        rc = get_lib().lr_timer_queue_cancel_all(self._ptr)
        _check_rc_zero(rc, "lr_timer_queue_cancel_all")

    def tick(self, now_ms: int) -> list[int]:
        """Advance the queue to ``now_ms`` and return the list of
        timer IDs that fired."""
        out_arr = ffi.new("lr_timer_id_t**")
        out_count = ffi.new("uintptr_t*")
        try:
            rc = get_lib().lr_timer_queue_tick(self._ptr, now_ms, out_arr, out_count)
            _check_rc_zero(rc, "lr_timer_queue_tick")
            n = int(out_count[0])
            if n == 0:
                return []
            arr = out_arr[0]
            ids = [int(arr[i]) for i in range(n)]
            return ids
        finally:
            if out_arr[0] != ffi.NULL and int(out_count[0]) > 0:
                get_lib().lr_timer_queue_drain_free(out_arr[0], out_count[0])

    @property
    def is_empty(self) -> bool:
        return bool(get_lib().lr_timer_queue_is_empty(self._ptr))

    def __len__(self) -> int:
        return int(get_lib().lr_timer_queue_len(self._ptr))

    def next_fire_ms(self) -> int:
        """Next scheduled fire time in milliseconds since the epoch,
        or 0 when the queue is empty."""
        return int(get_lib().lr_timer_queue_next_fire_ms(self._ptr))


# ---- MemoryConn (in-process paired transport for tests) ----


class MemoryConn:
    """Paired in-process byte transport — push bytes into one end,
    take them out of the other. Used by the FFI tests as a
    deterministic transport substitute for a network socket."""

    __slots__ = ("_ptr", "_freed")

    def __init__(self, ptr) -> None:
        self._ptr = ptr
        self._freed = False

    def __del__(self) -> None:
        self._close()

    def _close(self) -> None:
        if not self._freed and self._ptr is not None:
            get_lib().lr_memory_conn_free(self._ptr)
            self._freed = True

    def close(self) -> None:
        self._close()

    @classmethod
    def new(cls) -> "MemoryConn":
        p = get_lib().lr_memory_conn_new()
        if p == ffi.NULL:
            raise LrError("lr_memory_conn_new returned null")
        return cls(p)

    @classmethod
    def pair(cls) -> Tuple["MemoryConn", "MemoryConn"]:
        a = ffi.new("lr_memory_conn_t*")
        b = ffi.new("lr_memory_conn_t*")
        rc = get_lib().lr_memory_conn_pair(a, b)
        _check_rc_zero(rc, "lr_memory_conn_pair")
        return cls(a[0]), cls(b[0])

    def push_input(self, data: bytes) -> None:
        if not data:
            rc = get_lib().lr_memory_conn_push_input(self._ptr, ffi.NULL, 0)
        else:
            buf = ffi.from_buffer(data)
            rc = get_lib().lr_memory_conn_push_input(self._ptr, buf, len(data))
        _check_rc_zero(rc, "lr_memory_conn_push_input")

    def take_input(self) -> bytes:
        out = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_memory_conn_take_input(self._ptr, out)
        _check_rc_zero(rc, "lr_memory_conn_take_input")
        try:
            ptr = get_lib().lr_bytes_ptr(out)
            ln = get_lib().lr_bytes_len(out)
            return bytes(ffi.buffer(ptr, ln)) if ln else b""
        finally:
            get_lib().lr_bytes_free(out)

    def put_output(self, data: bytes) -> None:
        if not data:
            rc = get_lib().lr_memory_conn_put_output(self._ptr, ffi.NULL, 0)
        else:
            buf = ffi.from_buffer(data)
            rc = get_lib().lr_memory_conn_put_output(self._ptr, buf, len(data))
        _check_rc_zero(rc, "lr_memory_conn_put_output")

    def drain_output(self) -> bytes:
        out = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_memory_conn_drain_output(self._ptr, out)
        _check_rc_zero(rc, "lr_memory_conn_drain_output")
        try:
            ptr = get_lib().lr_bytes_ptr(out)
            ln = get_lib().lr_bytes_len(out)
            return bytes(ffi.buffer(ptr, ln)) if ln else b""
        finally:
            get_lib().lr_bytes_free(out)
