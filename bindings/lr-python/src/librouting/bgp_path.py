"""BGP Path Attributes — mirrors ``lr_bgp::path::PathAttributes``.

The :class:`BgpPathAttrs` class wraps the boxed ``lr_bgp_path_attrs_t``
handle so a Python embedder can build, populate and read the full
RFC 4271 §5.1 attribute set (ORIGIN, AS_PATH, NEXT_HOP, MULTI_EXIT_DISC,
LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR) plus the RFC 4456 / RFC 6793 /
RFC 7311 / RFC 8097 / RFC 9655 / RFC 4760 / RFC 8277 extensions, the
OSPF / Babel redistribution metadata (RFC 4577 §3 / RFC 7999 §3 +
``draft-ietf-babel-route-bgp-extensions``) and the IGP-metric /
peer-source-address routing knobs the daemon uses for best-path
selection.

The companion :class:`BgpLargeCommunity` wraps the boxed
``lr_bgp_large_community_t`` handle (RFC 8097 — three 32-bit fields:
global administrator + two local data words) just enough to drive
:meth:`BgpPathAttrs.insert_large_community`. The full
encode_set / decode_set surface is a separate follow-up.

The companion :class:`BgpAsPath` is a minimal RAII wrapper around the
opaque ``lr_bgp_as_path_t`` handle returned by :meth:`BgpPathAttrs.as_path`
and friends — it frees the handle on collection. The full BgpAsPath
surface (decode / encode / prepend / segment iteration) is a separate
follow-up.

The :class:`BgpNextHop` value type mirrors the ``lr_bgp_next_hop_t``
C struct: 16-byte address octets plus a ``kind`` (0=IPv4, 1=IPv6,
2=V4-over-V6 per RFC 5549) and a ``present`` flag.

The :class:`PathAttr` value type mirrors the ``(flags, type, value)``
triple returned by :meth:`BgpPathAttrs.at` and :meth:`BgpPathAttrs.get`.

Resources are released via ``__del__`` finalizers — a Python-side
equivalent of the Go runtime.SetFinalizer and the C++ RAII wrapper.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ._ffi import ffi, get_lib, alloc_bytes, free_bytes, copy_bytes
from .router import LrError, last_error

__all__ = [
    "BgpPathAttrs",
    "BgpLargeCommunity",
    "BgpAsPath",
    "BgpNextHop",
    "PathAttr",
    # ORIGIN attribute values (RFC 4271 §5.1.1).
    "ORIGIN_IGP",
    "ORIGIN_EGP",
    "ORIGIN_INCOMPLETE",
    # NEXT_HOP kind values (lr_bgp_next_hop_t::kind).
    "NEXT_HOP_V4",
    "NEXT_HOP_V6",
    "NEXT_HOP_V4_OVER_V6",
    # IANA BGP path attribute type codes (RFC 4271 §5.1 + extensions).
    # Mirrors `lr_bgp::path::AttrType` so a Python embedder can drive
    # `BgpPathAttrs.get` / `BgpPathAttrs.remove` / `BgpPathAttrs.at`
    # with the same constants the C ABI and the Rust crate use.
    "BGP_ATTR_ORIGIN",
    "BGP_ATTR_AS_PATH",
    "BGP_ATTR_NEXT_HOP",
    "BGP_ATTR_MED",
    "BGP_ATTR_LOCAL_PREF",
    "BGP_ATTR_ATOMIC_AGGREGATE",
    "BGP_ATTR_AGGREGATOR",
    "BGP_ATTR_COMMUNITIES",
    "BGP_ATTR_ORIGINATOR_ID",
    "BGP_ATTR_CLUSTER_LIST",
    "BGP_ATTR_MP_REACH_NLRI",
    "BGP_ATTR_MP_UNREACH_NLRI",
    "BGP_ATTR_EXT_COMMUNITIES",
    "BGP_ATTR_AS4_PATH",
    "BGP_ATTR_PMSI_TUNNEL",
    "BGP_ATTR_AIGP",
    "BGP_ATTR_LARGE_COMMUNITIES",
    "BGP_ATTR_OTC",
    # librouting-private attribute tags — never transmitted on the
    # wire; used by the Loc-RIB / policy DSL to carry metadata the
    # best-path selector reads.
    "BGP_ATTR_OSPF_METRIC2",
    "BGP_ATTR_OSPF_ROUTER_ID",
    "BGP_ATTR_BABEL_SEQNO",
    "BGP_ATTR_BABEL_ROUTER_ID",
    "BGP_ATTR_IGP_METRIC",
    "BGP_ATTR_PEER_SOURCE_ADDRESS",
    "BGP_ATTR_LR_MPLS_LABEL_STACK",
]

# ORIGIN attribute values (RFC 4271 §5.1.1).
ORIGIN_IGP = 0
ORIGIN_EGP = 1
ORIGIN_INCOMPLETE = 2

# NEXT_HOP kind values (lr_bgp_next_hop_t::kind).
NEXT_HOP_V4 = 0
NEXT_HOP_V6 = 1
NEXT_HOP_V4_OVER_V6 = 2

# IANA BGP path attribute type codes (RFC 4271 §5.1 + extensions).
# Mirrors `lr_bgp::path::AttrType` so a Python embedder can drive
# `BgpPathAttrs.get` / `BgpPathAttrs.remove` / `BgpPathAttrs.at`
# with the same constants the C ABI and the Rust crate use.
BGP_ATTR_ORIGIN = 1
BGP_ATTR_AS_PATH = 2
BGP_ATTR_NEXT_HOP = 3
BGP_ATTR_MED = 4
BGP_ATTR_LOCAL_PREF = 5
BGP_ATTR_ATOMIC_AGGREGATE = 6
BGP_ATTR_AGGREGATOR = 7
BGP_ATTR_COMMUNITIES = 8
BGP_ATTR_ORIGINATOR_ID = 9
BGP_ATTR_CLUSTER_LIST = 10
BGP_ATTR_MP_REACH_NLRI = 14
BGP_ATTR_MP_UNREACH_NLRI = 15
BGP_ATTR_EXT_COMMUNITIES = 16
BGP_ATTR_AS4_PATH = 17
BGP_ATTR_PMSI_TUNNEL = 22
BGP_ATTR_AIGP = 26
BGP_ATTR_LARGE_COMMUNITIES = 32
BGP_ATTR_OTC = 35

# librouting-private attribute tags — never transmitted on the
# wire; used by the Loc-RIB / policy DSL to carry metadata the
# best-path selector reads.
BGP_ATTR_OSPF_METRIC2 = 253
BGP_ATTR_OSPF_ROUTER_ID = 252
BGP_ATTR_BABEL_ROUTER_ID = 250
BGP_ATTR_BABEL_SEQNO = 249
BGP_ATTR_IGP_METRIC = 246
BGP_ATTR_PEER_SOURCE_ADDRESS = 245
BGP_ATTR_LR_MPLS_LABEL_STACK = 255


def _check_rc(rc: int, what: str) -> None:
    if rc != 0:
        raise LrError(f"{what} failed (rc={rc}): {last_error()}")


# ---------------------------------------------------------------------------
# BgpLargeCommunity — RFC 8097. Three 32-bit fields:
#   global_admin / local_data1 / local_data2.
# The minimal surface exposed here is construct + read + free.
# ---------------------------------------------------------------------------
class BgpLargeCommunity:
    """A single RFC 8097 Large Community ``(global, local1, local2)``.

    Wraps the boxed ``lr_bgp_large_community_t`` handle. The
    handle is freed by ``__del__`` (or ``close()`` / ``__exit__``);
    use the context-manager pattern when lifetime is lexically scoped.
    """

    def __init__(self, global_admin: int, local_data1: int, local_data2: int) -> None:
        ptr = get_lib().lr_bgp_large_community_new(
            int(global_admin), int(local_data1), int(local_data2)
        )
        if ptr == ffi.NULL:
            raise LrError(f"lr_bgp_large_community_new: {last_error()}")
        self._ptr = ptr

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_bgp_large_community_free(ptr)
            self._ptr = None

    def __enter__(self) -> "BgpLargeCommunity":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @property
    def global_admin(self) -> int:
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpLargeCommunity used after close()")
        return int(get_lib().lr_bgp_large_community_global_admin(self._ptr))

    @property
    def local_data1(self) -> int:
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpLargeCommunity used after close()")
        return int(get_lib().lr_bgp_large_community_local_data1(self._ptr))

    @property
    def local_data2(self) -> int:
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpLargeCommunity used after close()")
        return int(get_lib().lr_bgp_large_community_local_data2(self._ptr))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BgpLargeCommunity):
            return NotImplemented
        return (
            self.global_admin == other.global_admin
            and self.local_data1 == other.local_data1
            and self.local_data2 == other.local_data2
        )

    def __hash__(self) -> int:
        return hash((self.global_admin, self.local_data1, self.local_data2))

    def __repr__(self) -> str:
        return (
            f"BgpLargeCommunity(global_admin={self.global_admin}, "
            f"local_data1={self.local_data1}, local_data2={self.local_data2})"
        )


# ---------------------------------------------------------------------------
# BgpAsPath — minimal RAII wrapper. The full surface is a follow-up.
# ---------------------------------------------------------------------------
class BgpAsPath:
    """A minimal RAII wrapper around an opaque ``lr_bgp_as_path_t``.

    The handle is returned by :meth:`BgpPathAttrs.as_path`,
    :meth:`BgpPathAttrs.as_path_wire` and :meth:`BgpPathAttrs.as4_path`.
    The full AS_PATH surface (decode / encode / segment iteration / prepend
    / loop-check) is a separate follow-up; this class only owns the
    handle's lifetime so a Python embedder does not leak it.
    """

    def __init__(self, _ptr=None) -> None:
        # Internal use only — construct via BgpPathAttrs.as_path()
        # or via the (forthcoming) dedicated BgpAsPath module.
        self._ptr = _ptr

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_bgp_as_path_free(ptr)
            self._ptr = None

    def __enter__(self) -> "BgpAsPath":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._ptr is None or self._ptr == ffi.NULL


# ---------------------------------------------------------------------------
# BgpNextHop — value type mirroring lr_bgp_next_hop_t.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class BgpNextHop:
    """One IPv4/IPv6 next-hop value (RFC 4271 §5.1.3 / RFC 4760 §3 /
    RFC 5549 IPv4-over-IPv6).

    ``addr`` is always 16 bytes — the first 4 bytes are used for
    kind == 0 (IPv4). ``kind`` is one of :data:`NEXT_HOP_V4`,
    :data:`NEXT_HOP_V6`, :data:`NEXT_HOP_V4_OVER_V6`. ``present`` is
    ``True`` when the attribute is set on the underlying PathAttributes.
    """

    addr: bytes
    kind: int
    present: bool

    @property
    def ip_address(self) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Return the next-hop as a stdlib :class:`ipaddress` value, or
        ``None`` when the attribute is absent. IPv4-over-IPv6 returns an
        :class:`~ipaddress.IPv4Address` (the 4-byte IPv4 prefix)."""
        if not self.present:
            return None
        if self.kind == NEXT_HOP_V4:
            return ipaddress.IPv4Address(self.addr[:4])
        if self.kind == NEXT_HOP_V6:
            return ipaddress.IPv6Address(self.addr)
        if self.kind == NEXT_HOP_V4_OVER_V6:
            return ipaddress.IPv4Address(self.addr[:4])
        return None


# ---------------------------------------------------------------------------
# PathAttr — value type for the (flags, type, value) triple.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PathAttr:
    """One raw BGP path attribute as returned by :meth:`BgpPathAttrs.at`
    and :meth:`BgpPathAttrs.get`. ``flags`` is the BGP attribute flags
    byte (RFC 4271 §5.1 — well-known bit 0x40 transitive etc.),
    ``type`` is the IANA attribute type code, ``value`` is the raw
    attribute payload bytes."""

    flags: int
    type: int
    value: bytes


# ---------------------------------------------------------------------------
# BgpPathAttrs — the main RAII class.
# ---------------------------------------------------------------------------
class BgpPathAttrs:
    """An owned RFC 4271 §5.1 PathAttributes handle.

    Wraps the boxed ``lr_bgp_path_attrs_t`` so a Python embedder can
    build, populate and read the full well-known + optional attribute
    set the daemon uses for BGP best-path selection, MPLS labelled
    unicast, MP-BGP and OSPF / Babel redistribution metadata.

    Mirrors the public Rust API of ``lr_bgp::path::PathAttributes``
    one-to-one: each ``pub fn`` becomes a method, ``Option<T>`` returns
    become ``Optional[T]``, and ``Result<(), E>`` becomes raising
    :class:`~librouting.router.LrError`.

    The handle is freed by ``__del__`` (or ``close()`` / ``__exit__``);
    use the context-manager pattern when lifetime is lexically scoped.
    """

    def __init__(self) -> None:
        ptr = get_lib().lr_bgp_path_attrs_new()
        if ptr == ffi.NULL:
            raise LrError(f"lr_bgp_path_attrs_new: {last_error()}")
        self._ptr = ptr

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying handle. Safe to call multiple times."""
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_bgp_path_attrs_free(ptr)
            self._ptr = None

    def __enter__(self) -> "BgpPathAttrs":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._ptr is None or self._ptr == ffi.NULL

    # ---- lifecycle / introspection ----

    def __len__(self) -> int:
        return self.len()

    def len(self) -> int:
        """Number of typed attribute readers wired on this set (the
        ``PathAttributes::len`` counter — distinct from
        :meth:`count`, which is the raw attribute count including
        unknown / unparsed entries)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return 0
        return int(get_lib().lr_bgp_path_attrs_len(self._ptr))

    def is_empty(self) -> bool:
        """``True`` when no typed attribute is set. A non-typed-attr
        set may still have a non-zero :meth:`count`."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return True
        return bool(get_lib().lr_bgp_path_attrs_is_empty(self._ptr))

    def count(self) -> int:
        """Raw attribute count — the number of entries in the
        underlying ordered map, including unknown / unparsed
        attributes the typed readers do not surface. Returns 0 on
        a closed handle."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return 0
        return int(get_lib().lr_bgp_path_attrs_count(self._ptr))

    def at(self, index: int) -> Optional[PathAttr]:
        """Read the attribute at ``index`` in insertion order.
        Returns ``None`` when ``index`` is out of range."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        flags = ffi.new("uint8_t*")
        ty = ffi.new("uint8_t*")
        out = alloc_bytes()
        present = get_lib().lr_bgp_path_attrs_at(
            self._ptr, int(index), flags, ty, out
        )
        if not present:
            free_bytes(out)
            return None
        v = copy_bytes(out)
        free_bytes(out)
        return PathAttr(flags=int(flags[0]), type=int(ty[0]), value=v)

    def get(self, attr_type: int) -> Optional[PathAttr]:
        """Read the attribute with IANA type code ``attr_type``.
        Returns ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        flags = ffi.new("uint8_t*")
        ty = ffi.new("uint8_t*")
        out = alloc_bytes()
        present = get_lib().lr_bgp_path_attrs_get(
            self._ptr, int(attr_type), flags, ty, out
        )
        if not present:
            free_bytes(out)
            return None
        v = copy_bytes(out)
        free_bytes(out)
        return PathAttr(flags=int(flags[0]), type=int(ty[0]), value=v)

    def remove(self, attr_type: int) -> bool:
        """Remove the attribute with IANA type code ``attr_type``.
        Returns ``True`` when the attribute was present (and is now
        gone), ``False`` when it was absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_remove(self._ptr, int(attr_type)))

    def insert_raw(self, flags: int, attr_type: int, value: bytes) -> None:
        """Insert a raw attribute ``value`` with the given ``flags``
        and ``attr_type`` (IANA code). Raises :class:`LrError` on FFI
        errors."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError("value must be bytes-like")
        buf = bytes(value)
        rc = get_lib().lr_bgp_path_attrs_insert_raw(
            self._ptr, int(flags), int(attr_type), buf, len(buf)
        )
        _check_rc(rc, "lr_bgp_path_attrs_insert_raw")

    # ---- RFC 4271 §5.1 — well-known mandatory + discretionary ----

    def origin(self) -> Optional[int]:
        """Read the ORIGIN attribute (RFC 4271 §5.1.1). Returns one of
        :data:`ORIGIN_IGP` / :data:`ORIGIN_EGP` /
        :data:`ORIGIN_INCOMPLETE`, or ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint8_t*")
        if get_lib().lr_bgp_path_attrs_origin(self._ptr, out):
            return int(out[0])
        return None

    def med(self) -> Optional[int]:
        """Read the MULTI_EXIT_DISC attribute (RFC 4271 §5.1.4)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint32_t*")
        if get_lib().lr_bgp_path_attrs_med(self._ptr, out):
            return int(out[0])
        return None

    def local_pref(self) -> Optional[int]:
        """Read the LOCAL_PREF attribute (RFC 4271 §5.1.5)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint32_t*")
        if get_lib().lr_bgp_path_attrs_local_pref(self._ptr, out):
            return int(out[0])
        return None

    def set_local_pref(self, value: int) -> None:
        """Set the LOCAL_PREF attribute (RFC 4271 §5.1.5). The value
        is a 32-bit unsigned int. Raises :class:`LrError` on FFI errors."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        rc = get_lib().lr_bgp_path_attrs_set_local_pref(self._ptr, int(value))
        _check_rc(rc, "lr_bgp_path_attrs_set_local_pref")

    def atomic_aggregate(self) -> bool:
        """``True`` when the ATOMIC_AGGREGATE attribute is present
        (RFC 4271 §5.1.6 — the route was aggregated; the receiving
        speaker must NOT de-aggregate)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_atomic_aggregate(self._ptr))

    def aggregator(self) -> Optional[Tuple[int, int]]:
        """Read the AGGREGATOR attribute (RFC 4271 §5.1.7). Returns
        ``(asn, speaker)`` or ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out_asn = ffi.new("uint32_t*")
        out_spk = ffi.new("uint32_t*")
        if get_lib().lr_bgp_path_attrs_aggregator(self._ptr, out_asn, out_spk):
            return (int(out_asn[0]), int(out_spk[0]))
        return None

    def next_hop(self) -> Optional[BgpNextHop]:
        """Read the NEXT_HOP attribute (RFC 4271 §5.1.3). Returns a
        :class:`BgpNextHop` with ``present=False`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("lr_bgp_next_hop_t*")
        if get_lib().lr_bgp_path_attrs_next_hop(self._ptr, out):
            return _next_hop_from_c(out)
        return BgpNextHop(addr=b"\x00" * 16, kind=NEXT_HOP_V4, present=False)

    # ---- RFC 4271 §5.1.2 + RFC 6793 — AS_PATH ----

    def as_path(self) -> Optional[BgpAsPath]:
        """Read the AS_PATH attribute (RFC 4271 §5.1.2). Returns a
        :class:`BgpAsPath` handle (caller frees via ``close()`` or
        scope exit), or ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        ptr = get_lib().lr_bgp_path_attrs_as_path(self._ptr)
        if ptr == ffi.NULL:
            return None
        return BgpAsPath(_ptr=ptr)

    def as_path_wire(self, asn4: bool) -> Optional[BgpAsPath]:
        """Read the AS_PATH attribute in the explicit 2-byte or
        4-byte AS form (RFC 6793 §4 — when ``asn4`` is True the path
        carries 4-byte AS numbers). Returns ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        ptr = get_lib().lr_bgp_path_attrs_as_path_wire(self._ptr, 1 if asn4 else 0)
        if ptr == ffi.NULL:
            return None
        return BgpAsPath(_ptr=ptr)

    def as4_path(self) -> Optional[BgpAsPath]:
        """Read the AS4_PATH attribute (RFC 6793 §3 — the 4-byte AS
        form carried alongside the 2-byte AS_PATH for backward
        compatibility with speakers that did not negotiate 4-byte AS).
        Returns ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        ptr = get_lib().lr_bgp_path_attrs_as4_path(self._ptr)
        if ptr == ffi.NULL:
            return None
        return BgpAsPath(_ptr=ptr)

    # ---- RFC 4456 — Route Reflection ----

    def originator_id(self) -> Optional[int]:
        """Read the ORIGINATOR_ID attribute (RFC 4456 §5)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint32_t*")
        if get_lib().lr_bgp_path_attrs_originator_id(self._ptr, out):
            return int(out[0])
        return None

    def has_cluster_list(self) -> bool:
        """``True`` when the CLUSTER_LIST attribute is present
        (RFC 4456 §8)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_cluster_list(self._ptr))

    def cluster_list(self) -> bytes:
        """Read the CLUSTER_LIST attribute (RFC 4456 §8) as the raw
        byte stream — one 4-byte cluster-id per entry, in network
        byte order. Returns ``b""`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return b""
        out = alloc_bytes()
        # The C ABI returns the entry count; the byte payload is in `out`.
        get_lib().lr_bgp_path_attrs_cluster_list(self._ptr, out)
        v = copy_bytes(out)
        free_bytes(out)
        return v

    # ---- RFC 1997 / 4360 / 8097 — Communities ----

    def communities(self) -> List[int]:
        """Read the COMMUNITIES attribute (RFC 1997) as a list of u32
        values — each ``asn << 16 | value``. Returns ``[]`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return []
        out = alloc_bytes()
        n = int(get_lib().lr_bgp_path_attrs_communities(self._ptr, out))
        v = copy_bytes(out)
        free_bytes(out)
        if n == 0 or len(v) < n * 4:
            return []
        result = []
        for i in range(n):
            result.append(int.from_bytes(v[i * 4 : i * 4 + 4], "big"))
        return result

    def ext_communities(self) -> bytes:
        """Read the EXTENDED COMMUNITIES attribute (RFC 4360) as the
        raw 8-octet-per-entry byte stream. Returns ``b""`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return b""
        out = alloc_bytes()
        get_lib().lr_bgp_path_attrs_ext_communities(self._ptr, out)
        v = copy_bytes(out)
        free_bytes(out)
        return v

    def large_communities(self) -> List[BgpLargeCommunity]:
        """Read the LARGE COMMUNITIES attribute (RFC 8097) as a list
        of :class:`BgpLargeCommunity` (each 12 bytes — three 32-bit
        values, big-endian). Returns ``[]`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return []
        out = alloc_bytes()
        n = int(get_lib().lr_bgp_path_attrs_large_communities(self._ptr, out))
        v = copy_bytes(out)
        free_bytes(out)
        if n == 0 or len(v) < n * 12:
            return []
        result: List[BgpLargeCommunity] = []
        for i in range(n):
            chunk = v[i * 12 : i * 12 + 12]
            ga = int.from_bytes(chunk[0:4], "big")
            l1 = int.from_bytes(chunk[4:8], "big")
            l2 = int.from_bytes(chunk[8:12], "big")
            # Build directly to skip the redundant round-trip through
            # lr_bgp_large_community_new + the readers.
            c = BgpLargeCommunity.__new__(BgpLargeCommunity)
            ptr = get_lib().lr_bgp_large_community_new(ga, l1, l2)
            if ptr == ffi.NULL:
                raise LrError(f"lr_bgp_large_community_new: {last_error()}")
            c._ptr = ptr
            result.append(c)
        return result

    def has_community(self, community: int) -> bool:
        """``True`` when the COMMUNITIES attribute contains the given
        u32 community value (RFC 1997)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_community(self._ptr, int(community)))

    def insert_community(self, community: int) -> None:
        """Insert one u32 community value into the COMMUNITIES attribute
        (RFC 1997). Raises :class:`LrError` on FFI errors."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        rc = get_lib().lr_bgp_path_attrs_insert_community(self._ptr, int(community))
        _check_rc(rc, "lr_bgp_path_attrs_insert_community")

    def insert_large_community(self, c: BgpLargeCommunity) -> None:
        """Insert one :class:`BgpLargeCommunity` into the LARGE
        COMMUNITIES attribute (RFC 8097). Raises :class:`LrError` on
        FFI errors."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        if not isinstance(c, BgpLargeCommunity):
            raise TypeError("c must be a BgpLargeCommunity")
        if c._ptr is None or c._ptr == ffi.NULL:
            raise LrError("BgpLargeCommunity used after close()")
        rc = get_lib().lr_bgp_path_attrs_insert_large_community(self._ptr, c._ptr)
        _check_rc(rc, "lr_bgp_path_attrs_insert_large_community")

    # ---- RFC 7311 / 8124 — AIGP ----

    def has_aigp(self) -> bool:
        """``True`` when the AIGP attribute (RFC 7311) is present."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_aigp(self._ptr))

    def aigp(self) -> Optional[int]:
        """Read the AIGP attribute (RFC 7311) value as a 64-bit
        unsigned int. Returns ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint64_t*")
        if get_lib().lr_bgp_path_attrs_aigp(self._ptr, out):
            return int(out[0])
        return None

    # ---- RFC 9655 — OTC (Only To Customer) ----

    def has_otc(self) -> bool:
        """``True`` when the OTC attribute (RFC 9655) is present."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_otc(self._ptr))

    def otc(self) -> Optional[int]:
        """Read the OTC attribute (RFC 9655) value as a 32-bit
        unsigned int. Returns ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint32_t*")
        if get_lib().lr_bgp_path_attrs_otc(self._ptr, out):
            return int(out[0])
        return None

    # ---- RFC 6514 — PMSI Tunnel ----

    def has_pmsi_tunnel(self) -> bool:
        """``True`` when the PMSI_TUNNEL attribute (RFC 6514) is present."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_pmsi_tunnel(self._ptr))

    # ---- RFC 8277 — MPLS Label Stack ----

    def label_stack(self):
        """Read the LrMplsLabelStack attribute (RFC 8277 §3 — the
        MPLS label stack for BGP labelled unicast). Returns a
        :class:`~librouting.mpls.LabelStack` (owned by the caller)
        or ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        ptr = get_lib().lr_bgp_path_attrs_label_stack(self._ptr)
        if ptr == ffi.NULL:
            return None
        # Wrap the returned handle in the existing LabelStack class
        # via a private constructor.
        from .mpls import LabelStack
        s = LabelStack.__new__(LabelStack)
        s._ptr = ptr
        return s

    def set_label_stack(self, stack) -> None:
        """Set the LrMplsLabelStack attribute (RFC 8277 §3). ``stack``
        must be a :class:`~librouting.mpls.LabelStack` instance.
        Raises :class:`LrError` on FFI errors."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        from .mpls import LabelStack
        if not isinstance(stack, LabelStack):
            raise TypeError("stack must be a LabelStack")
        if stack._ptr is None or stack._ptr == ffi.NULL:
            raise LrError("LabelStack used after close()")
        rc = get_lib().lr_bgp_path_attrs_set_label_stack(self._ptr, stack._ptr)
        _check_rc(rc, "lr_bgp_path_attrs_set_label_stack")

    # ---- MP-BGP (RFC 4760) ----

    def mp_reach(self) -> Optional[Tuple[int, int, BgpNextHop, bytes]]:
        """Read the MP_REACH_NLRI attribute (RFC 4760 §3). Returns
        ``(family_afi, family_safi, next_hop, nlri_bytes)`` or
        ``None`` when absent. ``nlri_bytes`` is the raw byte stream
        after the next-hop field; the embedder parses the per-AFI/SAFI
        NLRI shape."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        afi = ffi.new("uint16_t*")
        safi = ffi.new("uint8_t*")
        nh = ffi.new("lr_bgp_next_hop_t*")
        out = alloc_bytes()
        present = get_lib().lr_bgp_path_attrs_mp_reach(
            self._ptr, afi, safi, nh, out
        )
        if not present:
            free_bytes(out)
            return None
        v = copy_bytes(out)
        free_bytes(out)
        return (int(afi[0]), int(safi[0]), _next_hop_from_c(nh), v)

    def mp_unreach(self) -> Optional[Tuple[int, int, bytes]]:
        """Read the MP_UNREACH_NLRI attribute (RFC 4760 §3). Returns
        ``(family_afi, family_safi, nlri_bytes)`` or ``None`` when
        absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        afi = ffi.new("uint16_t*")
        safi = ffi.new("uint8_t*")
        out = alloc_bytes()
        present = get_lib().lr_bgp_path_attrs_mp_unreach(
            self._ptr, afi, safi, out
        )
        if not present:
            free_bytes(out)
            return None
        v = copy_bytes(out)
        free_bytes(out)
        return (int(afi[0]), int(safi[0]), v)

    # ---- OSPF redistrib (RFC 4577 §3) ----

    def set_ospf_metric2(self, metric: int) -> None:
        """Set the OSPF metric2 attribute (RFC 4577 §3 — second OSPF
        metric on a BGP route redistributed from OSPF). The value is
        a 32-bit unsigned int. Raises :class:`LrError` on FFI errors."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        rc = get_lib().lr_bgp_path_attrs_set_ospf_metric2(self._ptr, int(metric))
        _check_rc(rc, "lr_bgp_path_attrs_set_ospf_metric2")

    def ospf_metric2(self) -> Optional[int]:
        """Read the OSPF metric2 attribute (RFC 4577 §3)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint32_t*")
        if get_lib().lr_bgp_path_attrs_ospf_metric2(self._ptr, out):
            return int(out[0])
        return None

    def has_ospf_metric2(self) -> bool:
        """``True`` when the OSPF metric2 attribute is present."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_ospf_metric2(self._ptr))

    def set_ospf_router_id(self, router_id: int) -> None:
        """Set the OSPF router-id attribute (RFC 4577 §3 — the OSPF
        router-id of the speaker that redistributed the route into
        BGP). The value is a 32-bit unsigned int."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        rc = get_lib().lr_bgp_path_attrs_set_ospf_router_id(self._ptr, int(router_id))
        _check_rc(rc, "lr_bgp_path_attrs_set_ospf_router_id")

    def ospf_router_id(self) -> Optional[int]:
        """Read the OSPF router-id attribute (RFC 4577 §3)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint32_t*")
        if get_lib().lr_bgp_path_attrs_ospf_router_id(self._ptr, out):
            return int(out[0])
        return None

    def has_ospf_router_id(self) -> bool:
        """``True`` when the OSPF router-id attribute is present."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_ospf_router_id(self._ptr))

    # ---- Babel redistrib (RFC 7999 + babel-ext) ----

    def set_babel_seqno(self, seqno: int) -> None:
        """Set the Babel seqno attribute (RFC 7999 §3 + babel-ext —
        the Babel sequence number carried on a Babel route
        redistributed into BGP). The value is a 16-bit unsigned int."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        rc = get_lib().lr_bgp_path_attrs_set_babel_seqno(self._ptr, int(seqno))
        _check_rc(rc, "lr_bgp_path_attrs_set_babel_seqno")

    def babel_seqno(self) -> Optional[int]:
        """Read the Babel seqno attribute (RFC 7999 §3 + babel-ext)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint16_t*")
        if get_lib().lr_bgp_path_attrs_babel_seqno(self._ptr, out):
            return int(out[0])
        return None

    def has_babel_seqno(self) -> bool:
        """``True`` when the Babel seqno attribute is present."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_babel_seqno(self._ptr))

    def set_babel_router_id(self, router_id: int) -> None:
        """Set the Babel router-id attribute (RFC 7999 §3 + babel-ext
        — the 64-bit Babel router-id). The value is a 64-bit
        unsigned int."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        rc = get_lib().lr_bgp_path_attrs_set_babel_router_id(self._ptr, int(router_id))
        _check_rc(rc, "lr_bgp_path_attrs_set_babel_router_id")

    def babel_router_id(self) -> Optional[int]:
        """Read the Babel router-id attribute (RFC 7999 §3 +
        babel-ext)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint64_t*")
        if get_lib().lr_bgp_path_attrs_babel_router_id(self._ptr, out):
            return int(out[0])
        return None

    def has_babel_router_id(self) -> bool:
        """``True`` when the Babel router-id attribute is present."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_babel_router_id(self._ptr))

    # ---- IGP metric (RFC 4271 §9.1.2.2 step 7) ----

    def set_igp_metric(self, metric: int) -> None:
        """Set the IGP metric attribute (RFC 4271 §9.1.2.2 best-path
        step 7 — the IGP metric to the NEXT_HOP). The value is a
        32-bit unsigned int."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        rc = get_lib().lr_bgp_path_attrs_set_igp_metric(self._ptr, int(metric))
        _check_rc(rc, "lr_bgp_path_attrs_set_igp_metric")

    def igp_metric(self) -> Optional[int]:
        """Read the IGP metric attribute (RFC 4271 §9.1.2.2 step 7)."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out = ffi.new("uint32_t*")
        if get_lib().lr_bgp_path_attrs_igp_metric(self._ptr, out):
            return int(out[0])
        return None

    def has_igp_metric(self) -> bool:
        """``True`` when the IGP metric attribute is present."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_igp_metric(self._ptr))

    # ---- Peer source address (RFC 4271 §6.3) ----

    def set_peer_source_address(self, addr: bytes, is_ipv6: bool) -> None:
        """Set the peer-source-address attribute (RFC 4271 §6.3 — the
        IPv4 (4-byte) or IPv6 (16-byte) source address of the BGP
        peer that sent the route). Raises :class:`LrError` on FFI
        errors."""
        if self._ptr is None or self._ptr == ffi.NULL:
            raise LrError("BgpPathAttrs used after close()")
        if not isinstance(addr, (bytes, bytearray, memoryview)):
            raise TypeError("addr must be bytes-like")
        buf = bytes(addr)
        expected = 16 if is_ipv6 else 4
        if len(buf) != expected:
            raise ValueError(f"addr must be {expected} bytes for is_ipv6={is_ipv6}")
        rc = get_lib().lr_bgp_path_attrs_set_peer_source_address(
            self._ptr, buf, 1 if is_ipv6 else 0
        )
        _check_rc(rc, "lr_bgp_path_attrs_set_peer_source_address")

    def peer_source_address(self) -> Optional[Tuple[bytes, bool]]:
        """Read the peer-source-address attribute (RFC 4271 §6.3).
        Returns ``(addr, is_ipv6)`` where ``addr`` is the 4-byte
        (IPv4) or 16-byte (IPv6) address, or ``None`` when absent."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return None
        out_addr = ffi.new("uint8_t[16]")
        out_is_v6 = ffi.new("uint8_t*")
        if get_lib().lr_bgp_path_attrs_peer_source_address(
            self._ptr, out_addr, out_is_v6
        ):
            is_v6 = bool(out_is_v6[0])
            addr = bytes(ffi.buffer(out_addr, 16 if is_v6 else 4))
            return (addr, is_v6)
        return None

    def has_peer_source_address(self) -> bool:
        """``True`` when the peer-source-address attribute is present."""
        if self._ptr is None or self._ptr == ffi.NULL:
            return False
        return bool(get_lib().lr_bgp_path_attrs_has_peer_source_address(self._ptr))


def _next_hop_from_c(cdata) -> BgpNextHop:
    """Build a :class:`BgpNextHop` from a CFFI ``lr_bgp_next_hop_t*``."""
    present = bool(cdata.present)
    kind = int(cdata.kind)
    addr = bytes(ffi.buffer(cdata.addr, 16))
    return BgpNextHop(addr=addr, kind=kind, present=present)
