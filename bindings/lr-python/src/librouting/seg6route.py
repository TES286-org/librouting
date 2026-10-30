"""SRv6 netlink route-table — `seg6` (encap) and `seg6local` (endpoint).

Mirrors the `lr_osroute::seg6_route` Rust crate (RFC 8754 §2 +
RFC 8986 §4 + the Linux `seg6` / `seg6local` lwtunnel netlink
surface) and the C ABI in `lr_ffi.h` (`lr_seg6_route_*` /
`lr_seg6_local_route_*` / `lr_seg6_netlink_*`).

The class hierarchy mirrors the Rust crate's module split:

* `Seg6Route`       — `lr_osroute::seg6_route::Seg6Route`       (RFC 8754 §2)
* `Seg6LocalRoute`  — `lr_osroute::seg6_route::Seg6LocalRoute`  (RFC 8986 §4)
* `Seg6Netlink`     — `lr_osroute::seg6_route::Seg6Netlink`     (NETLINK_ROUTE)
* `Seg6EncapMode` constants (Inline / Encap) and `Seg6RouteError`
  discriminants (the `ERR_*` constants) mirror the `LR_SEG6_*`
  `#define`s in `include/lr_ffi.h`.
* `Seg6RouteErr` — typed error raised by `Seg6Netlink` methods when
  the C ABI returns a positive `LR_SEG6_ERR_*` discriminant. Carries
  the discriminant in `code` and the human-readable message in
  `message`.

Every handle-owning type releases its C ABI handle via `__del__` /
`close()` / context-manager (`__enter__` / `__exit__`) — matching the
rest of this package's convention.
"""

from __future__ import annotations

import ipaddress
from typing import Optional, Union

from ._ffi import ffi, get_lib, alloc_bytes, free_bytes, copy_bytes
from .router import LrError, last_error
from .srv6 import Sid, Srh

# ----------------------------------------------------------------------
# Constants — mirror lr_osroute::seg6_route pub consts and the
# LR_SEG6_* defines in include/lr_ffi.h.
# ----------------------------------------------------------------------

# Seg6EncapMode (mirrors uapi/linux/seg6_iptunnel.h).
ENCAP_INLINE = int(get_lib().LR_SEG6_ENCAP_INLINE)
ENCAP_ENCAP = int(get_lib().LR_SEG6_ENCAP_ENCAP)

# Seg6RouteError discriminants — mirror lr_osroute::Seg6RouteError
# variants. Positive integers; the global LR_ERR_* codes remain
# negative.
ERR_UNSUPPORTED = int(get_lib().LR_SEG6_ERR_UNSUPPORTED)
ERR_NOT_ENABLED = int(get_lib().LR_SEG6_ERR_NOT_ENABLED)
ERR_SYSCALL = int(get_lib().LR_SEG6_ERR_SYSCALL)
ERR_KERNEL = int(get_lib().LR_SEG6_ERR_KERNEL)
ERR_BAD_SRH = int(get_lib().LR_SEG6_ERR_BAD_SRH)
ERR_UNSUPPORTED_ACTION = int(get_lib().LR_SEG6_ERR_UNSUPPORTED_ACTION)
ERR_UNKNOWN = int(get_lib().LR_SEG6_ERR_UNKNOWN)


# ----------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------

# Map Seg6RouteError discriminants to their stable names — mirror
# lr_seg6_route_err_name on the C ABI side.
_ERR_NAMES = {
    ERR_UNSUPPORTED: "unsupported",
    ERR_NOT_ENABLED: "not-enabled",
    ERR_SYSCALL: "syscall",
    ERR_KERNEL: "kernel",
    ERR_BAD_SRH: "bad-srh",
    ERR_UNSUPPORTED_ACTION: "unsupported-action",
}


class Seg6RouteErr(LrError):
    """Typed error raised by `Seg6Netlink` methods when the C ABI
    returns a positive `LR_SEG6_ERR_*` discriminant.

    Attributes
    ----------
    code : int
        The discriminant (one of the `ERR_*` constants defined above).
    message : str
        The human-readable message recorded in the last-error string.
    """

    __slots__ = ("code", "message")

    def __init__(self, code: int, message: str = ""):
        self.code = code
        self.message = message

    def __str__(self) -> str:
        name = _ERR_NAMES.get(self.code, "unknown")
        if not self.message:
            return f"seg6 route: {name} (code={self.code})"
        return f"seg6 route: {name}: {self.message} (code={self.code})"


def _raise_for_code(default_msg: str = "") -> None:
    """Build a `Seg6RouteErr` from the C ABI's last-error string + the
    discriminant returned by `lr_seg6_route_err_code`. Raises nothing
    on success (the caller already checked the rc).
    """
    code = int(get_lib().lr_seg6_route_err_code())
    if code == ERR_UNKNOWN:
        # Either no seg6 error was recorded or the discriminant could
        # not be parsed — fall back to a generic LrError so the
        # caller still sees the human-readable message.
        raise LrError(default_msg or last_error())
    raise Seg6RouteErr(code, last_error())


def err_name(code: int) -> str:
    """Return the stable name for a Seg6RouteError discriminant
    (mirror of the C ABI's `lr_seg6_route_err_name`). Returns
    `"unknown"` for an unrecognized code.
    """
    cstr = get_lib().lr_seg6_route_err_name(int(code))
    if cstr == ffi.NULL:
        return "unknown"
    return ffi.string(cstr).decode("utf-8", errors="replace")


def err_code() -> int:
    """Return the discriminant of the most recent Seg6RouteError
    recorded in the C ABI's last-error string. Returns `ERR_UNKNOWN`
    when no seg6 error is recorded.
    """
    return int(get_lib().lr_seg6_route_err_code())


# ----------------------------------------------------------------------
# Prefix helpers
# ----------------------------------------------------------------------

def _prefix_to_c(prefix: Union[str, tuple, "object"]) -> ffi.CData:
    """Build an `lr_prefix_t` from a prefix spec. Accepts:

    * a string (`"2001:db8::/64"` — parsed via `ipaddress.ip_network`)
    * a `(addr_bytes, prefix_len)` tuple (4-byte addr = IPv4,
      16-byte addr = IPv6)
    * a `PrefixSpec`-like object with `.addr` (bytes) and
      `.prefix_len` (int) attributes
    """
    if isinstance(prefix, str):
        net = ipaddress.ip_network(prefix, strict=False)
        packed = net.network_address.packed
        p = ffi.new("lr_prefix_t*")
        if net.version == 4:
            p.addr[0:4] = packed
            p.is_ipv6 = 0
        else:
            p.addr[0:16] = packed
            p.is_ipv6 = 1
        p.prefix_len = net.prefixlen
        return p
    if isinstance(prefix, tuple):
        addr, plen = prefix
    else:
        addr, plen = bytes(prefix.addr), int(prefix.prefix_len)
    if len(addr) not in (4, 16):
        raise LrError(f"prefix address must be 4 or 16 bytes, got {len(addr)}")
    p = ffi.new("lr_prefix_t*")
    p.addr[0 : len(addr)] = list(addr)
    p.is_ipv6 = 1 if len(addr) == 16 else 0
    p.prefix_len = plen
    return p


def _is_ipv6(prefix: Union[str, tuple, "object"]) -> bool:
    """Detect whether a prefix spec is IPv6 (used to validate before
    passing to `lr_seg6_route_new`, which rejects IPv4 prefixes).
    """
    if isinstance(prefix, str):
        return ipaddress.ip_network(prefix, strict=False).version == 6
    if isinstance(prefix, tuple):
        return len(prefix[0]) == 16
    return len(bytes(prefix.addr)) == 16


# ----------------------------------------------------------------------
# Seg6Route (RFC 8754 §2 — seg6 lwtunnel encap route)
# ----------------------------------------------------------------------

class Seg6Route:
    """A `seg6` encap route (RFC 8754 §2 — the LSP head-end: push an
    SRH on packets matching `prefix`).

    Wraps an `lr_seg6_route_t` opaque handle. The class mirrors
    `lr_osroute::seg6_route::Seg6Route`'s public API:
    `Seg6Route.new(prefix, srh)`, builder-style setters
    (`with_mode`, `with_if_index`), and `close()` / context-manager
    protocol.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            get_lib().lr_seg6_route_free(self._ptr)
            self._ptr = None

    def close(self) -> None:
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            get_lib().lr_seg6_route_free(self._ptr)
            self._ptr = None

    def __enter__(self) -> "Seg6Route":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    @classmethod
    def new(cls, prefix: Union[str, tuple, "object"], srh: Srh) -> "Seg6Route":
        """Build a `Seg6Route` from an IPv6 prefix and an SRH handle.

        The default encap mode is `Encap` (mirrors `ip route add ...
        encap seg6 mode encap ...`). The SRH handle is borrowed — the
        constructor clones the inner SRH.

        Raises
        ------
        LrError
            When `srh` is None or the prefix is IPv4 (the `seg6`
            lwtunnel only accepts IPv6 routes).
        """
        if srh is None or srh._ptr is None or srh._ptr == ffi.NULL:
            raise LrError("Seg6Route.new: srh is None")
        if not _is_ipv6(prefix):
            raise LrError("Seg6Route.new: prefix must be IPv6 (seg6 lwtunnel is IPv6-only)")
        cp = _prefix_to_c(prefix)
        ptr = get_lib().lr_seg6_route_new(cp[0], srh._ptr)
        if ptr == ffi.NULL:
            raise LrError(f"lr_seg6_route_new: {last_error()}")
        return cls(ptr)

    def with_mode(self, mode: int) -> "Seg6Route":
        """Set the encap mode (RFC 8754 §2 — Inline inserts the SRH
        into the existing IPv6 packet; Encap wraps it in an outer
        IPv6 header carrying the SRH). Builder-style.
        """
        rc = get_lib().lr_seg6_route_set_mode(self._ptr, int(mode))
        if rc != 0:
            raise LrError(f"lr_seg6_route_set_mode: {last_error()} (rc={rc})")
        return self

    def with_if_index(self, if_index: int) -> "Seg6Route":
        """Set the output interface index (`RTA_OIF`). The kernel's
        `fib6_nh_init` rejects a route that names neither an egress
        device nor a gateway with `ENODEV`, so callers usually set
        this. 0 means "let the kernel resolve via the gateway".
        Builder-style.
        """
        rc = get_lib().lr_seg6_route_set_if_index(self._ptr, int(if_index))
        if rc != 0:
            raise LrError(f"lr_seg6_route_set_if_index: {last_error()} (rc={rc})")
        return self


# ----------------------------------------------------------------------
# Seg6LocalRoute (RFC 8986 §4 — seg6local endpoint route)
# ----------------------------------------------------------------------

class Seg6LocalRoute:
    """A `seg6local` endpoint route (RFC 8986 §4 — the LSP tail-end:
    run `behavior` when a packet arrives addressed to `sid`).

    Wraps an `lr_seg6_local_route_t` opaque handle. The class
    mirrors `lr_osroute::seg6_route::Seg6LocalRoute`'s public API:
    `Seg6LocalRoute.new(sid, behavior_wire)`, builder-style setters
    (`with_if_index` / `with_nh4` / `with_nh6` / `with_iif` /
    `with_oif` / `with_table` / `with_vrf_table` / `with_srh`), and
    `close()` / context-manager protocol.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            get_lib().lr_seg6_local_route_free(self._ptr)
            self._ptr = None

    def close(self) -> None:
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            get_lib().lr_seg6_local_route_free(self._ptr)
            self._ptr = None

    def __enter__(self) -> "Seg6LocalRoute":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    @classmethod
    def new(cls, sid: Sid, behavior_wire: int) -> "Seg6LocalRoute":
        """Build a `Seg6LocalRoute` from a SID handle and an IANA
        behavior wire value (one of the `lr_srv6::Behavior` wire
        codes — End=1, End.X=5, End.T=9, …). The behavior is resolved
        via `Behavior::from_wire`; an unknown wire value is rejected.

        Raises
        ------
        LrError
            When `sid` is None or the behavior wire value is
            unrecognized.
        """
        if sid is None or sid._ptr is None or sid._ptr == ffi.NULL:
            raise LrError("Seg6LocalRoute.new: sid is None")
        ptr = get_lib().lr_seg6_local_route_new(sid._ptr, int(behavior_wire))
        if ptr == ffi.NULL:
            raise LrError(f"lr_seg6_local_route_new: {last_error()}")
        return cls(ptr)

    def with_if_index(self, if_index: int) -> "Seg6LocalRoute":
        rc = get_lib().lr_seg6_local_route_set_if_index(self._ptr, int(if_index))
        if rc != 0:
            raise LrError(f"lr_seg6_local_route_set_if_index: {last_error()} (rc={rc})")
        return self

    def with_nh4(self, nh4: bytes) -> "Seg6LocalRoute":
        if len(nh4) != 4:
            raise LrError(f"nh4 must be 4 bytes, got {len(nh4)}")
        rc = get_lib().lr_seg6_local_route_set_nh4(self._ptr, nh4)
        if rc != 0:
            raise LrError(f"lr_seg6_local_route_set_nh4: {last_error()} (rc={rc})")
        return self

    def with_nh6(self, nh6: bytes) -> "Seg6LocalRoute":
        if len(nh6) != 16:
            raise LrError(f"nh6 must be 16 bytes, got {len(nh6)}")
        rc = get_lib().lr_seg6_local_route_set_nh6(self._ptr, nh6)
        if rc != 0:
            raise LrError(f"lr_seg6_local_route_set_nh6: {last_error()} (rc={rc})")
        return self

    def with_iif(self, iif: int) -> "Seg6LocalRoute":
        rc = get_lib().lr_seg6_local_route_set_iif(self._ptr, int(iif))
        if rc != 0:
            raise LrError(f"lr_seg6_local_route_set_iif: {last_error()} (rc={rc})")
        return self

    def with_oif(self, oif: int) -> "Seg6LocalRoute":
        rc = get_lib().lr_seg6_local_route_set_oif(self._ptr, int(oif))
        if rc != 0:
            raise LrError(f"lr_seg6_local_route_set_oif: {last_error()} (rc={rc})")
        return self

    def with_table(self, table: int) -> "Seg6LocalRoute":
        rc = get_lib().lr_seg6_local_route_set_table(self._ptr, int(table))
        if rc != 0:
            raise LrError(f"lr_seg6_local_route_set_table: {last_error()} (rc={rc})")
        return self

    def with_vrf_table(self, vrf_table: int) -> "Seg6LocalRoute":
        rc = get_lib().lr_seg6_local_route_set_vrf_table(self._ptr, int(vrf_table))
        if rc != 0:
            raise LrError(f"lr_seg6_local_route_set_vrf_table: {last_error()} (rc={rc})")
        return self

    def with_srh(self, srh: Srh) -> "Seg6LocalRoute":
        if srh is None or srh._ptr is None or srh._ptr == ffi.NULL:
            raise LrError("Seg6LocalRoute.with_srh: srh is None")
        rc = get_lib().lr_seg6_local_route_set_srh(self._ptr, srh._ptr)
        if rc != 0:
            raise LrError(f"lr_seg6_local_route_set_srh: {last_error()} (rc={rc})")
        return self


# ----------------------------------------------------------------------
# Seg6Netlink (NETLINK_ROUTE backend)
# ----------------------------------------------------------------------

class Seg6Netlink:
    """A `NETLINK_ROUTE` backend for installing / deleting `seg6`
    and `seg6local` routes. Wraps an `lr_seg6_netlink_t` opaque
    handle. The class mirrors `lr_osroute::seg6_route::Seg6Netlink`'s
    public API: `Seg6Netlink.connect()`, `add_seg6_route` /
    `delete_seg6_route` / `add_seg6local_route` /
    `delete_seg6local_route`, `last_request_bytes` /
    `last_response_bytes` (diagnostic byte readers), and `close()` /
    context-manager protocol.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            get_lib().lr_seg6_netlink_free(self._ptr)
            self._ptr = None

    def close(self) -> None:
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            get_lib().lr_seg6_netlink_free(self._ptr)
            self._ptr = None

    def __enter__(self) -> "Seg6Netlink":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    @classmethod
    def connect(cls) -> "Seg6Netlink":
        """Open a `NETLINK_ROUTE` socket for SRv6 route installation.

        Raises
        ------
        Seg6RouteErr
            When the kernel's `seg6_enabled` sysctl is 0 (Code =
            `ERR_NOT_ENABLED`) or the platform has no SRv6 (Code =
            `ERR_UNSUPPORTED`).
        """
        ptr = get_lib().lr_seg6_netlink_connect()
        if ptr == ffi.NULL:
            _raise_for_code("lr_seg6_netlink_connect")
        return cls(ptr)

    def add_seg6_route(self, route: Seg6Route) -> None:
        if route is None or route._ptr is None or route._ptr == ffi.NULL:
            raise LrError("Seg6Netlink.add_seg6_route: route is None")
        rc = get_lib().lr_seg6_netlink_add_seg6_route(self._ptr, route._ptr)
        if rc != 0:
            _raise_for_code("lr_seg6_netlink_add_seg6_route")

    def delete_seg6_route(self, prefix: Union[str, tuple, "object"]) -> None:
        cp = _prefix_to_c(prefix)
        rc = get_lib().lr_seg6_netlink_delete_seg6_route(self._ptr, cp[0])
        if rc != 0:
            _raise_for_code("lr_seg6_netlink_delete_seg6_route")

    def add_seg6local_route(self, route: Seg6LocalRoute) -> None:
        if route is None or route._ptr is None or route._ptr == ffi.NULL:
            raise LrError("Seg6Netlink.add_seg6local_route: route is None")
        rc = get_lib().lr_seg6_netlink_add_seg6local_route(self._ptr, route._ptr)
        if rc != 0:
            _raise_for_code("lr_seg6_netlink_add_seg6local_route")

    def delete_seg6local_route(self, sid: Sid) -> None:
        if sid is None or sid._ptr is None or sid._ptr == ffi.NULL:
            raise LrError("Seg6Netlink.delete_seg6local_route: sid is None")
        rc = get_lib().lr_seg6_netlink_delete_seg6local_route(self._ptr, sid._ptr)
        if rc != 0:
            _raise_for_code("lr_seg6_netlink_delete_seg6local_route")

    def last_request_bytes(self) -> Optional[bytes]:
        out = alloc_bytes()
        rc = get_lib().lr_seg6_netlink_last_request_bytes(self._ptr, out)
        if rc != 0:
            free_bytes(out)
            raise LrError(f"lr_seg6_netlink_last_request_bytes: {last_error()} (rc={rc})")
        try:
            return copy_bytes(out)
        finally:
            free_bytes(out)

    def last_response_bytes(self) -> Optional[bytes]:
        out = alloc_bytes()
        rc = get_lib().lr_seg6_netlink_last_response_bytes(self._ptr, out)
        if rc != 0:
            free_bytes(out)
            raise LrError(f"lr_seg6_netlink_last_response_bytes: {last_error()} (rc={rc})")
        try:
            return copy_bytes(out)
        finally:
            free_bytes(out)
