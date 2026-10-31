"""RIB storage — Loc-RIB, Adj-RIB-In, Adj-RIB-Out, cross-protocol mux.

Mirrors the public Rust API of ``lr_rib::{LocRib, AdjRibIn, AdjRibOut,
RibMux, RouteSelector}`` and the C ABI surface in ``crates/lr-ffi/src/rib.rs``
(``lr_loc_rib_*``, ``lr_adj_rib_in_*``, ``lr_adj_rib_out_*``,
``lr_rib_mux_*``, ``lr_route_selector_*``).

Resources are released via ``__del__`` finalizers — the Python-side
equivalent of the Go runtime.SetFinalizer and the C++ RAII wrapper.

RFC references:
  * RFC 4271 §9 — the RIB model (Adj-RIB-In, Loc-RIB, Adj-RIB-Out).
  * RFC 7911 — Add-Path keeps more than one path per prefix in Loc-RIB.
  * RFC 8277 — labeled-unicast uses a source-prefix in the key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence, Tuple

from ._ffi import ffi, get_lib
from .router import LrError, last_error, PROTO_BGP, PROTO_OSPF, PROTO_OSPF3, PROTO_BABEL, PROTO_STATIC, PROTO_CONNECTED

# ---- AFI / SAFI constants (mirror NlriFamily in lr_core::nlri) ----

AFI_IPV4 = 1
AFI_IPV6 = 2
SAFI_UNICAST = 1
SAFI_MULTICAST = 2
SAFI_LABELED_UNICAST = 4


def _check_rc(rc: int, what: str) -> None:
    if rc < 0:
        raise LrError(f"{what} failed (rc={rc}): {last_error()}")


def _prefix_spec(spec) -> ffi.CData:
    """Build an ``lr_prefix_t`` from ``(addr, prefix_len)`` or any
    object with ``addr`` / ``prefix_len`` fields."""
    if isinstance(spec, tuple):
        addr = bytes(spec[0])
        plen = int(spec[1])
    else:
        addr = bytes(spec.addr)
        plen = int(spec.prefix_len)
    if len(addr) not in (4, 16):
        raise LrError("prefix address must be 4 or 16 bytes")
    p = ffi.new("lr_prefix_t*")
    p.addr[0:len(addr)] = list(addr)
    p.is_ipv6 = 1 if len(addr) == 16 else 0
    p.prefix_len = plen
    return p


def _core_prefix_spec(spec) -> ffi.CData:
    """Build an ``lr_core_prefix_t`` from ``(addr, prefix_len)`` or
    an object with ``addr`` / ``prefix_len`` fields. Used by
    ``lr_route_key_t``.

    IPv4 addresses occupy the *last* 4 bytes of the 16-byte octet
    array (the standard IPv4-mapped IPv6 layout the C ABI uses).
    """
    if isinstance(spec, tuple):
        addr = bytes(spec[0])
        plen = int(spec[1])
    else:
        addr = bytes(spec.addr)
        plen = int(spec.prefix_len)
    if len(addr) not in (4, 16):
        raise LrError("prefix address must be 4 or 16 bytes")
    p = ffi.new("lr_core_prefix_t*")
    # Zero the octets buffer first (IPv4 occupies the last 4 bytes).
    for i in range(16):
        p.addr.octets[i] = 0
    if len(addr) == 4:
        p.addr.is_ipv6 = 0
        # IPv4 occupies the last 4 bytes (the IPv4-mapped IPv6 layout).
        for i, b in enumerate(addr):
            p.addr.octets[12 + i] = b
    else:
        p.addr.is_ipv6 = 1
        for i, b in enumerate(addr):
            p.addr.octets[i] = b
    p.prefix_len = plen
    return p


@dataclass(frozen=True)
class RouteKey:
    """Repr-C ``lr_route_key_t`` mirror.

    ``prefix`` is ``(addr, prefix_len)`` (4 or 16 bytes). ``afi`` and
    ``safi`` are the address-family identifiers (``AFI_IPV4`` /
    ``SAFI_UNICAST`` etc.). ``source`` (optional) carries the source
    prefix used by RFC 8277 labeled-unicast.
    """

    prefix: Tuple[bytes, int]
    afi: int = AFI_IPV4
    safi: int = SAFI_UNICAST
    source: Optional[Tuple[bytes, int]] = None

    def _to_c(self) -> ffi.CData:
        k = ffi.new("lr_route_key_t*")
        k.prefix = _core_prefix_spec(self.prefix)[0]
        k.afi_safi = (int(self.afi) << 8) | (int(self.safi) & 0xFF)
        if self.source is not None:
            k.has_source = 1
            k.source_prefix = _core_prefix_spec(self.source)[0]
        else:
            k.has_source = 0
            # Zero out source_prefix
            for i in range(16):
                k.source_prefix.addr.octets[i] = 0
            k.source_prefix.prefix_len = 0
        return k


@dataclass(frozen=True)
class RouteOrigin:
    """Repr-C ``lr_route_origin_t`` mirror.

    ``protocol`` is one of the ``PROTO_*`` constants (``PROTO_BGP``,
    ``PROTO_OSPF``, ...). ``peer`` is the per-peer session handle (0
    for locally originated routes).
    """

    protocol: int
    peer: int = 0

    def _to_c(self) -> ffi.CData:
        o = ffi.new("lr_route_origin_t*")
        o.protocol = int(self.protocol) & 0xFF
        o.peer = int(self.peer)
        return o


@dataclass
class RibDiff:
    """Generation-based delta returned from :meth:`LocRib.diff_since`.

    Counts of routes added / modified / removed since the requested
    generation. The full per-route delta is not currently surfaced
    through the C ABI — only the three counts.
    """

    added: int = 0
    modified: int = 0
    removed: int = 0


class _BorrowedRoute:
    """A *borrowed* ``lr_route_t`` wrapper — the C side owns the
    underlying ``Route`` and the wrapper's lifetime ends when the
    iteration completes. The destructor is a no-op (does NOT call
    ``lr_route_free``); the borrow is only valid for the body of the
    iteration that produced it.

    Use this only inside the iterators returned by :meth:`LocRib.iter_best`
    / :meth:`LocRib.iter_paths` / :meth:`AdjRibIn.iter_all` /
    :meth:`AdjRibIn.iter_origin` / :meth:`AdjRibOut.iter_for`.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr) -> None:
        self._ptr = ptr

    def __del__(self) -> None:  # No-op: the C side owns the route.
        pass

    @property
    def ptr(self):
        return self._ptr


class LocRib:
    """Owned Loc-RIB handle (RFC 4271 §9.1).

    The Loc-RIB holds the routes after import policy and best-path
    selection. Routes are keyed by :class:`RouteKey`; under RFC 7911
    Add-Path, more than one path can be stored per key.
    """

    def __init__(self) -> None:
        ptr = get_lib().lr_loc_rib_new()
        if ptr == ffi.NULL:
            raise LrError(f"lr_loc_rib_new: {last_error()}")
        self._ptr = ptr

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_loc_rib_free(ptr)
            self._ptr = None

    def __enter__(self) -> "LocRib":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def install(self, route) -> int:
        """Install one path (the route handle is *consumed*).

        Returns 1 when the install actually changed the Loc-RIB (a new
        path was added or an existing one replaced with non-identical
        content); 0 for a byte-identical no-op (no generation bump).
        """
        rc = get_lib().lr_loc_rib_install(self._ptr, route._ptr)
        _check_rc(rc, "lr_loc_rib_install")
        # The LocRib took ownership; the Route wrapper must not free.
        route._ptr = None
        return int(rc)

    def uninstall(self, key: RouteKey) -> int:
        """Withdraw a key. Returns 1 when a route was withdrawn, 0 when
        the key was not present."""
        prefix_c = _prefix_spec(key.prefix)
        source_c = _prefix_spec(key.source) if key.source is not None else ffi.NULL
        rc = get_lib().lr_loc_rib_uninstall(
            self._ptr,
            prefix_c,
            int(key.afi),
            int(key.safi),
            source_c,
        )
        _check_rc(rc, "lr_loc_rib_uninstall")
        return int(rc)

    def install_set(self, key: RouteKey, routes: Sequence) -> None:
        """Install a ranked set of paths for a key (RFC 7911 — Add-Path
        keeps more than one path per prefix; the first element is the
        best path non-Add-Path consumers see). The handles are *not*
        consumed — the Loc-RIB clones the underlying ``Route`` value.
        """
        if not routes:
            raise LrError("install_set requires at least one route")
        key_c = key._to_c()
        arr = ffi.new(f"lr_route_t[{len(routes)}]")
        for i, r in enumerate(routes):
            arr[i] = r._ptr
        rc = get_lib().lr_loc_rib_install_set(self._ptr, key_c, arr, len(routes))
        _check_rc(rc, "lr_loc_rib_install_set")

    def paths_len(self) -> int:
        """Total number of stored paths (>= ``len()`` under RFC 7911
        Add-Path)."""
        return int(get_lib().lr_loc_rib_paths_len(self._ptr))

    def len(self) -> int:
        """Number of keys (prefixes) in the Loc-RIB."""
        return int(get_lib().lr_loc_rib_len(self._ptr))

    def __len__(self) -> int:
        return self.len()

    def is_empty(self) -> bool:
        return bool(get_lib().lr_loc_rib_is_empty(self._ptr))

    def generation(self) -> int:
        """Monotonic generation counter — callers can ask "what
        changed since generation X?"."""
        return int(get_lib().lr_loc_rib_generation(self._ptr))

    def best_present(self, key: RouteKey) -> bool:
        """True when a route is present for the given key."""
        prefix_c = _prefix_spec(key.prefix)
        source_c = _prefix_spec(key.source) if key.source is not None else ffi.NULL
        return bool(
            get_lib().lr_loc_rib_best_present(
                self._ptr, prefix_c, int(key.afi), int(key.safi), source_c
            )
        )

    def best(self, key: RouteKey):
        """Read the best path for a key. Returns a NEW :class:`Route`
        (a copy of the Loc-RIB's internal route) the caller owns, or
        ``None`` when the key is absent.
        """
        # Local import to avoid a circular import (policy.py imports
        # from _ffi; it does not import rib.py).
        from .policy import Route

        prefix_c = _prefix_spec(key.prefix)
        source_c = _prefix_spec(key.source) if key.source is not None else ffi.NULL
        out = ffi.new("lr_route_t*")
        rc = get_lib().lr_loc_rib_best(
            self._ptr, prefix_c, int(key.afi), int(key.safi), source_c, out
        )
        _check_rc(rc, "lr_loc_rib_best")
        if out[0] == ffi.NULL:
            return None
        # Wrap the boxed route as a Route handle. We need to assign
        # _ptr directly since we already own the allocation.
        r = Route.__new__(Route)
        r._ptr = out[0]
        return r

    def paths(self, key: RouteKey) -> int:
        """Number of paths stored for a key (RFC 7911 Add-Path)."""
        key_c = key._to_c()
        return int(get_lib().lr_loc_rib_paths(self._ptr, key_c))

    def iter_best(self) -> Iterator:
        """Walk every best route in the Loc-RIB.

        The callback receives a *borrowed* :class:`Route` handle — the
        caller must NOT free it. The iterator materializes each route
        into a temporary wrapper that's only valid for one iteration.
        """
        results: List = []

        @ffi.callback("void(lr_route_t, void *)")
        def cb(route, _user):
            r = _BorrowedRoute(route)
            results.append(r)

        count = get_lib().lr_loc_rib_iter_best(self._ptr, cb, ffi.NULL)
        if count < 0:
            raise LrError(f"lr_loc_rib_iter_best: {last_error()}")
        return iter(results)

    def iter_paths(self) -> Iterator:
        """Walk every path (every multipath entry, not just the best)
        in the Loc-RIB. See :meth:`iter_best` for the borrowing
        contract."""
        results: List = []

        @ffi.callback("void(lr_route_t, void *)")
        def cb(route, _user):
            r = _BorrowedRoute(route)
            results.append(r)

        count = get_lib().lr_loc_rib_iter_paths(self._ptr, cb, ffi.NULL)
        if count < 0:
            raise LrError(f"lr_loc_rib_iter_paths: {last_error()}")
        return iter(results)

    def iter_sets(self) -> Iterator[Tuple[Tuple[bytes, int, bool], int]]:
        """Walk every ``(RouteKey, paths)`` set in the Loc-RIB.

        Yields ``((addr, prefix_len, is_ipv6), path_count)`` tuples.
        ``addr`` is the first 4 bytes (for IPv4) or all 16 bytes (for
        IPv6) — the Loc-RIB iterator returns the IPv4 address in the
        first 4 bytes of a 16-byte buffer (zero-padded).
        """
        results: List[Tuple[Tuple[bytes, int, bool], int]] = []

        @ffi.callback("void(uint8_t *, uint8_t, uint8_t, uintptr_t, void *)")
        def cb(prefix_out, prefix_len, is_ipv6, path_count, _user):
            addr = bytes(ffi.buffer(prefix_out, 16))[:]
            results.append(((addr, int(prefix_len), bool(is_ipv6)), int(path_count)))

        count = get_lib().lr_loc_rib_iter_sets(self._ptr, cb, ffi.NULL)
        if count < 0:
            raise LrError(f"lr_loc_rib_iter_sets: {last_error()}")
        return iter(results)

    def diff_since(self, since_gen: int) -> RibDiff:
        """Compute the diff between the Loc-RIB's current state and
        its state at generation ``since_gen``. The diff is computed
        against the Loc-RIB's history ring (16 entries deep); for
        older diffs the function returns 0 in all three counts.
        """
        added = ffi.new("uintptr_t*")
        modified = ffi.new("uintptr_t*")
        removed = ffi.new("uintptr_t*")
        rc = get_lib().lr_loc_rib_diff_since(
            self._ptr, int(since_gen), added, modified, removed
        )
        _check_rc(rc, "lr_loc_rib_diff_since")
        return RibDiff(
            added=int(added[0]), modified=int(modified[0]), removed=int(removed[0])
        )


class AdjRibIn:
    """Owned Adj-RIB-In handle (RFC 4271 §9).

    The Adj-RIB-In holds the pre-policy routes received from each
    peer, keyed by ``(origin, RouteKey, path_id)``. Withdrawals
    remove by the same triple.
    """

    def __init__(self) -> None:
        ptr = get_lib().lr_adj_rib_in_new()
        if ptr == ffi.NULL:
            raise LrError(f"lr_adj_rib_in_new: {last_error()}")
        self._ptr = ptr

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_adj_rib_in_free(ptr)
            self._ptr = None

    def __enter__(self) -> "AdjRibIn":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def feed(self, origin: RouteOrigin, route) -> None:
        """Install one pre-policy route from ``origin``. The route
        handle is *consumed*."""
        rc = get_lib().lr_adj_rib_in_feed(
            self._ptr, int(origin.peer), int(origin.protocol), route._ptr
        )
        _check_rc(rc, "lr_adj_rib_in_feed")
        route._ptr = None

    def withdraw(self, origin: RouteOrigin, key: RouteKey, path_id: int = 0) -> int:
        """Withdraw one ``(origin, key, path_id)`` tuple. Returns 1
        when a route was withdrawn, 0 when no matching entry existed.
        """
        prefix_c = _prefix_spec(key.prefix)
        source_c = _prefix_spec(key.source) if key.source is not None else ffi.NULL
        rc = get_lib().lr_adj_rib_in_withdraw(
            self._ptr,
            int(origin.peer),
            int(origin.protocol),
            prefix_c,
            int(key.afi),
            int(key.safi),
            source_c,
            int(path_id),
        )
        _check_rc(rc, "lr_adj_rib_in_withdraw")
        return int(rc)

    def get(self, origin: RouteOrigin, key: RouteKey, path_id: int = 0):
        """Look up a route by ``(origin, key, path_id)``. Returns a
        NEW :class:`Route` (a copy) the caller owns, or ``None`` when
        absent."""
        from .policy import Route

        key_c = key._to_c()
        origin_c = origin._to_c()
        out = ffi.new("lr_route_t*")
        rc = get_lib().lr_adj_rib_in_get(self._ptr, origin_c[0], key_c, int(path_id), out)
        _check_rc(rc, "lr_adj_rib_in_get")
        if rc == 0 and out[0] == ffi.NULL:
            return None
        if rc == 1:
            r = Route.__new__(Route)
            r._ptr = out[0]
            return r
        return None

    def origins_for(self, key: RouteKey) -> List[RouteOrigin]:
        """List the origins that have a route for ``key``."""
        key_c = key._to_c()
        cap = 64
        out_origins = ffi.new(f"lr_route_origin_t[{cap}]")
        out_count = ffi.new("uintptr_t*")
        rc = get_lib().lr_adj_rib_in_origins_for(
            self._ptr, key_c, out_origins, cap, out_count
        )
        _check_rc(rc, "lr_adj_rib_in_origins_for")
        n = int(out_count[0])
        # If cap was too small, retry with the actual count.
        if n > cap:
            cap = n
            out_origins = ffi.new(f"lr_route_origin_t[{cap}]")
            rc = get_lib().lr_adj_rib_in_origins_for(
                self._ptr, key_c, out_origins, cap, out_count
            )
            _check_rc(rc, "lr_adj_rib_in_origins_for (retry)")
            n = int(out_count[0])
        return [
            RouteOrigin(protocol=int(out_origins[i].protocol), peer=int(out_origins[i].peer))
            for i in range(n)
        ]

    def clear(self) -> None:
        """Drop every route from every origin."""
        rc = get_lib().lr_adj_rib_in_clear(self._ptr)
        _check_rc(rc, "lr_adj_rib_in_clear")

    def clear_for(self, origin: RouteOrigin) -> None:
        """Drop every route from one origin."""
        origin_c = origin._to_c()
        rc = get_lib().lr_adj_rib_in_clear_for(self._ptr, origin_c[0])
        _check_rc(rc, "lr_adj_rib_in_clear_for")

    def len(self) -> int:
        return int(get_lib().lr_adj_rib_in_len(self._ptr))

    def __len__(self) -> int:
        return self.len()

    def is_empty(self) -> bool:
        return bool(get_lib().lr_adj_rib_in_is_empty(self._ptr))

    def iter_all(self) -> Iterator:
        """Walk every route in the Adj-RIB-In, regardless of origin.

        The callback receives a *borrowed* route handle — the caller
        must NOT free it. Returns a list of :class:`_BorrowedRoute`
        wrappers; the borrow is only valid until the next mutating
        call on this Adj-RIB-In.
        """
        results: List = []

        @ffi.callback("void(lr_route_t, void *)")
        def cb(route, _user):
            r = _BorrowedRoute(route)
            results.append(r)

        count = get_lib().lr_adj_rib_in_iter_all(self._ptr, cb, ffi.NULL)
        if count < 0:
            raise LrError(f"lr_adj_rib_in_iter_all: {last_error()}")
        return iter(results)

    def iter_origin(self, origin: RouteOrigin) -> Iterator:
        """Walk every route from one origin. See :meth:`iter_all` for
        the borrowing contract."""
        results: List = []

        @ffi.callback("void(lr_route_t, void *)")
        def cb(route, _user):
            r = _BorrowedRoute(route)
            results.append(r)

        count = get_lib().lr_adj_rib_in_iter_origin(
            self._ptr, int(origin.peer), int(origin.protocol), cb, ffi.NULL
        )
        if count < 0:
            raise LrError(f"lr_adj_rib_in_iter_origin: {last_error()}")
        return iter(results)


class AdjRibOut:
    """Owned Adj-RIB-Out handle (RFC 4271 §9).

    The Adj-RIB-Out holds the routes advertised to each peer, keyed
    by ``(dest, RouteKey, tx_path_id)``. Suppressions remove by the
    same triple.
    """

    def __init__(self) -> None:
        ptr = get_lib().lr_adj_rib_out_new()
        if ptr == ffi.NULL:
            raise LrError(f"lr_adj_rib_out_new: {last_error()}")
        self._ptr = ptr

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_adj_rib_out_free(ptr)
            self._ptr = None

    def __enter__(self) -> "AdjRibOut":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def advertise(self, dest: RouteOrigin, route, tx_path_id: int = 0) -> None:
        """Advertise one route to a destination. The route handle is
        *not* consumed — the Adj-RIB-Out stores a clone."""
        rc = get_lib().lr_adj_rib_out_advertise(
            self._ptr, int(dest.peer), int(dest.protocol), route._ptr, int(tx_path_id)
        )
        _check_rc(rc, "lr_adj_rib_out_advertise")

    def suppress(self, dest: RouteOrigin, key: RouteKey, tx_path_id: int = 0) -> int:
        """Suppress (withdraw) one ``(dest, key, path_id)`` tuple.
        Returns 1 when a route was suppressed, 0 when no matching entry
        existed."""
        prefix_c = _prefix_spec(key.prefix)
        source_c = _prefix_spec(key.source) if key.source is not None else ffi.NULL
        rc = get_lib().lr_adj_rib_out_suppress(
            self._ptr,
            int(dest.peer),
            int(dest.protocol),
            prefix_c,
            int(key.afi),
            int(key.safi),
            source_c,
            int(tx_path_id),
        )
        _check_rc(rc, "lr_adj_rib_out_suppress")
        return int(rc)

    def tx_path_ids(self, dest: RouteOrigin, key: RouteKey) -> List[int]:
        """Read the TX path IDs advertised to ``dest`` for ``key``."""
        key_c = key._to_c()
        dest_c = dest._to_c()
        cap = 64
        out_ids = ffi.new(f"uint32_t[{cap}]")
        out_count = ffi.new("uintptr_t*")
        rc = get_lib().lr_adj_rib_out_tx_path_ids(
            self._ptr, dest_c[0], key_c, out_ids, cap, out_count
        )
        _check_rc(rc, "lr_adj_rib_out_tx_path_ids")
        n = int(out_count[0])
        if n > cap:
            cap = n
            out_ids = ffi.new(f"uint32_t[{cap}]")
            rc = get_lib().lr_adj_rib_out_tx_path_ids(
                self._ptr, dest_c[0], key_c, out_ids, cap, out_count
            )
            _check_rc(rc, "lr_adj_rib_out_tx_path_ids (retry)")
            n = int(out_count[0])
        return [int(out_ids[i]) for i in range(min(n, cap))]

    def paths_for(
        self, dest: RouteOrigin, key: RouteKey
    ) -> List[Tuple[int, "_BorrowedRoute"]]:
        """Walk every advertised ``(tx_path_id, route)`` pair for
        ``(dest, key)``. Each route is *borrowed* — the Adj-RIB-Out
        owns it for the duration of the call; the borrow is only
        valid until the next mutating call on this Adj-RIB-Out.
        """
        key_c = key._to_c()
        dest_c = dest._to_c()
        results: List[Tuple[int, _BorrowedRoute]] = []

        @ffi.callback("void(uint32_t, lr_route_t, void *)")
        def cb(path_id, route, _user):
            results.append((int(path_id), _BorrowedRoute(route)))

        count = get_lib().lr_adj_rib_out_paths_for(
            self._ptr, dest_c[0], key_c, cb, ffi.NULL
        )
        if count < 0:
            raise LrError(f"lr_adj_rib_out_paths_for: {last_error()}")
        return results

    def advertised_keys(
        self, dest: RouteOrigin, family: Tuple[int, int]
    ) -> List[Tuple[RouteKey, List[int]]]:
        """Walk every ``(RouteKey, [tx_path_id])`` pair advertised to
        ``dest`` for the given AFI/SAFI ``family``. Each pair is
        materialized into Python-owned objects before the callback
        returns, so the returned list is safe to keep.
        """
        dest_c = dest._to_c()
        afi, safi = int(family[0]), int(family[1])
        results: List[Tuple[RouteKey, List[int]]] = []

        @ffi.callback("void(const lr_route_key_t *, const uint32_t *, uintptr_t, void *)")
        def cb(key_ptr, path_ids_ptr, path_id_count, _user):
            # Read the C key into a Python RouteKey.
            k_c = key_ptr[0]
            is_v6 = bool(k_c.prefix.addr.is_ipv6)
            if is_v6:
                addr = bytes(ffi.buffer(k_c.prefix.addr.octets, 16))
            else:
                addr = bytes(ffi.buffer(k_c.prefix.addr.octets + 12, 4))
            prefix = (addr, int(k_c.prefix.prefix_len))
            afi = int(k_c.afi_safi >> 8)
            safi = int(k_c.afi_safi & 0xFF)
            source = None
            if k_c.has_source != 0:
                if k_c.source_prefix.addr.is_ipv6:
                    src_addr = bytes(ffi.buffer(k_c.source_prefix.addr.octets, 16))
                else:
                    src_addr = bytes(ffi.buffer(k_c.source_prefix.addr.octets + 12, 4))
                source = (src_addr, int(k_c.source_prefix.prefix_len))
            rk = RouteKey(prefix=prefix, afi=afi, safi=safi, source=source)
            # Read the path_ids array (only valid for this invocation).
            n = int(path_id_count)
            ids = [int(path_ids_ptr[i]) for i in range(n)] if n > 0 else []
            results.append((rk, ids))

        count = get_lib().lr_adj_rib_out_advertised_keys(
            self._ptr, dest_c[0], afi, safi, cb, ffi.NULL
        )
        if count < 0:
            raise LrError(f"lr_adj_rib_out_advertised_keys: {last_error()}")
        return results

    def clear(self) -> None:
        rc = get_lib().lr_adj_rib_out_clear(self._ptr)
        _check_rc(rc, "lr_adj_rib_out_clear")

    def clear_for(self, dest: RouteOrigin) -> None:
        dest_c = dest._to_c()
        rc = get_lib().lr_adj_rib_out_clear_for(self._ptr, dest_c[0])
        _check_rc(rc, "lr_adj_rib_out_clear_for")

    def len(self) -> int:
        return int(get_lib().lr_adj_rib_out_len(self._ptr))

    def __len__(self) -> int:
        return self.len()

    def is_empty(self) -> bool:
        return bool(get_lib().lr_adj_rib_out_is_empty(self._ptr))

    def iter_for(self, dest: RouteOrigin) -> Iterator:
        """Walk every route advertised to a given destination. See
        :meth:`AdjRibIn.iter_all` for the borrowing contract."""
        results: List = []

        @ffi.callback("void(lr_route_t, void *)")
        def cb(route, _user):
            r = _BorrowedRoute(route)
            results.append(r)

        count = get_lib().lr_adj_rib_out_iter_for(
            self._ptr, int(dest.peer), int(dest.protocol), cb, ffi.NULL
        )
        if count < 0:
            raise LrError(f"lr_adj_rib_out_iter_for: {last_error()}")
        return iter(results)


class RibMux:
    """Cross-protocol mux handle (RFC 4271 §9 + the admin-distance
    model the daemon uses to merge BGP / OSPF / Babel routes into one
    FIB).

    Routes are keyed by :class:`RouteKey` only — the mux discards the
    origin metadata, keeping the route with the lowest administrative
    distance.
    """

    def __init__(self) -> None:
        ptr = get_lib().lr_rib_mux_new()
        if ptr == ffi.NULL:
            raise LrError(f"lr_rib_mux_new: {last_error()}")
        self._ptr = ptr

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_rib_mux_free(ptr)
            self._ptr = None

    def __enter__(self) -> "RibMux":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def install(self, route) -> None:
        """Install one route into the mux (the handle is *consumed*)."""
        rc = get_lib().lr_rib_mux_install(self._ptr, route._ptr)
        _check_rc(rc, "lr_rib_mux_install")
        route._ptr = None

    def uninstall(self, key: RouteKey) -> int:
        """Uninstall a key. Returns 1 when a route was withdrawn, 0
        when the key was not present."""
        prefix_c = _prefix_spec(key.prefix)
        source_c = _prefix_spec(key.source) if key.source is not None else ffi.NULL
        rc = get_lib().lr_rib_mux_uninstall(
            self._ptr, prefix_c, int(key.afi), int(key.safi), source_c
        )
        _check_rc(rc, "lr_rib_mux_uninstall")
        return int(rc)

    def get(self, key: RouteKey):
        """Read the merged route for a key. Returns a NEW
        :class:`Route` (a copy), or ``None`` when the key is absent."""
        from .policy import Route

        prefix_c = _prefix_spec(key.prefix)
        source_c = _prefix_spec(key.source) if key.source is not None else ffi.NULL
        out = ffi.new("lr_route_t*")
        rc = get_lib().lr_rib_mux_get(
            self._ptr, prefix_c, int(key.afi), int(key.safi), source_c, out
        )
        _check_rc(rc, "lr_rib_mux_get")
        if out[0] == ffi.NULL:
            return None
        r = Route.__new__(Route)
        r._ptr = out[0]
        return r

    def len(self) -> int:
        return int(get_lib().lr_rib_mux_len(self._ptr))

    def __len__(self) -> int:
        return self.len()

    def is_empty(self) -> bool:
        return bool(get_lib().lr_rib_mux_is_empty(self._ptr))

    def iter(self) -> Iterator:
        """Walk every merged route in the mux. The callback receives a
        *borrowed* route handle — the caller must NOT free it. The
        borrow is only valid until the next mutating call on this mux.
        """
        results: List = []

        @ffi.callback("void(lr_route_t, void *)")
        def cb(route, _user):
            r = _BorrowedRoute(route)
            results.append(r)

        count = get_lib().lr_rib_mux_iter(self._ptr, cb, ffi.NULL)
        if count < 0:
            raise LrError(f"lr_rib_mux_iter: {last_error()}")
        return iter(results)


class RouteSelector:
    """BIRD/FRR best-path selector (RFC 4271 §9.1)."""

    @staticmethod
    def select(routes: Sequence) -> int:
        """Apply the BIRD/FRR best-path selector to a flat array of
        route handles. Returns the index of the winning route, or -1
        when the array is empty / every handle is NULL. The handles
        are *not* consumed — the caller keeps ownership."""
        if not routes:
            return -1
        arr = ffi.new(f"lr_route_t[{len(routes)}]")
        for i, r in enumerate(routes):
            arr[i] = r._ptr
        rc = get_lib().lr_route_selector_select(arr, len(routes))
        if rc < -1:
            raise LrError(f"lr_route_selector_select: {last_error()}")
        return int(rc)

    @staticmethod
    def select_bgp(routes: Sequence) -> int:
        """Apply the BGP-specific best-path selector (RFC 4271 §9.1).
        Same contract as :meth:`select`."""
        if not routes:
            return -1
        arr = ffi.new(f"lr_route_t[{len(routes)}]")
        for i, r in enumerate(routes):
            arr[i] = r._ptr
        rc = get_lib().lr_route_selector_select_bgp(arr, len(routes))
        if rc < -1:
            raise LrError(f"lr_route_selector_select_bgp: {last_error()}")
        return int(rc)

    @staticmethod
    def compare(a, b) -> int:
        """Compare two routes with the daemon's default comparator
        (admin distance, then metric, then age, then protocol priority).

        Returns -1 when ``a`` is preferred over ``b``, 0 when they tie
        on every discriminator, 1 when ``b`` is preferred over ``a``,
        and raises :class:`LrError` on a NULL handle or a panic.
        """
        rc = get_lib().lr_route_selector_compare(a._ptr, b._ptr)
        if rc < -1:
            raise LrError(f"lr_route_selector_compare: {last_error()}")
        return int(rc)
