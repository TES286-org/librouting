"""Policy objects over the C ABI (ROADMAP-v3 D5.3): route handles,
prefix-lists, route-maps and the match resolver.

The route handle boxes a real Rust `Route`, so policy evaluation runs
against the same data model the library uses internally. The route-map
mirrors FRR `route-map` semantics: ordered entries, first match applies
its sets and decides; unknown list ids deny (fail-closed).
"""

from __future__ import annotations

from ._ffi import ffi, get_lib
from .router import LrError, last_error

__all__ = [
    "Route",
    "PrefixList",
    "RouteMap",
    "Resolver",
    "AsPathFilter",
    "CommunityEntry",
    "Match",
    "Set",
    # match kinds
    "MATCH_PREFIX_IN",
    "MATCH_AS_PATH_IN",
    "MATCH_COMMUNITY_IN",
    "MATCH_PROTOCOL_IS",
    "MATCH_NEXT_HOP_IN",
    # set kinds
    "SET_LOCAL_PREF",
    "SET_MED",
    "SET_NEXT_HOP",
    "SET_PREPEND_AS",
    "SET_ADD_COMMUNITY",
    "SET_METRIC",
    "SET_TAG",
    # entry verdicts
    "VERDICT_CONTINUE",
    "VERDICT_PERMIT",
    "VERDICT_DENY",
    # evaluate outcomes
    "EVAL_FALLTHROUGH",
    "EVAL_DENY",
    "EVAL_PERMIT",
]

# Route-map match condition kinds (LR_MATCH_*).
MATCH_PREFIX_IN = 0
MATCH_AS_PATH_IN = 1
MATCH_COMMUNITY_IN = 2
MATCH_PROTOCOL_IS = 3
MATCH_NEXT_HOP_IN = 4

# Route-map set action kinds (LR_SET_*).
SET_LOCAL_PREF = 0
SET_MED = 1
SET_NEXT_HOP = 2
SET_PREPEND_AS = 3
SET_ADD_COMMUNITY = 4
SET_METRIC = 5
SET_TAG = 6

# Route-map entry verdicts (LR_VERDICT_*).
VERDICT_CONTINUE = 0
VERDICT_PERMIT = 1
VERDICT_DENY = 2

# lr_route_map_evaluate outcomes (LR_EVAL_*).
EVAL_FALLTHROUGH = -1
EVAL_DENY = 0
EVAL_PERMIT = 1


def _prefix_spec(spec) -> ffi.CData:
    """Build an lr_prefix_t from (addr bytes, prefix_len) or a
    PrefixSpec-like object with ``addr`` / ``prefix_len``."""
    addr = bytes(spec[0]) if isinstance(spec, tuple) else bytes(spec.addr)
    plen = int(spec[1]) if isinstance(spec, tuple) else int(spec.prefix_len)
    if len(addr) not in (4, 16):
        raise LrError("prefix address must be 4 or 16 bytes")
    p = ffi.new("lr_prefix_t*")
    p.addr[0:len(addr)] = list(addr)
    p.is_ipv6 = 1 if len(addr) == 16 else 0
    p.prefix_len = plen
    return p


class Route:
    """An owned policy route handle (a boxed Rust ``Route``)."""

    def __init__(self, prefix, protocol: int):
        """``prefix`` is ``(addr, prefix_len)`` (4 or 16 bytes);
        ``protocol`` is one of the ``PROTO_*`` constants."""
        p = _prefix_spec(prefix)
        octets = bytes(p.addr[0:16 if p.is_ipv6 else 4])
        if p.is_ipv6:
            ptr = get_lib().lr_route_new_v6(octets, p.prefix_len, int(protocol))
        else:
            ptr = get_lib().lr_route_new_v4(octets, p.prefix_len, int(protocol))
        if ptr == ffi.NULL:
            raise LrError(f"lr_route_new: {last_error()}")
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None:
            get_lib().lr_route_free(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def set_next_hop(self, addr: bytes) -> None:
        if len(addr) not in (4, 16):
            raise LrError("next hop must be 4 or 16 bytes")
        rc = get_lib().lr_route_set_next_hop(self._ptr, addr, 1 if len(addr) == 16 else 0)
        if rc != 0:
            raise LrError(f"lr_route_set_next_hop failed (rc={rc}): {last_error()}")

    def set_local_pref(self, value: int) -> None:
        rc = get_lib().lr_route_set_local_pref(self._ptr, int(value))
        if rc != 0:
            raise LrError(f"lr_route_set_local_pref failed (rc={rc}): {last_error()}")

    def local_pref(self) -> int | None:
        out = ffi.new("uint32_t*")
        rc = get_lib().lr_route_local_pref(self._ptr, out)
        if rc == 1:
            return None
        if rc != 0:
            raise LrError(f"lr_route_local_pref failed (rc={rc}): {last_error()}")
        return int(out[0])

    def set_med(self, value: int) -> None:
        rc = get_lib().lr_route_set_med(self._ptr, int(value))
        if rc != 0:
            raise LrError(f"lr_route_set_med failed (rc={rc}): {last_error()}")

    def med(self) -> int | None:
        out = ffi.new("uint32_t*")
        rc = get_lib().lr_route_med(self._ptr, out)
        if rc == 1:
            return None
        if rc != 0:
            raise LrError(f"lr_route_med failed (rc={rc}): {last_error()}")
        return int(out[0])

    def set_origin(self, origin: int) -> None:
        rc = get_lib().lr_route_set_origin(self._ptr, int(origin))
        if rc != 0:
            raise LrError(f"lr_route_set_origin failed (rc={rc}): {last_error()}")

    def set_as_path(self, asns: list[int]) -> None:
        arr = ffi.new("uint32_t[]", [int(a) for a in asns]) if asns else ffi.NULL
        rc = get_lib().lr_route_set_as_path(self._ptr, arr, len(asns))
        if rc != 0:
            raise LrError(f"lr_route_set_as_path failed (rc={rc}): {last_error()}")

    def as_path(self) -> list[int]:
        n = get_lib().lr_route_as_path(self._ptr, ffi.NULL, 0)
        if n < 0:
            return []
        if n == 0:
            return []
        out = ffi.new("uint32_t[]", n)
        rc = get_lib().lr_route_as_path(self._ptr, out, n)
        if rc < 0:
            raise LrError(f"lr_route_as_path failed (rc={rc}): {last_error()}")
        return list(out)

    def add_community(self, asn: int, value: int) -> None:
        rc = get_lib().lr_route_add_community(self._ptr, int(asn), int(value))
        if rc != 0:
            raise LrError(f"lr_route_add_community failed (rc={rc}): {last_error()}")

    def set_communities(self, packed: list[int]) -> None:
        arr = ffi.new("uint64_t[]", [int(v) for v in packed]) if packed else ffi.NULL
        rc = get_lib().lr_route_set_communities(self._ptr, arr, len(packed))
        if rc != 0:
            raise LrError(f"lr_route_set_communities failed (rc={rc}): {last_error()}")

    def communities(self) -> list[int]:
        n = get_lib().lr_route_communities(self._ptr, ffi.NULL, 0)
        if n <= 0:
            return []
        out = ffi.new("uint64_t[]", n)
        rc = get_lib().lr_route_communities(self._ptr, out, n)
        if rc < 0:
            raise LrError(f"lr_route_communities failed (rc={rc}): {last_error()}")
        return list(out)

    def add_large_community(self, global_admin: int, local_data1: int, local_data2: int) -> None:
        rc = get_lib().lr_route_add_large_community(
            self._ptr, int(global_admin), int(local_data1), int(local_data2)
        )
        if rc != 0:
            raise LrError(f"lr_route_add_large_community failed (rc={rc}): {last_error()}")

    def large_communities(self) -> list[int]:
        """Flat triples: [g1, d1_1, d1_2, g2, ...]."""
        n = get_lib().lr_route_large_communities(self._ptr, ffi.NULL, 0)
        if n <= 0:
            return []
        out = ffi.new("uint32_t[]", n)
        rc = get_lib().lr_route_large_communities(self._ptr, out, n)
        if rc < 0:
            raise LrError(f"lr_route_large_communities failed (rc={rc}): {last_error()}")
        return list(out)

    def add_ext_community(self, kind: int, subtype: int, global_: int, local: int) -> None:
        rc = get_lib().lr_route_add_ext_community(
            self._ptr, int(kind), int(subtype), int(global_), int(local)
        )
        if rc != 0:
            raise LrError(f"lr_route_add_ext_community failed (rc={rc}): {last_error()}")

    def set_metric(self, value: int) -> None:
        rc = get_lib().lr_route_set_metric(self._ptr, int(value))
        if rc != 0:
            raise LrError(f"lr_route_set_metric failed (rc={rc}): {last_error()}")

    def metric(self) -> int:
        out = ffi.new("uint32_t*")
        rc = get_lib().lr_route_metric(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_metric failed (rc={rc}): {last_error()}")
        return int(out[0])

    def set_tag(self, tag: int | None) -> None:
        rc = get_lib().lr_route_set_tag(self._ptr, 0 if tag is None else 1, int(tag or 0))
        if rc != 0:
            raise LrError(f"lr_route_set_tag failed (rc={rc}): {last_error()}")


class PrefixList:
    """An owned prefix-list handle (FRR ge/le semantics, first-match
    evaluation, implicit deny)."""

    def __init__(self):
        ptr = get_lib().lr_prefix_list_new()
        if ptr == ffi.NULL:
            raise LrError("lr_prefix_list_new returned NULL")
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None:
            get_lib().lr_prefix_list_free(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def add(self, prefix, ge: int = 0, le: int = 255, permit: bool = True) -> None:
        p = _prefix_spec(prefix)
        rc = get_lib().lr_prefix_list_add(self._ptr, p, int(ge), int(le), 1 if permit else 0)
        if rc != 0:
            raise LrError(f"lr_prefix_list_add failed (rc={rc}): {last_error()}")

    def match(self, prefix) -> bool:
        p = _prefix_spec(prefix)
        rc = get_lib().lr_prefix_list_match(self._ptr, p)
        if rc < 0:
            raise LrError(f"lr_prefix_list_match failed (rc={rc}): {last_error()}")
        return rc == 1


class Match:
    """One route-map match condition."""

    def __init__(self, kind: int, list_id: int = 0, protocol: int = 0):
        self.kind = kind
        self.list_id = list_id
        self.protocol = protocol




class Set:
    """One route-map set action."""

    def __init__(self, kind: int, value: int = 0, value2: int = 0,
                 addr: bytes | None = None, is_ipv6: bool = False):
        self.kind = kind
        self.value = value
        self.value2 = value2
        self.addr = addr or b""
        self.is_ipv6 = is_ipv6

class RouteMap:
    """An owned route-map handle: ordered entries, first match wins
    (FRR route-map semantics)."""

    def __init__(self):
        ptr = get_lib().lr_route_map_new()
        if ptr == ffi.NULL:
            raise LrError("lr_route_map_new returned NULL")
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None:
            get_lib().lr_route_map_free(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def add_entry(self, matches: list[Match], sets: list[Set], verdict: int) -> None:
        cm = ffi.new("lr_match_t[]", len(matches)) if matches else ffi.NULL
        for i, m in enumerate(matches):
            cm[i].kind = m.kind
            cm[i].list_id = m.list_id
            cm[i].protocol = m.protocol
        cs = ffi.new("lr_set_t[]", len(sets)) if sets else ffi.NULL
        for i, s_ in enumerate(sets):
            cs[i].kind = s_.kind
            cs[i].is_ipv6 = 1 if s_.is_ipv6 else 0
            if s_.addr:
                cs[i].addr[0:len(s_.addr)] = list(s_.addr)
            cs[i].value = s_.value
            cs[i].value2 = s_.value2
        rc = get_lib().lr_route_map_add_entry(
            self._ptr,
            cm, len(matches),
            cs, len(sets),
            int(verdict),
        )
        if rc != 0:
            raise LrError(f"lr_route_map_add_entry failed (rc={rc}): {last_error()}")

    def evaluate(self, route: Route, resolver: "Resolver | None" = None) -> int:
        out = ffi.new("int32_t*")
        rp = resolver._ptr if resolver is not None else ffi.NULL
        rc = get_lib().lr_route_map_evaluate(self._ptr, route._ptr, rp, out)
        if rc != 0:
            raise LrError(f"lr_route_map_evaluate failed (rc={rc}): {last_error()}")
        return int(out[0])


class AsPathFilter:
    """One FRR-dialect AS-path access-list line."""

    def __init__(self, pattern: str, permit: bool):
        self.pattern = pattern
        self.permit = permit


class CommunityEntry:
    """One standard community-list line."""

    def __init__(self, communities: list[int], permit: bool):
        self.communities = communities
        self.permit = permit


class Resolver:
    """An owned policy resolver (a ``PolicySet``): the named registry
    of prefix-lists / AS-path filters / community lists that route-map
    match conditions resolve against."""

    def __init__(self):
        ptr = get_lib().lr_resolver_new()
        if ptr == ffi.NULL:
            raise LrError("lr_resolver_new returned NULL")
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None:
            get_lib().lr_resolver_free(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def add_prefix_list(self, name: str, prefix_list: PrefixList) -> int:
        out = get_lib().lr_resolver_add_prefix_list(self._ptr, name.encode(), prefix_list._ptr)
        if out < 0:
            raise LrError(f"lr_resolver_add_prefix_list failed (rc={out}): {last_error()}")
        return int(out)

    def add_as_path_list(self, name: str, filters: list[AsPathFilter]) -> int:
        # The patterns are borrowed only for the duration of the call,
        # but keep the cdata objects referenced until it returns.
        keepalive = [ffi.new("char[]", f.pattern.encode()) for f in filters]
        cf = ffi.new("lr_as_path_filter_t[]", len(filters)) if filters else ffi.NULL
        for i, f in enumerate(filters):
            cf[i].pattern = keepalive[i]
            cf[i].permit = 1 if f.permit else 0
        rc = get_lib().lr_resolver_add_as_path_list(
            self._ptr, name.encode(), cf, len(filters))
        if rc < 0:
            raise LrError(f"lr_resolver_add_as_path_list failed (rc={rc}): {last_error()}")
        return int(rc)

    def add_community_list(self, name: str, entries: list[CommunityEntry]) -> int:
        backing = [
            ffi.new("uint64_t[]", [int(v) for v in e.communities]) if e.communities else ffi.NULL
            for e in entries
        ]
        ce = ffi.new("lr_community_entry_t[]", len(entries)) if entries else ffi.NULL
        for i, e in enumerate(entries):
            ce[i].communities = backing[i]
            ce[i].count = len(e.communities)
            ce[i].permit = 1 if e.permit else 0
        rc = get_lib().lr_resolver_add_community_list(
            self._ptr, name.encode(), ce, len(entries))
        if rc < 0:
            raise LrError(f"lr_resolver_add_community_list failed (rc={rc}): {last_error()}")
        return int(rc)


# ===== D5.2 — Filter DSL: compile / evaluate / free =====

FILTER_ACCEPT = 0
FILTER_REJECT = 1
FILTER_FALLTHROUGH = 2

__all__ += ["CompiledFilter", "compile_filter", "FILTER_ACCEPT", "FILTER_REJECT", "FILTER_FALLTHROUGH"]


class CompiledFilter:
    """An owned compiled filter (the D3.7 stack VM — the same hot
    path the daemon executes per route)."""

    def __init__(self, name: str, body: str):
        ptr = get_lib().lr_filter_compile(name.encode(), body.encode())
        if ptr == ffi.NULL:
            raise LrError(f"lr_filter_compile failed: {last_error()}")
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None:
            get_lib().lr_filter_free(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def name(self) -> str:
        need = get_lib().lr_filter_name(self._ptr, ffi.NULL, 0)
        if need < 0:
            raise LrError(f"lr_filter_name failed (rc={need}): {last_error()}")
        buf = ffi.new("uint8_t[]", need)
        rc = get_lib().lr_filter_name(self._ptr, buf, need)
        if rc < 0:
            raise LrError(f"lr_filter_name failed (rc={rc}): {last_error()}")
        return bytes(buf[0:need - 1]).decode()

    def evaluate(self, route: Route) -> tuple[int, str]:
        """Run the filter against ``route`` with the built-in
        route-backed context (attribute reads/writes hit the route;
        ``roa.state`` is not-found). Returns ``(verdict, reason)``
        where ``verdict`` is ``FILTER_ACCEPT`` / ``FILTER_REJECT`` /
        ``FILTER_FALLTHROUGH`` and ``reason`` is the optional
        ``reject with`` payload."""
        verdict = ffi.new("int32_t*")
        reason = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_filter_evaluate(self._ptr, route._ptr, ffi.NULL, verdict, reason)
        if rc != 0:
            raise LrError(f"lr_filter_evaluate failed (rc={rc}): {last_error()}")
        out = ""
        if reason.ptr:
            n = int(get_lib().lr_bytes_len(reason))
            raw = bytes(ffi.buffer(get_lib().lr_bytes_ptr(reason), n))
            get_lib().lr_bytes_free(reason)
            out = raw.rstrip(b"\x00").decode()
        return int(verdict[0]), out


def compile_filter(name: str, body: str) -> CompiledFilter:
    """Compile a BIRD-like filter body. Raises :class:`LrError` with
    the 1-indexed line/column diagnostic on a parse error."""
    return CompiledFilter(name, body)
