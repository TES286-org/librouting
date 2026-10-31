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

    def next_hop(self) -> bytes | None:
        """Read the route's next hop (RFC 4271 §5.1.3). Returns the
        4- or 16-byte address, or ``None`` when the attribute is
        absent. The address length signals the family: 4 bytes for
        IPv4, 16 bytes for IPv6."""
        buf = ffi.new("uint8_t[16]")
        is_v6 = ffi.new("int32_t*")
        rc = get_lib().lr_route_next_hop(self._ptr, buf, is_v6)
        if rc == 1:
            return None
        if rc != 0:
            raise LrError(f"lr_route_next_hop failed (rc={rc}): {last_error()}")
        n = 16 if is_v6[0] else 4
        return bytes(buf[0:n])

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

    def origin(self) -> int | None:
        """Read the BGP ORIGIN (RFC 4271 §5.1.1): 0 IGP, 1 EGP, 2
        INCOMPLETE. Returns ``None`` when the attribute is absent."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_origin(self._ptr, out)
        if rc == 1:
            return None
        if rc != 0:
            raise LrError(f"lr_route_origin failed (rc={rc}): {last_error()}")
        return int(out[0])

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

    def set_large_communities(self, triples: list[int]) -> None:
        """Replace the LARGE_COMMUNITIES attribute (RFC 8092) from a
        flat ``[g1, d1_1, d1_2, g2, d2_1, d2_2, ...]`` list. An empty
        list drops the attribute. ``len(triples)`` must be a multiple
        of three; each triple is ``(global_admin, local_data1,
        local_data2)``."""
        if len(triples) % 3 != 0:
            raise LrError("large communities triples must come in groups of three")
        arr = ffi.new("uint32_t[]", [int(v) for v in triples]) if triples else ffi.NULL
        # The C ABI takes the entry count, not the u32 count.
        rc = get_lib().lr_route_set_large_communities(self._ptr, arr, len(triples) // 3)
        if rc != 0:
            raise LrError(f"lr_route_set_large_communities failed (rc={rc}): {last_error()}")

    def add_ext_community(self, kind: int, subtype: int, global_: int, local: int) -> None:
        rc = get_lib().lr_route_add_ext_community(
            self._ptr, int(kind), int(subtype), int(global_), int(local)
        )
        if rc != 0:
            raise LrError(f"lr_route_add_ext_community failed (rc={rc}): {last_error()}")

    def ext_communities(self) -> list[tuple[int, int, int, int]]:
        """Read the EXTENDED_COMMUNITIES attribute (RFC 4360). Each
        element is a ``(kind, subtype, global, local)`` tuple mirroring
        ``lr_ext_comm_t``."""
        n = get_lib().lr_route_ext_communities(self._ptr, ffi.NULL, 0)
        if n <= 0:
            return []
        out = ffi.new("struct lr_ext_comm_t[]", n)
        rc = get_lib().lr_route_ext_communities(self._ptr, out, n)
        if rc < 0:
            raise LrError(f"lr_route_ext_communities failed (rc={rc}): {last_error()}")
        # `global` is a Python keyword; go through getattr for the field.
        return [(int(e.kind), int(e.subtype), int(getattr(e, "global")), int(e.local)) for e in out]

    def set_ext_communities(self, items: list[tuple[int, int, int, int]]) -> None:
        """Replace the EXTENDED_COMMUNITIES attribute (RFC 4360) from a
        list of ``(kind, subtype, global, local)`` tuples. An empty list
        drops the attribute."""
        arr = ffi.new("struct lr_ext_comm_t[]", len(items)) if items else ffi.NULL
        for i, item in enumerate(items):
            kind, subtype, global_, local = item
            arr[i].kind = int(kind)
            arr[i].subtype = int(subtype)
            setattr(arr[i], "global", int(global_))
            arr[i].local = int(local)
        rc = get_lib().lr_route_set_ext_communities(self._ptr, arr, len(items))
        if rc != 0:
            raise LrError(f"lr_route_set_ext_communities failed (rc={rc}): {last_error()}")

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

    def tag(self) -> int | None:
        """Read the operator route tag. Returns ``None`` when the tag is
        absent (the route was created without calling ``set_tag``)."""
        out = ffi.new("uint32_t*")
        rc = get_lib().lr_route_tag(self._ptr, out)
        if rc == 1:
            return None
        if rc != 0:
            raise LrError(f"lr_route_tag failed (rc={rc}): {last_error()}")
        return int(out[0])

    # ---- Per-route BGP / Babel / OSPF attribute readers (RFC 4271
    # §5.1, RFC 4456 §8, RFC 6514 §5, RFC 7311, RFC 9231 §4, RFC 8966
    # §3.2/§4.6.9, RFC 2328 §16 / RFC 5340 §4.1). Mirrors the
    # `lr_route_*` C ABI surface in crates/lr-ffi/src/route_attrs.rs. ----

    def atomic_aggregate(self) -> bool:
        """True when the route carries an ATOMIC_AGGREGATE (RFC 4271
        §5.1.6)."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_atomic_aggregate(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_atomic_aggregate failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def originator_id(self) -> bytes | None:
        """The ORIGINATOR_ID (RFC 4456 §8) — 4-byte IPv4. Returns
        ``None`` when the attribute is absent."""
        addr = ffi.new("uint8_t[4]")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_originator_id(self._ptr, addr, present)
        if rc != 0:
            raise LrError(f"lr_route_originator_id failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return bytes(addr[0:4])

    def has_cluster_list(self) -> bool:
        """True when the route carries a CLUSTER_LIST (RFC 4456 §8)."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_cluster_list(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_cluster_list failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def cluster_list(self) -> list[bytes]:
        """The CLUSTER_LIST (RFC 4456 §8) — flat 4-byte IPv4
        Cluster-IDs."""
        n = ffi.new("uintptr_t*")
        rc = get_lib().lr_route_cluster_list_len(self._ptr, n)
        if rc != 0:
            raise LrError(f"lr_route_cluster_list_len failed (rc={rc}): {last_error()}")
        out: list[bytes] = []
        for i in range(int(n[0])):
            addr = ffi.new("uint8_t[4]")
            rc = get_lib().lr_route_cluster_list_at(self._ptr, i, addr)
            if rc != 0:
                raise LrError(f"lr_route_cluster_list_at failed (rc={rc}): {last_error()}")
            out.append(bytes(addr[0:4]))
        return out

    def has_otc(self) -> bool:
        """True when the route carries an OTC attribute (RFC 9231 §4)."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_otc(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_otc failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def otc(self) -> int | None:
        """The OTC value (RFC 9231 §4). Returns ``None`` when absent."""
        out = ffi.new("uint32_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_otc(self._ptr, out, present)
        if rc != 0:
            raise LrError(f"lr_route_otc failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(out[0])

    def has_aigp(self) -> bool:
        """True when the route carries an AIGP attribute (RFC 7311)."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_aigp(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_aigp failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def aigp(self) -> int | None:
        """The AIGP value (RFC 7311). Returns ``None`` when absent."""
        out = ffi.new("uint64_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_aigp(self._ptr, out, present)
        if rc != 0:
            raise LrError(f"lr_route_aigp failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(out[0])

    def has_aggregator(self) -> bool:
        """True when the route carries an AGGREGATOR (RFC 4271 §5.1.7 /
        RFC 6793 §4)."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_aggregator(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_aggregator failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def aggregator_asn(self) -> int | None:
        """The AGGREGATOR AS number (RFC 4271 §5.1.7 / RFC 6793 §4).
        Returns ``None`` when absent."""
        out = ffi.new("uint32_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_aggregator_asn(self._ptr, out, present)
        if rc != 0:
            raise LrError(f"lr_route_aggregator_asn failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(out[0])

    def aggregator_speaker(self) -> bytes | None:
        """The AGGREGATOR speaker IPv4 address (RFC 4271 §5.1.7 /
        RFC 6793 §4). 4 bytes. Returns ``None`` when absent."""
        addr = ffi.new("uint8_t[4]")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_aggregator_speaker(self._ptr, addr, present)
        if rc != 0:
            raise LrError(f"lr_route_aggregator_speaker failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return bytes(addr[0:4])

    def has_pmsi_tunnel(self) -> bool:
        """True when the route carries a PMSI_TUNNEL attribute
        (RFC 6514 §5)."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_pmsi_tunnel(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_pmsi_tunnel failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def pmsi_tunnel_flags(self) -> int | None:
        """The PMSI_TUNNEL flags (RFC 6514 §5). Returns ``None`` when
        absent."""
        flags = ffi.new("uint8_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_pmsi_tunnel_flags(self._ptr, flags, present)
        if rc != 0:
            raise LrError(f"lr_route_pmsi_tunnel_flags failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(flags[0])

    def as_sequence(self) -> list[int]:
        """The flat AS_SEQUENCE (RFC 4271 §5.1.2) — sets flattened in
        order."""
        n = ffi.new("uintptr_t*")
        rc = get_lib().lr_route_as_sequence_len(self._ptr, n)
        if rc != 0:
            raise LrError(f"lr_route_as_sequence_len failed (rc={rc}): {last_error()}")
        out: list[int] = []
        for i in range(int(n[0])):
            v = ffi.new("uint32_t*")
            rc = get_lib().lr_route_as_sequence_at(self._ptr, i, v)
            if rc != 0:
                raise LrError(f"lr_route_as_sequence_at failed (rc={rc}): {last_error()}")
            out.append(int(v[0]))
        return out

    def set_as_sequence(self, asns: list[int]) -> None:
        """Replace the route's AS_PATH with a flat AS_SEQUENCE (RFC 4271
        §5.1.2). The previous AS_PATH is overwritten."""
        arr = ffi.new("uint32_t[]", [int(a) for a in asns]) if asns else ffi.NULL
        rc = get_lib().lr_route_set_as_sequence(self._ptr, arr, len(asns))
        if rc != 0:
            raise LrError(f"lr_route_set_as_sequence failed (rc={rc}): {last_error()}")

    def prepend_as(self, asn: int) -> None:
        """Prepend ``asn`` to the route's AS_PATH (RFC 4271 §5.1.2 — the
        standard eBGP AS_PATH prepend action)."""
        rc = get_lib().lr_route_prepend_as(self._ptr, int(asn))
        if rc != 0:
            raise LrError(f"lr_route_prepend_as failed (rc={rc}): {last_error()}")

    def remove_community(self, asn: int, value: int) -> None:
        """Remove ``community`` from the COMMUNITIES attribute (RFC 1997
        §4). No-op when the route carries no COMMUNITIES or the
        community is not present."""
        rc = get_lib().lr_route_remove_community(self._ptr, int(asn), int(value))
        if rc != 0:
            raise LrError(f"lr_route_remove_community failed (rc={rc}): {last_error()}")

    def has_babel_metric(self) -> bool:
        """True when the route carries a Babel metric attribute (RFC 8966
        §3.2)."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_babel_metric(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_babel_metric failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def babel_metric(self) -> int | None:
        """The Babel primary metric (RFC 8966 §3.2 + §3.4.3). Returns
        ``None`` when absent."""
        out = ffi.new("uint32_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_babel_metric(self._ptr, out, present)
        if rc != 0:
            raise LrError(f"lr_route_babel_metric failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(out[0])

    def has_babel_seqno(self) -> bool:
        """True when the route carries a Babel sequence number
        attribute."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_babel_seqno(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_babel_seqno failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def babel_seqno(self) -> int | None:
        """The Babel sequence number (RFC 8966 §3.2 + §4.6.9). Returns
        ``None`` when absent."""
        out = ffi.new("uint16_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_babel_seqno(self._ptr, out, present)
        if rc != 0:
            raise LrError(f"lr_route_babel_seqno failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(out[0])

    def has_babel_router_id(self) -> bool:
        """True when the route carries a Babel router-id attribute."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_babel_router_id(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_babel_router_id failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def babel_router_id(self) -> bytes | None:
        """The Babel router-id (RFC 8966 §3.2 + §4.6.9), 8 bytes
        big-endian. Returns ``None`` when absent."""
        rid = ffi.new("uint8_t[8]")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_babel_router_id(self._ptr, rid, present)
        if rc != 0:
            raise LrError(f"lr_route_babel_router_id failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return bytes(rid[0:8])

    def has_ospf_metric1(self) -> bool:
        """True when the route carries an OSPF metric1 attribute (RFC 2328
        §16)."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_ospf_metric1(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_ospf_metric1 failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def ospf_metric1(self) -> int | None:
        """The OSPF primary metric (RFC 2328 §16 / RFC 5340 §4.1).
        Returns ``None`` when absent."""
        out = ffi.new("uint32_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_ospf_metric1(self._ptr, out, present)
        if rc != 0:
            raise LrError(f"lr_route_ospf_metric1 failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(out[0])

    def has_ospf_metric2(self) -> bool:
        """True when the route carries an OSPF metric2 attribute."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_ospf_metric2(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_ospf_metric2 failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def ospf_metric2(self) -> int | None:
        """The OSPF type-2 external metric (RFC 2328 §16.4 / RFC 5340
        §4.8.5). Returns ``None`` when absent."""
        out = ffi.new("uint32_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_ospf_metric2(self._ptr, out, present)
        if rc != 0:
            raise LrError(f"lr_route_ospf_metric2 failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(out[0])

    def has_ospf_tag(self) -> bool:
        """True when the route carries an OSPF tag attribute."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_ospf_tag(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_ospf_tag failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def ospf_tag(self) -> int | None:
        """The OSPF external route tag (RFC 2328 §A.4.5 / RFC 3101 §2.3
        / RFC 5340 §A.4.7 T bit / RFC 8362 External-Prefix sub-TLV 3).
        Returns ``None`` when absent."""
        out = ffi.new("uint32_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_ospf_tag(self._ptr, out, present)
        if rc != 0:
            raise LrError(f"lr_route_ospf_tag failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(out[0])

    def has_ospf_router_id(self) -> bool:
        """True when the route carries an OSPF router-id attribute."""
        out = ffi.new("uint8_t*")
        rc = get_lib().lr_route_has_ospf_router_id(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_route_has_ospf_router_id failed (rc={rc}): {last_error()}")
        return bool(out[0])

    def ospf_router_id(self) -> int | None:
        """The OSPF advertising router (RFC 2328 §A.4 / RFC 5340 §A.4).
        Returns ``None`` when absent."""
        out = ffi.new("uint32_t*")
        present = ffi.new("uint8_t*")
        rc = get_lib().lr_route_ospf_router_id(self._ptr, out, present)
        if rc != 0:
            raise LrError(f"lr_route_ospf_router_id failed (rc={rc}): {last_error()}")
        if not present[0]:
            return None
        return int(out[0])


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


class FilterContext:
    """An owned ``lr_filter_context_t`` callback table.

    Every field may be ``None`` (the default — built-in route-backed
    behaviour). Setting any field to a Python callable wires that
    callable into the C callback table so the filter VM calls back
    into Python instead of reading the route directly. The C++ RAII
    wrapper exposes the same table as a plain struct; this Python
    class adds the lifetime management cffi callbacks require (the
    ``@ffi.callback`` trampolines must be kept referenced for the
    lifetime of the context, otherwise cffi may free them while the
    table still points at them).

    Currently the most useful hook is :meth:`set_roa_state`, which
    mirrors the C harness's ``roa_always_invalid`` example and the
    C++ harness's ``roa_state`` lambda.
    """

    def __init__(self, user_data: object | None = None):
        self._table = ffi.new("lr_filter_context_t*")
        # Zero-init every function pointer so an unset field falls
        # through to the built-in route-backed behaviour.
        self._table.bgp_local_pref = ffi.NULL
        self._table.bgp_med = ffi.NULL
        self._table.bgp_next_hop = ffi.NULL
        self._table.bgp_as_path = ffi.NULL
        self._table.bgp_communities = ffi.NULL
        self._table.bgp_large_communities = ffi.NULL
        self._table.bgp_ext_communities = ffi.NULL
        self._table.bgp_origin = ffi.NULL
        self._table.roa_state = ffi.NULL
        self._table.set_bgp_local_pref = ffi.NULL
        self._table.set_bgp_med = ffi.NULL
        self._table.set_bgp_next_hop = ffi.NULL
        self._table.bgp_as_path_prepend = ffi.NULL
        self._table.bgp_communities_add = ffi.NULL
        self._table.set_bgp_communities = ffi.NULL
        self._table.set_bgp_as_path = ffi.NULL
        self._table.set_bgp_large_communities = ffi.NULL
        self._table.set_bgp_ext_communities = ffi.NULL
        # Hold strong references to every installed trampoline so cffi
        # does not GC them while the C side still holds the pointer.
        self._callbacks: dict[str, object] = {}
        # The user_data slot is a void* in C; Python keeps the real
        # object alive on this side and hands a sentinel pointer to
        # the C side. Callers that need to identify their object can
        # stash it on the FilterContext instead.
        self._user_obj = user_data
        self._table.user_data = ffi.NULL

    @property
    def _as_cptr(self):
        """Pass-through for callers that need the raw ``const
        lr_filter_context_t*`` (the C ABI takes it by pointer)."""
        return self._table

    def set_roa_state(self, fn) -> None:
        """Install a ``roa_state`` callback (RFC 6811). ``fn`` takes
        the route handle and returns one of the ``LR_ROA_VALID`` /
        ``LR_ROA_NOT_FOUND`` / ``LR_ROA_INVALID`` constants."""
        trampoline = ffi.callback("uint8_t(void *user_data, lr_route_t route)",
                                  lambda _ud, _r: int(fn(_r)))
        self._table.roa_state = trampoline
        self._callbacks["roa_state"] = trampoline

    def set_bgp_local_pref(self, fn) -> None:
        """Install a ``bgp_local_pref`` reader. ``fn`` takes the route
        handle and returns ``int | None`` (``None`` means absent)."""
        def trampoline(_ud, _r, out):
            v = fn(_r)
            if v is None:
                return 0
            out[0] = int(v) & 0xffffffff
            return 1
        cb = ffi.callback("int32_t(void *user_data, lr_route_t route, uint32_t *out)",
                          trampoline)
        self._table.bgp_local_pref = cb
        self._callbacks["bgp_local_pref"] = cb

    def set_bgp_med(self, fn) -> None:
        """Install a ``bgp_med`` reader. ``fn`` takes the route handle
        and returns ``int | None``."""
        def trampoline(_ud, _r, out):
            v = fn(_r)
            if v is None:
                return 0
            out[0] = int(v) & 0xffffffff
            return 1
        cb = ffi.callback("int32_t(void *user_data, lr_route_t route, uint32_t *out)",
                          trampoline)
        self._table.bgp_med = cb
        self._callbacks["bgp_med"] = cb

    def set_bgp_origin(self, fn) -> None:
        """Install a ``bgp_origin`` reader. ``fn`` takes the route
        handle and returns ``int | None`` (0/1/2 per RFC 4271 §5.1.1)."""
        def trampoline(_ud, _r, out):
            v = fn(_r)
            if v is None:
                return 0
            out[0] = int(v) & 0xff
            return 1
        cb = ffi.callback("int32_t(void *user_data, lr_route_t route, uint8_t *out)",
                          trampoline)
        self._table.bgp_origin = cb
        self._callbacks["bgp_origin"] = cb


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

    def evaluate(self, route: Route,
                 context: FilterContext | None = None) -> tuple[int, str]:
        """Run the filter against ``route``. With no ``context`` the
        built-in route-backed context is used (attribute reads/writes
        hit the route directly; ``roa.state`` is not-found). Pass a
        :class:`FilterContext` to override individual attribute
        readers — most commonly ``roa_state`` for RFC 6811 testing.

        Returns ``(verdict, reason)`` where ``verdict`` is
        ``FILTER_ACCEPT`` / ``FILTER_REJECT`` / ``FILTER_FALLTHROUGH``
        and ``reason`` is the optional ``reject with`` payload."""
        verdict = ffi.new("int32_t*")
        reason = ffi.new("lr_bytes_t*")
        ctx = context._as_cptr if context is not None else ffi.NULL
        rc = get_lib().lr_filter_evaluate(self._ptr, route._ptr, ctx, verdict, reason)
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
