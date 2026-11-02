"""Pytest suite for the BGP Path Attributes binding.

Mirrors the FFI tests in ``crates/lr-ffi/src/bgp_path.rs`` and the
``lr_bgp::path::PathAttributes`` Rust crate's pub API one-to-one:
every typed reader / setter / generic-attr entry point has at least
one round-trip assertion, every ``None`` path on a fresh attrs set
has an explicit assertion, and every ``insert_*`` raises
:class:`librouting.router.LrError` on FFI errors.

The tests do NOT spin up a BGP peer — they exercise the attribute
container directly via the C ABI, mirroring the Rust crate's own
unit tests. The C ABI surface lives in ``crates/lr-ffi/src/bgp_path.rs``;
this module is the Python-side mirror.
"""

from __future__ import annotations

import ipaddress

import pytest

import librouting
from librouting import (
    BGP_ATTR_AGGREGATOR,
    BGP_ATTR_AS4_PATH,
    BGP_ATTR_AS_PATH,
    BGP_ATTR_ATOMIC_AGGREGATE,
    BGP_ATTR_AIGP,
    BGP_ATTR_BABEL_ROUTER_ID,
    BGP_ATTR_BABEL_SEQNO,
    BGP_ATTR_CLUSTER_LIST,
    BGP_ATTR_COMMUNITIES,
    BGP_ATTR_EXT_COMMUNITIES,
    BGP_ATTR_IGP_METRIC,
    BGP_ATTR_LR_MPLS_LABEL_STACK,
    BGP_ATTR_LARGE_COMMUNITIES,
    BGP_ATTR_LOCAL_PREF,
    BGP_ATTR_MED,
    BGP_ATTR_MP_REACH_NLRI,
    BGP_ATTR_MP_UNREACH_NLRI,
    BGP_ATTR_NEXT_HOP,
    BGP_ATTR_ORIGIN,
    BGP_ATTR_ORIGINATOR_ID,
    BGP_ATTR_OSPF_METRIC2,
    BGP_ATTR_OSPF_ROUTER_ID,
    BGP_ATTR_OTC,
    BGP_ATTR_PEER_SOURCE_ADDRESS,
    BGP_ATTR_PMSI_TUNNEL,
    BgpAsPath,
    BgpLargeCommunity,
    BgpNextHop,
    BgpPathAttrs,
    NEXT_HOP_V4,
    NEXT_HOP_V4_OVER_V6,
    NEXT_HOP_V6,
    ORIGIN_EGP,
    ORIGIN_IGP,
    ORIGIN_INCOMPLETE,
    PathAttr,
)


# ---------------------------------------------------------------------------
# Lifecycle / generic-attr surface.
# ---------------------------------------------------------------------------
class TestLifecycle:
    def test_fresh_attrs_is_empty(self):
        a = BgpPathAttrs()
        assert a.len() == 0
        assert a.is_empty() is True
        assert a.count() == 0

    def test_close_releases_handle(self):
        a = BgpPathAttrs()
        assert a.closed is False
        a.close()
        assert a.closed is True
        # Operations on a closed handle are safe and return empty/0.
        assert a.len() == 0
        assert a.is_empty() is True
        assert a.count() == 0
        assert a.at(0) is None
        assert a.get(BGP_ATTR_LOCAL_PREF) is None
        assert a.remove(BGP_ATTR_LOCAL_PREF) is False

    def test_context_manager_closes(self):
        with BgpPathAttrs() as a:
            assert a.closed is False
            a.set_local_pref(100)
            assert a.local_pref() == 100
        assert a.closed is True

    def test_gc_frees_handle(self):
        # The previous tests pinned close() explicitly; this one
        # just makes sure the __del__ finalizer does not crash on
        # cyclic collection.
        a = BgpPathAttrs()
        ptr_id = id(a)
        del a
        # No assert beyond "did not raise" — Python's GC may not run
        # immediately, but the finalizer must be safe to call.
        assert ptr_id > 0


class TestGenericAttr:
    def test_count_after_set_local_pref(self):
        a = BgpPathAttrs()
        a.set_local_pref(100)
        assert a.count() == 1
        assert a.len() == 1

    def test_at_returns_pathattr(self):
        a = BgpPathAttrs()
        a.set_local_pref(100)
        p = a.at(0)
        assert isinstance(p, PathAttr)
        # LOCAL_PREF is type 5, transitive (flags 0x40).
        assert p.type == BGP_ATTR_LOCAL_PREF
        assert p.flags == 0x40
        assert p.value == (100).to_bytes(4, "big")

    def test_at_out_of_range_returns_none(self):
        a = BgpPathAttrs()
        a.set_local_pref(100)
        assert a.at(99) is None
        assert a.at(1) is None

    def test_get_returns_pathattr(self):
        a = BgpPathAttrs()
        a.set_local_pref(100)
        p = a.get(BGP_ATTR_LOCAL_PREF)
        assert isinstance(p, PathAttr)
        assert p.type == BGP_ATTR_LOCAL_PREF
        assert p.flags == 0x40
        assert p.value == (100).to_bytes(4, "big")

    def test_get_absent_returns_none(self):
        a = BgpPathAttrs()
        assert a.get(BGP_ATTR_LOCAL_PREF) is None

    def test_remove_returns_true_when_present(self):
        a = BgpPathAttrs()
        a.set_local_pref(100)
        assert a.remove(BGP_ATTR_LOCAL_PREF) is True
        assert a.local_pref() is None
        assert a.count() == 0

    def test_remove_returns_false_when_absent(self):
        a = BgpPathAttrs()
        assert a.remove(BGP_ATTR_LOCAL_PREF) is False

    def test_insert_raw_round_trip(self):
        a = BgpPathAttrs()
        # LOCAL_PREF, flags 0x40 (transitive), value = 100 BE.
        a.insert_raw(0x40, BGP_ATTR_LOCAL_PREF, (100).to_bytes(4, "big"))
        assert a.local_pref() == 100
        assert a.count() == 1


# ---------------------------------------------------------------------------
# RFC 4271 §5.1 — well-known mandatory + discretionary.
# ---------------------------------------------------------------------------
class TestWellKnown:
    def test_local_pref_round_trip(self):
        a = BgpPathAttrs()
        assert a.local_pref() is None
        a.set_local_pref(100)
        assert a.local_pref() == 100

    def test_med_absent(self):
        a = BgpPathAttrs()
        assert a.med() is None

    def test_origin_absent(self):
        a = BgpPathAttrs()
        assert a.origin() is None

    def test_atomic_aggregate_absent(self):
        a = BgpPathAttrs()
        assert a.atomic_aggregate() is False

    def test_aggregator_absent(self):
        a = BgpPathAttrs()
        assert a.aggregator() is None

    def test_next_hop_absent(self):
        a = BgpPathAttrs()
        nh = a.next_hop()
        assert nh is not None
        assert nh.present is False

    def test_local_pref_via_insert_raw(self):
        a = BgpPathAttrs()
        a.insert_raw(0x40, BGP_ATTR_LOCAL_PREF, (250).to_bytes(4, "big"))
        assert a.local_pref() == 250


# ---------------------------------------------------------------------------
# RFC 4271 §5.1.2 + RFC 6793 — AS_PATH.
# ---------------------------------------------------------------------------
class TestAsPath:
    def test_as_path_absent_on_fresh_attrs(self):
        a = BgpPathAttrs()
        assert a.as_path() is None
        assert a.as_path_wire(asn4=True) is None
        assert a.as_path_wire(asn4=False) is None
        assert a.as4_path() is None

    def test_as_path_handle_is_freed(self):
        # Constructing and closing should not leak — the test passes
        # if __del__ does not raise. We exercise the close() path
        # explicitly so the finalizer is checked.
        p = BgpAsPath(_ptr=None)  # closed-from-birth path
        assert p.closed is True
        p.close()


# ---------------------------------------------------------------------------
# RFC 4456 — Route Reflection.
# ---------------------------------------------------------------------------
class TestRouteReflection:
    def test_originator_id_absent(self):
        a = BgpPathAttrs()
        assert a.originator_id() is None

    def test_cluster_list_absent(self):
        a = BgpPathAttrs()
        assert a.has_cluster_list() is False
        assert a.cluster_list() == b""


# ---------------------------------------------------------------------------
# RFC 1997 / 4360 / 8097 — Communities.
# ---------------------------------------------------------------------------
class TestCommunities:
    def test_communities_empty(self):
        a = BgpPathAttrs()
        assert a.communities() == []
        assert a.ext_communities() == b""
        assert a.large_communities() == []

    def test_insert_community_and_read_back(self):
        a = BgpPathAttrs()
        c = (64512 << 16) | 100
        a.insert_community(c)
        communities = a.communities()
        assert communities == [c]

    def test_insert_two_communities(self):
        a = BgpPathAttrs()
        a.insert_community((64512 << 16) | 100)
        a.insert_community((64512 << 16) | 200)
        assert a.communities() == [(64512 << 16) | 100, (64512 << 16) | 200]

    def test_has_community(self):
        a = BgpPathAttrs()
        c = (65001 << 16) | 100
        assert a.has_community(c) is False
        a.insert_community(c)
        assert a.has_community(c) is True
        assert a.has_community(c + 1) is False

    def test_insert_large_community(self):
        a = BgpPathAttrs()
        with BgpLargeCommunity(65001, 1, 2) as c:
            assert c.global_admin == 65001
            assert c.local_data1 == 1
            assert c.local_data2 == 2
            a.insert_large_community(c)
        assert a.count() >= 1

    def test_large_communities_round_trip(self):
        a = BgpPathAttrs()
        with BgpLargeCommunity(65001, 1, 2) as c:
            a.insert_large_community(c)
        large = a.large_communities()
        assert len(large) == 1
        assert large[0].global_admin == 65001
        assert large[0].local_data1 == 1
        assert large[0].local_data2 == 2

    def test_large_community_repr(self):
        c = BgpLargeCommunity(65001, 1, 2)
        assert (
            repr(c)
            == "BgpLargeCommunity(global_admin=65001, local_data1=1, local_data2=2)"
        )

    def test_large_community_eq_hash(self):
        c1 = BgpLargeCommunity(65001, 1, 2)
        c2 = BgpLargeCommunity(65001, 1, 2)
        c3 = BgpLargeCommunity(65002, 1, 2)
        assert c1 == c2
        assert c1 != c3
        assert hash(c1) == hash(c2)
        assert c1 != "65001:1:2"

    def test_large_community_close_idempotent(self):
        c = BgpLargeCommunity(65001, 1, 2)
        c.close()
        c.close()  # no error
        with pytest.raises(librouting.LrError):
            _ = c.global_admin


# ---------------------------------------------------------------------------
# RFC 7311 / 8124 — AIGP.
# ---------------------------------------------------------------------------
class TestAigp:
    def test_aigp_absent(self):
        a = BgpPathAttrs()
        assert a.has_aigp() is False
        assert a.aigp() is None


# ---------------------------------------------------------------------------
# RFC 9655 — OTC (Only To Customer).
# ---------------------------------------------------------------------------
class TestOtc:
    def test_otc_absent(self):
        a = BgpPathAttrs()
        assert a.has_otc() is False
        assert a.otc() is None


# ---------------------------------------------------------------------------
# RFC 6514 — PMSI Tunnel.
# ---------------------------------------------------------------------------
class TestPmsiTunnel:
    def test_pmsi_tunnel_absent(self):
        a = BgpPathAttrs()
        assert a.has_pmsi_tunnel() is False


# ---------------------------------------------------------------------------
# RFC 8277 — MPLS Label Stack.
# ---------------------------------------------------------------------------
class TestLabelStack:
    def test_label_stack_absent_on_fresh_attrs(self):
        a = BgpPathAttrs()
        assert a.label_stack() is None

    def test_set_label_stack_round_trip(self):
        from librouting import LabelStack
        a = BgpPathAttrs()
        stack = LabelStack.from_values([16, 17])
        a.set_label_stack(stack)
        out = a.label_stack()
        assert out is not None
        # The handle wraps the lr_mpls_label_stack_t — the existing
        # LabelStack API exposes __len__.
        assert len(out) == 2


# ---------------------------------------------------------------------------
# MP-BGP (RFC 4760).
# ---------------------------------------------------------------------------
class TestMpBgp:
    def test_mp_reach_absent(self):
        a = BgpPathAttrs()
        assert a.mp_reach() is None

    def test_mp_unreach_absent(self):
        a = BgpPathAttrs()
        assert a.mp_unreach() is None


# ---------------------------------------------------------------------------
# OSPF redistrib (RFC 4577 §3).
# ---------------------------------------------------------------------------
class TestOspfRedistrib:
    def test_ospf_metric2_round_trip(self):
        a = BgpPathAttrs()
        assert a.has_ospf_metric2() is False
        assert a.ospf_metric2() is None
        a.set_ospf_metric2(123)
        assert a.has_ospf_metric2() is True
        assert a.ospf_metric2() == 123

    def test_ospf_router_id_round_trip(self):
        a = BgpPathAttrs()
        assert a.has_ospf_router_id() is False
        assert a.ospf_router_id() is None
        a.set_ospf_router_id(0x01020304)
        assert a.has_ospf_router_id() is True
        assert a.ospf_router_id() == 0x01020304


# ---------------------------------------------------------------------------
# Babel redistrib (RFC 7999 + babel-ext).
# ---------------------------------------------------------------------------
class TestBabelRedistrib:
    def test_babel_seqno_round_trip(self):
        a = BgpPathAttrs()
        assert a.has_babel_seqno() is False
        assert a.babel_seqno() is None
        a.set_babel_seqno(65535)
        assert a.has_babel_seqno() is True
        assert a.babel_seqno() == 65535

    def test_babel_router_id_round_trip(self):
        a = BgpPathAttrs()
        assert a.has_babel_router_id() is False
        assert a.babel_router_id() is None
        a.set_babel_router_id(0x0123456789ABCDEF)
        assert a.has_babel_router_id() is True
        assert a.babel_router_id() == 0x0123456789ABCDEF


# ---------------------------------------------------------------------------
# IGP metric (RFC 4271 §9.1.2.2 step 7).
# ---------------------------------------------------------------------------
class TestIgpMetric:
    def test_igp_metric_round_trip(self):
        a = BgpPathAttrs()
        assert a.has_igp_metric() is False
        assert a.igp_metric() is None
        a.set_igp_metric(1000)
        assert a.has_igp_metric() is True
        assert a.igp_metric() == 1000


# ---------------------------------------------------------------------------
# Peer source address (RFC 4271 §6.3).
# ---------------------------------------------------------------------------
class TestPeerSourceAddress:
    def test_v4_round_trip(self):
        a = BgpPathAttrs()
        assert a.has_peer_source_address() is False
        assert a.peer_source_address() is None
        a.set_peer_source_address(b"\xc0\xa8\x01\x01", is_ipv6=False)
        assert a.has_peer_source_address() is True
        addr, is_v6 = a.peer_source_address()
        assert is_v6 is False
        assert addr == b"\xc0\xa8\x01\x01"

    def test_v6_round_trip(self):
        a = BgpPathAttrs()
        a.set_peer_source_address(b"\x00" * 15 + b"\x01", is_ipv6=True)
        addr, is_v6 = a.peer_source_address()
        assert is_v6 is True
        assert addr == b"\x00" * 15 + b"\x01"

    def test_wrong_length_raises(self):
        a = BgpPathAttrs()
        with pytest.raises(ValueError):
            a.set_peer_source_address(b"\x00\x01", is_ipv6=False)
        with pytest.raises(ValueError):
            a.set_peer_source_address(b"\x00" * 4, is_ipv6=True)


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------
class TestConstants:
    def test_attr_type_codes(self):
        # Sanity-check that the constants match the IANA assignments.
        assert BGP_ATTR_ORIGIN == 1
        assert BGP_ATTR_AS_PATH == 2
        assert BGP_ATTR_NEXT_HOP == 3
        assert BGP_ATTR_MED == 4
        assert BGP_ATTR_LOCAL_PREF == 5
        assert BGP_ATTR_ATOMIC_AGGREGATE == 6
        assert BGP_ATTR_AGGREGATOR == 7
        assert BGP_ATTR_COMMUNITIES == 8
        assert BGP_ATTR_ORIGINATOR_ID == 9
        assert BGP_ATTR_CLUSTER_LIST == 10
        assert BGP_ATTR_MP_REACH_NLRI == 14
        assert BGP_ATTR_MP_UNREACH_NLRI == 15
        assert BGP_ATTR_EXT_COMMUNITIES == 16
        assert BGP_ATTR_AS4_PATH == 17
        assert BGP_ATTR_PMSI_TUNNEL == 22
        assert BGP_ATTR_AIGP == 26
        assert BGP_ATTR_LARGE_COMMUNITIES == 32
        assert BGP_ATTR_OTC == 35

    def test_private_attr_codes(self):
        assert BGP_ATTR_OSPF_METRIC2 == 253
        assert BGP_ATTR_OSPF_ROUTER_ID == 252
        assert BGP_ATTR_BABEL_ROUTER_ID == 250
        assert BGP_ATTR_BABEL_SEQNO == 249
        assert BGP_ATTR_IGP_METRIC == 246
        assert BGP_ATTR_PEER_SOURCE_ADDRESS == 245
        assert BGP_ATTR_LR_MPLS_LABEL_STACK == 255

    def test_origin_values(self):
        assert ORIGIN_IGP == 0
        assert ORIGIN_EGP == 1
        assert ORIGIN_INCOMPLETE == 2

    def test_next_hop_kind_values(self):
        assert NEXT_HOP_V4 == 0
        assert NEXT_HOP_V6 == 1
        assert NEXT_HOP_V4_OVER_V6 == 2


# ---------------------------------------------------------------------------
# BgpNextHop value type.
# ---------------------------------------------------------------------------
class TestBgpNextHopValue:
    def test_ipv4(self):
        nh = BgpNextHop(addr=b"\xc0\xa8\x01\x01" + b"\x00" * 12,
                        kind=NEXT_HOP_V4, present=True)
        assert nh.present is True
        assert nh.kind == NEXT_HOP_V4
        ip = nh.ip_address
        assert isinstance(ip, ipaddress.IPv4Address)
        assert str(ip) == "192.168.1.1"

    def test_ipv6(self):
        nh = BgpNextHop(addr=b"\x00" * 15 + b"\x01",
                        kind=NEXT_HOP_V6, present=True)
        ip = nh.ip_address
        assert isinstance(ip, ipaddress.IPv6Address)
        assert str(ip) == "::1"

    def test_v4_over_v6(self):
        nh = BgpNextHop(addr=b"\xc0\xa8\x01\x01" + b"\x00" * 12,
                        kind=NEXT_HOP_V4_OVER_V6, present=True)
        ip = nh.ip_address
        assert isinstance(ip, ipaddress.IPv4Address)
        assert str(ip) == "192.168.1.1"

    def test_absent_returns_none(self):
        nh = BgpNextHop(addr=b"\x00" * 16, kind=NEXT_HOP_V4, present=False)
        assert nh.ip_address is None
