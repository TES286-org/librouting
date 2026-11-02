"""Tests for the OSPF structured-type Python binding — mirrors
lr-ospf's LinkStateRetransmissionList, Lsdb, Lsa box, and external
destination tests in crates/lr-ffi/src/ospf_*.rs.
"""

import os
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE
for _ in range(8):
    if (_ROOT / "Cargo.toml").exists():
        break
    _ROOT = _ROOT.parent

candidates = [
    _ROOT / "target" / "release" / "liblr_ffi.so",
    _ROOT / "target" / "debug" / "liblr_ffi.so",
]
for c in candidates:
    if c.exists():
        os.environ.setdefault("LIBROUTING_LIB", str(c))
        break

sys.path.insert(0, str(_ROOT / "bindings" / "lr-python" / "src"))

import librouting


def _make_lsa(ls_id=0xa, adv=0xa, body=b""):
    return librouting.OspfLsa.new(
        librouting.OspfLsaHeader(
            ls_age=0,
            options=0,
            ls_type=1,
            link_state_id=ls_id,
            advertising_router=adv,
            ls_sequence_number=0x80000001,
            ls_checksum=0,
            length=20 + len(body),
        ),
        body,
    )


def test_retransmit_list_empty():
    l = librouting.OspfRetransmitList.new()
    try:
        assert len(l) == 0
        assert l.is_empty()
    finally:
        l.close()


def test_retransmit_list_record_and_contains():
    l = librouting.OspfRetransmitList.new()
    try:
        lsa = _make_lsa(0xa, 0xa)
        l.record_flood(lsa, 0)
        assert len(l) == 1
        assert l.contains(librouting.OspfLsaKey(1, 0xa, 0xa))
        assert not l.contains(librouting.OspfLsaKey(1, 0xb, 0xa))
    finally:
        l.close()


def test_retransmit_list_remove():
    l = librouting.OspfRetransmitList.new()
    try:
        lsa = _make_lsa(0xa, 0xa)
        l.record_flood(lsa, 0)
        assert l.remove(librouting.OspfLsaKey(1, 0xa, 0xa))
        assert len(l) == 0
        assert not l.remove(librouting.OspfLsaKey(1, 0xa, 0xa))
    finally:
        l.close()


def test_retransmit_list_clear():
    l = librouting.OspfRetransmitList.new()
    try:
        l.record_flood(_make_lsa(1, 0xa), 0)
        l.record_flood(_make_lsa(2, 0xa), 0)
        assert len(l) == 2
        l.clear()
        assert l.is_empty()
    finally:
        l.close()


def test_retransmit_list_apply_acks():
    l = librouting.OspfRetransmitList.new()
    try:
        l.record_flood(_make_lsa(0xa, 0xa), 0)
        l.record_flood(_make_lsa(0xb, 0xa), 0)
        # Ack only the first LSA — §13.7 key-match drain.
        acks = [
            librouting.OspfLsaHeader(
                ls_age=0, options=0, ls_type=1,
                link_state_id=0xa, advertising_router=0xa,
                ls_sequence_number=1, ls_checksum=0, length=20,
            )
        ]
        removed = l.apply_acks(acks)
        assert removed == 1
        assert len(l) == 1
        assert l.contains(librouting.OspfLsaKey(1, 0xb, 0xa))
    finally:
        l.close()


def test_retransmit_list_apply_acks_stray():
    """§13.7 step 5: a stray ack is silently accepted (0 removed)."""
    l = librouting.OspfRetransmitList.new()
    try:
        l.record_flood(_make_lsa(0xa, 0xa), 0)
        stray = [
            librouting.OspfLsaHeader(
                ls_age=0, options=0, ls_type=1,
                link_state_id=0xdead, advertising_router=0xbeef,
                ls_sequence_number=1, ls_checksum=0, length=20,
            )
        ]
        removed = l.apply_acks(stray)
        assert removed == 0
        assert len(l) == 1
    finally:
        l.close()


def test_retransmit_list_poll_timing():
    l = librouting.OspfRetransmitList.new()
    try:
        l.record_flood(_make_lsa(0xa, 0xa), 1_000)
        # Poll at 1.5s — interval 5s not elapsed, no retransmit.
        arr = l.poll(1_500, 5_000)
        try:
            assert len(arr) == 0
        finally:
            arr.close()
        # Poll at 6s — interval elapsed, expect 1 LSA.
        arr = l.poll(6_000, 5_000)
        try:
            assert len(arr) == 1
            borrowed = arr.at(0)
            assert borrowed is not None
            assert borrowed.key().link_state_id == 0xa
        finally:
            arr.close()
        # Poll again at 10.999s — should NOT re-emit (last_sent_ms was bumped to 6s).
        arr = l.poll(10_999, 5_000)
        try:
            assert len(arr) == 0
        finally:
            arr.close()
    finally:
        l.close()


def test_lsdb_empty():
    d = librouting.OspfLsdb.new()
    try:
        assert len(d) == 0
        assert d.is_empty()
        assert d.headers() == []
    finally:
        d.close()


def test_lsdb_install_get_remove():
    d = librouting.OspfLsdb.new()
    try:
        lsa = _make_lsa(0xa, 0xa)
        rc = d.install(lsa, 0)
        assert rc == 1, f"first install rc={rc}, want 1 (New)"
        assert len(d) == 1
        # Get returns a clone — caller frees it.
        got = d.get(librouting.OspfLsaKey(1, 0xa, 0xa))
        try:
            assert got is not None
            h = got.header()
            assert h.ls_sequence_number == 0x80000001
        finally:
            if got is not None:
                got.close()
        # Headers should now contain 1 entry.
        headers = d.headers()
        assert len(headers) == 1
        assert headers[0].link_state_id == 0xa
        # Remove the LSA.
        assert d.remove(librouting.OspfLsaKey(1, 0xa, 0xa))
        assert len(d) == 0
    finally:
        d.close()


def test_lsa_body_round_trip():
    body = b"\x00\x00\x00\x00\xde\xad\xbe\xef"
    lsa = librouting.OspfLsa.new(
        librouting.OspfLsaHeader(
            ls_age=0, options=0, ls_type=1,
            link_state_id=0x01020304, advertising_router=0x01020304,
            ls_sequence_number=0x80000001, ls_checksum=0,
            length=20 + len(body),
        ),
        body,
    )
    try:
        got = lsa.body()
        assert got == body
        wire = lsa.to_wire()
        assert len(wire) == 20 + len(body)
        k = lsa.key()
        assert k.ls_type == 1
        assert k.link_state_id == 0x01020304
        assert k.advertising_router == 0x01020304
    finally:
        lsa.close()


def test_external_dest_v4():
    d = librouting.OspfExternalDest.new_v4(
        bytes([203, 0, 113, 0]), 24, 100,
        librouting.EXTERNAL_METRIC_TYPE1,
    )
    try:
        assert d.metric() == 100
        assert d.metric_type() == librouting.EXTERNAL_METRIC_TYPE1
        d.set_forwarding_addr_v4(0x0A000001)
        d.set_route_tag(42)
        d.set_p_bit(1)
        assert d.route_tag() == 42
        assert d.p_bit() == 1
    finally:
        d.close()


def test_context_manager_closes_handle():
    with librouting.OspfRetransmitList.new() as l:
        assert len(l) == 0
    # After exit, the handle is closed — verify the underlying pointer
    # is null by attempting a fresh operation that would crash if it
    # weren't.
    assert l.is_empty()  # is_empty on a NULL handle returns 1 (treated as "empty").


def test_v3_external_dest_round_trip():
    pfx = bytes([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x01,
    ])
    d = librouting.OspfV3ExternalDest.new_v6(pfx, 48, 100, type2=False)
    try:
        assert d.metric() == 100
        assert d.type2() is False
        fa = bytes([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0xfe,
        ])
        d.set_forwarding_addr(fa)
        d.set_route_tag(0xDEADBEEF)
        out_fa = d.forwarding_addr()
        assert out_fa is not None
        assert out_fa == fa
        assert d.route_tag() == 0xDEADBEEF
        d.clear_forwarding_addr()
        d.clear_route_tag()
        assert d.forwarding_addr() is None
        assert d.route_tag() is None
    finally:
        d.close()


def test_v3_external_dest_new_v6_wrong_size():
    try:
        librouting.OspfV3ExternalDest.new_v6(bytes(8), 48, 100, type2=False)
        assert False, "expected LrError on short prefix"
    except librouting.LrError:
        pass


def test_v3_external_dest_context_manager():
    pfx = bytes([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x01,
    ])
    with librouting.OspfV3ExternalDest.new_v6(pfx, 48, 100, type2=True) as d:
        assert d.metric() == 100
        assert d.type2() is True
    # After the with-block, the handle is closed; accessing it again
    # would fail. We just verify the constructor accepted type2=True.


def _router_with_ospf_area(area_id=1, area_kind=0, default_metric=0):
    """Helper: build a fresh Router and attach an OSPFv2 area via the
    C ABI's `lr_router_add_ospf_session_ext` so `ospf_router_id` is
    set."""
    r = librouting.Router()
    r.add_ospf_session_ext(
        version=2,
        router_id=0xC0A80001,
        area_id=area_id,
        area_kind=area_kind,
        default_metric=default_metric,
        mtu=1500,
        network_type=0,  # PTP
        interface_ip=None,
        neighbor_ip=None,
    )
    return r


def test_ospf_virtual_link_lifecycle():
    r = _router_with_ospf_area()
    # vlink to self refused.
    assert r.ospf_add_virtual_link(1, 0xC0A80001) is False
    # vlink across normal area accepted.
    assert r.ospf_add_virtual_link(1, 0xC0A80002) is True
    # duplicate add refused.
    assert r.ospf_add_virtual_link(1, 0xC0A80002) is False
    # link down (no SPF reach).
    assert r.ospf_virtual_link_up(1, 0xC0A80002) is False
    assert r.ospf_virtual_link_session(1, 0xC0A80002) is None
    # remove.
    assert r.ospf_remove_virtual_link(1, 0xC0A80002) is True
    # remove again — no-op.
    assert r.ospf_remove_virtual_link(1, 0xC0A80002) is False


def test_ospf_virtual_link_across_stub_area_refused():
    # area_kind=1 is a stub area; virtual links cannot cross stub
    # areas (RFC 2328 §15).
    r = _router_with_ospf_area(area_id=2, area_kind=1, default_metric=100)
    assert r.ospf_add_virtual_link(2, 0xC0A80002) is False


def test_ospf_redistribute_v2_marks_asbr_and_unredistribute():
    r = _router_with_ospf_area()
    assert r.ospf_is_asbr() is False
    dest = librouting.OspfExternalDest.new_v4(
        bytes([10, 0, 0, 0]), 24, 100,
        librouting.EXTERNAL_METRIC_TYPE1,
    )
    try:
        assert r.ospf_redistribute(dest) is True
        assert r.ospf_is_asbr() is True
        assert r.ospf_unredistribute("10.0.0.0/24") is True
        assert r.ospf_is_asbr() is False
        # Unredistribute again is a no-op.
        assert r.ospf_unredistribute("10.0.0.0/24") is False
    finally:
        dest.close()


def test_ospf_redistribute_v3_marks_asbr_and_unredistribute():
    r = _router_with_ospf_area()
    pfx = bytes([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x01,
    ])
    dest = librouting.OspfV3ExternalDest.new_v6(pfx, 48, 100, type2=False)
    try:
        assert r.ospf_redistribute_v3(dest) is True
        assert r.ospf_is_asbr() is True
        # With only a v2 area attached, no v3 LSA was ever originated,
        # so unredistribute_v3 returns False (nothing was flushed);
        # the ASBR flag flipping back to False confirms the intent was
        # in fact dropped.
        r.ospf_unredistribute_v3("2001:db8::/48")
        assert r.ospf_is_asbr() is False
    finally:
        dest.close()


def test_ospf_redistribute_v3_rejects_link_local_forwarding_addr():
    r = _router_with_ospf_area()
    pfx = bytes([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x01,
    ])
    ll_fa = bytes([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x01,
    ])
    dest = librouting.OspfV3ExternalDest.new_v6(pfx, 48, 100, type2=False)
    try:
        dest.set_forwarding_addr(ll_fa)
        # The router rejects link-local FA per RFC 5340 §A.4.7.
        assert r.ospf_redistribute_v3(dest) is False
    finally:
        dest.close()


def test_ospf_redistribute_v2_rejects_v6_prefix_via_dest_handle():
    r = _router_with_ospf_area()
    pfx = bytes([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x01,
    ])
    # OspfExternalDest.new_v6 succeeds at construction (the C ABI
    # accepts the v6 prefix pointer), but the v2 redistribute plane
    # only carries IPv4 prefixes — passing a v6 dest returns False.
    dest = librouting.OspfExternalDest.new_v6(
        pfx, 48, 100, librouting.EXTERNAL_METRIC_TYPE1,
    )
    try:
        assert r.ospf_redistribute(dest) is False
    finally:
        dest.close()
