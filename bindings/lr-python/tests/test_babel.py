"""Tests for the Babel protocol Python binding (librouting.babel).

Mirrors the C ABI surface in crates/lr-ffi/src/babel*.rs and the
Rust API in lr_babel. Each test exercises one slice of the surface
end-to-end through the C ABI.

RFC references:
  * RFC 8966 — the Babel routing protocol.
  * RFC 8967 — the HMAC authentication extension.
"""

from __future__ import annotations

import pytest

import librouting
from librouting import (
    AE_IPV4,
    AE_IPV6,
    Ack,
    AckReq,
    BabelCodec,
    BabelFrame,
    BabelNeighbor,
    BabelRoute,
    BabelRouteKey,
    BabelRouteTable,
    Hello,
    Ihu,
    MAC_BLAKE2S128,
    MAC_HMAC_SHA256,
    MacKey,
    NextHop,
    PacketCounter,
    PseudoHeader,
    ReplayProtection,
    RouteRequest,
    RouterId,
    SeqnoRequest,
    Tlv,
    TLV_ACK,
    TLV_ACK_REQ,
    TLV_HELLO,
    TLV_IHU,
    TLV_PAD1,
    TLV_PADN,
    feasible,
    route_metric_sum,
    rtt_penalty,
    tlv_type_from_u8,
    tlv_type_name,
    tlv_type_to_u8,
)


# ---- TLV + Frame ----------------------------------------------------------


def test_tlv_pad1_round_trip():
    t = Tlv.pad1()
    assert t.kind == TLV_PAD1
    assert t.value == b""
    t.close()


def test_tlv_pad_n_round_trip():
    t = Tlv.pad_n(4)
    assert t.kind == TLV_PADN
    assert t.value == b"\x00\x00\x00\x00"
    t.close()


def test_tlv_new_round_trip():
    t = Tlv.new(TLV_ACK_REQ, b"\x00\x2a\x00\xc8")
    assert t.kind == TLV_ACK_REQ
    assert t.value == b"\x00\x2a\x00\xc8"
    t.close()


def test_tlv_close_is_idempotent():
    t = Tlv.pad1()
    t.close()
    t.close()  # second close is a no-op


def test_tlv_with_block_releases_on_exit():
    with Tlv.pad1() as t:
        assert t.kind == TLV_PAD1
    # After the with block, the handle is freed; calling close again
    # is safe (idempotent).


def test_frame_empty_construction():
    with BabelFrame.empty() as f:
        assert f.tlv_count == 0


def test_frame_push_tlv_increments_count():
    f = BabelFrame.empty()
    f.push_tlv(Tlv.pad1())
    assert f.tlv_count == 1
    assert f.tlv_type_at(0) == TLV_PAD1
    assert f.tlv_value_at(0) == b""
    f.close()


def test_frame_from_tlvs_consumes_handles():
    t1 = Tlv.pad1()
    t2 = Tlv.pad_n(2)
    f = BabelFrame.from_tlvs([t1, t2])
    assert f.tlv_count == 2
    # The TLV handles are consumed by the frame; the Python Tlv
    # objects must not free them again (close is a no-op).
    t1.close()
    t2.close()
    f.close()


def test_frame_iter_tlvs():
    f = BabelFrame.empty()
    f.push_tlv(Tlv.pad1())
    f.push_tlv(Tlv.pad_n(2))
    pairs = list(f.iter_tlvs())
    assert pairs == [(TLV_PAD1, b""), (TLV_PADN, b"\x00\x00")]
    f.close()


def test_frame_encode_round_trip():
    f = BabelFrame.empty()
    f.push_tlv(Tlv.pad1())
    wire = f.encode()
    # Babel frame wire: magic (0x2a) + version (0x02) + 2-byte
    # body_length (big-endian) + body. Pad1 is a single 0x00 byte.
    assert wire[0] == 0x2A  # MAGIC
    assert wire[1] == 0x02  # VERSION
    assert wire[2:4] == b"\x00\x01"  # body length = 1
    assert wire[4] == 0x00  # Pad1 body byte
    f.close()


def test_decode_frame_round_trip():
    f = BabelFrame.empty()
    f.push_tlv(Tlv.pad1())
    wire = f.encode()
    f.close()

    f2 = librouting.decode_frame(wire)
    assert f2.tlv_count >= 1
    # The decoded frame has the same magic + the Pad1 TLV at index 0.
    assert f2.tlv_type_at(0) == TLV_PAD1
    f2.close()


def test_frame_index_out_of_range():
    f = BabelFrame.empty()
    with pytest.raises(IndexError):
        f.tlv_type_at(0)
    with pytest.raises(IndexError):
        f.tlv_value_at(0)
    f.close()


# ---- TLV type enum helpers -----------------------------------------------


def test_tlv_type_to_u8_identity():
    assert tlv_type_to_u8(TLV_HELLO) == TLV_HELLO
    assert tlv_type_to_u8(TLV_IHU) == TLV_IHU


def test_tlv_type_from_u8_identity():
    assert tlv_type_from_u8(TLV_HELLO) == TLV_HELLO


def test_tlv_type_name_known():
    assert tlv_type_name(TLV_PAD1) != ""
    assert tlv_type_name(TLV_HELLO) != ""
    assert tlv_type_name(TLV_IHU) != ""


# ---- RouteKey + BabelRoute + BabelRouteTable ------------------------------


def _v4_key(addr=(10, 0, 0, 0), plen=8, rid_byte=1):
    return BabelRouteKey(
        destination=(bytes(addr), plen),
        source=None,
        router_id=bytes([rid_byte] * 8),
    )


def _v4_route(seqno=1, metric=100, nh=(10, 0, 0, 1), feasible=False, installed=False, **kwargs):
    return BabelRoute(
        key=_v4_key(**kwargs),
        seqno=seqno,
        metric=metric,
        next_hop=bytes(nh),
        feasible=feasible,
        installed=installed,
    )


def test_route_table_empty_lifecycle():
    t = BabelRouteTable.new()
    assert len(t) == 0
    assert t.is_empty()
    assert t.best_routes_count() == 0
    t.close()


def test_route_table_insert_and_get_v4():
    t = BabelRouteTable.new()
    r = _v4_route()
    t.insert(r)
    assert len(t) == 1
    assert not t.is_empty()

    got = t.get(_v4_key())
    assert got is not None
    assert got.seqno == 1
    assert got.metric == 100
    assert got.next_hop == bytes([10, 0, 0, 1])
    # The table marks a freshly-inserted route feasible when no
    # prior feasibility record exists (RFC 8966 §3.5.2).
    assert got.feasible is True
    assert got.installed is False  # install flag is not set by the table
    t.close()


def test_route_table_contains_missing_key():
    t = BabelRouteTable.new()
    assert t.contains(_v4_key()) is False
    t.close()


def test_route_table_get_missing_key_returns_none():
    t = BabelRouteTable.new()
    assert t.get(_v4_key()) is None
    t.close()


def test_route_table_withdraw_removes_route():
    t = BabelRouteTable.new()
    t.insert(_v4_route())
    assert len(t) == 1
    t.withdraw(_v4_key())
    assert len(t) == 0
    assert t.is_empty()
    t.close()


def test_route_table_iter_all_yields_inserted_routes():
    t = BabelRouteTable.new()
    t.insert(_v4_route(seqno=1, metric=100))
    routes = list(t.iter_all())
    assert len(routes) == 1
    assert routes[0].seqno == 1
    assert routes[0].metric == 100
    t.close()


def test_route_table_iter_best_yields_lowest_metric_feasible():
    t = BabelRouteTable.new()
    t.insert(_v4_route(seqno=1, metric=100))
    best = list(t.iter_best())
    assert len(best) == 1
    assert best[0].metric == 100
    assert t.best_routes_count() == 1
    t.close()


def test_route_table_v6_with_source_prefix():
    key = BabelRouteKey(
        destination=(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 64),
        source=(bytes([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 48),
        router_id=bytes([2] * 8),
    )
    route = BabelRoute(
        key=key,
        seqno=2,
        metric=200,
        next_hop=bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        feasible=True,
        installed=True,
    )
    t = BabelRouteTable.new()
    t.insert(route)
    assert len(t) == 1
    got = t.get(key)
    assert got is not None
    assert got.key.destination[0] == bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    assert got.key.destination[1] == 64
    assert got.key.is_source_specific
    assert got.key.source == (bytes([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 48)
    assert got.next_hop == bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
    t.close()


def test_route_table_with_block_releases_on_exit():
    with BabelRouteTable.new() as t:
        t.insert(_v4_route())
        assert len(t) == 1
    # After the with block, the table is freed.


def test_route_table_insert_rejects_bad_addr():
    bad_key = BabelRouteKey(
        destination=(b"\x00\x00", 8),  # 2-byte address
        source=None,
        router_id=bytes([1] * 8),
    )
    t = BabelRouteTable.new()
    with pytest.raises(librouting.LrError):
        t.insert(BabelRoute(key=bad_key, seqno=1, metric=1,
                             next_hop=bytes([10, 0, 0, 1]),
                             feasible=False, installed=False))
    t.close()


def test_route_table_expire_returns_withdrawn_count():
    # insert with interval_cs=1 (centiseconds); hold_ms is
    # max(interval_cs*60, 30_000) = 30_000 ms. After 30s, the route
    # expires.
    t = BabelRouteTable.new()
    t.insert(_v4_route(), interval_cs=1, now_ms=0)
    assert len(t) == 1
    n_expired = t.expire(now_ms=40_000)
    assert n_expired == 1
    assert len(t) == 0
    t.close()


# ---- BabelNeighbor --------------------------------------------------------


def test_neighbor_v4_lifecycle_and_hello():
    n = BabelNeighbor.new(bytes([10, 0, 0, 1]), now_ms=1000)
    n.hello(seqno=1, interval_cs=100, now_ms=1100)
    n.ihu(rxcost=96, interval_cs=100, now_ms=1100)
    # No timestamped Hello received -> RTT not valid.
    assert n.rtt_valid(now_ms=1200) is False
    assert n.rtt_us(now_ms=1200) == 0
    n.close()


def test_neighbor_v6_lifecycle():
    n = BabelNeighbor.new(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                          now_ms=0)
    n.hello(seqno=1, interval_cs=100, now_ms=100)
    assert n.rtt_valid(now_ms=200) is False
    n.close()


def test_neighbor_rejects_bad_addr():
    with pytest.raises(librouting.LrError):
        BabelNeighbor.new(b"")  # empty
    with pytest.raises(librouting.LrError):
        BabelNeighbor.new(b"\x00" * 8)  # 8 bytes is neither 4 nor 16


# ---- MacKey + PseudoHeader + PacketCounter + ReplayProtection -------------


def test_mac_key_hmac_sha256_round_trip():
    k = MacKey.hmac_sha256(b"my-secret")
    assert k.algorithm == MAC_HMAC_SHA256
    assert k.digest_len == 32
    assert k.secret == b"my-secret"
    k.close()


def test_mac_key_blake2s128_round_trip():
    k = MacKey.blake2s128(b"my-secret")
    assert k.algorithm == MAC_BLAKE2S128
    assert k.digest_len == 16
    assert k.secret == b"my-secret"
    k.close()


def test_mac_key_new_uses_default_algorithm():
    k = MacKey.new(b"my-secret")
    assert k.secret == b"my-secret"
    k.close()


def test_pseudo_header_v4_encode():
    ph = PseudoHeader.new_v4(bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]), 6696, 6696)
    wire = ph.encode()
    assert len(wire) > 0
    ph.close()


def test_pseudo_header_v6_encode():
    ph = PseudoHeader.new_v6(
        bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        6696, 6696,
    )
    wire = ph.encode()
    assert len(wire) > 0
    ph.close()


def test_packet_counter_round_trip():
    pc = PacketCounter.new(b"index", initial=10)
    assert pc.counter == 10
    assert pc.index_len == 5
    assert pc.index == b"index"
    pc.close()


def test_replay_protection_accept_strictly_higher():
    rp = ReplayProtection.new()
    assert rp.accept(b"idx", 5) is True
    assert rp.accept(b"idx", 3) is False  # lower counter is a replay
    assert rp.accept(b"idx", 5) is False  # equal counter is a replay
    assert rp.accept(b"idx", 6) is True
    rp.close()


# ---- Message constructors (Hello / Ihu / AckReq / Ack / NextHop / ...) ----


def test_hello_round_trip():
    h = Hello.new(seqno=1, interval_cs=100)
    assert h.seqno == 1
    assert h.interval_cs == 100
    h.set_unicast(True)
    assert h.flags != 0  # unicast flag is set
    wire = h.encode()
    assert len(wire) > 0
    h.close()


def test_ihu_round_trip():
    h = Ihu.new(rxcost=96, interval_cs=100)
    assert h.rxcost == 96
    assert h.interval_cs == 100
    wire = h.encode()
    assert len(wire) > 0
    h.close()


def test_ack_req_round_trip():
    a = AckReq.new(nonce=42, interval_cs=200)
    assert a.nonce == 42
    assert a.interval_cs == 200
    a.close()


def test_ack_round_trip():
    a = Ack.new(opaque=42)
    assert a.opaque == 42
    wire = a.encode()
    assert len(wire) > 0
    a.close()


def test_next_hop_v4_round_trip():
    n = NextHop.new(bytes([10, 0, 0, 1]))
    assert n.ae == AE_IPV4
    assert n.address == bytes([10, 0, 0, 1])
    wire = n.encode()
    assert len(wire) > 0
    n.close()


def test_next_hop_v6_round_trip():
    addr = bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    n = NextHop.new(addr)
    assert n.ae == AE_IPV6
    assert n.address == addr
    n.close()


def test_next_hop_rejects_bad_addr():
    with pytest.raises(librouting.LrError):
        NextHop.new(b"\x00\x00")  # neither 4 nor 16 bytes


def test_router_id_round_trip():
    rid = RouterId.new(bytes([1] * 8))
    assert rid.bytes_ == bytes([1] * 8)
    rid.close()


def test_router_id_rejects_bad_length():
    with pytest.raises(librouting.LrError):
        RouterId.new(b"\x00" * 7)


def test_route_request_wildcard_lifecycle():
    rr = RouteRequest.new_wildcard()
    rr.close()


def test_seqno_request_lifecycle():
    sr = SeqnoRequest.new(
        prefix=bytes([10, 0, 0, 0]),
        prefix_len=8,
        seqno=1,
        router_id=bytes([1] * 8),
    )
    sr.close()


def test_seqno_request_rejects_bad_router_id():
    with pytest.raises(librouting.LrError):
        SeqnoRequest.new(
            prefix=bytes([10, 0, 0, 0]),
            prefix_len=8,
            seqno=1,
            router_id=bytes([1] * 7),  # wrong length
        )


def test_seqno_request_rejects_bad_prefix():
    with pytest.raises(librouting.LrError):
        SeqnoRequest.new(
            prefix=b"\x00\x00",  # neither 4 nor 16
            prefix_len=8,
            seqno=1,
            router_id=bytes([1] * 8),
        )


# ---- Free function helpers -----------------------------------------------


def test_rtt_penalty_disabled_when_max_penalty_zero():
    assert rtt_penalty(500_000, 10_000, 120_000, 0) == 0


def test_rtt_penalty_clamps_at_max_penalty():
    # RTT way above rtt_max_us: penalty is clamped at max_penalty.
    assert rtt_penalty(1_000_000, 10_000, 120_000, 96) == 96


def test_rtt_penalty_interpolates_in_between():
    # RTT in the middle of the ramp window: linear interpolation.
    # rtt_min=10_000, rtt_max=120_000, max_penalty=96
    # rtt=65_000 -> halfway -> ~48 (with integer rounding)
    penalty = rtt_penalty(65_000, 10_000, 120_000, 96)
    assert 40 <= penalty <= 56  # roughly half


def test_route_metric_sum_sums_link_metrics():
    assert route_metric_sum([100, 200, 300]) == 600
    assert route_metric_sum([]) == 0
    assert route_metric_sum([42]) == 42


def test_feasible_strictly_better():
    # (seqno, metric) strictly better than (feasible_seqno, feasible_metric)
    # = (1, 100) vs (0, 200): seqno higher -> feasible
    assert feasible(route_seqno=1, route_metric=100,
                     feasible_seqno=0, feasible_metric=200) is True
    # (1, 100) vs (1, 100): equal -> not feasible (must be strictly better)
    assert feasible(route_seqno=1, route_metric=100,
                     feasible_seqno=1, feasible_metric=100) is False
    # (0, 50) vs (1, 100): seqno lower -> not feasible
    assert feasible(route_seqno=0, route_metric=50,
                     feasible_seqno=1, feasible_metric=100) is False
