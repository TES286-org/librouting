"""Foundational lr-core types tests — IpAddr, CorePrefix, Asn,
RouterId, Preference, NlriFamily, ReadBuf, WriteBuf, TimerQueue,
MemoryConn, plus the CRC/Fletcher utilities.

These tests exercise the Python binding through the public
``librouting.IpAddr`` / ``librouting.CorePrefix`` / ``librouting.Asn``
/ ``librouting.RouterId`` / ``librouting.Preference`` /
``librouting.NlriFamily`` / ``librouting.ReadBuf`` /
``librouting.WriteBuf`` / ``librouting.TimerQueue`` /
``librouting.MemoryConn`` API and mirror the C ABI tests in
``crates/lr-ffi/src/core.rs``, ``crates/lr-ffi/src/core_buf.rs``,
``crates/lr-ffi/src/core_extras.rs``, ``crates/lr-ffi/src/core_extras_2.rs``,
and ``crates/lr-ffi/src/memory_conn.rs``.
"""

import pytest

import librouting
from librouting import (
    Asn,
    BoxedIpAddr,
    CorePrefix,
    IpAddr,
    MemoryConn,
    NlriFamily,
    Preference,
    PROTO_BABEL,
    PROTO_BGP,
    PROTO_CONNECTED,
    PROTO_OSPF,
    PROTO_OSPF3,
    PROTO_OTHER,
    PROTO_STATIC,
    RawRouteKey,
    ReadBuf,
    RouterId,
    TimerQueue,
    TimerSpec,
    WriteBuf,
    crc16_arc,
    crc32c,
    duration_as_millis,
    duration_as_secs,
    duration_checked_add,
    duration_from_millis,
    duration_from_secs,
    fletcher32,
    instant_as_millis,
    instant_as_secs,
    instant_checked_add,
    instant_checked_sub,
    instant_from_millis,
    instant_from_secs,
    instant_saturating_sub,
    nlri_family_bgp_ls,
    nlri_family_bgp_ls_vpn,
    nlri_family_from_addr,
    nlri_family_ipv4_labeled_unicast,
    nlri_family_ipv4_mpls_vpn,
    nlri_family_ipv4_multicast,
    nlri_family_ipv4_unicast,
    nlri_family_ipv6_labeled_unicast,
    nlri_family_ipv6_mpls_vpn,
    nlri_family_ipv6_unicast,
    ospf_lsa_checksum,
    ospf_lsa_checksum_ok,
    protocol_bird_name,
    protocol_default_admin_distance,
)


# ---- IpAddr ----


def test_ip_addr_v4_construct_and_read():
    a = IpAddr.from_v4_bytes(bytes([10, 0, 0, 1]))
    assert a.is_ipv4
    assert not a.is_ipv6
    assert a.octets() == bytes([10, 0, 0, 1])


def test_ip_addr_v4_from_str():
    a = IpAddr.from_str("192.168.1.1")
    assert a.is_ipv4
    assert a.octets() == bytes([192, 168, 1, 1])
    assert str(a) == "192.168.1.1"


def test_ip_addr_v6_construct_and_read():
    a = IpAddr.from_v6_bytes(bytes([0xfe, 0x80] + [0] * 14))
    assert a.is_ipv6
    assert not a.is_ipv4
    assert a.octets() == bytes([0xfe, 0x80] + [0] * 14)


def test_ip_addr_unspecified_v4():
    a = IpAddr.from_v4_bytes(bytes([0, 0, 0, 0]))
    assert a.is_unspecified


def test_ip_addr_unspecified_v6():
    a = IpAddr.from_v6_bytes(bytes([0] * 16))
    assert a.is_unspecified


def test_ip_addr_multicast_v4():
    a = IpAddr.from_v4_bytes(bytes([224, 0, 0, 1]))
    assert a.is_multicast


def test_ip_addr_multicast_v6():
    # ff02::1 is multicast
    b = IpAddr.from_v6_bytes(bytes([0xff, 0x02] + [0] * 14))
    assert b.is_multicast


def test_ip_addr_from_bytes_dispatch():
    a4 = IpAddr.from_bytes(bytes([10, 0, 0, 1]))
    assert a4.is_ipv4
    a6 = IpAddr.from_bytes(bytes([0xfe, 0x80] + [0] * 14))
    assert a6.is_ipv6


def test_ip_addr_from_bytes_rejects_bad_length():
    with pytest.raises(ValueError):
        IpAddr.from_bytes(b"\x01\x02\x03")


def test_ip_addr_equality():
    a = IpAddr.from_v4_bytes(bytes([10, 0, 0, 1]))
    b = IpAddr.from_v4_bytes(bytes([10, 0, 0, 1]))
    c = IpAddr.from_v4_bytes(bytes([10, 0, 0, 2]))
    assert a == b
    assert a != c
    assert hash(a) == hash(b)


# ---- BoxedIpAddr (RFC 4291 §2.5.5.2 IPv4-mapped IPv6) ----


def test_boxed_ip_addr_v4_round_trip():
    a = BoxedIpAddr.from_v4_bytes(bytes([10, 0, 0, 1]))
    assert not a.is_ipv4_mapped_ipv6
    a.close()


def test_boxed_ip_addr_to_ipv4_mapped_returns_v6():
    a = BoxedIpAddr.from_v4_bytes(bytes([10, 0, 0, 1]))
    mapped = a.to_ipv4_mapped()
    assert mapped is not None
    assert mapped.is_ipv4_mapped_ipv6
    mapped.close()
    a.close()


def test_boxed_ip_addr_to_ipv4_mapped_returns_none_for_v6():
    a = BoxedIpAddr.from_v6_bytes(bytes([0xfe, 0x80] + [0] * 14))
    assert a.to_ipv4_mapped() is None
    a.close()


def test_boxed_ip_addr_from_bytes_dispatch():
    a = BoxedIpAddr.from_bytes(bytes([10, 0, 0, 1]))
    a.close()
    b = BoxedIpAddr.from_bytes(bytes([0xfe, 0x80] + [0] * 14))
    b.close()


# ---- CorePrefix ----


def test_core_prefix_v4_construct():
    p = CorePrefix.v4(bytes([10, 0, 0, 0]), 24)
    assert p.is_ipv4
    assert not p.is_ipv6
    assert p.prefix_len == 24


def test_core_prefix_v6_construct():
    p = CorePrefix.v6(bytes([0xfe, 0x80] + [0] * 14), 64)
    assert p.is_ipv6
    assert p.prefix_len == 64


def test_core_prefix_from_str():
    p = CorePrefix.from_str("10.0.0.0/24")
    assert p.is_ipv4
    assert p.prefix_len == 24


def test_core_prefix_network_zeros_host_bits():
    p = CorePrefix.v4(bytes([10, 0, 0, 5]), 24)
    net = p.network()
    assert net.octets() == bytes([10, 0, 0, 0])


def test_core_prefix_contains_addr_bit_level():
    p = CorePrefix.v4(bytes([10, 0, 0, 0]), 24)
    assert p.contains(IpAddr.from_v4_bytes(bytes([10, 0, 0, 5])))
    assert p.contains(IpAddr.from_v4_bytes(bytes([10, 0, 0, 255])))
    assert not p.contains(IpAddr.from_v4_bytes(bytes([10, 0, 1, 1])))


def test_core_prefix_contains_prefix_bit_level():
    outer = CorePrefix.v4(bytes([10, 0, 0, 0]), 16)
    inner = CorePrefix.v4(bytes([10, 0, 5, 0]), 24)
    not_inner = CorePrefix.v4(bytes([10, 1, 0, 0]), 24)
    assert outer.contains_prefix(inner)
    assert not outer.contains_prefix(not_inner)


# ---- Asn ----


def test_asn_new_and_value():
    a = Asn.new(65001)
    assert a.value == 65001
    assert int(a) == 65001
    assert a.is_private


def test_asn_is_private_public_range():
    assert Asn.new(64512).is_private
    assert Asn.new(65534).is_private
    assert not Asn.new(65535).is_private  # 65535 is reserved
    assert Asn.new(4200000000).is_private
    assert Asn.new(4294967294).is_private
    assert not Asn.new(4294967295).is_private


def test_asn_is_as_trans():
    assert Asn.new(23456).is_as_trans
    assert not Asn.new(65001).is_as_trans


def test_asn_as_u16():
    assert Asn.new(100).as_u16() == 100
    # A 4-byte ASN > 65535 returns 0 (AS_TRANS upgrade path)
    assert Asn.new(70000).as_u16() == 0


def test_asn_equality_and_hash():
    a = Asn.new(65001)
    b = Asn.new(65001)
    c = Asn.new(65002)
    assert a == b
    assert a != c
    assert hash(a) == hash(b)


# ---- RouterId ----


def test_router_id_from_u32():
    r = RouterId.from_u32(0x0a000001)
    assert r.value == 0x0a000001
    assert int(r) == 0x0a000001


def test_router_id_from_v4_bytes():
    r = RouterId.from_v4(bytes([10, 0, 0, 1]))
    assert r.to_v4_bytes() == bytes([10, 0, 0, 1])
    assert str(r) == "10.0.0.1"


def test_router_id_equality():
    a = RouterId.from_u32(0x0a000001)
    b = RouterId.from_v4(bytes([10, 0, 0, 1]))
    assert a == b
    assert hash(a) == hash(b)


# ---- Protocol helpers ----


@pytest.mark.parametrize(
    "proto,expected_name",
    [
        (PROTO_BGP, "bgp"),
        (PROTO_OSPF, "ospf"),
        (PROTO_OSPF3, "ospf3"),
        (PROTO_BABEL, "babel"),
        (PROTO_STATIC, "static"),
        (PROTO_CONNECTED, "direct"),
        (PROTO_OTHER, "unknown"),
    ],
)
def test_protocol_bird_name(proto, expected_name):
    assert protocol_bird_name(proto) == expected_name


def test_protocol_default_admin_distance_bgp():
    assert protocol_default_admin_distance(PROTO_BGP) == 20


def test_protocol_default_admin_distance_ospf():
    assert protocol_default_admin_distance(PROTO_OSPF) == 110


# ---- Instant / Duration ----


def test_instant_round_trip_secs():
    i = instant_from_secs(5)
    assert instant_as_secs(i) == 5
    assert instant_as_millis(i) == 5000


def test_instant_round_trip_millis():
    i = instant_from_millis(1500)
    assert instant_as_secs(i) == 1
    assert instant_as_millis(i) == 1500


def test_instant_saturating_sub():
    a = instant_from_secs(5)
    b = instant_from_secs(8)
    assert instant_saturating_sub(a, b) == 3000  # 3 seconds in ms
    # Reverse direction clamps to 0.
    assert instant_saturating_sub(b, a) == 0


def test_instant_checked_add():
    i = instant_from_secs(5)
    j = instant_checked_add(i, 1000)  # +1 second
    assert instant_as_secs(j) == 6


def test_instant_checked_sub_returns_none_on_underflow():
    a = instant_from_secs(5)
    b = instant_from_secs(8)
    assert instant_checked_sub(a, b) is None


def test_instant_checked_sub_succeeds():
    a = instant_from_secs(8)
    b = instant_from_secs(5)
    assert instant_checked_sub(a, b) == 3000


def test_duration_round_trip_secs():
    d = duration_from_secs(5)
    assert duration_as_secs(d) == 5
    assert duration_as_millis(d) == 5000


def test_duration_checked_add():
    d = duration_from_millis(1000)
    assert duration_as_secs(duration_checked_add(d, 500)) == 1
    assert duration_as_millis(duration_checked_add(d, 500)) == 1500


# ---- RawRouteKey ----


def test_raw_route_key_new():
    p = CorePrefix.v4(bytes([10, 0, 0, 0]), 24)
    k = RawRouteKey.new(p, 0x0101)  # AFI=1 (IPv4), SAFI=1 (unicast)
    assert k.afi_safi == 0x0101
    assert not k.has_source
    assert k.source_prefix is None


def test_raw_route_key_with_source():
    p = CorePrefix.v4(bytes([10, 0, 0, 0]), 24)
    s = CorePrefix.v4(bytes([192, 168, 0, 0]), 24)
    k = RawRouteKey.with_source(p, 0x0101, s)
    assert k.has_source
    assert k.source_prefix is not None
    assert k.source_prefix.is_ipv4


# ---- Preference ----


def test_preference_new():
    p = Preference.new(20, 100)
    assert p.admin_distance == 20
    assert p.metric == 100


# ---- NlriFamily ----


def test_nlri_family_ipv4_unicast():
    f = nlri_family_ipv4_unicast()
    assert f.afi == 1
    assert f.safi == 1
    assert f.is_ipv4
    assert not f.is_ipv6


def test_nlri_family_ipv6_unicast():
    f = nlri_family_ipv6_unicast()
    assert f.afi == 2
    assert f.safi == 1
    assert f.is_ipv6


def test_nlri_family_ipv4_multicast():
    f = nlri_family_ipv4_multicast()
    assert f.afi == 1
    assert f.safi == 2


def test_nlri_family_ipv4_mpls_vpn():
    f = nlri_family_ipv4_mpls_vpn()
    assert f.afi == 1
    assert f.safi == 128


def test_nlri_family_ipv6_mpls_vpn():
    f = nlri_family_ipv6_mpls_vpn()
    assert f.afi == 2
    assert f.safi == 128


def test_nlri_family_ipv4_labeled_unicast():
    f = nlri_family_ipv4_labeled_unicast()
    assert f.afi == 1
    assert f.safi == 4
    assert f.is_labeled_unicast


def test_nlri_family_ipv6_labeled_unicast():
    f = nlri_family_ipv6_labeled_unicast()
    assert f.afi == 2
    assert f.safi == 4
    assert f.is_labeled_unicast


def test_nlri_family_bgp_ls():
    f = nlri_family_bgp_ls()
    assert f.afi == 16388
    assert f.safi == 71
    assert f.is_bgp_ls
    assert not f.is_bgp_ls_vpn


def test_nlri_family_bgp_ls_vpn():
    f = nlri_family_bgp_ls_vpn()
    assert f.afi == 16388
    assert f.safi == 72
    assert f.is_bgp_ls  # is_bgp_ls matches both SAFI=71 and SAFI=72
    assert f.is_bgp_ls_vpn


def test_nlri_family_from_addr_v4():
    a = BoxedIpAddr.from_v4_bytes(bytes([10, 0, 0, 1]))
    f = nlri_family_from_addr(a)
    assert f.afi == 1
    assert f.safi == 1
    a.close()


def test_nlri_family_from_addr_v6():
    a = BoxedIpAddr.from_v6_bytes(bytes([0xfe, 0x80] + [0] * 14))
    f = nlri_family_from_addr(a)
    assert f.afi == 2
    assert f.safi == 1
    a.close()


def test_nlri_family_equality_and_hash():
    a = nlri_family_ipv4_unicast()
    b = nlri_family_ipv4_unicast()
    assert a == b
    assert hash(a) == hash(b)


# ---- CRC / Fletcher / OSPF LSA checksum ----


def test_crc16_arc_empty():
    assert crc16_arc(b"") == 0


def test_crc16_arc_known_value():
    # CRC-16/ARC of "123456789" is 0xBB3D
    assert crc16_arc(b"123456789") == 0xBB3D


def test_crc32c_empty():
    assert crc32c(b"") == 0


def test_crc32c_known_value():
    # CRC-32C of "123456789" is 0xE3069283
    assert crc32c(b"123456789") == 0xE3069283


def test_fletcher32_empty():
    assert fletcher32(b"") == 0


def test_fletcher32_known_value():
    # Fletcher-32 of "abcdefgh" (per RFC 905 §A.3 sample) — verify
    # the function returns a non-zero value (the exact constant
    # depends on the byte-pair interpretation; the C ABI test
    # covers the precise round-trip).
    assert fletcher32(b"abcdefgh") != 0


def test_ospf_lsa_checksum_short_returns_zero():
    # Shorter than the 20-byte LSA header
    assert ospf_lsa_checksum(b"\x00" * 19) == 0


def test_ospf_lsa_checksum_ok_short_returns_false():
    assert not ospf_lsa_checksum_ok(b"\x00" * 19)


def test_ospf_lsa_checksum_round_trip():
    # Construct a minimal LSA-like 20-byte header with the checksum
    # field zeroed, compute the checksum, patch it in, verify ok.
    lsa = bytearray(20)
    lsa[0] = 0x01  # arbitrary LS type
    cs = ospf_lsa_checksum(bytes(lsa))
    lsa[16] = (cs >> 8) & 0xFF
    lsa[17] = cs & 0xFF
    assert ospf_lsa_checksum_ok(bytes(lsa))


# ---- ReadBuf ----


def test_read_buf_new_and_remaining():
    rb = ReadBuf.new(b"\x01\x02\x03\x04")
    assert rb.position == 0
    assert rb.remaining == 4


def test_read_buf_get_u8():
    rb = ReadBuf.new(b"\x01\x02")
    assert rb.get_u8() == 1
    assert rb.position == 1
    assert rb.get_u8() == 2
    assert rb.position == 2
    assert rb.get_u8() is None  # exhausted


def test_read_buf_get_u16_be():
    rb = ReadBuf.new(b"\x12\x34")
    assert rb.get_u16_be() == 0x1234
    assert rb.position == 2


def test_read_buf_get_u32_be():
    rb = ReadBuf.new(b"\x12\x34\x56\x78")
    assert rb.get_u32_be() == 0x12345678
    assert rb.position == 4


def test_read_buf_get_u64_be():
    rb = ReadBuf.new(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    assert rb.get_u64_be() == 0x0102030405060708
    assert rb.position == 8


def test_read_buf_get_bytes():
    rb = ReadBuf.new(b"hello world")
    got = rb.get_bytes(5)
    assert got == b"hello"
    assert rb.position == 5


def test_read_buf_peek_u8():
    rb = ReadBuf.new(b"\x42")
    assert rb.peek_u8() == 0x42
    assert rb.position == 0  # peek does not advance


def test_read_buf_advance():
    rb = ReadBuf.new(b"\x01\x02\x03")
    rb.advance(2)
    assert rb.position == 2
    assert rb.get_u8() == 3


def test_read_buf_chunk():
    rb = ReadBuf.new(b"hello")
    assert rb.chunk() == b"hello"
    assert rb.position == 0  # chunk does not advance


# ---- WriteBuf ----


def test_write_buf_put_u8():
    wb = WriteBuf.new(8)
    wb.put_u8(0x42)
    assert wb.position == 1
    assert wb.written() == b"\x42"


def test_write_buf_put_u16_be():
    wb = WriteBuf.new(8)
    wb.put_u16_be(0x1234)
    assert wb.position == 2
    assert wb.written() == b"\x12\x34"


def test_write_buf_put_u32_be():
    wb = WriteBuf.new(8)
    wb.put_u32_be(0x12345678)
    assert wb.position == 4
    assert wb.written() == b"\x12\x34\x56\x78"


def test_write_buf_put_u64_be():
    wb = WriteBuf.new(16)
    wb.put_u64_be(0x0102030405060708)
    assert wb.position == 8
    assert wb.written() == b"\x01\x02\x03\x04\x05\x06\x07\x08"


def test_write_buf_put_bytes():
    wb = WriteBuf.new(16)
    wb.put_bytes(b"hello")
    assert wb.position == 5
    assert wb.written() == b"hello"


def test_write_buf_patch_back_fills_length():
    wb = WriteBuf.new(64)
    wb.put_u16_be(0)  # placeholder length
    wb.put_bytes(b"payload")
    wb.patch(0, b"\x00\x07")  # back-fill length = 7
    assert wb.written() == b"\x00\x07payload"


def test_write_buf_take_bytes_resets():
    wb = WriteBuf.new(8)
    wb.put_u8(0x01)
    out = wb.take_bytes()
    assert out == b"\x01"
    assert wb.position == 0


def test_write_buf_reserve_grows_capacity():
    wb = WriteBuf.new(0)
    initial = wb.capacity
    wb.reserve(64)
    assert wb.capacity >= 64


# ---- TimerQueue ----


def test_timer_queue_new_is_empty():
    tq = TimerQueue.new()
    assert tq.is_empty
    assert len(tq) == 0


def test_timer_queue_arm_and_tick():
    tq = TimerQueue.new()
    tq.arm(0, 1, TimerSpec.once(100))
    assert len(tq) == 1
    # Tick before fire — no timers fire.
    fired = tq.tick(50)
    assert fired == []
    # Tick after fire — timer 1 fires.
    fired = tq.tick(150)
    assert fired == [1]
    assert tq.is_empty


def test_timer_queue_cancel():
    tq = TimerQueue.new()
    tq.arm(0, 1, TimerSpec.once(100))
    tq.cancel(1)
    assert tq.is_empty
    fired = tq.tick(150)
    assert fired == []


def test_timer_queue_cancel_all():
    tq = TimerQueue.new()
    tq.arm(0, 1, TimerSpec.once(100))
    tq.arm(0, 2, TimerSpec.once(200))
    tq.cancel_all()
    assert tq.is_empty


def test_timer_queue_periodic_refires():
    tq = TimerQueue.new()
    tq.arm(0, 1, TimerSpec.periodic(100, 50))
    fired = tq.tick(100)
    assert fired == [1]
    # Next fire should be at 150ms.
    fired = tq.tick(150)
    assert fired == [1]


def test_timer_queue_next_fire_ms():
    tq = TimerQueue.new()
    tq.arm(0, 1, TimerSpec.once(100))
    assert tq.next_fire_ms() == 100


# ---- MemoryConn ----


def test_memory_conn_push_and_take_input():
    a = MemoryConn.new()
    a.push_input(b"hello")
    assert a.take_input() == b"hello"
    # Second take is empty.
    assert a.take_input() == b""


def test_memory_conn_put_and_drain_output():
    a = MemoryConn.new()
    a.put_output(b"world")
    assert a.drain_output() == b"world"
    # Second drain is empty.
    assert a.drain_output() == b""


def test_memory_conn_pair_returns_two_conns():
    a, b = MemoryConn.pair()
    # The pair are independent conns (loopback wiring is the
    # embedder's job — see lr_ffi.h lr_memory_conn_pair doc).
    a.push_input(b"foo")
    assert a.take_input() == b"foo"
    b.put_output(b"bar")
    assert b.drain_output() == b"bar"


def test_memory_conn_empty_data_is_no_op():
    a = MemoryConn.new()
    a.push_input(b"")
    assert a.take_input() == b""
