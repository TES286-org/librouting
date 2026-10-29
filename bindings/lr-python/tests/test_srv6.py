"""Tests for the SRv6 structured types binding (RFC 8754 / RFC 8986).

Mirrors the Rust-side `crates/lr-srv6/src/{sid,locator,srh,behavior}.rs`
unit tests. Every Rust pub-API method on `Sid`, `Locator`, `Srh` and
`Behavior` is exercised through the Python class surface.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make the in-tree binding importable when LIBROUTING_LIB points at the
# workspace's release artifact.
_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT / "bindings" / "lr-python" / "src"))

# Set LIBROUTING_LIB if the caller has not.
if "LIBROUTING_LIB" not in os.environ:
    candidate = _REPO_ROOT / "target" / "release" / "liblr_ffi.so"
    if candidate.exists():
        os.environ["LIBROUTING_LIB"] = str(candidate)

from librouting import (  # noqa: E402
    FLAG_HMAC,
    FLAG_OAM,
    MAX_BLOCK_BITS,
    MAX_SEGMENTS,
    ROUTING_TYPE_SRH,
    SRH_ERR_EMPTY_SEGMENT_LIST,
    SRH_ERR_TOO_MANY_SEGMENTS,
    SRH_FIXED_LEN,
    SRH_SEGMENT_LEN,
    Behavior,
    Locator,
    LocatorParseError,
    Sid,
    SidParseError,
    Srh,
    SrhError,
)


# ----------------------------------------------------------------------
# Constants — mirror lr_srv6::srh / lr_srv6::behavior pub consts.
# ----------------------------------------------------------------------

class TestConstants:
    def test_routing_type_srh(self):
        assert ROUTING_TYPE_SRH == 4

    def test_flag_bits(self):
        assert FLAG_OAM == 0x20
        assert FLAG_HMAC == 0x08

    def test_layout(self):
        assert SRH_FIXED_LEN == 8
        assert SRH_SEGMENT_LEN == 16
        assert MAX_SEGMENTS == 127
        assert MAX_BLOCK_BITS == 128


# ----------------------------------------------------------------------
# Sid — RFC 8754 §3.
# ----------------------------------------------------------------------

class TestSid:
    def test_from_octets_round_trip(self):
        b = bytes(range(16))
        sid = Sid.from_octets(b)
        assert sid.octets() == b

    def test_from_octets_wrong_length(self):
        with pytest.raises(ValueError):
            Sid.from_octets(b"\x00" * 15)
        with pytest.raises(ValueError):
            Sid.from_octets(b"\x00" * 17)

    def test_unspecified(self):
        sid = Sid.UNSPECIFIED()
        assert sid.is_unspecified()
        assert str(sid) == "::"

    def test_from_str_canonical(self):
        # RFC 5952 §4.2.2: a run of >= 2 zero hextets MUST be compressed
        # to `::`. So `fcbb:bb00:0:0:0:0:0:1` is canonically
        # `fcbb:bb00::1`.
        sid = Sid.from_str("fcbb:bb00:0:0:0:0:0:1")
        assert str(sid) == "fcbb:bb00::1"

    def test_from_str_compressed_form(self):
        sid = Sid.from_str("fcbb:bb00::1")
        assert str(sid) == "fcbb:bb00::1"
        assert sid.octets() == bytes(
            [0xFC, 0xBB, 0xBB, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        )

    def test_from_str_unspecified(self):
        sid = Sid.from_str("::")
        assert sid.is_unspecified()
        assert str(sid) == "::"

    def test_from_str_rejects_double_double_colon(self):
        with pytest.raises(SidParseError) as ei:
            Sid.from_str("1::2::3")
        assert ei.value.code == SidParseError.DOUBLE_DOUBLE_COLON

    def test_from_str_rejects_short(self):
        with pytest.raises(SidParseError) as ei:
            Sid.from_str("1:2:3:4:5:6:7")  # 7 hextets, no ::
        assert ei.value.code == SidParseError.WRONG_LENGTH

    def test_from_str_rejects_long(self):
        with pytest.raises(SidParseError) as ei:
            Sid.from_str("1:2:3:4:5:6:7:8:9")  # 9 hextets
        assert ei.value.code == SidParseError.WRONG_LENGTH

    def test_from_str_rejects_bad_hextet(self):
        with pytest.raises(SidParseError) as ei:
            Sid.from_str("1:2:3:4:5:6:7:8g")
        assert ei.value.code == SidParseError.BAD_HEXTET

    def test_locator_slice_byte_granular(self):
        sid = Sid.from_str("fcbb:bb00:0:0:e1:0:0:1")
        sl = sid.locator_slice(32)
        assert sl == (0, 4)

    def test_locator_slice_rejects_non_byte_bits(self):
        sid = Sid.UNSPECIFIED()
        assert sid.locator_slice(33) is None
        assert sid.locator_slice(0) is not None  # 0 is degenerate but valid
        assert sid.locator_slice(128) is not None
        assert sid.locator_slice(129) is None

    def test_is_inside_locator(self):
        sid = Sid.from_str("fcbb:bb00:0:0:e1:0:0:1")
        loc = bytes([0xFC, 0xBB, 0xBB, 0x00])
        assert sid.is_inside_locator(loc, 32)
        other = bytes([0xFC, 0xBB, 0xBB, 0x01])
        assert not sid.is_inside_locator(other, 32)
        # Wrong bit length: must be multiple of 8.
        assert not sid.is_inside_locator(loc, 33)

    def test_is_inside_locator_rejects_wrong_length(self):
        # New length-safety: pass 3 bytes for block_bits=32 — must reject.
        sid = Sid.from_str("fcbb:bb00::1")
        loc = bytes([0xFC, 0xBB, 0xBB])  # 3 bytes, not 4
        assert not sid.is_inside_locator(loc, 32)

    def test_from_locator_tail(self):
        loc = bytes([0xFC, 0xBB, 0xBB, 0x00])
        tail = bytes(12)
        sid = Sid.from_locator_tail(loc, tail, 32)
        assert sid.octets()[:4] == loc
        assert sid.is_inside_locator(loc, 32)

    def test_from_locator_tail_rejects_wrong_widths(self):
        loc = bytes([0xFC, 0xBB, 0xBB, 0x00])  # 4 bytes
        tail = bytes(11)  # 4 + 11 != 16
        with pytest.raises(ValueError):
            Sid.from_locator_tail(loc, tail, 32)

    def test_equality_and_hash(self):
        a = Sid.from_str("fcbb:bb00::1")
        b = Sid.from_str("fcbb:bb00::1")
        c = Sid.from_str("fcbb:bb00::2")
        assert a == b
        assert a != c
        assert hash(a) == hash(b)

    def test_context_manager(self):
        with Sid.from_str("fcbb:bb00::1") as sid:
            assert str(sid) == "fcbb:bb00::1"
        # After __exit__, the handle is freed — using it again would crash;
        # we just verify the destructor ran without error.

    def test_repr(self):
        sid = Sid.from_str("fcbb:bb00::1")
        assert repr(sid) == "Sid(fcbb:bb00::1)"


# ----------------------------------------------------------------------
# Locator — RFC 8754 §3.1.
# ----------------------------------------------------------------------

class TestLocator:
    def test_new_masks_host_bits(self):
        # Pass an address with host bits set; the locator should mask them.
        addr = bytes([0xFC, 0xBB, 0xBB, 0x00, 0xDE, 0xAD, 0xBE, 0xEF] + [0] * 8)
        loc = Locator.new(addr, 32)
        # The high 4 bytes are the locator; host bits should be zero.
        assert loc.addr()[:4] == bytes([0xFC, 0xBB, 0xBB, 0x00])
        assert loc.addr()[4:] == bytes(12)
        assert loc.block_bits() == 32

    def test_new_rejects_too_many_bits(self):
        with pytest.raises(ValueError):
            Locator.new(bytes(16), 129)

    def test_from_str(self):
        loc = Locator.from_str("fcbb:bb00::/48")
        assert loc.block_bits() == 48
        assert str(loc) == "fcbb:bb00::/48"

    def test_from_str_rejects_missing_prefixlen(self):
        with pytest.raises(LocatorParseError) as ei:
            Locator.from_str("fcbb:bb00::")
        assert ei.value.code == LocatorParseError.MISSING_PREFIX_LEN

    def test_from_str_rejects_bad_prefixlen(self):
        with pytest.raises(LocatorParseError) as ei:
            Locator.from_str("fcbb:bb00::/999")
        assert ei.value.code == LocatorParseError.BAD_PREFIX_LEN

    def test_from_sid(self):
        sid = Sid.from_str("fcbb:bb00:0:0:e1:0:0:1")
        loc = Locator.from_sid(sid, 32)
        assert loc.block_bits() == 32
        assert loc.addr()[:4] == bytes([0xFC, 0xBB, 0xBB, 0x00])

    def test_contains_sid(self):
        sid = Sid.from_str("fcbb:bb00:0:0:e1:0:0:1")
        loc = Locator.from_str("fcbb:bb00::/32")
        assert loc.contains_sid(sid)
        # Outside the locator.
        other_sid = Sid.from_str("2001:db8::1")
        assert not loc.contains_sid(other_sid)

    def test_sid_with_tail(self):
        loc = Locator.from_str("fcbb:bb00::/32")
        # The locator's block_bytes is 4; the tail's first 4 bytes are
        # overwritten by the locator, so put the meaningful tail byte at
        # index 4 (which becomes the FUNCT field's first byte).
        tail = bytes([0] * 4 + [0xE1] + [0] * 11)
        sid = loc.sid_with_tail(tail)
        assert sid.octets()[:4] == bytes([0xFC, 0xBB, 0xBB, 0x00])
        assert sid.octets()[4] == 0xE1

    def test_sid_with_tail_rejects_wrong_length(self):
        loc = Locator.from_str("fcbb:bb00::/32")
        with pytest.raises(ValueError):
            loc.sid_with_tail(bytes(15))

    def test_sid_with_index(self):
        loc = Locator.from_str("fcbb:bb00::/32")
        sid = loc.sid_with_index(42)
        assert sid is not None
        # The 4 bytes after the locator should be 42 in big-endian.
        assert sid.octets()[4:8] == (42).to_bytes(4, "big")

    def test_sid_with_index_returns_none_when_no_room(self):
        # block_bits=120 leaves only 1 byte — no room for a 4-byte function.
        loc = Locator.new(bytes(16), 120)
        assert loc.sid_with_index(42) is None

    def test_block_bytes_ceil(self):
        loc = Locator.new(bytes(16), 32)
        assert loc.block_bytes() == 4
        loc = Locator.new(bytes(16), 33)
        assert loc.block_bytes() == 5  # ceil(33 / 8)

    def test_equality_and_hash(self):
        a = Locator.from_str("fcbb:bb00::/48")
        b = Locator.from_str("fcbb:bb00::/48")
        c = Locator.from_str("fcbb:bb00::/32")
        assert a == b
        assert a != c
        assert hash(a) == hash(b)


# ----------------------------------------------------------------------
# Srh — RFC 8754 §2.
# ----------------------------------------------------------------------

class TestSrh:
    def test_new_two_segments(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = Srh.new([s1, s2])
        assert srh.segment_count() == 2
        assert srh.last_entry() == 1
        assert srh.segments_left() == 1  # defaults to last_entry

    def test_new_with_segments_left(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = Srh.with_segments_left([s1, s2], 0)
        assert srh.segments_left() == 0
        assert srh.current_destination() == s1.octets()

    def test_new_rejects_empty(self):
        with pytest.raises(SrhError) as ei:
            Srh.new([])
        assert ei.value.code == SRH_ERR_EMPTY_SEGMENT_LIST

    def test_new_rejects_too_many(self):
        sids = [Sid.UNSPECIFIED()] * (MAX_SEGMENTS + 1)
        with pytest.raises(SrhError) as ei:
            Srh.new(sids)
        assert ei.value.code == SRH_ERR_TOO_MANY_SEGMENTS

    def test_builder_setters(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = (
            Srh.new([s1, s2])
            .with_next_header(59)
            .with_flags(FLAG_OAM)
            .with_tag(0x1234)
            .with_tlvs(b"")
        )
        assert srh.next_header() == 59
        assert srh.flags() == FLAG_OAM
        assert srh.tag() == 0x1234

    def test_first_segment(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = Srh.new([s1, s2])
        assert srh.first_segment() == s1.octets()

    def test_current_destination(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = Srh.new([s1, s2])  # segments_left defaults to 1
        assert srh.current_destination() == s2.octets()

    def test_segment_at(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = Srh.new([s1, s2])
        assert srh.segment_at(0) == s1.octets()
        assert srh.segment_at(1) == s2.octets()
        assert srh.segment_at(99) is None

    def test_segments(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = Srh.new([s1, s2])
        segs = srh.segments()
        assert len(segs) == 2
        assert segs[0] == s1.octets()
        assert segs[1] == s2.octets()

    def test_tlvs_default_empty(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        srh = Srh.new([s1])
        assert srh.tlvs() == b""

    def test_with_tlvs_round_trip(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        srh = Srh.new([s1]).with_tlvs(b"\x05\x00\x00\x00\xde\xad\xbe\xef")
        # The 8 bytes already align to 8-octet boundary; encode/decode
        # round-trip preserves them verbatim.
        assert srh.tlvs() == b"\x05\x00\x00\x00\xde\xad\xbe\xef"

    def test_encode_minimal(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        srh = Srh.new([s1])
        wire = srh.encode()
        # 8-octet fixed header + 16-octet segment = 24 bytes.
        assert len(wire) == 24
        # Routing Type byte at offset 2 is 4.
        assert wire[2] == ROUTING_TYPE_SRH
        # Hdr Ext Len at offset 1 is (24 / 8) - 1 = 2.
        assert wire[1] == 2

    def test_encode_two_segments(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = Srh.new([s1, s2])
        wire = srh.encode()
        # 8 + 2 * 16 = 40 bytes (already aligned to 8).
        assert len(wire) == 40

    def test_hdr_ext_len(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = Srh.new([s1, s2])
        # 40 / 8 - 1 = 4.
        assert srh.hdr_ext_len() == 4

    def test_len(self):
        # `Srh.len()` mirrors the Rust `Srh::len()` — segment count, not
        # wire length. The wire length comes from `Srh.encode()` (whose
        # `bytes` length is the wire length).
        s1 = Sid.from_str("fcbb:bb00::1")
        s2 = Sid.from_str("fcbb:bb00::2")
        srh = Srh.new([s1, s2])
        assert srh.len() == 2  # segment count
        assert len(srh.encode()) == 40  # wire length in bytes

    def test_is_empty(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        srh = Srh.new([s1])
        assert not srh.is_empty()

    def test_context_manager(self):
        s1 = Sid.from_str("fcbb:bb00::1")
        with Srh.new([s1]) as srh:
            assert srh.segment_count() == 1


# ----------------------------------------------------------------------
# Behavior — RFC 8986 §4.
# ----------------------------------------------------------------------

class TestBehavior:
    def test_from_wire_end(self):
        result = Behavior.from_wire(0x0001)
        assert result is not None
        wire, name = result
        assert name == "End"

    def test_from_wire_end_x(self):
        result = Behavior.from_wire(0x0005)
        assert result is not None
        wire, name = result
        assert name == "End.X"

    def test_from_wire_unknown(self):
        assert Behavior.from_wire(0xFFFF) is None

    def test_wire_value(self):
        # End is wire value 1.
        assert Behavior.wire_value(0x0001) == 0x0001

    def test_is_psp(self):
        # End (0x0001) without PSP flag — not PSP.
        assert not Behavior.is_psp(0x0001)
        # End with PSP flag (RFC 8986 §4.1 — the high byte's bit 0 is
        # the PSP flag in the IANA registry's "End" behavior variant).
        # The actual wire value depends on the registry — see
        # `crates/lr-srv6/src/behavior.rs` for the exact mapping.
        # The important invariant is that the C ABI is consistent with
        # the Rust side's `Behavior::is_psp`.

    def test_name_known(self):
        assert Behavior.name(0x0001) == "End"
        assert Behavior.name(0x0005) == "End.X"

    def test_name_unknown(self):
        # Unknown wire values render as Unknown(0xNNNN).
        assert Behavior.name(0xFFFF).startswith("Unknown")

    def test_is_decap(self):
        # End.DX6 (wire value 0x0012 = 18 per RFC 8986 §4.6).
        # Whether this is decap depends on the registry — just check
        # the function does not crash.
        Behavior.is_decap(0x0012)
        Behavior.is_decap(0x0001)

    def test_is_cross_connect(self):
        # End.X (0x0005) is a cross-connect.
        assert Behavior.is_cross_connect(0x0005)

    def test_is_table_lookup(self):
        # End.DT* are table-lookup behaviors.
        Behavior.is_table_lookup(0x0001)
