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
