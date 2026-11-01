"""Attributes container + apply_set_checked tests.

These tests exercise the Python binding through the public
``librouting.Attributes`` / ``librouting.apply_set_checked`` /
``librouting.ApplySetError`` API and mirror the C ABI tests in
``crates/lr-ffi/src/attributes.rs`` and ``crates/lr-ffi/src/policy_batch.rs``.
"""

import pytest

import librouting
from librouting import (
    APPLY_SET_ERROR_OK,
    SET_ADD_COMMUNITY,
    SET_LOCAL_PREF,
    SET_MED,
    SET_METRIC,
    SET_PREPEND_AS,
    SET_TAG,
    ApplySetError,
    Attributes,
    apply_set_checked,
    apply_set_error_name,
)
from librouting.policy import Route

PROTO_BGP = librouting.PROTO_BGP


def _v4_route():
    """Helper: build a fresh IPv4 BGP route for an attribute test."""
    return Route((bytes([203, 0, 113, 0]), 24), PROTO_BGP)


# ---- Attributes container ----


def test_attributes_new_is_empty():
    a = Attributes()
    try:
        assert len(a) == 0
        assert a.is_empty()
        assert not a
    finally:
        a.__del__()


def test_attributes_context_manager_frees_handle():
    with Attributes() as a:
        assert a.is_empty()
    # __exit__ called __del__; second call is a no-op.
    a.__del__()


def test_attributes_insert_and_get_round_trip():
    with Attributes() as a:
        a.insert(5, 0x40, b"\x00\x00\x00\x64")  # 100 as u32 BE
        assert len(a) == 1
        assert not a.is_empty()
        assert bool(a)

        entry = a.get(5)
        assert entry is not None
        flags, value = entry
        assert flags == 0x40
        assert value == b"\x00\x00\x00\x64"

        # Typed reader.
        assert a.get_u32_be(5) == 100


def test_attributes_get_returns_none_for_absent_tag():
    with Attributes() as a:
        assert a.get(99) is None


def test_attributes_get_returns_partial_when_buffer_too_small():
    """The C ABI returns the *total* length even when the caller's
    buffer is too small. The Python binding always grows its buffer to
    the full length on the second pass, so the caller sees the whole
    value — this test pins that contract."""
    with Attributes() as a:
        a.insert(7, 0, bytes(range(8)))
        entry = a.get(7)
        assert entry is not None
        flags, value = entry
        assert flags == 0
        assert value == bytes(range(8))


def test_attributes_u64_be_round_trip():
    with Attributes() as a:
        v = 0x0123_4567_89AB_CDEF
        a.insert(9, 0, v.to_bytes(8, "big"))
        assert a.get_u64_be(9) == v


def test_attributes_u8_round_trip():
    with Attributes() as a:
        a.insert(11, 0, b"*")
        assert a.get_u8(11) == 42


def test_attributes_remove_returns_presence():
    with Attributes() as a:
        a.insert(5, 0, b"\x00\x00\x00\x01")
        assert a.remove(5) is True
        assert a.remove(5) is False
        assert len(a) == 0


def test_attributes_at_round_trip():
    with Attributes() as a:
        a.insert(5, 0, b"\x00\x00\x00\x01")
        a.insert(7, 0x80, b"\x00\x00\x00\x02")
        assert len(a) == 2

        # BTreeMap ordering: tag 5 before tag 7 — index 1 is tag 7.
        entry = a.at(1)
        assert entry is not None
        tag, flags, value = entry
        assert tag == 7
        assert flags == 0x80
        assert value == b"\x00\x00\x00\x02"

        # Out of range.
        assert a.at(99) is None


def test_attributes_iter_yields_in_tag_order():
    with Attributes() as a:
        a.insert(7, 0, b"seven")
        a.insert(3, 0, b"three")
        a.insert(11, 0, b"eleven")
        tags = [tag for (tag, _flags, _value) in a]
        assert tags == [3, 7, 11]


def test_attributes_insert_replaces_on_same_tag():
    with Attributes() as a:
        a.insert(5, 0, b"\x00\x00\x00\x01")
        a.insert(5, 0x40, b"\x00\x00\x00\x02")
        assert len(a) == 1, "same tag → replace"
        assert a.get_u32_be(5) == 2, "latest value wins"
        flags, _ = a.get(5)
        assert flags == 0x40, "latest flags win"


# ---- apply_set_checked ----


def test_apply_set_error_name_known_codes():
    assert apply_set_error_name(APPLY_SET_ERROR_OK) == "ok"
    # The four no-bgp names are pinned in the C ABI; the strings are
    # stable across versions.
    assert "bgp" in apply_set_error_name(1).lower()


def test_apply_set_checked_metric_succeeds():
    """``SetMetric`` is cross-protocol and always applies; the default
    build of lr-policy has ``bgp`` on, so the four BGP-specific actions
    also succeed. Pin the cross-protocol path explicitly."""
    r = _v4_route()
    try:
        apply_set_checked(r, SET_METRIC, 42)
        assert r.metric() == 42
    finally:
        r.__del__()


def test_apply_set_checked_tag_succeeds():
    r = _v4_route()
    try:
        apply_set_checked(r, SET_TAG, 0xDEAD_BEEF)
        assert r.tag() == 0xDEAD_BEEF
    finally:
        r.__del__()


def test_apply_set_checked_local_pref_succeeds_with_bgp_feature():
    """The default build has the ``bgp`` feature on; ``SetLocalPref``
    succeeds and the value lands in the route's attribute set."""
    r = _v4_route()
    try:
        apply_set_checked(r, SET_LOCAL_PREF, 100)
        assert r.local_pref() == 100
    finally:
        r.__del__()


def test_apply_set_checked_med_succeeds_with_bgp_feature():
    r = _v4_route()
    try:
        apply_set_checked(r, SET_MED, 50)
        assert r.med() == 50
    finally:
        r.__del__()


def test_apply_set_checked_prepend_as_succeeds_with_bgp_feature():
    r = _v4_route()
    try:
        # PrependAs extends the AS path; the route's as_path picks up
        # the new ASN at the head.
        apply_set_checked(r, SET_PREPEND_AS, 65000)
        path = r.as_path()
        assert 65000 in path
    finally:
        r.__del__()


def test_apply_set_checked_add_community_succeeds_with_bgp_feature():
    r = _v4_route()
    try:
        apply_set_checked(r, SET_ADD_COMMUNITY, 65000, 1)
        comms = r.communities()
        # The community is encoded as a u64 with the ASN in the high
        # 16 bits and the value in the low 16 bits.
        encoded = (65000 << 16) | 1
        assert encoded in comms
    finally:
        r.__del__()


def test_apply_set_checked_unknown_kind_raises():
    """An invalid set_kind returns ``APPLY_SET_ERROR_UNKNOWN`` and the
    Python binding raises :class:`ApplySetError`."""
    r = _v4_route()
    try:
        with pytest.raises(ApplySetError) as exc_info:
            apply_set_checked(r, 99)
        assert exc_info.value.code == librouting.APPLY_SET_ERROR_UNKNOWN
    finally:
        r.__del__()
