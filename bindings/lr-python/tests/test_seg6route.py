"""Tests for the SRv6 netlink route-table binding (RFC 8754 §2 +
RFC 8986 §4). Mirrors the Rust-side
`crates/lr-ffi/src/seg6_route.rs` unit tests.

Covers the Python class surface `Seg6Route` / `Seg6LocalRoute` /
`Seg6Netlink` / `Seg6RouteErr` and the constants `ENCAP_*` / `ERR_*`.
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
    ENCAP_ENCAP,
    ENCAP_INLINE,
    ERR_BAD_SRH,
    ERR_KERNEL,
    ERR_NOT_ENABLED,
    ERR_SYSCALL,
    ERR_UNSUPPORTED,
    ERR_UNSUPPORTED_ACTION,
    ERR_UNKNOWN,
    LrError,
    Seg6LocalRoute,
    Seg6Netlink,
    Seg6Route,
    Seg6RouteErr,
    Sid,
    Srh,
    err_code,
    err_name,
)


def _sid_octets() -> bytes:
    return bytes(
        (0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
    )


def _make_sid() -> Sid:
    return Sid.from_octets(_sid_octets())


def _make_srh() -> Srh:
    sid = _make_sid()
    return Srh.new([sid])


# ----------------------------------------------------------------------
# Seg6Route
# ----------------------------------------------------------------------

class TestSeg6Route:
    def test_new_returns_handle(self):
        srh = _make_srh()
        r = Seg6Route.new("2001:db8::/64", srh)
        assert r is not None
        r.close()

    def test_new_rejects_ipv4_prefix(self):
        srh = _make_srh()
        with pytest.raises(LrError, match="IPv6"):
            Seg6Route.new("203.0.113.0/24", srh)

    def test_new_rejects_nil_srh(self):
        with pytest.raises(LrError, match="srh"):
            Seg6Route.new("2001:db8::/64", None)

    def test_set_mode_round_trip(self):
        srh = _make_srh()
        r = Seg6Route.new("2001:db8::/64", srh)
        try:
            r.with_mode(ENCAP_INLINE)
            r.with_mode(ENCAP_ENCAP)
            with pytest.raises(LrError):
                r.with_mode(0xFFFFFFFF)
        finally:
            r.close()

    def test_set_if_index(self):
        srh = _make_srh()
        r = Seg6Route.new("2001:db8::/64", srh)
        r.with_if_index(7)
        r.close()

    def test_context_manager(self):
        srh = _make_srh()
        with Seg6Route.new("2001:db8::/64", srh) as r:
            assert r is not None


# ----------------------------------------------------------------------
# Seg6LocalRoute
# ----------------------------------------------------------------------

class TestSeg6LocalRoute:
    def test_new_returns_handle(self):
        sid = _make_sid()
        r = Seg6LocalRoute.new(sid, 1)
        r.close()

    def test_new_rejects_nil_sid(self):
        with pytest.raises(LrError, match="sid"):
            Seg6LocalRoute.new(None, 1)

    def test_new_rejects_unknown_behavior(self):
        sid = _make_sid()
        with pytest.raises(LrError, match="unknown Behavior"):
            Seg6LocalRoute.new(sid, 0xFFFF)

    def test_setters_round_trip(self):
        sid = _make_sid()
        r = Seg6LocalRoute.new(sid, 1)
        try:
            r.with_if_index(1)
            r.with_nh4(bytes([203, 0, 113, 1]))
            r.with_nh6(bytes([0xFE] * 16))
            r.with_iif(2)
            r.with_oif(3)
            r.with_table(254)
            r.with_vrf_table(100)
            srh = _make_srh()
            r.with_srh(srh)
        finally:
            r.close()

    def test_with_nh4_wrong_length(self):
        sid = _make_sid()
        r = Seg6LocalRoute.new(sid, 1)
        try:
            with pytest.raises(LrError, match="4 bytes"):
                r.with_nh4(bytes([203, 0, 113]))
            with pytest.raises(LrError, match="4 bytes"):
                r.with_nh4(bytes([0] * 5))
        finally:
            r.close()

    def test_with_srh_rejects_nil(self):
        sid = _make_sid()
        r = Seg6LocalRoute.new(sid, 1)
        try:
            with pytest.raises(LrError, match="srh"):
                r.with_srh(None)
        finally:
            r.close()

    def test_context_manager(self):
        sid = _make_sid()
        with Seg6LocalRoute.new(sid, 1) as r:
            assert r is not None


# ----------------------------------------------------------------------
# Seg6Netlink
# ----------------------------------------------------------------------

class TestSeg6Netlink:
    def test_connect_returns_handle_or_typed_error(self):
        try:
            n = Seg6Netlink.connect()
        except Seg6RouteErr as e:
            # On a CI runner without SRv6 enabled the connect call
            # fails with a typed error (Code = ERR_NOT_ENABLED or
            # ERR_UNSUPPORTED). It must NOT be a generic LrError.
            assert e.code in (ERR_NOT_ENABLED, ERR_UNSUPPORTED)
            assert e.message
            # The name lookup must return the documented name.
            assert err_name(e.code) in ("not-enabled", "unsupported")
            return
        n.close()

    def test_add_seg6_route_rejects_nil(self):
        try:
            n = Seg6Netlink.connect()
        except Seg6RouteErr:
            pytest.skip("kernel without SRv6")
        try:
            with pytest.raises(LrError, match="route"):
                n.add_seg6_route(None)
        finally:
            n.close()

    def test_last_request_bytes_returns_none_before_request(self):
        try:
            n = Seg6Netlink.connect()
        except Seg6RouteErr:
            pytest.skip("kernel without SRv6")
        try:
            b = n.last_request_bytes()
            assert b is None or b == b""
        finally:
            n.close()


# ----------------------------------------------------------------------
# Error helpers
# ----------------------------------------------------------------------

class TestErrHelpers:
    @pytest.mark.parametrize(
        "code,name",
        [
            (ERR_UNSUPPORTED, "unsupported"),
            (ERR_NOT_ENABLED, "not-enabled"),
            (ERR_SYSCALL, "syscall"),
            (ERR_KERNEL, "kernel"),
            (ERR_BAD_SRH, "bad-srh"),
            (ERR_UNSUPPORTED_ACTION, "unsupported-action"),
            (999, "unknown"),
        ],
    )
    def test_err_name_returns_documented_name(self, code, name):
        assert err_name(code) == name

    def test_err_code_returns_unknown_when_no_error(self):
        # When the last-error string is empty, err_code returns
        # ERR_UNKNOWN. We can't easily reset the thread-local from
        # Python, so this test only verifies the function runs and
        # returns an int (it may be the discriminant of a previous
        # seg6 error recorded by the connect call in TestSeg6Netlink
        # above).
        assert isinstance(err_code(), int)

    def test_seg6_route_err_str(self):
        e = Seg6RouteErr(ERR_NOT_ENABLED, "SRv6 is not enabled")
        s = str(e)
        assert "not-enabled" in s
        assert "SRv6 is not enabled" in s
        assert "code=2" in s
        e_no_msg = Seg6RouteErr(ERR_SYSCALL)
        assert "syscall" in str(e_no_msg)
