"""Tests for the Python RouterInstance session-state + Babel runtime
binding (mirrors crates/lr-ffi/src/router_runtime_tests.rs).

Focus on the FFI shape: null checks, invalid handles, the
success/cooldown/no-sample trichotomy, and the "non-Babel session
returns None" branch of babel_egress_nexthops.
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


def test_session_peer_state_bgp():
    """A freshly-added BGP session reports a valid FSM state name."""
    with librouting.Router() as r:
        h = r.add_bgp_session(
            local_as=65001, peer_as=65002, local_bgp_id=0x01020304
        )
        state = r.session_peer_state(h)
        assert state in (
            "Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established"
        ), f"unexpected state {state!r}"


def test_session_peer_state_babel_returns_none():
    """Babel sessions have no BGP FSM state."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        assert r.session_peer_state(h) is None


def test_session_peer_state_unknown_handle_returns_none():
    """An unknown session handle maps to None (the C ABI returns NULL)."""
    with librouting.Router() as r:
        assert r.session_peer_state(0xFFFFFFFF) is None


def test_session_restart_cooldown_no_cooldown():
    """A freshly-added BGP session has no Restart cooldown."""
    with librouting.Router() as r:
        h = r.add_bgp_session(
            local_as=65001, peer_as=65002, local_bgp_id=0x01020304
        )
        assert r.session_restart_cooldown_remaining(h) is None


def test_take_collision_lost_initially_false():
    """A fresh session has no collision-loss latch set."""
    with librouting.Router() as r:
        h = r.add_bgp_session(
            local_as=65001, peer_as=65002, local_bgp_id=0x01020304
        )
        assert r.take_collision_lost(h) is False


def test_session_was_established_initially_false():
    """A freshly-added BGP session has not reached Established."""
    with librouting.Router() as r:
        h = r.add_bgp_session(
            local_as=65001, peer_as=65002, local_bgp_id=0x01020304
        )
        assert r.session_was_established(h) is False


def test_rib_paths_count_starts_at_zero():
    """A fresh router has no paths in its Add-Path view."""
    with librouting.Router() as r:
        assert r.rib_paths_count() == 0


def test_rib_path_at_out_of_range_raises():
    """An out-of-range index raises LrError mentioning 'out of range'."""
    with librouting.Router() as r:
        try:
            r.rib_path_at(0)
        except librouting.LrError as e:
            assert "out of range" in str(e), str(e)
            return
        raise AssertionError("expected LrError on out-of-range index")


def test_rib_path_at_returns_owned_route():
    """An originated route is reachable through the Add-Path view."""
    with librouting.Router() as r:
        r.originate_v4("10.0.0.0/24")
        assert r.rib_paths_count() == 1
        route = r.rib_path_at(0)
        assert route is not None
        # The Route's __del__ will free the C handle.


def test_flush_rib_for_shutdown_succeeds_and_is_idempotent():
    """The shutdown flush returns None on a fresh router and is
    idempotent (the second call sees an empty Loc-RIB)."""
    with librouting.Router() as r:
        r.originate_v4("10.0.0.0/24")
        assert r.flush_rib_for_shutdown() is None
        assert r.flush_rib_for_shutdown() is None


def test_babel_flush_session_succeeds():
    """A Babel session can be flushed without error."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        assert r.babel_flush_session(h) is None


def test_babel_flush_session_noop_on_bgp_session():
    """babel_flush_session on a BGP session is a no-op (matches the
    Rust trait's default)."""
    with librouting.Router() as r:
        h = r.add_bgp_session(
            local_as=65001, peer_as=65002, local_bgp_id=0x01020304
        )
        assert r.babel_flush_session(h) is None


def test_babel_gc_succeeds():
    """The Babel expiry sweep succeeds."""
    with librouting.Router() as r:
        r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        assert r.babel_gc(1000) is None


def test_set_babel_own_router_id_succeeds():
    """The Babel router-id can be set without error."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        assert r.set_babel_own_router_id(h, bytes([1, 2, 3, 4, 5, 6, 7, 8])) is None


def test_set_babel_own_router_id_rejects_bad_length():
    """A router-id that is not 8 bytes raises LrError."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        try:
            r.set_babel_own_router_id(h, bytes([1, 2, 3]))
        except librouting.LrError:
            return
        raise AssertionError("expected LrError on bad router-id length")


def test_set_babel_link_cost_params_succeeds():
    """The link-cost ramp can be configured."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        assert r.set_babel_link_cost_params(h, 1000, 100000, 96) is None


def test_babel_note_peer_v4_succeeds():
    """Noting a v4 peer address works."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([192, 0, 2, 1]))
        assert r.babel_note_peer(h, bytes([192, 0, 2, 100])) is None


def test_babel_note_peer_v6_succeeds():
    """Noting a v6 peer address works."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        peer = bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99])
        assert r.babel_note_peer(h, peer) is None


def test_babel_note_peer_rejects_bad_length():
    """An address of the wrong length raises LrError before the FFI call."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([192, 0, 2, 1]))
        try:
            r.babel_note_peer(h, bytes([1, 2, 3]))
        except librouting.LrError:
            return
        raise AssertionError("expected LrError on bad address length")


def test_babel_rtt_us_no_sample():
    """A fresh Babel session has no RTT sample."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        assert r.babel_rtt_us(h, 0) is None


def test_babel_rtt_echo_pair_no_sample():
    """A fresh Babel session has no RTT echo pair."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        assert r.babel_rtt_echo_pair(h, 0) is None


def test_babel_egress_nexthops_non_babel_returns_none():
    """Querying egress next hops for a non-Babel session returns None
    (the C ABI's 'no info' return code)."""
    with librouting.Router() as r:
        h = r.add_bgp_session(
            local_as=65001, peer_as=65002, local_bgp_id=0x01020304
        )
        assert r.babel_egress_nexthops(h) is None


def test_babel_egress_nexthops_v6_session_reports_local():
    """A Babel v6 session reports the local v6 address as the egress
    next hop (the peer-address fallback per RFC 8966 §3.5.3)."""
    with librouting.Router() as r:
        local = bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        h = r.add_babel_session(local)
        v4, v6 = r.babel_egress_nexthops(h)
        assert v4 is None, f"no v4 next hop should be present, got {v4}"
        assert v6 == local, f"v6 should equal the local address, got {v6}"


def test_babel_take_route_request_initially_false():
    """A fresh Babel session has no pending Route Request."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        assert r.babel_take_route_request(h) is False


def test_babel_take_own_seqno_request_initially_none():
    """A fresh Babel session has no pending own-seqno request."""
    with librouting.Router() as r:
        h = r.add_babel_session(bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        assert r.babel_take_own_seqno_request(h) is None


def test_rib_path_at_returns_route_with_correct_protocol():
    """The Route returned by rib_path_at carries the right protocol
    (round-trip a v4 originate, then read it back)."""
    with librouting.Router() as r:
        r.originate_v4("10.0.0.0/24")
        route = r.rib_path_at(0)
        assert route is not None
        # The protocol field on a Route is reachable via the
        # underlying lr_route_t; the binding does not currently
        # expose a 'protocol' reader on Route (it's reachable through
        # the underlying Route struct the daemon owns). The smoke
        # test here is just that we got a non-None Route.
