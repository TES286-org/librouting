"""Pytest suite for the ``PeerHealthTable`` generated wrapper (issue #99).

The peer-health C ABI surface (``lr_peer_health_table_t`` handle, 9 entry
points) was added as part of issue #99 but the generated Python wrapper
had no dedicated test — the generic ``test_generated.py`` smoke suite
exercises the constructor's RAII lifecycle but does not drive the state
machine. This module closes that gap with an end-to-end test that:

- constructs a ``PeerHealthTable`` with a full-rollout config,
- accounts a burst of UPDATEs to escalate the peer past L0,
- verifies the tier query returns > 0 after the burst,
- reads back a session snapshot and checks the counters,
- confirms the degraded-count aggregate tracks the escalation,
- runs a tick and confirms it returns without error,
- frees the table (and double-free is a safe no-op).
"""

from __future__ import annotations

import pytest

from librouting._ffi import ffi
from librouting.generated import PeerHealthTable
from librouting.router import LrError


# AFI / SAFI constants matching the C side (IANA).
AFI_IPV4 = 1
SAFI_UNICAST = 1

# Rollout mode discriminants (lr_peer_health::RolloutMode).
ROLLOUT_FULL = 5


def _full_cfg_ptr():
    """Build a ``lr_peer_health_config_t`` with Full rollout and tight
    windows so a modest burst escalates the peer within the test."""
    cfg = ffi.new("struct lr_peer_health_config_t *")
    cfg.rollout = ROLLOUT_FULL
    cfg.short_window_s = 5
    cfg.mid_window_s = 30
    cfg.long_window_s = 120
    cfg.baseline_window_s = 480
    cfg.min_transition_interval_s = 0
    cfg.min_recovery_interval_s = 0
    cfg.max_stale_age_s = 60
    cfg.tick_interval_s = 1
    cfg.soft_degraded = 100
    cfg.hard_degraded = 0
    return cfg


def _train_then_burst(table, peer, burst_count=200):
    """Seed the baseline at 1 event/sec for 10s, then burst."""
    for i in range(10):
        table.account_update(peer, AFI_IPV4, SAFI_UNICAST, i * 1000)
    now = 10_000
    for _ in range(burst_count):
        table.account_update(peer, AFI_IPV4, SAFI_UNICAST, now)
        now += 10
    return now


def test_peer_health_table_construct_and_free():
    """The table constructs with a valid config and frees cleanly."""
    cfg = _full_cfg_ptr()
    t = PeerHealthTable.new(cfg)
    try:
        assert t.ptr != ffi.NULL
        assert t.session_count() == 0
    finally:
        t.free()
    # Double free is a safe no-op.
    t.free()


def test_peer_health_null_config_raises():
    """A null config pointer makes ``new`` raise ``LrError``."""
    with pytest.raises(LrError):
        PeerHealthTable.new(ffi.NULL)


def test_peer_health_escalation_and_tier_query():
    """A burst of UPDATEs escalates the peer; ``tier`` returns > 0."""
    cfg = _full_cfg_ptr()
    t = PeerHealthTable.new(cfg)
    try:
        _train_then_burst(t, peer=1)
        tier = t.tier(1, AFI_IPV4, SAFI_UNICAST)
        assert tier > 0, f"peer should be degraded after burst, got tier={tier}"
        # The session exists.
        assert t.session_count() >= 1
        # At least one session is degraded.
        assert t.degraded_count() >= 1
    finally:
        t.free()


def test_peer_health_session_snapshot_counters():
    """The session snapshot reports the UPDATE counter and tier."""
    cfg = _full_cfg_ptr()
    t = PeerHealthTable.new(cfg)
    try:
        _train_then_burst(t, peer=1, burst_count=50)
        out = ffi.new("struct lr_peer_health_session_t *")
        rc = t.session_snapshot(1, AFI_IPV4, SAFI_UNICAST, out)
        assert rc == 0, "session_snapshot should return 0 on success"
        assert out.peer_id == 1
        assert out.afi == AFI_IPV4
        assert out.safi == SAFI_UNICAST
        assert out.updates >= 50, f"updates counter should be >= 50, got {out.updates}"
        # The tier in the snapshot is the internal tier (after the
        # effective_tier cap); in Full mode it matches the public tier.
        assert out.tier == t.tier(1, AFI_IPV4, SAFI_UNICAST)
    finally:
        t.free()


def test_peer_health_snapshot_unknown_session_returns_error():
    """A snapshot for an unseen session returns a negative error code."""
    cfg = _full_cfg_ptr()
    t = PeerHealthTable.new(cfg)
    try:
        out = ffi.new("struct lr_peer_health_session_t *")
        with pytest.raises(LrError):
            t.session_snapshot(999, AFI_IPV4, SAFI_UNICAST, out)
    finally:
        t.free()


def test_peer_health_tick_runs_without_error():
    """A periodic tick transitions tiers and sweeps stale prefixes."""
    cfg = _full_cfg_ptr()
    t = PeerHealthTable.new(cfg)
    try:
        final_ms = _train_then_burst(t, peer=1)
        # A tick at the same instant is a no-op or transitions; either
        # way it must not error.
        changes = t.tick(final_ms + 60_000)
        assert isinstance(changes, int)
    finally:
        t.free()


def test_peer_health_off_mode_never_degrades():
    """In Off mode (rollout=0) the table accounts nothing and tier stays 0."""
    cfg = _full_cfg_ptr()
    cfg.rollout = 0  # Off
    t = PeerHealthTable.new(cfg)
    try:
        _train_then_burst(t, peer=1)
        assert t.tier(1, AFI_IPV4, SAFI_UNICAST) == 0
        assert t.session_count() == 0
        assert t.degraded_count() == 0
    finally:
        t.free()
