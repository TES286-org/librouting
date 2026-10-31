"""Tests for the Python RTR client binding (RFC 8210 §6-§8)."""

from __future__ import annotations

import librouting
from librouting import (
    RtrClient,
    RtrClientStep,
    RtrRoaDelta,
    RtrRoaEntry,
)


def test_rtr_client_fresh_client_readers():
    """The readers on a freshly-constructed client return the
    documented cold-start state (mirrors the FFI test in
    `crates/lr-ffi/src/rtr_client.rs`)."""
    with RtrClient() as c:
        assert c.version() != 0
        assert c.session_id() is None
        assert c.serial() is None
        assert c.phase_name() == "awaiting-reset"
        assert c.intervals() == (3600, 600, 7200)

        c.set_intervals(100, 60, 600)
        assert c.intervals() == (100, 60, 600)

        # on_connect emits an 8-byte Reset Query (RFC 8210 §5.3).
        bytes_out = c.on_connect()
        assert len(bytes_out) == 8
        # Type byte is at offset 1 — value 2 (Reset Query).
        assert bytes_out[1] == 2

        # poll on a fresh client returns an empty step.
        with c.poll(0) as step:
            assert isinstance(step, RtrClientStep)
            assert step.synced is False
            assert step.expired is False
            assert step.roa_delta_count == 0
            assert step.log_count == 0
            assert step.send_bytes == b""
            assert step.roa_delta_at(0) is None
            assert step.log_at(0) is None
            assert step.roa_deltas == []
            assert step.logs == []

        # snapshot on a fresh client is empty.
        assert c.snapshot() == []


def test_rtr_client_step_close_is_idempotent():
    """`RtrClientStep.close` is idempotent — the underlying C arrays
    are freed exactly once even when the caller calls close twice."""
    with RtrClient() as c:
        step = c.poll(0)
        step.close()
        step.close()  # second close is a no-op
        # After close, the step's accessors still return their
        # zero-state (the underlying C struct's fields are cleared
        # by `lr_rtr_client_step_free`).
        assert step.roa_delta_count == 0
        assert step.log_count == 0


def test_rtr_client_step_with_statement():
    """`RtrClientStep` supports the `with` block — close runs on
    exit and frees the underlying C arrays."""
    with RtrClient() as c:
        step = c.poll(0)
        with step:
            assert step.synced is False
        # After the with-block the underlying C arrays are freed.
        # `close` again is a no-op.
        step.close()


def test_rtr_client_step_after_cache_response():
    """Drive one Cache Response PDU through `on_pdu_raw`, then
    verify the step returned by the subsequent `poll` reflects the
    not-yet-synced state.

    The full-wire test that exercises End-of-Data with two ROA
    deltas lives in the Rust FFI test suite
    (`ffi_rtr_client_step_roa_deltas_after_full_sync`), since the
    encoder surface that produces a v1 EoD PDU is not yet exposed
    through the C ABI."""
    with RtrClient() as c:
        # RFC 8210 §5.4 Cache Response: version 1, type 3,
        # length 8, session ID 0x00ff.
        cache_resp = bytes(
            [
                0x01,  # version 1
                0x03,  # type 3 = Cache Response
                0x00,
                0x00,  # reserved
                0x00,
                0x00,
                0x00,
                0x08,  # length 8
                0x00,
                0xFF,  # session ID 0x00ff
            ]
        )
        with c.on_pdu_raw(cache_resp, 1_000) as step:
            assert step.synced is False
            assert step.roa_delta_count == 0

        # poll after the cache response — still no deltas (we have
        # not hit End of Data yet).
        with c.poll(1_500) as step:
            assert step.synced is False
            assert step.roa_delta_count == 0


def test_rtr_client_roa_delta_dataclass_shape():
    """`RtrRoaDelta` and `RtrRoaEntry` are immutable dataclasses —
    their fields match the C ABI's `lr_roa_delta_t` / `lr_roa_entry_t`."""
    entry = RtrRoaEntry(
        addr=bytes([192, 0, 2, 0]),
        prefix_len=24,
        max_length=24,
        asn=64512,
    )
    assert entry.is_ipv6 is False
    assert entry.prefix == "192.0.2.0"
    assert entry.network.with_prefixlen == "192.0.2.0/24"
    delta = RtrRoaDelta(announce=True, entry=entry)
    assert delta.announce is True
    assert delta.entry.asn == 64512


def test_rtr_client_handles_garbage_in_on_pdu_raw():
    """`on_pdu_raw` raises `LrError` on a malformed PDU — the codec
    rejects truncated input."""
    import pytest
    from librouting.router import LrError

    with RtrClient() as c:
        # Truncated Cache Response (header says length 8 but only
        # 4 bytes follow).
        truncated = bytes([0x01, 0x03, 0x00, 0x00])
        with pytest.raises(LrError):
            c.on_pdu_raw(truncated, 1_000)
        # Empty data raises immediately (the binding refuses to
        # construct a zero-length C pointer slice).
        with pytest.raises(LrError):
            c.on_pdu_raw(b"", 1_000)
