"""RTR client bindings (RFC 8210 §6-§8 RPKI-Router protocol).

`RtrClient` wraps the C `lr_rtr_client_t`: a transport-agnostic
state machine that drives the RPKI-Router protocol from the client
side. The embedder owns the TCP connection, the clock and the live
`RoaStore`; the `RtrClient` owns the protocol — `on_connect`
returns the initial query, `on_pdu_raw` advances per received PDU,
`poll` advances per the §6 timing rules.

The Python projection of `ClientStep` exposes the wire bytes, the
ROA deltas and the diagnostic log lines as Python-native types
(`bytes`, `RoaDelta` and `str`); the underlying C arrays are freed
when the `RtrClientStep` is garbage-collected or closed explicitly.

Mirrors `lr_bgp::rtr::client::{RtrClient, ClientStep, RoaDelta}`.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._ffi import ffi, get_lib
from .roa import _parse_network
from .router import LrError, last_error


@dataclass(frozen=True)
class RoaEntry:
    """One ROA record (RFC 6482 §3): authorized prefix, max length,
    origin AS. AS 0 marks the blackhole range (RFC 6483 §4)."""

    addr: bytes  # 4 bytes (IPv4) or 16 bytes (IPv6)
    prefix_len: int
    max_length: int
    asn: int

    @property
    def is_ipv6(self) -> bool:
        return len(self.addr) == 16

    @property
    def network(self):
        """The network as an `ipaddress.IPv4Network` or
        `IPv6Network`. Computed from `addr` + `prefix_len` (the
        C ABI's representation), so the property is non-recursive."""
        import ipaddress

        if self.is_ipv6:
            return ipaddress.IPv6Network((self.addr, self.prefix_len), strict=False)
        return ipaddress.IPv4Network((self.addr[:4], self.prefix_len), strict=False)

    @property
    def prefix(self) -> str:
        """The address part as a string (no `/prefixlen` suffix).
        For `192.0.2.0/24` returns `"192.0.2.0"`."""
        return str(self.network.network_address)


@dataclass(frozen=True)
class RoaDelta:
    """One record delta of a completed RTR sync (RFC 8210 §5.6/§5.7).
    `announce=True` is an announcement; `announce=False` is a
    withdrawal. The record is the same `RoaEntry` shape the
    `RoaStore.apply_deltas` Python API takes."""

    announce: bool
    entry: RoaEntry


def _entry_to_py(e) -> RoaEntry:
    is_ipv6 = bool(e.is_ipv6)
    if is_ipv6:
        addr = bytes(e.addr[i] for i in range(16))
    else:
        addr = bytes(e.addr[i] for i in range(4))
    return RoaEntry(
        addr=addr,
        prefix_len=int(e.prefix_len),
        max_length=int(e.max_length),
        asn=int(e.asn),
    )


class RtrClientStep:
    """Projection of one RTR protocol step — what the embedder should
    do after one state machine transition. Owns the wire bytes
    (`send_bytes`), the ROA deltas and the diagnostic log lines.
    All three are freed by `close` (or the garbage collector)."""

    __slots__ = ("_step", "_freed")

    def __init__(self, step):
        # The cffi handle is owned by this Python object. We keep a
        # reference so the GC does not collect the underlying C
        # struct until close() runs.
        self._step = step
        self._freed = False

    def __del__(self):
        self.close()

    def __enter__(self) -> "RtrClientStep":
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        if not self._freed and getattr(self, "_step", None) is not None:
            get_lib().lr_rtr_client_step_free(self._step)
            self._freed = True

    @property
    def synced(self) -> bool:
        """True when this step completed a sync (End of Data)."""
        return bool(self._step.synced)

    @property
    def drop(self) -> bool:
        """True when the transport connection should be closed."""
        return bool(self._step.drop)

    @property
    def expired(self) -> bool:
        """True when the last synced data exceeded its expire interval
        without a successful poll (§6) — validation must stop."""
        return bool(self._step.expired)

    @property
    def send_bytes(self) -> bytes:
        """Wire bytes to transmit (zero or more complete PDUs).
        Returns empty `bytes` when the step carries no outgoing PDU."""
        b = self._step.send_bytes
        n = int(b.len)
        if n == 0:
            return b""
        return bytes(ffi.buffer(b.ptr, n))

    @property
    def roa_delta_count(self) -> int:
        """Number of ROA deltas in this step (zero unless `synced`)."""
        return int(self._step.roa_delta_count)

    @property
    def log_count(self) -> int:
        """Number of diagnostic log lines the state machine produced."""
        return int(self._step.log_count)

    def roa_delta_at(self, i: int) -> RoaDelta | None:
        """Read the i-th ROA delta. Returns `None` on an out-of-bounds
        index or when the underlying array is empty."""
        if i < 0 or i >= self.roa_delta_count:
            return None
        out = ffi.new("lr_roa_delta_t*")
        rc = get_lib().lr_rtr_client_step_roa_delta_at(self._step, i, out)
        if rc != 0:
            return None
        return RoaDelta(
            announce=bool(out.announce),
            entry=_entry_to_py(out.entry),
        )

    @property
    def roa_deltas(self) -> list[RoaDelta]:
        """All ROA deltas in the step as a list."""
        n = self.roa_delta_count
        if n == 0:
            return []
        out: list[RoaDelta] = []
        for i in range(n):
            d = self.roa_delta_at(i)
            if d is None:
                break
            out.append(d)
        return out

    def log_at(self, i: int) -> str | None:
        """Read the i-th log line. Returns `None` on an out-of-bounds
        index or when the underlying array is empty."""
        if i < 0 or i >= self.log_count:
            return None
        need = int(get_lib().lr_rtr_client_step_log_at(self._step, i, ffi.NULL, 0))
        if need == 0:
            return None
        buf = ffi.new(f"uint8_t[{need + 1}]")
        n = int(get_lib().lr_rtr_client_step_log_at(self._step, i, buf, need + 1))
        if n == 0:
            return None
        return ffi.buffer(buf, n)[:].decode("utf-8", "replace")

    @property
    def logs(self) -> list[str]:
        """All log lines in the step as a list of `str`."""
        n = self.log_count
        if n == 0:
            return []
        out: list[str] = []
        for i in range(n):
            s = self.log_at(i)
            if s is None:
                break
            out.append(s)
        return out


class RtrClient:
    """Transport-agnostic RTR client state machine (RFC 8210 §6-§8).
    The embedder owns the TCP connection, the clock and the live
    `RoaStore`; the client owns the protocol."""

    def __init__(self):
        ptr = get_lib().lr_rtr_client_new()
        if not ptr:
            raise LrError("lr_rtr_client_new failed")
        self._ptr = ptr

    def __del__(self):
        ptr = getattr(self, "_ptr", None)
        if ptr:
            get_lib().lr_rtr_client_free(ptr)
            self._ptr = None

    def __enter__(self) -> "RtrClient":
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr:
            get_lib().lr_rtr_client_free(ptr)
            self._ptr = None

    def version(self) -> int:
        """The protocol version currently spoken (post-§7 downgrade)."""
        return int(get_lib().lr_rtr_client_version(self._ptr))

    def session_id(self) -> int | None:
        """The remembered session ID, or `None` until the first Cache
        Response (RFC 8210 §8.2)."""
        out = ffi.new("uint16_t*")
        if get_lib().lr_rtr_client_session_id(self._ptr, out) == 0:
            return None
        return int(out[0])

    def serial(self) -> int | None:
        """The serial of the last completed sync, or `None`."""
        out = ffi.new("uint32_t*")
        if get_lib().lr_rtr_client_serial(self._ptr, out) == 0:
            return None
        return int(out[0])

    def phase_name(self) -> str:
        """Phase name for diagnostics: "awaiting-reset",
        "awaiting-serial", "receiving" or "synced"."""
        need = int(get_lib().lr_rtr_client_phase_name(self._ptr, ffi.NULL, 0))
        if need == 0:
            return ""
        buf = ffi.new(f"uint8_t[{need + 1}]")
        n = int(get_lib().lr_rtr_client_phase_name(self._ptr, buf, need + 1))
        if n == 0:
            return ""
        return ffi.buffer(buf, n)[:].decode("utf-8", "replace")

    def intervals(self) -> tuple[int, int, int]:
        """§6 timing intervals (refresh, retry, expire — seconds)."""
        r = ffi.new("uint32_t*")
        re = ffi.new("uint32_t*")
        e = ffi.new("uint32_t*")
        rc = get_lib().lr_rtr_client_intervals(self._ptr, r, re, e)
        if rc != 0:
            raise LrError(f"lr_rtr_client_intervals failed (rc={rc}): {last_error()}")
        return int(r[0]), int(re[0]), int(e[0])

    def set_intervals(self, refresh: int, retry: int, expire: int) -> None:
        """Override the initial §6 intervals. A v1+ cache replaces
        all three from every End-of-Data PDU (§6), so this only
        shapes behaviour before the first End of Data and for v0
        caches."""
        rc = get_lib().lr_rtr_client_set_intervals(
            self._ptr, int(refresh), int(retry), int(expire)
        )
        if rc != 0:
            raise LrError(f"lr_rtr_client_set_intervals failed (rc={rc}): {last_error()}")

    def on_connect(self) -> bytes:
        """Bytes to transmit when the transport comes up (§8.1): a
        Serial Query when the client remembers an unexpired session,
        a Reset Query otherwise."""
        out = ffi.new("lr_bytes_t*")
        rc = get_lib().lr_rtr_client_on_connect(self._ptr, out)
        if rc != 0:
            raise LrError(f"lr_rtr_client_on_connect failed (rc={rc}): {last_error()}")
        n = int(out.len)
        data = bytes(ffi.buffer(out.ptr, n)) if n > 0 else b""
        get_lib().lr_bytes_free(out)
        return data

    def poll(self, now_ms: int) -> RtrClientStep:
        """Run the §6 timing rules at `now_ms` (milliseconds since the
        Unix epoch). Returns the projection of "what to do next" —
        the caller is expected to drain the returned step (`with`
        block, `close`, or rely on the finalizer)."""
        step = ffi.new("lr_rtr_client_step_t*")
        rc = get_lib().lr_rtr_client_poll(self._ptr, int(now_ms), step)
        if rc != 0:
            raise LrError(f"lr_rtr_client_poll failed (rc={rc}): {last_error()}")
        return RtrClientStep(step)

    def on_pdu_raw(self, data: bytes, now_ms: int) -> RtrClientStep:
        """Decode one RTR PDU from `data` and feed it to the client
        (RFC 8210 §5 / §8.2 — the receive-side entry point). Returns
        the same projection as `poll`."""
        if not data:
            raise LrError("on_pdu_raw: data is empty")
        step = ffi.new("lr_rtr_client_step_t*")
        rc = get_lib().lr_rtr_client_on_pdu_raw(
            self._ptr,
            ffi.from_buffer(data) if isinstance(data, bytes) else data,
            len(data),
            int(now_ms),
            step,
        )
        if rc != 0:
            raise LrError(f"lr_rtr_client_on_pdu_raw failed (rc={rc}): {last_error()}")
        return RtrClientStep(step)

    def snapshot(self) -> list[RoaEntry]:
        """Read the authoritative ROA record set after the last
        completed sync, sorted for deterministic snapshots.
        Returns an empty list on a fresh client or one whose first
        sync has not yet completed."""
        n = int(get_lib().lr_rtr_client_snapshot(self._ptr, ffi.NULL, 0))
        if n == 0:
            return []
        c_entries = ffi.new("lr_roa_entry_t[]", n)
        got = int(get_lib().lr_rtr_client_snapshot(self._ptr, c_entries, n))
        if got == 0:
            return []
        return [_entry_to_py(c_entries[i]) for i in range(got)]
