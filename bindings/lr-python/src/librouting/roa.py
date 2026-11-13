"""Live ROA store bindings (RFC 6482 / RFC 6811 / RFC 8210,
ROADMAP-v3 D2.3).

`RoaStore` wraps the C `lr_roa_store_t`: a thread-safe ROA database
with two provenance layers — static configuration entries and RTR
cache entries — and atomic whole-table snapshot swaps. Validation
reads run lock-free against a snapshot. Feed it from your own RTR
client or configuration loader; the daemon's `[bgp.rpki]` thread uses
the same store under the hood.
"""

from __future__ import annotations

import ipaddress

from ._ffi import ffi, get_lib
from .router import LrError, last_error

# RFC 6811 §2 validation outcomes (match the C LR_ROA_* constants).
ROA_VALID = 0
ROA_NOT_FOUND = 1
ROA_INVALID = 2


def _parse_network(prefix: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(prefix, strict=False)
    except ValueError as e:
        raise LrError(f"invalid prefix {prefix!r}: {e}") from e


def _fill_entry(dst, prefix: str, max_length: int, asn: int) -> None:
    """Fill one C `lr_roa_entry_t` from a CIDR string."""
    net = _parse_network(prefix)
    if max_length == 0:
        max_length = net.prefixlen
    if max_length < net.prefixlen:
        raise LrError(
            f"{prefix}: max_length {max_length} < prefix length {net.prefixlen} "
            "(RFC 6482 §3.3)"
        )
    packed = net.network_address.packed
    dst.is_ipv6 = 0 if net.version == 4 else 1
    for i, byte in enumerate(packed):
        dst.addr[i] = byte
    dst.prefix_len = int(net.prefixlen)
    dst.max_length = int(max_length)
    dst.asn = int(asn)


class RoaStore:
    """A live ROA database: static + RTR layers, atomic snapshot swaps,
    RFC 6811 §2 validation."""

    def __init__(self):
        ptr = get_lib().lr_roa_store_new()
        if not ptr:
            raise LrError("lr_roa_store_new failed")
        self._ptr = ptr

    def __del__(self):
        ptr = getattr(self, "_ptr", None)
        if ptr:
            get_lib().lr_roa_store_free(ptr)
            self._ptr = None

    def __enter__(self) -> "RoaStore":
        return self

    def __exit__(self, *_):
        self.__del__()

    def replace_static(self, entries) -> None:
        """Atomically replace the static (configuration) layer with
        ``entries`` — a list of ``(prefix, max_length, asn)`` tuples.
        ``max_length = 0`` means exact-prefix authorization. RTR-learned
        entries are preserved. A malformed entry fails the whole call
        atomically (nothing is applied)."""
        if not entries:
            # An empty list clears the layer — the C contract is
            # "NULL with len 0".
            rc = get_lib().lr_roa_store_replace_static(self._ptr, ffi.NULL, 0)
            if rc != 0:
                raise LrError(f"lr_roa_store_replace_static failed (rc={rc}): {last_error()}")
            return
        c_entries = ffi.new("lr_roa_entry_t[]", len(entries))
        for i, (prefix, max_length, asn) in enumerate(entries):
            _fill_entry(c_entries[i], prefix, int(max_length), int(asn))
        rc = get_lib().lr_roa_store_replace_static(self._ptr, c_entries, len(entries))
        if rc != 0:
            raise LrError(f"lr_roa_store_replace_static failed (rc={rc}): {last_error()}")

    def apply_deltas(self, deltas) -> None:
        """Apply one completed sync's delta batch atomically — a list of
        ``(announce, prefix, max_length, asn)`` tuples where ``announce``
        is truthy for announcements and falsy for withdrawals.
        Duplicates coalesce and unknown withdrawals are no-ops (the
        RFC 8210 §5.6 / §12 code-6 semantics)."""
        if not deltas:
            return
        c_deltas = ffi.new("lr_roa_delta_t[]", len(deltas))
        for i, (announce, prefix, max_length, asn) in enumerate(deltas):
            c_deltas[i].announce = 1 if announce else 0
            _fill_entry(c_deltas[i].entry, prefix, int(max_length), int(asn))
        rc = get_lib().lr_roa_store_apply_deltas(self._ptr, c_deltas, len(deltas))
        if rc != 0:
            raise LrError(f"lr_roa_store_apply_deltas failed (rc={rc}): {last_error()}")

    def clear_rtr(self) -> None:
        """Withdraw every RTR-learned entry — the RFC 8210 §6
        data-expiry and cache-change response. Static entries survive."""
        rc = get_lib().lr_roa_store_clear_rtr(self._ptr)
        if rc != 0:
            raise LrError(f"lr_roa_store_clear_rtr failed (rc={rc}): {last_error()}")

    def __len__(self) -> int:
        return int(get_lib().lr_roa_store_len(self._ptr))

    def validate(self, prefix: str, origin_as: int | None) -> int:
        """RFC 6811 §2 validation: return one of ``ROA_VALID``,
        ``ROA_NOT_FOUND``, ``ROA_INVALID``. ``origin_as = None`` (no
        AS_PATH) validates as ``ROA_NOT_FOUND``."""
        net = _parse_network(prefix)
        packed = net.network_address.packed
        addr = ffi.new("uint8_t[]", packed)
        state = ffi.new("uint8_t*")
        rc = get_lib().lr_roa_store_validate(
            self._ptr,
            addr if net.version == 4 else ffi.NULL,
            addr if net.version == 6 else ffi.NULL,
            int(net.prefixlen),
            int(origin_as or 0),
            0 if origin_as is None else 1,
            state,
        )
        if rc != 0:
            raise LrError(f"lr_roa_store_validate failed (rc={rc}): {last_error()}")
        return int(state[0])
