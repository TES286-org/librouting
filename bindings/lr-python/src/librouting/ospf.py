"""OSPF structured types — Link State Retransmission List, LSDB, LSA
box, LSA header, External-LSA destination.

Mirrors the ``lr_ospf`` Rust crate's pub modules (RFC 2328 §13 /
§13.5 / §13.6 / §13.7) and the C ABI surface in ``lr_ffi.h``
(``lr_ospf_retransmit_*``, ``lr_ospf_lsdb_*``, ``lr_ospf_lsa_*``,
``lr_ospf_external_*``). Each class wraps an opaque C ABI handle and
owns its lifetime through ``__del__`` / ``close()`` /
context-manager protocols. The class surface mirrors the Rust API
hierarchy:

* :class:`OspfLsaHeader`       — ``lr_ospf::lsa::LsaHeader``
* :class:`OspfLsaKey`          — ``lr_ospf::lsa::LsaKey``
* :class:`OspfLsa`             — ``lr_ospf::lsa::Lsa`` (boxed handle)
* :class:`OspfLsdb`            — ``lr_ospf::lsdb::Lsdb``
* :class:`OspfRetransmitList`  — ``lr_ospf::retransmit::LinkStateRetransmissionList``
* :class:`OspfExternalDest`    — ``lr_ospf::external::ExternalDestination``
* :class:`OspfLsaArray`        — flat C array returned by ``poll`` /
  ``refresh_due`` / ``age_out`` (the array owns every contained LSA;
  freeing it frees every LSA + the array storage)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ._ffi import ffi, get_lib, alloc_bytes, free_bytes, copy_bytes
from .router import LrError, last_error


# OSPF external-LSA metric type — RFC 2328 §2.3.
EXTERNAL_METRIC_TYPE1 = 1  # metric is added to the internal cost.
EXTERNAL_METRIC_TYPE2 = 2  # metric is compared only against other Type-2 routes.


def _check_rc(rc: int, what: str) -> None:
    if rc != 0:
        raise LrError(f"{what} failed (rc={rc}): {last_error()}")


# ----------------------------------------------------------------------
# OSPF LSA header + key value types — mirror lr_ospf::lsa.
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class OspfLsaHeader:
    """Fixed-layout 20-byte LSA header (RFC 2328 §A.4.1 for v2,
    RFC 5340 §A.4.2 for v3)."""

    ls_age: int
    options: int
    ls_type: int
    link_state_id: int
    advertising_router: int
    ls_sequence_number: int
    ls_checksum: int
    length: int


@dataclass(frozen=True)
class OspfLsaKey:
    """LSA identity tuple used by the LSDB and the retransmission list:
    ``(ls_type, link_state_id, advertising_router)``."""

    ls_type: int
    link_state_id: int
    advertising_router: int


def _hdr_to_c(hdr: OspfLsaHeader):
    """Write a Python OspfLsaHeader into a fresh C ``lr_ospf_lsa_hdr_t``
    and return the cffi newp handle."""
    c = ffi.new("lr_ospf_lsa_hdr_t*")
    c.ls_age = hdr.ls_age
    c.options = hdr.options
    c.ls_type = hdr.ls_type
    c.link_state_id = hdr.link_state_id
    c.advertising_router = hdr.advertising_router
    c.ls_sequence_number = hdr.ls_sequence_number
    c.ls_checksum = hdr.ls_checksum
    c.length = hdr.length
    return c


def _hdr_from_c(c) -> OspfLsaHeader:
    return OspfLsaHeader(
        ls_age=int(c.ls_age),
        options=int(c.options),
        ls_type=int(c.ls_type),
        link_state_id=int(c.link_state_id),
        advertising_router=int(c.advertising_router),
        ls_sequence_number=int(c.ls_sequence_number),
        ls_checksum=int(c.ls_checksum),
        length=int(c.length),
    )


# ----------------------------------------------------------------------
# OspfLsa — owned handle to one lr_ospf::lsa::Lsa instance.
# ----------------------------------------------------------------------


class OspfLsa:
    """An owned handle to one ``lr_ospf::lsa::Lsa`` (header + body).

    Construct with :meth:`new`. Read fields via :meth:`header`,
    :meth:`body`, :meth:`to_wire`, :meth:`key`. Finalize the checksum
    via :meth:`finalize` (RFC 2328 §12.1).
    """

    def __init__(self) -> None:
        self._ptr = ffi.NULL
        self._owns = True

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying handle. Safe to call multiple times."""
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL and self._owns:
            get_lib().lr_ospf_lsa_free(ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> "OspfLsa":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def new(cls, hdr: OspfLsaHeader, body: bytes = b"") -> "OspfLsa":
        """Construct a new LSA from a header and a body byte string."""
        c_hdr_box = get_lib().lr_ospf_lsa_header_new(
            hdr.ls_age,
            hdr.options,
            hdr.ls_type,
            hdr.link_state_id,
            hdr.advertising_router,
            hdr.ls_sequence_number,
            hdr.ls_checksum,
            hdr.length,
        )
        if c_hdr_box == ffi.NULL:
            raise LrError("lr_ospf_lsa_header_new returned NULL")
        body_buf = ffi.from_buffer(body) if body else ffi.NULL
        ptr = get_lib().lr_ospf_lsa_new(c_hdr_box, body_buf, len(body))
        if ptr == ffi.NULL:
            raise LrError("lr_ospf_lsa_new returned NULL")
        out = cls.__new__(cls)
        out._ptr = ptr
        out._owns = True
        return out

    def header(self) -> OspfLsaHeader:
        c = ffi.new("lr_ospf_lsa_hdr_t*")
        _check_rc(get_lib().lr_ospf_lsa_header_get(self._ptr, c),
                  "lr_ospf_lsa_header_get")
        return _hdr_from_c(c)

    def body(self) -> bytes:
        b = alloc_bytes()
        try:
            _check_rc(get_lib().lr_ospf_lsa_body(self._ptr, b),
                      "lr_ospf_lsa_body")
            return copy_bytes(b)
        finally:
            free_bytes(b)

    def to_wire(self) -> bytes:
        b = alloc_bytes()
        try:
            _check_rc(get_lib().lr_ospf_lsa_to_wire(self._ptr, b),
                      "lr_ospf_lsa_to_wire")
            return copy_bytes(b)
        finally:
            free_bytes(b)

    def finalize(self) -> None:
        """Compute and store the LSA checksum and length in place
        (RFC 2328 §12.1)."""
        _check_rc(get_lib().lr_ospf_lsa_finalize(self._ptr),
                  "lr_ospf_lsa_finalize")

    def checksum_ok(self) -> bool:
        """True when the LSA's checksum field validates against the body
        (RFC 2328 §13.1 (1) — verify the LSA checksum)."""
        return bool(get_lib().lr_ospf_lsa_handle_checksum_ok(self._ptr))

    def key(self) -> OspfLsaKey:
        ls_type = ffi.new("uint16_t*")
        ls_id = ffi.new("uint32_t*")
        adv = ffi.new("uint32_t*")
        _check_rc(get_lib().lr_ospf_lsa_key(self._ptr, ls_type, ls_id, adv),
                  "lr_ospf_lsa_key")
        return OspfLsaKey(int(ls_type[0]), int(ls_id[0]), int(adv[0]))


# ----------------------------------------------------------------------
# OspfLsaArray — flat C array of LSA handles returned by poll /
# refresh_due / age_out. The array owns every contained LSA.
# ----------------------------------------------------------------------


class OspfLsaArray:
    """An owned C array of LSA handles. ``close()`` frees the array AND
    every LSA inside it via ``lr_ospf_lsa_array_free``. Use
    :meth:`at` to borrow an individual LSA — do not call ``close()``
    on the borrowed LSA, the array owns it."""

    def __init__(self) -> None:
        self._ptr = ffi.NULL
        self._count = 0

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._ptr != ffi.NULL:
            get_lib().lr_ospf_lsa_array_free(self._ptr, self._count)
            self._ptr = ffi.NULL
            self._count = 0

    def __enter__(self) -> "OspfLsaArray":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def _from_c(cls, ptr, count: int) -> "OspfLsaArray":
        out = cls.__new__(cls)
        out._ptr = ptr
        out._count = int(count)
        return out

    def __len__(self) -> int:
        return self._count

    def at(self, i: int) -> Optional[OspfLsa]:
        """Return a *borrowed* LSA handle for index ``i`` (no allocation).
        The returned LSA aliases the array storage — do not call
        ``close()`` on it. Out-of-bounds indices return ``None``."""
        if i < 0 or i >= self._count or self._ptr == ffi.NULL:
            return None
        h = OspfLsa.__new__(OspfLsa)
        h._ptr = self._ptr[i]
        h._owns = False
        return h


# ----------------------------------------------------------------------
# OspfLsdb — owned handle to one area link-state database.
# ----------------------------------------------------------------------


class OspfLsdb:
    """An owned handle to one ``lr_ospf::lsdb::Lsdb`` area link-state
    database (RFC 2328 §12)."""

    def __init__(self) -> None:
        self._ptr = ffi.NULL

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._ptr != ffi.NULL:
            get_lib().lr_ospf_lsdb_free(self._ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> "OspfLsdb":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def new(cls) -> "OspfLsdb":
        ptr = get_lib().lr_ospf_lsdb_new()
        if ptr == ffi.NULL:
            raise LrError("lr_ospf_lsdb_new returned NULL")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    def install(self, lsa: OspfLsa, now_ms: int = 0) -> int:
        """Insert or replace ``lsa`` in the LSDB. The LSDB takes
        ownership of the LSA handle (do not close it after a successful
        call). Returns the install outcome code (1=New, 2=Replaced,
        0=Ignored, 3=Purged)."""
        if lsa._ptr == ffi.NULL or not lsa._owns:
            raise LrError("OspfLsdb.install: LSA handle is empty or borrowed")
        # Transfer ownership: detach the Python __del__ finalizer.
        ptr = lsa._ptr
        lsa._ptr = ffi.NULL
        lsa._owns = False
        rc = get_lib().lr_ospf_lsdb_install(self._ptr, ptr, int(now_ms))
        if rc < 0:
            raise LrError(f"lr_ospf_lsdb_install failed (rc={rc}): {last_error()}")
        return int(rc)

    def remove(self, key: OspfLsaKey) -> bool:
        rc = get_lib().lr_ospf_lsdb_remove(
            self._ptr, key.ls_type, key.link_state_id, key.advertising_router)
        if rc < 0:
            raise LrError(f"lr_ospf_lsdb_remove failed (rc={rc}): {last_error()}")
        return bool(rc)

    def get(self, key: OspfLsaKey) -> Optional[OspfLsa]:
        out = ffi.new("lr_ospf_lsa_box_t*")
        rc = get_lib().lr_ospf_lsdb_get(
            self._ptr, key.ls_type, key.link_state_id, key.advertising_router, out)
        if rc < 0:
            raise LrError(f"lr_ospf_lsdb_get failed (rc={rc}): {last_error()}")
        if out[0] == ffi.NULL:
            return None
        h = OspfLsa.__new__(OspfLsa)
        h._ptr = out[0]
        h._owns = True
        return h

    def __len__(self) -> int:
        return int(get_lib().lr_ospf_lsdb_len(self._ptr))

    def is_empty(self) -> bool:
        return bool(get_lib().lr_ospf_lsdb_is_empty(self._ptr))

    def headers(self) -> List[OspfLsaHeader]:
        out_ptr = ffi.new("lr_ospf_lsa_hdr_t**")
        out_count = ffi.new("uintptr_t*")
        _check_rc(get_lib().lr_ospf_lsdb_headers(self._ptr, out_ptr, out_count),
                  "lr_ospf_lsdb_headers")
        ptr = out_ptr[0]
        count = int(out_count[0])
        if ptr == ffi.NULL or count == 0:
            return []
        try:
            return [_hdr_from_c(ptr[i]) for i in range(count)]
        finally:
            get_lib().lr_ospf_lsa_hdr_array_free(ptr, count)

    def refresh_due(self, router_id: int, now_ms: int) -> OspfLsaArray:
        out_ptr = ffi.new("lr_ospf_lsa_box_t**")
        out_count = ffi.new("uintptr_t*")
        _check_rc(get_lib().lr_ospf_lsdb_refresh_due(
            self._ptr, int(router_id), int(now_ms), out_ptr, out_count),
            "lr_ospf_lsdb_refresh_due")
        return OspfLsaArray._from_c(out_ptr[0], int(out_count[0]))

    def age_out(self, now_ms: int) -> OspfLsaArray:
        out_ptr = ffi.new("lr_ospf_lsa_box_t**")
        out_count = ffi.new("uintptr_t*")
        _check_rc(get_lib().lr_ospf_lsdb_age_out(
            self._ptr, int(now_ms), out_ptr, out_count),
            "lr_ospf_lsdb_age_out")
        return OspfLsaArray._from_c(out_ptr[0], int(out_count[0]))


# ----------------------------------------------------------------------
# OspfRetransmitList — per-neighbor LSA retransmission list
# (RFC 2328 §13.5/§13.6/§13.7).
# ----------------------------------------------------------------------


class OspfRetransmitList:
    """An owned handle to one per-neighbor LSA retransmission list
    (RFC 2328 §13.5). Every LSA we flood to a neighbor is recorded
    here; the LS-Acknowledgment handler drains it (§13.7); the poll
    loop re-floods aged entries (§13.6)."""

    def __init__(self) -> None:
        self._ptr = ffi.NULL

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._ptr != ffi.NULL:
            get_lib().lr_ospf_retransmit_free(self._ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> "OspfRetransmitList":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def new(cls) -> "OspfRetransmitList":
        ptr = get_lib().lr_ospf_retransmit_new()
        if ptr == ffi.NULL:
            raise LrError("lr_ospf_retransmit_new returned NULL")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    def __len__(self) -> int:
        return int(get_lib().lr_ospf_retransmit_len(self._ptr))

    def is_empty(self) -> bool:
        return bool(get_lib().lr_ospf_retransmit_is_empty(self._ptr))

    def contains(self, key: OspfLsaKey) -> bool:
        return bool(get_lib().lr_ospf_retransmit_contains(
            self._ptr, key.ls_type, key.link_state_id, key.advertising_router))

    def record_flood(self, lsa: OspfLsa, now_ms: int) -> None:
        """Record `lsa` on the list stamped at `now_ms` (§13.5 step 5).
        The list takes ownership of the LSA handle — do not close it
        after a successful call."""
        if lsa._ptr == ffi.NULL or not lsa._owns:
            raise LrError("OspfRetransmitList.record_flood: LSA handle is empty or borrowed")
        ptr = lsa._ptr
        lsa._ptr = ffi.NULL
        lsa._owns = False
        _check_rc(get_lib().lr_ospf_retransmit_record_flood(self._ptr, ptr, int(now_ms)),
                  "lr_ospf_retransmit_record_flood")

    def remove(self, key: OspfLsaKey) -> bool:
        return bool(get_lib().lr_ospf_retransmit_remove(
            self._ptr, key.ls_type, key.link_state_id, key.advertising_router))

    def clear(self) -> None:
        get_lib().lr_ospf_retransmit_clear(self._ptr)

    def apply_acks(self, acks: List[OspfLsaHeader]) -> int:
        """Drain `acks` from the list (§13.7). Returns the number of
        entries actually removed — useful for diagnostics when an ack
        references an LSA we never flooded (a stray / duplicate ack
        per §13.7 step 5).

        Matching is by LSA identity (type / LS-ID / advertising router),
        NOT by sequence number — §13.7 step 5 allows the receiver to
        acknowledge an older instance."""
        if not acks:
            return 0
        c_arr = ffi.new(f"lr_ospf_lsa_hdr_t[{len(acks)}]")
        for i, a in enumerate(acks):
            c_arr[i].ls_age = a.ls_age
            c_arr[i].options = a.options
            c_arr[i].ls_type = a.ls_type
            c_arr[i].link_state_id = a.link_state_id
            c_arr[i].advertising_router = a.advertising_router
            c_arr[i].ls_sequence_number = a.ls_sequence_number
            c_arr[i].ls_checksum = a.ls_checksum
            c_arr[i].length = a.length
        return int(get_lib().lr_ospf_retransmit_apply_acks(
            self._ptr, c_arr, len(acks)))

    def poll(self, now_ms: int, rxmt_interval_ms: int) -> OspfLsaArray:
        """Return the LSAs whose `now_ms - last_sent_ms >=
        rxmt_interval_ms` (§13.6). The returned LSAs are NOT removed
        from the list; their `last_sent_ms` is bumped to `now_ms` so
        the next cycle waits another full interval. The returned array
        owns every contained LSA; free it via OspfLsaArray.close()."""
        out_ptr = ffi.new("lr_ospf_lsa_box_t**")
        out_count = ffi.new("uintptr_t*")
        _check_rc(get_lib().lr_ospf_retransmit_poll(
            self._ptr, int(now_ms), int(rxmt_interval_ms), out_ptr, out_count),
            "lr_ospf_retransmit_poll")
        return OspfLsaArray._from_c(out_ptr[0], int(out_count[0]))


# ----------------------------------------------------------------------
# OspfExternalDest — owned handle to one AS-external-LSA destination.
# ----------------------------------------------------------------------


class OspfExternalDest:
    """An owned handle to one AS-external-LSA destination (RFC 2328
    §2.3 and §A.4.5)."""

    def __init__(self) -> None:
        self._ptr = ffi.NULL

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._ptr != ffi.NULL:
            get_lib().lr_ospf_external_dest_free(self._ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> "OspfExternalDest":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def new_v4(cls, prefix_addr: bytes, prefix_len: int, metric: int,
               metric_type: int = EXTERNAL_METRIC_TYPE1) -> "OspfExternalDest":
        """Construct a Type-1 external destination for an IPv4 prefix.
        ``prefix_addr`` must be 4 bytes."""
        if len(prefix_addr) != 4:
            raise LrError(f"prefix_addr must be 4 bytes for v4, got {len(prefix_addr)}")
        buf = ffi.from_buffer(prefix_addr)
        ptr = get_lib().lr_ospf_external_dest_new(
            buf, ffi.NULL, int(prefix_len), int(metric), int(metric_type))
        if ptr == ffi.NULL:
            raise LrError("lr_ospf_external_dest_new returned NULL")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    @classmethod
    def new_v6(cls, prefix_addr: bytes, prefix_len: int, metric: int,
               metric_type: int = EXTERNAL_METRIC_TYPE1) -> "OspfExternalDest":
        """Construct a Type-1 external destination for an IPv6 prefix
        (RFC 5340 §4.4.1 — AS-external-LSA carries a v6 prefix).
        ``prefix_addr`` must be 16 bytes."""
        if len(prefix_addr) != 16:
            raise LrError(f"prefix_addr must be 16 bytes for v6, got {len(prefix_addr)}")
        buf = ffi.from_buffer(prefix_addr)
        ptr = get_lib().lr_ospf_external_dest_new(
            ffi.NULL, buf, int(prefix_len), int(metric), int(metric_type))
        if ptr == ffi.NULL:
            raise LrError("lr_ospf_external_dest_new returned NULL")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    def set_forwarding_addr_v4(self, addr: int) -> None:
        """Set the IPv4 forwarding address (RFC 2328 §2.3). When set,
        traffic for the prefix is forwarded directly to the FA rather
        than to the ASBR. Pass 0 to clear."""
        _check_rc(get_lib().lr_ospf_external_dest_set_forwarding_addr(
            self._ptr, int(addr)),
            "lr_ospf_external_dest_set_forwarding_addr")

    def set_route_tag(self, tag: int) -> None:
        _check_rc(get_lib().lr_ospf_external_dest_set_route_tag(
            self._ptr, int(tag)),
            "lr_ospf_external_dest_set_route_tag")

    def set_p_bit(self, p: int) -> None:
        """Set the P-bit (RFC 2328 §A.4.5). When 0, the LSA is not
        translated into a Type-7 by NSSA area border routers."""
        _check_rc(get_lib().lr_ospf_external_dest_set_p_bit(
            self._ptr, int(p)),
            "lr_ospf_external_dest_set_p_bit")

    def metric(self) -> int:
        return int(get_lib().lr_ospf_external_dest_metric(self._ptr))

    def metric_type(self) -> int:
        return int(get_lib().lr_ospf_external_dest_metric_type(self._ptr))

    def forwarding_addr(self) -> int:
        return int(get_lib().lr_ospf_external_dest_forwarding_addr(self._ptr))

    def route_tag(self) -> int:
        return int(get_lib().lr_ospf_external_dest_route_tag(self._ptr))

    def p_bit(self) -> int:
        return int(get_lib().lr_ospf_external_dest_p_bit(self._ptr))


class OspfV3ExternalDest:
    """An owned handle to one OSPFv3 AS-external-LSA destination
    (RFC 5340 §4.4.3.6 / §A.4.7) — the v3 counterpart of
    :class:`OspfExternalDest`. The v3 plane carries IPv6 prefixes
    only and the forwarding address is an IPv6 16-byte array."""

    def __init__(self) -> None:
        self._ptr = ffi.NULL

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._ptr != ffi.NULL:
            get_lib().lr_ospf_v3_external_dest_free(self._ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> "OspfV3ExternalDest":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def new_v6(cls, prefix_addr: bytes, prefix_len: int, metric: int,
               type2: bool = False) -> "OspfV3ExternalDest":
        """Construct a v3 external destination for an IPv6 prefix.
        ``prefix_addr`` must be 16 bytes. ``type2`` selects a Type-2
        external metric (E bit set) when ``True``."""
        if len(prefix_addr) != 16:
            raise LrError(f"prefix_addr must be 16 bytes for v3, got {len(prefix_addr)}")
        buf = ffi.from_buffer(prefix_addr)
        ptr = get_lib().lr_ospf_v3_external_dest_new(
            ffi.NULL, buf, int(prefix_len), int(metric), 1 if type2 else 0)
        if ptr == ffi.NULL:
            raise LrError("lr_ospf_v3_external_dest_new returned NULL")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    def set_forwarding_addr(self, addr: bytes) -> None:
        """Set the IPv6 forwarding address (RFC 5340 §A.4.7 ``F``
        bit). Must be a global IPv6 address — unspecified and
        link-local values are illegal and the router rejects the
        redistribute call when set. ``addr`` must be 16 bytes. Pass
        16 zero bytes to clear (or use :meth:`clear_forwarding_addr`
        for the no-arg form)."""
        if len(addr) != 16:
            raise LrError(f"forwarding_addr must be 16 bytes, got {len(addr)}")
        buf = ffi.from_buffer(addr)
        _check_rc(get_lib().lr_ospf_v3_external_dest_set_forwarding_addr(
            self._ptr, buf),
            "lr_ospf_v3_external_dest_set_forwarding_addr")

    def clear_forwarding_addr(self) -> None:
        """Drop the F bit (forwards to the ASBR)."""
        _check_rc(get_lib().lr_ospf_v3_external_dest_clear_forwarding_addr(
            self._ptr),
            "lr_ospf_v3_external_dest_clear_forwarding_addr")

    def set_route_tag(self, tag: int) -> None:
        """Set the external route tag (RFC 5340 §A.4.7 ``T`` bit)."""
        _check_rc(get_lib().lr_ospf_v3_external_dest_set_route_tag(
            self._ptr, int(tag)),
            "lr_ospf_v3_external_dest_set_route_tag")

    def clear_route_tag(self) -> None:
        """Drop the T bit."""
        _check_rc(get_lib().lr_ospf_v3_external_dest_clear_route_tag(
            self._ptr),
            "lr_ospf_v3_external_dest_clear_route_tag")

    def metric(self) -> int:
        return int(get_lib().lr_ospf_v3_external_dest_metric(self._ptr))

    def type2(self) -> bool:
        """``True`` when the metric is Type-2 (E bit set)."""
        return bool(get_lib().lr_ospf_v3_external_dest_type2(self._ptr))

    def forwarding_addr(self) -> Optional[bytes]:
        """Read the configured IPv6 forwarding address. Returns
        ``None`` when the F bit is clear; otherwise a 16-byte
        ``bytes`` object."""
        out = ffi.new("uint8_t[16]")
        rc = get_lib().lr_ospf_v3_external_dest_forwarding_addr(
            self._ptr, out)
        if rc < 0:
            raise LrError(f"lr_ospf_v3_external_dest_forwarding_addr: {last_error()}")
        if rc == 1:
            return bytes(ffi.buffer(out, 16))
        return None

    def route_tag(self) -> Optional[int]:
        """Read the configured external route tag. Returns ``None``
        when the T bit is clear."""
        out = ffi.new("uint32_t*")
        rc = get_lib().lr_ospf_v3_external_dest_route_tag(self._ptr, out)
        if rc < 0:
            raise LrError(f"lr_ospf_v3_external_dest_route_tag: {last_error()}")
        if rc == 1:
            return int(out[0])
        return None


# ----------------------------------------------------------------------
# OSPF area type — value type mirroring lr_router::OspfAreaType
# (RFC 2328 §3.6 stub areas; RFC 3101 NSSA). The Rust enum is ``Copy``
# and the C ABI represents it as a small ``#[repr(C)]`` struct passed
# by value, so the Python wrapper is a plain value class (no opaque
# handle, no finaliser). Construct via the classmethod factories
# (:meth:`OspfAreaType.normal`, :meth:`OspfAreaType.stub`,
# :meth:`OspfAreaType.stub_no_summary`, :meth:`OspfAreaType.nssa`,
# :meth:`OspfAreaType.nssa_no_summary`) and inspect via
# :attr:`kind`, :attr:`is_stub`, :attr:`is_nssa`, :attr:`is_stubby`,
# :attr:`no_summary`, :attr:`default_metric`.
# ----------------------------------------------------------------------

# Area-kind ids (mirror the C ABI LR_AREA_* constants).
AREA_NORMAL = 0
AREA_STUB = 1
AREA_STUB_NO_SUMMARY = 2
AREA_NSSA = 3
AREA_NSSA_NO_SUMMARY = 4

# Friendly kind names for `kind` reader.
_AREA_KIND_NAMES = {
    AREA_NORMAL: "normal",
    AREA_STUB: "stub",
    AREA_STUB_NO_SUMMARY: "stub_no_summary",
    AREA_NSSA: "nssa",
    AREA_NSSA_NO_SUMMARY: "nssa_no_summary",
}


class OspfAreaType:
    """OSPF area type policy (RFC 2328 §3.6 / RFC 3101) — value type
    wrapping ``lr_ospf_area_type_t``.

    The class is a thin Python value wrapper: every instance holds an
    ``lr_ospf_area_type_t`` C struct obtained from one of the
    classmethod factories and never frees anything. Use the
    :meth:`Router.ospf_set_area_type` and :meth:`Router.ospf_area_type`
    methods (see :mod:`librouting.router`) to drive the live router.
    """

    __slots__ = ("_t",)

    def __init__(self, kind: int = AREA_NORMAL, default_metric: int = 0) -> None:
        # Always store a *pointer* to the C struct in `_t`. CFFI's
        # auto-dereference means `self._t.kind` reads the field and
        # `self._t[0]` yields the struct-by-value the C ABI functions
        # taking `struct lr_ospf_area_type_t` by value expect.
        self._t = ffi.new("struct lr_ospf_area_type_t*")
        self._t.kind = int(kind)
        self._t.default_metric = int(default_metric)

    @classmethod
    def _from_c(cls, c_struct) -> "OspfAreaType":
        """Wrap an existing C struct (either returned by value from a
        C ABI constructor or filled into a caller-allocated out
        pointer by a reader). Normalizes both sources to a
        freshly-allocated pointer so the rest of the wrapper can
        treat ``self._t`` uniformly as a struct pointer."""
        out = cls.__new__(cls)
        out._t = ffi.new("struct lr_ospf_area_type_t*")
        out._t.kind = int(c_struct.kind)
        out._t.default_metric = int(c_struct.default_metric)
        return out

    # Back-compat alias used by the router reader path: the same
    # wrapping logic applies to either source of an owned CFFI
    # struct.
    _from_c_struct = _from_c

    @classmethod
    def normal(cls) -> "OspfAreaType":
        """Regular area — type-3 / type-4 summaries and type-5
        externals flow freely (RFC 2328 §3.6)."""
        return cls._from_c(get_lib().lr_ospf_area_type_normal())

    @classmethod
    def stub(cls, default_metric: int) -> "OspfAreaType":
        """Stub area (RFC 2328 §3.6): no type-5 / type-4 LSAs enter;
        border routers inject a type-3 summary default
        (``0.0.0.0/0``) with ``default_metric``. Summaries are
        imported — for the "totally stubby" variant use
        :meth:`stub_no_summary`."""
        return cls._from_c(get_lib().lr_ospf_area_type_stub(int(default_metric)))

    @classmethod
    def stub_no_summary(cls, default_metric: int) -> "OspfAreaType":
        """Totally-stubby stub area (no type-3 summaries except the
        injected default)."""
        return cls._from_c(get_lib().lr_ospf_area_type_stub_no_summary(int(default_metric)))

    @classmethod
    def nssa(cls, default_metric: int) -> "OspfAreaType":
        """Not-So-Stubby area (RFC 3101 §2.7): like stub, but
        internal ASBRs may redistribute externals as area-scoped
        type-7 LSAs, which the elected border router translates into
        type-5s for the rest of the AS."""
        return cls._from_c(get_lib().lr_ospf_area_type_nssa(int(default_metric)))

    @classmethod
    def nssa_no_summary(cls, default_metric: int) -> "OspfAreaType":
        """Totally-NSSA (no type-3 summaries except the type-3
        default)."""
        return cls._from_c(get_lib().lr_ospf_area_type_nssa_no_summary(int(default_metric)))

    @property
    def kind(self) -> int:
        """The area-kind id (one of the ``AREA_*`` constants in
        this module: ``AREA_NORMAL``, ``AREA_STUB``,
        ``AREA_STUB_NO_SUMMARY``, ``AREA_NSSA``,
        ``AREA_NSSA_NO_SUMMARY``)."""
        return int(self._t.kind)

    @property
    def kind_name(self) -> str:
        """Lower-case ASCII kind name (``"normal"``, ``"stub"``,
        ``"stub_no_summary"``, ``"nssa"``, ``"nssa_no_summary"``)."""
        return _AREA_KIND_NAMES.get(int(self._t.kind), "unknown")

    @property
    def is_stub(self) -> bool:
        """``True`` for the stub variants (``stub`` or
        ``stub_no_summary``)."""
        return bool(get_lib().lr_ospf_area_type_is_stub(self._t[0]))

    @property
    def is_nssa(self) -> bool:
        """``True`` for the NSSA variants (``nssa`` or
        ``nssa_no_summary``)."""
        return bool(get_lib().lr_ospf_area_type_is_nssa(self._t[0]))

    @property
    def is_stubby(self) -> bool:
        """``True`` for stub or NSSA — type-5 / type-4 LSAs are
        refused."""
        return bool(get_lib().lr_ospf_area_type_is_stubby(self._t[0]))

    @property
    def no_summary(self) -> bool:
        """``True`` for the totally-stubby / totally-NSSA variants
        (no type-3 summaries except the injected default)."""
        return bool(get_lib().lr_ospf_area_type_no_summary(self._t[0]))

    @property
    def default_metric(self) -> Optional[int]:
        """Border-router-injected default-route metric (``None`` for
        ``Normal``; the metric for stub / NSSA)."""
        out = ffi.new("uint32_t*")
        if get_lib().lr_ospf_area_type_default_metric(self._t[0], out):
            return int(out[0])
        return None

    def c_handle(self):
        """Borrow the underlying C struct (for internal use by the
        :class:`Router` methods)."""
        return self._t[0]

    def __repr__(self) -> str:
        if self.default_metric is None:
            return f"OspfAreaType(kind={self.kind_name!r})"
        return (f"OspfAreaType(kind={self.kind_name!r}, "
                f"default_metric={self.default_metric})")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OspfAreaType):
            return NotImplemented
        return self.kind == other.kind and self.default_metric == other.default_metric

    def __hash__(self) -> int:
        return hash((self.kind, self.default_metric))
