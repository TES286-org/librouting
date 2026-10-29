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
