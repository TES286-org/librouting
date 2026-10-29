// OSPF structured types — Link State Retransmission List, LSDB, LSA
// box, LSA header, External-LSA destination.
//
// Mirrors the `lr_ospf` Rust crate (RFC 2328 §13 / §13.5 / §13.6 /
// §13.7 — the per-neighbor LSA retransmission list, the area LSDB,
// and the AS-external-LSA origination surface) and the C ABI surface
// in `lr_ffi.h` (`lr_ospf_retransmit_*`, `lr_ospf_lsdb_*`,
// `lr_ospf_lsa_*`, `lr_ospf_external_*`).
//
// # API hierarchy
//
// The Go surface mirrors the Rust crate's module split:
//   - OspfRetransmitList  — lr_ospf::retransmit::LinkStateRetransmissionList
//   - OspfLsdb             — lr_ospf::lsdb::Lsdb
//   - OspfLsa              — lr_ospf::lsa::Lsa (boxed handle, not the
//                            projection struct in librouting.go which is
//                            read-only)
//   - OspfLsaHeader        — lr_ospf::lsa::LsaHeader (boxed handle)
//   - OspfExternalDest     — lr_ospf::external::ExternalDestination
//
// Each owned handle frees its C pointer via runtime.SetFinalizer when
// the Go value leaves scope, matching the rest of this package.

package librouting

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -llr_ffi

#include <stdlib.h>
#include "lr_ffi.h"
*/
import "C"

import (
        "fmt"
        "runtime"
        "unsafe"
)

// ----------------------------------------------------------------------
// OSPF LSA types — mirror lr_ospf::lsa::{Lsa, LsaHeader, LsaKey}.
// ----------------------------------------------------------------------

// OspfLsaHeader is the fixed-layout 20-byte LSA header (RFC 2328
// §A.4.1 for v2, RFC 5340 §A.4.2 for v3). Fields are exposed as Go
// scalars so the caller can read or write them without going through
// the C ABI.
type OspfLsaHeader struct {
        LsAge             uint16
        Options           uint8
        LsType            uint16
        LinkStateID       uint32
        AdvertisingRouter uint32
        LsSequenceNumber  uint32
        LsChecksum        uint16
        Length            uint16
}

// OspfLsaKey is the LSA identity tuple used by the LSDB and the
// retransmission list: (ls_type, link_state_id, advertising_router).
type OspfLsaKey struct {
        LsType            uint16
        LinkStateID       uint32
        AdvertisingRouter uint32
}

// toC writes the Go header into a C struct. The caller owns the
// C struct (typically stack-allocated).
func (h OspfLsaHeader) toC(c *C.struct_lr_ospf_lsa_hdr_t) {
        c.ls_age = C.uint16_t(h.LsAge)
        c.options = C.uint8_t(h.Options)
        c.ls_type = C.uint16_t(h.LsType)
        c.link_state_id = C.uint32_t(h.LinkStateID)
        c.advertising_router = C.uint32_t(h.AdvertisingRouter)
        c.ls_sequence_number = C.uint32_t(h.LsSequenceNumber)
        c.ls_checksum = C.uint16_t(h.LsChecksum)
        c.length = C.uint16_t(h.Length)
}

// fromC reads a C struct into a fresh Go header.
func ospfLsaHeaderFromC(c *C.struct_lr_ospf_lsa_hdr_t) OspfLsaHeader {
        return OspfLsaHeader{
                LsAge:             uint16(c.ls_age),
                Options:           uint8(c.options),
                LsType:            uint16(c.ls_type),
                LinkStateID:       uint32(c.link_state_id),
                AdvertisingRouter: uint32(c.advertising_router),
                LsSequenceNumber:  uint32(c.ls_sequence_number),
                LsChecksum:        uint16(c.ls_checksum),
                Length:            uint16(c.length),
        }
}

// OspfLsaHandle is an owned handle to one lr_ospf::lsa::Lsa instance
// (header + body bytes). The handle owns the underlying Rust Box<Lsa>;
// callers free it via Free or the runtime finalizer.
type OspfLsaHandle struct {
        ptr C.lr_ospf_lsa_box_t
}

// NewOspfLsa constructs a new LSA from a header and a body byte slice.
// Mirrors lr_ospf_lsa_new (which takes a header-box + body bytes).
func NewOspfLsa(hdr OspfLsaHeader, body []byte) (*OspfLsaHandle, error) {
        cHdrBox := C.lr_ospf_lsa_header_new(
                C.uint16_t(hdr.LsAge),
                C.uint8_t(hdr.Options),
                C.uint16_t(hdr.LsType),
                C.uint32_t(hdr.LinkStateID),
                C.uint32_t(hdr.AdvertisingRouter),
                C.uint32_t(hdr.LsSequenceNumber),
                C.uint16_t(hdr.LsChecksum),
                C.uint16_t(hdr.Length))
        if cHdrBox == nil {
                return nil, fmt.Errorf("lr_ospf_lsa_header_new returned null")
        }
        var bodyPtr *C.uint8_t
        if len(body) > 0 {
                bodyPtr = (*C.uint8_t)(unsafe.Pointer(&body[0]))
        }
        h := C.lr_ospf_lsa_new(cHdrBox, bodyPtr, C.uintptr_t(len(body)))
        if h == nil {
                return nil, fmt.Errorf("lr_ospf_lsa_new returned null")
        }
        out := &OspfLsaHandle{ptr: h}
        runtime.SetFinalizer(out, (*OspfLsaHandle).destroy)
        return out, nil
}

func (l *OspfLsaHandle) destroy() {
        if l.ptr != nil {
                C.lr_ospf_lsa_free(l.ptr)
                l.ptr = nil
        }
}

// Free releases the handle (optional; a finalizer also runs).
func (l *OspfLsaHandle) Free() {
        runtime.SetFinalizer(l, nil)
        l.destroy()
}

// Header reads the LSA header as a Go struct.
func (l *OspfLsaHandle) Header() (OspfLsaHeader, error) {
        var c C.struct_lr_ospf_lsa_hdr_t
        rc := C.lr_ospf_lsa_header_get(l.ptr, &c)
        if rc != 0 {
                return OspfLsaHeader{}, fmt.Errorf("lr_ospf_lsa_header_get: %s (rc=%d)", LastError(), int(rc))
        }
        return ospfLsaHeaderFromC(&c), nil
}

// Body returns a copy of the LSA body bytes (caller owns the slice).
func (l *OspfLsaHandle) Body() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_ospf_lsa_body(l.ptr, &b)
        if rc != 0 {
                return nil, fmt.Errorf("lr_ospf_lsa_body: %s (rc=%d)", LastError(), int(rc))
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// ToWire returns the serialized wire form (header + body, exactly
// `length` bytes). The caller owns the returned slice.
func (l *OspfLsaHandle) ToWire() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_ospf_lsa_to_wire(l.ptr, &b)
        if rc != 0 {
                return nil, fmt.Errorf("lr_ospf_lsa_to_wire: %s (rc=%d)", LastError(), int(rc))
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// Finalize computes and stores the LSA checksum and length fields
// in-place (RFC 2328 §12.1).
func (l *OspfLsaHandle) Finalize() error {
        rc := C.lr_ospf_lsa_finalize(l.ptr)
        if rc != 0 {
                return fmt.Errorf("lr_ospf_lsa_finalize: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// ChecksumOk reports whether the LSA's checksum field validates
// against the body (RFC 2328 §13.1 (1) — "verify the LSA checksum").
func (l *OspfLsaHandle) ChecksumOk() bool {
        return C.lr_ospf_lsa_handle_checksum_ok(l.ptr) != 0
}

// Key returns the LSA identity tuple.
func (l *OspfLsaHandle) Key() (OspfLsaKey, error) {
        var lsType C.uint16_t
        var lsID C.uint32_t
        var adv C.uint32_t
        rc := C.lr_ospf_lsa_key(l.ptr, &lsType, &lsID, &adv)
        if rc != 0 {
                return OspfLsaKey{}, fmt.Errorf("lr_ospf_lsa_key: %s (rc=%d)", LastError(), int(rc))
        }
        return OspfLsaKey{
                LsType:            uint16(lsType),
                LinkStateID:       uint32(lsID),
                AdvertisingRouter: uint32(adv),
        }, nil
}

// ----------------------------------------------------------------------
// OSPF LSDB — mirror lr_ospf::lsdb::Lsdb.
// ----------------------------------------------------------------------

// OspfLsdb is an owned handle to one area link-state database.
type OspfLsdb struct {
        ptr C.lr_ospf_lsdb_t
}

// NewOspfLsdb constructs an empty LSDB.
func NewOspfLsdb() *OspfLsdb {
        db := &OspfLsdb{ptr: C.lr_ospf_lsdb_new()}
        runtime.SetFinalizer(db, (*OspfLsdb).destroy)
        return db
}

func (d *OspfLsdb) destroy() {
        if d.ptr != nil {
                C.lr_ospf_lsdb_free(d.ptr)
                d.ptr = nil
        }
}

// Free releases the handle (optional; a finalizer also runs).
func (d *OspfLsdb) Free() {
        runtime.SetFinalizer(d, nil)
        d.destroy()
}

// Install inserts or replaces `lsa` in the LSDB. The LSDB takes
// ownership of the LSA handle (the caller should not Free it after
// a successful Install — transfer it). Returns true if the install
// changed the database, false if the instance was older or identical.
func (d *OspfLsdb) Install(lsa *OspfLsaHandle) (bool, error) {
        if lsa == nil || lsa.ptr == nil {
                return false, fmt.Errorf("OspfLsdb.Install: nil LSA handle")
        }
        // Transfer ownership: the C side boxes the LSA into the LSDB.
        // Detach the Go finalizer so the Rust side is the sole owner.
        ptr := lsa.ptr
        runtime.SetFinalizer(lsa, nil)
        lsa.ptr = nil
        rc := C.lr_ospf_lsdb_install(d.ptr, ptr, 0)
        if rc < 0 {
                return false, fmt.Errorf("lr_ospf_lsdb_install: %s (rc=%d)", LastError(), int(rc))
        }
        return rc != 0, nil
}

// Remove drops the LSA identified by `key` from the LSDB. Returns
// true if an entry was removed.
func (d *OspfLsdb) Remove(key OspfLsaKey) (bool, error) {
        rc := C.lr_ospf_lsdb_remove(d.ptr, C.uint16_t(key.LsType), C.uint32_t(key.LinkStateID), C.uint32_t(key.AdvertisingRouter))
        if rc < 0 {
                return false, fmt.Errorf("lr_ospf_lsdb_remove: %s (rc=%d)", LastError(), int(rc))
        }
        return rc != 0, nil
}

// Get returns a *borrowed* LSA handle (read-only) for `key`, or
// (nil, nil) when the LSA is not in the LSDB. The returned handle
// is owned by the LSDB — do not Free it.
func (d *OspfLsdb) Get(key OspfLsaKey) (*OspfLsaHandle, error) {
        var out C.lr_ospf_lsa_box_t
        rc := C.lr_ospf_lsdb_get(d.ptr, C.uint16_t(key.LsType), C.uint32_t(key.LinkStateID), C.uint32_t(key.AdvertisingRouter), &out)
        if rc < 0 {
                return nil, fmt.Errorf("lr_ospf_lsdb_get: %s (rc=%d)", LastError(), int(rc))
        }
        if out == nil {
                return nil, nil
        }
        // The C side returns a *clone* (boxed) — the caller owns it.
        h := &OspfLsaHandle{ptr: out}
        runtime.SetFinalizer(h, (*OspfLsaHandle).destroy)
        return h, nil
}

// Len returns the number of LSAs in the database.
func (d *OspfLsdb) Len() int {
        return int(C.lr_ospf_lsdb_len(d.ptr))
}

// IsEmpty reports whether the LSDB contains zero LSAs.
func (d *OspfLsdb) IsEmpty() bool {
        return C.lr_ospf_lsdb_is_empty(d.ptr) != 0
}

// Headers returns every LSA header in the LSDB as a Go slice. The
// headers are copied out of a C buffer that is freed before return.
func (d *OspfLsdb) Headers() ([]OspfLsaHeader, error) {
        var cPtr *C.struct_lr_ospf_lsa_hdr_t
        var count C.uintptr_t
        rc := C.lr_ospf_lsdb_headers(d.ptr, &cPtr, &count)
        if rc != 0 {
                return nil, fmt.Errorf("lr_ospf_lsdb_headers: %s (rc=%d)", LastError(), int(rc))
        }
        if cPtr == nil || count == 0 {
                return nil, nil
        }
        defer C.lr_ospf_lsa_hdr_array_free(cPtr, count)
        n := int(count)
        slice := (*[1 << 28]C.struct_lr_ospf_lsa_hdr_t)(unsafe.Pointer(cPtr))[:n:n]
        out := make([]OspfLsaHeader, n)
        for i, h := range slice {
                out[i] = ospfLsaHeaderFromC(&h)
        }
        return out, nil
}

// RefreshDue returns the list of LSAs whose LS age has crossed
// LSRefreshTime (RFC 2328 §14.1) and need re-origination. The
// returned array owns every contained LSA; free it via OspfLsaArray.Free.
func (d *OspfLsdb) RefreshDue(routerID uint32, nowMs uint64) (*OspfLsaArray, error) {
        var outPtr *C.lr_ospf_lsa_box_t
        var count C.uintptr_t
        rc := C.lr_ospf_lsdb_refresh_due(d.ptr, C.uint32_t(routerID), C.uint64_t(nowMs), &outPtr, &count)
        if rc != 0 {
                return nil, fmt.Errorf("lr_ospf_lsdb_refresh_due: %s (rc=%d)", LastError(), int(rc))
        }
        if outPtr == nil || count == 0 {
                return &OspfLsaArray{}, nil
        }
        arr := &OspfLsaArray{ptr: outPtr, count: int(count)}
        runtime.SetFinalizer(arr, (*OspfLsaArray).destroy)
        return arr, nil
}

// AgeOut applies the MaxAGE flush pass (RFC 2328 §14.1/§14.4) at
// `nowMs`. Returns the list of LSAs whose age crossed MaxAge and were
// flushed from the database. The returned array owns every contained
// LSA; free it via OspfLsaArray.Free.
func (d *OspfLsdb) AgeOut(nowMs uint64) (*OspfLsaArray, error) {
        var outPtr *C.lr_ospf_lsa_box_t
        var count C.uintptr_t
        rc := C.lr_ospf_lsdb_age_out(d.ptr, C.uint64_t(nowMs), &outPtr, &count)
        if rc != 0 {
                return nil, fmt.Errorf("lr_ospf_lsdb_age_out: %s (rc=%d)", LastError(), int(rc))
        }
        if outPtr == nil || count == 0 {
                return &OspfLsaArray{}, nil
        }
        arr := &OspfLsaArray{ptr: outPtr, count: int(count)}
        runtime.SetFinalizer(arr, (*OspfLsaArray).destroy)
        return arr, nil
}

// ----------------------------------------------------------------------
// OSPF Link State Retransmission List — RFC 2328 §13.5/§13.6/§13.7
// ----------------------------------------------------------------------

// OspfRetransmitList is an owned handle to one per-neighbor LSA
// retransmission list (RFC 2328 §13.5). Every LSA we flood to a
// neighbor is recorded here; the LS-Acknowledgment handler drains
// it (§13.7); the poll loop re-floods aged entries (§13.6).
type OspfRetransmitList struct {
        ptr C.lr_ospf_retransmit_t
}

// NewOspfRetransmitList constructs an empty list.
func NewOspfRetransmitList() *OspfRetransmitList {
        l := &OspfRetransmitList{ptr: C.lr_ospf_retransmit_new()}
        runtime.SetFinalizer(l, (*OspfRetransmitList).destroy)
        return l
}

func (l *OspfRetransmitList) destroy() {
        if l.ptr != nil {
                C.lr_ospf_retransmit_free(l.ptr)
                l.ptr = nil
        }
}

// Free releases the handle (optional; a finalizer also runs).
func (l *OspfRetransmitList) Free() {
        runtime.SetFinalizer(l, nil)
        l.destroy()
}

// Len returns the number of LSAs currently awaiting acknowledgment.
func (l *OspfRetransmitList) Len() int {
        return int(C.lr_ospf_retransmit_len(l.ptr))
}

// IsEmpty reports whether the list holds no entries.
func (l *OspfRetransmitList) IsEmpty() bool {
        return C.lr_ospf_retransmit_is_empty(l.ptr) != 0
}

// Contains reports whether the list holds the LSA identified by `key`.
func (l *OspfRetransmitList) Contains(key OspfLsaKey) bool {
        return C.lr_ospf_retransmit_contains(l.ptr,
                C.uint16_t(key.LsType),
                C.uint32_t(key.LinkStateID),
                C.uint32_t(key.AdvertisingRouter)) != 0
}

// RecordFlood adds `lsa` to the list, stamped at `nowMs` (RFC 2328
// §13.5 step 5). The list takes ownership of the LSA handle —
// transfer it (do not Free it after a successful call).
func (l *OspfRetransmitList) RecordFlood(lsa *OspfLsaHandle, nowMs uint64) error {
        if lsa == nil || lsa.ptr == nil {
                return fmt.Errorf("OspfRetransmitList.RecordFlood: nil LSA handle")
        }
        ptr := lsa.ptr
        runtime.SetFinalizer(lsa, nil)
        lsa.ptr = nil
        rc := C.lr_ospf_retransmit_record_flood(l.ptr, ptr, C.uint64_t(nowMs))
        if rc != 0 {
                return fmt.Errorf("lr_ospf_retransmit_record_flood: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// Remove drops the entry identified by `key` from the list. Returns
// true if an entry was removed.
func (l *OspfRetransmitList) Remove(key OspfLsaKey) bool {
        return C.lr_ospf_retransmit_remove(l.ptr,
                C.uint16_t(key.LsType),
                C.uint32_t(key.LinkStateID),
                C.uint32_t(key.AdvertisingRouter)) != 0
}

// Clear drops every entry from the list. Used on neighbor reset
// (RFC 2328 §10.1 Kill, §10.9 sequence-mismatch restart).
func (l *OspfRetransmitList) Clear() {
        C.lr_ospf_retransmit_clear(l.ptr)
}

// ApplyAcks drains every LSA header in `acks` from the list (RFC 2328
// §13.7). Returns the number of entries actually removed — useful for
// diagnostics when an ack references an LSA we never flooded (a stray
// / duplicate ack per §13.7 step 5).
//
// Matching is by LSA identity (type / LS-ID / advertising router),
// NOT by sequence number — §13.7 step 5 allows the receiver to
// acknowledge an older instance.
func (l *OspfRetransmitList) ApplyAcks(acks []OspfLsaHeader) (int, error) {
        if len(acks) == 0 {
                return 0, nil
        }
        // Build a flat C array of lr_ospf_lsa_hdr_t.
        cArr := make([]C.struct_lr_ospf_lsa_hdr_t, len(acks))
        for i, a := range acks {
                a.toC(&cArr[i])
        }
        removed := C.lr_ospf_retransmit_apply_acks(l.ptr,
                (*C.struct_lr_ospf_lsa_hdr_t)(unsafe.Pointer(&cArr[0])),
                C.uintptr_t(len(acks)))
        return int(removed), nil
}

// Poll returns the LSAs whose `nowMs - last_sent_ms >= rxmtIntervalMs`
// (RFC 2328 §13.6). The returned LSAs are NOT removed from the list;
// their `last_sent_ms` is bumped to `nowMs` so the next cycle waits
// another full interval.
//
// The returned array owns every contained LSA handle. Freeing the
// array (via Free on the returned *OspfLsaArray) frees each LSA and
// the array storage itself. Do NOT call Free on individual LSAs
// obtained via At — they are owned by the array.
func (l *OspfRetransmitList) Poll(nowMs, rxmtIntervalMs uint64) (*OspfLsaArray, error) {
        var outPtr *C.lr_ospf_lsa_box_t
        var count C.uintptr_t
        rc := C.lr_ospf_retransmit_poll(l.ptr,
                C.uint64_t(nowMs),
                C.uint64_t(rxmtIntervalMs),
                &outPtr,
                &count)
        if rc != 0 {
                return nil, fmt.Errorf("lr_ospf_retransmit_poll: %s (rc=%d)", LastError(), int(rc))
        }
        if outPtr == nil || count == 0 {
                return &OspfLsaArray{}, nil
        }
        arr := &OspfLsaArray{ptr: outPtr, count: int(count)}
        runtime.SetFinalizer(arr, (*OspfLsaArray).destroy)
        return arr, nil
}

// OspfLsaArray owns a flat C array of LSA handles returned by Poll /
// RefreshDue / AgeOut. Free releases the array AND every LSA inside it
// (via lr_ospf_lsa_array_free). Use At to borrow individual LSAs.
type OspfLsaArray struct {
        ptr   *C.lr_ospf_lsa_box_t
        count int
}

func (a *OspfLsaArray) destroy() {
        if a.ptr != nil {
                C.lr_ospf_lsa_array_free(a.ptr, C.uintptr_t(a.count))
                a.ptr = nil
                a.count = 0
        }
}

// Free releases the array AND every LSA inside it. Optional — a
// finalizer also runs.
func (a *OspfLsaArray) Free() {
        runtime.SetFinalizer(a, nil)
        a.destroy()
}

// Len returns the number of LSAs in the array.
func (a *OspfLsaArray) Len() int { return a.count }

// At returns a *borrowed* LSA handle for index i (no allocation).
// The returned handle aliases the array storage — do NOT call Free on
// it; the array owns it. Out-of-bounds indices return nil.
func (a *OspfLsaArray) At(i int) *OspfLsaHandle {
        if i < 0 || i >= a.count || a.ptr == nil {
                return nil
        }
        slice := (*[1 << 28]C.lr_ospf_lsa_box_t)(unsafe.Pointer(a.ptr))[:a.count:a.count]
        return &OspfLsaHandle{ptr: slice[i]} // borrowed — no finalizer.
}

// ----------------------------------------------------------------------
// OSPF external-LSA origination surface — mirror lr_ospf::external.
// ----------------------------------------------------------------------

// OspfExternalMetricType selects whether the route's metric is Type 1
// (comparable to intra-area OSPF metrics) or Type 2 (always preferred
// over Type 1, only compared amongst itself). RFC 2328 §2.3.
type OspfExternalMetricType int32

const (
        // OspfExternalType1 — metric is added to the internal cost.
        OspfExternalType1 OspfExternalMetricType = 1
        // OspfExternalType2 — metric is compared only against other Type-2 routes.
        OspfExternalType2 OspfExternalMetricType = 2
)

// OspfExternalDest is an owned handle to one AS-external-LSA
// destination (RFC 2328 §2.3 and §A.4.5).
type OspfExternalDest struct {
        ptr C.lr_ospf_external_dest_t
}

// NewOspfExternalDestV4 constructs a Type-1 external destination for
// an IPv4 prefix with the given metric. Use SetForwardingAddr /
// SetRouteTag / SetPBit to populate the optional fields.
func NewOspfExternalDestV4(prefixAddr [4]byte, prefixLen uint8, metric uint32, metricType OspfExternalMetricType) (*OspfExternalDest, error) {
        ptr := C.lr_ospf_external_dest_new(
                (*C.uint8_t)(unsafe.Pointer(&prefixAddr[0])),
                nil,
                C.uint8_t(prefixLen),
                C.uint32_t(metric),
                C.int32_t(metricType))
        if ptr == nil {
                return nil, fmt.Errorf("lr_ospf_external_dest_new returned null")
        }
        d := &OspfExternalDest{ptr: ptr}
        runtime.SetFinalizer(d, (*OspfExternalDest).destroy)
        return d, nil
}

// NewOspfExternalDestV6 constructs a Type-1 external destination for
// an IPv6 prefix (RFC 5340 §4.4.1 — AS-external-LSA carries a v6 prefix).
func NewOspfExternalDestV6(prefixAddr [16]byte, prefixLen uint8, metric uint32, metricType OspfExternalMetricType) (*OspfExternalDest, error) {
        ptr := C.lr_ospf_external_dest_new(
                nil,
                (*C.uint8_t)(unsafe.Pointer(&prefixAddr[0])),
                C.uint8_t(prefixLen),
                C.uint32_t(metric),
                C.int32_t(metricType))
        if ptr == nil {
                return nil, fmt.Errorf("lr_ospf_external_dest_new returned null")
        }
        d := &OspfExternalDest{ptr: ptr}
        runtime.SetFinalizer(d, (*OspfExternalDest).destroy)
        return d, nil
}

func (d *OspfExternalDest) destroy() {
        if d.ptr != nil {
                C.lr_ospf_external_dest_free(d.ptr)
                d.ptr = nil
        }
}

// Free releases the handle.
func (d *OspfExternalDest) Free() {
        runtime.SetFinalizer(d, nil)
        d.destroy()
}

// SetForwardingAddrV4 sets the IPv4 forwarding address (RFC 2328
// §2.3). When set, traffic for the prefix is forwarded directly to
// the FA rather than to the ASBR. Pass 0 to clear.
func (d *OspfExternalDest) SetForwardingAddrV4(addr uint32) error {
        rc := C.lr_ospf_external_dest_set_forwarding_addr(d.ptr, C.uint32_t(addr))
        if rc != 0 {
                return fmt.Errorf("lr_ospf_external_dest_set_forwarding_addr: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// SetRouteTag sets the 32-bit external route tag (RFC 2328 §2.3).
func (d *OspfExternalDest) SetRouteTag(tag uint32) error {
        rc := C.lr_ospf_external_dest_set_route_tag(d.ptr, C.uint32_t(tag))
        if rc != 0 {
                return fmt.Errorf("lr_ospf_external_dest_set_route_tag: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// SetPBit sets the P-bit (RFC 2328 §A.4.5) — when 0, the LSA is not
// translated into a Type-7 by NSSA area border routers.
func (d *OspfExternalDest) SetPBit(p uint8) error {
        rc := C.lr_ospf_external_dest_set_p_bit(d.ptr, C.uint8_t(p))
        if rc != 0 {
                return fmt.Errorf("lr_ospf_external_dest_set_p_bit: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// Metric reads the configured metric.
func (d *OspfExternalDest) Metric() uint32 {
        return uint32(C.lr_ospf_external_dest_metric(d.ptr))
}

// MetricType reads the configured metric type (1 or 2).
func (d *OspfExternalDest) MetricType() OspfExternalMetricType {
        return OspfExternalMetricType(C.lr_ospf_external_dest_metric_type(d.ptr))
}

// RouteTag reads the 32-bit external route tag.
func (d *OspfExternalDest) RouteTag() uint32 {
        return uint32(C.lr_ospf_external_dest_route_tag(d.ptr))
}

// PBit reads the P-bit.
func (d *OspfExternalDest) PBit() uint8 {
        return uint8(C.lr_ospf_external_dest_p_bit(d.ptr))
}
