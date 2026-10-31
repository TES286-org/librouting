// Babel routing protocol — frame codec, route table, neighbor FSM, auth.
//
// Mirrors the Rust crate `lr_babel` (RFC 8966 — the Babel routing
// protocol; plus RFC 8967 — the HMAC authentication extension) and
// the C ABI surface in `lr_ffi.h` (the `lr_babel_*` entry points).
//
// # API hierarchy
//
// The Go surface mirrors the Rust crate's module split:
//   - BabelFrame        — lr_babel::BabelFrame       (RFC 8966 §4.1)
//   - Tlv               — lr_babel::tlv::Tlv          (RFC 8966 §4.4)
//   - BabelCodec        — lr_babel::codec::BabelCodec (RFC 8966 §4.3 + RFC 8967)
//   - BabelRoute        — lr_babel::route::BabelRoute (RFC 8966 §3.2)
//   - BabelRouteKey     — lr_babel::route::RouteKey   (RFC 8966 §3.1)
//   - BabelRouteTable   — lr_babel::route::BabelRouteTable (RFC 8966 §3.5)
//   - BabelNeighbor     — lr_babel::neighbor::BabelNeighbor (RFC 8966 §3.4)
//   - MacKey            — lr_babel::auth::BabelMacKey (RFC 8967 §2.1)
//   - PseudoHeader      — lr_babel::auth::BabelPseudoHeader (RFC 8967 §4.2)
//   - PacketCounter     — lr_babel::auth::BabelPacketCounter (RFC 8967 §3.2)
//   - ReplayProtection   — lr_babel::auth::BabelReplayProtection (RFC 8967 §3.3)
//   - Hello/Ihu/AckReq/Ack/NextHop/RouterId/RouteRequest/SeqnoRequest — lr_babel::message::*
//
// Each type owns its C ABI handle and frees it via a finalizer when
// the Go value leaves scope. Use Free() for explicit teardown.

package librouting

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -llr_ffi

#include <stdlib.h>
#include <string.h>
#include "lr_ffi.h"

// Forward-declare the Go trampoline cgo will export.
extern int32_t go_lr_babel_route_iter_cb(lr_babel_route_t route, void *user);
*/
import "C"

import (
        "fmt"
        "runtime"
        "sync"
        "unsafe"
)

// ----------------------------------------------------------------------
// Constants — TLV type codes (RFC 8966 §4.4 Table 1) + AE values +
// MAC algorithm constants.
// ----------------------------------------------------------------------

// TLV type codes (RFC 8966 §4.4 — Table 1).
const (
        BabelTlvTypePad1          = 0
        BabelTlvTypePadN          = 1
        BabelTlvTypeAckReq        = 2
        BabelTlvTypeAck           = 3
        BabelTlvTypeHello         = 4
        BabelTlvTypeIhu           = 5
        BabelTlvTypeRouterID      = 6
        BabelTlvTypeNextHop       = 7
        BabelTlvTypeUpdate        = 8
        BabelTlvTypeRouteRequest  = 9
        BabelTlvTypeSeqnoRequest  = 10
        BabelTlvTypeTSpc          = 11
        BabelTlvTypeHmac          = 12
        BabelTlvTypeUnsupported   = 255
)

// Address Encoding (AE) — RFC 8966 §4.4.4 + RFC 8967 §4.1.
const (
        BabelAEWildcard       = 0
        BabelAEIPv4           = 1
        BabelAEIPv6           = 2
        BabelAEIPv6LinkLocal  = 3
)

// MAC algorithm constants — mirror `BabelMacAlgorithm` in lr_babel::auth.
const (
        BabelMacHMACSHA256    = 1
        BabelMacBlake2s128    = 2
)

// ----------------------------------------------------------------------
// Errors
// ----------------------------------------------------------------------

// BabelError wraps a non-zero return code from a lr_babel_* entry
// point together with the thread-local last-error string.
type BabelError struct {
        Op  string
        RC  int
        Msg string
}

func (e *BabelError) Error() string {
        return fmt.Sprintf("%s: %s (rc=%d)", e.Op, e.Msg, e.RC)
}

func babelErr(op string, rc C.int32_t) error {
        return &BabelError{Op: op, RC: int(rc), Msg: LastError()}
}

// babelErrU wraps a non-zero uintptr_t return code (used by C ABI
// functions that return a count or pointer rather than a signed int).
func babelErrU(op string, rc C.size_t) error {
        return &BabelError{Op: op, RC: int(rc), Msg: LastError()}
}

// babelErrB wraps a non-zero uint8_t return code (used by C ABI
// functions that return a boolean as u8).
func babelErrB(op string, rc C.uint8_t) error {
        return &BabelError{Op: op, RC: int(rc), Msg: LastError()}
}

func babelRcErr(op string, rc C.int32_t) error {
        if rc == 0 {
                return nil
        }
        return babelErr(op, rc)
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

// babelAddrToGo converts a 16-byte C buffer to a Go slice. For IPv4
// the C ABI writes the 4-byte address into the last 4 bytes (the
// IPv4-mapped IPv6 layout used by lr_babel_route_key_*_addr /
// lr_babel_route_next_hop). For IPv6 the full 16 bytes are used.
func babelAddrToGo(buf []byte, isIPv6 bool) []byte {
        if isIPv6 {
                return append([]byte(nil), buf[:16]...)
        }
        return append([]byte(nil), buf[12:16]...)
}

// babelAddrToC copies a Go address slice (4 or 16 bytes) into a
// freshly-allocated C buffer. The returned pointer must be freed by
// the caller via C.free.
func babelAddrToC(addr []byte) (unsafe.Pointer, error) {
        if len(addr) != 4 && len(addr) != 16 {
                return nil, fmt.Errorf("address must be 4 or 16 bytes, got %d", len(addr))
        }
        cBuf := C.malloc(C.size_t(len(addr)))
        if cBuf == nil {
                return nil, fmt.Errorf("malloc failed")
        }
        C.memcpy(cBuf, unsafe.Pointer(&addr[0]), C.size_t(len(addr)))
        return cBuf, nil
}

// ----------------------------------------------------------------------
// Tlv — RFC 8966 §4.4 — the atomic unit of a Babel frame body.
// ----------------------------------------------------------------------

// Tlv is an owned handle to a Babel TLV.
type Tlv struct {
        ptr    C.lr_babel_tlv_t
        freed  bool
}

// NewBabelTlv builds a TLV with the given kind code and value bytes.
func NewBabelTlv(kind uint8, value []byte) (*Tlv, error) {
        var valuePtr *C.uint8_t
        if len(value) > 0 {
                valuePtr = (*C.uint8_t)(unsafe.Pointer(&value[0]))
        }
        ptr := C.lr_babel_tlv_new(C.uint8_t(kind), valuePtr, C.size_t(len(value)))
        if ptr == nil {
                return nil, fmt.Errorf("lr_babel_tlv_new: %s", LastError())
        }
        t := &Tlv{ptr: ptr}
        runtime.SetFinalizer(t, (*Tlv).destroy)
        return t, nil
}

// BabelTlvPad1 returns a Pad1 TLV (RFC 8966 §4.4.1 — single byte).
func BabelTlvPad1() *Tlv {
        t := &Tlv{ptr: C.lr_babel_tlv_pad1()}
        runtime.SetFinalizer(t, (*Tlv).destroy)
        return t
}

// BabelTlvPadN returns a PadN TLV (RFC 8966 §4.4.2 — n zero bytes).
func BabelTlvPadN(n int) *Tlv {
        t := &Tlv{ptr: C.lr_babel_tlv_pad_n(C.size_t(n))}
        runtime.SetFinalizer(t, (*Tlv).destroy)
        return t
}

// Kind returns the TLV's wire type code.
func (t *Tlv) Kind() uint8 {
        return uint8(C.lr_babel_tlv_kind(t.ptr))
}

// Value returns the TLV's value bytes (a fresh copy).
func (t *Tlv) Value() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_babel_tlv_value(t.ptr, &b)
        if rc != 0 {
                return nil, babelErr("lr_babel_tlv_value", rc)
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// Free releases the underlying handle. Safe to call multiple times.
func (t *Tlv) Free() {
        t.destroy()
}

func (t *Tlv) destroy() {
        if t.freed || t.ptr == nil {
                return
        }
        C.lr_babel_tlv_free(t.ptr)
        t.ptr = nil
        t.freed = true
}

// BabelTlvTypeToU8 converts a TLV type enum value to its wire byte
// (identity — kept for ABI symmetry with FromU8).
func BabelTlvTypeToU8(kind uint8) uint8 {
        return uint8(C.lr_babel_tlv_type_to_u8(C.uint8_t(kind)))
}

// BabelTlvTypeFromU8 converts a wire TLV type byte back to the
// high-level enum value.
func BabelTlvTypeFromU8(wire uint8) uint8 {
        return uint8(C.lr_babel_tlv_type_from_u8(C.uint8_t(wire)))
}

// BabelTlvTypeName returns the human-readable name for a wire TLV type.
func BabelTlvTypeName(wire uint8) string {
        s := C.lr_babel_tlv_type_name(C.uint8_t(wire))
        if s == nil {
                return ""
        }
        return C.GoString(s)
}

// ----------------------------------------------------------------------
// BabelFrame — RFC 8966 §4.1.
// ----------------------------------------------------------------------

// BabelFrame is an owned handle to a Babel frame body (a flat list of TLVs).
type BabelFrame struct {
        ptr   C.lr_babel_frame_t
        freed bool
}

// NewBabelFrame builds an empty Babel frame.
func NewBabelFrame() *BabelFrame {
        f := &BabelFrame{ptr: C.lr_babel_frame_new_empty()}
        runtime.SetFinalizer(f, (*BabelFrame).destroy)
        return f
}

// NewBabelFrameFromTlvs builds a frame from a flat slice of TLV
// handles. The frame takes ownership of the TLV handles — they must
// not be reused after this call.
func NewBabelFrameFromTlvs(tlvs []*Tlv) (*BabelFrame, error) {
        if len(tlvs) == 0 {
                f := &BabelFrame{ptr: C.lr_babel_frame_new_from_tlvs(nil, 0)}
                runtime.SetFinalizer(f, (*BabelFrame).destroy)
                return f, nil
        }
        arr := make([]C.lr_babel_tlv_t, len(tlvs))
        for i, t := range tlvs {
                arr[i] = t.ptr
                // Frame takes ownership; prevent double-free.
                t.freed = true
        }
        f := &BabelFrame{ptr: C.lr_babel_frame_new_from_tlvs(&arr[0], C.size_t(len(arr)))}
        if f.ptr == nil {
                return nil, fmt.Errorf("lr_babel_frame_new_from_tlvs: %s", LastError())
        }
        runtime.SetFinalizer(f, (*BabelFrame).destroy)
        return f, nil
}

// DecodeBabelFrame decodes a raw Babel wire frame into a BabelFrame.
func DecodeBabelFrame(data []byte) (*BabelFrame, error) {
        var out C.lr_babel_frame_t
        rc := C.lr_babel_decode_frame((*C.uint8_t)(unsafe.Pointer(&data[0])),
                C.size_t(len(data)), &out)
        if rc != 0 {
                return nil, babelErr("lr_babel_decode_frame", rc)
        }
        if out == nil {
                return nil, fmt.Errorf("lr_babel_decode_frame returned NULL out")
        }
        f := &BabelFrame{ptr: out}
        runtime.SetFinalizer(f, (*BabelFrame).destroy)
        return f, nil
}

// PushTlv appends one TLV (consumes the Tlv handle — do not reuse).
func (f *BabelFrame) PushTlv(t *Tlv) error {
        rc := C.lr_babel_frame_push_tlv(f.ptr, t.ptr)
        if rc != 0 {
                return babelErr("lr_babel_frame_push_tlv", rc)
        }
        t.freed = true
        return nil
}

// TlvCount returns the number of TLVs in the frame.
func (f *BabelFrame) TlvCount() int {
        return int(C.lr_babel_frame_tlv_count(f.ptr))
}

// TlvTypeAt returns the wire type code of TLV `index`.
func (f *BabelFrame) TlvTypeAt(index int) (uint8, error) {
        n := f.TlvCount()
        if index < 0 || index >= n {
                return 0, fmt.Errorf("TLV index %d out of range (count=%d)", index, n)
        }
        return uint8(C.lr_babel_frame_tlv_type_at(f.ptr, C.size_t(index))), nil
}

// TlvValueAt returns the value bytes of TLV `index` (a fresh copy).
func (f *BabelFrame) TlvValueAt(index int) ([]byte, error) {
        n := f.TlvCount()
        if index < 0 || index >= n {
                return nil, fmt.Errorf("TLV index %d out of range (count=%d)", index, n)
        }
        length := int(C.lr_babel_frame_tlv_value_len_at(f.ptr, C.size_t(index)))
        if length == 0 {
                return nil, nil
        }
        out := make([]byte, length)
        copied := C.lr_babel_frame_tlv_value_at(f.ptr, C.size_t(index),
                (*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(length))
        if copied == 0 {
                return nil, nil
        }
        return out[:int(copied)], nil
}

// Encode serialises the frame to its on-the-wire representation.
func (f *BabelFrame) Encode() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_babel_encode_frame(f.ptr, &b)
        if rc != 0 {
                return nil, babelErr("lr_babel_encode_frame", rc)
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// Free releases the underlying handle. Safe to call multiple times.
func (f *BabelFrame) Free() { f.destroy() }

func (f *BabelFrame) destroy() {
        if f.freed || f.ptr == nil {
                return
        }
        C.lr_babel_frame_free(f.ptr)
        f.ptr = nil
        f.freed = true
}

// ----------------------------------------------------------------------
// BabelCodec — RFC 8966 §4.3 + RFC 8967.
// ----------------------------------------------------------------------

// BabelCodec is an owned handle to a streaming Babel codec.
type BabelCodec struct {
        ptr   C.lr_babel_codec_t
        freed bool
}

// NewBabelCodec constructs a streaming codec.
func NewBabelCodec() *BabelCodec {
        c := &BabelCodec{ptr: C.lr_babel_codec_new()}
        runtime.SetFinalizer(c, (*BabelCodec).destroy)
        return c
}

// DecodeSlice feeds one wire slice and returns a BabelFrame when a
// complete frame is decoded.
func (c *BabelCodec) DecodeSlice(data []byte) (*BabelFrame, error) {
        var out C.lr_babel_frame_t
        rc := C.lr_babel_codec_decode_slice(c.ptr,
                (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), &out)
        if rc != 0 {
                return nil, babelErr("lr_babel_codec_decode_slice", rc)
        }
        if out == nil {
                return nil, nil // not enough bytes yet
        }
        f := &BabelFrame{ptr: out}
        runtime.SetFinalizer(f, (*BabelFrame).destroy)
        return f, nil
}

// EncodeVec encodes a frame to its on-the-wire representation.
func (c *BabelCodec) EncodeVec(f *BabelFrame) ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_babel_codec_encode_vec(c.ptr, f.ptr, &b)
        if rc != 0 {
                return nil, babelErr("lr_babel_codec_encode_vec", rc)
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// Free releases the underlying handle. Safe to call multiple times.
func (c *BabelCodec) Free() { c.destroy() }

func (c *BabelCodec) destroy() {
        if c.freed || c.ptr == nil {
                return
        }
        C.lr_babel_codec_free(c.ptr)
        c.ptr = nil
        c.freed = true
}

// ----------------------------------------------------------------------
// BabelRouteKey + BabelRoute — RFC 8966 §3.1 / §3.2.
// ----------------------------------------------------------------------

// BabelRouteKey is the (destination prefix, optional source prefix,
// 8-byte router_id) tuple that identifies a Babel route.
type BabelRouteKey struct {
        DestinationAddr     []byte // 4 (IPv4) or 16 (IPv6) bytes
        DestinationPrefixLen uint8
        SourceAddr          []byte // nil or 4/16 bytes
        SourcePrefixLen     uint8
        RouterID            []byte // 8 bytes
}

// IsSourceSpecific returns true when the key carries a source prefix.
func (k BabelRouteKey) IsSourceSpecific() bool { return len(k.SourceAddr) > 0 }

// BabelRoute is a per-route entry: key + seqno + metric + next hop +
// feasible/installed flags.
type BabelRoute struct {
        Key      BabelRouteKey
        Seqno    uint16
        Metric   uint32
        NextHop  []byte // 4 (IPv4) or 16 (IPv6) bytes
        Feasible bool
        Installed bool
}

// babelRouteKeyToC builds an owned lr_babel_route_key_t handle from
// the Go BabelRouteKey. The caller MUST call lr_babel_route_key_free
// on the returned handle.
func babelRouteKeyToC(k BabelRouteKey) (C.lr_babel_route_key_t, error) {
        if len(k.DestinationAddr) != 4 && len(k.DestinationAddr) != 16 {
                return nil, fmt.Errorf("destination address must be 4 or 16 bytes, got %d",
                        len(k.DestinationAddr))
        }
        if len(k.RouterID) != 8 {
                return nil, fmt.Errorf("router_id must be 8 bytes, got %d", len(k.RouterID))
        }
        destPtr, err := babelAddrToC(k.DestinationAddr)
        if err != nil {
                return nil, err
        }
        defer C.free(destPtr)

        destIsIPv6 := C.uint8_t(0)
        if len(k.DestinationAddr) == 16 {
                destIsIPv6 = 1
        }

        var srcPresent C.uint8_t = 0
        var srcIsIPv6 C.uint8_t = 0
        var srcPtr unsafe.Pointer
        var srcPrefixLen C.uint8_t
        if k.IsSourceSpecific() {
                if len(k.SourceAddr) != 4 && len(k.SourceAddr) != 16 {
                        return nil, fmt.Errorf("source address must be 4 or 16 bytes, got %d",
                                len(k.SourceAddr))
                }
                srcPtr, err = babelAddrToC(k.SourceAddr)
                if err != nil {
                        return nil, err
                }
                defer C.free(srcPtr)
                srcPresent = 1
                if len(k.SourceAddr) == 16 {
                        srcIsIPv6 = 1
                }
                srcPrefixLen = C.uint8_t(k.SourcePrefixLen)
        }

        rid := make([]byte, 8)
        copy(rid, k.RouterID)

        h := C.lr_babel_route_key_new(
                destIsIPv6,
                (*C.uint8_t)(destPtr),
                C.uint8_t(k.DestinationPrefixLen),
                srcPresent,
                srcIsIPv6,
                (*C.uint8_t)(srcPtr),
                srcPrefixLen,
                (*C.uint8_t)(unsafe.Pointer(&rid[0])),
        )
        if h == nil {
                return nil, fmt.Errorf("lr_babel_route_key_new: %s", LastError())
        }
        return h, nil
}

// babelRouteKeyFromC reads a BabelRouteKey from a borrowed key
// handle. Does NOT free the handle.
func babelRouteKeyFromC(h C.lr_babel_route_key_t) BabelRouteKey {
        isV6 := C.lr_babel_route_key_destination_is_ipv6(h) != 0
        out := make([]byte, 16)
        C.lr_babel_route_key_destination_addr(h, (*C.uint8_t)(unsafe.Pointer(&out[0])))
        destAddr := babelAddrToGo(out, isV6)
        destPlen := uint8(C.lr_babel_route_key_destination_prefix_len(h))

        var srcAddr []byte
        var srcPlen uint8
        if C.lr_babel_route_key_source_present(h) != 0 {
                srcIsV6 := C.lr_babel_route_key_source_is_ipv6(h) != 0
                sout := make([]byte, 16)
                C.lr_babel_route_key_source_addr(h, (*C.uint8_t)(unsafe.Pointer(&sout[0])))
                srcAddr = babelAddrToGo(sout, srcIsV6)
                srcPlen = uint8(C.lr_babel_route_key_source_prefix_len(h))
        }

        rid := make([]byte, 8)
        C.lr_babel_route_key_router_id(h, (*C.uint8_t)(unsafe.Pointer(&rid[0])))
        return BabelRouteKey{
                DestinationAddr:     destAddr,
                DestinationPrefixLen: destPlen,
                SourceAddr:           srcAddr,
                SourcePrefixLen:      srcPlen,
                RouterID:             rid,
        }
}

// babelRouteFromC reads a BabelRoute from a borrowed route handle.
// Does NOT free the handle.
func babelRouteFromC(h C.lr_babel_route_t) BabelRoute {
        keyH := C.lr_babel_route_borrow_key(h)
        key := babelRouteKeyFromC(keyH)
        seqno := uint16(C.lr_babel_route_seqno(h))
        metric := uint32(C.lr_babel_route_metric(h))
        isV6 := C.lr_babel_route_next_hop_is_ipv6(h) != 0
        out := make([]byte, 16)
        C.lr_babel_route_next_hop(h, (*C.uint8_t)(unsafe.Pointer(&out[0])))
        nextHop := babelAddrToGo(out, isV6)
        return BabelRoute{
                Key:      key,
                Seqno:    seqno,
                Metric:   metric,
                NextHop:  nextHop,
                Feasible: C.lr_babel_route_feasible(h) != 0,
                Installed: C.lr_babel_route_installed(h) != 0,
        }
}

// ----------------------------------------------------------------------
// BabelRouteTable — RFC 8966 §3.5.
// ----------------------------------------------------------------------

// BabelRouteTable is an owned handle to a per-neighbor Babel route
// table. The table tracks feasibility state per destination and
// yields the lowest-metric feasible route per destination via
// IterBest.
type BabelRouteTable struct {
        ptr   C.lr_babel_route_table_t
        freed bool
}

// NewBabelRouteTable constructs an empty BabelRouteTable.
func NewBabelRouteTable() *BabelRouteTable {
        t := &BabelRouteTable{ptr: C.lr_babel_route_table_new()}
        runtime.SetFinalizer(t, (*BabelRouteTable).destroy)
        return t
}

// Len returns the number of routes in the table.
func (t *BabelRouteTable) Len() int {
        return int(C.lr_babel_route_table_len(t.ptr))
}

// IsEmpty returns true when the table holds no routes.
func (t *BabelRouteTable) IsEmpty() bool {
        return C.lr_babel_route_table_is_empty(t.ptr) != 0
}

// Insert inserts a route. With non-zero interval_cs/now_ms the
// route's hold deadline is pushed out (RFC 8966 §3.2.5).
func (t *BabelRouteTable) Insert(r BabelRoute) error {
        keyH, err := babelRouteKeyToC(r.Key)
        if err != nil {
                return err
        }
        defer C.lr_babel_route_key_free(keyH)
        if len(r.NextHop) != 4 && len(r.NextHop) != 16 {
                return fmt.Errorf("next_hop must be 4 or 16 bytes, got %d", len(r.NextHop))
        }
        nhPtr, err := babelAddrToC(r.NextHop)
        if err != nil {
                return err
        }
        defer C.free(nhPtr)
        nhIsIPv6 := C.uint8_t(0)
        if len(r.NextHop) == 16 {
                nhIsIPv6 = 1
        }
        ra := C.lr_babel_route_new(
                keyH,
                C.uint16_t(r.Seqno),
                C.uint32_t(r.Metric),
                nhIsIPv6,
                (*C.uint8_t)(nhPtr),
                toCBool(r.Feasible),
                toCBool(r.Installed),
        )
        if ra == nil {
                return fmt.Errorf("lr_babel_route_new: %s", LastError())
        }
        defer C.lr_babel_route_free(ra)
        rc := C.lr_babel_route_table_insert(t.ptr, ra)
        return babelRcErr("lr_babel_route_table_insert", rc)
}

// Withdraw removes the route stored under the given key.
func (t *BabelRouteTable) Withdraw(key BabelRouteKey) error {
        h, err := babelRouteKeyToC(key)
        if err != nil {
                return err
        }
        defer C.lr_babel_route_key_free(h)
        rc := C.lr_babel_route_table_withdraw(t.ptr, h)
        return babelRcErr("lr_babel_route_table_withdraw", rc)
}

// Expire drops routes whose hold deadline has lapsed. Returns the
// number of routes withdrawn.
func (t *BabelRouteTable) Expire(nowMs uint64) int {
        return int(C.lr_babel_route_table_expire(t.ptr, C.uint64_t(nowMs)))
}

// Contains reports whether the table holds a route for the given key.
func (t *BabelRouteTable) Contains(key BabelRouteKey) (bool, error) {
        h, err := babelRouteKeyToC(key)
        if err != nil {
                return false, err
        }
        defer C.lr_babel_route_key_free(h)
        return C.lr_babel_route_table_contains(t.ptr, h) != 0, nil
}

// Get returns the route stored under the given key (a snapshot copy).
// Returns ok=false when the key is not present.
func (t *BabelRouteTable) Get(key BabelRouteKey) (r BabelRoute, ok bool, err error) {
        h, err := babelRouteKeyToC(key)
        if err != nil {
                return BabelRoute{}, false, err
        }
        defer C.lr_babel_route_key_free(h)
        rp := C.lr_babel_route_table_get(t.ptr, h)
        if rp == nil {
                return BabelRoute{}, false, nil
        }
        return babelRouteFromC(rp), true, nil
}

// BestRoutesCount returns the number of best routes (lowest-metric
// feasible per destination).
func (t *BabelRouteTable) BestRoutesCount() int {
        return int(C.lr_babel_route_table_best_routes_count(t.ptr))
}

// IterAll calls fn for each route in the table. fn may return an
// error to stop early; the error is propagated.
func (t *BabelRouteTable) IterAll(fn func(BabelRoute) error) error {
        return babelRouteIterCommon(t.ptr, false, fn)
}

// IterBest calls fn for each best (lowest-metric feasible) route per
// destination. fn may return an error to stop early.
func (t *BabelRouteTable) IterBest(fn func(BabelRoute) error) error {
        return babelRouteIterCommon(t.ptr, true, fn)
}

// Free releases the underlying handle.
func (t *BabelRouteTable) Free() { t.destroy() }

func (t *BabelRouteTable) destroy() {
        if t.freed || t.ptr == nil {
                return
        }
        C.lr_babel_route_table_free(t.ptr)
        t.ptr = nil
        t.freed = true
}

// babelRouteIterCommon drives the iter / best_routes_iter C ABI
// callbacks through a Go trampoline that looks up the user-supplied
// function by index.
func babelRouteIterCommon(table C.lr_babel_route_table_t, best bool, fn func(BabelRoute) error) error {
        idx := babelIterCallbackRegister(fn)
        defer babelIterCallbackRelease(idx)
        user := unsafe.Pointer(uintptr(idx))
        if best {
                rc := C.lr_babel_route_table_best_routes_iter(table,
                        (C.lr_babel_route_iter_cb)(C.go_lr_babel_route_iter_cb), user)
                return babelRcErr("lr_babel_route_table_best_routes_iter", rc)
        }
        rc := C.lr_babel_route_table_iter(table,
                (C.lr_babel_route_iter_cb)(C.go_lr_babel_route_iter_cb), user)
        return babelRcErr("lr_babel_route_table_iter", rc)
}

// ---- Go trampoline for lr_babel_route_table_iter / _best_routes_iter.

var (
        babelIterCallbacksMu sync.Mutex
        babelIterCallbacks   = map[int]func(BabelRoute) error{}
        babelIterCallbackSeq int
)

func babelIterCallbackRegister(fn func(BabelRoute) error) int {
        babelIterCallbacksMu.Lock()
        defer babelIterCallbacksMu.Unlock()
        babelIterCallbackSeq++
        babelIterCallbacks[babelIterCallbackSeq] = fn
        return babelIterCallbackSeq
}

func babelIterCallbackRelease(idx int) {
        babelIterCallbacksMu.Lock()
        defer babelIterCallbacksMu.Unlock()
        delete(babelIterCallbacks, idx)
}

func babelIterCallbackLookup(idx int) func(BabelRoute) error {
        babelIterCallbacksMu.Lock()
        defer babelIterCallbacksMu.Unlock()
        return babelIterCallbacks[idx]
}

//export go_lr_babel_route_iter_cb
func go_lr_babel_route_iter_cb(route C.lr_babel_route_t, user unsafe.Pointer) C.int32_t {
        idx := int(uintptr(user))
        fn := babelIterCallbackLookup(idx)
        if fn == nil {
                return 0
        }
        r := babelRouteFromC(route)
        if err := fn(r); err != nil {
                // Returning a non-zero int32 signals the C ABI to stop
                // early. We can't surface the actual Go error back through
                // the C ABI, so we stash it as a sentinel return.
                return 1
        }
        return 0
}

// ----------------------------------------------------------------------
// BabelNeighbor — RFC 8966 §3.4.
// ----------------------------------------------------------------------

// BabelNeighbor is an owned handle to a per-neighbor Babel FSM.
type BabelNeighbor struct {
        ptr   C.lr_babel_neighbor_t
        freed bool
}

// NewBabelNeighbor constructs a BabelNeighbor for the given remote
// address (4 bytes IPv4 or 16 bytes IPv6).
func NewBabelNeighbor(addr []byte, nowMs uint64) (*BabelNeighbor, error) {
        if len(addr) != 4 && len(addr) != 16 {
                return nil, fmt.Errorf("address must be 4 or 16 bytes, got %d", len(addr))
        }
        var v4Ptr, v6Ptr *C.uint8_t
        if len(addr) == 4 {
                v4Ptr = (*C.uint8_t)(unsafe.Pointer(&addr[0]))
        } else {
                v6Ptr = (*C.uint8_t)(unsafe.Pointer(&addr[0]))
        }
        h := C.lr_babel_neighbor_new(v4Ptr, v6Ptr, C.uint64_t(nowMs))
        if h == nil {
                return nil, fmt.Errorf("lr_babel_neighbor_new: %s", LastError())
        }
        n := &BabelNeighbor{ptr: h}
        runtime.SetFinalizer(n, (*BabelNeighbor).destroy)
        return n, nil
}

// Hello feeds a Hello TLV into the neighbor FSM.
func (n *BabelNeighbor) Hello(seqno, intervalCs uint16, nowMs uint64) error {
        rc := C.lr_babel_neighbor_hello(n.ptr, C.uint16_t(seqno),
                C.uint16_t(intervalCs), C.uint64_t(nowMs))
        return babelRcErr("lr_babel_neighbor_hello", rc)
}

// Ihu feeds an IHU TLV into the neighbor FSM.
func (n *BabelNeighbor) Ihu(rxcost, intervalCs uint16, nowMs uint64) error {
        rc := C.lr_babel_neighbor_ihu(n.ptr, C.uint16_t(rxcost),
                C.uint16_t(intervalCs), C.uint64_t(nowMs))
        return babelRcErr("lr_babel_neighbor_ihu", rc)
}

// RttUS returns the current RTT estimate in microseconds, or 0 when
// no valid RTT sample is available.
func (n *BabelNeighbor) RttUS(nowMs uint64) uint32 {
        return uint32(C.lr_babel_neighbor_rtt_us(n.ptr, C.uint64_t(nowMs)))
}

// RttValid reports whether the RTT estimate is within the validity window.
func (n *BabelNeighbor) RttValid(nowMs uint64) bool {
        return C.lr_babel_neighbor_rtt_valid(n.ptr, C.uint64_t(nowMs)) != 0
}

// Free releases the underlying handle.
func (n *BabelNeighbor) Free() { n.destroy() }

func (n *BabelNeighbor) destroy() {
        if n.freed || n.ptr == nil {
                return
        }
        C.lr_babel_neighbor_free(n.ptr)
        n.ptr = nil
        n.freed = true
}

// ----------------------------------------------------------------------
// MacKey + PseudoHeader + PacketCounter + ReplayProtection — RFC 8967.
// ----------------------------------------------------------------------

// MacKey is an owned handle to a Babel MAC key (RFC 8967 §2.1).
type MacKey struct {
        ptr   C.lr_babel_mac_key_t
        freed bool
}

// NewMacKey builds a MacKey with the given algorithm and secret.
func NewMacKey(algorithm int, secret []byte) (*MacKey, error) {
        var secretPtr *C.uint8_t
        if len(secret) > 0 {
                secretPtr = (*C.uint8_t)(unsafe.Pointer(&secret[0]))
        }
        h := C.lr_babel_mac_key_new(C.int32_t(algorithm), secretPtr, C.size_t(len(secret)))
        if h == nil {
                return nil, fmt.Errorf("lr_babel_mac_key_new: %s", LastError())
        }
        k := &MacKey{ptr: h}
        runtime.SetFinalizer(k, (*MacKey).destroy)
        return k, nil
}

// NewMacKeyHmacSHA256 builds a MacKey with HMAC-SHA256.
func NewMacKeyHmacSHA256(secret []byte) *MacKey {
        var secretPtr *C.uint8_t
        if len(secret) > 0 {
                secretPtr = (*C.uint8_t)(unsafe.Pointer(&secret[0]))
        }
        k := &MacKey{ptr: C.lr_babel_mac_key_hmac_sha256(secretPtr, C.size_t(len(secret)))}
        runtime.SetFinalizer(k, (*MacKey).destroy)
        return k
}

// NewMacKeyBlake2s128 builds a MacKey with BLAKE2s-128.
func NewMacKeyBlake2s128(secret []byte) *MacKey {
        var secretPtr *C.uint8_t
        if len(secret) > 0 {
                secretPtr = (*C.uint8_t)(unsafe.Pointer(&secret[0]))
        }
        k := &MacKey{ptr: C.lr_babel_mac_key_blake2s128(secretPtr, C.size_t(len(secret)))}
        runtime.SetFinalizer(k, (*MacKey).destroy)
        return k
}

// Algorithm returns the MAC algorithm constant.
func (k *MacKey) Algorithm() int {
        return int(C.lr_babel_mac_key_algorithm(k.ptr))
}

// DigestLen returns the MAC digest length.
func (k *MacKey) DigestLen() int {
        return int(C.lr_babel_mac_key_digest_len(k.ptr))
}

// SecretLen returns the secret length.
func (k *MacKey) SecretLen() int {
        return int(C.lr_babel_mac_key_secret_len(k.ptr))
}

// Secret returns a fresh copy of the secret bytes.
func (k *MacKey) Secret() ([]byte, error) {
        n := k.SecretLen()
        if n == 0 {
                return nil, nil
        }
        out := make([]byte, n)
        // The C ABI returns the number of bytes copied (a usize); 0
        // signals a NULL/empty/invalid case.
        copied := C.lr_babel_mac_key_secret_copy(k.ptr,
                (*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(n))
        if int(copied) == 0 {
                return nil, fmt.Errorf("lr_babel_mac_key_secret_copy: %s", LastError())
        }
        return out[:int(copied)], nil
}

// Free releases the underlying handle.
func (k *MacKey) Free() { k.destroy() }

func (k *MacKey) destroy() {
        if k.freed || k.ptr == nil {
                return
        }
        C.lr_babel_mac_key_free(k.ptr)
        k.ptr = nil
        k.freed = true
}

// PseudoHeader is an owned handle to a Babel pseudo-header (RFC 8967 §4.2).
type PseudoHeader struct {
        ptr   C.lr_babel_pseudo_header_t
        freed bool
}

// NewPseudoHeaderV4 builds an IPv4 pseudo-header.
func NewPseudoHeaderV4(src, dst []byte, srcPort, dstPort uint16) (*PseudoHeader, error) {
        if len(src) != 4 || len(dst) != 4 {
                return nil, fmt.Errorf("src and dst must both be 4 bytes for v4")
        }
        h := C.lr_babel_pseudo_header_new_v4(
                (*C.uint8_t)(unsafe.Pointer(&src[0])),
                C.uint16_t(srcPort),
                (*C.uint8_t)(unsafe.Pointer(&dst[0])),
                C.uint16_t(dstPort),
        )
        if h == nil {
                return nil, fmt.Errorf("lr_babel_pseudo_header_new_v4: %s", LastError())
        }
        p := &PseudoHeader{ptr: h}
        runtime.SetFinalizer(p, (*PseudoHeader).destroy)
        return p, nil
}

// NewPseudoHeaderV6 builds an IPv6 pseudo-header.
func NewPseudoHeaderV6(src, dst []byte, srcPort, dstPort uint16) (*PseudoHeader, error) {
        if len(src) != 16 || len(dst) != 16 {
                return nil, fmt.Errorf("src and dst must both be 16 bytes for v6")
        }
        h := C.lr_babel_pseudo_header_new_v6(
                (*C.uint8_t)(unsafe.Pointer(&src[0])),
                C.uint16_t(srcPort),
                (*C.uint8_t)(unsafe.Pointer(&dst[0])),
                C.uint16_t(dstPort),
        )
        if h == nil {
                return nil, fmt.Errorf("lr_babel_pseudo_header_new_v6: %s", LastError())
        }
        p := &PseudoHeader{ptr: h}
        runtime.SetFinalizer(p, (*PseudoHeader).destroy)
        return p, nil
}

// Encode returns the on-the-wire pseudo-header bytes.
func (p *PseudoHeader) Encode() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_babel_pseudo_header_encode(p.ptr, &b)
        if rc != 0 {
                return nil, babelErr("lr_babel_pseudo_header_encode", rc)
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// Free releases the underlying handle.
func (p *PseudoHeader) Free() { p.destroy() }

func (p *PseudoHeader) destroy() {
        if p.freed || p.ptr == nil {
                return
        }
        C.lr_babel_pseudo_header_free(p.ptr)
        p.ptr = nil
        p.freed = true
}

// PacketCounter is an owned handle to a per-source packet counter.
type PacketCounter struct {
        ptr   C.lr_babel_packet_counter_t
        freed bool
}

// NewPacketCounter builds a packet counter with the given index and
// initial counter value.
func NewPacketCounter(index []byte, initial uint32) (*PacketCounter, error) {
        var idxPtr *C.uint8_t
        if len(index) > 0 {
                idxPtr = (*C.uint8_t)(unsafe.Pointer(&index[0]))
        }
        h := C.lr_babel_packet_counter_new(idxPtr, C.size_t(len(index)), C.uint32_t(initial))
        if h == nil {
                return nil, fmt.Errorf("lr_babel_packet_counter_new: %s", LastError())
        }
        c := &PacketCounter{ptr: h}
        runtime.SetFinalizer(c, (*PacketCounter).destroy)
        return c, nil
}

// Counter returns the current counter value.
func (c *PacketCounter) Counter() uint32 {
        return uint32(C.lr_babel_packet_counter_peek_counter(c.ptr))
}

// IndexLen returns the length of the index bytes.
func (c *PacketCounter) IndexLen() int {
        return int(C.lr_babel_packet_counter_peek_index_len(c.ptr))
}

// Index returns a fresh copy of the index bytes.
func (c *PacketCounter) Index() ([]byte, error) {
        n := c.IndexLen()
        if n == 0 {
                return nil, nil
        }
        out := make([]byte, n)
        copied := C.lr_babel_packet_counter_peek_index_copy(c.ptr,
                (*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(n))
        if int(copied) == 0 {
                return nil, fmt.Errorf("lr_babel_packet_counter_peek_index_copy: %s", LastError())
        }
        return out[:int(copied)], nil
}

// Free releases the underlying handle.
func (c *PacketCounter) Free() { c.destroy() }

func (c *PacketCounter) destroy() {
        if c.freed || c.ptr == nil {
                return
        }
        C.lr_babel_packet_counter_free(c.ptr)
        c.ptr = nil
        c.freed = true
}

// ReplayProtection is an owned handle to inbound replay-protection state.
type ReplayProtection struct {
        ptr   C.lr_babel_replay_protection_t
        freed bool
}

// NewReplayProtection constructs a fresh replay-protection state.
func NewReplayProtection() *ReplayProtection {
        r := &ReplayProtection{ptr: C.lr_babel_replay_protection_new()}
        runtime.SetFinalizer(r, (*ReplayProtection).destroy)
        return r
}

// Accept returns true when the (index, counter) pair is strictly
// greater than the previously-accepted counter for this index.
func (r *ReplayProtection) Accept(index []byte, counter uint32) (bool, error) {
        var idxPtr *C.uint8_t
        if len(index) > 0 {
                idxPtr = (*C.uint8_t)(unsafe.Pointer(&index[0]))
        }
        rc := C.lr_babel_replay_protection_accept(r.ptr, idxPtr, C.size_t(len(index)),
                C.uint32_t(counter))
        if rc < 0 {
                return false, babelErrB("lr_babel_replay_protection_accept", rc)
        }
        return rc != 0, nil
}

// Free releases the underlying handle.
func (r *ReplayProtection) Free() { r.destroy() }

func (r *ReplayProtection) destroy() {
        if r.freed || r.ptr == nil {
                return
        }
        C.lr_babel_replay_protection_free(r.ptr)
        r.ptr = nil
        r.freed = true
}

// ----------------------------------------------------------------------
// Babel message constructors — RFC 8966 §4.4.
// ----------------------------------------------------------------------

// BabelHello is an owned handle to a Hello TLV.
type BabelHello struct {
        ptr   C.lr_babel_hello_t
        freed bool
}

// NewBabelHello builds a Hello TLV with the given seqno + interval.
func NewBabelHello(seqno, intervalCs uint16) *BabelHello {
        h := &BabelHello{ptr: C.lr_babel_hello_new(C.uint16_t(seqno), C.uint16_t(intervalCs))}
        runtime.SetFinalizer(h, (*BabelHello).destroy)
        return h
}

// Seqno returns the Hello's seqno.
func (h *BabelHello) Seqno() uint16 {
        return uint16(C.lr_babel_hello_seqno(h.ptr))
}

// IntervalCs returns the Hello's interval in centiseconds.
func (h *BabelHello) IntervalCs() uint16 {
        return uint16(C.lr_babel_hello_interval_cs(h.ptr))
}

// SetUnicast toggles the unicast flag.
func (h *BabelHello) SetUnicast(on bool) error {
        rc := C.lr_babel_hello_set_unicast(h.ptr, toCBool(on))
        return babelRcErr("lr_babel_hello_set_unicast", rc)
}

// Flags returns the Hello's flags.
func (h *BabelHello) Flags() uint16 {
        return uint16(C.lr_babel_hello_flags(h.ptr))
}

// Encode returns the on-the-wire bytes.
func (h *BabelHello) Encode() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_babel_hello_encode(h.ptr, &b)
        if rc != 0 {
                return nil, babelErr("lr_babel_hello_encode", rc)
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// Free releases the underlying handle.
func (h *BabelHello) Free() { h.destroy() }

func (h *BabelHello) destroy() {
        if h.freed || h.ptr == nil {
                return
        }
        C.lr_babel_hello_free(h.ptr)
        h.ptr = nil
        h.freed = true
}

// BabelIhu is an owned handle to an IHU TLV.
type BabelIhu struct {
        ptr   C.lr_babel_ihu_t
        freed bool
}

// NewBabelIhu builds an IHU TLV with the given rxcost + interval.
func NewBabelIhu(rxcost, intervalCs uint16) *BabelIhu {
        h := &BabelIhu{ptr: C.lr_babel_ihu_new(C.uint16_t(rxcost), C.uint16_t(intervalCs))}
        runtime.SetFinalizer(h, (*BabelIhu).destroy)
        return h
}

// AE returns the IHU's Address Encoding.
func (h *BabelIhu) AE() uint8 {
        return uint8(C.lr_babel_ihu_ae(h.ptr))
}

// Rxcost returns the IHU's rxcost.
func (h *BabelIhu) Rxcost() uint16 {
        return uint16(C.lr_babel_ihu_rxcost(h.ptr))
}

// IntervalCs returns the IHU's interval in centiseconds.
func (h *BabelIhu) IntervalCs() uint16 {
        return uint16(C.lr_babel_ihu_interval_cs(h.ptr))
}

// Encode returns the on-the-wire bytes.
func (h *BabelIhu) Encode() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_babel_ihu_encode(h.ptr, &b)
        if rc != 0 {
                return nil, babelErr("lr_babel_ihu_encode", rc)
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// Free releases the underlying handle.
func (h *BabelIhu) Free() { h.destroy() }

func (h *BabelIhu) destroy() {
        if h.freed || h.ptr == nil {
                return
        }
        C.lr_babel_ihu_free(h.ptr)
        h.ptr = nil
        h.freed = true
}

// BabelAckReq is an owned handle to an Acknowledgment Request TLV.
type BabelAckReq struct {
        ptr   C.lr_babel_ack_req_t
        freed bool
}

// NewBabelAckReq builds an AckReq TLV.
func NewBabelAckReq(nonce, intervalCs uint16) *BabelAckReq {
        a := &BabelAckReq{ptr: C.lr_babel_ack_req_new(C.uint16_t(nonce), C.uint16_t(intervalCs))}
        runtime.SetFinalizer(a, (*BabelAckReq).destroy)
        return a
}

// Nonce returns the AckReq's nonce.
func (a *BabelAckReq) Nonce() uint16 {
        return uint16(C.lr_babel_ack_req_nonce(a.ptr))
}

// IntervalCs returns the AckReq's interval in centiseconds.
func (a *BabelAckReq) IntervalCs() uint16 {
        return uint16(C.lr_babel_ack_req_interval_cs(a.ptr))
}

// Free releases the underlying handle.
func (a *BabelAckReq) Free() { a.destroy() }

func (a *BabelAckReq) destroy() {
        if a.freed || a.ptr == nil {
                return
        }
        C.lr_babel_ack_req_free(a.ptr)
        a.ptr = nil
        a.freed = true
}

// BabelAck is an owned handle to an Acknowledgment TLV.
type BabelAck struct {
        ptr   C.lr_babel_ack_t
        freed bool
}

// NewBabelAck builds an Ack TLV.
func NewBabelAck(opaque uint16) *BabelAck {
        a := &BabelAck{ptr: C.lr_babel_ack_new(C.uint16_t(opaque))}
        runtime.SetFinalizer(a, (*BabelAck).destroy)
        return a
}

// Opaque returns the Ack's opaque value.
func (a *BabelAck) Opaque() uint16 {
        return uint16(C.lr_babel_ack_opaque(a.ptr))
}

// Encode returns the on-the-wire bytes.
func (a *BabelAck) Encode() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_babel_ack_encode(a.ptr, &b)
        if rc != 0 {
                return nil, babelErr("lr_babel_ack_encode", rc)
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// Free releases the underlying handle.
func (a *BabelAck) Free() { a.destroy() }

func (a *BabelAck) destroy() {
        if a.freed || a.ptr == nil {
                return
        }
        C.lr_babel_ack_free(a.ptr)
        a.ptr = nil
        a.freed = true
}

// BabelNextHop is an owned handle to a Next Hop TLV.
type BabelNextHop struct {
        ptr   C.lr_babel_next_hop_t
        freed bool
}

// NewBabelNextHop builds a NextHop TLV from a 4 (IPv4) or 16 (IPv6)
// byte address.
func NewBabelNextHop(addr []byte) (*BabelNextHop, error) {
        if len(addr) == 4 {
                n := &BabelNextHop{ptr: C.lr_babel_next_hop_new_v4(
                        (*C.uint8_t)(unsafe.Pointer(&addr[0])))}
                runtime.SetFinalizer(n, (*BabelNextHop).destroy)
                return n, nil
        }
        if len(addr) == 16 {
                n := &BabelNextHop{ptr: C.lr_babel_next_hop_new_v6(
                        (*C.uint8_t)(unsafe.Pointer(&addr[0])))}
                runtime.SetFinalizer(n, (*BabelNextHop).destroy)
                return n, nil
        }
        return nil, fmt.Errorf("address must be 4 or 16 bytes, got %d", len(addr))
}

// AE returns the NextHop's Address Encoding.
func (n *BabelNextHop) AE() uint8 {
        return uint8(C.lr_babel_next_hop_ae(n.ptr))
}

// Address returns the NextHop's address bytes.
func (n *BabelNextHop) Address() []byte {
        out := make([]byte, 16)
        copied := C.lr_babel_next_hop_address(n.ptr,
                (*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(16))
        nCopied := int(copied)
        if nCopied == 0 {
                return nil
        }
        return out[:nCopied]
}

// Encode returns the on-the-wire bytes.
func (n *BabelNextHop) Encode() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_babel_next_hop_encode(n.ptr, &b)
        if rc != 0 {
                return nil, babelErr("lr_babel_next_hop_encode", rc)
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// Free releases the underlying handle.
func (n *BabelNextHop) Free() { n.destroy() }

func (n *BabelNextHop) destroy() {
        if n.freed || n.ptr == nil {
                return
        }
        C.lr_babel_next_hop_free(n.ptr)
        n.ptr = nil
        n.freed = true
}

// BabelRouterID is an owned handle to a Router-ID TLV.
type BabelRouterID struct {
        ptr   C.lr_babel_router_id_t
        freed bool
}

// NewBabelRouterID builds a Router-ID TLV from an 8-byte identifier.
func NewBabelRouterID(routerID []byte) (*BabelRouterID, error) {
        if len(routerID) != 8 {
                return nil, fmt.Errorf("router_id must be 8 bytes, got %d", len(routerID))
        }
        r := &BabelRouterID{ptr: C.lr_babel_router_id_new(
                (*C.uint8_t)(unsafe.Pointer(&routerID[0])))}
        runtime.SetFinalizer(r, (*BabelRouterID).destroy)
        return r, nil
}

// Bytes returns the 8-byte router identifier.
func (r *BabelRouterID) Bytes() ([]byte, error) {
        // The C ABI copies 10 bytes out (2 reserved + 8 router_id).
        out := make([]byte, 10)
        rc := C.lr_babel_router_id_bytes(r.ptr, (*C.uint8_t)(unsafe.Pointer(&out[0])))
        if rc != 0 {
                return nil, babelErr("lr_babel_router_id_bytes", rc)
        }
        // The router_id occupies bytes 2..10 (RFC 8966 §4.4.10 — the
        // first 2 bytes are reserved/zero).
        return out[2:10], nil
}

// Free releases the underlying handle.
func (r *BabelRouterID) Free() { r.destroy() }

func (r *BabelRouterID) destroy() {
        if r.freed || r.ptr == nil {
                return
        }
        C.lr_babel_router_id_free(r.ptr)
        r.ptr = nil
        r.freed = true
}

// BabelRouteRequest is an owned handle to a wildcard Route Request TLV.
type BabelRouteRequest struct {
        ptr   C.lr_babel_route_request_t
        freed bool
}

// NewBabelRouteRequestWildcard builds a wildcard Route Request.
func NewBabelRouteRequestWildcard() *BabelRouteRequest {
        r := &BabelRouteRequest{ptr: C.lr_babel_route_request_new_wildcard()}
        runtime.SetFinalizer(r, (*BabelRouteRequest).destroy)
        return r
}

// Free releases the underlying handle.
func (r *BabelRouteRequest) Free() { r.destroy() }

func (r *BabelRouteRequest) destroy() {
        if r.freed || r.ptr == nil {
                return
        }
        C.lr_babel_route_request_free(r.ptr)
        r.ptr = nil
        r.freed = true
}

// BabelSeqnoRequest is an owned handle to a Seqno Request TLV.
type BabelSeqnoRequest struct {
        ptr   C.lr_babel_seqno_request_t
        freed bool
}

// NewBabelSeqnoRequest builds a Seqno Request TLV.
func NewBabelSeqnoRequest(prefix []byte, prefixLen uint8, seqno uint16,
        routerID []byte, hopCount uint8) (*BabelSeqnoRequest, error) {
        if len(prefix) != 4 && len(prefix) != 16 {
                return nil, fmt.Errorf("prefix must be 4 or 16 bytes, got %d", len(prefix))
        }
        if len(routerID) != 8 {
                return nil, fmt.Errorf("router_id must be 8 bytes, got %d", len(routerID))
        }
        var v4Ptr, v6Ptr *C.uint8_t
        if len(prefix) == 4 {
                v4Ptr = (*C.uint8_t)(unsafe.Pointer(&prefix[0]))
        } else {
                v6Ptr = (*C.uint8_t)(unsafe.Pointer(&prefix[0]))
        }
        h := C.lr_babel_seqno_request_new(
                v4Ptr, v6Ptr, C.uint8_t(prefixLen), C.uint16_t(seqno),
                (*C.uint8_t)(unsafe.Pointer(&routerID[0])),
                C.uint8_t(hopCount),
        )
        if h == nil {
                return nil, fmt.Errorf("lr_babel_seqno_request_new: %s", LastError())
        }
        r := &BabelSeqnoRequest{ptr: h}
        runtime.SetFinalizer(r, (*BabelSeqnoRequest).destroy)
        return r, nil
}

// Free releases the underlying handle.
func (r *BabelSeqnoRequest) Free() { r.destroy() }

func (r *BabelSeqnoRequest) destroy() {
        if r.freed || r.ptr == nil {
                return
        }
        C.lr_babel_seqno_request_free(r.ptr)
        r.ptr = nil
        r.freed = true
}

// ----------------------------------------------------------------------
// Free function helpers — metric helpers (RFC 8966 §A.2.4 / §3.1 / §3.2.2).
// ----------------------------------------------------------------------

// BabelRttPenalty is the RTT-based extra link cost (RFC 8966 §A.2.4).
func BabelRttPenalty(rttUS, rttMinUS, rttMaxUS uint32, maxPenalty uint16) uint16 {
        return uint16(C.lr_babel_rtt_penalty(C.uint32_t(rttUS), C.uint32_t(rttMinUS),
                C.uint32_t(rttMaxUS), C.uint16_t(maxPenalty)))
}

// BabelRouteMetricSum sums a slice of per-link metric values.
func BabelRouteMetricSum(linkMetrics []uint32) uint32 {
        if len(linkMetrics) == 0 {
                return 0
        }
        arr := make([]C.uint32_t, len(linkMetrics))
        for i, m := range linkMetrics {
                arr[i] = C.uint32_t(m)
        }
        return uint32(C.lr_babel_route_metric_sum(&arr[0], C.size_t(len(arr))))
}

// BabelFeasible reports the Babel feasibility condition (RFC 8966 §3.2.2).
func BabelFeasible(routeSeqno uint16, routeMetric uint32,
        feasibleSeqno uint16, feasibleMetric uint32) bool {
        return C.lr_babel_feasible(C.uint16_t(routeSeqno), C.uint32_t(routeMetric),
                C.uint16_t(feasibleSeqno), C.uint32_t(feasibleMetric)) != 0
}
