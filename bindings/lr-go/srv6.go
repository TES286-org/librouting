// SRv6 structured types — Segment Identifier, Locator, Routing Header,
// Behavior. Mirrors the `lr_srv6` Rust crate (RFC 8754 SRv6 data-plane
// primitives + RFC 8986 endpoint behavior registry).
//
// This file mirrors the public Rust API of `lr_srv6::{Sid, Locator,
// Srh, Behavior}` and the C ABI surface in `lr_ffi.h` (`lr_srv6_*`).
// All resources are garbage-collected via runtime.SetFinalizer when
// the corresponding Go values leave scope, matching the rest of this
// package.
//
// # API hierarchy
//
// The Go surface mirrors the Rust crate's module split:
//   - Sid       — lr_srv6::Sid       (RFC 8754 §3)
//   - Locator   — lr_srv6::Locator   (RFC 8754 §3.1)
//   - Srh       — lr_srv6::Srh       (RFC 8754 §2)
//   - Behavior  — lr_srv6::Behavior  (RFC 8986 §4 — endpoint behaviors)
//
// Each type owns its C ABI handle and frees it via a finalizer when
// the Go value leaves scope. Use Free() for explicit teardown.
//
// # Constants
//
// The SRH layout constants (RFC 8754 §2), flag bits (RFC 8754 §2.1),
// TLV types (RFC 8200 §4.4) and the SrhError discriminant codes mirror
// the LR_SRV6_* #defines in `lr_ffi.h` so a Go caller does not have to
// re-derive them from the RFC.

package librouting

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -llr_ffi

#include <stdlib.h>
#include "lr_ffi.h"
*/
import "C"

import (
        "errors"
        "fmt"
        "runtime"
        "unsafe"
)

// ----------------------------------------------------------------------
// Constants — mirror lr_srv6::srh pub consts and the LR_SRV6_* defines
// in include/lr_ffi.h.
// ----------------------------------------------------------------------

// SRH routing type (RFC 8754 §2, IANA "IPv6 Routing Types" registry).
const SRv6RoutingTypeSRH = 4

// SRH flag bits (RFC 8754 §2.1 + the Linux uapi deployed set).
const (
        SRv6FlagOAM       = 0x20
        SRv6FlagHMAC      = 0x08
        SRv6FlagAlert     = 0x10
        SRv6FlagProtected = 0x40
)

// SRH layout (RFC 8754 §2).
const (
        SRv6SRHFixedLen    = 8
        SRv6SRHSegmentLen  = 16
        SRv6TLVPad1        = 0
        SRv6TLVPadN        = 1
        SRv6MaxSegments    = 127
        SRv6MaxBlockBits   = 128
)

// SrhError discriminants — mirror lr_srv6::SrhError variants.
const (
        SRv6SRHErrTooShort              = 0
        SRv6SRHErrLengthMismatch        = 1
        SRv6SRHErrEmptySegmentList      = 2
        SRv6SRHErrTooManySegments       = 3
        SRv6SRHErrLastEntryOutOfRange   = 4
        SRv6SRHErrSegmentsLeftOutOfRange = 5
        SRv6SRHErrWrongRoutingType      = 6
        SRv6SRHErrReservedFlagBits      = 7
        SRv6SRHErrUnknown               = -1
)

// SidParseError discriminants — mirror lr_srv6::SidParseError variants
// (the C ABI's lr_srv6_sid_parse_error_name uses the same codes).
const (
        SRv6SidParseErrEmpty              = 1
        SRv6SidParseErrDoubleDoubleColon = 2
        SRv6SidParseErrBadHextet         = 3
        SRv6SidParseErrWrongLength       = 4
)

// LocatorParseError discriminants — mirror lr_srv6::LocatorParseError
// variants (the C ABI's lr_srv6_locator_parse_error_name uses the same
// codes).
const (
        SRv6LocatorParseErrMissingPrefixLen = 1
        SRv6LocatorParseErrBadAddr          = 2
        SRv6LocatorParseErrBadPrefixLen     = 3
)

// ----------------------------------------------------------------------
// Errors
// ----------------------------------------------------------------------

// SRv6SidParseError is returned when a SID string fails to parse
// (RFC 5952 §4). Code mirrors the C ABI's discriminant.
type SRv6SidParseError struct {
        Code int
}

func (e *SRv6SidParseError) Error() string {
        name := "UnknownSidParseError"
        switch e.Code {
        case SRv6SidParseErrEmpty:
                name = "Empty"
        case SRv6SidParseErrDoubleDoubleColon:
                name = "DoubleDoubleColon"
        case SRv6SidParseErrBadHextet:
                name = "BadHextet"
        case SRv6SidParseErrWrongLength:
                name = "WrongLength"
        }
        return fmt.Sprintf("SidParseError(%s)", name)
}

// Is enables errors.Is matching against discriminant codes.
func (e *SRv6SidParseError) Is(target error) bool {
        t, ok := target.(*SRv6SidParseError)
        return ok && t.Code == e.Code
}

// SRv6LocatorParseError is returned when a Locator string fails to
// parse (RFC 8754 §3.1 + RFC 5952 §4).
type SRv6LocatorParseError struct {
        Code int
}

func (e *SRv6LocatorParseError) Error() string {
        name := "UnknownLocatorParseError"
        switch e.Code {
        case SRv6LocatorParseErrMissingPrefixLen:
                name = "MissingPrefixLen"
        case SRv6LocatorParseErrBadAddr:
                name = "BadAddr"
        case SRv6LocatorParseErrBadPrefixLen:
                name = "BadPrefixLen"
        }
        return fmt.Sprintf("LocatorParseError(%s)", name)
}

// Is enables errors.Is matching against discriminant codes.
func (e *SRv6LocatorParseError) Is(target error) bool {
        t, ok := target.(*SRv6LocatorParseError)
        return ok && t.Code == e.Code
}

// SRv6SrhError is returned when an SRH encode/decode fails
// (RFC 8754 §2 — `SrhError` discriminant).
type SRv6SrhError struct {
        Code int
}

func (e *SRv6SrhError) Error() string {
        name := "UnknownSrhError"
        switch e.Code {
        case SRv6SRHErrTooShort:
                name = "TooShort"
        case SRv6SRHErrLengthMismatch:
                name = "LengthMismatch"
        case SRv6SRHErrEmptySegmentList:
                name = "EmptySegmentList"
        case SRv6SRHErrTooManySegments:
                name = "TooManySegments"
        case SRv6SRHErrLastEntryOutOfRange:
                name = "LastEntryOutOfRange"
        case SRv6SRHErrSegmentsLeftOutOfRange:
                name = "SegmentsLeftOutOfRange"
        case SRv6SRHErrWrongRoutingType:
                name = "WrongRoutingType"
        case SRv6SRHErrReservedFlagBits:
                name = "ReservedFlagBits"
        }
        return fmt.Sprintf("SrhError(%s)", name)
}

// Is enables errors.Is matching against discriminant codes.
func (e *SRv6SrhError) Is(target error) bool {
        t, ok := target.(*SRv6SrhError)
        return ok && t.Code == e.Code
}

// srhErrorFromLast reads the C ABI's last-error discriminant and
// returns an *SRv6SrhError if it is an SRH error, or nil otherwise.
func srhErrorFromLast() error {
        code := int(C.lr_srv6_srh_last_err_code())
        if code == SRv6SRHErrUnknown {
                return nil
        }
        return &SRv6SrhError{Code: code}
}

// ----------------------------------------------------------------------
// Sid — 128-bit SRv6 Segment Identifier (RFC 8754 §3).
// ----------------------------------------------------------------------

// SRv6Sid is an owned handle to a 128-bit SRv6 Segment Identifier.
// The handle is garbage-collected via a finalizer that calls
// lr_srv6_sid_free.
type SRv6Sid struct {
        ptr C.lr_srv6_sid_t
}

// NewSRv6Sid builds a SID from 16 raw bytes (network byte order).
// Returns an error if len(octets) != 16.
func NewSRv6Sid(octets []byte) (*SRv6Sid, error) {
        if len(octets) != 16 {
                return nil, fmt.Errorf("SRv6Sid must be 16 bytes, got %d", len(octets))
        }
        ptr := C.lr_srv6_sid_new((*C.uint8_t)(unsafe.Pointer(&octets[0])))
        if ptr == nil {
                return nil, fmt.Errorf("lr_srv6_sid_new: %s", LastError())
        }
        s := &SRv6Sid{ptr: ptr}
        runtime.SetFinalizer(s, (*SRv6Sid).destroy)
        return s, nil
}

// SRv6SidUnspecified returns the all-zeros SID (`::`).
func SRv6SidUnspecified() *SRv6Sid {
        s, _ := NewSRv6Sid(make([]byte, 16))
        return s
}

// ParseSRv6Sid parses a SID from the canonical IPv6 textual form
// (RFC 5952 §4). Returns *SRv6SidParseError on malformed input.
func ParseSRv6Sid(s string) (*SRv6Sid, error) {
        if len(s) == 0 {
                return nil, &SRv6SidParseError{Code: SRv6SidParseErrEmpty}
        }
        cs := C.CString(s)
        defer C.free(unsafe.Pointer(cs))
        out := make([]byte, 16)
        rc := C.lr_srv6_sid_from_str(cs, (*C.uint8_t)(unsafe.Pointer(&out[0])))
        if rc == 0 {
                // Wrap the parsed bytes in a Sid handle via the byte ctor
                // (the from_str C ABI writes to a raw buffer, not an
                // lr_srv6_sid_t handle).
                return NewSRv6Sid(out)
        }
        if rc > 0 {
                // Positive rc is a SidParseError discriminant.
                return nil, &SRv6SidParseError{Code: int(rc)}
        }
        // Negative rc is a generic LrError.
        return nil, fmt.Errorf("lr_srv6_sid_from_str: %s (rc=%d)", LastError(), int(rc))
}

// NewSRv6SidFromLocatorTail builds a SID by concatenating a locator
// byte string and a function/argument tail (RFC 8754 §3.1). Mirrors
// `Sid::from_locator_tail` in `lr_srv6::sid`.
func NewSRv6SidFromLocatorTail(locator, tail []byte, locatorBlockBits uint8) (*SRv6Sid, error) {
        locBytes := int(locatorBlockBits / 8)
        if len(locator) != locBytes {
                return nil, fmt.Errorf("locator must be %d bytes for block_bits=%d, got %d",
                        locBytes, locatorBlockBits, len(locator))
        }
        if len(tail)+locBytes != 16 {
                return nil, fmt.Errorf("locator + tail must be 16 bytes, got %d",
                        locBytes+len(tail))
        }
        var locPtr, tailPtr *C.uint8_t
        if len(locator) > 0 {
                locPtr = (*C.uint8_t)(unsafe.Pointer(&locator[0]))
        }
        if len(tail) > 0 {
                tailPtr = (*C.uint8_t)(unsafe.Pointer(&tail[0]))
        }
        ptr := C.lr_srv6_sid_from_locator_tail(
                locPtr, C.size_t(len(locator)),
                tailPtr, C.size_t(len(tail)),
                C.uint8_t(locatorBlockBits),
        )
        if ptr == nil {
                return nil, fmt.Errorf("lr_srv6_sid_from_locator_tail: %s", LastError())
        }
        s := &SRv6Sid{ptr: ptr}
        runtime.SetFinalizer(s, (*SRv6Sid).destroy)
        return s, nil
}

func (s *SRv6Sid) destroy() {
        if s.ptr != nil {
                C.lr_srv6_sid_free(s.ptr)
                s.ptr = nil
        }
}

// Free releases the handle (optional; a finalizer also runs).
func (s *SRv6Sid) Free() {
        runtime.SetFinalizer(s, nil)
        s.destroy()
}

// Octets returns the 16 raw bytes (network byte order).
func (s *SRv6Sid) Octets() ([]byte, error) {
        out := make([]byte, 16)
        rc := C.lr_srv6_sid_octets(s.ptr, (*C.uint8_t)(unsafe.Pointer(&out[0])))
        if rc != 0 {
                return nil, fmt.Errorf("lr_srv6_sid_octets: %s (rc=%d)", LastError(), int(rc))
        }
        return out, nil
}

// String returns the canonical IPv6 textual form (RFC 5952 §4). The
// C ABI uses a thread-local static buffer, so the result is copied
// before the call returns.
func (s *SRv6Sid) String() string {
        octets, err := s.Octets()
        if err != nil {
                return "<bad sid>"
        }
        cs := C.lr_srv6_sid_to_str((*C.uint8_t)(unsafe.Pointer(&octets[0])))
        if cs == nil {
                return ""
        }
        return C.GoString(cs)
}

// IsUnspecified returns true when the SID equals the all-zeros SID.
func (s *SRv6Sid) IsUnspecified() bool {
        return uint8(C.lr_srv6_sid_is_unspecified(s.ptr)) != 0
}

// LocatorSlice slices the locator prefix out of the SID (RFC 8754
// §3.1). Returns (offset, length) so the caller can borrow the slice
// via sid.Octets()[offset:offset+len]. Returns ok=false when
// locatorBlockBits exceeds 128 or is not a multiple of 8.
func (s *SRv6Sid) LocatorSlice(locatorBlockBits uint8) (offset, length int, ok bool) {
        var off, ln C.size_t
        ok = uint8(C.lr_srv6_sid_locator_slice(
                s.ptr, C.uint8_t(locatorBlockBits), &off, &ln,
        )) != 0
        if ok {
                offset = int(off)
                length = int(ln)
        }
        return
}

// IsInsideLocator reports whether the SID falls inside the given
// locator block (RFC 8754 §3.1). Returns false (rather than erroring)
// on an invalid bit length.
func (s *SRv6Sid) IsInsideLocator(locator []byte, locatorBlockBits uint8) bool {
        if len(locator) == 0 {
                return false
        }
        return uint8(C.lr_srv6_sid_is_inside_locator(
                s.ptr,
                (*C.uint8_t)(unsafe.Pointer(&locator[0])),
                C.size_t(len(locator)),
                C.uint8_t(locatorBlockBits),
        )) != 0
}

// ----------------------------------------------------------------------
// Locator — RFC 8754 §3.1.
// ----------------------------------------------------------------------

// SRv6Locator is an owned handle to a locator block (an IPv6 prefix
// plus its bit length). Mirrors `lr_srv6::Locator`.
type SRv6Locator struct {
        ptr C.lr_srv6_locator_t
}

// NewSRv6Locator constructs a Locator from a 16-byte address and a
// bit length. The address is masked so host bits are zero.
func NewSRv6Locator(addr []byte, blockBits uint8) (*SRv6Locator, error) {
        if len(addr) != 16 {
                return nil, fmt.Errorf("addr must be 16 bytes, got %d", len(addr))
        }
        if blockBits > SRv6MaxBlockBits {
                return nil, fmt.Errorf("blockBits must be <= %d, got %d", SRv6MaxBlockBits, blockBits)
        }
        ptr := C.lr_srv6_locator_new((*C.uint8_t)(unsafe.Pointer(&addr[0])), C.uint8_t(blockBits))
        if ptr == nil {
                return nil, fmt.Errorf("lr_srv6_locator_new: %s", LastError())
        }
        l := &SRv6Locator{ptr: ptr}
        runtime.SetFinalizer(l, (*SRv6Locator).destroy)
        return l, nil
}

// NewSRv6LocatorFromSid builds a Locator from a Sid's high blockBits
// bits.
func NewSRv6LocatorFromSid(sid *SRv6Sid, blockBits uint8) (*SRv6Locator, error) {
        if sid == nil {
                return nil, errors.New("NewSRv6LocatorFromSid: nil sid")
        }
        ptr := C.lr_srv6_locator_from_sid(sid.ptr, C.uint8_t(blockBits))
        if ptr == nil {
                return nil, fmt.Errorf("lr_srv6_locator_from_sid: %s", LastError())
        }
        l := &SRv6Locator{ptr: ptr}
        runtime.SetFinalizer(l, (*SRv6Locator).destroy)
        return l, nil
}

// ParseSRv6Locator parses "fcbb:bb00::/48" (RFC 5952 §4 + a /prefix
// suffix). Returns *SRv6LocatorParseError on malformed input.
func ParseSRv6Locator(s string) (*SRv6Locator, error) {
        if len(s) == 0 {
                return nil, &SRv6LocatorParseError{Code: SRv6LocatorParseErrMissingPrefixLen}
        }
        cs := C.CString(s)
        defer C.free(unsafe.Pointer(cs))
        addrOut := make([]byte, 16)
        var bitsOut C.uint8_t
        rc := C.lr_srv6_locator_from_str(
                cs,
                (*C.uint8_t)(unsafe.Pointer(&addrOut[0])),
                &bitsOut,
        )
        if rc == 0 {
                return NewSRv6Locator(addrOut, uint8(bitsOut))
        }
        if rc > 0 {
                return nil, &SRv6LocatorParseError{Code: int(rc)}
        }
        return nil, fmt.Errorf("lr_srv6_locator_from_str: %s (rc=%d)", LastError(), int(rc))
}

func (l *SRv6Locator) destroy() {
        if l.ptr != nil {
                C.lr_srv6_locator_free(l.ptr)
                l.ptr = nil
        }
}

// Free releases the handle (optional; a finalizer also runs).
func (l *SRv6Locator) Free() {
        runtime.SetFinalizer(l, nil)
        l.destroy()
}

// Addr returns the raw 16-byte address (host bits zeroed).
func (l *SRv6Locator) Addr() ([]byte, error) {
        out := make([]byte, 16)
        rc := C.lr_srv6_locator_addr(l.ptr, (*C.uint8_t)(unsafe.Pointer(&out[0])))
        if rc != 0 {
                return nil, fmt.Errorf("lr_srv6_locator_addr: %s (rc=%d)", LastError(), int(rc))
        }
        return out, nil
}

// BlockBits returns the locator prefix length in bits.
func (l *SRv6Locator) BlockBits() uint8 {
        return uint8(C.lr_srv6_locator_block_bits(l.ptr))
}

// BlockBytes returns the locator's byte length (rounded up).
func (l *SRv6Locator) BlockBytes() int {
        return int(C.lr_srv6_locator_block_bytes(l.ptr))
}

// ContainsSid reports whether `sid` falls inside this locator.
func (l *SRv6Locator) ContainsSid(sid *SRv6Sid) bool {
        if sid == nil {
                return false
        }
        return uint8(C.lr_srv6_locator_contains_sid(l.ptr, sid.ptr)) != 0
}

// SidWithTail builds a Sid under this locator by appending the
// 16-byte `tail` (function + arguments).
func (l *SRv6Locator) SidWithTail(tail []byte) (*SRv6Sid, error) {
        if len(tail) != 16 {
                return nil, fmt.Errorf("tail must be 16 bytes, got %d", len(tail))
        }
        ptr := C.lr_srv6_locator_sid_with_tail(l.ptr, (*C.uint8_t)(unsafe.Pointer(&tail[0])))
        if ptr == nil {
                return nil, fmt.Errorf("lr_srv6_locator_sid_with_tail: %s", LastError())
        }
        s := &SRv6Sid{ptr: ptr}
        runtime.SetFinalizer(s, (*SRv6Sid).destroy)
        return s, nil
}

// SidWithIndex allocates a Sid at a given function index inside this
// locator. Returns nil when the locator leaves no room for a 4-byte
// function.
func (l *SRv6Locator) SidWithIndex(functionIndex uint32) (*SRv6Sid, error) {
        ptr := C.lr_srv6_locator_sid_with_index(l.ptr, C.uint32_t(functionIndex))
        if ptr == nil {
                return nil, nil
        }
        s := &SRv6Sid{ptr: ptr}
        runtime.SetFinalizer(s, (*SRv6Sid).destroy)
        return s, nil
}

// String returns the canonical "<addr>/<bits>" textual form.
func (l *SRv6Locator) String() string {
        addr, err := l.Addr()
        if err != nil {
                return "<bad locator>"
        }
        cs := C.lr_srv6_locator_to_str(
                (*C.uint8_t)(unsafe.Pointer(&addr[0])),
                C.uint8_t(l.BlockBits()),
        )
        if cs == nil {
                return ""
        }
        return C.GoString(cs)
}

// ----------------------------------------------------------------------
// Srh — IPv6 Segment Routing Header (RFC 8754 §2).
// ----------------------------------------------------------------------

// SRv6Srh is an owned handle to a Segment Routing Header.
type SRv6Srh struct {
        ptr C.lr_srv6_srh_t
}

// NewSRv6Srh builds an SRH from a segment list. Each entry is either
// a *SRv6Sid or a 16-byte []byte. segmentsLeft defaults to
// len(segments)-1 (RFC 8754 §4.2 — the sender's view).
func NewSRv6Srh(segments []any) (*SRv6Srh, error) {
        return newSRv6SrhWithSegmentsLeft(segments, -1)
}

// NewSRv6SrhWithSegmentsLeft is like NewSRv6Srh but with an explicit
// segmentsLeft.
func NewSRv6SrhWithSegmentsLeft(segments []any, segmentsLeft uint8) (*SRv6Srh, error) {
        return newSRv6SrhWithSegmentsLeft(segments, int(segmentsLeft))
}

func newSRv6SrhWithSegmentsLeft(segments []any, segmentsLeft int) (*SRv6Srh, error) {
        if len(segments) == 0 {
                return nil, &SRv6SrhError{Code: SRv6SRHErrEmptySegmentList}
        }
        if len(segments) > SRv6MaxSegments {
                return nil, &SRv6SrhError{Code: SRv6SRHErrTooManySegments}
        }
        flat := make([]byte, 0, len(segments)*16)
        for i, s := range segments {
                switch v := s.(type) {
                case *SRv6Sid:
                        o, err := v.Octets()
                        if err != nil {
                                return nil, fmt.Errorf("segment %d: %w", i, err)
                        }
                        flat = append(flat, o...)
                case []byte:
                        if len(v) != 16 {
                                return nil, fmt.Errorf("segment %d: must be 16 bytes, got %d", i, len(v))
                        }
                        flat = append(flat, v...)
                default:
                        return nil, fmt.Errorf("segment %d: must be *SRv6Sid or []byte, got %T", i, s)
                }
        }
        var ptr C.lr_srv6_srh_t
        if segmentsLeft < 0 {
                ptr = C.lr_srv6_srh_new(
                        (*C.uint8_t)(unsafe.Pointer(&flat[0])),
                        C.size_t(len(segments)),
                )
        } else {
                ptr = C.lr_srv6_srh_new_with_segments_left(
                        (*C.uint8_t)(unsafe.Pointer(&flat[0])),
                        C.size_t(len(segments)),
                        C.uint8_t(segmentsLeft),
                        1, // segments_left_present: caller provided an explicit value
                )
        }
        if ptr == nil {
                return nil, fmt.Errorf("lr_srv6_srh_new: %s", LastError())
        }
        srh := &SRv6Srh{ptr: ptr}
        runtime.SetFinalizer(srh, (*SRv6Srh).destroy)
        return srh, nil
}

func (s *SRv6Srh) destroy() {
        if s.ptr != nil {
                C.lr_srv6_srh_free(s.ptr)
                s.ptr = nil
        }
}

// Free releases the handle (optional; a finalizer also runs).
func (s *SRv6Srh) Free() {
        runtime.SetFinalizer(s, nil)
        s.destroy()
}

// WithNextHeader sets the Next Header field (RFC 8200 §2). Builder-style.
func (s *SRv6Srh) WithNextHeader(nextHeader uint8) *SRv6Srh {
        C.lr_srv6_srh_set_next_header(s.ptr, C.uint8_t(nextHeader))
        return s
}

// WithFlags sets the flags (RFC 8754 §2.1). Builder-style.
func (s *SRv6Srh) WithFlags(flags uint8) *SRv6Srh {
        C.lr_srv6_srh_set_flags(s.ptr, C.uint8_t(flags))
        return s
}

// WithTag sets the Tag field (RFC 8754 §2.4). Builder-style.
func (s *SRv6Srh) WithTag(tag uint16) *SRv6Srh {
        C.lr_srv6_srh_set_tag(s.ptr, C.uint16_t(tag))
        return s
}

// WithTlvs sets the TLV bytes (RFC 8754 §2.6). Builder-style.
func (s *SRv6Srh) WithTlvs(tlvs []byte) (*SRv6Srh, error) {
        if len(tlvs) == 0 {
                rc := C.lr_srv6_srh_set_tlvs(s.ptr, nil, 0)
                if rc != 0 {
                        return nil, fmt.Errorf("lr_srv6_srh_set_tlvs: %s (rc=%d)", LastError(), int(rc))
                }
                return s, nil
        }
        rc := C.lr_srv6_srh_set_tlvs(
                s.ptr,
                (*C.uint8_t)(unsafe.Pointer(&tlvs[0])),
                C.size_t(len(tlvs)),
        )
        if rc != 0 {
                return nil, fmt.Errorf("lr_srv6_srh_set_tlvs: %s (rc=%d)", LastError(), int(rc))
        }
        return s, nil
}

// NextHeader reads the Next Header field.
func (s *SRv6Srh) NextHeader() uint8 {
        return uint8(C.lr_srv6_srh_next_header(s.ptr))
}

// SegmentsLeft reads the Segments Left field.
func (s *SRv6Srh) SegmentsLeft() uint8 {
        return uint8(C.lr_srv6_srh_segments_left(s.ptr))
}

// LastEntry reads the Last Entry field.
func (s *SRv6Srh) LastEntry() uint8 {
        return uint8(C.lr_srv6_srh_last_entry(s.ptr))
}

// Flags reads the flags field.
func (s *SRv6Srh) Flags() uint8 {
        return uint8(C.lr_srv6_srh_flags(s.ptr))
}

// Tag reads the Tag field.
func (s *SRv6Srh) Tag() uint16 {
        return uint16(C.lr_srv6_srh_tag(s.ptr))
}

// SegmentCount returns the number of segments in the SRH.
func (s *SRv6Srh) SegmentCount() int {
        return int(C.lr_srv6_srh_segment_count(s.ptr))
}

// Len returns the number of segments — mirrors Rust's `Srh::len`.
// For the wire length in bytes, see Encode().
func (s *SRv6Srh) Len() int {
        return int(C.lr_srv6_srh_len(s.ptr))
}

// IsEmpty returns true when the SRH has no segments.
func (s *SRv6Srh) IsEmpty() bool {
        return uint8(C.lr_srv6_srh_is_empty(s.ptr)) != 0
}

// HdrExtLen returns the Hdr Ext Len field (RFC 8200 §4.8 — 8-octet
// units, minus 1).
func (s *SRv6Srh) HdrExtLen() uint8 {
        return uint8(C.lr_srv6_srh_hdr_ext_len(s.ptr))
}

// SegmentAt returns the 16-byte segment at the given index, or
// an error when index is out of range.
func (s *SRv6Srh) SegmentAt(index int) ([]byte, error) {
        out := make([]byte, 16)
        rc := C.lr_srv6_srh_segment_at(s.ptr, C.size_t(index), (*C.uint8_t)(unsafe.Pointer(&out[0])))
        if rc != 0 {
                return nil, fmt.Errorf("lr_srv6_srh_segment_at: out of range (rc=%d)", int(rc))
        }
        return out, nil
}

// Segments returns all segments as a slice of 16-byte slices.
func (s *SRv6Srh) Segments() ([][]byte, error) {
        n := s.SegmentCount()
        out := make([][]byte, n)
        for i := 0; i < n; i++ {
                b, err := s.SegmentAt(i)
                if err != nil {
                        return nil, err
                }
                out[i] = b
        }
        return out, nil
}

// FirstSegment returns Segment List[0] — the destination address at
// the sender (RFC 8754 §4.1).
func (s *SRv6Srh) FirstSegment() ([]byte, error) {
        out := make([]byte, 16)
        rc := C.lr_srv6_srh_first_segment(s.ptr, (*C.uint8_t)(unsafe.Pointer(&out[0])))
        if rc != 0 {
                return nil, fmt.Errorf("lr_srv6_srh_first_segment: empty SRH (rc=%d)", int(rc))
        }
        return out, nil
}

// CurrentDestination returns Segment List[Segments Left] — the
// current destination address (RFC 8754 §4.1).
func (s *SRv6Srh) CurrentDestination() ([]byte, error) {
        out := make([]byte, 16)
        rc := C.lr_srv6_srh_current_destination(s.ptr, (*C.uint8_t)(unsafe.Pointer(&out[0])))
        if rc != 0 {
                return nil, fmt.Errorf("lr_srv6_srh_current_destination: empty SRH (rc=%d)", int(rc))
        }
        return out, nil
}

// Tlvs returns the TLV bytes following the segment list (RFC 8754 §2.6).
func (s *SRv6Srh) Tlvs() ([]byte, error) {
        var out C.struct_lr_bytes_t
        rc := C.lr_srv6_srh_tlvs(s.ptr, &out)
        if rc != 0 {
                return nil, fmt.Errorf("lr_srv6_srh_tlvs: %s (rc=%d)", LastError(), int(rc))
        }
        return copyBytes(&out), nil
}

// Encode encodes the SRH into wire bytes (RFC 8754 §2 — auto-padded
// to a multiple of 8 octets). Returns *SRv6SrhError on encode failure.
func (s *SRv6Srh) Encode() ([]byte, error) {
        var out C.struct_lr_bytes_t
        rc := C.lr_srv6_srh_encode(s.ptr, &out)
        if rc != 0 {
                if srhErr := srhErrorFromLast(); srhErr != nil {
                        return nil, srhErr
                }
                return nil, fmt.Errorf("lr_srv6_srh_encode: %s (rc=%d)", LastError(), int(rc))
        }
        return copyBytes(&out), nil
}

// ----------------------------------------------------------------------
// Behavior — RFC 8986 endpoint behavior registry.
// ----------------------------------------------------------------------

// SRv6BehaviorFromWire parses a 16-bit wire value into the canonical
// (wire, name) pair. Returns ("", false) when the wire value does not
// name a known behavior.
func SRv6BehaviorFromWire(wire uint16) (canonicalWire uint16, name string, ok bool) {
        var outValue C.uint16_t
        buf := make([]byte, 64)
        got := uint8(C.lr_srv6_behavior_from_wire(
                C.uint16_t(wire),
                &outValue,
                (*C.char)(unsafe.Pointer(&buf[0])),
                C.size_t(len(buf)),
        ))
        if got == 0 {
                return 0, "", false
        }
        canonicalWire = uint16(outValue)
        // Find the NUL terminator.
        end := 0
        for end < len(buf) && buf[end] != 0 {
                end++
        }
        name = string(buf[:end])
        return canonicalWire, name, true
}

// SRv6BehaviorWireValue returns the canonical wire value for `wire`
// (strips reserved bits). Returns 0 for unknown values.
func SRv6BehaviorWireValue(wire uint16) uint16 {
        return uint16(C.lr_srv6_behavior_wire_value(C.uint16_t(wire)))
}

// SRv6BehaviorName returns the IANA-registered behavior name (e.g.
// "End", "End.X", "End.DX6") for `wire`. Returns "Unknown(0xNNNN)" for
// unknown values.
func SRv6BehaviorName(wire uint16) string {
        if w, name, ok := SRv6BehaviorFromWire(wire); ok {
                _ = w
                return name
        }
        return fmt.Sprintf("Unknown(0x%04x)", wire)
}

// SRv6BehaviorIsPSP returns true when the behavior carries the
// Penultimate Segment Pop flag (RFC 8986 §4.16).
func SRv6BehaviorIsPSP(wire uint16) bool {
        return uint8(C.lr_srv6_behavior_is_psp(C.uint16_t(wire))) != 0
}

// SRv6BehaviorIsUSP returns true when the behavior carries the
// Ultimate Segment Pop flag (RFC 8986 §4.16).
func SRv6BehaviorIsUSP(wire uint16) bool {
        return uint8(C.lr_srv6_behavior_is_usp(C.uint16_t(wire))) != 0
}

// SRv6BehaviorIsUSD returns true when the behavior carries the
// Ultimate Segment Decap flag (RFC 8986 §4.16).
func SRv6BehaviorIsUSD(wire uint16) bool {
        return uint8(C.lr_srv6_behavior_is_usd(C.uint16_t(wire))) != 0
}

// SRv6BehaviorIsDecap returns true when the behavior is a decap
// (End.D*, RFC 8986 §4.5-§4.13).
func SRv6BehaviorIsDecap(wire uint16) bool {
        return uint8(C.lr_srv6_behavior_is_decap(C.uint16_t(wire))) != 0
}

// SRv6BehaviorIsCrossConnect returns true when the behavior is a
// cross-connect variant (End.X*, RFC 8986 §4.2).
func SRv6BehaviorIsCrossConnect(wire uint16) bool {
        return uint8(C.lr_srv6_behavior_is_cross_connect(C.uint16_t(wire))) != 0
}

// SRv6BehaviorIsTableLookup returns true when the behavior does a
// table lookup (End.DT*, RFC 8986 §4.7-§4.9).
func SRv6BehaviorIsTableLookup(wire uint16) bool {
        return uint8(C.lr_srv6_behavior_is_table_lookup(C.uint16_t(wire))) != 0
}
