// Generic ordered attribute set + apply_set_checked surface.
// Mirrors the Rust crate `lr_core::attr::Attributes` (the BTreeMap
// keyed by 8-bit tag that backs every `Route::attributes` field) and
// the `lr_policy::action::apply_set_checked` fail-closed surface.
//
// This file mirrors the public Rust API of
// `lr_core::attr::{Attributes, Attribute, AttrTag}` and the C ABI
// surface in `lr_ffi.h` (`lr_attributes_*`, `lr_apply_set_*`).
//
// # API hierarchy
//
// The Go surface mirrors the Rust module split:
//   - Attributes      — lr_core::attr::Attributes (generic typed-attribute carrier)
//   - ApplySetChecked — lr_policy::action::apply_set_checked (fail-closed SetAction)
//   - ApplySetError   — lr_policy::action::ApplySetError (RequiresBgpFeature variant)
//
// Each owned handle is garbage-collected via runtime.SetFinalizer,
// matching the rest of this package. Use Free() for explicit teardown.

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
// Constants — mirror LR_APPLY_SET_ERROR_* in lr_ffi.h.
//
// The SetAction discriminants (LR_SET_*) are already defined in
// librouting.go (SetLocalPref / SetMed / SetPrependAs /
// SetAddCommunity / SetMetric / SetTag). This file adds the
// ApplySetError discriminants that did not previously have Go coverage.
// ----------------------------------------------------------------------

// ApplySetError discriminants (LR_APPLY_SET_ERROR_*). Mirror the
// constants defined in crates/lr-ffi/src/policy_batch.rs. The OK case
// is 0; the four *_NO_BGP cases correspond to the four BGP-specific
// SetActions when the lr-policy crate is built without the bgp
// feature (fail-closed).
const (
	ApplySetErrorOK                = C.LR_APPLY_SET_ERROR_OK
	ApplySetErrorLocalPrefNoBgp    = C.LR_APPLY_SET_ERROR_LOCAL_PREF_NO_BGP
	ApplySetErrorMedNoBgp          = C.LR_APPLY_SET_ERROR_MED_NO_BGP
	ApplySetErrorPrependAsNoBgp    = C.LR_APPLY_SET_ERROR_PREPEND_AS_NO_BGP
	ApplySetErrorAddCommunityNoBgp = C.LR_APPLY_SET_ERROR_ADD_COMMUNITY_NO_BGP
	ApplySetErrorNotWired          = C.LR_APPLY_SET_ERROR_NOT_WIRED
	ApplySetErrorUnknown           = C.LR_APPLY_SET_ERROR_UNKNOWN
)

// ApplySetErrorName returns the C ABI's name for an ApplySetError
// discriminant (mirrors lr_apply_set_error_name). The string is stable
// across versions for the documented discriminants.
func ApplySetErrorName(code uint8) string {
	ptr := C.lr_apply_set_error_name(C.uint8_t(code))
	if ptr == nil {
		return fmt.Sprintf("unknown ApplySetError code %d", code)
	}
	return C.GoString(ptr)
}

// ApplySetCheckedError is the error type returned by ApplySetChecked
// when the action cannot be applied. The Code field carries the raw
// LR_APPLY_SET_ERROR_* discriminant so a Go caller can switch on it;
// the Error() string is the C ABI's name for the discriminant.
type ApplySetCheckedError struct {
	Code uint8
}

// Error implements the error interface. The string form is the C
// ABI's name for the discriminant (e.g. "SetLocalPref needs bgp
// feature"), so a Go log line matches the C / Python / C++ binding's
// diagnostic exactly.
func (e *ApplySetCheckedError) Error() string {
	return ApplySetErrorName(e.Code)
}

// ApplySetChecked applies a SetAction to a Route via the fail-closed
// apply_set_checked surface. Mirrors lr_policy::action::apply_set_checked.
//
// The per-action payload shape follows the Rust SetAction variant:
//
//   - SetLocalPref:    arg1 = value (u32)
//   - SetMed:          arg1 = value (u32)
//   - SetPrependAs:    arg1 = asn (u32)
//   - SetAddCommunity: arg1 = asn (u32), arg2 = local (u16)
//   - SetMetric:       arg1 = value (u32)
//   - SetTag:          arg1 = tag (u32)
//
// SetNextHop is not handled here because the variant takes an IpAddr
// (16 bytes for IPv6) that does not fit in three u32 slots; the
// dedicated Route.SetNextHop is the surface for that variant.
//
// Returns an *ApplySetCheckedError when the action cannot be applied
// (e.g. a BGP-specific action against a no-bgp build of lr-policy).
func ApplySetChecked(route *Route, setKind uint8, arg1, arg2, arg3 uint32) error {
	if route == nil || route.ptr == nil {
		return errors.New("ApplySetChecked: nil route")
	}
	code := C.lr_apply_set_checked(route.ptr, C.uint8_t(setKind),
		C.uint32_t(arg1), C.uint32_t(arg2), C.uint32_t(arg3))
	if uint8(code) == ApplySetErrorOK {
		return nil
	}
	return &ApplySetCheckedError{Code: uint8(code)}
}

// ----------------------------------------------------------------------
// Attributes — mirrors lr_core::attr::Attributes.
// ----------------------------------------------------------------------

// Attributes is an owned generic attribute-set handle. Wraps the
// boxed lr_attributes_t so a Go embedder can build, populate and read
// a typed-attribute container using the same surface the Rust crate
// exposes. The container is a BTreeMap keyed by 8-bit tag — insertion
// replaces any existing entry for the same tag, iteration order is
// ascending by tag.
type Attributes struct {
	ptr C.lr_attributes_t
}

// NewAttributes constructs an empty Attributes set.
func NewAttributes() (*Attributes, error) {
	p := C.lr_attributes_new()
	if p == nil {
		return nil, fmt.Errorf("lr_attributes_new: %s", LastError())
	}
	a := &Attributes{ptr: p}
	runtime.SetFinalizer(a, func(o *Attributes) {
		if o.ptr != nil {
			C.lr_attributes_free(o.ptr)
			o.ptr = nil
		}
	})
	return a, nil
}

// Free releases the handle. Safe to call multiple times.
func (a *Attributes) Free() {
	if a == nil {
		return
	}
	runtime.SetFinalizer(a, nil)
	if a.ptr != nil {
		C.lr_attributes_free(a.ptr)
		a.ptr = nil
	}
}

// Len returns the number of attributes in the set. Returns 0 on a
// NULL handle (the safe default for "no attributes to read").
func (a *Attributes) Len() int {
	if a == nil || a.ptr == nil {
		return 0
	}
	return int(C.lr_attributes_len(a.ptr))
}

// IsEmpty reports whether the set holds no attributes. Returns true
// on a NULL handle.
func (a *Attributes) IsEmpty() bool {
	if a == nil || a.ptr == nil {
		return true
	}
	return C.lr_attributes_is_empty(a.ptr) != 0
}

// Insert inserts / replaces one attribute by tag. The value bytes
// are the raw attribute payload; an empty (or nil) value inserts the
// tag with no payload.
func (a *Attributes) Insert(tag uint8, flags uint8, value []byte) error {
	if a == nil || a.ptr == nil {
		return errors.New("Attributes.Insert: nil handle")
	}
	var ptr *C.uint8_t
	if len(value) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&value[0]))
	}
	rc := C.lr_attributes_insert(a.ptr, C.uint8_t(tag), C.uint8_t(flags),
		ptr, C.size_t(len(value)))
	if rc != 0 {
		return fmt.Errorf("lr_attributes_insert failed (rc=%d): %s", int(rc), LastError())
	}
	return nil
}

// Get reads one attribute by tag. Returns (flags, value, true) when
// the tag is present, (0, nil, false) when absent. The full value is
// returned — the C ABI returns the total length even when the
// caller's buffer is too small, and this binding grows its slice to
// fit on the second pass.
func (a *Attributes) Get(tag uint8) (flags uint8, value []byte, ok bool, err error) {
	if a == nil || a.ptr == nil {
		return 0, nil, false, errors.New("Attributes.Get: nil handle")
	}
	var cFlags C.uint8_t
	// Two-pass: discover the length, then read it.
	n := C.lr_attributes_get(a.ptr, C.uint8_t(tag), &cFlags, nil, 0)
	if int64(n) < 0 {
		// -1 LR_ERR_NULL (impossible here), -2 LR_ERR_INVALID_HANDLE
		// means absent.
		return 0, nil, false, nil
	}
	if n == 0 {
		return uint8(cFlags), nil, true, nil
	}
	buf := make([]byte, int(n))
	got := C.lr_attributes_get(a.ptr, C.uint8_t(tag), &cFlags,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if int64(got) < 0 {
		return 0, nil, false, nil
	}
	return uint8(cFlags), buf[:int(got)], true, nil
}

// GetU32BE reads a 4-byte big-endian unsigned integer attribute.
// Returns 0 when the tag is absent or the value is not exactly 4
// bytes long — use Get when the distinction matters.
func (a *Attributes) GetU32BE(tag uint8) uint32 {
	if a == nil || a.ptr == nil {
		return 0
	}
	return uint32(C.lr_attributes_get_u32_be(a.ptr, C.uint8_t(tag)))
}

// GetU64BE reads an 8-byte big-endian unsigned integer attribute.
// Returns 0 when the tag is absent or the value is not exactly 8
// bytes long.
func (a *Attributes) GetU64BE(tag uint8) uint64 {
	if a == nil || a.ptr == nil {
		return 0
	}
	return uint64(C.lr_attributes_get_u64_be(a.ptr, C.uint8_t(tag)))
}

// GetU8 reads a 1-byte unsigned integer attribute. Returns 0 when
// the tag is absent.
func (a *Attributes) GetU8(tag uint8) uint8 {
	if a == nil || a.ptr == nil {
		return 0
	}
	return uint8(C.lr_attributes_get_u8(a.ptr, C.uint8_t(tag)))
}

// Remove removes one attribute by tag. Returns true when the
// attribute was present (and is now removed), false when it was not
// in the set.
func (a *Attributes) Remove(tag uint8) (bool, error) {
	if a == nil || a.ptr == nil {
		return false, errors.New("Attributes.Remove: nil handle")
	}
	rc := C.lr_attributes_remove(a.ptr, C.uint8_t(tag))
	if rc < 0 {
		return false, fmt.Errorf("lr_attributes_remove failed (rc=%d): %s", int(rc), LastError())
	}
	return rc != 0, nil
}

// At reads one attribute by index. Returns (tag, flags, value, true)
// when the index is in range, (0, 0, nil, false) otherwise.
// Iteration order is ascending by tag (BTreeMap order).
func (a *Attributes) At(index int) (tag, flags uint8, value []byte, ok bool, err error) {
	if a == nil || a.ptr == nil {
		return 0, 0, nil, false, errors.New("Attributes.At: nil handle")
	}
	var cTag, cFlags C.uint8_t
	n := C.lr_attributes_at(a.ptr, C.size_t(index), &cTag, &cFlags, nil, 0)
	if int64(n) < 0 {
		return 0, 0, nil, false, nil
	}
	if n == 0 {
		return uint8(cTag), uint8(cFlags), nil, true, nil
	}
	buf := make([]byte, int(n))
	got := C.lr_attributes_at(a.ptr, C.size_t(index), &cTag, &cFlags,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if int64(got) < 0 {
		return 0, 0, nil, false, nil
	}
	return uint8(cTag), uint8(cFlags), buf[:int(got)], true, nil
}

// Iter returns a slice of (tag, flags, value) tuples for every
// attribute in ascending tag order. Convenience wrapper around At —
// the caller does not have to drive the index loop.
func (a *Attributes) Iter() ([]AttributesEntry, error) {
	n := a.Len()
	out := make([]AttributesEntry, 0, n)
	for i := 0; i < n; i++ {
		tag, flags, value, ok, err := a.At(i)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		out = append(out, AttributesEntry{Tag: tag, Flags: flags, Value: value})
	}
	return out, nil
}

// AttributesEntry is one element of the Attributes container, as
// returned by Iter / At.
type AttributesEntry struct {
	Tag   uint8
	Flags uint8
	Value []byte
}
