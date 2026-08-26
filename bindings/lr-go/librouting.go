// Package librouting provides a Go binding for the librouting C ABI.
//
// It exposes the Layer-3 router lifecycle (NewRouter, AddBGPSession,
// FeedInput, DrainOutput, Tick) and Layer-1 codec helpers (DecodeBGP,
// EncodeKeepalive, DecodeBabel). All resources are garbage-collected via
// runtime.SetFinalizer when the corresponding Go values leave scope.
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

// Router is an owned handle to a librouting router instance.
type Router struct {
	ptr C.lr_router_t
}

// NewRouter creates a new router. The returned *Router is garbage-collected
// via a finalizer that calls lr_router_destroy.
func NewRouter() (*Router, error) {
	r := C.lr_router_new()
	if r == nil {
		return nil, fmt.Errorf("lr_router_new returned null")
	}
	out := &Router{ptr: r}
	runtime.SetFinalizer(out, func(o *Router) {
		if o.ptr != nil {
			C.lr_router_destroy(o.ptr)
			o.ptr = nil
		}
	})
	return out, nil
}

// AddBGPSession adds a BGP session. Returns the session handle.
func (r *Router) AddBGPSession(localAS, peerAS, localBGPID uint32, holdTime, keepalive uint16, asn4 bool) (uint64, error) {
	var h C.uint64_t
	rc := C.lr_router_add_bgp_session(
		r.ptr,
		C.uint32_t(localAS),
		C.uint32_t(peerAS),
		C.uint32_t(localBGPID),
		C.uint16_t(holdTime),
		C.uint16_t(keepalive),
		toCBool(asn4),
		&h,
	)
	if rc != 0 {
		return 0, fmt.Errorf("lr_router_add_bgp_session: %s (rc=%d)", LastError(), int(rc))
	}
	return uint64(h), nil
}

// FeedInput pushes bytes from the peer transport into a session.
func (r *Router) FeedInput(session uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	rc := C.lr_router_feed_input(
		r.ptr,
		C.uint64_t(session),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_feed_input: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// DrainOutput drains bytes the session prepared for the peer transport.
func (r *Router) DrainOutput(session uint64) ([]byte, error) {
	var b C.struct_lr_bytes_t
	rc := C.lr_router_drain_output(
		r.ptr,
		C.uint64_t(session),
		&b,
	)
	if rc != 0 {
		return nil, fmt.Errorf("lr_router_drain_output: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), nil
}

// Tick advances the router clock by `nowMs` milliseconds.
func (r *Router) Tick(nowMs uint64) error {
	rc := C.lr_router_tick(r.ptr, C.uint64_t(nowMs))
	if rc != 0 {
		return fmt.Errorf("lr_router_tick: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// ABIVersion returns the packed ABI version of the linked library.
func ABIVersion() uint32 {
	return uint32(C.lr_abi_version())
}

// LastError returns the most recent error message from the C side.
func LastError() string {
	cstr := C.lr_last_error()
	if cstr == nil {
		return "no error"
	}
	return C.GoString(cstr)
}

// EncodeKeepalive returns the bytes of a BGP KEEPALIVE message.
func EncodeKeepalive() ([]byte, error) {
	var b C.struct_lr_bytes_t
	rc := C.lr_bgp_encode_keepalive(&b)
	if rc != 0 {
		return nil, fmt.Errorf("lr_bgp_encode_keepalive: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), nil
}

// DecodeBGP decodes a single BGP message from `data`. Returns the canonical
// re-encoded bytes of the message on success.
func DecodeBGP(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	var b C.struct_lr_bytes_t
	rc := C.lr_bgp_decode(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&b,
	)
	if rc != 0 {
		return nil, fmt.Errorf("lr_bgp_decode: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), nil
}

// toCBool converts a Go bool to a C.uint8_t (0 or 1).
func toCBool(b bool) C.uint8_t {
	if b {
		return 1
	}
	return 0
}

// copyBytes copies a C lr_bytes_t's contents into a Go slice.
func copyBytes(b *C.struct_lr_bytes_t) []byte {
	n := int(C.lr_bytes_len(b))
	if n == 0 {
		return nil
	}
	ptr := C.lr_bytes_ptr(b)
	out := make([]byte, n)
	copy(out, C.GoBytes(unsafe.Pointer(ptr), C.int(n)))
	return out
}
