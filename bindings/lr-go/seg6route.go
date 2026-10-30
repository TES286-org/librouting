// SRv6 netlink route-table — `seg6` (encap) and `seg6local` (endpoint)
// route installation. Mirrors the `lr_osroute::seg6_route` Rust crate
// (RFC 8754 §2 + RFC 8986 §4 + the Linux `seg6` / `seg6local` lwtunnel
// netlink surface) and the C ABI in `lr_ffi.h` (`lr_seg6_route_*` /
// `lr_seg6_local_route_*` / `lr_seg6_netlink_*`).
//
// # API hierarchy
//
// The Go surface mirrors the Rust crate's module split:
//   - Seg6Route       — lr_osroute::seg6_route::Seg6Route       (RFC 8754 §2)
//   - Seg6LocalRoute  — lr_osroute::seg6_route::Seg6LocalRoute  (RFC 8986 §4)
//   - Seg6Netlink     — lr_osroute::seg6_route::Seg6Netlink     (NETLINK_ROUTE)
//   - Seg6EncapMode   — lr_osroute::seg6_route::Seg6EncapMode   (Inline / Encap)
//   - Seg6RouteError  — lr_osroute::seg6_route::Seg6RouteError
//
// Each handle-owning type (Seg6Route / Seg6LocalRoute / Seg6Netlink)
// frees its C ABI handle via a finalizer when the Go value leaves
// scope. Use Free() for explicit teardown.
//
// # Constants
//
// The encap-mode constants (`Seg6EncapInline` / `Seg6EncapEncap`) and
// the `Seg6RouteError` discriminant codes mirror the `LR_SEG6_*`
// `#define`s in `include/lr_ffi.h` so a Go caller does not have to
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
// Constants — mirror lr_osroute::seg6_route pub consts and the
// LR_SEG6_* defines in include/lr_ffi.h.
// ----------------------------------------------------------------------

// Seg6EncapMode (mirrors uapi/linux/seg6_iptunnel.h).
const (
	// Seg6EncapInline inserts the SRH into the existing IPv6 packet
	// without adding an outer header.
	Seg6EncapInline = uint32(C.LR_SEG6_ENCAP_INLINE)
	// Seg6EncapEncap wraps the original packet in an outer IPv6
	// header carrying the SRH; the default for tunneled traffic.
	Seg6EncapEncap = uint32(C.LR_SEG6_ENCAP_ENCAP)
)

// Seg6RouteError discriminants — mirror lr_osroute::Seg6RouteError
// variants. Positive integers; the global LR_ERR_* codes remain
// negative.
const (
	// Seg6ErrUnsupported: the platform has no SRv6 (non-Linux
	// builds).
	Seg6ErrUnsupported = int32(C.LR_SEG6_ERR_UNSUPPORTED)
	// Seg6ErrNotEnabled: the kernel's `seg6_enabled` sysctl is 0 —
	// the embedder must `sysctl -w net.ipv6.conf.all.seg6_enabled=1`
	// first.
	Seg6ErrNotEnabled = int32(C.LR_SEG6_ERR_NOT_ENABLED)
	// Seg6ErrSyscall: a netlink syscall failed (sendmsg / recv /
	// socket / bind).
	Seg6ErrSyscall = int32(C.LR_SEG6_ERR_SYSCALL)
	// Seg6ErrKernel: the kernel rejected the request (e.g. EEXIST
	// on a duplicate SID, ENODEV on a device-less IPv6 route).
	Seg6ErrKernel = int32(C.LR_SEG6_ERR_KERNEL)
	// Seg6ErrBadSrh: the SRH encode failed (RFC 8754 §2 validation:
	// empty segment list, reserved flag bits, out-of-range
	// segments_left, etc.).
	Seg6ErrBadSrh = int32(C.LR_SEG6_ERR_BAD_SRH)
	// Seg6ErrUnsupportedAction: the behavior cannot be encoded as a
	// `seg6local` action (the kernel's `seg6_action_table` has no
	// descriptor for it, or the route's parameter set does not
	// satisfy the kernel's contract for it).
	Seg6ErrUnsupportedAction = int32(C.LR_SEG6_ERR_UNSUPPORTED_ACTION)
	// Seg6ErrUnknown is the forward-compat sentinel returned when
	// no Seg6RouteError is recorded (the last FFI call succeeded or
	// stored a non-Seg6Route error).
	Seg6ErrUnknown = int32(C.LR_SEG6_ERR_UNKNOWN)
)

// ----------------------------------------------------------------------
// Errors
// ----------------------------------------------------------------------

// Seg6RouteErr is the typed error returned by the Seg6Netlink methods
// when the C ABI returns a positive LR_SEG6_ERR_* discriminant. The
// Code field carries the discriminant; the Message field carries the
// human-readable message recorded in the last-error string.
type Seg6RouteErr struct {
	Code    int32
	Message string
}

// Error implements the error interface.
func (e *Seg6RouteErr) Error() string {
	name := Seg6RouteErrName(e.Code)
	if e.Message == "" {
		return fmt.Sprintf("seg6 route: %s (code=%d)", name, e.Code)
	}
	return fmt.Sprintf("seg6 route: %s: %s (code=%d)", name, e.Message, e.Code)
}

// newSeg6RouteErr builds a Seg6RouteErr from the C ABI's last-error
// string + the discriminant.
func newSeg6RouteErr(code int32) *Seg6RouteErr {
	if code <= 0 {
		// Not a seg6-specific error — fall back to a generic
		// wrapper.
		return &Seg6RouteErr{Code: Seg6ErrUnknown, Message: LastError()}
	}
	return &Seg6RouteErr{Code: code, Message: LastError()}
}

// Seg6RouteErrName returns the stable name for a Seg6RouteError
// discriminant (mirror of the C ABI's lr_seg6_route_err_name).
func Seg6RouteErrName(code int32) string {
	cstr := C.lr_seg6_route_err_name(C.int32_t(code))
	if cstr == nil {
		return "unknown"
	}
	return C.GoString(cstr)
}

// Seg6RouteErrCode returns the discriminant of the most recent
// Seg6RouteError recorded in the C ABI's last-error string. Returns
// Seg6ErrUnknown when no seg6 error is recorded.
func Seg6RouteErrCode() int32 {
	return int32(C.lr_seg6_route_err_code())
}

// ----------------------------------------------------------------------
// Seg6Route (RFC 8754 §2 — seg6 lwtunnel encap route)
// ----------------------------------------------------------------------

// Seg6Route is an owned handle to a `seg6` encap route (RFC 8754 §2 —
// the LSP head-end: push an SRH on packets matching `prefix`). The
// handle is garbage-collected via a finalizer that calls
// lr_seg6_route_free.
type Seg6Route struct {
	ptr C.lr_seg6_route_t
}

// NewSeg6Route builds a Seg6Route from an IPv6 prefix and an SRH
// handle. The default encap mode is Encap (mirrors `ip route add ...
// encap seg6 mode encap ...`). The SRH handle is borrowed — the
// constructor clones the inner SRH.
func NewSeg6Route(prefix PrefixSpec, srh *SRv6Srh) (*Seg6Route, error) {
	if srh == nil || srh.ptr == nil {
		return nil, errors.New("NewSeg6Route: srh is nil")
	}
	if !prefix.IsIPv6 {
		return nil, errors.New("NewSeg6Route: prefix must be IPv6 (seg6 lwtunnel is IPv6-only)")
	}
	cp, err := prefix.toC()
	if err != nil {
		return nil, fmt.Errorf("NewSeg6Route: %v", err)
	}
	ptr := C.lr_seg6_route_new(cp, srh.ptr)
	if ptr == nil {
		return nil, fmt.Errorf("lr_seg6_route_new: %s", LastError())
	}
	r := &Seg6Route{ptr: ptr}
	runtime.SetFinalizer(r, func(s *Seg6Route) { s.destroy() })
	return r, nil
}

func (r *Seg6Route) destroy() {
	if r.ptr != nil {
		C.lr_seg6_route_free(r.ptr)
		r.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (r *Seg6Route) Free() {
	runtime.SetFinalizer(r, nil)
	r.destroy()
}

// WithMode sets the encap mode (RFC 8754 §2 — Inline inserts the SRH
// into the existing IPv6 packet; Encap wraps it in an outer IPv6
// header carrying the SRH). Builder-style.
func (r *Seg6Route) WithMode(mode uint32) (*Seg6Route, error) {
	rc := C.lr_seg6_route_set_mode(r.ptr, C.uint32_t(mode))
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_route_set_mode: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// WithIfIndex sets the output interface index (RTA_OIF). The kernel's
// fib6_nh_init rejects a route that names neither an egress device
// nor a gateway with ENODEV, so callers usually set this. 0 means
// "let the kernel resolve via the gateway". Builder-style.
func (r *Seg6Route) WithIfIndex(ifIndex uint32) (*Seg6Route, error) {
	rc := C.lr_seg6_route_set_if_index(r.ptr, C.uint32_t(ifIndex))
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_route_set_if_index: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// ----------------------------------------------------------------------
// Seg6LocalRoute (RFC 8986 §4 — seg6local endpoint route)
// ----------------------------------------------------------------------

// Seg6LocalRoute is an owned handle to a `seg6local` endpoint route
// (RFC 8986 §4 — the LSP tail-end: run `behavior` when a packet
// arrives addressed to `sid`). The handle is garbage-collected via a
// finalizer that calls lr_seg6_local_route_free.
type Seg6LocalRoute struct {
	ptr C.lr_seg6_local_route_t
}

// NewSeg6LocalRoute builds a Seg6LocalRoute from a SID handle and an
// IANA behavior wire value (one of the lr_srv6::Behavior wire codes
// — End=1, End.X=5, End.T=9, …). The behavior is resolved via
// Behavior::from_wire; an unknown wire value is rejected with an
// error.
func NewSeg6LocalRoute(sid *SRv6Sid, behaviorWire uint16) (*Seg6LocalRoute, error) {
	if sid == nil || sid.ptr == nil {
		return nil, errors.New("NewSeg6LocalRoute: sid is nil")
	}
	ptr := C.lr_seg6_local_route_new(sid.ptr, C.uint16_t(behaviorWire))
	if ptr == nil {
		return nil, fmt.Errorf("lr_seg6_local_route_new: %s", LastError())
	}
	r := &Seg6LocalRoute{ptr: ptr}
	runtime.SetFinalizer(r, func(s *Seg6LocalRoute) { s.destroy() })
	return r, nil
}

func (r *Seg6LocalRoute) destroy() {
	if r.ptr != nil {
		C.lr_seg6_local_route_free(r.ptr)
		r.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (r *Seg6LocalRoute) Free() {
	runtime.SetFinalizer(r, nil)
	r.destroy()
}

// WithIfIndex sets the route-level egress interface index (RTA_OIF).
// Required for the install to be accepted: the kernel's fib6_nh_init
// rejects a route that names neither an egress device nor a gateway
// with ENODEV. Builder-style.
func (r *Seg6LocalRoute) WithIfIndex(ifIndex uint32) (*Seg6LocalRoute, error) {
	rc := C.lr_seg6_local_route_set_if_index(r.ptr, C.uint32_t(ifIndex))
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_local_route_set_if_index: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// WithNh4 sets the IPv4 next-hop (SEG6_LOCAL_NH4 — the End.DX4
// parameter). `nh4` is a 4-byte buffer in network byte order.
// Builder-style.
func (r *Seg6LocalRoute) WithNh4(nh4 [4]byte) (*Seg6LocalRoute, error) {
	rc := C.lr_seg6_local_route_set_nh4(r.ptr, (*C.uint8_t)(unsafe.Pointer(&nh4[0])))
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_local_route_set_nh4: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// WithNh6 sets the IPv6 next-hop (SEG6_LOCAL_NH6 — the End.X / End.DX6
// parameter). `nh6` is a 16-byte buffer in network byte order.
// Builder-style.
func (r *Seg6LocalRoute) WithNh6(nh6 [16]byte) (*Seg6LocalRoute, error) {
	rc := C.lr_seg6_local_route_set_nh6(r.ptr, (*C.uint8_t)(unsafe.Pointer(&nh6[0])))
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_local_route_set_nh6: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// WithIif sets the input interface index (SEG6_LOCAL_IIF). Note: no
// mainline kernel `seg6local` action consumes the IIF parameter
// today — the install will fail with a descriptive error until a
// kernel action adopts it. Builder-style.
func (r *Seg6LocalRoute) WithIif(iif uint32) (*Seg6LocalRoute, error) {
	rc := C.lr_seg6_local_route_set_iif(r.ptr, C.uint32_t(iif))
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_local_route_set_iif: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// WithOif sets the output interface index (SEG6_LOCAL_OIF — the
// End.DX2 parameter; an optional End.X steering parameter).
// Builder-style.
func (r *Seg6LocalRoute) WithOif(oif uint32) (*Seg6LocalRoute, error) {
	rc := C.lr_seg6_local_route_set_oif(r.ptr, C.uint32_t(oif))
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_local_route_set_oif: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// WithTable sets the routing table ID (SEG6_LOCAL_TABLE — the End.T
// parameter; also tolerated by the legacy End.DT6 path on a
// non-L3-master kernel). Mutually exclusive with WithVrfTable in
// practice — every kernel action descriptor accepts at most one of
// the two, and the encoder's parameter contract check rejects a
// route that sets both. Builder-style.
func (r *Seg6LocalRoute) WithTable(table uint32) (*Seg6LocalRoute, error) {
	rc := C.lr_seg6_local_route_set_table(r.ptr, C.uint32_t(table))
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_local_route_set_table: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// WithVrfTable sets the VRF table ID (SEG6_LOCAL_VRFTABLE — the
// End.DT4 / End.DT46 parameter; also accepted by the L3-master-dev
// form of End.DT6). Mutually exclusive with WithTable. Builder-style.
func (r *Seg6LocalRoute) WithVrfTable(vrfTable uint32) (*Seg6LocalRoute, error) {
	rc := C.lr_seg6_local_route_set_vrf_table(r.ptr, C.uint32_t(vrfTable))
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_local_route_set_vrf_table: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// WithSrh sets the SRv6 Routing Header (SEG6_LOCAL_SRH — the
// End.B6.Insert / End.B6.Encaps parameter). The SRH is the same wire
// form a `seg6` encap route pushes (RFC 8754 §2); the endpoint
// inserts (End.B6.Insert) or wraps (End.B6.Encaps) it onto the
// packet at the binding-SID endpoint. The SRH handle is borrowed —
// the setter clones the inner SRH. Builder-style.
func (r *Seg6LocalRoute) WithSrh(srh *SRv6Srh) (*Seg6LocalRoute, error) {
	if srh == nil || srh.ptr == nil {
		return nil, errors.New("Seg6LocalRoute.WithSrh: srh is nil")
	}
	rc := C.lr_seg6_local_route_set_srh(r.ptr, srh.ptr)
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_local_route_set_srh: %s (rc=%d)", LastError(), int(rc))
	}
	return r, nil
}

// ----------------------------------------------------------------------
// Seg6Netlink (NETLINK_ROUTE backend)
// ----------------------------------------------------------------------

// Seg6Netlink is an owned handle to a NETLINK_ROUTE backend for
// installing / deleting seg6 / seg6local routes. The handle is
// garbage-collected via a finalizer that calls
// lr_seg6_netlink_free.
type Seg6Netlink struct {
	ptr C.lr_seg6_netlink_t
}

// NewSeg6Netlink opens a NETLINK_ROUTE socket for SRv6 route
// installation. Returns a Seg6RouteErr (Code = Seg6ErrNotEnabled or
// Seg6ErrUnsupported) when the kernel's `seg6_enabled` sysctl is 0
// or the platform has no SRv6.
func NewSeg6Netlink() (*Seg6Netlink, error) {
	ptr := C.lr_seg6_netlink_connect()
	if ptr == nil {
		return nil, newSeg6RouteErr(Seg6RouteErrCode())
	}
	n := &Seg6Netlink{ptr: ptr}
	runtime.SetFinalizer(n, func(s *Seg6Netlink) { s.destroy() })
	return n, nil
}

func (n *Seg6Netlink) destroy() {
	if n.ptr != nil {
		C.lr_seg6_netlink_free(n.ptr)
		n.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (n *Seg6Netlink) Free() {
	runtime.SetFinalizer(n, nil)
	n.destroy()
}

// AddSeg6Route installs a `seg6` encap route (RFC 8754 §2 — the LSP
// head-end: push an SRH on packets matching `prefix`). The kernel's
// fib6_nh_init rejects a route that names neither an egress device
// nor a gateway, so the caller usually sets `if_index` via
// Seg6Route.WithIfIndex.
func (n *Seg6Netlink) AddSeg6Route(route *Seg6Route) error {
	if route == nil || route.ptr == nil {
		return errors.New("Seg6Netlink.AddSeg6Route: route is nil")
	}
	rc := C.lr_seg6_netlink_add_seg6_route(n.ptr, route.ptr)
	if rc != 0 {
		return newSeg6RouteErr(Seg6RouteErrCode())
	}
	return nil
}

// DeleteSeg6Route deletes a `seg6` encap route by prefix (the
// minimal prefix-shaped delete iproute2 sends: `ip route del
// PREFIX`).
func (n *Seg6Netlink) DeleteSeg6Route(prefix PrefixSpec) error {
	cp, err := prefix.toC()
	if err != nil {
		return fmt.Errorf("Seg6Netlink.DeleteSeg6Route: %v", err)
	}
	rc := C.lr_seg6_netlink_delete_seg6_route(n.ptr, cp)
	if rc != 0 {
		return newSeg6RouteErr(Seg6RouteErrCode())
	}
	return nil
}

// AddSeg6LocalRoute installs a `seg6local` endpoint route (RFC 8986
// §4 — the LSP tail-end: run `behavior` when a packet arrives
// addressed to `sid`). The kernel's `seg6_action_table` requires a
// per-behavior parameter set; the encoder fails fast with
// Seg6ErrUnsupportedAction for behaviors or parameter sets the
// kernel would reject with a bare EINVAL.
func (n *Seg6Netlink) AddSeg6LocalRoute(route *Seg6LocalRoute) error {
	if route == nil || route.ptr == nil {
		return errors.New("Seg6Netlink.AddSeg6LocalRoute: route is nil")
	}
	rc := C.lr_seg6_netlink_add_seg6local_route(n.ptr, route.ptr)
	if rc != 0 {
		return newSeg6RouteErr(Seg6RouteErrCode())
	}
	return nil
}

// DeleteSeg6LocalRoute deletes a `seg6local` endpoint route by SID
// (the same minimal prefix-shaped delete as DeleteSeg6Route, against
// the local table — seg6local rows are /128 SIDs).
func (n *Seg6Netlink) DeleteSeg6LocalRoute(sid *SRv6Sid) error {
	if sid == nil || sid.ptr == nil {
		return errors.New("Seg6Netlink.DeleteSeg6LocalRoute: sid is nil")
	}
	rc := C.lr_seg6_netlink_delete_seg6local_route(n.ptr, sid.ptr)
	if rc != 0 {
		return newSeg6RouteErr(Seg6RouteErrCode())
	}
	return nil
}

// LastRequestBytes returns the most recent request bytes (the
// diagnostic for "the kernel rejected this and I need to see what
// \"this\" was" — hex-dump it on failure and compare against a
// reference implementation's bytes). Returns nil when no request has
// been sent yet.
func (n *Seg6Netlink) LastRequestBytes() ([]byte, error) {
	var out C.struct_lr_bytes_t
	rc := C.lr_seg6_netlink_last_request_bytes(n.ptr, &out)
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_netlink_last_request_bytes: %s (rc=%d)", LastError(), int(rc))
	}
	if out.ptr == nil || out.len == 0 {
		C.lr_bytes_free(&out)
		return nil, nil
	}
	buf := C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len))
	C.lr_bytes_free(&out)
	return buf, nil
}

// LastResponseBytes returns the most recent response bytes (the raw
// NAK, extack attributes included, for the same purpose as
// LastRequestBytes). Returns nil when no response has been received
// yet.
func (n *Seg6Netlink) LastResponseBytes() ([]byte, error) {
	var out C.struct_lr_bytes_t
	rc := C.lr_seg6_netlink_last_response_bytes(n.ptr, &out)
	if rc != 0 {
		return nil, fmt.Errorf("lr_seg6_netlink_last_response_bytes: %s (rc=%d)", LastError(), int(rc))
	}
	if out.ptr == nil || out.len == 0 {
		C.lr_bytes_free(&out)
		return nil, nil
	}
	buf := C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len))
	C.lr_bytes_free(&out)
	return buf, nil
}
