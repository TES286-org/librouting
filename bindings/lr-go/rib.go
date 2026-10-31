// RIB storage — Loc-RIB, Adj-RIB-In, Adj-RIB-Out, cross-protocol mux.
//
// Mirrors the public Rust API of `lr_rib::{LocRib, AdjRibIn, AdjRibOut,
// RibMux, RouteSelector}` and the C ABI surface in `lr_ffi.h`
// (`lr_loc_rib_*`, `lr_adj_rib_in_*`, `lr_adj_rib_out_*`,
// `lr_rib_mux_*`, `lr_route_selector_*`). All resources are
// garbage-collected via runtime.SetFinalizer when the corresponding Go
// values leave scope, matching the rest of this package.
//
// RFC references:
//   - RFC 4271 §9: the RIB model (Adj-RIB-In, Loc-RIB, Adj-RIB-Out).
//   - RFC 7911: Add-Path keeps more than one path per prefix in Loc-RIB.
//   - RFC 8277: labeled-unicast uses a source-prefix in the key.

package librouting

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -llr_ffi

#include <stdlib.h>
#include "lr_ffi.h"

// Forward-declare the Go trampolines cgo will export. The Go side
// implements them; cgo provides the C-callable symbol.
extern void go_lr_route_iter_cb(lr_route_t route, void *user);
extern void go_lr_loc_rib_iter_sets_cb(uint8_t *prefix_out,
                                        uint8_t prefix_len,
                                        uint8_t is_ipv6,
                                        uintptr_t path_count,
                                        void *user);
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// AFI / SAFI constants (mirror NlriFamily in lr_core::nlri).
const (
	AFIIPv4        = 1
	AFIIPv6        = 2
	SAFIUnicast    = 1
	SAFIMulticast  = 2
	SAFILabeledUni = 4
)

// RouteKey mirrors `lr_core::rib::RouteKey` and the C ABI's
// `lr_route_key_t`. The prefix is (addr, prefixLen); the address is 4
// or 16 bytes. AFI/SAFI identify the NLRI family. The optional source
// prefix carries the RFC 8277 source-specific address.
type RouteKey struct {
	Addr      []byte // 4 (IPv4) or 16 (IPv6) bytes
	PrefixLen uint8
	AFI       uint16
	SAFI      uint8
	Source    []byte // nil or 4/16 bytes
	SourceLen uint8
}

// RouteOrigin mirrors `lr_core::rib::RouteOrigin` and the C ABI's
// `lr_route_origin_t`. Protocol is one of the Protocol* constants;
// Peer is the per-peer session handle (0 for locally originated).
type RouteOrigin struct {
	Protocol Protocol
	Peer     uint64
}

// RibDiff is the generation-based delta returned from LocRib.DiffSince.
// Only the three counts are surfaced through the C ABI today.
type RibDiff struct {
	Added    uint
	Modified uint
	Removed  uint
}

// ---- Callback registry ----
//
// The C ABI takes raw `void (*)(lr_route_t, void *)` function
// pointers, so we register Go-side callbacks in a map keyed by an
// integer index and pass that index as the `user` pointer. The
// exported Go trampolines (`go_lr_route_iter_cb` etc.) look up the
// callback by index and invoke it.

var (
	ribCallbacksMu sync.Mutex
	ribCallbacks   = map[int]interface{}{}
	ribCallbackSeq int
)

func ribCallbackRegister(cb interface{}) int {
	ribCallbacksMu.Lock()
	defer ribCallbacksMu.Unlock()
	ribCallbackSeq++
	ribCallbacks[ribCallbackSeq] = cb
	return ribCallbackSeq
}

func ribCallbackRelease(idx int) {
	ribCallbacksMu.Lock()
	defer ribCallbacksMu.Unlock()
	delete(ribCallbacks, idx)
}

func ribCallbackLookup(idx int) interface{} {
	ribCallbacksMu.Lock()
	defer ribCallbacksMu.Unlock()
	return ribCallbacks[idx]
}

//export go_lr_route_iter_cb
func go_lr_route_iter_cb(route C.lr_route_t, user unsafe.Pointer) {
	idx := int(uintptr(user))
	cb := ribCallbackLookup(idx)
	if fn, ok := cb.(func(C.lr_route_t)); ok {
		fn(route)
	}
}

//export go_lr_loc_rib_iter_sets_cb
func go_lr_loc_rib_iter_sets_cb(prefixOut *C.uint8_t, prefixLen C.uint8_t, isIPv6 C.uint8_t, pathCount C.uintptr_t, user unsafe.Pointer) {
	idx := int(uintptr(user))
	cb := ribCallbackLookup(idx)
	if fn, ok := cb.(func(LocRibSetEntry)); ok {
		var entry LocRibSetEntry
		// Read 16 bytes from prefixOut; the C ABI places the IPv4
		// address in the first 4 bytes (zero-padded after).
		buf := (*[16]C.uint8_t)(unsafe.Pointer(prefixOut))
		for i := 0; i < 16; i++ {
			entry.Addr[i] = byte(buf[i])
		}
		entry.PrefixLen = uint8(prefixLen)
		entry.IsIPv6 = isIPv6 != 0
		entry.PathCount = uint(pathCount)
		fn(entry)
	}
}

// toC builds a `lr_route_key_t` from this RouteKey. The returned C
// struct lives on the heap; the caller passes its address to the C
// ABI and lets Go GC the backing memory.
func (k *RouteKey) toC() C.lr_route_key_t {
	var ck C.lr_route_key_t
	writeCorePrefix(&ck.prefix, k.Addr, k.PrefixLen)
	ck.afi_safi = C.uint16_t((uint16(k.AFI) << 8) | (uint16(k.SAFI) & 0xff))
	if k.Source != nil {
		ck.has_source = C.uint8_t(1)
		writeCorePrefix(&ck.source_prefix, k.Source, k.SourceLen)
	} else {
		ck.has_source = C.uint8_t(0)
	}
	return ck
}

// writeCorePrefix fills a `lr_core_prefix_t` from an address slice
// and a prefix length. The address slice must be 4 or 16 bytes. IPv4
// addresses occupy the *last* 4 bytes of the 16-byte `octets` array
// (the IPv4-mapped IPv6 layout the C ABI uses).
func writeCorePrefix(p *C.lr_core_prefix_t, addr []byte, prefixLen uint8) {
	// Zero the octets first.
	for i := 0; i < 16; i++ {
		p.addr.octets[i] = 0
	}
	if len(addr) == 4 {
		p.addr.is_ipv6 = 0
		for i, b := range addr {
			p.addr.octets[12+i] = C.uint8_t(b)
		}
	} else {
		p.addr.is_ipv6 = 1
		for i, b := range addr {
			p.addr.octets[i] = C.uint8_t(b)
		}
	}
	p.prefix_len = C.uint8_t(prefixLen)
}

// toPrefixC builds a `lr_prefix_t` from a (addr, prefixLen) pair. Used
// by the lr_loc_rib_uninstall / lr_adj_rib_in_withdraw / etc. that
// take a `lr_prefix_t` directly instead of a `lr_route_key_t`.
func toPrefixC(addr []byte, prefixLen uint8) C.lr_prefix_t {
	var p C.lr_prefix_t
	for i := 0; i < 16; i++ {
		p.addr[i] = 0
	}
	if len(addr) == 4 {
		p.is_ipv6 = 0
		for i, b := range addr {
			p.addr[i] = C.uint8_t(b)
		}
	} else {
		p.is_ipv6 = 1
		for i, b := range addr {
			p.addr[i] = C.uint8_t(b)
		}
	}
	p.prefix_len = C.uint8_t(prefixLen)
	return p
}

// LocRib is an owned Loc-RIB handle (RFC 4271 §9.1).
type LocRib struct {
	ptr C.lr_loc_rib_t
}

// NewLocRib constructs an empty Loc-RIB.
func NewLocRib() (*LocRib, error) {
	p := C.lr_loc_rib_new()
	if p == nil {
		return nil, fmt.Errorf("lr_loc_rib_new: %s", LastError())
	}
	r := &LocRib{ptr: p}
	runtime.SetFinalizer(r, (*LocRib).destroy)
	return r, nil
}

func (r *LocRib) destroy() {
	if r.ptr != nil {
		C.lr_loc_rib_free(r.ptr)
		r.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (r *LocRib) Free() {
	runtime.SetFinalizer(r, nil)
	r.destroy()
}

// Install one path into the Loc-RIB. The route handle is *consumed*
// — the caller must not use it after this call. Returns true when
// the install changed the Loc-RIB (a new path or non-identical
// replacement); false for a byte-identical no-op (no generation bump).
func (r *LocRib) Install(route *Route) (bool, error) {
	rc := C.lr_loc_rib_install(r.ptr, route.ptr)
	if rc < 0 {
		return false, fmt.Errorf("lr_loc_rib_install: %s (rc=%d)", LastError(), int(rc))
	}
	// LocRib took ownership.
	route.ptr = nil
	return int(rc) == 1, nil
}

// Uninstall a key. Returns true when a route was withdrawn, false
// when the key was not present.
func (r *LocRib) Uninstall(key RouteKey) (bool, error) {
	prefixC := toPrefixC(key.Addr, key.PrefixLen)
	var sourceC *C.lr_prefix_t
	if key.Source != nil {
		s := toPrefixC(key.Source, key.SourceLen)
		sourceC = &s
	}
	rc := C.lr_loc_rib_uninstall(r.ptr, &prefixC, C.uint16_t(key.AFI), C.uint8_t(key.SAFI), sourceC)
	if rc < 0 {
		return false, fmt.Errorf("lr_loc_rib_uninstall: %s (rc=%d)", LastError(), int(rc))
	}
	return int(rc) == 1, nil
}

// InstallSet installs a ranked set of paths for a key (RFC 7911 —
// Add-Path keeps more than one path per prefix; the first element is
// the best path non-Add-Path consumers see). The handles are *not*
// consumed — the Loc-RIB clones the underlying Route value.
func (r *LocRib) InstallSet(key RouteKey, routes []*Route) error {
	if len(routes) == 0 {
		return fmt.Errorf("InstallSet: at least one route required")
	}
	keyC := key.toC()
	arr := make([]C.lr_route_t, len(routes))
	for i, rt := range routes {
		arr[i] = rt.ptr
	}
	rc := C.lr_loc_rib_install_set(r.ptr, &keyC, (*C.lr_route_t)(unsafe.Pointer(&arr[0])), C.uintptr_t(len(routes)))
	if rc < 0 {
		return fmt.Errorf("lr_loc_rib_install_set: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// PathsLen returns the total number of stored paths (>= Len() under
// RFC 7911 Add-Path).
func (r *LocRib) PathsLen() uint {
	return uint(C.lr_loc_rib_paths_len(r.ptr))
}

// Len returns the number of keys (prefixes) in the Loc-RIB.
func (r *LocRib) Len() uint {
	return uint(C.lr_loc_rib_len(r.ptr))
}

// IsEmpty reports whether the Loc-RIB holds no keys.
func (r *LocRib) IsEmpty() bool {
	return C.lr_loc_rib_is_empty(r.ptr) != 0
}

// Generation returns the monotonic generation counter.
func (r *LocRib) Generation() uint64 {
	return uint64(C.lr_loc_rib_generation(r.ptr))
}

// BestPresent reports whether a route is present for the given key.
func (r *LocRib) BestPresent(key RouteKey) bool {
	prefixC := toPrefixC(key.Addr, key.PrefixLen)
	var sourceC *C.lr_prefix_t
	if key.Source != nil {
		s := toPrefixC(key.Source, key.SourceLen)
		sourceC = &s
	}
	return C.lr_loc_rib_best_present(r.ptr, &prefixC, C.uint16_t(key.AFI), C.uint8_t(key.SAFI), sourceC) != 0
}

// Best returns the best path for a key. Returns a NEW Route (a copy
// the Loc-RIB's internal route) the caller owns, or nil when the
// key is absent.
func (r *LocRib) Best(key RouteKey) (*Route, error) {
	prefixC := toPrefixC(key.Addr, key.PrefixLen)
	var sourceC *C.lr_prefix_t
	if key.Source != nil {
		s := toPrefixC(key.Source, key.SourceLen)
		sourceC = &s
	}
	var out C.lr_route_t
	rc := C.lr_loc_rib_best(r.ptr, &prefixC, C.uint16_t(key.AFI), C.uint8_t(key.SAFI), sourceC, &out)
	if rc < 0 {
		return nil, fmt.Errorf("lr_loc_rib_best: %s (rc=%d)", LastError(), int(rc))
	}
	if out == nil {
		return nil, nil
	}
	rt := &Route{ptr: out}
	runtime.SetFinalizer(rt, (*Route).destroy)
	return rt, nil
}

// Paths returns the number of paths stored for a key (RFC 7911 Add-Path).
func (r *LocRib) Paths(key RouteKey) uint {
	keyC := key.toC()
	return uint(C.lr_loc_rib_paths(r.ptr, &keyC))
}

// LocRibSetEntry is one (prefix, path_count) tuple returned by IterSets.
type LocRibSetEntry struct {
	Addr      [16]byte
	PrefixLen uint8
	IsIPv6    bool
	PathCount uint
}

// IterSets walks every (RouteKey, paths) set in the Loc-RIB. The
// callback receives the prefix (as a 16-byte buffer; for IPv4 the
// address occupies the first 4 bytes, the rest is zero) plus the
// number of paths in that set. Returns the number of sets visited.
func (r *LocRib) IterSets(cb func(entry LocRibSetEntry)) (uint, error) {
	idx := ribCallbackRegister(cb)
	defer ribCallbackRelease(idx)
	rc := C.lr_loc_rib_iter_sets(r.ptr,
		(*[0]byte)(C.go_lr_loc_rib_iter_sets_cb),
		unsafe.Pointer(uintptr(idx)))
	if int64(rc) < 0 {
		return 0, fmt.Errorf("lr_loc_rib_iter_sets: %s", LastError())
	}
	return uint(rc), nil
}

// BorrowedRoute is one borrowed route returned by IterBest / IterPaths
// / AdjRibIn.IterAll / etc. The C side owns the underlying Route —
// the borrow is only valid for the body of the iteration callback.
type BorrowedRoute struct {
	ptr C.lr_route_t
}

// Ptr returns the underlying C handle (for use by other Route
// readers in the same package).
func (b BorrowedRoute) Ptr() C.lr_route_t { return b.ptr }

// IterBest walks every best route in the Loc-RIB. The callback
// receives a *borrowed* route handle — the caller must NOT free it.
// Returns the number of routes visited.
func (r *LocRib) IterBest(cb func(rt BorrowedRoute)) (uint, error) {
	idx := ribCallbackRegister(func(p C.lr_route_t) {
		cb(BorrowedRoute{ptr: p})
	})
	defer ribCallbackRelease(idx)
	rc := C.lr_loc_rib_iter_best(r.ptr,
		(*[0]byte)(C.go_lr_route_iter_cb),
		unsafe.Pointer(uintptr(idx)))
	if int64(rc) < 0 {
		return 0, fmt.Errorf("lr_loc_rib_iter_best: %s", LastError())
	}
	return uint(rc), nil
}

// IterPaths walks every path (every multipath entry, not just the
// best) in the Loc-RIB. The callback receives a *borrowed* route
// handle. Returns the number of paths visited.
func (r *LocRib) IterPaths(cb func(rt BorrowedRoute)) (uint, error) {
	idx := ribCallbackRegister(func(p C.lr_route_t) {
		cb(BorrowedRoute{ptr: p})
	})
	defer ribCallbackRelease(idx)
	rc := C.lr_loc_rib_iter_paths(r.ptr,
		(*[0]byte)(C.go_lr_route_iter_cb),
		unsafe.Pointer(uintptr(idx)))
	if int64(rc) < 0 {
		return 0, fmt.Errorf("lr_loc_rib_iter_paths: %s", LastError())
	}
	return uint(rc), nil
}

// DiffSince computes the diff between the Loc-RIB's current state and
// its state at generation `sinceGen`. The diff is computed against
// the Loc-RIB's history ring (16 entries deep); for older diffs
// all three counts are 0.
func (r *LocRib) DiffSince(sinceGen uint64) (RibDiff, error) {
	var added, modified, removed C.uintptr_t
	rc := C.lr_loc_rib_diff_since(r.ptr, C.uint64_t(sinceGen), &added, &modified, &removed)
	if rc < 0 {
		return RibDiff{}, fmt.Errorf("lr_loc_rib_diff_since: %s (rc=%d)", LastError(), int(rc))
	}
	return RibDiff{
		Added:    uint(added),
		Modified: uint(modified),
		Removed:  uint(removed),
	}, nil
}

// AdjRibIn is an owned Adj-RIB-In handle (RFC 4271 §9).
type AdjRibIn struct {
	ptr C.lr_adj_rib_in_t
}

// NewAdjRibIn constructs an empty Adj-RIB-In.
func NewAdjRibIn() (*AdjRibIn, error) {
	p := C.lr_adj_rib_in_new()
	if p == nil {
		return nil, fmt.Errorf("lr_adj_rib_in_new: %s", LastError())
	}
	r := &AdjRibIn{ptr: p}
	runtime.SetFinalizer(r, (*AdjRibIn).destroy)
	return r, nil
}

func (r *AdjRibIn) destroy() {
	if r.ptr != nil {
		C.lr_adj_rib_in_free(r.ptr)
		r.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (r *AdjRibIn) Free() {
	runtime.SetFinalizer(r, nil)
	r.destroy()
}

// Feed installs one pre-policy route from `origin`. The route handle
// is *consumed* — the caller must not use it after this call.
func (r *AdjRibIn) Feed(origin RouteOrigin, route *Route) error {
	rc := C.lr_adj_rib_in_feed(r.ptr, C.uint64_t(origin.Peer), C.int32_t(origin.Protocol), route.ptr)
	if rc < 0 {
		return fmt.Errorf("lr_adj_rib_in_feed: %s (rc=%d)", LastError(), int(rc))
	}
	route.ptr = nil
	return nil
}

// Withdraw one (origin, key, pathID) tuple. Returns true when a route
// was withdrawn, false when no matching entry existed.
func (r *AdjRibIn) Withdraw(origin RouteOrigin, key RouteKey, pathID uint32) (bool, error) {
	prefixC := toPrefixC(key.Addr, key.PrefixLen)
	var sourceC *C.lr_prefix_t
	if key.Source != nil {
		s := toPrefixC(key.Source, key.SourceLen)
		sourceC = &s
	}
	rc := C.lr_adj_rib_in_withdraw(r.ptr, C.uint64_t(origin.Peer), C.int32_t(origin.Protocol),
		&prefixC, C.uint16_t(key.AFI), C.uint8_t(key.SAFI), sourceC, C.uint32_t(pathID))
	if rc < 0 {
		return false, fmt.Errorf("lr_adj_rib_in_withdraw: %s (rc=%d)", LastError(), int(rc))
	}
	return int(rc) == 1, nil
}

// Get looks up a route by (origin, key, pathID). Returns a NEW Route
// (a copy) the caller owns, or nil when absent.
func (r *AdjRibIn) Get(origin RouteOrigin, key RouteKey, pathID uint32) (*Route, error) {
	keyC := key.toC()
	originC := C.lr_route_origin_t{
		protocol: C.uint8_t(origin.Protocol),
		peer:     C.uint64_t(origin.Peer),
	}
	var out C.lr_route_t
	rc := C.lr_adj_rib_in_get(r.ptr, originC, &keyC, C.uint32_t(pathID), &out)
	if rc < 0 {
		return nil, fmt.Errorf("lr_adj_rib_in_get: %s (rc=%d)", LastError(), int(rc))
	}
	if rc == 0 && out == nil {
		return nil, nil
	}
	if rc == 1 {
		rt := &Route{ptr: out}
		runtime.SetFinalizer(rt, (*Route).destroy)
		return rt, nil
	}
	return nil, nil
}

// OriginsFor lists the origins that have a route for `key`.
func (r *AdjRibIn) OriginsFor(key RouteKey) ([]RouteOrigin, error) {
	keyC := key.toC()
	cap := 64
	out := make([]C.lr_route_origin_t, cap)
	var count C.uintptr_t
	rc := C.lr_adj_rib_in_origins_for(r.ptr, &keyC,
		(*C.lr_route_origin_t)(unsafe.Pointer(&out[0])), C.uintptr_t(cap), &count)
	if rc < 0 {
		return nil, fmt.Errorf("lr_adj_rib_in_origins_for: %s (rc=%d)", LastError(), int(rc))
	}
	n := uint(count)
	if n > uint(cap) {
		// Retry with the actual count.
		out = make([]C.lr_route_origin_t, n)
		rc = C.lr_adj_rib_in_origins_for(r.ptr, &keyC,
			(*C.lr_route_origin_t)(unsafe.Pointer(&out[0])), C.uintptr_t(n), &count)
		if rc < 0 {
			return nil, fmt.Errorf("lr_adj_rib_in_origins_for (retry): %s (rc=%d)", LastError(), int(rc))
		}
		n = uint(count)
	}
	origins := make([]RouteOrigin, n)
	for i := uint(0); i < n; i++ {
		origins[i] = RouteOrigin{
			Protocol: Protocol(out[i].protocol),
			Peer:     uint64(out[i].peer),
		}
	}
	return origins, nil
}

// Clear drops every route from every origin.
func (r *AdjRibIn) Clear() error {
	rc := C.lr_adj_rib_in_clear(r.ptr)
	if rc < 0 {
		return fmt.Errorf("lr_adj_rib_in_clear: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// ClearFor drops every route from one origin.
func (r *AdjRibIn) ClearFor(origin RouteOrigin) error {
	originC := C.lr_route_origin_t{
		protocol: C.uint8_t(origin.Protocol),
		peer:     C.uint64_t(origin.Peer),
	}
	rc := C.lr_adj_rib_in_clear_for(r.ptr, originC)
	if rc < 0 {
		return fmt.Errorf("lr_adj_rib_in_clear_for: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Len returns the total number of stored routes.
func (r *AdjRibIn) Len() uint {
	return uint(C.lr_adj_rib_in_len(r.ptr))
}

// IsEmpty reports whether the Adj-RIB-In holds no routes.
func (r *AdjRibIn) IsEmpty() bool {
	return C.lr_adj_rib_in_is_empty(r.ptr) != 0
}

// IterAll walks every route in the Adj-RIB-In, regardless of origin.
// The callback receives a *borrowed* route handle — the caller must
// NOT free it. Returns the number of routes visited.
func (r *AdjRibIn) IterAll(cb func(rt BorrowedRoute)) (uint, error) {
	idx := ribCallbackRegister(func(p C.lr_route_t) {
		cb(BorrowedRoute{ptr: p})
	})
	defer ribCallbackRelease(idx)
	rc := C.lr_adj_rib_in_iter_all(r.ptr,
		(*[0]byte)(C.go_lr_route_iter_cb),
		unsafe.Pointer(uintptr(idx)))
	if int64(rc) < 0 {
		return 0, fmt.Errorf("lr_adj_rib_in_iter_all: %s", LastError())
	}
	return uint(rc), nil
}

// IterOrigin walks every route from one origin. The callback
// receives a *borrowed* route handle. Returns the number of routes
// visited.
func (r *AdjRibIn) IterOrigin(origin RouteOrigin, cb func(rt BorrowedRoute)) (uint, error) {
	idx := ribCallbackRegister(func(p C.lr_route_t) {
		cb(BorrowedRoute{ptr: p})
	})
	defer ribCallbackRelease(idx)
	rc := C.lr_adj_rib_in_iter_origin(r.ptr, C.uint64_t(origin.Peer), C.int32_t(origin.Protocol),
		(*[0]byte)(C.go_lr_route_iter_cb),
		unsafe.Pointer(uintptr(idx)))
	if int64(rc) < 0 {
		return 0, fmt.Errorf("lr_adj_rib_in_iter_origin: %s", LastError())
	}
	return uint(rc), nil
}

// AdjRibOut is an owned Adj-RIB-Out handle (RFC 4271 §9).
type AdjRibOut struct {
	ptr C.lr_adj_rib_out_t
}

// NewAdjRibOut constructs an empty Adj-RIB-Out.
func NewAdjRibOut() (*AdjRibOut, error) {
	p := C.lr_adj_rib_out_new()
	if p == nil {
		return nil, fmt.Errorf("lr_adj_rib_out_new: %s", LastError())
	}
	r := &AdjRibOut{ptr: p}
	runtime.SetFinalizer(r, (*AdjRibOut).destroy)
	return r, nil
}

func (r *AdjRibOut) destroy() {
	if r.ptr != nil {
		C.lr_adj_rib_out_free(r.ptr)
		r.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (r *AdjRibOut) Free() {
	runtime.SetFinalizer(r, nil)
	r.destroy()
}

// Advertise one route to a destination. The route handle is *not*
// consumed — the Adj-RIB-Out stores a clone.
func (r *AdjRibOut) Advertise(dest RouteOrigin, route *Route, txPathID uint32) error {
	rc := C.lr_adj_rib_out_advertise(r.ptr, C.uint64_t(dest.Peer), C.int32_t(dest.Protocol),
		route.ptr, C.uint32_t(txPathID))
	if rc < 0 {
		return fmt.Errorf("lr_adj_rib_out_advertise: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Suppress (withdraw) one (dest, key, txPathID) tuple. Returns true
// when a route was suppressed, false when no matching entry existed.
func (r *AdjRibOut) Suppress(dest RouteOrigin, key RouteKey, txPathID uint32) (bool, error) {
	prefixC := toPrefixC(key.Addr, key.PrefixLen)
	var sourceC *C.lr_prefix_t
	if key.Source != nil {
		s := toPrefixC(key.Source, key.SourceLen)
		sourceC = &s
	}
	rc := C.lr_adj_rib_out_suppress(r.ptr, C.uint64_t(dest.Peer), C.int32_t(dest.Protocol),
		&prefixC, C.uint16_t(key.AFI), C.uint8_t(key.SAFI), sourceC, C.uint32_t(txPathID))
	if rc < 0 {
		return false, fmt.Errorf("lr_adj_rib_out_suppress: %s (rc=%d)", LastError(), int(rc))
	}
	return int(rc) == 1, nil
}

// TxPathIDs returns the TX path IDs advertised to `dest` for `key`.
func (r *AdjRibOut) TxPathIDs(dest RouteOrigin, key RouteKey) ([]uint32, error) {
	keyC := key.toC()
	destC := C.lr_route_origin_t{
		protocol: C.uint8_t(dest.Protocol),
		peer:     C.uint64_t(dest.Peer),
	}
	cap := 64
	out := make([]C.uint32_t, cap)
	var count C.uintptr_t
	rc := C.lr_adj_rib_out_tx_path_ids(r.ptr, destC, &keyC,
		(*C.uint32_t)(unsafe.Pointer(&out[0])), C.uintptr_t(cap), &count)
	if rc < 0 {
		return nil, fmt.Errorf("lr_adj_rib_out_tx_path_ids: %s (rc=%d)", LastError(), int(rc))
	}
	n := uint(count)
	if n > uint(cap) {
		out = make([]C.uint32_t, n)
		rc = C.lr_adj_rib_out_tx_path_ids(r.ptr, destC, &keyC,
			(*C.uint32_t)(unsafe.Pointer(&out[0])), C.uintptr_t(n), &count)
		if rc < 0 {
			return nil, fmt.Errorf("lr_adj_rib_out_tx_path_ids (retry): %s (rc=%d)", LastError(), int(rc))
		}
		n = uint(count)
	}
	ids := make([]uint32, n)
	for i := uint(0); i < n; i++ {
		ids[i] = uint32(out[i])
	}
	return ids, nil
}

// Clear drops every advertised route. The RIB becomes empty.
func (r *AdjRibOut) Clear() error {
	rc := C.lr_adj_rib_out_clear(r.ptr)
	if rc < 0 {
		return fmt.Errorf("lr_adj_rib_out_clear: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// ClearFor drops every advertised route for one destination.
func (r *AdjRibOut) ClearFor(dest RouteOrigin) error {
	destC := C.lr_route_origin_t{
		protocol: C.uint8_t(dest.Protocol),
		peer:     C.uint64_t(dest.Peer),
	}
	rc := C.lr_adj_rib_out_clear_for(r.ptr, destC)
	if rc < 0 {
		return fmt.Errorf("lr_adj_rib_out_clear_for: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Len returns the total number of stored advertised routes.
func (r *AdjRibOut) Len() uint {
	return uint(C.lr_adj_rib_out_len(r.ptr))
}

// IsEmpty reports whether the Adj-RIB-Out holds no routes.
func (r *AdjRibOut) IsEmpty() bool {
	return C.lr_adj_rib_out_is_empty(r.ptr) != 0
}

// IterFor walks every route advertised to a given destination. The
// callback receives a *borrowed* route handle. Returns the number of
// routes visited.
func (r *AdjRibOut) IterFor(dest RouteOrigin, cb func(rt BorrowedRoute)) (uint, error) {
	idx := ribCallbackRegister(func(p C.lr_route_t) {
		cb(BorrowedRoute{ptr: p})
	})
	defer ribCallbackRelease(idx)
	rc := C.lr_adj_rib_out_iter_for(r.ptr, C.uint64_t(dest.Peer), C.int32_t(dest.Protocol),
		(*[0]byte)(C.go_lr_route_iter_cb),
		unsafe.Pointer(uintptr(idx)))
	if int64(rc) < 0 {
		return 0, fmt.Errorf("lr_adj_rib_out_iter_for: %s", LastError())
	}
	return uint(rc), nil
}

// RibMux is the cross-protocol mux handle (RFC 4271 §9 + the
// admin-distance model the daemon uses to merge BGP / OSPF / Babel
// routes into one FIB).
type RibMux struct {
	ptr C.lr_rib_mux_t
}

// NewRibMux constructs an empty RibMux.
func NewRibMux() (*RibMux, error) {
	p := C.lr_rib_mux_new()
	if p == nil {
		return nil, fmt.Errorf("lr_rib_mux_new: %s", LastError())
	}
	r := &RibMux{ptr: p}
	runtime.SetFinalizer(r, (*RibMux).destroy)
	return r, nil
}

func (r *RibMux) destroy() {
	if r.ptr != nil {
		C.lr_rib_mux_free(r.ptr)
		r.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (r *RibMux) Free() {
	runtime.SetFinalizer(r, nil)
	r.destroy()
}

// Install one route into the mux (the handle is *consumed*).
func (r *RibMux) Install(route *Route) error {
	rc := C.lr_rib_mux_install(r.ptr, route.ptr)
	if rc < 0 {
		return fmt.Errorf("lr_rib_mux_install: %s (rc=%d)", LastError(), int(rc))
	}
	route.ptr = nil
	return nil
}

// Uninstall a key. Returns true when a route was withdrawn, false
// when the key was not present.
func (r *RibMux) Uninstall(key RouteKey) (bool, error) {
	prefixC := toPrefixC(key.Addr, key.PrefixLen)
	var sourceC *C.lr_prefix_t
	if key.Source != nil {
		s := toPrefixC(key.Source, key.SourceLen)
		sourceC = &s
	}
	rc := C.lr_rib_mux_uninstall(r.ptr, &prefixC, C.uint16_t(key.AFI), C.uint8_t(key.SAFI), sourceC)
	if rc < 0 {
		return false, fmt.Errorf("lr_rib_mux_uninstall: %s (rc=%d)", LastError(), int(rc))
	}
	return int(rc) == 1, nil
}

// Get returns the merged route for a key. Returns a NEW Route (a
// copy), or nil when the key is absent.
func (r *RibMux) Get(key RouteKey) (*Route, error) {
	prefixC := toPrefixC(key.Addr, key.PrefixLen)
	var sourceC *C.lr_prefix_t
	if key.Source != nil {
		s := toPrefixC(key.Source, key.SourceLen)
		sourceC = &s
	}
	var out C.lr_route_t
	rc := C.lr_rib_mux_get(r.ptr, &prefixC, C.uint16_t(key.AFI), C.uint8_t(key.SAFI), sourceC, &out)
	if rc < 0 {
		return nil, fmt.Errorf("lr_rib_mux_get: %s (rc=%d)", LastError(), int(rc))
	}
	if out == nil {
		return nil, nil
	}
	rt := &Route{ptr: out}
	runtime.SetFinalizer(rt, (*Route).destroy)
	return rt, nil
}

// Len returns the number of merged routes.
func (r *RibMux) Len() uint {
	return uint(C.lr_rib_mux_len(r.ptr))
}

// IsEmpty reports whether the mux holds no routes.
func (r *RibMux) IsEmpty() bool {
	return C.lr_rib_mux_is_empty(r.ptr) != 0
}

// RouteSelector applies the BIRD/FRR best-path selector (RFC 4271
// §9.1).
type RouteSelector struct{}

// Select applies the BIRD/FRR best-path selector to a flat slice of
// route handles. Returns the index of the winning route, or -1 when
// the slice is empty. The handles are *not* consumed.
func (RouteSelector) Select(routes []*Route) int {
	if len(routes) == 0 {
		return -1
	}
	arr := make([]C.lr_route_t, len(routes))
	for i, r := range routes {
		arr[i] = r.ptr
	}
	rc := C.lr_route_selector_select((*C.lr_route_t)(unsafe.Pointer(&arr[0])), C.uintptr_t(len(routes)))
	return int(int64(rc))
}

// SelectBGP applies the BGP-specific best-path selector (RFC 4271
// §9.1). Same contract as Select.
func (RouteSelector) SelectBGP(routes []*Route) int {
	if len(routes) == 0 {
		return -1
	}
	arr := make([]C.lr_route_t, len(routes))
	for i, r := range routes {
		arr[i] = r.ptr
	}
	rc := C.lr_route_selector_select_bgp((*C.lr_route_t)(unsafe.Pointer(&arr[0])), C.uintptr_t(len(routes)))
	return int(int64(rc))
}
