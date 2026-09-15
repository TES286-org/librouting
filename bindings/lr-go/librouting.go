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
// Graceful restart (RFC 4724) is enabled with a 120 s restart time;
// Long-Lived Graceful Restart (RFC 9494) is disabled.
func (r *Router) AddBGPSession(localAS, peerAS, localBGPID uint32, holdTime, keepalive uint16, asn4 bool) (uint64, error) {
	return r.AddBGPSessionExt(localAS, peerAS, localBGPID, holdTime, keepalive, asn4,
		true, 120, false, 0, 0)
}

// AddBGPSessionExt adds a BGP session with explicit graceful-restart
// configuration (RFC 4724 + RFC 9494). Returns the session handle.
//
// restartTime and llgrStaleTime are seconds. LLGR requires GR: when llgr
// is enabled with gracefulRestart disabled the LLGR capability is not
// advertised (RFC 9494 §4.1). llgrMaxStale caps the stale time received
// from the peer; 0 honours the peer's value.
func (r *Router) AddBGPSessionExt(localAS, peerAS, localBGPID uint32, holdTime, keepalive uint16, asn4 bool,
	gracefulRestart bool, restartTime uint16, llgr bool, llgrStaleTime, llgrMaxStale uint32) (uint64, error) {
	var h C.uint64_t
	rc := C.lr_router_add_bgp_session_ext(
		r.ptr,
		C.uint32_t(localAS),
		C.uint32_t(peerAS),
		C.uint32_t(localBGPID),
		C.uint16_t(holdTime),
		C.uint16_t(keepalive),
		toCBool(asn4),
		toCBool(gracefulRestart),
		C.uint16_t(restartTime),
		toCBool(llgr),
		C.uint32_t(llgrStaleTime),
		C.uint32_t(llgrMaxStale),
		&h,
	)
	if rc != 0 {
		return 0, fmt.Errorf("lr_router_add_bgp_session_ext: %s (rc=%d)", LastError(), int(rc))
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

// RequestRouteRefresh asks an established peer to resend the specified address
// family. It returns false when the session did not negotiate RFC 2918.
func (r *Router) RequestRouteRefresh(session uint64, afi uint16, safi uint8) (bool, error) {
	rc := C.lr_router_request_route_refresh(
		r.ptr,
		C.uint64_t(session),
		C.uint16_t(afi),
		C.uint8_t(safi),
	)
	if rc < 0 {
		return false, fmt.Errorf("lr_router_request_route_refresh: %s (rc=%d)", LastError(), int(rc))
	}
	return rc == 1, nil
}

// SetMRAI configures the per-prefix RFC 4271 UPDATE batching interval.
// Setting zero disables batching and flushes pending updates.
func (r *Router) SetMRAI(session uint64, intervalMs uint64) error {
	rc := C.lr_router_set_mrai(r.ptr, C.uint64_t(session), C.uint64_t(intervalMs))
	if rc != 0 {
		return fmt.Errorf("lr_router_set_mrai: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetAddPath enables or disables RFC 7911 Add-Path on one BGP session.
// Call it after AddBGPSession and before StartSession — the capability is
// negotiated in OPEN. The peer must also offer Add-Path for it to take
// effect; see also SetAddPathMaxPaths.
func (r *Router) SetAddPath(session uint64, enabled bool) error {
	rc := C.lr_router_set_add_path(r.ptr, C.uint64_t(session), toCBool(enabled))
	if rc != 0 {
		return fmt.Errorf("lr_router_set_add_path: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetAddPathMaxPaths caps how many paths per prefix the RFC 7911 decision
// process keeps in the Loc-RIB and advertises to Add-Path peers
// (router-wide; values below 1 are clamped to 1).
func (r *Router) SetAddPathMaxPaths(maxPaths uint32) error {
	rc := C.lr_router_set_add_path_max_paths(r.ptr, C.uint32_t(maxPaths))
	if rc != 0 {
		return fmt.Errorf("lr_router_set_add_path_max_paths: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetEbgpRequiresPolicy enables or disables the RFC 8212 default eBGP
// route behaviors (router-wide). When enabled, an external BGP session
// (eBGP or a confederation boundary) with no explicit import policy
// declared via SetSessionPolicy discards received routes, and one with
// no export policy advertises nothing (RFC 8212 §3).
func (r *Router) SetEbgpRequiresPolicy(enabled bool) error {
	rc := C.lr_router_set_ebgp_requires_policy(r.ptr, toCBool(enabled))
	if rc != 0 {
		return fmt.Errorf("lr_router_set_ebgp_requires_policy: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetEnforceFirstAs enables or disables FRR `bgp enforce-first-as`
// (router-wide, W2.2). When enabled, an UPDATE from an external BGP
// peer (eBGP or a confederation boundary) whose AS_PATH leftmost
// sequence segment's first AS is not the peer's negotiated AS is
// dropped before Adj-RIB-In. When off (the default — `no bgp
// enforce-first-as`), the route is admitted subject to the ordinary
// policy and safety checks. iBGP and confederation-internal sessions
// are exempt, mirroring FRR.
func (r *Router) SetEnforceFirstAs(enabled bool) error {
	rc := C.lr_router_set_enforce_first_as(r.ptr, toCBool(enabled))
	if rc != 0 {
		return fmt.Errorf("lr_router_set_enforce_first_as: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetSessionPolicy declares which directions of a BGP session carry an
// explicit policy (RFC 8212 §3). A direction left false is subject to
// the RFC 8212 default deny when SetEbgpRequiresPolicy(true) is active.
// Call after AddBGPSession; unknown session handles return an error.
func (r *Router) SetSessionPolicy(session uint64, import_, export bool) error {
	rc := C.lr_router_set_session_policy(r.ptr, C.uint64_t(session), toCBool(import_), toCBool(export))
	if rc != 0 {
		return fmt.Errorf("lr_router_set_session_policy: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// ExtNextHopTuple is a single RFC 5549 Extended Next-Hop tuple: IPv4
// unicast NLRI can be resolved over an IPv6 next-hop when all three
// fields are 1, 1, 2 respectively.
type ExtNextHopTuple struct {
	NlriAfi    uint16
	NlriSafi   uint8
	NexthopAfi uint16
}

// SetExtendedNextHop configures RFC 5549 Extended Next-Hop on a BGP
// session. Pass an empty slice to clear. Must be called after
// AddBGPSession and before StartSession — the capability is negotiated
// in OPEN.
func (r *Router) SetExtendedNextHop(session uint64, tuples []ExtNextHopTuple) error {
	if len(tuples) == 0 {
		rc := C.lr_router_set_extended_next_hop(r.ptr, C.uint64_t(session), nil, 0)
		if rc != 0 {
			return fmt.Errorf("lr_router_set_extended_next_hop: %s (rc=%d)", LastError(), int(rc))
		}
		return nil
	}
	buf := make([]byte, 5*len(tuples))
	for i, t := range tuples {
		buf[5*i+0] = byte(t.NlriAfi >> 8)
		buf[5*i+1] = byte(t.NlriAfi)
		buf[5*i+2] = t.NlriSafi
		buf[5*i+3] = byte(t.NexthopAfi >> 8)
		buf[5*i+4] = byte(t.NexthopAfi)
	}
	rc := C.lr_router_set_extended_next_hop(
		r.ptr,
		C.uint64_t(session),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.uintptr_t(len(tuples)),
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_set_extended_next_hop: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// MPFamily is a single RFC 4760 multiprotocol family: AFI + SAFI.
type MPFamily struct {
	Afi  uint16
	Safi uint8
}

// SetMPFamilies overrides the MP-BGP address families advertised in OPEN.
// Common values: {AFI=1, SAFI=1} for IPv4 unicast, {AFI=2, SAFI=1} for
// IPv6 unicast. Must be called before StartSession.
func (r *Router) SetMPFamilies(session uint64, families []MPFamily) error {
	if len(families) == 0 {
		rc := C.lr_router_set_mp_families(r.ptr, C.uint64_t(session), nil, 0)
		if rc != 0 {
			return fmt.Errorf("lr_router_set_mp_families: %s (rc=%d)", LastError(), int(rc))
		}
		return nil
	}
	buf := make([]byte, 4*len(families))
	for i, f := range families {
		buf[4*i+0] = byte(f.Afi >> 8)
		buf[4*i+1] = byte(f.Afi)
		buf[4*i+2] = 0 // reserved
		buf[4*i+3] = f.Safi
	}
	rc := C.lr_router_set_mp_families(
		r.ptr,
		C.uint64_t(session),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.uintptr_t(len(families)),
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_set_mp_families: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetLocalAddress sets the local source address for next-hop-self egress.
// Accepts 4-byte (IPv4) or 16-byte (IPv6) slices. For RFC 5549 ENH
// egress over IPv6 pass a 16-byte IPv6 address. Must be called before
// StartSession.
func (r *Router) SetLocalAddress(session uint64, addr []byte) error {
	var afi uint16
	switch len(addr) {
	case 4:
		afi = 1
	case 16:
		afi = 2
	default:
		return fmt.Errorf("SetLocalAddress: bad address length %d (want 4 or 16)", len(addr))
	}
	rc := C.lr_router_set_local_address(
		r.ptr,
		C.uint64_t(session),
		C.uint16_t(afi),
		(*C.uint8_t)(unsafe.Pointer(&addr[0])),
		C.uintptr_t(len(addr)),
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_set_local_address: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetDefaultIPv4Unicast configures FRR `bgp default ipv4-unicast`
// (W2.1) for one BGP session. When `enabled` is true (the default),
// IPv4 unicast is implicitly active even when SetMpFamilies did not
// list it. When false, IPv4 unicast must be added explicitly via
// SetMpFamilies to be active — the FRR `no bgp default ipv4-unicast`
// posture. Must be called before StartSession; unknown handles or
// already-established sessions return an error.
func (r *Router) SetDefaultIPv4Unicast(session uint64, enabled bool) error {
	rc := C.lr_router_set_default_ipv4_unicast(
		r.ptr,
		C.uint64_t(session),
		toCBool(enabled),
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_set_default_ipv4_unicast: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetLocalAsTolerance configures FRR `neighbor X allowas-in N` / BIRD
// `allow local as` (W2.3) for one BGP session. tolerance = 0 (the
// default) rejects any occurrence of the local AS in a received
// AS_PATH (RFC 4271 §9.1.2.15). N > 0 admits up to N occurrences
// (FRR `allowas-in N`, default N=1). math.MaxUint32 admits any
// number (FRR `allowas-any`). iBGP is exempt. Must be called before
// StartSession; unknown handles or already-established sessions
// return an error.
func (r *Router) SetLocalAsTolerance(session uint64, tolerance uint32) error {
	rc := C.lr_router_set_local_as_tolerance(
		r.ptr,
		C.uint64_t(session),
		C.uint32_t(tolerance),
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_set_local_as_tolerance: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetSoftReconfigInbound configures FRR `neighbor X soft-reconfiguration
// inbound` (W2.4) for one BGP session. When enabled is true, the
// router retains the pre-policy Adj-RIB-In for the session — the raw
// received routes before the import hook chain runs — so
// SoftReconfigInbound can re-evaluate the policy without re-fetching
// from the peer (`clear ip bgp * soft in`). Off by default (FRR's
// default; the cost is duplicate RIB memory per peer). Must be called
// before StartSession; unknown handles or already-established
// sessions return an error.
func (r *Router) SetSoftReconfigInbound(session uint64, enabled bool) error {
	rc := C.lr_router_set_soft_reconfig_inbound(
		r.ptr,
		C.uint64_t(session),
		toCBool(enabled),
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_set_soft_reconfig_inbound: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SoftReconfigInbound is FRR `clear ip bgp * soft in` (W2.4):
// re-evaluate the import policy against the pre-policy Adj-RIB-In
// for the session, replacing the session's entries in the
// post-policy RIB with the re-imported routes. Returns the number of
// routes re-evaluated. No-ops (returns 0) when the session did not
// have SetSoftReconfigInbound(true) enabled — the pre-policy RIB was
// not retained.
func (r *Router) SoftReconfigInbound(session uint64) (int64, error) {
	rc := C.lr_router_soft_reconfig_inbound(r.ptr, C.uint64_t(session))
	if rc < 0 {
		return 0, fmt.Errorf("lr_router_soft_reconfig_inbound: %s (rc=%d)", LastError(), int(rc))
	}
	return int64(rc), nil
}

// Tick advances the router clock by `nowMs` milliseconds.
func (r *Router) Tick(nowMs uint64) error {
	rc := C.lr_router_tick(r.ptr, C.uint64_t(nowMs))
	if rc != 0 {
		return fmt.Errorf("lr_router_tick: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// StartSession begins protocol operation on a session (BGP: ManualStart +
// TransportOpen). Call once the transport is connected.
func (r *Router) StartSession(session uint64) error {
	rc := C.lr_router_start_session(r.ptr, C.uint64_t(session))
	if rc != 0 {
		return fmt.Errorf("lr_router_start_session: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// OriginateV4 injects a local IPv4 route ("203.0.113.0/24"-style addr + plen
// + optional next-hop) into Loc-RIB and advertises it to established peers.
func (r *Router) OriginateV4(prefix [4]byte, prefixLen uint8, nextHop *[4]byte) error {
	var nhPtr *C.uint8_t
	if nextHop != nil {
		nhPtr = (*C.uint8_t)(unsafe.Pointer(&nextHop[0]))
	}
	rc := C.lr_router_originate_v4(
		r.ptr,
		(*C.uint8_t)(unsafe.Pointer(&prefix[0])),
		C.uint8_t(prefixLen),
		nhPtr,
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_originate_v4: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// OriginateV6 injects a local IPv6 unicast route (AFI=2, SAFI=1) into
// Loc-RIB and advertises it to established MP-BGP peers via
// MP_REACH_NLRI. The v6 counterpart of OriginateV4.
func (r *Router) OriginateV6(prefix [16]byte, prefixLen uint8, nextHop *[16]byte) error {
	var nhPtr *C.uint8_t
	if nextHop != nil {
		nhPtr = (*C.uint8_t)(unsafe.Pointer(&nextHop[0]))
	}
	rc := C.lr_router_originate_v6(
		r.ptr,
		(*C.uint8_t)(unsafe.Pointer(&prefix[0])),
		C.uint8_t(prefixLen),
		nhPtr,
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_originate_v6: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// WithdrawV4 removes a locally originated IPv4 route (FRR "no network"):
// the prefix leaves the originated set, the decision process re-runs (a
// beaten peer path is restored; an empty set withdraws the prefix from
// every session) and peers see the withdrawal. Returns nil and
// withdrawn=false when the prefix was not locally originated — an
// idempotent no-op, matching FRR/BIRD "no network" on an absent
// statement.
func (r *Router) WithdrawV4(prefix [4]byte, prefixLen uint8) (withdrawn bool, err error) {
	rc := C.lr_router_withdraw_v4(
		r.ptr,
		(*C.uint8_t)(unsafe.Pointer(&prefix[0])),
		C.uint8_t(prefixLen),
	)
	if rc < 0 {
		return false, fmt.Errorf("lr_router_withdraw_v4: %s (rc=%d)", LastError(), int(rc))
	}
	return rc == 0, nil
}

// WithdrawV6 removes a locally originated IPv6 unicast route. See
// WithdrawV4 for the semantics.
func (r *Router) WithdrawV6(prefix [16]byte, prefixLen uint8) (withdrawn bool, err error) {
	rc := C.lr_router_withdraw_v6(
		r.ptr,
		(*C.uint8_t)(unsafe.Pointer(&prefix[0])),
		C.uint8_t(prefixLen),
	)
	if rc < 0 {
		return false, fmt.Errorf("lr_router_withdraw_v6: %s (rc=%d)", LastError(), int(rc))
	}
	return rc == 0, nil
}

// OriginateLabeledV4 injects an RFC 8277 labelled IPv4 BGP route
// (AFI=1, SAFI=4) into Loc-RIB. The label stack is supplied as a slice
// of 20-bit label values; the bottom-of-stack bit is set automatically.
// Pass nil for nextHop to leave the route without a next-hop (the egress
// path will synthesise one from the local address where appropriate).
func (r *Router) OriginateLabeledV4(prefix [4]byte, prefixLen uint8, labels []uint32, nextHop *[4]byte) error {
	var nhPtr *C.uint8_t
	if nextHop != nil {
		nhPtr = (*C.uint8_t)(unsafe.Pointer(&nextHop[0]))
	}
	var labelsPtr *C.uint32_t
	if len(labels) > 0 {
		labelsPtr = (*C.uint32_t)(unsafe.Pointer(&labels[0]))
	}
	rc := C.lr_router_originate_labeled_v4(
		r.ptr,
		(*C.uint8_t)(unsafe.Pointer(&prefix[0])),
		C.uint8_t(prefixLen),
		labelsPtr,
		C.size_t(len(labels)),
		nhPtr,
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_originate_labeled_v4: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// OriginateLabeledV6 injects an RFC 8277 labelled IPv6 BGP route
// (AFI=2, SAFI=4). See OriginateLabeledV4 for label-stack semantics.
func (r *Router) OriginateLabeledV6(prefix [16]byte, prefixLen uint8, labels []uint32, nextHop *[16]byte) error {
	var nhPtr *C.uint8_t
	if nextHop != nil {
		nhPtr = (*C.uint8_t)(unsafe.Pointer(&nextHop[0]))
	}
	var labelsPtr *C.uint32_t
	if len(labels) > 0 {
		labelsPtr = (*C.uint32_t)(unsafe.Pointer(&labels[0]))
	}
	rc := C.lr_router_originate_labeled_v6(
		r.ptr,
		(*C.uint8_t)(unsafe.Pointer(&prefix[0])),
		C.uint8_t(prefixLen),
		labelsPtr,
		C.size_t(len(labels)),
		nhPtr,
	)
	if rc != 0 {
		return fmt.Errorf("lr_router_originate_labeled_v6: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// MplsPlatformLabels returns the kernel's MPLS platform-labels
// capability (Linux only). Returns 0 when MPLS routing is not enabled,
// 16 or 20 when it is. Non-Linux platforms always return 0.
func MplsPlatformLabels() uint32 {
	return uint32(C.lr_mpls_platform_labels())
}

// RibLen returns the number of routes currently in Loc-RIB.
func (r *Router) RibLen() (int64, error) {
	n := C.lr_router_rib_len(r.ptr)
	if n < 0 {
		return 0, fmt.Errorf("lr_router_rib_len failed (rc=%d)", int(n))
	}
	return int64(n), nil
}

// RibDump renders the Loc-RIB as a text table (one route per line).
func (r *Router) RibDump() (string, error) {
	var b C.struct_lr_bytes_t
	rc := C.lr_router_rib_dump(r.ptr, &b)
	if rc != 0 {
		return "", fmt.Errorf("lr_router_rib_dump: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return string(copyBytes(&b)), nil
}

// SessionsDump renders every session's operational summary as a text
// table (one line per session: handle, kind, ASNs, state, ...).
func (r *Router) SessionsDump() (string, error) {
	var b C.struct_lr_bytes_t
	rc := C.lr_router_sessions_dump(r.ptr, &b)
	if rc != 0 {
		return "", fmt.Errorf("lr_router_sessions_dump: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return string(copyBytes(&b)), nil
}

// AddROAEntry adds one Route Origin Authorization entry to the
// router's ROA table (RFC 6482 §3 / RFC 6811 §2). Pass exactly one
// of `prefixV4` (4 bytes) or `prefixV6` (16 bytes); the other MUST
// be nil. maxLength == 0 means "exact prefix length only" (the
// common /24 case). When ROA validation is enabled via
// SetROAValidate, the router rejects routes whose origin AS is not
// authorized at import time. The filter DSL's roa.state accessor
// reads the same table.
func (r *Router) AddROAEntry(prefixV4, prefixV6 []byte, prefixLen, maxLength uint8, asn uint32) error {
	var v4Ptr, v6Ptr *C.uint8_t
	if prefixV4 != nil {
		if len(prefixV4) != 4 {
			return fmt.Errorf("AddROAEntry: prefixV4 must be 4 bytes, got %d", len(prefixV4))
		}
		v4Ptr = (*C.uint8_t)(&prefixV4[0])
	}
	if prefixV6 != nil {
		if len(prefixV6) != 16 {
			return fmt.Errorf("AddROAEntry: prefixV6 must be 16 bytes, got %d", len(prefixV6))
		}
		v6Ptr = (*C.uint8_t)(&prefixV6[0])
	}
	if v4Ptr == nil && v6Ptr == nil {
		return fmt.Errorf("AddROAEntry: at least one of prefixV4 / prefixV6 must be non-nil")
	}
	rc := C.lr_router_add_roa_entry(r.ptr, v4Ptr, v6Ptr, C.uint8_t(prefixLen), C.uint8_t(maxLength), C.uint32_t(asn))
	if rc != 0 {
		return fmt.Errorf("lr_router_add_roa_entry: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetROAValidate toggles RFC 6811 §2 prefix-origin validation on
// (enable = true) or off (false). When on, every received BGP
// UPDATE is validated against the router's ROA table; Invalid
// routes are rejected at import time.
func (r *Router) SetROAValidate(enable bool) error {
	var v C.uint8_t
	if enable {
		v = 1
	}
	rc := C.lr_router_set_roa_validate(r.ptr, v)
	if rc != 0 {
		return fmt.Errorf("lr_router_set_roa_validate: %s (rc=%d)", LastError(), int(rc))
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

// EncodeSRv6SRH encodes an SRv6 Segment Routing Header (RFC 8754 §2)
// from a flat byte slice of SIDs. Each SID is 16 bytes; `sids` must
// have length `n * 16`. Returns the on-wire SRH bytes (8-octet fixed
// header + segment list).
func EncodeSRv6SRH(sids []byte) ([]byte, error) {
	if len(sids) == 0 {
		return nil, fmt.Errorf("empty SID list")
	}
	if len(sids)%16 != 0 {
		return nil, fmt.Errorf("SID list length %d is not a multiple of 16", len(sids))
	}
	var b C.struct_lr_bytes_t
	rc := C.lr_srv6_encode_srh(
		(*C.uint8_t)(unsafe.Pointer(&sids[0])),
		C.size_t(len(sids)),
		&b,
	)
	if rc != 0 {
		return nil, fmt.Errorf("lr_srv6_encode_srh: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), nil
}

// DecodeSRv6SRH decodes an SRv6 SRH (RFC 8754 §2) from `data`. Returns
// the concatenation of the segment list (16 bytes per SID) and any TLV
// bytes present in the SRH.
func DecodeSRv6SRH(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	var b C.struct_lr_bytes_t
	rc := C.lr_srv6_decode_srh(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&b,
	)
	if rc != 0 {
		return nil, fmt.Errorf("lr_srv6_decode_srh: %s (rc=%d)", LastError(), int(rc))
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

// ---- ROA store (RFC 6482 / RFC 6811 / RFC 8210, ROADMAP-v3 D2.3) ----

// ROA validation outcomes (RFC 6811 §2) returned by RoaStore.Validate.
const (
	RoaValid    = 0
	RoaNotFound = 1
	RoaInvalid  = 2
)

// RoaEntry is one ROA record (RFC 6482 §3): the authorized prefix, the
// longest authorized prefix length, and the origin AS. Addr is 4 bytes
// (IPv4) or 16 bytes (IPv6). AS 0 marks the blackhole range (RFC 6483 §4).
type RoaEntry struct {
	Addr      []byte
	PrefixLen uint8
	MaxLength uint8
	ASN       uint32
}

// RoaDelta is one record delta of a completed RTR sync (RFC 8210 §5.6/§5.7).
type RoaDelta struct {
	Announce bool
	Entry    RoaEntry
}

// RoaStore is a live, thread-safe ROA database with two provenance
// layers (static configuration + RTR cache) and atomic whole-table
// snapshot swaps. Validation reads run lock-free against a snapshot.
type RoaStore struct {
	ptr C.lr_roa_store_t
}

// NewRoaStore creates an empty store. The returned *RoaStore is
// garbage-collected via a finalizer that calls lr_roa_store_free.
func NewRoaStore() (*RoaStore, error) {
	s := C.lr_roa_store_new()
	if s == nil {
		return nil, fmt.Errorf("lr_roa_store_new returned null")
	}
	out := &RoaStore{ptr: s}
	runtime.SetFinalizer(out, func(o *RoaStore) {
		if o.ptr != nil {
			C.lr_roa_store_free(o.ptr)
			o.ptr = nil
		}
	})
	return out, nil
}

// Close releases the store early. Idempotent; the finalizer covers
// missing Close calls, but calling Close twice is still safe.
func (s *RoaStore) Close() {
	if s.ptr != nil {
		C.lr_roa_store_free(s.ptr)
		s.ptr = nil
	}
}

// fillCEntry copies a Go RoaEntry into a C lr_roa_entry_t. Returns an
// error when the address byte count is neither 4 nor 16.
func fillCEntry(dst *C.struct_lr_roa_entry_t, e RoaEntry) error {
	switch len(e.Addr) {
	case 4:
		dst.is_ipv6 = 0
		for i := 0; i < 4; i++ {
			dst.addr[i] = C.uint8_t(e.Addr[i])
		}
	case 16:
		dst.is_ipv6 = 1
		for i := 0; i < 16; i++ {
			dst.addr[i] = C.uint8_t(e.Addr[i])
		}
	default:
		return fmt.Errorf("RoaEntry.Addr must be 4 or 16 bytes, got %d", len(e.Addr))
	}
	dst.prefix_len = C.uint8_t(e.PrefixLen)
	dst.max_length = C.uint8_t(e.MaxLength)
	dst.asn = C.uint32_t(e.ASN)
	return nil
}

// ReplaceStatic atomically replaces the store's static (configuration)
// layer. RTR-learned entries are preserved. A malformed entry fails the
// whole call atomically (nothing is applied).
func (s *RoaStore) ReplaceStatic(entries []RoaEntry) error {
	// An empty slice clears the layer — the C contract is
	// "NULL with len 0" and Go maps nil onto it directly.
	if len(entries) == 0 {
		rc := C.lr_roa_store_replace_static(s.ptr, nil, 0)
		if rc != 0 {
			return fmt.Errorf("lr_roa_store_replace_static: %s (rc=%d)", LastError(), int(rc))
		}
		return nil
	}
	cEntries := make([]C.struct_lr_roa_entry_t, len(entries))
	for i := range entries {
		if err := fillCEntry(&cEntries[i], entries[i]); err != nil {
			return fmt.Errorf("ReplaceStatic: %w", err)
		}
	}
	rc := C.lr_roa_store_replace_static(s.ptr, &cEntries[0], C.size_t(len(cEntries)))
	if rc != 0 {
		return fmt.Errorf("lr_roa_store_replace_static: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// ApplyDeltas applies one completed sync's delta batch atomically.
// Duplicates coalesce and unknown withdrawals are no-ops (the RFC 8210
// §5.6 / §12 code-6 semantics).
func (s *RoaStore) ApplyDeltas(deltas []RoaDelta) error {
	if len(deltas) == 0 {
		return nil
	}
	cDeltas := make([]C.struct_lr_roa_delta_t, len(deltas))
	for i := range deltas {
		if err := fillCEntry(&cDeltas[i].entry, deltas[i].Entry); err != nil {
			return fmt.Errorf("ApplyDeltas: %w", err)
		}
		cDeltas[i].announce = toCBool(deltas[i].Announce)
	}
	rc := C.lr_roa_store_apply_deltas(s.ptr, &cDeltas[0], C.size_t(len(cDeltas)))
	if rc != 0 {
		return fmt.Errorf("lr_roa_store_apply_deltas: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// ClearRTR withdraws every RTR-learned entry — the RFC 8210 §6
// data-expiry and cache-change response. Static entries survive.
func (s *RoaStore) ClearRTR() error {
	rc := C.lr_roa_store_clear_rtr(s.ptr)
	if rc != 0 {
		return fmt.Errorf("lr_roa_store_clear_rtr: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Len returns the current merged entry count (static + RTR, deduplicated).
func (s *RoaStore) Len() int {
	return int(C.lr_roa_store_len(s.ptr))
}

// Validate runs the RFC 6811 §2 validation for (prefixAddr, prefixLen,
// originAS). prefixAddr is 4 bytes (IPv4) or 16 bytes (IPv6). hasOrigin
// = false (no AS_PATH) validates as RoaNotFound. Returns one of the
// Roa* outcome constants.
func (s *RoaStore) Validate(prefixAddr []byte, prefixLen uint8, originAS uint32, hasOrigin bool) (int, error) {
	var state C.uint8_t
	var v4, v6 *C.uint8_t
	switch len(prefixAddr) {
	case 4:
		v4 = (*C.uint8_t)(unsafe.Pointer(&prefixAddr[0]))
	case 16:
		v6 = (*C.uint8_t)(unsafe.Pointer(&prefixAddr[0]))
	default:
		return 0, fmt.Errorf("Validate: prefixAddr must be 4 or 16 bytes, got %d", len(prefixAddr))
	}
	rc := C.lr_roa_store_validate(s.ptr, v4, v6, C.uint8_t(prefixLen), C.uint32_t(originAS), toCBool(hasOrigin), &state)
	if rc != 0 {
		return 0, fmt.Errorf("lr_roa_store_validate: %s (rc=%d)", LastError(), int(rc))
	}
	return int(state), nil
}

// ===== D4.4 — redistribution / aggregation / damping =====

// Wire protocol identifiers for AddRedistributionPipe. Mirrors
// LrProtocol in lr_ffi.h.
type Protocol int

const (
	ProtoBgp       Protocol = 0
	ProtoOspf      Protocol = 1
	ProtoOspf3     Protocol = 2
	ProtoBabel     Protocol = 3
	ProtoStatic    Protocol = 4
	ProtoConnected Protocol = 5
)

// Metric transformation for a redistribution pipe.
type MetricPolicy int

const (
	MetricInherit MetricPolicy = 0
	MetricFixed   MetricPolicy = 1
	MetricAdd     MetricPolicy = 2
)

// PrefixSpec is one IPv4/IPv6 prefix. Addr is 4 bytes (IPv4) or
// 16 bytes (IPv6) — the same convention as the ROA entry API.
type PrefixSpec struct {
	Addr      []byte
	IsIPv6    bool
	PrefixLen uint8
}

func (p PrefixSpec) toC() (C.lr_prefix_t, error) {
	var out C.lr_prefix_t
	if p.IsIPv6 {
		if len(p.Addr) != 16 {
			return out, fmt.Errorf("IPv6 prefix Addr must be 16 bytes, got %d", len(p.Addr))
		}
		for i := 0; i < 16; i++ {
			out.addr[i] = C.uint8_t(p.Addr[i])
		}
		out.is_ipv6 = 1
	} else {
		if len(p.Addr) != 4 {
			return out, fmt.Errorf("IPv4 prefix Addr must be 4 bytes, got %d", len(p.Addr))
		}
		for i := 0; i < 4; i++ {
			out.addr[i] = C.uint8_t(p.Addr[i])
		}
		out.is_ipv6 = 0
	}
	out.prefix_len = C.uint8_t(p.PrefixLen)
	return out, nil
}

// AddRedistributionPipe installs a redistribution pipe (BIRD `pipe` /
// FRR `redistribute`): routes from source are re-originated into
// target with the configured metric policy, optional tag and optional
// allow-list. allow == nil redistributes everything.
func (r *Router) AddRedistributionPipe(source, target Protocol, metricPolicy MetricPolicy,
	metric uint32, hasTag bool, tag uint32, allow []PrefixSpec) error {
	var allowPtr *C.lr_prefix_t
	var cAllow []C.lr_prefix_t
	if len(allow) > 0 {
		for _, a := range allow {
			cp, err := a.toC()
			if err != nil {
				return fmt.Errorf("AddRedistributionPipe: %v", err)
			}
			cAllow = append(cAllow, cp)
		}
		allowPtr = &cAllow[0]
	}
	var ht C.int
	if hasTag {
		ht = 1
	}
	rc := C.lr_router_add_redistribution_pipe(r.ptr, C.int(source), C.int(target),
		C.int(metricPolicy), C.uint32_t(metric), ht, C.uint32_t(tag), allowPtr,
		C.size_t(len(cAllow)))
	if rc != 0 {
		return fmt.Errorf("lr_router_add_redistribution_pipe: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// AddAggregate registers an RFC 4271 §9.2.2.2 aggregate: originated
// with a zeroed AS_PATH + ATOMIC_AGGREGATE + AGGREGATOR while a
// more-specific exists, withdrawn when the last one disappears.
func (r *Router) AddAggregate(prefix PrefixSpec) error {
	cp, err := prefix.toC()
	if err != nil {
		return fmt.Errorf("AddAggregate: %v", err)
	}
	rc := C.lr_router_add_aggregate(r.ptr, &cp)
	if rc != 0 {
		return fmt.Errorf("lr_router_add_aggregate: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// RemoveAggregate withdraws a previously registered aggregate.
// Unknown prefixes are a no-op.
func (r *Router) RemoveAggregate(prefix PrefixSpec) error {
	cp, err := prefix.toC()
	if err != nil {
		return fmt.Errorf("RemoveAggregate: %v", err)
	}
	rc := C.lr_router_remove_aggregate(r.ptr, &cp)
	if rc != 0 {
		return fmt.Errorf("lr_router_remove_aggregate: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// DampingConfig carries the RFC 2439 §4.7 tunables (mirrors
// lr_damping_config_t).
type DampingConfig struct {
	AdditiveIncr         uint32
	SuppressThreshold    uint32
	ReuseThreshold       uint32
	UpperLimit           uint32
	DecayIntervalS       uint64
	DecayFactorActive    float64
	DecayFactorWithdrawn float64
}

// Damping is an owned handle to a shared damping table. The router's
// import hook keeps its own reference; Destroy releases the
// embedder's decay access. A runtime finalizer also destroys it.
type Damping struct {
	ptr C.lr_damping_t
}

// SetDamping installs the RFC 2439 damping import hook on the router
// and returns the shared table handle. Drive periodic decay with
// (*Damping).Decay — the in-process analogue of the daemon's
// lr-damping-decay thread.
func (r *Router) SetDamping(cfg DampingConfig) (*Damping, error) {
	d := C.lr_router_set_damping(r.ptr, &C.lr_damping_config_t{
		additive_incr:          C.uint32_t(cfg.AdditiveIncr),
		suppress_threshold:     C.uint32_t(cfg.SuppressThreshold),
		reuse_threshold:        C.uint32_t(cfg.ReuseThreshold),
		upper_limit:            C.uint32_t(cfg.UpperLimit),
		decay_interval_s:       C.uint64_t(cfg.DecayIntervalS),
		decay_factor_active:    C.double(cfg.DecayFactorActive),
		decay_factor_withdrawn: C.double(cfg.DecayFactorWithdrawn),
	})
	if d == nil {
		return nil, fmt.Errorf("lr_router_set_damping: %s", LastError())
	}
	out := &Damping{ptr: d}
	runtime.SetFinalizer(out, func(o *Damping) {
		if o.ptr != nil {
			C.lr_damping_destroy(o.ptr)
			o.ptr = nil
		}
	})
	return out, nil
}

// Decay drives one damping decay pass at wall-clock nowS (seconds)
// and returns the number of prefixes that re-emerged.
func (d *Damping) Decay(nowS uint64) (int, error) {
	if d.ptr == nil {
		return 0, fmt.Errorf("Decay: damping handle destroyed")
	}
	rc := C.lr_damping_decay(d.ptr, C.uint64_t(nowS))
	if rc < 0 {
		return 0, fmt.Errorf("lr_damping_decay: %s (rc=%d)", LastError(), int(rc))
	}
	return int(rc), nil
}

// Destroy releases the damping handle (idempotent).
func (d *Damping) Destroy() {
	if d.ptr != nil {
		C.lr_damping_destroy(d.ptr)
		d.ptr = nil
	}
}
