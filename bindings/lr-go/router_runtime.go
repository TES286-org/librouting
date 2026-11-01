// Package librouting — Router runtime hooks.
//
// Mirrors the C ABI surface in `crates/lr-ffi/src/router_runtime.rs`
// (the RouterInstance trait methods the daemon uses for BGP FSM state
// inspection, Babel runtime control and graceful shutdown). The Go
// shapes follow the Rust API hierarchy: a method on `*Router` for
// every Rust `RouterInstance` trait method the C ABI exposes, with
// the same parameter names the Rust trait uses (so a Go embedder can
// read the Rust docstring and translate the call site 1:1).

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

// SessionPeerState returns the BGP FSM state name of a session by
// handle (one of "Idle", "Connect", "Active", "OpenSent",
// "OpenConfirm", "Established" for BGP). Returns ("", false) for
// non-BGP / unknown sessions, ("", true) for an invalid router
// handle (the C ABI returns NULL in both cases — the bool carries
// the "valid router" bit so callers can distinguish).
//
// The returned string aliases a thread-local C buffer reused by
// every lr_*_name entry point; copy it before the next such call.
func (r *Router) SessionPeerState(session uint64) (string, bool) {
	ptr := C.lr_router_session_peer_state(r.ptr, C.uint64_t(session))
	if ptr == nil {
		// Either the router handle was invalid or the session is
		// unknown / not a BGP session. The bool here means "did the
		// router lock succeed?" — false means the router itself was
		// invalid, true means the session lookup failed. We cannot
		// tell the two NULL cases apart from the Go side without
		// another call (and the lock-then-lookup race is not worth
		// it); the common-case transport knows its router handle is
		// valid, so the bool is "router valid" and an empty string
		// with bool=true means "session is not BGP / unknown".
		return "", r.ptr != nil
	}
	return C.GoString(ptr), true
}

// RestartCooldownRemaining returns the remaining milliseconds of the
// max-prefix "Restart" cooldown for a session (BIRD `restart time`,
// FRR `bgp maximum-prefix restart <secs>`). Returns (remaining, true,
// nil) when a cooldown is in effect, (0, false, nil) when no cooldown
// is in effect (the session never tripped Restart or the configured
// cooldown has elapsed).
func (r *Router) RestartCooldownRemaining(session uint64) (uint64, bool, error) {
	var ms C.uint64_t
	rc := C.lr_router_session_restart_cooldown_remaining(r.ptr, C.uint64_t(session), &ms)
	if rc < 0 {
		return 0, false, fmt.Errorf("lr_router_session_restart_cooldown_remaining: %s (rc=%d)", LastError(), int(rc))
	}
	if rc == 1 {
		return uint64(ms), true, nil
	}
	return 0, false, nil
}

// TakeCollisionLost consumes the RFC 4271 §6.8 collision-loss latch
// of a session. Returns true exactly once after the session lost a
// collision (its own resolver closed it, or a Cease / Connection
// Collision Resolution NOTIFICATION arrived) since the latch was
// last consumed. The latch is consumed on read; a subsequent call
// returns false until the next collision.
func (r *Router) TakeCollisionLost(session uint64) (bool, error) {
	rc := C.lr_router_take_collision_lost(r.ptr, C.uint64_t(session))
	if rc < 0 {
		return false, fmt.Errorf("lr_router_take_collision_lost: %s (rc=%d)", LastError(), int(rc))
	}
	return rc == 1, nil
}

// SessionWasEstablished reports whether the session's CURRENT
// transport incarnation ever reached Established. Embedders use it
// to reset reconnect backoff only after a genuinely working session
// (a handshake that died at OpenConfirm must keep the exponential
// backoff growing).
func (r *Router) SessionWasEstablished(session uint64) (bool, error) {
	rc := C.lr_router_session_was_established(r.ptr, C.uint64_t(session))
	if rc < 0 {
		return false, fmt.Errorf("lr_router_session_was_established: %s (rc=%d)", LastError(), int(rc))
	}
	return rc == 1, nil
}

// RibPathsCount returns the number of paths in the Loc-RIB's Add-Path
// view (RFC 7911) — the full multiplicity when Add-Path is configured.
// The companion RibLen returns the best-path count (one per prefix).
func (r *Router) RibPathsCount() (int64, error) {
	n := C.lr_router_rib_paths_count(r.ptr)
	if n < 0 {
		return 0, fmt.Errorf("lr_router_rib_paths_count: %s (rc=%d)", LastError(), int(n))
	}
	return int64(n), nil
}

// RibPathAt borrows one path from the Loc-RIB's Add-Path view at
// index idx (0-based). Returns an owned *Route the caller MUST
// release with Route.Free (a finalizer also runs). Returns an error
// of kind "out of range" when idx is out of range; the underlying C
// ABI returns -6 in that case. The returned *Route boxes a clone of
// the underlying route (the inner &Route cannot outlive the router
// lock that guards the Loc-RIB).
func (r *Router) RibPathAt(idx int) (*Route, error) {
	var route C.lr_route_t
	rc := C.lr_router_rib_path_at(r.ptr, C.size_t(idx), &route)
	if rc != 0 {
		if rc == -6 {
			return nil, fmt.Errorf("lr_router_rib_path_at: index %d out of range: %s", idx, LastError())
		}
		return nil, fmt.Errorf("lr_router_rib_path_at: %s (rc=%d)", LastError(), int(rc))
	}
	// Wrap the C handle in a Go *Route with a finalizer that calls
	// lr_route_free — same pattern NewRouteFromV4 etc. use.
	out := &Route{ptr: route}
	runtime.SetFinalizer(out, (*Route).destroy)
	return out, nil
}

// FlushRibForShutdown flushes every Loc-RIB route — the daemon
// shutdown hook RFC 4271 leaves to the implementor. Queues one
// RouteWithdrawn event per Loc-RIB key (the event consumer / ticker's
// final drain hands them to the kernel mirror so the routes this
// daemon installed leave the kernel with it — BIRD's krt parity).
// Idempotent: calling twice queues the withdrawals twice (the second
// call sees an empty Loc-RIB and queues nothing).
func (r *Router) FlushRibForShutdown() error {
	rc := C.lr_router_flush_rib_for_shutdown(r.ptr)
	if rc != 0 {
		return fmt.Errorf("lr_router_flush_rib_for_shutdown: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// BabelFlushSession drops every route learned over the Babel session
// `session` and applies the withdrawal delta to Loc-RIB — the
// "check link" response when an interface goes operationally down
// (BIRD `check link yes`, RFC 8966 §A.2). The session stays alive for
// the link's return: routes re-learn from the peer's Updates when
// the interface comes back. A no-op (returns nil) for non-Babel
// sessions, matching the Rust trait's default.
func (r *Router) BabelFlushSession(session uint64) error {
	rc := C.lr_router_babel_flush_session(r.ptr, C.uint64_t(session))
	if rc != 0 {
		return fmt.Errorf("lr_router_babel_flush_session: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// BabelGC runs one Babel expiry sweep (RFC 8966 §3.2.5): expire
// routes whose re-announcement hold time lapsed and retract
// everything a dead neighbour taught us, applying the Loc-RIB
// deltas. The transport should call this about once a second;
// nowMs is the same wall-clock milliseconds Tick advances.
func (r *Router) BabelGC(nowMs uint64) error {
	rc := C.lr_router_babel_gc(r.ptr, C.uint64_t(nowMs))
	if rc != 0 {
		return fmt.Errorf("lr_router_babel_gc: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetBabelOwnRouterID pins the Babel router-id this node announces
// on session `session` (RFC 8966 §3.3). id must be exactly 8 bytes
// (the Babel router-id, RFC 8966 §3.3.1 — the EUI-64 or any other
// unique 64-bit value). A no-op (returns nil) for non-Babel sessions.
func (r *Router) SetBabelOwnRouterID(session uint64, id [8]byte) error {
	rc := C.lr_router_set_babel_own_router_id(r.ptr, C.uint64_t(session), (*C.uint8_t)(unsafe.Pointer(&id[0])))
	if rc != 0 {
		return fmt.Errorf("lr_router_set_babel_own_router_id: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// BabelLinkCostParams configures the reception-side link-cost ramp
// of a Babel session (RFC 8966 §A.2.4): the RTT penalty bounds and
// the maximum applied on top of the txcost learned from the peer's
// IHU when an Update's advertised metric is folded into the local
// route metric. rttCost 0 (babeld's default) keeps the RTT feature
// off. All three parameters are microseconds. A no-op (returns
// nil) for non-Babel sessions.
func (r *Router) SetBabelLinkCostParams(session uint64, rttMinUs, rttMaxUs uint32, rttCost uint16) error {
	rc := C.lr_router_set_babel_link_cost_params(r.ptr, C.uint64_t(session), C.uint32_t(rttMinUs), C.uint32_t(rttMaxUs), C.uint16_t(rttCost))
	if rc != 0 {
		return fmt.Errorf("lr_router_set_babel_link_cost_params: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// BabelNotePeer tells the Babel runtime the address the peer's
// datagrams come from (RFC 8966 §3.5.3). addr must be 4 bytes for
// IPv4 or 16 bytes for IPv6. The runtime is constructed with the
// local bind address, so the transport MUST call this per datagram
// or v6 routes fall back to our own address as the next hop.
func (r *Router) BabelNotePeer(session uint64, addr []byte) error {
	if len(addr) != 4 && len(addr) != 16 {
		return fmt.Errorf("BabelNotePeer: bad address length (want 4 or 16, got %d)", len(addr))
	}
	isV6 := C.uint8_t(0)
	if len(addr) == 16 {
		isV6 = 1
	}
	rc := C.lr_router_babel_note_peer(r.ptr, C.uint64_t(session), isV6, (*C.uint8_t)(unsafe.Pointer(&addr[0])))
	if rc != 0 {
		return fmt.Errorf("lr_router_babel_note_peer: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// BabelRTTUs returns the smoothed RTT measured toward the peer of a
// Babel session (BABEL-RTT, RFC 8966 §A.2.4). Returns (us, true, nil)
// when a fresh sample is available, (0, false, nil) when no fresh
// sample exists or the session is not a Babel session.
func (r *Router) BabelRTTUs(session, nowMs uint64) (uint32, bool, error) {
	var us C.uint32_t
	rc := C.lr_router_babel_rtt_us(r.ptr, C.uint64_t(session), C.uint64_t(nowMs), &us)
	if rc < 0 {
		return 0, false, fmt.Errorf("lr_router_babel_rtt_us: %s (rc=%d)", LastError(), int(rc))
	}
	if rc == 1 {
		return uint32(us), true, nil
	}
	return 0, false, nil
}

// BabelRTTEchoPair returns the BABEL-RTT pair the next IHU toward
// the session's peer should echo — (peer Hello timestamp, our
// receive time), valid only while the Hello is fresh (RFC 8966
// §A.2.4; babeld's 1 s echo window). Returns (echoTs, recvUs, true,
// nil) when a fresh pair is available, zero values with false
// otherwise.
func (r *Router) BabelRTTEchoPair(session, nowMs uint64) (echoTs, recvUs uint32, ok bool, err error) {
	var echo, recv C.uint32_t
	rc := C.lr_router_babel_rtt_echo(r.ptr, C.uint64_t(session), C.uint64_t(nowMs), &echo, &recv)
	if rc < 0 {
		return 0, 0, false, fmt.Errorf("lr_router_babel_rtt_echo: %s (rc=%d)", LastError(), int(rc))
	}
	if rc == 1 {
		return uint32(echo), uint32(recv), true, nil
	}
	return 0, 0, false, nil
}

// BabelEgressNexthops returns the current next-hop addresses the
// Babel peer advertises in its Update streams. Returns (v4, v6, true,
// nil) for a Babel session (v4 / v6 may individually be nil if the
// peer has not advertised a next hop for that family yet); returns
// (nil, nil, false, nil) for a non-Babel session or an unknown
// session handle (the C ABI's "no info" return code).
func (r *Router) BabelEgressNexthops(session uint64) (v4, v6 []byte, ok bool, err error) {
	var v4p, v6p C.uint8_t
	v4buf := make([]byte, 4)
	v6buf := make([]byte, 16)
	rc := C.lr_router_babel_egress_nexthops(
		r.ptr,
		C.uint64_t(session),
		&v4p,
		(*C.uint8_t)(unsafe.Pointer(&v4buf[0])),
		&v6p,
		(*C.uint8_t)(unsafe.Pointer(&v6buf[0])),
	)
	if rc < 0 {
		return nil, nil, false, fmt.Errorf("lr_router_babel_egress_nexthops: %s (rc=%d)", LastError(), int(rc))
	}
	if rc == 1 {
		// Non-Babel session / unknown handle.
		return nil, nil, false, nil
	}
	// rc == 0: success. Slice the buffers down to what's present.
	if v4p != 0 {
		v4 = v4buf
	} else {
		v4 = nil
	}
	if v6p != 0 {
		v6 = v6buf
	} else {
		v6 = nil
	}
	return v4, v6, true, nil
}

// BabelTakeRouteRequest takes the pending "a Route Request arrived"
// flag (RFC 8966 §3.2.6). Returns true exactly once after any Route
// Request TLV (wildcard or specific) was seen on the session; the
// transport answers by announcing immediately instead of waiting for
// the periodic tick.
func (r *Router) BabelTakeRouteRequest(session uint64) (bool, error) {
	rc := C.lr_router_babel_take_route_request(r.ptr, C.uint64_t(session))
	if rc < 0 {
		return false, fmt.Errorf("lr_router_babel_take_route_request: %s (rc=%d)", LastError(), int(rc))
	}
	return rc == 1, nil
}

// BabelTakeOwnSeqnoRequest takes the pending "a Seqno Request for
// our own router-id arrived" event (RFC 8966 §3.2.6.2). Returns
// (seqno, true, nil) exactly once after a peer asked us to re-announce
// with (at least) that seqno — the restart-recovery path when a peer
// remembers a higher seqno than our fresh boot value. The transport
// bumps its announcement seqno to at least seqno and re-announces.
func (r *Router) BabelTakeOwnSeqnoRequest(session uint64) (seqno uint16, ok bool, err error) {
	var s C.uint16_t
	rc := C.lr_router_babel_take_own_seqno_request(r.ptr, C.uint64_t(session), &s)
	if rc < 0 {
		return 0, false, fmt.Errorf("lr_router_babel_take_own_seqno_request: %s (rc=%d)", LastError(), int(rc))
	}
	if rc == 1 {
		return uint16(s), true, nil
	}
	return 0, false, nil
}
