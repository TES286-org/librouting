// Package librouting — Router runtime hook tests.
//
// Mirrors the Rust unit tests in `crates/lr-ffi/src/router_runtime_tests.rs`:
// every new method is exercised against a fresh router (no protocol
// handshake) so the Go tests focus on the FFI shape — null checks,
// invalid handles, the success/cooldown/no-sample return trichotomy
// — rather than on reproducing a full BGP/Babel run.

package librouting

import (
	"strings"
	"testing"
)

// TestSessionPeerStateBGP asserts that a freshly-added BGP session
// reports a valid FSM state name through the handle-keyed reader.
func TestSessionPeerStateBGP(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBGPSession(65001, 65002, 0x01020304, 90, 30, true)
	if err != nil {
		t.Fatalf("AddBGPSession: %v", err)
	}

	state, ok := r.SessionPeerState(h)
	if !ok {
		t.Fatal("SessionPeerState: expected ok=true for a valid BGP session")
	}
	switch state {
	case "Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established":
		// Valid FSM state name.
	default:
		t.Fatalf("unexpected FSM state name %q", state)
	}
}

// TestSessionPeerStateBabelIsNotBGP asserts that Babel sessions have
// no BGP FSM state — the handle-keyed reader returns ok=true (router
// valid) with an empty string (session is not BGP).
func TestSessionPeerStateBabelIsNotBGP(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	state, ok := r.SessionPeerState(h)
	if !ok {
		t.Fatal("Babel session: expected ok=true (router is valid)")
	}
	if state != "" {
		t.Fatalf("Babel session should have empty state, got %q", state)
	}
}

// TestSessionPeerStateUnknownHandle asserts that an unknown session
// handle maps to ok=true (router is still valid) + empty string.
func TestSessionPeerStateUnknownHandle(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	state, ok := r.SessionPeerState(0xFFFFFFFF)
	if !ok {
		t.Fatal("unknown handle should still report router-valid")
	}
	if state != "" {
		t.Fatalf("unknown handle should have empty state, got %q", state)
	}
}

// TestRestartCooldownNoCooldown asserts that a freshly-added BGP
// session reports no Restart cooldown.
func TestRestartCooldownNoCooldown(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBGPSession(65001, 65002, 0x01020304, 90, 30, true)
	if err != nil {
		t.Fatalf("AddBGPSession: %v", err)
	}
	remaining, ok, err := r.RestartCooldownRemaining(h)
	if err != nil {
		t.Fatalf("RestartCooldownRemaining: %v", err)
	}
	if ok {
		t.Fatalf("no cooldown should be in effect, got remaining=%d", remaining)
	}
}

// TestTakeCollisionLostInitiallyFalse asserts that a fresh session
// has no collision-loss latch set.
func TestTakeCollisionLostInitiallyFalse(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBGPSession(65001, 65002, 0x01020304, 90, 30, true)
	if err != nil {
		t.Fatalf("AddBGPSession: %v", err)
	}
	lost, err := r.TakeCollisionLost(h)
	if err != nil {
		t.Fatalf("TakeCollisionLost: %v", err)
	}
	if lost {
		t.Fatal("no collision should be recorded yet")
	}
}

// TestSessionWasEstablishedInitiallyFalse asserts that a freshly-added
// BGP session has not reached Established.
func TestSessionWasEstablishedInitiallyFalse(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBGPSession(65001, 65002, 0x01020304, 90, 30, true)
	if err != nil {
		t.Fatalf("AddBGPSession: %v", err)
	}
	est, err := r.SessionWasEstablished(h)
	if err != nil {
		t.Fatalf("SessionWasEstablished: %v", err)
	}
	if est {
		t.Fatal("fresh session has not reached Established")
	}
}

// TestRibPathsCountStartsAtZero asserts that a fresh router has no
// paths in its Add-Path view.
func TestRibPathsCountStartsAtZero(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	n, err := r.RibPathsCount()
	if err != nil {
		t.Fatalf("RibPathsCount: %v", err)
	}
	if n != 0 {
		t.Fatalf("fresh router should have 0 paths, got %d", n)
	}
}

// TestRibPathAtOutOfRange asserts that an out-of-range index returns
// an error mentioning "out of range".
func TestRibPathAtOutOfRange(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	_, err = r.RibPathAt(0)
	if err == nil {
		t.Fatal("expected out-of-range error, got nil")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected 'out of range' in error, got %v", err)
	}
}

// TestRibPathAtReturnsOwnedRoute asserts that an originated route is
// reachable through the Add-Path view and the returned *Route can be
// freed explicitly.
func TestRibPathAtReturnsOwnedRoute(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	prefix := [4]byte{10, 0, 0, 1}
	if err := r.OriginateV4(prefix, 24, nil); err != nil {
		t.Fatalf("OriginateV4: %v", err)
	}
	n, err := r.RibPathsCount()
	if err != nil {
		t.Fatalf("RibPathsCount: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 path after originate, got %d", n)
	}
	route, err := r.RibPathAt(0)
	if err != nil {
		t.Fatalf("RibPathAt: %v", err)
	}
	if route == nil {
		t.Fatal("expected non-nil route")
	}
	// Explicit free; the finalizer would also handle it.
	route.Free()
}

// TestFlushRibForShutdownSucceeds asserts that the shutdown flush
// returns nil on a fresh router and is idempotent.
func TestFlushRibForShutdownSucceeds(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	prefix := [4]byte{10, 0, 0, 1}
	if err := r.OriginateV4(prefix, 24, nil); err != nil {
		t.Fatalf("OriginateV4: %v", err)
	}
	if err := r.FlushRibForShutdown(); err != nil {
		t.Fatalf("FlushRibForShutdown: %v", err)
	}
	// Idempotent.
	if err := r.FlushRibForShutdown(); err != nil {
		t.Fatalf("FlushRibForShutdown (2nd): %v", err)
	}
}

// TestBabelFlushSessionSucceeds asserts that a Babel session can be
// flushed without error.
func TestBabelFlushSessionSucceeds(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	if err := r.BabelFlushSession(h); err != nil {
		t.Fatalf("BabelFlushSession: %v", err)
	}
}

// TestBabelGCSucceeds asserts that the Babel expiry sweep succeeds.
func TestBabelGCSucceeds(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	if _, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}); err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	if err := r.BabelGC(1000); err != nil {
		t.Fatalf("BabelGC: %v", err)
	}
}

// TestSetBabelOwnRouterIDSucceeds asserts that the Babel router-id can
// be set without error.
func TestSetBabelOwnRouterIDSucceeds(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	id := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := r.SetBabelOwnRouterID(h, id); err != nil {
		t.Fatalf("SetBabelOwnRouterID: %v", err)
	}
}

// TestSetBabelLinkCostParamsSucceeds asserts that the link-cost ramp
// can be configured.
func TestSetBabelLinkCostParamsSucceeds(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	if err := r.SetBabelLinkCostParams(h, 1000, 100000, 96); err != nil {
		t.Fatalf("SetBabelLinkCostParams: %v", err)
	}
}

// TestBabelNotePeerV4Succeeds asserts that noting a v4 peer address
// works.
func TestBabelNotePeerV4Succeeds(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{192, 0, 2, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	if err := r.BabelNotePeer(h, []byte{192, 0, 2, 100}); err != nil {
		t.Fatalf("BabelNotePeer: %v", err)
	}
}

// TestBabelNotePeerV6Succeeds asserts that noting a v6 peer address works.
func TestBabelNotePeerV6Succeeds(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	peer := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99}
	if err := r.BabelNotePeer(h, peer); err != nil {
		t.Fatalf("BabelNotePeer: %v", err)
	}
}

// TestBabelNotePeerBadLength asserts that an address of the wrong
// length is rejected up front (Go-side check, no FFI call).
func TestBabelNotePeerBadLength(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{192, 0, 2, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	if err := r.BabelNotePeer(h, []byte{1, 2, 3}); err == nil {
		t.Fatal("BabelNotePeer should reject a 3-byte address")
	}
}

// TestBabelRTTUsNoSample asserts that a fresh Babel session has no
// RTT sample.
func TestBabelRTTUsNoSample(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	us, ok, err := r.BabelRTTUs(h, 0)
	if err != nil {
		t.Fatalf("BabelRTTUs: %v", err)
	}
	if ok {
		t.Fatalf("no sample should be available yet, got us=%d", us)
	}
}

// TestBabelRTTEchoPairNoSample asserts that a fresh Babel session has
// no RTT echo pair.
func TestBabelRTTEchoPairNoSample(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	_, _, ok, err := r.BabelRTTEchoPair(h, 0)
	if err != nil {
		t.Fatalf("BabelRTTEchoPair: %v", err)
	}
	if ok {
		t.Fatal("no echo pair should be available yet")
	}
}

// TestBabelEgressNexthopsNonBabelReturnsNotOk asserts that querying
// egress next hops for a non-Babel session returns ok=false (the C
// ABI's "no info" return code).
func TestBabelEgressNexthopsNonBabelReturnsNotOk(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBGPSession(65001, 65002, 0x01020304, 90, 30, true)
	if err != nil {
		t.Fatalf("AddBGPSession: %v", err)
	}
	v4, v6, ok, err := r.BabelEgressNexthops(h)
	if err != nil {
		t.Fatalf("BabelEgressNexthops: %v", err)
	}
	if ok {
		t.Fatal("non-Babel session should return ok=false")
	}
	if v4 != nil || v6 != nil {
		t.Fatalf("non-Babel session should have nil nexthops, got v4=%v v6=%v", v4, v6)
	}
}

// TestBabelEgressNexthopsBabelV6ReturnsLocal asserts that a Babel v6
// session reports the local v6 address as the egress next hop (the
// peer-address fallback per RFC 8966 §3.5.3).
func TestBabelEgressNexthopsBabelV6ReturnsLocal(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	local := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	h, err := r.AddBabelSession(local)
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	v4, v6, ok, err := r.BabelEgressNexthops(h)
	if err != nil {
		t.Fatalf("BabelEgressNexthops: %v", err)
	}
	if !ok {
		t.Fatal("Babel session should return ok=true")
	}
	if v4 != nil {
		t.Fatalf("no v4 next hop should be present, got %v", v4)
	}
	if v6 == nil {
		t.Fatal("expected v6 next hop equal to local address")
	}
	if len(v6) != 16 {
		t.Fatalf("v6 next hop should be 16 bytes, got %d", len(v6))
	}
	for i, b := range v6 {
		if b != local[i] {
			t.Fatalf("v6[%d]=%d does not match local[%d]=%d", i, b, i, local[i])
		}
	}
}

// TestBabelTakeRouteRequestInitiallyFalse asserts that a fresh Babel
// session has no pending Route Request.
func TestBabelTakeRouteRequestInitiallyFalse(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	ok, err := r.BabelTakeRouteRequest(h)
	if err != nil {
		t.Fatalf("BabelTakeRouteRequest: %v", err)
	}
	if ok {
		t.Fatal("no Route Request should be pending yet")
	}
}

// TestBabelTakeOwnSeqnoRequestInitiallyFalse asserts that a fresh
// Babel session has no pending own-seqno request.
func TestBabelTakeOwnSeqnoRequestInitiallyFalse(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	h, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession: %v", err)
	}
	_, ok, err := r.BabelTakeOwnSeqnoRequest(h)
	if err != nil {
		t.Fatalf("BabelTakeOwnSeqnoRequest: %v", err)
	}
	if ok {
		t.Fatal("no own-seqno request should be pending yet")
	}
}
