// Package librouting tests.
package librouting

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func TestNewRouter(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	if r == nil {
		t.Fatal("nil router")
	}
	// GC finalizer should clean up — explicit destroy is also OK.
	r.ptr = nil // suppress duplicate free in finalizer
}

func TestABIVersion(t *testing.T) {
	v := ABIVersion()
	if v == 0 {
		t.Fatal("ABI version should not be 0")
	}
}

func TestEncodeKeepalive(t *testing.T) {
	b, err := EncodeKeepalive()
	if err != nil {
		t.Fatalf("EncodeKeepalive: %v", err)
	}
	if len(b) != 19 {
		t.Fatalf("expected 19-byte KEEPALIVE, got %d", len(b))
	}
	if b[18] != 4 {
		t.Fatalf("expected type=4 (KEEPALIVE), got %d", b[18])
	}
}

func TestDecodeBGP(t *testing.T) {
	// Encode a keepalive, then decode it.
	b, err := EncodeKeepalive()
	if err != nil {
		t.Fatalf("EncodeKeepalive: %v", err)
	}
	out, err := DecodeBGP(b)
	if err != nil {
		t.Fatalf("DecodeBGP: %v", err)
	}
	if len(out) != len(b) {
		t.Fatalf("expected roundtrip len %d, got %d", len(b), len(out))
	}
}

func TestEncodeSRv6SRH(t *testing.T) {
	// Two SIDs in the documentation prefix (RFC 3849):
	//   2001:db8:dead:beef::1
	//   2001:db8:dead:beef::2
	sid1 := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
		0, 0, 0, 0, 0, 0, 0, 1,
	}
	sid2 := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
		0, 0, 0, 0, 0, 0, 0, 2,
	}
	sids := append(sid1, sid2...)
	srh, err := EncodeSRv6SRH(sids)
	if err != nil {
		t.Fatalf("EncodeSRv6SRH: %v", err)
	}
	// SRH length: 8 fixed + 2*16 segments = 40.
	if len(srh) != 40 {
		t.Fatalf("expected 40-byte SRH, got %d", len(srh))
	}
	// Routing Type at offset 2 = 4 (RFC 8754 §2; IANA "IPv6 Routing
	// Types" registry — 43 is the Routing header's Next Header value,
	// a different field at a different layer).
	if srh[2] != 4 {
		t.Fatalf("expected Routing Type 4, got %d", srh[2])
	}
	// Decode back — the returned bytes are the segment list concatenated.
	decoded, err := DecodeSRv6SRH(srh)
	if err != nil {
		t.Fatalf("DecodeSRv6SRH: %v", err)
	}
	if !bytesEqual(decoded, sids) {
		t.Fatalf("SRH roundtrip mismatch:\n  got %v\n  want %v", decoded, sids)
	}
}

func TestEncodeSRv6SRHRejectsBadLength(t *testing.T) {
	bad := make([]byte, 17) // not a multiple of 16
	_, err := EncodeSRv6SRH(bad)
	if err == nil {
		t.Fatal("EncodeSRv6SRH must reject bad length")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDataPlane(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	h, err := r.AddBGPSession(64512, 64513, 0x0a000001, 90, 0, true)
	if err != nil {
		t.Fatalf("AddBGPSession: %v", err)
	}
	if err := r.StartSession(h); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	open, err := r.DrainOutput(h)
	if err != nil {
		t.Fatalf("DrainOutput: %v", err)
	}
	if len(open) < 29 || open[18] != 1 {
		t.Fatalf("expected queued OPEN, got %d bytes type=%d", len(open), open[18])
	}

	nh := [4]byte{192, 0, 2, 1}
	if err := r.OriginateV4([4]byte{203, 0, 113, 0}, 24, &nh); err != nil {
		t.Fatalf("OriginateV4: %v", err)
	}
	n, err := r.RibLen()
	if err != nil {
		t.Fatalf("RibLen: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected rib len 1, got %d", n)
	}

	// RFC 8277 labelled-unicast origination (label stack = [100]).
	if err := r.OriginateLabeledV4([4]byte{198, 51, 100, 0}, 24, []uint32{100}, &nh); err != nil {
		t.Fatalf("OriginateLabeledV4: %v", err)
	}
	n, err = r.RibLen()
	if err != nil {
		t.Fatalf("RibLen after labelled: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected rib len 2 after labelled originate, got %d", n)
	}

	// MPLS platform-labels query (0 in CI; 16/20 in a lab).
	mpl := MplsPlatformLabels()
	if mpl != 0 && mpl != 16 && mpl != 20 {
		t.Fatalf("unexpected MplsPlatformLabels value: %d", mpl)
	}
	dump, err := r.RibDump()
	if err != nil {
		t.Fatalf("RibDump: %v", err)
	}
	if !strings.Contains(dump, "203.0.113.0/24") {
		t.Fatalf("rib dump missing prefix: %q", dump)
	}
	sessions, err := r.SessionsDump()
	if err != nil {
		t.Fatalf("SessionsDump: %v", err)
	}
	// The session was started and its OPEN drained, so the FSM sits in
	// OpenSent awaiting the peer's OPEN.
	if !strings.Contains(sessions, "kind=bgp") || !strings.Contains(sessions, "state=OpenSent") {
		t.Fatalf("sessions dump missing bgp session: %q", sessions)
	}
	r.ptr = nil
}

// TestAddBGPSessionExtLLGR verifies the extended session constructor
// advertises the RFC 9494 LLGR capability (code 71, one 7-byte tuple).
func TestAddBGPSessionExtLLGR(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	h, err := r.AddBGPSessionExt(64512, 64513, 0x0a000001, 90, 0, true,
		true, 120, true, 3600, 0)
	if err != nil {
		t.Fatalf("AddBGPSessionExt: %v", err)
	}
	if err := r.StartSession(h); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	open, err := r.DrainOutput(h)
	if err != nil {
		t.Fatalf("DrainOutput: %v", err)
	}
	hasLLGR := false
	for i := 19; i+1 < len(open); i++ {
		if open[i] == 71 && open[i+1] == 7 {
			hasLLGR = true
			break
		}
	}
	if !hasLLGR {
		t.Fatalf("OPEN does not advertise the LLGR capability (code 71)")
	}
	r.ptr = nil
}

// TestSetAddPath verifies the RFC 7911 Add-Path setters: the OPEN
// advertises capability 69 with one 4-byte <AFI, SAFI, Send/Receive>
// tuple for IPv4 unicast, and toggling after establishment is rejected.
func TestSetAddPath(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	h, err := r.AddBGPSession(64512, 64513, 0x0a000001, 90, 0, true)
	if err != nil {
		t.Fatalf("AddBGPSession: %v", err)
	}
	if err := r.SetAddPathMaxPaths(4); err != nil {
		t.Fatalf("SetAddPathMaxPaths: %v", err)
	}
	if err := r.SetAddPath(h, true); err != nil {
		t.Fatalf("SetAddPath: %v", err)
	}
	if err := r.StartSession(h); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	open, err := r.DrainOutput(h)
	if err != nil {
		t.Fatalf("DrainOutput: %v", err)
	}
	// Capability 69, length 4: AFI 0/1, SAFI 1, Send/Receive 3 (both).
	hasAddPath := false
	for i := 19; i+5 < len(open); i++ {
		if open[i] == 69 && open[i+1] == 4 &&
			open[i+2] == 0 && open[i+3] == 1 && open[i+4] == 1 && open[i+5] == 3 {
			hasAddPath = true
			break
		}
	}
	if !hasAddPath {
		t.Fatalf("OPEN does not advertise Add-Path (code 69, len 4, send+recv)")
	}
	r.ptr = nil
}

// TestRfc8212 verifies the RFC 8212 ABI: the mode toggle and the
// per-session policy-presence declaration (unknown handles fail closed).
func TestRfc8212(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	h, err := r.AddBGPSession(64512, 64513, 0x0a000001, 90, 0, true)
	if err != nil {
		t.Fatalf("AddBGPSession: %v", err)
	}
	if err := r.SetEbgpRequiresPolicy(true); err != nil {
		t.Fatalf("SetEbgpRequiresPolicy(true): %v", err)
	}
	if err := r.SetSessionPolicy(h, true, true); err != nil {
		t.Fatalf("SetSessionPolicy: %v", err)
	}
	// Unknown session handle: the declaration must fail closed.
	if err := r.SetSessionPolicy(9999, true, true); err == nil {
		t.Fatalf("SetSessionPolicy on unknown session must error")
	}
	if err := r.SetEbgpRequiresPolicy(false); err != nil {
		t.Fatalf("SetEbgpRequiresPolicy(false): %v", err)
	}
	// FRR `bgp enforce-first-as` (W2.2): the router-wide toggle is
	// callable from Go and round-trips through the C ABI.
	if err := r.SetEnforceFirstAs(true); err != nil {
		t.Fatalf("SetEnforceFirstAs(true): %v", err)
	}
	if err := r.SetEnforceFirstAs(false); err != nil {
		t.Fatalf("SetEnforceFirstAs(false): %v", err)
	}
	// FRR `bgp default ipv4-unicast` (W2.1): the per-session toggle
	// is callable from Go and round-trips through the C ABI. Unknown
	// handles fail closed.
	if err := r.SetDefaultIPv4Unicast(h, false); err != nil {
		t.Fatalf("SetDefaultIPv4Unicast(false): %v", err)
	}
	if err := r.SetDefaultIPv4Unicast(h, true); err != nil {
		t.Fatalf("SetDefaultIPv4Unicast(true): %v", err)
	}
	if err := r.SetDefaultIPv4Unicast(9999, true); err == nil {
		t.Fatalf("SetDefaultIPv4Unicast on unknown session must error")
	}
	// FRR `neighbor X allowas-in N` / BIRD `allow local as` (W2.3):
	// the per-session tolerance is callable from Go and round-trips
	// through the C ABI. Unknown handles fail closed.
	if err := r.SetLocalAsTolerance(h, 1); err != nil {
		t.Fatalf("SetLocalAsTolerance(1): %v", err)
	}
	if err := r.SetLocalAsTolerance(h, 0); err != nil {
		t.Fatalf("SetLocalAsTolerance(0): %v", err)
	}
	if err := r.SetLocalAsTolerance(h, math.MaxUint32); err != nil {
		t.Fatalf("SetLocalAsTolerance(allowas-any): %v", err)
	}
	if err := r.SetLocalAsTolerance(9999, 1); err == nil {
		t.Fatalf("SetLocalAsTolerance on unknown session must error")
	}
	// FRR `neighbor X soft-reconfiguration inbound` (W2.4): the
	// per-session toggle + the soft reconfiguration op are callable
	// from Go and round-trip through the C ABI.
	if err := r.SetSoftReconfigInbound(h, true); err != nil {
		t.Fatalf("SetSoftReconfigInbound(true): %v", err)
	}
	if err := r.SetSoftReconfigInbound(h, false); err != nil {
		t.Fatalf("SetSoftReconfigInbound(false): %v", err)
	}
	if err := r.SetSoftReconfigInbound(9999, true); err == nil {
		t.Fatalf("SetSoftReconfigInbound on unknown session must error")
	}
	// soft_reconfig_inbound on a session with the flag off is a
	// no-op (returns 0). An unknown session is also a no-op (returns
	// 0) — the pre-policy RIB is empty for that origin.
	n, err := r.SoftReconfigInbound(h)
	if err != nil {
		t.Fatalf("SoftReconfigInbound: %v", err)
	}
	if n != 0 {
		t.Fatalf("SoftReconfigInbound no-op when flag is off: got %d", n)
	}
	n, err = r.SoftReconfigInbound(9999)
	if err != nil {
		t.Fatalf("SoftReconfigInbound on unknown handle: %v", err)
	}
	if n != 0 {
		t.Fatalf("SoftReconfigInbound no-op on unknown handle: got %d", n)
	}
	r.ptr = nil
}

// ---- ROA store (RFC 6482 / RFC 6811 / RFC 8210, ROADMAP-v3 D2.3) ----

func TestRoaStoreLifecycle(t *testing.T) {
	s, err := NewRoaStore()
	if err != nil {
		t.Fatalf("NewRoaStore: %v", err)
	}
	defer s.Close()
	if s.Len() != 0 {
		t.Fatalf("new store must be empty, got %d", s.Len())
	}

	statics := []RoaEntry{
		{Addr: []byte{198, 51, 100, 0}, PrefixLen: 24, MaxLength: 24, ASN: 64513},
		{Addr: []byte{203, 0, 113, 0}, PrefixLen: 24, MaxLength: 26, ASN: 64512},
	}
	if err := s.ReplaceStatic(statics); err != nil {
		t.Fatalf("ReplaceStatic: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len after ReplaceStatic = %d, want 2", s.Len())
	}

	state, err := s.Validate([]byte{198, 51, 100, 0}, 24, 64513, true)
	if err != nil || state != RoaValid {
		t.Fatalf("Validate authorized = (%d, %v), want (RoaValid, nil)", state, err)
	}
	state, _ = s.Validate([]byte{198, 51, 100, 0}, 24, 64512, true)
	if state != RoaInvalid {
		t.Fatalf("Validate wrong origin = %d, want RoaInvalid", state)
	}
	state, _ = s.Validate([]byte{203, 0, 113, 0}, 27, 64512, true)
	if state != RoaInvalid {
		t.Fatalf("Validate /27 under max 26 = %d, want RoaInvalid", state)
	}
	state, _ = s.Validate([]byte{203, 0, 113, 0}, 24, 0, false)
	if state != RoaNotFound {
		t.Fatalf("Validate without origin = %d, want RoaNotFound", state)
	}

	// One announce delta + a duplicate: RFC 8210 §5.6 coalescing.
	deltas := []RoaDelta{
		{Announce: true, Entry: RoaEntry{Addr: []byte{192, 0, 2, 0}, PrefixLen: 24, MaxLength: 24, ASN: 64512}},
		{Announce: true, Entry: RoaEntry{Addr: []byte{192, 0, 2, 0}, PrefixLen: 24, MaxLength: 24, ASN: 64512}},
	}
	if err := s.ApplyDeltas(deltas); err != nil {
		t.Fatalf("ApplyDeltas: %v", err)
	}
	if s.Len() != 3 {
		t.Fatalf("Len after deltas = %d, want 3 (2 static + 1 rtr)", s.Len())
	}

	// Data expiry: the cache layer goes, the static layer survives.
	if err := s.ClearRTR(); err != nil {
		t.Fatalf("ClearRTR: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len after ClearRTR = %d, want 2", s.Len())
	}

	// Malformed entry fails the whole batch atomically.
	bad := []RoaDelta{{Announce: true, Entry: RoaEntry{Addr: []byte{10, 0, 0, 0}, PrefixLen: 8, MaxLength: 4, ASN: 64512}}}
	if err := s.ApplyDeltas(bad); err == nil {
		t.Fatal("ApplyDeltas with max_length < prefix_len must fail")
	}
	if s.Len() != 2 {
		t.Fatalf("store changed after failed batch: %d", s.Len())
	}
}

func TestRedistributionAndAggregate(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	err = r.AddRedistributionPipe(ProtoOspf, ProtoBgp, MetricFixed, 100, true, 65000,
		[]PrefixSpec{{Addr: []byte{10, 0, 0, 0}, PrefixLen: 8}})
	if err != nil {
		t.Fatalf("AddRedistributionPipe: %v", err)
	}
	err = r.AddRedistributionPipe(Protocol(99), ProtoBgp, MetricInherit, 0, false, 0, nil)
	if err == nil {
		t.Fatal("unknown protocol id must fail")
	}

	prefix := PrefixSpec{Addr: []byte{203, 0, 113, 0}, PrefixLen: 24}
	if err := r.AddAggregate(prefix); err != nil {
		t.Fatalf("AddAggregate: %v", err)
	}
	if err := r.RemoveAggregate(prefix); err != nil {
		t.Fatalf("RemoveAggregate: %v", err)
	}
}

func TestDamping(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	d, err := r.SetDamping(DampingConfig{
		AdditiveIncr:         1000,
		SuppressThreshold:    2000,
		ReuseThreshold:       750,
		UpperLimit:           60000,
		DecayIntervalS:       30,
		DecayFactorActive:    0.97,
		DecayFactorWithdrawn: 0.5,
	})
	if err != nil {
		t.Fatalf("SetDamping: %v", err)
	}
	defer d.Destroy()
	n, err := d.Decay(1000)
	if err != nil || n != 0 {
		t.Fatalf("Decay on idle table: got (%d, %v), want (0, nil)", n, err)
	}
}

func TestOSPFAndBabelSessions(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	// OSPFv2 + OSPFv3 on the same 32-bit router-id share the id domain.
	h, err := r.AddOSPFSession(0x0a000001, 0)
	if err != nil {
		t.Fatalf("AddOSPFSession: %v", err)
	}
	if h == 0 {
		t.Fatal("OSPF session handle must be non-zero")
	}
	h3, err := r.AddOSPFv3Session(0x0a000001, 3)
	if err != nil {
		t.Fatalf("AddOSPFv3Session: %v", err)
	}
	if h3 == h {
		t.Fatal("session handles must be distinct")
	}
	// A second router-id is rejected by the router.
	if _, err := r.AddOSPFSession(0x0a000002, 5); err == nil {
		t.Fatal("router-id mismatch must fail")
	}
	// The backbone (area 0) can never be a stub (RFC 2328 §3.6).
	if _, err := r.AddOSPFSessionExt(OspfV2, 0x0a000001, 0, AreaStub, 1000, 1500,
		NetPtp, false, 0, false, 0); err == nil {
		t.Fatal("backbone stub must fail")
	}
	// Unknown enums fail closed.
	if _, err := r.AddOSPFSessionExt(4, 0x0a000001, 3, AreaNormal, 0, 1500,
		NetPtp, false, 0, false, 0); err == nil {
		t.Fatal("version 4 must fail")
	}
	// A totally-NSSA area with the segment identities attaches.
	hx, err := r.AddOSPFSessionExt(OspfV2, 0x0a000001, 1, AreaNssaNoSummary, 1000, 1500,
		NetBroadcast, true, 0x0a000101, true, 0x0a000102)
	if err != nil {
		t.Fatalf("AddOSPFSessionExt: %v", err)
	}
	if hx == 0 {
		t.Fatal("ext OSPF session handle must be non-zero")
	}

	// Babel: one IPv6 link-local interface, one IPv4 interface.
	hb, err := r.AddBabelSession([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("AddBabelSession v6: %v", err)
	}
	if hb == 0 {
		t.Fatal("Babel session handle must be non-zero")
	}
	if _, err := r.AddBabelSession([]byte{192, 0, 2, 1}); err != nil {
		t.Fatalf("AddBabelSession v4: %v", err)
	}
	if _, err := r.AddBabelSession([]byte{1, 2, 3}); err == nil {
		t.Fatal("a 3-byte address must fail")
	}
}

func TestOriginateAndWithdrawLifecycle(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	v4 := [4]byte{203, 0, 113, 0}
	v6 := [16]byte{0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// Withdrawing a prefix that was never originated is an idempotent
	// no-op (FRR "no network" on an absent statement).
	if w, err := r.WithdrawV4(v4, 24); err != nil || w {
		t.Fatalf("WithdrawV4 on empty router: got (%v, %v), want (false, nil)", w, err)
	}

	if err := r.OriginateV4(v4, 24, nil); err != nil {
		t.Fatalf("OriginateV4: %v", err)
	}
	if err := r.OriginateV6(v6, 32, nil); err != nil {
		t.Fatalf("OriginateV6: %v", err)
	}
	n, err := r.RibLen()
	if err != nil || n != 2 {
		t.Fatalf("RibLen after originates: got (%d, %v), want (2, nil)", n, err)
	}

	if w, err := r.WithdrawV4(v4, 24); err != nil || !w {
		t.Fatalf("WithdrawV4: got (%v, %v), want (true, nil)", w, err)
	}
	if w, err := r.WithdrawV6(v6, 32); err != nil || !w {
		t.Fatalf("WithdrawV6: got (%v, %v), want (true, nil)", w, err)
	}
	n, err = r.RibLen()
	if err != nil || n != 0 {
		t.Fatalf("RibLen after withdraws: got (%d, %v), want (0, nil)", n, err)
	}

	// Second withdraw of the same prefixes is a no-op again.
	if w, err := r.WithdrawV4(v4, 24); err != nil || w {
		t.Fatalf("repeat WithdrawV4: got (%v, %v), want (false, nil)", w, err)
	}
	if w, err := r.WithdrawV6(v6, 32); err != nil || w {
		t.Fatalf("repeat WithdrawV6: got (%v, %v), want (false, nil)", w, err)
	}

	// Out-of-range prefix lengths are rejected up front.
	if err := r.OriginateV4(v4, 33, nil); err == nil {
		t.Fatal("OriginateV4 with plen 33 must fail")
	}
	if err := r.OriginateV6(v6, 129, nil); err == nil {
		t.Fatal("OriginateV6 with plen 129 must fail")
	}
	if _, err := r.WithdrawV4(v4, 33); err == nil {
		t.Fatal("WithdrawV4 with plen 33 must fail")
	}
	if _, err := r.WithdrawV6(v6, 129); err == nil {
		t.Fatal("WithdrawV6 with plen 129 must fail")
	}
}

func TestStaticRouteLifecycle(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	v4 := [4]byte{203, 0, 113, 0}
	v6 := [16]byte{0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	nh4 := [4]byte{192, 0, 2, 1}
	nh6 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	bhV4 := [4]byte{10, 0, 0, 0}

	// install_static_v4 with a real next-hop + metric.
	if err := r.InstallStaticV4(v4, 24, &nh4, 10, 0); err != nil {
		t.Fatalf("InstallStaticV4 with nh: %v", err)
	}
	// install_static_v4 as a blackhole (nil next-hop).
	if err := r.InstallStaticV4(bhV4, 8, nil, 0, 65000); err != nil {
		t.Fatalf("InstallStaticV4 blackhole: %v", err)
	}
	// install_static_v6 with a real next-hop.
	if err := r.InstallStaticV6(v6, 32, &nh6, 0, 0); err != nil {
		t.Fatalf("InstallStaticV6: %v", err)
	}
	n, err := r.RibLen()
	if err != nil || n != 3 {
		t.Fatalf("RibLen after statics: got (%d, %v), want (3, nil)", n, err)
	}

	// Out-of-range prefix lengths are rejected up front.
	if err := r.InstallStaticV4(v4, 33, &nh4, 0, 0); err == nil {
		t.Fatal("InstallStaticV4 with plen 33 must fail")
	}
	if err := r.InstallStaticV6(v6, 129, &nh6, 0, 0); err == nil {
		t.Fatal("InstallStaticV6 with plen 129 must fail")
	}

	// Uninstall removes the routes one at a time.
	if w, err := r.UninstallStaticV4(v4, 24); err != nil || !w {
		t.Fatalf("UninstallStaticV4 of installed route: got (%v, %v), want (true, nil)", w, err)
	}
	if w, err := r.UninstallStaticV4(bhV4, 8); err != nil || !w {
		t.Fatalf("UninstallStaticV4 of blackhole: got (%v, %v), want (true, nil)", w, err)
	}
	if w, err := r.UninstallStaticV6(v6, 32); err != nil || !w {
		t.Fatalf("UninstallStaticV6: got (%v, %v), want (true, nil)", w, err)
	}
	n, err = r.RibLen()
	if err != nil || n != 0 {
		t.Fatalf("RibLen after uninstalls: got (%d, %v), want (0, nil)", n, err)
	}

	// Repeated uninstall is an idempotent no-op.
	if w, err := r.UninstallStaticV4(v4, 24); err != nil || w {
		t.Fatalf("repeat UninstallStaticV4: got (%v, %v), want (false, nil)", w, err)
	}
}

func TestBGPMessageEncoders(t *testing.T) {
	// OPEN with the ASN4 capability.
	open, err := EncodeOpen(64512, 90, [4]byte{10, 0, 0, 1}, true)
	if err != nil {
		t.Fatalf("EncodeOpen: %v", err)
	}
	if len(open) < 30 || open[18] != 1 {
		t.Fatalf("OPEN wire form: type=%d len=%d", open[18], len(open))
	}
	if _, err := EncodeOpen(4200000000, 90, [4]byte{10, 0, 0, 1}, false); err == nil {
		t.Fatal("4-byte AS with as4 off must fail")
	}
	if _, err := EncodeOpen(64512, 1, [4]byte{10, 0, 0, 1}, false); err == nil {
		t.Fatal("hold time 1 must fail")
	}

	// NOTIFICATION with and without data.
	n, err := EncodeNotification(6, 3, nil)
	if err != nil || len(n) != 21 || n[18] != 3 {
		t.Fatalf("EncodeNotification: got (%d bytes, err=%v)", len(n), err)
	}
	n, err = EncodeNotification(2, 4, []byte{1, 2})
	if err != nil || len(n) != 23 {
		t.Fatalf("EncodeNotification with data: got (%d bytes, err=%v)", len(n), err)
	}

	// Withdraw-only UPDATE.
	pfx := []PrefixSpec{{Addr: []byte{203, 0, 113, 0}, PrefixLen: 24}}
	w, err := EncodeUpdateWithdrawV4(pfx)
	if err != nil {
		t.Fatalf("EncodeUpdateWithdrawV4: %v", err)
	}
	if w[18] != 2 {
		t.Fatalf("UPDATE type = %d", w[18])
	}
	if _, err := EncodeUpdateWithdrawV4(
		[]PrefixSpec{{Addr: make([]byte, 16), IsIPv6: true, PrefixLen: 32}}); err == nil {
		t.Fatal("IPv6 prefix in the legacy NLRI section must fail")
	}

	// Announcement UPDATE (ORIGIN=IGP, AS_PATH 64513 64512).
	a, err := EncodeUpdateAnnounceV4(pfx, [4]byte{192, 0, 2, 1}, []uint32{64513, 64512}, 0, false)
	if err != nil {
		t.Fatalf("EncodeUpdateAnnounceV4: %v", err)
	}
	if a[18] != 2 || len(a) <= 23 {
		t.Fatalf("announce UPDATE wire form: type=%d len=%d", a[18], len(a))
	}
	if _, err := EncodeUpdateAnnounceV4(pfx, [4]byte{192, 0, 2, 1}, nil, 3, false); err == nil {
		t.Fatal("ORIGIN 3 must fail")
	}
}

func TestPollEvents(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer func() { r.ptr = nil }()

	if err := r.OriginateV4([4]byte{203, 0, 113, 0}, 24, nil); err != nil {
		t.Fatalf("OriginateV4: %v", err)
	}
	if err := r.OriginateV4([4]byte{198, 51, 100, 0}, 24, nil); err != nil {
		t.Fatalf("OriginateV4: %v", err)
	}
	events, err := r.PollEvents(8)
	if err != nil {
		t.Fatalf("PollEvents: %v", err)
	}
	sawInstalled := false
	for _, ev := range events {
		if ev.Kind == EventRouteInstalled {
			sawInstalled = true
			if ev.PrefixLen > 32 {
				t.Fatalf("installed event plen %d", ev.PrefixLen)
			}
		}
	}
	if !sawInstalled {
		t.Fatal("RouteInstalled event not observed")
	}

	// Requeue semantics: one slot at a time drains everything.
	if err := r.OriginateV4([4]byte{192, 0, 2, 0}, 24, nil); err != nil {
		t.Fatalf("OriginateV4: %v", err)
	}
	slot, err := r.PollEvents(1)
	if err != nil {
		t.Fatalf("PollEvents(1): %v", err)
	}
	first := slot[0].Prefix
	drained := len(slot)
	for {
		more, err := r.PollEvents(1)
		if err != nil {
			t.Fatalf("PollEvents loop: %v", err)
		}
		if len(more) == 0 {
			break
		}
		drained++
		_ = more
	}
	_ = first

	// Invalid capacity is rejected.
	if _, err := r.PollEvents(0); err == nil {
		t.Fatal("PollEvents(0) must fail")
	}
}

func TestPolicyObjects(t *testing.T) {
	// Route handle: attribute round trip.
	rt, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer rt.Free()
	if err := rt.SetLocalPref(250); err != nil {
		t.Fatalf("SetLocalPref: %v", err)
	}
	if lp, ok, err := rt.LocalPref(); err != nil || !ok || lp != 250 {
		t.Fatalf("LocalPref: got (%d, %v, %v), want (250, true, nil)", lp, ok, err)
	}
	if err := rt.SetOrigin(0); err != nil {
		t.Fatalf("SetOrigin: %v", err)
	}
	if err := rt.SetOrigin(7); err == nil {
		t.Fatal("ORIGIN 7 must be rejected")
	}
	path := []uint32{64513, 65010, 64512}
	if err := rt.SetAsPath(path); err != nil {
		t.Fatalf("SetAsPath: %v", err)
	}
	got, err := rt.AsPath()
	if err != nil || len(got) != 3 || got[1] != 65010 {
		t.Fatalf("AsPath: got %v, %v", got, err)
	}
	if err := rt.SetCommunities([]uint64{(64512 << 16) | 100}); err != nil {
		t.Fatalf("SetCommunities: %v", err)
	}
	if err := rt.AddCommunity(4294967295, 1); err == nil {
		t.Fatal("a 4-byte ASN must be rejected for a standard community")
	}
	comms, err := rt.Communities()
	if err != nil || len(comms) != 1 || comms[0] != (64512<<16)|100 {
		t.Fatalf("Communities: got %v, %v", comms, err)
	}
	if err := rt.AddLargeCommunity(4200000000, 7, 9); err != nil {
		t.Fatalf("AddLargeCommunity: %v", err)
	}
	lc, err := rt.LargeCommunities()
	if err != nil || len(lc) != 3 {
		t.Fatalf("LargeCommunities: got %v, %v", lc, err)
	}
	if err := rt.AddExtCommunity(0x42, 0x02, 64512, 5); err != nil {
		t.Fatalf("AddExtCommunity: %v", err)
	}
	ec, err := rt.ExtCommunities()
	if err != nil || len(ec) != 1 || ec[0].Kind != 0x42 {
		t.Fatalf("ExtCommunities: got %v, %v", ec, err)
	}

	// Prefix-list: 10.0.0.0/8 ge 16 le 24.
	pl, err := NewPrefixList()
	if err != nil {
		t.Fatalf("NewPrefixList: %v", err)
	}
	defer pl.Free()
	if err := pl.Add(PrefixSpec{Addr: []byte{10, 0, 0, 0}, PrefixLen: 8}, 16, 24, true); err != nil {
		t.Fatalf("PrefixList.Add: %v", err)
	}
	if ok, err := pl.Match(PrefixSpec{Addr: []byte{10, 1, 1, 0}, PrefixLen: 24}); err != nil || !ok {
		t.Fatalf("Match in-range: got (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := pl.Match(PrefixSpec{Addr: []byte{10, 0, 0, 0}, PrefixLen: 8}); err != nil || ok {
		t.Fatalf("Match ge gate: got (%v, %v), want (false, nil)", ok, err)
	}

	// Resolver + route-map: the FRR flow.
	res, err := NewResolver()
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	defer res.Free()
	any4, err := NewPrefixList()
	if err != nil {
		t.Fatalf("NewPrefixList any: %v", err)
	}
	defer any4.Free()
	if err := any4.Add(PrefixSpec{Addr: []byte{10, 0, 0, 0}, PrefixLen: 0}, 0, 32, true); err != nil {
		t.Fatalf("PrefixList.Add any: %v", err)
	}
	id, err := res.AddPrefixList("all-v4", any4)
	if err != nil || id != 0 {
		t.Fatalf("AddPrefixList: got (%d, %v), want (0, nil)", id, err)
	}

	rm, err := NewRouteMap()
	if err != nil {
		t.Fatalf("NewRouteMap: %v", err)
	}
	defer rm.Free()
	if err := rm.AddEntry([]Match{{Kind: MatchPrefixIn, ListID: 0}},
		[]Set{{Kind: SetLocalPref, Value: 300}}, VerdictPermit); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	verdict, err := rm.Evaluate(rt, res)
	if err != nil || verdict != EvalPermit {
		t.Fatalf("Evaluate: got (%d, %v), want (%d, nil)", verdict, err, EvalPermit)
	}
	if lp, _, _ := rt.LocalPref(); lp != 300 {
		t.Fatalf("set not applied: local_pref = %d, want 300", lp)
	}
	if verdict, err := rm.Evaluate(rt, nil); err != nil || verdict != EvalFallthrough {
		t.Fatalf("NULL resolver must fail the match: got (%d, %v), want (%d, nil)",
			verdict, err, EvalFallthrough)
	}
}

func TestRouteAttributeReadersAndReplacers(t *testing.T) {
	// Round-trip coverage for the Route readers and bulk replacers
	// that were previously asymmetric with the C ABI (defects.txt L243):
	// NextHop / Origin / Tag readers, and SetLargeCommunities /
	// SetExtCommunities / Metric.
	rt, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer rt.Free()

	// NextHop: absent by default; v4 round-trip; v6 round-trip.
	if nh, ok, err := rt.NextHop(); err != nil || ok || nh != nil {
		t.Fatalf("NextHop default: got (%v, %v, %v), want (nil, false, nil)", nh, ok, err)
	}
	v4 := []byte{198, 51, 100, 1}
	if err := rt.SetNextHop(v4); err != nil {
		t.Fatalf("SetNextHop v4: %v", err)
	}
	if nh, ok, err := rt.NextHop(); err != nil || !ok || !bytes.Equal(nh, v4) {
		t.Fatalf("NextHop v4: got (%v, %v, %v), want (%v, true, nil)", nh, ok, err, v4)
	}
	v6 := []byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if err := rt.SetNextHop(v6); err != nil {
		t.Fatalf("SetNextHop v6: %v", err)
	}
	if nh, ok, err := rt.NextHop(); err != nil || !ok || !bytes.Equal(nh, v6) {
		t.Fatalf("NextHop v6: got (%v, %v, %v), want (%v, true, nil)", nh, ok, err, v6)
	}

	// Origin: absent by default; IGP / EGP / INCOMPLETE round-trip.
	if o, ok, err := rt.Origin(); err != nil || ok || o != 0 {
		t.Fatalf("Origin default: got (%d, %v, %v), want (0, false, nil)", o, ok, err)
	}
	for _, o := range []byte{0, 1, 2} {
		if err := rt.SetOrigin(o); err != nil {
			t.Fatalf("SetOrigin(%d): %v", o, err)
		}
		got, ok, err := rt.Origin()
		if err != nil || !ok || got != o {
			t.Fatalf("Origin(%d): got (%d, %v, %v), want (%d, true, nil)", o, got, ok, err, o)
		}
	}

	// SetLargeCommunities replaces the whole attribute.
	if err := rt.SetLargeCommunities([]uint32{4200000000, 7, 9, 4200000001, 8, 10}); err != nil {
		t.Fatalf("SetLargeCommunities: %v", err)
	}
	lc, err := rt.LargeCommunities()
	if err != nil || len(lc) != 6 || lc[0] != 4200000000 || lc[5] != 10 {
		t.Fatalf("LargeCommunities: got %v, %v", lc, err)
	}
	// Empty drops the attribute.
	if err := rt.SetLargeCommunities(nil); err != nil {
		t.Fatalf("SetLargeCommunities(nil): %v", err)
	}
	if lc, err := rt.LargeCommunities(); err != nil || len(lc) != 0 {
		t.Fatalf("LargeCommunities after drop: got %v, %v", lc, err)
	}
	// Triples must come in groups of three.
	if err := rt.SetLargeCommunities([]uint32{1, 2}); err == nil {
		t.Fatal("SetLargeCommunities odd triples must be rejected")
	}

	// SetExtCommunities: set/round-trip.
	items := []ExtCommunity{
		{Kind: 0x42, Subtype: 0x02, Global: 64512, Local: 5},
		{Kind: 0x01, Subtype: 0x01, Global: 65000, Local: 100},
	}
	if err := rt.SetExtCommunities(items); err != nil {
		t.Fatalf("SetExtCommunities: %v", err)
	}
	ec, err := rt.ExtCommunities()
	if err != nil || len(ec) != 2 || ec[0] != items[0] || ec[1] != items[1] {
		t.Fatalf("ExtCommunities: got %v, %v", ec, err)
	}
	// Empty drops.
	if err := rt.SetExtCommunities(nil); err != nil {
		t.Fatalf("SetExtCommunities(nil): %v", err)
	}
	if ec, err := rt.ExtCommunities(); err != nil || len(ec) != 0 {
		t.Fatalf("ExtCommunities after drop: got %v, %v", ec, err)
	}

	// Metric: round-trip.
	if err := rt.SetMetric(42); err != nil {
		t.Fatalf("SetMetric: %v", err)
	}
	if m, err := rt.Metric(); err != nil || m != 42 {
		t.Fatalf("Metric: got (%d, %v), want (42, nil)", m, err)
	}

	// Tag: absent by default; set/clear round-trip.
	if tag, ok, err := rt.Tag(); err != nil || ok || tag != 0 {
		t.Fatalf("Tag default: got (%d, %v, %v), want (0, false, nil)", tag, ok, err)
	}
	if err := rt.SetTag(3735928559, true); err != nil {
		t.Fatalf("SetTag: %v", err)
	}
	if tag, ok, err := rt.Tag(); err != nil || !ok || tag != 3735928559 {
		t.Fatalf("Tag after set: got (%d, %v, %v), want (3735928559, true, nil)", tag, ok, err)
	}
	if err := rt.SetTag(0, false); err != nil {
		t.Fatalf("SetTag clear: %v", err)
	}
	if tag, ok, err := rt.Tag(); err != nil || ok || tag != 0 {
		t.Fatalf("Tag after clear: got (%d, %v, %v), want (0, false, nil)", tag, ok, err)
	}
	// A zero tag set with ok=true is still present.
	if err := rt.SetTag(0, true); err != nil {
		t.Fatalf("SetTag(0,true): %v", err)
	}
	if tag, ok, err := rt.Tag(); err != nil || !ok || tag != 0 {
		t.Fatalf("Tag(0,true): got (%d, %v, %v), want (0, true, nil)", tag, ok, err)
	}
}

func TestFilterDSL(t *testing.T) {
	f, err := Compile("go-f", "if bgp.local_pref >= 200 then { accept; } else { reject with \"low\"; }")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	defer f.Free()
	name, err := f.Name()
	if err != nil || name != "go-f" {
		t.Fatalf("Name: got (%q, %v), want (go-f, nil)", name, err)
	}

	rt, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer rt.Free()

	if err := rt.SetLocalPref(250); err != nil {
		t.Fatalf("SetLocalPref: %v", err)
	}
	verdict, reason, err := f.Evaluate(rt)
	if err != nil || verdict != FilterAccept || reason != "" {
		t.Fatalf("Evaluate high: got (%d, %q, %v), want (%d, \"\", nil)",
			verdict, reason, err, FilterAccept)
	}
	if err := rt.SetLocalPref(100); err != nil {
		t.Fatalf("SetLocalPref low: %v", err)
	}
	verdict, reason, err = f.Evaluate(rt)
	if err != nil || verdict != FilterReject || reason != "low" {
		t.Fatalf("Evaluate low: got (%d, %q, %v), want (%d, \"low\", nil)",
			verdict, reason, err, FilterReject)
	}

	// Mutations persist: the filter rewrote LOCAL_PREF.
	if err := rt.SetLocalPref(300); err != nil {
		t.Fatalf("SetLocalPref reset: %v", err)
	}
	mut, err := Compile("go-mut", "bgp.local_pref = 42;")
	if err != nil {
		t.Fatalf("Compile mut: %v", err)
	}
	defer mut.Free()
	if _, _, err := mut.Evaluate(rt); err != nil {
		t.Fatalf("Evaluate mut: %v", err)
	}
	if lp, _, _ := rt.LocalPref(); lp != 42 {
		t.Fatalf("mutation not applied: local_pref = %d, want 42", lp)
	}

	// Parse errors surface with the diagnostic.
	if _, err := Compile("go-bad", "if bgp.local_pref = "); err == nil {
		t.Fatal("parse error must fail")
	}
}

func TestFilterDSLOspfMetric1(t *testing.T) {
	// `ospf.metric1` reads route.Preference.Metric for OSPF routes
	// and 0 for non-OSPF routes (RFC 2328 §16 / RFC 5340 §4.1).
	high, err := Compile("go-ospf-high",
		"if defined(ospf.metric1) && ospf.metric1 > 100 then reject; accept;")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	defer high.Free()

	// OSPFv2 route with metric 200 - above the threshold, rejected.
	ospf, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoOspf)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer ospf.Free()
	if err := ospf.SetMetric(200); err != nil {
		t.Fatalf("SetMetric: %v", err)
	}
	verdict, _, err := high.Evaluate(ospf)
	if err != nil || verdict != FilterReject {
		t.Fatalf("Evaluate high-cost OSPF: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterReject)
	}

	// OSPFv2 route with metric 50 - below the threshold, accepted.
	low, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoOspf)
	if err != nil {
		t.Fatalf("NewRouteV4 low: %v", err)
	}
	defer low.Free()
	if err := low.SetMetric(50); err != nil {
		t.Fatalf("SetMetric low: %v", err)
	}
	verdict, _, err = high.Evaluate(low)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate low-cost OSPF: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	// Non-OSPF (BGP) route: `defined(ospf.metric1)` is false, so
	// the `&&` short-circuits and the route is accepted.
	bgp, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4 bgp: %v", err)
	}
	defer bgp.Free()
	if err := bgp.SetMetric(200); err != nil {
		t.Fatalf("SetMetric bgp: %v", err)
	}
	verdict, _, err = high.Evaluate(bgp)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate non-OSPF (BGP): got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	// OSPFv3 also surfaces the metric (RFC 5340 §4.1 mirrors OSPFv2 §16).
	ospf3, err := NewRouteV6([16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1}, 64, ProtoOspf3)
	if err != nil {
		t.Fatalf("NewRouteV6: %v", err)
	}
	defer ospf3.Free()
	if err := ospf3.SetMetric(220); err != nil {
		t.Fatalf("SetMetric ospf3: %v", err)
	}
	v3, err := Compile("go-ospf3", "if ospf.metric1 == 220 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile v3: %v", err)
	}
	defer v3.Free()
	verdict, _, err = v3.Evaluate(ospf3)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv3: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
}

func TestFilterDSLOspfMetric2(t *testing.T) {
	// `ospf.metric2` reads the private `LrOspfMetric2`
	// path-attribute tag (RFC 2328 §16.4 / RFC 5340 §4.8.5) the
	// OSPF route computation attaches to type-2 external routes.
	// The binding exercises the FFI surface — Go → C ABI → Rust
	// filter eval → `lr-policy::ospf::metric2` accessor — so a
	// regression in any layer surfaces here.
	//
	// The "present" path (a route carrying the `LrOspfMetric2`
	// attribute) is exercised by the `lr-policy::ospf::metric2_*`
	// unit tests (which synthesize the attribute directly via
	// `Attributes::insert`) and the
	// `lr-router::instance::tests::ospfv3_inter_area_and_external_routes_published`
	// integration test (which populates the attribute via the
	// OSPF route computation, the only producer). The binding
	// cannot reach that path because the C ABI does not expose
	// a setter for the `LrOspfMetric2` tag — embedders read the
	// field but never inject it; the OSPF daemon is the only
	// producer. The binding test pins the "absent" path (the
	// FFI surface, the parser, the protocol-kind fast path, and
	// the absence-handling default), which is the layer an
	// embedder's regression would surface through.
	rejectHigh, err := Compile("go-ospf-metric2-high",
		"if defined(ospf.metric2) && ospf.metric2 > 100 then reject; accept;")
	if err != nil {
		t.Fatalf("Compile rejectHigh: %v", err)
	}
	defer rejectHigh.Free()
	readZero, err := Compile("go-ospf-metric2-zero",
		"if ospf.metric2 == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile readZero: %v", err)
	}
	defer readZero.Free()

	// An OSPFv2 route without the `LrOspfMetric2` attribute —
	// i.e. an intra-area, inter-area or type-1 external route
	// (the OSPF route computation only attaches the tag for
	// type-2 externals). `defined(ospf.metric2)` is false, so
	// the `&&` short-circuits and the route is accepted;
	// `ospf.metric2 == 0` reads the unwrap_or(0) default
	// (mirrors BIRD's eattr default for an unattached
	// `ospf_metric2` reference).
	ospf, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoOspf)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer ospf.Free()
	if err := ospf.SetMetric(200); err != nil {
		t.Fatalf("SetMetric: %v", err)
	}
	// `preference.metric` is 200 — `ospf.metric2` must NOT read
	// it (the attribute is absent). `defined()` short-circuits.
	verdict, _, err := rejectHigh.Evaluate(ospf)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv2 rejectHigh: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	verdict, _, err = readZero.Evaluate(ospf)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv2 readZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	// OSPFv3 mirrors OSPFv2 (RFC 5340 §4.8.5 mirrors §16.4) —
	// same absence-handling default.
	ospf3, err := NewRouteV6([16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1}, 64, ProtoOspf3)
	if err != nil {
		t.Fatalf("NewRouteV6: %v", err)
	}
	defer ospf3.Free()
	if err := ospf3.SetMetric(220); err != nil {
		t.Fatalf("SetMetric ospf3: %v", err)
	}
	verdict, _, err = rejectHigh.Evaluate(ospf3)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv3 rejectHigh: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	v3Zero, err := Compile("go-ospf3-metric2-zero",
		"if ospf.metric2 == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile v3Zero: %v", err)
	}
	defer v3Zero.Free()
	verdict, _, err = v3Zero.Evaluate(ospf3)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv3 readZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	// A non-OSPF (BGP) route: `defined(ospf.metric2)` is false
	// (the protocol-kind fast path rejects non-OSPF routes
	// before the attribute lookup), so the `&&` short-circuits
	// and the route is accepted. The protocol-kind fast path is
	// the same shape `ospf.metric1` exposes — defensive, in
	// case a non-OSPF route somehow carries the attribute (the
	// OSPF route computation never attaches the tag to a
	// non-OSPF route, but a hand-crafted test route that
	// violates the invariant still reads as 0).
	bgp, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4 bgp: %v", err)
	}
	defer bgp.Free()
	if err := bgp.SetMetric(200); err != nil {
		t.Fatalf("SetMetric bgp: %v", err)
	}
	verdict, _, err = rejectHigh.Evaluate(bgp)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate non-OSPF (BGP): got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
}

func TestFilterDSLOspfTag(t *testing.T) {
	// `ospf.tag` reads the route's external route tag (RFC 2328
	// §A.4.5 bullet h / RFC 3101 §2.3 / RFC 5340 §A.4.7 T bit /
	// RFC 8362 §3.6 External-Prefix sub-TLV 3) the OSPF route
	// computation populates from the LSA's tag for external
	// routes. The binding exercises the FFI surface — Go → C ABI
	// → Rust filter eval → `lr-policy::ospf::tag` accessor — so
	// a regression in any layer surfaces here.
	//
	// Unlike `ospf.metric2` (whose `LrOspfMetric2` attribute has
	// no C ABI setter — the OSPF daemon is the only producer),
	// `ospf.tag` reads the existing `Route::tag` field, which
	// the C ABI exposes via `lr_route_set_tag`. The binding can
	// therefore exercise both the "absent" path (no tag set —
	// the default for an intra-area / inter-area OSPF route)
	// and the "present" path (a tag set via `SetTag`,
	// mirroring what `ospf_recompute` attaches for an external
	// route whose LSA carried a tag).
	rejectTagged, err := Compile("go-ospf-tag-tagged",
		"if defined(ospf.tag) && ospf.tag == 3735928559 then reject; accept;")
	if err != nil {
		t.Fatalf("Compile rejectTagged: %v", err)
	}
	defer rejectTagged.Free()
	readZero, err := Compile("go-ospf-tag-zero",
		"if ospf.tag == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile readZero: %v", err)
	}
	defer readZero.Free()

	// An OSPFv2 route without a tag — i.e. an intra-area /
	// inter-area route (the OSPF route computation leaves
	// `Route::tag = None` for those). `defined(ospf.tag)` is
	// false, so the `&&` short-circuits and the route is
	// accepted; `ospf.tag == 0` reads the unwrap_or(0) default
	// (mirrors BIRD's eattr default for an unattached
	// `ospf_tag` reference).
	ospf, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoOspf)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer ospf.Free()
	if err := ospf.SetMetric(200); err != nil {
		t.Fatalf("SetMetric: %v", err)
	}
	verdict, _, err := rejectTagged.Evaluate(ospf)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv2 rejectTagged: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	verdict, _, err = readZero.Evaluate(ospf)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv2 readZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	// An OSPFv2 route with a tag set via `SetTag` — mirrors
	// the shape `ospf_recompute` attaches for an external route
	// whose LSA carried a tag. `defined(ospf.tag)` is true; the
	// canonical idiom `if defined(ospf.tag) && ospf.tag ==
	// 3735928559 then accept;` matches.
	ospfTagged, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoOspf)
	if err != nil {
		t.Fatalf("NewRouteV4 ospfTagged: %v", err)
	}
	defer ospfTagged.Free()
	if err := ospfTagged.SetMetric(10); err != nil {
		t.Fatalf("SetMetric ospfTagged: %v", err)
	}
	if err := ospfTagged.SetTag(3735928559, true); err != nil {
		t.Fatalf("SetTag ospfTagged: %v", err)
	}
	acceptTagged, err := Compile("go-ospf-tag-accept-tagged",
		"if defined(ospf.tag) && ospf.tag == 3735928559 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile acceptTagged: %v", err)
	}
	defer acceptTagged.Free()
	verdict, _, err = acceptTagged.Evaluate(ospfTagged)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv2 acceptTagged: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	verdict, _, err = rejectTagged.Evaluate(ospfTagged)
	if err != nil || verdict != FilterReject {
		t.Fatalf("Evaluate OSPFv2 rejectTagged (tagged): got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterReject)
	}

	// A v2 external with the default zero tag is "present but
	// zero" — `defined(ospf.tag)` is true (the v2 LSA body
	// always carries a 4-byte tag, zero being well-formed per
	// RFC 2328 §A.4.5), and `ospf.tag == 0` reads 0.
	ospfZeroTag, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoOspf)
	if err != nil {
		t.Fatalf("NewRouteV4 ospfZeroTag: %v", err)
	}
	defer ospfZeroTag.Free()
	if err := ospfZeroTag.SetMetric(10); err != nil {
		t.Fatalf("SetMetric ospfZeroTag: %v", err)
	}
	if err := ospfZeroTag.SetTag(0, true); err != nil {
		t.Fatalf("SetTag ospfZeroTag: %v", err)
	}
	definedZero, err := Compile("go-ospf-tag-defined-zero",
		"if defined(ospf.tag) && ospf.tag == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile definedZero: %v", err)
	}
	defer definedZero.Free()
	verdict, _, err = definedZero.Evaluate(ospfZeroTag)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv2 zero-tag definedZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	// An OSPF route with no tag set: `defined(ospf.tag)` is
	// false, so the `&&` short-circuits and the route is
	// rejected by the definedZero filter (the canonical
	// v2-zero-tag idiom should not match a route with no tag).
	verdict, _, err = definedZero.Evaluate(ospf)
	if err != nil || verdict != FilterReject {
		t.Fatalf("Evaluate OSPFv2 no-tag definedZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterReject)
	}

	// OSPFv3 mirrors OSPFv2 (RFC 5340 §A.4.7 T bit mirrors
	// §A.4.5) — the v3 form surfaces `Some(t)` when the T bit
	// is set, so a `SetTag` call mirrors the T-bit-set case.
	ospf3Tagged, err := NewRouteV6([16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1}, 64, ProtoOspf3)
	if err != nil {
		t.Fatalf("NewRouteV6 ospf3Tagged: %v", err)
	}
	defer ospf3Tagged.Free()
	if err := ospf3Tagged.SetMetric(220); err != nil {
		t.Fatalf("SetMetric ospf3Tagged: %v", err)
	}
	if err := ospf3Tagged.SetTag(3405705229, true); err != nil {
		t.Fatalf("SetTag ospf3Tagged: %v", err)
	}
	v3Accept, err := Compile("go-ospf3-tag-accept",
		"if defined(ospf.tag) && ospf.tag == 3405705229 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile v3Accept: %v", err)
	}
	defer v3Accept.Free()
	verdict, _, err = v3Accept.Evaluate(ospf3Tagged)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv3 tagged v3Accept: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	// OSPFv3 with no tag set: `defined(ospf.tag)` is false (the
	// absence-handling default mirrors the v2 form's
	// intra-area / inter-area case).
	ospf3, err := NewRouteV6([16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1}, 64, ProtoOspf3)
	if err != nil {
		t.Fatalf("NewRouteV6 ospf3: %v", err)
	}
	defer ospf3.Free()
	if err := ospf3.SetMetric(220); err != nil {
		t.Fatalf("SetMetric ospf3: %v", err)
	}
	verdict, _, err = v3Accept.Evaluate(ospf3)
	if err != nil || verdict != FilterReject {
		t.Fatalf("Evaluate OSPFv3 no-tag v3Accept: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterReject)
	}

	// A non-OSPF (BGP) route: `defined(ospf.tag)` is false (the
	// protocol-kind fast path rejects non-OSPF routes,
	// mirroring BIRD's eattr absence on non-OSPF routes), so
	// the `&&` short-circuits and the route is accepted. The
	// `SetTag` call is the legitimate case where `Route::tag`
	// carries an operator-assigned tag for OSPF redistribution
	// — `ospf.tag` on the BGP route still reads as `0` /
	// not-defined because the protocol-kind fast path rejects
	// non-OSPF routes.
	bgp, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4 bgp: %v", err)
	}
	defer bgp.Free()
	if err := bgp.SetMetric(200); err != nil {
		t.Fatalf("SetMetric bgp: %v", err)
	}
	if err := bgp.SetTag(99, true); err != nil {
		t.Fatalf("SetTag bgp: %v", err)
	}
	verdict, _, err = rejectTagged.Evaluate(bgp)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate non-OSPF (BGP) rejectTagged: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	bgpReadZero, err := Compile("go-bgp-tag-zero",
		"if ospf.tag == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile bgpReadZero: %v", err)
	}
	defer bgpReadZero.Free()
	verdict, _, err = bgpReadZero.Evaluate(bgp)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate non-OSPF (BGP) bgpReadZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
}

func TestFilterDSLOspfRouterId(t *testing.T) {
	// `ospf.router_id` reads the private `LrOspfRouterId`
	// path-attribute tag (RFC 2328 §A.4 `Advertising Router`
	// field / RFC 5340 §A.4 the same field on every v3 LSA) the
	// OSPF route computation attaches to every OSPFv2 / OSPFv3
	// route with a known originating LSA. The binding exercises
	// the FFI surface — Go → C ABI → Rust filter eval →
	// `lr-policy::ospf::router_id` accessor — so a regression in
	// any layer surfaces here.
	//
	// The "present" path (a route carrying the `LrOspfRouterId`
	// attribute) is exercised by the `lr-policy::ospf::router_id_*`
	// unit tests (which synthesize the attribute directly via
	// `Attributes::insert`) and the
	// `lr-router::instance::tests::ospfv3_inter_area_and_external_routes_published`
	// integration test (which populates the attribute via the
	// OSPF route computation, the only producer). The binding
	// cannot reach that path because the C ABI does not expose
	// a setter for the `LrOspfRouterId` tag — embedders read the
	// field but never inject it; the OSPF daemon is the only
	// producer. The binding test pins the "absent" path (the
	// FFI surface, the parser, the protocol-kind fast path, and
	// the absence-handling default), which is the layer an
	// embedder's regression would surface through.
	rejectFromSpecific, err := Compile("go-ospf-rid-specific",
		// 192.0.2.1 = 0xc000_0201 = 3221225985
		"if defined(ospf.router_id) && ospf.router_id == 3221225985 then reject; accept;")
	if err != nil {
		t.Fatalf("Compile rejectFromSpecific: %v", err)
	}
	defer rejectFromSpecific.Free()
	readZero, err := Compile("go-ospf-rid-zero",
		"if ospf.router_id == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile readZero: %v", err)
	}
	defer readZero.Free()

	// An OSPFv2 route without the `LrOspfRouterId` attribute —
	// i.e. a synthetic test route (the OSPF route computation
	// would attach the attribute for every received OSPF route
	// per RFC 2328 §A.4). `defined(ospf.router_id)` is false, so
	// the `&&` short-circuits and the route is accepted;
	// `ospf.router_id == 0` reads the unwrap_or(0) default
	// (mirrors BIRD's eattr default for an unattached
	// `ospf_router_id` reference).
	ospf, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoOspf)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer ospf.Free()
	if err := ospf.SetMetric(200); err != nil {
		t.Fatalf("SetMetric: %v", err)
	}
	// `preference.metric` is 200 — `ospf.router_id` must NOT
	// read it (the attribute is absent). `defined()` short-circuits.
	verdict, _, err := rejectFromSpecific.Evaluate(ospf)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv2 rejectFromSpecific: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	verdict, _, err = readZero.Evaluate(ospf)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv2 readZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	// OSPFv3 mirrors OSPFv2 (RFC 5340 §A.4 mirrors §A.4) — same
	// absence-handling default.
	ospf3, err := NewRouteV6([16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1}, 64, ProtoOspf3)
	if err != nil {
		t.Fatalf("NewRouteV6: %v", err)
	}
	defer ospf3.Free()
	if err := ospf3.SetMetric(220); err != nil {
		t.Fatalf("SetMetric ospf3: %v", err)
	}
	verdict, _, err = rejectFromSpecific.Evaluate(ospf3)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv3 rejectFromSpecific: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	v3Zero, err := Compile("go-ospf3-rid-zero",
		"if ospf.router_id == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile v3Zero: %v", err)
	}
	defer v3Zero.Free()
	verdict, _, err = v3Zero.Evaluate(ospf3)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate OSPFv3 readZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	// A non-OSPF (BGP) route: `defined(ospf.router_id)` is false
	// (the protocol-kind fast path rejects non-OSPF routes
	// before the attribute lookup), so the `&&` short-circuits
	// and the route is accepted. The protocol-kind fast path is
	// the same shape `ospf.metric1` / `ospf.metric2` expose —
	// defensive, in case a non-OSPF route somehow carries the
	// attribute (the OSPF route computation never attaches the
	// tag to a non-OSPF route, but a hand-crafted test route
	// that violates the invariant still reads as 0).
	bgp, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4 bgp: %v", err)
	}
	defer bgp.Free()
	if err := bgp.SetMetric(200); err != nil {
		t.Fatalf("SetMetric bgp: %v", err)
	}
	verdict, _, err = rejectFromSpecific.Evaluate(bgp)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate non-OSPF (BGP): got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
}

func TestFilterDSLBabelMetric(t *testing.T) {
	// `babel.metric` reads route.Preference.Metric for Babel routes
	// and 0 for non-Babel routes (RFC 8966 §3.2 + §3.4.3 — the
	// value the Update TLV advertised, folded into
	// route.Preference.Metric by the Babel route computation
	// after applying the receiver-side link cost). The binding
	// exercises the full path — Go → C ABI → Rust filter eval →
	// `lr-policy::babel::metric` accessor — so a regression in
	// any layer surfaces here.
	rejectHigh, err := Compile("go-babel-high",
		"if defined(babel.metric) && babel.metric > 100 then reject; accept;")
	if err != nil {
		t.Fatalf("Compile rejectHigh: %v", err)
	}
	defer rejectHigh.Free()

	babel, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBabel)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer babel.Free()
	if err := babel.SetMetric(192); err != nil {
		t.Fatalf("SetMetric: %v", err)
	}
	verdict, _, err := rejectHigh.Evaluate(babel)
	if err != nil || verdict != FilterReject {
		t.Fatalf("Evaluate high-metric Babel: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterReject)
	}

	low, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBabel)
	if err != nil {
		t.Fatalf("NewRouteV4 low: %v", err)
	}
	defer low.Free()
	if err := low.SetMetric(50); err != nil {
		t.Fatalf("SetMetric low: %v", err)
	}
	verdict, _, err = rejectHigh.Evaluate(low)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate low-metric Babel: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	zero, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBabel)
	if err != nil {
		t.Fatalf("NewRouteV4 zero: %v", err)
	}
	defer zero.Free()
	if err := zero.SetMetric(0); err != nil {
		t.Fatalf("SetMetric zero: %v", err)
	}
	acceptZero, err := Compile("go-babel-zero",
		"if defined(babel.metric) && babel.metric == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile acceptZero: %v", err)
	}
	defer acceptZero.Free()
	verdict, _, err = acceptZero.Evaluate(zero)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate zero-metric Babel: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	bgp, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4 bgp: %v", err)
	}
	defer bgp.Free()
	if err := bgp.SetMetric(200); err != nil {
		t.Fatalf("SetMetric bgp: %v", err)
	}
	verdict, _, err = rejectHigh.Evaluate(bgp)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate non-Babel (BGP) rejectHigh: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	verdict, _, err = acceptZero.Evaluate(bgp)
	if err != nil || verdict != FilterReject {
		t.Fatalf("Evaluate non-Babel (BGP) acceptZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterReject)
	}
}

func TestFilterDSLBabelSeqno(t *testing.T) {
	// `babel.seqno` reads the private `LrBabelSeqno`
	// path-attribute tag (RFC 8966 §3.2 + §4.6.9 — the 16-bit
	// unsigned sequence number carried in every Update TLV)
	// the Babel route computation attaches to every Babel
	// route it publishes. The binding exercises the FFI
	// surface — Go → C ABI → Rust filter eval →
	// `lr-policy::babel::seqno` accessor — so a regression
	// in any layer surfaces here.
	//
	// The "present" path (a route carrying the `LrBabelSeqno`
	// attribute) is exercised by the
	// `lr-policy::babel::seqno_*` unit tests (which
	// synthesize the attribute directly via
	// `Attributes::insert`) and the
	// `lr-router::tests::babel_announcement::babel_announcement_attaches_seqno_and_router_id_attributes`
	// integration test (which populate the attribute via the Babel
	// route computation, the only producer). The binding
	// cannot reach that path because the C ABI does not
	// expose a setter for the `LrBabelSeqno` tag — embedders
	// read the field but never inject it; the Babel daemon
	// is the only producer. The binding test pins the
	// "absent" path (the FFI surface, the parser, the
	// protocol-kind fast path, and the absence-handling
	// default), which is the layer an embedder's regression
	// would surface through.
	rejectHigh, err := Compile("go-babel-seqno-high",
		"if defined(babel.seqno) && babel.seqno > 100 then reject; accept;")
	if err != nil {
		t.Fatalf("Compile rejectHigh: %v", err)
	}
	defer rejectHigh.Free()
	readZero, err := Compile("go-babel-seqno-zero",
		"if babel.seqno == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile readZero: %v", err)
	}
	defer readZero.Free()

	babel, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBabel)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer babel.Free()
	if err := babel.SetMetric(192); err != nil {
		t.Fatalf("SetMetric: %v", err)
	}
	verdict, _, err := rejectHigh.Evaluate(babel)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate Babel rejectHigh: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	verdict, _, err = readZero.Evaluate(babel)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate Babel readZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	bgp, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4 bgp: %v", err)
	}
	defer bgp.Free()
	if err := bgp.SetMetric(200); err != nil {
		t.Fatalf("SetMetric bgp: %v", err)
	}
	verdict, _, err = rejectHigh.Evaluate(bgp)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate non-Babel (BGP): got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
}

func TestFilterDSLBabelRouterId(t *testing.T) {
	// `babel.router_id` reads the private `LrBabelRouterId`
	// path-attribute tag (RFC 8966 §3.2 + §4.6.8 — the
	// 64-bit EUI-64-style Router-ID carried in every
	// Update TLV's Router-Id TLV) the Babel route
	// computation attaches to every Babel route it
	// publishes. The binding exercises the FFI surface —
	// Go → C ABI → Rust filter eval →
	// `lr-policy::babel::router_id` accessor — so a
	// regression in any layer surfaces here.
	//
	// The "present" path (a route carrying the
	// `LrBabelRouterId` attribute) is exercised by the
	// `lr-policy::babel::router_id_*` unit tests (which
	// synthesize the attribute directly via
	// `Attributes::insert`) and the
	// `lr-router::tests::babel_announcement::babel_announcement_attaches_seqno_and_router_id_attributes`
	// integration test (which populate the attribute via the Babel
	// route computation, the only producer). The binding
	// cannot reach that path because the C ABI does not
	// expose a setter for the `LrBabelRouterId` tag —
	// embedders read the field but never inject it; the
	// Babel daemon is the only producer. The binding test
	// pins the "absent" path (the FFI surface, the parser,
	// the protocol-kind fast path, and the
	// absence-handling default), which is the layer an
	// embedder's regression would surface through.
	rejectKnown, err := Compile("go-babel-rid-known",
		// 0x0102030405060708 = 72623859790382856
		"if defined(babel.router_id) && babel.router_id == 72623859790382856 then reject; accept;")
	if err != nil {
		t.Fatalf("Compile rejectKnown: %v", err)
	}
	defer rejectKnown.Free()
	readZero, err := Compile("go-babel-rid-zero",
		"if babel.router_id == 0 then accept; reject;")
	if err != nil {
		t.Fatalf("Compile readZero: %v", err)
	}
	defer readZero.Free()

	babel, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBabel)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	defer babel.Free()
	if err := babel.SetMetric(192); err != nil {
		t.Fatalf("SetMetric: %v", err)
	}
	verdict, _, err := rejectKnown.Evaluate(babel)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate Babel rejectKnown: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
	verdict, _, err = readZero.Evaluate(babel)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate Babel readZero: got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}

	bgp, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV4 bgp: %v", err)
	}
	defer bgp.Free()
	if err := bgp.SetMetric(200); err != nil {
		t.Fatalf("SetMetric bgp: %v", err)
	}
	verdict, _, err = rejectKnown.Evaluate(bgp)
	if err != nil || verdict != FilterAccept {
		t.Fatalf("Evaluate non-Babel (BGP): got (%d, _, %v), want (%d, _, nil)",
			verdict, err, FilterAccept)
	}
}

func TestBgpMessageDecodeOpenRoundTrip(t *testing.T) {
	// OPEN with 4-byte AS: BgpMessage.OpenMyAs unwraps AS_TRANS (23456)
	// and surfaces the real 32-bit AS from the RFC 6793 capability.
	wire, err := EncodeOpen(4_200_000_000, 180, [4]byte{10, 0, 0, 1}, true)
	if err != nil {
		t.Fatalf("EncodeOpen: %v", err)
	}
	m, err := DecodeBgpMessage(wire)
	if err != nil {
		t.Fatalf("DecodeBgpMessage: %v", err)
	}
	defer m.Close()

	if k, _ := m.Kind(); k != BGPMsgOpen {
		t.Fatalf("Kind: got %d, want %d (OPEN)", k, BGPMsgOpen)
	}
	if v, _ := m.OpenVersion(); v != 4 {
		t.Fatalf("OpenVersion: got %d, want 4", v)
	}
	if asn, _ := m.OpenMyAs(); asn != 4_200_000_000 {
		t.Fatalf("OpenMyAs: got %d, want 4_200_000_000 (unwrapped AS_TRANS)", asn)
	}
	if h, _ := m.OpenHoldTime(); h != 180 {
		t.Fatalf("OpenHoldTime: got %d, want 180", h)
	}
	id, _ := m.OpenBgpID()
	if id != [4]byte{10, 0, 0, 1} {
		t.Fatalf("OpenBgpID: got %v, want [10 0 0 1]", id)
	}

	// Exactly one optional parameter: the capabilities TLV carrying
	// the Four-Octet-AS capability (code 65, length 4).
	n, _ := m.OpenParamCount()
	if n != 1 {
		t.Fatalf("OpenParamCount: got %d, want 1", n)
	}
	p, err := m.OpenParamAt(0)
	if err != nil {
		t.Fatalf("OpenParamAt(0): %v", err)
	}
	if p.ParamType != 2 {
		t.Fatalf("ParamType: got %d, want 2 (capabilities, RFC 5492)", p.ParamType)
	}
	if len(p.Value) < 6 {
		t.Fatalf("Value: too short (%d bytes), want >= 6", len(p.Value))
	}
	if p.Value[0] != 65 {
		t.Fatalf("Value[0]: got %d, want 65 (Four-Octet-AS capability)", p.Value[0])
	}
	if p.Value[1] != 4 {
		t.Fatalf("Value[1]: got %d, want 4 (capability length)", p.Value[1])
	}
	capAs := uint32(p.Value[2])<<24 | uint32(p.Value[3])<<16 | uint32(p.Value[4])<<8 | uint32(p.Value[5])
	if capAs != 4_200_000_000 {
		t.Fatalf("Value[2:6]: got %d, want 4_200_000_000", capAs)
	}

	// Out-of-range returns an error (LR_ERR_OTHER).
	if _, err := m.OpenParamAt(99); err == nil {
		t.Fatalf("OpenParamAt(99): expected error, got nil")
	}

	// Variant-mismatch reader returns an error (LR_ERR_INVALID_HANDLE).
	if _, err := m.NotificationCode(); err == nil {
		t.Fatalf("NotificationCode on OPEN: expected error, got nil")
	}
}

func TestBgpMessageDecodeOpen16bitNoCapability(t *testing.T) {
	// OPEN with 16-bit AS and no Four-Octet-AS capability: OpenMyAs
	// returns the raw 16-bit field (no AS_TRANS unwrap).
	wire, err := EncodeOpen(64512, 90, [4]byte{10, 0, 0, 1}, false)
	if err != nil {
		t.Fatalf("EncodeOpen: %v", err)
	}
	m, err := DecodeBgpMessage(wire)
	if err != nil {
		t.Fatalf("DecodeBgpMessage: %v", err)
	}
	defer m.Close()
	if asn, _ := m.OpenMyAs(); asn != 64512 {
		t.Fatalf("OpenMyAs: got %d, want 64512 (no capability, raw 16-bit field)", asn)
	}
	if n, _ := m.OpenParamCount(); n != 0 {
		t.Fatalf("OpenParamCount: got %d, want 0", n)
	}
}

func TestBgpMessageDecodeNotificationRoundTrip(t *testing.T) {
	wire, err := EncodeNotification(1, 2, []byte{0xde, 0xad, 0xbe, 0xef})
	if err != nil {
		t.Fatalf("EncodeNotification: %v", err)
	}
	m, err := DecodeBgpMessage(wire)
	if err != nil {
		t.Fatalf("DecodeBgpMessage: %v", err)
	}
	defer m.Close()
	if k, _ := m.Kind(); k != BGPMsgNotification {
		t.Fatalf("Kind: got %d, want %d (NOTIFICATION)", k, BGPMsgNotification)
	}
	if c, _ := m.NotificationCode(); c != 1 {
		t.Fatalf("NotificationCode: got %d, want 1 (Header)", c)
	}
	if s, _ := m.NotificationSubcode(); s != 2 {
		t.Fatalf("NotificationSubcode: got %d, want 2 (Conn-Not-Sync)", s)
	}
	d, _ := m.NotificationData()
	if !bytesEqual(d, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("NotificationData: got %v, want [de ad be ef]", d)
	}
}

func TestBgpMessageDecodeNotificationCompact(t *testing.T) {
	wire, err := EncodeNotification(6, 4, nil)
	if err != nil {
		t.Fatalf("EncodeNotification: %v", err)
	}
	m, err := DecodeBgpMessage(wire)
	if err != nil {
		t.Fatalf("DecodeBgpMessage: %v", err)
	}
	defer m.Close()
	if k, _ := m.Kind(); k != BGPMsgNotification {
		t.Fatalf("Kind: got %d, want %d (NOTIFICATION)", k, BGPMsgNotification)
	}
	d, _ := m.NotificationData()
	if len(d) != 0 {
		t.Fatalf("NotificationData: got %d bytes, want 0", len(d))
	}
}

func TestBgpMessageDecodeUpdateWithdrawOnly(t *testing.T) {
	wire, err := EncodeUpdateWithdrawV4([]PrefixSpec{
		{Addr: []byte{203, 0, 113, 0}, PrefixLen: 24},
		{Addr: []byte{198, 51, 100, 0}, PrefixLen: 25},
	})
	if err != nil {
		t.Fatalf("EncodeUpdateWithdrawV4: %v", err)
	}
	m, err := DecodeBgpMessage(wire)
	if err != nil {
		t.Fatalf("DecodeBgpMessage: %v", err)
	}
	defer m.Close()
	if k, _ := m.Kind(); k != BGPMsgUpdate {
		t.Fatalf("Kind: got %d, want %d (UPDATE)", k, BGPMsgUpdate)
	}
	if n, _ := m.UpdateWithdrawnCount(); n != 2 {
		t.Fatalf("UpdateWithdrawnCount: got %d, want 2", n)
	}
	if n, _ := m.UpdateNlriCount(); n != 0 {
		t.Fatalf("UpdateNlriCount: got %d, want 0", n)
	}
	if n, _ := m.UpdateAttrCount(); n != 0 {
		t.Fatalf("UpdateAttrCount: got %d, want 0", n)
	}
	p0, _ := m.UpdateWithdrawnAt(0)
	if !bytesEqual(p0.Addr, []byte{203, 0, 113, 0}) || p0.PrefixLen != 24 {
		t.Fatalf("UpdateWithdrawnAt(0): got %+v, want 203.0.113.0/24", p0)
	}
	p1, _ := m.UpdateWithdrawnAt(1)
	if !bytesEqual(p1.Addr, []byte{198, 51, 100, 0}) || p1.PrefixLen != 25 {
		t.Fatalf("UpdateWithdrawnAt(1): got %+v, want 198.51.100.0/25", p1)
	}
	if _, err := m.UpdateWithdrawnAt(99); err == nil {
		t.Fatalf("UpdateWithdrawnAt(99): expected error, got nil")
	}
}

func TestBgpMessageDecodeUpdateAnnounce(t *testing.T) {
	wire, err := EncodeUpdateAnnounceV4(
		[]PrefixSpec{{Addr: []byte{203, 0, 113, 0}, PrefixLen: 24}},
		[4]byte{192, 0, 2, 1},
		[]uint32{64512, 64513, 64514},
		0, false,
	)
	if err != nil {
		t.Fatalf("EncodeUpdateAnnounceV4: %v", err)
	}
	m, err := DecodeBgpMessage(wire)
	if err != nil {
		t.Fatalf("DecodeBgpMessage: %v", err)
	}
	defer m.Close()
	if k, _ := m.Kind(); k != BGPMsgUpdate {
		t.Fatalf("Kind: got %d, want %d (UPDATE)", k, BGPMsgUpdate)
	}
	if n, _ := m.UpdateNlriCount(); n != 1 {
		t.Fatalf("UpdateNlriCount: got %d, want 1", n)
	}
	p, _ := m.UpdateNlriAt(0)
	if !bytesEqual(p.Addr, []byte{203, 0, 113, 0}) || p.PrefixLen != 24 {
		t.Fatalf("UpdateNlriAt(0): got %+v, want 203.0.113.0/24", p)
	}
	attrs, _ := m.UpdateAttrs()
	if len(attrs) < 3 {
		t.Fatalf("UpdateAttrs: got %d, want >= 3", len(attrs))
	}
	byType := map[uint8]PathAttr{}
	for _, a := range attrs {
		byType[a.AttrType] = a
	}
	if _, ok := byType[1]; !ok {
		t.Fatalf("UpdateAttrs: missing ORIGIN (type 1)")
	}
	if _, ok := byType[3]; !ok {
		t.Fatalf("UpdateAttrs: missing NEXT_HOP (type 3)")
	}
	if !bytesEqual(byType[1].Value, []byte{0}) {
		t.Fatalf("ORIGIN value: got %v, want [0] (IGP)", byType[1].Value)
	}
	if !bytesEqual(byType[3].Value, []byte{192, 0, 2, 1}) {
		t.Fatalf("NEXT_HOP value: got %v, want [192 0 2 1]", byType[3].Value)
	}
}

func TestBgpMessageDecodeKeepalive(t *testing.T) {
	wire, err := EncodeKeepalive()
	if err != nil {
		t.Fatalf("EncodeKeepalive: %v", err)
	}
	m, err := DecodeBgpMessage(wire)
	if err != nil {
		t.Fatalf("DecodeBgpMessage: %v", err)
	}
	defer m.Close()
	if k, _ := m.Kind(); k != BGPMsgKeepalive {
		t.Fatalf("Kind: got %d, want %d (KEEPALIVE)", k, BGPMsgKeepalive)
	}
}

func TestBgpMessageDecodeRejectsTruncated(t *testing.T) {
	if _, err := DecodeBgpMessage([]byte{0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatalf("DecodeBgpMessage: expected error on truncated input, got nil")
	}
}

func TestBgpMessageCloseIsIdempotent(t *testing.T) {
	wire, err := EncodeKeepalive()
	if err != nil {
		t.Fatalf("EncodeKeepalive: %v", err)
	}
	m, err := DecodeBgpMessage(wire)
	if err != nil {
		t.Fatalf("DecodeBgpMessage: %v", err)
	}
	m.Close()
	m.Close() // second close is a no-op
	if _, err := m.Kind(); err == nil {
		t.Fatalf("Kind after Close: expected error, got nil")
	}
}

func TestBgpMessageWalkAllVariantsViaKind(t *testing.T) {
	cases := []struct {
		wire []byte
		want uint8
	}{
		{mustEncodeOpen(t, 64512, 90, [4]byte{10, 0, 0, 1}, false), BGPMsgOpen},
		{mustEncode(t, EncodeKeepalive), BGPMsgKeepalive},
		{mustEncode(t, func() ([]byte, error) { return EncodeNotification(6, 4, nil) }), BGPMsgNotification},
		{mustEncode(t, func() ([]byte, error) {
			return EncodeUpdateWithdrawV4([]PrefixSpec{{Addr: []byte{203, 0, 113, 0}, PrefixLen: 24}})
		}), BGPMsgUpdate},
	}
	for _, c := range cases {
		m, err := DecodeBgpMessage(c.wire)
		if err != nil {
			t.Fatalf("DecodeBgpMessage: %v", err)
		}
		k, _ := m.Kind()
		if k != c.want {
			t.Fatalf("Kind: got %d, want %d", k, c.want)
		}
		m.Close()
	}
}

func mustEncode(t *testing.T, f func() ([]byte, error)) []byte {
	t.Helper()
	b, err := f()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func mustEncodeOpen(t *testing.T, myAs uint32, holdTime uint16, bgpId [4]byte, as4 bool) []byte {
	t.Helper()
	b, err := EncodeOpen(myAs, holdTime, bgpId, as4)
	if err != nil {
		t.Fatalf("EncodeOpen: %v", err)
	}
	return b
}
