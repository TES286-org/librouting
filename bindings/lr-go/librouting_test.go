// Package librouting tests.
package librouting

import (
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
	// Routing Type at offset 2 = 43 (RFC 8754 §2).
	if srh[2] != 43 {
		t.Fatalf("expected Routing Type 43, got %d", srh[2])
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
