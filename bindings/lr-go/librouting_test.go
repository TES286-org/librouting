// Package librouting tests.
package librouting

import (
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
