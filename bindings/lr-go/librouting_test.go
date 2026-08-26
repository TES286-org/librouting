// Package librouting tests.
package librouting

import (
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
