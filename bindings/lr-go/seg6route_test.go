package librouting

import (
	"errors"
	"testing"
)

// v6PrefixSpec builds a PrefixSpec for 2001:db8::/64.
func v6PrefixSpec() PrefixSpec {
	return PrefixSpec{
		Addr: []byte{
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
		},
		IsIPv6:    true,
		PrefixLen: 64,
	}
}

// v4PrefixSpec builds a PrefixSpec for 203.0.113.0/24 (used to test
// IPv4 rejection).
func v4PrefixSpec() PrefixSpec {
	return PrefixSpec{
		Addr:      []byte{203, 0, 113, 0},
		IsIPv6:    false,
		PrefixLen: 24,
	}
}

// v6SIDOctets returns the 16-byte representation of 2001:db8::1.
func v6SIDOctets() []byte {
	return []byte{
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1,
	}
}

// newSeg6Srh builds a 1-segment SRH handle for the test seg6_route
// surface. Returns the SRH handle and a tear-down function the
// caller must defer.
func newSeg6Srh(t *testing.T) (*SRv6Srh, func()) {
	sid, err := NewSRv6Sid(v6SIDOctets())
	if err != nil {
		t.Fatalf("NewSRv6Sid: %v", err)
	}
	srh, err := NewSRv6Srh([]any{sid})
	if err != nil {
		sid.Free()
		t.Fatalf("NewSRv6Srh: %v", err)
	}
	return srh, func() {
		srh.Free()
		sid.Free()
	}
}

func TestSeg6RouteNewReturnsHandle(t *testing.T) {
	srh, cleanup := newSeg6Srh(t)
	defer cleanup()
	r, err := NewSeg6Route(v6PrefixSpec(), srh)
	if err != nil {
		t.Fatalf("NewSeg6Route: %v", err)
	}
	defer r.Free()
}

func TestSeg6RouteNewRejectsIPv4Prefix(t *testing.T) {
	srh, cleanup := newSeg6Srh(t)
	defer cleanup()
	if _, err := NewSeg6Route(v4PrefixSpec(), srh); err == nil {
		t.Error("NewSeg6Route accepted an IPv4 prefix")
	}
}

func TestSeg6RouteNewRejectsNilSrh(t *testing.T) {
	if _, err := NewSeg6Route(v6PrefixSpec(), nil); err == nil {
		t.Error("NewSeg6Route accepted a nil SRH")
	}
}

func TestSeg6RouteSetModeRoundTrip(t *testing.T) {
	srh, cleanup := newSeg6Srh(t)
	defer cleanup()
	r, err := NewSeg6Route(v6PrefixSpec(), srh)
	if err != nil {
		t.Fatalf("NewSeg6Route: %v", err)
	}
	defer r.Free()
	if _, err := r.WithMode(Seg6EncapInline); err != nil {
		t.Errorf("WithMode(Inline): %v", err)
	}
	if _, err := r.WithMode(Seg6EncapEncap); err != nil {
		t.Errorf("WithMode(Encap): %v", err)
	}
	if _, err := r.WithMode(0xFFFFFFFF); err == nil {
		t.Error("WithMode(unknown) should have failed")
	}
}

func TestSeg6RouteSetIfIndexRoundTrip(t *testing.T) {
	srh, cleanup := newSeg6Srh(t)
	defer cleanup()
	r, err := NewSeg6Route(v6PrefixSpec(), srh)
	if err != nil {
		t.Fatalf("NewSeg6Route: %v", err)
	}
	defer r.Free()
	if _, err := r.WithIfIndex(7); err != nil {
		t.Errorf("WithIfIndex(7): %v", err)
	}
}

func TestSeg6LocalRouteNewReturnsHandle(t *testing.T) {
	sid, err := NewSRv6Sid(v6SIDOctets())
	if err != nil {
		t.Fatalf("NewSRv6Sid: %v", err)
	}
	defer sid.Free()
	// End behavior (RFC 8986 §4.1) — IANA wire value 1.
	r, err := NewSeg6LocalRoute(sid, 1)
	if err != nil {
		t.Fatalf("NewSeg6LocalRoute: %v", err)
	}
	defer r.Free()
}

func TestSeg6LocalRouteNewRejectsNilSid(t *testing.T) {
	if _, err := NewSeg6LocalRoute(nil, 1); err == nil {
		t.Error("NewSeg6LocalRoute accepted a nil SID")
	}
}

func TestSeg6LocalRouteNewRejectsUnknownBehavior(t *testing.T) {
	sid, err := NewSRv6Sid(v6SIDOctets())
	if err != nil {
		t.Fatalf("NewSRv6Sid: %v", err)
	}
	defer sid.Free()
	// 0xFFFF is not in the IANA registry.
	if _, err := NewSeg6LocalRoute(sid, 0xFFFF); err == nil {
		t.Error("NewSeg6LocalRoute accepted an unknown behavior")
	}
}

func TestSeg6LocalRouteSettersRoundTrip(t *testing.T) {
	sid, err := NewSRv6Sid(v6SIDOctets())
	if err != nil {
		t.Fatalf("NewSRv6Sid: %v", err)
	}
	defer sid.Free()
	r, err := NewSeg6LocalRoute(sid, 1)
	if err != nil {
		t.Fatalf("NewSeg6LocalRoute: %v", err)
	}
	defer r.Free()

	if _, err := r.WithIfIndex(1); err != nil {
		t.Errorf("WithIfIndex: %v", err)
	}
	if _, err := r.WithNh4([4]byte{203, 0, 113, 1}); err != nil {
		t.Errorf("WithNh4: %v", err)
	}
	// WithNh6 — see TestSeg6LocalRouteWithNh6 for the dedicated test.
	if _, err := r.WithIif(2); err != nil {
		t.Errorf("WithIif: %v", err)
	}
	if _, err := r.WithOif(3); err != nil {
		t.Errorf("WithOif: %v", err)
	}
	if _, err := r.WithTable(254); err != nil {
		t.Errorf("WithTable: %v", err)
	}
	if _, err := r.WithVrfTable(100); err != nil {
		t.Errorf("WithVrfTable: %v", err)
	}

	srh, cleanup := newSeg6Srh(t)
	defer cleanup()
	if _, err := r.WithSrh(srh); err != nil {
		t.Errorf("WithSrh: %v", err)
	}
}

func TestSeg6LocalRouteWithNh6(t *testing.T) {
	sid, err := NewSRv6Sid(v6SIDOctets())
	if err != nil {
		t.Fatalf("NewSRv6Sid: %v", err)
	}
	defer sid.Free()
	r, err := NewSeg6LocalRoute(sid, 1)
	if err != nil {
		t.Fatalf("NewSeg6LocalRoute: %v", err)
	}
	defer r.Free()
	var nh6 [16]byte
	for i := range nh6 {
		nh6[i] = 0xfe
	}
	if _, err := r.WithNh6(nh6); err != nil {
		t.Errorf("WithNh6: %v", err)
	}
}

func TestSeg6LocalRouteWithSrhRejectsNil(t *testing.T) {
	sid, err := NewSRv6Sid(v6SIDOctets())
	if err != nil {
		t.Fatalf("NewSRv6Sid: %v", err)
	}
	defer sid.Free()
	r, err := NewSeg6LocalRoute(sid, 1)
	if err != nil {
		t.Fatalf("NewSeg6LocalRoute: %v", err)
	}
	defer r.Free()
	if _, err := r.WithSrh(nil); err == nil {
		t.Error("WithSrh accepted a nil SRH")
	}
}

func TestSeg6NetlinkConnectReturnsNullOrHandle(t *testing.T) {
	n, err := NewSeg6Netlink()
	if err != nil {
		// On a CI runner without SRv6 enabled the connect call fails
		// with a Seg6RouteErr (Code = Seg6ErrNotEnabled or
		// Seg6ErrUnsupported). The failure must NOT be a generic
		// error.
		var sErr *Seg6RouteErr
		if !errors.As(err, &sErr) {
			t.Fatalf("expected *Seg6RouteErr, got %T: %v", err, err)
		}
		if sErr.Code != Seg6ErrNotEnabled && sErr.Code != Seg6ErrUnsupported {
			t.Errorf("expected NotEnabled or Unsupported, got code=%d", sErr.Code)
		}
		// The name lookup must return the documented name.
		name := Seg6RouteErrName(sErr.Code)
		if name != "not-enabled" && name != "unsupported" {
			t.Errorf("Seg6RouteErrName(%d) = %q, want not-enabled or unsupported", sErr.Code, name)
		}
		return
	}
	defer n.Free()
}

func TestSeg6NetlinkAddSeg6RouteRejectsNil(t *testing.T) {
	n, err := NewSeg6Netlink()
	if err != nil {
		t.Skipf("NewSeg6Netlink: %v (kernel without SRv6)", err)
	}
	defer n.Free()
	if err := n.AddSeg6Route(nil); err == nil {
		t.Error("AddSeg6Route(nil) should have failed")
	}
}

func TestSeg6NetlinkDeleteSeg6RouteRejectsIPv4(t *testing.T) {
	n, err := NewSeg6Netlink()
	if err != nil {
		t.Skipf("NewSeg6Netlink: %v", err)
	}
	defer n.Free()
	if err := n.DeleteSeg6Route(v4PrefixSpec()); err == nil {
		t.Error("DeleteSeg6Route(IPv4) should have failed")
	}
}

func TestSeg6NetlinkLastRequestBytesNilHandle(t *testing.T) {
	// LastRequestBytes returns nil (no error) when no request has
	// been sent yet — the C ABI writes an empty lr_bytes_t.
	n, err := NewSeg6Netlink()
	if err != nil {
		t.Skipf("NewSeg6Netlink: %v", err)
	}
	defer n.Free()
	b, err := n.LastRequestBytes()
	if err != nil {
		t.Fatalf("LastRequestBytes: %v", err)
	}
	if b != nil {
		t.Errorf("LastRequestBytes before any request: %v, want nil", b)
	}
}

func TestSeg6RouteErrNameReturnsKnownNames(t *testing.T) {
	cases := []struct {
		code int32
		name string
	}{
		{Seg6ErrUnsupported, "unsupported"},
		{Seg6ErrNotEnabled, "not-enabled"},
		{Seg6ErrSyscall, "syscall"},
		{Seg6ErrKernel, "kernel"},
		{Seg6ErrBadSrh, "bad-srh"},
		{Seg6ErrUnsupportedAction, "unsupported-action"},
		{999, "unknown"},
	}
	for _, c := range cases {
		if got := Seg6RouteErrName(c.code); got != c.name {
			t.Errorf("Seg6RouteErrName(%d) = %q, want %q", c.code, got, c.name)
		}
	}
}
