// Package librouting tests for the auto-generated wrappers in generated.go.
//
// The previous round of the FFI bindings parity work (issue #92) added a
// mechanical auto-gen layer covering every `lr_*` C ABI entry point that
// did not already have a hand-written Go wrapper. The auto-gen layer had
// no test coverage of its own — this file closes that gap.
//
// Each test exercises a representative generated constructor + the
// `Free()` RAII lifecycle + a generated method that wraps a handle-attached
// reader. The test confirms:
//   - the generated factory returns a non-nil pointer;
//   - `Free()` clears the pointer (idempotent — safe to call twice);
//   - the generated readers round-trip the values set by the factory;
//
// The cases below use symbols that the Go generator actually emitted.
// Symbols whose hand-written counterparts (e.g. `MPLSLabelStack`,
// `MacKey`, `SRv6Sid`) already invoke the C ABI directly are NOT
// re-emitted by the generator (existing_go_symbols() detects the call
// and skips it), so those constructors live only in the hand-written
// files and are covered by the existing tests there.
package librouting

import (
	"testing"
)

func TestGeneratedBgpCommunityRoundTrip(t *testing.T) {
	c, err := NewBgpCommunity(64512, 100)
	if err != nil {
		t.Fatalf("NewBgpCommunity: %v", err)
	}
	if c == nil {
		t.Fatal("NewBgpCommunity returned nil")
	}
	defer c.Free()

	asn, err := c.Asn()
	if err != nil {
		t.Fatalf("BgpCommunity.Asn: %v", err)
	}
	if asn != 64512 {
		t.Errorf("BgpCommunity.Asn = %d, want 64512", asn)
	}

	val, err := c.Value()
	if err != nil {
		t.Fatalf("BgpCommunity.Value: %v", err)
	}
	if val != 100 {
		t.Errorf("BgpCommunity.Value = %d, want 100", val)
	}

	// Free should be idempotent.
	c.Free()
}

func TestGeneratedBgpCodecLifecycle(t *testing.T) {
	codec, err := NewBgpCodec()
	if err != nil {
		t.Fatalf("NewBgpCodec: %v", err)
	}
	if codec == nil {
		t.Fatal("NewBgpCodec returned nil")
	}
	if codec.Closed() {
		t.Fatal("BgpCodec closed before Free()")
	}
	codec.Free()
	if !codec.Closed() {
		t.Fatal("BgpCodec not closed after Free()")
	}
	// Free is idempotent.
	codec.Free()
}

func TestGeneratedLdpLabelRoundTrip(t *testing.T) {
	lbl, err := NewLdpLabel(100)
	if err != nil {
		t.Fatalf("NewLdpLabel: %v", err)
	}
	if lbl == nil {
		t.Fatal("NewLdpLabel returned nil")
	}
	defer lbl.Free()

	v, err := lbl.Value()
	if err != nil {
		t.Fatalf("LdpLabel.Value: %v", err)
	}
	if v != 100 {
		t.Errorf("LdpLabel.Value = %d, want 100", v)
	}
}

func TestGeneratedBgpCommunityAsU32(t *testing.T) {
	// ASN 64512 (0xFC00), value 100 (0x0064) -> 0xFC000064 = 4227859556
	c, err := NewBgpCommunity(64512, 100)
	if err != nil {
		t.Fatalf("NewBgpCommunity: %v", err)
	}
	defer c.Free()
	v, err := c.AsU32()
	if err != nil {
		t.Fatalf("BgpCommunity.AsU32: %v", err)
	}
	if v != 0xFC000064 {
		t.Errorf("BgpCommunity.AsU32 = 0x%X, want 0xFC000064", v)
	}
}

// TestGeneratedPolicyChainLifecycle covers a no-arg generated
// constructor + Free lifecycle on a non-protocol-specific type.
func TestGeneratedPolicyChainLifecycle(t *testing.T) {
	pc, err := NewPolicyChain()
	if err != nil {
		t.Fatalf("NewPolicyChain: %v", err)
	}
	if pc == nil {
		t.Fatal("NewPolicyChain returned nil")
	}
	if pc.Closed() {
		t.Fatal("PolicyChain closed before Free()")
	}
	pc.Free()
	if !pc.Closed() {
		t.Fatal("PolicyChain not closed after Free()")
	}
	pc.Free() // idempotent
}

// TestGeneratedRoaTableLifecycle covers the RoaTable no-arg
// constructor; RoaTable is exercised by the hand-written test suite
// for the actual RPKI validation surface, but the generated lifecycle
// (Free idempotency + Closed predicate) was not previously covered.
func TestGeneratedRoaTableLifecycle(t *testing.T) {
	rt, err := NewRoaTable()
	if err != nil {
		t.Fatalf("NewRoaTable: %v", err)
	}
	if rt == nil {
		t.Fatal("NewRoaTable returned nil")
	}
	if rt.Closed() {
		t.Fatal("RoaTable closed before Free()")
	}
	rt.Free()
	if !rt.Closed() {
		t.Fatal("RoaTable not closed after Free()")
	}
	rt.Free() // idempotent
}

// TestGeneratedRoaTableBuilderLifecycle covers the RoaTableBuilder
// no-arg constructor.
func TestGeneratedRoaTableBuilderLifecycle(t *testing.T) {
	b, err := NewRoaTableBuilder()
	if err != nil {
		t.Fatalf("NewRoaTableBuilder: %v", err)
	}
	if b == nil {
		t.Fatal("NewRoaTableBuilder returned nil")
	}
	b.Free()
	b.Free() // idempotent
}

// TestGeneratedBgpLsAttrLifecycle covers the BgpLsAttr no-arg
// constructor.
func TestGeneratedBgpLsAttrLifecycle(t *testing.T) {
	a, err := NewBgpLsAttr()
	if err != nil {
		t.Fatalf("NewBgpLsAttr: %v", err)
	}
	if a == nil {
		t.Fatal("NewBgpLsAttr returned nil")
	}
	a.Free()
	a.Free() // idempotent
}

// TestGeneratedSafetyNetLifecycle covers a constructor with a single
// scalar argument (uint32 local_as). The SafetyNet is the BGP safety
// net (RFC 9655 OTC) helper.
func TestGeneratedSafetyNetLifecycle(t *testing.T) {
	sn, err := NewSafetyNet(64512)
	if err != nil {
		t.Fatalf("NewSafetyNet: %v", err)
	}
	if sn == nil {
		t.Fatal("NewSafetyNet returned nil")
	}
	if sn.Closed() {
		t.Fatal("SafetyNet closed before Free()")
	}
	sn.Free()
	if !sn.Closed() {
		t.Fatal("SafetyNet not closed after Free()")
	}
	sn.Free() // idempotent
}

// TestGeneratedOspfNssaDefaultLifecycle covers a constructor with a
// single uint32 metric argument.
func TestGeneratedOspfNssaDefaultLifecycle(t *testing.T) {
	d, err := NewOspfNssaDefault(100)
	if err != nil {
		t.Fatalf("NewOspfNssaDefault: %v", err)
	}
	if d == nil {
		t.Fatal("NewOspfNssaDefault returned nil")
	}
	if d.Closed() {
		t.Fatal("OspfNssaDefault closed before Free()")
	}
	d.Free()
	if !d.Closed() {
		t.Fatal("OspfNssaDefault not closed after Free()")
	}
	d.Free() // idempotent
}

// TestGeneratedBgpOtcLifecycle covers the BgpOtc (RFC 9655 OTC)
// wrapper. The handle-attached readers (OnReceive, CanAdvertise) need
// a route context and are exercised by the hand-written tests; the
// generated lifecycle (Free idempotency + Closed predicate) is what
// this test covers.
func TestGeneratedBgpOtcLifecycle(t *testing.T) {
	o, err := NewBgpOtc(64512)
	if err != nil {
		t.Fatalf("NewBgpOtc: %v", err)
	}
	if o == nil {
		t.Fatal("NewBgpOtc returned nil")
	}
	if o.Closed() {
		t.Fatal("BgpOtc closed before Free()")
	}
	o.Free()
	if !o.Closed() {
		t.Fatal("BgpOtc not closed after Free()")
	}
	o.Free() // idempotent
}
