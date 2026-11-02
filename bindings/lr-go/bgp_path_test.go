// Tests for the BGP Path Attributes binding.
//
// Mirrors the FFI tests in crates/lr-ffi/src/bgp_path.rs and the
// lr_bgp::path::PathAttributes Rust crate's pub API one-to-one: every
// typed reader / setter / generic-attr entry point has at least one
// round-trip assertion, every nil path on a fresh attrs set has an
// explicit assertion, and every Insert* returns an error on FFI
// errors.
//
// The tests do NOT spin up a BGP peer — they exercise the attribute
// container directly via the C ABI, mirroring the Rust crate's own
// unit tests. The C ABI surface lives in crates/lr-ffi/src/bgp_path.rs;
// this file is the Go-side mirror.

package librouting

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// Lifecycle / generic-attr surface.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_FreshIsEmpty(t *testing.T) {
	a, err := NewBgpPathAttrs()
	if err != nil {
		t.Fatalf("NewBgpPathAttrs: %v", err)
	}
	defer a.Free()
	if a.Len() != 0 {
		t.Errorf("Len = %d, want 0", a.Len())
	}
	if !a.IsEmpty() {
		t.Errorf("IsEmpty = false, want true")
	}
	if a.Count() != 0 {
		t.Errorf("Count = %d, want 0", a.Count())
	}
}

func TestBgpPathAttrs_FreeReleasesHandle(t *testing.T) {
	a, err := NewBgpPathAttrs()
	if err != nil {
		t.Fatalf("NewBgpPathAttrs: %v", err)
	}
	a.Free()
	if !a.Closed() {
		t.Errorf("Closed = false, want true")
	}
	// Operations on a freed handle are safe and return empty/0.
	if a.Len() != 0 {
		t.Errorf("Len after free = %d, want 0", a.Len())
	}
	if !a.IsEmpty() {
		t.Errorf("IsEmpty after free = false, want true")
	}
	if a.Count() != 0 {
		t.Errorf("Count after free = %d, want 0", a.Count())
	}
	if _, ok, _ := a.At(0); ok {
		t.Errorf("At(0) after free returned ok=true")
	}
	if _, ok, _ := a.Get(BGPAttrLocalPref); ok {
		t.Errorf("Get(LocalPref) after free returned ok=true")
	}
	if a.Remove(BGPAttrLocalPref) {
		t.Errorf("Remove after free returned true")
	}
}

func TestBgpPathAttrs_CountAfterSetLocalPref(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if err := a.SetLocalPref(100); err != nil {
		t.Fatalf("SetLocalPref: %v", err)
	}
	if a.Count() != 1 {
		t.Errorf("Count = %d, want 1", a.Count())
	}
	if a.Len() != 1 {
		t.Errorf("Len = %d, want 1", a.Len())
	}
}

func TestBgpPathAttrs_AtReturnsPathAttr(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if err := a.SetLocalPref(100); err != nil {
		t.Fatalf("SetLocalPref: %v", err)
	}
	p, ok, err := a.At(0)
	if err != nil {
		t.Fatalf("At(0): %v", err)
	}
	if !ok {
		t.Fatal("At(0) returned ok=false")
	}
	if p.AttrType != BGPAttrLocalPref {
		t.Errorf("Type = %d, want %d", p.AttrType, BGPAttrLocalPref)
	}
	if p.Flags != 0x40 {
		t.Errorf("Flags = %#x, want 0x40", p.Flags)
	}
	want := []byte{0, 0, 0, 100}
	if !bytes.Equal(p.Value, want) {
		t.Errorf("Value = %v, want %v", p.Value, want)
	}
}

func TestBgpPathAttrs_AtOutOfRange(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	a.SetLocalPref(100)
	_, ok, _ := a.At(99)
	if ok {
		t.Error("At(99) returned ok=true")
	}
	_, ok, _ = a.At(1)
	if ok {
		t.Error("At(1) returned ok=true")
	}
}

func TestBgpPathAttrs_GetReturnsPathAttr(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	a.SetLocalPref(100)
	p, ok, _ := a.Get(BGPAttrLocalPref)
	if !ok {
		t.Fatal("Get(LocalPref) returned ok=false")
	}
	if p.AttrType != BGPAttrLocalPref {
		t.Errorf("Type = %d, want %d", p.AttrType, BGPAttrLocalPref)
	}
	if p.Flags != 0x40 {
		t.Errorf("Flags = %#x, want 0x40", p.Flags)
	}
	want := []byte{0, 0, 0, 100}
	if !bytes.Equal(p.Value, want) {
		t.Errorf("Value = %v, want %v", p.Value, want)
	}
}

func TestBgpPathAttrs_GetAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	_, ok, _ := a.Get(BGPAttrLocalPref)
	if ok {
		t.Error("Get(LocalPref) on fresh attrs returned ok=true")
	}
}

func TestBgpPathAttrs_RemoveTrueWhenPresent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	a.SetLocalPref(100)
	if !a.Remove(BGPAttrLocalPref) {
		t.Error("Remove returned false, want true")
	}
	if _, ok := a.LocalPref(); ok {
		t.Error("LocalPref after Remove returned ok=true")
	}
	if a.Count() != 0 {
		t.Errorf("Count after Remove = %d, want 0", a.Count())
	}
}

func TestBgpPathAttrs_RemoveFalseWhenAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.Remove(BGPAttrLocalPref) {
		t.Error("Remove on fresh attrs returned true")
	}
}

func TestBgpPathAttrs_InsertRawRoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	value := []byte{0, 0, 0, 250}
	if err := a.InsertRaw(0x40, BGPAttrLocalPref, value); err != nil {
		t.Fatalf("InsertRaw: %v", err)
	}
	if lp, ok := a.LocalPref(); !ok || lp != 250 {
		t.Errorf("LocalPref = (%d, %v), want (250, true)", lp, ok)
	}
	if a.Count() != 1 {
		t.Errorf("Count = %d, want 1", a.Count())
	}
}

// ---------------------------------------------------------------------------
// RFC 4271 §5.1 — well-known mandatory + discretionary.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_LocalPrefRoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if _, ok := a.LocalPref(); ok {
		t.Error("LocalPref on fresh attrs returned ok=true")
	}
	if err := a.SetLocalPref(100); err != nil {
		t.Fatalf("SetLocalPref: %v", err)
	}
	if lp, ok := a.LocalPref(); !ok || lp != 100 {
		t.Errorf("LocalPref = (%d, %v), want (100, true)", lp, ok)
	}
}

func TestBgpPathAttrs_MedAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if _, ok := a.Med(); ok {
		t.Error("Med on fresh attrs returned ok=true")
	}
}

func TestBgpPathAttrs_OriginAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if _, ok := a.Origin(); ok {
		t.Error("Origin on fresh attrs returned ok=true")
	}
}

func TestBgpPathAttrs_AtomicAggregateAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.AtomicAggregate() {
		t.Error("AtomicAggregate on fresh attrs returned true")
	}
}

func TestBgpPathAttrs_AggregatorAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if _, _, ok := a.Aggregator(); ok {
		t.Error("Aggregator on fresh attrs returned ok=true")
	}
}

func TestBgpPathAttrs_NextHopAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	nh := a.NextHop()
	if nh.Present {
		t.Error("NextHop.Present = true, want false")
	}
}

// ---------------------------------------------------------------------------
// RFC 4271 §5.1.2 + RFC 6793 — AS_PATH.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_AsPathAbsentOnFreshAttrs(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.AsPath() != nil {
		t.Error("AsPath on fresh attrs returned non-nil")
	}
	if a.AsPathWire(true) != nil {
		t.Error("AsPathWire(true) on fresh attrs returned non-nil")
	}
	if a.AsPathWire(false) != nil {
		t.Error("AsPathWire(false) on fresh attrs returned non-nil")
	}
	if a.As4Path() != nil {
		t.Error("As4Path on fresh attrs returned non-nil")
	}
}

func TestBgpAsPath_FreeOnNil(t *testing.T) {
	// A nil-wrapped BgpAsPath should be safe to Free.
	p := &BgpAsPath{}
	p.Free()
	if !p.Closed() {
		t.Error("Closed after Free = false, want true")
	}
}

// ---------------------------------------------------------------------------
// RFC 4456 — Route Reflection.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_OriginatorIDAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if _, ok := a.OriginatorID(); ok {
		t.Error("OriginatorID on fresh attrs returned ok=true")
	}
}

func TestBgpPathAttrs_ClusterListAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasClusterList() {
		t.Error("HasClusterList on fresh attrs returned true")
	}
	if a.ClusterList() != nil {
		t.Error("ClusterList on fresh attrs returned non-nil")
	}
}

// ---------------------------------------------------------------------------
// RFC 1997 / 4360 / 8097 — Communities.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_CommunitiesEmpty(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if c := a.Communities(); c != nil {
		t.Errorf("Communities = %v, want nil", c)
	}
	if c := a.ExtCommunities(); c != nil {
		t.Errorf("ExtCommunities = %v, want nil", c)
	}
	if c, _ := a.LargeCommunities(); c != nil {
		t.Errorf("LargeCommunities = %v, want nil", c)
	}
}

func TestBgpPathAttrs_InsertCommunityAndReadBack(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	c := uint32(64512)<<16 | 100
	if err := a.InsertCommunity(c); err != nil {
		t.Fatalf("InsertCommunity: %v", err)
	}
	got := a.Communities()
	if len(got) != 1 || got[0] != c {
		t.Errorf("Communities = %v, want [%d]", got, c)
	}
}

func TestBgpPathAttrs_InsertTwoCommunities(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	c1 := uint32(64512)<<16 | 100
	c2 := uint32(64512)<<16 | 200
	a.InsertCommunity(c1)
	a.InsertCommunity(c2)
	got := a.Communities()
	if len(got) != 2 || got[0] != c1 || got[1] != c2 {
		t.Errorf("Communities = %v, want [%d, %d]", got, c1, c2)
	}
}

func TestBgpPathAttrs_HasCommunity(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	c := uint32(65001)<<16 | 100
	if a.HasCommunity(c) {
		t.Error("HasCommunity on fresh attrs returned true")
	}
	a.InsertCommunity(c)
	if !a.HasCommunity(c) {
		t.Error("HasCommunity after insert returned false")
	}
	if a.HasCommunity(c + 1) {
		t.Error("HasCommunity(c+1) returned true")
	}
}

func TestBgpPathAttrs_InsertLargeCommunity(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	c, err := NewBgpLargeCommunity(65001, 1, 2)
	if err != nil {
		t.Fatalf("NewBgpLargeCommunity: %v", err)
	}
	defer c.Free()
	if c.GlobalAdmin() != 65001 || c.LocalData1() != 1 || c.LocalData2() != 2 {
		t.Errorf("LargeCommunity = %d:%d:%d, want 65001:1:2",
			c.GlobalAdmin(), c.LocalData1(), c.LocalData2())
	}
	if err := a.InsertLargeCommunity(c); err != nil {
		t.Fatalf("InsertLargeCommunity: %v", err)
	}
	if a.Count() < 1 {
		t.Errorf("Count = %d, want >= 1", a.Count())
	}
}

func TestBgpPathAttrs_LargeCommunitiesRoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	c, _ := NewBgpLargeCommunity(65001, 1, 2)
	defer c.Free()
	a.InsertLargeCommunity(c)
	large, err := a.LargeCommunities()
	if err != nil {
		t.Fatalf("LargeCommunities: %v", err)
	}
	if len(large) != 1 {
		t.Fatalf("len(LargeCommunities) = %d, want 1", len(large))
	}
	if large[0].GlobalAdmin() != 65001 ||
		large[0].LocalData1() != 1 ||
		large[0].LocalData2() != 2 {
		t.Errorf("LargeCommunities[0] = %v, want 65001:1:2", large[0])
	}
}

func TestBgpLargeCommunity_String(t *testing.T) {
	c, _ := NewBgpLargeCommunity(65001, 1, 2)
	defer c.Free()
	if s := c.String(); s != "65001:1:2" {
		t.Errorf("String = %q, want %q", s, "65001:1:2")
	}
}

func TestBgpLargeCommunity_FreeIdempotent(t *testing.T) {
	c, _ := NewBgpLargeCommunity(65001, 1, 2)
	c.Free()
	c.Free() // no panic
}

// ---------------------------------------------------------------------------
// RFC 7311 / 8124 — AIGP.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_AigpAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasAigp() {
		t.Error("HasAigp on fresh attrs returned true")
	}
	if _, ok := a.Aigp(); ok {
		t.Error("Aigp on fresh attrs returned ok=true")
	}
}

// ---------------------------------------------------------------------------
// RFC 9655 — OTC.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_OtcAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasOtc() {
		t.Error("HasOtc on fresh attrs returned true")
	}
	if _, ok := a.Otc(); ok {
		t.Error("Otc on fresh attrs returned ok=true")
	}
}

// ---------------------------------------------------------------------------
// RFC 6514 — PMSI Tunnel.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_PmsiTunnelAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasPmsiTunnel() {
		t.Error("HasPmsiTunnel on fresh attrs returned true")
	}
}

// ---------------------------------------------------------------------------
// RFC 8277 — MPLS Label Stack.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_LabelStackAbsentOnFreshAttrs(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.LabelStack() != nil {
		t.Error("LabelStack on fresh attrs returned non-nil")
	}
}

func TestBgpPathAttrs_SetLabelStackRoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	stack, err := NewMPLSLabelStackFromValues([]uint32{16, 17})
	if err != nil {
		t.Fatalf("NewMPLSLabelStackFromValues: %v", err)
	}
	defer stack.Free()
	if err := a.SetLabelStack(stack); err != nil {
		t.Fatalf("SetLabelStack: %v", err)
	}
	out := a.LabelStack()
	if out == nil {
		t.Fatal("LabelStack returned nil after SetLabelStack")
	}
	defer out.Free()
	if out.Len() != 2 {
		t.Errorf("Len = %d, want 2", out.Len())
	}
}

// ---------------------------------------------------------------------------
// MP-BGP (RFC 4760).
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_MpReachAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if _, ok, _ := a.MpReach(); ok {
		t.Error("MpReach on fresh attrs returned ok=true")
	}
}

func TestBgpPathAttrs_MpUnreachAbsent(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if _, ok, _ := a.MpUnreach(); ok {
		t.Error("MpUnreach on fresh attrs returned ok=true")
	}
}

// ---------------------------------------------------------------------------
// OSPF redistrib (RFC 4577 §3).
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_OspfMetric2RoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasOspfMetric2() {
		t.Error("HasOspfMetric2 on fresh attrs returned true")
	}
	if _, ok := a.OspfMetric2(); ok {
		t.Error("OspfMetric2 on fresh attrs returned ok=true")
	}
	if err := a.SetOspfMetric2(123); err != nil {
		t.Fatalf("SetOspfMetric2: %v", err)
	}
	if !a.HasOspfMetric2() {
		t.Error("HasOspfMetric2 after Set returned false")
	}
	if v, ok := a.OspfMetric2(); !ok || v != 123 {
		t.Errorf("OspfMetric2 = (%d, %v), want (123, true)", v, ok)
	}
}

func TestBgpPathAttrs_OspfRouterIDRoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasOspfRouterID() {
		t.Error("HasOspfRouterID on fresh attrs returned true")
	}
	if _, ok := a.OspfRouterID(); ok {
		t.Error("OspfRouterID on fresh attrs returned ok=true")
	}
	if err := a.SetOspfRouterID(0x01020304); err != nil {
		t.Fatalf("SetOspfRouterID: %v", err)
	}
	if !a.HasOspfRouterID() {
		t.Error("HasOspfRouterID after Set returned false")
	}
	if v, ok := a.OspfRouterID(); !ok || v != 0x01020304 {
		t.Errorf("OspfRouterID = (%#x, %v), want (0x01020304, true)", v, ok)
	}
}

// ---------------------------------------------------------------------------
// Babel redistrib (RFC 7999 + babel-ext).
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_BabelSeqnoRoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasBabelSeqno() {
		t.Error("HasBabelSeqno on fresh attrs returned true")
	}
	if _, ok := a.BabelSeqno(); ok {
		t.Error("BabelSeqno on fresh attrs returned ok=true")
	}
	if err := a.SetBabelSeqno(65535); err != nil {
		t.Fatalf("SetBabelSeqno: %v", err)
	}
	if !a.HasBabelSeqno() {
		t.Error("HasBabelSeqno after Set returned false")
	}
	if v, ok := a.BabelSeqno(); !ok || v != 65535 {
		t.Errorf("BabelSeqno = (%d, %v), want (65535, true)", v, ok)
	}
}

func TestBgpPathAttrs_BabelRouterIDRoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasBabelRouterID() {
		t.Error("HasBabelRouterID on fresh attrs returned true")
	}
	if _, ok := a.BabelRouterID(); ok {
		t.Error("BabelRouterID on fresh attrs returned ok=true")
	}
	const rid = 0x0123456789ABCDEF
	if err := a.SetBabelRouterID(rid); err != nil {
		t.Fatalf("SetBabelRouterID: %v", err)
	}
	if !a.HasBabelRouterID() {
		t.Error("HasBabelRouterID after Set returned false")
	}
	if v, ok := a.BabelRouterID(); !ok || v != rid {
		t.Errorf("BabelRouterID = (%#x, %v), want (%#x, true)", v, ok, rid)
	}
}

// ---------------------------------------------------------------------------
// IGP metric (RFC 4271 §9.1.2.2 step 7).
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_IgpMetricRoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasIgpMetric() {
		t.Error("HasIgpMetric on fresh attrs returned true")
	}
	if _, ok := a.IgpMetric(); ok {
		t.Error("IgpMetric on fresh attrs returned ok=true")
	}
	if err := a.SetIgpMetric(1000); err != nil {
		t.Fatalf("SetIgpMetric: %v", err)
	}
	if !a.HasIgpMetric() {
		t.Error("HasIgpMetric after Set returned false")
	}
	if v, ok := a.IgpMetric(); !ok || v != 1000 {
		t.Errorf("IgpMetric = (%d, %v), want (1000, true)", v, ok)
	}
}

// ---------------------------------------------------------------------------
// Peer source address (RFC 4271 §6.3).
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_PeerSourceAddressV4RoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if a.HasPeerSourceAddress() {
		t.Error("HasPeerSourceAddress on fresh attrs returned true")
	}
	if _, _, ok := a.PeerSourceAddress(); ok {
		t.Error("PeerSourceAddress on fresh attrs returned ok=true")
	}
	addr := []byte{0xc0, 0xa8, 0x01, 0x01}
	if err := a.SetPeerSourceAddress(addr, false); err != nil {
		t.Fatalf("SetPeerSourceAddress: %v", err)
	}
	if !a.HasPeerSourceAddress() {
		t.Error("HasPeerSourceAddress after Set returned false")
	}
	got, isV6, ok := a.PeerSourceAddress()
	if !ok {
		t.Fatal("PeerSourceAddress returned ok=false")
	}
	if isV6 {
		t.Error("isIPv6 = true, want false")
	}
	if !bytes.Equal(got, addr) {
		t.Errorf("Addr = %v, want %v", got, addr)
	}
}

func TestBgpPathAttrs_PeerSourceAddressV6RoundTrip(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	addr := make([]byte, 16)
	addr[15] = 1
	if err := a.SetPeerSourceAddress(addr, true); err != nil {
		t.Fatalf("SetPeerSourceAddress: %v", err)
	}
	got, isV6, ok := a.PeerSourceAddress()
	if !ok {
		t.Fatal("PeerSourceAddress returned ok=false")
	}
	if !isV6 {
		t.Error("isIPv6 = false, want true")
	}
	if !bytes.Equal(got, addr) {
		t.Errorf("Addr = %v, want %v", got, addr)
	}
}

func TestBgpPathAttrs_PeerSourceAddressWrongLength(t *testing.T) {
	a, _ := NewBgpPathAttrs()
	defer a.Free()
	if err := a.SetPeerSourceAddress([]byte{0, 1}, false); err == nil {
		t.Error("SetPeerSourceAddress(v4 with 2 bytes) returned nil error")
	}
	if err := a.SetPeerSourceAddress(make([]byte, 4), true); err == nil {
		t.Error("SetPeerSourceAddress(v6 with 4 bytes) returned nil error")
	}
}

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

func TestBgpPathAttrs_AttrTypeCodes(t *testing.T) {
	// Sanity-check that the constants match the IANA assignments.
	if BGPAttrOrigin != 1 {
		t.Errorf("BGPAttrOrigin = %d, want 1", BGPAttrOrigin)
	}
	if BGPAttrAsPath != 2 {
		t.Errorf("BGPAttrAsPath = %d, want 2", BGPAttrAsPath)
	}
	if BGPAttrNextHop != 3 {
		t.Errorf("BGPAttrNextHop = %d, want 3", BGPAttrNextHop)
	}
	if BGPAttrMed != 4 {
		t.Errorf("BGPAttrMed = %d, want 4", BGPAttrMed)
	}
	if BGPAttrLocalPref != 5 {
		t.Errorf("BGPAttrLocalPref = %d, want 5", BGPAttrLocalPref)
	}
	if BGPAttrAtomicAggregate != 6 {
		t.Errorf("BGPAttrAtomicAggregate = %d, want 6", BGPAttrAtomicAggregate)
	}
	if BGPAttrAggregator != 7 {
		t.Errorf("BGPAttrAggregator = %d, want 7", BGPAttrAggregator)
	}
	if BGPAttrCommunities != 8 {
		t.Errorf("BGPAttrCommunities = %d, want 8", BGPAttrCommunities)
	}
	if BGPAttrOriginatorID != 9 {
		t.Errorf("BGPAttrOriginatorID = %d, want 9", BGPAttrOriginatorID)
	}
	if BGPAttrClusterList != 10 {
		t.Errorf("BGPAttrClusterList = %d, want 10", BGPAttrClusterList)
	}
	if BGPAttrMpReachNlri != 14 {
		t.Errorf("BGPAttrMpReachNlri = %d, want 14", BGPAttrMpReachNlri)
	}
	if BGPAttrMpUnreachNlri != 15 {
		t.Errorf("BGPAttrMpUnreachNlri = %d, want 15", BGPAttrMpUnreachNlri)
	}
	if BGPAttrExtCommunities != 16 {
		t.Errorf("BGPAttrExtCommunities = %d, want 16", BGPAttrExtCommunities)
	}
	if BGPAttrAs4Path != 17 {
		t.Errorf("BGPAttrAs4Path = %d, want 17", BGPAttrAs4Path)
	}
	if BGPAttrPmsiTunnel != 22 {
		t.Errorf("BGPAttrPmsiTunnel = %d, want 22", BGPAttrPmsiTunnel)
	}
	if BGPAttrAigp != 26 {
		t.Errorf("BGPAttrAigp = %d, want 26", BGPAttrAigp)
	}
	if BGPAttrLargeCommunities != 32 {
		t.Errorf("BGPAttrLargeCommunities = %d, want 32", BGPAttrLargeCommunities)
	}
	if BGPAttrOtc != 35 {
		t.Errorf("BGPAttrOtc = %d, want 35", BGPAttrOtc)
	}
}

func TestBgpPathAttrs_PrivateAttrCodes(t *testing.T) {
	if BGPAttrOspfMetric2 != 253 {
		t.Errorf("BGPAttrOspfMetric2 = %d, want 253", BGPAttrOspfMetric2)
	}
	if BGPAttrOspfRouterID != 252 {
		t.Errorf("BGPAttrOspfRouterID = %d, want 252", BGPAttrOspfRouterID)
	}
	if BGPAttrBabelRouterID != 250 {
		t.Errorf("BGPAttrBabelRouterID = %d, want 250", BGPAttrBabelRouterID)
	}
	if BGPAttrBabelSeqno != 249 {
		t.Errorf("BGPAttrBabelSeqno = %d, want 249", BGPAttrBabelSeqno)
	}
	if BGPAttrIgpMetric != 246 {
		t.Errorf("BGPAttrIgpMetric = %d, want 246", BGPAttrIgpMetric)
	}
	if BGPAttrPeerSourceAddress != 245 {
		t.Errorf("BGPAttrPeerSourceAddress = %d, want 245", BGPAttrPeerSourceAddress)
	}
	if BGPAttrLrMplsLabelStack != 255 {
		t.Errorf("BGPAttrLrMplsLabelStack = %d, want 255", BGPAttrLrMplsLabelStack)
	}
}

// ---------------------------------------------------------------------------
// BgpNextHop value type.
// ---------------------------------------------------------------------------

func TestBgpNextHop_IPv4(t *testing.T) {
	nh := BgpNextHop{
		Addr:    [16]byte{0xc0, 0xa8, 0x01, 0x01},
		Kind:    NextHopV4,
		Present: true,
	}
	ip, ok := nh.IPAddress()
	if !ok {
		t.Fatal("IPAddress returned ok=false")
	}
	if ip.String() != "192.168.1.1" {
		t.Errorf("IPAddress = %s, want 192.168.1.1", ip.String())
	}
}

func TestBgpNextHop_IPv6(t *testing.T) {
	var addr [16]byte
	addr[15] = 1
	nh := BgpNextHop{Addr: addr, Kind: NextHopV6, Present: true}
	ip, ok := nh.IPAddress()
	if !ok {
		t.Fatal("IPAddress returned ok=false")
	}
	if ip.String() != "::1" {
		t.Errorf("IPAddress = %s, want ::1", ip.String())
	}
}

func TestBgpNextHop_V4OverV6(t *testing.T) {
	nh := BgpNextHop{
		Addr:    [16]byte{0xc0, 0xa8, 0x01, 0x01},
		Kind:    NextHopV4OverV6,
		Present: true,
	}
	ip, ok := nh.IPAddress()
	if !ok {
		t.Fatal("IPAddress returned ok=false")
	}
	if ip.String() != "192.168.1.1" {
		t.Errorf("IPAddress = %s, want 192.168.1.1", ip.String())
	}
}

func TestBgpNextHop_AbsentReturnsZero(t *testing.T) {
	nh := BgpNextHop{Kind: NextHopV4, Present: false}
	if _, ok := nh.IPAddress(); ok {
		t.Error("IPAddress on absent NextHop returned ok=true")
	}
}
