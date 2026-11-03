// Tests for the OSPF structured-type binding — mirrors lr-ospf's
// LinkStateRetransmissionList, Lsdb, Lsa box, and external
// destination tests in crates/lr-ffi/src/ospf_*.rs.

package librouting

import (
	"testing"
)

func TestOspfRetransmitListEmpty(t *testing.T) {
	l := NewOspfRetransmitList()
	defer l.Free()
	if l.Len() != 0 {
		t.Fatalf("empty list Len = %d, want 0", l.Len())
	}
	if !l.IsEmpty() {
		t.Fatalf("empty list IsEmpty = false, want true")
	}
}

func TestOspfRetransmitListRecordAndContains(t *testing.T) {
	l := NewOspfRetransmitList()
	defer l.Free()

	lsa, err := NewOspfLsa(OspfLsaHeader{
		LsType:            1,
		LinkStateID:       0xa,
		AdvertisingRouter: 0xa,
		Length:            20,
	}, nil)
	if err != nil {
		t.Fatalf("NewOspfLsa: %v", err)
	}

	if err := l.RecordFlood(lsa, 0); err != nil {
		t.Fatalf("RecordFlood: %v", err)
	}
	if l.Len() != 1 {
		t.Fatalf("after RecordFlood Len = %d, want 1", l.Len())
	}
	if !l.Contains(OspfLsaKey{LsType: 1, LinkStateID: 0xa, AdvertisingRouter: 0xa}) {
		t.Fatalf("Contains(0xa/0xa) = false, want true")
	}
	if l.Contains(OspfLsaKey{LsType: 1, LinkStateID: 0xb, AdvertisingRouter: 0xa}) {
		t.Fatalf("Contains(0xb/0xa) = true, want false")
	}
}

func TestOspfRetransmitListRemove(t *testing.T) {
	l := NewOspfRetransmitList()
	defer l.Free()

	lsa, _ := NewOspfLsa(OspfLsaHeader{
		LsType:            1,
		LinkStateID:       0xa,
		AdvertisingRouter: 0xa,
		Length:            20,
	}, nil)
	_ = l.RecordFlood(lsa, 0)
	if !l.Remove(OspfLsaKey{LsType: 1, LinkStateID: 0xa, AdvertisingRouter: 0xa}) {
		t.Fatalf("Remove returned false, want true")
	}
	if l.Len() != 0 {
		t.Fatalf("after Remove Len = %d, want 0", l.Len())
	}
	if l.Remove(OspfLsaKey{LsType: 1, LinkStateID: 0xa, AdvertisingRouter: 0xa}) {
		t.Fatalf("Remove on missing entry returned true, want false")
	}
}

func TestOspfRetransmitListClear(t *testing.T) {
	l := NewOspfRetransmitList()
	defer l.Free()

	lsa1, _ := NewOspfLsa(OspfLsaHeader{LsType: 1, LinkStateID: 1, AdvertisingRouter: 0xa, Length: 20}, nil)
	lsa2, _ := NewOspfLsa(OspfLsaHeader{LsType: 1, LinkStateID: 2, AdvertisingRouter: 0xa, Length: 20}, nil)
	_ = l.RecordFlood(lsa1, 0)
	_ = l.RecordFlood(lsa2, 0)
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2", l.Len())
	}
	l.Clear()
	if !l.IsEmpty() {
		t.Fatalf("after Clear IsEmpty = false, want true")
	}
}

func TestOspfRetransmitListApplyAcks(t *testing.T) {
	l := NewOspfRetransmitList()
	defer l.Free()

	lsa1, _ := NewOspfLsa(OspfLsaHeader{LsType: 1, LinkStateID: 0xa, AdvertisingRouter: 0xa, Length: 20}, nil)
	lsa2, _ := NewOspfLsa(OspfLsaHeader{LsType: 1, LinkStateID: 0xb, AdvertisingRouter: 0xa, Length: 20}, nil)
	_ = l.RecordFlood(lsa1, 0)
	_ = l.RecordFlood(lsa2, 0)

	// Ack the first LSA only — §13.7 key-match drain.
	acks := []OspfLsaHeader{
		{LsType: 1, LinkStateID: 0xa, AdvertisingRouter: 0xa, Length: 20},
	}
	removed, err := l.ApplyAcks(acks)
	if err != nil {
		t.Fatalf("ApplyAcks: %v", err)
	}
	if removed != 1 {
		t.Fatalf("ApplyAcks removed = %d, want 1", removed)
	}
	if l.Len() != 1 {
		t.Fatalf("after ApplyAcks Len = %d, want 1", l.Len())
	}
	if !l.Contains(OspfLsaKey{LsType: 1, LinkStateID: 0xb, AdvertisingRouter: 0xa}) {
		t.Fatalf("after ApplyAcks(0xa) the 0xb entry should still be on the list")
	}
}

func TestOspfRetransmitListApplyAcksStray(t *testing.T) {
	l := NewOspfRetransmitList()
	defer l.Free()
	lsa, _ := NewOspfLsa(OspfLsaHeader{LsType: 1, LinkStateID: 0xa, AdvertisingRouter: 0xa, Length: 20}, nil)
	_ = l.RecordFlood(lsa, 0)

	// Stray ack — references an LSA we never flooded. §13.7 step 5:
	// silently accepted (0 removed, list unchanged).
	stray := []OspfLsaHeader{
		{LsType: 1, LinkStateID: 0xdead, AdvertisingRouter: 0xbeef, Length: 20},
	}
	removed, _ := l.ApplyAcks(stray)
	if removed != 0 {
		t.Fatalf("stray ack removed = %d, want 0", removed)
	}
	if l.Len() != 1 {
		t.Fatalf("after stray ack Len = %d, want 1", l.Len())
	}
}

func TestOspfRetransmitListPollTiming(t *testing.T) {
	l := NewOspfRetransmitList()
	defer l.Free()
	lsa, _ := NewOspfLsa(OspfLsaHeader{LsType: 1, LinkStateID: 0xa, AdvertisingRouter: 0xa, Length: 20}, nil)
	_ = l.RecordFlood(lsa, 1_000)

	// Poll at 1.5s — interval 5s not elapsed, no retransmit.
	out, err := l.Poll(1_500, 5_000)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("Poll at 1.5s returned %d LSAs, want 0", out.Len())
	}
	out.Free()

	// Poll at 6s — interval elapsed, expect 1 LSA.
	out, err = l.Poll(6_000, 5_000)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if out.Len() != 1 {
		t.Fatalf("Poll at 6s returned %d LSAs, want 1", out.Len())
	}
	out.Free()

	// Poll again at 10.999s — should NOT re-emit (last_sent_ms was bumped to 6s).
	out, _ = l.Poll(10_999, 5_000)
	if out.Len() != 0 {
		t.Fatalf("Poll at 10.999s returned %d LSAs, want 0 (last_sent_ms was bumped to 6s)", out.Len())
	}
	out.Free()
}

func TestOspfLsdbEmpty(t *testing.T) {
	d := NewOspfLsdb()
	defer d.Free()
	if d.Len() != 0 {
		t.Fatalf("empty LSDB Len = %d, want 0", d.Len())
	}
	if !d.IsEmpty() {
		t.Fatalf("empty LSDB IsEmpty = false, want true")
	}
	headers, err := d.Headers()
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if len(headers) != 0 {
		t.Fatalf("empty LSDB Headers = %d, want 0", len(headers))
	}
}

func TestOspfLsdbInstallGetRemove(t *testing.T) {
	d := NewOspfLsdb()
	defer d.Free()

	lsa, _ := NewOspfLsa(OspfLsaHeader{
		LsType:            1,
		LinkStateID:       0xa,
		AdvertisingRouter: 0xa,
		LsSequenceNumber:  0x80000001,
		Length:            20,
	}, nil)
	changed, err := d.Install(lsa)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !changed {
		t.Fatalf("first Install changed = false, want true")
	}
	if d.Len() != 1 {
		t.Fatalf("after Install Len = %d, want 1", d.Len())
	}

	// Get returns a clone — caller frees it.
	got, err := d.Get(OspfLsaKey{LsType: 1, LinkStateID: 0xa, AdvertisingRouter: 0xa})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatalf("Get returned nil for present LSA")
	}
	defer got.Free()
	if h, err := got.Header(); err != nil || h.LsSequenceNumber != 0x80000001 {
		t.Fatalf("Get returned wrong seqno: h=%+v err=%v", h, err)
	}

	// Headers should now contain 1 entry.
	headers, _ := d.Headers()
	if len(headers) != 1 {
		t.Fatalf("Headers = %d, want 1", len(headers))
	}

	// Remove the LSA.
	removed, err := d.Remove(OspfLsaKey{LsType: 1, LinkStateID: 0xa, AdvertisingRouter: 0xa})
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !removed {
		t.Fatalf("Remove returned false, want true")
	}
	if d.Len() != 0 {
		t.Fatalf("after Remove Len = %d, want 0", d.Len())
	}
}

func TestOspfLsaBodyRoundTrip(t *testing.T) {
	body := []byte{0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef}
	lsa, err := NewOspfLsa(OspfLsaHeader{
		LsType:            1,
		LinkStateID:       0x01020304,
		AdvertisingRouter: 0x01020304,
		LsSequenceNumber:  0x80000001,
		Length:            uint16(20 + len(body)),
	}, body)
	if err != nil {
		t.Fatalf("NewOspfLsa: %v", err)
	}
	defer lsa.Free()

	got, err := lsa.Body()
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("Body len = %d, want %d", len(got), len(body))
	}
	for i, b := range got {
		if b != body[i] {
			t.Fatalf("Body[%d] = 0x%x, want 0x%x", i, b, body[i])
		}
	}

	wire, err := lsa.ToWire()
	if err != nil {
		t.Fatalf("ToWire: %v", err)
	}
	if len(wire) != 20+len(body) {
		t.Fatalf("ToWire len = %d, want %d", len(wire), 20+len(body))
	}

	key, err := lsa.Key()
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if key.LsType != 1 || key.LinkStateID != 0x01020304 || key.AdvertisingRouter != 0x01020304 {
		t.Fatalf("Key = %+v, want (1, 0x01020304, 0x01020304)", key)
	}
}

func TestOspfExternalDestV4(t *testing.T) {
	addr := [4]byte{203, 0, 113, 0}
	d, err := NewOspfExternalDestV4(addr, 24, 100, OspfExternalType1)
	if err != nil {
		t.Fatalf("NewOspfExternalDestV4: %v", err)
	}
	defer d.Free()

	if d.Metric() != 100 {
		t.Fatalf("Metric = %d, want 100", d.Metric())
	}
	if d.MetricType() != OspfExternalType1 {
		t.Fatalf("MetricType = %d, want %d", d.MetricType(), OspfExternalType1)
	}

	if err := d.SetForwardingAddrV4(0x0a000001); err != nil {
		t.Fatalf("SetForwardingAddrV4: %v", err)
	}
	if err := d.SetRouteTag(42); err != nil {
		t.Fatalf("SetRouteTag: %v", err)
	}
	if err := d.SetPBit(1); err != nil {
		t.Fatalf("SetPBit: %v", err)
	}

	if d.RouteTag() != 42 {
		t.Fatalf("RouteTag = %d, want 42", d.RouteTag())
	}
	if d.PBit() != 1 {
		t.Fatalf("PBit = %d, want 1", d.PBit())
	}
}

// TestOspfV3ExternalDest exercises the v3 external-LSA destination
// builder + readers (RFC 5340 §4.4.3.6 / §A.4.7).
func TestOspfV3ExternalDest(t *testing.T) {
	pfx := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x01}
	d, err := NewOspfV3ExternalDestV6(pfx, 48, 100, false)
	if err != nil {
		t.Fatalf("NewOspfV3ExternalDestV6: %v", err)
	}
	defer d.Free()
	if d.Metric() != 100 {
		t.Fatalf("Metric = %d, want 100", d.Metric())
	}
	if d.Type2() {
		t.Fatalf("Type2 = true, want false")
	}
	fa := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0xfe}
	if err := d.SetForwardingAddr(fa); err != nil {
		t.Fatalf("SetForwardingAddr: %v", err)
	}
	if err := d.SetRouteTag(0xDEADBEEF); err != nil {
		t.Fatalf("SetRouteTag: %v", err)
	}
	outFA, ok, err := d.ForwardingAddr()
	if err != nil {
		t.Fatalf("ForwardingAddr: %v", err)
	}
	if !ok {
		t.Fatalf("ForwardingAddr ok=false, want true")
	}
	if outFA != fa {
		t.Fatalf("ForwardingAddr = %x, want %x", outFA, fa)
	}
	outTag, ok, err := d.RouteTag()
	if err != nil {
		t.Fatalf("RouteTag: %v", err)
	}
	if !ok {
		t.Fatalf("RouteTag ok=false, want true")
	}
	if outTag != 0xDEADBEEF {
		t.Fatalf("RouteTag = %x, want DEADBEEF", outTag)
	}
	if err := d.ClearForwardingAddr(); err != nil {
		t.Fatalf("ClearForwardingAddr: %v", err)
	}
	if err := d.ClearRouteTag(); err != nil {
		t.Fatalf("ClearRouteTag: %v", err)
	}
	if _, ok, err := d.ForwardingAddr(); err != nil || ok {
		t.Fatalf("ForwardingAddr after clear: ok=%v err=%v", ok, err)
	}
	if _, ok, err := d.RouteTag(); err != nil || ok {
		t.Fatalf("RouteTag after clear: ok=%v err=%v", ok, err)
	}
}

// helper: build a Router and attach an OSPFv2 area so the OSPF
// runtime methods have somewhere to land.
func routerWithOspfArea(t *testing.T, areaID uint32, areaKind uint32, defaultMetric uint32) *Router {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	_, err = r.AddOSPFSessionExt(OspfV2, // OSPFv2
		0xC0A80001, // router_id
		areaID,
		areaKind,
		defaultMetric,
		1500,     // mtu
		NetPtp,   // network_type=PTP
		false, 0, // no interface_ip
		false, 0, // no neighbor_ip
	)
	if err != nil {
		t.Fatalf("AddOSPFSessionExt: %v", err)
	}
	return r
}

func TestOspfVirtualLinkLifecycle(t *testing.T) {
	r := routerWithOspfArea(t, 1, 0, 0)
	// vlink to self refused.
	if ok, err := r.OspfAddVirtualLink(1, 0xC0A80001); err != nil || ok {
		t.Fatalf("vlink to self: ok=%v err=%v", ok, err)
	}
	// vlink across normal area accepted.
	if ok, err := r.OspfAddVirtualLink(1, 0xC0A80002); err != nil || !ok {
		t.Fatalf("vlink across normal area: ok=%v err=%v", ok, err)
	}
	// duplicate add refused.
	if ok, err := r.OspfAddVirtualLink(1, 0xC0A80002); err != nil || ok {
		t.Fatalf("duplicate vlink: ok=%v err=%v", ok, err)
	}
	// link down (no SPF reach).
	if ok, err := r.OspfVirtualLinkUp(1, 0xC0A80002); err != nil || ok {
		t.Fatalf("vlink up before SPF: ok=%v err=%v", ok, err)
	}
	if _, ok, err := r.OspfVirtualLinkSession(1, 0xC0A80002); err != nil || ok {
		t.Fatalf("vlink session before SPF: ok=%v err=%v", ok, err)
	}
	// remove.
	if ok, err := r.OspfRemoveVirtualLink(1, 0xC0A80002); err != nil || !ok {
		t.Fatalf("vlink remove: ok=%v err=%v", ok, err)
	}
	// remove again — no-op.
	if ok, err := r.OspfRemoveVirtualLink(1, 0xC0A80002); err != nil || ok {
		t.Fatalf("vlink remove again: ok=%v err=%v", ok, err)
	}
}

func TestOspfVirtualLinkAcrossStubAreaRefused(t *testing.T) {
	// areaKind=1 is a stub area; virtual links cannot cross stub
	// areas (RFC 2328 §15).
	r := routerWithOspfArea(t, 2, 1, 100)
	if ok, err := r.OspfAddVirtualLink(2, 0xC0A80002); err != nil || ok {
		t.Fatalf("vlink across stub: ok=%v err=%v", ok, err)
	}
}

func TestOspfRedistributeV2AndAsbr(t *testing.T) {
	r := routerWithOspfArea(t, 1, 0, 0)
	if ok, err := r.OspfIsAsbr(); err != nil || ok {
		t.Fatalf("IsAsbr before: ok=%v err=%v", ok, err)
	}
	addr := [4]byte{10, 0, 0, 0}
	dest, err := NewOspfExternalDestV4(addr, 24, 100, OspfExternalType1)
	if err != nil {
		t.Fatalf("NewOspfExternalDestV4: %v", err)
	}
	defer dest.Free()
	if ok, err := r.OspfRedistribute(dest); err != nil || !ok {
		t.Fatalf("Redistribute: ok=%v err=%v", ok, err)
	}
	if ok, err := r.OspfIsAsbr(); err != nil || !ok {
		t.Fatalf("IsAsbr after redistribute: ok=%v err=%v", ok, err)
	}
	if ok, err := r.OspfUnredistribute(addr[:], 24); err != nil || !ok {
		t.Fatalf("Unredistribute: ok=%v err=%v", ok, err)
	}
	if ok, err := r.OspfIsAsbr(); err != nil || ok {
		t.Fatalf("IsAsbr after unredistribute: ok=%v err=%v", ok, err)
	}
	// Unredistribute again is a no-op.
	if ok, err := r.OspfUnredistribute(addr[:], 24); err != nil || ok {
		t.Fatalf("Unredistribute again: ok=%v err=%v", ok, err)
	}
}

func TestOspfRedistributeV3AndAsbr(t *testing.T) {
	r := routerWithOspfArea(t, 1, 0, 0)
	pfx := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x01}
	dest, err := NewOspfV3ExternalDestV6(pfx, 48, 100, false)
	if err != nil {
		t.Fatalf("NewOspfV3ExternalDestV6: %v", err)
	}
	defer dest.Free()
	if ok, err := r.OspfRedistributeV3(dest); err != nil || !ok {
		t.Fatalf("RedistributeV3: ok=%v err=%v", ok, err)
	}
	if ok, err := r.OspfIsAsbr(); err != nil || !ok {
		t.Fatalf("IsAsbr after v3 redistribute: ok=%v err=%v", ok, err)
	}
	// With only a v2 area attached, no v3 LSA was ever originated, so
	// unredistribute_v3 returns false (nothing was flushed) — the
	// ASBR flag flipping back to false confirms the intent was in
	// fact dropped.
	if _, err := r.OspfUnredistributeV3(pfx[:], 48); err != nil {
		t.Fatalf("UnredistributeV3: %v", err)
	}
	if ok, err := r.OspfIsAsbr(); err != nil || ok {
		t.Fatalf("IsAsbr after v3 unredistribute: ok=%v err=%v", ok, err)
	}
}

func TestOspfRedistributeV3RejectsLinkLocalFA(t *testing.T) {
	r := routerWithOspfArea(t, 1, 0, 0)
	pfx := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x01}
	llFA := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x01}
	dest, err := NewOspfV3ExternalDestV6(pfx, 48, 100, false)
	if err != nil {
		t.Fatalf("NewOspfV3ExternalDestV6: %v", err)
	}
	defer dest.Free()
	if err := dest.SetForwardingAddr(llFA); err != nil {
		t.Fatalf("SetForwardingAddr: %v", err)
	}
	// The router rejects link-local FA per RFC 5340 §A.4.7.
	if ok, err := r.OspfRedistributeV3(dest); err != nil || ok {
		t.Fatalf("RedistributeV3 with link-local FA: ok=%v err=%v", ok, err)
	}
}

func TestOspfRedistributeV2RejectsV6Prefix(t *testing.T) {
	r := routerWithOspfArea(t, 1, 0, 0)
	pfx := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x01}
	// OspfExternalDestV6 succeeds at construction (the C ABI
	// accepts the v6 prefix pointer), but the v2 redistribute plane
	// only carries IPv4 prefixes — passing a v6 dest returns false.
	dest, err := NewOspfExternalDestV6(pfx, 48, 100, OspfExternalType1)
	if err != nil {
		t.Fatalf("NewOspfExternalDestV6: %v", err)
	}
	defer dest.Free()
	if ok, err := r.OspfRedistribute(dest); err != nil || ok {
		t.Fatalf("Redistribute v6 dest: ok=%v err=%v", ok, err)
	}
}

// ----- OspfAreaType value-type wrapper tests (issue #92) -----

func TestOspfAreaTypeConstructorsRoundTrip(t *testing.T) {
	normal := NewOspfAreaTypeNormal()
	if normal.Kind() != AreaNormal {
		t.Fatalf("normal.Kind() = %d, want %d", normal.Kind(), AreaNormal)
	}
	if normal.KindName() != "normal" {
		t.Fatalf("normal.KindName() = %q, want %q", normal.KindName(), "normal")
	}
	if normal.IsStub() || normal.IsNssa() || normal.IsStubby() {
		t.Fatalf("normal: stub=%v nssa=%v stubby=%v", normal.IsStub(), normal.IsNssa(), normal.IsStubby())
	}
	if normal.NoSummary() {
		t.Fatalf("normal.NoSummary() = true, want false")
	}
	if dm, ok := normal.DefaultMetric(); ok {
		t.Fatalf("normal.DefaultMetric() = (%d, true), want (0, false)", dm)
	}

	stub := NewOspfAreaTypeStub(42)
	if stub.Kind() != AreaStub {
		t.Fatalf("stub.Kind() = %d, want %d", stub.Kind(), AreaStub)
	}
	if !stub.IsStub() || stub.IsNssa() || !stub.IsStubby() {
		t.Fatalf("stub: stub=%v nssa=%v stubby=%v", stub.IsStub(), stub.IsNssa(), stub.IsStubby())
	}
	if stub.NoSummary() {
		t.Fatalf("stub.NoSummary() = true, want false")
	}
	if dm, ok := stub.DefaultMetric(); !ok || dm != 42 {
		t.Fatalf("stub.DefaultMetric() = (%d, %v), want (42, true)", dm, ok)
	}

	stubNs := NewOspfAreaTypeStubNoSummary(7)
	if stubNs.Kind() != AreaStubNoSummary {
		t.Fatalf("stubNs.Kind() = %d, want %d", stubNs.Kind(), AreaStubNoSummary)
	}
	if !stubNs.IsStub() || !stubNs.IsStubby() || !stubNs.NoSummary() {
		t.Fatalf("stubNs: stub=%v stubby=%v no_summary=%v", stubNs.IsStub(), stubNs.IsStubby(), stubNs.NoSummary())
	}
	if dm, ok := stubNs.DefaultMetric(); !ok || dm != 7 {
		t.Fatalf("stubNs.DefaultMetric() = (%d, %v), want (7, true)", dm, ok)
	}

	nssa := NewOspfAreaTypeNssa(99)
	if nssa.Kind() != AreaNssa {
		t.Fatalf("nssa.Kind() = %d, want %d", nssa.Kind(), AreaNssa)
	}
	if nssa.IsStub() || !nssa.IsNssa() || !nssa.IsStubby() {
		t.Fatalf("nssa: stub=%v nssa=%v stubby=%v", nssa.IsStub(), nssa.IsNssa(), nssa.IsStubby())
	}
	if nssa.NoSummary() {
		t.Fatalf("nssa.NoSummary() = true, want false")
	}
	if dm, ok := nssa.DefaultMetric(); !ok || dm != 99 {
		t.Fatalf("nssa.DefaultMetric() = (%d, %v), want (99, true)", dm, ok)
	}

	nssaNs := NewOspfAreaTypeNssaNoSummary(3)
	if nssaNs.Kind() != AreaNssaNoSummary {
		t.Fatalf("nssaNs.Kind() = %d, want %d", nssaNs.Kind(), AreaNssaNoSummary)
	}
	if !nssaNs.IsNssa() || !nssaNs.IsStubby() || !nssaNs.NoSummary() {
		t.Fatalf("nssaNs: nssa=%v stubby=%v no_summary=%v", nssaNs.IsNssa(), nssaNs.IsStubby(), nssaNs.NoSummary())
	}
	if dm, ok := nssaNs.DefaultMetric(); !ok || dm != 3 {
		t.Fatalf("nssaNs.DefaultMetric() = (%d, %v), want (3, true)", dm, ok)
	}
}

func TestOspfAreaTypeEqual(t *testing.T) {
	a := NewOspfAreaTypeStub(7)
	b := NewOspfAreaTypeStub(7)
	c := NewOspfAreaTypeStub(8)
	if !a.Equal(b) {
		t.Fatalf("a.Equal(b) = false, want true")
	}
	if a.Equal(c) {
		t.Fatalf("a.Equal(c) = true, want false")
	}
	if NewOspfAreaTypeNormal().Equal(NewOspfAreaTypeStub(0)) {
		t.Fatalf("normal.Equal(stub(0)) = true, want false")
	}
}

func TestOspfAreaTypeReaderRoundTripViaRouter(t *testing.T) {
	// Attach an NSSA area with default_metric=42 and read it back.
	r := routerWithOspfArea(t, 7, AreaNssa, 42)
	areaType, ok, err := r.OspfAreaType(7)
	if err != nil {
		t.Fatalf("OspfAreaType(7): %v", err)
	}
	if !ok {
		t.Fatalf("OspfAreaType(7): not attached")
	}
	if areaType.Kind() != AreaNssa {
		t.Fatalf("areaType.Kind() = %d, want %d", areaType.Kind(), AreaNssa)
	}
	if !areaType.IsNssa() {
		t.Fatalf("areaType.IsNssa() = false, want true")
	}
	if !areaType.IsStubby() {
		t.Fatalf("areaType.IsStubby() = false, want true")
	}
	if areaType.NoSummary() {
		t.Fatalf("areaType.NoSummary() = true, want false")
	}
	if dm, ok := areaType.DefaultMetric(); !ok || dm != 42 {
		t.Fatalf("areaType.DefaultMetric() = (%d, %v), want (42, true)", dm, ok)
	}
	// Unknown area returns (_, false, nil).
	if _, ok, err := r.OspfAreaType(999); err != nil || ok {
		t.Fatalf("OspfAreaType(999): ok=%v err=%v", ok, err)
	}
}

func TestOspfSetAreaTypeRoundTripsDefaultMetric(t *testing.T) {
	// Start with a Normal area; the struct-value setter carries
	// the new default_metric through.
	r := routerWithOspfArea(t, 5, AreaNormal, 0)
	if ok, err := r.OspfSetAreaType(5, NewOspfAreaTypeNssa(42)); err != nil || !ok {
		t.Fatalf("OspfSetAreaType(5, nssa(42)): ok=%v err=%v", ok, err)
	}
	areaType, ok, err := r.OspfAreaType(5)
	if err != nil || !ok {
		t.Fatalf("OspfAreaType(5): ok=%v err=%v", ok, err)
	}
	if areaType.Kind() != AreaNssa {
		t.Fatalf("areaType.Kind() = %d, want %d", areaType.Kind(), AreaNssa)
	}
	if dm, ok := areaType.DefaultMetric(); !ok || dm != 42 {
		t.Fatalf("areaType.DefaultMetric() = (%d, %v), want (42, true)", dm, ok)
	}
	// Convert to totally-NSSA(7).
	if ok, err := r.OspfSetAreaType(5, NewOspfAreaTypeNssaNoSummary(7)); err != nil || !ok {
		t.Fatalf("OspfSetAreaType(5, nssa_no_summary(7)): ok=%v err=%v", ok, err)
	}
	areaType, ok, err = r.OspfAreaType(5)
	if err != nil || !ok {
		t.Fatalf("OspfAreaType(5): ok=%v err=%v", ok, err)
	}
	if areaType.Kind() != AreaNssaNoSummary {
		t.Fatalf("areaType.Kind() = %d, want %d", areaType.Kind(), AreaNssaNoSummary)
	}
	if !areaType.NoSummary() {
		t.Fatalf("areaType.NoSummary() = false, want true")
	}
	if dm, ok := areaType.DefaultMetric(); !ok || dm != 7 {
		t.Fatalf("areaType.DefaultMetric() = (%d, %v), want (7, true)", dm, ok)
	}
	// No-op conversion returns false.
	if ok, err := r.OspfSetAreaType(5, NewOspfAreaTypeNssaNoSummary(7)); err != nil || ok {
		t.Fatalf("no-op conversion: ok=%v err=%v", ok, err)
	}
	// Backbone cannot become stub.
	bb := routerWithOspfArea(t, 0, AreaNormal, 0)
	if ok, err := bb.OspfSetAreaType(0, NewOspfAreaTypeStub(1)); err != nil || ok {
		t.Fatalf("backbone to stub: ok=%v err=%v", ok, err)
	}
}

// TestOspfSetAreaTypeKindRoundTrip exercises the legacy i32-kind
// setter (lr_router_ospf_set_area_type). It must convert an
// attached Normal area to NSSA, but it always drops the
// border-router-injected default-route metric to 0 (the legacy
// entry point has no slot for the metric).
func TestOspfSetAreaTypeKindRoundTrip(t *testing.T) {
	r := routerWithOspfArea(t, 7, AreaNormal, 0)
	if ok, err := r.OspfSetAreaTypeKind(7, AreaNssa); err != nil || !ok {
		t.Fatalf("OspfSetAreaTypeKind(7, nssa): ok=%v err=%v", ok, err)
	}
	areaType, ok, err := r.OspfAreaType(7)
	if err != nil || !ok {
		t.Fatalf("OspfAreaType(7): ok=%v err=%v", ok, err)
	}
	if areaType.Kind() != AreaNssa {
		t.Fatalf("areaType.Kind() = %d, want %d", areaType.Kind(), AreaNssa)
	}
	// The legacy i32-kind setter drops the default_metric to 0.
	if dm, ok := areaType.DefaultMetric(); !ok || dm != 0 {
		t.Fatalf("default_metric = (%d, %v), want (0, true) — legacy kind setter drops metric", dm, ok)
	}
	// No-op conversion (same kind) returns false.
	if ok, err := r.OspfSetAreaTypeKind(7, AreaNssa); err != nil || ok {
		t.Fatalf("no-op OspfSetAreaTypeKind: ok=%v err=%v", ok, err)
	}
	// Backbone cannot become stub via the legacy setter either.
	bb := routerWithOspfArea(t, 0, AreaNormal, 0)
	if ok, err := bb.OspfSetAreaTypeKind(0, AreaStub); err != nil || ok {
		t.Fatalf("backbone to stub (legacy): ok=%v err=%v", ok, err)
	}
}

// TestOspfRouterLsaFlagsReaderRoundTrip covers the C ABI reader for
// `DefaultRouter::ospf_router_lsa_flags` (RFC 2328 §A.4.2 V/E/B bits):
// empty area reads back V=0/E=0/B=0; unknown area reads back (_, false, nil);
// redistribute flips the E-bit on.
func TestOspfRouterLsaFlagsReaderRoundTrip(t *testing.T) {
	r := routerWithOspfArea(t, 1, AreaNormal, 0)
	// Empty area: V=0, E=0, B=0.
	flags, ok, err := r.OspfRouterLsaFlags(1)
	if err != nil || !ok {
		t.Fatalf("OspfRouterLsaFlags(1): ok=%v err=%v", ok, err)
	}
	if flags.VirtualLink || flags.Asbr || flags.Border {
		t.Fatalf("empty area flags = %+v, want all false", flags)
	}
	// Unknown area: (_, false, nil).
	if _, ok, err := r.OspfRouterLsaFlags(999); err != nil || ok {
		t.Fatalf("OspfRouterLsaFlags(999): ok=%v err=%v", ok, err)
	}
	// Redistribute one v2 /24: E-bit flips on.
	addr := [4]byte{10, 0, 0, 0}
	dest, err := NewOspfExternalDestV4(addr, 24, 100, OspfExternalType1)
	if err != nil {
		t.Fatalf("NewOspfExternalDestV4: %v", err)
	}
	defer dest.Free()
	if ok, err := r.OspfRedistribute(dest); err != nil || !ok {
		t.Fatalf("OspfRedistribute: ok=%v err=%v", ok, err)
	}
	flags, ok, err = r.OspfRouterLsaFlags(1)
	if err != nil || !ok {
		t.Fatalf("OspfRouterLsaFlags after redist: ok=%v err=%v", ok, err)
	}
	if flags.VirtualLink {
		t.Fatalf("V-bit still set: %+v", flags)
	}
	if !flags.Asbr {
		t.Fatalf("E-bit not set after redistribute: %+v", flags)
	}
	if flags.Border {
		t.Fatalf("B-bit set on single-area router: %+v", flags)
	}
}

// TestSetOspfDrStateRoundTrip exercises the DR/BDR election reporting
// (RFC 2328 §9.4 step 7): the no-op push (dr=bdr=0, matching the
// runtime's initialised state) returns changed=false; a real first
// push returns changed=true; the same pair again returns changed=false;
// an unknown session returns an error.
func TestSetOspfDrStateRoundTrip(t *testing.T) {
	r := routerWithOspfArea(t, 0, AreaNormal, 0)
	// Recover the session handle via the inspection surface.
	summaries, err := r.SessionSummaries()
	if err != nil {
		t.Fatalf("SessionSummaries: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("SessionSummaries len = %d, want 1", len(summaries))
	}
	session := summaries[0].Handle
	// No-op push (0/0): changed=false.
	if changed, err := r.SetOspfDrState(session, 0, 0); err != nil || changed {
		t.Fatalf("SetOspfDrState(0,0): changed=%v err=%v", changed, err)
	}
	// First real pair: changed=true.
	if changed, err := r.SetOspfDrState(session, 0xC0A80001, 0xC0A80002); err != nil || !changed {
		t.Fatalf("SetOspfDrState(0xC0A80001, 0xC0A80002): changed=%v err=%v", changed, err)
	}
	// Same pair again: changed=false.
	if changed, err := r.SetOspfDrState(session, 0xC0A80001, 0xC0A80002); err != nil || changed {
		t.Fatalf("SetOspfDrState(again): changed=%v err=%v", changed, err)
	}
	// Unknown session: error.
	if _, err := r.SetOspfDrState(999, 1, 2); err == nil {
		t.Fatalf("SetOspfDrState(999, ...): err=nil, want error")
	}
}

// TestRouterReadersRoundTrip covers the simple router-wide readers
// (`EnforceFirstAs`, `AddPathMaxPaths`, `RoaValidateEnabled`) — the
// reader side of the existing setters. Each reader defaults to the
// documented value (false / 1 / false) and tracks the setter's
// changes.
func TestRouterReadersRoundTrip(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	// EnforceFirstAs: default false.
	if r.EnforceFirstAs() {
		t.Fatalf("EnforceFirstAs default = true, want false")
	}
	if err := r.SetEnforceFirstAs(true); err != nil {
		t.Fatalf("SetEnforceFirstAs(true): %v", err)
	}
	if !r.EnforceFirstAs() {
		t.Fatalf("EnforceFirstAs after SetEnforceFirstAs(true) = false, want true")
	}
	if err := r.SetEnforceFirstAs(false); err != nil {
		t.Fatalf("SetEnforceFirstAs(false): %v", err)
	}
	if r.EnforceFirstAs() {
		t.Fatalf("EnforceFirstAs after SetEnforceFirstAs(false) = true, want false")
	}

	// AddPathMaxPaths: default 1.
	if got := r.AddPathMaxPaths(); got != 1 {
		t.Fatalf("AddPathMaxPaths default = %d, want 1", got)
	}
	if err := r.SetAddPathMaxPaths(4); err != nil {
		t.Fatalf("SetAddPathMaxPaths(4): %v", err)
	}
	if got := r.AddPathMaxPaths(); got != 4 {
		t.Fatalf("AddPathMaxPaths after SetAddPathMaxPaths(4) = %d, want 4", got)
	}
	// Setter clamps 0 to 1.
	if err := r.SetAddPathMaxPaths(0); err != nil {
		t.Fatalf("SetAddPathMaxPaths(0): %v", err)
	}
	if got := r.AddPathMaxPaths(); got != 1 {
		t.Fatalf("AddPathMaxPaths after SetAddPathMaxPaths(0) = %d, want 1 (clamped)", got)
	}

	// RoaValidateEnabled: default false.
	if r.RoaValidateEnabled() {
		t.Fatalf("RoaValidateEnabled default = true, want false")
	}
	if err := r.SetROAValidate(true); err != nil {
		t.Fatalf("SetROAValidate(true): %v", err)
	}
	if !r.RoaValidateEnabled() {
		t.Fatalf("RoaValidateEnabled after SetROAValidate(true) = false, want true")
	}
	if err := r.SetROAValidate(false); err != nil {
		t.Fatalf("SetROAValidate(false): %v", err)
	}
	if r.RoaValidateEnabled() {
		t.Fatalf("RoaValidateEnabled after SetROAValidate(false) = true, want false")
	}
}
