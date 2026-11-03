// Foundational lr-core types tests — BoxedIpAddr, NlriFamily,
// RawRouteKey, Preference, ReadBuf, WriteBuf, TimerQueue, MemoryConn,
// CRC/Fletcher/OSPF LSA checksum, Instant/Duration helpers.
//
// These tests exercise the Go binding through the public
// NewBoxedIPv4 / NewNlriFamilyIPv4Unicast / NewRawRouteKey /
// NewPreference / NewReadBuf / NewWriteBuf / NewTimerQueue /
// NewMemoryConn API and mirror the C ABI tests in
// crates/lr-ffi/src/core.rs, core_buf.rs, core_extras.rs,
// core_extras_2.rs, memory_conn.rs.

package librouting

import (
	"bytes"
	"testing"
)

// ---- IpAddr extras (already in core.go) ----

func TestIpAddrV4Octets(t *testing.T) {
	a := NewIpAddrV4([4]byte{10, 0, 0, 1})
	if !a.IsIPv4() {
		t.Fatalf("expected IPv4, got IPv6")
	}
	o := a.Octets4()
	if o != [4]byte{10, 0, 0, 1} {
		t.Fatalf("octets4 mismatch: %v", o)
	}
}

func TestIpAddrV6IsUnspecified(t *testing.T) {
	a := NewIpAddrV6([16]byte{})
	if !a.IsIPv6() {
		t.Fatalf("expected IPv6")
	}
	if !a.IsUnspecified() {
		t.Fatalf("expected unspecified")
	}
}

func TestIpAddrV4Multicast(t *testing.T) {
	a := NewIpAddrV4([4]byte{224, 0, 0, 1})
	if !a.IsMulticast() {
		t.Fatalf("expected multicast")
	}
}

func TestIpAddrV6Multicast(t *testing.T) {
	var o [16]byte
	o[0] = 0xff
	o[1] = 0x02
	a := NewIpAddrV6(o)
	if !a.IsMulticast() {
		t.Fatalf("expected multicast")
	}
}

// ---- CorePrefix ----

func TestCorePrefixV4NetworkZerosHostBits(t *testing.T) {
	p := NewCorePrefixV4([4]byte{10, 0, 0, 5}, 24)
	net, err := p.Network()
	if err != nil {
		t.Fatalf("Network: %v", err)
	}
	o := net.Octets4()
	if o != [4]byte{10, 0, 0, 0} {
		t.Fatalf("network mismatch: %v", o)
	}
}

func TestCorePrefixV4ContainsBitLevel(t *testing.T) {
	p := NewCorePrefixV4([4]byte{10, 0, 0, 0}, 24)
	if !p.Contains(NewIpAddrV4([4]byte{10, 0, 0, 5})) {
		t.Fatalf("expected contains 10.0.0.5")
	}
	if p.Contains(NewIpAddrV4([4]byte{10, 0, 1, 1})) {
		t.Fatalf("expected NOT to contain 10.0.1.1")
	}
}

func TestCorePrefixV4ContainsPrefixBitLevel(t *testing.T) {
	outer := NewCorePrefixV4([4]byte{10, 0, 0, 0}, 16)
	inner := NewCorePrefixV4([4]byte{10, 0, 5, 0}, 24)
	notInner := NewCorePrefixV4([4]byte{10, 1, 0, 0}, 24)
	if !outer.ContainsPrefix(inner) {
		t.Fatalf("expected outer contains inner")
	}
	if outer.ContainsPrefix(notInner) {
		t.Fatalf("expected outer NOT to contain notInner")
	}
}

// ---- Asn extras ----

func TestAsnAsU16(t *testing.T) {
	a := NewAsn(100)
	if v := a.AsU16(); v != 100 {
		t.Fatalf("AsU16: expected 100, got %d", v)
	}
	b := NewAsn(70000)
	if v := b.AsU16(); v != 0 {
		t.Fatalf("AsU16: expected 0 (AS_TRANS), got %d", v)
	}
}

func TestAsnIsAS23456(t *testing.T) {
	a := NewAsn(23456)
	if !a.IsAS23456() {
		t.Fatalf("expected IsAS23456")
	}
}

// ---- RouterID ----

func TestRouterIDRoundTrip(t *testing.T) {
	r := NewRouterIDFromV4([4]byte{10, 0, 0, 1})
	o, err := r.ToV4Bytes()
	if err != nil {
		t.Fatalf("ToV4Bytes: %v", err)
	}
	if o != [4]byte{10, 0, 0, 1} {
		t.Fatalf("ToV4Bytes mismatch: %v", o)
	}
}

// ---- Protocol helpers ----

func TestProtocolBirdName(t *testing.T) {
	cases := []struct {
		proto uint8
		want  string
	}{
		{ProtocolBgp, "bgp"},
		{ProtocolOspfv2, "ospf"},
		{ProtocolOspfv3, "ospf3"},
		{ProtocolBabel, "babel"},
		{ProtocolStatic, "static"},
		{ProtocolConnected, "direct"},
		{ProtocolOther, "unknown"},
	}
	for _, c := range cases {
		got, err := ProtocolBirdName(c.proto)
		if err != nil {
			t.Fatalf("ProtocolBirdName(%d): %v", c.proto, err)
		}
		if got != c.want {
			t.Fatalf("ProtocolBirdName(%d): expected %q, got %q", c.proto, c.want, got)
		}
	}
}

func TestProtocolDefaultAdminDistance(t *testing.T) {
	if v := ProtocolDefaultAdminDistance(ProtocolBgp); v != 20 {
		t.Fatalf("BGP admin distance: expected 20, got %d", v)
	}
	if v := ProtocolDefaultAdminDistance(ProtocolOspfv2); v != 110 {
		t.Fatalf("OSPF admin distance: expected 110, got %d", v)
	}
}

// ---- BoxedIpAddr ----

func TestBoxedIpAddrV4RoundTrip(t *testing.T) {
	a, err := NewBoxedIPv4([4]byte{10, 0, 0, 1})
	if err != nil {
		t.Fatalf("NewBoxedIPv4: %v", err)
	}
	defer a.Close()
	if a.IsIPv4MappedIPv6() {
		t.Fatalf("V4 should not be IPv4-mapped IPv6")
	}
}

func TestBoxedIpAddrToIPv4Mapped(t *testing.T) {
	a, err := NewBoxedIPv4([4]byte{10, 0, 0, 1})
	if err != nil {
		t.Fatalf("NewBoxedIPv4: %v", err)
	}
	defer a.Close()
	mapped := a.ToIPv4Mapped()
	if mapped == nil {
		t.Fatalf("expected mapped, got nil")
	}
	defer mapped.Close()
	if !mapped.IsIPv4MappedIPv6() {
		t.Fatalf("expected IPv4-mapped IPv6")
	}
}

func TestBoxedIpAddrToIPv4MappedReturnsNilForV6(t *testing.T) {
	a, err := NewBoxedIPv6([16]byte{0xfe, 0x80})
	if err != nil {
		t.Fatalf("NewBoxedIPv6: %v", err)
	}
	defer a.Close()
	if mapped := a.ToIPv4Mapped(); mapped != nil {
		t.Fatalf("expected nil for V6 input, got %v", mapped)
		mapped.Close()
	}
}

func TestBoxedIPFromBytes(t *testing.T) {
	a, err := NewBoxedIPFromBytes([]byte{10, 0, 0, 1})
	if err != nil {
		t.Fatalf("V4: %v", err)
	}
	defer a.Close()
	b, err := NewBoxedIPFromBytes([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("V6: %v", err)
	}
	defer b.Close()
	if _, err := NewBoxedIPFromBytes([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for bad length")
	}
}

// ---- NlriFamily ----

func TestNlriFamilyConstructors(t *testing.T) {
	tests := []struct {
		name  string
		ctor  func() NlriFamily
		afi   uint16
		safi  uint8
		ipv4  bool
		ipv6  bool
		ls    bool
		lsvpn bool
	}{
		{"ipv4_unicast", NlriFamilyIPv4Unicast, 1, 1, true, false, false, false},
		{"ipv6_unicast", NlriFamilyIPv6Unicast, 2, 1, false, true, false, false},
		{"ipv4_multicast", NlriFamilyIPv4Multicast, 1, 2, true, false, false, false},
		{"ipv4_mpls_vpn", NlriFamilyIPv4MplsVpn, 1, 128, true, false, false, false},
		{"ipv6_mpls_vpn", NlriFamilyIPv6MplsVpn, 2, 128, false, true, false, false},
		{"ipv4_labeled_unicast", NlriFamilyIPv4LabeledUnicast, 1, 4, true, false, false, false},
		{"ipv6_labeled_unicast", NlriFamilyIPv6LabeledUnicast, 2, 4, false, true, false, false},
		{"bgp_ls", NlriFamilyBgpLs, 16388, 71, false, false, true, false},
		{"bgp_ls_vpn", NlriFamilyBgpLsVpn, 16388, 72, false, false, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.ctor()
			if f.Afi() != tc.afi {
				t.Fatalf("afi: expected %d, got %d", tc.afi, f.Afi())
			}
			if f.Safi() != tc.safi {
				t.Fatalf("safi: expected %d, got %d", tc.safi, f.Safi())
			}
			if f.IsIPv4() != tc.ipv4 {
				t.Fatalf("IsIPv4: expected %v, got %v", tc.ipv4, f.IsIPv4())
			}
			if f.IsIPv6() != tc.ipv6 {
				t.Fatalf("IsIPv6: expected %v, got %v", tc.ipv6, f.IsIPv6())
			}
			if f.IsBgpLs() != tc.ls {
				t.Fatalf("IsBgpLs: expected %v, got %v", tc.ls, f.IsBgpLs())
			}
			if f.IsBgpLsVpn() != tc.lsvpn {
				t.Fatalf("IsBgpLsVpn: expected %v, got %v", tc.lsvpn, f.IsBgpLsVpn())
			}
		})
	}
}

func TestNlriFamilyFromAddrV4(t *testing.T) {
	a, err := NewBoxedIPv4([4]byte{10, 0, 0, 1})
	if err != nil {
		t.Fatalf("NewBoxedIPv4: %v", err)
	}
	defer a.Close()
	f, err := NlriFamilyFromAddr(a)
	if err != nil {
		t.Fatalf("NlriFamilyFromAddr: %v", err)
	}
	if f.Afi() != 1 || f.Safi() != 1 {
		t.Fatalf("expected (1, 1), got (%d, %d)", f.Afi(), f.Safi())
	}
}

func TestNlriFamilyFromAddrV6(t *testing.T) {
	a, err := NewBoxedIPv6([16]byte{0xfe, 0x80})
	if err != nil {
		t.Fatalf("NewBoxedIPv6: %v", err)
	}
	defer a.Close()
	f, err := NlriFamilyFromAddr(a)
	if err != nil {
		t.Fatalf("NlriFamilyFromAddr: %v", err)
	}
	if f.Afi() != 2 || f.Safi() != 1 {
		t.Fatalf("expected (2, 1), got (%d, %d)", f.Afi(), f.Safi())
	}
}

// ---- RawRouteKey ----

func TestRawRouteKeyNew(t *testing.T) {
	p := NewCorePrefixV4([4]byte{10, 0, 0, 0}, 24)
	k, err := NewRawRouteKey(p, 0x0101)
	if err != nil {
		t.Fatalf("NewRawRouteKey: %v", err)
	}
	if k.AfiSafi() != 0x0101 {
		t.Fatalf("AfiSafi: expected 0x0101, got 0x%04x", k.AfiSafi())
	}
	if k.HasSource() {
		t.Fatalf("expected no source")
	}
}

func TestRawRouteKeyWithSource(t *testing.T) {
	p := NewCorePrefixV4([4]byte{10, 0, 0, 0}, 24)
	s := NewCorePrefixV4([4]byte{192, 168, 0, 0}, 24)
	k, err := NewRawRouteKeyWithSource(p, 0x0101, s)
	if err != nil {
		t.Fatalf("NewRawRouteKeyWithSource: %v", err)
	}
	if !k.HasSource() {
		t.Fatalf("expected source")
	}
	if !k.SourcePrefix().Addr.IsIPv4() {
		t.Fatalf("expected source to be IPv4")
	}
}

// ---- Preference ----

func TestPreferenceNew(t *testing.T) {
	p := NewPreference(20, 100)
	if p.AdminDistance != 20 || p.Metric != 100 {
		t.Fatalf("expected (20, 100), got (%d, %d)", p.AdminDistance, p.Metric)
	}
}

// ---- Instant / Duration ----

func TestInstantRoundTripSecs(t *testing.T) {
	i := InstantFromSecs(5)
	if InstantAsSecs(i) != 5 {
		t.Fatalf("expected 5 secs, got %d", InstantAsSecs(i))
	}
	if InstantAsMillis(i) != 5000 {
		t.Fatalf("expected 5000 ms, got %d", InstantAsMillis(i))
	}
}

func TestInstantRoundTripMillis(t *testing.T) {
	i := InstantFromMillis(1500)
	if InstantAsSecs(i) != 1 {
		t.Fatalf("expected 1 sec, got %d", InstantAsSecs(i))
	}
	if InstantAsMillis(i) != 1500 {
		t.Fatalf("expected 1500 ms, got %d", InstantAsMillis(i))
	}
}

func TestInstantSaturatingSub(t *testing.T) {
	a := InstantFromSecs(5)
	b := InstantFromSecs(8)
	if v := InstantSaturatingSub(a, b); v != 3000 {
		t.Fatalf("expected 3000, got %d", v)
	}
	if v := InstantSaturatingSub(b, a); v != 0 {
		t.Fatalf("expected 0 (clamped), got %d", v)
	}
}

func TestInstantCheckedAdd(t *testing.T) {
	i := InstantFromSecs(5)
	j := InstantCheckedAdd(i, 1000)
	if InstantAsSecs(j) != 6 {
		t.Fatalf("expected 6 secs, got %d", InstantAsSecs(j))
	}
}

func TestInstantCheckedSubUnderflow(t *testing.T) {
	a := InstantFromSecs(5)
	b := InstantFromSecs(8)
	if _, ok := InstantCheckedSub(a, b); ok {
		t.Fatalf("expected underflow -> ok=false")
	}
}

func TestInstantCheckedSubSuccess(t *testing.T) {
	a := InstantFromSecs(8)
	b := InstantFromSecs(5)
	v, ok := InstantCheckedSub(a, b)
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if v != 3000 {
		t.Fatalf("expected 3000, got %d", v)
	}
}

func TestDurationRoundTripSecs(t *testing.T) {
	d := DurationFromSecs(5)
	if DurationAsSecs(d) != 5 {
		t.Fatalf("expected 5, got %d", DurationAsSecs(d))
	}
	if DurationAsMillis(d) != 5000 {
		t.Fatalf("expected 5000, got %d", DurationAsMillis(d))
	}
}

func TestDurationCheckedAdd(t *testing.T) {
	d := DurationFromMillis(1000)
	if v := DurationAsMillis(DurationCheckedAdd(d, 500)); v != 1500 {
		t.Fatalf("expected 1500, got %d", v)
	}
}

// ---- CRC / Fletcher / OSPF LSA checksum ----

func TestCRC16ARCKnownValue(t *testing.T) {
	// CRC-16/ARC of "123456789" is 0xBB3D
	if v := CRC16ARC([]byte("123456789")); v != 0xBB3D {
		t.Fatalf("expected 0xBB3D, got 0x%04x", v)
	}
}

func TestCRC16ARCEmpty(t *testing.T) {
	if v := CRC16ARC(nil); v != 0 {
		t.Fatalf("expected 0, got 0x%04x", v)
	}
}

func TestCRC32CKnownValue(t *testing.T) {
	// CRC-32C of "123456789" is 0xE3069283
	if v := CRC32C([]byte("123456789")); v != 0xE3069283 {
		t.Fatalf("expected 0xE3069283, got 0x%08x", v)
	}
}

func TestCRC32CEmpty(t *testing.T) {
	if v := CRC32C(nil); v != 0 {
		t.Fatalf("expected 0, got 0x%08x", v)
	}
}

func TestFletcher32Empty(t *testing.T) {
	if v := Fletcher32(nil); v != 0 {
		t.Fatalf("expected 0, got 0x%08x", v)
	}
}

func TestFletcher32NonEmpty(t *testing.T) {
	if v := Fletcher32([]byte("abcdefgh")); v == 0 {
		t.Fatalf("expected non-zero, got 0")
	}
}

func TestOspfLsaChecksumShortReturnsZero(t *testing.T) {
	if v := OspfLsaChecksum(make([]byte, 19)); v != 0 {
		t.Fatalf("expected 0, got 0x%04x", v)
	}
}

func TestOspfLsaChecksumOkShortReturnsFalse(t *testing.T) {
	if OspfLsaChecksumOk(make([]byte, 19)) {
		t.Fatalf("expected false")
	}
}

func TestOspfLsaChecksumRoundTrip(t *testing.T) {
	// Construct a minimal LSA-like 20-byte header with checksum zeroed,
	// compute, patch in, verify.
	lsa := make([]byte, 20)
	lsa[0] = 0x01
	cs := OspfLsaChecksum(lsa)
	lsa[16] = byte((cs >> 8) & 0xFF)
	lsa[17] = byte(cs & 0xFF)
	if !OspfLsaChecksumOk(lsa) {
		t.Fatalf("expected checksum ok after patch")
	}
}

// ---- ReadBuf ----

func TestReadBufNewAndRemaining(t *testing.T) {
	rb, err := NewReadBuf([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("NewReadBuf: %v", err)
	}
	defer rb.Close()
	if rb.Position() != 0 {
		t.Fatalf("position: expected 0, got %d", rb.Position())
	}
	if rb.Remaining() != 4 {
		t.Fatalf("remaining: expected 4, got %d", rb.Remaining())
	}
}

func TestReadBufGetU8(t *testing.T) {
	rb, err := NewReadBuf([]byte{1, 2})
	if err != nil {
		t.Fatalf("NewReadBuf: %v", err)
	}
	defer rb.Close()
	v, ok := rb.GetU8()
	if !ok || v != 1 {
		t.Fatalf("GetU8 #1: expected (1, true), got (%d, %v)", v, ok)
	}
	v, ok = rb.GetU8()
	if !ok || v != 2 {
		t.Fatalf("GetU8 #2: expected (2, true), got (%d, %v)", v, ok)
	}
	_, ok = rb.GetU8()
	if ok {
		t.Fatalf("expected ok=false after exhaustion")
	}
}

func TestReadBufGetU16BE(t *testing.T) {
	rb, _ := NewReadBuf([]byte{0x12, 0x34})
	defer rb.Close()
	v, ok := rb.GetU16BE()
	if !ok || v != 0x1234 {
		t.Fatalf("GetU16BE: expected 0x1234, got 0x%04x", v)
	}
}

func TestReadBufGetU32BE(t *testing.T) {
	rb, _ := NewReadBuf([]byte{0x12, 0x34, 0x56, 0x78})
	defer rb.Close()
	v, ok := rb.GetU32BE()
	if !ok || v != 0x12345678 {
		t.Fatalf("GetU32BE: expected 0x12345678, got 0x%08x", v)
	}
}

func TestReadBufGetU64BE(t *testing.T) {
	rb, _ := NewReadBuf([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	defer rb.Close()
	v, ok := rb.GetU64BE()
	if !ok || v != 0x0102030405060708 {
		t.Fatalf("GetU64BE: expected 0x0102030405060708, got 0x%016x", v)
	}
}

func TestReadBufGetBytes(t *testing.T) {
	rb, _ := NewReadBuf([]byte("hello world"))
	defer rb.Close()
	b, ok := rb.GetBytes(5)
	if !ok || !bytes.Equal(b, []byte("hello")) {
		t.Fatalf("GetBytes: expected 'hello', got %q", string(b))
	}
	if rb.Position() != 5 {
		t.Fatalf("position: expected 5, got %d", rb.Position())
	}
}

func TestReadBufPeekU8(t *testing.T) {
	rb, _ := NewReadBuf([]byte{0x42})
	defer rb.Close()
	v, ok := rb.PeekU8()
	if !ok || v != 0x42 {
		t.Fatalf("PeekU8: expected 0x42, got 0x%02x", v)
	}
	if rb.Position() != 0 {
		t.Fatalf("position should not advance on peek")
	}
}

func TestReadBufAdvance(t *testing.T) {
	rb, _ := NewReadBuf([]byte{1, 2, 3})
	defer rb.Close()
	if err := rb.Advance(2); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	v, ok := rb.GetU8()
	if !ok || v != 3 {
		t.Fatalf("after Advance, GetU8: expected 3, got %d", v)
	}
}

func TestReadBufChunk(t *testing.T) {
	rb, _ := NewReadBuf([]byte("hello"))
	defer rb.Close()
	b, err := rb.Chunk()
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if !bytes.Equal(b, []byte("hello")) {
		t.Fatalf("Chunk: expected 'hello', got %q", string(b))
	}
	if rb.Position() != 0 {
		t.Fatalf("Chunk should not advance position")
	}
}

// ---- WriteBuf ----

func TestWriteBufPutU8(t *testing.T) {
	wb, err := NewWriteBuf(8)
	if err != nil {
		t.Fatalf("NewWriteBuf: %v", err)
	}
	defer wb.Close()
	if err := wb.PutU8(0x42); err != nil {
		t.Fatalf("PutU8: %v", err)
	}
	if wb.Position() != 1 {
		t.Fatalf("position: expected 1, got %d", wb.Position())
	}
	b, err := wb.Written()
	if err != nil {
		t.Fatalf("Written: %v", err)
	}
	if !bytes.Equal(b, []byte{0x42}) {
		t.Fatalf("Written: expected [0x42], got %v", b)
	}
}

func TestWriteBufPutU16BE(t *testing.T) {
	wb, _ := NewWriteBuf(8)
	defer wb.Close()
	wb.PutU16BE(0x1234)
	b, _ := wb.Written()
	if !bytes.Equal(b, []byte{0x12, 0x34}) {
		t.Fatalf("Written: expected [0x12,0x34], got %v", b)
	}
}

func TestWriteBufPutU32BE(t *testing.T) {
	wb, _ := NewWriteBuf(8)
	defer wb.Close()
	wb.PutU32BE(0x12345678)
	b, _ := wb.Written()
	if !bytes.Equal(b, []byte{0x12, 0x34, 0x56, 0x78}) {
		t.Fatalf("Written: expected [0x12,0x34,0x56,0x78], got %v", b)
	}
}

func TestWriteBufPutU64BE(t *testing.T) {
	wb, _ := NewWriteBuf(16)
	defer wb.Close()
	wb.PutU64BE(0x0102030405060708)
	b, _ := wb.Written()
	if !bytes.Equal(b, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("Written: expected [1..8], got %v", b)
	}
}

func TestWriteBufPutBytes(t *testing.T) {
	wb, _ := NewWriteBuf(16)
	defer wb.Close()
	wb.PutBytes([]byte("hello"))
	b, _ := wb.Written()
	if !bytes.Equal(b, []byte("hello")) {
		t.Fatalf("Written: expected 'hello', got %q", string(b))
	}
}

func TestWriteBufPatchBackFillsLength(t *testing.T) {
	wb, _ := NewWriteBuf(64)
	defer wb.Close()
	wb.PutU16BE(0) // placeholder length
	wb.PutBytes([]byte("payload"))
	wb.Patch(0, []byte{0x00, 0x07}) // back-fill length = 7
	b, _ := wb.Written()
	if !bytes.Equal(b, []byte{0x00, 0x07, 'p', 'a', 'y', 'l', 'o', 'a', 'd'}) {
		t.Fatalf("patched: expected 0x00 0x07 payload, got %v", b)
	}
}

func TestWriteBufTakeBytesResets(t *testing.T) {
	wb, _ := NewWriteBuf(8)
	defer wb.Close()
	wb.PutU8(0x01)
	b, _ := wb.TakeBytes()
	if !bytes.Equal(b, []byte{0x01}) {
		t.Fatalf("TakeBytes: expected [0x01], got %v", b)
	}
	if wb.Position() != 0 {
		t.Fatalf("position after take: expected 0, got %d", wb.Position())
	}
}

func TestWriteBufReserveGrowsCapacity(t *testing.T) {
	wb, _ := NewWriteBuf(0)
	defer wb.Close()
	if err := wb.Reserve(64); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if wb.Capacity() < 64 {
		t.Fatalf("expected capacity >= 64, got %d", wb.Capacity())
	}
}

// ---- TimerQueue ----

func TestTimerQueueNewIsEmpty(t *testing.T) {
	tq, err := NewTimerQueue()
	if err != nil {
		t.Fatalf("NewTimerQueue: %v", err)
	}
	defer tq.Close()
	if !tq.IsEmpty() {
		t.Fatalf("expected empty")
	}
	if tq.Len() != 0 {
		t.Fatalf("expected len 0, got %d", tq.Len())
	}
}

func TestTimerQueueArmAndTick(t *testing.T) {
	tq, _ := NewTimerQueue()
	defer tq.Close()
	if err := tq.Arm(0, 1, TimerSpecOnce(100)); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if tq.Len() != 1 {
		t.Fatalf("expected len 1, got %d", tq.Len())
	}
	fired, err := tq.Tick(50)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(fired) != 0 {
		t.Fatalf("Tick(50): expected no fire, got %v", fired)
	}
	fired, err = tq.Tick(150)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(fired) != 1 || fired[0] != 1 {
		t.Fatalf("Tick(150): expected [1], got %v", fired)
	}
	if !tq.IsEmpty() {
		t.Fatalf("expected empty after fire")
	}
}

func TestTimerQueueCancel(t *testing.T) {
	tq, _ := NewTimerQueue()
	defer tq.Close()
	tq.Arm(0, 1, TimerSpecOnce(100))
	if err := tq.Cancel(1); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if !tq.IsEmpty() {
		t.Fatalf("expected empty after cancel")
	}
	fired, _ := tq.Tick(150)
	if len(fired) != 0 {
		t.Fatalf("expected no fire, got %v", fired)
	}
}

func TestTimerQueueCancelAll(t *testing.T) {
	tq, _ := NewTimerQueue()
	defer tq.Close()
	tq.Arm(0, 1, TimerSpecOnce(100))
	tq.Arm(0, 2, TimerSpecOnce(200))
	if err := tq.CancelAll(); err != nil {
		t.Fatalf("CancelAll: %v", err)
	}
	if !tq.IsEmpty() {
		t.Fatalf("expected empty")
	}
}

func TestTimerQueuePeriodicRefires(t *testing.T) {
	tq, _ := NewTimerQueue()
	defer tq.Close()
	tq.Arm(0, 1, TimerSpecPeriodic(100, 50))
	fired, _ := tq.Tick(100)
	if len(fired) != 1 || fired[0] != 1 {
		t.Fatalf("Tick(100): expected [1], got %v", fired)
	}
	fired, _ = tq.Tick(150)
	if len(fired) != 1 || fired[0] != 1 {
		t.Fatalf("Tick(150): expected [1], got %v", fired)
	}
}

func TestTimerQueueNextFireMs(t *testing.T) {
	tq, _ := NewTimerQueue()
	defer tq.Close()
	tq.Arm(0, 1, TimerSpecOnce(100))
	if v := tq.NextFireMs(); v != 100 {
		t.Fatalf("expected 100, got %d", v)
	}
}

// ---- MemoryConn ----

func TestMemoryConnPushAndTakeInput(t *testing.T) {
	c, err := NewMemoryConn()
	if err != nil {
		t.Fatalf("NewMemoryConn: %v", err)
	}
	defer c.Close()
	if err := c.PushInput([]byte("hello")); err != nil {
		t.Fatalf("PushInput: %v", err)
	}
	b, err := c.TakeInput()
	if err != nil {
		t.Fatalf("TakeInput: %v", err)
	}
	if !bytes.Equal(b, []byte("hello")) {
		t.Fatalf("TakeInput: expected 'hello', got %q", string(b))
	}
	// Second take is empty.
	b, _ = c.TakeInput()
	if len(b) != 0 {
		t.Fatalf("expected empty, got %q", string(b))
	}
}

func TestMemoryConnPutAndDrainOutput(t *testing.T) {
	c, _ := NewMemoryConn()
	defer c.Close()
	if err := c.PutOutput([]byte("world")); err != nil {
		t.Fatalf("PutOutput: %v", err)
	}
	b, err := c.DrainOutput()
	if err != nil {
		t.Fatalf("DrainOutput: %v", err)
	}
	if !bytes.Equal(b, []byte("world")) {
		t.Fatalf("DrainOutput: expected 'world', got %q", string(b))
	}
	// Second drain is empty.
	b, _ = c.DrainOutput()
	if len(b) != 0 {
		t.Fatalf("expected empty, got %q", string(b))
	}
}

func TestMemoryConnPairReturnsTwoConns(t *testing.T) {
	a, b, err := NewMemoryConnPair()
	if err != nil {
		t.Fatalf("NewMemoryConnPair: %v", err)
	}
	defer a.Close()
	defer b.Close()
	// Pair are independent (loopback wiring is the embedder's job).
	a.PushInput([]byte("foo"))
	got, _ := a.TakeInput()
	if !bytes.Equal(got, []byte("foo")) {
		t.Fatalf("a.TakeInput: expected 'foo', got %q", string(got))
	}
	b.PutOutput([]byte("bar"))
	got, _ = b.DrainOutput()
	if !bytes.Equal(got, []byte("bar")) {
		t.Fatalf("b.DrainOutput: expected 'bar', got %q", string(got))
	}
}

func TestMemoryConnEmptyDataIsNoOp(t *testing.T) {
	c, _ := NewMemoryConn()
	defer c.Close()
	if err := c.PushInput(nil); err != nil {
		t.Fatalf("PushInput(nil): %v", err)
	}
	b, _ := c.TakeInput()
	if len(b) != 0 {
		t.Fatalf("expected empty, got %q", string(b))
	}
}
