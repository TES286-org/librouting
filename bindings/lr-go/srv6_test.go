// Tests for the SRv6 structured types binding (RFC 8754 / RFC 8986).
//
// Mirrors the Rust-side `crates/lr-srv6/src/{sid,locator,srh,behavior}.rs`
// unit tests and the Python `bindings/lr-python/tests/test_srv6.py`.
// Every Rust pub-API method on `Sid`, `Locator`, `Srh` and `Behavior`
// is exercised through the Go class surface.

package librouting

import (
	"errors"
	"testing"
)

// ----------------------------------------------------------------------
// Constants — mirror lr_srv6::srh pub consts and the LR_SRV6_* defines
// in include/lr_ffi.h.
// ----------------------------------------------------------------------

func TestSRv6Constants(t *testing.T) {
	if SRv6RoutingTypeSRH != 4 {
		t.Errorf("SRv6RoutingTypeSRH = %d, want 4", SRv6RoutingTypeSRH)
	}
	if SRv6FlagOAM != 0x20 {
		t.Errorf("SRv6FlagOAM = 0x%02x, want 0x20", SRv6FlagOAM)
	}
	if SRv6FlagHMAC != 0x08 {
		t.Errorf("SRv6FlagHMAC = 0x%02x, want 0x08", SRv6FlagHMAC)
	}
	if SRv6SRHFixedLen != 8 {
		t.Errorf("SRv6SRHFixedLen = %d, want 8", SRv6SRHFixedLen)
	}
	if SRv6SRHSegmentLen != 16 {
		t.Errorf("SRv6SRHSegmentLen = %d, want 16", SRv6SRHSegmentLen)
	}
	if SRv6MaxSegments != 127 {
		t.Errorf("SRv6MaxSegments = %d, want 127", SRv6MaxSegments)
	}
	if SRv6MaxBlockBits != 128 {
		t.Errorf("SRv6MaxBlockBits = %d, want 128", SRv6MaxBlockBits)
	}
}

// ----------------------------------------------------------------------
// Sid — RFC 8754 §3.
// ----------------------------------------------------------------------

func TestSRv6SidFromOctetsRoundTrip(t *testing.T) {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(i)
	}
	sid, err := NewSRv6Sid(b)
	if err != nil {
		t.Fatalf("NewSRv6Sid: %v", err)
	}
	defer sid.Free()
	got, err := sid.Octets()
	if err != nil {
		t.Fatalf("Octets: %v", err)
	}
	if len(got) != 16 {
		t.Fatalf("Octets returned %d bytes, want 16", len(got))
	}
	for i := range b {
		if got[i] != b[i] {
			t.Fatalf("byte %d: got %02x, want %02x", i, got[i], b[i])
		}
	}
}

func TestSRv6SidFromOctetsWrongLength(t *testing.T) {
	if _, err := NewSRv6Sid(make([]byte, 15)); err == nil {
		t.Error("NewSRv6Sid(15 bytes) should have failed")
	}
	if _, err := NewSRv6Sid(make([]byte, 17)); err == nil {
		t.Error("NewSRv6Sid(17 bytes) should have failed")
	}
}

func TestSRv6SidUnspecified(t *testing.T) {
	sid := SRv6SidUnspecified()
	defer sid.Free()
	if !sid.IsUnspecified() {
		t.Error("Unspecified SID should be unspecified")
	}
	if got := sid.String(); got != "::" {
		t.Errorf("String() = %q, want %q", got, "::")
	}
}

func TestSRv6SidFromStrCanonical(t *testing.T) {
	sid, err := ParseSRv6Sid("fcbb:bb00:0:0:0:0:0:1")
	if err != nil {
		t.Fatalf("ParseSRv6Sid: %v", err)
	}
	defer sid.Free()
	// RFC 5952 §4.2.2: a run of >= 2 zero hextets MUST be compressed
	// to `::`. So `fcbb:bb00:0:0:0:0:0:1` is canonically
	// `fcbb:bb00::1`.
	if got := sid.String(); got != "fcbb:bb00::1" {
		t.Errorf("String() = %q, want %q", got, "fcbb:bb00::1")
	}
}

func TestSRv6SidFromStrCompressedForm(t *testing.T) {
	sid, err := ParseSRv6Sid("fcbb:bb00::1")
	if err != nil {
		t.Fatalf("ParseSRv6Sid: %v", err)
	}
	defer sid.Free()
	if got := sid.String(); got != "fcbb:bb00::1" {
		t.Errorf("String() = %q, want %q", got, "fcbb:bb00::1")
	}
	octets, _ := sid.Octets()
	want := []byte{0xFC, 0xBB, 0xBB, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	for i, b := range want {
		if octets[i] != b {
			t.Fatalf("byte %d: got %02x, want %02x", i, octets[i], b)
		}
	}
}

func TestSRv6SidFromStrUnspecified(t *testing.T) {
	sid, err := ParseSRv6Sid("::")
	if err != nil {
		t.Fatalf("ParseSRv6Sid(::): %v", err)
	}
	defer sid.Free()
	if !sid.IsUnspecified() {
		t.Error(":: should be unspecified")
	}
}

func TestSRv6SidParseErrorCodes(t *testing.T) {
	cases := []struct {
		input string
		code  int
	}{
		{"1::2::3", SRv6SidParseErrDoubleDoubleColon},
		{"1:2:3:4:5:6:7", SRv6SidParseErrWrongLength},     // 7 hextets, no ::
		{"1:2:3:4:5:6:7:8:9", SRv6SidParseErrWrongLength}, // 9 hextets
		{"1:2:3:4:5:6:7:8g", SRv6SidParseErrBadHextet},
		{"", SRv6SidParseErrEmpty},
	}
	for _, c := range cases {
		_, err := ParseSRv6Sid(c.input)
		if err == nil {
			t.Errorf("ParseSRv6Sid(%q) should have failed", c.input)
			continue
		}
		var parseErr *SRv6SidParseError
		if !errors.As(err, &parseErr) {
			t.Errorf("ParseSRv6Sid(%q) returned %T, want *SRv6SidParseError", c.input, err)
			continue
		}
		if parseErr.Code != c.code {
			t.Errorf("ParseSRv6Sid(%q) code = %d, want %d", c.input, parseErr.Code, c.code)
		}
	}
}

func TestSRv6SidLocatorSlice(t *testing.T) {
	sid, err := ParseSRv6Sid("fcbb:bb00:0:0:e1:0:0:1")
	if err != nil {
		t.Fatalf("ParseSRv6Sid: %v", err)
	}
	defer sid.Free()
	off, length, ok := sid.LocatorSlice(32)
	if !ok {
		t.Fatal("LocatorSlice(32) failed")
	}
	if off != 0 || length != 4 {
		t.Errorf("LocatorSlice(32) = (%d, %d), want (0, 4)", off, length)
	}
}

func TestSRv6SidLocatorSliceRejectsNonByteBits(t *testing.T) {
	sid := SRv6SidUnspecified()
	defer sid.Free()
	if _, _, ok := sid.LocatorSlice(33); ok {
		t.Error("LocatorSlice(33) should fail (not multiple of 8)")
	}
	if _, _, ok := sid.LocatorSlice(129); ok {
		t.Error("LocatorSlice(129) should fail (> 128)")
	}
	if _, _, ok := sid.LocatorSlice(0); !ok {
		t.Error("LocatorSlice(0) should succeed (degenerate but valid)")
	}
}

func TestSRv6SidIsInsideLocator(t *testing.T) {
	sid, _ := ParseSRv6Sid("fcbb:bb00:0:0:e1:0:0:1")
	defer sid.Free()
	loc := []byte{0xFC, 0xBB, 0xBB, 0x00}
	if !sid.IsInsideLocator(loc, 32) {
		t.Error("should be inside fcbb:bb00:../32")
	}
	other := []byte{0xFC, 0xBB, 0xBB, 0x01}
	if sid.IsInsideLocator(other, 32) {
		t.Error("should NOT be inside fcbb:bb01:../32")
	}
}

func TestSRv6SidIsInsideLocatorRejectsWrongLength(t *testing.T) {
	sid, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer sid.Free()
	// 3 bytes for block_bits=32 — must reject (need 4 bytes).
	loc := []byte{0xFC, 0xBB, 0xBB}
	if sid.IsInsideLocator(loc, 32) {
		t.Error("3-byte locator with block_bits=32 should be rejected")
	}
}

func TestSRv6SidFromLocatorTail(t *testing.T) {
	loc := []byte{0xFC, 0xBB, 0xBB, 0x00}
	tail := make([]byte, 12)
	sid, err := NewSRv6SidFromLocatorTail(loc, tail, 32)
	if err != nil {
		t.Fatalf("NewSRv6SidFromLocatorTail: %v", err)
	}
	defer sid.Free()
	octets, _ := sid.Octets()
	for i, b := range loc {
		if octets[i] != b {
			t.Fatalf("byte %d: got %02x, want %02x", i, octets[i], b)
		}
	}
	if !sid.IsInsideLocator(loc, 32) {
		t.Error("should be inside its own locator")
	}
}

func TestSRv6SidFromLocatorTailRejectsWrongWidths(t *testing.T) {
	loc := []byte{0xFC, 0xBB, 0xBB, 0x00} // 4 bytes
	tail := make([]byte, 11)              // 4 + 11 != 16
	if _, err := NewSRv6SidFromLocatorTail(loc, tail, 32); err == nil {
		t.Error("should reject 11-byte tail with 4-byte locator")
	}
}

// ----------------------------------------------------------------------
// Locator — RFC 8754 §3.1.
// ----------------------------------------------------------------------

func TestSRv6LocatorNewMasksHostBits(t *testing.T) {
	addr := []byte{0xFC, 0xBB, 0xBB, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0}
	loc, err := NewSRv6Locator(addr, 32)
	if err != nil {
		t.Fatalf("NewSRv6Locator: %v", err)
	}
	defer loc.Free()
	got, _ := loc.Addr()
	// The high 4 bytes are the locator; host bits should be zero.
	for i, b := range []byte{0xFC, 0xBB, 0xBB, 0x00} {
		if got[i] != b {
			t.Fatalf("byte %d: got %02x, want %02x", i, got[i], b)
		}
	}
	for i := 4; i < 16; i++ {
		if got[i] != 0 {
			t.Fatalf("host byte %d: got %02x, want 0", i, got[i])
		}
	}
	if loc.BlockBits() != 32 {
		t.Errorf("BlockBits = %d, want 32", loc.BlockBits())
	}
}

func TestSRv6LocatorNewRejectsTooManyBits(t *testing.T) {
	if _, err := NewSRv6Locator(make([]byte, 16), 129); err == nil {
		t.Error("NewSRv6Locator(129 bits) should fail")
	}
}

func TestSRv6LocatorFromStr(t *testing.T) {
	loc, err := ParseSRv6Locator("fcbb:bb00::/48")
	if err != nil {
		t.Fatalf("ParseSRv6Locator: %v", err)
	}
	defer loc.Free()
	if loc.BlockBits() != 48 {
		t.Errorf("BlockBits = %d, want 48", loc.BlockBits())
	}
	if got := loc.String(); got != "fcbb:bb00::/48" {
		t.Errorf("String() = %q, want %q", got, "fcbb:bb00::/48")
	}
}

func TestSRv6LocatorParseErrorCodes(t *testing.T) {
	// Missing /prefixlen.
	_, err := ParseSRv6Locator("fcbb:bb00::")
	if err == nil {
		t.Fatal("ParseSRv6Locator should have failed on missing /prefixlen")
	}
	var parseErr *SRv6LocatorParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *SRv6LocatorParseError, got %T", err)
	}
	if parseErr.Code != SRv6LocatorParseErrMissingPrefixLen {
		t.Errorf("code = %d, want %d", parseErr.Code, SRv6LocatorParseErrMissingPrefixLen)
	}
	// Bad prefix len.
	_, err = ParseSRv6Locator("fcbb:bb00::/999")
	if err == nil {
		t.Fatal("ParseSRv6Locator should have failed on /999")
	}
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *SRv6LocatorParseError, got %T", err)
	}
	if parseErr.Code != SRv6LocatorParseErrBadPrefixLen {
		t.Errorf("code = %d, want %d", parseErr.Code, SRv6LocatorParseErrBadPrefixLen)
	}
}

func TestSRv6LocatorFromSid(t *testing.T) {
	sid, _ := ParseSRv6Sid("fcbb:bb00:0:0:e1:0:0:1")
	defer sid.Free()
	loc, err := NewSRv6LocatorFromSid(sid, 32)
	if err != nil {
		t.Fatalf("NewSRv6LocatorFromSid: %v", err)
	}
	defer loc.Free()
	if loc.BlockBits() != 32 {
		t.Errorf("BlockBits = %d, want 32", loc.BlockBits())
	}
	addr, _ := loc.Addr()
	for i, b := range []byte{0xFC, 0xBB, 0xBB, 0x00} {
		if addr[i] != b {
			t.Fatalf("byte %d: got %02x, want %02x", i, addr[i], b)
		}
	}
}

func TestSRv6LocatorContainsSid(t *testing.T) {
	sid, _ := ParseSRv6Sid("fcbb:bb00:0:0:e1:0:0:1")
	defer sid.Free()
	loc, _ := ParseSRv6Locator("fcbb:bb00::/32")
	defer loc.Free()
	if !loc.ContainsSid(sid) {
		t.Error("should contain sid")
	}
	other, _ := ParseSRv6Sid("2001:db8::1")
	defer other.Free()
	if loc.ContainsSid(other) {
		t.Error("should NOT contain 2001:db8::1")
	}
}

func TestSRv6LocatorSidWithTail(t *testing.T) {
	loc, _ := ParseSRv6Locator("fcbb:bb00::/32")
	defer loc.Free()
	// The locator's block_bytes is 4; the tail's first 4 bytes are
	// overwritten by the locator, so put the meaningful tail byte at
	// index 4 (which becomes the FUNCT field's first byte).
	tail := make([]byte, 16)
	tail[4] = 0xE1
	sid, err := loc.SidWithTail(tail)
	if err != nil {
		t.Fatalf("SidWithTail: %v", err)
	}
	defer sid.Free()
	octets, _ := sid.Octets()
	for i, b := range []byte{0xFC, 0xBB, 0xBB, 0x00} {
		if octets[i] != b {
			t.Fatalf("byte %d: got %02x, want %02x", i, octets[i], b)
		}
	}
	if octets[4] != 0xE1 {
		t.Errorf("octets[4] = %02x, want 0xE1", octets[4])
	}
}

func TestSRv6LocatorSidWithTailRejectsWrongLength(t *testing.T) {
	loc, _ := ParseSRv6Locator("fcbb:bb00::/32")
	defer loc.Free()
	if _, err := loc.SidWithTail(make([]byte, 15)); err == nil {
		t.Error("SidWithTail(15 bytes) should fail")
	}
}

func TestSRv6LocatorSidWithIndex(t *testing.T) {
	loc, _ := ParseSRv6Locator("fcbb:bb00::/32")
	defer loc.Free()
	sid, err := loc.SidWithIndex(42)
	if err != nil {
		t.Fatalf("SidWithIndex: %v", err)
	}
	if sid == nil {
		t.Fatal("SidWithIndex returned nil")
	}
	defer sid.Free()
	octets, _ := sid.Octets()
	// The 4 bytes after the locator should be 42 in big-endian.
	want := []byte{0, 0, 0, 42}
	for i, b := range want {
		if octets[4+i] != b {
			t.Fatalf("byte %d: got %02x, want %02x", 4+i, octets[4+i], b)
		}
	}
}

func TestSRv6LocatorSidWithIndexReturnsNilWhenNoRoom(t *testing.T) {
	// block_bits=120 leaves only 1 byte — no room for a 4-byte function.
	loc, err := NewSRv6Locator(make([]byte, 16), 120)
	if err != nil {
		t.Fatalf("NewSRv6Locator: %v", err)
	}
	defer loc.Free()
	sid, err := loc.SidWithIndex(42)
	if err != nil {
		t.Fatalf("SidWithIndex: %v", err)
	}
	if sid != nil {
		t.Error("SidWithIndex should return nil when no room for a 4-byte function")
		sid.Free()
	}
}

func TestSRv6LocatorBlockBytesCeil(t *testing.T) {
	loc, _ := NewSRv6Locator(make([]byte, 16), 32)
	defer loc.Free()
	if loc.BlockBytes() != 4 {
		t.Errorf("BlockBytes(32) = %d, want 4", loc.BlockBytes())
	}
	loc2, _ := NewSRv6Locator(make([]byte, 16), 33)
	defer loc2.Free()
	if loc2.BlockBytes() != 5 {
		t.Errorf("BlockBytes(33) = %d, want 5", loc2.BlockBytes())
	}
}

// ----------------------------------------------------------------------
// Srh — RFC 8754 §2.
// ----------------------------------------------------------------------

func TestSRv6SrhNewTwoSegments(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, err := NewSRv6Srh([]any{s1, s2})
	if err != nil {
		t.Fatalf("NewSRv6Srh: %v", err)
	}
	defer srh.Free()
	if srh.SegmentCount() != 2 {
		t.Errorf("SegmentCount = %d, want 2", srh.SegmentCount())
	}
	if srh.LastEntry() != 1 {
		t.Errorf("LastEntry = %d, want 1", srh.LastEntry())
	}
	if srh.SegmentsLeft() != 1 {
		t.Errorf("SegmentsLeft = %d, want 1 (defaults to last_entry)", srh.SegmentsLeft())
	}
}

func TestSRv6SrhNewWithSegmentsLeft(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, err := NewSRv6SrhWithSegmentsLeft([]any{s1, s2}, 0)
	if err != nil {
		t.Fatalf("NewSRv6SrhWithSegmentsLeft: %v", err)
	}
	defer srh.Free()
	if srh.SegmentsLeft() != 0 {
		t.Errorf("SegmentsLeft = %d, want 0", srh.SegmentsLeft())
	}
	first, _ := srh.FirstSegment()
	firstOct, _ := s1.Octets()
	for i, b := range firstOct {
		if first[i] != b {
			t.Fatalf("FirstSegment byte %d: got %02x, want %02x", i, first[i], b)
		}
	}
}

func TestSRv6SrhNewRejectsEmpty(t *testing.T) {
	_, err := NewSRv6Srh(nil)
	if err == nil {
		t.Fatal("NewSRv6Srh(nil) should fail")
	}
	var srhErr *SRv6SrhError
	if !errors.As(err, &srhErr) {
		t.Fatalf("expected *SRv6SrhError, got %T", err)
	}
	if srhErr.Code != SRv6SRHErrEmptySegmentList {
		t.Errorf("code = %d, want %d", srhErr.Code, SRv6SRHErrEmptySegmentList)
	}
}

func TestSRv6SrhNewRejectsTooMany(t *testing.T) {
	sids := make([]any, SRv6MaxSegments+1)
	for i := range sids {
		sids[i] = make([]byte, 16)
	}
	_, err := NewSRv6Srh(sids)
	if err == nil {
		t.Fatal("NewSRv6Srh(128 sids) should fail")
	}
	var srhErr *SRv6SrhError
	if !errors.As(err, &srhErr) {
		t.Fatalf("expected *SRv6SrhError, got %T", err)
	}
	if srhErr.Code != SRv6SRHErrTooManySegments {
		t.Errorf("code = %d, want %d", srhErr.Code, SRv6SRHErrTooManySegments)
	}
}

func TestSRv6SrhBuilderSetters(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, err := NewSRv6Srh([]any{s1, s2})
	if err != nil {
		t.Fatalf("NewSRv6Srh: %v", err)
	}
	defer srh.Free()
	srh.WithNextHeader(59).WithFlags(SRv6FlagOAM).WithTag(0x1234)
	if _, err := srh.WithTlvs(nil); err != nil {
		t.Fatalf("WithTlvs: %v", err)
	}
	if srh.NextHeader() != 59 {
		t.Errorf("NextHeader = %d, want 59", srh.NextHeader())
	}
	if srh.Flags() != SRv6FlagOAM {
		t.Errorf("Flags = 0x%02x, want 0x%02x", srh.Flags(), SRv6FlagOAM)
	}
	if srh.Tag() != 0x1234 {
		t.Errorf("Tag = 0x%04x, want 0x1234", srh.Tag())
	}
}

func TestSRv6SrhFirstSegment(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, _ := NewSRv6Srh([]any{s1, s2})
	defer srh.Free()
	first, err := srh.FirstSegment()
	if err != nil {
		t.Fatalf("FirstSegment: %v", err)
	}
	oct, _ := s1.Octets()
	for i, b := range oct {
		if first[i] != b {
			t.Fatalf("byte %d: got %02x, want %02x", i, first[i], b)
		}
	}
}

func TestSRv6SrhCurrentDestination(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, _ := NewSRv6Srh([]any{s1, s2}) // segments_left defaults to 1
	defer srh.Free()
	cur, err := srh.CurrentDestination()
	if err != nil {
		t.Fatalf("CurrentDestination: %v", err)
	}
	oct, _ := s2.Octets()
	for i, b := range oct {
		if cur[i] != b {
			t.Fatalf("byte %d: got %02x, want %02x", i, cur[i], b)
		}
	}
}

func TestSRv6SrhSegmentAt(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, _ := NewSRv6Srh([]any{s1, s2})
	defer srh.Free()
	oct0, _ := s1.Octets()
	oct1, _ := s2.Octets()
	at0, err := srh.SegmentAt(0)
	if err != nil {
		t.Fatalf("SegmentAt(0): %v", err)
	}
	for i, b := range oct0 {
		if at0[i] != b {
			t.Fatalf("SegmentAt(0) byte %d: got %02x, want %02x", i, at0[i], b)
		}
	}
	at1, err := srh.SegmentAt(1)
	if err != nil {
		t.Fatalf("SegmentAt(1): %v", err)
	}
	for i, b := range oct1 {
		if at1[i] != b {
			t.Fatalf("SegmentAt(1) byte %d: got %02x, want %02x", i, at1[i], b)
		}
	}
	if _, err := srh.SegmentAt(99); err == nil {
		t.Error("SegmentAt(99) should fail")
	}
}

func TestSRv6SrhSegments(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, _ := NewSRv6Srh([]any{s1, s2})
	defer srh.Free()
	segs, err := srh.Segments()
	if err != nil {
		t.Fatalf("Segments: %v", err)
	}
	if len(segs) != 2 {
		t.Fatalf("len(segs) = %d, want 2", len(segs))
	}
}

func TestSRv6SrhTlvsDefaultEmpty(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	srh, _ := NewSRv6Srh([]any{s1})
	defer srh.Free()
	tlvs, err := srh.Tlvs()
	if err != nil {
		t.Fatalf("Tlvs: %v", err)
	}
	if len(tlvs) != 0 {
		t.Errorf("len(tlvs) = %d, want 0", len(tlvs))
	}
}

func TestSRv6SrhWithTlvsRoundTrip(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	srh, _ := NewSRv6Srh([]any{s1})
	defer srh.Free()
	in := []byte{0x05, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}
	if _, err := srh.WithTlvs(in); err != nil {
		t.Fatalf("WithTlvs: %v", err)
	}
	got, err := srh.Tlvs()
	if err != nil {
		t.Fatalf("Tlvs: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("len(tlvs) = %d, want %d", len(got), len(in))
	}
	for i, b := range in {
		if got[i] != b {
			t.Fatalf("byte %d: got %02x, want %02x", i, got[i], b)
		}
	}
}

func TestSRv6SrhEncodeMinimal(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	srh, _ := NewSRv6Srh([]any{s1})
	defer srh.Free()
	wire, err := srh.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// 8-octet fixed header + 16-octet segment = 24 bytes.
	if len(wire) != 24 {
		t.Errorf("len(wire) = %d, want 24", len(wire))
	}
	// Routing Type byte at offset 2 is 4.
	if wire[2] != SRv6RoutingTypeSRH {
		t.Errorf("wire[2] = %d, want %d (Routing Type)", wire[2], SRv6RoutingTypeSRH)
	}
	// Hdr Ext Len at offset 1 is (24 / 8) - 1 = 2.
	if wire[1] != 2 {
		t.Errorf("wire[1] = %d, want 2 (Hdr Ext Len)", wire[1])
	}
}

func TestSRv6SrhEncodeTwoSegments(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, _ := NewSRv6Srh([]any{s1, s2})
	defer srh.Free()
	wire, err := srh.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// 8 + 2 * 16 = 40 bytes (already aligned to 8).
	if len(wire) != 40 {
		t.Errorf("len(wire) = %d, want 40", len(wire))
	}
}

func TestSRv6SrhHdrExtLen(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, _ := NewSRv6Srh([]any{s1, s2})
	defer srh.Free()
	// 40 / 8 - 1 = 4.
	if srh.HdrExtLen() != 4 {
		t.Errorf("HdrExtLen = %d, want 4", srh.HdrExtLen())
	}
}

func TestSRv6SrhLen(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	s2, _ := ParseSRv6Sid("fcbb:bb00::2")
	defer s2.Free()
	srh, _ := NewSRv6Srh([]any{s1, s2})
	defer srh.Free()
	// Srh.Len() mirrors Rust's Srh::len() — segment count, not wire length.
	if srh.Len() != 2 {
		t.Errorf("Len = %d, want 2", srh.Len())
	}
	wire, _ := srh.Encode()
	if len(wire) != 40 {
		t.Errorf("len(wire) = %d, want 40", len(wire))
	}
}

func TestSRv6SrhIsEmpty(t *testing.T) {
	s1, _ := ParseSRv6Sid("fcbb:bb00::1")
	defer s1.Free()
	srh, _ := NewSRv6Srh([]any{s1})
	defer srh.Free()
	if srh.IsEmpty() {
		t.Error("IsEmpty should be false")
	}
}

// ----------------------------------------------------------------------
// Behavior — RFC 8986 §4.
// ----------------------------------------------------------------------

func TestSRv6BehaviorFromWireEnd(t *testing.T) {
	wire, name, ok := SRv6BehaviorFromWire(0x0001)
	if !ok {
		t.Fatal("BehaviorFromWire(0x0001) should succeed")
	}
	if name != "End" {
		t.Errorf("name = %q, want %q", name, "End")
	}
	_ = wire
}

func TestSRv6BehaviorFromWireEndX(t *testing.T) {
	_, name, ok := SRv6BehaviorFromWire(0x0005)
	if !ok {
		t.Fatal("BehaviorFromWire(0x0005) should succeed")
	}
	if name != "End.X" {
		t.Errorf("name = %q, want %q", name, "End.X")
	}
}

func TestSRv6BehaviorFromWireUnknown(t *testing.T) {
	_, _, ok := SRv6BehaviorFromWire(0xFFFF)
	if ok {
		t.Error("BehaviorFromWire(0xFFFF) should fail")
	}
}

func TestSRv6BehaviorNameKnown(t *testing.T) {
	if got := SRv6BehaviorName(0x0001); got != "End" {
		t.Errorf("Name(0x0001) = %q, want %q", got, "End")
	}
	if got := SRv6BehaviorName(0x0005); got != "End.X" {
		t.Errorf("Name(0x0005) = %q, want %q", got, "End.X")
	}
}

func TestSRv6BehaviorNameUnknown(t *testing.T) {
	if got := SRv6BehaviorName(0xFFFF); got != "Unknown(0xffff)" {
		t.Errorf("Name(0xFFFF) = %q, want %q", got, "Unknown(0xffff)")
	}
}

func TestSRv6BehaviorWireValue(t *testing.T) {
	if got := SRv6BehaviorWireValue(0x0001); got != 0x0001 {
		t.Errorf("WireValue(0x0001) = %d, want 1", got)
	}
}

func TestSRv6BehaviorIsCrossConnect(t *testing.T) {
	// End.X (0x0005) is a cross-connect.
	if !SRv6BehaviorIsCrossConnect(0x0005) {
		t.Error("End.X should be cross-connect")
	}
}

func TestSRv6BehaviorFlagQueries(t *testing.T) {
	// Just verify the queries don't crash.
	SRv6BehaviorIsPSP(0x0001)
	SRv6BehaviorIsUSP(0x0001)
	SRv6BehaviorIsUSD(0x0001)
	SRv6BehaviorIsDecap(0x0001)
	SRv6BehaviorIsTableLookup(0x0001)
}
