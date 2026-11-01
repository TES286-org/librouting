// Tests for the Attributes container + ApplySetChecked binding.
//
// Mirrors the Rust-side `crates/lr-ffi/src/attributes.rs` and
// `crates/lr-ffi/src/policy_batch.rs` unit tests and the Python
// `bindings/lr-python/tests/test_attributes.py`. Every Rust pub-API
// method on `Attributes` and every SetAction variant handled by
// `apply_set_checked` is exercised through the Go class surface.

package librouting

import (
	"bytes"
	"testing"
)

// ----------------------------------------------------------------------
// Constants — mirror LR_SET_* and LR_APPLY_SET_ERROR_*.
// ----------------------------------------------------------------------

func TestAttributesConstants(t *testing.T) {
	if SetLocalPref != 0 {
		t.Errorf("SetLocalPref = %d, want 0", SetLocalPref)
	}
	if SetMed != 1 {
		t.Errorf("SetMed = %d, want 1", SetMed)
	}
	if SetPrependAs != 3 {
		t.Errorf("SetPrependAs = %d, want 3", SetPrependAs)
	}
	if SetMetric != 5 {
		t.Errorf("SetMetric = %d, want 5", SetMetric)
	}
	if SetTag != 6 {
		t.Errorf("SetTag = %d, want 6", SetTag)
	}
	if ApplySetErrorOK != 0 {
		t.Errorf("ApplySetErrorOK = %d, want 0", ApplySetErrorOK)
	}
	if ApplySetErrorUnknown != 6 {
		t.Errorf("ApplySetErrorUnknown = %d, want 6", ApplySetErrorUnknown)
	}
}

func TestApplySetErrorName(t *testing.T) {
	if got := ApplySetErrorName(ApplySetErrorOK); got != "ok" {
		t.Errorf("ApplySetErrorName(OK) = %q, want \"ok\"", got)
	}
	// The four no-bgp names mention "bgp".
	if got := ApplySetErrorName(ApplySetErrorLocalPrefNoBgp); got != "SetLocalPref needs bgp feature" {
		t.Errorf("ApplySetErrorName(LocalPrefNoBgp) = %q, want the documented string", got)
	}
}

// ----------------------------------------------------------------------
// Attributes container
// ----------------------------------------------------------------------

func TestAttributesNewIsEmpty(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	if a.Len() != 0 {
		t.Errorf("Len = %d, want 0", a.Len())
	}
	if !a.IsEmpty() {
		t.Error("IsEmpty = false, want true")
	}
}

func TestAttributesInsertAndGetRoundTrip(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	value := []byte{0, 0, 0, 100} // 100 as u32 BE
	if err := a.Insert(5, 0x40, value); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if a.Len() != 1 {
		t.Errorf("Len = %d, want 1", a.Len())
	}
	if a.IsEmpty() {
		t.Error("IsEmpty = true, want false")
	}
	flags, got, ok, err := a.Get(5)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get: ok = false, want true")
	}
	if flags != 0x40 {
		t.Errorf("flags = 0x%02x, want 0x40", flags)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("value = %v, want %v", got, value)
	}
	// Typed reader.
	if v := a.GetU32BE(5); v != 100 {
		t.Errorf("GetU32BE = %d, want 100", v)
	}
}

func TestAttributesGetAbsentReturnsOkFalse(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	_, _, ok, err := a.Get(99)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("ok = true, want false for absent tag")
	}
}

func TestAttributesGetReturnsFullValueWhenLarge(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	value := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	if err := a.Insert(7, 0, value); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	_, got, ok, err := a.Get(7)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get: ok = false, want true")
	}
	if !bytes.Equal(got, value) {
		t.Errorf("value = %v, want %v", got, value)
	}
}

func TestAttributesU64BERoundTrip(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	v := uint64(0x0123_4567_89AB_CDEF)
	be := []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
	if err := a.Insert(9, 0, be); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if got := a.GetU64BE(9); got != v {
		t.Errorf("GetU64BE = 0x%x, want 0x%x", got, v)
	}
}

func TestAttributesU8RoundTrip(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	if err := a.Insert(11, 0, []byte{42}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if got := a.GetU8(11); got != 42 {
		t.Errorf("GetU8 = %d, want 42", got)
	}
}

func TestAttributesRemoveReturnsPresence(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	if err := a.Insert(5, 0, []byte{0, 0, 0, 1}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	present, err := a.Remove(5)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !present {
		t.Error("Remove = false, want true for present tag")
	}
	present, err = a.Remove(5)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if present {
		t.Error("Remove = true, want false for absent tag")
	}
	if a.Len() != 0 {
		t.Errorf("Len = %d, want 0", a.Len())
	}
}

func TestAttributesAtRoundTrip(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	if err := a.Insert(5, 0, []byte{0, 0, 0, 1}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := a.Insert(7, 0x80, []byte{0, 0, 0, 2}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if a.Len() != 2 {
		t.Errorf("Len = %d, want 2", a.Len())
	}
	// BTreeMap ordering: tag 5 before tag 7 — index 1 is tag 7.
	tag, flags, value, ok, err := a.At(1)
	if err != nil {
		t.Fatalf("At: %v", err)
	}
	if !ok {
		t.Fatal("At: ok = false, want true")
	}
	if tag != 7 {
		t.Errorf("tag = %d, want 7", tag)
	}
	if flags != 0x80 {
		t.Errorf("flags = 0x%02x, want 0x80", flags)
	}
	if !bytes.Equal(value, []byte{0, 0, 0, 2}) {
		t.Errorf("value = %v, want [0 0 0 2]", value)
	}
	// Out of range.
	_, _, _, ok, _ = a.At(99)
	if ok {
		t.Error("At(99) ok = true, want false")
	}
}

func TestAttributesIterYieldsInTagOrder(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	if err := a.Insert(7, 0, []byte("seven")); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := a.Insert(3, 0, []byte("three")); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := a.Insert(11, 0, []byte("eleven")); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	entries, err := a.Iter()
	if err != nil {
		t.Fatalf("Iter: %v", err)
	}
	got := make([]uint8, len(entries))
	for i, e := range entries {
		got[i] = e.Tag
	}
	want := []uint8{3, 7, 11}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tags = %v, want %v", got, want)
			break
		}
	}
}

func TestAttributesInsertReplacesOnSameTag(t *testing.T) {
	a, err := NewAttributes()
	if err != nil {
		t.Fatalf("NewAttributes: %v", err)
	}
	defer a.Free()
	if err := a.Insert(5, 0, []byte{0, 0, 0, 1}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := a.Insert(5, 0x40, []byte{0, 0, 0, 2}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if a.Len() != 1 {
		t.Errorf("Len = %d, want 1 (replace)", a.Len())
	}
	if v := a.GetU32BE(5); v != 2 {
		t.Errorf("GetU32BE = %d, want 2 (latest value wins)", v)
	}
	flags, _, _, _ := a.Get(5)
	if flags != 0x40 {
		t.Errorf("flags = 0x%02x, want 0x40 (latest flags win)", flags)
	}
}

// ----------------------------------------------------------------------
// ApplySetChecked
// ----------------------------------------------------------------------

func newTestV4Route(t *testing.T) *Route {
	t.Helper()
	r, err := NewRouteV4([4]byte{203, 0, 113, 0}, 24, ProtocolBgp)
	if err != nil {
		t.Fatalf("NewRouteV4: %v", err)
	}
	return r
}

func TestApplySetCheckedMetricSucceeds(t *testing.T) {
	r := newTestV4Route(t)
	defer r.Free()
	if err := ApplySetChecked(r, SetMetric, 42, 0, 0); err != nil {
		t.Fatalf("ApplySetChecked(SetMetric): %v", err)
	}
	got, err := r.Metric()
	if err != nil {
		t.Fatalf("Metric: %v", err)
	}
	if got != 42 {
		t.Errorf("Metric = %d, want 42", got)
	}
}

func TestApplySetCheckedTagSucceeds(t *testing.T) {
	r := newTestV4Route(t)
	defer r.Free()
	if err := ApplySetChecked(r, SetTag, 0xDEAD_BEEF, 0, 0); err != nil {
		t.Fatalf("ApplySetChecked(SetTag): %v", err)
	}
	got, _, err := r.Tag()
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if got != 0xDEAD_BEEF {
		t.Errorf("Tag = 0x%x, want 0xDEAD_BEEF", got)
	}
}

func TestApplySetCheckedLocalPrefSucceedsWithBgpFeature(t *testing.T) {
	r := newTestV4Route(t)
	defer r.Free()
	if err := ApplySetChecked(r, SetLocalPref, 100, 0, 0); err != nil {
		t.Fatalf("ApplySetChecked(SetLocalPref): %v", err)
	}
	got, ok, err := r.LocalPref()
	if err != nil {
		t.Fatalf("LocalPref: %v", err)
	}
	if !ok {
		t.Fatal("LocalPref: ok = false, want true")
	}
	if got != 100 {
		t.Errorf("LocalPref = %d, want 100", got)
	}
}

func TestApplySetCheckedMedSucceedsWithBgpFeature(t *testing.T) {
	r := newTestV4Route(t)
	defer r.Free()
	if err := ApplySetChecked(r, SetMed, 50, 0, 0); err != nil {
		t.Fatalf("ApplySetChecked(SetMed): %v", err)
	}
	got, ok, err := r.Med()
	if err != nil {
		t.Fatalf("Med: %v", err)
	}
	if !ok {
		t.Fatal("Med: ok = false, want true")
	}
	if got != 50 {
		t.Errorf("Med = %d, want 50", got)
	}
}

func TestApplySetCheckedPrependAsSucceedsWithBgpFeature(t *testing.T) {
	r := newTestV4Route(t)
	defer r.Free()
	if err := ApplySetChecked(r, SetPrependAs, 65000, 0, 0); err != nil {
		t.Fatalf("ApplySetChecked(SetPrependAs): %v", err)
	}
	path, err := r.AsPath()
	if err != nil {
		t.Fatalf("AsPath: %v", err)
	}
	found := false
	for _, asn := range path {
		if asn == 65000 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AsPath = %v, want 65000 somewhere in the path", path)
	}
}

func TestApplySetCheckedAddCommunitySucceedsWithBgpFeature(t *testing.T) {
	r := newTestV4Route(t)
	defer r.Free()
	if err := ApplySetChecked(r, SetAddCommunity, 65000, 1, 0); err != nil {
		t.Fatalf("ApplySetChecked(SetAddCommunity): %v", err)
	}
	comms, err := r.Communities()
	if err != nil {
		t.Fatalf("Communities: %v", err)
	}
	encoded := uint64(65000)<<16 | 1
	found := false
	for _, c := range comms {
		if c == encoded {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Communities = %v, want encoded %d in the list", comms, encoded)
	}
}

func TestApplySetCheckedUnknownKindRaisesError(t *testing.T) {
	r := newTestV4Route(t)
	defer r.Free()
	err := ApplySetChecked(r, 99, 0, 0, 0)
	if err == nil {
		t.Fatal("ApplySetChecked(99) returned nil, want *ApplySetCheckedError")
	}
	tce, ok := err.(*ApplySetCheckedError)
	if !ok {
		t.Fatalf("err type = %T, want *ApplySetCheckedError", err)
	}
	if tce.Code != ApplySetErrorUnknown {
		t.Errorf("Code = %d, want %d (ApplySetErrorUnknown)", tce.Code, ApplySetErrorUnknown)
	}
}

func TestApplySetCheckedNilRouteReturnsError(t *testing.T) {
	if err := ApplySetChecked(nil, SetMetric, 0, 0, 0); err == nil {
		t.Fatal("ApplySetChecked(nil, …) returned nil, want error")
	}
}
