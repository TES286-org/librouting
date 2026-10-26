// MPLS Label / LabelStack tests (RFC 3032 §2.1, RFC 8277 §2.2/§2.3).
package librouting

import (
	"bytes"
	"testing"
)

func TestMPLSLabelNewAndReaders(t *testing.T) {
	l := NewMPLSLabel(100)
	defer l.Free()
	if l.Value() != 100 {
		t.Fatalf("Value = %d, want 100", l.Value())
	}
	if l.TC() != 0 {
		t.Fatalf("TC = %d, want 0", l.TC())
	}
	if l.TTL() != 64 {
		t.Fatalf("TTL = %d, want 64", l.TTL())
	}
	if l.IsReserved() {
		t.Fatal("label 100 must not be reserved")
	}
}

func TestMPLSLabelReserved(t *testing.T) {
	l := NewMPLSLabel(0)
	defer l.Free()
	if !l.IsReserved() {
		t.Fatal("label 0 must be reserved")
	}
}

func TestMPLSLabelNewCheckedRejectsOversize(t *testing.T) {
	// 0x100000 = 1 << 20 = MAX_VALUE + 1.
	_, err := NewMPLSLabelChecked(0x100000)
	if err == nil {
		t.Fatal("oversize value must error")
	}
}

func TestMPLSLabelWithTCAndTTL(t *testing.T) {
	l := NewMPLSLabel(0xfffff)
	l = l.WithTC(7)
	l = l.WithTTL(255)
	defer l.Free()
	if l.TC() != 7 {
		t.Fatalf("TC = %d, want 7", l.TC())
	}
	if l.TTL() != 255 {
		t.Fatalf("TTL = %d, want 255", l.TTL())
	}
}

func TestMPLSLabelWithTCMasksHighBits(t *testing.T) {
	l := NewMPLSLabel(16)
	l = l.WithTC(0xff)
	defer l.Free()
	if l.TC() != 0x07 {
		t.Fatalf("TC = %#x, want 0x07 (3-bit mask)", l.TC())
	}
}

func TestMPLSLabelEncode3OctetAnd4Octet(t *testing.T) {
	// Label 100, TC=0, TTL=64, bottom-of-stack.
	l := NewMPLSLabel(100)
	l = l.WithTC(0).WithTTL(64)
	defer l.Free()

	out3, err := l.Encode3Octet(true)
	if err != nil {
		t.Fatalf("Encode3Octet: %v", err)
	}
	want3 := []byte{0x00, 0x06, 0x41}
	if !bytes.Equal(out3, want3) {
		t.Fatalf("3-octet encode = %x, want %x", out3, want3)
	}

	out4, err := l.Encode4Octet(true)
	if err != nil {
		t.Fatalf("Encode4Octet: %v", err)
	}
	want4 := []byte{0x00, 0x06, 0x41, 0x40}
	if !bytes.Equal(out4, want4) {
		t.Fatalf("4-octet encode = %x, want %x", out4, want4)
	}
}

func TestMPLSStackFromValuesRoundtrip4Octet(t *testing.T) {
	values := []uint32{16, 240, 1048575}
	s, err := NewMPLSLabelStackFromValues(values)
	if err != nil {
		t.Fatalf("NewMPLSLabelStackFromValues: %v", err)
	}
	defer s.Free()
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
	if s.IsEmpty() {
		t.Fatal("IsEmpty should be false")
	}

	// Read the middle entry.
	spec, err := s.At(1)
	if err != nil {
		t.Fatalf("At(1): %v", err)
	}
	if spec.Value != 240 {
		t.Fatalf("At(1).Value = %d, want 240", spec.Value)
	}

	// Encode as 4-octet wire form (12 bytes) and decode it back.
	enc, err := s.Encode4Octet()
	if err != nil {
		t.Fatalf("Encode4Octet: %v", err)
	}
	if len(enc) != 12 {
		t.Fatalf("encoded len = %d, want 12", len(enc))
	}

	dec, err := DecodeMPLSLabelStack4Octet(enc)
	if err != nil {
		t.Fatalf("DecodeMPLSLabelStack4Octet: %v", err)
	}
	defer dec.Free()
	if dec.Len() != 3 {
		t.Fatalf("decoded Len = %d, want 3", dec.Len())
	}
	last, err := dec.At(2)
	if err != nil {
		t.Fatalf("At(2): %v", err)
	}
	if last.Value != 1048575 {
		t.Fatalf("At(2).Value = %d, want 1048575", last.Value)
	}
}

func TestMPLSStackFromLabelsRoundtrip3Octet(t *testing.T) {
	specs := []MPLSLabelSpec{
		{Value: 16, TC: 0, TTL: 0},
		{Value: 240, TC: 0, TTL: 0},
	}
	s, err := NewMPLSLabelStackFromLabels(specs)
	if err != nil {
		t.Fatalf("NewMPLSLabelStackFromLabels: %v", err)
	}
	defer s.Free()

	enc, err := s.Encode3Octet()
	if err != nil {
		t.Fatalf("Encode3Octet: %v", err)
	}
	if len(enc) != 6 {
		t.Fatalf("encoded len = %d, want 6", len(enc))
	}

	dec, err := DecodeMPLSLabelStack3Octet(enc)
	if err != nil {
		t.Fatalf("DecodeMPLSLabelStack3Octet: %v", err)
	}
	defer dec.Free()
	if dec.Len() != 2 {
		t.Fatalf("decoded Len = %d, want 2", dec.Len())
	}
}

func TestMPLSStackPushPop(t *testing.T) {
	s := NewMPLSLabelStack()
	defer s.Free()

	top := NewMPLSLabel(100)
	if err := s.Push(top); err != nil {
		t.Fatalf("Push: %v", err)
	}
	bot := NewMPLSLabel(200)
	if err := s.PushBottom(bot); err != nil {
		t.Fatalf("PushBottom: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}

	// Top is at index 0.
	spec, err := s.At(0)
	if err != nil {
		t.Fatalf("At(0): %v", err)
	}
	if spec.Value != 100 {
		t.Fatalf("At(0).Value = %d, want 100", spec.Value)
	}

	// Pop the top — pops 100.
	popped, err := s.Pop()
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if !popped {
		t.Fatal("Pop should return true")
	}
	if s.Len() != 1 {
		t.Fatalf("Len after pop = %d, want 1", s.Len())
	}

	// The bottom label (200) is now at index 0.
	spec, err = s.At(0)
	if err != nil {
		t.Fatalf("At(0): %v", err)
	}
	if spec.Value != 200 {
		t.Fatalf("At(0).Value = %d, want 200", spec.Value)
	}

	// Pop again — pops 200.
	popped, err = s.Pop()
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if !popped {
		t.Fatal("Pop should return true")
	}
	if !s.IsEmpty() {
		t.Fatal("IsEmpty should be true")
	}

	// Pop on an empty stack returns false (no label was popped).
	popped, err = s.Pop()
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if popped {
		t.Fatal("Pop on empty stack should return false")
	}
}

func TestMPLSStackAtReturnsErrorOnOOB(t *testing.T) {
	s := NewMPLSLabelStack()
	defer s.Free()
	_, err := s.At(0)
	if err == nil {
		t.Fatal("At(0) on empty stack should error")
	}
}

func TestMPLSStackDecode4OctetRejectsUnevenLength(t *testing.T) {
	bytes := []byte{0, 1, 2} // not a multiple of 4
	_, err := DecodeMPLSLabelStack4Octet(bytes)
	if err == nil {
		t.Fatal("uneven length should error")
	}
}

func TestMPLSStackLabelsReturnsAllSpecs(t *testing.T) {
	specs := []MPLSLabelSpec{
		{Value: 16, TC: 0, TTL: 0},
		{Value: 240, TC: 0, TTL: 0},
		{Value: 1048575, TC: 0, TTL: 0},
	}
	s, err := NewMPLSLabelStackFromLabels(specs)
	if err != nil {
		t.Fatalf("NewMPLSLabelStackFromLabels: %v", err)
	}
	defer s.Free()
	out, err := s.Labels()
	if err != nil {
		t.Fatalf("Labels: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	if out[2].Value != 1048575 {
		t.Fatalf("out[2].Value = %d, want 1048575", out[2].Value)
	}
}
