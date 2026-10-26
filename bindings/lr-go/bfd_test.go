package librouting

import (
	"testing"
)

func TestBfdPacketNew(t *testing.T) {
	p := NewBfdPacket()
	defer p.Free()
	if p.Version() != 1 {
		t.Fatalf("Version = %d, want 1", p.Version())
	}
	if p.Diag() != 0 {
		t.Fatalf("Diag = %d, want 0", p.Diag())
	}
	if p.State() != BFDStateDown {
		t.Fatalf("State = %d, want %d", p.State(), BFDStateDown)
	}
	if p.DetectMult() != 3 {
		t.Fatalf("DetectMult = %d, want 3", p.DetectMult())
	}
	if p.DesiredMinTxInterval() != 1_000_000 {
		t.Fatalf("DesiredMinTxInterval = %d, want 1_000_000", p.DesiredMinTxInterval())
	}
	if p.Length() != 24 {
		t.Fatalf("Length = %d, want 24", p.Length())
	}
}

func TestBfdHeartbeat(t *testing.T) {
	p := NewBfdHeartbeat(0x1234, 0x5678)
	defer p.Free()
	if p.State() != BFDStateUp {
		t.Fatalf("State = %d, want Up(%d)", p.State(), BFDStateUp)
	}
	if p.MyDiscriminator() != 0x1234 {
		t.Fatalf("MyDisc = %#x, want 0x1234", p.MyDiscriminator())
	}
	if p.YourDiscriminator() != 0x5678 {
		t.Fatalf("YourDisc = %#x, want 0x5678", p.YourDiscriminator())
	}
}

func TestBfdSetters(t *testing.T) {
	p := NewBfdPacket()
	defer p.Free()
	if err := p.SetDiag(BFDDiagCtrlExpired); err != nil {
		t.Fatalf("SetDiag: %v", err)
	}
	if err := p.SetState(BFDStateUp); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	if err := p.SetDetectMult(5); err != nil {
		t.Fatalf("SetDetectMult: %v", err)
	}
	if err := p.SetMyDiscriminator(0xaabbccdd); err != nil {
		t.Fatalf("SetMyDiscriminator: %v", err)
	}
	if p.Diag() != BFDDiagCtrlExpired {
		t.Fatalf("Diag = %d, want %d", p.Diag(), BFDDiagCtrlExpired)
	}
	if p.State() != BFDStateUp {
		t.Fatalf("State = %d, want %d", p.State(), BFDStateUp)
	}
	if p.DetectMult() != 5 {
		t.Fatalf("DetectMult = %d, want 5", p.DetectMult())
	}
	if p.MyDiscriminator() != 0xaabbccdd {
		t.Fatalf("MyDisc = %#x, want 0xaabbccdd", p.MyDiscriminator())
	}
}

func TestBfdSetStateClampsInvalid(t *testing.T) {
	p := NewBfdPacket()
	defer p.Free()
	if err := p.SetState(99); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	if p.State() != BFDStateAdminDown {
		t.Fatalf("State = %d, want AdminDown(%d) (clamped)", p.State(), BFDStateAdminDown)
	}
}

func TestBfdSetFlagsMasksReserved(t *testing.T) {
	p := NewBfdPacket()
	defer p.Free()
	if err := p.SetFlags(0xff); err != nil {
		t.Fatalf("SetFlags: %v", err)
	}
	if p.Flags() != 0b0011_1111 {
		t.Fatalf("Flags = %#x, want 0x3f (M|D|A|C|F|P masked)", p.Flags())
	}
}

func TestBfdEncodeDecodeRoundtrip(t *testing.T) {
	p := NewBfdHeartbeat(0xdeadbeef, 0xcafebabe)
	defer p.Free()
	enc, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(enc) != 24 {
		t.Fatalf("encoded len = %d, want 24", len(enc))
	}
	dec, err := DecodeBfdPacket(enc)
	if err != nil {
		t.Fatalf("DecodeBfdPacket: %v", err)
	}
	defer dec.Free()
	if dec.State() != BFDStateUp {
		t.Fatalf("State = %d, want Up", dec.State())
	}
	if dec.MyDiscriminator() != 0xdeadbeef {
		t.Fatalf("MyDisc = %#x, want 0xdeadbeef", dec.MyDiscriminator())
	}
	if dec.YourDiscriminator() != 0xcafebabe {
		t.Fatalf("YourDisc = %#x, want 0xcafebabe", dec.YourDiscriminator())
	}
}

func TestBfdDecodeRejectsTooShort(t *testing.T) {
	bytes := []byte{0, 1, 2}
	_, err := DecodeBfdPacket(bytes)
	if err == nil {
		t.Fatal("expected error on too-short input")
	}
}
