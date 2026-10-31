package librouting

import (
	"bytes"
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

// ---- BFD AuthType readers (RFC 5880 §8 IANA codes) ----

func TestBfdAuthTypeReaders(t *testing.T) {
	if got := BFDAuthTypeExpectedDigestLen(BFDAuthTypeKeyedMd5); got != 16 {
		t.Fatalf("MD5 expected digest len = %d, want 16", got)
	}
	if got := BFDAuthTypeExpectedDigestLen(BFDAuthTypeKeyedSha1); got != 20 {
		t.Fatalf("SHA1 expected digest len = %d, want 20", got)
	}
	if got := BFDAuthTypeExpectedDigestLen(BFDAuthTypeMeticulousKeyedMd5); got != 16 {
		t.Fatalf("Meticulous MD5 expected digest len = %d, want 16", got)
	}
	if got := BFDAuthTypeExpectedDigestLen(BFDAuthTypeMeticulousKeyedSha1); got != 20 {
		t.Fatalf("Meticulous SHA1 expected digest len = %d, want 20", got)
	}
	if got := BFDAuthTypeExpectedDigestLen(BFDAuthTypeSimplePassword); got != -1 {
		t.Fatalf("Simple Password expected digest len = %d, want -1", got)
	}
	if got := BFDAuthTypeExpectedDigestLen(99); got != -1 {
		t.Fatalf("Unknown type expected digest len = %d, want -1", got)
	}
	if !BFDAuthTypeIsKeyedHash(BFDAuthTypeKeyedMd5) {
		t.Fatal("MD5 should be keyed-hash")
	}
	if BFDAuthTypeIsKeyedHash(BFDAuthTypeSimplePassword) {
		t.Fatal("Simple Password should not be keyed-hash")
	}
	if !BFDAuthTypeIsMeticulous(BFDAuthTypeMeticulousKeyedMd5) {
		t.Fatal("Meticulous MD5 should be meticulous")
	}
	if BFDAuthTypeIsMeticulous(BFDAuthTypeKeyedMd5) {
		t.Fatal("Plain Keyed MD5 should not be meticulous")
	}
}

// ---- BfdAuthKey lifecycle ----

func TestBfdAuthKeyRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef")
	k, err := NewBfdAuthKey(7, secret)
	if err != nil {
		t.Fatalf("NewBfdAuthKey: %v", err)
	}
	defer k.Free()
	if k.KeyID() != 7 {
		t.Fatalf("KeyID = %d, want 7", k.KeyID())
	}
	if k.DataLen() != 16 {
		t.Fatalf("DataLen = %d, want 16", k.DataLen())
	}
	data, err := k.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	if !bytes.Equal(data, secret) {
		t.Fatalf("Data = %v, want %v", data, secret)
	}
}

func TestBfdAuthKeySimplePassword(t *testing.T) {
	pw := []byte("hunter2")
	k, err := NewBfdAuthKeySimplePassword(3, pw)
	if err != nil {
		t.Fatalf("NewBfdAuthKeySimplePassword: %v", err)
	}
	defer k.Free()
	if k.KeyID() != 3 {
		t.Fatalf("KeyID = %d, want 3", k.KeyID())
	}
	if k.DataLen() != 7 {
		t.Fatalf("DataLen = %d, want 7", k.DataLen())
	}
}

// ---- BfdAuthSection lifecycle ----

func TestBfdAuthSectionSimplePassword(t *testing.T) {
	pw := []byte("hunter2")
	s, err := NewBfdAuthSectionSimplePassword(pw, 7)
	if err != nil {
		t.Fatalf("NewBfdAuthSectionSimplePassword: %v", err)
	}
	defer s.Free()
	if s.AuthType() != BFDAuthTypeSimplePassword {
		t.Fatalf("AuthType = %d, want %d", s.AuthType(), BFDAuthTypeSimplePassword)
	}
	if s.KeyID() != 7 {
		t.Fatalf("KeyID = %d, want 7", s.KeyID())
	}
	if seq, ok := s.Sequence(); ok {
		t.Fatalf("Sequence = (%d, true), want (0, false)", seq)
	}
	if s.DataLen() != 7 {
		t.Fatalf("DataLen = %d, want 7", s.DataLen())
	}
	if s.WireLen() != 3+7 {
		t.Fatalf("WireLen = %d, want 10", s.WireLen())
	}
	data, err := s.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	if !bytes.Equal(data, pw) {
		t.Fatalf("Data = %v, want %v", data, pw)
	}
}

func TestBfdAuthSectionKeyedMd5(t *testing.T) {
	digest := make([]byte, 16)
	s, err := NewBfdAuthSectionKeyedMd5(2, 0xDEADBEEF, digest)
	if err != nil {
		t.Fatalf("NewBfdAuthSectionKeyedMd5: %v", err)
	}
	defer s.Free()
	if s.AuthType() != BFDAuthTypeKeyedMd5 {
		t.Fatalf("AuthType = %d, want %d", s.AuthType(), BFDAuthTypeKeyedMd5)
	}
	if s.KeyID() != 2 {
		t.Fatalf("KeyID = %d, want 2", s.KeyID())
	}
	if seq, ok := s.Sequence(); !ok || seq != 0xDEADBEEF {
		t.Fatalf("Sequence = (%d, %v), want (0xDEADBEEF, true)", seq, ok)
	}
	if s.DataLen() != 16 {
		t.Fatalf("DataLen = %d, want 16", s.DataLen())
	}
	if s.WireLen() != 24 {
		t.Fatalf("WireLen = %d, want 24", s.WireLen())
	}
}

func TestBfdAuthSectionKeyedSha1(t *testing.T) {
	digest := make([]byte, 20)
	s, err := NewBfdAuthSectionKeyedSha1(4, 0xFEEDFACE, digest)
	if err != nil {
		t.Fatalf("NewBfdAuthSectionKeyedSha1: %v", err)
	}
	defer s.Free()
	if s.AuthType() != BFDAuthTypeKeyedSha1 {
		t.Fatalf("AuthType = %d, want %d", s.AuthType(), BFDAuthTypeKeyedSha1)
	}
	if s.WireLen() != 28 {
		t.Fatalf("WireLen = %d, want 28", s.WireLen())
	}
}

func TestBfdAuthSectionMeticulousVariants(t *testing.T) {
	digest16 := make([]byte, 16)
	mmd5, err := NewBfdAuthSectionMeticulousKeyedMd5(3, 42, digest16)
	if err != nil {
		t.Fatalf("NewBfdAuthSectionMeticulousKeyedMd5: %v", err)
	}
	defer mmd5.Free()
	if mmd5.AuthType() != BFDAuthTypeMeticulousKeyedMd5 {
		t.Fatalf("AuthType = %d, want %d", mmd5.AuthType(), BFDAuthTypeMeticulousKeyedMd5)
	}

	digest20 := make([]byte, 20)
	msha1, err := NewBfdAuthSectionMeticulousKeyedSha1(5, 42, digest20)
	if err != nil {
		t.Fatalf("NewBfdAuthSectionMeticulousKeyedSha1: %v", err)
	}
	defer msha1.Free()
	if msha1.AuthType() != BFDAuthTypeMeticulousKeyedSha1 {
		t.Fatalf("AuthType = %d, want %d", msha1.AuthType(), BFDAuthTypeMeticulousKeyedSha1)
	}
}

// ---- BfdPacket auth integration ----

func TestBfdPacketAuthAbsentByDefault(t *testing.T) {
	p := NewBfdPacket()
	defer p.Free()
	if p.AuthPresent() {
		t.Fatal("fresh packet should not carry auth")
	}
	sec, err := p.Auth()
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if sec != nil {
		t.Fatal("Auth should return nil on fresh packet")
	}
}

func TestBfdPacketSetAuthSimplePasswordRoundTrip(t *testing.T) {
	p := NewBfdPacket()
	defer p.Free()
	pw := []byte("hunter2")
	s, err := NewBfdAuthSectionSimplePassword(pw, 7)
	if err != nil {
		t.Fatalf("NewBfdAuthSectionSimplePassword: %v", err)
	}
	if err := p.SetAuth(s); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	// SetAuth consumed `s` — its Free() must be a no-op now.
	s.Free()
	if !p.AuthPresent() {
		t.Fatal("packet should carry auth after SetAuth")
	}
	sec, err := p.Auth()
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	defer sec.Free()
	if sec == nil {
		t.Fatal("Auth should return non-nil")
	}
	if sec.AuthType() != BFDAuthTypeSimplePassword {
		t.Fatalf("AuthType = %d, want %d", sec.AuthType(), BFDAuthTypeSimplePassword)
	}
	if sec.KeyID() != 7 {
		t.Fatalf("KeyID = %d, want 7", sec.KeyID())
	}
	if sec.DataLen() != 7 {
		t.Fatalf("DataLen = %d, want 7", sec.DataLen())
	}
	// Clear via nil.
	if err := p.SetAuth(nil); err != nil {
		t.Fatalf("SetAuth(nil): %v", err)
	}
	if p.AuthPresent() {
		t.Fatal("packet should not carry auth after SetAuth(nil)")
	}
}

// ---- BfdKeyedAuth ----

func TestBfdKeyedAuthAuthSectionForTx(t *testing.T) {
	secret := []byte("0123456789abcdef")
	a, err := NewBfdKeyedAuth(BFDAuthAlgoKeyedMd5, 7, secret)
	if err != nil {
		t.Fatalf("NewBfdKeyedAuth: %v", err)
	}
	defer a.Free()
	if a.XmitSeq() != 0 {
		t.Fatalf("XmitSeq = %d, want 0", a.XmitSeq())
	}
	if a.KeyID() != 7 {
		t.Fatalf("KeyID = %d, want 7", a.KeyID())
	}
	if a.DigestLen() != 16 {
		t.Fatalf("DigestLen = %d, want 16", a.DigestLen())
	}
	if a.IsMeticulous() {
		t.Fatal("KeyedMd5 should not be meticulous")
	}

	sec, err := a.AuthSectionForTx()
	if err != nil {
		t.Fatalf("AuthSectionForTx: %v", err)
	}
	defer sec.Free()
	if sec.AuthType() != BFDAuthTypeKeyedMd5 {
		t.Fatalf("AuthType = %d, want %d", sec.AuthType(), BFDAuthTypeKeyedMd5)
	}
	if sec.KeyID() != 7 {
		t.Fatalf("KeyID = %d, want 7", sec.KeyID())
	}
	if seq, ok := sec.Sequence(); !ok || seq != 0 {
		t.Fatalf("Sequence = (%d, %v), want (0, true)", seq, ok)
	}
	if sec.DataLen() != 16 {
		t.Fatalf("DataLen = %d, want 16", sec.DataLen())
	}
	data, err := sec.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	if !bytes.Equal(data, secret) {
		t.Fatalf("Data = %v, want %v", data, secret)
	}

	// AdvanceXmitSeq bumps the counter.
	if err := a.AdvanceXmitSeq(); err != nil {
		t.Fatalf("AdvanceXmitSeq: %v", err)
	}
	if a.XmitSeq() != 1 {
		t.Fatalf("XmitSeq after advance = %d, want 1", a.XmitSeq())
	}
}

func TestBfdKeyedAuthEndToEndSignAndVerifyMd5(t *testing.T) {
	// End-to-end: build a packet + auth section, encode, sign, decode,
	// verify — mirrors the Rust-side `sign_and_verify_round_trip_md5`.
	secret := []byte("0123456789abcdef")
	auth, err := NewBfdKeyedAuth(BFDAuthAlgoKeyedMd5, 7, secret)
	if err != nil {
		t.Fatalf("NewBfdKeyedAuth: %v", err)
	}
	defer auth.Free()

	p := NewBfdHeartbeat(0x11112222, 0x33334444)
	defer p.Free()
	if err := p.SetFlags(0b0000_0100); err != nil { // A bit
		t.Fatalf("SetFlags: %v", err)
	}
	sec, err := auth.AuthSectionForTx()
	if err != nil {
		t.Fatalf("AuthSectionForTx: %v", err)
	}
	if err := p.SetAuth(sec); err != nil { // consumes `sec`
		t.Fatalf("SetAuth: %v", err)
	}
	wire, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Sign the encoded packet in place — the last 16 bytes
	// (MD5 digest) are replaced with the computed hash.
	if err := auth.SignPacket(wire); err != nil {
		t.Fatalf("SignPacket: %v", err)
	}

	// Decode the signed packet — the auth section's `data` field
	// now carries the received digest.
	dec, err := DecodeBfdPacket(wire)
	if err != nil {
		t.Fatalf("DecodeBfdPacket: %v", err)
	}
	defer dec.Free()
	secOut, err := dec.Auth()
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	defer secOut.Free()
	if secOut == nil {
		t.Fatal("Auth should return non-nil on signed packet")
	}

	// Verify the inbound packet — should authenticate (first
	// packet, AuthSeqKnown=0 → accept any sequence).
	ok, err := auth.VerifyInbound(wire, secOut, 3)
	if err != nil {
		t.Fatalf("VerifyInbound: %v", err)
	}
	if !ok {
		t.Fatal("VerifyInbound should return true on the signed packet")
	}
	if !auth.RcvAuthSeqKnown() {
		t.Fatal("RcvAuthSeqKnown should be true after verify")
	}
}
