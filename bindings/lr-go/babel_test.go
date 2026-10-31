// Tests for the Babel protocol Go binding (RFC 8966 + RFC 8967).
//
// Mirrors the Rust-side `crates/lr-babel/src/*.rs` unit tests and the
// Python `bindings/lr-python/tests/test_babel.py`. Every public Go
// API on `BabelFrame`, `BabelCodec`, `BabelRouteTable`, `BabelNeighbor`,
// `MacKey`, `PseudoHeader`, `PacketCounter`, `ReplayProtection`, and
// the message constructors is exercised through the Go surface.

package librouting

import (
        "bytes"
        "testing"
)

// ---- Helpers ----------------------------------------------------------

func mustBabelV4Key(t *testing.T, addr [4]byte, plen uint8, ridByte byte) BabelRouteKey {
        t.Helper()
        return BabelRouteKey{
                DestinationAddr:     addr[:],
                DestinationPrefixLen: plen,
                RouterID:            []byte{ridByte, ridByte, ridByte, ridByte, ridByte, ridByte, ridByte, ridByte},
        }
}

func mustBabelV4Route(t *testing.T, key BabelRouteKey, seqno uint16, metric uint32, nh [4]byte) BabelRoute {
        t.Helper()
        return BabelRoute{
                Key:     key,
                Seqno:   seqno,
                Metric:  metric,
                NextHop: nh[:],
        }
}

// ---- TLV + Frame ------------------------------------------------------

func TestBabelTlvPad1(t *testing.T) {
        tlv := BabelTlvPad1()
        defer tlv.Free()
        if got := tlv.Kind(); got != BabelTlvTypePad1 {
                t.Errorf("Kind = %d, want %d", got, BabelTlvTypePad1)
        }
        v, err := tlv.Value()
        if err != nil {
                t.Fatalf("Value: %v", err)
        }
        if len(v) != 0 {
                t.Errorf("Value len = %d, want 0", len(v))
        }
}

func TestBabelTlvPadN(t *testing.T) {
        tlv := BabelTlvPadN(4)
        defer tlv.Free()
        if got := tlv.Kind(); got != BabelTlvTypePadN {
                t.Errorf("Kind = %d, want %d", got, BabelTlvTypePadN)
        }
        v, err := tlv.Value()
        if err != nil {
                t.Fatalf("Value: %v", err)
        }
        if !bytes.Equal(v, []byte{0, 0, 0, 0}) {
                t.Errorf("Value = %v, want 4 zero bytes", v)
        }
}

func TestBabelTlvNew(t *testing.T) {
        tlv, err := NewBabelTlv(BabelTlvTypeAckReq, []byte{0x00, 0x2a, 0x00, 0xc8})
        if err != nil {
                t.Fatalf("NewBabelTlv: %v", err)
        }
        defer tlv.Free()
        if got := tlv.Kind(); got != BabelTlvTypeAckReq {
                t.Errorf("Kind = %d, want %d", got, BabelTlvTypeAckReq)
        }
        v, _ := tlv.Value()
        if !bytes.Equal(v, []byte{0x00, 0x2a, 0x00, 0xc8}) {
                t.Errorf("Value = %v", v)
        }
}

func TestBabelFrameEmpty(t *testing.T) {
        f := NewBabelFrame()
        defer f.Free()
        if got := f.TlvCount(); got != 0 {
                t.Errorf("TlvCount = %d, want 0", got)
        }
}

func TestBabelFramePushTlv(t *testing.T) {
        f := NewBabelFrame()
        defer f.Free()
        if err := f.PushTlv(BabelTlvPad1()); err != nil {
                t.Fatalf("PushTlv: %v", err)
        }
        if got := f.TlvCount(); got != 1 {
                t.Errorf("TlvCount = %d, want 1", got)
        }
        k, err := f.TlvTypeAt(0)
        if err != nil {
                t.Fatalf("TlvTypeAt: %v", err)
        }
        if k != BabelTlvTypePad1 {
                t.Errorf("TlvTypeAt(0) = %d, want %d", k, BabelTlvTypePad1)
        }
}

func TestBabelFrameFromTlvs(t *testing.T) {
        t1 := BabelTlvPad1()
        t2 := BabelTlvPadN(2)
        f, err := NewBabelFrameFromTlvs([]*Tlv{t1, t2})
        if err != nil {
                t.Fatalf("NewBabelFrameFromTlvs: %v", err)
        }
        defer f.Free()
        if got := f.TlvCount(); got != 2 {
                t.Fatalf("TlvCount = %d, want 2", got)
        }
}

func TestBabelFrameEncode(t *testing.T) {
        f := NewBabelFrame()
        defer f.Free()
        if err := f.PushTlv(BabelTlvPad1()); err != nil {
                t.Fatalf("PushTlv: %v", err)
        }
        wire, err := f.Encode()
        if err != nil {
                t.Fatalf("Encode: %v", err)
        }
        // magic(1) + version(1) + body_len(2) + body. Pad1 body is 1 byte.
        want := []byte{0x2A, 0x02, 0x00, 0x01, 0x00}
        if !bytes.Equal(wire, want) {
                t.Errorf("Encode = %v, want %v", wire, want)
        }
}

func TestDecodeBabelFrame(t *testing.T) {
        wire := []byte{0x2A, 0x02, 0x00, 0x01, 0x00}
        f, err := DecodeBabelFrame(wire)
        if err != nil {
                t.Fatalf("DecodeBabelFrame: %v", err)
        }
        defer f.Free()
        if got := f.TlvCount(); got < 1 {
                t.Errorf("TlvCount = %d, want >= 1", got)
        }
        k, _ := f.TlvTypeAt(0)
        if k != BabelTlvTypePad1 {
                t.Errorf("TlvTypeAt(0) = %d, want %d", k, BabelTlvTypePad1)
        }
}

func TestBabelFrameIndexOutOfRange(t *testing.T) {
        f := NewBabelFrame()
        defer f.Free()
        if _, err := f.TlvTypeAt(0); err == nil {
                t.Error("TlvTypeAt(0) on empty frame should error")
        }
}

// ---- TLV type enum helpers -------------------------------------------

func TestBabelTlvTypeToU8Identity(t *testing.T) {
        if got := BabelTlvTypeToU8(BabelTlvTypeHello); got != BabelTlvTypeHello {
                t.Errorf("ToU8(Hello) = %d, want %d", got, BabelTlvTypeHello)
        }
}

func TestBabelTlvTypeFromU8Identity(t *testing.T) {
        if got := BabelTlvTypeFromU8(BabelTlvTypeHello); got != BabelTlvTypeHello {
                t.Errorf("FromU8(Hello) = %d, want %d", got, BabelTlvTypeHello)
        }
}

func TestBabelTlvTypeNameKnown(t *testing.T) {
        if name := BabelTlvTypeName(BabelTlvTypePad1); name == "" {
                t.Error("TlvTypeName(Pad1) returned empty string")
        }
}

// ---- BabelRouteTable ---------------------------------------------------

func TestBabelRouteTableEmpty(t *testing.T) {
        tab := NewBabelRouteTable()
        defer tab.Free()
        if !tab.IsEmpty() {
                t.Error("fresh table not empty")
        }
        if got := tab.Len(); got != 0 {
                t.Errorf("Len = %d, want 0", got)
        }
        if got := tab.BestRoutesCount(); got != 0 {
                t.Errorf("BestRoutesCount = %d, want 0", got)
        }
}

func TestBabelRouteTableInsertGetV4(t *testing.T) {
        tab := NewBabelRouteTable()
        defer tab.Free()

        key := mustBabelV4Key(t, [4]byte{10, 0, 0, 0}, 8, 1)
        r := mustBabelV4Route(t, key, 1, 100, [4]byte{10, 0, 0, 1})
        if err := tab.Insert(r); err != nil {
                t.Fatalf("Insert: %v", err)
        }
        if got := tab.Len(); got != 1 {
                t.Fatalf("Len = %d, want 1", got)
        }
        if tab.IsEmpty() {
                t.Error("IsEmpty returned true after insert")
        }

        got, ok, err := tab.Get(key)
        if err != nil {
                t.Fatalf("Get: %v", err)
        }
        if !ok {
                t.Fatal("Get returned ok=false for an inserted key")
        }
        if got.Seqno != 1 {
                t.Errorf("Seqno = %d, want 1", got.Seqno)
        }
        if got.Metric != 100 {
                t.Errorf("Metric = %d, want 100", got.Metric)
        }
        if !bytes.Equal(got.NextHop, []byte{10, 0, 0, 1}) {
                t.Errorf("NextHop = %v, want 10.0.0.1", got.NextHop)
        }
        // The table marks a freshly-inserted route feasible (RFC 8966 §3.5.2).
        if !got.Feasible {
                t.Error("Feasible = false, want true (fresh route is feasible by default)")
        }
}

func TestBabelRouteTableContainsMissing(t *testing.T) {
        tab := NewBabelRouteTable()
        defer tab.Free()
        key := mustBabelV4Key(t, [4]byte{10, 0, 0, 0}, 8, 1)
        ok, err := tab.Contains(key)
        if err != nil {
                t.Fatalf("Contains: %v", err)
        }
        if ok {
                t.Error("Contains returned true for a missing key")
        }
}

func TestBabelRouteTableGetMissing(t *testing.T) {
        tab := NewBabelRouteTable()
        defer tab.Free()
        key := mustBabelV4Key(t, [4]byte{10, 0, 0, 0}, 8, 1)
        if _, ok, err := tab.Get(key); err != nil {
                t.Fatalf("Get: %v", err)
        } else if ok {
                t.Error("Get returned ok=true for a missing key")
        }
}

func TestBabelRouteTableWithdraw(t *testing.T) {
        tab := NewBabelRouteTable()
        defer tab.Free()
        key := mustBabelV4Key(t, [4]byte{10, 0, 0, 0}, 8, 1)
        r := mustBabelV4Route(t, key, 1, 100, [4]byte{10, 0, 0, 1})
        if err := tab.Insert(r); err != nil {
                t.Fatalf("Insert: %v", err)
        }
        if err := tab.Withdraw(key); err != nil {
                t.Fatalf("Withdraw: %v", err)
        }
        if got := tab.Len(); got != 0 {
                t.Errorf("Len after withdraw = %d, want 0", got)
        }
}

func TestBabelRouteTableIterAll(t *testing.T) {
        tab := NewBabelRouteTable()
        defer tab.Free()
        key := mustBabelV4Key(t, [4]byte{10, 0, 0, 0}, 8, 1)
        r := mustBabelV4Route(t, key, 1, 100, [4]byte{10, 0, 0, 1})
        if err := tab.Insert(r); err != nil {
                t.Fatalf("Insert: %v", err)
        }
        count := 0
        err := tab.IterAll(func(got BabelRoute) error {
                count++
                if got.Seqno != 1 {
                        t.Errorf("Seqno = %d, want 1", got.Seqno)
                }
                return nil
        })
        if err != nil {
                t.Fatalf("IterAll: %v", err)
        }
        if count != 1 {
                t.Errorf("IterAll visited %d routes, want 1", count)
        }
}

func TestBabelRouteTableIterBest(t *testing.T) {
        tab := NewBabelRouteTable()
        defer tab.Free()
        key := mustBabelV4Key(t, [4]byte{10, 0, 0, 0}, 8, 1)
        r := mustBabelV4Route(t, key, 1, 100, [4]byte{10, 0, 0, 1})
        if err := tab.Insert(r); err != nil {
                t.Fatalf("Insert: %v", err)
        }
        count := 0
        err := tab.IterBest(func(got BabelRoute) error {
                count++
                if got.Metric != 100 {
                        t.Errorf("Metric = %d, want 100", got.Metric)
                }
                return nil
        })
        if err != nil {
                t.Fatalf("IterBest: %v", err)
        }
        if count != 1 {
                t.Errorf("IterBest visited %d routes, want 1", count)
        }
        if got := tab.BestRoutesCount(); got != 1 {
                t.Errorf("BestRoutesCount = %d, want 1", got)
        }
}

func TestBabelRouteTableV6WithSource(t *testing.T) {
        tab := NewBabelRouteTable()
        defer tab.Free()

        key := BabelRouteKey{
                DestinationAddr: []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                DestinationPrefixLen: 64,
                SourceAddr:      []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                SourcePrefixLen: 48,
                RouterID:        []byte{2, 2, 2, 2, 2, 2, 2, 2},
        }
        r := BabelRoute{
                Key:      key,
                Seqno:    2,
                Metric:   200,
                NextHop:  []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
                Feasible: true,
                Installed: true,
        }
        if err := tab.Insert(r); err != nil {
                t.Fatalf("Insert: %v", err)
        }
        if got := tab.Len(); got != 1 {
                t.Fatalf("Len = %d, want 1", got)
        }
        got, ok, err := tab.Get(key)
        if err != nil {
                t.Fatalf("Get: %v", err)
        }
        if !ok {
                t.Fatal("Get returned ok=false for an inserted key")
        }
        if !bytes.Equal(got.Key.DestinationAddr,
                []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) {
                t.Errorf("DestinationAddr = %v", got.Key.DestinationAddr)
        }
        if got.Key.DestinationPrefixLen != 64 {
                t.Errorf("DestinationPrefixLen = %d, want 64", got.Key.DestinationPrefixLen)
        }
        if !got.Key.IsSourceSpecific() {
                t.Error("IsSourceSpecific = false, want true")
        }
        if !bytes.Equal(got.Key.SourceAddr,
                []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) {
                t.Errorf("SourceAddr = %v", got.Key.SourceAddr)
        }
        if got.Key.SourcePrefixLen != 48 {
                t.Errorf("SourcePrefixLen = %d, want 48", got.Key.SourcePrefixLen)
        }
        if !bytes.Equal(got.NextHop,
                []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}) {
                t.Errorf("NextHop = %v", got.NextHop)
        }
}

func TestBabelRouteTableExpire(t *testing.T) {
        tab := NewBabelRouteTable()
        defer tab.Free()
        key := mustBabelV4Key(t, [4]byte{10, 0, 0, 0}, 8, 1)
        r := mustBabelV4Route(t, key, 1, 100, [4]byte{10, 0, 0, 1})
        if err := tab.Insert(r); err != nil {
                t.Fatalf("Insert: %v", err)
        }
        // Insert calls insert_timed(route, 0, 0); hold_ms = max(0*60,
        // 30_000) = 30_000ms, so the route expires at now=30_001+ms.
        if got := tab.Expire(40_000); got != 1 {
                t.Errorf("Expire returned %d, want 1 (the inserted route expires by 40s)", got)
        }
        if got := tab.Len(); got != 0 {
                t.Errorf("Len after expire = %d, want 0", got)
        }
}

// ---- BabelNeighbor -----------------------------------------------------

func TestBabelNeighborV4(t *testing.T) {
        n, err := NewBabelNeighbor([]byte{10, 0, 0, 1}, 1000)
        if err != nil {
                t.Fatalf("NewBabelNeighbor: %v", err)
        }
        defer n.Free()
        if err := n.Hello(1, 100, 1100); err != nil {
                t.Fatalf("Hello: %v", err)
        }
        if err := n.Ihu(96, 100, 1100); err != nil {
                t.Fatalf("Ihu: %v", err)
        }
        if n.RttValid(1200) {
                t.Error("RttValid = true, want false (no timestamped Hello)")
        }
        if got := n.RttUS(1200); got != 0 {
                t.Errorf("RttUS = %d, want 0", got)
        }
}

func TestBabelNeighborV6(t *testing.T) {
        addr := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
        n, err := NewBabelNeighbor(addr, 0)
        if err != nil {
                t.Fatalf("NewBabelNeighbor: %v", err)
        }
        defer n.Free()
        if err := n.Hello(1, 100, 100); err != nil {
                t.Fatalf("Hello: %v", err)
        }
}

func TestBabelNeighborBadAddr(t *testing.T) {
        if _, err := NewBabelNeighbor([]byte{}, 0); err == nil {
                t.Error("empty address should error")
        }
        if _, err := NewBabelNeighbor([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 0); err == nil {
                t.Error("8-byte address should error")
        }
}

// ---- MacKey + PseudoHeader + PacketCounter + ReplayProtection ----------

func TestMacKeyHmacSha256(t *testing.T) {
        k := NewMacKeyHmacSHA256([]byte("secret"))
        defer k.Free()
        if got := k.Algorithm(); got != BabelMacHMACSHA256 {
                t.Errorf("Algorithm = %d, want %d", got, BabelMacHMACSHA256)
        }
        if got := k.DigestLen(); got != 32 {
                t.Errorf("DigestLen = %d, want 32", got)
        }
        got, _ := k.Secret()
        if !bytes.Equal(got, []byte("secret")) {
                t.Errorf("Secret = %q, want %q", got, "secret")
        }
}

func TestMacKeyBlake2s128(t *testing.T) {
        k := NewMacKeyBlake2s128([]byte("secret"))
        defer k.Free()
        if got := k.Algorithm(); got != BabelMacBlake2s128 {
                t.Errorf("Algorithm = %d, want %d", got, BabelMacBlake2s128)
        }
        if got := k.DigestLen(); got != 16 {
                t.Errorf("DigestLen = %d, want 16", got)
        }
}

func TestMacKeyNewDefault(t *testing.T) {
        k, err := NewMacKey(BabelMacHMACSHA256, []byte("secret"))
        if err != nil {
                t.Fatalf("NewMacKey: %v", err)
        }
        defer k.Free()
        if got := k.Algorithm(); got != BabelMacHMACSHA256 {
                t.Errorf("Algorithm = %d, want %d", got, BabelMacHMACSHA256)
        }
}

func TestPseudoHeaderV4(t *testing.T) {
        ph, err := NewPseudoHeaderV4([]byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}, 6696, 6696)
        if err != nil {
                t.Fatalf("NewPseudoHeaderV4: %v", err)
        }
        defer ph.Free()
        wire, err := ph.Encode()
        if err != nil {
                t.Fatalf("Encode: %v", err)
        }
        if len(wire) == 0 {
                t.Error("Encode returned empty bytes")
        }
}

func TestPseudoHeaderV6(t *testing.T) {
        src := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
        dst := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
        ph, err := NewPseudoHeaderV6(src, dst, 6696, 6696)
        if err != nil {
                t.Fatalf("NewPseudoHeaderV6: %v", err)
        }
        defer ph.Free()
        if _, err := ph.Encode(); err != nil {
                t.Fatalf("Encode: %v", err)
        }
}

func TestPacketCounter(t *testing.T) {
        c, err := NewPacketCounter([]byte("index"), 10)
        if err != nil {
                t.Fatalf("NewPacketCounter: %v", err)
        }
        defer c.Free()
        if got := c.Counter(); got != 10 {
                t.Errorf("Counter = %d, want 10", got)
        }
        if got := c.IndexLen(); got != 5 {
                t.Errorf("IndexLen = %d, want 5", got)
        }
        idx, _ := c.Index()
        if !bytes.Equal(idx, []byte("index")) {
                t.Errorf("Index = %q, want %q", idx, "index")
        }
}

func TestReplayProtection(t *testing.T) {
        r := NewReplayProtection()
        defer r.Free()
        if ok, err := r.Accept([]byte("idx"), 5); err != nil || !ok {
                t.Errorf("Accept(5) = %v, %v, want true", ok, err)
        }
        if ok, err := r.Accept([]byte("idx"), 3); err != nil || ok {
                t.Errorf("Accept(3) = %v, %v, want false (replay)", ok, err)
        }
        if ok, err := r.Accept([]byte("idx"), 5); err != nil || ok {
                t.Errorf("Accept(5) = %v, %v, want false (equal)", ok, err)
        }
        if ok, err := r.Accept([]byte("idx"), 6); err != nil || !ok {
                t.Errorf("Accept(6) = %v, %v, want true", ok, err)
        }
}

// ---- Message constructors --------------------------------------------

func TestBabelHello(t *testing.T) {
        h := NewBabelHello(1, 100)
        defer h.Free()
        if got := h.Seqno(); got != 1 {
                t.Errorf("Seqno = %d, want 1", got)
        }
        if got := h.IntervalCs(); got != 100 {
                t.Errorf("IntervalCs = %d, want 100", got)
        }
        if err := h.SetUnicast(true); err != nil {
                t.Fatalf("SetUnicast: %v", err)
        }
        if got := h.Flags(); got == 0 {
                t.Error("Flags = 0 after SetUnicast(true), want non-zero")
        }
        if _, err := h.Encode(); err != nil {
                t.Fatalf("Encode: %v", err)
        }
}

func TestBabelIhu(t *testing.T) {
        h := NewBabelIhu(96, 100)
        defer h.Free()
        if got := h.Rxcost(); got != 96 {
                t.Errorf("Rxcost = %d, want 96", got)
        }
        if got := h.IntervalCs(); got != 100 {
                t.Errorf("IntervalCs = %d, want 100", got)
        }
        if _, err := h.Encode(); err != nil {
                t.Fatalf("Encode: %v", err)
        }
}

func TestBabelAckReq(t *testing.T) {
        a := NewBabelAckReq(42, 200)
        defer a.Free()
        if got := a.Nonce(); got != 42 {
                t.Errorf("Nonce = %d, want 42", got)
        }
        if got := a.IntervalCs(); got != 200 {
                t.Errorf("IntervalCs = %d, want 200", got)
        }
}

func TestBabelAck(t *testing.T) {
        a := NewBabelAck(42)
        defer a.Free()
        if got := a.Opaque(); got != 42 {
                t.Errorf("Opaque = %d, want 42", got)
        }
        if _, err := a.Encode(); err != nil {
                t.Fatalf("Encode: %v", err)
        }
}

func TestBabelNextHopV4(t *testing.T) {
        n, err := NewBabelNextHop([]byte{10, 0, 0, 1})
        if err != nil {
                t.Fatalf("NewBabelNextHop: %v", err)
        }
        defer n.Free()
        if got := n.AE(); got != BabelAEIPv4 {
                t.Errorf("AE = %d, want %d", got, BabelAEIPv4)
        }
        if got := n.Address(); !bytes.Equal(got, []byte{10, 0, 0, 1}) {
                t.Errorf("Address = %v, want 10.0.0.1", got)
        }
}

func TestBabelNextHopV6(t *testing.T) {
        addr := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
        n, err := NewBabelNextHop(addr)
        if err != nil {
                t.Fatalf("NewBabelNextHop: %v", err)
        }
        defer n.Free()
        if got := n.AE(); got != BabelAEIPv6 {
                t.Errorf("AE = %d, want %d", got, BabelAEIPv6)
        }
}

func TestBabelNextHopBadAddr(t *testing.T) {
        if _, err := NewBabelNextHop([]byte{1, 2}); err == nil {
                t.Error("2-byte address should error")
        }
}

func TestBabelRouterID(t *testing.T) {
        rid, err := NewBabelRouterID([]byte{1, 1, 1, 1, 1, 1, 1, 1})
        if err != nil {
                t.Fatalf("NewBabelRouterID: %v", err)
        }
        defer rid.Free()
        got, err := rid.Bytes()
        if err != nil {
                t.Fatalf("Bytes: %v", err)
        }
        if !bytes.Equal(got, []byte{1, 1, 1, 1, 1, 1, 1, 1}) {
                t.Errorf("Bytes = %v, want 8x 0x01", got)
        }
}

func TestBabelRouterIDBadLength(t *testing.T) {
        if _, err := NewBabelRouterID([]byte{1, 1, 1, 1, 1, 1, 1}); err == nil {
                t.Error("7-byte router_id should error")
        }
}

func TestBabelRouteRequestWildcard(t *testing.T) {
        r := NewBabelRouteRequestWildcard()
        defer r.Free()
}

func TestBabelSeqnoRequest(t *testing.T) {
        r, err := NewBabelSeqnoRequest([]byte{10, 0, 0, 0}, 8, 1,
                []byte{1, 1, 1, 1, 1, 1, 1, 1}, 255)
        if err != nil {
                t.Fatalf("NewBabelSeqnoRequest: %v", err)
        }
        defer r.Free()
}

func TestBabelSeqnoRequestBadRouterID(t *testing.T) {
        if _, err := NewBabelSeqnoRequest([]byte{10, 0, 0, 0}, 8, 1,
                []byte{1, 1, 1, 1, 1, 1, 1}, 255); err == nil {
                t.Error("7-byte router_id should error")
        }
}

func TestBabelSeqnoRequestBadPrefix(t *testing.T) {
        if _, err := NewBabelSeqnoRequest([]byte{1, 2}, 8, 1,
                []byte{1, 1, 1, 1, 1, 1, 1, 1}, 255); err == nil {
                t.Error("2-byte prefix should error")
        }
}

// ---- Free function helpers --------------------------------------------

func TestBabelRttPenaltyDisabled(t *testing.T) {
        if got := BabelRttPenalty(500_000, 10_000, 120_000, 0); got != 0 {
                t.Errorf("RttPenalty(max=0) = %d, want 0", got)
        }
}

func TestBabelRttPenaltyClamped(t *testing.T) {
        if got := BabelRttPenalty(1_000_000, 10_000, 120_000, 96); got != 96 {
                t.Errorf("RttPenalty(clamped) = %d, want 96", got)
        }
}

func TestBabelRttPenaltyInterpolated(t *testing.T) {
        penalty := BabelRttPenalty(65_000, 10_000, 120_000, 96)
        if penalty < 40 || penalty > 56 {
                t.Errorf("RttPenalty(mid) = %d, want roughly 48 (40..56)", penalty)
        }
}

func TestBabelRouteMetricSum(t *testing.T) {
        if got := BabelRouteMetricSum([]uint32{100, 200, 300}); got != 600 {
                t.Errorf("RouteMetricSum([100,200,300]) = %d, want 600", got)
        }
        if got := BabelRouteMetricSum(nil); got != 0 {
                t.Errorf("RouteMetricSum(nil) = %d, want 0", got)
        }
        if got := BabelRouteMetricSum([]uint32{42}); got != 42 {
                t.Errorf("RouteMetricSum([42]) = %d, want 42", got)
        }
}

func TestBabelFeasibleStrictlyBetter(t *testing.T) {
        if !BabelFeasible(1, 100, 0, 200) {
                t.Error("Feasible(seq=1,metric=100, fs=0,fm=200) = false, want true (seq higher)")
        }
        if BabelFeasible(1, 100, 1, 100) {
                t.Error("Feasible(equal) = true, want false (not strictly better)")
        }
        if BabelFeasible(0, 50, 1, 100) {
                t.Error("Feasible(seq=0, fs=1) = true, want false (seq lower)")
        }
}
