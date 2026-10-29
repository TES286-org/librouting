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
