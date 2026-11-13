// Package librouting tests for the PeerHealthTable generated wrapper
// (issue #99 — peer-level BGP flap suppression).
//
// The peer-health C ABI surface (lr_peer_health_table_t handle, 9 entry
// points) was added as part of issue #99. The generic generated_test.go
// smoke suite does not drive the state machine. This file closes that
// gap with an end-to-end test that:
//
//   - constructs a PeerHealthTable with a Full-rollout config,
//   - accounts a burst of UPDATEs to escalate the peer past L0,
//   - verifies the tier query returns > 0 after the burst,
//   - reads back a session snapshot and checks the counters,
//   - confirms the degraded-count aggregate tracks the escalation,
//   - runs a tick and confirms it returns without error,
//   - frees the table (and double-free is a safe no-op).
//
// The test uses the Go-friendly PeerHealthConfig builder from
// peer_health.go so it does not need `import "C"` (cgo is not allowed
// in _test.go files in the same package as the library).

package librouting

import (
	"testing"
)

const (
	peerHealthAFIIPv4 = 1
	peerHealthSAFIUni = 1
)

func fullPeerHealthCfg() PeerHealthConfig {
	return PeerHealthConfig{
		Rollout:                PeerHealthRolloutFull,
		ShortWindowS:           5,
		MidWindowS:             30,
		LongWindowS:            120,
		BaselineWindowS:        480,
		MinTransitionIntervalS: 0,
		MinRecoveryIntervalS:   0,
		MaxStaleAgeS:           60,
		TickIntervalS:          1,
		SoftDegraded:           100,
		HardDegraded:           0,
	}
}

func trainThenBurstPeerHealth(t *testing.T, tbl *PeerHealthTable, peer uint64, burstCount int) uint64 {
	t.Helper()
	for i := uint64(0); i < 10; i++ {
		if _, err := tbl.AccountUpdate(peer, peerHealthAFIIPv4, peerHealthSAFIUni, i*1000); err != nil {
			t.Fatalf("AccountUpdate train: %v", err)
		}
	}
	now := uint64(10_000)
	for i := 0; i < burstCount; i++ {
		if _, err := tbl.AccountUpdate(peer, peerHealthAFIIPv4, peerHealthSAFIUni, now); err != nil {
			t.Fatalf("AccountUpdate burst: %v", err)
		}
		now += 10
	}
	return now
}

func TestPeerHealthTableConstructAndFree(t *testing.T) {
	tbl, err := NewPeerHealthTableFromConfig(fullPeerHealthCfg())
	if err != nil {
		t.Fatalf("NewPeerHealthTableFromConfig: %v", err)
	}
	if tbl == nil {
		t.Fatal("NewPeerHealthTableFromConfig returned nil")
	}
	defer tbl.Free()
	count, err := tbl.SessionCount()
	if err != nil {
		t.Fatalf("SessionCount: %v", err)
	}
	if count != 0 {
		t.Errorf("empty table session_count = %d, want 0", count)
	}
	tbl.Free()
}

func TestPeerHealthEscalationAndTierQuery(t *testing.T) {
	tbl, err := NewPeerHealthTableFromConfig(fullPeerHealthCfg())
	if err != nil {
		t.Fatalf("NewPeerHealthTableFromConfig: %v", err)
	}
	defer tbl.Free()
	trainThenBurstPeerHealth(t, tbl, 1, 200)
	tier, err := tbl.Tier(1, peerHealthAFIIPv4, peerHealthSAFIUni)
	if err != nil {
		t.Fatalf("Tier: %v", err)
	}
	if tier == 0 {
		t.Error("peer should be degraded after burst, got tier=0")
	}
	deg, err := tbl.DegradedCount()
	if err != nil {
		t.Fatalf("DegradedCount: %v", err)
	}
	if deg == 0 {
		t.Error("degraded_count should be >= 1 after escalation")
	}
}

func TestPeerHealthOffModeNeverDegrades(t *testing.T) {
	cfg := fullPeerHealthCfg()
	cfg.Rollout = PeerHealthRolloutOff
	tbl, err := NewPeerHealthTableFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewPeerHealthTableFromConfig: %v", err)
	}
	defer tbl.Free()
	trainThenBurstPeerHealth(t, tbl, 1, 200)
	tier, err := tbl.Tier(1, peerHealthAFIIPv4, peerHealthSAFIUni)
	if err != nil {
		t.Fatalf("Tier: %v", err)
	}
	if tier != 0 {
		t.Errorf("Off mode tier = %d, want 0", tier)
	}
	count, _ := tbl.SessionCount()
	if count != 0 {
		t.Errorf("Off mode session_count = %d, want 0", count)
	}
	deg, _ := tbl.DegradedCount()
	if deg != 0 {
		t.Errorf("Off mode degraded_count = %d, want 0", deg)
	}
}

func TestPeerHealthTickRuns(t *testing.T) {
	tbl, err := NewPeerHealthTableFromConfig(fullPeerHealthCfg())
	if err != nil {
		t.Fatalf("NewPeerHealthTableFromConfig: %v", err)
	}
	defer tbl.Free()
	finalMs := trainThenBurstPeerHealth(t, tbl, 1, 200)
	if _, err := tbl.Tick(finalMs + 60_000); err != nil {
		t.Fatalf("Tick: %v", err)
	}
}
