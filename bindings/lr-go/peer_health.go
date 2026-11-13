// Package librouting hand-written helpers for the PeerHealthTable
// surface (issue #99 — peer-level BGP flap suppression).
//
// The generated layer in generated.go exposes
// `NewPeerHealthTable(cfg *C.lr_peer_health_config_t)` and the
// per-handle methods, but the caller still has to construct the C
// config struct. This file provides a Go-friendly `PeerHealthConfig`
// builder that mirrors the Rust-side defaults and constructs the C
// struct, so embedders (and the test below) do not have to drop into
// cgo themselves.
//
// The constants mirror `lr_peer_health::RolloutMode` (config.rs):
//   Off=0, Observe=1, Shadow=2, ShadowBestPath=3, Limited=4, Full=5.

package librouting

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -llr_ffi

#include <stdlib.h>
#include "lr_ffi.h"
*/
import "C"

import (
        "fmt"
        "unsafe"
)

// Rollout mode discriminants matching lr_peer_health::RolloutMode.
const (
        PeerHealthRolloutOff            = 0
        PeerHealthRolloutObserve        = 1
        PeerHealthRolloutShadow         = 2
        PeerHealthRolloutShadowBestPath = 3
        PeerHealthRolloutLimited        = 4
        PeerHealthRolloutFull           = 5
)

// PeerHealthConfig is a Go-friendly mirror of the C
// `lr_peer_health_config_t` struct. Zero values pick up the Rust-side
// defaults (the C struct's `into_rust()` only overrides a field when
// the value is non-zero, so a zeroed Go struct produces the default
// config). Fields that have no natural zero value (rollout) must be
// set explicitly.
type PeerHealthConfig struct {
        Rollout                  uint8
        ShortWindowS             uint64
        MidWindowS               uint64
        LongWindowS              uint64
        BaselineWindowS          uint64
        MinTransitionIntervalS   uint64
        MinRecoveryIntervalS     uint64
        MaxStaleAgeS             uint64
        TickIntervalS            uint64
        SoftDegraded             uint32
        HardDegraded             uint32
}

// cPtr allocates a C `lr_peer_health_config_t` on the C heap and
// populates it from the Go struct. The caller owns the pointer and
// must free it with C.free.
func (cfg PeerHealthConfig) cPtr() (*C.lr_peer_health_config_t, error) {
        p := (*C.lr_peer_health_config_t)(C.malloc(C.size_t(unsafe.Sizeof(C.lr_peer_health_config_t{}))))
        if p == nil {
                return nil, fmt.Errorf("PeerHealthConfig.cPtr: malloc failed")
        }
        *p = C.lr_peer_health_config_t{}
        p.rollout = C.uint8_t(cfg.Rollout)
        p.short_window_s = C.uint64_t(cfg.ShortWindowS)
        p.mid_window_s = C.uint64_t(cfg.MidWindowS)
        p.long_window_s = C.uint64_t(cfg.LongWindowS)
        p.baseline_window_s = C.uint64_t(cfg.BaselineWindowS)
        p.min_transition_interval_s = C.uint64_t(cfg.MinTransitionIntervalS)
        p.min_recovery_interval_s = C.uint64_t(cfg.MinRecoveryIntervalS)
        p.max_stale_age_s = C.uint64_t(cfg.MaxStaleAgeS)
        p.tick_interval_s = C.uint64_t(cfg.TickIntervalS)
        p.soft_degraded = C.uint32_t(cfg.SoftDegraded)
        p.hard_degraded = C.uint32_t(cfg.HardDegraded)
        return p, nil
}

// NewPeerHealthTableFromConfig constructs a PeerHealthTable from a
// Go-friendly PeerHealthConfig, hiding the cgo struct allocation.
// The caller owns the returned table and must call Free on it.
func NewPeerHealthTableFromConfig(cfg PeerHealthConfig) (*PeerHealthTable, error) {
        cCfg, err := cfg.cPtr()
        if err != nil {
                return nil, err
        }
        defer C.free(unsafe.Pointer(cCfg))
        // NewPeerHealthTable already registers a runtime finalizer on the
        // returned handle; do not double-register.
        return NewPeerHealthTable(cCfg)
}
