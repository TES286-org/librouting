//! End-to-end coverage for issue #99 — peer-level flap suppression.
//!
//! Exercises the full integration path:
//! 1. A `PeerHealthTable` with a `PeerHealthImportHook` installed
//!    on the import chain.
//! 2. A burst of UPDATEs from one peer triggers escalation.
//! 3. The hook stamps `LrPeerHealthTier` on routes from the
//!    degraded peer.
//! 4. `BestPath::rank_tiered` picks the L0 candidate over the L1
//!    candidate when both are available.
//!
//! This test does not use real BGP sessions — it drives the hook
//! directly with synthetic routes, mirroring the `DampingImportHook`
//! tests in `lr-policy`.

use std::sync::{Arc, Mutex};

use lr_bgp::best_path::{BestPath, BestPathConfig};
use lr_bgp::path::PathAttributes;
use lr_core::addr::Prefix;
use lr_core::attr::{Attribute, Attributes};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
use lr_peer_health::{GlobalBudgets, PeerHealthConfig, PeerHealthTable, RolloutMode, WindowBudget};
use lr_policy::hooks::{HookVerdict, ImportHook, PeerHealthImportHook};

fn cfg_test() -> PeerHealthConfig {
    let mut cfg = PeerHealthConfig::default();
    cfg.rollout = RolloutMode::Full;
    cfg.short_window = WindowBudget {
        window_s: 5,
        enter_multiplier: 1.5,
        exit_multiplier: 0.75,
        emergency_multiplier: 8.0,
    };
    cfg.mid_window = WindowBudget {
        window_s: 30,
        enter_multiplier: 1.5,
        exit_multiplier: 0.75,
        emergency_multiplier: 8.0,
    };
    cfg.long_window = WindowBudget {
        window_s: 120,
        enter_multiplier: 1.5,
        exit_multiplier: 0.75,
        emergency_multiplier: 8.0,
    };
    cfg.baseline_window_s = 480;
    cfg.min_baseline_rate_eps = 0.1;
    cfg.min_transition_interval_s = 0;
    cfg.min_recovery_interval_s = 0;
    cfg.dwell_s = [0, 0, 0, 0];
    cfg.max_stale_age_s = 60;
    cfg.tick_interval_s = 1;
    cfg.global_budgets = GlobalBudgets {
        soft_degraded: 100,
        hard_degraded: 0,
    };
    cfg
}

fn bgp_route(prefix: [u8; 4], plen: u8, peer: u64, age_ms: u64) -> Route {
    let mut attrs = Attributes::new();
    attrs.insert(Attribute {
        tag: lr_core::attr::AttrTag(2),
        flags: 0,
        value: vec![2, 1, 0, 0, 100],
    });
    Route {
        key: RouteKey::new(Prefix::new_v4(prefix, plen), NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin { proto: 0, peer },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 0),
        next_hop: None,
        attributes: attrs,
        age_ms,
        path_id: 0,
        tag: None,
    }
}

#[test]
fn peer_health_e2e_escalation_and_tiered_selection() {
    let table = Arc::new(Mutex::new(PeerHealthTable::new(cfg_test())));
    let hook = PeerHealthImportHook::new(Arc::clone(&table));

    // Phase 1: train the baseline at 1 event/sec for 10 seconds.
    for i in 0..10u64 {
        let mut r = bgp_route([203, 0, 113, 0], 24, 1, i * 1000);
        let _ = hook.on_import(&mut r);
    }

    // Phase 2: burst 200 events at 10ms apart starting at t=10s.
    // The peer should escalate past L0.
    for i in 0..200u64 {
        let mut r = bgp_route([203, 0, 113, 0], 24, 1, 10_000 + i * 10);
        let _ = hook.on_import(&mut r);
    }

    // The peer is now degraded.
    assert!(
        table
            .lock()
            .unwrap()
            .is_degraded(1, NlriFamily::IPV4_UNICAST),
        "peer should be degraded after the burst"
    );

    // Phase 3: verify the tier attribute is stamped on a fresh route
    // from the degraded peer.
    let mut r_degraded = bgp_route([203, 0, 113, 0], 24, 1, 20_000);
    let _ = hook.on_import(&mut r_degraded);
    let attrs_degraded: PathAttributes = r_degraded.attributes.clone().into();
    assert!(
        attrs_degraded.has_peer_health_tier(),
        "route from degraded peer must carry the tier attribute"
    );
    let tier = attrs_degraded.peer_health_tier().unwrap();
    assert!(
        tier > 0,
        "tier must be above L0 for a degraded peer, got {tier}"
    );

    // Phase 4: a route from a non-degraded peer (peer 2, never seen
    // by the table) has no tier attribute — treated as L0 by
    // BestPath::rank_tiered.
    let r_fresh = bgp_route([203, 0, 113, 0], 24, 2, 20_000);

    // BestPath::select_tiered should pick the L0 (fresh) route over
    // the degraded route.
    let routes = [r_fresh.clone(), r_degraded.clone()];
    let cfg = BestPathConfig::default();
    let best = BestPath::select_tiered(&routes, &cfg).unwrap();
    assert_eq!(
        best.origin.peer, 2,
        "L0 (fresh) candidate must win over degraded candidate"
    );

    // BestPath::select (without tiering) picks peer 1 because both
    // routes have the same AS path and peer 1 has a lower peer-id
    // — the tiered path is what prevents the degraded route from
    // winning.
    let best_plain = BestPath::select(&routes, &cfg).unwrap();
    assert_eq!(
        best_plain.origin.peer, 1,
        "without tiering, lower peer-id wins the tie"
    );
}

#[test]
fn peer_health_e2e_off_mode_no_stamp() {
    let mut cfg = cfg_test();
    cfg.rollout = RolloutMode::Off;
    let table = Arc::new(Mutex::new(PeerHealthTable::new(cfg)));
    let hook = PeerHealthImportHook::new(Arc::clone(&table));

    let mut r = bgp_route([203, 0, 113, 0], 24, 1, 1_000);
    let verdict = hook.on_import(&mut r);
    assert!(matches!(verdict, HookVerdict::Keep));

    let attrs: PathAttributes = r.attributes.clone().into();
    assert!(
        !attrs.has_peer_health_tier(),
        "Off mode must not stamp the tier attribute"
    );
    assert!(
        table.lock().unwrap().is_empty(),
        "Off mode must not create session state"
    );
}

#[test]
fn peer_health_e2e_observe_mode_accounts_without_stamping() {
    let mut cfg = cfg_test();
    cfg.rollout = RolloutMode::Observe;
    let table = Arc::new(Mutex::new(PeerHealthTable::new(cfg)));
    let hook = PeerHealthImportHook::new(Arc::clone(&table));

    // Train + burst.
    for i in 0..10u64 {
        let mut r = bgp_route([203, 0, 113, 0], 24, 1, i * 1000);
        let _ = hook.on_import(&mut r);
    }
    for i in 0..200u64 {
        let mut r = bgp_route([203, 0, 113, 0], 24, 1, 10_000 + i * 10);
        let _ = hook.on_import(&mut r);
    }

    // Counters recorded...
    let snap = table
        .lock()
        .unwrap()
        .session_snapshot(1, NlriFamily::IPV4_UNICAST)
        .unwrap();
    assert!(snap.counters.updates >= 200);

    // ...but the public tier is L0 (observe does not stamp).
    assert_eq!(
        table.lock().unwrap().tier(1, NlriFamily::IPV4_UNICAST),
        lr_peer_health::PeerHealthTier::L0
    );
}
