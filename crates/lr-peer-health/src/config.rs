//! Configuration for peer-level flap suppression (issue #99).

use crate::tier::PeerHealthTier;

/// Rollout phase for the flap-suppression mechanism (issue #99
/// §Rollout).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum RolloutMode {
    #[default]
    Off = 0,
    Observe = 1,
    Shadow = 2,
    ShadowBestPath = 3,
    Limited = 4,
    Full = 5,
}

impl RolloutMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Observe => "observe",
            Self::Shadow => "shadow",
            Self::ShadowBestPath => "shadow-best-path",
            Self::Limited => "limited",
            Self::Full => "full",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "off" => Self::Off,
            "observe" => Self::Observe,
            "shadow" => Self::Shadow,
            "shadow-best-path" | "shadow_best_path" | "shadowbestpath" => Self::ShadowBestPath,
            "limited" => Self::Limited,
            "full" => Self::Full,
            _ => return None,
        })
    }

    /// True when the import hook stamps the `LrPeerHealthTier`
    /// attribute on routes so `BestPath::rank_tiered` runs and
    /// actually changes selection. Only `limited` and `full` do
    /// this — issue #99 §Rollout: shadow modes must not affect
    /// routing. The `shadow-best-path` mode observes the would-be
    /// best path via `PeerHealthShadowSelectionHook` without
    /// stamping.
    pub fn stamps_tier(self) -> bool {
        matches!(self, Self::Limited | Self::Full)
    }

    pub fn applies_stale(self) -> bool {
        matches!(self, Self::Limited | Self::Full)
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Off),
            1 => Some(Self::Observe),
            2 => Some(Self::Shadow),
            3 => Some(Self::ShadowBestPath),
            4 => Some(Self::Limited),
            5 => Some(Self::Full),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WindowKind {
    Short = 0,
    Mid = 1,
    Long = 2,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowBudget {
    pub window_s: u64,
    pub enter_multiplier: f64,
    pub exit_multiplier: f64,
    pub emergency_multiplier: f64,
}

impl WindowBudget {
    pub fn budget_for(&self, baseline_eps: f64) -> u64 {
        let raw = self.enter_multiplier * baseline_eps * (self.window_s as f64);
        raw.max(1.0) as u64
    }

    pub fn exit_budget(&self, baseline_eps: f64) -> u64 {
        let raw = self.exit_multiplier * baseline_eps * (self.window_s as f64);
        raw.max(1.0) as u64
    }

    pub fn emergency_budget(&self, baseline_eps: f64) -> u64 {
        let raw = self.emergency_multiplier * baseline_eps * (self.window_s as f64);
        raw.max(1.0) as u64
    }
}

pub const DEFAULT_SHORT_WINDOW_S: u64 = 5;
pub const DEFAULT_MID_WINDOW_S: u64 = 30;
pub const DEFAULT_LONG_WINDOW_S: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExclusionKind {
    Startup = 0,
    RouteRefresh = 1,
    PolicyChange = 2,
    GracefulRestart = 3,
    LongLivedGracefulRestart = 4,
    Maintenance = 5,
}

impl ExclusionKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::RouteRefresh => "route-refresh",
            Self::PolicyChange => "policy-change",
            Self::GracefulRestart => "graceful-restart",
            Self::LongLivedGracefulRestart => "llgr",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "startup" => Self::Startup,
            "route-refresh" | "route_refresh" => Self::RouteRefresh,
            "policy-change" | "policy_change" => Self::PolicyChange,
            "graceful-restart" | "graceful_restart" => Self::GracefulRestart,
            "llgr" => Self::LongLivedGracefulRestart,
            "maintenance" => Self::Maintenance,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GlobalBudgets {
    pub soft_degraded: u32,
    pub hard_degraded: u32,
}

impl Default for GlobalBudgets {
    fn default() -> Self {
        Self {
            soft_degraded: 10,
            hard_degraded: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PeerHealthConfig {
    pub rollout: RolloutMode,
    pub short_window: WindowBudget,
    pub mid_window: WindowBudget,
    pub long_window: WindowBudget,
    pub baseline_window_s: u64,
    pub ewma_alpha: f64,
    pub min_baseline_rate_eps: f64,
    pub min_transition_interval_s: u64,
    pub min_recovery_interval_s: u64,
    pub max_backoff: u32,
    pub dwell_s: [u64; 4],
    pub max_stale_age_s: u64,
    pub tick_interval_s: u64,
    pub global_budgets: GlobalBudgets,
}

impl Default for PeerHealthConfig {
    fn default() -> Self {
        Self {
            rollout: RolloutMode::Off,
            short_window: WindowBudget {
                window_s: DEFAULT_SHORT_WINDOW_S,
                enter_multiplier: 5.0,
                exit_multiplier: 2.5,
                emergency_multiplier: 25.0,
            },
            mid_window: WindowBudget {
                window_s: DEFAULT_MID_WINDOW_S,
                enter_multiplier: 8.0,
                exit_multiplier: 4.0,
                emergency_multiplier: 40.0,
            },
            long_window: WindowBudget {
                window_s: DEFAULT_LONG_WINDOW_S,
                enter_multiplier: 12.0,
                exit_multiplier: 6.0,
                emergency_multiplier: 60.0,
            },
            baseline_window_s: 480,
            ewma_alpha: 0.05,
            min_baseline_rate_eps: 0.1,
            min_transition_interval_s: 10,
            min_recovery_interval_s: 60,
            max_backoff: 16,
            dwell_s: [0, 60, 180, 600],
            max_stale_age_s: 300,
            tick_interval_s: 5,
            global_budgets: GlobalBudgets::default(),
        }
    }
}

impl PeerHealthConfig {
    pub fn longest_window_s(&self) -> u64 {
        self.baseline_window_s.max(self.long_window.window_s)
    }

    pub fn dwell_s(&self, tier: PeerHealthTier) -> u64 {
        let idx = tier as usize;
        self.dwell_s.get(idx).copied().unwrap_or(0)
    }

    pub fn effective_tier(&self, tier: PeerHealthTier) -> PeerHealthTier {
        match self.rollout {
            RolloutMode::Limited if tier > PeerHealthTier::L1 => PeerHealthTier::L1,
            _ => tier,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_round_trip() {
        for &m in &[
            RolloutMode::Off,
            RolloutMode::Observe,
            RolloutMode::Shadow,
            RolloutMode::ShadowBestPath,
            RolloutMode::Limited,
            RolloutMode::Full,
        ] {
            assert_eq!(RolloutMode::from_name(m.name()), Some(m));
        }
        assert_eq!(RolloutMode::from_name("nope"), None);
    }

    #[test]
    fn stamps_tier_flags() {
        // Issue #99 §Rollout: shadow modes must not stamp the tier
        // attribute — only `limited` and `full` affect selection.
        assert!(!RolloutMode::Off.stamps_tier());
        assert!(!RolloutMode::Observe.stamps_tier());
        assert!(!RolloutMode::Shadow.stamps_tier());
        assert!(!RolloutMode::ShadowBestPath.stamps_tier());
        assert!(RolloutMode::Limited.stamps_tier());
        assert!(RolloutMode::Full.stamps_tier());
    }

    #[test]
    fn applies_stale_flags() {
        assert!(!RolloutMode::ShadowBestPath.applies_stale());
        assert!(RolloutMode::Limited.applies_stale());
        assert!(RolloutMode::Full.applies_stale());
    }

    #[test]
    fn effective_tier_caps_at_l1_in_limited_mode() {
        let cfg = PeerHealthConfig {
            rollout: RolloutMode::Limited,
            ..PeerHealthConfig::default()
        };
        assert_eq!(cfg.effective_tier(PeerHealthTier::L3), PeerHealthTier::L1);
        assert_eq!(cfg.effective_tier(PeerHealthTier::L0), PeerHealthTier::L0);
    }

    #[test]
    fn window_budget_floor_is_one_event() {
        let w = WindowBudget {
            window_s: 5,
            enter_multiplier: 5.0,
            exit_multiplier: 2.5,
            emergency_multiplier: 25.0,
        };
        assert_eq!(w.budget_for(0.0), 1);
    }

    #[test]
    fn window_budget_scales_with_baseline() {
        let w = WindowBudget {
            window_s: 10,
            enter_multiplier: 5.0,
            exit_multiplier: 2.5,
            emergency_multiplier: 25.0,
        };
        assert_eq!(w.budget_for(1.0), 50);
    }

    #[test]
    fn exclusion_kind_round_trip() {
        for &k in &[
            ExclusionKind::Startup,
            ExclusionKind::RouteRefresh,
            ExclusionKind::PolicyChange,
            ExclusionKind::GracefulRestart,
            ExclusionKind::LongLivedGracefulRestart,
            ExclusionKind::Maintenance,
        ] {
            assert_eq!(ExclusionKind::from_name(k.name()), Some(k));
        }
    }

    #[test]
    fn dwell_indexed_by_tier() {
        let cfg = PeerHealthConfig {
            dwell_s: [0, 60, 180, 600],
            ..PeerHealthConfig::default()
        };
        assert_eq!(cfg.dwell_s(PeerHealthTier::L0), 0);
        assert_eq!(cfg.dwell_s(PeerHealthTier::L1), 60);
        assert_eq!(cfg.dwell_s(PeerHealthTier::L2), 180);
        assert_eq!(cfg.dwell_s(PeerHealthTier::L3), 600);
    }
}
