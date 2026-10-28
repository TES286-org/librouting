//! Damping constants FFI — RFC 2439 default values.
//!
//! Mirrors `lr_damping`'s default constants so a C embedder can pass
//! them to `lr_damping_config_new` without re-deriving them from the
//! RFC.

#![allow(dead_code)]

// ---- Default damping parameters (RFC 2439 §4.8 / BIRD 2 / FRR 10) ----

/// Default additive increment per flap (RFC 2439 §4.8.1).
pub const LR_DAMPING_DEFAULT_ADDITIVE_INCR: u32 = 1000;
/// Default suppress threshold above which a route is dampened (RFC
/// 2439 §4.8.1).
pub const LR_DAMPING_DEFAULT_SUPPRESS_THRESHOLD: u32 = 2000;
/// Default reuse threshold below which a dampened route is unsuppressed
/// (RFC 2439 §4.8.1).
pub const LR_DAMPING_DEFAULT_REUSE_THRESHOLD: u32 = 750;
/// Default upper limit on the figure of merit (RFC 2439 §4.8.1 — a
/// ceiling on the penalty so a flapping route cannot accumulate
/// unbounded dampening).
pub const LR_DAMPING_DEFAULT_UPPER_LIMIT: u32 = 60000;
/// Default decay interval in seconds (RFC 2439 §4.8.2).
pub const LR_DAMPING_DEFAULT_DECAY_INTERVAL_S: u64 = 30;
/// Default decay factor applied while the route is active (announced).
pub const LR_DAMPING_DEFAULT_DECAY_FACTOR_ACTIVE: f64 = 0.97;
/// Default decay factor applied while the route is withdrawn.
pub const LR_DAMPING_DEFAULT_DECAY_FACTOR_WITHDRAWN: f64 = 0.5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_damping_defaults_match_rfc() {
        assert_eq!(LR_DAMPING_DEFAULT_ADDITIVE_INCR, 1000);
        assert_eq!(LR_DAMPING_DEFAULT_SUPPRESS_THRESHOLD, 2000);
        assert_eq!(LR_DAMPING_DEFAULT_REUSE_THRESHOLD, 750);
        assert_eq!(LR_DAMPING_DEFAULT_UPPER_LIMIT, 60000);
        assert_eq!(LR_DAMPING_DEFAULT_DECAY_INTERVAL_S, 30);
        assert!((LR_DAMPING_DEFAULT_DECAY_FACTOR_ACTIVE - 0.97).abs() < f64::EPSILON);
        assert!((LR_DAMPING_DEFAULT_DECAY_FACTOR_WITHDRAWN - 0.5).abs() < f64::EPSILON);
    }
}
