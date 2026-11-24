//! BGP route flap damping (RFC 2439).
//!
//! Route flap damping suppresses unstable prefixes: each time a route flaps
//! (withdraws + re-announces) it accumulates a "figure of merit" (FoM); when
//! the FoM crosses a threshold the route is suppressed (its routes are
//! dropped from the Loc-RIB). The FoM decays exponentially over time, so
//! stable routes eventually re-emerge.
//!
//! ## Algorithm
//!
//! - **Per-prefix FoM**: float in the range [0, UPPER_LIMIT].
//! - **On withdraw**: `FoM += ADDITIVE_INCREASE`. Caps at `UPPER_LIMIT`.
//!   (RFC 2439 §4.2 increments the FoM only on the reachable →
//!   unreachable transition; the re-announce increment below is the
//!   Cisco de-facto variant, enabled for stability on damped prefixes.)
//! - **On re-announce**: `FoM += reuse * (1 - decay_withdrawn)` (Cisco
//!   variant — RFC 2439 itself does not penalise re-announcement).
//! - **On decay (per decay_interval)**: `FoM = FoM * decay_factor`.
//! - **Suppress** when `FoM >= SUPPRESS_THRESHOLD` (strictly above per the
//!   RFC's wording; we use >= so the boundary is deterministic).
//! - **Reuse** when `FoM < REUSE_THRESHOLD` (after being suppressed).
//!
//! Default constants (Cisco-style, per RFC 2439 §4.7's sample parameters
//! adapted to decay factors):
//!
//! - `additive_incr       = 1000`
//! - `suppress_threshold  = 2000`
//! - `reuse_threshold     = 750`
//! - `upper_limit         = 60000`
//! - `decay_interval      = 30s`
//! - `decay_factor_active = 0.97`
//! - `decay_factor_withdrawn = 0.5`
//!
//! These constants are tunable via [`DampingConfig`].
//!
//! ## Note on RFC 2439 status
//!
//! Route flap damping with the RFC 2439 defaults is documented as harmful
//! by RFC 7196: the penalty model "severely penalize[s] sites for being
//! well connected" (each path explored during a convergence event
//! re-triggers the figure of merit), which is why most operators turn RFD
//! off on Internet-facing eBGP. RFC 7196 prescribes the conservative
//! parameter changes that make it usable; [`DampingConfig`] exposes them.
//! The module is provided here as an *opt-in* mechanism controlled by the
//! policy chain, off by default.

#![forbid(unsafe_code)]

use core::cmp::min;

use lr_core::addr::Prefix;

/// Default damping constants (RFC 2439 §4.2 / §4.7, Cisco-style).
pub const DEFAULT_ADDITIVE_INCR: u32 = 1000;
pub const DEFAULT_SUPPRESS_THRESHOLD: u32 = 2000;
pub const DEFAULT_REUSE_THRESHOLD: u32 = 750;
pub const DEFAULT_UPPER_LIMIT: u32 = 60000;
pub const DEFAULT_DECAY_INTERVAL_S: u64 = 30;
pub const DEFAULT_DECAY_FACTOR_ACTIVE: f64 = 0.97;
pub const DEFAULT_DECAY_FACTOR_WITHDRAWN: f64 = 0.5;

/// Per-prefix damping configuration. Most operators never change this from
/// RFC 2439 defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct DampingConfig {
    pub additive_incr: u32,
    pub suppress_threshold: u32,
    pub reuse_threshold: u32,
    pub upper_limit: u32,
    pub decay_interval_s: u64,
    pub decay_factor_active: f64,
    pub decay_factor_withdrawn: f64,
}

impl Default for DampingConfig {
    fn default() -> Self {
        Self {
            additive_incr: DEFAULT_ADDITIVE_INCR,
            suppress_threshold: DEFAULT_SUPPRESS_THRESHOLD,
            reuse_threshold: DEFAULT_REUSE_THRESHOLD,
            upper_limit: DEFAULT_UPPER_LIMIT,
            decay_interval_s: DEFAULT_DECAY_INTERVAL_S,
            decay_factor_active: DEFAULT_DECAY_FACTOR_ACTIVE,
            decay_factor_withdrawn: DEFAULT_DECAY_FACTOR_WITHDRAWN,
        }
    }
}

/// Per-prefix damping state. Owned by [`DampingTable`].
#[derive(Debug, Clone, PartialEq)]
pub struct DampingEntry {
    pub prefix: Prefix,
    pub figure_of_merit: f64,
    pub suppressed: bool,
    /// Wall-clock seconds of the last decay tick.
    pub last_decay_s: u64,
    /// Wall-clock seconds of the last flap.
    pub last_flap_s: u64,
    /// Number of historical flaps (does not affect suppression).
    pub flap_count: u32,
}

impl DampingEntry {
    pub fn new(prefix: Prefix, now_s: u64) -> Self {
        Self {
            prefix,
            figure_of_merit: 0.0,
            suppressed: false,
            last_decay_s: now_s,
            last_flap_s: now_s,
            flap_count: 0,
        }
    }
}

/// Per-instance damping table. Owns a BTreeMap of prefix → entry.
#[derive(Debug, Clone)]
pub struct DampingTable {
    cfg: DampingConfig,
    inner: std::collections::BTreeMap<Prefix, DampingEntry>,
}

impl DampingTable {
    pub fn new(cfg: DampingConfig) -> Self {
        Self {
            cfg,
            inner: std::collections::BTreeMap::new(),
        }
    }

    pub fn config(&self) -> &DampingConfig {
        &self.cfg
    }

    /// Replace the tuning parameters, keeping the figure-of-merit
    /// history (the SIGHUP reload path — the daemon re-points the
    /// live table instead of rebuilding it so a re-tune does not
    /// reset accumulated flaps). Every future `on_withdraw` /
    /// `on_announce` / `decay_all` call reads the new parameters; the
    /// per-prefix entries (FoM, suppression flag, timestamps) survive
    /// verbatim. This is the same semantics FRR's `bgp dampening`
    /// re-tune carries: parameter changes apply to future
    /// computations, existing history is not discarded.
    ///
    /// A raised `reuse_threshold` can leave suppressed entries whose
    /// FoM is already below the new threshold still flagged; the next
    /// `decay_all` pass re-evaluates every entry against the fresh
    /// parameters and reactivates them (the decay ticker's regular
    /// cadence, at most one `decay_interval_s` away).
    pub fn update_config(&mut self, cfg: DampingConfig) {
        self.cfg = cfg;
    }

    /// Record a withdrawal. Returns `true` if the route should be suppressed
    /// (i.e. dropped from the Loc-RIB) as a result.
    pub fn on_withdraw(&mut self, prefix: &Prefix, now_s: u64) -> bool {
        let entry = self
            .inner
            .entry(*prefix)
            .or_insert_with(|| DampingEntry::new(*prefix, now_s));
        Self::decay_to_now(entry, &self.cfg, now_s);
        entry.figure_of_merit += self.cfg.additive_incr as f64;
        entry.figure_of_merit =
            min(entry.figure_of_merit as u64, self.cfg.upper_limit as u64) as f64;
        entry.last_flap_s = now_s;
        entry.flap_count = entry.flap_count.saturating_add(1);
        let suppress = entry.figure_of_merit >= self.cfg.suppress_threshold as f64;
        if suppress {
            entry.suppressed = true;
        }
        suppress
    }

    /// Record a re-announcement. Returns `true` if the route remains
    /// suppressed.
    pub fn on_announce(&mut self, prefix: &Prefix, now_s: u64) -> bool {
        let entry = self
            .inner
            .entry(*prefix)
            .or_insert_with(|| DampingEntry::new(*prefix, now_s));
        Self::decay_to_now(entry, &self.cfg, now_s);
        // On re-announce, FoM increases by reuse * (1 - decay_withdrawn).
        let incr = self.cfg.reuse_threshold as f64 * (1.0 - self.cfg.decay_factor_withdrawn);
        entry.figure_of_merit += incr;
        entry.figure_of_merit =
            min(entry.figure_of_merit as u64, self.cfg.upper_limit as u64) as f64;
        entry.last_flap_s = now_s;
        entry.flap_count = entry.flap_count.saturating_add(1);
        if entry.figure_of_merit >= self.cfg.suppress_threshold as f64 {
            entry.suppressed = true;
        }
        entry.suppressed
    }

    /// True if the prefix is currently suppressed.
    pub fn is_suppressed(&self, prefix: &Prefix) -> bool {
        self.inner
            .get(prefix)
            .map(|e| e.suppressed)
            .unwrap_or(false)
    }

    /// Decay all entries up to `now_s`. Routes whose FoM drops below the
    /// reuse threshold become un-suppressed. Returns the list of newly-
    /// un-suppressed prefixes (so the embedder can re-inject them).
    pub fn decay_all(&mut self, now_s: u64) -> Vec<Prefix> {
        let mut reactivated = Vec::new();
        for entry in self.inner.values_mut() {
            Self::decay_to_now(entry, &self.cfg, now_s);
            if entry.suppressed && entry.figure_of_merit < self.cfg.reuse_threshold as f64 {
                entry.suppressed = false;
                reactivated.push(entry.prefix);
            }
        }
        reactivated
    }

    /// Forget a prefix entirely (e.g. after operator's manual reset).
    pub fn forget(&mut self, prefix: &Prefix) {
        self.inner.remove(prefix);
    }

    /// Iterate over all entries.
    pub fn entries(&self) -> impl Iterator<Item = &DampingEntry> {
        self.inner.values()
    }

    /// Decay a single entry to `now_s` using the active or withdrawn decay
    /// factor (depending on whether the route is currently suppressed).
    fn decay_to_now(entry: &mut DampingEntry, cfg: &DampingConfig, now_s: u64) {
        if now_s <= entry.last_decay_s {
            return;
        }
        let elapsed_s = now_s - entry.last_decay_s;
        let intervals = (elapsed_s as f64) / (cfg.decay_interval_s as f64);
        if intervals < 1.0 {
            return;
        }
        let factor = if entry.suppressed {
            cfg.decay_factor_withdrawn
        } else {
            cfg.decay_factor_active
        };
        let total_decay = factor.powf(intervals);
        entry.figure_of_merit *= total_decay;
        if entry.figure_of_merit < 1.0 {
            entry.figure_of_merit = 0.0;
        }
        entry.last_decay_s = now_s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn single_flap_does_not_suppress() {
        let mut t = DampingTable::new(DampingConfig::default());
        let now = 0;
        let suppress = t.on_withdraw(&p("10.0.0.0/8"), now);
        assert!(!suppress, "single withdraw should not suppress");
    }

    #[test]
    fn three_rapid_flaps_suppress() {
        let mut t = DampingTable::new(DampingConfig::default());
        // Three withdrawals in rapid succession (each adds 1000, threshold 2000).
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        let suppress = t.on_withdraw(&p("10.0.0.0/8"), 0);
        assert!(suppress, "FoM >= 2000 should suppress");
        assert!(t.is_suppressed(&p("10.0.0.0/8")));
    }

    #[test]
    fn decay_unsuppresses_after_time() {
        let mut t = DampingTable::new(DampingConfig::default());
        // Three rapid flaps to suppress.
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        assert!(t.is_suppressed(&p("10.0.0.0/8")));
        // Advance time well past the decay interval (use a long gap).
        let reactivated = t.decay_all(60 * 60); // 1 hour
        assert!(reactivated.contains(&p("10.0.0.0/8")));
        assert!(!t.is_suppressed(&p("10.0.0.0/8")));
    }

    #[test]
    fn forget_clears_state() {
        let mut t = DampingTable::new(DampingConfig::default());
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.forget(&p("10.0.0.0/8"));
        assert!(!t.is_suppressed(&p("10.0.0.0/8")));
        assert_eq!(t.entries().count(), 0);
    }

    #[test]
    fn update_config_keeps_history_and_applies_new_params() {
        // Default tuning: three rapid flaps suppress (FoM 3000 >= 2000).
        let mut t = DampingTable::new(DampingConfig::default());
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        assert!(
            t.on_withdraw(&p("10.0.0.0/8"), 0),
            "defaults: 3rd flap suppresses"
        );

        // Re-tune: a much higher suppress threshold and a lower
        // additive increment. The existing entry (FoM 3000,
        // suppressed) survives; the fresh parameters govern future
        // computations.
        let mut tuned = DampingConfig::default();
        tuned.suppress_threshold = 10_000;
        tuned.additive_incr = 500;
        t.update_config(tuned.clone());
        assert_eq!(t.config(), &tuned, "the table carries the fresh config");
        assert_eq!(t.entries().count(), 1, "history is not discarded");
        let entry = t.entries().next().unwrap().clone();
        assert!(
            entry.suppressed,
            "the suppression flag survives the re-tune"
        );
        assert_eq!(entry.flap_count, 3, "the flap history survives the re-tune");

        // The new increment applies: a 4th flap adds 500, not 1000
        // (FoM was 3000 at t=0; no decay in between).
        let fom_before = entry.figure_of_merit;
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        let after = t.entries().next().unwrap().clone();
        assert!(
            (after.figure_of_merit - fom_before - 500.0).abs() < f64::EPSILON,
            "the fresh additive_incr governs: {}",
            after.figure_of_merit
        );

        // A fresh prefix under the fresh tuning: even three more
        // rapid flaps do not reach the raised threshold.
        let mut fresh = DampingTable::new(DampingConfig::default());
        fresh.update_config(tuned);
        assert!(
            !fresh.on_withdraw(&p("192.0.2.0/24"), 0),
            "1st flap: no suppress"
        );
        assert!(
            !fresh.on_withdraw(&p("192.0.2.0/24"), 0),
            "2nd flap: no suppress"
        );
        assert!(
            !fresh.on_withdraw(&p("192.0.2.0/24"), 0),
            "3rd flap: no suppress"
        );
    }

    #[test]
    fn update_config_raised_reuse_reactivates_on_next_decay() {
        // Suppress a prefix under the defaults, then raise the reuse
        // threshold above the entry's FoM. The next decay_all pass
        // re-evaluates against the fresh parameters and reactivates.
        let mut t = DampingTable::new(DampingConfig::default());
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        assert!(t.on_withdraw(&p("10.0.0.0/8"), 0));

        let mut tuned = DampingConfig::default();
        // FoM is 3000; decay_factor_withdrawn 0.5 over one interval
        // halves it to 1500. A reuse threshold of 2000 reactivates.
        tuned.reuse_threshold = 2_000;
        t.update_config(tuned);
        let reactivated = t.decay_all(30); // one decay interval later
        assert!(
            reactivated.contains(&p("10.0.0.0/8")),
            "the raised reuse threshold reactivates the suppressed prefix"
        );
        assert!(!t.is_suppressed(&p("10.0.0.0/8")));
    }
}
