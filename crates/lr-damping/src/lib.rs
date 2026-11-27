//! BGP route flap damping (RFC 2439).
//!
//! Route flap damping suppresses unstable prefixes: each time a route
//! flaps (withdraws + re-announces) it accumulates a "figure of merit" (FoM); when
//! the FoM crosses a threshold the route is suppressed (its routes are
//! dropped from the Loc-RIB). The FoM decays exponentially over time, so
//! stable routes eventually re-emerge.
//!
//! ## Algorithm
//!
//! - **Per-prefix FoM**: float in the range `[0, upper_limit]`.
//! - **On withdraw** (RFC 2439 §4.8.2): decay the FoM to now with the
//!   factor for the state that held since the last update (the route
//!   was reachable), then `FoM += additive_incr` and cap at
//!   `upper_limit`. The route becomes unreachable.
//! - **On re-announce** (RFC 2439 §4.8.3): if no damping structure
//!   exists, none is created — the route is used. Otherwise decay the
//!   FoM to now with the unreachable factor, then: below the suppress
//!   threshold (unsuppressed) or the reuse threshold (suppressed),
//!   the route is used — a suppressed route whose FoM decayed below
//!   reuse transitions back to unsuppressed on the announcement, not
//!   only on the ticker.
//! - **On decay (per `decay_interval_s`)**: `FoM *= decay_factor` for
//!   the entry's reachability state. A suppressed entry that drops
//!   below `reuse_threshold` is reactivated.
//! - **Penalties land only on the reachable → unreachable transition**
//!   (RFC 2439 §5: "Penalties for instability should only be applied
//!   when a route is removed or replaced and not when a route is
//!   added") — one `additive_incr` per flap, none on advertisement
//!   and none on a route's first announcement.
//! - **Suppress** when `FoM >= suppress_threshold` (§4.8.3's
//!   "figure-of-merit < cut → use the route" — equality suppresses).
//! - **Reuse** when `FoM < reuse_threshold` (after being suppressed).
//!
//! Default constants — the FRR `bgp dampening` scale (penalty 1000,
//! reuse 750, suppress 2000, max-suppress 60 min with a 15-minute
//! half-life) with the §4.7 sample's equal reachable/unreachable
//! decay of 15 minutes, expressed per 30-second tick:
//!
//! - `additive_incr          = 1000`
//! - `suppress_threshold     = 2000`
//! - `reuse_threshold        = 750`
//! - `upper_limit            = 12000`  (FRR ceiling: reuse × 2^(60/15))
//! - `decay_interval_s       = 30`
//! - `decay_factor_active    = 0.977160` (2^(-30/900))
//! - `decay_factor_withdrawn = 0.977160`
//!
//! These constants are tunable via [`DampingConfig`]; the constructor
//! validates them (see [`DampingConfig::validate`]).
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

/// Default damping constants (FRR `bgp dampening` scale; RFC 2439
/// §4.2 parameter semantics).
pub const DEFAULT_ADDITIVE_INCR: u32 = 1000;
pub const DEFAULT_SUPPRESS_THRESHOLD: u32 = 2000;
pub const DEFAULT_REUSE_THRESHOLD: u32 = 750;
/// FRR's ceiling: `reuse × 2^(max-suppress-time / half-life)` with the
/// 60-minute max-suppress and 15-minute half-life defaults —
/// 750 × 16. The RFC 2439 §4.5 formula for the same quantities has a
/// known typographical defect (the parenthesization), and the FRR
/// computation is the operative one.
pub const DEFAULT_UPPER_LIMIT: u32 = 12000;
pub const DEFAULT_DECAY_INTERVAL_S: u64 = 30;
/// 2^(-30/900): a 15-minute half-life per 30-second tick (RFC 2439
/// §4.7 sample: decay-ok = 15 minutes).
pub const DEFAULT_DECAY_FACTOR_ACTIVE: f64 = 0.977160;
/// RFC 2439 §4.7 sample: decay-ng = 15 minutes as well. The §4.2
/// default for an unspecified decay-ng is no decay at all while
/// unreachable, which would leave withdrawn entries pinned forever;
/// the sample's equal decay keeps the table draining.
pub const DEFAULT_DECAY_FACTOR_WITHDRAWN: f64 = 0.977160;

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
    /// Whether the route is currently announced (reachable). RFC
    /// 2439 §4.2 keys the decay rate on reachability — "reduced by
    /// half if the route is considered reachable (whether suppressed
    /// or not)" — not on suppression.
    pub reachable: bool,
    /// Wall-clock seconds of the last decay tick.
    pub last_decay_s: u64,
    /// Wall-clock seconds of the last flap.
    pub last_flap_s: u64,
    /// Number of historical flaps — one per reachable → unreachable
    /// transition (RFC 2439 §4.3), i.e. per withdraw, not per event.
    pub flap_count: u32,
}

impl DampingEntry {
    pub fn new(prefix: Prefix, now_s: u64) -> Self {
        Self {
            prefix,
            figure_of_merit: 0.0,
            suppressed: false,
            reachable: true,
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

impl DampingConfig {
    /// Check the RFC 2439 §4.2 parameter constraints the table
    /// enforces: `reuse < suppress` (an inverted suppress curve
    /// toggles suppression on every tick), `upper_limit >=
    /// suppress_threshold`, decay factors in `(0.0, 1.0]` (a factor
    /// outside the interval makes the FoM diverge, freeze or NaN),
    /// and a non-zero decay interval. FRR's `bgp dampening` rejects
    /// the same combinations at configuration time.
    pub fn validate(&self) -> Result<(), String> {
        if self.reuse_threshold >= self.suppress_threshold {
            return Err(format!(
                "damping: reuse_threshold ({}) must be < suppress_threshold ({})",
                self.reuse_threshold, self.suppress_threshold
            ));
        }
        if self.upper_limit < self.suppress_threshold {
            return Err(format!(
                "damping: upper_limit ({}) must be >= suppress_threshold ({})",
                self.upper_limit, self.suppress_threshold
            ));
        }
        if !(0.0 < self.decay_factor_active && self.decay_factor_active <= 1.0) {
            return Err(format!(
                "damping: decay_factor_active ({}) must be in (0.0, 1.0]",
                self.decay_factor_active
            ));
        }
        if !(0.0 < self.decay_factor_withdrawn && self.decay_factor_withdrawn <= 1.0) {
            return Err(format!(
                "damping: decay_factor_withdrawn ({}) must be in (0.0, 1.0]",
                self.decay_factor_withdrawn
            ));
        }
        if self.decay_interval_s == 0 {
            return Err("damping: decay_interval_s must be > 0".into());
        }
        Ok(())
    }
}

impl DampingTable {
    /// Build a table, validating the configuration first (see
    /// [`DampingConfig::validate`]).
    pub fn new(cfg: DampingConfig) -> Result<Self, String> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            inner: std::collections::BTreeMap::new(),
        })
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
    /// computations, existing history is not discarded. Invalid
    /// parameters are rejected and the table keeps the old ones.
    ///
    /// A raised `reuse_threshold` can leave suppressed entries whose
    /// FoM is already below the new threshold still flagged; the next
    /// `decay_all` pass re-evaluates every entry against the fresh
    /// parameters and reactivates them (the decay ticker's regular
    /// cadence, at most one `decay_interval_s` away).
    pub fn update_config(&mut self, cfg: DampingConfig) -> Result<(), String> {
        cfg.validate()?;
        self.cfg = cfg;
        Ok(())
    }

    /// Record a withdrawal (the reachable → unreachable transition,
    /// RFC 2439 §4.8.2). Returns `true` if the route should be
    /// suppressed (i.e. dropped from the Loc-RIB) as a result.
    pub fn on_withdraw(&mut self, prefix: &Prefix, now_s: u64) -> bool {
        let cfg = self.cfg.clone();
        let entry = self
            .inner
            .entry(*prefix)
            .or_insert_with(|| DampingEntry::new(*prefix, now_s));
        // §4.8.2: decay with the array for the state that held over
        // the elapsed span (the route was reachable), then increment.
        Self::decay_to_now(entry, &cfg, now_s);
        entry.figure_of_merit += cfg.additive_incr as f64;
        entry.figure_of_merit = min(entry.figure_of_merit as u64, cfg.upper_limit as u64) as f64;
        entry.last_flap_s = now_s;
        entry.flap_count = entry.flap_count.saturating_add(1);
        entry.reachable = false;
        let suppress = entry.figure_of_merit >= cfg.suppress_threshold as f64;
        if suppress {
            entry.suppressed = true;
        }
        suppress
    }

    /// Record a re-announcement (the unreachable → reachable
    /// transition, RFC 2439 §4.8.3). Returns `true` if the route
    /// remains suppressed.
    ///
    /// A route with no damping structure is used and no structure is
    /// created (§4.8.3 step 1-2). No penalty lands on advertisement
    /// (§5: "Penalties for instability should only be applied when a
    /// route is removed or replaced and not when a route is added").
    /// A suppressed route whose FoM has decayed below the reuse
    /// threshold transitions back to unsuppressed here (§4.8.3
    /// step 3) — the reuse decision is not deferred to the ticker.
    pub fn on_announce(&mut self, prefix: &Prefix, now_s: u64) -> bool {
        let cfg = self.cfg.clone();
        let Some(entry) = self.inner.get_mut(prefix) else {
            return false;
        };
        Self::decay_to_now(entry, &cfg, now_s);
        entry.reachable = true;
        // §4.8.3 step 3.
        if !entry.suppressed && entry.figure_of_merit < cfg.suppress_threshold as f64 {
            return false;
        }
        if entry.suppressed && entry.figure_of_merit < cfg.reuse_threshold as f64 {
            entry.suppressed = false;
            return false;
        }
        entry.suppressed = true;
        true
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
        let cfg = self.cfg.clone();
        let mut reactivated = Vec::new();
        for entry in self.inner.values_mut() {
            Self::decay_to_now(entry, &cfg, now_s);
            if entry.suppressed && entry.figure_of_merit < cfg.reuse_threshold as f64 {
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

    /// Decay a single entry to `now_s`, selecting the decay factor by
    /// the entry's reachability (RFC 2439 §4.2: the half-life "while
    /// reachable" applies "whether suppressed or not"; the
    /// unreachable half-life applies while the route is withdrawn).
    fn decay_to_now(entry: &mut DampingEntry, cfg: &DampingConfig, now_s: u64) {
        if now_s <= entry.last_decay_s {
            return;
        }
        let elapsed_s = now_s - entry.last_decay_s;
        let intervals = (elapsed_s as f64) / (cfg.decay_interval_s as f64);
        if intervals < 1.0 {
            return;
        }
        let factor = if entry.reachable {
            cfg.decay_factor_active
        } else {
            cfg.decay_factor_withdrawn
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
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
        let now = 0;
        let suppress = t.on_withdraw(&p("10.0.0.0/8"), now);
        assert!(!suppress, "single withdraw should not suppress");
    }

    #[test]
    fn three_rapid_flaps_suppress() {
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
        // Three withdrawals in rapid succession (each adds 1000, threshold 2000).
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        let suppress = t.on_withdraw(&p("10.0.0.0/8"), 0);
        assert!(suppress, "FoM >= 2000 should suppress");
        assert!(t.is_suppressed(&p("10.0.0.0/8")));
    }

    #[test]
    fn decay_unsuppresses_after_time() {
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
        // Three rapid flaps to suppress, then the route is re-announced
        // (reachable) and the ticker decays the FoM at the reachable
        // rate (RFC 2439 §4.2: "reduced by half if the route is
        // considered reachable (whether suppressed or not)").
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        assert!(t.on_announce(&p("10.0.0.0/8"), 1));
        assert!(t.is_suppressed(&p("10.0.0.0/8")));
        let mut now = 1u64;
        for _ in 0..200 {
            now += 30;
            let reactivated = t.decay_all(now);
            if reactivated.contains(&p("10.0.0.0/8")) {
                assert!(!t.is_suppressed(&p("10.0.0.0/8")));
                return;
            }
        }
        panic!("route stayed suppressed after 200 decay ticks");
    }

    #[test]
    fn forget_clears_state() {
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.forget(&p("10.0.0.0/8"));
        assert!(!t.is_suppressed(&p("10.0.0.0/8")));
        assert_eq!(t.entries().count(), 0);
    }

    #[test]
    fn update_config_keeps_history_and_applies_new_params() {
        // Default tuning: three rapid flaps suppress (FoM 3000 >= 2000).
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
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
        let tuned = DampingConfig {
            suppress_threshold: 10_000,
            additive_incr: 500,
            ..DampingConfig::default()
        };
        t.update_config(tuned.clone()).unwrap();
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
        let mut fresh = DampingTable::new(DampingConfig::default()).unwrap();
        fresh.update_config(tuned).unwrap();
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
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        t.on_withdraw(&p("10.0.0.0/8"), 0);
        assert!(t.on_withdraw(&p("10.0.0.0/8"), 0));

        let tuned = DampingConfig {
            reuse_threshold: 3_500,
            suppress_threshold: 4_000,
            ..DampingConfig::default()
        };
        t.update_config(tuned).unwrap();
        let reactivated = t.decay_all(30); // one decay interval later
        assert!(
            reactivated.contains(&p("10.0.0.0/8")),
            "the raised reuse threshold reactivates the suppressed prefix"
        );
        assert!(!t.is_suppressed(&p("10.0.0.0/8")));
    }

    // -----------------------------------------------------------------------
    // Audit H65 batch: RFC 2439 §4.8 semantics — no announce penalty, no
    // entry on first announcement, reuse on announcement, decay keyed on
    // reachability, flaps counted per withdraw.
    // -----------------------------------------------------------------------

    #[test]
    fn first_announcement_creates_no_entry_and_costs_nothing() {
        // RFC 2439 §4.8.1/§4.8.3: "if there is no damping structure,
        // ... don't create a new damping structure ... use the route",
        // and §5: "Penalties for instability should only be applied
        // when a route is removed or replaced and not when a route is
        // added."
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
        assert!(!t.on_announce(&p("203.0.113.0/24"), 0));
        assert_eq!(t.entries().count(), 0, "no entry is created");
        assert!(!t.is_suppressed(&p("203.0.113.0/24")));
    }

    #[test]
    fn re_announcement_adds_no_penalty() {
        // One flap (withdraw + re-announce): the FoM must be exactly
        // the withdraw penalty afterwards — the pre-correction code
        // added `reuse * (1 - decay_withdrawn)` on every announce.
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        assert!(!t.on_announce(&p("198.51.100.0/24"), 0));
        let entry = t.entries().next().unwrap().clone();
        assert!(
            (entry.figure_of_merit - 1000.0).abs() < f64::EPSILON,
            "one flap costs one additive_incr, got {}",
            entry.figure_of_merit
        );
        assert_eq!(entry.flap_count, 1, "a flap is one withdraw");
    }

    #[test]
    fn suppressed_route_reuses_on_announcement_below_reuse() {
        // RFC 2439 §4.8.3 step 3: "if (suppressed and
        // figure-of-merit < reuse) { set state to not suppressed ...
        // use the route }". Suppress the prefix, let the FoM decay
        // below reuse while the peer stays quiet, then announce: the
        // route must be admitted, not held out until the next tick.
        let mut t = DampingTable::new(DampingConfig {
            // Compressed decay: 4x per interval halves the FoM fast.
            decay_factor_active: 0.5,
            decay_factor_withdrawn: 0.5,
            ..DampingConfig::default()
        })
        .unwrap();
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        assert!(t.is_suppressed(&p("198.51.100.0/24")));
        // Two intervals of decay: 3000 -> 1500 -> 750 -> still >= 750.
        // A third: 375 < 750.
        t.decay_all(60);
        assert!(t.is_suppressed(&p("198.51.100.0/24")));
        // The peer re-announces after the FoM crossed reuse.
        t.decay_all(90);
        assert!(!t.is_suppressed(&p("198.51.100.0/24")));
    }

    #[test]
    fn decay_uses_the_reachable_factor_while_suppressed() {
        // RFC 2439 §4.2: the reachable half-life applies "whether
        // suppressed or not". A suppressed but re-announced route must
        // decay at the ACTIVE factor — the pre-correction code keyed
        // the factor on the suppression flag, shrinking a 15-minute
        // half-life to 30 seconds and making suppression collapse in
        // a few ticks.
        let mut t = DampingTable::new(DampingConfig {
            decay_factor_active: 0.9,
            decay_factor_withdrawn: 0.1,
            ..DampingConfig::default()
        })
        .unwrap();
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        assert!(t.on_announce(&p("198.51.100.0/24"), 0));
        t.decay_all(30); // one interval
        let fom = t.entries().next().unwrap().figure_of_merit;
        assert!(
            (fom - 3000.0 * 0.9).abs() < f64::EPSILON,
            "reachable suppressed entry decays at the active factor, got {fom}"
        );
    }

    #[test]
    fn withdrawn_route_decays_at_the_unreachable_factor() {
        // A route that flapped and stayed withdrawn decays at the
        // unreachable rate (§4.2 decay-ng).
        let mut t = DampingTable::new(DampingConfig {
            decay_factor_active: 0.9,
            decay_factor_withdrawn: 0.5,
            ..DampingConfig::default()
        })
        .unwrap();
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        t.on_withdraw(&p("198.51.100.0/24"), 0);
        t.decay_all(30);
        let fom = t.entries().next().unwrap().figure_of_merit;
        assert!(
            (fom - 3000.0 * 0.5).abs() < f64::EPSILON,
            "withdrawn entry decays at the unreachable factor, got {fom}"
        );
    }

    #[test]
    fn invalid_configurations_are_rejected() {
        // reuse >= suppress, factors outside (0, 1], a zero interval
        // and a ceiling below the suppress threshold are all refused
        // by the constructor and by update_config.
        let bad = DampingConfig {
            reuse_threshold: 2000,
            ..DampingConfig::default()
        };
        assert!(DampingTable::new(bad.clone()).is_err());
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
        assert!(t.update_config(bad).is_err());
        assert!(
            t.config().reuse_threshold == 750,
            "the rejected re-tune does not stick"
        );
        assert!(DampingTable::new(DampingConfig {
            decay_factor_active: 0.0,
            ..DampingConfig::default()
        })
        .is_err());
        assert!(DampingTable::new(DampingConfig {
            decay_factor_withdrawn: 1.5,
            ..DampingConfig::default()
        })
        .is_err());
        assert!(DampingTable::new(DampingConfig {
            decay_interval_s: 0,
            ..DampingConfig::default()
        })
        .is_err());
        assert!(DampingTable::new(DampingConfig {
            upper_limit: 1000,
            ..DampingConfig::default()
        })
        .is_err());
    }

    #[test]
    fn upper_limit_caps_the_figure_of_merit() {
        let mut t = DampingTable::new(DampingConfig::default()).unwrap();
        for i in 0..20 {
            t.on_withdraw(&p("198.51.100.0/24"), i);
        }
        let fom = t.entries().next().unwrap().figure_of_merit;
        assert_eq!(fom, DEFAULT_UPPER_LIMIT as f64);
    }
}
