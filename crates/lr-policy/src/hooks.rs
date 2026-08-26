//! Policy hooks: extension points for route selection, import, and export.
//!
//! The router ships a default policy pipeline:
//!
//! 1. Inbound decode → 2. Safety net (loop check, NEXT_HOP sanity) → 3. Import
//!    filter chain → 4. Adj-RIB-In → 5. Best-path selection → 6. Loc-RIB →
//! 7. Export filter chain → 8. Adj-RIB-Out → 9. Outbound encode.
//!
//! Each of steps 2, 3, 5, 7 is a **hook point** — an embedder can supply a
//! trait object that runs in addition to (or instead of) the default
//! implementation. This lets operators implement non-standard behavior
//! (e.g. prefer routes from a specific peer regardless of attributes) without
//! forking the codebase.
//!
//! Hook contracts:
//!
//! - **[`ImportHook`]** — invoked after decode, before the route enters
//!   Adj-RIB-In. May modify or drop the route.
//! - **[`SelectionHook`]** — invoked during best-path selection; may
//!   override the comparator (returns `Some(Ordering)` instead of `None` to
//!   force a result).
//! - **[`ExportHook`]** — invoked after the route is selected for the
//!   Adj-RIB-Out, before encode. May modify or drop the route.
//!
//! All hooks are non-blocking and synchronous. Long-running work should be
//! deferred to a background task and surfaced as a flag attribute on the
//! route itself.

use core::cmp::Ordering;

use lr_core::rib::Route;

/// Verdict returned by a hook. The route is either dropped, kept as-is, or
/// replaced by a modified copy.
#[derive(Debug, Clone)]
pub enum HookVerdict {
    /// Drop the route (do not insert into Adj-RIB-In / Adj-RIB-Out).
    Drop,
    /// Keep the route as-is.
    Keep,
    /// Replace the route with the supplied modified copy.
    Replace(Route),
}

/// Hook invoked on inbound, after decode, before Adj-RIB-In insertion.
pub trait ImportHook: Send {
    /// Optional human-readable name (for diagnostics).
    fn name(&self) -> &str {
        "import-hook"
    }
    /// Process the inbound route. May mutate or drop it.
    fn on_import(&self, route: &mut Route) -> HookVerdict;
}

/// Hook invoked during best-path selection.
pub trait SelectionHook: Send {
    fn name(&self) -> &str {
        "selection-hook"
    }
    /// Compare two routes for selection. Return:
    /// - `Some(Less)` if `a` is preferred over `b`.
    /// - `Some(Equal)` if equally preferred.
    /// - `Some(Greater)` if `b` is preferred over `a`.
    /// - `None` to defer to the default comparator.
    fn compare(&self, a: &Route, b: &Route) -> Option<Ordering>;
}

/// Hook invoked on outbound, after Loc-RIB, before Adj-RIB-Out encode.
pub trait ExportHook: Send {
    fn name(&self) -> &str {
        "export-hook"
    }
    /// Process the outbound route. May mutate or drop it.
    fn on_export(&self, route: &mut Route) -> HookVerdict;
}

/// A collection of hooks + safety net configuration. Aggregated by the
/// router instance and invoked at the appropriate pipeline stages.
#[derive(Default)]
pub struct HookChain {
    pub import: Vec<Box<dyn ImportHook>>,
    pub selection: Vec<Box<dyn SelectionHook>>,
    pub export: Vec<Box<dyn ExportHook>>,
}

impl HookChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all import hooks on the route. The final verdict is determined by
    /// the *last* hook that returns `Drop`/`Replace`; otherwise `Keep`.
    pub fn run_import(&self, route: &mut Route) -> HookVerdict {
        let mut verdict = HookVerdict::Keep;
        for h in &self.import {
            let v = h.on_import(route);
            match v {
                HookVerdict::Drop => return HookVerdict::Drop,
                HookVerdict::Replace(r) => {
                    *route = r;
                    verdict = HookVerdict::Keep;
                }
                HookVerdict::Keep => verdict = HookVerdict::Keep,
            }
        }
        verdict
    }

    /// Run all selection hooks; the first that returns `Some(Ordering)`
    /// wins; otherwise `None` (caller falls back to the default comparator).
    pub fn run_selection(&self, a: &Route, b: &Route) -> Option<Ordering> {
        for h in &self.selection {
            if let Some(ord) = h.compare(a, b) {
                return Some(ord);
            }
        }
        None
    }

    /// Run all export hooks on the route.
    pub fn run_export(&self, route: &mut Route) -> HookVerdict {
        let mut verdict = HookVerdict::Keep;
        for h in &self.export {
            let v = h.on_export(route);
            match v {
                HookVerdict::Drop => return HookVerdict::Drop,
                HookVerdict::Replace(r) => {
                    *route = r;
                    verdict = HookVerdict::Keep;
                }
                HookVerdict::Keep => verdict = HookVerdict::Keep,
            }
        }
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn route(prefix: [u8; 4], plen: u8, peer: u64) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4(prefix, plen), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
        }
    }

    struct DropPrefixHook;
    impl ImportHook for DropPrefixHook {
        fn on_import(&self, r: &mut Route) -> HookVerdict {
            if r.key
                .prefix
                .contains(&lr_core::addr::IpAddr::V4([10, 0, 0, 1]))
                && r.key.prefix.prefix_len <= 8
            {
                HookVerdict::Drop
            } else {
                HookVerdict::Keep
            }
        }
    }

    struct PreferPeerHook(u64);
    impl SelectionHook for PreferPeerHook {
        fn compare(&self, a: &Route, b: &Route) -> Option<Ordering> {
            if a.origin.peer == self.0 && b.origin.peer != self.0 {
                Some(Ordering::Less)
            } else if a.origin.peer != self.0 && b.origin.peer == self.0 {
                Some(Ordering::Greater)
            } else {
                None
            }
        }
    }

    struct AddTagHook;
    impl ExportHook for AddTagHook {
        fn on_export(&self, r: &mut Route) -> HookVerdict {
            r.preference.metric += 1;
            HookVerdict::Keep
        }
    }

    #[test]
    fn drop_hook_drops_matching_route() {
        let chain = HookChain {
            import: vec![Box::new(DropPrefixHook)],
            selection: vec![],
            export: vec![],
        };
        let mut r = route([10, 0, 0, 0], 8, 1);
        assert!(matches!(chain.run_import(&mut r), HookVerdict::Drop));
    }

    #[test]
    fn drop_hook_passes_through_non_matching() {
        let chain = HookChain {
            import: vec![Box::new(DropPrefixHook)],
            selection: vec![],
            export: vec![],
        };
        let mut r = route([192, 168, 0, 0], 24, 1);
        assert!(matches!(chain.run_import(&mut r), HookVerdict::Keep));
    }

    #[test]
    fn selection_hook_can_force_preference() {
        let chain = HookChain {
            import: vec![],
            selection: vec![Box::new(PreferPeerHook(1))],
            export: vec![],
        };
        let a = route([10, 0, 0, 0], 8, 1);
        let b = route([10, 0, 0, 0], 8, 2);
        // Prefer peer 1 (a) — should return Less.
        assert_eq!(chain.run_selection(&a, &b), Some(Ordering::Less));
    }

    #[test]
    fn export_hook_can_modify_route() {
        let chain = HookChain {
            import: vec![],
            selection: vec![],
            export: vec![Box::new(AddTagHook)],
        };
        let mut r = route([10, 0, 0, 0], 8, 1);
        let initial_metric = r.preference.metric;
        let _ = chain.run_export(&mut r);
        assert_eq!(r.preference.metric, initial_metric + 1);
    }
}
