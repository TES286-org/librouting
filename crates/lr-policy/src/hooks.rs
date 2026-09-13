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
//! Built-in hooks:
//!
//! - **[`GracefulShutdownExportHook`]** — RFC 8326 §3.1 sender side: when a
//!   route carries the `GRACEFUL_SHUTDOWN` community, zero its LOCAL_PREF
//!   on the export copy so receivers prefer alternatives before the session
//!   actually goes down. The community itself is preserved so downstream
//!   peers see the signal.
//!
//! All hooks are non-blocking and synchronous. Long-running work should be
//! deferred to a background task and surfaced as a flag attribute on the
//! route itself.

use core::cmp::Ordering;

use lr_core::rib::Route;

#[cfg(feature = "bgp")]
use lr_bgp::path::{Community, PathAttributes};

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
    /// Destination-aware variant: the router calls this with the id of
    /// the session the route is being advertised to, so per-peer
    /// export policy can dispatch on it. The default delegates to
    /// [`ExportHook::on_export`], preserving destination-agnostic
    /// behaviour for existing hooks.
    fn on_export_to(&self, route: &mut Route, destination: u64) -> HookVerdict {
        let _ = destination;
        self.on_export(route)
    }
}

/// RFC 8326 §3.1 sender-side graceful shutdown hook.
///
/// When a route carries the `GRACEFUL_SHUTDOWN` community
/// (`0xFFFF:0000`, [`Community::GRACEFUL_SHUTDOWN`]), the export
/// copy has its `LOCAL_PREF` set to zero so receiving speakers
/// prefer alternative paths. The community itself is preserved so
/// downstream peers see the signal (RFC 8326 §3.1: "the
/// GRACEFUL_SHUTDOWN community ... SHOULD be retained").
///
/// The hook is idempotent: re-running it on a route that already
/// has `LOCAL_PREF == 0` is a no-op.
///
/// The hook is destination-agnostic — RFC 8326 makes no exception
/// for the recipient. Embedders that want to selectively disable
/// the behaviour on a particular session should install the hook
/// only on the relevant sessions, not globally.
///
/// This is the canonical implementation; the daemon installs it by
/// default on the BGP export chain. Embedders may install their own
/// `ExportHook` implementation if they need a different policy
/// (e.g. to drop the route entirely rather than advertise with
/// `LOCAL_PREF == 0`).
///
/// [`Community::GRACEFUL_SHUTDOWN`]: lr_bgp::path::Community::GRACEFUL_SHUTDOWN
#[cfg(feature = "bgp")]
#[derive(Debug, Default, Clone, Copy)]
pub struct GracefulShutdownExportHook;

#[cfg(feature = "bgp")]
impl GracefulShutdownExportHook {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "bgp")]
impl ExportHook for GracefulShutdownExportHook {
    fn name(&self) -> &str {
        "rfc8326-graceful-shutdown"
    }

    fn on_export(&self, route: &mut Route) -> HookVerdict {
        // Take ownership of the attribute bag without cloning so we
        // can use the high-level PathAttributes accessors mutably.
        // The conversion is infallible (From<Attributes> for
        // PathAttributes is total) so we always put the bag back,
        // modified or not.
        let mut attrs: PathAttributes = core::mem::take(&mut route.attributes).into();

        if attrs.has_community(Community::GRACEFUL_SHUTDOWN) {
            // RFC 8326 §3.1: "the BGP speaker ... SHOULD set the
            // LOCAL_PREF value to 0 for the routes ... being
            // advertised". We preserve the community so downstream
            // peers can also act on it.
            attrs.set_local_pref(0);
        }

        route.attributes = attrs.into();
        HookVerdict::Keep
    }
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
        self.run_export_to(route, u64::MAX)
    }

    /// Run all export hooks with the destination session id. Hooks
    /// that do not override [`ExportHook::on_export_to`] behave
    /// exactly as under [`HookChain::run_export`].
    pub fn run_export_to(&self, route: &mut Route, destination: u64) -> HookVerdict {
        let mut verdict = HookVerdict::Keep;
        for h in &self.export {
            let v = h.on_export_to(route, destination);
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
            path_id: 0,
            tag: None,
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

    /// Helper: build a route whose attribute bag carries a single
    /// LOCAL_PREF attribute at the supplied value. Used by the
    /// RFC 8326 hook tests below.
    #[cfg(feature = "bgp")]
    fn route_with_local_pref(prefix: [u8; 4], plen: u8, peer: u64, lp: u32) -> Route {
        let mut r = route(prefix, plen, peer);
        let mut attrs: PathAttributes = r.attributes.clone().into();
        attrs.set_local_pref(lp);
        r.attributes = attrs.into();
        r
    }

    /// Helper: attach a community to a route's attribute bag.
    #[cfg(feature = "bgp")]
    fn attach_community(r: &mut Route, c: Community) {
        let mut attrs: PathAttributes = r.attributes.clone().into();
        attrs.insert_community(c);
        r.attributes = attrs.into();
    }

    /// Helper: read LOCAL_PREF back from a route (None if absent).
    #[cfg(feature = "bgp")]
    fn local_pref_of(r: &Route) -> Option<u32> {
        let attrs: PathAttributes = r.attributes.clone().into();
        attrs.local_pref().map(|lp| lp.0)
    }

    /// Helper: check whether the route still carries a community.
    #[cfg(feature = "bgp")]
    fn has_community(r: &Route, c: Community) -> bool {
        let attrs: PathAttributes = r.attributes.clone().into();
        attrs.has_community(c)
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_zeroes_local_pref_when_community_present() {
        // RFC 8326 §3.1: a route carrying the GRACEFUL_SHUTDOWN
        // community on export must have LOCAL_PREF set to zero so
        // receivers prefer alternatives.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let hook = GracefulShutdownExportHook::new();
        let verdict = hook.on_export(&mut r);
        assert!(
            matches!(verdict, HookVerdict::Keep),
            "hook must keep, not drop"
        );
        assert_eq!(local_pref_of(&r), Some(0), "LOCAL_PREF must be zeroed");
        assert!(
            has_community(&r, Community::GRACEFUL_SHUTDOWN),
            "GRACEFUL_SHUTDOWN community must be preserved"
        );
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_is_noop_when_community_absent() {
        // Routes without the community pass through unchanged — the
        // hook is opt-in via the community marker, never global.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        let hook = GracefulShutdownExportHook::new();
        let _ = hook.on_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(100), "LOCAL_PREF must be preserved");
        assert!(
            !has_community(&r, Community::GRACEFUL_SHUTDOWN),
            "no community should have been added"
        );
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_inserts_local_pref_when_absent() {
        // RFC 8326 §3.1 does not require LOCAL_PREF to pre-exist on
        // the route. If the attribute is absent (e.g. eBGP-learned
        // route), the hook still injects LOCAL_PREF=0 so the
        // receiver's import path sees the explicit "least preferred"
        // signal rather than a default-100 fallback.
        let mut r = route([203, 0, 113, 0], 24, 1);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        assert!(local_pref_of(&r).is_none(), "precondition: no LOCAL_PREF");
        let hook = GracefulShutdownExportHook::new();
        let _ = hook.on_export(&mut r);
        assert_eq!(
            local_pref_of(&r),
            Some(0),
            "LOCAL_PREF must be inserted at zero"
        );
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_is_idempotent() {
        // Running the hook twice must not produce a different
        // result — the second pass finds LOCAL_PREF already at 0
        // and is a no-op.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let hook = GracefulShutdownExportHook::new();
        let _ = hook.on_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
        let _ = hook.on_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_legacy_planned_shutdown_alias_triggers_hook() {
        // RFC 8326 renamed PLANNED_SHUTDOWN (draft-ietf-idr-shutdown)
        // to GRACEFUL_SHUTDOWN at the same wire value
        // (0xFFFF:0000). Configs using the legacy alias must still
        // trigger the hook.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::PLANNED_SHUTDOWN);
        let hook = GracefulShutdownExportHook::new();
        let _ = hook.on_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_runs_in_hook_chain() {
        // Verify the hook composes with the HookChain plumbing the
        // router actually uses (HookChain::run_export).
        let chain = HookChain {
            import: vec![],
            selection: vec![],
            export: vec![Box::new(GracefulShutdownExportHook::new())],
        };
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let _ = chain.run_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
    }
}
