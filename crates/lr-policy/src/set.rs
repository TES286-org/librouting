//! Named policy set — the registry binding user-defined names to
//! prefix-lists, AS-path filters, community lists and route-maps, plus
//! the per-session dispatch hooks that attach route-maps to peers.
//!
//! This is the bridge between a declarative config (TOML tables, CLI
//! flags of any embedder) and the policy engine: the embedder parses
//! its config into a [`PolicySet`], wires per-session route-maps via
//! [`PolicySet::bind_import`] / [`PolicySet::bind_export`], and
//! registers the returned [`PolicyHooks`] on the router's hook chain.
//!
//! Evaluation semantics for a bound route-map follow FRR route-map
//! behavior: entries are tried in order; the first matching entry
//! applies its sets and its `permit` verdict; when no entry matches
//! the route is **denied** (implicit deny). `permit`-with-no-match on
//! the *last* entry is therefore required to accept everything else —
//! exactly like `route-map X permit 100` with no `match` clause.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::action::{MatchCondition, MatchResolver};
use crate::as_path_filter::{AsPathFilter, AsPathFilterBank};
use crate::community_list::{CommunityList, CommunityListBank};
use crate::hooks::{ExportHook, HookVerdict, ImportHook};
use crate::prefix_list::{PrefixList, PrefixListBank};
use crate::route_map::{RouteMap, RouteMapEntry};
use lr_core::addr::Prefix;
use lr_core::rib::Route;

/// Named collection of policy objects. Also resolves match conditions
/// as a [`MatchResolver`] (list ids are internal and stable).
#[derive(Default)]
pub struct PolicySet {
    prefix_names: BTreeMap<String, u32>,
    prefix_bank: PrefixListBank,
    as_path_names: BTreeMap<String, u32>,
    as_path_bank: AsPathFilterBank,
    community_names: BTreeMap<String, u32>,
    community_bank: CommunityListBank,
    maps: BTreeMap<String, RouteMap>,
    /// Per-session import route-maps (session id -> map name).
    import_bindings: BTreeMap<u64, String>,
    /// Per-session export route-maps (session id -> map name).
    export_bindings: BTreeMap<u64, String>,
}

impl PolicySet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a prefix-list under `name`; returns its list id.
    pub fn add_prefix_list(&mut self, name: impl Into<String>, list: PrefixList) -> u32 {
        let id = self.prefix_bank.len() as u32;
        self.prefix_bank.add(id, list);
        self.prefix_names.insert(name.into(), id);
        id
    }

    /// Register an AS-path filter list under `name`; returns its id.
    pub fn add_as_path_list(&mut self, name: impl Into<String>, filters: Vec<AsPathFilter>) -> u32 {
        let id = self.as_path_bank.len() as u32;
        self.as_path_bank.add(filters);
        self.as_path_names.insert(name.into(), id);
        id
    }

    /// Register a community list under `name`; returns its id.
    pub fn add_community_list(&mut self, name: impl Into<String>, list: CommunityList) -> u32 {
        let id = self.community_bank.len() as u32;
        self.community_bank.add(list);
        self.community_names.insert(name.into(), id);
        id
    }

    /// Register (or replace) a route-map under `name`.
    pub fn add_route_map(&mut self, name: impl Into<String>, map: RouteMap) {
        self.maps.insert(name.into(), map);
    }

    /// Append one entry to a registered route-map (creates it when
    /// absent — handy for incremental config parsing).
    pub fn push_route_map_entry(&mut self, name: impl Into<String>, entry: RouteMapEntry) {
        self.maps.entry(name.into()).or_default().push(entry);
    }

    /// Look up a list id by name, resolving `match_prefix` /
    /// `match_as_path` / `match_community` conditions.
    pub fn list_id(&self, kind: ListKind, name: &str) -> Option<u32> {
        match kind {
            ListKind::Prefix => self.prefix_names.get(name).copied(),
            ListKind::AsPath => self.as_path_names.get(name).copied(),
            ListKind::Community => self.community_names.get(name).copied(),
        }
    }

    pub fn route_map(&self, name: &str) -> Option<&RouteMap> {
        self.maps.get(name)
    }

    pub fn route_map_names(&self) -> impl Iterator<Item = &str> {
        self.maps.keys().map(|s| s.as_str())
    }

    /// Resolve a symbolic match (list kind + name) into a concrete
    /// [`MatchCondition`]. `None` when the referenced list does not
    /// exist — callers should treat that as a configuration error
    /// before wiring hooks.
    pub fn match_condition(&self, kind: ListKind, name: &str) -> Option<MatchCondition> {
        let id = self.list_id(kind, name)?;
        Some(match kind {
            ListKind::Prefix => MatchCondition::PrefixIn { list_id: id },
            ListKind::AsPath => MatchCondition::AsPathIn { list_id: id },
            ListKind::Community => MatchCondition::CommunityIn { list_id: id },
        })
    }

    /// Attach `map` as the import policy of `session`.
    pub fn bind_import(&mut self, session: u64, map: impl Into<String>) {
        self.import_bindings.insert(session, map.into());
    }

    /// Attach `map` as the export policy of `session`.
    pub fn bind_export(&mut self, session: u64, map: impl Into<String>) {
        self.export_bindings.insert(session, map.into());
    }

    /// Freeze the set into the dispatch hook pair. The set keeps
    /// working (bindings are copied), so the embedder can build first
    /// and validate references with [`PolicySet::validate`] before
    /// calling this.
    pub fn hooks(self) -> PolicyHooks {
        PolicyHooks {
            inner: Arc::new(self),
        }
    }

    /// Verify that every bound route-map exists. Returns the first
    /// missing reference as `Err((session, direction, name))`.
    pub fn validate(&self) -> Result<(), (u64, &'static str, String)> {
        for (session, name) in &self.import_bindings {
            if !self.maps.contains_key(name) {
                return Err((*session, "import", name.clone()));
            }
        }
        for (session, name) in &self.export_bindings {
            if !self.maps.contains_key(name) {
                return Err((*session, "export", name.clone()));
            }
        }
        Ok(())
    }

    /// Evaluate the route-map bound to `session` in `direction`
    /// against `route`. `None` means: no map bound — keep the route.
    fn evaluate_bound(
        &self,
        bindings: &BTreeMap<u64, String>,
        session: u64,
        route: &mut Route,
    ) -> Option<bool> {
        let name = bindings.get(&session)?;
        let map = self.maps.get(name)?;
        match map.evaluate(route, self) {
            Some(v) => Some(v),
            // FRR route-map semantics: no entry matched -> deny.
            None => Some(false),
        }
    }
}

/// Which kind of named list a match refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    Prefix,
    AsPath,
    Community,
}

impl MatchResolver for PolicySet {
    fn prefix_in(&self, list_id: u32, p: &Prefix) -> bool {
        self.prefix_bank.evaluate(list_id, p)
    }

    fn as_path_in(&self, list_id: u32, route: &Route) -> bool {
        self.as_path_bank.evaluate(list_id, route)
    }

    fn community_in(&self, list_id: u32, route: &Route) -> bool {
        self.community_bank.evaluate(list_id, route)
    }

    fn next_hop_in(&self, list_id: u32, route: &Route) -> bool {
        // FRR `match ip next-hop prefix-list`: a /32-or-/128 view of
        // the route's next hop checked against a prefix list.
        let Some(nh) = route.next_hop else {
            return false;
        };
        let prefix = match nh {
            lr_core::addr::IpAddr::V4(octets) => Prefix::new_v4(octets, 32),
            lr_core::addr::IpAddr::V6(octets) => Prefix::new_v6(octets, 128),
        };
        self.prefix_bank.evaluate(list_id, &prefix)
    }
}

/// Dispatch hook pair: applies per-session route-maps at the import
/// and export stages. Register one instance per stage:
///
/// ```ignore
/// let hooks = set.hooks();
/// router.hooks_mut().import.push(Box::new(hooks.clone()));
/// router.hooks_mut().export.push(Box::new(hooks));
/// ```
///
/// Routes whose session has no binding pass through untouched, so
/// policy-free peers keep their existing behaviour. Sessions with a
/// bound map but no matching entry are denied (implicit deny, FRR
/// route-map semantics).
#[derive(Clone)]
pub struct PolicyHooks {
    inner: Arc<PolicySet>,
}

impl ImportHook for PolicyHooks {
    fn name(&self) -> &str {
        "policy-set"
    }

    fn on_import(&self, route: &mut Route) -> HookVerdict {
        let session = route.origin.peer;
        match self
            .inner
            .evaluate_bound(&self.inner.import_bindings, session, route)
        {
            Some(true) => HookVerdict::Keep,
            Some(false) => HookVerdict::Drop,
            None => HookVerdict::Keep,
        }
    }
}

impl ExportHook for PolicyHooks {
    fn name(&self) -> &str {
        "policy-set"
    }

    fn on_export(&self, route: &mut Route) -> HookVerdict {
        // Destination-agnostic call (run_export): the router passes
        // u64::MAX when the destination is unknown. No session can
        // bind that id, so the route passes through.
        let _ = route;
        HookVerdict::Keep
    }

    fn on_export_to(&self, route: &mut Route, destination: u64) -> HookVerdict {
        match self
            .inner
            .evaluate_bound(&self.inner.export_bindings, destination, route)
        {
            Some(true) => HookVerdict::Keep,
            Some(false) => HookVerdict::Drop,
            None => HookVerdict::Keep,
        }
    }
}

// Private binding storage lives on PolicySet via the
// `import_bindings` / `export_bindings` fields above.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::SetAction;
    use crate::community_list::CommunityListEntry;
    use crate::prefix_list::PrefixListEntry;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn route_for(prefix: &[u8; 4]) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4(*prefix, 24), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 7 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
        }
    }

    #[test]
    fn route_map_dispatch_by_session() {
        let mut set = PolicySet::new();
        // "doc" permits 198.51.100.0/24 and longer; everything else
        // falls through the list's implicit deny.
        let mut doc = PrefixList::new();
        doc.push(PrefixListEntry {
            prefix: Prefix::new_v4([198, 51, 100, 0], 24),
            ge: 24,
            le: 32,
            permit: true,
        });
        set.add_prefix_list("doc", doc);

        // rm: deny doc prefixes, permit the rest (implicit final entry).
        set.push_route_map_entry(
            "peer-in",
            RouteMapEntry {
                matches: vec![set.match_condition(ListKind::Prefix, "doc").unwrap()],
                sets: vec![],
                verdict: Some(false),
            },
        );
        set.push_route_map_entry(
            "peer-in",
            RouteMapEntry {
                matches: vec![],
                sets: vec![SetAction::SetLocalPref(250)],
                verdict: Some(true),
            },
        );
        set.bind_import(7, "peer-in");
        assert!(set.validate().is_ok());
        let hooks = set.hooks();

        let mut doc = route_for(&[198, 51, 100, 0]);
        assert!(matches!(hooks.on_import(&mut doc), HookVerdict::Drop));

        let mut ok = route_for(&[203, 0, 113, 0]);
        assert!(matches!(hooks.on_import(&mut ok), HookVerdict::Keep));
        // SetLocalPref writes the LOCAL_PREF path attribute, not the
        // cross-protocol admin distance (which stays 20 for BGP).
        assert_eq!(ok.preference.admin_distance, 20);
        assert_eq!(crate::bgp::local_pref(&ok), Some(250));

        // Session without a binding: untouched.
        let mut other = route_for(&[198, 51, 100, 0]);
        other.origin.peer = 9;
        assert!(matches!(hooks.on_import(&mut other), HookVerdict::Keep));
    }

    #[test]
    fn export_dispatch_uses_destination() {
        let mut set = PolicySet::new();
        let mut only_doc = PrefixList::new();
        only_doc.push(PrefixListEntry {
            prefix: Prefix::new_v4([198, 51, 100, 0], 24),
            ge: 24,
            le: 32,
            permit: true,
        });
        set.add_prefix_list("doc-only", only_doc);
        set.push_route_map_entry(
            "out",
            RouteMapEntry {
                matches: vec![set.match_condition(ListKind::Prefix, "doc-only").unwrap()],
                sets: vec![],
                verdict: Some(true),
            },
        );
        set.bind_export(3, "out");
        let hooks = set.hooks();

        let mut doc = route_for(&[198, 51, 100, 0]);
        assert!(matches!(hooks.on_export_to(&mut doc, 3), HookVerdict::Keep));
        assert!(matches!(hooks.on_export_to(&mut doc, 4), HookVerdict::Keep));

        let mut other = route_for(&[203, 0, 113, 0]);
        // Destination 3 has a map that does not match -> deny.
        assert!(matches!(
            hooks.on_export_to(&mut other, 3),
            HookVerdict::Drop
        ));
        // Destination 4 has no map -> pass.
        assert!(matches!(
            hooks.on_export_to(&mut other, 4),
            HookVerdict::Keep
        ));
        // Destination-agnostic call -> pass (u64::MAX never bound).
        assert!(matches!(hooks.on_export(&mut other), HookVerdict::Keep));
    }

    #[test]
    fn validate_reports_missing_map() {
        let mut set = PolicySet::new();
        set.bind_import(1, "nope");
        assert_eq!(set.validate(), Err((1, "import", "nope".to_string())));
    }

    #[test]
    fn community_list_match_through_resolver() {
        let mut set = PolicySet::new();
        let mut cl = CommunityList::new();
        cl.push(CommunityListEntry {
            communities: vec![lr_bgp::path::communities::Community::new(64512, 42).as_u32()],
            permit: true,
        });
        set.add_community_list("known", cl);
        set.push_route_map_entry(
            "c-in",
            RouteMapEntry {
                matches: vec![set.match_condition(ListKind::Community, "known").unwrap()],
                sets: vec![],
                verdict: Some(true),
            },
        );
        set.bind_import(5, "c-in");

        let mut tagged = route_for(&[203, 0, 113, 0]);
        crate::bgp::add_community(
            &mut tagged,
            lr_bgp::path::communities::Community::new(64512, 42),
        );
        let hooks = set.hooks();
        assert!(matches!(hooks.on_import(&mut tagged), HookVerdict::Keep));

        let mut untagged = route_for(&[203, 0, 113, 0]);
        untagged.origin.peer = 5;
        assert!(matches!(hooks.on_import(&mut untagged), HookVerdict::Drop));
    }
}
