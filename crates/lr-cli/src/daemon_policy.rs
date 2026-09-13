//! TOML policy objects for `lr-daemon`: `[[prefix-list]]`,
//! `[[as-path-list]]`, `[[community-list]]` and `[[route-map]]`
//! tables plus per-peer `import = "<route-map>"` / `export =
//! "<route-map>"` attachment, compiled into an
//! [`lr_policy::PolicySet`] wired onto the router hooks.
//!
//! Design: declarative tables mapping 1:1 onto `lr-policy` primitives
//! — no filter DSL and no embedded scripting. Entries within one
//! route-map apply in ascending `entry` order (ties keep file order),
//! mirroring FRR `route-map NAME permit N` instances.

use core::str::FromStr;
use std::process::ExitCode;

use lr_core::addr::Prefix;
use lr_policy::action::SetAction;
use lr_policy::as_path_filter::AsPathFilter;
use lr_policy::community_list::{CommunityList, CommunityListEntry};
use lr_policy::filter::{self as dsl, EvalResult, Filter as DslFilter, FilterContext};
use lr_policy::prefix_list::{PrefixList, PrefixListEntry};
use lr_policy::route_map::RouteMapEntry;
use lr_policy::{ListKind, PolicySet};

use crate::daemon_config::DaemonConfig;

/// One `[[prefix-list]]` table: `name`, `prefix`, optional
/// `ge`/`le`/`permit` (ge defaults to the prefix length, le to
/// unbounded, permit to true).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PrefixListSpec {
    pub name: String,
    pub prefix: String,
    pub ge: Option<u8>,
    pub le: Option<u8>,
    pub permit: Option<bool>,
}

/// One `[[as-path-list]]` table: `name`, `pattern`, `permit`.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct AsPathListSpec {
    pub name: String,
    pub pattern: String,
    pub permit: Option<bool>,
}

/// One `[[community-list]]` table: `name`, `communities`, `permit`.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct CommunityListSpec {
    pub name: String,
    pub communities: Vec<String>,
    pub permit: Option<bool>,
}

/// One `[[route-map]]` table instance (a single entry of the named
/// map): `name`, optional `entry` (ordering key), any of
/// `match_prefix` / `match_as_path` / `match_community` (AND), set
/// keys `set_local_pref` / `set_med` / `set_metric` / `set_next_hop` /
/// `prepend` / `add_community`, and `permit` for the verdict
/// (absent = continue to the next entry).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct RouteMapSpec {
    pub name: String,
    pub entry: u32,
    pub match_prefix: Option<String>,
    pub match_as_path: Option<String>,
    pub match_community: Option<String>,
    pub set_local_pref: Option<u32>,
    pub set_med: Option<u32>,
    pub set_metric: Option<u32>,
    pub set_next_hop: Option<String>,
    /// Space-separated AS numbers, prepended in order
    /// (FRR `set as-path prepend 65001 65001`).
    pub prepend: Option<String>,
    /// One `asn:value` community (or several, space-separated).
    pub add_community: Option<String>,
    pub permit: Option<bool>,
}

/// Compile the parsed policy tables into a [`PolicySet`].
///
/// Every reference (route-map -> list, peer -> route-map) must resolve;
/// unknown names are startup errors — fail closed, never silently
/// permissive.
pub(crate) fn build_policy_set(cfg: &DaemonConfig) -> Result<PolicySet, String> {
    let mut set = PolicySet::new();

    for spec in &cfg.prefix_lists {
        let prefix = Prefix::from_str(&spec.prefix).map_err(|e| {
            format!(
                "prefix-list '{}': bad prefix '{}': {}",
                spec.name, spec.prefix, e
            )
        })?;
        let mut list = PrefixList::new();
        list.push(PrefixListEntry {
            prefix,
            ge: spec.ge.unwrap_or(prefix.prefix_len),
            le: spec.le.unwrap_or(255),
            permit: spec.permit.unwrap_or(true),
        });
        set.add_prefix_list(spec.name.clone(), list);
    }

    for spec in &cfg.as_path_lists {
        set.add_as_path_list(
            spec.name.clone(),
            vec![AsPathFilter {
                pattern: spec.pattern.clone(),
                permit: spec.permit.unwrap_or(true),
            }],
        );
    }

    for spec in &cfg.community_lists {
        let mut comms = Vec::new();
        for c in &spec.communities {
            comms.push(
                parse_community(c).map_err(|e| format!("community-list '{}': {}", spec.name, e))?,
            );
        }
        let mut list = CommunityList::new();
        list.push(CommunityListEntry {
            communities: comms,
            permit: spec.permit.unwrap_or(true),
        });
        set.add_community_list(spec.name.clone(), list);
    }

    // Route-map entries: ascending `entry`, ties in file order.
    let mut ordered: Vec<&RouteMapSpec> = cfg.route_maps.iter().collect();
    ordered.sort_by_key(|s| s.entry);
    for spec in ordered {
        let mut matches = Vec::new();
        if let Some(name) = &spec.match_prefix {
            matches.push(set.match_condition(ListKind::Prefix, name).ok_or_else(|| {
                format!("route-map '{}': unknown prefix-list '{}'", spec.name, name)
            })?);
        }
        if let Some(name) = &spec.match_as_path {
            matches.push(set.match_condition(ListKind::AsPath, name).ok_or_else(|| {
                format!("route-map '{}': unknown as-path-list '{}'", spec.name, name)
            })?);
        }
        if let Some(name) = &spec.match_community {
            matches.push(
                set.match_condition(ListKind::Community, name)
                    .ok_or_else(|| {
                        format!(
                            "route-map '{}': unknown community-list '{}'",
                            spec.name, name
                        )
                    })?,
            );
        }

        let mut sets = Vec::new();
        if let Some(v) = spec.set_local_pref {
            sets.push(SetAction::SetLocalPref(v));
        }
        if let Some(v) = spec.set_med {
            sets.push(SetAction::SetMed(v));
        }
        if let Some(v) = spec.set_metric {
            sets.push(SetAction::SetMetric(v));
        }
        if let Some(ip) = &spec.set_next_hop {
            let ip = lr_core::addr::IpAddr::from_str(ip).map_err(|e| {
                format!(
                    "route-map '{}': bad set_next_hop '{}': {}",
                    spec.name, ip, e
                )
            })?;
            sets.push(SetAction::SetNextHop(ip));
        }
        if let Some(list) = &spec.prepend {
            for token in list.split_whitespace() {
                let asn: u32 = token.parse().map_err(|_| {
                    format!("route-map '{}': bad prepend AS '{}'", spec.name, token)
                })?;
                sets.push(SetAction::PrependAs(lr_core::addr::Asn(asn)));
            }
        }
        if let Some(list) = &spec.add_community {
            for token in list.split_whitespace() {
                let c = parse_community(token)
                    .map_err(|e| format!("route-map '{}': {}", spec.name, e))?;
                sets.push(SetAction::AddCommunity(
                    lr_core::addr::Asn(c >> 16),
                    (c & 0xffff) as u16,
                ));
            }
        }

        set.push_route_map_entry(
            spec.name.clone(),
            RouteMapEntry {
                matches,
                sets,
                verdict: spec.permit,
            },
        );
    }

    Ok(set)
}

/// Parse `asn:value`, a plain decimal u32 or the well-known RFC 1997
/// names (`no-export`, `no-advertise`, `no-peer`, plus the lr
/// RFC 9494 names `llgr-stale` / `no-llgr`).
pub(crate) fn parse_community(text: &str) -> Result<u32, String> {
    let t = text.trim();
    match t {
        "no-export" => return Ok(0xFFFFFF01),
        "no-advertise" => return Ok(0xFFFFFF02),
        "no-peer" => return Ok(0xFFFFFF03),
        "llgr-stale" => return Ok(0xFFFF0000),
        "no-llgr" => return Ok(0xFFFF0001),
        _ => {}
    }
    if let Some((asn, value)) = t.split_once(':') {
        let asn: u32 = asn
            .parse()
            .map_err(|_| format!("bad community '{}' (expected asn:value)", t))?;
        let value: u16 = value
            .parse()
            .map_err(|_| format!("bad community '{}' (expected asn:value)", t))?;
        if asn > 0xFFFF {
            return Err(format!("bad community '{}' (asn part exceeds 16 bits)", t));
        }
        return Ok((asn << 16) | value as u32);
    }
    t.parse::<u32>().map_err(|_| {
        format!(
            "bad community '{}' (expected asn:value, decimal or well-known name)",
            t
        )
    })
}

/// Wire per-peer `import`/`export` route-maps onto session handles.
/// Call before [`PolicySet::hooks`]; returns a startup error when a
/// peer references an unknown route-map (fail closed).
pub(crate) fn bind_peer_policies(
    cfg: &DaemonConfig,
    set: &mut PolicySet,
    session_of_peer: impl Fn(usize) -> u64,
) -> Result<(), String> {
    for (idx, peer) in cfg.peers.iter().enumerate() {
        if let Some(name) = &peer.import {
            if set.route_map(name).is_none() {
                return Err(format!(
                    "peer {}: unknown route-map '{}'",
                    peer.label(),
                    name
                ));
            }
            set.bind_import(session_of_peer(idx), name.clone());
        }
        if let Some(name) = &peer.export {
            if set.route_map(name).is_none() {
                return Err(format!(
                    "peer {}: unknown route-map '{}'",
                    peer.label(),
                    name
                ));
            }
            set.bind_export(session_of_peer(idx), name.clone());
        }
    }
    Ok(())
}

/// Compile every `[[filter]]` body in the config into a [`DslFilter`]
/// and return them keyed by name. Returns a startup error on the
/// first filter that fails to parse or has a duplicate name.
pub(crate) fn build_filters(cfg: &DaemonConfig) -> Result<Vec<(String, DslFilter)>, String> {
    let mut out = Vec::with_capacity(cfg.filters.len());
    let mut seen = std::collections::BTreeSet::new();
    for spec in &cfg.filters {
        let name = spec.name.as_deref().unwrap_or("");
        if !seen.insert(name.to_string()) {
            return Err(format!("filter '{name}' declared twice"));
        }
        let body = spec.body.as_deref().unwrap_or("");
        let filter = dsl::compile(name, body).map_err(|e| format!("filter '{name}': {e}"))?;
        out.push((name.to_string(), filter));
    }
    Ok(out)
}

/// A concrete [`FilterContext`] backed by `lr_policy::bgp`'s typed
/// accessors. Used by both the import and export filter hooks.
/// The ROA half is a shared [`lr_bgp::RoaStore`]: the RTR client
/// thread swaps snapshots underneath as syncs land, so `roa.state`
/// in every filter tracks the live cache data without any
/// recompilation (ROADMAP-v3 D2.3/D2.4).
pub(crate) struct DaemonFilterContext {
    roa: std::sync::Arc<lr_bgp::RoaStore>,
}

impl DaemonFilterContext {
    pub(crate) fn new(roa: std::sync::Arc<lr_bgp::RoaStore>) -> Self {
        Self { roa }
    }
}

impl FilterContext for DaemonFilterContext {
    fn bgp_local_pref(&self, route: &lr_core::rib::Route) -> Option<u32> {
        lr_policy::bgp::local_pref(route)
    }
    fn bgp_med(&self, route: &lr_core::rib::Route) -> Option<u32> {
        lr_policy::bgp::med(route)
    }
    fn bgp_next_hop(&self, route: &lr_core::rib::Route) -> Option<lr_core::addr::IpAddr> {
        route.next_hop
    }
    fn bgp_as_path(&self, route: &lr_core::rib::Route) -> Vec<lr_core::addr::Asn> {
        lr_policy::bgp::as_sequence(route)
    }
    fn bgp_communities(&self, route: &lr_core::rib::Route) -> Vec<(lr_core::addr::Asn, u16)> {
        lr_policy::bgp::communities(route)
            .into_iter()
            .map(|c| {
                let raw = c.as_u32();
                let asn = raw >> 16;
                let val = (raw & 0xFFFF) as u16;
                (lr_core::addr::Asn(asn), val)
            })
            .collect()
    }
    fn bgp_origin(&self, _route: &lr_core::rib::Route) -> Option<u8> {
        // Origin attribute (IGP=0, EGP=1, INCOMPLETE=2) — not yet
        // surfaced by lr-policy::bgp. Future work.
        Some(0)
    }
    fn roa_state(&self, route: &lr_core::rib::Route) -> lr_policy::filter::RoaStateLit {
        use lr_policy::filter::RoaStateLit;
        let origin = lr_policy::bgp::as_sequence(route).last().copied();
        // Snapshot once per evaluation: every `roa.state` access in
        // one filter run sees the same table version, and the load is
        // a single `Arc` clone under a read lock.
        let table = self.roa.load();
        let state = table.validate(&route.key.prefix, origin);
        match state {
            lr_bgp::RoaState::Valid => RoaStateLit::Valid,
            lr_bgp::RoaState::NotFound => RoaStateLit::NotFound,
            lr_bgp::RoaState::Invalid => RoaStateLit::Invalid,
        }
    }
    fn set_bgp_local_pref(&self, route: &mut lr_core::rib::Route, value: u32) {
        lr_policy::bgp::set_local_pref(route, value)
    }
    fn set_bgp_med(&self, route: &mut lr_core::rib::Route, value: u32) {
        lr_policy::bgp::set_med(route, value)
    }
    fn set_bgp_next_hop(&self, route: &mut lr_core::rib::Route, value: lr_core::addr::IpAddr) {
        route.next_hop = Some(value);
    }
    fn bgp_as_path_prepend(&self, route: &mut lr_core::rib::Route, asn: lr_core::addr::Asn) {
        lr_policy::bgp::prepend_as(route, asn)
    }
    fn bgp_communities_add(
        &self,
        route: &mut lr_core::rib::Route,
        asn: lr_core::addr::Asn,
        val: u16,
    ) {
        if asn.0 <= u16::MAX as u32 {
            let c = lr_bgp::path::communities::Community::new(asn.0 as u16, val);
            lr_policy::bgp::add_community(route, c);
        }
    }
}

/// A BGP-style import hook wrapping a compiled DSL filter. Routes
/// matching `accept` are kept; `reject` drops them; `fallthrough`
/// defers to the next hook in the chain.
pub(crate) struct FilterImportHook {
    pub filter: DslFilter,
    pub ctx: std::sync::Arc<DaemonFilterContext>,
}

impl lr_policy::hooks::ImportHook for FilterImportHook {
    fn name(&self) -> &str {
        &self.filter.name
    }
    fn on_import(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        match dsl::evaluate(&self.filter, route, self.ctx.as_ref()) {
            EvalResult::Accept => lr_policy::hooks::HookVerdict::Keep,
            EvalResult::Reject(_) => lr_policy::hooks::HookVerdict::Drop,
            EvalResult::Fallthrough => lr_policy::hooks::HookVerdict::Keep,
        }
    }
}

/// A BGP-style export hook wrapping a compiled DSL filter. Same
/// semantics as [`FilterImportHook`] but on the outbound side.
pub(crate) struct FilterExportHook {
    pub filter: DslFilter,
    pub ctx: std::sync::Arc<DaemonFilterContext>,
}

impl lr_policy::hooks::ExportHook for FilterExportHook {
    fn name(&self) -> &str {
        &self.filter.name
    }
    fn on_export(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        match dsl::evaluate(&self.filter, route, self.ctx.as_ref()) {
            EvalResult::Accept => lr_policy::hooks::HookVerdict::Keep,
            EvalResult::Reject(_) => lr_policy::hooks::HookVerdict::Drop,
            EvalResult::Fallthrough => lr_policy::hooks::HookVerdict::Keep,
        }
    }
}

/// Build the router-wide ROA table from the `[[roa]]` config tables.
pub(crate) fn build_roa_table(cfg: &DaemonConfig) -> Result<lr_bgp::RoaTable, String> {
    let mut builder = lr_bgp::RoaTableBuilder::new();
    for spec in &cfg.roas {
        let prefix = spec.prefix.as_deref().unwrap_or("");
        let asn = spec
            .asn
            .ok_or_else(|| format!("[[roa]] {prefix} without 'asn'"))?;
        builder
            .add(prefix, spec.max_length, asn)
            .map_err(|e| format!("[[roa]] {prefix}: {e}"))?;
    }
    Ok(builder.build())
}

/// Convenience wrapper used by `main` to fail with exit code 2 on
/// policy configuration errors.
pub(crate) fn policy_error(msg: String) -> ExitCode {
    eprintln!("error: {}", msg);
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_config::parse_toml_subset;
    use crate::daemon_config::DaemonConfig;

    fn parse(text: &str) -> DaemonConfig {
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(text, &mut cfg).unwrap();
        cfg
    }

    #[test]
    fn community_syntaxes() {
        assert_eq!(parse_community("64512:100"), Ok(0xFC00_0064));
        assert_eq!(parse_community("4224"), Ok(4224));
        assert_eq!(parse_community("no-export"), Ok(0xFFFFFF01));
        assert!(parse_community("70000:1").is_err());
        assert!(parse_community("garbage").is_err());
    }

    #[test]
    fn policy_tables_compile() {
        let cfg = parse(
            "[[prefix-list]]\nname = \"doc\"\nprefix = \"198.51.100.0/24\"\n\n\
             [[route-map]]\nname = \"in\"\nentry = 10\nmatch_prefix = \"doc\"\npermit = false\n\n\
             [[route-map]]\nname = \"in\"\nentry = 20\nset_local_pref = 250\npermit = true\n",
        );
        assert_eq!(cfg.prefix_lists.len(), 1);
        assert_eq!(cfg.route_maps.len(), 2);
        let set = build_policy_set(&cfg).unwrap();
        assert!(set.route_map("in").is_some());
    }

    #[test]
    fn unknown_references_fail_closed() {
        let cfg = parse("[[route-map]]\nname = \"x\"\nmatch_prefix = \"ghost\"\npermit = true\n");
        let err = build_policy_set(&cfg).err().expect("must fail");
        assert!(err.contains("unknown prefix-list 'ghost'"), "{err}");

        let mut cfg2 = DaemonConfig::with_defaults();
        cfg2.peers.push(crate::daemon_config::PeerSpec {
            import: Some("ghost-map".into()),
            ..Default::default()
        });
        let mut set = PolicySet::new();
        let err = bind_peer_policies(&cfg2, &mut set, |i| i as u64).unwrap_err();
        assert!(err.contains("unknown route-map 'ghost-map'"), "{err}");
    }

    #[test]
    fn route_map_entries_apply_in_entry_order() {
        let cfg = parse(
            "[[route-map]]\nname = \"m\"\nentry = 20\npermit = true\n\n\
             [[route-map]]\nname = \"m\"\nentry = 10\npermit = false\n",
        );
        let set = build_policy_set(&cfg).unwrap();
        // Entry 10 (deny) must be first regardless of file order.
        let map = set.route_map("m").unwrap();
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].verdict, Some(false));
    }

    #[test]
    fn roa_table_builds_from_config() {
        let cfg = parse(
            "[[roa]]\nprefix = \"203.0.113.0/24\"\nasn = 64512\n\n\
             [[roa]]\nprefix = \"198.51.100.0/24\"\nmax_length = 26\nasn = 64513\n",
        );
        let t = build_roa_table(&cfg).unwrap();
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn roa_table_rejects_bad_config() {
        let cfg = parse("[[roa]]\nprefix = \"203.0.113.0/24\"\nmax_length = 23\nasn = 64512\n");
        let err = build_roa_table(&cfg).unwrap_err();
        assert!(err.contains("max_length"), "{err}");
    }

    #[test]
    fn filters_compile() {
        let cfg = parse(
            "[[filter]]\nname = \"customer-in\"\nbody = \"if net ~ 203.0.113.0/24 then accept; reject;\"\n",
        );
        let filters = build_filters(&cfg).unwrap();
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].0, "customer-in");
    }

    #[test]
    fn filter_duplicate_name_fails() {
        let cfg = parse(
            "[[filter]]\nname = \"dup\"\nbody = \"accept;\"\n\n\
             [[filter]]\nname = \"dup\"\nbody = \"reject;\"\n",
        );
        let err = build_filters(&cfg).unwrap_err();
        assert!(err.contains("declared twice"), "{err}");
    }

    #[test]
    fn filter_parse_error_fails() {
        let cfg = parse("[[filter]]\nname = \"bad\"\nbody = \"if net ~ then accept;\"\n");
        let err = build_filters(&cfg).unwrap_err();
        assert!(err.contains("filter 'bad'"), "{err}");
    }

    #[test]
    fn filter_with_variables_and_arithmetic_compiles() {
        // A non-trivial BIRD-style filter: variable bindings,
        // arithmetic, prefix-set range, method call, append.
        let cfg = parse(
            "[[filter]]\nname = \"complex\"\nbody = \"let p = 100; let q = p * 2; if bgp.local_pref < q && net ~ [ 10.0.0.0/8{16,24} ] then { bgp.local_pref = q; bgp.communities += [ 64512:100 ]; accept; } reject;\"\n",
        );
        let filters = build_filters(&cfg).unwrap();
        assert_eq!(filters.len(), 1);
    }
}
