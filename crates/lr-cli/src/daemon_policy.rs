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
        let filter = dsl::compile(name, body).map_err(|e| {
            // Issue #18 Phase 0: render the positioned diagnostic with
            // a source snippet — the body IS the source, so spans are
            // directly displayable to the operator.
            format!(
                "filter '{name}': {}\n{}",
                e,
                dsl::render_snippet(body, e.span, &e.kind.to_string())
            )
        })?;
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
#[derive(Debug)]
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
    fn bgp_origin(&self, route: &lr_core::rib::Route) -> Option<u8> {
        // GitHub #19 P3: read ORIGIN from the route's attribute set
        // in place (no Vec clone). Defaults to IGP (0) when absent —
        // BIRD's `f_new` default for locally originated routes.
        Some(lr_policy::bgp::origin(route).unwrap_or(0))
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
    fn set_bgp_communities(
        &self,
        route: &mut lr_core::rib::Route,
        set: Vec<(lr_core::addr::Asn, u16)>,
    ) {
        let cs: Vec<lr_bgp::path::communities::Community> = set
            .into_iter()
            .filter(|(asn, _)| asn.0 <= u16::MAX as u32)
            .map(|(asn, val)| lr_bgp::path::communities::Community::new(asn.0 as u16, val))
            .collect();
        lr_policy::bgp::set_communities(route, cs);
    }
    fn set_bgp_as_path(&self, route: &mut lr_core::rib::Route, seq: Vec<lr_core::addr::Asn>) {
        lr_policy::bgp::set_as_sequence(route, seq);
    }
    fn bgp_large_communities(&self, route: &lr_core::rib::Route) -> Vec<(u32, u32, u32)> {
        lr_policy::bgp::large_communities(route)
            .into_iter()
            .map(|c| (c.global_admin, c.local_data1, c.local_data2))
            .collect()
    }
    fn bgp_ext_communities(&self, route: &lr_core::rib::Route) -> Vec<(u8, u8, u32, u16)> {
        lr_policy::bgp::ext_communities(route)
            .into_iter()
            .map(|c| (c.kind, c.subtype, c.global, c.local))
            .collect()
    }
    fn set_bgp_large_communities(
        &self,
        route: &mut lr_core::rib::Route,
        set: Vec<(u32, u32, u32)>,
    ) {
        let cs: Vec<lr_bgp::path::communities::LargeCommunity> = set
            .into_iter()
            .map(|(g, d1, d2)| lr_bgp::path::communities::LargeCommunity::new(g, d1, d2))
            .collect();
        lr_policy::bgp::set_large_communities(route, cs);
    }
    fn set_bgp_ext_communities(
        &self,
        route: &mut lr_core::rib::Route,
        set: Vec<(u8, u8, u32, u16)>,
    ) {
        let cs: Vec<lr_bgp::path::communities::ExtendedCommunity> = set
            .into_iter()
            .map(|(k, s, g, l)| lr_bgp::path::communities::ExtendedCommunity::new(k, s, g, l))
            .collect();
        lr_policy::bgp::set_ext_communities(route, cs);
    }
}

/// A BGP-style import hook wrapping a compiled DSL filter. Routes
/// matching `accept` are kept; `reject` drops them; `fallthrough`
/// defers to the next hook in the chain.
pub(crate) struct FilterImportHook {
    pub filter: DslFilter,
    /// Precompiled bytecode (ROADMAP-v3 D3.7): built once at hook
    /// construction, executed per route — the import/export hot path
    /// no longer re-walks the AST.
    pub compiled: lr_policy::filter::bytecode::CompiledFilter,
    pub ctx: std::sync::Arc<DaemonFilterContext>,
    /// Latency histogram (ROADMAP-v3 D12.4). `None` unless the
    /// metrics endpoint is configured — the per-route timing (two
    /// `Instant::now()` calls) is opt-in so the hot path stays free
    /// of observability cost when nobody is scraping.
    pub stats: Option<std::sync::Arc<crate::metrics::DurationHistogram>>,
}

impl lr_policy::hooks::ImportHook for FilterImportHook {
    fn name(&self) -> &str {
        &self.filter.name
    }
    fn on_import(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        match &self.stats {
            Some(hist) => {
                let t0 = std::time::Instant::now();
                let verdict =
                    lr_policy::filter::bytecode::execute(&self.compiled, route, self.ctx.as_ref());
                hist.record(t0.elapsed().as_nanos() as u64);
                map_verdict(verdict)
            }
            None => map_verdict(lr_policy::filter::bytecode::execute(
                &self.compiled,
                route,
                self.ctx.as_ref(),
            )),
        }
    }
}

/// Map an [`EvalResult`] onto the hook verdict shared by both
/// directions: `accept`/`fallthrough` keep the route, `reject` drops
/// it.
fn map_verdict(result: EvalResult) -> lr_policy::hooks::HookVerdict {
    match result {
        EvalResult::Accept => lr_policy::hooks::HookVerdict::Keep,
        EvalResult::Reject(_) => lr_policy::hooks::HookVerdict::Drop,
        EvalResult::Fallthrough => lr_policy::hooks::HookVerdict::Keep,
    }
}

/// A BGP-style export hook wrapping a compiled DSL filter. Same
/// semantics as [`FilterImportHook`] but on the outbound side.
pub(crate) struct FilterExportHook {
    pub filter: DslFilter,
    /// See [`FilterImportHook::compiled`].
    pub compiled: lr_policy::filter::bytecode::CompiledFilter,
    pub ctx: std::sync::Arc<DaemonFilterContext>,
    /// See [`FilterImportHook::stats`].
    pub stats: Option<std::sync::Arc<crate::metrics::DurationHistogram>>,
}

impl lr_policy::hooks::ExportHook for FilterExportHook {
    fn name(&self) -> &str {
        &self.filter.name
    }
    fn on_export(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        match &self.stats {
            Some(hist) => {
                let t0 = std::time::Instant::now();
                let verdict =
                    lr_policy::filter::bytecode::execute(&self.compiled, route, self.ctx.as_ref());
                hist.record(t0.elapsed().as_nanos() as u64);
                map_verdict(verdict)
            }
            None => map_verdict(lr_policy::filter::bytecode::execute(
                &self.compiled,
                route,
                self.ctx.as_ref(),
            )),
        }
    }
}

/// One end of a Babel import/export filter pair: a compiled bytecode
/// filter and its evaluation context. Held by the daemon and consulted
/// per route — for the import direction the [`BabelFilterImportHook`]
/// wrapper does the per-route check; for the export direction the
/// daemon's announcement builder calls [`BabelFilter::accepts`].
///
/// Constructed by [`build_babel_filter`].
#[derive(Debug)]
pub(crate) struct BabelFilter {
    pub name: String,
    pub compiled: lr_policy::filter::bytecode::CompiledFilter,
    pub ctx: std::sync::Arc<DaemonFilterContext>,
}

impl BabelFilter {
    /// True when the route is accepted by the filter (`accept` or
    /// `fallthrough`); false when rejected. The export path uses this
    /// to skip routes the operator does not want announced over Babel.
    pub fn accepts(&self, route: &lr_core::rib::Route) -> bool {
        let mut tmp = route.clone();
        let verdict =
            lr_policy::filter::bytecode::execute(&self.compiled, &mut tmp, self.ctx.as_ref());
        !matches!(verdict, EvalResult::Reject(_))
    }
}

/// Look up the named filter in the daemon's `[[filter]]` tables and
/// compile it for use as a Babel import or export filter. `None` when
/// the name is `None` (no filter configured). Errors out when the
/// filter name is unknown or fails to compile — Babel filter wiring
/// fails closed like every other protocol surface.
pub(crate) fn build_babel_filter(
    cfg: &DaemonConfig,
    name: &Option<String>,
    roa: &std::sync::Arc<lr_bgp::RoaStore>,
) -> Result<Option<BabelFilter>, String> {
    let Some(name) = name.as_deref() else {
        return Ok(None);
    };
    let filters = build_filters(cfg)?;
    let Some((_, filter)) = filters.iter().find(|(n, _)| n == name) else {
        return Err(format!(
            "babel: unknown filter '{name}' (declared filters: {})",
            filters
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    };
    let compiled = lr_policy::filter::bytecode::compile(filter);
    Ok(Some(BabelFilter {
        name: name.to_string(),
        compiled,
        ctx: std::sync::Arc::new(DaemonFilterContext::new(std::sync::Arc::clone(roa))),
    }))
}

/// Babel import hook: runs a compiled DSL filter on every route
/// received on a Babel session (the route's `protocol` field is
/// `Protocol::Babel`). Routes from any other protocol pass through
/// unchanged — the operator's filter body does not need to scope
/// itself with `if proto == "babel"`.
///
/// Mirrors [`FilterImportHook`] but adds the protocol gate so the
/// filter and BGP's per-peer filters can coexist on the same router
/// (the Babel filter never evaluates against a BGP-learned route,
/// and vice versa).
pub(crate) struct BabelFilterImportHook {
    pub inner: BabelFilter,
    /// See [`FilterImportHook::stats`].
    pub stats: Option<std::sync::Arc<crate::metrics::DurationHistogram>>,
}

impl lr_policy::hooks::ImportHook for BabelFilterImportHook {
    fn name(&self) -> &str {
        &self.inner.name
    }
    fn on_import(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        if route.protocol != lr_core::rib::Protocol::Babel {
            return lr_policy::hooks::HookVerdict::Keep;
        }
        match &self.stats {
            Some(hist) => {
                let t0 = std::time::Instant::now();
                let verdict = lr_policy::filter::bytecode::execute(
                    &self.inner.compiled,
                    route,
                    self.inner.ctx.as_ref(),
                );
                hist.record(t0.elapsed().as_nanos() as u64);
                map_verdict(verdict)
            }
            None => map_verdict(lr_policy::filter::bytecode::execute(
                &self.inner.compiled,
                route,
                self.inner.ctx.as_ref(),
            )),
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

    /// The D12.4 hook timing: a hook built with a histogram records
    /// one observation per evaluation (count and sum both move), and
    /// the verdict is unchanged by the timing wrapper.
    #[test]
    fn filter_hook_records_latency() {
        use lr_core::rib::Route;
        use lr_policy::hooks::{HookVerdict, ImportHook};

        let f = dsl::compile("timed", "if net ~ [ 192.0.2.0/24 ] then accept; reject;").unwrap();
        let ctx = std::sync::Arc::new(DaemonFilterContext::new(std::sync::Arc::new(
            lr_bgp::RoaStore::new(),
        )));
        let hist = std::sync::Arc::new(crate::metrics::DurationHistogram::new());
        let hook = FilterImportHook {
            compiled: lr_policy::filter::bytecode::compile(&f),
            filter: f,
            ctx,
            stats: Some(std::sync::Arc::clone(&hist)),
        };

        let mut route = Route {
            key: lr_core::rib::RouteKey::new(
                lr_core::addr::Prefix::new_v4([192, 0, 2, 0], 24),
                lr_core::nlri::NlriFamily::IPV4_UNICAST,
            ),
            origin: lr_core::rib::RouteOrigin { proto: 0, peer: 1 },
            protocol: lr_core::rib::Protocol::Bgp,
            preference: lr_core::rib::Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        assert!(matches!(hook.on_import(&mut route), HookVerdict::Keep));
        assert_eq!(hist.count(), 1, "one evaluation recorded");

        let mut other = route.clone();
        other.key.prefix = lr_core::addr::Prefix::new_v4([198, 51, 100, 0], 24);
        assert!(matches!(hook.on_import(&mut other), HookVerdict::Drop));
        assert_eq!(hist.count(), 2, "second evaluation recorded");
    }

    /// Babel filter lookup: a named filter declared in `[[filter]]`
    /// blocks resolves to a compiled BabelFilter; an unknown name
    /// fails closed.
    #[test]
    fn babel_filter_builds_from_named_filter() {
        let cfg = parse(
            "[[filter]]\nname = \"babel-in\"\nbody = \"if net ~ [ 10.0.0.0/8 ] then accept; reject;\"\n",
        );
        let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
        let f = build_babel_filter(&cfg, &Some("babel-in".into()), &roa)
            .expect("filter must compile")
            .expect("filter must be found");
        assert_eq!(f.name, "babel-in");
    }

    /// Unknown babel filter name → startup error (typo protection;
    /// the daemon must not silently run with no filter).
    #[test]
    fn babel_filter_unknown_name_fails() {
        let cfg = parse("[[filter]]\nname = \"babel-in\"\nbody = \"accept;\"\n");
        let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
        let err = build_babel_filter(&cfg, &Some("ghost".into()), &roa).unwrap_err();
        assert!(err.contains("unknown filter 'ghost'"), "{err}");
    }

    /// `None` filter name → no filter (the historical accept-all
    /// behaviour). This is the path every existing config takes.
    #[test]
    fn babel_filter_none_when_unconfigured() {
        let cfg = DaemonConfig::with_defaults();
        let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
        let f = build_babel_filter(&cfg, &None, &roa).unwrap();
        assert!(f.is_none(), "no filter name → no filter");
    }

    /// The BabelFilterImportHook only runs the DSL against
    /// `Protocol::Babel` routes; BGP/OSPF/connected routes pass
    /// through unchanged (the operator's filter body does not need
    /// to scope itself with `if proto == "babel"`).
    #[test]
    fn babel_import_hook_skips_non_babel_routes() {
        use lr_core::rib::Route;
        use lr_policy::hooks::{HookVerdict, ImportHook};

        // The filter rejects everything — but the hook must only
        // apply to Babel routes, so a BGP route passing through this
        // hook should still be kept (it never reaches the DSL).
        let cfg = parse("[[filter]]\nname = \"drop-all\"\nbody = \"reject;\"\n");
        let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
        let f = build_babel_filter(&cfg, &Some("drop-all".into()), &roa)
            .unwrap()
            .unwrap();
        let hook = BabelFilterImportHook {
            inner: BabelFilter {
                name: f.name.clone(),
                compiled: f.compiled.clone(),
                ctx: f.ctx.clone(),
            },
            stats: None,
        };

        // A BGP route: must pass through unchanged.
        let mut bgp_route = Route {
            key: lr_core::rib::RouteKey::new(
                lr_core::addr::Prefix::new_v4([192, 0, 2, 0], 24),
                lr_core::nlri::NlriFamily::IPV4_UNICAST,
            ),
            origin: lr_core::rib::RouteOrigin { proto: 0, peer: 1 },
            protocol: lr_core::rib::Protocol::Bgp,
            preference: lr_core::rib::Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        assert!(
            matches!(hook.on_import(&mut bgp_route), HookVerdict::Keep),
            "BGP route must bypass the babel filter"
        );

        // A Babel route: must be dropped by the `reject;` body.
        let mut babel_route = bgp_route.clone();
        babel_route.protocol = lr_core::rib::Protocol::Babel;
        assert!(
            matches!(hook.on_import(&mut babel_route), HookVerdict::Drop),
            "Babel route must hit the filter and be dropped"
        );
    }

    /// The export-side `BabelFilter::accepts` mirrors the import-side
    /// verdict: accept / fallthrough → true, reject → false.
    #[test]
    fn babel_export_filter_accepts_routes() {
        let cfg = parse(
            "[[filter]]\nname = \"out\"\nbody = \"if net ~ [ 10.0.0.0/8 ] then accept; reject;\"\n",
        );
        let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
        let f = build_babel_filter(&cfg, &Some("out".into()), &roa)
            .unwrap()
            .unwrap();

        let mut route = lr_core::rib::Route {
            key: lr_core::rib::RouteKey::new(
                lr_core::addr::Prefix::new_v4([10, 0, 0, 0], 8),
                lr_core::nlri::NlriFamily::IPV4_UNICAST,
            ),
            origin: lr_core::rib::RouteOrigin { proto: 0, peer: 0 },
            protocol: lr_core::rib::Protocol::Bgp,
            preference: lr_core::rib::Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        assert!(f.accepts(&route), "10.0.0.0/8 matches → accept");

        route.key.prefix = lr_core::addr::Prefix::new_v4([192, 0, 2, 0], 24);
        assert!(!f.accepts(&route), "192.0.2.0/24 does not match → reject");
    }
}
