//! Policy objects for `lr-daemon`: `[[prefix-list]]`,
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

use crate::Component;
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
        let pl = prefix.prefix_len;
        let family_max: u8 = if prefix.is_ipv4() { 32 } else { 128 };
        // FRR `ip prefix-list` semantics: with neither `ge` nor `le`
        // the entry matches the prefix length exactly; with `ge`
        // alone the window is [ge, family max]; with `le` alone it is
        // [plen, le]. (The old default — `le = 255` unconditionally —
        // made `permit 10.0.0.0/8` silently admit 10.1.2.0/24.)
        let ge = spec.ge.unwrap_or(pl);
        let le = match (spec.ge, spec.le) {
            (_, Some(le)) => le,
            (Some(_), None) => family_max,
            (None, None) => pl,
        };
        // FRR vty validation: an impossible window is a config error,
        // not a silently-never-matching entry. Fail closed.
        if ge < pl {
            return Err(format!(
                "prefix-list '{}': ge {ge} is below the prefix length {pl}",
                spec.name
            ));
        }
        if le < pl {
            return Err(format!(
                "prefix-list '{}': le {le} is below the prefix length {pl}",
                spec.name
            ));
        }
        if le > family_max {
            return Err(format!(
                "prefix-list '{}': le {le} exceeds the {}-bit family maximum",
                spec.name, family_max
            ));
        }
        if ge > le {
            return Err(format!(
                "prefix-list '{}': ge {ge} is greater than le {le}",
                spec.name
            ));
        }
        let mut list = PrefixList::new();
        list.push(PrefixListEntry {
            prefix,
            ge,
            le,
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

/// Compile every `[[filter]]` body in the config into a [`DslFilter`]
/// and return them keyed by name. Returns a startup error on the
/// first filter that fails to parse or has a duplicate name.
pub(crate) fn build_filters(cfg: &DaemonConfig) -> Result<Vec<(String, DslFilter)>, String> {
    // Build the shared-function preamble once. Each
    // declared function becomes a `function name(params) { body }`
    // declaration; the preamble is prepended to every filter body
    // before compilation so the functions are callable from any
    // filter and from any other shared function. The DSL parser
    // fails closed on a duplicate name or a shadow of a built-in.
    let shared_preamble = render_filter_function_preamble(&cfg.filter_functions)?;
    let mut out = Vec::with_capacity(cfg.filters.len());
    let mut seen = std::collections::BTreeSet::new();
    for spec in &cfg.filters {
        let name = spec.name.as_deref().unwrap_or("");
        if !seen.insert(name.to_string()) {
            return Err(format!("filter '{name}' declared twice"));
        }
        // Prepend the shared functions so the filter body can call
        // them. The preamble carries no statements, so a filter with
        // no body of its own still compiles (it falls through).
        let body = spec.body.as_deref().unwrap_or("");
        let full = if shared_preamble.is_empty() {
            body.to_string()
        } else {
            format!("{shared_preamble}\n{body}")
        };
        let filter = dsl::compile(name, &full).map_err(|e| {
            // Phase 0: render the positioned diagnostic with
            // a source snippet — the body IS the source, so spans are
            // directly displayable to the operator.
            format!(
                "filter '{name}': {}\n{}",
                e,
                dsl::render_snippet(&full, e.span, &e.kind.to_string())
            )
        })?;
        out.push((name.to_string(), filter));
    }
    Ok(out)
}

/// Render the shared-function declarations as a DSL preamble string.
/// Each `[[filter_function]]` becomes `function name(params) { body }`
/// on its own line; the declarations are emitted in config order so a
/// later function can call an earlier one. The body is the operator's
/// DSL source verbatim — the parser validates it.
///
/// Returns `Ok(String::new())` when no shared functions are declared,
/// so `build_filters` can skip the prepend work entirely on a config
/// without `[[filter_function]]` tables.
fn render_filter_function_preamble(
    funcs: &[crate::daemon_config::FilterFunctionSpec],
) -> Result<String, String> {
    if funcs.is_empty() {
        return Ok(String::new());
    }
    // Detect duplicate names early — the DSL parser would also catch
    // them, but the error message there points at the second
    // declaration's line in the synthetic preamble, not at the
    // operator's config file. Surface the duplicate here instead.
    let mut seen = std::collections::BTreeSet::new();
    let mut out = String::new();
    for func in funcs {
        let name = func.name.as_deref().unwrap_or("");
        if name.is_empty() {
            return Err("a [[filter_function]] is missing its 'name'".to_string());
        }
        if !seen.insert(name.to_string()) {
            return Err(format!("filter function '{name}' declared twice"));
        }
        let params = func.params.join(", ");
        // The DSL spells the return-type annotation `=> type`
        // (TokenKind::Arrow — the lexer's `=` + `>` form); `->`
        // lexes as `Minus` + `Gt` and fails to parse, so the
        // preamble must render the arrow the grammar expects.
        let ret = match &func.return_type {
            Some(t) => format!(" => {t}"),
            None => String::new(),
        };
        let body = func.body.as_deref().unwrap_or("");
        out.push_str(&format!("function {name}({params}){ret} {{\n{body}\n}}\n"));
    }
    Ok(out)
}

/// A concrete [`FilterContext`] backed by `lr_policy::bgp`'s typed
/// accessors. Used by both the import and export filter hooks.
/// The ROA half is a shared [`lr_bgp::RoaStore`]: the RTR client
/// thread swaps snapshots underneath as syncs land, so `roa.state`
/// in every filter tracks the live cache data without any
/// recompilation.
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
///
/// A configured peer's import filter applies only to routes learned
/// from that peer's sessions (BIRD `protocol bgp { import filter ... }`
/// / FRR `neighbor X route-map ... in`). [`sessions`](Self::sessions)
/// binds the hook to the router session handles that peer owns — a
/// bidirectional neighbor has two (outbound + inbound challenger), and
/// both share the same configured filter. `None` is the router-wide
/// form used by the built-in ROA validation hook, which intentionally
/// runs for every BGP session.
pub(crate) struct FilterImportHook {
    pub filter: DslFilter,
    /// Precompiled bytecode: built once at hook
    /// construction, executed per route — the import/export hot path
    /// no longer re-walks the AST.
    pub compiled: lr_policy::filter::bytecode::CompiledFilter,
    pub ctx: std::sync::Arc<DaemonFilterContext>,
    /// Latency histogram. `None` unless the
    /// metrics endpoint is configured — the per-route timing (two
    /// `Instant::now()` calls) is opt-in so the hot path stays free
    /// of observability cost when nobody is scraping.
    pub stats: Option<std::sync::Arc<crate::metrics::DurationHistogram>>,
    /// Router sessions this filter is bound to. `None` means the hook
    /// applies to every session (the router-wide ROA validation hook).
    pub sessions: Option<std::collections::BTreeSet<u64>>,
}

impl FilterImportHook {
    /// True when this hook must evaluate `route`. A bound hook ignores
    /// routes from every session outside its peer binding instead of
    /// rejecting them — an import filter on one neighbor must never
    /// become an implicit global filter.
    fn applies_to(&self, route: &lr_core::rib::Route) -> bool {
        match &self.sessions {
            Some(sessions) => sessions.contains(&route.origin.peer),
            None => true,
        }
    }

    fn evaluate(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
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

impl lr_policy::hooks::ImportHook for FilterImportHook {
    fn name(&self) -> &str {
        &self.filter.name
    }
    fn on_import(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        if !self.applies_to(route) {
            return lr_policy::hooks::HookVerdict::Keep;
        }
        self.evaluate(route)
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
        filter_accepts(&self.compiled, self.ctx.as_ref(), route)
    }
}

/// Look up a named `[[filter]]` body and compile it. `None` when the
/// name is `None` (no filter configured). The `owner` label prefixes
/// the error so the operator knows which protocol surface referenced
/// the unknown name. Every filter-wiring path fails closed here.
fn compile_named_filter(
    cfg: &DaemonConfig,
    name: &Option<String>,
    owner: &str,
) -> Result<Option<(String, lr_policy::filter::bytecode::CompiledFilter)>, String> {
    let Some(name) = name.as_deref() else {
        return Ok(None);
    };
    let filters = build_filters(cfg)?;
    let Some((_, filter)) = filters.iter().find(|(n, _)| n == name) else {
        return Err(format!(
            "{owner}: unknown filter '{name}' (declared filters: {})",
            filters
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    };
    Ok(Some((
        name.to_string(),
        lr_policy::filter::bytecode::compile(filter),
    )))
}

/// True when `compiled` accepts the route (`accept` or `fallthrough`).
/// Only an explicit `reject` drops it — the BIRD default for a filter
/// with no matching statement is accept, and both Babel and the kernel
/// mirror follow that.
fn filter_accepts(
    compiled: &lr_policy::filter::bytecode::CompiledFilter,
    ctx: &DaemonFilterContext,
    route: &lr_core::rib::Route,
) -> bool {
    let mut tmp = route.clone();
    let verdict = lr_policy::filter::bytecode::execute(compiled, &mut tmp, ctx);
    !matches!(verdict, EvalResult::Reject(_))
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
    Ok(
        compile_named_filter(cfg, name, "babel")?.map(|(name, compiled)| BabelFilter {
            name,
            compiled,
            ctx: std::sync::Arc::new(DaemonFilterContext::new(std::sync::Arc::clone(roa))),
        }),
    )
}

/// A compiled kernel FIB export filter (BIRD `protocol kernel { export
/// filter ...; }`). Unlike Babel's filter this one is consulted once
/// per Loc-RIB route at install time, before any plain/blackhole/LSP
/// operation: a rejected route leaves the FIB untouched and a later
/// withdrawal has nothing to delete (the mirror tracks what it
/// installed).
#[derive(Debug)]
pub(crate) struct KernelFilter {
    pub name: String,
    pub compiled: lr_policy::filter::bytecode::CompiledFilter,
    pub ctx: std::sync::Arc<DaemonFilterContext>,
}

impl KernelFilter {
    /// True when the route may be installed into the kernel FIB.
    pub fn accepts(&self, route: &lr_core::rib::Route) -> bool {
        filter_accepts(&self.compiled, self.ctx.as_ref(), route)
    }
}

/// Compile `[kernel] export_filter` against the declared filters.
/// `None` when the operator configured no filter. Fails closed on an
/// unknown name or a body that does not compile.
pub(crate) fn build_kernel_filter(
    cfg: &DaemonConfig,
    roa: &std::sync::Arc<lr_bgp::RoaStore>,
) -> Result<Option<KernelFilter>, String> {
    Ok(
        compile_named_filter(cfg, &cfg.kernel_export_filter, "kernel")?.map(|(name, compiled)| {
            KernelFilter {
                name,
                compiled,
                ctx: std::sync::Arc::new(DaemonFilterContext::new(std::sync::Arc::clone(roa))),
            }
        }),
    )
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
    log_error!(Component::Policy, "error: {msg}");
    ExitCode::from(2)
}

/// The compiled policy the daemon's BGP engine dispatches through —
/// the route-map half and the per-session filter-DSL half behind one
/// swap boundary.
///
/// The router's hook chain is append-only, but a configuration
/// reload must replace every route-map, named list and per-session
/// filter binding without restarting a single session. The daemon
/// therefore installs the two dispatch hooks
/// ([`LiveRouteMapDispatch`], [`LiveFilterDispatch`]) once at
/// startup; both read the *current* state through the shared
/// `Arc<RwLock<Arc<LivePolicyState>>>`, and a reload builds a fresh
/// state and swaps it under one write-lock acquisition. Import-side
/// evaluation order is unchanged from the static-hook shape:
/// route-maps first (the route-map dispatch hook), the router-wide
/// ROA validation hook in the middle, per-session filter DSL last
/// (the filter dispatch hook).
///
/// Route-map bindings are per *peer*, materialised on every session
/// handle the peer owns — the outbound session and the RFC 4271 §6.8
/// inbound challenger both run the neighbour's `import`/`export`
/// route-maps. (The static shape bound only the outbound handle, so
/// an inbound-landed session bypassed the route-map — the dispatch
/// closes that gap and matches the filter-DSL binding shape.)
#[derive(Clone)]
pub(crate) struct LivePolicyState {
    /// Route-map + named-list dispatch (the `PolicySet::hooks()`
    /// shape: per-session route-map bindings and the list banks).
    route_maps: lr_policy::set::PolicyHooks,
    /// Per-session compiled import filters, keyed by session handle.
    import_filters: std::collections::BTreeMap<u64, NamedCompiledFilter>,
    /// Per-session compiled export filters, keyed by session handle.
    export_filters: std::collections::BTreeMap<u64, NamedCompiledFilter>,
    /// Evaluation-latency histograms by (direction, filter name),
    /// carried across reloads so a re-built filter keeps its series
    /// instead of registering a duplicate one.
    stats:
        std::collections::BTreeMap<(u8, String), std::sync::Arc<crate::metrics::DurationHistogram>>,
}

/// One compiled `[[filter]]` body plus the histogram its evaluations
/// record into (when the metrics endpoint is enabled).
#[derive(Clone)]
pub(crate) struct NamedCompiledFilter {
    pub compiled: lr_policy::filter::bytecode::CompiledFilter,
    pub stats: Option<std::sync::Arc<crate::metrics::DurationHistogram>>,
}

/// The shared, swap-on-reload holder the dispatch hooks read through.
pub(crate) type SharedPolicyState =
    std::sync::Arc<std::sync::RwLock<std::sync::Arc<LivePolicyState>>>;

impl LivePolicyState {
    /// Look up one named route-map (network origination,
    /// `[[bgp.network_route_map]]` lookups).
    pub(crate) fn route_map(&self, name: &str) -> Option<lr_policy::route_map::RouteMap> {
        self.route_maps.route_map(name).cloned()
    }

    /// Swap this state in as the dispatch source.
    pub(crate) fn install(self, shared: &SharedPolicyState) {
        *shared.write().unwrap() = std::sync::Arc::new(self);
    }
}

/// Take (or reuse) the evaluation-latency histogram for one
/// (direction, filter name) pair, registering a fresh series against
/// the metrics registry when the name is new.
fn take_histogram(
    stats: &mut std::collections::BTreeMap<
        (u8, String),
        std::sync::Arc<crate::metrics::DurationHistogram>,
    >,
    metrics: Option<&std::sync::Arc<crate::metrics::FilterMetricsRegistry>>,
    direction: u8,
    name: &str,
) -> Option<std::sync::Arc<crate::metrics::DurationHistogram>> {
    let metrics = metrics?;
    let key = (direction, name.to_string());
    if let Some(h) = stats.get(&key) {
        return Some(std::sync::Arc::clone(h));
    }
    let h = metrics.register(
        if direction == 0 {
            crate::metrics::FilterDirection::Import
        } else {
            crate::metrics::FilterDirection::Export
        },
        name,
    );
    stats.insert(key, std::sync::Arc::clone(&h));
    Some(h)
}

/// Build the full live policy from a configuration: the route-map
/// half (`build_policy_set` + per-peer bindings) and the per-session
/// filter-DSL half, plus the stats map.
///
/// `session_of_peer` maps a config peer index to the session handles
/// the live router holds for it — the outbound handle and the
/// optional §6.8 challenger — so bindings land on every session the
/// peer owns even after a reload replaced some of them. `None`
/// (unknown peer index, e.g. a removed peer) skips the binding.
///
/// `prior` is the state being replaced (startup passes `None`): its
/// stats map carries over so a filter that survives the reload keeps
/// its histogram series.
pub(crate) fn build_live_policy_state(
    cfg: &DaemonConfig,
    metrics: Option<&std::sync::Arc<crate::metrics::FilterMetricsRegistry>>,
    prior: Option<&LivePolicyState>,
    session_of_peer: impl Fn(usize) -> Option<(u64, Option<u64>)>,
) -> Result<LivePolicyState, String> {
    // ---- Route-map half ----
    let mut set = build_policy_set(cfg)?;
    for (idx, peer) in cfg.peers.iter().enumerate() {
        let Some((out_handle, in_handle)) = session_of_peer(idx) else {
            continue;
        };
        // Both handles carry the neighbour's route-maps: a
        // bidirectional peer's inbound challenger session imports and
        // exports the same policy as its outbound transport.
        for handle in core::iter::once(out_handle).chain(in_handle) {
            if let Some(name) = &peer.import {
                if set.route_map(name).is_none() {
                    return Err(format!(
                        "peer {}: unknown route-map '{}'",
                        peer.label(),
                        name
                    ));
                }
                set.bind_import(handle, name.clone());
            }
            if let Some(name) = &peer.export {
                if set.route_map(name).is_none() {
                    return Err(format!(
                        "peer {}: unknown route-map '{}'",
                        peer.label(),
                        name
                    ));
                }
                set.bind_export(handle, name.clone());
            }
        }
    }
    if let Err((session, direction, name)) = set.validate() {
        return Err(format!(
            "session #{session}: {} binding references unknown route-map '{name}'",
            direction
        ));
    }
    let route_maps = set.hooks();

    // ---- Filter-DSL half ----
    let filters = build_filters(cfg)?;
    let by_name: std::collections::BTreeMap<&str, &DslFilter> =
        filters.iter().map(|(n, f)| (n.as_str(), f)).collect();
    let mut stats = prior.map(|p| p.stats.clone()).unwrap_or_default();
    let mut import_filters = std::collections::BTreeMap::new();
    let mut export_filters = std::collections::BTreeMap::new();
    for (idx, peer) in cfg.peers.iter().enumerate() {
        let Some((out_handle, in_handle)) = session_of_peer(idx) else {
            continue;
        };
        let handles: Vec<u64> = core::iter::once(out_handle).chain(in_handle).collect();
        if let Some(name) = &peer.import_filter {
            let Some(f) = by_name.get(name.as_str()) else {
                return Err(format!("peer {}: unknown filter '{name}'", peer.label()));
            };
            let compiled = lr_policy::filter::bytecode::compile(f);
            for handle in &handles {
                import_filters.insert(
                    *handle,
                    NamedCompiledFilter {
                        compiled: compiled.clone(),
                        stats: take_histogram(&mut stats, metrics, 0, name),
                    },
                );
            }
        }
        if let Some(name) = &peer.export_filter {
            let Some(f) = by_name.get(name.as_str()) else {
                return Err(format!("peer {}: unknown filter '{name}'", peer.label()));
            };
            let compiled = lr_policy::filter::bytecode::compile(f);
            for handle in &handles {
                export_filters.insert(
                    *handle,
                    NamedCompiledFilter {
                        compiled: compiled.clone(),
                        stats: take_histogram(&mut stats, metrics, 1, name),
                    },
                );
            }
        }
    }
    Ok(LivePolicyState {
        route_maps,
        import_filters,
        export_filters,
        stats,
    })
}

/// The empty state a policy-free daemon dispatches through.
impl Default for LivePolicyState {
    fn default() -> Self {
        Self {
            route_maps: PolicySet::new().hooks(),
            import_filters: std::collections::BTreeMap::new(),
            export_filters: std::collections::BTreeMap::new(),
            stats: std::collections::BTreeMap::new(),
        }
    }
}

/// The route-map dispatch hook: per-session route-map bindings and
/// the named-list banks, read through the swap boundary. Installed
/// once (before the ROA hook, matching the static chain order); a
/// reload swaps the state it reads.
#[derive(Clone)]
pub(crate) struct LiveRouteMapDispatch {
    shared: SharedPolicyState,
}

impl LiveRouteMapDispatch {
    pub(crate) fn new(shared: SharedPolicyState) -> Self {
        Self { shared }
    }
}

impl lr_policy::hooks::ImportHook for LiveRouteMapDispatch {
    fn name(&self) -> &str {
        "live-route-maps"
    }
    fn on_import(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        self.shared.read().unwrap().route_maps.on_import(route)
    }
}

impl lr_policy::hooks::ExportHook for LiveRouteMapDispatch {
    fn name(&self) -> &str {
        "live-route-maps"
    }
    fn on_export(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        self.shared.read().unwrap().route_maps.on_export(route)
    }
    fn on_export_to(
        &self,
        route: &mut lr_core::rib::Route,
        destination: u64,
    ) -> lr_policy::hooks::HookVerdict {
        self.shared
            .read()
            .unwrap()
            .route_maps
            .on_export_to(route, destination)
    }
}

impl lr_policy::action::MatchResolver for LiveRouteMapDispatch {
    fn prefix_in(&self, list_id: u32, p: &Prefix) -> bool {
        self.shared.read().unwrap().route_maps.prefix_in(list_id, p)
    }
    fn as_path_in(&self, list_id: u32, route: &lr_core::rib::Route) -> bool {
        self.shared
            .read()
            .unwrap()
            .route_maps
            .as_path_in(list_id, route)
    }
    fn community_in(&self, list_id: u32, route: &lr_core::rib::Route) -> bool {
        self.shared
            .read()
            .unwrap()
            .route_maps
            .community_in(list_id, route)
    }
    fn next_hop_in(&self, list_id: u32, route: &lr_core::rib::Route) -> bool {
        self.shared
            .read()
            .unwrap()
            .route_maps
            .next_hop_in(list_id, route)
    }
}

/// The per-session filter-DSL dispatch hook. Installed once (after
/// the ROA hook, matching the static chain order); a reload swaps the
/// state it reads. Sessions without a binding pass through — a filter
/// on one neighbour must never become an implicit global filter.
#[derive(Clone)]
pub(crate) struct LiveFilterDispatch {
    shared: SharedPolicyState,
    ctx: std::sync::Arc<DaemonFilterContext>,
}

impl LiveFilterDispatch {
    pub(crate) fn new(shared: SharedPolicyState, ctx: std::sync::Arc<DaemonFilterContext>) -> Self {
        Self { shared, ctx }
    }

    fn evaluate(
        &self,
        f: &NamedCompiledFilter,
        route: &mut lr_core::rib::Route,
    ) -> lr_policy::hooks::HookVerdict {
        match &f.stats {
            Some(hist) => {
                let t0 = std::time::Instant::now();
                let verdict =
                    lr_policy::filter::bytecode::execute(&f.compiled, route, self.ctx.as_ref());
                hist.record(t0.elapsed().as_nanos() as u64);
                map_verdict(verdict)
            }
            None => map_verdict(lr_policy::filter::bytecode::execute(
                &f.compiled,
                route,
                self.ctx.as_ref(),
            )),
        }
    }
}

impl lr_policy::hooks::ImportHook for LiveFilterDispatch {
    fn name(&self) -> &str {
        "live-filters-import"
    }
    fn on_import(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        let state = std::sync::Arc::clone(&self.shared.read().unwrap());
        let Some(f) = state.import_filters.get(&route.origin.peer) else {
            return lr_policy::hooks::HookVerdict::Keep;
        };
        self.evaluate(f, route)
    }
}

impl lr_policy::hooks::ExportHook for LiveFilterDispatch {
    fn name(&self) -> &str {
        "live-filters-export"
    }
    fn on_export(&self, route: &mut lr_core::rib::Route) -> lr_policy::hooks::HookVerdict {
        // The destination-agnostic entry point cannot know which peer
        // this route is headed to. Every binding this dispatch holds
        // is per-session, so the route passes through here and is
        // evaluated by `on_export_to` with the real destination.
        let _ = route;
        lr_policy::hooks::HookVerdict::Keep
    }
    fn on_export_to(
        &self,
        route: &mut lr_core::rib::Route,
        destination: u64,
    ) -> lr_policy::hooks::HookVerdict {
        let state = std::sync::Arc::clone(&self.shared.read().unwrap());
        let Some(f) = state.export_filters.get(&destination) else {
            return lr_policy::hooks::HookVerdict::Keep;
        };
        self.evaluate(f, route)
    }
}

#[cfg(test)]
#[path = "daemon_policy_tests.rs"]
mod tests;
