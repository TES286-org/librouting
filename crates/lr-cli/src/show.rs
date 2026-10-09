//! `show <subsystem>` command family — the BIRD-style operational
//! visibility surface (issue #52).
//!
//! The runtime API's legacy commands (`status`, `sessions`, `routes`)
//! stay where they are; this module adds a parallel `show …` family
//! that mirrors the BIRD console's `show status` / `show protocols` /
//! `show route count` shape, so an operator's BIRD muscle memory
//! transfers.
//!
//! The dispatch is shared by the Unix and Windows `serve_connection`
//! implementations (both construct a [`ShowCtx`] from their own
//! `ConnDeps` and call [`dispatch`]). The renderer is platform-
//! independent: it walks the router under the same `RwLock` the
//! legacy commands hold, for the same short scope.
//!
//! # Wire shape
//!
//! ```text
//! show status               daemon summary (extended: per-protocol
//!                           session counts, route counts, memory)
//! show sessions             one line per session (same shape as
//!                           the legacy `sessions` command, plus the
//!                           new `transitions=` / `uptime-ms=` /
//!                           `last-error=` fields)
//! show sessions detail      multi-line per-session block (BIRD style)
//! show session <handle>     deep dive for one session
//! show routes count         Loc-RIB grouped by protocol
//! show memory               process RSS / virtual size
//! ```
//!
//! Each handler renders its full body into a `String` and returns it
//! (the caller adds a trailing newline if the body does not end with
//! one). An unknown `show <sub>` returns `None` so the caller can fall
//! back to the unknown-command reply.

use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

use lr_router::{DefaultRouter, RouterInstance, SessionSummary};

use crate::api::DaemonInfo;

/// Borrowed view of the daemon state the `show` family needs. Built
/// cheaply from either platform's `ConnDeps` per command.
pub struct ShowCtx<'a> {
    pub info: &'a DaemonInfo,
    pub router: &'a Arc<RwLock<DefaultRouter>>,
    pub status_lines: &'a Arc<dyn Fn() -> Vec<String> + Send + Sync>,
    pub started: std::time::Instant,
}

/// Try to handle a `show …` command. `rest` is the full command
/// line (e.g. `show status`, `show session 1`). Returns `Some(body)`
/// when the command matched — the body is the full reply, including
/// any trailing newline. Returns `None` when `rest` is not a `show`
/// command, so the caller can dispatch it through the legacy match.
pub fn dispatch(rest: &str, ctx: &ShowCtx<'_>) -> Option<String> {
    let sub = rest.strip_prefix("show ")?.trim();
    let body = match sub {
        "" | "status" => render_show_status(ctx),
        "sessions" => render_show_sessions(ctx, false),
        "sessions detail" => render_show_sessions(ctx, true),
        "memory" => render_show_memory(ctx),
        "routes count" => render_show_routes_count(ctx),
        _ if sub.starts_with("session ") => {
            let handle_str = sub["session ".len()..].trim();
            match handle_str.parse::<u64>() {
                Ok(handle) => render_show_session(ctx, handle),
                Err(_) => format!("error: invalid session handle '{handle_str}'"),
            }
        }
        other => format!("error: unknown show sub-command '{other}'"),
    };
    let mut out = body;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Some(out)
}

/// `show status` — extended version of the legacy `status` command.
/// Adds per-protocol session breakdown (BIRD `show protocols` summary
/// shape) and the daemon's resident memory.
fn render_show_status(ctx: &ShowCtx<'_>) -> String {
    let (summaries, rib_len) = {
        let r = ctx.router.read().unwrap();
        (r.session_summaries(), r.rib_len())
    };
    let sessions = summaries.len() as u64;
    let established = summaries.iter().filter(|s| s.established).count() as u64;
    let mut by_kind: std::collections::BTreeMap<&'static str, (u64, u64)> =
        std::collections::BTreeMap::new();
    for s in &summaries {
        let e = s.established as u64;
        by_kind
            .entry(s.kind)
            .and_modify(|(n, e_)| {
                *n += 1;
                *e_ += e;
            })
            .or_insert((1, e));
    }
    let mem = process_memory();

    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "version {}", ctx.info.version);
    let _ = writeln!(out, "local-as {}", ctx.info.local_as);
    let _ = writeln!(out, "peer-as {}", ctx.info.peer_as);
    let _ = writeln!(out, "router-id {}", ctx.info.router_id);
    let _ = writeln!(
        out,
        "config {}",
        ctx.info.config_path.as_deref().unwrap_or("(none)")
    );
    let _ = writeln!(out, "uptime-secs {}", ctx.started.elapsed().as_secs());
    let _ = writeln!(out, "sessions {} established {}", sessions, established);
    let _ = writeln!(out, "rib-entries {}", rib_len);
    for (kind, (n, e)) in &by_kind {
        let _ = writeln!(out, "  kind={} total={} established={}", kind, n, e);
    }
    let _ = writeln!(
        out,
        "memory rss-bytes={} vsize-bytes={}",
        fmt_bytes(mem.rss_bytes),
        fmt_bytes(mem.vsize_bytes)
    );
    for line in (ctx.status_lines)() {
        let _ = writeln!(out, "{line}");
    }
    out
}

/// `show sessions [detail]` — one-line summary per session, plus an
/// optional multi-line deep dive when `detail` is set. The one-line
/// shape extends the legacy `sessions` command with the new
/// `transitions=` / `uptime-ms=` / `last-error=` / `last-error-at-ms=`
/// fields (issue #52).
fn render_show_sessions(ctx: &ShowCtx<'_>, detail: bool) -> String {
    let summaries = ctx.router.read().unwrap().session_summaries();
    let mut out = String::with_capacity(summaries.len() * 128);
    for s in &summaries {
        let _ = writeln!(
            out,
            "#{handle} kind={kind} local-as={la} peer-as={pa} \
             state={state} established={est} peer-id={id} \
             hold-time={hold} adj-rib-in={ar} \
             updates-rx={urx} updates-tx={utx} \
             transitions={tr} uptime-ms={up} \
             last-error={err} last-error-at-ms={err_at}",
            handle = s.handle.0,
            kind = s.kind,
            la = s.local_as.0,
            pa = s.peer_as.0,
            state = s.state,
            est = s.established,
            id = s
                .peer_bgp_id
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".into()),
            hold = s.negotiated_hold_time,
            ar = s.adj_rib_in_len,
            urx = s.updates_received,
            utx = s.updates_sent,
            tr = s.stats.state_transitions,
            up = s.stats.established_at_ms,
            err = s.stats.last_error.as_str(),
            err_at = s.stats.last_error_at_ms,
        );
        if detail {
            render_session_detail(&mut out, s);
        }
    }
    out
}

/// `show session <handle>` — deep dive for one session. Returns an
/// error line when the handle does not match a configured session.
fn render_show_session(ctx: &ShowCtx<'_>, handle: u64) -> String {
    let summaries = ctx.router.read().unwrap().session_summaries();
    let Some(s) = summaries.iter().find(|s| s.handle.0 == handle) else {
        return format!("error: no session with handle {handle}");
    };
    let mut out = String::with_capacity(384);
    let _ = writeln!(out, "handle {}", s.handle.0);
    let _ = writeln!(out, "kind {}", s.kind);
    let _ = writeln!(out, "local-as {}", s.local_as.0);
    let _ = writeln!(out, "peer-as {}", s.peer_as.0);
    let _ = writeln!(out, "state {}", s.state);
    let _ = writeln!(out, "established {}", s.established);
    if let Some(id) = s.peer_bgp_id {
        let _ = writeln!(out, "peer-bgp-id {}", id);
    }
    let _ = writeln!(out, "negotiated-hold-time {}", s.negotiated_hold_time);
    let _ = writeln!(out, "adj-rib-in {}", s.adj_rib_in_len);
    let _ = writeln!(out, "updates-received {}", s.updates_received);
    let _ = writeln!(out, "updates-sent {}", s.updates_sent);
    render_session_detail(&mut out, s);
    out
}

/// `show routes count` — Loc-RIB size grouped by `Route::protocol`.
/// Mirrors BIRD `show route count` and FRR `show ip route summary`.
fn render_show_routes_count(ctx: &ShowCtx<'_>) -> String {
    let r = ctx.router.read().unwrap();
    let mut by_proto: std::collections::BTreeMap<&'static str, u64> =
        std::collections::BTreeMap::new();
    let mut total = 0u64;
    for route in r.rib_paths_snapshot() {
        let name = route.protocol.bird_name();
        *by_proto.entry(name).or_insert(0) += 1;
        total += 1;
    }
    let mut out = String::with_capacity(128);
    let _ = writeln!(out, "total {}", total);
    for (proto, n) in &by_proto {
        let _ = writeln!(out, "  proto={} routes={}", proto, n);
    }
    out
}

/// `show memory` — process RSS and virtual size. Returns "unknown"
/// on platforms without a discoverable value (matches BIRD's
/// `show memory` "not available" stance).
fn render_show_memory(ctx: &ShowCtx<'_>) -> String {
    let mem = process_memory();
    let mut out = String::with_capacity(96);
    let _ = writeln!(out, "uptime-secs {}", ctx.started.elapsed().as_secs());
    let _ = writeln!(out, "rss-bytes {}", fmt_bytes(mem.rss_bytes));
    let _ = writeln!(out, "vsize-bytes {}", fmt_bytes(mem.vsize_bytes));
    out
}

/// Multi-line detail block appended under a session line in `show
/// sessions detail` and rendered standalone in `show session <h>`.
fn render_session_detail(out: &mut String, s: &SessionSummary) {
    let _ = writeln!(
        out,
        "  stats: established-at-ms={} last-transition-at-ms={} \
         state-transitions={}",
        s.stats.established_at_ms, s.stats.last_transition_at_ms, s.stats.state_transitions,
    );
    let _ = writeln!(
        out,
        "  last-error: kind={} at-ms={}",
        s.stats.last_error.as_str(),
        s.stats.last_error_at_ms,
    );
}

/// Process memory snapshot. On Linux, reads `/proc/self/status` for
/// `VmRSS` and `VmSize` (the same fields `top` and `ps` report). On
/// other platforms, both fields are `None` — BIRD's `show memory` does
/// the same on platforms without a discoverable value.
struct ProcessMemory {
    rss_bytes: Option<u64>,
    vsize_bytes: Option<u64>,
}

impl ProcessMemory {
    fn unknown() -> Self {
        Self {
            rss_bytes: None,
            vsize_bytes: None,
        }
    }
}

fn process_memory() -> ProcessMemory {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/self/status") {
            let mut rss_kb: Option<u64> = None;
            let mut vsize_kb: Option<u64> = None;
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    rss_kb = parse_kb(rest);
                } else if let Some(rest) = line.strip_prefix("VmSize:") {
                    vsize_kb = parse_kb(rest);
                }
                if rss_kb.is_some() && vsize_kb.is_some() {
                    break;
                }
            }
            return ProcessMemory {
                rss_bytes: rss_kb.map(|kb| kb * 1024),
                vsize_bytes: vsize_kb.map(|kb| kb * 1024),
            };
        }
        ProcessMemory::unknown()
    }
    #[cfg(not(target_os = "linux"))]
    {
        ProcessMemory::unknown()
    }
}

/// Format a memory byte count: `None` → the string `unknown` (BIRD
/// parity for "no value available"); `Some(n)` → the integer.
fn fmt_bytes(value: Option<u64>) -> String {
    match value {
        Some(n) => n.to_string(),
        None => "unknown".to_string(),
    }
}

/// Parse the `VmRSS:\t   1234 kB` form out of `/proc/self/status`.
/// Returns `None` when the field does not parse as a number (the
/// kernel format is stable, but defensive parsing is cheap).
fn parse_kb(rest: &str) -> Option<u64> {
    rest.split_whitespace().next()?.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::DaemonInfo;
    use lr_core::addr::Asn;
    use lr_router::{DefaultRouter, SessionConfig};
    use std::sync::{Arc, RwLock};

    /// Build a `ShowCtx` from a stack-allocated status-lines closure.
    /// The closure is wrapped in an `Arc` so the `ShowCtx` borrows a
    /// real `Arc<dyn Fn()…>` like the daemon's runtime API thread.
    fn ctx<'a>(
        router: &'a Arc<RwLock<DefaultRouter>>,
        info: &'a DaemonInfo,
        status_lines: &'a Arc<dyn Fn() -> Vec<String> + Send + Sync>,
        started: std::time::Instant,
    ) -> ShowCtx<'a> {
        ShowCtx {
            info,
            router,
            status_lines,
            started,
        }
    }

    fn make_router_with_session() -> Arc<RwLock<DefaultRouter>> {
        let router = Arc::new(RwLock::new(DefaultRouter::new()));
        {
            let mut r = router.write().unwrap();
            r.add_session(SessionConfig::bgp(
                Asn(64512),
                Asn(64513),
                lr_core::addr::RouterId::from_v4([10, 0, 0, 1]),
            ))
            .unwrap();
            r.originate(
                lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
                Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
            );
        }
        router
    }

    #[test]
    fn dispatch_returns_none_for_non_show_command() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        assert!(dispatch("status", &cx).is_none());
        assert!(dispatch("sessions", &cx).is_none());
        assert!(dispatch("routes", &cx).is_none());
        assert!(dispatch("shutdown", &cx).is_none());
    }

    #[test]
    fn show_status_renders_extended_fields() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        let body = dispatch("show status", &cx).expect("show status matched");
        assert!(body.contains("version test"), "body: {body}");
        assert!(body.contains("sessions 1 established 0"), "body: {body}");
        assert!(body.contains("rib-entries 1"), "body: {body}");
        assert!(
            body.contains("kind=bgp total=1 established=0"),
            "body: {body}"
        );
        assert!(body.contains("memory rss-bytes="), "body: {body}");
    }

    #[test]
    fn show_sessions_extends_legacy_output() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        let body = dispatch("show sessions", &cx).expect("show sessions matched");
        // Legacy fields preserved.
        assert!(body.contains("kind=bgp"), "body: {body}");
        assert!(body.contains("local-as=64512"), "body: {body}");
        assert!(body.contains("peer-as=64513"), "body: {body}");
        // New issue #52 fields present.
        assert!(body.contains("transitions="), "body: {body}");
        assert!(body.contains("uptime-ms="), "body: {body}");
        assert!(body.contains("last-error="), "body: {body}");
        assert!(body.contains("last-error-at-ms="), "body: {body}");
    }

    #[test]
    fn show_sessions_detail_appends_stats_block() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        let body = dispatch("show sessions detail", &cx).expect("show sessions detail matched");
        assert!(body.contains("stats: established-at-ms="), "body: {body}");
        assert!(body.contains("last-error: kind="), "body: {body}");
    }

    #[test]
    fn show_session_handle_renders_deep_dive() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        let body = dispatch("show session 1", &cx).expect("show session matched");
        assert!(body.contains("handle 1"), "body: {body}");
        assert!(body.contains("kind bgp"), "body: {body}");
        assert!(body.contains("negotiated-hold-time"), "body: {body}");
        assert!(body.contains("stats: established-at-ms="), "body: {body}");
    }

    #[test]
    fn show_session_unknown_handle_reports_error() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        let body = dispatch("show session 999", &cx).expect("show session matched");
        assert!(
            body.contains("error: no session with handle 999"),
            "body: {body}"
        );
    }

    #[test]
    fn show_routes_count_groups_by_protocol() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        let body = dispatch("show routes count", &cx).expect("show routes count matched");
        // The originated route is local — its `protocol` field is
        // whatever `Route::protocol` the router assigns to originated
        // routes; the count surface is what we are testing here, not
        // the protocol mapping.
        assert!(body.contains("total 1"), "body: {body}");
        assert!(body.contains("proto="), "body: {body}");
    }

    #[test]
    fn show_memory_renders_uptime_and_rss() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        let body = dispatch("show memory", &cx).expect("show memory matched");
        assert!(body.contains("uptime-secs "), "body: {body}");
        assert!(body.contains("rss-bytes "), "body: {body}");
        assert!(body.contains("vsize-bytes "), "body: {body}");
    }

    #[test]
    fn show_unknown_subcommand_returns_error() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        let body = dispatch("show bogus", &cx).expect("show bogus matched (as error)");
        assert!(
            body.contains("error: unknown show sub-command 'bogus'"),
            "body: {body}"
        );
    }

    #[test]
    fn show_session_non_numeric_handle_returns_error() {
        let router = make_router_with_session();
        let info = DaemonInfo {
            version: "test".into(),
            local_as: 64512,
            peer_as: 64513,
            router_id: "10.0.0.1".into(),
            config_path: None,
        };
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let cx = ctx(&router, &info, &status_lines, std::time::Instant::now());
        let body = dispatch("show session not-a-number", &cx).expect("show session matched");
        assert!(
            body.contains("error: invalid session handle"),
            "body: {body}"
        );
    }
}
