//! `lr-daemon config check <file>` — validate a configuration file and
//! report what it resolves to, without starting the daemon
//! (ROADMAP-v3 D16 Phase 1, GitHub #18).
//!
//! The checker loads through [`crate::daemon_config::load_config_file`]
//! — the same entry point startup and reload use — and then runs
//! [`DaemonConfig::finalize`], so "check passes" is exactly "a daemon
//! would accept this file": template inheritance, cross-section name
//! references (route-map → prefix-list, peer → filter), RPKI intervals
//! and every other `finalize` invariant are exercised here at
//! config-editing time instead of at boot.
//!
//! This also pins the IR-equality property the DSL migration relies
//! on: whatever frontend produced the file (the TOML subset today, the
//! native DSL from Phase 2 on), the resulting [`DaemonConfig`] is the
//! single typed IR the rest of the daemon consumes.

use std::process::ExitCode;

use crate::compat::Dialect;
use crate::daemon_config::{load_config_file, DaemonConfig};

pub(super) fn config_check(args: &[String]) -> ExitCode {
    // Dispatch shape: `lr-daemon config check [options] <file>` —
    // `args[0]` is the `check` subcommand word itself.
    if args.is_empty() || args[0] != "check" {
        eprintln!("error: unknown config subcommand (expected 'check')");
        eprintln!("usage: lr-daemon config check [--dialect bird|frr|toml] <config-file>");
        return ExitCode::from(2);
    }
    let args = &args[1..];
    let mut path: Option<&str> = None;
    let mut forced: Option<Dialect> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--dialect" || a == "--config-dialect" {
            if i + 1 >= args.len() {
                eprintln!("config check: {a} needs a value (bird | frr | toml)");
                return ExitCode::from(2);
            }
            match Dialect::from_flag(&args[i + 1]) {
                Ok(d) => forced = Some(d),
                Err(e) => {
                    eprintln!("config check: {e}");
                    return ExitCode::from(2);
                }
            }
            i += 2;
        } else if a.starts_with('-') && a != "-" {
            eprintln!("config check: unknown option '{a}'");
            eprintln!("usage: lr-daemon config check [--dialect bird|frr|toml] <config-file>");
            return ExitCode::from(2);
        } else if path.is_some() {
            eprintln!("config check: unexpected extra argument '{a}'");
            eprintln!("usage: lr-daemon config check [--dialect bird|frr|toml] <config-file>");
            return ExitCode::from(2);
        } else {
            path = Some(a);
            i += 1;
        }
    }
    let Some(path) = path else {
        eprintln!("usage: lr-daemon config check [--dialect bird|frr|toml] <config-file>");
        return ExitCode::from(2);
    };

    let mut cfg = DaemonConfig::default();
    if let Err(e) = load_config_file(path, forced, &mut cfg) {
        eprintln!("config check: {path}: {e}");
        return ExitCode::from(1);
    }
    // Finalize exactly like startup: merges peer templates, resolves
    // the cross-section references and validates every section's
    // invariants. A failure here would fail the daemon at boot.
    if let Err(e) = cfg.finalize() {
        eprintln!("config check: {path}: {e}");
        return ExitCode::from(1);
    }

    let dialect = cfg
        .config_dialect
        .clone()
        .unwrap_or_else(|| "toml".to_string());
    println!("config check: {path}: OK (dialect {dialect})");
    println!("  protocols: {}", cfg.protocol_set().join(","));
    if cfg.explicit_peers {
        println!(
            "  peers: {} explicit, {} templates",
            cfg.peers.len(),
            cfg.peer_templates.len()
        );
    } else {
        println!(
            "  peers: {} (legacy single-peer, 0 templates)",
            cfg.peers.len()
        );
    }
    println!(
        "  networks: {} originated, {} labeled",
        cfg.networks.len(),
        cfg.labeled_networks.len()
    );
    println!(
        "  policy: {} filters, {} route-maps, {} prefix-lists, {} as-path-lists, {} community-lists",
        cfg.filters.len(),
        cfg.route_maps.len(),
        cfg.prefix_lists.len(),
        cfg.as_path_lists.len(),
        cfg.community_lists.len()
    );
    println!(
        "  babel: {} interfaces, {} keys | ospf: {} areas, {} interfaces | roa: {} static entries | redistribute: {} pipes, {} aggregates",
        cfg.babel_interfaces.len(),
        cfg.babel_keys.len(),
        cfg.ospf_areas.len(),
        cfg.ospf_interfaces.len(),
        cfg.roas.len(),
        cfg.redistributes.len(),
        cfg.aggregates.len()
    );
    if cfg.warnings.is_empty() {
        println!("  warnings: 0");
    } else {
        println!("  warnings: {}", cfg.warnings.len());
        for w in &cfg.warnings {
            println!("    warning: {w}");
        }
    }
    ExitCode::SUCCESS
}
