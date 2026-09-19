//! `lr-daemon config check <file>` — validate a configuration file and
//! report what it resolves to, without starting the daemon
//! (ROADMAP-v3 D16 Phase 1, GitHub #18). `lr-daemon config to-dsl
//! <file>` — the D16 Phase 2 TOML→DSL converter — lives here too: both
//! subcommands share the same load entry, usage conventions and exit
//! codes.
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
    // Dispatch shape: `lr-daemon config <check|to-dsl> [options]
    // <file>` — `args[0]` is the subcommand word itself.
    match args.first().map(String::as_str) {
        Some("check") => config_check_cmd(&args[1..]),
        Some("to-dsl") => config_to_dsl(&args[1..]),
        _ => {
            eprintln!("error: unknown config subcommand (expected 'check' or 'to-dsl')");
            eprintln!("usage: lr-daemon config check [--dialect lr|toml|bird|frr] <config-file>");
            eprintln!("       lr-daemon config to-dsl [--dialect lr|toml|bird|frr] <config-file>");
            ExitCode::from(2)
        }
    }
}

/// `lr-daemon config check [options] <file>`.
fn config_check_cmd(args: &[String]) -> ExitCode {
    // The outer dispatch already consumed the `check` word.
    let mut path: Option<&str> = None;
    let mut forced: Option<Dialect> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--dialect" || a == "--config-dialect" {
            if i + 1 >= args.len() {
                eprintln!("config check: {a} needs a value (lr | toml | bird | frr)");
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
            eprintln!("usage: lr-daemon config check [--dialect lr|toml|bird|frr] <config-file>");
            return ExitCode::from(2);
        } else if path.is_some() {
            eprintln!("config check: unexpected extra argument '{a}'");
            eprintln!("usage: lr-daemon config check [--dialect lr|toml|bird|frr] <config-file>");
            return ExitCode::from(2);
        } else {
            path = Some(a);
            i += 1;
        }
    }
    let Some(path) = path else {
        eprintln!("usage: lr-daemon config check [--dialect lr|toml|bird|frr] <config-file>");
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

/// `lr-daemon config to-dsl [--dialect lr|toml|bird|frr] <file>` —
/// print the config as an equivalent `.lr` program (ROADMAP-v3 D16
/// Phase 2). Loads through the same entry as startup and `check`, so
/// anything the daemon accepts converts; conversion is deterministic
/// and refuses input it cannot represent faithfully (parse warnings,
/// filter descriptions), never silently dropping semantics. Works on
/// the pre-finalize IR: finalization merges peer templates and would
/// destroy source-level structure.
fn config_to_dsl(args: &[String]) -> ExitCode {
    let mut path: Option<&str> = None;
    let mut forced: Option<Dialect> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--dialect" || a == "--config-dialect" {
            if i + 1 >= args.len() {
                eprintln!("config to-dsl: {a} needs a value (lr | toml | bird | frr)");
                return ExitCode::from(2);
            }
            match Dialect::from_flag(&args[i + 1]) {
                Ok(d) => forced = Some(d),
                Err(e) => {
                    eprintln!("config to-dsl: {e}");
                    return ExitCode::from(2);
                }
            }
            i += 2;
        } else if a.starts_with('-') && a != "-" {
            eprintln!("config to-dsl: unknown option '{a}'");
            eprintln!("usage: lr-daemon config to-dsl [--dialect lr|toml|bird|frr] <config-file>");
            return ExitCode::from(2);
        } else if path.is_some() {
            eprintln!("config to-dsl: unexpected extra argument '{a}'");
            eprintln!("usage: lr-daemon config to-dsl [--dialect lr|toml|bird|frr] <config-file>");
            return ExitCode::from(2);
        } else {
            path = Some(a);
            i += 1;
        }
    }
    let Some(path) = path else {
        eprintln!("usage: lr-daemon config to-dsl [--dialect lr|toml|bird|frr] <config-file>");
        return ExitCode::from(2);
    };

    let mut cfg = DaemonConfig::default();
    if let Err(e) = load_config_file(path, forced, &mut cfg) {
        eprintln!("config to-dsl: {path}: {e}");
        return ExitCode::from(1);
    }
    match crate::config_dsl::to_dsl(&cfg) {
        Ok(dsl) => {
            print!("{dsl}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("config to-dsl: {path}: {e}");
            ExitCode::from(1)
        }
    }
}
