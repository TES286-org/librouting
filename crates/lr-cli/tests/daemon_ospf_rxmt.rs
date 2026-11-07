//! End-to-end coverage for the per-session OSPF `RxmtInterval` knob
//! (RFC 2328 Appendix B; BIRD `rxmtint`, FRR `retransmit-interval`).
//!
//! defects.txt `crates/lr-ospf/src/exchange.rs:L54` recorded that
//! `RXMT_INTERVAL_MS = 5_000` was hardcoded and not configurable from
//! the daemon. The prior `feat(ospf): DbExchange exposes per-neighbor
//! RxmtInterval` commit (`93f3406`) added the lower-level
//! `DbExchange::with_rxmt_interval` builder; this round wires the
//! knob through `SessionConfig::with_ospf_rxmt_interval`, the daemon
//! config schema (`[ospf] rxmt_interval`, `[[ospf.interface]]
//! rxmt_interval`), the CLI flag (`--ospf-rxmt-interval`, alias
//! `--ospf-retransmit-interval`), and the BIRD / FRR translation
//! (`retransmit N;` / `ip ospf retransmit-interval N`).
//!
//! These tests exercise the CLI surface end-to-end through the real
//! `lr-daemon` binary's `--help` output (no root required — the
//! daemon never starts a socket) and `config check` (also no socket
//! work — `config check` loads + finalizes the config and exits).
//! The per-session override path through the live OSPF runtime is
//! covered by the unit tests in `crates/lr-router/src/instance/tests.rs`
//! (`ospf_session_rxmt_interval_override_drives_retransmit_gap`,
//! `ospf_session_default_rxmt_interval_still_fires_at_5s`,
//! `ospf_session_with_rxmt_interval_clamps_zero_to_one_ms`).

#![cfg(unix)]

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

/// `lr-daemon --help` advertises the new `--ospf-rxmt-interval S` flag
/// and its `--ospf-retransmit-interval S` alias.
///
/// The CLI surface is the operator's first contact with the knob; if
/// `--help` does not list it, an operator scanning the help cannot
/// discover it without reading the docs. The help text also names
/// the RFC 2328 Appendix B `RxmtInterval` reference and the alias so
/// an operator familiar with BIRD `rxmtint` / FRR
/// `retransmit-interval` recognises the knob without cross-referencing
/// the docs.
#[test]
fn help_advertises_ospf_rxmt_interval_flag() {
    let out = Command::new(BIN)
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon --help");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        out.status.success(),
        "lr-daemon --help exited non-zero: {combined}"
    );
    assert!(
        combined.contains("--ospf-rxmt-interval"),
        "expected `--ospf-rxmt-interval` in --help output; got:\n{combined}"
    );
    assert!(
        combined.contains("--ospf-retransmit-interval") || combined.contains("alias --ospf-retransmit-interval"),
        "expected the `--ospf-retransmit-interval` alias to be mentioned in --help output; got:\n{combined}"
    );
}

/// `lr-daemon config check` reports the OSPF interface count, and a
/// config that names `rxmt_interval` parses cleanly through the same
/// load + finalize path startup uses. The `ospf: {} areas, {}
/// interfaces` line is the surface the operator sees at config-editing
/// time — the per-interface `rxmt_interval` value lands in the
/// `OspfIfSpec` struct but the report's per-interface detail is
/// limited to the count today; the daemon-config unit tests cover the
/// per-interface value (see `ospf_rxmt_interval_global_and_per_interface_parse`).
///
/// What this e2e test proves is that a config carrying the new key
/// does not break the `config check` exit code — a regression here
/// would mean the parser rejected the key or `finalize` tripped on
/// the new field.
#[test]
fn config_check_accepts_ospf_rxmt_interval_key() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-ospf-rxmt-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "[ospf]\nrxmt_interval = 8\n\n\
         [[ospf.interface]]\nname = \"lo\"\nrxmt_interval = 30\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "lr-daemon config check exited non-zero for a config with `rxmt_interval`; output:\n{combined}"
    );
    assert!(
        combined.contains("OK (dialect toml)"),
        "expected OK in config check output; got:\n{combined}"
    );
    assert!(
        combined.contains("ospf: 0 areas, 1 interfaces"),
        "expected `ospf: 0 areas, 1 interfaces` in config check output; got:\n{combined}"
    );
}

/// `lr-daemon config check` accepts the `retransmit_interval` alias
/// too — a config that came in through `lr translate frr` (which
/// preserves the FRR `retransmit-interval` keyword as
/// `retransmit_interval` so the source operator recognises the field
/// name) must load cleanly.
#[test]
fn config_check_accepts_ospf_retransmit_interval_alias() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-ospf-retransmit-alias-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "[ospf]\nretransmit_interval = 8\n\n\
         [[ospf.interface]]\nname = \"lo\"\nretransmit_interval = 30\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "lr-daemon config check exited non-zero for the alias `retransmit_interval`; output:\n{combined}"
    );
    assert!(
        combined.contains("OK (dialect toml)"),
        "expected OK in config check output for the alias; got:\n{combined}"
    );
}

/// `lr-daemon config check` rejects `[ospf] rxmt_interval = 0` at
/// parse time — the daemon would otherwise clamp 0 ms to 1 ms (the
/// `DbExchange::with_rxmt_interval` poll-loop busy-spin guard), but a
/// 0 in the operator's config is almost certainly a typo, so the
/// parser surfaces it before the daemon starts.
#[test]
fn config_check_rejects_ospf_rxmt_interval_zero() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-ospf-rxmt-zero-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(&path, "[ospf]\nrxmt_interval = 0\n").expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let _ = std::fs::remove_file(&path);
    assert!(
        !out.status.success(),
        "lr-daemon config check should exit non-zero for `rxmt_interval = 0`; output:\n{combined}"
    );
    assert!(
        combined.contains("rxmt_interval 0 is invalid"),
        "expected the 0-s rejection in the error; got:\n{combined}"
    );
}
