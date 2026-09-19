//! End-to-end tests for `lr-daemon config check <file>` (ROADMAP-v3
//! D16 Phase 1, GitHub #18).
//!
//! Each test runs the real `lr-daemon` binary as a subprocess and
//! asserts the exit code plus the stdout/stderr report. `config check`
//! never starts a daemon — it loads through the same
//! `load_config_file` + `finalize` path startup uses, so a passing
//! check is exactly "a daemon would accept this file".
//!
//! Coverage: a valid multi-section TOML (the full resolved report),
//! the shipped `templates/daemon.toml` golden file, a parse error, a
//! cross-section reference error that only `finalize` catches, the
//! BIRD compat dialect, dialect forcing, and the usage-error paths.

#![cfg(unix)]

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

/// Run `lr-daemon config check …`; return (exit_code, stdout, stderr).
fn check(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run lr-daemon config check");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Write `text` to a uniquely named temp file; return its path.
fn fixture(tag: &str, text: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("lr-config-check-{tag}-{}.toml", std::process::id()));
    std::fs::write(&path, text).expect("write fixture");
    path
}

#[test]
fn valid_config_reports_resolved_ir() {
    let path = fixture(
        "valid",
        "[bgp]\n\
         local_as = 64512\n\
         peer_as = 64513\n\
         router_id = \"10.0.0.1\"\n\
         peer_addr = \"192.0.2.2:179\"\n\
         networks = [\"203.0.113.0/24\"]\n\n\
         [[prefix-list]]\n\
         name = \"customer\"\n\
         prefix = \"203.0.113.0/24\"\n\n\
         [[route-map]]\n\
         name = \"to-customer\"\n\
         entry = 10\n\
         match_prefix = \"customer\"\n\
         permit = true\n",
    );
    let (code, stdout, stderr) = check(&["config", "check", path.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("OK (dialect toml)"), "stdout: {stdout}");
    assert!(stdout.contains("protocols: bgp"), "stdout: {stdout}");
    // The legacy single peer is synthesised at finalize.
    assert!(
        stdout.contains("peers: 1 (legacy single-peer, 0 templates)"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("networks: 1 originated, 0 labeled"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("1 route-maps, 1 prefix-lists"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("warnings: 0"), "stdout: {stdout}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn shipped_template_passes() {
    // The standing golden file: whatever the template documents must
    // stay checkable. CWD is the package root under `cargo test`.
    let template =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/daemon.toml");
    let (code, stdout, stderr) = check(&["config", "check", template.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("OK (dialect toml)"), "stdout: {stdout}");
    assert!(stdout.contains("warnings: 0"), "stdout: {stdout}");
}

#[test]
fn shipped_lr_template_passes() {
    // Phase 3's DSL-first twin: the native dialect the daemon prefers
    // must be checkable out of the box — content detection (no
    // --config-dialect flag) recognises the .lr block grammar.
    let template =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/daemon.lr");
    let (code, stdout, stderr) = check(&["config", "check", template.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("OK (dialect lr)"), "stdout: {stdout}");
    assert!(stdout.contains("protocols: bgp"), "stdout: {stdout}");
    assert!(
        stdout.contains("peers: 1 (legacy single-peer, 0 templates)"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("2 route-maps, 1 prefix-lists"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("warnings: 0"), "stdout: {stdout}");
}

#[test]
fn lr_dialect_forcing_still_works_on_filter_only_files() {
    // A file whose top-level statements are only `filter` blocks rides
    // BIRD's detection heuristic (`filter f { … }` is ambiguous with
    // BIRD), so an explicit `--dialect lr` must force the native
    // frontend — the documented flag contract from Phase 2.
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-lr-forced-{}.lr",
        std::process::id()
    ));
    std::fs::write(&path, "filter \"in\" {\n    accept;\n}\n").expect("write fixture");
    let (code, stdout, stderr) =
        check(&["config", "check", "--dialect", "lr", path.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("OK (dialect lr)"), "stdout: {stdout}");
    assert!(stdout.contains("warnings: 0"), "stdout: {stdout}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn parse_error_fails_with_position() {
    let path = fixture("parse-error", "[bgp]\nlocal_as = 64512\nthis is not toml\n");
    let (code, stdout, stderr) = check(&["config", "check", path.to_str().unwrap()]);
    assert_eq!(code, 1, "stdout: {stdout}");
    assert!(stderr.contains("config check:"), "stderr: {stderr}");
    assert!(stderr.contains("line 3"), "stderr: {stderr}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cross_section_reference_error_is_caught() {
    // Parses fine, fails finalize: the peer references a
    // peer-template that does not exist — exactly the class of error
    // that previously surfaced only at daemon start.
    let path = fixture(
        "cross-section",
        "[bgp]\n\
         local_as = 64512\n\
         peer_as = 64513\n\
         router_id = \"10.0.0.1\"\n\n\
         [[peer]]\n\
         remote = \"192.0.2.2:179\"\n\
         extends = \"missing-template\"\n",
    );
    let (code, _stdout, stderr) = check(&["config", "check", path.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("unknown peer-template 'missing-template'"),
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn bird_dialect_is_detected_and_reported() {
    let path = fixture(
        "bird",
        "router id 10.0.0.1;\n\
         protocol device {}\n",
    );
    let (code, stdout, stderr) = check(&["config", "check", path.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("OK (dialect bird)"), "stdout: {stdout}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn forced_dialect_overrides_detection() {
    let path = fixture("forced", "router id 10.0.0.1;\nprotocol device {}\n");
    // BIRD content forced through the TOML parser fails closed…
    let (code, _stdout, stderr) = check(&[
        "config",
        "check",
        "--dialect",
        "toml",
        path.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "stderr: {stderr}");
    // …and a bad dialect name is a usage error.
    let (code, _stdout, stderr) = check(&[
        "config",
        "check",
        "--dialect",
        "juniper",
        path.to_str().unwrap(),
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad --config-dialect"), "stderr: {stderr}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn usage_errors_exit_two() {
    // No file at all.
    let (code, _stdout, stderr) = check(&["config", "check"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage:"), "stderr: {stderr}");
    // Unknown subcommand word.
    let (code, _stdout, stderr) = check(&["config", "reformat", "x.toml"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("expected 'check'"), "stderr: {stderr}");
    // Unknown option.
    let (code, _stdout, stderr) = check(&["config", "check", "--json", "x.toml"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown option"), "stderr: {stderr}");
    // Extra positional argument.
    let (code, _stdout, stderr) = check(&["config", "check", "a.toml", "b.toml"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("unexpected extra argument"),
        "stderr: {stderr}"
    );
}

#[test]
fn missing_file_fails_cleanly() {
    let (code, _stdout, stderr) = check(&["config", "check", "/nonexistent/lr-test.toml"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("cannot read config /nonexistent/lr-test.toml"),
        "stderr: {stderr}"
    );
}
