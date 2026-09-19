//! End-to-end tests for `lr-daemon config to-dsl <file>` (ROADMAP-v3
//! D16 Phase 2, GitHub #18).
//!
//! Each test runs the real `lr-daemon` binary as a subprocess and
//! asserts exit codes plus output. The converter loads through the
//! same `load_config_file` path as startup and `check`, renders the
//! pre-finalize IR deterministically, and refuses input it cannot
//! represent faithfully.
//!
//! Coverage: TOML → `.lr` conversion whose output passes `config
//! check` as the native dialect, byte-identical determinism across
//! runs, filter bodies with quotes surviving the round trip, the
//! shipped `templates/daemon.toml`, parse-warning refusal, and the
//! usage-error paths.

#![cfg(unix)]

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

/// Run `lr-daemon config to-dsl …`; return (exit_code, stdout, stderr).
fn to_dsl(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run lr-daemon config to-dsl");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

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

fn fixture(tag: &str, text: &str, ext: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "lr-config-to-dsl-{tag}-{}.{}",
        std::process::id(),
        ext
    ));
    std::fs::write(&path, text).expect("write fixture");
    path
}

#[test]
fn converts_toml_and_the_output_checks_as_lr() {
    let path = fixture(
        "convert",
        "[bgp]\n\
         local_as = 64512\n\
         router_id = \"10.0.0.1\"\n\
         hold_time = 45\n\
         networks = [\"203.0.113.0/24\"]\n\
         \n\
         [[peer]]\n\
         name = \"core-1\"\n\
         remote = \"192.0.2.2:179\"\n\
         peer_as = 65010\n\
         \n\
         [[prefix-list]]\n\
         name = \"customer\"\n\
         prefix = \"203.0.113.0/24\"\n",
        "toml",
    );
    let (code, stdout, stderr) = to_dsl(&["config", "to-dsl", path.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("bgp {"), "{stdout}");
    assert!(stdout.contains("local_as 64512;"), "{stdout}");
    assert!(stdout.contains("peer core-1 {"), "{stdout}");
    // The converted file is a first-class config: the checker accepts
    // it as the native dialect with no warnings.
    let lr = fixture("converted", &stdout, "lr");
    let (code, stdout, stderr) = check(&["config", "check", lr.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("dialect lr"), "{stdout}");
    assert!(stdout.contains("warnings: 0"), "{stdout}");
}

#[test]
fn conversion_is_deterministic() {
    let path = fixture(
        "determinism",
        "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n",
        "toml",
    );
    let args = ["config", "to-dsl", path.to_str().unwrap()];
    let (code1, out1, _) = to_dsl(&args);
    let (code2, out2, _) = to_dsl(&args);
    assert_eq!(code1, 0);
    assert_eq!(code2, 0);
    assert_eq!(out1, out2, "same IR must render byte-identically");
}

#[test]
fn filter_body_quotes_survive_the_round_trip() {
    // The TOML body carries \" escapes; the DSL emits the filter
    // source verbatim between braces and `config check` accepts it.
    let path = fixture(
        "filter-quotes",
        "[[filter]]\n\
         name = \"in\"\n\
         body = \"if proto == \\\"bgp\\\" then accept;\\nelse reject;\"\n",
        "toml",
    );
    let (code, stdout, stderr) = to_dsl(&["config", "to-dsl", path.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("filter in {"), "{stdout}");
    assert!(
        stdout.contains("if proto == \"bgp\""),
        "escaped quotes unescaped: {stdout}"
    );
    let lr = fixture("filter-converted", &stdout, "lr");
    let (code, _, stderr) = check(&["config", "check", lr.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
}

#[test]
fn converts_the_shipped_template() {
    // templates/daemon.toml is the standing golden file: it converts,
    // the result checks as .lr, and converting it twice is stable.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let template = format!("{manifest}/../../templates/daemon.toml");
    let args = ["config", "to-dsl", template.as_str()];
    let (code, out1, stderr) = to_dsl(&args);
    assert_eq!(code, 0, "{stderr}");
    let (_, out2, _) = to_dsl(&args);
    assert_eq!(out1, out2);
    let lr = fixture("template-converted", &out1, "lr");
    let (code, stdout, stderr) = check(&["config", "check", lr.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("warnings: 0"), "{stdout}");
}

#[test]
fn the_shipped_lr_template_round_trips_idempotently() {
    // Phase 3's DSL-first twin is itself a converter citizen: the
    // .lr template converts, converting the conversion is byte-stable
    // (the emission rule is a fixpoint), and the result still checks.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let template = format!("{manifest}/../../templates/daemon.lr");
    let args = ["config", "to-dsl", template.as_str()];
    let (code, out1, stderr) = to_dsl(&args);
    assert_eq!(code, 0, "{stderr}");
    let rt = fixture("lr-template-rt", &out1, "lr");
    let (code, out2, stderr) = to_dsl(&["config", "to-dsl", rt.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(out1, out2, "to-dsl must be a fixpoint on its own output");
    let (code, stdout, _) = check(&["config", "check", rt.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(stdout.contains("dialect lr"), "{stdout}");
}

#[test]
fn both_shipped_templates_convert_identically() {
    // The golden cross-frontend property, end to end: daemon.lr
    // documents the same configuration as daemon.toml, so both
    // templates must render the same .lr program — the standing
    // guarantee operators rely on when migrating with `config to-dsl`.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let toml_template = format!("{manifest}/../../templates/daemon.toml");
    let lr_template = format!("{manifest}/../../templates/daemon.lr");
    let (_, from_toml, stderr) = to_dsl(&["config", "to-dsl", toml_template.as_str()]);
    assert_eq!(
        to_dsl(&["config", "to-dsl", lr_template.as_str()]),
        (0, from_toml.clone(), String::new()),
        "stderr: {stderr}"
    );
}

#[test]
fn refuses_configs_with_parse_warnings() {
    // Unknown tables are tolerated-with-warning by the TOML frontend;
    // the converter refuses rather than emitting a file that means
    // less than the input.
    let path = fixture(
        "warnings",
        "[bgp]\nlocal_as = 64512\n\n[unknown-thing]\nx = 1\n",
        "toml",
    );
    let (code, stdout, stderr) = to_dsl(&["config", "to-dsl", path.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("refusing to convert"), "{stderr}");
}

#[test]
fn to_dsl_stays_silent_about_the_toml_deprecation() {
    // Phase 4 decision (issue #18): the deprecation notice fires on
    // the surfaces that load a config for a *running* daemon —
    // startup, reload, `config check`. The converter is the
    // migration tool itself, runs on TOML by design, and its stderr
    // stays clean for scripts.
    let path = fixture(
        "quiet",
        "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n",
        "toml",
    );
    let (code, _stdout, stderr) = to_dsl(&["config", "to-dsl", path.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(!stderr.contains("deprecation"), "stderr: {stderr}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn usage_errors_exit_two() {
    let (code, _, stderr) = to_dsl(&["config", "to-dsl"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("usage: lr-daemon config to-dsl"),
        "{stderr}"
    );

    let (code, _, stderr) = to_dsl(&["config", "to-dsl", "--bogus", "x"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown option"), "{stderr}");

    let (code, _, stderr) = to_dsl(&["config", "to-dsl", "--dialect"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("needs a value"), "{stderr}");

    let (code, _, stderr) = to_dsl(&["config", "frobnicate"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown config subcommand"), "{stderr}");
}

#[test]
fn missing_file_exits_one() {
    let (code, _, stderr) = to_dsl(&["config", "to-dsl", "/nonexistent/config.toml"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("cannot read config"), "{stderr}");
}
