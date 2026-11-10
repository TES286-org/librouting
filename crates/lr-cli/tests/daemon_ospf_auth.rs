//! End-to-end coverage for the OSPFv2 authentication CLI surface
//! (RFC 2328 §D — NullAuth, SimplePassword, CryptoAuth).
//!
//! defects.txt `crates/lr-cli/src/daemon_ospf.rs:L42-L47` recorded
//! that "OSPFv2 only; authentication is not wired into the daemon
//! yet." The prior `feat(daemon): OSPFv2 SimplePassword auth wiring
//! end-to-end (issue #92)` (commit `47a330e`) and `feat(daemon):
//! OSPFv2 CryptoAuth daemon wiring end-to-end (issue #92)` (commit
//! `52086d7`) landed the apply/verify round-trip in the daemon's
//! send/receive paths and the `--ospf-auth-type` /
//! `--ospf-auth-password` / `--ospf-auth-key` / `--ospf-auth-key-id`
//! / `--ospf-auth-algorithm` CLI flags. The unit tests in
//! `daemon_ospf_tests.rs` cover the apply/verify codec round-trip
//! and the TOML parse surface for `[ospf.auth]`.
//!
//! These tests exercise the operator-visible CLI / `config check`
//! surface end-to-end through the real `lr-daemon` binary, so a
//! regression that drops one of the auth flags from `--help` (the
//! previous shape: the daemon accepted the flags but `--help` did
//! not advertise them) or breaks the `config check` acceptance of
//! `[ospf.auth]` (the previous shape: a single-section `[ospf.auth]`
//! header produced a spurious `unknown section [ospf.auth] (ignored)`
//! warning even though the keys parsed correctly) fails here.
//!
//! The TOML `[ospf.auth]` block and the DSL `ospf_auth { ... }`
//! block both lower through `apply_config_key`'s `ospf.auth` arm
//! (the single shared dispatch the .lr DSL migration relies on),
//! so each test exercises both frontends through `config check
//! --dialect toml|lr`.

#![cfg(unix)]

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

/// `lr-daemon --help` advertises every `--ospf-auth-*` flag the
/// parser accepts. The previous shape of the help text omitted
/// the entire auth cluster — the daemon silently accepted the
/// flags but an operator scanning `--help` had no way to discover
/// them without reading the docs. Each flag is matched on its own
/// line so a regression that drops one (but keeps the others) is
/// visible per flag, not just as a count delta.
#[test]
fn help_advertises_ospf_auth_flags() {
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
    for flag in [
        "--ospf-auth-type",
        "--ospf-auth-password",
        "--ospf-auth-key",
        "--ospf-auth-key-id",
        "--ospf-auth-algorithm",
    ] {
        assert!(
            combined.contains(flag),
            "expected `{flag}` in --help output; got:\n{combined}"
        );
    }
    // The `--ospf-authentication-*` aliases are advertised too, so
    // an operator familiar with the long-form spelling recognises
    // the knob without cross-referencing the docs.
    for alias in [
        "--ospf-authentication-type",
        "--ospf-authentication-password",
        "--ospf-authentication-key",
        "--ospf-authentication-key-id",
        "--ospf-authentication-algorithm",
    ] {
        assert!(
            combined.contains(alias),
            "expected the `{alias}` alias in --help output; got:\n{combined}"
        );
    }
}

/// `lr-daemon config check` accepts a TOML config with `[ospf.auth]`
/// `type = "simple"` + `password = "..."` and produces **zero
/// warnings**. The previous shape of the parser emitted a spurious
/// `unknown section [ospf.auth] (ignored)` warning for the
/// single-section header, even though the keys parsed correctly —
/// misleading the operator into thinking the auth block had been
/// silently dropped. With `ospf.auth` admitted to the
/// single-section allowlist, a clean config check is the
/// operator-visible signal that the block is in effect.
///
/// The fixture sets `protocol = "ospf"` so the auth block is
/// in scope (the `finalize_ospf` gate's `runs_protocol("ospf")`
/// check would otherwise emit a warning and skip the auth
/// validation, leaving the operator's first signal at daemon-
/// startup time rather than at config-check time).
#[test]
fn config_check_toml_ospf_auth_simple_no_warning() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-toml-simple-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ospf\"\n[ospf.auth]\ntype = \"simple\"\npassword = \"secret12\"\n",
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
        "lr-daemon config check exited non-zero for [ospf.auth] simple; output:\n{combined}"
    );
    assert!(
        combined.contains("OK (dialect toml)"),
        "expected OK in config check output; got:\n{combined}"
    );
    assert!(
        !combined.contains("unknown section"),
        "the spurious 'unknown section [ospf.auth]' warning must not appear; got:\n{combined}"
    );
    assert!(
        combined.contains("warnings: 0"),
        "expected zero warnings for a clean [ospf.auth] block; got:\n{combined}"
    );
}

/// `lr-daemon config check` accepts a TOML config with
/// `[ospf.auth] type = "crypto"` + `key` + `key_id` + `algorithm`
/// and produces zero warnings — the CryptoAuth form is as
/// well-formed as the SimplePassword form for the parser.
#[test]
fn config_check_toml_ospf_auth_crypto_no_warning() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-toml-crypto-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ospf\"\n\
         [ospf.auth]\n\
         type = \"crypto\"\n\
         key = \"shared-secret\"\n\
         key_id = 1\n\
         algorithm = \"hmac-sha256\"\n",
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
        "lr-daemon config check exited non-zero for [ospf.auth] crypto; output:\n{combined}"
    );
    assert!(
        combined.contains("OK (dialect toml)"),
        "expected OK in config check output; got:\n{combined}"
    );
    assert!(
        !combined.contains("unknown section"),
        "the spurious 'unknown section [ospf.auth]' warning must not appear; got:\n{combined}"
    );
    assert!(
        combined.contains("warnings: 0"),
        "expected zero warnings for a clean crypto [ospf.auth] block; got:\n{combined}"
    );
}

/// `lr-daemon config check --dialect lr` accepts the native DSL
/// form `ospf_auth { ... }` with the same keys. The .lr DSL is the
/// daemon's recommended frontend (TOML is deprecated, planned for
/// removal in 2.0), so a config that came in through `lr translate`
/// or was hand-edited as `.lr` must round-trip the auth block too.
/// The previous shape of the parser did not recognise
/// `ospf_auth { ... }` at all — the block was rejected as an
/// unknown top-level block.
#[test]
fn config_check_dsl_ospf_auth_simple_block_parses() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-dsl-simple-{}-{}.lr",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol ospf;\nospf_auth {\n    type \"simple\";\n    password \"secret12\";\n}\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", "--dialect", "lr", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check --dialect lr");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "lr-daemon config check --dialect lr exited non-zero for ospf_auth {{ type simple; }}; output:\n{combined}"
    );
    assert!(
        combined.contains("OK (dialect lr)"),
        "expected OK (dialect lr) in config check output; got:\n{combined}"
    );
    assert!(
        combined.contains("warnings: 0"),
        "expected zero warnings for a clean DSL ospf_auth block; got:\n{combined}"
    );
}

/// `lr-daemon config check --dialect lr` accepts the CryptoAuth
/// shape through the DSL frontend too. The crypto keys are
/// `type`, `key`, `key_id` and `algorithm` — the same key set as
/// the TOML form.
#[test]
fn config_check_dsl_ospf_auth_crypto_block_parses() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-dsl-crypto-{}-{}.lr",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol ospf;\n\
         ospf_auth {\n\
         \x20   type \"crypto\";\n\
         \x20   key \"shared-secret\";\n\
         \x20   key_id 1;\n\
         \x20   algorithm \"hmac-sha256\";\n\
         }\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", "--dialect", "lr", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check --dialect lr");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "lr-daemon config check --dialect lr exited non-zero for crypto ospf_auth; output:\n{combined}"
    );
    assert!(
        combined.contains("OK (dialect lr)"),
        "expected OK (dialect lr) in config check output; got:\n{combined}"
    );
    assert!(
        combined.contains("warnings: 0"),
        "expected zero warnings for a clean DSL crypto ospf_auth block; got:\n{combined}"
    );
}

/// `lr-daemon config check` rejects `[ospf.auth] type = "simple"`
/// without a `password` at finalize time — fail-closed at
/// config-editing time, matching the daemon's startup behaviour.
/// The error message names the strategy and the missing key so the
/// operator can fix the typo without re-reading the docs.
///
/// Each rejection test sets `protocol = "ospf"` so the
/// `finalize_ospf` gate runs (the `runs_protocol("ospf")` check
/// would otherwise emit a warning and skip the auth validation,
/// leaving the operator's first signal at daemon-startup time
/// rather than at config-check time).
#[test]
fn config_check_rejects_simple_without_password() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-simple-no-password-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ospf\"\n[ospf.auth]\ntype = \"simple\"\n",
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
        !out.status.success(),
        "lr-daemon config check should exit non-zero for simple without password; output:\n{combined}"
    );
    assert!(
        combined.contains("[ospf.auth] type = \"simple\" requires a 'password' key"),
        "expected the missing-password rejection; got:\n{combined}"
    );
}

/// `lr-daemon config check` rejects `[ospf.auth] type = "crypto"`
/// without a `key` at finalize time — same fail-closed rule as
/// the simple/password pair.
#[test]
fn config_check_rejects_crypto_without_key() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-crypto-no-key-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ospf\"\n[ospf.auth]\ntype = \"crypto\"\nkey_id = 1\n",
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
        !out.status.success(),
        "lr-daemon config check should exit non-zero for crypto without key; output:\n{combined}"
    );
    assert!(
        combined.contains("[ospf.auth] type = \"crypto\" requires a non-empty 'key' key"),
        "expected the missing-key rejection; got:\n{combined}"
    );
}

/// `lr-daemon config check` rejects `[ospf.auth] type = "crypto"`
/// without a `key_id` — the CryptoAuth Key ID is mandatory per
/// RFC 2328 §D.3.1, so the daemon refuses to start without one.
#[test]
fn config_check_rejects_crypto_without_key_id() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-crypto-no-key-id-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ospf\"\n[ospf.auth]\ntype = \"crypto\"\nkey = \"shared-secret\"\n",
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
        !out.status.success(),
        "lr-daemon config check should exit non-zero for crypto without key_id; output:\n{combined}"
    );
    assert!(
        combined.contains("[ospf.auth] type = \"crypto\" requires a 'key_id' key"),
        "expected the missing-key_id rejection; got:\n{combined}"
    );
}

/// `lr-daemon config check` rejects an unknown `[ospf.auth] type`
/// at parse time (fail-closed before finalize). The accepted set
/// is `null | simple | crypto` (with aliases `none`, `off`,
/// `password`, `simple-password`, `md5`, `message-digest`); a
/// typo like `bogus` is rejected so the operator does not
/// silently fall back to NullAuth.
#[test]
fn config_check_rejects_unknown_auth_type() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-unknown-type-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ospf\"\n[ospf.auth]\ntype = \"bogus\"\n",
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
        !out.status.success(),
        "lr-daemon config check should exit non-zero for an unknown ospf.auth type; output:\n{combined}"
    );
    assert!(
        combined.contains("unknown ospf.auth type 'bogus'"),
        "expected the unknown-type rejection; got:\n{combined}"
    );
}

/// `lr-daemon config check` rejects an unknown
/// `[ospf.auth] algorithm` at parse time. The accepted set is
/// `hmac-sha256` (with aliases `hmac-sha-256`, `sha256`) and
/// `hmac-sha1` (with aliases `hmac-sha-1`, `sha1`); a typo like
/// `bogus` is rejected.
#[test]
fn config_check_rejects_unknown_auth_algorithm() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-unknown-algo-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ospf\"\n\
         [ospf.auth]\n\
         type = \"crypto\"\n\
         key = \"shared-secret\"\n\
         key_id = 1\n\
         algorithm = \"bogus\"\n",
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
        !out.status.success(),
        "lr-daemon config check should exit non-zero for an unknown algorithm; output:\n{combined}"
    );
    assert!(
        combined.contains("unknown ospf.auth algorithm 'bogus'"),
        "expected the unknown-algorithm rejection; got:\n{combined}"
    );
}

/// `lr-daemon config to-dsl` round-trips a TOML config carrying
/// `[ospf.auth]` into an `.lr` program with the equivalent
/// `ospf_auth { ... }` block. The DSL migration (TOML deprecated,
/// planned removal in 2.0) depends on this round-trip so an
/// operator who runs `lr-daemon config to-dsl daemon.toml >
/// daemon.lr` keeps the auth block in the converted file.
#[test]
fn config_to_dsl_round_trips_ospf_auth_simple() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-toml-to-dsl-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ospf\"\n[ospf.auth]\ntype = \"simple\"\npassword = \"secret12\"\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "to-dsl", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config to-dsl");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "lr-daemon config to-dsl exited non-zero; output:\n{combined}"
    );
    assert!(
        combined.contains("ospf_auth {"),
        "expected an `ospf_auth {{ ... }}` block in the DSL output; got:\n{combined}"
    );
    assert!(
        combined.contains("type simple;"),
        "expected `type simple;` in the DSL output; got:\n{combined}"
    );
    assert!(
        combined.contains("password secret12;"),
        "expected `password secret12;` in the DSL output; got:\n{combined}"
    );
}

/// `lr-daemon config to-dsl` round-trips the CryptoAuth form too
/// — the emitted DSL carries the `type`, `key`, `key_id` and
/// `algorithm` keys, so a TOML config moves to the DSL without
/// losing the auth strategy.
#[test]
fn config_to_dsl_round_trips_ospf_auth_crypto() {
    let path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-toml-to-dsl-crypto-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ospf\"\n\
         [ospf.auth]\n\
         type = \"crypto\"\n\
         key = \"shared-secret\"\n\
         key_id = 1\n\
         algorithm = \"hmac-sha256\"\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "to-dsl", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config to-dsl");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "lr-daemon config to-dsl exited non-zero for crypto; output:\n{combined}"
    );
    assert!(
        combined.contains("ospf_auth {"),
        "expected an `ospf_auth {{ ... }}` block in the DSL output; got:\n{combined}"
    );
    assert!(
        combined.contains("type crypto;"),
        "expected `type crypto;` in the DSL output; got:\n{combined}"
    );
    assert!(
        combined.contains("key shared-secret;"),
        "expected `key shared-secret;` in the DSL output; got:\n{combined}"
    );
    assert!(
        combined.contains("key_id 1;"),
        "expected `key_id 1;` in the DSL output; got:\n{combined}"
    );
    assert!(
        combined.contains("algorithm hmac-sha256;"),
        "expected `algorithm hmac-sha256;` in the DSL output; got:\n{combined}"
    );
}

/// The round-trip is idempotent: a TOML config converted to DSL
/// and re-loaded as DSL produces the same `OspfAuthSpec`. This
/// pins the IR-equality property the DSL migration relies on —
/// the two frontends share `apply_config_key`'s `ospf.auth` arm,
/// so a config that came in through either path lands on the
/// same typed IR. A regression that drops a key from the DSL
/// emitter (or the TOML parser) breaks the round-trip here.
#[test]
fn config_to_dsl_round_trip_idempotent() {
    // Step 1: TOML → DSL. The fixture includes `protocol = "ospf"`
    // so the `to-dsl` emitter includes `protocol ospf;` in the
    // output (otherwise the round-tripped DSL would warn "OSPF
    // tables present but the protocol set is '' (ignored)").
    let toml_path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-rt-toml-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &toml_path,
        "protocol = \"ospf\"\n\
         [ospf.auth]\n\
         type = \"crypto\"\n\
         key = \"shared-secret\"\n\
         key_id = 7\n\
         algorithm = \"hmac-sha256\"\n",
    )
    .expect("write fixture");
    let to_dsl = Command::new(BIN)
        .args(["config", "to-dsl", toml_path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config to-dsl");
    let _ = std::fs::remove_file(&toml_path);
    assert!(to_dsl.status.success(), "TOML → DSL failed");
    let dsl = String::from_utf8_lossy(&to_dsl.stdout).to_string();
    assert!(
        dsl.contains("protocol ospf;"),
        "expected `protocol ospf;` in the DSL output; got:\n{dsl}"
    );
    // Step 2: write the DSL output to a file and re-check it.
    let dsl_path = std::env::temp_dir().join(format!(
        "lr-ospf-auth-rt-dsl-{}-{}.lr",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(&dsl_path, &dsl).expect("write DSL fixture");
    let check = Command::new(BIN)
        .args([
            "config",
            "check",
            "--dialect",
            "lr",
            dsl_path.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check --dialect lr");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr),
    );
    let _ = std::fs::remove_file(&dsl_path);
    assert!(
        check.status.success(),
        "DSL re-check failed; output:\n{combined}"
    );
    assert!(
        combined.contains("OK (dialect lr)"),
        "expected OK (dialect lr) after the round-trip; got:\n{combined}"
    );
    assert!(
        combined.contains("warnings: 0"),
        "expected zero warnings after the round-trip; got:\n{combined}"
    );
}
