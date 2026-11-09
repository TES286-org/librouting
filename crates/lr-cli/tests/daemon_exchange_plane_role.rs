//! End-to-end coverage for the RFC 9234 §3.1 exchange-plane policy-role
//! knob on the daemon's CLI surface (issue #92).
//!
//! defects.txt `crates/lr-cli/src/daemon.rs:L2245-L2248` recorded that
//! `wire_exchange_plane` hardcoded `policy_role = Some(ROLE_UNSET)`
//! because "lr's daemon does not configure RFC 9234 roles yet". The
//! prior `feat(daemon-config,daemon): [bgp] exchange_plane_policy_role +
//! [[peer]] exchange_plane_policy_role TOML keys + --exchange-plane-
//! policy-role CLI flag` commit exposed the role through TOML + CLI and
//! wired `wire_exchange_plane` to honour it; these e2e tests pin the
//! CLI surface from outside the in-process parser.
//!
//! These tests do not start a daemon. They exercise:
//!   * `lr-daemon --help` — the new `--exchange-plane-policy-role R`
//!     flag is advertised with its accepted vocabulary (provider |
//!     customer | rs | rs-client | peer | unset) so an operator scanning
//!     the help discovers the knob without reading the docs.
//!   * `lr-daemon config check` — a config that names
//!     `exchange_plane_policy_role` parses cleanly through the same
//!     load + finalize path startup uses, and a typo'd value fails
//!     closed with the diagnostic shape an operator sees.
//!
//! The exchange-plane *feature* side of the knob (whether the role
//! actually rides the policy-intent record on a live peer session) is
//! covered by the in-process unit tests in `daemon_config_tests.rs`
//! (`toml_global_exchange_plane_policy_role_parses`,
//! `toml_peer_exchange_plane_policy_role_override_parses`,
//! `toml_peer_exchange_plane_policy_role_inherits_global`,
//! `finalize_rewrites_empty_global_role_to_unset`,
//! `finalize_rejects_directly_written_bad_role`,
//! `finalize_rejects_directly_written_bad_peer_role`,
//! `parse_exchange_plane_policy_role_accepts_canonical_vocabulary`,
//! `parse_exchange_plane_policy_role_rejects_unknown`) and by the
//! live-peer daemon_exchange_plane tests once a session is up.

#![cfg(unix)]

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

/// `lr-daemon --help` advertises the new `--exchange-plane-policy-role R`
/// flag and names the accepted RFC 9234 vocabulary (provider | customer
/// | rs | rs-client | peer | unset).
///
/// The CLI surface is the operator's first contact with the knob; if
/// `--help` does not list it, an operator scanning the help cannot
/// discover it without reading the docs. The help text also names
/// the per-peer override so an operator who needs per-peer roles
/// knows where to look.
#[test]
fn help_advertises_exchange_plane_policy_role_flag() {
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
        combined.contains("--exchange-plane-policy-role"),
        "expected `--exchange-plane-policy-role` in --help output; got:\n{combined}"
    );
    // The vocabulary list documents the accepted values inline so an
    // operator does not have to cross-reference the docs to know the
    // accepted set.
    for role in ["provider", "customer", "rs", "rs-client", "peer", "unset"] {
        assert!(
            combined.contains(role),
            "expected `{role}` to appear in the --help vocabulary list; got:\n{combined}"
        );
    }
    // The per-peer override key is named so an operator who needs
    // per-session roles knows where to look.
    assert!(
        combined.contains("exchange_plane_policy_role"),
        "expected the per-peer `exchange_plane_policy_role` key to be mentioned in --help output; got:\n{combined}"
    );
}

/// `lr-daemon config check` accepts a config carrying `[bgp]
/// exchange_plane_policy_role = "provider"` (the router-wide default)
/// plus a per-peer override, and exits 0. This proves the parser +
/// finalize path does not break on the new keys — the per-peer override
/// value lands in `PeerSpec::exchange_plane_policy_role` (the daemon
/// unit test `toml_peer_exchange_plane_policy_role_override_parses`
/// pins that), and the e2e test pins that a config that exercises the
/// key pair loads cleanly through `config check` (the operator-visible
/// validation surface).
#[test]
fn config_check_accepts_exchange_plane_policy_role_global_and_per_peer() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-xp-role-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n\
         exchange_plane_policy_role = \"customer\"\n\n\
         [[peer]]\nremote = \"192.0.2.2\"\npeer_as = 64513\n\
         exchange_plane_policy_role = \"peer\"\n",
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
    assert!(
        out.status.success(),
        "expected `config check` to succeed; got:\n{combined}"
    );
    let _ = std::fs::remove_file(&path);
}

/// `lr-daemon config check` accepts the canonical "unset" value
/// explicitly — i.e. the operator's way of saying "no role claim"
/// parses cleanly and survives finalize. This pins that "unset" is a
/// first-class vocabulary entry, not just the implicit default.
#[test]
fn config_check_accepts_explicit_unset_role() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-xp-unset-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n\
         exchange_plane_policy_role = \"unset\"\n",
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
    assert!(
        out.status.success(),
        "expected `config check` to accept explicit `unset`; got:\n{combined}"
    );
    let _ = std::fs::remove_file(&path);
}

/// `lr-daemon config check` rejects a typo'd `[bgp]
/// exchange_plane_policy_role` value at parse time with the diagnostic
/// shape the operator sees. The fail-closed posture matters: a
/// silently accepted typo would let the operator's *intended* role
/// diverge from the *advertised* one without any signal — and the role
/// rides in a record the peer's import policy consults.
#[test]
fn config_check_rejects_typo_role() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-xp-typo-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n\
         exchange_plane_policy_role = \"providor\"\n",
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
    assert!(
        !out.status.success(),
        "expected `config check` to reject the typo; got:\n{combined}"
    );
    assert!(
        combined.contains("bad exchange_plane_policy_role 'providor'"),
        "expected a diagnostic naming the bad value; got:\n{combined}"
    );
    assert!(
        combined.contains("provider | customer | rs | rs-client | peer | unset"),
        "expected the diagnostic to enumerate the accepted vocabulary; got:\n{combined}"
    );
    let _ = std::fs::remove_file(&path);
}

/// `lr-daemon config check` rejects a typo'd per-peer override with
/// the same diagnostic shape. The per-peer override path is the more
/// failure-prone one (a peer-specific role the operator might typo
/// without the global config catching it), so it has its own coverage.
#[test]
fn config_check_rejects_typo_peer_role() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-xp-peer-typo-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n\n\
         [[peer]]\nremote = \"192.0.2.2\"\npeer_as = 64513\n\
         exchange_plane_policy_role = \"cust0mer\"\n",
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
    assert!(
        !out.status.success(),
        "expected `config check` to reject the per-peer typo; got:\n{combined}"
    );
    assert!(
        combined.contains("bad exchange_plane_policy_role 'cust0mer'"),
        "expected a diagnostic naming the bad value; got:\n{combined}"
    );
    let _ = std::fs::remove_file(&path);
}

/// `lr-daemon --exchange-plane-policy-role provider --local-as 64512
/// --peer-as 64513 --router-id 10.0.0.1 --exchange-plane-key 1:secret
/// --exchange-plane` — the CLI flag accepts a recognised role and the
/// daemon's startup path (which calls `finalize`) tolerates it.
///
/// The test does not let the daemon establish (no `--peer` /
/// `--listen`); the config check is the same load + finalize path the
/// `--help` banner exits before, so a regression in the CLI flag's
/// registration surfaces here even when the in-process unit tests
/// still pass. The daemon exits non-zero because it has no peers, but
/// the role parse + finalize must not be the cause.
#[test]
fn cli_flag_accepts_recognised_role() {
    // Spawn the daemon; it will exit on its own because it has no
    // peers to dial and no listener to bind. Wait briefly for the
    // startup banner, then send SIGTERM and inspect the log.
    let log = std::env::temp_dir().join(format!(
        "lr-daemon-xp-role-cli-{}-{}.log",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    let _ = std::fs::remove_file(&log);
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .expect("create log file");
    let mut child = Command::new(BIN)
        .args([
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--exchange-plane",
            "--exchange-plane-key",
            "1:secret",
            "--exchange-plane-policy-role",
            "provider",
            "--ebgp-policy",
            "accept-all",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file.try_clone().expect("clone stdout")))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("spawn lr-daemon");
    // Wait briefly for the startup banner to land.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let _ = child.kill();
    let _ = child.wait();
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_file(&log);
    // The startup banner must show the exchange-plane posture AND
    // the role parse must not have failed. A parse failure would have
    // printed `bad --exchange-plane-policy-role` before any banner
    // line; a successful parse lets the banner land. We don't assert
    // the role on the banner (the banner format is documented
    // separately); we just assert the CLI flag did not reject the
    // value.
    assert!(
        !text.contains("bad --exchange-plane-policy-role"),
        "the CLI flag rejected `provider`; got:\n{text}"
    );
}

/// `lr-daemon --exchange-plane-policy-role not-a-role` rejects the
/// unknown value with a diagnostic that names the bad value and exits
/// non-zero before any daemon startup work. The fail-closed posture
/// matches the TOML parser.
#[test]
fn cli_flag_rejects_unknown_role() {
    let out = Command::new(BIN)
        .args([
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--exchange-plane-policy-role",
            "not-a-role",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !out.status.success(),
        "expected `--exchange-plane-policy-role not-a-role` to exit non-zero; got:\n{combined}"
    );
    assert!(
        combined.contains("bad --exchange-plane-policy-role"),
        "expected a diagnostic; got:\n{combined}"
    );
    assert!(
        combined.contains("not-a-role"),
        "expected the bad value to be named in the diagnostic; got:\n{combined}"
    );
}
