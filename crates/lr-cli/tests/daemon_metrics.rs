//! End-to-end tests for the Prometheus `/metrics` HTTP endpoint
//! (ROADMAP-v3 D12.2).
//!
//! Each test spawns the real `lr-daemon` binary
//! (`CARGO_BIN_EXE_lr-daemon`) on a loopback port with
//! `--metrics-addr`, then scrapes `GET /metrics` over HTTP and asserts
//! the Prometheus text exposition format. The same shape
//! `daemon_runtime.rs` uses for the API-socket round-trip tests;
//! the difference is the client side is plain `std::net::TcpStream`
//! (no Unix domain socket), since Prometheus scrapes over TCP.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DAEMON: &str = env!("CARGO_BIN_EXE_lr-daemon");

/// A spawned `lr-daemon` with its log file path so the test can wait
/// for the "metrics endpoint on" marker before scraping.
struct Daemon {
    child: std::process::Child,
    log: std::path::PathBuf,
}

impl Daemon {
    fn spawn(args: &[&str], tag: &str) -> Self {
        let log =
            std::env::temp_dir().join(format!("lr-metrics-test-{tag}-{}.log", std::process::id()));
        let log_file = std::fs::File::create(&log).expect("create log file");
        let child = Command::new(DAEMON)
            .args(args)
            .stdout(Stdio::from(log_file.try_clone().expect("clone stdout")))
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("spawn lr-daemon");
        Self { child, log }
    }

    /// Block until the daemon's log contains `needle` (15 s deadline).
    fn wait_log(&self, needle: &str, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&self.log) {
                if text.contains(needle) {
                    return;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        panic!("daemon did not report '{what}' within 15 s; log:\n{text}");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Belt-and-braces: a panic before shutdown leaves the daemon
        // running, which would hang the test harness. Kill on drop.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Pick a free TCP port on loopback. The daemon's metrics listener
/// will rebind it; the brief window between this bind and the daemon's
/// bind is racy, but the daemon sets `SO_REUSEADDR` (the macOS fix
/// `1862a91`) so a stale TIME_WAIT does not block the rebind.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One HTTP round trip: send `GET <path> HTTP/1.0`, return the raw
/// response bytes (status line + headers + body). A 5 s deadline
/// mirrors `daemon_runtime.rs::api_ask`.
fn http_get(addr: &str, path: &str) -> String {
    let mut conn = TcpStream::connect(addr).expect("connect to metrics endpoint");
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        conn,
        "GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    conn.flush().unwrap();
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).expect("read response");
    String::from_utf8_lossy(&buf).into_owned()
}

/// Split an HTTP response into (status_line, headers, body).
fn split_response(resp: &str) -> (&str, Vec<&str>, &str) {
    // Find the blank line that separates headers from body.
    let split = resp.find("\r\n\r\n").unwrap_or(resp.len());
    let head = &resp[..split];
    let body = if split < resp.len() {
        &resp[split + 4..]
    } else {
        ""
    };
    let mut lines = head.lines();
    let status = lines.next().unwrap_or("");
    let headers: Vec<&str> = lines.collect();
    (status, headers, body)
}

/// `GET /metrics` returns the full Prometheus exposition with the
/// daemon's identity, uptime, session/RIB/ROA counters.
#[test]
fn metrics_endpoint_serves_prometheus_exposition() {
    let port = free_port();
    let metrics_addr = format!("127.0.0.1:{port}");
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18401",
            "--network",
            "203.0.113.0/24",
            "--metrics-addr",
            &metrics_addr,
        ],
        "metrics",
    );
    d.wait_log("metrics endpoint on", "metrics endpoint up");

    let resp = http_get(&metrics_addr, "/metrics");
    let (status, headers, body) = split_response(&resp);
    assert!(
        status.starts_with("HTTP/1.0 200"),
        "status line: {status}; full response:\n{resp}"
    );
    assert!(
        headers
            .iter()
            .any(|h| h.starts_with("Content-Type:") && h.contains("text/plain")),
        "Content-Type header missing or wrong: {headers:?}"
    );
    // Prometheus exposition format requires the version=0.0.4 marker.
    assert!(
        headers.iter().any(|h| h.contains("version=0.0.4")),
        "Content-Type should declare version=0.0.4: {headers:?}"
    );

    // Every metric we expose must carry HELP + TYPE.
    for metric in [
        "lr_info",
        "lr_uptime_seconds",
        "lr_sessions_total",
        "lr_established_sessions",
        "lr_rib_entries",
        "lr_adj_rib_in_entries",
    ] {
        assert!(
            body.contains(&format!("# HELP {metric} ")),
            "body missing HELP for {metric}; body:\n{body}"
        );
        assert!(
            body.contains(&format!("# TYPE {metric} gauge")),
            "body missing TYPE for {metric}; body:\n{body}"
        );
    }

    // Identity gauge carries the daemon's local_as and router_id.
    assert!(
        body.contains(
            "lr_info{version=\"1.0.0-rc.3\",local_as=\"64512\",router_id=\"10.0.0.1\"} 1"
        ),
        "lr_info line missing or wrong; body:\n{body}"
    );

    // One BGP session, Idle (no peer connecting).
    assert!(
        body.contains("lr_sessions_total{kind=\"bgp\",state=\"Idle\"} 1"),
        "sessions_total line missing or wrong; body:\n{body}"
    );
    assert!(
        body.contains("lr_established_sessions{kind=\"bgp\"} 0"),
        "established_sessions line missing or wrong; body:\n{body}"
    );

    // The Loc-RIB carries the originated network.
    assert!(
        body.contains("lr_rib_entries 1"),
        "rib_entries line missing or wrong; body:\n{body}"
    );

    // The ROA store is present (the BGP daemon always builds a
    // `RoaStore`, even when empty), so lr_roa_entries appears.
    assert!(
        body.contains("# TYPE lr_roa_entries gauge"),
        "lr_roa_entries TYPE line missing; body:\n{body}"
    );
    assert!(
        body.contains("lr_roa_entries 0"),
        "lr_roa_entries value missing or wrong; body:\n{body}"
    );
}

/// `GET /` returns a one-line pointer to `/metrics` so an operator
/// pointing a browser at the endpoint sees something useful.
#[test]
fn metrics_root_returns_pointer() {
    let port = free_port();
    let metrics_addr = format!("127.0.0.1:{port}");
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18402",
            "--metrics-addr",
            &metrics_addr,
        ],
        "root",
    );
    d.wait_log("metrics endpoint on", "metrics endpoint up");

    let resp = http_get(&metrics_addr, "/");
    let (status, _headers, body) = split_response(&resp);
    assert!(
        status.starts_with("HTTP/1.0 200"),
        "status line: {status}; full response:\n{resp}"
    );
    assert!(
        body.contains("/metrics"),
        "root body should point to /metrics; body:\n{body}"
    );
}

/// `GET /nonexistent` returns `404 Not Found`.
#[test]
fn metrics_unknown_path_returns_404() {
    let port = free_port();
    let metrics_addr = format!("127.0.0.1:{port}");
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18403",
            "--metrics-addr",
            &metrics_addr,
        ],
        "404",
    );
    d.wait_log("metrics endpoint on", "metrics endpoint up");

    let resp = http_get(&metrics_addr, "/nonexistent");
    let (status, _headers, body) = split_response(&resp);
    assert!(
        status.starts_with("HTTP/1.0 404"),
        "status line: {status}; full response:\n{resp}"
    );
    assert!(
        body.contains("not found"),
        "404 body should say 'not found'; body:\n{body}"
    );
}

/// A `POST` (or any non-GET method) returns `404` — the endpoint
/// serves only `GET`.
#[test]
fn metrics_rejects_non_get_methods() {
    let port = free_port();
    let metrics_addr = format!("127.0.0.1:{port}");
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18404",
            "--metrics-addr",
            &metrics_addr,
        ],
        "post",
    );
    d.wait_log("metrics endpoint on", "metrics endpoint up");

    let mut conn = TcpStream::connect(&metrics_addr).expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(conn, "POST /metrics HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
    conn.flush().unwrap();
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf).into_owned();
    let (status, _headers, _body) = split_response(&resp);
    assert!(
        status.starts_with("HTTP/1.0 404"),
        "non-GET should 404; status: {status}"
    );
}

/// The metrics endpoint is **opt-in** — without `--metrics-addr` the
/// daemon does not start one. Verify by checking the daemon's log
/// for the absence of the "metrics endpoint on" marker.
#[test]
fn metrics_disabled_by_default() {
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18405",
        ],
        "disabled",
    );
    // Wait for the daemon to come up (it prints the banner early).
    d.wait_log("librouting daemon (lr-daemon)", "daemon up");
    // Give the daemon a moment to potentially start a metrics thread
    // (it should not). 500 ms is well past the metrics thread spawn
    // point in the daemon's startup sequence.
    thread::sleep(Duration::from_millis(500));
    let log = std::fs::read_to_string(&d.log).unwrap_or_default();
    assert!(
        !log.contains("metrics endpoint on"),
        "metrics endpoint should not start without --metrics-addr; log:\n{log}"
    );
}

/// The metrics exposition is **stable across scrapes** — the same
/// daemon scraped twice within a short window produces the same
/// metric ordering (BTreeMap-sorted) so a Prometheus federation
/// query does not see label churn.
#[test]
fn metrics_exposition_is_stable_across_scrapes() {
    let port = free_port();
    let metrics_addr = format!("127.0.0.1:{port}");
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18406",
            "--network",
            "203.0.113.0/24",
            "--metrics-addr",
            &metrics_addr,
        ],
        "stable",
    );
    d.wait_log("metrics endpoint on", "metrics endpoint up");

    let resp1 = http_get(&metrics_addr, "/metrics");
    // Brief pause — the uptime value may tick by one second between
    // scrapes; we strip the uptime line before comparing.
    thread::sleep(Duration::from_millis(300));
    let resp2 = http_get(&metrics_addr, "/metrics");

    let strip_uptime = |resp: &str| -> String {
        resp.lines()
            .filter(|l| !l.starts_with("lr_uptime_seconds") && !l.contains("lr_uptime_seconds"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        strip_uptime(&resp1),
        strip_uptime(&resp2),
        "exposition should be stable across scrapes (modulo uptime)"
    );
}

/// A bind failure (port already in use) is fatal: the daemon exits
/// non-zero with a "metrics endpoint" error on stderr.
#[test]
fn metrics_bind_failure_is_fatal() {
    // Occupy a port with a listener the daemon cannot have (it holds
    // the bind for the test's lifetime).
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = squatter.local_addr().unwrap();
    let port = addr.port();
    // Drop the listener's address into the daemon's path — the daemon
    // will try to bind and fail with EADDRINUSE.
    let metrics_addr = format!("127.0.0.1:{port}");
    let mut d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18407",
            "--metrics-addr",
            &metrics_addr,
        ],
        "bindfail",
    );
    // Wait for the daemon to exit (failure is synchronous — the
    // spawn_metrics call returns Err before the daemon enters its
    // main loop).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut exit_ok = false;
    let mut log_text = String::new();
    while Instant::now() < deadline {
        match d.child.try_wait() {
            Ok(Some(status)) => {
                exit_ok = status.code() != Some(0);
                log_text = std::fs::read_to_string(&d.log).unwrap_or_default();
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => break,
        }
    }
    // Drop the squatter so the daemon could have bound — but the
    // daemon should have already exited.
    drop(squatter);
    assert!(
        exit_ok,
        "daemon should exit non-zero on metrics bind failure"
    );
    assert!(
        log_text.contains("metrics endpoint") && log_text.contains("bind"),
        "log should mention the bind failure; log:\n{log_text}"
    );
}

/// Use `BufRead::read_line` somewhere so the `BufRead` import is not
/// flagged as unused. The metrics tests above use `read_to_end`
/// instead; this is a compile-time guard for the import.
#[allow(dead_code)]
fn _bufread_used(reader: &mut BufReader<&[u8]>) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).ok();
    line
}
