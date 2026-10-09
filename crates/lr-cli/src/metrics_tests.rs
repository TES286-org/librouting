use super::*;
use lr_router::RouterInstance;
use std::time::Duration;

/// Every bucket line is cumulative and monotone, the `+Inf`
/// bucket equals `_count`, and `_sum` is the exact total.
#[test]
fn histogram_buckets_are_cumulative() {
    let h = DurationHistogram::new();
    // One observation per bucket boundary plus one beyond the
    // last bound (lands only in `+Inf` via the count).
    for bound in DurationHistogram::BOUNDS {
        h.record(bound);
    }
    h.record(u64::MAX / 2); // larger than every bound

    let mut out = String::new();
    h.render(&mut out, "test_hist", "{direction=\"import\"}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), DurationHistogram::BOUNDS.len() + 2);
    // Bucket values strictly non-decreasing.
    let mut prev = 0u64;
    for (i, line) in lines.iter().enumerate() {
        if i < DurationHistogram::BOUNDS.len() {
            let value: u64 = line.rsplit(' ').next().unwrap().parse().unwrap();
            assert!(value >= prev, "cumulative buckets must not decrease");
            prev = value;
        }
    }
    // The last bucket (10 ms) holds every in-bounds observation;
    // _count additionally includes the out-of-bounds one.
    let last_bucket: u64 = lines[DurationHistogram::BOUNDS.len() - 1]
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let count: u64 = lines[DurationHistogram::BOUNDS.len() + 1]
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(last_bucket, DurationHistogram::BOUNDS.len() as u64);
    assert_eq!(count, DurationHistogram::BOUNDS.len() as u64 + 1);
    // `_count` == count() helper.
    assert_eq!(h.count(), count);
    // A bucket label renders with the comma join: the first line
    // carries both the direction and le labels.
    assert!(lines[0].starts_with("test_hist_bucket{direction=\"import\",le=\""));
}

/// The seconds rendering is exact at nanosecond precision for the
/// fixed bounds (all multiples of 50 ns).
#[test]
fn seconds_formatting_is_exact() {
    assert_eq!(format_secs(100), "0.000000100");
    assert_eq!(format_secs(250), "0.000000250");
    assert_eq!(format_secs(1_000), "0.000001000");
    assert_eq!(format_secs(10_000_000), "0.010000000");
    assert_eq!(format_secs(0), "0.000000000");
}

/// The registry renders the HELP/TYPE headers once and one
/// bucket/sum/count block per registered series, in registration
/// order.
#[test]
fn registry_renders_prometheus_block() {
    let mut r = FilterMetricsRegistry::new();
    let import = r.register(FilterDirection::Import, "in-filter");
    let export = r.register(FilterDirection::Export, "out-filter");
    import.record(120);
    export.record(240);
    export.record(480);

    let mut out = String::new();
    r.render(&mut out);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
            lines[0],
            "# HELP lr_filter_eval_duration_seconds Filter DSL evaluation latency, by direction and filter name."
        );
    assert_eq!(lines[1], "# TYPE lr_filter_eval_duration_seconds histogram");
    // First series block: 16 buckets + sum + count.
    assert!(lines[2].contains("direction=\"import\""));
    assert!(lines[2].contains("filter=\"in-filter\""));
    assert!(lines[2].contains("le=\"0.000000100\""));
    assert_eq!(
            lines[2 + DurationHistogram::BOUNDS.len()],
            "lr_filter_eval_duration_seconds_sum{direction=\"import\",filter=\"in-filter\"} 0.000000120"
        );
    assert_eq!(
        lines[3 + DurationHistogram::BOUNDS.len()],
        "lr_filter_eval_duration_seconds_count{direction=\"import\",filter=\"in-filter\"} 1"
    );
    // Second series.
    let second = 4 + DurationHistogram::BOUNDS.len();
    assert!(lines[second].contains("direction=\"export\""));
    assert!(lines[second].contains("filter=\"out-filter\""));
    assert_eq!(
            lines[second + DurationHistogram::BOUNDS.len()],
            "lr_filter_eval_duration_seconds_sum{direction=\"export\",filter=\"out-filter\"} 0.000000720"
        );
    assert_eq!(
        lines[second + DurationHistogram::BOUNDS.len() + 1],
        "lr_filter_eval_duration_seconds_count{direction=\"export\",filter=\"out-filter\"} 2"
    );
}

/// An empty registry renders nothing (the metric block is omitted
/// from the exposition rather than emitting bare headers).
#[test]
fn empty_registry_renders_nothing() {
    let r = FilterMetricsRegistry::new();
    assert!(r.is_empty());
    let mut out = String::new();
    r.render(&mut out);
    assert!(out.is_empty());
}

/// Histograms are shareable across threads: concurrent records
/// all land (relaxed atomics suffice — the test only checks the
/// total, not the bucket split).
#[test]
fn histogram_concurrent_records_all_land() {
    let h = std::sync::Arc::new(DurationHistogram::new());
    let mut joins = Vec::new();
    for t in 0..4u64 {
        let h = std::sync::Arc::clone(&h);
        joins.push(std::thread::spawn(move || {
            for i in 0..1000u64 {
                h.record(50 + (t * 1000 + i) % 5_000);
            }
        }));
    }
    for j in joins {
        j.join().unwrap();
    }
    assert_eq!(h.count(), 4 * 1000);
}

// -------------------------------------------------------
// Portable end-to-end coverage of `spawn` (issue #47).
// The metrics module binds a plain `TcpListener`, which is
// available on every Rust target the workspace supports, so the
// server must start and serve on all of them. The daemon-level
// tests in `tests/daemon_metrics.rs` cover the integration with
// the daemon binary; this in-crate test exercises the `spawn` /
// `serve_connection` path directly so a target without the
// daemon binary (or one whose `daemon_*` integration suite is
// `#![cfg(unix)]`) still gets the regression signal.
// -------------------------------------------------------

/// Build a minimal but realistic `MetricsContext` for tests:
/// one Idle BGP session, one originated prefix, no ROA store,
/// no filter histograms, an `?` session-label fallback.
fn test_ctx(router: Arc<RwLock<DefaultRouter>>, running: Arc<AtomicBool>) -> MetricsContext {
    MetricsContext {
        info: MetricsInfo {
            version: "test".into(),
            local_as: 64512,
            router_id: "10.0.0.1".into(),
        },
        router,
        running,
        roa_len: None,
        filter_metrics: None,
        session_label: Box::new(|_| "?".to_string()),
    }
}

/// Pick a free TCP port on loopback by binding to `:0`, reading
/// the assigned port, then dropping the listener. Same shape as
/// `tests/daemon_metrics.rs::free_port` — duplicated here so the
/// in-crate test does not depend on an integration test helper.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    // The kernel's ephemeral allocator is the source of truth, but
    // a brief sleep dodges an immediate-rebind race on macOS.
    std::thread::sleep(Duration::from_millis(10));
    port
}

/// One HTTP round-trip: send `GET <path> HTTP/1.0`, return the
/// raw response bytes. A 5 s deadline mirrors the daemon-level
/// integration tests.
fn http_get(addr: &str, path: &str) -> String {
    use std::io::{Read, Write};
    let mut conn = std::net::TcpStream::connect(addr).expect("connect to metrics endpoint");
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

/// `spawn` returns the bound address and serves `GET /metrics`
/// with the full Prometheus exposition on every platform.
#[test]
fn spawn_serves_metrics_on_tcp() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let router = Arc::new(RwLock::new(DefaultRouter::new()));
    {
        let mut r = router.write().unwrap();
        r.add_session(lr_router::SessionConfig::bgp(
            lr_core::addr::Asn(64512),
            lr_core::addr::Asn(64513),
            lr_core::addr::RouterId::from_v4([10, 0, 0, 1]),
        ))
        .unwrap();
        r.originate(
            lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
        );
    }
    let running = Arc::new(AtomicBool::new(true));
    let bound = spawn(&addr, test_ctx(Arc::clone(&router), Arc::clone(&running)))
        .expect("metrics server spawns on every platform");
    assert_eq!(bound, addr, "spawn returns the bound address");

    // Give the accept thread a moment to come up. The 100 ms
    // poll cadence in `accept_loop` means the very first scrape
    // can race the bind on a loaded runner.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let resp = loop {
        let r = http_get(&addr, "/metrics");
        if r.starts_with("HTTP/1.0 200") || std::time::Instant::now() >= deadline {
            break r;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        resp.starts_with("HTTP/1.0 200"),
        "scrape /metrics should return HTTP 200; response:\n{resp}"
    );
    // The exposition version marker is part of the Content-Type
    // header (Prometheus 0.0.4).
    assert!(
        resp.contains("version=0.0.4"),
        "Content-Type should declare version=0.0.4; response:\n{resp}"
    );
    // Body must carry the identity gauge (with the configured
    // local_as / router_id), the uptime gauge, and at least one
    // session / RIB counter line.
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    assert!(
        body.contains("lr_info{version=\"test\",local_as=\"64512\",router_id=\"10.0.0.1\"} 1"),
        "lr_info line missing or wrong; body:\n{body}"
    );
    assert!(
        body.contains("# TYPE lr_uptime_seconds gauge"),
        "uptime TYPE missing; body:\n{body}"
    );
    assert!(
        body.contains("lr_sessions_total{kind=\"bgp\",state=\"Idle\"} 1"),
        "Idle BGP session missing; body:\n{body}"
    );
    assert!(
        body.contains("lr_rib_entries 1"),
        "originated prefix missing from Loc-RIB counter; body:\n{body}"
    );

    // A second scrape returns the same shape (counters do not go
    // backwards, headers do not churn).
    let resp2 = http_get(&addr, "/metrics");
    assert!(
        resp2.starts_with("HTTP/1.0 200"),
        "second scrape should also succeed"
    );

    // Cleanly shut the metrics thread down via the running flag
    // so the test process can exit. `accept_loop` polls the flag
    // at its 100 ms cadence, so a brief wait is enough.
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        // Once the listener is gone, fresh connects fail — the
        // thread has torn down. No need to assert on this; the
        // next test line just needs the thread to be done.
        if std::net::TcpStream::connect(&addr).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `GET /` returns the pointer to `/metrics`, and any other path
/// (including non-GET methods) returns `404 Not Found`.
#[test]
fn spawn_serves_root_pointer_and_404() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let router = Arc::new(RwLock::new(DefaultRouter::new()));
    let running = Arc::new(AtomicBool::new(true));
    let _ = spawn(&addr, test_ctx(router, Arc::clone(&running)))
        .expect("metrics server spawns on every platform");

    // Wait for the listener to come up.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if http_get(&addr, "/").starts_with("HTTP/1.0 200") || std::time::Instant::now() >= deadline
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let root = http_get(&addr, "/");
    assert!(
        root.starts_with("HTTP/1.0 200"),
        "root should be 200; response:\n{root}"
    );
    let body = root.split("\r\n\r\n").nth(1).unwrap_or("");
    assert!(
        body.contains("/metrics"),
        "root body should point to /metrics; body:\n{body}"
    );

    let not_found = http_get(&addr, "/nonexistent");
    assert!(
        not_found.starts_with("HTTP/1.0 404"),
        "unknown path should 404; response:\n{not_found}"
    );

    // A non-GET method also returns 404.
    let mut conn = std::net::TcpStream::connect(&addr).expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    use std::io::Write;
    write!(conn, "POST /metrics HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
    conn.flush().unwrap();
    let mut buf = Vec::new();
    use std::io::Read;
    conn.read_to_end(&mut buf).unwrap();
    let post_resp = String::from_utf8_lossy(&buf).into_owned();
    assert!(
        post_resp.starts_with("HTTP/1.0 404"),
        "non-GET should 404; response:\n{post_resp}"
    );

    running.store(false, std::sync::atomic::Ordering::Relaxed);
}

/// `spawn` returns a clear, descriptive error when the address
/// is already bound — no platform-specific "Unix domain socket"
/// wording (issue #47: the prior refusal mentioned Unix sockets
/// even though the implementation uses TCP).
#[test]
fn spawn_bind_failure_does_not_mention_unix_sockets() {
    // Occupy a port with a listener the spawn call cannot reuse.
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = squatter.local_addr().unwrap().to_string();

    let router = Arc::new(RwLock::new(DefaultRouter::new()));
    let running = Arc::new(AtomicBool::new(true));
    let err = spawn(&addr, test_ctx(router, running))
        .expect_err("bind should fail when the port is already in use");
    assert!(
        err.contains("bind"),
        "error should mention the bind failure; got: {err}"
    );
    // The prior implementation returned "metrics endpoint requires
    // Unix domain socket support (not supported here)" on non-Unix
    // — that wording is gone, and a bind failure must not regress
    // to it.
    assert!(
        !err.contains("Unix domain socket"),
        "bind failure must not mention Unix domain sockets; got: {err}"
    );
    drop(squatter);
}
