//! Integration tests for the daemon ROA loader (issue #100).
//!
//! The format parsers in `lr-bgp::roa_loader_tests` cover the
//! text→entries conversion. These tests cover the daemon-side
//! concerns: mtime-based file watching, URL fetching, the
//! layer-registry union semantics and the SIGHUP-driven
//! repoint / shutdown control plane.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lr_bgp::roa::RoaState;
use lr_bgp::{RoaEntry, RoaStore};
use lr_core::addr::{Asn, Prefix};

use super::*;

fn p4(o: [u8; 4], len: u8) -> Prefix {
    Prefix::new_v4(o, len)
}

fn entry(prefix: Prefix, max: u8, asn: u32) -> RoaEntry {
    RoaEntry {
        prefix,
        max_length: max,
        asn: Asn(asn),
    }
}

fn tmp_roa_file(name: &str, body: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lr-roa-loader-test-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    path
}

// ============================================================
// RoaLayerRegistry
// ============================================================

#[test]
fn registry_replaces_one_source() {
    let store = Arc::new(RoaStore::new());
    let mut reg = RoaLayerRegistry::new();
    let e1 = entry(p4([203, 0, 113, 0], 24), 24, 64512);
    reg.replace("src-a".to_string(), vec![e1], &store);
    assert_eq!(store.len(), 1);
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::Valid
    );
}

#[test]
fn registry_unions_multiple_sources() {
    let store = Arc::new(RoaStore::new());
    let mut reg = RoaLayerRegistry::new();
    let e1 = entry(p4([203, 0, 113, 0], 24), 24, 64512);
    let e2 = entry(p4([198, 51, 100, 0], 24), 24, 64513);
    reg.replace("src-a".to_string(), vec![e1], &store);
    reg.replace("src-b".to_string(), vec![e2], &store);
    assert_eq!(store.len(), 2);
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::Valid
    );
    assert_eq!(
        store
            .load()
            .validate(&p4([198, 51, 100, 0], 24), Some(Asn(64513))),
        RoaState::Valid
    );
}

#[test]
fn registry_deduplicates_overlapping_entries() {
    let store = Arc::new(RoaStore::new());
    let mut reg = RoaLayerRegistry::new();
    let e = entry(p4([203, 0, 113, 0], 24), 24, 64512);
    reg.replace("src-a".to_string(), vec![e], &store);
    reg.replace("src-b".to_string(), vec![e], &store);
    // Same entry in two layers — counts once.
    assert_eq!(store.len(), 1);
}

#[test]
fn registry_remove_drops_one_source() {
    let store = Arc::new(RoaStore::new());
    let mut reg = RoaLayerRegistry::new();
    let e1 = entry(p4([203, 0, 113, 0], 24), 24, 64512);
    let e2 = entry(p4([198, 51, 100, 0], 24), 24, 64513);
    reg.replace("src-a".to_string(), vec![e1], &store);
    reg.replace("src-b".to_string(), vec![e2], &store);
    assert_eq!(store.len(), 2);
    reg.remove("src-a", &store);
    assert_eq!(store.len(), 1);
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::NotFound
    );
    assert_eq!(
        store
            .load()
            .validate(&p4([198, 51, 100, 0], 24), Some(Asn(64513))),
        RoaState::Valid
    );
}

#[test]
fn registry_inline_layer_is_preserved() {
    let store = Arc::new(RoaStore::new());
    let mut reg = RoaLayerRegistry::new();
    let inline = entry(p4([192, 0, 2, 0], 24), 24, 64514);
    reg.replace_inline(vec![inline], &store);
    let e1 = entry(p4([203, 0, 113, 0], 24), 24, 64512);
    reg.replace("src-a".to_string(), vec![e1], &store);
    assert_eq!(store.len(), 2);
    // Removing the source keeps the inline layer.
    reg.remove("src-a", &store);
    assert_eq!(store.len(), 1);
    assert_eq!(
        store
            .load()
            .validate(&p4([192, 0, 2, 0], 24), Some(Asn(64514))),
        RoaState::Valid
    );
}

// ============================================================
// RoaSourceSpec
// ============================================================

#[test]
fn resolve_format_explicit_pinned() {
    let spec = RoaSourceSpec {
        path: Some("/etc/lr/roas.txt".to_string()),
        url: None,
        format: Some(RoaFormat::Jq),
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    assert_eq!(spec.resolve_format().unwrap(), RoaFormat::Jq);
}

#[test]
fn resolve_format_inferred_from_extension() {
    let spec = |path: &str| RoaSourceSpec {
        path: Some(path.to_string()),
        url: None,
        format: None,
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    assert_eq!(
        spec("/etc/roas.bird").resolve_format().unwrap(),
        RoaFormat::Bird
    );
    assert_eq!(
        spec("/etc/roas.json").resolve_format().unwrap(),
        RoaFormat::Jq
    );
    assert_eq!(
        spec("/etc/roas.csv").resolve_format().unwrap(),
        RoaFormat::Awk
    );
    assert_eq!(
        spec("/etc/roas.toml").resolve_format().unwrap(),
        RoaFormat::Native
    );
}

#[test]
fn resolve_format_unknown_extension_errors() {
    let spec = RoaSourceSpec {
        path: Some("/etc/roas.bin".to_string()),
        url: None,
        format: None,
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    assert!(spec.resolve_format().is_err());
}

#[test]
fn resolve_format_for_url_uses_extension_in_path() {
    let spec = RoaSourceSpec {
        path: None,
        url: Some("https://example.com/roas.json".to_string()),
        format: None,
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    assert_eq!(spec.resolve_format().unwrap(), RoaFormat::Jq);
}

#[test]
fn resolve_interval_defaults_to_one_hour() {
    let spec = RoaSourceSpec {
        path: None,
        url: Some("https://example.com/roas.json".to_string()),
        format: None,
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    assert_eq!(spec.resolve_interval(), Duration::from_secs(3600));
}

#[test]
fn resolve_interval_clamped_to_one_minute() {
    // RFC 8210 §6 SHOULD: do not poll more often than the cache's
    // refresh interval. Clamp the operator's `interval = 1` so a
    // typo does not hammer the origin.
    let spec = RoaSourceSpec {
        path: None,
        url: Some("https://example.com/roas.json".to_string()),
        format: None,
        interval: Some(1),
        user_agent: None,
        program: None,
        program_file: None,
    };
    assert_eq!(spec.resolve_interval(), Duration::from_secs(60));
}

#[test]
fn resolve_interval_honours_operator_value() {
    let spec = RoaSourceSpec {
        path: None,
        url: Some("https://example.com/roas.json".to_string()),
        format: None,
        interval: Some(900),
        user_agent: None,
        program: None,
        program_file: None,
    };
    assert_eq!(spec.resolve_interval(), Duration::from_secs(900));
}

// ============================================================
// File source end-to-end (mtime reload)
// ============================================================

#[test]
fn loader_thread_loads_bird_file_at_startup() {
    let path = tmp_roa_file(
        "roas.bird",
        "roa 203.0.113.0/24 max 24 as 64512;\nroa 198.51.100.0/24 max 26 as 64513;\n",
    );
    let store = Arc::new(RoaStore::new());
    let registry = Arc::new(Mutex::new(RoaLayerRegistry::new()));
    let running = Arc::new(AtomicBool::new(true));
    let spec = RoaSourceSpec {
        path: Some(path.to_string_lossy().into_owned()),
        url: None,
        format: Some(RoaFormat::Bird),
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    let handle = spawn_roa_loader(spec, store.clone(), registry, running.clone());
    // Wait for the initial load to land.
    for _ in 0..50 {
        if store.len() == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(store.len(), 2, "roas did not load");
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::Valid
    );
    // Shutdown the thread.
    running.store(false, Ordering::Relaxed);
    let _ = handle.shutdown();
    // The shutdown removes the source's contribution.
    for _ in 0..50 {
        if store.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(store.is_empty(), "roa layer should be cleared on shutdown");
}

#[test]
fn loader_thread_reloads_when_file_changes() {
    let path = tmp_roa_file("roas.bird", "roa 203.0.113.0/24 max 24 as 64512;\n");
    let store = Arc::new(RoaStore::new());
    let registry = Arc::new(Mutex::new(RoaLayerRegistry::new()));
    let running = Arc::new(AtomicBool::new(true));
    let spec = RoaSourceSpec {
        path: Some(path.to_string_lossy().into_owned()),
        url: None,
        format: Some(RoaFormat::Bird),
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    let handle = spawn_roa_loader(spec, store.clone(), registry, running.clone());
    // Wait for the initial load.
    for _ in 0..50 {
        if store.len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(store.len(), 1);
    // Rewrite the file with one more entry. Bump mtime.
    std::thread::sleep(Duration::from_millis(20));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(b"roa 203.0.113.0/24 max 24 as 64512;\nroa 198.51.100.0/24 max 24 as 64513;\n")
        .unwrap();
    drop(f);
    // Wait for the mtime poll to pick up the change. The loader
    // polls every 5 s, so we wait up to 15 s.
    for _ in 0..300 {
        if store.len() == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(store.len(), 2, "roas did not reload on mtime change");
    running.store(false, Ordering::Relaxed);
    let _ = handle.shutdown();
}

#[test]
fn loader_thread_preserves_previous_snapshot_on_bad_file() {
    // Initial good file.
    let path = tmp_roa_file("roas.bird", "roa 203.0.113.0/24 max 24 as 64512;\n");
    let store = Arc::new(RoaStore::new());
    let registry = Arc::new(Mutex::new(RoaLayerRegistry::new()));
    let running = Arc::new(AtomicBool::new(true));
    let spec = RoaSourceSpec {
        path: Some(path.to_string_lossy().into_owned()),
        url: None,
        format: Some(RoaFormat::Bird),
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    let handle = spawn_roa_loader(spec, store.clone(), registry, running.clone());
    for _ in 0..50 {
        if store.len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(store.len(), 1);
    // Corrupt the file — a typo'd prefix must not weaken the live
    // table.
    std::thread::sleep(Duration::from_millis(20));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(b"roa not-a-prefix max 24 as 64512;\n").unwrap();
    drop(f);
    // Wait for the mtime poll to pick up the change.
    std::thread::sleep(Duration::from_millis(500));
    // The previous snapshot is preserved.
    assert_eq!(
        store.len(),
        1,
        "roa table must keep the previous snapshot on parse error"
    );
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::Valid
    );
    running.store(false, Ordering::Relaxed);
    let _ = handle.shutdown();
}

#[test]
fn loader_thread_supports_jq_format() {
    // The jq transform program reads Routinator JSON on stdin and
    // emits BIRD-format lines on stdout. The loader parses the
    // program's stdout with `parse_bird`.
    let path = tmp_roa_file(
        "roas.json",
        r#"{"roas":[{"asn":"AS64512","prefix":"203.0.113.0/24","maxLength":24}]}"#,
    );
    let store = Arc::new(RoaStore::new());
    let registry = Arc::new(Mutex::new(RoaLayerRegistry::new()));
    let running = Arc::new(AtomicBool::new(true));
    let spec = RoaSourceSpec {
        path: Some(path.to_string_lossy().into_owned()),
        url: None,
        format: Some(RoaFormat::Jq),
        interval: None,
        user_agent: None,
        program: Some(r#".roas[] | "roa \(.prefix) max \(.maxLength) as \(.asn);""#.to_string()),
        program_file: None,
    };
    let handle = spawn_roa_loader(spec, store.clone(), registry, running.clone());
    for _ in 0..100 {
        if store.len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        store.len(),
        1,
        "jq format: entries did not load. status: {}",
        handle.status_line()
    );
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::Valid
    );
    running.store(false, Ordering::Relaxed);
    let _ = handle.shutdown();
}

#[test]
fn loader_thread_supports_awk_format() {
    // The awk transform program reads CSV on stdin and emits BIRD
    // lines on stdout. The loader parses the program's stdout with
    // `parse_bird`.
    let path = tmp_roa_file(
        "roas.csv",
        "ASN,Prefix,MaxLength,TrustAnchor\nAS64512,203.0.113.0/24,24,ripe\n",
    );
    let store = Arc::new(RoaStore::new());
    let registry = Arc::new(Mutex::new(RoaLayerRegistry::new()));
    let running = Arc::new(AtomicBool::new(true));
    let spec = RoaSourceSpec {
        path: Some(path.to_string_lossy().into_owned()),
        url: None,
        format: Some(RoaFormat::Awk),
        interval: None,
        user_agent: None,
        program: Some(
            r#"BEGIN{FS=","} NR>1 { printf "roa %s max %s as %s;\n", $2, $3, $1 }"#.to_string(),
        ),
        program_file: None,
    };
    let handle = spawn_roa_loader(spec, store.clone(), registry, running.clone());
    for _ in 0..100 {
        if store.len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        store.len(),
        1,
        "awk format: entries did not load. status: {}",
        handle.status_line()
    );
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::Valid
    );
    running.store(false, Ordering::Relaxed);
    let _ = handle.shutdown();
}

#[test]
fn loader_thread_status_line_reports_state() {
    let path = tmp_roa_file("roas.bird", "roa 203.0.113.0/24 max 24 as 64512;\n");
    let store = Arc::new(RoaStore::new());
    let registry = Arc::new(Mutex::new(RoaLayerRegistry::new()));
    let running = Arc::new(AtomicBool::new(true));
    let spec = RoaSourceSpec {
        path: Some(path.to_string_lossy().into_owned()),
        url: None,
        format: Some(RoaFormat::Bird),
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    let handle = spawn_roa_loader(spec, store.clone(), registry, running.clone());
    for _ in 0..50 {
        if store.len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let line = handle.status_line();
    assert!(line.contains("roa-source:"), "line: {line}");
    assert!(line.contains("type=file"), "line: {line}");
    assert!(line.contains("format=bird"), "line: {line}");
    assert!(line.contains("entries=1"), "line: {line}");
    assert!(line.contains("state=ok"), "line: {line}");
    running.store(false, Ordering::Relaxed);
    let _ = handle.shutdown();
}

#[test]
fn loader_thread_repoint_changes_path() {
    let path_a = tmp_roa_file("a.bird", "roa 203.0.113.0/24 max 24 as 64512;\n");
    let path_b = tmp_roa_file("b.bird", "roa 198.51.100.0/24 max 24 as 64513;\n");
    let store = Arc::new(RoaStore::new());
    let registry = Arc::new(Mutex::new(RoaLayerRegistry::new()));
    let running = Arc::new(AtomicBool::new(true));
    let spec_a = RoaSourceSpec {
        path: Some(path_a.to_string_lossy().into_owned()),
        url: None,
        format: Some(RoaFormat::Bird),
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    let handle = spawn_roa_loader(spec_a, store.clone(), registry, running.clone());
    for _ in 0..50 {
        if store.len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(store.len(), 1);
    // Repoint to a different file.
    let spec_b = RoaSourceSpec {
        path: Some(path_b.to_string_lossy().into_owned()),
        url: None,
        format: Some(RoaFormat::Bird),
        interval: None,
        user_agent: None,
        program: None,
        program_file: None,
    };
    handle.repoint(spec_b);
    // Wait for the repoint to land. The old source's entry
    // should be replaced by the new source's entry.
    for _ in 0..100 {
        if store
            .load()
            .validate(&p4([198, 51, 100, 0], 24), Some(Asn(64513)))
            == RoaState::Valid
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        store
            .load()
            .validate(&p4([198, 51, 100, 0], 24), Some(Asn(64513))),
        RoaState::Valid,
        "repointed source should validate the new prefix"
    );
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::NotFound,
        "repointed source should drop the old prefix"
    );
    running.store(false, Ordering::Relaxed);
    let _ = handle.shutdown();
}

// ============================================================
// URL source end-to-end (against a local HTTP server)
// ============================================================

#[test]
fn loader_thread_fetches_url() {
    use std::net::TcpListener;
    // Spin up a tiny HTTP server that serves a JSON ROA dump.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = r#"{"roas":[{"asn":"AS64512","prefix":"203.0.113.0/24","maxLength":24}]}"#;
    let body_clone = body.to_string();
    let server = std::thread::spawn(move || {
        // Accept exactly one connection, serve the JSON body, exit.
        let mut s = listener.accept().unwrap().0;
        let mut buf = [0u8; 1024];
        let _ = std::io::Read::read(&mut s, &mut buf);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body_clone.len(),
            body_clone
        );
        let _ = std::io::Write::write_all(&mut s, resp.as_bytes());
    });
    let store = Arc::new(RoaStore::new());
    let registry = Arc::new(Mutex::new(RoaLayerRegistry::new()));
    let running = Arc::new(AtomicBool::new(true));
    let spec = RoaSourceSpec {
        path: None,
        url: Some(format!("http://{addr}/roas.json")),
        format: Some(RoaFormat::Jq),
        interval: Some(60),
        user_agent: None,
        program: Some(r#".roas[] | "roa \(.prefix) max \(.maxLength) as \(.asn);""#.to_string()),
        program_file: None,
    };
    let handle = spawn_roa_loader(spec, store.clone(), registry, running.clone());
    for _ in 0..100 {
        if store.len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(store.len(), 1, "roas did not load from URL");
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::Valid
    );
    running.store(false, Ordering::Relaxed);
    let _ = handle.shutdown();
    let _ = server.join();
}

#[test]
fn loader_thread_url_fetch_failure_keeps_previous_snapshot() {
    use std::net::TcpListener;
    // Initial URL: a server that serves a single ROA, then shuts
    // down. The second poll cycle will fail to connect.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body =
        r#"{"roas":[{"asn":"AS64512","prefix":"203.0.113.0/24","maxLength":24}]}"#.to_string();
    let server = std::thread::spawn(move || {
        // Serve exactly one request, then exit (the next fetch
        // will fail to connect — that is the test's intent).
        let mut s = listener.accept().unwrap().0;
        let mut buf = [0u8; 1024];
        let _ = std::io::Read::read(&mut s, &mut buf);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = std::io::Write::write_all(&mut s, resp.as_bytes());
    });
    let store = Arc::new(RoaStore::new());
    let registry = Arc::new(Mutex::new(RoaLayerRegistry::new()));
    let running = Arc::new(AtomicBool::new(true));
    let spec = RoaSourceSpec {
        path: None,
        url: Some(format!("http://{addr}/roas.json")),
        format: Some(RoaFormat::Jq),
        interval: Some(60),
        user_agent: None,
        program: Some(r#".roas[] | "roa \(.prefix) max \(.maxLength) as \(.asn);""#.to_string()),
        program_file: None,
    };
    let handle = spawn_roa_loader(spec, store.clone(), registry, running.clone());
    for _ in 0..100 {
        if store.len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(store.len(), 1);
    let _ = server.join();
    // The next poll cycle (after the server shut down) must NOT
    // drop the existing snapshot.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        store.len(),
        1,
        "previous snapshot must survive a fetch failure"
    );
    assert_eq!(
        store
            .load()
            .validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
        RoaState::Valid
    );
    running.store(false, Ordering::Relaxed);
    let _ = handle.shutdown();
}

// ============================================================
// Status line shape
// ============================================================

#[test]
fn status_line_includes_error_when_unhealthy() {
    let st = RoaLoaderStatus {
        source: "/etc/lr/roas.bird".to_string(),
        is_url: false,
        entries: 0,
        healthy: false,
        last_load_age_s: None,
        last_error: Some("io: read failed".to_string()),
        format: "bird",
        has_program: false,
    };
    let line = st.status_line();
    assert!(line.contains("state=error"), "line: {line}");
    assert!(line.contains("error=\"io: read failed\""), "line: {line}");
}

#[test]
fn status_line_includes_age_when_loaded() {
    let st = RoaLoaderStatus {
        source: "https://example.com/roas.json".to_string(),
        is_url: true,
        entries: 42,
        healthy: true,
        last_load_age_s: Some(300),
        last_error: None,
        format: "jq",
        has_program: true,
    };
    let line = st.status_line();
    assert!(line.contains("type=url"), "line: {line}");
    assert!(line.contains("format=jq"), "line: {line}");
    assert!(line.contains("entries=42"), "line: {line}");
    assert!(line.contains("state=ok"), "line: {line}");
    assert!(line.contains("last-load=300s"), "line: {line}");
}
