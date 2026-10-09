use super::*;

use lr_core::addr::Prefix;

/// Split a drained output buffer into individual BGP messages
/// (marker + 2-byte length framing). Drains can coalesce messages
/// exactly like TCP does; the wire proxy records per message.
fn split_messages(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 19 <= buf.len() {
        let len = u16::from_be_bytes([buf[i + 16], buf[i + 17]]) as usize;
        let end = i + len;
        if end > buf.len() || buf[i..i + 16].iter().any(|b| *b != 0xff) {
            break; // torn tail or garbage — the proxy would buffer
        }
        out.push(buf[i..end].to_vec());
        i = end;
    }
    out
}

fn tmp(name: &str) -> String {
    std::env::temp_dir()
        .join(format!("lr_parity_{}_{}.tmp", std::process::id(), name))
        .to_str()
        .unwrap()
        .to_string()
}

/// Drive two in-process routers through a real OPEN/KEEPALIVE/
/// UPDATE exchange, recording speaker A's *sent* bytes as a
/// capture — the exact artifact the wire proxy would have produced
/// for the reference-to-lr direction. The receiver side is driven
/// strictly from the capture file afterwards, exactly like the
/// offline replay.
fn exchange_and_capture(path: &str) {
    let mut a = DefaultRouter::new(); // the "reference" speaker
    a.set_ebgp_requires_policy(false);
    let mut b = DefaultRouter::new(); // counterparty (drives the FSM)
    b.set_ebgp_requires_policy(false);
    let ha = a
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_u32(0x0a000001),
        ))
        .unwrap();
    let hb = b
        .add_session(SessionConfig::bgp(
            Asn(64513),
            Asn(64512),
            RouterId::from_u32(0x0a000002),
        ))
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();

    // A's OPEN is the captured stream's first message.
    for msg in split_messages(&a.drain_output(ha)) {
        append_capture(path, "down", &msg).unwrap();
    }
    // Counterparty handshake (never captured). Wire-order faithful:
    // B receives A's OPEN (the captured bytes) and answers with its
    // OPEN + KEEPALIVE; A receives those and reaches Established.
    for msg in split_messages(&b.drain_output(hb)) {
        // B's own OPEN — feed it to A (it was on the wire too, but
        // the capture records the reference-to-lr direction only;
        // the replayed router synthesizes its own OPEN).
        a.feed_input(ha, &msg).unwrap();
    }
    for msg in split_messages(&a.drain_output(ha)) {
        // A's KEEPALIVE (queued on OPEN receipt) — part of the
        // reference-to-lr stream.
        if msg[18] != 3 {
            append_capture(path, "down", &msg).unwrap();
        }
    }
    // B still needs A's OPEN to leave OpenSent... but the capture
    // already has it: feed it now (wire order on B's side is not
    // the capture's concern).
    for m in read_capture(path).unwrap() {
        let bytes = hex_decode(&m.hex).unwrap();
        if bytes[18] == 1 {
            b.feed_input(hb, &bytes).unwrap(); // B: A's OPEN
            break;
        }
    }
    let b_ka = b.drain_output(hb);
    for msg in split_messages(&b_ka) {
        a.feed_input(ha, &msg).unwrap(); // A: KA received -> Established
    }
    // A is Established: capture everything it queues (KEEPALIVE,
    // End-of-RIB) except NOTIFICATIONs.
    let established_out = a.drain_output(ha);
    for msg in split_messages(&established_out) {
        if msg[18] != 3 {
            append_capture(path, "down", &msg).unwrap();
        }
    }

    // Two originated routes cross the wire as UPDATEs.
    a.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(lr_core::addr::IpAddr::V4([192, 0, 2, 9])),
    );
    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(lr_core::addr::IpAddr::V4([192, 0, 2, 9])),
    );
    for msg in split_messages(&a.drain_output(ha)) {
        if msg[18] != 3 {
            append_capture(path, "down", &msg).unwrap();
        }
    }
}

#[test]
fn parity_replay_end_to_end() {
    let capture = tmp("cap");
    let dump_b = tmp("b_mrt");
    let dump_c = tmp("c_mrt");
    let _ = std::fs::remove_file(&capture);
    exchange_and_capture(&capture);

    // Feed a receiver strictly from the captured stream — the
    // original receiver's Loc-RIB is the in-process ground truth.
    let mut b = DefaultRouter::new();
    b.set_ebgp_requires_policy(false);
    let hb = b
        .add_session(SessionConfig::bgp(
            Asn(64513),
            Asn(64512),
            RouterId::from_u32(0x0a000002),
        ))
        .unwrap();
    b.start_session(hb).unwrap();
    let _ = b.drain_output(hb); // B's own OPEN
    for m in read_capture(&capture).unwrap() {
        let bytes = hex_decode(&m.hex).unwrap();
        b.feed_input(hb, &bytes).unwrap();
        b.tick(lr_core::time::Instant(1_000_000));
        let _ = b.drain_output(hb);
        let _ = b.poll_events();
    }
    let routes: Vec<lr_core::rib::Route> = b.rib_paths_snapshot().into_iter().cloned().collect();
    assert_eq!(routes.len(), 2, "receiver must hold both routes");
    write_rib_dump(&routes, RouterId::from_u32(0x0a000002), Asn(64512), &dump_b).expect("dump B");

    // Replay the same capture through the CLI path into a fresh
    // router and dump its Loc-RIB.
    let cfg = ReplayConfig {
        capture: capture.clone(),
        direction: "down".to_string(),
        local_as: 64513,
        peer_as: 64512,
        router_id: "10.0.0.2".to_string(),
        output: dump_c.clone(),
    };
    let records = run_replay(&cfg).expect("replay must succeed");
    assert_eq!(records, 2, "replayed Loc-RIB must carry both prefixes");

    // Content parity: the replay must match the original receiver.
    let report = diff_rib_dumps(
        &lr_mrt::parse_file(&dump_b).unwrap(),
        &lr_mrt::parse_file(&dump_c).unwrap(),
    );
    assert!(
        report.is_clean(),
        "replay must match the original receiver: {report:?}"
    );
    assert_eq!(report.identical, 2);
    for f in [&capture, &dump_b, &dump_c] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn diff_reports_missing_and_mismatched_prefixes() {
    let p1 = Prefix::new_v4([198, 51, 100, 0], 24);
    let p2 = Prefix::new_v4([203, 0, 113, 0], 24);
    let entry = |nh: [u8; 4]| -> RibEntry {
        let mut attrs = vec![0x40u8, 3, 4];
        attrs.extend_from_slice(&nh);
        RibEntry {
            peer_index: 0,
            originated_time: 0,
            path_id: 0,
            attributes: attrs,
        }
    };
    let table = |prefix: lr_core::addr::Prefix, e: RibEntry| -> MrtRecord {
        MrtRecord::Rib(RibTable {
            sequence: 0,
            prefix,
            add_path: false,
            entries: vec![e],
        })
    };
    let a = vec![
        table(p1, entry([192, 0, 2, 9])),
        table(p2, entry([192, 0, 2, 9])),
    ];
    let b = vec![
        table(p1, entry([192, 0, 2, 9])),  // identical
        table(p2, entry([192, 0, 2, 10])), // next hop differs
    ];

    let report = diff_rib_dumps(&a, &b);
    assert!(!report.is_clean());
    assert_eq!(report.only_in_a.len(), 0);
    assert_eq!(report.only_in_b.len(), 0);
    assert_eq!(report.mismatched.len(), 1);
    assert_eq!(report.mismatched[0].0, p2);
    assert_eq!(report.identical, 1);

    // A prefix missing from B is reported as only-in-A.
    let report = diff_rib_dumps(&a, &b[..1]);
    assert_eq!(report.only_in_a, vec![p2]);
    assert_eq!(report.identical, 1);
}

#[test]
fn capture_json_roundtrip() {
    let capture = tmp("roundtrip");
    let _ = std::fs::remove_file(&capture);
    append_capture(&capture, "down", &[0xff, 0x00, 0xab]).unwrap();
    append_capture(&capture, "up", &[1, 2, 3]).unwrap();
    let msgs = read_capture(&capture).unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].dir, "down");
    assert_eq!(hex_decode(&msgs[0].hex).unwrap(), vec![0xff, 0x00, 0xab]);
    assert_eq!(msgs[1].dir, "up");
    assert_eq!(hex_decode(&msgs[1].hex).unwrap(), vec![1, 2, 3]);
    let _ = std::fs::remove_file(&capture);
}
