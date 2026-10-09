
use super::*;
use crate::rtr::pdu::{decode, encode_vec, RtrPdu, RTR_VERSION_0, RTR_VERSION_1, RTR_VERSION_2};
use lr_core::addr::{Asn, Prefix};

const V: u8 = RTR_VERSION_1;
const NOW: u64 = 1_000;

fn roa(addr: [u8; 4], plen: u8, max: u8, asn: u32) -> RoaEntry {
    RoaEntry::with_max_length(Prefix::new_v4(addr, plen), max, Asn::new(asn)).unwrap()
}

fn feed(client: &mut RtrClient, pdu: &RtrPdu, now_ms: u64) -> ClientStep {
    // ASPA needs v2; encode each PDU at the session version or
    // its own minimum, whichever is higher.
    let wire = encode_vec(pdu, V.max(pdu.min_version()));
    let (ver, decoded, _) = decode(&wire).unwrap().unwrap();
    client.on_pdu(ver, &decoded, now_ms)
}

fn cache_response(session: u16) -> RtrPdu {
    RtrPdu::CacheResponse {
        session_id: session,
    }
}

fn eod(session: u16, serial: u32) -> RtrPdu {
    RtrPdu::EndOfData {
        session_id: session,
        serial,
        refresh_interval: Some(60),
        retry_interval: Some(30),
        expire_interval: Some(600),
    }
}

fn announced(entry: &RoaEntry) -> RtrPdu {
    RtrPdu::Ipv4Prefix {
        announce: true,
        prefix: entry.prefix,
        max_length: entry.max_length,
        asn: entry.asn.as_u32(),
    }
}

fn withdrawn(entry: &RoaEntry) -> RtrPdu {
    RtrPdu::Ipv4Prefix {
        announce: false,
        prefix: entry.prefix,
        max_length: entry.max_length,
        asn: entry.asn.as_u32(),
    }
}

/// Decode the first PDU in a send buffer.
fn first_query(send: &[u8]) -> RtrPdu {
    let (_v, out, _n) = decode(send).unwrap().unwrap();
    out
}

#[test]
fn cold_start_sends_reset_query_and_full_sync() {
    let mut c = RtrClient::new();
    let send = c.on_connect();
    assert_eq!(first_query(&send), RtrPdu::ResetQuery);
    assert_eq!(c.phase_name(), "awaiting-reset");

    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    let b = roa([198, 51, 100, 0], 24, 24, 64513);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &announced(&b), NOW);
    let step = feed(&mut c, &eod(0x00ff, 5), NOW);

    assert!(step.synced);
    assert!(!step.drop);
    assert_eq!(c.session_id(), Some(0x00ff));
    assert_eq!(c.serial(), Some(5));
    assert_eq!(c.phase_name(), "synced");
    assert_eq!(step.roa_deltas.len(), 2);
    assert!(step.roa_deltas.iter().all(|d| d.announce));
    let snap = c.snapshot();
    assert!(snap.contains(&a));
    assert!(snap.contains(&b));
    // Sorted: 192.0.2.0 before 198.51.100.0.
    assert_eq!(snap.first(), Some(&a));
}

#[test]
fn serial_sync_applies_incremental_deltas() {
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    let b = roa([198, 51, 100, 0], 24, 24, 64513);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &announced(&b), NOW);
    feed(&mut c, &eod(0x00ff, 5), NOW);

    // Serial query (refresh timer) then an incremental response:
    // add c, withdraw b.
    let c_net = roa([203, 0, 113, 0], 24, 24, 64514);
    let step = c.poll(NOW + 61_000);
    assert_eq!(
        first_query(&step.send),
        RtrPdu::SerialQuery {
            session_id: 0x00ff,
            serial: 5
        }
    );
    feed(&mut c, &cache_response(0x00ff), NOW + 61_000);
    feed(&mut c, &announced(&c_net), NOW + 61_000);
    feed(&mut c, &withdrawn(&b), NOW + 61_000);
    let step = feed(&mut c, &eod(0x00ff, 6), NOW + 61_000);

    assert!(step.synced);
    assert_eq!(c.serial(), Some(6));
    let announced: Vec<_> = step
        .roa_deltas
        .iter()
        .filter(|d| d.announce)
        .map(|d| d.entry)
        .collect();
    let withdrawn: Vec<_> = step
        .roa_deltas
        .iter()
        .filter(|d| !d.announce)
        .map(|d| d.entry)
        .collect();
    assert_eq!(announced, vec![c_net]);
    assert_eq!(withdrawn, vec![b]);
    assert_eq!(c.snapshot().len(), 2);
}

#[test]
fn reconnect_uses_serial_query_with_remembered_session() {
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &eod(0x00ff, 5), NOW);

    // A fresh transport connection (§8.1): the remembered
    // (session, serial) makes the first query a Serial Query.
    let send = c.on_connect();
    assert_eq!(
        first_query(&send),
        RtrPdu::SerialQuery {
            session_id: 0x00ff,
            serial: 5
        }
    );
}

#[test]
fn session_change_on_serial_response_reissues_reset() {
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &eod(0x00ff, 5), NOW);

    // Refresh, but the cache restarted: session changed.
    c.poll(NOW + 61_000);
    let step = feed(&mut c, &cache_response(0x0aaa), NOW + 61_000);
    assert_eq!(first_query(&step.send), RtrPdu::ResetQuery);
    assert_eq!(c.session_id(), Some(0x0aaa));
    assert_eq!(c.phase_name(), "awaiting-reset");
}

#[test]
fn serial_notify_triggers_immediate_query_when_synced() {
    let mut c = RtrClient::new();
    c.on_connect();
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &eod(0x00ff, 5), NOW);

    let step = feed(
        &mut c,
        &RtrPdu::SerialNotify {
            session_id: 0x00ff,
            serial: 6,
        },
        NOW + 5_000,
    );
    assert_eq!(
        first_query(&step.send),
        RtrPdu::SerialQuery {
            session_id: 0x00ff,
            serial: 5
        }
    );
}

#[test]
fn serial_notify_from_foreign_session_resets() {
    let mut c = RtrClient::new();
    c.on_connect();
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &eod(0x00ff, 5), NOW);

    let step = feed(
        &mut c,
        &RtrPdu::SerialNotify {
            session_id: 0x0bbb,
            serial: 1,
        },
        NOW + 5_000,
    );
    assert_eq!(first_query(&step.send), RtrPdu::ResetQuery);
}

#[test]
fn serial_notify_during_startup_is_ignored() {
    let mut c = RtrClient::new();
    c.on_connect();
    // §7: ignore regardless of version before the first sync.
    let step = feed(
        &mut c,
        &RtrPdu::SerialNotify {
            session_id: 1,
            serial: 9,
        },
        NOW,
    );
    assert!(step.send.is_empty());
    assert!(!step.drop);
    assert_eq!(c.phase_name(), "awaiting-reset");
}

#[test]
fn cache_reset_reissues_reset_query() {
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &eod(0x00ff, 5), NOW);
    c.poll(NOW + 61_000);

    // §8.3: the cache cannot serve the increment.
    let step = feed(&mut c, &RtrPdu::CacheReset, NOW + 61_000);
    assert_eq!(first_query(&step.send), RtrPdu::ResetQuery);
    // Records survive until the reset response replaces them.
    assert_eq!(c.snapshot().len(), 1);
}

#[test]
fn no_data_available_drops_the_session() {
    let mut c = RtrClient::new();
    c.on_connect();
    let step = feed(
        &mut c,
        &RtrPdu::ErrorReport {
            error_code: RtrErrorCode::NoDataAvailable,
            erroneous_pdu: Vec::new(),
            error_text: Some("cache warming up".into()),
        },
        NOW,
    );
    assert!(step.drop);
    // Not an expiry — the cache said "no data", the retry
    // interval governs reconnecting.
    assert!(!step.expired);
}

#[test]
fn fatal_error_report_drops_the_session() {
    let mut c = RtrClient::new();
    c.on_connect();
    let step = feed(
        &mut c,
        &RtrPdu::ErrorReport {
            error_code: RtrErrorCode::UnsupportedPduType,
            erroneous_pdu: Vec::new(),
            error_text: None,
        },
        NOW,
    );
    assert!(step.drop);
    assert!(!step.logs.is_empty());
}

#[test]
fn version_downgrades_before_first_sync() {
    let mut c = RtrClient::new();
    assert_eq!(c.version(), RTR_VERSION_2);
    // The cache answers our v2 query with v1 PDUs.
    feed(&mut c, &cache_response(1), NOW);
    assert_eq!(c.version(), RTR_VERSION_1);
    // After the first completed sync the version is frozen.
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &eod(1, 1), NOW);
    assert_eq!(c.version(), RTR_VERSION_1);
}

#[test]
fn prefix_pdu_outside_a_sync_is_ignored() {
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    let step = feed(&mut c, &announced(&a), NOW);
    assert!(!step.drop);
    assert!(!step.synced);
    assert!(c.snapshot().is_empty());
}

#[test]
fn end_of_data_session_mismatch_drops() {
    let mut c = RtrClient::new();
    c.on_connect();
    feed(&mut c, &cache_response(0x00ff), NOW);
    let step = feed(&mut c, &eod(0x0aaa, 5), NOW);
    assert!(step.drop);
    assert!(!step.synced);
}

#[test]
fn unknown_withdrawal_is_logged_noop() {
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &eod(0x00ff, 5), NOW);

    // Serial sync that withdraws something we never had.
    c.poll(NOW + 61_000);
    let ghost = roa([10, 0, 0, 0], 8, 8, 1);
    feed(&mut c, &cache_response(0x00ff), NOW + 61_000);
    let step = feed(&mut c, &withdrawn(&ghost), NOW + 61_000);
    assert!(!step.drop);
    let step = feed(&mut c, &eod(0x00ff, 6), NOW + 61_000);
    assert!(step.synced);
    assert!(step.roa_deltas.is_empty());
    assert_eq!(c.snapshot().len(), 1);
}

#[test]
fn duplicate_announcement_coalesces() {
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &announced(&a), NOW); // duplicate
    let step = feed(&mut c, &eod(0x00ff, 5), NOW);
    assert_eq!(step.roa_deltas.len(), 1);
    assert_eq!(c.snapshot().len(), 1);
}

#[test]
fn v0_end_of_data_uses_default_intervals() {
    let mut c = RtrClient::new();
    c.on_connect();
    feed(&mut c, &cache_response(1), NOW);
    let step = feed(
        &mut c,
        &RtrPdu::EndOfData {
            session_id: 1,
            serial: 3,
            refresh_interval: None,
            retry_interval: None,
            expire_interval: None,
        },
        NOW,
    );
    assert!(step.synced);
    assert_eq!(
        c.intervals(),
        (
            DEFAULT_REFRESH_INTERVAL,
            DEFAULT_RETRY_INTERVAL,
            DEFAULT_EXPIRE_INTERVAL
        )
    );
}

#[test]
fn refresh_and_expire_timers() {
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    // 60 s refresh, 600 s expire (from the eod below).
    feed(&mut c, &eod(0x00ff, 5), NOW);

    // Before refresh: nothing.
    let step = c.poll(NOW + 59_000);
    assert!(step.send.is_empty());
    // At refresh: serial query.
    let step = c.poll(NOW + 60_000);
    assert_eq!(
        first_query(&step.send),
        RtrPdu::SerialQuery {
            session_id: 0x00ff,
            serial: 5
        }
    );
    // Well past expire (no sync since): expired, no query spam.
    let step = c.poll(NOW + 700_000);
    assert!(step.expired);
    assert!(step.send.is_empty());
}

#[test]
fn router_key_and_aspa_are_accepted_but_unused() {
    let mut c = RtrClient::new();
    c.on_connect();
    feed(&mut c, &cache_response(1), NOW);
    let step = feed(
        &mut c,
        &RtrPdu::RouterKey {
            announce: true,
            ski: [0u8; 20],
            asn: 64512,
            subject_public_key_info: vec![0x30],
        },
        NOW,
    );
    assert!(!step.drop);
    let step = feed(
        &mut c,
        &RtrPdu::Aspa {
            announce: true,
            customer_asn: 64496,
            providers: vec![64500],
        },
        NOW,
    );
    assert!(!step.drop);
    let step = feed(&mut c, &eod(1, 1), NOW);
    assert!(step.synced);
    assert!(step.roa_deltas.is_empty());
}

#[test]
fn same_serial_response_produces_no_deltas() {
    // A serial query answered with the same serial (nothing new):
    // the authoritative set is unchanged.
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &eod(0x00ff, 5), NOW);

    c.poll(NOW + 61_000);
    feed(&mut c, &cache_response(0x00ff), NOW + 61_000);
    let step = feed(&mut c, &eod(0x00ff, 5), NOW + 61_000);
    assert!(step.synced);
    assert!(step.roa_deltas.is_empty());
}

#[test]
fn configured_intervals_shape_the_first_refresh() {
    // The embedder's configured intervals apply before the first
    // End of Data: a short refresh polls sooner than the default.
    let mut c = RtrClient::new();
    c.set_intervals(60, 30, 120);
    assert_eq!(c.intervals(), (60, 30, 120));
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &eod(0x00ff, 1), NOW);
    // Default refresh is 3600 s — at 61 s an unconfigured client
    // would stay quiet; this one sends its refresh Serial Query.
    let step = c.poll(NOW + 61_000);
    assert!(!step.send.is_empty());
}

#[test]
fn stray_end_of_data_is_corrupt_data_and_records_survive() {
    // A duplicate EoD after a completed sync must NOT swap the
    // (empty) batch in as authoritative — §10: corrupt data,
    // Error Report + drop, records unchanged.
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &eod(0x00ff, 1), NOW);
    assert_eq!(c.snapshot().len(), 1);

    let step = feed(&mut c, &eod(0x00ff, 1), NOW);
    assert!(step.drop);
    assert!(!step.synced);
    assert!(step.roa_deltas.is_empty());
    assert_eq!(c.snapshot().len(), 1, "records must survive a stray EoD");
    // The wire carried an Error Report (Corrupt Data).
    let (ver, pdu, _) = decode(&step.send).unwrap().unwrap();
    assert_eq!(ver, RTR_VERSION_1);
    assert!(matches!(
        pdu,
        RtrPdu::ErrorReport {
            error_code: RtrErrorCode::CorruptData,
            ..
        }
    ));

    // Same violation while a query is in flight.
    let mut c = RtrClient::new();
    c.on_connect();
    let step = feed(&mut c, &eod(0x00ff, 1), NOW);
    assert!(step.drop);
    assert!(step.roa_deltas.is_empty());
}

#[test]
fn configured_intervals_survive_v0_end_of_data() {
    // A v0 cache carries no intervals in EoD — the embedder's
    // configured values keep governing (§6: "its configured
    // defaults").
    let mut c = RtrClient::new();
    c.set_intervals(120, 45, 240);
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    // A true v0 EoD (the feed helper speaks v1, whose encoder
    // materializes defaults for the interval fields): encode at
    // version 0 and decode back.
    let wire = encode_vec(
        &RtrPdu::EndOfData {
            session_id: 0x00ff,
            serial: 1,
            refresh_interval: None,
            retry_interval: None,
            expire_interval: None,
        },
        RTR_VERSION_0,
    );
    let (ver, pdu, _) = decode(&wire).unwrap().unwrap();
    assert_eq!(ver, RTR_VERSION_0);
    assert!(matches!(
        &pdu,
        RtrPdu::EndOfData {
            refresh_interval: None,
            ..
        }
    ));
    let step = c.on_pdu(ver, &pdu, NOW);
    assert!(step.synced);
    assert_eq!(c.intervals(), (120, 45, 240));
}

#[test]
fn higher_version_pdu_is_reported_and_dropped() {
    // §5.11 / §12 code 8: the session never speaks a higher
    // version than it sent — a v2 PDU against a v1 session is a
    // violation, not a §7 upgrade.
    let mut c = RtrClient::new();
    c.on_connect();
    let a = roa([192, 0, 2, 0], 24, 24, 64512);
    feed(&mut c, &cache_response(0x00ff), NOW);
    feed(&mut c, &announced(&a), NOW);
    feed(&mut c, &eod(0x00ff, 1), NOW);
    assert_eq!(c.version(), RTR_VERSION_1);

    // A v2 Serial Notify after the sync: fatal, records intact.
    let wire = encode_vec(
        &RtrPdu::SerialNotify {
            session_id: 0x00ff,
            serial: 2,
        },
        RTR_VERSION_2,
    );
    let (ver, pdu, _) = decode(&wire).unwrap().unwrap();
    assert_eq!(ver, RTR_VERSION_2);
    let step = c.on_pdu(ver, &pdu, NOW);
    assert!(step.drop);
    assert!(matches!(
        decode(&step.send).unwrap().unwrap().1,
        RtrPdu::ErrorReport {
            error_code: RtrErrorCode::UnexpectedProtocolVersion,
            ..
        }
    ));
    assert_eq!(c.snapshot().len(), 1);
}
