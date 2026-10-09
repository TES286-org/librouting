
extern crate std;

use super::*;

fn config_a() -> ExchangePlaneConfig {
    ExchangePlaneConfig {
        hints: true,
        provenance: true,
        nonce: [1, 2, 3, 4, 5, 6, 7, 8],
        keys: vec![
            ExchangeKey::hmac_sha256(1, "alpha"),
            ExchangeKey::hmac_sha256(2, "beta"),
        ],
        policy_role: None,
        policy_import_digest: None,
        policy_export_digest: None,
        provenance_scope: 8,
        origin_base_secs: 1_700_000_000,
        origin_ttl_secs: 86_400,
    }
}

fn config_b() -> ExchangePlaneConfig {
    ExchangePlaneConfig {
        hints: true,
        provenance: false,
        nonce: [8, 7, 6, 5, 4, 3, 2, 1],
        keys: vec![
            ExchangeKey::hmac_sha256(2, "beta"),
            ExchangeKey::hmac_sha256(3, "gamma"),
        ],
        policy_role: None,
        policy_import_digest: None,
        policy_export_digest: None,
        provenance_scope: 8,
        origin_base_secs: 1_700_000_000,
        origin_ttl_secs: 86_400,
    }
}

#[test]
fn capability_roundtrip() {
    let cfg = config_a();
    let cap = cfg.capability();
    assert_eq!(cap.code.to_u8(), CAPABILITY_CODE);
    let open = parse_capability(&cap).expect("parses");
    assert_eq!(open.version, VERSION);
    assert_eq!(open.flags, cfg.flags());
    assert_eq!(open.nonce, cfg.nonce);
    assert_eq!(
        open.offered_keys,
        vec![(1, KeyAlg::HmacSha256), (2, KeyAlg::HmacSha256)]
    );
}

#[test]
fn parse_ignores_other_capabilities() {
    let cap = Capability::route_refresh();
    assert!(parse_capability(&cap).is_none());
}

#[test]
fn parse_rejects_truncated_value() {
    let mut cap = config_a().capability();
    cap.value.truncate(5);
    assert!(parse_capability(&cap).is_none());
}

#[test]
fn negotiation_activates_on_intersection() {
    let session = negotiate(
        &config_a(),
        &parse_capability(&config_b().capability()).unwrap(),
    )
    .expect("key 2 is shared");
    assert_eq!(session.keys.len(), 1);
    assert_eq!(session.keys[0].id, 2);
    assert_eq!(session.peer_nonce, [8, 7, 6, 5, 4, 3, 2, 1]);
}

#[test]
fn negotiation_deactivates_without_shared_keys() {
    let mut peer = config_b();
    peer.keys = vec![ExchangeKey::hmac_sha256(9, "delta")];
    let open = parse_capability(&peer.capability()).unwrap();
    assert!(negotiate(&config_a(), &open).is_none());
}

#[test]
fn negotiation_deactivates_on_version_mismatch() {
    let mut peer = config_b();
    let mut cap = peer.capability();
    cap.value[0] = VERSION + 1;
    peer.nonce = cap.value[2..10].try_into().unwrap();
    let open = parse_capability(&cap).unwrap();
    assert!(negotiate(&config_a(), &open).is_none());
}

#[test]
fn record_roundtrip_all_classes() {
    let mut record = ExchangeRecord::new(SCOPE_LINK_LOCAL, 2, [0xAA; NONCE_LEN], 42);
    record.records.push(Record::Hint(HintRecord {
        rank: 1,
        damp_fom: 1500,
        igp_cost: 30,
    }));
    record.records.push(Record::Policy(PolicyIntent {
        role: ROLE_CUSTOMER,
        import_digest: [1; 8],
        export_digest: [2; 8],
    }));
    record.records.push(Record::Origin(OriginAttestation {
        origin_as: 64512,
        max_valid_len: 24,
        expiry: 1_800_000_000,
    }));
    record.records.push(Record::Segment(PathSegmentSig {
        asn: 64512,
        digest: [7; 32],
    }));
    // An unknown-class TLV the receiver of a newer version might
    // add — class 200, value 4 bytes. The decoder must skip it.
    let mut bytes = record.encode();
    bytes.extend_from_slice(&[200, 0, 4, 0xDE, 0xAD, 0xBE, 0xEF]);
    let decoded = ExchangeRecord::decode(&bytes).expect("decodes");
    assert_eq!(decoded.version, VERSION);
    assert_eq!(decoded.scope, SCOPE_LINK_LOCAL);
    assert_eq!(decoded.key_id, 2);
    assert_eq!(decoded.sequence, 42);
    assert_eq!(decoded.nonce_echo, [0xAA; NONCE_LEN]);
    assert_eq!(decoded.records, record.records);
    assert!(decoded.tag.is_none());
}

#[test]
fn truncated_tlv_is_an_error() {
    let mut record = ExchangeRecord::new(1, 1, [0; NONCE_LEN], 1);
    record.records.push(Record::Hint(HintRecord {
        rank: 1,
        damp_fom: 0,
        igp_cost: 0,
    }));
    let mut bytes = record.encode();
    bytes.truncate(bytes.len() - 2);
    assert_eq!(
        ExchangeRecord::decode(&bytes),
        Err(ExchangePlaneError::Truncated)
    );
}

#[test]
fn bad_version_is_an_error() {
    let mut record = ExchangeRecord::new(1, 1, [0; NONCE_LEN], 1);
    record.version = VERSION + 1;
    let bytes = record.encode();
    assert_eq!(
        ExchangeRecord::decode(&bytes),
        Err(ExchangePlaneError::BadVersion)
    );
}

#[test]
fn sign_and_verify_roundtrip() {
    let key = ExchangeKey::hmac_sha256(2, "beta");
    let mut record = ExchangeRecord::new(1, 2, [0; NONCE_LEN], 7);
    record.records.push(Record::Origin(OriginAttestation {
        origin_as: 64512,
        max_valid_len: 24,
        expiry: 1_800_000_000,
    }));
    record.sign(&key);
    assert!(record.verify(&key));
    assert!(!record.verify(&ExchangeKey::hmac_sha256(2, "wrong")));
    // Any tampering breaks the tag.
    let mut bytes = record.encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let decoded = ExchangeRecord::decode(&bytes).unwrap();
    assert!(!decoded.verify(&key));
}

#[test]
fn unsigned_record_never_verifies() {
    let key = ExchangeKey::hmac_sha256(1, "alpha");
    let record = ExchangeRecord::new(1, 1, [0; NONCE_LEN], 7);
    assert!(!record.verify(&key));
}

#[test]
fn duplicate_tag_is_an_error() {
    let key = ExchangeKey::hmac_sha256(1, "alpha");
    let mut record = ExchangeRecord::new(1, 1, [0; NONCE_LEN], 7);
    record.sign(&key);
    let bytes = record.encode();
    // Append the tag TLV a second time.
    let mut twice = bytes.clone();
    let tag_start = bytes.len() - 3 - TAG_LEN;
    twice.extend_from_slice(&bytes[tag_start..]);
    assert_eq!(
        ExchangeRecord::decode(&twice),
        Err(ExchangePlaneError::BadLength)
    );
}

#[test]
fn attribute_is_optional_transitive() {
    // O=1 T=1 (design §4): non-lr transit forwards with Partial set.
    assert_eq!(ExchangeRecord::attribute_flags(), 0b1100_0000);
}

#[test]
fn replay_accepts_fresh_and_rejects_stale() {
    let local_nonce = [9; NONCE_LEN];
    let mut tracker = ReplayTracker::new();
    assert_eq!(
        tracker.accept(1, 10, &local_nonce, &local_nonce),
        ReplayDecision::Accept
    );
    assert_eq!(
        tracker.accept(1, 10, &local_nonce, &local_nonce),
        ReplayDecision::StaleSequence
    );
    assert_eq!(
        tracker.accept(1, 5, &local_nonce, &local_nonce),
        ReplayDecision::StaleSequence
    );
    assert_eq!(
        tracker.accept(1, 11, &local_nonce, &local_nonce),
        ReplayDecision::Accept
    );
    // Independent sequence spaces per key id.
    assert_eq!(
        tracker.accept(2, 1, &local_nonce, &local_nonce),
        ReplayDecision::Accept
    );
}

#[test]
fn replay_rejects_foreign_session_nonce() {
    let local_nonce = [9; NONCE_LEN];
    let foreign = [8; NONCE_LEN];
    let mut tracker = ReplayTracker::new();
    assert_eq!(
        tracker.accept(1, 10, &foreign, &local_nonce),
        ReplayDecision::ForeignSession
    );
}

#[test]
fn replay_resets_on_new_session_instance() {
    let mut tracker = ReplayTracker::new();
    let local_nonce = [9; NONCE_LEN];
    assert_eq!(
        tracker.accept(1, 100, &local_nonce, &local_nonce),
        ReplayDecision::Accept
    );
    tracker.reset();
    assert_eq!(
        tracker.accept(1, 1, &local_nonce, &local_nonce),
        ReplayDecision::Accept
    );
}

// ----- egress record-set construction (W6.3 follow-up) -----

fn session_for(local: &ExchangePlaneConfig, peer_nonce: [u8; 8]) -> ExchangePlaneSession {
    ExchangePlaneSession {
        version: VERSION,
        peer_flags: FLAG_HINTS_CAPABLE | FLAG_PROVENANCE_CAPABLE,
        peer_nonce,
        local_nonce: local.nonce,
        keys: local.keys.clone(),
    }
}

fn egress_prefix() -> lr_core::addr::Prefix {
    lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24)
}

#[test]
fn build_record_set_originates_full_set() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    let mut local = local;
    local.policy_role = Some(ROLE_CUSTOMER);
    local.policy_import_digest = Some([1; 8]);
    local.policy_export_digest = Some([2; 8]);
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
    };
    let out = build_record_set(&local, &session, &input, 1).expect("records attached");
    // Hint + policy (scope 1) + origin attestation + our segment sig.
    assert!(matches!(out.record.records[0], Record::Hint(_)));
    assert!(matches!(out.record.records[1], Record::Policy(p) if p.role == ROLE_CUSTOMER));
    let origin = out
        .record
        .records
        .iter()
        .find_map(|r| match r {
            Record::Origin(o) => Some(*o),
            _ => None,
        })
        .expect("origin attestation");
    assert_eq!(origin.origin_as, 64512);
    assert_eq!(origin.max_valid_len, 24);
    assert_eq!(origin.expiry, 1_700_000_000 + 86_400);
    assert!(matches!(
        out.record.records.last(),
        Some(Record::Segment(s)) if s.asn == 64512
    ));
    // Scope carries the originator's budget.
    assert_eq!(out.record.scope, 8);
    // The tag verifies under the negotiated key and echoes the peer
    // nonce (design §6).
    assert_eq!(out.record.nonce_echo, [0xAA; NONCE_LEN]);
    assert!(out.record.verify(&session.keys[0]));
}

#[test]
fn build_record_set_skips_unenabled_classes() {
    let mut local = config_a();
    local.hints = false;
    local.provenance = false;
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
    };
    assert!(build_record_set(&local, &session, &input, 1).is_none());
}

#[test]
fn build_record_set_gates_on_peer_flags() {
    // The peer did not advertise the provenance flag: no provenance
    // records even though the local side is willing (design §5 —
    // every class is only meaningful with the receiver's consent).
    let local = config_a();
    let mut session = session_for(&local, [0xAA; NONCE_LEN]);
    session.peer_flags = FLAG_HINTS_CAPABLE;
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
    };
    let out = build_record_set(&local, &session, &input, 1).expect("hint still attached");
    assert_eq!(out.record.records.len(), 1);
    assert!(matches!(out.record.records[0], Record::Hint(_)));
    assert_eq!(out.record.scope, 1);
}

#[test]
fn build_record_set_exhausted_scope_strips_provenance() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    // A received set at scope 1 has no budget left (§7: scope 0
    // strips the attribute entirely).
    let mut received = ExchangeRecord::new(1, 1, [0xAA; NONCE_LEN], 5);
    received.records.push(Record::Origin(OriginAttestation {
        origin_as: 65000,
        max_valid_len: 24,
        expiry: 999,
    }));
    let input = EgressInput {
        local_as: 64512,
        locally_originated: false,
        prefix: &egress_prefix(),
        received: Some(&received),
        peer_as: 64513,
    };
    // Hints are still rebuilt fresh (they are ours, not relayed).
    let out = build_record_set(&local, &session, &input, 1).expect("hint attached");
    assert!(out
        .record
        .records
        .iter()
        .all(|r| matches!(r, Record::Hint(_) | Record::Policy(_)),));
}

#[test]
fn build_record_set_relays_and_re_signs_chain() {
    let upstream = config_a();
    let upstream_session = session_for(&upstream, [0xBB; NONCE_LEN]);
    let upstream_input = EgressInput {
        local_as: 65000,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64512,
    };
    let first = build_record_set(&upstream, &upstream_session, &upstream_input, 1).expect("origin");

    // The downstream hop forwards the received chain with the scope
    // decremented and its own signature appended.
    let down = config_b();
    let mut down = down;
    down.provenance = true;
    let down_session = session_for(&down, [0xCC; NONCE_LEN]);
    let down_input = EgressInput {
        local_as: 64512,
        locally_originated: false,
        prefix: &egress_prefix(),
        received: Some(&first.record),
        peer_as: 64513,
    };
    let second = build_record_set(&down, &down_session, &down_input, 1).expect("chain forwarded");
    assert_eq!(second.record.scope, first.record.scope - 1);
    // Origin attestation + upstream segment + own segment.
    let segments: Vec<&PathSegmentSig> = second
        .record
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Segment(s) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[1].asn, 64512);
    // The whole chain verifies with both hops' keys (the receiver's
    // validation walk, design §5.3).
    let keys = vec![
        (65000u32, upstream_session.keys[0].clone()),
        (64512u32, down_session.keys[0].clone()),
    ];
    let (path, broken) = verify_provenance_chain(&second.record.records, &keys);
    assert!(broken.is_none());
    assert_eq!(path, vec![(65000, 65000), (64512, 65000)]);
}

#[test]
fn build_record_set_drops_headless_chain() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    // A received set whose origin attestation went missing (e.g. a
    // truncated hop) is not forwardable.
    let mut received = ExchangeRecord::new(4, 1, [0xAA; NONCE_LEN], 5);
    received.records.push(Record::Segment(PathSegmentSig {
        asn: 65000,
        digest: [7; 32],
    }));
    let input = EgressInput {
        local_as: 64512,
        locally_originated: false,
        prefix: &egress_prefix(),
        received: Some(&received),
        peer_as: 64513,
    };
    let out = build_record_set(&local, &session, &input, 1).expect("hint still attached");
    assert!(!out
        .record
        .records
        .iter()
        .any(|r| matches!(r, Record::Origin(_) | Record::Segment(_))));
}

#[test]
fn store_roundtrips() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
    };
    let out = build_record_set(&local, &session, &input, 1).expect("records");
    let stored = store_verified(&out.record);
    let (kind, payload) = load_store(&stored).expect("verified store");
    assert_eq!(kind, STORE_VERIFIED);
    let decoded = ExchangeRecord::decode(payload).unwrap();
    assert_eq!(decoded, out.record);

    let raw_store = store_partial_raw(&[1, 2, 3]);
    let (kind, raw) = load_store(&raw_store).expect("raw store");
    assert_eq!(kind, STORE_PARTIAL_RAW);
    assert_eq!(raw, &[1, 2, 3]);

    assert!(load_store(&[9, 0]).is_none(), "unknown kind rejected");
}

#[test]
fn chain_verification_detects_tampering() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
    };
    let out = build_record_set(&local, &session, &input, 1).expect("records");
    let keys = vec![(64512u32, session.keys[0].clone())];
    let (path, broken) = verify_provenance_chain(&out.record.records, &keys);
    assert!(broken.is_none() && path.len() == 1);

    // Flip one bit in the segment digest: the chain breaks there.
    let mut tampered = out.record.records.clone();
    if let Some(Record::Segment(s)) = tampered.last_mut() {
        s.digest[0] ^= 0x01;
    }
    let (_, broken) = verify_provenance_chain(&tampered, &keys);
    assert_eq!(broken, Some(0));
}
