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
        igp_metric: None,
        damp_fom: None,
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
        igp_metric: None,
        damp_fom: None,
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
        igp_metric: None,
        damp_fom: None,
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
        igp_metric: None,
        damp_fom: None,
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
        igp_metric: None,
        damp_fom: None,
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
        igp_metric: None,
        damp_fom: None,
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
        igp_metric: None,
        damp_fom: None,
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
        igp_metric: None,
        damp_fom: None,
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
        igp_metric: None,
        damp_fom: None,
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

// ----- HintRecord igp_cost / damp_fom wiring (issue #92 follow-up) -----
//
// defects.txt flagged `build_record_set` for hard-coding the
// HintRecord's `igp_cost` and `damp_fom` to 0. The IGP cost is now
// wired through `EgressInput::igp_metric` (the embedder-populated
// private `LrIgpMetric` tag, RFC 4271 §9.1.2.2 step (g)). The damping
// FoM field exists on `EgressInput` for a follow-up that wires the
// daemon's `DampingTable` through a private attribute tag; the FSM
// passes `None` for now and the hint records 0 (the documented "off"
// value).

/// Pull the first `HintRecord` out of a record set, or panic. Used by
/// the wiring tests below so each can assert on the hint's fields
/// without repeating the records-walk boilerplate.
fn hint_of(out: &EgressOutput) -> HintRecord {
    out.record
        .records
        .iter()
        .find_map(|r| match r {
            Record::Hint(h) => Some(*h),
            _ => None,
        })
        .expect("HintRecord present")
}

/// `None` IGP metric (no `LrIgpMetric` tag on the route) flows through
/// to `igp_cost = 0` — the documented "off" value (design §5.1). This
/// matches the best-path comparator's "absent → u32::MAX" only in the
/// sense that both treat absent as a fixed sentinel; the hint's
/// sentinel is 0 because the hint is advisory and a 0 cost reads as
/// "no IGP information" rather than "infinite cost".
#[test]
fn build_record_set_hint_igp_cost_zero_when_metric_absent() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
        igp_metric: None,
        damp_fom: None,
    };
    let out = build_record_set(&local, &session, &input, 1).expect("records");
    let h = hint_of(&out);
    assert_eq!(h.rank, 1);
    assert_eq!(h.igp_cost, 0, "absent IGP metric falls through to 0");
    assert_eq!(h.damp_fom, 0, "absent FoM falls through to 0");
}

/// `Some(N)` IGP metric flows through unchanged: the receiver sees the
/// sender's actual IGP cost to the route's NEXT_HOP, the input the
/// RFC 4271 §9.1.2.2 tie-break assumes "all the BGP speakers within an
/// autonomous system can ascertain" but inter-AS receivers otherwise
/// cannot see (design §5.1).
#[test]
fn build_record_set_hint_igp_cost_carries_input_metric() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
        igp_metric: Some(1234),
        damp_fom: None,
    };
    let out = build_record_set(&local, &session, &input, 1).expect("records");
    let h = hint_of(&out);
    assert_eq!(
        h.igp_cost, 1234,
        "input.igp_metric flows through to HintRecord.igp_cost"
    );
    // damp_fom is still None on the input side; the hint carries 0.
    assert_eq!(h.damp_fom, 0);
}

/// `Some(N)` damping FoM flows through unchanged. The daemon's
/// follow-up that wires the `DampingTable` to populate this field
/// depends on this contract; pinning it here keeps a regression that
/// re-zeroes the FoM from silently changing the wire hint.
#[test]
fn build_record_set_hint_damp_fom_carries_input_fom() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
        igp_metric: None,
        damp_fom: Some(1500),
    };
    let out = build_record_set(&local, &session, &input, 1).expect("records");
    let h = hint_of(&out);
    assert_eq!(
        h.damp_fom, 1500,
        "input.damp_fom flows through to HintRecord.damp_fom"
    );
    assert_eq!(h.igp_cost, 0, "absent IGP metric still 0 when FoM is set");
}

/// Both fields together. The hint carries the sender's actual IGP
/// cost and damping FoM for the prefix — the receiver's policy can
/// prefer the path with the lower IGP cost (RFC 4271 §9.1.2.2 step
/// (g) input the receiver would otherwise have to approximate) and
/// avoid a path the sender is actively damping (RFC 2439 advisory).
#[test]
fn build_record_set_hint_carries_both_metric_and_fom() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
        igp_metric: Some(42),
        damp_fom: Some(750),
    };
    let out = build_record_set(&local, &session, &input, 1).expect("records");
    let h = hint_of(&out);
    assert_eq!(h.igp_cost, 42);
    assert_eq!(h.damp_fom, 750);
    assert_eq!(
        h.rank, 1,
        "rank stays 1 — the decision process is untouched"
    );
}

/// The hint's `igp_cost` round-trips through the wire codec when the
/// input carries an IGP metric. This pins the encode → decode
/// symmetry for the newly-wired field: a regression that changes the
/// byte layout (e.g. truncating to u16) would be caught here, not
/// just in the abstract record_roundtrip test above.
#[test]
fn hint_igp_cost_round_trips_through_wire() {
    let local = config_a();
    let session = session_for(&local, [0xAA; NONCE_LEN]);
    let input = EgressInput {
        local_as: 64512,
        locally_originated: true,
        prefix: &egress_prefix(),
        received: None,
        peer_as: 64513,
        igp_metric: Some(0x1234_5678),
        damp_fom: Some(0xABCD),
    };
    let out = build_record_set(&local, &session, &input, 1).expect("records");
    // Round-trip the record set through encode → decode and verify
    // the hint's fields survive byte-for-byte.
    let wire = out.record.encode();
    let decoded = ExchangeRecord::decode(&wire).expect("decodes");
    let h = hint_of(&EgressOutput {
        record: decoded,
        key_id: out.key_id,
    });
    assert_eq!(h.igp_cost, 0x1234_5678, "u32 igp_cost round-trips");
    assert_eq!(h.damp_fom, 0xABCD, "u16 damp_fom round-trips");
}
