use super::*;

#[test]
fn strip_ipv4_header_extracts_ospf() {
    let pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        7,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    // Simulate a raw-socket datagram: 20-byte IP header (protocol 89)
    // in front of the OSPF packet.
    let mut dg = vec![0u8; 20];
    dg[0] = 0x45; // IPv4, IHL 5
    dg[9] = 89; // OSPF
    dg.extend_from_slice(&pkt);
    let stripped = strip_ipv4_header(&dg).unwrap();
    assert_eq!(stripped, &pkt[..]);
    // Non-OSPF protocol, wrong version, truncated → None.
    let mut other = dg.clone();
    other[9] = 6; // TCP
    assert!(strip_ipv4_header(&other).is_none());
    let mut v6 = dg.clone();
    v6[0] = 0x65;
    assert!(strip_ipv4_header(&v6).is_none());
    assert!(strip_ipv4_header(&dg[..12]).is_none());
}

#[test]
fn demux_header_parses_and_rejects() {
    let pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        7,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![0x0a00_0002],
    )
    .unwrap();
    let (rid, area, len) = demux_header(&pkt).unwrap();
    assert_eq!(rid, 0x0a00_0001);
    assert_eq!(area, 7);
    assert_eq!(len as usize, pkt.len());
    // Short / wrong version / bad length → None.
    assert!(demux_header(&pkt[..20]).is_none());
    let mut v3 = pkt.clone();
    v3[0] = 3;
    assert!(demux_header(&v3).is_none());
    let mut bad_len = pkt.clone();
    bad_len[3] = 0xff; // length > buffer
    assert!(demux_header(&bad_len).is_none());
}

#[test]
fn area_kind_mapping() {
    use lr_router::OspfAreaType;
    let mut spec = OspfAreaSpec {
        id: Some(1),
        kind: Some("stub".into()),
        no_summary: Some(false),
        stub_metric: Some(42),
    };
    assert_eq!(area_kind(&spec), Some(OspfAreaType::stub(42)));
    spec.no_summary = Some(true);
    assert_eq!(area_kind(&spec), Some(OspfAreaType::stub_no_summary(42)));
    spec.kind = Some("nssa".into());
    assert_eq!(area_kind(&spec), Some(OspfAreaType::nssa_no_summary(42)));
    spec.no_summary = Some(false);
    spec.stub_metric = None;
    assert_eq!(
        area_kind(&spec),
        Some(OspfAreaType::nssa(DEFAULT_STUB_METRIC))
    );
    // normal / unset → no router call needed.
    spec.kind = None;
    assert_eq!(area_kind(&spec), None);
    spec.kind = Some("normal".into());
    assert_eq!(area_kind(&spec), None);
}

// ---------------------------------------------------------------------------
// OSPFv2 SimplePassword auth — RFC 2328 §D wiring.
// The daemon signs every outgoing packet with the configured password
// (au_type = 1 + 8-byte auth_data) and drops received packets whose
// au_type or auth_data do not match (§D.1 "If the authentication
// proves unsuccessful, the packet is dropped"). Crypto auth (AuType 2,
// RFC 5709) is a follow-up — the wire codec and `CryptoAuth` helper
// already exist in `lr_ospf::auth::crypto`; the daemon wiring
// (per-packet trailer append + anti-replay state) is the next slice.
// ---------------------------------------------------------------------------

/// A freshly encoded OSPFv2 Hello with no auth applied has au_type = 0
/// (NullAuth) and an all-zero auth_data field — the codec default.
#[test]
fn build_hello_emits_null_auth_by_default() {
    let pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    // au_type is at offset 14..16, auth_data at 16..24.
    assert_eq!(
        u16::from_be_bytes([pkt[14], pkt[15]]),
        0,
        "NullAuth au_type"
    );
    assert_eq!(&pkt[16..24], &[0u8; 8], "all-zero auth_data");
}

/// `apply_ospf_auth(None, ...)` is a no-op: the packet is unchanged.
/// Returns `false` so the caller knows the existing checksum stands.
#[test]
fn apply_ospf_auth_null_is_noop() {
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    finalize_v2_packet(&mut pkt);
    let before = pkt.clone();
    let mut auth = OspfAuthState::None;
    let applied = apply_ospf_auth(&mut auth, &mut pkt);
    assert!(!applied, "NullAuth apply returns false");
    assert_eq!(pkt, before, "NullAuth apply is a no-op");
}

/// `apply_ospf_auth(Some(...), ...)` writes au_type = 1, the password
/// into auth_data, and zeroes the checksum (so the caller can
/// `finalize_v2_packet` to recompute). Returns `true`.
#[test]
fn apply_ospf_auth_simple_password_writes_au_type_and_auth_data() {
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    finalize_v2_packet(&mut pkt); // router-like checksum
    let mut auth = OspfAuthState::Simple(lr_ospf::auth::SimplePassword::new(b"secret12"));
    let applied = apply_ospf_auth(&mut auth, &mut pkt);
    assert!(applied, "SimplePassword apply returns true");
    assert_eq!(
        u16::from_be_bytes([pkt[14], pkt[15]]),
        1,
        "au_type = 1 (SimplePassword)"
    );
    assert_eq!(&pkt[16..24], b"secret12", "auth_data = password");
    assert_eq!(
        u16::from_be_bytes([pkt[12], pkt[13]]),
        0,
        "checksum zeroed (caller must finalize_v2_packet)"
    );
}

/// After apply + finalize, the packet carries a valid §A.1 checksum
/// (the v2_packet_checksum_ok verifier confirms). This is the contract
/// every send path in the daemon relies on.
#[test]
fn apply_ospf_auth_then_finalize_produces_valid_checksum() {
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    let mut auth = OspfAuthState::Simple(lr_ospf::auth::SimplePassword::new(b"secure!!!"));
    apply_ospf_auth(&mut auth, &mut pkt);
    finalize_v2_packet(&mut pkt);
    assert!(
        v2_packet_checksum_ok(&pkt),
        "post-auth finalize produces a §A.1-valid checksum"
    );
}

/// `verify_ospf_auth(None, ...)` accepts every packet (NullAuth).
#[test]
fn verify_ospf_auth_null_accepts_everything() {
    let pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    let mut auth = OspfAuthState::None;
    assert!(verify_ospf_auth(&mut auth, &pkt), "NullAuth accepts");
    // Even a packet with au_type = 1 is accepted under NullAuth (the
    // RFC says AuType 0 is "no authentication" — the auth_data field is
    // ignored). The receive path's gate is the configured auth, not
    // the wire au_type.
    let mut au1 = pkt.clone();
    au1[14..16].copy_from_slice(&1u16.to_be_bytes());
    assert!(
        verify_ospf_auth(&mut auth, &au1),
        "NullAuth ignores wire au_type"
    );
}

/// `verify_ospf_auth(Some(...), ...)` accepts a packet signed with
/// the same password and rejects one with a different password, a
/// different au_type, or a truncated header.
#[test]
fn verify_ospf_auth_simple_password_round_trip() {
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    let mut auth = OspfAuthState::Simple(lr_ospf::auth::SimplePassword::new(b"secret12"));
    apply_ospf_auth(&mut auth, &mut pkt);
    assert!(
        verify_ospf_auth(&mut auth, &pkt),
        "signed packet verifies against the same password"
    );
    // Wrong password → reject.
    let mut wrong = OspfAuthState::Simple(lr_ospf::auth::SimplePassword::new(b"WRONG!!!1"));
    assert!(
        !verify_ospf_auth(&mut wrong, &pkt),
        "packet signed with 'secret12' does not verify against 'WRONG!!!1'"
    );
    // Tampered auth_data → reject.
    let mut tampered = pkt.clone();
    tampered[16] ^= 0xff;
    assert!(
        !verify_ospf_auth(&mut auth, &tampered),
        "tampered auth_data is rejected"
    );
    // Wrong au_type → reject.
    let mut wrong_au = pkt.clone();
    wrong_au[14..16].copy_from_slice(&0u16.to_be_bytes()); // NullAuth
    assert!(
        !verify_ospf_auth(&mut auth, &wrong_au),
        "au_type = 0 under SimplePassword config is rejected"
    );
    // Truncated header → reject.
    assert!(
        !verify_ospf_auth(&mut auth, &pkt[..20]),
        "truncated header is rejected"
    );
}

/// `build_ospf_auth` returns `OspfAuthState::None` for `null` (the
/// default), `OspfAuthState::Simple` for `simple`, and
/// `OspfAuthState::Crypto` for `crypto`.
#[test]
fn build_ospf_auth_maps_config_to_strategy() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".into();
    assert!(
        matches!(build_ospf_auth(&cfg), OspfAuthState::None),
        "default is NullAuth"
    );

    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("null".into()),
        password: None,
        key: None,
        key_id: None,
        algorithm: None,
    };
    assert!(
        matches!(build_ospf_auth(&cfg), OspfAuthState::None),
        "explicit null → NullAuth"
    );

    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("simple".into()),
        password: Some("secret12".into()),
        key: None,
        key_id: None,
        algorithm: None,
    };
    let auth = build_ospf_auth(&cfg);
    match auth {
        OspfAuthState::Simple(s) => assert_eq!(&s.password, b"secret12"),
        other => panic!("expected Simple, got {other:?}"),
    }

    // Empty password → all-zero credential (wire-valid, weak).
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("simple".into()),
        password: Some("".into()),
        key: None,
        key_id: None,
        algorithm: None,
    };
    let auth = build_ospf_auth(&cfg);
    match auth {
        OspfAuthState::Simple(s) => assert_eq!(
            &s.password, &[0u8; 8],
            "empty password → all-zero credential"
        ),
        other => panic!("expected Simple, got {other:?}"),
    }

    // Crypto → CryptoAuth with the default HMAC-SHA-256.
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("crypto".into()),
        password: None,
        key: Some("shared-secret".into()),
        key_id: Some(7),
        algorithm: None,
    };
    let auth = build_ospf_auth(&cfg);
    match auth {
        OspfAuthState::Crypto(arc) => {
            let ca = arc.lock().unwrap();
            assert_eq!(ca.key_id, 7);
            assert_eq!(ca.algorithm, lr_ospf::auth::CryptoAlgorithm::HmacSha256);
            assert_eq!(ca.key, b"shared-secret".to_vec());
        }
        other => panic!("expected Crypto, got {other:?}"),
    }

    // Crypto → HMAC-SHA-1 when algorithm = "hmac-sha1".
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("crypto".into()),
        password: None,
        key: Some("shared-secret".into()),
        key_id: Some(7),
        algorithm: Some("hmac-sha1".into()),
    };
    let auth = build_ospf_auth(&cfg);
    match auth {
        OspfAuthState::Crypto(arc) => {
            let ca = arc.lock().unwrap();
            assert_eq!(ca.algorithm, lr_ospf::auth::CryptoAlgorithm::HmacSha1);
        }
        other => panic!("expected Crypto, got {other:?}"),
    }
}

/// Config-parse coverage for `[ospf.auth]`: `type` and `password` keys,
/// the `simple` strategy, the `crypto` alias `md5` (now accepted
/// rather than rejected), and the alias `auth_type` for `type`.
#[test]
fn parse_ospf_auth_simple_password() {
    use crate::daemon_config::parse_toml_subset;
    let toml = r#"
[ospf.auth]
type = "simple"
password = "secret12"
"#;
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(toml, &mut cfg).unwrap();
    assert_eq!(cfg.ospf_auth.effective_type(), "simple");
    assert_eq!(cfg.ospf_auth.password.as_deref(), Some("secret12"));
}

#[test]
fn parse_ospf_auth_crypto_aliases_md5_and_message_digest() {
    use crate::daemon_config::parse_toml_subset;
    for alias in ["md5", "crypto", "message-digest"] {
        let toml = format!(
            r#"
[ospf.auth]
type = "{alias}"
key = "shared-secret"
key_id = 1
"#
        );
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(&toml, &mut cfg)
            .unwrap_or_else(|e| panic!("alias '{alias}' rejected: {e}"));
        assert_eq!(
            cfg.ospf_auth.effective_type(),
            "crypto",
            "alias '{alias}' → crypto"
        );
        assert_eq!(cfg.ospf_auth.key.as_deref(), Some("shared-secret"));
        assert_eq!(cfg.ospf_auth.key_id, Some(1));
    }
}

#[test]
fn parse_ospf_auth_crypto_keys_and_algorithm() {
    use crate::daemon_config::parse_toml_subset;
    let toml = r#"
[ospf.auth]
type = "crypto"
key = "shared-secret"
key_id = 7
algorithm = "hmac-sha1"
"#;
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(toml, &mut cfg).unwrap();
    assert_eq!(cfg.ospf_auth.effective_type(), "crypto");
    assert_eq!(cfg.ospf_auth.key.as_deref(), Some("shared-secret"));
    assert_eq!(cfg.ospf_auth.key_id, Some(7));
    assert_eq!(cfg.ospf_auth.effective_algorithm(), "hmac-sha1");
}

#[test]
fn parse_ospf_auth_crypto_algorithm_aliases() {
    use crate::daemon_config::parse_toml_subset;
    // All accepted spellings of HMAC-SHA-256.
    for spelling in ["hmac-sha256", "hmac-sha-256", "sha256"] {
        let toml = format!(
            r#"
[ospf.auth]
type = "crypto"
key = "shared-secret"
key_id = 1
algorithm = "{spelling}"
"#
        );
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(&toml, &mut cfg).unwrap_or_else(|e| panic!("spelling '{spelling}': {e}"));
        assert_eq!(cfg.ospf_auth.algorithm.as_deref(), Some("hmac-sha256"));
    }
    // All accepted spellings of HMAC-SHA-1.
    for spelling in ["hmac-sha1", "hmac-sha-1", "sha1"] {
        let toml = format!(
            r#"
[ospf.auth]
type = "crypto"
key = "shared-secret"
key_id = 1
algorithm = "{spelling}"
"#
        );
        let mut cfg = DaemonConfig::with_defaults();
        parse_toml_subset(&toml, &mut cfg).unwrap_or_else(|e| panic!("spelling '{spelling}': {e}"));
        assert_eq!(cfg.ospf_auth.algorithm.as_deref(), Some("hmac-sha1"));
    }
}

#[test]
fn parse_ospf_auth_unknown_algorithm_rejected() {
    use crate::daemon_config::parse_toml_subset;
    let toml = r#"
[ospf.auth]
type = "crypto"
key = "shared-secret"
key_id = 1
algorithm = "md5"
"#;
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(toml, &mut cfg).unwrap_err();
    assert!(
        err.contains("unknown ospf.auth algorithm"),
        "unknown algorithm rejected, got: {err}"
    );
}

#[test]
fn parse_ospf_auth_unknown_type_rejected() {
    use crate::daemon_config::parse_toml_subset;
    let toml = r#"
[ospf.auth]
type = "kerberos"
"#;
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(toml, &mut cfg).unwrap_err();
    assert!(
        err.contains("unknown ospf.auth type"),
        "unknown type rejected, got: {err}"
    );
}

#[test]
fn parse_ospf_auth_unknown_key_rejected() {
    use crate::daemon_config::parse_toml_subset;
    let toml = r#"
[ospf.auth]
type = "null"
bogus_key = 1
"#;
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(toml, &mut cfg).unwrap_err();
    assert!(
        err.contains("unknown [ospf.auth] key 'bogus_key'"),
        "unknown key rejected (typo protection), got: {err}"
    );
}

/// `simple` auth without a `password` key fails closed at finalize
/// time — the operator almost certainly forgot the line.
#[test]
fn finalize_ospf_auth_simple_without_password_fails_closed() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".into();
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("lo".into()),
        ..Default::default()
    });
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("simple".into()),
        password: None,
        key: None,
        key_id: None,
        algorithm: None,
    };
    let err = cfg.finalize().unwrap_err();
    assert!(
        err.contains("type = \"simple\" requires a 'password'"),
        "missing password rejected at finalize, got: {err}"
    );
}

/// `simple` auth with a >8-byte password is accepted (the daemon
/// truncates to 8 bytes per RFC 2328 §D.2) but emits a warning so the
/// operator notices the truncation.
#[test]
fn finalize_ospf_auth_long_password_warns() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".into();
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("lo".into()),
        ..Default::default()
    });
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("simple".into()),
        password: Some("abcdefghij".into()), // 10 bytes
        key: None,
        key_id: None,
        algorithm: None,
    };
    cfg.finalize().unwrap();
    assert!(
        cfg.warnings.iter().any(|w| w.contains("truncates to 8")),
        "long password warns, got warnings: {:?}",
        cfg.warnings
    );
}

// ---------------------------------------------------------------------------
// OSPFv2 Crypto auth — RFC 2328 §D.3 + RFC 5709 daemon wiring.
// The daemon signs every outgoing packet with au_type = 2 + an RFC 5709
// authentication trailer (Key ID + Auth Data Len + Crypto Seq + HMAC-SHA
// digest) and verifies the trailer on every received packet, including
// the §D.3.3 anti-replay crypto_seq check (strictly greater than the
// last-seen value).
// ---------------------------------------------------------------------------

/// `apply_ospf_auth(Crypto, ...)` writes au_type = 2, the
/// `(key_id | auth_data_len | crypto_seq | 0x0000)` auth_data field, and
/// appends the RFC 5709 trailer (Key ID + Auth Data Len + Crypto Seq +
/// HMAC-SHA-256 digest). The trailer length is 6 + 32 = 38 for SHA-256
/// (RFC 5709 §2.2), so the packet grows by 38 bytes.
#[test]
fn apply_ospf_auth_crypto_appends_trailer_and_sets_header_fields() {
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    let body_len = pkt.len();
    finalize_v2_packet(&mut pkt);
    let mut auth = OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(
        7,
        b"shared-secret".to_vec(),
    ))));
    let applied = apply_ospf_auth(&mut auth, &mut pkt);
    assert!(applied, "Crypto apply returns true");
    assert_eq!(
        u16::from_be_bytes([pkt[14], pkt[15]]),
        2,
        "au_type = 2 (Crypto)"
    );
    // Header auth_data: key_id (1) | auth_data_len (1, = 32 for SHA-256)
    // | crypto_seq (4, big-endian) | zero (2).
    assert_eq!(pkt[16], 7, "auth_data.key_id = 7");
    assert_eq!(pkt[17], 32, "auth_data.auth_data_len = 32 (SHA-256 digest)");
    let seq = u32::from_be_bytes([pkt[18], pkt[19], pkt[20], pkt[21]]);
    assert_eq!(seq, 1, "first packet's crypto_seq = 1 (advance_seq ran)");
    assert_eq!(&pkt[22..24], &[0u8, 0u8], "trailing 2 bytes zero");
    // The trailer is appended after the body. Total trailer length
    // is 6 (overhead) + 32 (SHA-256 digest) = 38 bytes.
    let trailer_len = 6 + 32;
    assert_eq!(pkt.len(), body_len + trailer_len, "trailer appended");
    // The trailer's first byte is the Key ID; second is Auth Data Len
    // (the digest length only); bytes 2..6 are the Crypto Seq.
    let trailer = &pkt[body_len..];
    assert_eq!(trailer[0], 7, "trailer.key_id = 7");
    assert_eq!(trailer[1], 32, "trailer.auth_data_len = 32");
    let trailer_seq = u32::from_be_bytes([trailer[2], trailer[3], trailer[4], trailer[5]]);
    assert_eq!(trailer_seq, 1, "trailer.crypto_seq = 1 (matches header)");
    // The trailing 32 bytes are the HMAC-SHA-256 digest — non-zero on
    // any real input (an all-zero digest would be a hash collision
    // coincidence we cannot engineer).
    let digest = &trailer[6..];
    assert_ne!(digest, &[0u8; 32], "digest is not all zeros");
    // The OSPF length field at offset 2..4 stays at the body length
    // (RFC 5709 §3 — the trailer is NOT counted in the OSPF length).
    let ospf_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    assert_eq!(
        ospf_len, body_len,
        "OSPF length stays at body length (trailer excluded)"
    );
}

/// `apply_ospf_auth` advances the crypto_seq on every call so the
/// anti-replay window sees a strictly larger value on every packet
/// (RFC 2328 §D.3.2).
#[test]
fn apply_ospf_auth_crypto_advances_seq_monotonically() {
    let mut auth = OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(
        1,
        b"shared-secret".to_vec(),
    ))));
    let build = || {
        build_hello(
            RouterId::from_u32(0x0a00_0001),
            0,
            &HelloWire {
                network_mask: 0xffff_ff00,
                hello_interval: 10,
                dead_interval: 40,
                priority: 1,
                dr: 0,
                bdr: 0,
            },
            vec![],
        )
        .unwrap()
    };
    let mut seqs = Vec::new();
    for _ in 0..3 {
        let mut pkt = build();
        apply_ospf_auth(&mut auth, &mut pkt);
        let seq = u32::from_be_bytes([pkt[18], pkt[19], pkt[20], pkt[21]]);
        seqs.push(seq);
    }
    assert_eq!(
        seqs,
        vec![1, 2, 3],
        "crypto_seq is 1, 2, 3 across three packets"
    );
}

/// `apply_ospf_auth(Crypto, ...)` with HMAC-SHA-1 produces a 26-byte
/// trailer (6 + 20-byte SHA-1 digest, per RFC 5709 §2.1).
#[test]
fn apply_ospf_auth_crypto_hmac_sha1_trailer_length() {
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    let body_len = pkt.len();
    let mut auth = OspfAuthState::Crypto(Arc::new(Mutex::new(
        lr_ospf::auth::CryptoAuth::new(1, b"shared-secret".to_vec()).with_sha1(),
    )));
    apply_ospf_auth(&mut auth, &mut pkt);
    assert_eq!(pkt.len(), body_len + 6 + 20, "trailer = 6 + 20 (SHA-1)");
    assert_eq!(pkt[17], 20, "auth_data_len = 20 (SHA-1 digest length)");
}

/// `verify_ospf_auth(Crypto, ...)` round-trips: a packet signed by
/// `apply_ospf_auth` verifies against the same key. The anti-replay
/// `last_peer_seq` updates so the second packet verifies too.
#[test]
fn verify_ospf_auth_crypto_round_trip() {
    let key = b"shared-secret".to_vec();
    let sender = Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(1, key.clone())));
    let mut receiver =
        OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(1, key))));
    for i in 1..=3 {
        let mut pkt = build_hello(
            RouterId::from_u32(0x0a00_0001),
            0,
            &HelloWire {
                network_mask: 0xffff_ff00,
                hello_interval: 10,
                dead_interval: 40,
                priority: 1,
                dr: 0,
                bdr: 0,
            },
            vec![],
        )
        .unwrap();
        let mut send_auth = OspfAuthState::Crypto(Arc::clone(&sender));
        apply_ospf_auth(&mut send_auth, &mut pkt);
        finalize_v2_packet(&mut pkt);
        assert!(
            verify_ospf_auth(&mut receiver, &pkt),
            "packet #{i} verifies against the same key"
        );
    }
}

/// `verify_ospf_auth(Crypto, ...)` rejects a packet whose trailer
/// was tampered with (a single bit flip in the digest). The MAC
/// comparison fails and the packet is dropped (RFC 2328 §D.1).
#[test]
fn verify_ospf_auth_crypto_rejects_tampered_digest() {
    let key = b"shared-secret".to_vec();
    let mut auth = OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(
        1,
        key.clone(),
    ))));
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    let mut send_auth =
        OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(1, key))));
    apply_ospf_auth(&mut send_auth, &mut pkt);
    finalize_v2_packet(&mut pkt);
    // Tamper with the digest (the very last byte of the trailer).
    let last = pkt.len() - 1;
    pkt[last] ^= 0xff;
    assert!(
        !verify_ospf_auth(&mut auth, &pkt),
        "tampered digest is rejected"
    );
}

/// `verify_ospf_auth(Crypto, ...)` rejects a packet whose Key ID
/// does not match the configured key (RFC 2328 §D.3.3 — "If there
/// is no authentication data for this Key ID in the LSA, the packet
/// is dropped").
#[test]
fn verify_ospf_auth_crypto_rejects_wrong_key_id() {
    let key = b"shared-secret".to_vec();
    let mut auth = OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(
        7,
        key.clone(),
    ))));
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    let mut send_auth = OspfAuthState::Crypto(Arc::new(Mutex::new(
        // Different key_id (1 vs the receiver's 7).
        lr_ospf::auth::CryptoAuth::new(1, key),
    )));
    apply_ospf_auth(&mut send_auth, &mut pkt);
    finalize_v2_packet(&mut pkt);
    assert!(
        !verify_ospf_auth(&mut auth, &pkt),
        "packet with key_id 1 under a key_id 7 config is rejected"
    );
}

/// `verify_ospf_auth(Crypto, ...)` rejects a packet signed with a
/// different key — the MAC comparison fails even with a matching
/// Key ID (a wrong key produces a different digest).
#[test]
fn verify_ospf_auth_crypto_rejects_wrong_key() {
    let mut auth = OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(
        1,
        b"shared-secret".to_vec(),
    ))));
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    let mut send_auth = OspfAuthState::Crypto(Arc::new(Mutex::new(
        // Same key_id, different secret.
        lr_ospf::auth::CryptoAuth::new(1, b"different-secret".to_vec()),
    )));
    apply_ospf_auth(&mut send_auth, &mut pkt);
    finalize_v2_packet(&mut pkt);
    assert!(
        !verify_ospf_auth(&mut auth, &pkt),
        "packet signed with a different secret is rejected"
    );
}

/// `verify_ospf_auth(Crypto, ...)` enforces the §D.3.3 anti-replay
/// check: a packet whose crypto_seq is less than or equal to the
/// last-seen value is rejected even if the MAC is otherwise correct.
/// The very first packet (no last-seen yet) is always accepted to
/// bootstrap the session.
#[test]
fn verify_ospf_auth_crypto_anti_replay_rejects_stale_seq() {
    let key = b"shared-secret".to_vec();
    let sender = Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(1, key.clone())));
    let mut receiver =
        OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(1, key))));
    let build = || {
        build_hello(
            RouterId::from_u32(0x0a00_0001),
            0,
            &HelloWire {
                network_mask: 0xffff_ff00,
                hello_interval: 10,
                dead_interval: 40,
                priority: 1,
                dr: 0,
                bdr: 0,
            },
            vec![],
        )
        .unwrap()
    };
    // First packet (seq = 1) — accepted; last_peer_seq becomes Some(1).
    let mut p1 = build();
    let mut s = OspfAuthState::Crypto(Arc::clone(&sender));
    apply_ospf_auth(&mut s, &mut p1);
    finalize_v2_packet(&mut p1);
    assert!(
        verify_ospf_auth(&mut receiver, &p1),
        "first packet (seq 1) is accepted to bootstrap"
    );
    // Second packet (seq = 2) — accepted; last_peer_seq becomes Some(2).
    let mut p2 = build();
    let mut s = OspfAuthState::Crypto(Arc::clone(&sender));
    apply_ospf_auth(&mut s, &mut p2);
    finalize_v2_packet(&mut p2);
    assert!(
        verify_ospf_auth(&mut receiver, &p2),
        "second packet (seq 2 > 1) is accepted"
    );
    // Replay p1 (seq = 1, <= last_peer_seq = 2) — rejected.
    assert!(
        !verify_ospf_auth(&mut receiver, &p1),
        "replayed packet (seq 1 <= 2) is rejected by anti-replay"
    );
}

/// `verify_ospf_auth(Crypto, ...)` rejects a packet with au_type ≠ 2
/// (a SimplePassword or NullAuth packet under a Crypto config).
#[test]
fn verify_ospf_auth_crypto_rejects_wrong_au_type() {
    let mut auth = OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(
        1,
        b"shared-secret".to_vec(),
    ))));
    let pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    assert!(
        !verify_ospf_auth(&mut auth, &pkt),
        "NullAuth packet (au_type 0) under Crypto config is rejected"
    );
}

/// `verify_ospf_auth(Crypto, ...)` rejects a truncated packet that
/// does not even fit the trailer.
#[test]
fn verify_ospf_auth_crypto_rejects_truncated_trailer() {
    let mut auth = OspfAuthState::Crypto(Arc::new(Mutex::new(lr_ospf::auth::CryptoAuth::new(
        1,
        b"shared-secret".to_vec(),
    ))));
    // Build a packet whose auth_data_len claims a 32-byte digest
    // but the buffer is too short to carry the trailer.
    let mut pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        0,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    pkt[14..16].copy_from_slice(&2u16.to_be_bytes()); // au_type = 2
    pkt[17] = 32; // auth_data_len = 32 (SHA-256), but no trailer present
    assert!(
        !verify_ospf_auth(&mut auth, &pkt),
        "packet claiming a 32-byte trailer but missing it is rejected"
    );
}

/// `[ospf.auth] type = "crypto"` without a `key` fails closed at
/// finalize time.
#[test]
fn finalize_ospf_auth_crypto_without_key_fails_closed() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".into();
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("lo".into()),
        ..Default::default()
    });
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("crypto".into()),
        password: None,
        key: None,
        key_id: Some(1),
        algorithm: None,
    };
    let err = cfg.finalize().unwrap_err();
    assert!(
        err.contains("type = \"crypto\" requires a non-empty 'key'"),
        "missing key rejected at finalize, got: {err}"
    );
}

/// `[ospf.auth] type = "crypto"` without a `key_id` fails closed at
/// finalize time.
#[test]
fn finalize_ospf_auth_crypto_without_key_id_fails_closed() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".into();
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("lo".into()),
        ..Default::default()
    });
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("crypto".into()),
        password: None,
        key: Some("shared-secret".into()),
        key_id: None,
        algorithm: None,
    };
    let err = cfg.finalize().unwrap_err();
    assert!(
        err.contains("type = \"crypto\" requires a 'key_id'"),
        "missing key_id rejected at finalize, got: {err}"
    );
}

/// `[ospf.auth] type = "crypto" algorithm = "hmac-sha1"` is accepted
/// but emits a warning recommending HMAC-SHA-256 (RFC 5709 §2.2).
#[test]
fn finalize_ospf_auth_crypto_sha1_warns() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".into();
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("lo".into()),
        ..Default::default()
    });
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("crypto".into()),
        password: None,
        key: Some("shared-secret".into()),
        key_id: Some(1),
        algorithm: Some("hmac-sha1".into()),
    };
    cfg.finalize().unwrap();
    assert!(
        cfg.warnings
            .iter()
            .any(|w| w.contains("recommends HMAC-SHA-256")),
        "SHA-1 algorithm warns, got warnings: {:?}",
        cfg.warnings
    );
}

/// `[ospf.auth] type = "crypto" password = "..."` warns that the
/// `password` key is ignored under crypto (the operator should use
/// `key` instead).
#[test]
fn finalize_ospf_auth_crypto_with_stale_password_warns() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".into();
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("lo".into()),
        ..Default::default()
    });
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("crypto".into()),
        password: Some("ignored".into()),
        key: Some("shared-secret".into()),
        key_id: Some(1),
        algorithm: None,
    };
    cfg.finalize().unwrap();
    assert!(
        cfg.warnings
            .iter()
            .any(|w| w.contains("ignored when type = \"crypto\"")),
        "stale password warns, got warnings: {:?}",
        cfg.warnings
    );
}

/// A minimal `OspfDaemon` for the graceful-restart status tests —
/// only the fields `refresh_gr_status` reads are populated, every
/// other field is the empty/default shape. Keeping this builder in
/// the test module (next to the only callers) avoids a production
/// `Default` impl that would imply a daemon can boot without a
/// router, interfaces or transports.
fn gr_status_test_daemon(
    gr_recovery: BTreeMap<u32, lr_ospf::gr::RestartTracker>,
    neighbors: BTreeMap<(u32, u32), Neighbor>,
) -> OspfDaemon {
    OspfDaemon {
        router: Arc::new(RwLock::new(DefaultRouter::new())),
        interfaces: Vec::new(),
        neighbors,
        pending_reorig: BTreeMap::new(),
        asbr_latched: None,
        anchors: BTreeMap::new(),
        lsa_seq: BTreeMap::new(),
        gr_helper_enabled: true,
        gr_helper_cap: 120,
        gr_grace_period: 60,
        gr_seq_floor: 0,
        gr_state_file: None,
        gr_recovery,
        gr_topology: BTreeMap::new(),
        sr_srgb: None,
        sr_sids: Vec::new(),
        sr_ranges: Vec::new(),
        sr_link_active: BTreeMap::new(),
        sr_link_pops: BTreeMap::new(),
        install_kernel_mpls: false,
        sr_seq: BTreeMap::new(),
        gr_status: Arc::new(std::sync::Mutex::new(Vec::new())),
        router_id: RouterId::from_u32(0),
        event_bus: lr_router::event_bus::EventBus::new(),
        auth: OspfAuthState::None,
        reload_coord: Arc::new(super::OspfReloadCoord::new(
            &crate::daemon_config::DaemonConfig::with_defaults(),
        )),
    }
}

/// Build a `Neighbor` whose helper is active with `grace_deadline_ms`.
/// `refresh_gr_status` reads `n.helper.is_active()` and
/// `n.helper.grace_deadline_ms()` — the rest of the neighbour is the
/// shape the daemon would have built (a SessionHandle is opaque, the
/// ifindex and established flag are irrelevant to the status line).
fn gr_status_test_neighbor(deadline_ms: u64) -> Neighbor {
    let mut helper = lr_ospf::gr::HelperEntry::default();
    let lsa = lr_ospf::lsa::grace::GraceLsaBody {
        grace_period: 60,
        reason: lr_ospf::lsa::grace::GraceReason::SoftwareRestart,
        ipv4_address: None,
        ipv6_address: None,
    };
    let check = lr_ospf::gr::HelperCheck {
        neighbor_full: true,
        helper_enabled: true,
        supported_grace_cap_secs: 120,
        self_restarting: false,
        lsa: &lsa,
        lsa_age_secs: 0,
        now_ms: deadline_ms.saturating_sub(u64::from(lsa.grace_period) * 1_000),
    };
    let transition = helper.on_grace_lsa(check);
    assert!(
        matches!(transition, lr_ospf::gr::HelperTransition::Entered { .. }),
        "the helper entered active mode"
    );
    Neighbor {
        handle: SessionHandle(0),
        ifindex: 1,
        established: true,
        helper,
    }
}

/// `refresh_gr_status` reports the *remaining* grace for each
/// helper, not the absolute deadline or the configured period. The
/// pre-fix shape computed `grace_deadline_ms().saturating_sub(0) /
/// 1_000` — a no-op subtraction that printed the absolute deadline in
/// seconds, so a helper that started at daemon t=0 with a 60 s grace
/// period read "60s grace left" forever, even when only 1 s remained.
#[test]
fn refresh_gr_status_reports_remaining_grace_for_helpers() {
    // Tracker: started at t=0 with a 60 s grace period → deadline
    // 60_000 ms on the daemon clock.
    let tracker = lr_ospf::gr::RestartTracker::new(60, 0);
    assert_eq!(tracker.grace_deadline_ms(), 60_000);
    let gr_recovery = BTreeMap::from([(0u32, tracker)]);
    // Helper: same deadline (entered at t=0 with a 60 s period).
    let neighbors = BTreeMap::from([((0u32, 0x0a00_0001u32), gr_status_test_neighbor(60_000))]);
    let daemon = gr_status_test_daemon(gr_recovery, neighbors);

    // Halfway through the grace window: 10 s left (60_000 - 50_000).
    daemon.refresh_gr_status(50_000);
    let lines = daemon.gr_status.lock().unwrap().clone();
    let helper_line = lines
        .iter()
        .find(|l| l.contains("grace left"))
        .expect("the helper status line is present");
    assert!(
        helper_line.contains("10s grace left"),
        "10 s remaining (50 s into a 60 s window), got: {helper_line}"
    );
    // The recovery line carries the absolute deadline in seconds —
    // the operator's `+Xs` correlation view against other daemon
    // log lines. A regression that subtracts now_ms here would read
    // "grace until +10s" instead of the absolute "+60s".
    let recovery_line = lines
        .iter()
        .find(|l| l.contains("recovering"))
        .expect("the recovery status line is present");
    assert!(
        recovery_line.contains("grace until +60s"),
        "the absolute deadline in seconds, got: {recovery_line}"
    );

    // At the deadline: 0 s left.
    daemon.refresh_gr_status(60_000);
    let lines = daemon.gr_status.lock().unwrap().clone();
    let helper_line = lines
        .iter()
        .find(|l| l.contains("grace left"))
        .expect("the helper status line is present");
    assert!(
        helper_line.contains("0s grace left"),
        "0 s remaining at the deadline, got: {helper_line}"
    );

    // Past the deadline: still 0 s left (saturating_sub clamps; the
    // helper stays active until `poll` sees the deadline and fires
    // the GraceTimeout exit, which is a separate pump_gr pass).
    daemon.refresh_gr_status(70_000);
    let lines = daemon.gr_status.lock().unwrap().clone();
    let helper_line = lines
        .iter()
        .find(|l| l.contains("grace left"))
        .expect("the helper status line is present");
    assert!(
        helper_line.contains("0s grace left"),
        "0 s remaining past the deadline (clamped), got: {helper_line}"
    );
}

/// A helper that became inactive (`on_flush` or `poll` fired the
/// GraceTimeout exit) does not appear in the status lines at all.
#[test]
fn refresh_gr_status_omits_inactive_helpers() {
    let gr_recovery = BTreeMap::new();
    let mut helper = lr_ospf::gr::HelperEntry::default();
    let lsa = lr_ospf::lsa::grace::GraceLsaBody {
        grace_period: 60,
        reason: lr_ospf::lsa::grace::GraceReason::SoftwareRestart,
        ipv4_address: None,
        ipv6_address: None,
    };
    let check = lr_ospf::gr::HelperCheck {
        neighbor_full: true,
        helper_enabled: true,
        supported_grace_cap_secs: 120,
        self_restarting: false,
        lsa: &lsa,
        lsa_age_secs: 0,
        now_ms: 0,
    };
    helper.on_grace_lsa(check);
    // Flush: helper mode exits.
    let _ = helper.on_flush();
    assert!(!helper.is_active());
    let neighbors = BTreeMap::from([(
        (0u32, 0x0a00_0001u32),
        Neighbor {
            handle: SessionHandle(0),
            ifindex: 1,
            established: true,
            helper,
        },
    )]);
    let daemon = gr_status_test_daemon(gr_recovery, neighbors);
    daemon.refresh_gr_status(5_000);
    let lines = daemon.gr_status.lock().unwrap().clone();
    assert!(
        !lines.iter().any(|l| l.contains("grace left")),
        "no helper status line, got: {lines:?}"
    );
}

// ---------------------------------------------------------------------
// Configuration reload — the interface set as units (issue #101).
// Planner-level tests: everything the reload closure does before the
// engine's apply pass. The kernel-touching paths (the Add op resolves
// the fresh interface against the kernel) need raw OSPF sockets and
// are covered by the netns integration scripts; these cover the pure
// diff surface — retunes, removals, rejection, policy swaps, the
// restart-required report and the chaining contract.
// ---------------------------------------------------------------------

/// A startup-shaped config: two p2p interfaces in area 0 (the names
/// never reach the kernel on the planner-only paths).
fn reload_cfg_two_interfaces() -> DaemonConfig {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v2".to_string();
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("eth0".to_string()),
        cost: Some(10),
        ..Default::default()
    });
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("eth1".to_string()),
        cost: Some(20),
        ..Default::default()
    });
    cfg.router_id = "1.1.1.1".to_string();
    cfg
}

/// A cost retune is one unit: the kept interface's parameters diff
/// into a Retune op and the report names the field.
#[test]
fn reload_plan_retunes_a_kept_interface() {
    let cfg = reload_cfg_two_interfaces();
    let coord = super::OspfReloadCoord::new(&cfg);
    let mut fresh = cfg.clone();
    fresh.ospf_interfaces[0].cost = Some(50);
    let lines = super::plan_ospf_reload(&fresh, &coord).expect("valid fresh config");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("eth0 re-tuned (cost -> 50)")),
        "the retune line names the interface and the field: {lines:?}"
    );
    let plans = coord.take_plans();
    assert_eq!(plans.len(), 1, "one plan queued");
    assert_eq!(plans[0].ops.len(), 1, "one unit");
    assert!(
        matches!(&plans[0].ops[0], super::OspfIfOp::Retune(name, retune)
            if name == "eth0" && retune.cost == Some(50)),
        "the op is a cost retune on eth0"
    );
    assert!(plans[0].auth.is_none() && plans[0].gr_helper.is_none());
}

/// An interface dropped from the fresh configuration tears its unit
/// down; the untouched sibling keeps running.
#[test]
fn reload_plan_removes_a_dropped_interface() {
    let cfg = reload_cfg_two_interfaces();
    let coord = super::OspfReloadCoord::new(&cfg);
    let mut fresh = cfg.clone();
    fresh.ospf_interfaces.remove(1);
    let lines = super::plan_ospf_reload(&fresh, &coord).expect("valid fresh config");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("eth1 removed (adjacencies closed, LSAs re-originated)")),
        "the removal line names the interface: {lines:?}"
    );
    let plans = coord.take_plans();
    assert_eq!(plans.len(), 1);
    assert!(
        matches!(&plans[0].ops[0], super::OspfIfOp::Remove(name) if name == "eth1"),
        "the op is a teardown of eth1"
    );
}

/// A pure timer retune queues the unit but does not force the area's
/// LSA re-origination (the apply pass picks the forced flag).
#[test]
fn reload_plan_timer_retune_is_not_lsa_relevant() {
    let cfg = reload_cfg_two_interfaces();
    let coord = super::OspfReloadCoord::new(&cfg);
    let mut fresh = cfg.clone();
    fresh.ospf_interfaces[0].hello_interval = Some(3);
    super::plan_ospf_reload(&fresh, &coord).expect("valid fresh config");
    let plans = coord.take_plans();
    assert_eq!(plans.len(), 1);
    assert!(
        matches!(&plans[0].ops[0], super::OspfIfOp::Retune(_, retune)
            if retune.cost.is_none() && retune.hello_interval == Some(3)),
        "the retune carries the hello delta only"
    );
}

/// A duplicate interface name makes the unit diff ambiguous: the whole
/// reload aborts and nothing is queued (the atomicity contract).
#[test]
fn reload_plan_rejects_duplicate_interface_names() {
    let cfg = reload_cfg_two_interfaces();
    let coord = super::OspfReloadCoord::new(&cfg);
    let mut fresh = cfg.clone();
    fresh
        .ospf_interfaces
        .push(crate::daemon_config::OspfIfSpec {
            name: Some("eth0".to_string()),
            cost: Some(99),
            ..Default::default()
        });
    let err = super::plan_ospf_reload(&fresh, &coord).expect_err("duplicate name rejected");
    assert!(err.contains("duplicate interface 'eth0'"), "got: {err}");
    assert!(coord.take_plans().is_empty(), "nothing queued on abort");
}

/// An unknown network type is named per interface and aborts the
/// reload before anything is queued.
#[test]
fn reload_plan_rejects_unknown_network_type() {
    let cfg = reload_cfg_two_interfaces();
    let coord = super::OspfReloadCoord::new(&cfg);
    let mut fresh = cfg.clone();
    fresh.ospf_interfaces[0].network_type = Some("nbma".to_string());
    let err = super::plan_ospf_reload(&fresh, &coord).expect_err("unknown type rejected");
    assert!(
        err.contains("eth0") && err.contains("unknown network_type 'nbma'"),
        "the error names the interface and the value: {err}"
    );
    assert!(coord.take_plans().is_empty(), "nothing queued on abort");
}

/// An `[ospf.auth]` change swaps the daemon-wide strategy in place —
/// the plan carries the fresh state and the report says new packets
/// carry it (peers must be reconfigured in lockstep).
#[test]
fn reload_plan_swaps_the_auth_strategy_in_place() {
    let cfg = reload_cfg_two_interfaces();
    let coord = super::OspfReloadCoord::new(&cfg);
    let mut fresh = cfg.clone();
    fresh.ospf_auth.auth_type = Some("simple".to_string());
    fresh.ospf_auth.password = Some("hunter2".to_string());
    let lines = super::plan_ospf_reload(&fresh, &coord).expect("valid fresh config");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("auth strategy -> simple") && l.contains("fresh strategy")),
        "the swap line names the fresh strategy: {lines:?}"
    );
    let plans = coord.take_plans();
    assert_eq!(plans.len(), 1, "the policy swap queues a plan");
    assert!(plans[0].auth.is_some(), "the fresh strategy rides the plan");
    assert!(plans[0].ops.is_empty(), "no interface units involved");
}

/// Daemon-wide identity surfaces (router-id, SR origination, area
/// types, GR role) are reported as requiring a restart — honestly,
/// instead of silently ignoring the change.
#[test]
fn reload_plan_reports_restart_required_surfaces() {
    let mut cfg = reload_cfg_two_interfaces();
    cfg.ospf_srgb_base = Some(16000);
    cfg.ospf_srgb_range = Some(1000);
    let coord = super::OspfReloadCoord::new(&cfg);
    let mut fresh = cfg.clone();
    fresh.router_id = "2.2.2.2".to_string();
    let lines = super::plan_ospf_reload(&fresh, &coord).expect("valid fresh config");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("router-id change requires a restart")),
        "the router-id line is reported: {lines:?}"
    );
    // No interface ops (the set is unchanged), nothing queued: a
    // restart-required report alone is not a reload.
    assert!(coord.take_plans().is_empty());
}

/// Consecutive reloads chain: the target tables advance at queue
/// time, so a second SIGHUP with the same configuration is a no-op
/// (idempotent) — the LDP daemon's `current_binds` contract.
#[test]
fn reload_plan_chains_targets_so_a_repeat_is_a_noop() {
    let cfg = reload_cfg_two_interfaces();
    let coord = super::OspfReloadCoord::new(&cfg);
    let mut fresh = cfg.clone();
    fresh.ospf_interfaces[0].cost = Some(50);
    super::plan_ospf_reload(&fresh, &coord).expect("first reload queues");
    assert_eq!(coord.take_plans().len(), 1);
    // Same fresh configuration again: the diff against the advanced
    // target is empty — no ops, no plan.
    let lines = super::plan_ospf_reload(&fresh, &coord).expect("second reload");
    assert!(
        !lines.iter().any(|l| l.contains("queued")),
        "nothing queued on the repeat: {lines:?}"
    );
    assert!(coord.take_plans().is_empty());
}
