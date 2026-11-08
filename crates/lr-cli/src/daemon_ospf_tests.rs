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
// OSPFv2 SimplePassword auth — RFC 2328 §D wiring (issue #92).
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
    let applied = apply_ospf_auth(None, &mut pkt);
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
    let auth = lr_ospf::auth::SimplePassword::new(b"secret12");
    let applied = apply_ospf_auth(Some(&auth), &mut pkt);
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
    let auth = lr_ospf::auth::SimplePassword::new(b"secure!!!");
    apply_ospf_auth(Some(&auth), &mut pkt);
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
    assert!(verify_ospf_auth(None, &pkt), "NullAuth accepts");
    // Even a packet with au_type = 1 is accepted under NullAuth (the
    // RFC says AuType 0 is "no authentication" — the auth_data field is
    // ignored). The receive path's gate is the configured auth, not
    // the wire au_type.
    let mut au1 = pkt.clone();
    au1[14..16].copy_from_slice(&1u16.to_be_bytes());
    assert!(
        verify_ospf_auth(None, &au1),
        "NullAuth ignores wire au_type"
    );
}

/// `verify_ospf_auth(Some(...), ...)` accepts a packet signed with
/// the same password and rejects one with a different password, a
/// different au_type, or a truncated header.
#[test]
fn verify_ospf_auth_simple_password_round_trip() {
    let auth = lr_ospf::auth::SimplePassword::new(b"secret12");
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
    apply_ospf_auth(Some(&auth), &mut pkt);
    assert!(
        verify_ospf_auth(Some(&auth), &pkt),
        "signed packet verifies against the same password"
    );
    // Wrong password → reject.
    let wrong = lr_ospf::auth::SimplePassword::new(b"WRONG!!!1");
    assert!(
        !verify_ospf_auth(Some(&wrong), &pkt),
        "packet signed with 'secret12' does not verify against 'WRONG!!!1'"
    );
    // Tampered auth_data → reject.
    let mut tampered = pkt.clone();
    tampered[16] ^= 0xff;
    assert!(
        !verify_ospf_auth(Some(&auth), &tampered),
        "tampered auth_data is rejected"
    );
    // Wrong au_type → reject.
    let mut wrong_au = pkt.clone();
    wrong_au[14..16].copy_from_slice(&0u16.to_be_bytes()); // NullAuth
    assert!(
        !verify_ospf_auth(Some(&auth), &wrong_au),
        "au_type = 0 under SimplePassword config is rejected"
    );
    // Truncated header → reject.
    assert!(
        !verify_ospf_auth(Some(&auth), &pkt[..20]),
        "truncated header is rejected"
    );
}

/// `build_ospf_auth` returns `None` for `null` (the default) and
/// `Some(SimplePassword)` for `simple`. Crypto auth (`md5`) is
/// rejected at parse time, so it never reaches `build_ospf_auth`.
#[test]
fn build_ospf_auth_maps_config_to_strategy() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".into();
    assert!(build_ospf_auth(&cfg).is_none(), "default is NullAuth");

    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("null".into()),
        password: None,
    };
    assert!(build_ospf_auth(&cfg).is_none(), "explicit null → NullAuth");

    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("simple".into()),
        password: Some("secret12".into()),
    };
    let auth = build_ospf_auth(&cfg).expect("simple → SimplePassword");
    assert_eq!(&auth.password, b"secret12");

    // Empty password → all-zero credential (wire-valid, weak).
    cfg.ospf_auth = crate::daemon_config::OspfAuthSpec {
        auth_type: Some("simple".into()),
        password: Some("".into()),
    };
    let auth = build_ospf_auth(&cfg).expect("simple → SimplePassword");
    assert_eq!(
        &auth.password, &[0u8; 8],
        "empty password → all-zero credential"
    );
}

/// Config-parse coverage for `[ospf.auth]`: `type` and `password` keys,
/// the `simple` strategy, the fail-closed rejection of `md5`, and
/// the alias `auth_type` for `type`.
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
fn parse_ospf_auth_md5_rejected_at_parse_time() {
    use crate::daemon_config::parse_toml_subset;
    let toml = r#"
[ospf.auth]
type = "md5"
password = "secret12"
"#;
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(toml, &mut cfg).unwrap_err();
    assert!(
        err.contains("crypto auth") && err.contains("not wired"),
        "md5 rejected with a clear message, got: {err}"
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
key_id = 1
"#;
    let mut cfg = DaemonConfig::with_defaults();
    let err = parse_toml_subset(toml, &mut cfg).unwrap_err();
    assert!(
        err.contains("unknown [ospf.auth] key 'key_id'"),
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
    };
    cfg.finalize().unwrap();
    assert!(
        cfg.warnings.iter().any(|w| w.contains("truncates to 8")),
        "long password warns, got warnings: {:?}",
        cfg.warnings
    );
}
