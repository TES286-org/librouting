use super::*;
use crate::daemon_config::{DaemonConfig, OspfSrv6LocatorSpec};

fn locator_spec(prefix: &str) -> OspfSrv6LocatorSpec {
    OspfSrv6LocatorSpec {
        prefix: Some(prefix.to_string()),
        ..Default::default()
    }
}

fn v6_octets(text: &str) -> [u8; 16] {
    match text.parse::<IpAddr>().expect("valid v6") {
        IpAddr::V6(o) => o,
        _ => panic!("not v6"),
    }
}

#[test]
fn srv6_off_without_locators() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_srv6_receive = true;
    // Reception alone does not turn origination on: the daemon
    // carries SRv6 state only when locators are configured.
    assert!(Srv6Origination::maybe_from_config(&cfg).is_none());
    cfg.ospf_srv6_locators = vec![locator_spec("2001:db8:a:1::/48")];
    assert!(Srv6Origination::maybe_from_config(&cfg).is_some());
}

#[test]
fn srv6_origination_defaults() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_srv6_locators = vec![locator_spec("2001:db8:a:1::/48")];
    let s = Srv6Origination::from_config(&cfg);
    // No O-flag by default; algorithm 0 derived from the locator.
    assert_eq!(s.capabilities, 0);
    assert_eq!(s.algorithms, vec![0]);
    assert!(s.msds.is_empty());
    assert_eq!(s.locators.len(), 1);
    let loc = &s.locators[0];
    assert_eq!(loc.route_type, locator_route_type::INTRA_AREA);
    assert_eq!(loc.algorithm, 0);
    assert_eq!(loc.locator_len, 48);
    assert_eq!(loc.options, 0);
    assert_eq!(loc.metric, 0);
    assert_eq!(loc.prefix, v6_octets("2001:db8:a:1::"));
    // The End SID defaults to the locator prefix, behavior End,
    // no SID Structure sub-TLV.
    assert_eq!(loc.end_sids.len(), 1);
    let sid = &loc.end_sids[0];
    assert_eq!(sid.behavior, 1);
    assert_eq!(sid.sid, v6_octets("2001:db8:a:1::"));
    assert!(sid.structure.is_none());
    // The encoded TLV round-trips through the slice-2 decoder.
    let mut wire = Vec::new();
    loc.encode(&mut wire);
    let (decoded, _) = Srv6LocatorTlv::decode(&wire, 0).expect("decodable");
    assert_eq!(&decoded, loc);
}

#[test]
fn srv6_origination_full_attributes() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_srv6_o_flag = true;
    cfg.ospf_srv6_max_sl = Some(8);
    cfg.ospf_srv6_max_end_d = Some(6);
    cfg.ospf_srv6_locators = vec![
        OspfSrv6LocatorSpec {
            prefix: Some("2001:db8:a:1::/64".to_string()),
            algorithm: Some(128), // flexible-algorithm space
            metric: Some(30),
            anycast: Some(true),
            sid: Some("2001:db8:a:1:f00d::".to_string()),
            behavior: Some(1),
            block_len: Some(32),
            node_len: Some(16),
            function_len: Some(16),
            argument_len: Some(0),
        },
        locator_spec("2001:db8:a:2::/64"),
    ];
    let s = Srv6Origination::from_config(&cfg);
    assert_eq!(s.capabilities, SRV6_CAP_O_FLAG);
    // Distinct algorithms, ascending (BTreeSet order).
    assert_eq!(s.algorithms, vec![0, 128]);
    // MSD pairs in the 41/42/44/45 wire order, only the configured ones.
    assert_eq!(
        s.msds,
        vec![(msd_type::SRH_MAX_SL, 8), (msd_type::SRH_MAX_END_D, 6)]
    );
    assert_eq!(s.locators.len(), 2);
    let first = &s.locators[0];
    assert_eq!(first.options, PREFIX_OPT_AC);
    assert_eq!(first.metric, 30);
    assert_eq!(first.end_sids[0].sid, v6_octets("2001:db8:a:1:f00d::"));
    assert_eq!(
        first.end_sids[0].structure,
        Some(Srv6SidStructure {
            lb_len: 32,
            ln_len: 16,
            func_len: 16,
            arg_len: 0,
        })
    );
    // The full TLV round-trips through the slice-2 decoder.
    let mut wire = Vec::new();
    first.encode(&mut wire);
    let (decoded, _) = Srv6LocatorTlv::decode(&wire, 0).expect("decodable");
    assert_eq!(&decoded, first);
}

#[test]
fn lan_end_x_base_masks_host_bits() {
    // /96: the low 32 bits clear — the Router-ID argument slot.
    assert_eq!(
        mask_lan_base("2001:db8:a:1:ffff:ffff:ffff:ffff/96", &[])
            .unwrap()
            .0,
        v6_octets("2001:db8:a:1:ffff:ffff::")
    );
    // /64: everything below the prefix clears.
    assert_eq!(
        mask_lan_base("2001:db8:a:1:dead:beef::1/64", &[])
            .unwrap()
            .0,
        v6_octets("2001:db8:a:1::")
    );
    // A non-byte-aligned length keeps the partial octet's high
    // bits (100 = 12 bytes + 4 bits: 0xff & 0xf0 = 0xf0).
    assert_eq!(
        mask_lan_base("2001:db8:a:1:0:0:ffff:ffff/100", &[])
            .unwrap()
            .0,
        v6_octets("2001:db8:a:1::f000:0")
    );
    // The covering locator's algorithm rides along (algorithm 128
    // on the covering locator, 0 default on the other).
    let locators = vec![
        locator_spec("2001:db8:a:1::/48"),
        OspfSrv6LocatorSpec {
            prefix: Some("2001:db8:b::/48".to_string()),
            algorithm: Some(128),
            ..Default::default()
        },
    ];
    assert_eq!(
        mask_lan_base("2001:db8:b:ffff::/96", &locators).unwrap().1,
        128
    );
    assert_eq!(
        mask_lan_base("2001:db8:a:1:ffff::/96", &locators)
            .unwrap()
            .1,
        0
    );
}

#[test]
fn e_router_links_broadcast_carries_9_1_and_9_2() {
    // A BDR's transit link (§A.4.3 type 2): Full with the DR
    // 3.3.3.3 and the DR-Others 4.4.4.4 + 5.5.5.5. RFC 9513 §9:
    // the plain End.X (§9.1) covers the DR adjacency, one LAN
    // End.X (§9.2) per DR-Other, all riding the same link.
    let links = vec![lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_TRANSIT,
        metric: 10,
        interface_id: 5,
        neighbor_interface_id: 77,
        neighbor_router_id: 0x0303_0303, // the DR
    }];
    let end_x_by_if = BTreeMap::new();
    let mut lan_end_x_by_if = BTreeMap::new();
    lan_end_x_by_if.insert(
        5u32,
        LanEndXSpec {
            dr_sid: Some((v6_octets("2001:db8:a:1::100"), 0)),
            base: Some((v6_octets("2001:db8:a:1:ffff::"), 0)),
            neighbors: vec![0x0404_0404, 0x0505_0505],
        },
    );
    let out = e_router_links(&links, &end_x_by_if, &lan_end_x_by_if);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].link_type, LINK_TYPE_TRANSIT);
    // §9.1: one plain End.X, the configured SID verbatim.
    let plain = lr_ospf::lsa::srv6::walk_end_x_sub_tlvs(&out[0].sub_tlvs);
    assert_eq!(plain.len(), 1);
    assert_eq!(plain[0].sid, v6_octets("2001:db8:a:1::100"));
    assert_eq!(plain[0].behavior, 5); // End.X (RFC 8986)
    assert_eq!(plain[0].algorithm, 0);
    assert_eq!(plain[0].flags, 0);
    // §9.2: one LAN End.X per neighbor, the SID derived as
    // base | Router-ID (the RID fills the low 32 bits).
    let lan = lr_ospf::lsa::srv6::walk_lan_end_x_sub_tlvs(&out[0].sub_tlvs);
    assert_eq!(lan.len(), 2);
    assert_eq!(lan[0].neighbor_router_id, 0x0404_0404);
    assert_eq!(lan[0].sid, v6_octets("2001:db8:a:1:ffff::404:404"));
    assert_eq!(lan[0].behavior, 5);
    assert_eq!(lan[1].neighbor_router_id, 0x0505_0505);
    assert_eq!(lan[1].sid, v6_octets("2001:db8:a:1:ffff::505:505"));
    // The §9.1 sub-TLV precedes the §9.2 instances on the wire
    // (type 31 before 32 in emission order; the §9.1 instance is
    // 4 + 24 = 28 octets, 4-aligned, so the LAN form starts at
    // 28).
    let t = u16::from_be_bytes([out[0].sub_tlvs[0], out[0].sub_tlvs[1]]);
    assert_eq!(t, lr_ospf::lsa::srv6::EXT_SUBTLV_END_X_SID);
    let t2 = u16::from_be_bytes([out[0].sub_tlvs[28], out[0].sub_tlvs[29]]);
    assert_eq!(t2, lr_ospf::lsa::srv6::EXT_SUBTLV_LAN_END_X_SID);
}

#[test]
fn e_router_links_dr_has_no_9_1_dr_adjacency() {
    // The DR describes itself (§A.4.3 self-referential shape): it
    // has no adjacency to a DR, so no §9.1 sub-TLV — only the
    // §9.2 LAN End.X per Full neighbor (BDR + DR-Others).
    let links = vec![lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_TRANSIT,
        metric: 10,
        interface_id: 5,
        neighbor_interface_id: 5,
        neighbor_router_id: 0x0303_0303, // ourselves
    }];
    let end_x_by_if = BTreeMap::new();
    let mut lan_end_x_by_if = BTreeMap::new();
    lan_end_x_by_if.insert(
        5u32,
        LanEndXSpec {
            dr_sid: None,
            base: Some((v6_octets("2001:db8:a:1:ffff::"), 0)),
            neighbors: vec![0x0202_0202, 0x0404_0404],
        },
    );
    let out = e_router_links(&links, &end_x_by_if, &lan_end_x_by_if);
    assert!(lr_ospf::lsa::srv6::walk_end_x_sub_tlvs(&out[0].sub_tlvs).is_empty());
    let lan = lr_ospf::lsa::srv6::walk_lan_end_x_sub_tlvs(&out[0].sub_tlvs);
    assert_eq!(lan.len(), 2);
    assert_eq!(lan[0].neighbor_router_id, 0x0202_0202);
    assert_eq!(lan[0].sid, v6_octets("2001:db8:a:1:ffff::202:202"));
}

#[test]
fn e_router_links_p2p_keeps_the_plain_form() {
    // A p2p link (§A.4.3 type 1) with the §9.1 SID configured:
    // exactly one plain End.X, no LAN forms.
    let links = vec![lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: 5,
        neighbor_interface_id: 77,
        neighbor_router_id: 0x0202_0202,
    }];
    let mut end_x_by_if = BTreeMap::new();
    end_x_by_if.insert(5u32, (v6_octets("2001:db8:a:1::100"), 0));
    let out = e_router_links(&links, &end_x_by_if, &BTreeMap::new());
    let plain = lr_ospf::lsa::srv6::walk_end_x_sub_tlvs(&out[0].sub_tlvs);
    assert_eq!(plain.len(), 1);
    assert_eq!(plain[0].sid, v6_octets("2001:db8:a:1::100"));
    assert!(lr_ospf::lsa::srv6::walk_lan_end_x_sub_tlvs(&out[0].sub_tlvs).is_empty());
}

// ---------------------------------------------------------------------------
// RFC 7166 OSPFv3 authentication trailer — daemon wiring
// ---------------------------------------------------------------------------

/// Build a minimal OSPFv3 packet (16-byte header + 4-byte Hello body
/// tail to round it up to the v3 header length). The body shape itself
/// does not matter for the auth tests — the MAC is computed over the
/// packet bytes verbatim (with the checksum field zeroed), so any
/// 16+ byte v3-shaped buffer round-trips.
fn minimal_v3_packet() -> Vec<u8> {
    let mut h = vec![0u8; lr_ospf::packet::OspfHeader::LEN_V3];
    h[0] = 3; // version 3
    h[1] = 1; // type = Hello
    let len = lr_ospf::packet::OspfHeader::LEN_V3 as u16;
    h[2..4].copy_from_slice(&len.to_be_bytes());
    h[4..8].copy_from_slice(&1u32.to_be_bytes()); // router id
    h[8..12].copy_from_slice(&0u32.to_be_bytes()); // area id
    h[12..14].copy_from_slice(&0u16.to_be_bytes()); // checksum (zeroed)
    h[14..16].copy_from_slice(&0u16.to_be_bytes()); // instance id
    h
}

/// `OspfV3AuthState::None` is the default — `is_active()` returns
/// false, and both `apply_ospf_v3_auth` and `verify_ospf_v3_auth` are
/// no-ops (apply returns false so the caller falls through to the
/// finalize path; verify returns true so the caller accepts the
/// packet).
#[test]
fn ospf_v3_auth_state_default_is_null() {
    let mut state = OspfV3AuthState::default();
    assert!(!state.is_active(), "default is NullAuth — not active");
    let mut bytes = minimal_v3_packet();
    let applied = apply_ospf_v3_auth(&mut state, &mut bytes, [0u8; 16]);
    assert!(!applied, "NullAuth apply is a no-op (returns false)");
    assert_eq!(
        bytes.len(),
        lr_ospf::packet::OspfHeader::LEN_V3,
        "NullAuth does not append a trailer"
    );
    let verified = verify_ospf_v3_auth(&mut state, &bytes, [0u8; 16]);
    assert!(verified, "NullAuth verify accepts everything");
}

/// `build_ospf_v3_auth` constructs `None` for the default config (no
/// `[ospf.auth]` block) and for `type = "null"` (the explicit default)
/// and constructs `Crypto` for `type = "crypto"` with the configured
/// SA ID, key and algorithm.
#[test]
fn build_ospf_v3_auth_maps_config_to_state() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v3".to_string();
    // Default: no `[ospf.auth]` block → None.
    let state = build_ospf_v3_auth(&cfg);
    assert!(matches!(state, OspfV3AuthState::None));

    // Explicit null.
    cfg.ospf_auth.auth_type = Some("null".to_string());
    let state = build_ospf_v3_auth(&cfg);
    assert!(matches!(state, OspfV3AuthState::None));

    // Crypto with HMAC-SHA-256 (the default).
    cfg.ospf_auth.auth_type = Some("crypto".to_string());
    cfg.ospf_auth.key = Some("shared-secret".to_string());
    cfg.ospf_auth.key_id = Some(7);
    let state = build_ospf_v3_auth(&cfg);
    match state {
        OspfV3AuthState::Crypto(arc) => {
            let ca = arc.lock().unwrap();
            assert_eq!(ca.sa_id, 7, "SA ID = key_id (widened to u16)");
            assert_eq!(ca.algorithm, lr_ospf::auth::CryptoAlgorithm::HmacSha256);
            assert_eq!(ca.key, b"shared-secret", "key from config");
        }
        _ => panic!("crypto config produces Crypto state"),
    }

    // HMAC-SHA-1 override.
    cfg.ospf_auth.algorithm = Some("hmac-sha1".to_string());
    let state = build_ospf_v3_auth(&cfg);
    match state {
        OspfV3AuthState::Crypto(arc) => {
            let ca = arc.lock().unwrap();
            assert_eq!(ca.algorithm, lr_ospf::auth::CryptoAlgorithm::HmacSha1);
        }
        _ => panic!("crypto config produces Crypto state"),
    }
}

/// `apply_ospf_v3_auth` under Crypto appends the RFC 7166 trailer
/// (16-octet fixed header + 32-byte SHA-256 digest = 48 octets) and
/// zeroes the OSPFv3 header checksum (offset 12..14). The OSPF
/// length at offset 2..4 stays at the body length (the trailer is
/// NOT counted — RFC 7166 §4.2).
#[test]
fn apply_ospf_v3_auth_appends_trailer_and_zeros_checksum() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v3".to_string();
    cfg.ospf_auth.auth_type = Some("crypto".to_string());
    cfg.ospf_auth.key = Some("shared-secret".to_string());
    cfg.ospf_auth.key_id = Some(7);
    let mut state = build_ospf_v3_auth(&cfg);

    let mut bytes = minimal_v3_packet();
    let body_len = bytes.len();
    let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let applied = apply_ospf_v3_auth(&mut state, &mut bytes, src);
    assert!(applied, "Crypto apply returns true");
    // Trailer = 16 (fixed header) + 32 (SHA-256 digest) = 48 bytes.
    assert_eq!(
        bytes.len(),
        body_len + 48,
        "trailer appended (RFC 7166 §4.1)"
    );
    // Checksum field zeroed (offset 12..14).
    assert_eq!(&bytes[12..14], &[0u8, 0u8], "checksum zeroed (§4.2)");
    // OSPF length stays at the body length.
    let ospf_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    assert_eq!(
        ospf_len, body_len,
        "OSPF length excludes the trailer (§4.2)"
    );
    // The trailer's Auth Type = 1 (HMAC), Auth Data Len = 48 (entire
    // trailer), SA ID = 7 (from key_id).
    let trailer = &bytes[body_len..];
    assert_eq!(
        u16::from_be_bytes([trailer[0], trailer[1]]),
        1,
        "Auth Type = HMAC"
    );
    assert_eq!(
        u16::from_be_bytes([trailer[2], trailer[3]]),
        48,
        "Auth Data Len = 48 (entire trailer)"
    );
    assert_eq!(u16::from_be_bytes([trailer[6], trailer[7]]), 7, "SA ID = 7");
}

/// `apply_ospf_v3_auth` advances the crypto_seq on every call so
/// successive packets carry strictly larger sequence numbers
/// (RFC 7166 §4.6 anti-replay).
#[test]
fn apply_ospf_v3_auth_advances_seq_monotonically() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v3".to_string();
    cfg.ospf_auth.auth_type = Some("crypto".to_string());
    cfg.ospf_auth.key = Some("key".to_string());
    cfg.ospf_auth.key_id = Some(1);
    let mut state = build_ospf_v3_auth(&cfg);
    let src = [0u8; 16];

    let mut bytes_a = minimal_v3_packet();
    apply_ospf_v3_auth(&mut state, &mut bytes_a, src);
    let seq_a = u64::from_be_bytes([
        bytes_a[bytes_a.len() - 48 + 8],
        bytes_a[bytes_a.len() - 48 + 9],
        bytes_a[bytes_a.len() - 48 + 10],
        bytes_a[bytes_a.len() - 48 + 11],
        bytes_a[bytes_a.len() - 48 + 12],
        bytes_a[bytes_a.len() - 48 + 13],
        bytes_a[bytes_a.len() - 48 + 14],
        bytes_a[bytes_a.len() - 48 + 15],
    ]);

    let mut bytes_b = minimal_v3_packet();
    apply_ospf_v3_auth(&mut state, &mut bytes_b, src);
    let seq_b = u64::from_be_bytes([
        bytes_b[bytes_b.len() - 48 + 8],
        bytes_b[bytes_b.len() - 48 + 9],
        bytes_b[bytes_b.len() - 48 + 10],
        bytes_b[bytes_b.len() - 48 + 11],
        bytes_b[bytes_b.len() - 48 + 12],
        bytes_b[bytes_b.len() - 48 + 13],
        bytes_b[bytes_b.len() - 48 + 14],
        bytes_b[bytes_b.len() - 48 + 15],
    ]);
    assert!(seq_b > seq_a, "crypto_seq advances between calls");
}

/// A signed packet verifies at the receiver when the same key, SA ID
/// and source IPv6 address are configured. The round-trip mirrors
/// what two daemons on a link would see: the sender signs with its
/// link-local, the receiver verifies with the peer's link-local
/// (the same address — the packet's source).
#[test]
fn apply_ospf_v3_auth_then_verify_roundtrip() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v3".to_string();
    cfg.ospf_auth.auth_type = Some("crypto".to_string());
    cfg.ospf_auth.key = Some("shared-secret".to_string());
    cfg.ospf_auth.key_id = Some(1);
    let mut signer = build_ospf_v3_auth(&cfg);
    let mut verifier = build_ospf_v3_auth(&cfg);

    let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut bytes = minimal_v3_packet();
    apply_ospf_v3_auth(&mut signer, &mut bytes, src);
    assert!(
        verify_ospf_v3_auth(&mut verifier, &bytes, src),
        "matching key + SA ID + source verifies"
    );
}

/// A packet signed with one key fails verification when the verifier
/// is configured with a different key — the MAC mismatch is the
/// security boundary (RFC 7166 §4.5).
#[test]
fn apply_ospf_v3_auth_wrong_key_rejected() {
    let mut cfg_sign = DaemonConfig::with_defaults();
    cfg_sign.protocol = "ospf".to_string();
    cfg_sign.ospf_version = "v3".to_string();
    cfg_sign.ospf_auth.auth_type = Some("crypto".to_string());
    cfg_sign.ospf_auth.key = Some("correct".to_string());
    cfg_sign.ospf_auth.key_id = Some(1);
    let mut signer = build_ospf_v3_auth(&cfg_sign);

    let mut cfg_verify = DaemonConfig::with_defaults();
    cfg_verify.protocol = "ospf".to_string();
    cfg_verify.ospf_version = "v3".to_string();
    cfg_verify.ospf_auth.auth_type = Some("crypto".to_string());
    cfg_verify.ospf_auth.key = Some("wrong".to_string());
    cfg_verify.ospf_auth.key_id = Some(1);
    let mut verifier = build_ospf_v3_auth(&cfg_verify);

    let src = [0u8; 16];
    let mut bytes = minimal_v3_packet();
    apply_ospf_v3_auth(&mut signer, &mut bytes, src);
    assert!(
        !verify_ospf_v3_auth(&mut verifier, &bytes, src),
        "wrong key must fail the MAC check"
    );
}

/// A packet signed with one source fails verification when the
/// verifier passes a different source — Apad (RFC 7166 §2.3/§4.5)
/// embeds the source in the MAC input.
#[test]
fn apply_ospf_v3_auth_wrong_source_rejected() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v3".to_string();
    cfg.ospf_auth.auth_type = Some("crypto".to_string());
    cfg.ospf_auth.key = Some("key".to_string());
    cfg.ospf_auth.key_id = Some(1);
    let mut signer = build_ospf_v3_auth(&cfg);
    let mut verifier = build_ospf_v3_auth(&cfg);

    let mut src_a = [0u8; 16];
    src_a[15] = 1;
    let mut src_b = [0u8; 16];
    src_b[15] = 2;
    let mut bytes = minimal_v3_packet();
    apply_ospf_v3_auth(&mut signer, &mut bytes, src_a);
    assert!(
        verify_ospf_v3_auth(&mut verifier, &bytes, src_a),
        "matching source verifies"
    );
    // Re-create the verifier — verify mutates last_peer_seq, so a
    // second verify call against the same packet would fail the
    // anti-replay check (the correct behaviour, but not what this
    // test asserts).
    let mut verifier = build_ospf_v3_auth(&cfg);
    assert!(
        !verify_ospf_v3_auth(&mut verifier, &bytes, src_b),
        "different source must fail the MAC check (Apad mismatch)"
    );
}

/// A replayed packet (the same bytes verified twice) is rejected on
/// the second call — the anti-replay check (RFC 7166 §4.6) keeps the
/// last seen `crypto_seq` and rejects any sequence ≤ it.
#[test]
fn apply_ospf_v3_auth_replay_rejected() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v3".to_string();
    cfg.ospf_auth.auth_type = Some("crypto".to_string());
    cfg.ospf_auth.key = Some("key".to_string());
    cfg.ospf_auth.key_id = Some(1);
    let mut signer = build_ospf_v3_auth(&cfg);
    let mut verifier = build_ospf_v3_auth(&cfg);

    let src = [0u8; 16];
    let mut bytes = minimal_v3_packet();
    apply_ospf_v3_auth(&mut signer, &mut bytes, src);
    assert!(
        verify_ospf_v3_auth(&mut verifier, &bytes, src),
        "first packet accepted"
    );
    assert!(
        !verify_ospf_v3_auth(&mut verifier, &bytes, src),
        "replay must be rejected (anti-replay, RFC 7166 §4.6)"
    );
}

/// `verify_ospf_v3_auth` under `None` (NullAuth) accepts a packet
/// that has no trailer — a sender without auth configured sends a
/// bare OSPFv3 packet, and the receiver without auth accepts it.
/// The OSPF length at offset 2..4 matches the datagram length (no
/// trailer is appended).
#[test]
fn verify_ospf_v3_auth_null_accepts_no_trailer() {
    let mut state = OspfV3AuthState::default();
    let bytes = minimal_v3_packet();
    assert!(
        verify_ospf_v3_auth(&mut state, &bytes, [0u8; 16]),
        "NullAuth accepts a packet with no trailer"
    );
}

/// `verify_ospf_v3_auth` under `Crypto` rejects a packet that has
/// no trailer (the OSPF length matches the datagram length, so the
/// split leaves an empty trailer slice — V3Auth::verify rejects
/// that as a malformed trailer).
#[test]
fn verify_ospf_v3_auth_crypto_rejects_no_trailer() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v3".to_string();
    cfg.ospf_auth.auth_type = Some("crypto".to_string());
    cfg.ospf_auth.key = Some("key".to_string());
    cfg.ospf_auth.key_id = Some(1);
    let mut verifier = build_ospf_v3_auth(&cfg);

    let bytes = minimal_v3_packet();
    assert!(
        !verify_ospf_v3_auth(&mut verifier, &bytes, [0u8; 16]),
        "Crypto must reject a packet with no trailer (fail-closed)"
    );
}

/// HMAC-SHA-1 produces a 20-byte digest (vs SHA-256's 32), so the
/// trailer is 16 + 20 = 36 bytes — pin the algorithm dispatch so a
/// regression that flips the SHA-256/SHA-1 wire length is caught.
#[test]
fn apply_ospf_v3_auth_hmac_sha1_trailer_length() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v3".to_string();
    cfg.ospf_auth.auth_type = Some("crypto".to_string());
    cfg.ospf_auth.key = Some("key".to_string());
    cfg.ospf_auth.key_id = Some(1);
    cfg.ospf_auth.algorithm = Some("hmac-sha1".to_string());
    let mut state = build_ospf_v3_auth(&cfg);

    let mut bytes = minimal_v3_packet();
    let body_len = bytes.len();
    apply_ospf_v3_auth(&mut state, &mut bytes, [0u8; 16]);
    assert_eq!(
        bytes.len(),
        body_len + 36,
        "SHA-1 trailer = 16 fixed header + 20 digest"
    );
}

/// `[ospf.auth] type = "simple"` is rejected at finalize time when
/// `[ospf] version = "v3"` — RFC 5340 §A.3.1 removed the auth_data
/// field from the header, so SimplePassword is not a v3 strategy.
/// The error message names RFC 7166 as the v3 alternative. The
/// finalize_ospf path only fires when OSPF is configured (at least
/// one OSPF interface), so the test carries a stub interface.
#[test]
fn finalize_ospf_rejects_simple_under_v3() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v3".to_string();
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("lo".to_string()),
        ..Default::default()
    });
    cfg.ospf_auth.auth_type = Some("simple".to_string());
    cfg.ospf_auth.password = Some("secret".to_string());
    let err = cfg.finalize().expect_err("simple under v3 fails closed");
    let msg = err.to_string();
    assert!(
        msg.contains("not valid for OSPFv3"),
        "error explains the v3 incompatibility"
    );
    assert!(
        msg.contains("RFC 7166"),
        "error names RFC 7166 as the v3 alternative"
    );
}

/// `[ospf.auth] type = "simple"` under v2 still finalizes cleanly
/// (the v3-only rejection does not affect the v2 path).
#[test]
fn finalize_ospf_accepts_simple_under_v2() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_version = "v2".to_string();
    cfg.ospf_interfaces.push(crate::daemon_config::OspfIfSpec {
        name: Some("lo".to_string()),
        ..Default::default()
    });
    cfg.ospf_auth.auth_type = Some("simple".to_string());
    cfg.ospf_auth.password = Some("secret".to_string());
    cfg.finalize().expect("v2 simple is valid");
}
