//! BFD Strict-Mode end-to-end tests
//! (draft-ietf-idr-bgp-bfd-strict-mode-19).
//!
//! The wire capability is inert on its own: the session must hold its
//! KEEPALIVE and OpenConfirm transition until BFD reports Up when both
//! speakers advertised the capability, and a BFD Down in Established
//! must send Cease / BFD Down (6/10) and purge the peer's routes
//! instead of retaining them under graceful restart.

use lr_bgp::BfdState;
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

fn pump(a: &mut DefaultRouter, ha: SessionHandle, b: &mut DefaultRouter, hb: SessionHandle) {
    for _ in 0..16 {
        let out_a = a.drain_output(ha);
        if !out_a.is_empty() {
            b.feed_input(hb, &out_a).unwrap();
        }
        let out_b = b.drain_output(hb);
        if !out_b.is_empty() {
            a.feed_input(ha, &out_b).unwrap();
        }
        if out_a.is_empty() && out_b.is_empty() {
            return;
        }
    }
    panic!("byte pump did not converge");
}

fn strict_cfg(local_as: u32, peer_as: u32, rid: [u8; 4], local: [u8; 4]) -> SessionConfig {
    SessionConfig::bgp(Asn(local_as), Asn(peer_as), RouterId::from_v4(rid))
        .with_local_address(IpAddr::V4(local))
        .with_bfd_strict_mode()
        .with_mrai_ms(0)
}

/// The OPEN is generated with the capability list; locate the first
/// (and only) capability parameter and decode it.
fn open_capabilities(open: &[u8]) -> Vec<lr_bgp::capabilities::Capability> {
    // BGP header (19) + version (1) + my_as (2) + hold (2) + bgp_id
    // (4) = 28, then the optional-parameter length.
    let opt_len = open[28] as usize;
    let params = &open[29..29 + opt_len];
    assert_eq!(params[0], 2, "capability parameter");
    lr_bgp::capabilities::Capability::decode_set(&params[2..2 + params[1] as usize])
}

/// Both sides advertise strict-mode but BFD is Down: the handshake
/// stops in OpenSent until BFD Up, then completes.
#[test]
fn bfd_strict_mode_gates_open_confirm_until_up() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(strict_cfg(64512, 64513, [10, 0, 0, 1], [192, 0, 2, 1]))
        .unwrap();
    let hb = b
        .add_session(strict_cfg(64513, 64512, [10, 0, 0, 2], [192, 0, 2, 2]))
        .unwrap();
    a.set_bfd_state(ha, Some(BfdState::Down));
    b.set_bfd_state(hb, Some(BfdState::Down));
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();

    let a_open = a.drain_output(ha);
    assert!(!a_open.is_empty(), "the OPEN still goes out");
    b.feed_input(hb, &a_open).unwrap();
    let b_open = b.drain_output(hb);
    a.feed_input(ha, &b_open).unwrap();

    assert_eq!(a.session_peer_state(ha), Some("OpenSent"));
    assert_eq!(b.session_peer_state(hb), Some("OpenSent"));
    assert!(
        a.drain_output(ha).is_empty(),
        "no KEEPALIVE may be sent while BFD is Down"
    );

    // BFD Up releases both sides.
    a.set_bfd_state(ha, Some(BfdState::Up));
    b.set_bfd_state(hb, Some(BfdState::Up));
    let a_ka = a.drain_output(ha);
    let b_ka = b.drain_output(hb);
    assert!(!a_ka.is_empty() && !b_ka.is_empty());
    a.feed_input(ha, &b_ka).unwrap();
    b.feed_input(hb, &a_ka).unwrap();
    assert_eq!(a.session_peer_state(ha), Some("Established"));
    assert_eq!(b.session_peer_state(hb), Some("Established"));

    // A route learned from B is present.
    let prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    b.originate(prefix, Some(IpAddr::V4([192, 0, 2, 2])));
    pump(&mut a, ha, &mut b, hb);
    assert!(
        a.rib_paths_snapshot()
            .iter()
            .any(|r| r.key.prefix == prefix),
        "the session must carry routes once Established"
    );

    // BFD Down in Established: Cease / BFD Down and an immediate purge
    // (no graceful-restart retention — the forwarding path is gone).
    a.set_bfd_state(ha, Some(BfdState::Down));
    let out = a.drain_output(ha);
    assert_eq!(out[18], 3, "NOTIFICATION");
    assert_eq!(out[19], 6, "Cease");
    assert_eq!(out[20], 10, "BFD Down");
    assert_eq!(a.session_peer_state(ha), Some("Idle"));
    assert!(
        a.rib_paths_snapshot()
            .iter()
            .all(|r| r.key.prefix != prefix),
        "BFD Down must purge the peer's routes, not retain them"
    );
}

/// Strict-mode is negotiated: a peer that does not advertise the
/// capability keeps the normal OPEN path even when local BFD is Down.
#[test]
fn bfd_strict_mode_does_not_gate_a_non_strict_peer() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(strict_cfg(64512, 64513, [10, 0, 0, 1], [192, 0, 2, 1]))
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2]))
                .with_mrai_ms(0),
        )
        .unwrap();
    a.set_bfd_state(ha, Some(BfdState::Down));
    b.set_bfd_state(hb, Some(BfdState::Down));
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    assert_eq!(a.session_peer_state(ha), Some("Established"));
}

/// The capability is advertised only when BFD itself is enabled (the
/// draft's `BfdEnabled`): a strict-mode-only configuration is inert.
#[test]
fn bfd_strict_mode_capability_requires_bfd_enabled() {
    let mut a = DefaultRouter::new();
    let mut cfg = SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
        .with_local_address(IpAddr::V4([192, 0, 2, 1]));
    cfg.bfd_strict_mode = true; // bfd_enabled stays false
    let ha = a.add_session(cfg).unwrap();
    a.start_session(ha).unwrap();
    let open = a.drain_output(ha);
    let caps = open_capabilities(&open);
    assert!(
        !caps
            .iter()
            .any(|c| c.code == lr_bgp::capabilities::CapabilityCode::BfdStrictMode),
        "code 74 must be absent without BFD"
    );
}
