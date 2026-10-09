use super::*;
use lr_core::addr::RouterId;

// ===== RFC 4271 §6.8 connection collision resolution =====

/// One side of the simulated peer. Every instance carries the same BGP
/// Identifier — from the router under test's perspective they are the
/// same speaker seen over two transports, which is exactly what a
/// connection collision looks like.
fn collision_peer(bgp_id: [u8; 4]) -> (DefaultRouter, SessionHandle) {
    let mut p = DefaultRouter::new();
    let s = p
        .add_session(SessionConfig::bgp(
            Asn(64513),
            Asn(64512),
            RouterId::from_v4(bgp_id),
        ))
        .unwrap();
    (p, s)
}

/// A router-under-test session in the §6.8 collision group 1.
fn collision_session(
    r: &mut DefaultRouter,
    locally_initiated: bool,
    local_id: [u8; 4],
) -> SessionHandle {
    let mut cfg = SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4(local_id));
    cfg.collision_group = Some(1);
    cfg.locally_initiated = locally_initiated;
    r.add_session(cfg).unwrap()
}

/// Handshake one connection up to Established (or stop early when the
/// router closes it mid-handshake). Returns the peer's final state.
fn handshake(
    r: &mut DefaultRouter,
    r_session: SessionHandle,
    p: &mut DefaultRouter,
    p_session: SessionHandle,
) -> &'static str {
    p.start_session(p_session).unwrap();
    r.start_session(r_session).unwrap();
    // The peer's OPEN arrives on our transport.
    let p_open = p.drain_output(p_session);
    r.feed_input(r_session, &p_open).unwrap();
    // Our reply: KEEPALIVE when we survived the §6.8 check, the Cease
    // NOTIFICATION when we lost.
    let reply = r.drain_output(r_session);
    p.feed_input(p_session, &reply).unwrap();
    if !matches!(
        r.session_peer_state(r_session),
        Some("OpenConfirm") | Some("Established")
    ) {
        return p.session_peer_state(p_session).unwrap_or("Idle");
    }
    // Complete the handshake in both directions.
    let p_keepalive = p.drain_output(p_session);
    r.feed_input(r_session, &p_keepalive).unwrap();
    let _ = r.drain_output(r_session);
    r.session_peer_state(r_session).unwrap_or("Idle")
}

/// Collect (code, subcode) of every NOTIFICATION in a wire chunk.
fn notification_codes(bytes: &[u8]) -> Vec<(u8, u8)> {
    use lr_core::codec::Decoder;
    let mut out = Vec::new();
    let mut r = lr_core::buf::ReadBuf::new(bytes);
    let mut codec = lr_bgp::codec::BgpCodec::new();
    while let Ok(Some(m)) = codec.decode(&mut r) {
        if let lr_bgp::message::BgpMessage::Notification(n) = m {
            out.push((n.error_code, n.error_subcode));
        }
    }
    out
}

/// The router's BGP Identifier is LOWER than the peer's: the
/// remotely-initiated connection wins, so the outbound (locally
/// initiated) transport is closed with Cease/7 while the inbound one
/// completes the handshake.
#[test]
fn collision_lower_local_id_loses_outbound_transport() {
    let mut r = DefaultRouter::new();
    // 10.0.0.1 < 10.0.0.9 — the locally initiated session must lose.
    let s_out = collision_session(&mut r, true, [10, 0, 0, 1]);
    let s_in = collision_session(&mut r, false, [10, 0, 0, 1]);
    let (mut a, a_session) = collision_peer([10, 0, 0, 9]);
    let (mut b, b_session) = collision_peer([10, 0, 0, 9]);

    r.start_session(s_out).unwrap();
    r.start_session(s_in).unwrap();
    // The outbound transport's OPEN reply arrives first.
    a.start_session(a_session).unwrap();
    let a_open = a.drain_output(a_session);
    r.feed_input(s_out, &a_open).unwrap();
    // §6.8: the sibling (inbound, remotely initiated, OpenSent) wins.
    assert_eq!(r.session_peer_state(s_out), Some("Idle"));
    let loss = r.drain_output(s_out);
    assert_eq!(
        notification_codes(&loss),
        vec![(6, 7)],
        "Cease / Connection Collision Resolution expected"
    );
    // The inbound transport completes its handshake untouched.
    let outcome = handshake(&mut r, s_in, &mut b, b_session);
    assert_eq!(outcome, "Established");
}

/// The router's BGP Identifier is HIGHER than the peer's: the locally
/// initiated connection survives and the inbound challenger is closed.
#[test]
fn collision_higher_local_id_keeps_outbound_transport() {
    let mut r = DefaultRouter::new();
    let s_out = collision_session(&mut r, true, [10, 0, 0, 9]);
    let s_in = collision_session(&mut r, false, [10, 0, 0, 9]);
    let (mut a, a_session) = collision_peer([10, 0, 0, 1]);
    let _b = collision_peer([10, 0, 0, 1]);

    r.start_session(s_out).unwrap();
    r.start_session(s_in).unwrap();
    a.start_session(a_session).unwrap();
    let a_open = a.drain_output(a_session);
    r.feed_input(s_out, &a_open).unwrap();
    // §6.8: our outbound connection (locally initiated, higher ID wins)
    // survives; the inbound challenger is closed.
    assert_eq!(r.session_peer_state(s_in), Some("Idle"));
    let loss = r.drain_output(s_in);
    assert_eq!(notification_codes(&loss), vec![(6, 7)]);
    // The outbound transport completes its handshake.
    let outcome = handshake(&mut r, s_out, &mut a, a_session);
    assert_eq!(outcome, "Established");
    assert_eq!(r.session_peer_state(s_out), Some("Established"));
}

/// A collision against an Established sibling always closes the new
/// connection, regardless of BGP Identifier ordering.
#[test]
fn collision_established_sibling_wins() {
    let mut r = DefaultRouter::new();
    let s_out = collision_session(&mut r, true, [10, 0, 0, 9]);
    let s_in = collision_session(&mut r, false, [10, 0, 0, 9]);
    let (mut a, a_session) = collision_peer([10, 0, 0, 1]);
    let (mut b, b_session) = collision_peer([10, 0, 0, 1]);

    // Bring the outbound transport fully up first.
    assert_eq!(handshake(&mut r, s_out, &mut a, a_session), "Established");
    // Now the inbound challenger arrives — the Established connection
    // wins, the challenger gets Cease/7.
    r.start_session(s_in).unwrap();
    b.start_session(b_session).unwrap();
    let b_open = b.drain_output(b_session);
    r.feed_input(s_in, &b_open).unwrap();
    assert_eq!(r.session_peer_state(s_in), Some("Idle"));
    let loss = r.drain_output(s_in);
    assert_eq!(notification_codes(&loss), vec![(6, 7)]);
    assert_eq!(r.session_peer_state(s_out), Some("Established"));
}

/// Sessions without a collision group never interfere, even with
/// identical peer BGP Identifiers.
#[test]
fn no_collision_group_means_no_resolution() {
    let mut r = DefaultRouter::new();
    let plain_cfg = |r: &mut DefaultRouter| {
        r.add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 1]),
        ))
        .unwrap()
    };
    let s1 = plain_cfg(&mut r);
    let s2 = plain_cfg(&mut r);
    let (mut a, a_session) = collision_peer([10, 0, 0, 9]);
    let (mut b, b_session) = collision_peer([10, 0, 0, 9]);

    assert_eq!(handshake(&mut r, s1, &mut a, a_session), "Established");
    assert_eq!(handshake(&mut r, s2, &mut b, b_session), "Established");
    assert_eq!(r.session_peer_state(s1), Some("Established"));
    assert_eq!(r.session_peer_state(s2), Some("Established"));
}

/// A wire-level Cease / Connection Collision Resolution NOTIFICATION
/// (RFC 4486 subcode 7): marker + length + type 3 + code 6 + subcode 7.
fn cease_collision_resolution() -> Vec<u8> {
    // BGP NOTIFICATION (RFC 4271 §4.5): 16-octet marker, length 21,
    // type 3, Error Code 6 (Cease), Error Subcode 7 (Connection
    // Collision Resolution), no data.
    let mut b = vec![0xffu8; 16];
    b.extend_from_slice(&21u16.to_be_bytes());
    b.push(3);
    b.push(6);
    b.push(7);
    b
}

/// RFC 4486 §4.1: an administrative close of a live session queues a
/// Cease / Administrative Shutdown NOTIFICATION on the wire before
/// the transport goes away.
#[test]
fn shutdown_session_flushes_cease_admin_shutdown() {
    let mut r = DefaultRouter::new();
    let s = r
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 9]),
        ))
        .unwrap();
    let (mut a, a_session) = collision_peer([10, 0, 0, 1]);
    assert_eq!(handshake(&mut r, s, &mut a, a_session), "Established");
    let _ = r.drain_output(s);

    r.shutdown_session(s);
    assert_eq!(r.session_peer_state(s), Some("Idle"));
    let out = r.drain_output(s);
    assert_eq!(
        notification_codes(&out),
        vec![(6, 2)],
        "Cease / Administrative Shutdown expected on the wire"
    );
}

/// A received NOTIFICATION is a deliberate goodbye (RFC 4486): the
/// peer announced it is going away, so RFC 4724/9494 retention must
/// NOT arm (BIRD parity — BIRD retains only on silent transport
/// deaths; retaining after an announced shutdown would blackhole
/// traffic for the whole window).
#[test]
fn received_notification_purges_instead_of_retaining() {
    let mut r = DefaultRouter::new();
    let s = r
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 9]),
        ))
        .unwrap();
    let (mut a, a_session) = collision_peer([10, 0, 0, 1]);
    assert_eq!(handshake(&mut r, s, &mut a, a_session), "Established");
    let _ = r.drain_output(s);
    // The peer administratively shuts down: Cease / Administrative
    // Shutdown (RFC 4486 §4.1 subcode 2).
    let mut bye = vec![0xffu8; 16];
    bye.extend_from_slice(&21u16.to_be_bytes());
    bye.extend_from_slice(&[3, 6, 2]);
    r.feed_input(s, &bye).unwrap();
    assert_eq!(r.session_peer_state(s), Some("Idle"));
    r.close_session(s);
    let retention = r.poll_events().iter().any(
        |e| matches!(e, RouterEvent::Log(l) if l.contains("entered graceful-restart retention")),
    );
    assert!(
        !retention,
        "a peer's announced shutdown must not arm retention"
    );
}

/// Our own administrative close (shutdown_session, RFC 4486 §4.1)
/// deliberately ends the session — retention must not arm.
#[test]
fn administrative_close_purges_instead_of_retaining() {
    let mut r = DefaultRouter::new();
    let s = r
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 9]),
        ))
        .unwrap();
    let (mut a, a_session) = collision_peer([10, 0, 0, 1]);
    assert_eq!(handshake(&mut r, s, &mut a, a_session), "Established");
    let _ = r.drain_output(s);
    r.shutdown_session(s);
    let out = r.drain_output(s);
    assert_eq!(notification_codes(&out), vec![(6, 2)]);
    r.close_session(s);
    let retention = r.poll_events().iter().any(
        |e| matches!(e, RouterEvent::Log(l) if l.contains("entered graceful-restart retention")),
    );
    assert!(!retention, "an administrative close must not arm retention");
}

/// A Cease / Connection Collision Resolution NOTIFICATION received
/// from the peer — its resolver closing our transport — latches the
/// same collision-loss signal our own resolver produces, so the
/// embedder can hold the connector back in both flavors.
#[test]
fn received_cease_6_7_latches_collision_loss() {
    let mut r = DefaultRouter::new();
    let s_out = collision_session(&mut r, true, [10, 0, 0, 9]);
    let (mut a, a_session) = collision_peer([10, 0, 0, 1]);

    // Single-transport OPEN exchange: no sibling, no local resolution.
    r.start_session(s_out).unwrap();
    a.start_session(a_session).unwrap();
    let a_open = a.drain_output(a_session);
    r.feed_input(s_out, &a_open).unwrap();
    assert_eq!(r.session_peer_state(s_out), Some("OpenConfirm"));
    assert!(!r.take_collision_lost(s_out), "no loss yet");

    // The peer's resolver sends Cease/7 on this transport.
    r.feed_input(s_out, &cease_collision_resolution()).unwrap();
    assert_eq!(r.session_peer_state(s_out), Some("Idle"));
    assert!(
        r.take_collision_lost(s_out),
        "a received Cease/7 must latch the loss"
    );
    assert!(!r.take_collision_lost(s_out), "the latch is consumed once");
}

/// The collision-loss latch is per transport incarnation: restarting
/// the session clears it, so a later unrelated Idle is not mistaken
/// for a collision loss.
#[test]
fn collision_loss_latch_cleared_by_start_session() {
    let mut r = DefaultRouter::new();
    // 10.0.0.1 < 10.0.0.9 — the locally initiated transport loses.
    let s_out = collision_session(&mut r, true, [10, 0, 0, 1]);
    let s_in = collision_session(&mut r, false, [10, 0, 0, 1]);
    let (mut a, a_session) = collision_peer([10, 0, 0, 9]);
    let (mut b, b_session) = collision_peer([10, 0, 0, 9]);

    // s_out loses to the inbound sibling (lower local ID).
    r.start_session(s_out).unwrap();
    r.start_session(s_in).unwrap();
    a.start_session(a_session).unwrap();
    let a_open = a.drain_output(a_session);
    r.feed_input(s_out, &a_open).unwrap();
    assert_eq!(r.session_peer_state(s_out), Some("Idle"));
    assert!(r.take_collision_lost(s_out));

    // A fresh transport incarnation starts with a clean latch.
    r.start_session(s_out).unwrap();
    assert!(!r.take_collision_lost(s_out));

    // The inbound sibling still completes its handshake untouched.
    let outcome = handshake(&mut r, s_in, &mut b, b_session);
    assert_eq!(outcome, "Established");
}

/// RFC 4724 §2: retention protects the routes an ESTABLISHED session
/// learned. A transport that dies mid-handshake — e.g. a §6.8
/// collision loser — must NOT enter retention (the rc.4 defect:
/// every collision round pinned a 120 s retention for a session that
/// never had routes, short-circuiting the next teardown's cleanup).
#[test]
fn gr_retention_only_for_established_sessions() {
    let mut r = DefaultRouter::new();
    // SessionConfig::bgp defaults negotiate RFC 4724 (restart time
    // 120 s) with a GR-capable peer.
    let s_est = r
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 9]),
        ))
        .unwrap();
    let s_never = r
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 9]),
        ))
        .unwrap();
    let (mut a, a_session) = collision_peer([10, 0, 0, 1]);

    // Established transport dies → retention applies.
    assert_eq!(handshake(&mut r, s_est, &mut a, a_session), "Established");
    r.close_session(s_est);
    let established_path = r
        .poll_events()
        .iter()
        .filter_map(|e| match e {
            RouterEvent::Log(line) => Some(line.clone()),
            _ => None,
        })
        .any(|line| line.contains("entered graceful-restart retention"));
    assert!(established_path, "an Established session enters retention");

    // Never-established transport dies → plain purge, no retention.
    r.start_session(s_never).unwrap();
    r.close_session(s_never);
    let events = r.poll_events();
    let retention = events.iter().any(|e| {
            matches!(e, RouterEvent::Log(line) if line.contains("entered graceful-restart retention"))
        });
    assert!(
        !retention,
        "a never-established session must not enter retention"
    );
}
