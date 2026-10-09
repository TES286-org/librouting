
use super::*;

fn cfg_100ms() -> BfdConfig {
    BfdConfig {
        detect_mult: 3,
        desired_min_tx_interval: 100_000,
        required_min_rx_interval: 100_000,
        required_min_echo_interval: 0,
        role: SessionRole::Active,
        auth_key: None,
    }
}

fn make_session() -> BfdSession {
    let mut s = BfdSession::new(cfg_100ms(), 0x11111111);
    let _ = s.start(Instant(0));
    s
}

fn make_packet(state: State, my_disc: u32, your_disc: u32) -> BfdPacket {
    BfdPacket {
        diag: Diagnostic::None,
        state,
        flags: PacketFlags::empty(),
        detect_mult: 3,
        my_discriminator: my_disc,
        your_discriminator: your_disc,
        desired_min_tx_interval: 100_000,
        required_min_rx_interval: 100_000,
        required_min_echo_interval: 0,
        auth: None,
    }
}

fn encode_packet(p: &BfdPacket) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = WriteBuf::new(&mut buf);
    let codec = BfdCodec::new();
    let n = codec.encode(p, &mut w).unwrap();
    buf[..n].to_vec()
}

fn decode_first(bytes: &[u8]) -> BfdPacket {
    let mut codec = BfdCodec::new();
    let mut r = ReadBuf::new(bytes);
    codec.decode(&mut r).unwrap().unwrap()
}

#[test]
fn session_starts_down() {
    let mut s = make_session();
    assert_eq!(s.state(), State::Down);
    // Active role: an initial packet was queued with State=Down
    // and your_disc=0 (§6.1).
    let out = s.drain_outgoing();
    assert_eq!(out.len(), BfdPacket::MIN_LEN);
    let p = decode_first(&out);
    assert_eq!(p.state, State::Down);
    assert_eq!(p.my_discriminator, 0x11111111);
    assert_eq!(p.your_discriminator, 0);
    // Not Up yet: advertised tx interval is floored at one second.
    assert_eq!(p.desired_min_tx_interval, 1_000_000);
    assert_eq!(p.detect_mult, 3);
}

#[test]
fn down_to_init_on_peer_down() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p = make_packet(State::Down, 0x22222222, 0);
    let evs = s.feed_bytes(Instant(10), &encode_packet(&p));
    assert!(evs.iter().any(|e| matches!(
        e,
        BfdSessionEvent::StateChanged {
            to: State::Init,
            ..
        }
    )));
    assert_eq!(s.state(), State::Init);
    assert_eq!(s.remote_discriminator(), 0x22222222);
    // The state change triggers an immediate packet (§6.8.7).
    let out = s.drain_outgoing();
    let p = decode_first(&out);
    assert_eq!(p.state, State::Init);
    assert_eq!(p.your_discriminator, 0x22222222);
}

#[test]
fn init_to_up_on_peer_up() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p1 = make_packet(State::Down, 0x22222222, 0);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p1));
    assert_eq!(s.state(), State::Init);
    let _ = s.drain_outgoing();
    let p2 = make_packet(State::Up, 0x22222222, 0x11111111);
    let evs = s.feed_bytes(Instant(20), &encode_packet(&p2));
    assert!(evs
        .iter()
        .any(|e| matches!(e, BfdSessionEvent::StateChanged { to: State::Up, .. })));
    assert!(s.is_up());
}

/// RFC 5880 §6.8.6: Down + received Init → **Up** (not Init). With
/// the historical bug both peers stuck in Init forever.
#[test]
fn down_plus_init_goes_straight_up() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p = make_packet(State::Init, 0x22222222, 0x11111111);
    let evs = s.feed_bytes(Instant(10), &encode_packet(&p));
    assert!(evs
        .iter()
        .any(|e| matches!(e, BfdSessionEvent::StateChanged { to: State::Up, .. })));
    assert_eq!(s.state(), State::Up);
}

/// RFC 5880 §6.8.6: Init + received Init → Up.
#[test]
fn init_plus_init_goes_up() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p1 = make_packet(State::Down, 0x22222222, 0);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p1));
    assert_eq!(s.state(), State::Init);
    let _ = s.drain_outgoing();
    let p2 = make_packet(State::Init, 0x22222222, 0x11111111);
    let evs = s.feed_bytes(Instant(20), &encode_packet(&p2));
    assert!(evs
        .iter()
        .any(|e| matches!(e, BfdSessionEvent::StateChanged { to: State::Up, .. })));
    assert_eq!(s.state(), State::Up);
}

/// The full two-session handshake: two Active sessions exchange
/// their generated packets and both reach Up without any manual
/// priming — the regression test for the Init deadlock.
#[test]
fn two_sessions_reach_up_together() {
    let mut a = BfdSession::new(cfg_100ms(), 0x11111111);
    let mut b = BfdSession::new(cfg_100ms(), 0x22222222);
    let _ = a.start(Instant(0));
    let _ = b.start(Instant(0));
    let mut t = 0u64;
    for _ in 0..10 {
        // Deliver each side's output to the other, plus timer ticks.
        let out_a = a.drain_outgoing();
        if !out_a.is_empty() {
            let _ = b.feed_bytes(Instant(t), &out_a);
        }
        let out_b = b.drain_outgoing();
        if !out_b.is_empty() {
            let _ = a.feed_bytes(Instant(t), &out_b);
        }
        if a.is_up() && b.is_up() {
            break;
        }
        t += 5;
        let _ = a.tick(Instant(t));
        let _ = b.tick(Instant(t));
    }
    assert!(a.is_up(), "A stuck in {}", a.state());
    assert!(b.is_up(), "B stuck in {}", b.state());
}

/// Two live sessions keep exchanging packets and STAY Up: the
/// detection timer must be replaced (not stacked) on every
/// received packet, or the entries armed during the handshake
/// fire one detection time in and tear the healthy session down.
#[test]
fn two_sessions_stay_up() {
    let mut a = BfdSession::new(cfg_100ms(), 0x11111111);
    let mut b = BfdSession::new(cfg_100ms(), 0x22222222);
    let _ = a.start(Instant(0));
    let _ = b.start(Instant(0));
    // Drive 3 seconds at 10 ms resolution (10x the detection time).
    let mut t = 0u64;
    while t < 3000 {
        t += 10;
        let _ = a.tick(Instant(t));
        let _ = b.tick(Instant(t));
        let out_a = a.drain_outgoing();
        if !out_a.is_empty() {
            let evs = b.feed_bytes(Instant(t), &out_a);
            assert!(
                !evs.iter().any(|e| matches!(e, BfdSessionEvent::Timeout)),
                "B timed out at t={t}ms while A was alive"
            );
        }
        let out_b = b.drain_outgoing();
        if !out_b.is_empty() {
            let evs = a.feed_bytes(Instant(t), &out_b);
            assert!(
                !evs.iter().any(|e| matches!(e, BfdSessionEvent::Timeout)),
                "A timed out at t={t}ms while B was alive"
            );
        }
    }
    assert!(
        a.is_up(),
        "A ended in {} after 3s of live exchange",
        a.state()
    );
    assert!(
        b.is_up(),
        "B ended in {} after 3s of live exchange",
        b.state()
    );
}

#[test]
fn timeout_brings_session_down() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p = make_packet(State::Down, 0x22222222, 0);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p));
    assert_eq!(s.state(), State::Init);
    // Detection time = 3 × max(100ms local rx, 100ms peer tx)
    // = 300ms; the packet arrived at t=10.
    assert_eq!(s.detection_time_us(), 300_000);
    let evs = s.tick(Instant(320));
    assert!(evs.iter().any(|e| matches!(e, BfdSessionEvent::Timeout)));
    assert!(evs.iter().any(|e| matches!(
        e,
        BfdSessionEvent::StateChanged {
            from: State::Init,
            to: State::Down,
            ..
        }
    )));
    assert_eq!(s.state(), State::Down);
    assert_eq!(s.local_diag(), Diagnostic::CtrlExpired);
}

/// §6.8.4: the detection time uses the PEER's detect multiplier,
/// not a negotiated minimum of the two.
#[test]
fn detection_time_uses_peer_detect_mult() {
    let mut s = make_session(); // local detect_mult = 3
    let _ = s.drain_outgoing();
    let mut p = make_packet(State::Down, 0x22222222, 0);
    p.detect_mult = 5; // peer advertises 5
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p));
    // 5 × max(100ms, 100ms) = 500ms.
    assert_eq!(s.detection_time_us(), 500_000);
}

/// §6.8.7: our transmit interval is max(our desired, peer's
/// required rx) — the slower system dictates the rate. While not
/// Up the one-second idle floor (§6.8.3) dominates.
#[test]
fn tx_interval_follows_peer_required_rx() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    // Down + Init → Up directly.
    let mut p = make_packet(State::Init, 0x22222222, 0x11111111);
    p.required_min_rx_interval = 250_000; // peer wants <= 250ms
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p));
    assert!(s.is_up());
    assert_eq!(s.tx_interval_us(), 250_000);
    // Still Init (not Up): the idle floor wins even against a
    // peer asking for a faster rate.
    let mut s2 = make_session();
    let _ = s2.drain_outgoing();
    let mut p2 = make_packet(State::Down, 0x22222222, 0);
    p2.required_min_rx_interval = 250_000;
    let _ = s2.feed_bytes(Instant(10), &encode_packet(&p2));
    assert_eq!(s2.state(), State::Init);
    assert_eq!(s2.tx_interval_us(), 1_000_000);
}

/// §6.8.7: transmitted intervals are jittered by 0-25% (75-90%
/// when the local detect multiplier is 1).
#[test]
fn tx_jitter_within_bounds() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    // Down + Init → Up directly.
    let p = make_packet(State::Init, 0x22222222, 0x11111111);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p));
    assert!(s.is_up());
    // Negotiated interval 100ms; observe timer deadlines across
    // many re-arms: every interval must fall in [75ms, 100ms].
    let mut t = 10u64;
    for _ in 0..200 {
        t += 1;
        let _ = s.tick(Instant(t));
        let out = s.drain_outgoing();
        if out.is_empty() {
            continue;
        }
        // A packet was sent at t; the next fire is within
        // [75, 100] ms of t.
        for probe in 74..=101 {
            let evs = s.tick(Instant(t + probe));
            if evs
                .iter()
                .any(|e| matches!(e, BfdSessionEvent::OutboundQueued))
            {
                assert!(probe >= 75, "fired after {}ms (< 75ms)", probe);
                assert!(probe <= 100, "fired after {}ms (> 100ms)", probe);
                t += probe;
                let _ = s.drain_outgoing();
                break;
            }
        }
    }
}

#[test]
fn timeout_only_from_init_or_up() {
    // A session that is merely Down (never heard from the peer)
    // must not emit Timeout on detect-timer expiry.
    let mut s = make_session();
    let _ = s.drain_outgoing();
    // No peer packet: detect timer never armed by receipt.
    let evs = s.tick(Instant(10_000));
    assert!(!evs.iter().any(|e| matches!(e, BfdSessionEvent::Timeout)));
}

#[test]
fn received_admin_down_takes_us_down() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p1 = make_packet(State::Down, 0x22222222, 0);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p1));
    let p2 = make_packet(State::Up, 0x22222222, 0x11111111);
    let _ = s.feed_bytes(Instant(20), &encode_packet(&p2));
    assert!(s.is_up());
    let p3 = make_packet(State::AdminDown, 0x22222222, 0x11111111);
    let evs = s.feed_bytes(Instant(30), &encode_packet(&p3));
    assert!(evs.iter().any(|e| matches!(
        e,
        BfdSessionEvent::StateChanged {
            to: State::Down,
            ..
        }
    )));
    assert_eq!(s.state(), State::Down);
    assert_eq!(s.local_diag(), Diagnostic::NeighborSignaled);
}

#[test]
fn up_to_down_on_peer_down_sets_diag() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p1 = make_packet(State::Down, 0x22222222, 0);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p1));
    let p2 = make_packet(State::Up, 0x22222222, 0x11111111);
    let _ = s.feed_bytes(Instant(20), &encode_packet(&p2));
    assert!(s.is_up());
    let p3 = make_packet(State::Down, 0x22222222, 0x11111111);
    let _ = s.feed_bytes(Instant(30), &encode_packet(&p3));
    assert_eq!(s.state(), State::Down);
    assert_eq!(s.local_diag(), Diagnostic::NeighborSignaled);
}

/// §6.8.6 MUST-discard: zero My Discriminator.
#[test]
fn discards_zero_my_discriminator() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p = make_packet(State::Down, 0, 0);
    assert!(s.feed_bytes(Instant(10), &encode_packet(&p)).is_empty());
    assert_eq!(s.state(), State::Down);
    assert_eq!(s.remote_discriminator(), 0);
}

/// §6.8.6 MUST-discard: your_disc=0 with a state above Down.
#[test]
fn discards_discovery_packet_in_non_down_state() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p = make_packet(State::Up, 0x22222222, 0);
    assert!(s.feed_bytes(Instant(10), &encode_packet(&p)).is_empty());
    assert_eq!(s.state(), State::Down);
}

/// §6.8.6 MUST-discard: zero detect multiplier. The wire encoder
/// clamps detect_mult, so the invalid value is injected directly.
#[test]
fn discards_zero_detect_mult() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p = make_packet(State::Down, 0x22222222, 0);
    let mut bytes = encode_packet(&p);
    bytes[2] = 0; // Detect Mult = 0
    assert!(s.feed_bytes(Instant(10), &bytes).is_empty());
}

/// §6.5: Poll and Final MUST NOT both be set; §6.8.6: M bit set.
#[test]
fn discards_invalid_flag_combinations() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let mut p = make_packet(State::Down, 0x22222222, 0);
    p.flags = PacketFlags::POLL | PacketFlags::FINAL;
    assert!(s.feed_bytes(Instant(10), &encode_packet(&p)).is_empty());
    let mut p = make_packet(State::Down, 0x22222222, 0);
    p.flags = PacketFlags::MULTIPOINT;
    assert!(s.feed_bytes(Instant(10), &encode_packet(&p)).is_empty());
}

/// §6.8.7: receiving a Poll triggers an immediate Final response,
/// independent of the periodic transmit timer. The state change
/// also queues an announcement packet, so the Final may be the
/// second packet in the drain.
#[test]
fn poll_gets_immediate_final_response() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p1 = make_packet(State::Down, 0x22222222, 0);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p1));
    let _ = s.drain_outgoing();
    let mut p2 = make_packet(State::Init, 0x22222222, 0x11111111);
    p2.flags = PacketFlags::POLL;
    let evs = s.feed_bytes(Instant(20), &encode_packet(&p2));
    assert!(evs
        .iter()
        .any(|e| matches!(e, BfdSessionEvent::OutboundQueued)));
    let out = s.drain_outgoing();
    let mut codec = BfdCodec::new();
    let mut r = ReadBuf::new(&out);
    let mut saw_final = false;
    while let Ok(Some(pkt)) = codec.decode(&mut r) {
        if pkt.flags.contains(PacketFlags::FINAL) {
            saw_final = true;
            assert!(!pkt.flags.contains(PacketFlags::POLL));
        }
    }
    assert!(saw_final, "no Final response in {} bytes", out.len());
}

/// §6.8.3 + §6.5: an increased tx interval while Up is advertised
/// immediately on the periodic (Poll-flagged) packets but takes
/// effect only after the peer's Final.
#[test]
fn interval_increase_waits_for_final() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p1 = make_packet(State::Init, 0x22222222, 0x11111111);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p1));
    assert!(s.is_up());
    assert_eq!(s.tx_interval_us(), 100_000);
    let _ = s.drain_outgoing(); // the Up announcement
    let _ = s.update_timers(Instant(25), 300_000, 100_000);
    assert!(s.poll_active());
    // The running cadence is still the old one.
    assert_eq!(s.tx_interval_us(), 100_000);
    // The next periodic packet carries P and the NEW value.
    let mut sent = None;
    for step in 0..300u64 {
        let evs = s.tick(Instant(26 + step));
        let out = s.drain_outgoing();
        if !out.is_empty() {
            sent = Some(out);
            break;
        }
        assert!(
            !evs.iter().any(|e| matches!(e, BfdSessionEvent::Timeout)),
            "session timed out before the poll packet"
        );
    }
    let sent = sent.expect("poll packet transmitted");
    let poll_pkt = decode_first(&sent);
    assert!(poll_pkt.flags.contains(PacketFlags::POLL));
    assert_eq!(poll_pkt.desired_min_tx_interval, 300_000);
    // The peer's Final applies the pending value.
    let mut fin = make_packet(State::Up, 0x22222222, 0x11111111);
    fin.flags = PacketFlags::FINAL;
    let _ = s.feed_bytes(Instant(500), &encode_packet(&fin));
    assert!(!s.poll_active());
    assert_eq!(s.tx_interval_us(), 300_000);
}

/// §6.8.3: a decreased tx interval applies immediately (no wait
/// for Final) — but never faster than the peer's advertised
/// required rx interval allows.
#[test]
fn interval_decrease_applies_immediately() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p1 = make_packet(State::Init, 0x22222222, 0x11111111);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p1));
    assert!(s.is_up());
    let _ = s.update_timers(Instant(25), 50_000, 40_000);
    // The peer still advertises required rx = 100ms, so the
    // effective interval stays peer-limited.
    assert_eq!(s.tx_interval_us(), 100_000);
    // Once the peer advertises a smaller required rx, our faster
    // desired tx takes over.
    let mut p2 = make_packet(State::Up, 0x22222222, 0x11111111);
    p2.required_min_rx_interval = 30_000;
    let _ = s.feed_bytes(Instant(30), &encode_packet(&p2));
    assert_eq!(s.tx_interval_us(), 50_000);
}

/// §6.8.3: while not Up the desired tx interval is floored at one
/// second; entering Up drops the floor.
#[test]
fn idle_floor_while_not_up() {
    let mut s = BfdSession::new(cfg_100ms(), 0x11111111);
    let _ = s.start(Instant(0));
    // Down: 1s floor.
    assert_eq!(s.tx_interval_us(), 1_000_000);
    let _ = s.drain_outgoing();
    let p1 = make_packet(State::Down, 0x22222222, 0);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p1));
    let p2 = make_packet(State::Up, 0x22222222, 0x11111111);
    let _ = s.feed_bytes(Instant(20), &encode_packet(&p2));
    assert!(s.is_up());
    // Up: the configured 100ms applies (floored only when not Up).
    assert_eq!(s.tx_interval_us(), 100_000);
}

/// Passive sessions stay quiet until the peer speaks (§6.8.7).
#[test]
fn passive_waits_for_peer() {
    let mut cfg = cfg_100ms();
    cfg.role = SessionRole::Passive;
    let mut s = BfdSession::new(cfg, 0x11111111);
    let evs = s.start(Instant(0));
    assert!(evs.is_empty());
    assert!(s.drain_outgoing().is_empty());
    // First peer packet unlocks transmission.
    let p = make_packet(State::Down, 0x22222222, 0);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p));
    assert!(!s.drain_outgoing().is_empty());
}

/// §6.8.6: when the peer enters Demand mode with both sides Up we
/// cease periodic transmission.
#[test]
fn remote_demand_ceases_periodic_tx() {
    let mut s = make_session();
    let _ = s.drain_outgoing();
    let p1 = make_packet(State::Down, 0x22222222, 0);
    let _ = s.feed_bytes(Instant(10), &encode_packet(&p1));
    let p2 = make_packet(State::Up, 0x22222222, 0x11111111);
    let _ = s.feed_bytes(Instant(20), &encode_packet(&p2));
    assert!(s.is_up());
    assert!(s.tx_allowed());
    let mut p3 = make_packet(State::Up, 0x22222222, 0x11111111);
    p3.flags = PacketFlags::DEMAND;
    let _ = s.feed_bytes(Instant(30), &encode_packet(&p3));
    assert!(!s.tx_allowed());
}

/// Simple Password authentication (§4.2, §6.7.2): matching key and
/// password accepted; mismatch discarded with AuthFailed.
#[test]
fn simple_password_auth() {
    let mut cfg = cfg_100ms();
    cfg.auth_key = Some(crate::auth::AuthKey::simple_password(5, b"secret"));
    let mut s = BfdSession::new(cfg, 0x11111111);
    let _ = s.start(Instant(0));
    let out = s.drain_outgoing();
    let p = decode_first(&out);
    assert!(p.flags.contains(PacketFlags::AUTH));
    assert_eq!(p.auth.as_ref().unwrap().key_id, 5);
    assert_eq!(p.length(), 24 + 3 + 6);

    // Good password: accepted.
    let mut good = make_packet(State::Down, 0x22222222, 0);
    good.flags = PacketFlags::AUTH;
    good.auth = Some(AuthSection::simple_password(b"secret".to_vec(), 5));
    let evs = s.feed_bytes(Instant(10), &encode_packet(&good));
    assert!(!evs.iter().any(|e| matches!(e, BfdSessionEvent::AuthFailed)));
    assert_eq!(s.state(), State::Init);

    // Wrong password: discarded with AuthFailed.
    let mut bad = make_packet(State::Down, 0x22222222, 0);
    bad.flags = PacketFlags::AUTH;
    bad.auth = Some(AuthSection::simple_password(b"wrong".to_vec(), 5));
    let evs = s.feed_bytes(Instant(20), &encode_packet(&bad));
    assert!(evs.iter().any(|e| matches!(e, BfdSessionEvent::AuthFailed)));
    // And an unauthenticated packet while auth is configured:
    let unauth = make_packet(State::Down, 0x22222222, 0);
    let evs = s.feed_bytes(Instant(30), &encode_packet(&unauth));
    assert!(evs.iter().any(|e| matches!(e, BfdSessionEvent::AuthFailed)));
}

#[test]
fn admin_down_discards_packets() {
    let mut s = make_session();
    let _ = s.admin_down();
    assert_eq!(s.state(), State::AdminDown);
    let p = make_packet(State::Down, 0x22222222, 0);
    assert!(s.feed_bytes(Instant(10), &encode_packet(&p)).is_empty());
    assert_eq!(s.remote_discriminator(), 0);
}
