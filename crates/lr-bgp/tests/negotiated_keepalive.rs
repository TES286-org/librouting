use lr_bgp::fsm::timer_ids;
use lr_bgp::{BgpAction, BgpEvent, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, RouterId};
use lr_core::time::Instant;
use lr_core::timer::TimerQueue;

fn apply_timers(actions: &[BgpAction], queue: &mut TimerQueue, now: u64) {
    for action in actions {
        match action {
            BgpAction::SetTimer(id, spec) => queue.arm(Instant(now), *id, *spec),
            BgpAction::CancelTimer(id) => queue.cancel(*id),
            BgpAction::Close => panic!("session expired despite timely keepalives"),
            _ => {}
        }
    }
}

#[test]
fn keepalive_uses_negotiated_hold_time_for_every_period() {
    for configured in [0, 1, 30] {
        let mut cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg_a.keepalive = configured;
        let mut cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        cfg_b.hold_time = 9;
        let mut a = BgpPeer::new(cfg_a);
        let mut b = BgpPeer::new(cfg_b);
        for peer in [&mut a, &mut b] {
            peer.step(BgpEvent::ManualStart);
            peer.step(BgpEvent::TransportOpen);
        }
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        let a_actions = a.feed_bytes(&b_open).unwrap();
        let b_actions = b.feed_bytes(&a_open).unwrap();
        let expected_ms = if configured == 1 { 1000 } else { 3000 };
        assert!(a_actions.iter().any(|action| matches!(
            action,
            BgpAction::SetTimer(id, spec)
                if *id == timer_ids::KEEPALIVE && spec.after_ms == expected_ms
        )));
        let mut qa = TimerQueue::new();
        let mut qb = TimerQueue::new();
        apply_timers(&a_actions, &mut qa, 0);
        apply_timers(&b_actions, &mut qb, 0);
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        apply_timers(&a.feed_bytes(&b_ka).unwrap(), &mut qa, 0);
        apply_timers(&b.feed_bytes(&a_ka).unwrap(), &mut qb, 0);
        for now in (1000..=30_000).step_by(1000) {
            for id in qa.tick(Instant(now)) {
                let event = if id == timer_ids::KEEPALIVE {
                    BgpEvent::TimerKeepalive
                } else {
                    BgpEvent::TimerHoldExpired
                };
                apply_timers(&a.step(event), &mut qa, now);
            }
            for id in qb.tick(Instant(now)) {
                let event = if id == timer_ids::KEEPALIVE {
                    BgpEvent::TimerKeepalive
                } else {
                    BgpEvent::TimerHoldExpired
                };
                apply_timers(&b.step(event), &mut qb, now);
            }
            let a_out = a.drain_outgoing();
            let b_out = b.drain_outgoing();
            apply_timers(&a.feed_bytes(&b_out).unwrap(), &mut qa, now);
            apply_timers(&b.feed_bytes(&a_out).unwrap(), &mut qb, now);
            assert!(a.is_established() && b.is_established());
        }
    }
}
