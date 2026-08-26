//! End-to-end route propagation tests over the full stack:
//! codec → FSM → Adj-RIB-In → decision → Loc-RIB → egress → wire.
//!
//! The harness wires two (or three) `DefaultRouter`s together with a
//! synchronous byte pump — the same byte-stream contract an embedder uses
//! with real TCP sockets (see `tcp_smoke.rs` for the socket variant).

use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

/// Pump bytes between two routers' sessions until no output remains on
/// either side (bounded iterations to fail fast on runaway loops).
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

/// Wire up an eBGP pair; returns (router_a, router_b, session_a, session_b).
fn ebgp_pair() -> (DefaultRouter, DefaultRouter, SessionHandle, SessionHandle) {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    (a, b, ha, hb)
}

#[test]
fn ebgp_session_establishes() {
    let (mut a, mut b, ha, hb) = ebgp_pair();
    pump(&mut a, ha, &mut b, hb);
    let events: Vec<String> = a
        .poll_events()
        .into_iter()
        .filter_map(|e| match e {
            lr_router::RouterEvent::PeerStateChange { state, .. } => Some(state.to_string()),
            _ => None,
        })
        .collect();
    assert!(events.iter().any(|s| s == "Established"));
    let _ = b.poll_events();
}

/// A originates a prefix; B installs it with A's AS in the path and A's
/// address as next-hop (next-hop-self).
#[test]
fn ebgp_route_propagates_end_to_end() {
    let (mut a, mut b, ha, hb) = ebgp_pair();
    let _ = a.poll_events();
    let _ = b.poll_events();

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    // Pump A → B (the UPDATE) and back (nothing expected).
    pump(&mut a, ha, &mut b, hb);

    let snapshot = b.rib_snapshot();
    assert_eq!(snapshot.len(), 1, "B must have exactly one route");
    let r = snapshot[0];
    assert_eq!(r.key.prefix, Prefix::new_v4([203, 0, 113, 0], 24));
    assert_eq!(r.next_hop, Some(IpAddr::V4([192, 0, 2, 1])));

    // Decode the AS path from the attribute bag (canonical 4-byte form).
    let attrs: lr_bgp::path::PathAttributes = r.attributes.clone().into();
    let path = attrs.as_path().expect("AS_PATH present");
    assert_eq!(path.as_sequence(), vec![Asn(64512)]);

    // B saw a RouteInstalled event.
    let saw_install = b
        .poll_events()
        .into_iter()
        .any(|e| matches!(e, lr_router::RouterEvent::RouteInstalled(_)));
    assert!(saw_install, "B must emit RouteInstalled");
}

/// Withdrawing the origination propagates as a BGP withdrawal to B.
#[test]
fn ebgp_withdraw_propagates() {
    let (mut a, mut b, ha, hb) = ebgp_pair();
    let _ = a.poll_events();
    let _ = b.poll_events();

    let key = a.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);
    assert_eq!(b.rib_snapshot().len(), 1);

    a.unoriginate(&key);
    pump(&mut a, ha, &mut b, hb);
    assert!(
        b.rib_snapshot().is_empty(),
        "B must withdraw after A retracts"
    );
    let saw_withdraw = b
        .poll_events()
        .into_iter()
        .any(|e| matches!(e, lr_router::RouterEvent::RouteWithdrawn(_)));
    assert!(saw_withdraw, "B must emit RouteWithdrawn");
}

/// Three-router transit topology: C receives A's route with [64513, 64512].
#[test]
fn ebgp_transit_three_routers() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new(); // transit
    let mut c = DefaultRouter::new();

    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb_in = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    let hb_out = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64514), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 5])),
        )
        .unwrap();
    let hc = c
        .add_session(
            SessionConfig::bgp(Asn(64514), Asn(64513), RouterId::from_v4([10, 0, 0, 3]))
                .with_local_address(IpAddr::V4([192, 0, 2, 6])),
        )
        .unwrap();

    a.start_session(ha).unwrap();
    b.start_session(hb_in).unwrap();
    b.start_session(hb_out).unwrap();
    c.start_session(hc).unwrap();

    pump(&mut a, ha, &mut b, hb_in);
    pump(&mut b, hb_out, &mut c, hc);
    let _ = a.poll_events();
    let _ = b.poll_events();
    let _ = c.poll_events();

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb_in);
    // B now has the route; advertise it towards C.
    pump(&mut b, hb_out, &mut c, hc);

    assert_eq!(b.rib_snapshot().len(), 1);
    let snap = c.rib_snapshot();
    assert_eq!(snap.len(), 1, "C must see the route through B");
    let attrs: lr_bgp::path::PathAttributes = snap[0].attributes.clone().into();
    let path = attrs.as_path().expect("AS_PATH present");
    assert_eq!(path.as_sequence(), vec![Asn(64513), Asn(64512)]);
}

/// Import hook that drops a specific prefix — the route never reaches
/// B's Loc-RIB.
#[test]
fn import_hook_filters_route() {
    use lr_core::rib::Route;
    use lr_policy::hooks::{HookChain, HookVerdict, ImportHook};

    struct DropDot113;
    impl ImportHook for DropDot113 {
        fn name(&self) -> &str {
            "drop-203.0.113.0/24"
        }
        fn on_import(&self, route: &mut Route) -> HookVerdict {
            if route.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24) {
                HookVerdict::Drop
            } else {
                HookVerdict::Keep
            }
        }
    }

    let (mut a, mut b, ha, hb) = ebgp_pair();
    *b.hooks_mut() = HookChain {
        import: vec![Box::new(DropDot113)],
        ..Default::default()
    };
    let _ = a.poll_events();
    let _ = b.poll_events();

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);
    assert!(
        b.rib_snapshot().is_empty(),
        "import hook must drop the route"
    );
}

/// Export hook that rewrites the community — B sees the modified attribute.
#[test]
fn export_hook_rewrites_route() {
    use lr_bgp::path::{AttrType, PathAttrFlags, PathAttribute};
    use lr_core::rib::Route;
    use lr_policy::hooks::{ExportHook, HookChain, HookVerdict};

    struct TagCommunity;
    impl ExportHook for TagCommunity {
        fn name(&self) -> &str {
            "tag-community"
        }
        fn on_export(&self, route: &mut Route) -> HookVerdict {
            let mut attrs: lr_bgp::path::PathAttributes = route.attributes.clone().into();
            attrs.insert(PathAttribute::new(
                PathAttrFlags::new().set_optional(true).set_transitive(true),
                AttrType::Communities,
                lr_bgp::path::Community::encode_set(&[lr_bgp::path::Community::from_u32(
                    0x1234_5678,
                )]),
            ));
            route.attributes = attrs.into();
            HookVerdict::Replace(route.clone())
        }
    }

    let (mut a, mut b, ha, hb) = ebgp_pair();
    *a.hooks_mut() = HookChain {
        export: vec![Box::new(TagCommunity)],
        ..Default::default()
    };
    let _ = a.poll_events();
    let _ = b.poll_events();

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 1);
    let attrs: lr_bgp::path::PathAttributes = snap[0].attributes.clone().into();
    assert_eq!(
        attrs.communities(),
        vec![lr_bgp::path::Community::from_u32(0x1234_5678)]
    );
}

/// Safety net: a route whose AS_PATH already contains B's AS is rejected
/// (classic loop prevention, RFC 4271 §9.1.2.2).
#[test]
fn safety_net_rejects_as_loop() {
    let (mut a, mut b, ha, hb) = ebgp_pair();
    let _ = a.poll_events();
    let _ = b.poll_events();

    // Originate on A, but pre-poison the AS path with B's AS by crafting the
    // route via a second session. Simpler: A advertises a route it learned
    // "from B" — modelled by injecting a route whose path contains 64513.
    // We do that by hand-crafting the originate attributes:
    let key = {
        use lr_bgp::path::{AsPath, AttrType, PathAttrFlags, PathAttribute, PathAttributes};
        let prefix = Prefix::new_v4([198, 51, 100, 0], 24);
        let mut attrs = PathAttributes::new();
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));
        // Path that loops through B's AS.
        let mut path = AsPath::from_sequence([Asn(64513), Asn(64200)]);
        path.prepend(Asn(64513));
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            path.encode_4(),
        ));
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::NextHop,
            vec![192, 0, 2, 1],
        ));
        // Encode the looping route as a wire UPDATE and feed it directly
        // to B's session (emulating what a buggy/malicious peer would send).
        let mut update = lr_bgp::message::update::Update::new();
        update.attributes = attrs;
        update.nlri.push(prefix);
        let msg = lr_bgp::BgpMessage::Update(update);
        let codec = lr_bgp::BgpCodec::new();
        let bytes = codec.encode_vec(&msg).unwrap();
        // Feed straight into B's session (bypassing A's egress rewriting).
        b.feed_input(hb, &bytes).unwrap();
        prefix
    };
    let _ = key;
    // No further pumping needed — the bytes went directly to B.
    assert!(
        b.rib_snapshot().is_empty(),
        "B must reject a route containing its own AS"
    );
    let saw_reject = b
        .poll_events()
        .into_iter()
        .any(|e| matches!(e, lr_router::RouterEvent::Log(l) if l.contains("safety")));
    assert!(saw_reject, "safety net must log the rejection");
    let _ = ha;
}

/// Best-path: two eBGP sessions to B; the shorter AS path wins.
#[test]
fn best_path_prefers_shorter_as_path() {
    let mut b = DefaultRouter::new();
    let mut a1 = DefaultRouter::new();
    let mut a2 = DefaultRouter::new();

    // B is AS 64513 with two eBGP sessions: one to A1 (AS 64512), one to
    // A2 (AS 64200).
    let h1 = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb1 = a1
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 1, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    let h2 = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64200), RouterId::from_v4([10, 0, 0, 3]))
                .with_local_address(IpAddr::V4([192, 0, 2, 3])),
        )
        .unwrap();
    let hb2 = a2
        .add_session(
            SessionConfig::bgp(Asn(64200), Asn(64513), RouterId::from_v4([10, 0, 1, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 4])),
        )
        .unwrap();

    b.start_session(h1).unwrap();
    b.start_session(h2).unwrap();
    a1.start_session(hb1).unwrap();
    a2.start_session(hb2).unwrap();
    pump(&mut a1, hb1, &mut b, h1);
    pump(&mut a2, hb2, &mut b, h2);
    let _ = b.poll_events();
    let _ = a1.poll_events();
    let _ = a2.poll_events();

    a1.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a1, hb1, &mut b, h1);

    // A2 originates the same prefix but with a longer path (prepending).
    {
        use lr_bgp::path::{AsPath, AttrType, PathAttrFlags, PathAttribute, PathAttributes};
        let prefix = Prefix::new_v4([203, 0, 113, 0], 24);
        let mut attrs = PathAttributes::new();
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));
        let path = AsPath::from_sequence([Asn(64200), Asn(64201), Asn(64202), Asn(64203)]);
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            path.encode_4(),
        ));
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::NextHop,
            vec![192, 0, 2, 3],
        ));
        let mut update = lr_bgp::message::update::Update::new();
        update.attributes = attrs;
        update.nlri.push(prefix);
        let bytes = lr_bgp::BgpCodec::new()
            .encode_vec(&lr_bgp::BgpMessage::Update(update))
            .unwrap();
        b.feed_input(h2, &bytes).unwrap();
    }

    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 1, "exactly one best route");
    let attrs: lr_bgp::path::PathAttributes = snap[0].attributes.clone().into();
    let path = attrs.as_path().unwrap();
    assert_eq!(
        path.as_sequence(),
        vec![Asn(64512)],
        "the shorter AS path (from A1) must win"
    );
}

/// Hold-time expiry tears the session down when tick advances past it.
#[test]
fn hold_timer_expiry_resets_session() {
    let (mut a, mut _b, ha, _hb) = ebgp_pair();
    let _ = a.poll_events();
    // Negotiated hold time defaults to 90s; advance well past it.
    a.tick(lr_core::time::Instant(200_000));
    let out = a.drain_output(ha);
    // The output stream may contain a queued KEEPALIVE followed by the
    // NOTIFICATION — scan complete frames for a type-3 message.
    let mut saw_notification = false;
    let mut i = 0usize;
    while i + 19 <= out.len() {
        let len = u16::from_be_bytes([out[i + 16], out[i + 17]]) as usize;
        if i + 19 + (len.saturating_sub(19)) > out.len() {
            break;
        }
        if out[i + 18] == 3 {
            saw_notification = true;
        }
        i += len.max(19);
    }
    assert!(saw_notification, "NOTIFICATION (hold expired) must be sent");
    // The session must report Idle after the teardown.
    let went_idle = a.poll_events().into_iter().any(|e| {
        matches!(
            e,
            lr_router::RouterEvent::PeerStateChange { state: "Idle", .. }
        )
    });
    assert!(went_idle, "session must transition to Idle");
}
