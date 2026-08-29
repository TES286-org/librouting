//! End-to-end coverage of the eight BGP session establishment modes
//! required for production parity with BIRD/FRR:
//!
//! 1. **Standard dual-stack** — IPv4 + IPv6 each an independent BGP session.
//! 2. **Link-local dual-stack** — IPv4 session + IPv6 session over `fe80::`.
//! 3. **MP-BGP** — a single IPv6 transport carrying IPv4 + IPv6 NLRI
//!    (MP_REACH for both families, no Extended Next-Hop).
//! 4. **MP-BGP + link-local** — same as 3 over `fe80::`.
//! 5. **Extended Next-Hop (RFC 5549)** — a single IPv6 session carrying
//!    IPv4 NLRI with an IPv6 next-hop.
//! 6. **ENH + link-local** — same as 5 over `fe80::`.
//! 7. **Pure IPv6** — a single IPv6 session, IPv6 NLRI only.
//! 8. **Pure IPv6 + link-local** — same as 7 over `fe80::`.
//!
//! All tests use the in-process byte pump (no real sockets) so they run
//! anywhere; the daemon-driven interop scripts under `tests/interop/`
//! exercise the same modes over real TCP against BIRD/FRR.

use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
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

fn assert_established(r: &DefaultRouter, h: SessionHandle, label: &str) {
    let summary = r
        .session_summaries()
        .into_iter()
        .find(|s| s.handle == h)
        .unwrap_or_else(|| panic!("{label}: session summary missing"));
    assert!(
        summary.established,
        "{label}: session not Established (state={})",
        summary.state
    );
}

const V4_ROUTER_ID_A: RouterId = RouterId::from_v4([10, 0, 0, 1]);
const V4_ROUTER_ID_B: RouterId = RouterId::from_v4([10, 0, 0, 2]);

/// An IPv6 global next-hop used as the source for ENH egress and as the
/// IPv6 NLRI next-hop on MP-BGP sessions.
const V6_GUA_A: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const V6_GUA_B: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
/// IPv6 link-local addresses — the form used by the link-local modes.
const V6_LL_A: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const V6_LL_B: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

// =============================================================================
// Mode 1 — Standard dual-stack (two independent BGP sessions: v4 + v6)
// =============================================================================

#[test]
fn mode1_standard_dual_stack() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    // IPv4 session.
    let h4a = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let h4b = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    // IPv6 session (MP-BGP for IPv6 unicast; IPv4 NLRI not carried here).
    let h6a = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_mp_families(vec![NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_GUA_A)),
        )
        .unwrap();
    let h6b = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_mp_families(vec![NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_GUA_B)),
        )
        .unwrap();
    a.start_session(h4a).unwrap();
    a.start_session(h6a).unwrap();
    b.start_session(h4b).unwrap();
    b.start_session(h6b).unwrap();
    pump(&mut a, h4a, &mut b, h4b);
    pump(&mut a, h6a, &mut b, h6b);
    assert_established(&a, h4a, "mode1 v4");
    assert_established(&b, h4b, "mode1 v4");
    assert_established(&a, h6a, "mode1 v6");
    assert_established(&b, h6b, "mode1 v6");

    // Originate v4 + v6 prefixes; each propagates over its own session.
    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    a.originate_family(
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
            64,
        ),
        NlriFamily::IPV6_UNICAST,
        Some(IpAddr::V6(V6_GUA_A)),
    );
    pump(&mut a, h4a, &mut b, h4b);
    pump(&mut a, h6a, &mut b, h6b);

    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 2, "mode1: B must hold the v4 and v6 routes");
    assert!(
        snap.iter().any(|r| r.key.family == NlriFamily::IPV4_UNICAST
            && r.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24)),
        "mode1: v4 prefix present"
    );
    assert!(
        snap.iter()
            .any(|r| r.key.family == NlriFamily::IPV6_UNICAST),
        "mode1: v6 prefix present"
    );
}

// =============================================================================
// Mode 2 — Link-local dual-stack (IPv4 session + IPv6 session over fe80::)
// =============================================================================

#[test]
fn mode2_link_local_dual_stack() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    // IPv4 session (unchanged from mode 1).
    let h4a = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let h4b = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    // IPv6 session using link-local addresses as the source / next-hop.
    let h6a = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_mp_families(vec![NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_LL_A)),
        )
        .unwrap();
    let h6b = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_mp_families(vec![NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_LL_B)),
        )
        .unwrap();
    a.start_session(h4a).unwrap();
    a.start_session(h6a).unwrap();
    b.start_session(h4b).unwrap();
    b.start_session(h6b).unwrap();
    pump(&mut a, h4a, &mut b, h4b);
    pump(&mut a, h6a, &mut b, h6b);
    assert_established(&a, h4a, "mode2 v4");
    assert_established(&a, h6a, "mode2 v6 link-local");

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    a.originate_family(
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0],
            64,
        ),
        NlriFamily::IPV6_UNICAST,
        Some(IpAddr::V6(V6_LL_A)),
    );
    pump(&mut a, h4a, &mut b, h4b);
    pump(&mut a, h6a, &mut b, h6b);

    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 2, "mode2: B must hold the v4 and v6 routes");
    // The IPv6 next-hop on B's v6 route is the link-local address A advertised.
    let v6_route = snap
        .iter()
        .find(|r| r.key.family == NlriFamily::IPV6_UNICAST)
        .expect("mode2: v6 prefix present");
    assert_eq!(v6_route.next_hop, Some(IpAddr::V6(V6_LL_A)));
}

// =============================================================================
// Mode 3 — MP-BGP: single IPv6 transport carrying v4 + v6 NLRI
// =============================================================================

#[test]
fn mode3_mp_bgp_single_v6_session() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    // Single session, IPv6 transport, MP-BGP for both families (no ENH).
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_GUA_A)),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_GUA_B)),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    assert_established(&a, ha, "mode3");

    // Both families propagate over the single session.
    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    a.originate_family(
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0],
            64,
        ),
        NlriFamily::IPV6_UNICAST,
        Some(IpAddr::V6(V6_GUA_A)),
    );
    pump(&mut a, ha, &mut b, hb);

    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 2, "mode3: B must hold both prefixes");
    // The IPv4 route keeps its IPv4 next-hop — ENH was not negotiated.
    let v4 = snap
        .iter()
        .find(|r| r.key.family == NlriFamily::IPV4_UNICAST)
        .expect("mode3: v4 prefix present");
    assert_eq!(v4.next_hop, Some(IpAddr::V4([192, 0, 2, 1])));
}

// =============================================================================
// Mode 4 — MP-BGP + link-local transport
// =============================================================================

#[test]
fn mode4_mp_bgp_link_local() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_LL_A)),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_LL_B)),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    assert_established(&a, ha, "mode4");

    a.originate_family(
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0],
            64,
        ),
        NlriFamily::IPV6_UNICAST,
        Some(IpAddr::V6(V6_LL_A)),
    );
    pump(&mut a, ha, &mut b, hb);
    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 1, "mode4: B must hold the v6 route");
    assert_eq!(snap[0].next_hop, Some(IpAddr::V6(V6_LL_A)));
}

// =============================================================================
// Mode 5 — Extended Next-Hop (RFC 5549): IPv6 transport, IPv4 NLRI over IPv6 next-hop
// =============================================================================

#[test]
fn mode5_extended_next_hop() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_extended_next_hop()
                // Local source is IPv6 — eBGP egress will rewrite IPv4
                // NEXT_HOP to this IPv6 address (RFC 5549 wire form).
                .with_local_address(IpAddr::V6(V6_GUA_A)),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_extended_next_hop()
                .with_local_address(IpAddr::V6(V6_GUA_B)),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    assert_established(&a, ha, "mode5");

    // Originate an IPv4 prefix; the next-hop advertised to B is A's IPv6.
    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 1, "mode5: B must hold the IPv4 route");
    let r = &snap[0];
    assert_eq!(r.key.family, NlriFamily::IPV4_UNICAST);
    assert_eq!(
        r.next_hop,
        Some(IpAddr::V6(V6_GUA_A)),
        "mode5: IPv4 route carried over an IPv6 next-hop (RFC 5549)"
    );
}

// =============================================================================
// Mode 6 — ENH + link-local transport
// =============================================================================

#[test]
fn mode6_extended_next_hop_link_local() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_extended_next_hop()
                .with_local_address(IpAddr::V6(V6_LL_A)),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_extended_next_hop()
                .with_local_address(IpAddr::V6(V6_LL_B)),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    assert_established(&a, ha, "mode6");

    a.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 1, "mode6: B must hold the IPv4 route");
    assert_eq!(
        snap[0].next_hop,
        Some(IpAddr::V6(V6_LL_A)),
        "mode6: IPv4 route carried over a link-local IPv6 next-hop"
    );
}

// =============================================================================
// Mode 7 — Pure IPv6 (single v6 session, v6 NLRI only)
// =============================================================================

#[test]
fn mode7_pure_ipv6() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_mp_families(vec![NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_GUA_A)),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_mp_families(vec![NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_GUA_B)),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    assert_established(&a, ha, "mode7");

    a.originate_family(
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0],
            64,
        ),
        NlriFamily::IPV6_UNICAST,
        Some(IpAddr::V6(V6_GUA_A)),
    );
    pump(&mut a, ha, &mut b, hb);
    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 1, "mode7: B must hold the v6 route");
    assert_eq!(snap[0].key.family, NlriFamily::IPV6_UNICAST);
    assert_eq!(snap[0].next_hop, Some(IpAddr::V6(V6_GUA_A)));
}

// =============================================================================
// Mode 8 — Pure IPv6 + link-local transport
// =============================================================================

#[test]
fn mode8_pure_ipv6_link_local() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_ROUTER_ID_A)
                .with_mp_families(vec![NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_LL_A)),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_ROUTER_ID_B)
                .with_mp_families(vec![NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6(V6_LL_B)),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    assert_established(&a, ha, "mode8");

    a.originate_family(
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0],
            64,
        ),
        NlriFamily::IPV6_UNICAST,
        Some(IpAddr::V6(V6_LL_A)),
    );
    pump(&mut a, ha, &mut b, hb);
    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 1, "mode8: B must hold the v6 route");
    assert_eq!(snap[0].next_hop, Some(IpAddr::V6(V6_LL_A)));
}

// =============================================================================
// Regression — ENH capability is not advertised when not configured
// =============================================================================

/// A session without `with_extended_next_hop` must NOT advertise the
/// capability, even when the local source is IPv6 and the family list
/// includes IPv4 unicast. This guards against accidental ENH enablement
/// that would surprise peers (RFC 5549 §4: only advertise what is
/// explicitly configured).
#[test]
fn enh_not_advertised_when_disabled() {
    use lr_bgp::{BgpEvent, BgpPeer};
    use lr_core::codec::Decoder;

    let mut a = BgpPeer::new(lr_bgp::PeerConfig::new(
        Asn(64512),
        Asn(64513),
        V4_ROUTER_ID_A,
    ));
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    let open_bytes = a.drain_outgoing();
    let mut codec = lr_bgp::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&open_bytes);
    let msg = codec.decode(&mut r).unwrap().unwrap();
    let lr_bgp::BgpMessage::Open(open) = msg else {
        panic!("expected OPEN");
    };
    let caps = open
        .params
        .iter()
        .filter_map(|p| {
            if p.param_type == lr_bgp::message::open::OpenParam::PARAM_TYPE_CAPABILITY {
                Some(lr_bgp::capabilities::Capability::decode_set(&p.value))
            } else {
                None
            }
        })
        .flatten()
        .collect::<Vec<_>>();
    assert!(
        !caps
            .iter()
            .any(|c| c.code == lr_bgp::capabilities::CapabilityCode::ExtendedNextHop),
        "ENH must not be advertised without with_extended_next_hop"
    );
}

/// A session with `with_extended_next_hop` must advertise the (1,1,2)
/// tuple in OPEN.
#[test]
fn enh_advertised_when_configured() {
    use lr_bgp::capabilities::{Capability, CapabilityCode};
    use lr_bgp::{BgpEvent, BgpPeer, PeerConfig};
    use lr_core::codec::Decoder;

    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), V4_ROUTER_ID_A);
    cfg.extended_next_hop = vec![(1, 1, 2)];
    let mut a = BgpPeer::new(cfg);
    a.step(BgpEvent::ManualStart);
    a.step(BgpEvent::TransportOpen);
    let open_bytes = a.drain_outgoing();
    let mut codec = lr_bgp::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&open_bytes);
    let msg = codec.decode(&mut r).unwrap().unwrap();
    let lr_bgp::BgpMessage::Open(open) = msg else {
        panic!("expected OPEN");
    };
    let caps: Vec<Capability> = open
        .params
        .iter()
        .filter_map(|p| {
            if p.param_type == lr_bgp::message::open::OpenParam::PARAM_TYPE_CAPABILITY {
                Some(Capability::decode_set(&p.value))
            } else {
                None
            }
        })
        .flatten()
        .collect();
    let enh = caps
        .iter()
        .find(|c| c.code == CapabilityCode::ExtendedNextHop)
        .expect("ENH capability advertised");
    assert_eq!(enh.as_extended_next_hop(), Some(vec![(1, 1, 2)]));
    // The wire value must be the RFC 5549 §4 / RFC 8950 §4 6-byte tuple
    // (AFI:2, SAFI:2, NH-AFI:2) — byte-identical to what BIRD 2.x and FRR
    // send, and the only form both accept (they OPEN-error anything that
    // is not a multiple of 6).
    assert_eq!(enh.value, vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x02]);
}
