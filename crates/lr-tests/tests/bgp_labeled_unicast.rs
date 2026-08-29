//! End-to-end RFC 8277 BGP labelled-unicast (BGP-LU) tests.
//!
//! Verifies the full labelled-route lifecycle over a two-router eBGP pair:
//!
//!   1. `originate_labeled` injects a route with an MPLS label stack into
//!      router A's Loc-RIB.
//!   2. The eBGP egress path encodes the label stack into MP_REACH_NLRI
//!      (AFI=1/SAFI=4) using the RFC 8277 §3.2 wire form.
//!   3. Router B's FSM decodes the labelled NLRI, restores the label stack
//!      onto the route via the private `LrMplsLabelStack` attribute, and
//!      installs the route in its Loc-RIB.
//!   4. `unoriginate` propagates a labelled withdrawal via MP_UNREACH_NLRI
//!      and B removes the route.

use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_mpls::{Label, LabelStack};
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

/// Wire up an eBGP pair that negotiates IPv4 labelled-unicast.
fn ebgp_lu_pair() -> (DefaultRouter, DefaultRouter, SessionHandle, SessionHandle) {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1]))
                .with_mp_families(vec![
                    NlriFamily::IPV4_UNICAST,
                    NlriFamily::IPV4_LABELED_UNICAST,
                ]),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2]))
                .with_mp_families(vec![
                    NlriFamily::IPV4_UNICAST,
                    NlriFamily::IPV4_LABELED_UNICAST,
                ]),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    (a, b, ha, hb)
}

/// A originates a labelled route; B installs it with the same label stack.
#[test]
fn ebgp_labeled_route_propagates() {
    let (mut a, mut b, ha, hb) = ebgp_lu_pair();
    let _ = a.poll_events();
    let _ = b.poll_events();

    let stack = LabelStack::from_labels([Label::new(100)]);
    a.originate_labeled(
        Prefix::new_v4([203, 0, 113, 0], 24),
        NlriFamily::IPV4_LABELED_UNICAST,
        stack.clone(),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snapshot = b.rib_snapshot();
    assert_eq!(snapshot.len(), 1, "B must have exactly one labelled route");
    let r = &snapshot[0];
    assert_eq!(r.key.prefix, Prefix::new_v4([203, 0, 113, 0], 24));
    assert_eq!(r.key.family, NlriFamily::IPV4_LABELED_UNICAST);
    assert_eq!(r.next_hop, Some(IpAddr::V4([192, 0, 2, 1])));

    let attrs: lr_bgp::path::PathAttributes = r.attributes.clone().into();
    let decoded_stack = attrs
        .label_stack()
        .expect("route carries the label stack attribute");
    assert_eq!(decoded_stack.len(), 1, "exactly one label");
    assert_eq!(decoded_stack.labels()[0].value, 100);
}

/// Withdrawing a labelled route propagates as a labelled MP_UNREACH.
#[test]
fn ebgp_labeled_withdraw_propagates() {
    let (mut a, mut b, ha, hb) = ebgp_lu_pair();
    let _ = a.poll_events();
    let _ = b.poll_events();

    let stack = LabelStack::from_labels([Label::new(200)]);
    let key = a.originate_labeled(
        Prefix::new_v4([198, 51, 100, 0], 24),
        NlriFamily::IPV4_LABELED_UNICAST,
        stack,
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);
    assert_eq!(b.rib_snapshot().len(), 1);

    a.unoriginate(&key);
    pump(&mut a, ha, &mut b, hb);
    assert!(
        b.rib_snapshot().is_empty(),
        "B must withdraw after A retracts the labelled route"
    );
}

/// A multi-label stack round-trips end-to-end.
#[test]
fn ebgp_labeled_multi_label_stack() {
    let (mut a, mut b, ha, hb) = ebgp_lu_pair();
    let _ = a.poll_events();
    let _ = b.poll_events();

    let stack = LabelStack::from_labels([Label::new(100), Label::new(200), Label::new(300)]);
    a.originate_labeled(
        Prefix::new_v4([10, 0, 0, 0], 8),
        NlriFamily::IPV4_LABELED_UNICAST,
        stack.clone(),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snapshot = b.rib_snapshot();
    assert_eq!(snapshot.len(), 1);
    let attrs: lr_bgp::path::PathAttributes = snapshot[0].attributes.clone().into();
    let decoded = attrs.label_stack().expect("label stack present");
    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded.labels()[0].value, 100);
    assert_eq!(decoded.labels()[1].value, 200);
    assert_eq!(decoded.labels()[2].value, 300);
}

/// The implicit-null label (value 3) round-trips — it is the canonical
/// "pop the label and forward the IP packet" marker.
#[test]
fn ebgp_labeled_implicit_null() {
    let (mut a, mut b, ha, hb) = ebgp_lu_pair();
    let _ = a.poll_events();
    let _ = b.poll_events();

    let stack = LabelStack::from_labels([Label::IMPLICIT_NULL]);
    a.originate_labeled(
        Prefix::new_v4([10, 99, 0, 0], 16),
        NlriFamily::IPV4_LABELED_UNICAST,
        stack,
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snapshot = b.rib_snapshot();
    assert_eq!(snapshot.len(), 1);
    let attrs: lr_bgp::path::PathAttributes = snapshot[0].attributes.clone().into();
    let decoded = attrs.label_stack().expect("label stack present");
    assert_eq!(decoded.labels()[0].value, Label::IMPLICIT_NULL.value);
}
