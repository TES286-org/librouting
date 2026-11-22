//! RFC 5291 / RFC 5292 Outbound Route Filtering end-to-end tests.
//!
//! The capability exchange alone is inert: the receiver of routes must
//! send ORF entries in a ROUTE-REFRESH, the sender must apply them to
//! its Adj-RIB-Out, and an IMMEDIATE update must re-advertise the
//! family so the new filter takes effect. The router also withholds the
//! initial dump for a family until the peer's ORF (or a plain
//! ROUTE-REFRESH) arrives, per RFC 5291 §6.

use lr_bgp::message::{AddressPrefixOrf, OrfAction, OrfWhenToRefresh};
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

fn pump(a: &mut DefaultRouter, ha: SessionHandle, b: &mut DefaultRouter, hb: SessionHandle) {
    for _ in 0..32 {
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

/// `mode` is the RFC 5291 §5 Send/Receive value: 1 receive, 2 send,
/// 3 both.
fn bgp_cfg(local_as: u32, peer_as: u32, rid: [u8; 4], local: [u8; 4]) -> SessionConfig {
    SessionConfig::bgp(Asn(local_as), Asn(peer_as), RouterId::from_v4(rid))
        .with_local_address(IpAddr::V4(local))
        .with_mrai_ms(0)
}

fn orf_mode(cfg: SessionConfig, mode: u8) -> SessionConfig {
    let mut cfg = cfg;
    cfg.orf = vec![(1, 1, vec![(64, mode)])];
    cfg
}

fn has(router: &DefaultRouter, prefix: Prefix) -> bool {
    router
        .rib_paths_snapshot()
        .iter()
        .any(|r| r.key.prefix == prefix)
}

/// B sends a PERMIT ORF for `10.0.0.0/16`; A must withhold its initial
/// dump until that ORF arrives, then advertise only the matching route.
#[test]
fn orf_permit_filters_the_peers_adj_rib_out() {
    let permitted = Prefix::new_v4([10, 0, 0, 0], 24);
    let denied = Prefix::new_v4([10, 1, 0, 0], 24);

    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(orf_mode(
            bgp_cfg(64512, 64513, [10, 0, 0, 1], [192, 0, 2, 1]),
            1, // receive ORF from B
        ))
        .unwrap();
    let hb = b
        .add_session(
            orf_mode(
                bgp_cfg(64513, 64512, [10, 0, 0, 2], [192, 0, 2, 2]),
                2, // send ORF to A
            )
            .with_orf_entries(
                NlriFamily::IPV4_UNICAST,
                vec![AddressPrefixOrf::add(
                    10,
                    true,
                    Prefix::new_v4([10, 0, 0, 0], 16),
                    0,
                    0,
                )],
            ),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    a.originate(permitted, Some(IpAddr::V4([192, 0, 2, 1])));
    a.originate(denied, Some(IpAddr::V4([192, 0, 2, 1])));
    pump(&mut a, ha, &mut b, hb);

    assert!(
        a.orf_entries(ha)
            .iter()
            .any(|(f, e)| *f == NlriFamily::IPV4_UNICAST && e.iter().any(|e| e.sequence == 10)),
        "A must have installed B's ORF"
    );
    assert!(has(&b, permitted), "the permitted route must be advertised");
    assert!(
        !has(&b, denied),
        "a route outside the ORF must not be advertised"
    );
}

/// A DENY entry blocks the matching route; a route matching no entry is
/// also withheld (RFC 5291 §6).
#[test]
fn orf_deny_and_no_match_withhold_routes() {
    let denied = Prefix::new_v4([198, 51, 100, 0], 24);
    let unmatched = Prefix::new_v4([203, 0, 113, 0], 24);
    let permitted = Prefix::new_v4([192, 0, 2, 0], 24);

    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(orf_mode(
            bgp_cfg(64512, 64513, [10, 0, 0, 1], [192, 0, 2, 1]),
            1,
        ))
        .unwrap();
    let hb = b
        .add_session(
            orf_mode(bgp_cfg(64513, 64512, [10, 0, 0, 2], [192, 0, 2, 2]), 2).with_orf_entries(
                NlriFamily::IPV4_UNICAST,
                vec![
                    AddressPrefixOrf::add(1, false, Prefix::new_v4([198, 51, 100, 0], 24), 0, 0),
                    AddressPrefixOrf::add(2, true, Prefix::new_v4([192, 0, 2, 0], 24), 0, 0),
                ],
            ),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    for p in [denied, unmatched, permitted] {
        a.originate(p, Some(IpAddr::V4([192, 0, 2, 1])));
    }
    pump(&mut a, ha, &mut b, hb);

    assert!(has(&b, permitted), "the permit entry matches");
    assert!(!has(&b, denied), "the deny entry wins over no permit");
    assert!(
        !has(&b, unmatched),
        "a route matching no ORF entry must not be advertised"
    );

    // REMOVE-ALL lifts the filter: A re-advertises everything.
    let remove_all = AddressPrefixOrf {
        sequence: 0,
        action: OrfAction::RemoveAll,
        permit: false,
        prefix: Prefix::new_v4([0, 0, 0, 0], 0),
        min_len: 0,
        max_len: 0,
    };
    assert!(b
        .send_orf(
            hb,
            NlriFamily::IPV4_UNICAST,
            OrfWhenToRefresh::Immediate,
            &[remove_all],
        )
        .unwrap());
    pump(&mut a, ha, &mut b, hb);
    assert!(a.orf_entries(ha).is_empty(), "REMOVE-ALL clears the ORF");
    assert!(
        has(&b, denied) && has(&b, unmatched),
        "all routes flow again"
    );
}

/// `When-to-refresh = DEFER` stores the entries but withholds the refresh
/// until a plain ROUTE-REFRESH arrives (RFC 5291 §6).
#[test]
fn orf_defer_waits_for_a_plain_refresh() {
    let permitted = Prefix::new_v4([10, 0, 0, 0], 24);

    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(orf_mode(
            bgp_cfg(64512, 64513, [10, 0, 0, 1], [192, 0, 2, 1]),
            1,
        ))
        .unwrap();
    let hb = b
        .add_session(orf_mode(
            bgp_cfg(64513, 64512, [10, 0, 0, 2], [192, 0, 2, 2]),
            2,
        ))
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    b.send_orf(
        hb,
        NlriFamily::IPV4_UNICAST,
        OrfWhenToRefresh::Defer,
        &[AddressPrefixOrf::add(
            1,
            true,
            Prefix::new_v4([10, 0, 0, 0], 16),
            0,
            0,
        )],
    )
    .unwrap();
    pump(&mut a, ha, &mut b, hb);
    // The entry is installed but no refresh happened yet.
    assert!(a.orf_entries(ha).iter().any(|(_, e)| !e.is_empty()));

    a.originate(permitted, Some(IpAddr::V4([192, 0, 2, 1])));
    pump(&mut a, ha, &mut b, hb);
    assert!(!has(&b, permitted), "DEFER must not refresh on its own");

    // A plain ROUTE-REFRESH applies the deferred ORF.
    assert!(b.request_route_refresh(hb, NlriFamily::IPV4_UNICAST));
    pump(&mut a, ha, &mut b, hb);
    assert!(has(&b, permitted), "the plain refresh applies the ORF");
}
