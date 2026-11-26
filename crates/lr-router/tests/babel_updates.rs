//! Babel update reception against the reference implementations' wire
//! behaviour: RFC 8966 §4.5.2 prefix compression (BIRD's v6
//! announcements), the RFC 9229 §2.4 AE 4 IPv4-via-IPv6 encoding, the
//! own-router-id self-echo guard, wildcard retractions, and the
//! Route/Seqno Request handshake (§3.2.6) — plus the Loc-RIB preference
//! order that keeps an operator's static route from being displaced by
//! a Babel-learned route for the same prefix.

use lr_babel::message::{
    Hello, Ihu, NextHop, PrefixCache, RouteRequest, RouterId as RouterIdTlv, SeqnoRequest, Update,
};
use lr_babel::tlv::{Tlv, TlvType};
use lr_core::addr::{IpAddr, Prefix};
use lr_core::rib::Protocol;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

const PEER_ID: [u8; 8] = [0, 0, 0, 0, 0xac, 0x17, 0x0a, 0x61];
const OWN_ID: [u8; 8] = [0, 0, 0, 0, 0xac, 0x17, 0x0a, 0x66];

fn frame(tlvs: Vec<Tlv>) -> Vec<u8> {
    let mut frame = lr_babel::BabelFrame::empty();
    frame
        .body
        .push(Tlv::new(TlvType::Hello, Hello::new(1, 100).encode()));
    // The peer's IHU carries its rxcost toward us — the txcost the
    // reception-side link cost is built from. babeld/BIRD accept no
    // Update from a neighbour that has not sent an IHU yet, so the
    // daemon-shaped frame always carries one.
    frame
        .body
        .push(Tlv::new(TlvType::Ihu, Ihu::new(96, 300).encode()));
    frame.body.extend(tlvs);
    lr_babel::BabelCodec::new().encode_vec(&frame).unwrap()
}

fn router_id_tlv(id: [u8; 8]) -> Tlv {
    Tlv::new(TlvType::RouterId, RouterIdTlv { id }.encode().to_vec())
}

fn update_tlv(
    ae: u8,
    plen: u8,
    flags: u8,
    omitted: u8,
    prefix: &[u8],
    seqno: u16,
    metric: u16,
) -> Tlv {
    Tlv::new(
        TlvType::Update,
        Update {
            ae,
            flags,
            prefix_len: plen,
            omitted,
            interval_cs: 300,
            seqno,
            metric,
            prefix: prefix.to_vec(),
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        }
        .encode(),
    )
}

/// `fd00:286:11e:6::/64` as a full 16-byte array.
fn fd00_6() -> Prefix {
    Prefix::new_v6(
        [
            0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        64,
    )
}

/// `fd10:127:286:6::/64` as a full 16-byte array.
fn fd10_6() -> Prefix {
    Prefix::new_v6(
        [
            0xfd, 0x10, 0x01, 0x27, 0x02, 0x86, 0x00, 0x06, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        64,
    )
}

/// `fd00:286:11e::/48` as a full 16-byte array.
fn fd00_48() -> Prefix {
    Prefix::new_v6(
        [
            0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        48,
    )
}

fn babel_session() -> (Box<dyn RouterInstance>, lr_router::SessionHandle) {
    let mut r: Box<dyn RouterInstance> = Box::new(DefaultRouter::new());
    let h = r
        .add_session(SessionConfig::babel(IpAddr::V6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])))
        .unwrap();
    r.start_session(h).unwrap();
    r.set_babel_own_router_id(h, OWN_ID);
    (r, h)
}

/// A frame with an explicit Hello seqno and IHU rxcost, for meshes where
/// each neighbour advertises a different link cost.
fn mesh_frame(hello_seqno: u16, rxcost: u16, tlvs: Vec<Tlv>) -> Vec<u8> {
    let mut f = lr_babel::BabelFrame::empty();
    f.body.push(Tlv::new(
        TlvType::Hello,
        Hello::new(hello_seqno, 100).encode(),
    ));
    f.body
        .push(Tlv::new(TlvType::Ihu, Ihu::new(rxcost, 300).encode()));
    f.body.extend(tlvs);
    lr_babel::BabelCodec::new().encode_vec(&f).unwrap()
}

fn link_local(last: u8) -> IpAddr {
    IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last])
}

fn rib_route(r: &dyn RouterInstance, prefix: Prefix) -> lr_core::rib::Route {
    r.rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == prefix)
        .unwrap_or_else(|| panic!("no route for {prefix}"))
}

fn snapshot_has(r: &dyn RouterInstance, prefix: Prefix, protocol: Protocol) -> bool {
    r.rib_snapshot()
        .iter()
        .any(|rt| rt.key.prefix == prefix && rt.protocol == protocol)
}

/// BIRD's exact v6 shape: a DEF_PREFIX-flagged /64 followed by sibling
/// /64s that omit the shared leading octet, then a fully-compressed
/// /48 (omit=6, zero in-band octets). Pre-fix, the siblings were
/// learned with corrupted prefixes (the tail octets read as the head)
/// and the /48 was dropped outright.
#[test]
fn compressed_v6_updates_install_correct_prefixes() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    let bytes = frame(vec![
        v6_nh.clone(),
        router_id_tlv(PEER_ID),
        // fd00:286:11e:6::/64, full 8 octets, sets the default prefix.
        update_tlv(
            2,
            64,
            Update::FLAG_PREFIX,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            3,
            100,
        ),
        // fd10:127:286:6::/64 announced as omit=1 + 7 octets.
        update_tlv(
            2,
            64,
            0,
            1,
            &[0x10, 0x01, 0x27, 0x02, 0x86, 0x00, 0x06],
            3,
            100,
        ),
        // fd00:286:11e::/48, fully compressed: omit=6, 0 octets.
        update_tlv(2, 48, 0, 6, &[], 3, 100),
    ]);
    r.feed_input(h, &bytes).unwrap();

    assert!(
        snapshot_has(r.as_ref(), fd00_6(), Protocol::Babel),
        "the uncompressed /64 must install"
    );
    assert!(
        snapshot_has(r.as_ref(), fd10_6(), Protocol::Babel),
        "the partially-compressed /64 must install with the FULL prefix (fd10:127:286:6::/64), not the corrupted tail"
    );
    assert!(
        snapshot_has(r.as_ref(), fd00_48(), Protocol::Babel),
        "the fully-compressed /48 must install (pre-fix it was dropped)"
    );
}

/// RFC 9229 §2.4: an AE 4 Update is an IPv4 destination routed over the
/// IPv6 next hop — the encoding BIRD/babeld expect on a v6-only tunnel.
#[test]
fn ae4_update_installs_v4_route_over_v6_next_hop() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    let bytes = frame(vec![
        v6_nh,
        router_id_tlv(PEER_ID),
        // 172.23.10.97/32 via the v6 next hop.
        update_tlv(4, 32, 0, 0, &[172, 23, 10, 97], 3, 100),
    ]);
    r.feed_input(h, &bytes).unwrap();
    assert!(
        snapshot_has(
            r.as_ref(),
            Prefix::new_v4([172, 23, 10, 97], 32),
            Protocol::Babel
        ),
        "AE 4 update must install an IPv4 route"
    );
    let route = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([172, 23, 10, 97], 32))
        .unwrap();
    assert_eq!(
        route.next_hop,
        Some(IpAddr::V6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
        ])),
        "the v6 NextHop TLV must carry the AE 4 route"
    );
}

/// A peer re-advertising our own claims back at us (no-split-horizon
/// echo, e.g. BIRD with `export all` on a single link) must be ignored
/// — BIRD's `msg->router_id == p->router_id` guard.
#[test]
fn self_router_id_echo_is_ignored() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    let bytes = frame(vec![
        v6_nh,
        router_id_tlv(OWN_ID), // OUR router-id, echoed back by the peer.
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            3,
            100,
        ),
    ]);
    r.feed_input(h, &bytes).unwrap();
    assert!(
        r.rib_snapshot().is_empty(),
        "self-echoed updates must not install routes"
    );
}

/// An AE 0 (wildcard) Update with metric infinity is the §4.6.9
/// "retract everything from this neighbour" signal.
#[test]
fn wildcard_retraction_flushes_the_neighbours_routes() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    let teach = frame(vec![
        v6_nh.clone(),
        router_id_tlv(PEER_ID),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            3,
            100,
        ),
    ]);
    r.feed_input(h, &teach).unwrap();
    assert!(snapshot_has(r.as_ref(), fd00_6(), Protocol::Babel));

    let retract = frame(vec![
        v6_nh,
        router_id_tlv(PEER_ID),
        update_tlv(0, 0, 0, 0, &[], 0, 0xFFFF),
    ]);
    r.feed_input(h, &retract).unwrap();
    assert!(
        r.rib_snapshot().is_empty(),
        "wildcard retraction must flush the neighbour's routes"
    );
}

/// Route Requests (§3.2.6) and own-router-id Seqno Requests (§3.2.6.2)
/// surface to the transport through the take-API.
#[test]
fn route_and_seqno_requests_surface_to_the_transport() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    // A wildcard route request (AE 0, plen 0).
    let req = frame(vec![Tlv::new(
        TlvType::RouteRequest,
        RouteRequest {
            ae: 0,
            prefix_len: 0,
            prefix: Vec::new(),
        }
        .encode(),
    )]);
    r.feed_input(h, &req).unwrap();
    assert!(r.babel_take_route_request(h), "route request must surface");
    assert!(!r.babel_take_route_request(h), "and clear on take");

    // A seqno request naming OUR router-id: seqno 500 requested.
    let seqno_req = frame(vec![Tlv::new(
        TlvType::SeqnoRequest,
        SeqnoRequest {
            ae: 2,
            prefix_len: 64,
            prefix: vec![0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            seqno: 500,
            hop_count: 2,
            router_id: OWN_ID,
        }
        .encode(),
    )]);
    r.feed_input(h, &seqno_req).unwrap();
    assert_eq!(
        r.babel_take_own_seqno_request(h),
        Some(500),
        "own seqno request must surface with the requested value"
    );
    assert_eq!(r.babel_take_own_seqno_request(h), None, "and clear on take");

    // A seqno request for a foreign router-id must NOT surface.
    let foreign_req = frame(vec![Tlv::new(
        TlvType::SeqnoRequest,
        SeqnoRequest {
            ae: 2,
            prefix_len: 64,
            prefix: vec![0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            seqno: 500,
            hop_count: 2,
            router_id: PEER_ID,
        }
        .encode(),
    )]);
    r.feed_input(h, &foreign_req).unwrap();
    assert_eq!(r.babel_take_own_seqno_request(h), None);

    // None of the request TLVs install routes.
    let _ = v6_nh;
    assert!(r.rib_snapshot().is_empty());
}

/// The load-bearing preference rule: a Babel-learned route for a prefix
/// the operator ALSO configured as a static must not displace the
/// static — the daemon keeps announcing its own aggregate and the
/// kernel keeps the operator's blackhole. Withdrawing the Babel copy
/// leaves the static installed.
#[test]
fn static_route_is_not_displaced_by_babel_route() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::babel(IpAddr::V4([169, 254, 6, 2])))
        .unwrap();
    r.start_session(h).unwrap();
    r.set_babel_own_router_id(h, OWN_ID);

    let prefix = Prefix::new_v4([172, 23, 10, 96], 27);
    let key = lr_core::rib::RouteKey::new(prefix, lr_core::nlri::NlriFamily::IPV4_UNICAST);
    r.install_static(
        prefix,
        lr_core::nlri::NlriFamily::IPV4_UNICAST,
        None,
        10,
        None,
    );
    assert!(snapshot_has(&r, prefix, Protocol::Static));

    // The peer announces the SAME aggregate over Babel (both tunnel ends
    // originate it). Pre-fix this blindly replaced the static.
    let v4_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 1,
            address: IpAddr::V4([169, 254, 6, 2]),
        }
        .encode(),
    );
    let teach = frame(vec![
        v4_nh.clone(),
        router_id_tlv(PEER_ID),
        update_tlv(1, 27, 0, 0, &[172, 23, 10, 96], 3, 0),
    ]);
    r.feed_input(h, &teach).unwrap();

    let best = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key == key)
        .unwrap();
    assert_eq!(
        best.protocol,
        Protocol::Static,
        "the static (admin distance 1) must win over the Babel route (120)"
    );
    assert_eq!(best.next_hop, None, "the blackhole next hop is preserved");

    // The Babel copy is still recorded: when the peer retracts it, the
    // static simply stays (no spurious withdraw event either).
    let retract = frame(vec![
        v4_nh,
        router_id_tlv(PEER_ID),
        update_tlv(1, 27, 0, 0, &[172, 23, 10, 96], 3, 0xFFFF),
    ]);
    r.feed_input(h, &retract).unwrap();
    let best = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key == key)
        .unwrap();
    assert_eq!(
        best.protocol,
        Protocol::Static,
        "retracting the Babel copy must leave the static installed"
    );
}

/// The mirror image: when the static goes away (config reload) and only
/// the Babel route remains, it takes over — the fallback path.
#[test]
fn babel_route_takes_over_when_static_is_removed() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::babel(IpAddr::V4([169, 254, 6, 2])))
        .unwrap();
    r.start_session(h).unwrap();
    r.set_babel_own_router_id(h, OWN_ID);

    let prefix = Prefix::new_v4([172, 23, 10, 96], 27);
    let family = lr_core::nlri::NlriFamily::IPV4_UNICAST;
    let key = lr_core::rib::RouteKey::new(prefix, family);
    r.install_static(prefix, family, None, 10, None);

    let v4_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 1,
            address: IpAddr::V4([169, 254, 6, 2]),
        }
        .encode(),
    );
    let teach = frame(vec![
        v4_nh,
        router_id_tlv(PEER_ID),
        update_tlv(1, 27, 0, 0, &[172, 23, 10, 96], 3, 0),
    ]);
    r.feed_input(h, &teach).unwrap();
    assert_eq!(
        r.rib_snapshot()
            .iter()
            .find(|rt| rt.key == key)
            .unwrap()
            .protocol,
        Protocol::Static
    );

    // Operator removes the static (reload): the Babel route wins.
    r.uninstall_static(&key);
    assert!(
        snapshot_has(&r, prefix, Protocol::Babel),
        "the recorded Babel route must take over after the static is removed"
    );
}

/// PrefixCache unit sanity on the BIRD wire form: partially- and
/// fully-compressed Updates expand to the full prefix.
#[test]
fn prefix_cache_expands_bird_wire_form() {
    let mut cache = PrefixCache::default();
    let first = cache
        .expand(&Update {
            ae: 2,
            flags: Update::FLAG_PREFIX,
            prefix_len: 64,
            omitted: 0,
            interval_cs: 300,
            seqno: 1,
            metric: 202,
            prefix: vec![0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        })
        .unwrap();
    assert_eq!(first.prefix.len(), 8);
    let second = cache
        .expand(&Update {
            ae: 2,
            flags: 0,
            prefix_len: 64,
            omitted: 7,
            interval_cs: 300,
            seqno: 1,
            metric: 202,
            prefix: vec![0x06],
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        })
        .unwrap();
    assert_eq!(
        second.prefix,
        vec![0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06]
    );
}

/// A peer retraction (metric=infinity) must annotate the withdrawal
/// delta with the reason "babel peer retraction (metric=infinity)".
/// This is the diagnostic the production report asked for: the operator
/// needs to see WHY a Babel route disappeared.
#[test]
fn retraction_withdrawal_carries_reason() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    let teach = frame(vec![
        v6_nh.clone(),
        router_id_tlv(PEER_ID),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            3,
            100,
        ),
    ]);
    r.feed_input(h, &teach).unwrap();
    assert!(snapshot_has(r.as_ref(), fd00_6(), Protocol::Babel));
    // Drain the install events.
    let _ = r.poll_events();

    let retract = frame(vec![
        v6_nh,
        router_id_tlv(PEER_ID),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            3,
            0xFFFF,
        ),
    ]);
    r.feed_input(h, &retract).unwrap();
    let events = r.poll_events();
    // The withdrawal reason must surface as a Log event BEFORE the
    // RouteWithdrawn event.
    let log_msg = events.iter().find_map(|e| match e {
        lr_router::RouterEvent::Log(msg) => Some(msg.as_str()),
        _ => None,
    });
    assert!(
        log_msg.is_some(),
        "a retraction must emit a Log event with the withdraw reason"
    );
    let log_msg = log_msg.unwrap();
    assert!(
        log_msg.contains("peer retraction"),
        "the reason must mention 'peer retraction', got: {log_msg}"
    );
    assert!(
        log_msg.contains("metric=infinity"),
        "the reason must mention 'metric=infinity', got: {log_msg}"
    );
}

/// A wildcard retraction (RFC 8966 §4.6.9 — AE 0, metric 0xFFFF) must
/// annotate the withdrawal delta with the reason "babel peer wildcard
/// retraction" — NOT the misleading fallback "babel best-path
/// displacement". This is the production-report symptom: a BIRD peer
/// whose BGP upstreams disconnected sent a wildcard retraction, and
/// the operator saw "best-path displacement" and (correctly) concluded
/// the message was wrong — with one upstream, no "election" can
/// produce zero paths. The actual cause is an explicit peer-side
/// retraction, not a local-decision displacement.
#[test]
fn wildcard_retraction_carries_reason() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    // Teach two routes from the peer — the wildcard retraction will
    // flush both, and the reason must mention the count.
    let teach = frame(vec![
        v6_nh.clone(),
        router_id_tlv(PEER_ID),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            3,
            100,
        ),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x10, 0x01, 0x27, 0x02, 0x86, 0x00, 0x06],
            3,
            100,
        ),
    ]);
    r.feed_input(h, &teach).unwrap();
    assert!(snapshot_has(r.as_ref(), fd00_6(), Protocol::Babel));
    assert!(snapshot_has(r.as_ref(), fd10_6(), Protocol::Babel));
    // Drain the install events.
    let _ = r.poll_events();

    // The peer sends a wildcard retraction (AE 0, metric 0xFFFF).
    let retract = frame(vec![
        v6_nh,
        router_id_tlv(PEER_ID),
        update_tlv(0, 0, 0, 0, &[], 0, 0xFFFF),
    ]);
    r.feed_input(h, &retract).unwrap();
    let events = r.poll_events();
    let log_msg = events.iter().find_map(|e| match e {
        lr_router::RouterEvent::Log(msg) => Some(msg.as_str()),
        _ => None,
    });
    assert!(
        log_msg.is_some(),
        "a wildcard retraction must emit a Log event with the withdraw reason"
    );
    let log_msg = log_msg.unwrap();
    assert!(
        log_msg.contains("wildcard retraction"),
        "the reason must mention 'wildcard retraction' (not 'best-path displacement'), got: {log_msg}"
    );
    assert!(
        log_msg.contains("metric=infinity"),
        "the reason must mention 'metric=infinity', got: {log_msg}"
    );
    assert!(
        log_msg.contains("2 route(s)"),
        "the reason must mention the route count, got: {log_msg}"
    );
    assert!(
        !log_msg.contains("best-path displacement"),
        "the misleading fallback must NOT fire for wildcard retractions, got: {log_msg}"
    );
}

/// Multiple per-prefix retractions in one frame must produce a
/// count-annotated reason ("N route(s)") rather than only naming the
/// LAST prefix. Pre-fix, `last_withdraw_reason` was a single String
/// overwritten on every retraction TLV — a 29-route retraction frame
/// logged only the last prefix, hiding the scope of the retraction
/// from the operator.
#[test]
fn multi_prefix_retraction_carries_count() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    // Teach two routes from the peer.
    let teach = frame(vec![
        v6_nh.clone(),
        router_id_tlv(PEER_ID),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            3,
            100,
        ),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x10, 0x01, 0x27, 0x02, 0x86, 0x00, 0x06],
            3,
            100,
        ),
    ]);
    r.feed_input(h, &teach).unwrap();
    assert!(snapshot_has(r.as_ref(), fd00_6(), Protocol::Babel));
    assert!(snapshot_has(r.as_ref(), fd10_6(), Protocol::Babel));
    let _ = r.poll_events();

    // Retract both prefixes in one frame.
    let retract = frame(vec![
        v6_nh,
        router_id_tlv(PEER_ID),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            3,
            0xFFFF,
        ),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x10, 0x01, 0x27, 0x02, 0x86, 0x00, 0x06],
            3,
            0xFFFF,
        ),
    ]);
    r.feed_input(h, &retract).unwrap();
    let events = r.poll_events();
    let log_msg = events
        .iter()
        .find_map(|e| match e {
            lr_router::RouterEvent::Log(msg) => Some(msg.as_str()),
            _ => None,
        })
        .expect("multi-prefix retraction must emit a Log event");
    assert!(
        log_msg.contains("peer retraction"),
        "the reason must mention 'peer retraction', got: {log_msg}"
    );
    assert!(
        log_msg.contains("metric=infinity"),
        "the reason must mention 'metric=infinity', got: {log_msg}"
    );
    assert!(
        log_msg.contains("2 route(s)"),
        "the reason must mention the count (not just the last prefix), got: {log_msg}"
    );
}

/// RFC 8966 §3.5.2: an infeasible update (same seqno, worse metric)
/// MUST NOT displace the existing feasible route. The production
/// report showed a single-upstream tunnel flapping — routes
/// installed, withdrawn with the misleading "babel best-path
/// displacement" reason, re-installed — because the pre-fix
/// `insert_timed` unconditionally overwrote the feasible route with
/// the infeasible one. `best_routes()` then skipped the infeasible
/// entry, `diff()` produced a withdrawal, and the reason renderer
/// logged the "best-path displacement" fallback.
///
/// This test feeds the exact stimulus at the router level: a
/// feasible Update, then an infeasible Update with the same seqno
/// but a worse metric. The route must stay installed, and no
/// "best-path displacement" Log event must fire.
#[test]
fn infeasible_update_does_not_displace_feasible_route() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    // 1. Teach a feasible route: seqno 100, metric 100.
    let teach = frame(vec![
        v6_nh.clone(),
        router_id_tlv(PEER_ID),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            100,
            100,
        ),
    ]);
    r.feed_input(h, &teach).unwrap();
    assert!(
        snapshot_has(r.as_ref(), fd00_6(), Protocol::Babel),
        "the feasible route must install"
    );
    // Drain the install events.
    let _ = r.poll_events();

    // 2. Re-advertise with the SAME seqno but a WORSE metric (1000).
    //    Per RFC 8966 §3.5.1, this is infeasible: seqno == FD.seqno
    //    AND metric >= FD.metric. The fix ignores it; the pre-fix
    //    bug overwrote the feasible route and produced a withdrawal.
    let worse = frame(vec![
        v6_nh,
        router_id_tlv(PEER_ID),
        update_tlv(
            2,
            64,
            0,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
            100,
            1000,
        ),
    ]);
    r.feed_input(h, &worse).unwrap();

    // 3. The route must STILL be in the RIB.
    assert!(
        snapshot_has(r.as_ref(), fd00_6(), Protocol::Babel),
        "the feasible route must not be displaced by the infeasible update"
    );

    // 4. No "best-path displacement" Log event must have fired.
    let events = r.poll_events();
    let displacement_log = events.iter().find_map(|e| match e {
        lr_router::RouterEvent::Log(msg) if msg.contains("best-path displacement") => {
            Some(msg.as_str())
        }
        _ => None,
    });
    assert!(
        displacement_log.is_none(),
        "infeasible update must not produce a 'best-path displacement' withdrawal; got: {:?}",
        displacement_log
    );

    // 5. No RouteWithdrawn event for the prefix.
    let withdrawn = events.iter().any(|e| {
        matches!(
            e,
            lr_router::RouterEvent::RouteWithdrawn(k) if k.prefix == fd00_6()
        )
    });
    assert!(
        !withdrawn,
        "infeasible update must not withdraw the feasible route"
    );
}

/// A Babel interface has many neighbours, but one speaker. The receiver
/// must fold each neighbour's own IHU cost into that neighbour's routes
/// and select the lowest total metric per prefix — BIRD's
/// `babel_select_route` and FRR's `find_best_route`. A single shared link
/// cost made the last datagram heard win, which pointed every prefix at
/// one next hop with the same metric.
#[test]
fn multiple_neighbours_select_the_lowest_cost_route() {
    let (mut r, h) = babel_session();
    let peer_a = link_local(0x0a);
    let peer_b = link_local(0x0b);
    let dest_bytes = [0xfd, 0, 0, 0, 0, 0, 0, 1];
    let dest = Prefix::new_v6([0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], 64);

    // Neighbour A: its IHU reports rxcost 200, so A's route costs 200.
    r.babel_note_peer(h, peer_a);
    let from_a = mesh_frame(
        1,
        200,
        vec![
            router_id_tlv([0, 0, 0, 0, 0, 0, 0, 1]),
            Tlv::new(
                TlvType::NextHop,
                NextHop {
                    ae: 2,
                    address: peer_a,
                }
                .encode(),
            ),
            update_tlv(2, 64, 0, 0, &dest_bytes, 1, 0),
        ],
    );
    r.feed_input(h, &from_a).unwrap();
    let selected = rib_route(r.as_ref(), dest);
    assert_eq!(selected.next_hop, Some(peer_a));
    assert_eq!(selected.preference.metric, 200);

    // Neighbour B: a better link (rxcost 96) on the SAME interface.
    r.babel_note_peer(h, peer_b);
    let from_b = mesh_frame(
        1,
        96,
        vec![
            router_id_tlv([0, 0, 0, 0, 0, 0, 0, 2]),
            Tlv::new(
                TlvType::NextHop,
                NextHop {
                    ae: 2,
                    address: peer_b,
                }
                .encode(),
            ),
            update_tlv(2, 64, 0, 0, &dest_bytes, 1, 0),
        ],
    );
    r.feed_input(h, &from_b).unwrap();
    let selected = rib_route(r.as_ref(), dest);
    assert_eq!(
        selected.next_hop,
        Some(peer_b),
        "the cheaper neighbour must win the election"
    );
    assert_eq!(selected.preference.metric, 96);

    // Re-hearing both neighbours' identical claims must not churn the
    // selected route. This is the batch withdraw/re-install flap.
    let _ = r.poll_events();
    for _ in 0..5 {
        r.babel_note_peer(h, peer_a);
        r.feed_input(h, &from_a).unwrap();
        r.babel_note_peer(h, peer_b);
        r.feed_input(h, &from_b).unwrap();
    }
    let events = r.poll_events();
    assert!(
        events.iter().all(|e| {
            !matches!(
                e,
                lr_router::RouterEvent::RouteInstalled(_)
                    | lr_router::RouterEvent::RouteWithdrawn(_)
            )
        }),
        "identical re-announcements must not churn the route: {events:?}"
    );
    assert_eq!(rib_route(r.as_ref(), dest).next_hop, Some(peer_b));

    // B retracts only its own claim; A's route must take over instead of
    // the prefix disappearing.
    let b_retract = mesh_frame(
        1,
        96,
        vec![
            router_id_tlv([0, 0, 0, 0, 0, 0, 0, 2]),
            Tlv::new(
                TlvType::NextHop,
                NextHop {
                    ae: 2,
                    address: peer_b,
                }
                .encode(),
            ),
            update_tlv(2, 64, 0, 0, &dest_bytes, 1, 0xFFFF),
        ],
    );
    r.babel_note_peer(h, peer_b);
    r.feed_input(h, &b_retract).unwrap();
    let selected = rib_route(r.as_ref(), dest);
    assert_eq!(
        selected.next_hop,
        Some(peer_a),
        "the surviving neighbour's route must be selected"
    );
    assert_eq!(selected.preference.metric, 200);

    // A's wildcard retraction flushes only A's routes.
    let a_retract = mesh_frame(
        1,
        200,
        vec![
            router_id_tlv([0, 0, 0, 0, 0, 0, 0, 1]),
            update_tlv(0, 0, 0, 0, &[], 0, 0xFFFF),
        ],
    );
    r.babel_note_peer(h, peer_a);
    r.feed_input(h, &a_retract).unwrap();
    assert!(
        !snapshot_has(r.as_ref(), dest, Protocol::Babel),
        "the last neighbour's retraction must withdraw the prefix"
    );
}

/// In a mesh, several neighbours re-advertise the same origin's claim
/// with the same (seqno, metric). RFC 8966 §3.2.6 keys routes by neighbour,
/// so each copy stays in the cache and the cheapest link is selected.
#[test]
fn same_origin_claim_via_two_neighbours_is_an_alternate() {
    let (mut r, h) = babel_session();
    let peer_a = link_local(0x0a);
    let peer_b = link_local(0x0b);
    let dest_bytes = [0xfd, 0, 0, 0, 0, 0, 0, 2];
    let dest = Prefix::new_v6([0xfd, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0], 64);

    for (peer, rxcost) in [(peer_a, 200u16), (peer_b, 96u16)] {
        r.babel_note_peer(h, peer);
        let frame = mesh_frame(
            1,
            rxcost,
            vec![
                router_id_tlv([0, 0, 0, 0, 0, 0, 0, 9]),
                Tlv::new(
                    TlvType::NextHop,
                    NextHop {
                        ae: 2,
                        address: peer,
                    }
                    .encode(),
                ),
                update_tlv(2, 64, 0, 0, &dest_bytes, 42, 0),
            ],
        );
        r.feed_input(h, &frame).unwrap();
    }

    let selected = rib_route(r.as_ref(), dest);
    assert_eq!(selected.next_hop, Some(peer_b));
    assert_eq!(selected.preference.metric, 96);
}

/// RFC 8966 §4.6.9: a prefix of Plen=0 carries zero in-band octets —
/// the default route (::/0 for AE 2, 0.0.0.0/0 for AE 1). The
/// production path used to read the empty octet vector as a malformed
/// Update and return, so a peer's default-route announcement AND its
/// retraction were both silently dropped (a stale default route then
/// lingered until the neighbour expired). Both directions install and
/// retract now.
#[test]
fn plen_zero_default_route_installs_and_retracts() {
    let (mut r, h) = babel_session();
    let v6_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        }
        .encode(),
    );
    let v4_nh = Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 1,
            address: IpAddr::V4([192, 0, 2, 2]),
        }
        .encode(),
    );
    let default_v6 = Prefix::new_v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0);
    let default_v4 = Prefix::new_v4([0, 0, 0, 0], 0);

    let announce = frame(vec![
        v6_nh.clone(),
        v4_nh,
        router_id_tlv(PEER_ID),
        // ::/0, AE 2, zero in-band octets.
        update_tlv(2, 0, 0, 0, &[], 3, 100),
        // 0.0.0.0/0, AE 1, zero in-band octets.
        update_tlv(1, 0, 0, 0, &[], 3, 100),
    ]);
    r.feed_input(h, &announce).unwrap();
    assert!(
        snapshot_has(r.as_ref(), default_v6, Protocol::Babel),
        "the v6 default route (Plen=0, zero octets) must install"
    );
    assert!(
        snapshot_has(r.as_ref(), default_v4, Protocol::Babel),
        "the v4 default route (Plen=0, zero octets) must install"
    );

    // A per-prefix retraction of ::/0 — metric infinity on the same
    // (AE, Plen, prefix) shape — must withdraw it.
    let retract = frame(vec![
        v6_nh,
        router_id_tlv(PEER_ID),
        update_tlv(2, 0, 0, 0, &[], 3, 0xFFFF),
    ]);
    r.feed_input(h, &retract).unwrap();
    assert!(
        !snapshot_has(r.as_ref(), default_v6, Protocol::Babel),
        "retracting the v6 default route must withdraw it (pre-fix the retraction was dropped and the stale default lingered)"
    );
    assert!(
        snapshot_has(r.as_ref(), default_v4, Protocol::Babel),
        "the v4 default route is a distinct prefix and must survive the v6 retraction"
    );
}
