//! Babel update reception against the reference implementations' wire
//! behaviour: RFC 8966 §4.5.2 prefix compression (BIRD's v6
//! announcements), the RFC 9229 §2.4 AE 4 IPv4-via-IPv6 encoding, the
//! own-router-id self-echo guard, wildcard retractions, and the
//! Route/Seqno Request handshake (§3.2.6) — plus the Loc-RIB preference
//! order that keeps an operator's static route from being displaced by
//! a Babel-learned route for the same prefix.

use lr_babel::message::{
    Hello, NextHop, PrefixCache, RouteRequest, RouterId as RouterIdTlv, SeqnoRequest, Update,
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
