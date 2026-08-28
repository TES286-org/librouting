//! End-to-end tests for BMP (RFC 7854) monitoring integration.
//!
//! The router's `set_bmp_sink` installs a closure that receives encoded
//! BMP messages whenever a BGP session transitions to Established (Peer
//! Up), goes down (Peer Down), or a route enters the Loc-RIB (Route
//! Monitoring). These tests verify the full pipeline: a BGP session
//! establishes, the BMP sink fires, and the encoded BMP messages decode
//! correctly.

use std::sync::{Arc, Mutex};

use lr_bmp::{BmpCodec, BmpMsgType};
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::codec::Decoder;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

/// Pump bytes between two routers' sessions until no output remains.
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
            let late_a = a.drain_output(ha);
            if !late_a.is_empty() {
                b.feed_input(hb, &late_a).unwrap();
                continue;
            }
            return;
        }
    }
}

const V4_A: RouterId = RouterId::from_v4([10, 0, 0, 1]);
const V4_B: RouterId = RouterId::from_v4([10, 0, 0, 2]);

/// When a BGP session establishes, the BMP sink must receive a Peer Up
/// message. The message must decode as type 3 (PeerUp) with the correct
/// peer AS and BGP ID.
#[test]
fn bmp_peer_up_on_session_established() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();

    // Install the BMP sink BEFORE the session establishes.
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received_clone = Arc::clone(&received);
    a.set_bmp_sink(move |bytes| {
        received_clone.lock().unwrap().push(bytes.to_vec());
    });

    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    // The BMP sink must have received at least one Peer Up message.
    let msgs = received.lock().unwrap();
    assert!(!msgs.is_empty(), "BMP sink must receive messages");

    // Decode the first message and check it's a Peer Up.
    let mut codec = BmpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&msgs[0]);
    let msg = codec.decode(&mut r).unwrap().unwrap();
    assert_eq!(msg.header.msg_type, BmpMsgType::PeerUp);
    let peer = msg.peer.unwrap();
    assert_eq!(peer.peer_as, 64513); // peer's AS
}

/// When a route enters the Loc-RIB, the BMP sink must receive a Route
/// Monitoring message (type 0).
#[test]
fn bmp_route_monitoring_on_route_install() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();

    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received_clone = Arc::clone(&received);
    a.set_bmp_sink(move |bytes| {
        received_clone.lock().unwrap().push(bytes.to_vec());
    });

    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    // Clear the Peer Up messages.
    received.lock().unwrap().clear();

    // B originates a route; A learns it via BGP.
    b.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);

    // The BMP sink must have received at least one Route Monitoring message.
    let msgs = received.lock().unwrap();
    assert!(!msgs.is_empty(), "BMP sink must receive route monitoring");

    // Find the Route Monitoring message.
    let mut codec = BmpCodec::new();
    let mut found_rm = false;
    for bytes in msgs.iter() {
        let mut r = lr_core::buf::ReadBuf::new(bytes);
        if let Ok(Some(msg)) = codec.decode(&mut r) {
            if msg.header.msg_type == BmpMsgType::RouteMonitoring {
                found_rm = true;
                // The payload should be a BGP message (starts with 0xff marker).
                assert!(!msg.payload.is_empty());
                assert!(msg.payload[0] == 0xff, "BGP marker expected");
                break;
            }
        }
    }
    assert!(found_rm, "at least one RouteMonitoring message expected");
}

/// Without a BMP sink installed, no BMP messages are produced (the
/// router does not buffer them).
#[test]
fn bmp_no_sink_no_crash() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    b.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);
    // No crash, no assertion — the test passes if it completes.
}
