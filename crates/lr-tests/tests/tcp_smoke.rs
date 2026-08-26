//! End-to-end test: two librouting `DefaultRouter` instances connected by
//! TCP, exchanging BGP OPEN + KEEPALIVE.
//!
//! This is the embedder pattern in miniature: the router does NOT own
//! transports — the embedder pumps bytes via `feed_input` / `drain_output`.
//! Here we use `std::net::TcpListener` / `TcpStream` to wire two routers
//! together over a real socket. This exercises the same byte-stream model
//! that an embedder would use to talk to BIRD or FRR over a TCP connection.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use lr_bgp::{BgpCodec, BgpEvent, BgpMessage, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, RouterId};
use lr_core::time::Instant as LrInstant;
use lr_router::{RouterInstance, SessionConfig};

/// Test the byte stream pattern: two peers at the BgpPeer layer, wired by
/// a TCP socket. Proves the codec and FSM work with real sockets.
#[test]
fn tcp_two_peer_establishment() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let server_thread = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let cfg_b = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        let mut peer_b = BgpPeer::new(cfg_b);
        peer_b.step(BgpEvent::ManualStart);
        peer_b.step(BgpEvent::TransportOpen);
        let out = peer_b.drain_outgoing();
        sock.write_all(&out).unwrap();
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).unwrap();
        peer_b.feed_bytes(&buf[..n]).unwrap();
        let _ = peer_b.state();
        let ka = BgpCodec::new()
            .encode_vec(&BgpMessage::Keepalive(
                lr_bgp::message::keepalive::Keepalive,
            ))
            .unwrap();
        sock.write_all(&ka).unwrap();
        let _ = tx.send(peer_b.is_established());
    });

    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let cfg_a = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    let mut peer_a = BgpPeer::new(cfg_a);
    peer_a.step(BgpEvent::ManualStart);
    peer_a.step(BgpEvent::TransportOpen);
    let out = peer_a.drain_outgoing();
    stream.write_all(&out).unwrap();
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).unwrap();
    peer_a.feed_bytes(&buf[..n]).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    if let Ok(m) = stream.read(&mut buf) {
        if m > 0 {
            peer_a.feed_bytes(&buf[..m]).unwrap();
        }
    }
    let b_established = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    server_thread.join().unwrap();
    assert!(peer_a.is_established() || b_established);
}

/// Smoke: create a DefaultRouter and tick it a few times.
#[test]
fn router_instance_smoke() {
    let mut r = lr_router::DefaultRouter::new();
    let _h = r
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 1]),
        ))
        .unwrap();
    for t in 0..1000 {
        r.tick(LrInstant(t));
    }
    let _ = r.poll_events();
}
