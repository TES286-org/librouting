//! BGP + BFD integration — scaffolding template.
//!
//! See docs/examples/bfd_integration.md for the full walkthrough.

use lr_bfd::{BfdConfig, BfdSession, SessionRole};
use lr_bgp::{BgpPeer, BgpEvent, PeerConfig};
use lr_core::addr::{Asn, RouterId};
use lr_core::time::Instant;

fn main() {
    // 1. Start BGP
    let mut bgp = BgpPeer::new(PeerConfig::new(
        Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]),
    ));
    bgp.step(BgpEvent::ManualStart);
    bgp.step(BgpEvent::TransportOpen);

    // 2. Two BFD sessions wired together (in-process demo of the
    //    RFC 5880 handshake; a real deployment drives them from UDP
    //    sockets on port 3784 — see lr_osroute::bfd_transport and the
    //    daemon's --bfd wiring).
    let cfg = BfdConfig {
        detect_mult: 3,
        desired_min_tx_interval: 100_000,
        required_min_rx_interval: 100_000,
        role: SessionRole::Active,
        ..Default::default()
    };
    let mut a = BfdSession::new(cfg.clone(), 0x11111111);
    let mut b = BfdSession::new(cfg, 0x22222222);
    let _ = a.start(Instant(0));
    let _ = b.start(Instant(0));

    let mut t = 0u64;
    for _ in 0..20 {
        // Exchange whatever the sessions want to send ...
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

    println!("BGP+BFD scaffold: BFD session A = {}, B = {}", a.state(), b.state());
    // 3. Feed BFD liveness into your session management: when the BFD
    //    session goes Down, tear the BGP transport down immediately
    //    instead of waiting out the hold timer (what `lr-daemon --bfd`
    //    does; see docs/examples/bfd_integration.md).
    if a.is_up() {
        println!("BGP established: {}", bgp.is_established());
    }
}
