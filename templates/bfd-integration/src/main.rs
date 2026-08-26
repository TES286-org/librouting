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

    // 2. Start BFD
    let cfg = BfdConfig {
        detect_mult: 3,
        desired_min_tx_interval: 50_000,
        required_min_rx_interval: 50_000,
        role: SessionRole::Active,
        ..Default::default()
    };
    let mut bfd = BfdSession::new(cfg, 0x11111111);
    let _evs = bfd.start(Instant(0));

    println!("BGP+BFD scaffold ready. Drain bytes:");
    println!("  bgp: {} bytes", bgp.drain_outgoing().len());
    println!("  bfd: {} bytes", bfd.drain_outgoing().len());
    println!();
    println!("Wire the two together per docs/examples/bfd_integration.md.");
}
