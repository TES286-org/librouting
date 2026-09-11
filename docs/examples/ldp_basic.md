# Example: LDP label distribution (RFC 5036)

LDP is the signaling protocol MPLS LSRs use to distribute FEC-to-label
bindings. Two LSRs discover each other with UDP Hellos on port 646
(`ff02::1:6` v6 / `224.0.0.106` v4 for link discovery; targeted Hellos
are unicast), establish a TCP session on port 646, negotiate session
parameters with the Initialization message, and then exchange Address
and Label Mapping messages.

The reference daemon wires this end-to-end (`lr-daemon --protocol ldp`),
including the kernel MPLS dataplane mirror on Linux
(`--install-kernel-routes`). This example shows the library-level pieces
an embedder composes; the byte-pump pattern mirrors the
[BFD example](bfd_integration.md) and the daemon's own `daemon_ldp.rs`.

## Architecture

```text
         ┌─────────────────┐
         │  LdpEngine      │  ← stateful: sessions, adjacencies, LIB
         │  (lr-ldp)       │
         └────────┬────────┘
                  │ feed_udp / feed_tcp / tick / on_accepted / on_connected
                  │ drain_udp / drain_tcp_all / take_events
                  ▼
         ┌─────────────────┐
         │ embedder        │  ← owns the UDP + TCP sockets, the time
         │ (this example)  │    source and the FEC→label bookkeeping
         └─────────────────┘
```

The engine is I/O-free: it consumes bytes and connection events,
produces outbound bytes and connection requests, and reports
state transitions through `EngineEvent`s. The embedder only moves
bytes between the engine and the network.

## A complete LSP-establishment cycle

This is the same shape the daemon's `daemon_ldp.rs` runs against
real FRR `ldpd` in `tests/interop/ldp_frr.sh`.

```rust
// Cargo.toml:
// [dependencies]
// lr-ldp = "0.1"
// lr-core = "0.1"

use lr_core::addr::IpAddr;
use lr_core::time::Instant;
use lr_ldp::{
    engine::{EngineEvent, LdpEngine, LdpEngineConfig},
    Fec, FecElement, GenericLabel, LdpId,
};

// Two LSRs on loopback. (The reference daemon supports dual-stack
// and RFC 7552 transport-address selection; this example uses IPv4
// for brevity.)
const A_ID: [u8; 4] = [1, 1, 1, 1];
const B_ID: [u8; 4] = [2, 2, 2, 2];
const A_ADDR: IpAddr = IpAddr::V4([127, 0, 0, 1]);
const B_ADDR: IpAddr = IpAddr::V4([127, 0, 0, 2]);

fn build_engine(id: [u8; 4], addr: IpAddr, peer: IpAddr) -> LdpEngine {
    let mut cfg = LdpEngineConfig::new(LdpId::new(id, 0), addr);
    cfg.targeted_peers = vec![peer];
    cfg.accept_targeted = true;
    cfg.keepalive_time = 2;          // short for test pacing (RFC §3.5.3)
    cfg.targeted_hello_hold = 9;     // hello every hold/3 = 3s
    cfg.interface_addresses = vec![IpAddr::V4([10, 99, 1, 1])];
    LdpEngine::new(cfg)
}

fn main() {
    let mut a = build_engine(A_ID, A_ADDR, B_ADDR);
    let mut b = build_engine(B_ID, B_ADDR, A_ADDR);

    // The embedder pumps both engines. The pump function is identical
    // to the daemon's: drain outbound UDP/TCP, deliver inbound bytes,
    // drive tick(now) so hello refreshes and KeepAlive timers fire,
    // and dispatch EngineEvents to open/accept TCP connections.
    //
    // In production the pump runs in a dedicated thread; here we just
    // loop in main for the example.

    let peer_a = LdpId::new(A_ID, 0);
    let peer_b = LdpId::new(B_ID, 0);

    // Phase 1: discovery + session establishment. The engine emits
    // SessionUp once the Initialization / KeepAlive exchange completes
    // (RFC 5036 §2.5.4). The active side is the LSR with the higher
    // transport address (§2.5.2) — here B (127.0.0.2 > 127.0.0.1),
    // so B dials A.
    loop {
        let now = Instant::from_millis(/* logical clock */ 0);
        let ev_a = pump(&mut a, now, /* peer's udp/tcp port */ 0, 0);
        let ev_b = pump(&mut b, now, 0, 0);
        let up = |evs: &[EngineEvent], peer: LdpId| evs.iter().any(
            |e| matches!(e, EngineEvent::SessionUp { peer_id, .. } if *peer_id == peer)
        );
        if up(&ev_a, peer_b) && up(&ev_b, peer_a) {
            break;
        }
        // sleep 20ms between pump rounds
    }

    // Phase 2: advertise a FEC binding. A is the egress LSR for
    // 10.10.0.0/24, allocates label 100, and advertises it to B.
    // The engine builds the Label Mapping message (§3.4.1 FEC TLV +
    // §3.4.2.1 Generic Label TLV), the embedder ships the bytes.
    a.advertise_mapping(
        Fec::new(vec![FecElement::Prefix(lr_core::addr::Prefix::new_v4([10, 10, 0, 0], 24))]),
        GenericLabel(100),
    );

    loop {
        let now = Instant::from_millis(0);
        let ev_b = pump(&mut b, now, 0, 0);
        // B learned the mapping (DU, independent control).
        if ev_b.iter().any(|e| matches!(
            e,
            EngineEvent::MappingLearned {
                peer_id,
                label: GenericLabel(100),
                ..
            } if *peer_id == peer_a
        )) {
            break;
        }
    }

    // B's LIB now holds: 10.10.0.0/24 → label 100 via A.
    // B allocates its own label (say 200) for the same FEC and
    // advertises it back to A (DU mode: every LSR advertises to every
    // peer). The engine's `transit_allocation` flag (set in the daemon)
    // makes B a transit LSR: it re-advertises A's binding upstream,
    // swapping the label.
    let bindings = b.engine().lib().bindings_from(peer_a);
    assert!(bindings.any(|b| b.label().0 == 100));

    // Phase 3: withdrawal. A withdraws the binding (e.g. the prefix
    // went away). B must release the label.
    a.withdraw_mapping(Fec::new(vec![FecElement::Prefix(
        lr_core::addr::Prefix::new_v4([10, 10, 0, 0], 24),
    )]));
    // Pump again; B's LIB clears the entry.
}

/// One pump round: tick the engine, drain its outbound UDP and TCP,
/// deliver inbound bytes. The real daemon's `daemon_ldp.rs` has the
/// production version with real sockets; this stub shows the shape.
fn pump(
    engine: &mut LdpEngine,
    now: Instant,
    _peer_udp_port: u16,
    _peer_tcp_port: u16,
) -> Vec<EngineEvent> {
    engine.tick(now);
    // 1. Drain outbound UDP (Hellos). For each (dest, bytes), send
    //    them via the embedder's UDP socket to (dest, 646).
    for (_dest, _bytes) in engine.drain_udp() {
        // self.udp.send_to(&bytes, (dest, 646)).ok();
    }
    // 2. Drain outbound TCP bytes per connection, write to the
    //    matching TcpStream.
    for (_conn, _bytes) in engine.drain_tcp_all() {
        // self.conns.get_mut(&conn).unwrap().write_all(&bytes).ok();
    }
    // 3. Inbound UDP: feed each datagram with its source address.
    //    while let Ok((n, _from)) = self.udp.recv_from(&mut buf) {
    //        engine.feed_udp(now, src_addr, &buf[..n]);
    //    }
    // 4. Inbound TCP: feed each connection's bytes.
    //    for (id, stream) in &self.conns {
    //        let n = stream.read(&mut buf).unwrap_or(0);
    //        engine.feed_tcp(now, *id, &buf[..n]);
    //    }
    // 5. EngineEvents: open/accept TCP connections as directed.
    //    for ev in engine.take_events() { ... }
    engine.take_events()
}
```

## What the daemon adds on top

The reference `lr-daemon --protocol ldp`:

1. **Wires the sockets** — UDP discovery (link + targeted) and TCP
   session, both on port 646. The daemon owns one UDP receive socket
   per interface for link Hellos and one for targeted Hellos.
2. **Drives the active/passive decision** — the engine's
   `EngineEvent::EstablishTransport` tells the daemon which peer to
   dial (the one with the lower transport address, per §2.5.2). The
   daemon's `daemon_ldp.rs` does the `TcpStream::connect`.
3. **Installs the dataplane** — on Linux, the daemon mirrors the
   learned LIB into the kernel MPLS LSP table via
   `lr_osroute::mpls_route::MplsNetlink`. A locally originated
   binding installs an AF_MPLS pop route (LSP tail); a learned
   binding installs an encap route pushing the label toward the
   peer (LSP head). See
   [`docs/examples/os_integration.md`](os_integration.md) for the
   `OsRouteTable` shape.
4. **Dual-stack transport (RFC 7552)** — the daemon's
   `LdpEngineConfig::transport_addr_v6` carries the IPv6 transport
   address; the engine advertises both v4 and v6 in the Hello's
   IPv4 Transport Address / IPv6 Transport Address TLVs and picks
   the family per the §6.1.1 preference rules. The interop suite
   exercises this in `tests/interop/ldp_frr_v6.sh`.

## CLI flags

```bash
lr-daemon --protocol ldp \
    --router-id 10.0.0.1 \
    --ldp-transport 10.0.0.1 \
    --ldp-interface eth0 \
    --ldp-targeted 192.0.2.2 \
    --ldp-bind 10.10.0.0/24=100 \
    --install-kernel-routes
```

See [`docs/lr-cli.md`](../lr-cli.md) for the full `--ldp-*` flag
reference and `templates/daemon.toml` for the TOML schema. The
interop lab `tests/interop/ldp_frr.sh` runs the full lifecycle
(discovery → session → binding → dataplane) against FRR `ldpd`.
