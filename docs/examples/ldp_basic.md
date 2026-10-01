# LDP label distribution

LDP is how MPLS label switched routers (LSRs) tell each other which label
to push for which forwarding equivalence class (FEC). This page configures
`lr-daemon --protocol ldp` for two directly connected LSRs, then shows
the library calls an embedder makes to run the same engine by hand.

## Topology

```text
   LSR A  eth0 ────────────────────────────── eth0  LSR B
   transport 10.0.0.1                         transport 10.0.0.2
   binds 203.0.113.0/24 label 24000
```

A and B discover each other with UDP Hellos on port 646
(`224.0.0.2` for link discovery, unicast for targeted discovery),
establish a TCP session on the same port, and exchange label bindings.

## Configuration

```lr
protocol ldp;

ldp {
    transport "10.0.0.1";        # advertised transport address
    keepalive_time 15s;          # session KeepAlive Time (RFC 5036 3.5.3)
    link_hold_time 15s;          # link Hello hold time (3.5.2.1)
    install_kernel true;         # mirror the LIB into the kernel MPLS table
    label_min 16;                # automatic allocation range
    label_max 1048575;

    interface "eth0" { }         # link discovery on this interface

    targeted "10.0.0.2" { }      # extended discovery; unicast Hellos

    bind "203.0.113.0/24" {      # local FEC-to-label binding,
        label 24000;             # downstream unsolicited to every peer
    }
}
```

`label 0` in a `bind` block makes the engine allocate from
`label_min..=label_max` instead. The same configuration on the command
line, which also takes `--ldp-bind PFX[=LABEL]`:

```sh
lr-daemon --protocol ldp --router-id 10.0.0.1 \
    --ldp-transport 10.0.0.1 --ldp-interface eth0 \
    --ldp-targeted 10.0.0.2 --ldp-bind 203.0.113.0/24=24000 \
    --install-kernel-routes
```

Port 646 is privileged: run as root, or inside `unshare -Urn` with the
namespace's own interfaces.

## What the daemon does

1. Logs `daemon: ldp binding 203.0.113.0/24 label 24000` for each
   configured binding.
2. Discovers the peer and reports
   `ldp: session up peer ... keepalive 15s max-pdu ...` once the
   Initialization and KeepAlive exchange completes (RFC 5036 §2.5.4).
3. Logs `ldp: mapping learned <prefix> label <label> from <peer>` and
   installs the head of the LSP, an encap route pushing that label
   toward the peer.
4. Installs the tail of each locally bound prefix as an in-label pop to
   local delivery, logged as
   `ldp: in-label <label> -> pop (local delivery) for <prefix>`.

With `install_kernel true` the daemon connects to the kernel MPLS table
at startup and logs
`daemon: mpls route table connected — installing LDP LSPs`.

## Verify

```sh
# Head: traffic to the learned prefix enters the LSP.
ip route show 203.0.113.0/24

# Tail: the locally bound prefix pops to local delivery.
sudo ip -f mpls route show
```

The head entry reads `203.0.113.0/24 encap mpls 24000 via inet
10.0.0.2` when the peer advertised label `24000`; the daemon logs the
same as `ldp: 203.0.113.0/24 encap mpls [24000] via 10.0.0.2`. The tail
entry is an in-label route with no `via`. A missing kernel MPLS module
leaves the daemon running with the LIB populated and the install logging
`failed` per prefix.

## Running the engine yourself

`LdpEngine` is I/O free: the embedder owns the UDP and TCP sockets and
feeds bytes in. This is the same shape `daemon_ldp.rs` uses:

```rust
// Cargo.toml:
// [dependencies]
// lr-ldp = "<version>"
// lr-core = "<version>"

use lr_core::addr::{IpAddr, Prefix};
use lr_core::time::Instant;
use lr_ldp::{EngineEvent, GenericLabel, LdpEngine, LdpEngineConfig, LdpId};

fn engine(id: [u8; 4], transport: IpAddr, peer: IpAddr) -> LdpEngine {
    let mut cfg = LdpEngineConfig::new(LdpId::new(id, 0), transport);
    cfg.targeted_peers = vec![peer];
    cfg.keepalive_time = 15;
    LdpEngine::new(cfg)
}

fn main() {
    let mut a = engine([10, 0, 0, 1], IpAddr::V4([10, 0, 0, 1]), IpAddr::V4([10, 0, 0, 2]));

    // Drive time, ship outbound bytes, feed inbound bytes with their
    // source address, then react to the engine's events.
    a.tick(Instant::from_millis(0));
    for (_dest, _bytes) in a.drain_udp() {
        // send to _dest on UDP 646
    }
    for event in a.take_events() {
        if let EngineEvent::EstablishTransport { peer_id, transport_addr } = event {
            // TcpStream::connect(transport_addr:646), then
            // a.on_connected(now, conn, peer_id)
            let _ = (peer_id, transport_addr);
        }
    }

    // Advertise a local FEC-to-label binding.
    let fec = Prefix::new_v4([203, 0, 113, 0], 24);
    a.advertise_mapping(fec, GenericLabel(24000));
    assert!(a.lib().advertised_label(&lr_ldp::mapping::FecKey::new(fec)).is_some());

    // Withdraw it: the label is released and a Label Withdraw goes out.
    a.withdraw_mapping(fec);
    assert!(a.lib().advertised_bindings().next().is_none());
}
```

Bindings learned from a peer are enumerated with
`LdpEngine::lib().bindings_from(peer_id)`, which yields
`(&FecKey, &GenericLabel)` pairs. The engine allocates a transit label
for a learned FEC only when `LdpEngineConfig::transit_allocation` is on;
the swap then arrives as `EngineEvent::TransitSwapChanged`.

## Reference

- RFC 5036 — LDP Specification
- RFC 7552 — LDP over IPv6 (dual-stack discovery and transport)
- [`bgp_labeled_unicast.md`](bgp_labeled_unicast.md) — the same MPLS
  dataplane with BGP-LU signalling
