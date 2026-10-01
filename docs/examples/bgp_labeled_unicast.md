# BGP labelled unicast into the Linux MPLS table

This page configures two `lr-daemon` instances to exchange RFC 8277
labelled routes and install them in the Linux forwarding table, and shows
how to confirm the label switched path (LSP) is in place. Read it if you
are bringing up SR-MPLS without LDP.

## Topology

```text
ingress LSR                        egress LSR
192.0.2.1                          192.0.2.2
    |                                  |
    |  BGP-LU: 198.51.100.0/24, label 100
    |<---------------------------------|
    |
    |  AF_MPLS: push 100 toward 192.0.2.2
```

The ingress originates nothing; it learns the labelled prefix and
installs an encap route. The egress originates the prefix with the label
from `labeled_networks` and installs an in-label pop route. BGP-LU
distributes the label; the kernel does the forwarding.

## Configuration

Ingress, `ingress.lr`:

```lr
protocol bgp;

bgp {
    local_as 64512;
    peer_as 64513;
    router_id "10.0.0.1";
    peer_addr "192.0.2.2:179";
    local_address "192.0.2.1";

    mp_families ["ipv4-unicast", "ipv4-labeled-unicast"];
    install_kernel true;
}
```

Egress, `egress.lr`. `labeled_networks` entries are
`"<prefix> <labels>"`, top of stack first:

```lr
protocol bgp;

bgp {
    local_as 64513;
    peer_as 64512;
    router_id "10.0.0.2";
    peer_addr "192.0.2.1:179";
    local_address "192.0.2.2";

    mp_families ["ipv4-unicast", "ipv4-labeled-unicast"];
    labeled_networks ["198.51.100.0/24 100"];
    install_kernel true;
}
```

Both sides need `ipv4-labeled-unicast` in `mp_families`: that value is
the RFC 8277 NLRI family, and without it the labelled routes are neither
advertised nor accepted. `install_kernel true` is the same switch as
`--install-kernel-routes`.

## Run

```sh
sudo modprobe mpls_router
sudo modprobe mpls_iptunnel
sudo sysctl -w net.mpls.platform_labels=1000

sudo lr-daemon --config egress.lr    # originate the prefix first
sudo lr-daemon --config ingress.lr
```

## What the daemon does

1. The egress originates `198.51.100.0/24` with label `100` and logs
   `daemon: originating labelled 198.51.100.0/24`.
2. The egress classifies its own best route as the LSP tail and installs
   an in-label pop route to `lo` (`MplsRoute::pop_local`).
3. The ingress receives the labelled NLRI, stores the label stack under
   the private `LrMplsLabelStack` attribute, and installs an encap route
   that pushes `100` toward `192.0.2.2`
   (`MplsNetlink::add_encap_route`).

A label stack whose top label is implicit-null (3, RFC 3032 §2.1) means
penultimate-hop popping: the tail originates it instead of a real label,
and the ingress forwards unlabelled.

## Verify

```sh
lrctl --socket /run/lr-daemon.api routes show 198.51.100.0/24

# Ingress: reachable only by pushing the label.
ip route show 198.51.100.0/24

# Egress: the in-label pops to local delivery.
sudo ip -f mpls route show
```

The ingress entry reads `198.51.100.0/24 encap mpls 100 via inet
192.0.2.2`. The egress MPLS table holds in-label `100` with no `via`,
which is the pop-to-local shape. If the kernel has no MPLS support, the
daemon logs `daemon: mpls route table unavailable (...); LSP install
disabled` and continues with plain IP forwarding.

## Reading the label stack from the library

An embedder that owns its own forwarding plane reads the stack off the
Loc-RIB route. `lr_core::rib::Route` is a plain struct, so the attribute
is built with `Attribute { tag, flags, value }`:

```rust
use lr_bgp::path::AttrType;
use lr_core::attr::{AttrTag, Attribute};
use lr_core::rib::Route;
use lr_mpls::{Label, LabelStack};

/// Attach an RFC 8277 label stack the way the router pipeline does.
fn set_label_stack(route: &mut Route, stack: &LabelStack) {
    route.attributes.insert(Attribute {
        tag: AttrTag(AttrType::LrMplsLabelStack.to_u8()),
        flags: 0x20, // optional
        value: stack.encode_4octet(),
    });
}

/// The top label an ingress must push; `None` for an unlabelled route.
fn top_label(route: &Route) -> Option<Label> {
    let tag = AttrTag(AttrType::LrMplsLabelStack.to_u8());
    let attr = route.attributes.get(tag)?;
    LabelStack::decode_4octet(&attr.value).ok()?.labels().first().copied()
}
```

## Reference

- RFC 8277 — Using BGP to Bind MPLS Labels to Address Prefixes
- RFC 3032 §2.1 — reserved label values
- [`ldp_basic.md`](ldp_basic.md) — the same dataplane with LDP signalling
- [`../INTEROP.md`](../INTEROP.md) — running the labelled-unicast lab
