# Example: BGP Labelled Unicast (RFC 8277) → MPLS dataplane

BGP-LU carries MPLS labels inside BGP UPDATEs: the NLRI is
`(prefix, label)` and the next-hop is the egress LSR's address. This
is the simplest SR-MPLS dataplane — no LDP, no LSR-by-LSR signalling,
the labels are pushed onto the stack at the ingress and popped at the
egress (or at the penultimate hop when the implicit-null label is
used).

The reference daemon runs this end-to-end on Linux:

- `lr-daemon --network 203.0.113.0/24 --peer ...` with locally
  originated prefixes implicitly advertises them as BGP-LU when the
  peer's MP-BGP family includes labelled-unicast.
- `--install-kernel-routes` mirrors the Loc-RIB into both the plain
  IP FIB and the `AF_MPLS` netlink table. Locally originated labelled
  routes install an in-label pop route (LSP tail); peer-advertised
  routes install an encap route pushing the label stack toward the BGP
  next hop (LSP head).

This example shows the library-level pieces an embedder composes; the
byte-pump pattern mirrors the [LDP example](ldp_basic.md).

## The dataplane model

```text
ingress LSR                       transit LSR(s)                    egress LSR
─────────────                     ─────────────                    ───────────
IP packet   ───►  push label  ───►  swap label  ───►  pop label  ───►  IP packet
                  (encap)            (swap)            (local)
                  AF_MPLS            AF_MPLS            AF_MPLS
                  push 100           swap 100→200       pop 200 → lo
```

In the simplest one-hop case there is no transit: the ingress pushes
the label and the egress pops it. BGP-LU's role is to *distribute*
the labels: the egress advertises `(prefix, label=200)` to the
ingress, and the ingress installs `push 200 → next-hop` in its
AF_MPLS table.

## The label-stack attribute

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "1.0.0-rc.4"
// lr-mpls = "1.0.0-rc.4"
// lr-core = "1.0.0-rc.4"

use lr_bgp::path::AttrType;
use lr_core::attr::{Attr, AttrTag};
use lr_core::rib::Route;
use lr_mpls::{Label, LabelStack};

/// The private path-attribute tag the router attaches to BGP-LU
/// routes (both originated and received). The kernel-mirror slice
/// reads this attribute to classify the route (pop local / push /
/// plain IP fallback).
const LR_MPLS_LABEL_STACK_TAG: u8 = AttrType::LrMplsLabelStack as u8;

/// Build a labelled route originated by this router: the LSP tail.
/// `label` is the value remote peers use to reach the prefix; peers
/// push this label to enter the LSP. PHP-style tails originate
/// `Label::IMPLICIT_NULL` (3) instead, which means "do not push,
/// forward unlabeled to me" (RFC 3032 §2.1).
fn originate_labelled_route(
    prefix: lr_core::addr::Prefix,
    next_hop: lr_core::addr::IpAddr,
    label: Label,
) -> Route {
    let mut route = Route::new(prefix, next_hop);
    let stack = LabelStack::new(vec![label]);
    route.attributes.insert(
        AttrTag(LR_MPLS_LABEL_STACK_TAG),
        Attr::new(LR_MPLS_LABEL_STACK_TAG, stack.encode_4octet()),
    );
    route
}

/// Inspect a received route's label stack (the LSP head case).
/// Returns `None` for unlabelled routes; the first label is the
/// one the ingress must push.
fn received_label(route: &Route) -> Option<Label> {
    let attr = route
        .attributes
        .get(AttrTag(LR_MPLS_LABEL_STACK_TAG))?;
    let stack = LabelStack::decode_4octet(&attr.value).ok()?;
    stack.labels().first().copied()
}

fn main() {
    // LSP tail: this router owns 203.0.113.0/24 and is reachable via
    // label 100. Peers push 100 to reach this prefix.
    let tail_route = originate_labelled_route(
        lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
        lr_core::addr::IpAddr::V4([192, 0, 2, 1]),
        Label::new_value(100),
    );
    assert_eq!(
        received_label(&tail_route),
        Some(Label::new_value(100))
    );

    // PHP case: this router is the penultimate hop. Peers do NOT push
    // a label; the egress pops and forwards unlabeled.
    let php_route = originate_labelled_route(
        lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
        lr_core::addr::IpAddr::V4([192, 0, 2, 1]),
        Label::IMPLICIT_NULL,
    );
    // The kernel mirror recognizes implicit-null as "do not push"
    // (LspDecision::Plain), so plain IP forwarding applies.
    assert_eq!(php_route.attributes.get(AttrTag(LR_MPLS_LABEL_STACK_TAG))
        .map(|a| LabelStack::decode_4octet(&a.value).unwrap().labels()[0].value),
        Some(Label::IMPLICIT_NULL.value));
}
```

## The kernel mirror (Linux)

The daemon's `KernelMirror` (in `crates/lr-cli/src/daemon.rs`) classifies
each best route and installs the corresponding AF_MPLS entry:

| Classification                  | Install action                                      |
| ------------------------------- | --------------------------------------------------- |
| `LspDecision::PopLocal(label)` | `MplsRoute::pop_local(label, lo_if_index=1)` — in-label → lo, local delivery. The LSP tail. |
| `LspDecision::Push(stack)`      | `MplsNetlink::add_encap_route(prefix, stack, next_hop, 0)` — push the label stack toward the BGP next hop. The LSP head. |
| `LspDecision::Plain`            | Plain IP route via `OsRouteTable::add_route` (unlabelled, or PHP / no-label case). |

```text
ingress LSR                                egress LSR (owns 203.0.113.0/24)
──────────────                             ─────────────────────────────────
BGP-LU UPDATE arrives:                     Loc-RIB entry:
  prefix 203.0.113.0/24                      prefix 203.0.113.0/24
  label  100                                 label  100
  next-hop 192.0.2.1                         (locally originated)
                                            ↓
Loc-RIB entry:                              KernelMirror:
  prefix 203.0.113.0/24                       MplsRoute::pop_local(100, 1)
  label  100                                 → AF_MPLS in-label 100 → dev lo
  next-hop 192.0.2.1
  ↓
KernelMirror:
  MplsNetlink::add_encap_route(
    203.0.113.0/24, [100], 192.0.2.1, 0)
  → encap route pushes label 100 toward 192.0.2.1
```

## CLI flags

```bash
# Ingress (head of LSP): originate the prefix and install the encap.
lr-daemon --local-as 64512 --peer-as 64513 \
    --router-id 10.0.0.1 --peer 192.0.2.2:179 \
    --local-address 192.0.2.1 \
    --network 203.0.113.0/24 \
    --install-kernel-routes

# Egress (tail of LSP): learn the prefix and install the pop route.
# The label the egress advertised is the one the ingress pushes.
lr-daemon --local-as 64513 --peer-as 64512 \
    --router-id 10.0.0.2 --peer 192.0.2.1:179 \
    --local-address 192.0.2.2 \
    --network 198.51.100.0/24 \
    --install-kernel-routes
```

The interop lab `tests/interop/labeled_unicast.sh` exercises the
full lifecycle (negotiate, advertise, install, forward, withdraw)
between two `lr-daemon` instances, and `tests/interop/mpls_lsp.sh`
extends it through a real Linux kernel MPLS dataplane. See
[`docs/INTEROP.md`](../INTEROP.md) for the local reproduction steps.

## Dataplane requirements

The Linux kernel needs the MPLS modules loaded:

```sh
sudo modprobe mpls_router
sudo modprobe mpls_iptunnel
sudo sysctl -w net.mpls.platform_labels=1000
# Per-interface input is enabled by the interop scripts.
```

Without these the daemon prints `mpls route table unavailable; LSP
install disabled` and falls back to plain IP forwarding only
(reachability first, labels second — BIRD behaves the same way).
