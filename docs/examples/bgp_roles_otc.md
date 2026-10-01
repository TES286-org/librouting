# BGP roles and the OTC attribute

RFC 9234 puts the business relationship on the wire. The OPEN carries
the role capability, and egress stamps customer-bound routes with the
Only-to-the-Customer (OTC) attribute so a downstream provider can reject
a route leak without trusting the sender's AS_PATH. This page shows the
`otc_role` field an embedder sets and the helpers the library exposes.

## Topology

```text
    provider AS65000  <-- eBGP -->  customer AS64512  <-- eBGP -->  provider AS65001
    role: Provider                  role: Customer                  role: Provider
```

The role is configured **relative to the peer**: a customer sets
`Customer` on the sessions facing its providers.

## Wiring

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "<version>"
// lr-core = "<version>"

use lr_bgp::role::otc::{otc_can_advertise, otc_on_receive, Otc};
use lr_bgp::role::OtcRole;
use lr_core::addr::Asn;

fn main() {
    // Facing a provider: we are the customer. A route arriving with no
    // OTC is tagged with the provider's AS (RFC 9234 §5, rule 3).
    let role = OtcRole::Customer;
    assert!(otc_on_receive(None, role, Asn(65001)).is_ok());

    // Facing our customer: we are the provider. A route that already
    // carries OTC came from the customer and is a leak (§5, rule 1).
    let provider = OtcRole::Provider;
    assert!(otc_on_receive(Some(Otc(65001)), provider, Asn(64512)).is_err());

    // Egress (§5, rule 2): a route carrying OTC never goes to a
    // provider, a peer or a route server; it may go to a customer.
    assert!(!otc_can_advertise(Otc(64512), OtcRole::Customer));
    assert!(otc_can_advertise(Otc(64512), OtcRole::Provider));
}
```

Set the role on the peer config; `OtcRole::Unset` (the default) leaves
the session inert:

```rust
cfg.otc_role = OtcRole::Customer;
```

## What is enforced where

| Direction | Entry point | Status |
| --------- | ----------- | ------ |
| Egress | `otc_can_advertise`, called from `BgpPeer::advertise` | enforced |
| Ingress | `otc_on_receive` | helper only; call it from an import hook |
| OPEN | the role capability | negotiated; `Unset` is inert |

`BgpPeer::advertise` consults the egress rule before it encodes the
UPDATE, so an OTC route is silently withheld from providers and peers.
The ingress rules are a pure helper: the FSM does not call
`otc_on_receive` today, so an embedder that wants the §5 checks must run
them from an `ImportHook`.

## Check

The §5 rules are pure functions, so test them directly — that is also
the cheapest way to confirm which topological role a session took:

```rust
use lr_bgp::role::otc::{otc_can_advertise, Otc};
use lr_bgp::role::OtcRole;

assert!(!otc_can_advertise(Otc(64512), OtcRole::Peer));
assert!(otc_can_advertise(Otc(0), OtcRole::Peer));
```

`Otc(0)` means "no OTC set" and is always advertisable.

## Reference

- RFC 9234 — BGP OPEN Policy Roles and the Only-to-Customer attribute
- [`bgp_route_server.md`](bgp_route_server.md) — the `RouteServer` and
  `RsClient` roles
