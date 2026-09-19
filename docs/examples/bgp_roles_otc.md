# Example: BGP roles and the OTC attribute (RFC 9234)

Roles put the business relationship on the wire. Each eBGP speaker
configures its role *relative to the peer*; the OPEN carries the
capability, and the egress path stamps customer-bound routes with the
Only-to-the-Customer (OTC) attribute so downstream providers can
mechanically reject leaks (the defect `docs/research/BGP-DEFECTS.md`
§3 documents).

```
   provider AS65000          customer AS64512          provider AS65001
        |                          |                          |
        +--------- eBGP -----------+--------- eBGP -----------+
        role = Provider            role = Customer            role = Provider
```

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "1.0.0-rc.4"

use lr_bgp::role::OtcRole;

fn main() {
    // The customer side: routes received from the providers carry OTC,
    // and every route the customer re-advertises to its own providers
    // is stamped with OTC on egress.
    let customer_role = OtcRole::Customer;

    // The provider side (facing the customer): a route that arrives
    // already carrying OTC is a leak — reject it before Adj-RIB-In.
    let provider_role = OtcRole::Provider;

    // Sanity: the same route (no OTC yet) entering the customer.
    assert!(matches!(
        lr_bgp::role::otc::otc_on_receive(None, customer_role, lr_core::addr::Asn(65001)),
        Ok(_)
    ));
    // A provider receiving a customer route with OTC set = leak.
    assert!(lr_bgp::role::otc::otc_on_receive(
        Some(lr_bgp::role::otc::Otc(65001)),
        provider_role,
        lr_core::addr::Asn(64512),
    )
    .is_err());
}
```

What is enforced where, today:

| Direction | Rule | Status |
| --------- | ---- | ------ |
| Egress | `otc_can_advertise` — a route carrying OTC is never advertised to providers, peers, or route servers (`lr-bgp::advertise` consults it for every session) | enforced |
| Ingress | `otc_on_receive` — the §5 leak rules (route from a customer must not carry OTC; from a peer it must carry the peer's AS) | helper shipped; FSM enforcement is future work, so embedders call it from their import hook today |
| OPEN | the role capability | negotiated like every other capability; an unconfigured (`Unset`) peer is inert |

The daemon-level knob (`[peer] otc_role = "provider" | ...`) follows
the library wiring; until it lands, embedded users set
`PeerConfig::otc_role` directly. Compare `docs/PARITY.md` for how
FRR's `bgp enforce-first-as`-style knobs pair with this one.
