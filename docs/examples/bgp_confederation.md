# BGP confederation

A confederation is a set of sub-ASes that behave like eBGP internally and
appear as one AS to the outside world. This page shows the
`ConfederationConfig` an embedder attaches to a peer and what the library
does with it. There is no daemon configuration key for confederations.

## Topology

```text
   AS 64512  <-- eBGP (confed) -->  AS 64513  <-- eBGP (confed) -->  AS 64514
        \                                                                /
         +------------------ confederation 64512 ----------------------+
                                    |
                                    | plain eBGP
                                    v
                                 AS 65000
```

## Wiring

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "<version>"
// lr-core = "<version>"

use lr_bgp::role::{ConfederationConfig, PeerRole};
use lr_bgp::{BgpPeer, PeerConfig};
use lr_core::addr::{Asn, RouterId};

/// Our own sub-AS is 64512; the confederation covers 64512-64515.
fn peer(peer_as: u32) -> PeerConfig {
    let mut cfg =
        PeerConfig::new(Asn(64512), Asn(peer_as), RouterId::from_v4([10, 0, 0, 1]));
    cfg.confederation = Some(ConfederationConfig::new(vec![64512, 64513, 64514, 64515]));
    cfg
}

fn main() {
    // Same confederation, different sub-AS.
    let confed_peer = peer(64513);
    assert_eq!(confed_peer.peer_role(), PeerRole::ConfederationExternal);
    let _bgp = BgpPeer::new(confed_peer);

    // Outside the confederation: ordinary eBGP.
    let external = peer(65000);
    assert_eq!(external.peer_role(), PeerRole::Ebgp);
    let _bgp = BgpPeer::new(external);
}
```

`PeerConfig::peer_role` reads `local_as`, `peer_as` and the member list:
an equal ASN inside the list is `ConfederationInternal`, a different
member is `ConfederationExternal`, and anything outside the list falls
back to `Ebgp` or `Ibgp`. `ConfederationInternal` counts as internal for
iBGP split-horizon; `ConfederationExternal` counts as external, which is
also what RFC 8212's deny-in/deny-out default keys off.

## AS_PATH handling

The wire segment types are `lr_bgp::path::AsPathType::ConfedSequence` and
`ConfedSet`; the codec encodes and decodes both, and
`AsPath::loop_check` scans `ConfedSequence` members along with ordinary
`Sequence` members.

Two behaviours to know before you rely on confederations:

- `AsPath::prepend` always prepends into an `AS_SEQUENCE` segment. It
  never creates an `AS_CONFED_SEQUENCE`, so a confederation-external
  advertisement carries the sub-AS as an ordinary AS_PATH hop.
- `BgpPeer::advertise` re-encodes the AS_PATH it was handed. It does not
  strip `AS_CONFED_*` segments when a route leaves the confederation, so
  an embedder that needs RFC 5065 §5.3 removal must do it in an export
  hook.

Confederation segments are **not** counted in the AS_PATH length by
default, per RFC 5065 §5.3(3). To opt into FRR's
`bgp bestpath as-path confed` behaviour, set
`BestPathConfig::count_confed_in_path_len = true`; the comparator then
uses `AsPath::length_with_confed`.

## Check

`PeerConfig::peer_role` is the single decision point, so a unit test on
the config covers the classification:

```rust
let cfg = peer(64513);
assert_eq!(cfg.peer_role(), PeerRole::ConfederationExternal);
assert!(cfg.is_ebgp(), "confederation-external counts as external");
```

`is_ebgp` returns true for both `Ebgp` and `ConfederationExternal`, which
is also what RFC 8212's deny-in/deny-out default keys off.

## Reference

- RFC 6793 — BGP Support for Four-Octet AS Number Space (confederations)
- RFC 5065 §5.3 — AS_PATH length rules
- [`bgp_route_reflector.md`](bgp_route_reflector.md) — iBGP without
  sub-ASes
