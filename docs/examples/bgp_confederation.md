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

- `AsPath::prepend` always prepends into an `AS_SEQUENCE` segment. Use
  [`AsPath::prepend_confed`](../../crates/lr-bgp/src/path/as_path.rs)
  when you need an `AS_CONFED_SEQUENCE` hop (RFC 5065 §4.1(b)): an
  existing leftmost `AS_CONFED_SEQUENCE` is extended in place so the
  path keeps one confed segment.
- `BgpPeer::advertise` re-encodes the AS_PATH it was handed and applies
  the full RFC 5065 §4.1(b)/(c)(1)/(5) rules (landed in rc.6):
  when advertising into a confederation-internal peer the local AS is
  prepended as an `AS_CONFED_SEQUENCE`; when advertising to a peer
  outside the confederation every `AS_CONFED_*` segment is stripped
  (via `AsPath::strip_confed`) and the local AS is prepended into the
  outer `AS_SEQUENCE`. An embedder that needs a different policy can
  still do it in an export hook, but the default behaviour matches
  BIRD and FRR.

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
