# OSPF ABR summaries and NSSA areas

An area border router (ABR) advertises reachability between areas with
type-3 summary-LSAs, and a not-so-stubby area (NSSA) imports external
routes as type-7 LSAs. This page configures both and shows the
origination helpers an embedder drives.

## Topology

```text
     area 1 (stub)            backbone (area 0)         area 2 (NSSA)
   +----------------+        +-------------+         +----------------+
   | 10.10.0.0/16   |        |             |         | 10.20.0.0/16   |
   |  no externals  +--------+  ABR (R1)   +---------+  type-7 in,    |
   |  default in    |  p2p   |             |  p2p    |  translated    |
   +----------------+        +-------------+         +----------------+
```

## Configuration

```lr
protocol ospf;

ospf {
    hello_interval 10s;
    dead_interval 40s;

    # Non-backbone areas are declared before interfaces reference them.
    area 1 {
        type "stub";          # normal | stub | nssa
        no_summary true;      # totally-stubby: suppress all type-3s
        stub_metric 10;       # metric of the injected default route
    }

    area 2 {
        type "nssa";
        stub_metric 10;       # NSSA: injects its own default
    }

    interface "eth0" {
        area 0;               # the ABR's backbone interface
        cost 10;
    }

    interface "eth1" {
        area 1;
        cost 10;
    }

    interface "eth2" {
        area 2;
        cost 10;
    }
}
```

`type` accepts exactly `normal`, `stub` and `nssa`. There is no
`totally-stubby` value: set `no_summary true` on a `stub` area for
totally-stubby, or on an `nssa` area for totally-NSSA. Area 0 is always
`normal`; declaring it as stub or NSSA is a startup error. An area with
no `stub_metric` uses 10.

## Originating a summary

The ABR re-advertises each intra-area network into area 0 as a type-3
summary-LSA whose metric is that network's intra-area SPF cost:

```rust
// Cargo.toml:
// [dependencies]
// lr-ospf = "<version>"
// lr-core = "<version>"

use lr_core::addr::Prefix;
use lr_ospf::abr::{flush_summary_lsa, originate_summary_lsa, SummaryDestination};

fn main() {
    // 10.10.0.0/16 costs 30 from the ABR's intra-area SPF.
    let dest = SummaryDestination::new(Prefix::new_v4([10, 10, 0, 0], 16), 30);

    // First origination: no previous instance, so the sequence space
    // starts at the initial value. The LSA comes back finalized — length
    // fixed and the RFC 2328 §C.4 checksum computed — ready to flood.
    let lsa = originate_summary_lsa(0x01010101, &dest, None).unwrap();

    // Later refreshes continue the sequence space (§12.4). Returning
    // None means the space is exhausted: flush and re-originate (§12.1.2).
    let refresh = originate_summary_lsa(
        0x01010101,
        &dest,
        Some(lsa.header.ls_sequence_number),
    );
    assert!(refresh.is_some());

    // A destination that leaves the area is flushed, not silently
    // dropped: age the LSA to MaxAge and flood it (§14.1).
    let _flush = flush_summary_lsa(&lsa);
}
```

The ABR summarizes into a non-backbone area only the routes it derived
from the backbone, never summaries read from another non-backbone area
(RFC 2328 §16.2). That is what keeps inter-area paths loop-free and
confines every inter-area route to area 0.

## NSSA translation

`lr-ospf::nssa` holds the type-7 pieces: `originate_nssa_lsa`,
`flush_nssa_lsa`, `originate_nssa_default_lsa`, `p_bit_set`,
`is_elected_translator` and `nssa_routes`. The daemon wires them per
area:

1. An NSSA imports external routes as type-7 LSAs.
2. When the P-bit is set (`p_bit_set`) and this ABR wins the translator
   election (`is_elected_translator`), it re-announces them into the
   backbone as type-5 LSAs.
3. `originate_nssa_default_lsa` injects the area's own default route;
   `no_summary true` additionally suppresses the type-3 summaries.

## Verify

```sh
lrctl --socket /run/lr-daemon.api routes show 10.10.0.0/16
```

The stub area's routers see the ABR's default route and no externals.
In the NSSA, a type-7 LSA that is translated appears in the backbone as
a type-5 for the same prefix with the forwarding address per RFC 3101
§2.5; a P-bit-clear LSA is never translated.

## Reference

- RFC 2328 §12.4.3, §16.2 — summary-LSA origination and the backbone
  rule
- RFC 3101 — The OSPF Not-So-Stubby Area Option
- [`ospfv3_srv6.md`](ospfv3_srv6.md) — OSPFv3 with SRv6 locators
