# Example: OSPF ABR summaries and NSSA areas (RFC 2328 §12.4.3 / §16.2, RFC 3101)

An area border router stitches OSPF areas together by originating
type-3 summary-LSAs — and the one-direction-via-backbone rule is what
keeps inter-area paths loop-free without virtual links. This example
walks the ABR job and the stub/NSSA filters around it:

```
      area 1 (stub)          backbone 0.0.0.0          area 2 (NSSA)
  +----------------+        +-------------+         +----------------+
  | 10.10.0.0/16   |        |             |         | 10.20.0.0/16   |
  |  no externals  +--------+  ABR (R1)   +---------+  type-7 in,    |
  |  default in    |  p2p   |             |  p2p    |  translated    |
  +----------------+        +-------------+         +----------------+
```

## 1. Summarizing intra-area reachability into the backbone

The ABR scans an area's routing table and re-advertises each intra-area
network into area 0 as a summary-LSA whose metric is that network's
intra-area cost:

```rust
// Cargo.toml:
// [dependencies]
// lr-ospf = "1.0.0-rc.4"

use lr_core::addr::Prefix;
use lr_ospf::abr::{originate_summary_lsa, SummaryDestination};

fn main() {
    // 10.10.0.0/16 costs 30 from the ABR's intra-area SPF.
    let dest = SummaryDestination::new(
        Prefix::new_v4([10, 10, 0, 0], 16),
        30,
    );

    // First origination: no previous instance, the LSA starts the
    // sequence space. The returned LSA is finalized (length + the
    // RFC 2328 §C.4 checksum) and ready to flood.
    let lsa = originate_summary_lsa(0x01010101, &dest, None).unwrap();

    // Later refreshes continue the sequence space: pass the current
    // instance's sequence number (§12.4) — MinLSArrival pacing is the
    // caller's job (§14).
    let _refresh = originate_summary_lsa(
        0x01010101,
        &dest,
        Some(lsa.header.ls_sequence_number),
    );
}
```

## 2. The backbone-only rule

The same helper serves the reverse direction, but the route set an ABR
summarizes into a non-backbone area is *the routes derived from the
backbone only* — never summaries read from other non-backbone areas
(§16.2). Inter-area routes therefore always traverse area 0, which is
what keeps the loop-free property without virtual links; when the
backbone is partitioned, repair it with a virtual link (§15, already
implemented — see `STATUS.md`) rather than leaking summaries sideways.

## 3. Withdrawing a summary

A destination that leaves an area is flushed, not silently dropped:
age the LSA to MaxAge and flood — with the sequence number advanced so
peers accept it as newer:

```rust
use lr_ospf::abr::flush_summary_lsa;

let _flush = flush_summary_lsa(&lsa);
```

## 4. NSSA: type-7 in, type-5 out

A not-so-stubby area imports external routes as type-7 LSAs and, when
the P-bit is set and the ABR wins translation, re-announces them into
the backbone as type-5. The pieces in `lr-ospf::nssa` cover the
type-7 encoding, the forwarding-address rules, and the default cost
options; the daemon wires them through `[[ospf.area]]` with
`type = "nssa"` / `"stub"` / `"totally-stubby"` (+ `no_summary`), and
the e2e matrix in `STATUS.md` (stub/NSSA row) exercises translation,
election, and flush lifecycles end to end. The embedder-level flow:

```
type-7 LSA arrives in the NSSA  ->  P-bit set?  ->  ABR translates to
                                                    type-5 into area 0
default injection              ->  stub/totally-stubby gate the summary
                                   default; NSSA injects its own
```

The unit and e2e coverage for every step lives in `lr-ospf` and the
redistribution/stub suites (`crates/lr-tests/tests/`), which is the
executable form of this example.
