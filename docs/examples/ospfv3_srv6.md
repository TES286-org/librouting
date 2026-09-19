# Example: OSPFv3 SRv6 (RFC 9513) — locator distribution and dataplane

SRv6 is the IPv6 dataplane for Segment Routing: a 128-bit SID
encodes a behavior (End, End.X, End.DX6, etc.), and the SRH
(Segment Routing Header, RFC 8754) carries an ordered list of
SIDs that a packet traverses. The control plane that distributes
SIDs in an OSPFv3 domain is RFC 9513.

The reference daemon runs this end-to-end: an OSPFv3 router
configured with `[[ospf.srv6_locator]]` tables originates the
SRv6 Capabilities TLV (on the RI LSA) and the SRv6 Locator LSA,
peers receive and install the locators as IPv6 forwarding entries
(`--ospf-srv6-receive`), and the kernel dataplane on Linux
mirrors them into `seg6` / `seg6local` routes.

This example shows the library-level pieces an embedder composes.

## The locator model

```text
    SID = LOCATOR : FUNCT : ARGS
    ─────────  ──────  ─────
       │        │       │
       │        │       └─ per-behavior arguments (usually 0)
       │        └─ the behavior's function (End, End.X, End.DX6, …)
       └─ routable prefix (BGP/IGP-reachable), distributed by RFC 9513
```

A locator is an IPv6 prefix (RFC 8754 §3.1). The `End` SID on a
node is by convention `<locator>::` (the locator itself), and the
`End.X` SID (per-adjacency, RFC 9513 §9) is `<locator>::<adjacency-
specific-funct>`. The control plane distributes the locators; the
SIDs are derived from the locators by composition.

## Origination (the SRv6 node)

```rust
// Cargo.toml:
// [dependencies]
// lr-srv6 = "0.1"
// lr-ospf = "1.0.0-rc.4"
// lr-core = "1.0.0-rc.4"

use lr_core::addr::Prefix;
use lr_ospf::lsa::srv6::{
    originate_v3_srv6_locator_lsa, originate_v3_srv6_ri_lsa, Srv6EndSidSubTlv,
    Srv6LocatorTlv, Srv6SidStructure, SRV6_CAP_O_FLAG,
};
use lr_srv6::{Behavior, Sid};

/// A node's SRv6 configuration (the daemon's `[ospf]` section +
/// `[[ospf.srv6_locator]]` tables maps to this shape).
struct NodeSrv6Config {
    /// Locator prefix, e.g. fc00:dead:beef::/48.
    locator_prefix: [u8; 16],
    locator_len: u8,
    /// SR-Algorithm (0 = SPF, the default).
    algorithm: u8,
    /// End SID (defaults to the locator itself).
    end_sid: [u8; 16],
    /// End behavior (defaults to End — RFC 8986 §4.2 opcode 5).
    end_behavior: u16,
    /// Node MSDs (Max Segments Left = type 41, Max End.Pop = 42, …).
    msds: Vec<(u8, u8)>, // (msd_type, value)
    router_id: u32,
}

fn originate_node_lsas(cfg: &NodeSrv6Config) {
    // The RI LSA carries the SRv6 Capabilities TLV (O-flag, RFC 9513
    // §3 — advertises "I can do SRv6"), the SR-Algorithm TLV and
    // the Node MSD TLV.
    let capabilities = SRV6_CAP_O_FLAG; // bit 1 = O-flag
    let msds: &[lr_ospf::lsa::srv6::NodeMsd] = &cfg.msds; // NodeMsd = (u8, u8)
    let _ri_lsa = originate_v3_srv6_ri_lsa(
        cfg.router_id,
        capabilities,
        &[cfg.algorithm],
        &msds,
        None, // first origination; subsequent: Some(prev_seq)
    )
    .expect("RI LSA originates");

    // The Locator LSA carries one Locator TLV per configured locator,
    // each with an End SID sub-TLV (RFC 9513 §8) and the SID Structure
    // sub-TLV (§10 — the LOC:FUNCT:ARGS bit-lengths the receiver uses
    // to compose adjacency-SID SIDs from the locator).
    let locator_tlv = Srv6LocatorTlv {
        route_type: 1, // intra-area
        algorithm: cfg.algorithm,
        locator_len: cfg.locator_len,
        options: 0,
        metric: 0,
        prefix: cfg.locator_prefix,
        end_sids: vec![Srv6EndSidSubTlv {
            flags: 0,
            behavior: cfg.end_behavior,
            sid: cfg.end_sid,
            structure: Some(Srv6SidStructure {
                // LOC:FUNCT:ARGS bit-lengths (RFC 8986 §3.2). For
                // fc00:dead:beef::/48 + a 16-bit function field:
                // lb_len=32 (block), ln_len=16 (node) → locator=48,
                // func_len=16, arg_len=0.
                lb_len: 32,
                ln_len: 16,
                func_len: 16,
                arg_len: 0,
            }),
        }],
        fwd_addr: None,
        route_tag: None,
    };
    let _locator_lsa = originate_v3_srv6_locator_lsa(
        cfg.router_id,
        0, // Link State ID — caller-chosen
        &[locator_tlv],
        None, // first origination
    )
    .expect("Locator LSA originates");
    // The daemon floods these LSAs per-area in the same LSU as the
    // topology LSAs (Router-LSA etc.); peers extract the locator
    // and install it in their srv6db projection.
}

fn main() {
    let cfg = NodeSrv6Config {
        locator_prefix: [0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0],
        locator_len: 48,
        algorithm: 0,
        end_sid: [0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0], // == locator
        end_behavior: Behavior::End as u16, // RFC 8986 §4.1 opcode 1
        msds: vec![(41, 16), (42, 16), (44, 16), (45, 16)],
        router_id: 0x0a000001, // 10.0.0.1
    };
    originate_node_lsas(&cfg);
}
```

## Reception (the SRv6-capable peer)

The `lr_ospf::srv6db` module is the per-node LSDB projection. The
peer's SPF run attaches locator routes (§5: metric = the
advertising router's SPF distance, link-local first hop). The
`DefaultRouter::set_ospf_srv6_receive` flag (off by default,
fail-closed) installs supported-algorithm (0/SPF) locators as IPv6
forwarding entries with §5's IAP-beats-locator preference.

```rust
use lr_router::DefaultRouter;
use lr_ospf::srv6db;

// Inside the embedder's poll loop, after the LSDB has been
// updated from a received LSU:
let mut router = DefaultRouter::new();
// Enable SRv6 reception (fail-closed — must be set explicitly).
router.set_ospf_srv6_receive(true);

// After SPF runs and the srv6db is populated:
let db = router.ospf_srv6_databases();
for node in db.nodes() {
    println!("node {} capabilities:", node.router_id);
    println!("  O-flag: {}", node.capabilities.o_flag);
    println!("  algorithms: {:?}", node.algorithms);
    for msd in &node.msds {
        println!("  MSD {:?}: {}", msd.kind, msd.value);
    }
    for loc in &node.locators {
        println!("  locator {} algorithm {} metric {}",
                 loc.prefix, loc.algorithm, loc.metric);
        for sid in &loc.end_sids {
            println!("    End SID {} behavior {:?}", sid.sid, sid.behavior);
        }
    }
}
```

## CLI flags

```bash
# Originator: advertise the locator and End SID.
lr-daemon --protocol ospf --ospf-version v3 \
    --router-id 10.0.0.1 \
    --ospf-interface eth0 --ospf-area 0 \
    --ospf-srv6-locator fc00:dead:beef::/48 \
    --ospf-srv6-receive \
    --ospf-srv6-o-flag \
    --ospf-srv6-max-sl 16 \
    --install-kernel-routes

# Receiver: install the originator's locator as an IPv6 route.
lr-daemon --protocol ospf --ospf-version v3 \
    --router-id 10.0.0.2 \
    --ospf-interface eth0 --ospf-area 0 \
    --ospf-srv6-receive \
    --install-kernel-routes
```

## The interop lab

The 3-node lab `tests/interop/ospf6_frr_srv6.sh` exercises this
end-to-end:

```text
   lr1 (originator)  ←→  FRR 10.3 ospf6d (relay)  ←→  lr2 (receiver)
```

`ospf6d` has no SRv6 support, but per RFC 5340 §4.2.1 it stores and
re-floods the U-bit-set unknown E-LSAs (the SRv6 RI + Locator LSAs).
`lr2` installs `lr1`'s locator through the FRR relay as an
`Ospfv3` route with a link-local next hop.

## What's missing (the roadmap)

The current slice (RFC 9513 slices 1-3) covers Node SIDs only. The
adjacency SIDs — End.X and LAN End.X (RFC 9513 §9) — ride on the
RFC 8362 E-Router-Link TLV, which is the next planned slice. See
[`docs/ROADMAP.md`](../ROADMAP.md) §"Phase 3 — plan" item 2 for
the design and the interop gate.

The `BGP SR Policy` (RFC 9256 / 9430) slice is the consumer side:
receive candidate/dynamic SR policies as VPN routes, resolve them
to `lr-srv6` segment lists, and steer matching Loc-RIB entries into
`seg6` encap routes in the kernel mirror (the BGP-LU LSP-mirror
slice's shape, extended to SRv6 policies). See
[`docs/ROADMAP.md`](../ROADMAP.md) §"Phase 3 — plan" item 4.
