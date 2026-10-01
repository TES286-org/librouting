# OSPFv3 SRv6 locator distribution

RFC 9513 distributes SRv6 locators in an OSPFv3 domain: a router
originates a Locator LSA carrying its locator and End SID, and its peers
project those into a per-node SID database and install them as IPv6
forwarding entries. This page configures the originator and the
receiver, then verifies both SIDs.

## The locator model

```text
    SID = LOCATOR : FUNCT : ARGS
    ─────────  ──────  ─────
       │        │       │
       │        │       └─ per-behavior arguments (usually 0)
       │        └─ the behavior function (End, End.X, End.DX6, ...)
       └─ routable prefix, distributed by RFC 9513
```

The End SID is the locator itself; an End.X SID (RFC 9513 §9) is a
per-adjacency SID inside the locator.

## Configuration

Originator:

```lr
protocol ospf;

ospf {
    version "v3";
    srv6_o_flag true;        # advertise the RFC 9259 O-flag
    srv6_max_sl 16;          # Node MSD: SRH Max Segments Left (type 41)
    srv6_max_end_pop 16;     # MSD type 42
    srv6_max_h_encaps 16;    # MSD type 44
    srv6_max_end_d 16;       # MSD type 45

    srv6-locator "2001:db8:a:1::/48" {
        algorithm 0;         # 0 = SPF, the default
        metric 0;
        behavior 1;          # RFC 8986 §4.1 End
    }

    interface "eth0" {
        area 0;
        # RFC 9513 §9.1: the adjacency SID. Must fall inside a locator.
        srv6_end_x "2001:db8:a:1::100";
    }

    interface "eth1" {
        area 0;
        network_type "broadcast";
        # RFC 9513 §9.2: base prefix for the per-neighbor LAN End.X
        # SIDs; the neighbor Router-ID fills the low 32 bits, so the
        # prefix length is at most /96.
        srv6_end_x_lan "2001:db8:a:2:ffff::/96";
    }
}
```

`sid` overrides the End SID (default: the locator with host bits
zeroed). The four `block_len`, `node_len`, `function_len` and
`argument_len` keys add the §10 SID Structure sub-TLV, and are
all-or-none.

Receiver:

```lr
protocol ospf;

ospf {
    version "v3";
    srv6_receive true;       # off by default — fail closed
}
```

Both sides need `--install-kernel-routes` for the kernel mirror. The
equivalent CLI:

```sh
lr-daemon --protocol ospf --ospf-version v3 --router-id 10.0.0.1 \
    --ospf-interface eth0 --ospf-area 0 \
    --ospf-srv6-locator 2001:db8:a:1::/48 \
    --ospf-srv6-o-flag --ospf-srv6-receive \
    --install-kernel-routes
```

`--ospf-srv6-locator` takes the prefix only; the other locator keys and
the Node MSD values are configuration-file keys.

## Originating the LSAs

The RI LSA carries the SRv6 Capabilities TLV, the SR-Algorithm TLV and
the Node MSD TLV; the Locator LSA carries one Locator TLV per locator,
each with its End SID:

```rust
// Cargo.toml:
// [dependencies]
// lr-ospf = "<version>"
// lr-srv6 = "<version>"

use lr_ospf::lsa::srv6::{
    originate_v3_srv6_locator_lsa, originate_v3_srv6_ri_lsa, NodeMsd,
    Srv6EndSidSubTlv, Srv6LocatorTlv, SRV6_CAP_O_FLAG,
};
use lr_srv6::Behavior;

fn main() {
    let router_id = 0x0a00_0001; // 10.0.0.1
    let locator: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x0a, 0x00, 0x01,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // Node MSDs: (msd_type, value) — RFC 9352 §4 types 41/42/44/45.
    let msds: Vec<NodeMsd> = vec![(41, 16), (42, 16), (44, 16), (45, 16)];
    let ri = originate_v3_srv6_ri_lsa(
        router_id,
        SRV6_CAP_O_FLAG,
        &[0],   // SR-Algorithm: 0 = SPF
        &msds,
        None,   // first origination
    )
    .expect("RI LSA originates");

    let locator_tlv = Srv6LocatorTlv {
        route_type: 1,        // intra-area
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 0,
        prefix: locator,
        end_sids: vec![Srv6EndSidSubTlv {
            flags: 0,
            behavior: Behavior::End as u16,
            sid: locator,     // the End SID defaults to the locator
            structure: None,  // add Srv6SidStructure for the §10 sub-TLV
        }],
        fwd_addr: None,
        route_tag: None,
    };
    let locator_lsa = originate_v3_srv6_locator_lsa(
        router_id,
        0,            // Link State ID — caller-chosen
        &[locator_tlv],
        None,
    )
    .expect("Locator LSA originates");

    assert!(!ri.body.is_empty());
    assert!(!locator_lsa.body.is_empty());
}
```

Flood both LSAs per area in the same LSU as the topology LSAs. Pass the
current instance's `header.ls_sequence_number` as `prev_seq` on every
later refresh; `None` restarts the sequence space.

## Reception

`DefaultRouter::set_ospf_srv6_receive(true)` turns on the projection: the
SPF run attaches locator routes with the advertising router's distance as
the metric (RFC 9513 §5), and supported-algorithm (SPF) locators become
IPv6 forwarding entries. The flag is off by default, so an embedder that
does not set it keeps the fail-closed behaviour.

`DefaultRouter::ospf_srv6_databases()` returns the per-area
`lr_ospf::srv6db::Srv6Database`, which holds each node's capabilities,
algorithms, MSDs, locators, End SIDs and adjacency End.X SIDs.

## Verify

The daemon's status view lists each projected adjacency SID:

```sh
lrctl --socket /run/lr-daemon.api status | grep srv6-endx
```

```text
srv6-endx 2001:db8:a:1::100 area=0 router=0a000002 behavior=5 alg=0 neighbor=0a000001
```

`behavior=5` is End.X (RFC 8986 §4.2); a LAN End.X line carries a
trailing `lan` plus the neighbor Router-ID that filled the low 32 bits
(§9.2). To confirm the receiver installed a learned locator:

```sh
lrctl --socket /run/lr-daemon.api routes show 2001:db8:a:1::/48
```

The route carries `proto=Ospfv3` and a link-local next hop, and the
receiver logs `route installed 2001:db8:a:1::/64` as it goes in.

The 3-node interop lab `tests/interop/ospf6_frr_srv6.sh` runs this
through a real FRR `ospf6d` relay: `ospf6d` has no SRv6 support, but per
RFC 5340 §4.2.1 it stores and re-floods U-bit-set unknown E-LSAs.

## Reference

- RFC 9513 — OSPFv3 Extensions for SRv6 (locator TLV, End and End.X SIDs)
- RFC 8986 §4.1, §4.2 — End and End.X behaviors
- RFC 8754 — IPv6 Segment Routing Header
- [`../INTEROP.md`](../INTEROP.md) — the SRv6 labs
