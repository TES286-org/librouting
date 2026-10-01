# Installing Loc-RIB routes into the kernel

This page installs a best route into the operating system FIB from an
embedder, then reads the table back and removes it. Read it if you are
writing your own mirror instead of using the daemon's
`--install-kernel-routes`.

## The abstraction

`lr_osroute::OsRouteTable` is a **trait**: each platform supplies one
implementor. `RtNetlink` is an alias resolved at compile time —
`linux::RtNetlink` on Linux, `bsd::RouteSocket` on the BSDs and macOS,
`windows::IpHelper` on Windows. `SystemRouteTable` is the same alias
under a clearer name; prefer it in new code.

The trait surface is small:

| Method | Effect |
| ------ | ------ |
| `add_route` | install `prefix` via `next_hop` on an interface index |
| `add_route_tagged` | the same, plus the `RTPROT_*` protocol tag |
| `add_blackhole_route` | discard matching traffic |
| `delete_route` | remove the entry for a prefix |
| `list_routes` | dump the FIB as `Vec<KernelRoute>` |
| `has_route` | is there an entry for this prefix? |

## Install, list, delete

```rust
// Cargo.toml:
// [dependencies]
// lr-osroute = "<version>"
// lr-core = "<version>"

use lr_core::addr::{IpAddr, Prefix};
use lr_core::rib::Protocol;
use lr_osroute::{OsRouteTable, RtNetlink};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rt = RtNetlink::connect()?;

    let prefix: Prefix = "203.0.113.0/24".parse()?;
    let gw: IpAddr = "198.51.100.1".parse()?;

    // Install: reach 203.0.113.0/24 via 198.51.100.1 on eth0.
    let if_index = 2;
    rt.add_route_tagged(prefix, gw, if_index, Protocol::Bgp)?;
    assert!(rt.has_route(prefix)?);

    // Read the table back. `KernelRoute` carries the prefix, the next
    // hop, the interface index, the metric and the protocol tag.
    for r in rt.list_routes()? {
        println!(
            "{} metric={} via {} dev {}",
            r.prefix,
            r.metric,
            r.next_hop.map(|n| n.to_string()).unwrap_or_else(|| "on-link".into()),
            r.if_index.unwrap_or(0),
        );
    }

    // Withdraw.
    rt.delete_route(prefix)?;
    assert!(!rt.has_route(prefix)?);
    Ok(())
}
```

`add_route_tagged` falls back to `add_route` on backends that cannot
carry a protocol tag, so it is always safe to call. The tag is what
`ip route` shows as `proto bgp`, and what keeps a cleanup sweep from
deleting routes another daemon installed.

## What to watch for

- **Privileges.** Installing routes needs `CAP_NET_ADMIN` on Linux.
  Windows needs an elevated process.
- **Persistence.** Kernel routes do not survive a reboot. Re-install
  them from your configuration on every start.
- **Ordering.** Run the route through `lr-policy`'s `SafetyNet` before
  installing it, so a martian or bogon prefix never reaches the FIB.
- **Interface indices.** `next_hop` alone is enough for a global
  address. A link-local IPv6 gateway needs the interface index, and
  Linux rejects the install without it.

## Check

```sh
ip route show proto bgp          # Linux
route print                      # Windows
```

Compare against `lrctl --socket /run/lr-daemon.api routes show`, which
prints the Loc-RIB the mirror was fed from. A route present in one and
absent in the other is either a failed syscall or a safety-net drop.

## Reference

- [`../OS-INTEGRATION.md`](../OS-INTEGRATION.md) — the platform matrix
  and the transports
- [`bgp_labeled_unicast.md`](bgp_labeled_unicast.md) — the MPLS table,
  which mirrors the same way
