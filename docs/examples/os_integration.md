# Example: OS route table integration (Linux rtnetlink)

This example installs a Loc-RIB route into the Linux kernel FIB. After
the route is installed, the kernel forwards traffic to the next hop
without further user-space intervention.

```rust
// Cargo.toml:
// [dependencies]
// lr-osroute = "1.0.0-rc.4"

use lr_osroute::{OsRouteTable, RtNetlink};
use lr_core::addr::{Prefix, IpAddr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rt = RtNetlink::connect()?;

    // Add a route: 203.0.113.0/24 via 198.51.100.1 on eth0 (if_index 2).
    let prefix: Prefix = "203.0.113.0/24".parse()?;
    let gw: IpAddr = "198.51.100.1".parse()?;
    rt.add_route(prefix, gw, 2)?;

    // List all routes currently in the kernel.
    let routes = rt.list_routes()?;
    for r in routes {
        println!(
            "{}/{} via {} dev {}",
            r.prefix,
            r.metric,
            r.next_hop.map(|n| n.to_string()).unwrap_or_default(),
            r.if_index.unwrap_or(0)
        );
    }

    // Delete the route we just added.
    rt.delete_route(prefix)?;
    Ok(())
}
```

## Notes

- **Privileges**: installing routes requires `CAP_NET_ADMIN` (Linux). Run
  as root or grant the capability.
- **Persistence**: routes installed via rtnetlink do **not** survive
  reboot. Use a config file + a supervisor to re-install on boot.
- **Validation**: the `SafetyNet` in `lr-policy` should run *before*
  installing into the kernel to prevent installing martian prefixes.
