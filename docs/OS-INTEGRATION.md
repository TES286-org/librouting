# OS Integration Guide — `lr-osroute`

`lr-osroute` is librouting's **reference implementation** for the boundary
between the library's Loc-RIB and the host's kernel forwarding information
base (FIB). This document explains what exists today, how each backend
works, and — most importantly — **how to port the integration to a system
that is not covered out of the box**.

```text
+---------------------------------------------------+
|                  your embedder                    |
|        (lr-daemon, or your own supervisor)        |
+------------------------+--------------------------+
                         | OsRouteTable::{add,delete,list}_route
                         v
+---------------------------------------------------+
|                   lr-osroute                      |
|   OsRouteTable trait   |  backends:               |
|   (portable contract) |   linux::RtNetlink        |
|                        |   bsd::RouteSocket       |
|                        |   windows::IpHelper      |
|                        |   stub::StubRouteTable   |
+------------------------+--------------------------+
                         | syscalls / FFI
                         v
+---------------------------------------------------+
|                kernel routing table               |
|   (rtnetlink / route(4) socket / IP Helper API)   |
+---------------------------------------------------+
```

## Backend status matrix

| Platform | Backend                              | Add | Delete | List | Verification                                                                      |
| -------- | ------------------------------------ | --- | ------ | ---- | --------------------------------------------------------------------------------- |
| Linux    | `linux::RtNetlink` (rtnetlink)       | ✅  | ✅     | ✅   | E2E tested on Linux CI + `--install-kernel-routes`                                |
| FreeBSD  | `bsd::RouteSocket` (route(4) socket) | ✅  | ✅     | ✅   | Cross-compile checked; layout verified against `sys/net/route.h`                  |
| NetBSD   | `bsd::RouteSocket`                   | ✅  | ✅     | ✅   | Cross-compile checked; layout verified against `sys/net/route.h`                  |
| OpenBSD  | `bsd::RouteSocket`                   | ✅  | ✅     | ✅   | Source-level verification (no prebuilt Rust std for the target from a Linux host) |
| macOS    | `bsd::RouteSocket`                   | ✅  | ✅     | ✅   | Source-level verification against xnu `bsd/net/route.h`                           |
| Windows  | `windows::IpHelper` (IP Helper API)  | ✅  | ✅     | ✅   | Cross-compile checked (x86_64-pc-windows-gnu), full link against `iphlpapi`       |
| other    | `stub::StubRouteTable`               | —   | —      | —    | Compile-only stub; returns errors at runtime                                      |

The unified entry point is the type alias `lr_osroute::SystemRouteTable`,
which resolves to the native backend of the compilation target. The
historical name `lr_osroute::RtNetlink` keeps working on every platform
(it aliases the native backend), so older embedders compile unchanged.

```rust
use lr_osroute::{OsRouteTable, SystemRouteTable};

let mut rt = SystemRouteTable::connect()?;        // e.g. rtnetlink on Linux
rt.add_route(prefix, next_hop, 0)?;               // if_index 0 = let the OS resolve
let routes = rt.list_routes()?;
```

## Backend design notes

### Linux — rtnetlink (`linux.rs`)

A `NETLINK_ROUTE` socket speaks the rtnetlink protocol (RFC 3549): route
additions are `RTM_NEWROUTE` messages with a `struct rtmsg` header plus
TLV attributes (`RTA_DST`, `RTA_GATEWAY`, `RTA_OIF`, `RTA_PRIORITY`), and
dumps are `RTM_GETROUTE` + `NLM_F_DUMP` requests. No external crates are
used — the handful of C ABI entry points (`socket`, `bind`, `sendmsg`,
`recv`) are declared directly. When `if_index == 0` the `RTA_OIF`
attribute is omitted so the kernel resolves the output interface from the
gateway (`ip route add ... via GW` semantics). Adds carry
`NLM_F_CREATE | NLM_F_REPLACE`: a missing route is created and an existing
best route for the prefix is atomically replaced.

### BSD family — route(4) socket (`bsd.rs`)

All BSDs (and macOS) expose the FIB through the `PF_ROUTE` routing socket:
messages built from a versioned `struct rt_msghdr` plus the sockaddrs
selected by the `rtm_addrs` bitmask, and table dumps via
`sysctl(CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0)`.

The header layout **drifted between the BSDs**, so per-OS compile-time
constants pin the exact sizes and field offsets (verified against each
system's `sys/net/route.h`):

| OS            | `sizeof(rt_msghdr)` | `RTM_VERSION` | `AF_INET6` | quirks                                         |
| ------------- | ------------------: | ------------: | ---------: | ---------------------------------------------- |
| FreeBSD 13/14 |                 152 |             5 |         28 | `_rtm_spare1`, `rtm_fmask`, `u_long rtm_inits` |
| OpenBSD 7.x   |                  96 |             5 |         24 | `rtm_hdrlen` must be set to the header size    |
| NetBSD 10     |                 120 |             4 |         24 | `__align64` members                            |
| macOS (xnu)   |                  92 |             5 |         30 | classic 4.4BSD layout                          |

Sockaddrs inside a message are padded to `sizeof(long)` (8 bytes on
64-bit): `sockaddr_in` stays 16 bytes, `sockaddr_in6` (28) becomes 32.
Message replies are matched on `rtm_seq` so unrelated asynchronous
route-change notifications are skipped, and `SO_RCVTIMEO` bounds every
read. Deletes treat `ESRCH` ("no such route") as success so
reconciliation loops are idempotent.

### Windows — IP Helper API (`windows.rs`)

Windows' FIB lives behind `iphlpapi.dll`:

- `CreateIpForwardEntry2` / `DeleteIpForwardEntry2` modify rows described
  by `MIB_IPFORWARD_ROW2`; the SDK layouts and entry points come from
  Microsoft's generated `windows-sys` bindings.
- `GetIpForwardTable2` snapshots the whole table; `FreeMibTable` releases
  the buffer.
- Rows are initialised by `InitializeIpForwardEntry` (infinite lifetimes,
  `Publish=FALSE`, `Immortal=TRUE`).
- `NL_ROUTE_PROTOCOL` is set to `MIB_PROTOCOL_BGP` (14) — matching what
  `Get-NetRoute -Protocol` reports for BGP-learned routes.
- When `if_index == 0`, `GetBestRoute2` resolves the interface separately
  for every next hop using Windows' actual forwarding policy and interface
  metrics. IPv6 link-local gateways carry that interface as their scope ID.
- Deletes scan the table and only remove rows **we** installed
  (`Protocol == BGP`) — foreign rows are never touched.

Notes: routes created this way are _not_ boot-persistent; a daemon should
re-install its best paths after restart (which `lr-daemon` does whenever
the RIB converges). Requires elevation to modify the table.

## Writing a backend for another system

Implement the `OsRouteTable` trait — that is the entire contract:

```rust
pub trait OsRouteTable {
    type Error: std::error::Error;

    fn add_route(&mut self, prefix: Prefix, next_hop: IpAddr, if_index: u32)
        -> Result<(), Self::Error>;
    fn delete_route(&mut self, prefix: Prefix) -> Result<(), Self::Error>;
    fn list_routes(&mut self) -> Result<Vec<KernelRoute>, Self::Error>;
    // has_route() has a default implementation on top of list_routes().
}
```

Guidelines distilled from the three in-tree backends:

1. **Use authoritative bindings.** A small direct syscall surface is
   reasonable on Linux, where the UAPI is stable and tested from synthetic
   messages. For SDK-defined structures such as Windows IP Helper, prefer
   generated vendor bindings (`windows-sys`) so layouts cannot drift.
2. **Idempotency.** Route daemons reconcile state in loops: re-adding an
   existing route and deleting a missing one should both succeed (or
   return a typed "already exists / not found" the caller can treat as
   success). Linux: delete gets `ESRCH`; Windows: `ERROR_NOT_FOUND`;
   BSD: `ESRCH`.
3. **Scope your deletes.** Only remove entries your system created
   (Linux `RTPROT_BGP`, Windows `MIB_PROTOCOL_BGP`, BSD `RTF_STATIC`).
   Never modify kernel/RA/DHCP-learned rows.
4. **Attribute provenance.** Map the OS' route-origin field to
   `lr_core::rib::Protocol` in `list_routes()` so cross-protocol
   comparison (administrative distance) works.
5. **Bound your syscalls.** Any blocking read needs a timeout; the BSD
   backend sets `SO_RCVTIMEO` for exactly this reason.
6. **Document the layout.** If your interface is a binary struct (all
   three are), cite the authoritative header and pin sizes with
   `const _: () = assert!(size_of::<T>() == N);`.

### Worked example: illumos/Solaris

illumos exposes routes through a PF_ROUTE-compatible routing socket
(derived from the same 4.4BSD lineage) plus `UDP` routing-socket
extensions. A minimal port would:

1. `git grep 'target_os = "freebsd"' crates/lr-osroute/src/bsd.rs` and add
   `target_os = "solaris"` where the layouts match.
2. Verify `sizeof(struct rt_msghdr)` from
   `usr/src/uts/common/net/route.h` — illumos kept the classic layout
   with 32-bit `rtm_inits`, close to the macOS one.
3. Register the alias in `lib.rs`:
   `pub use bsd::RouteSocket as SystemRouteTable` for
   `target_os = "solaris"`, and update the `PLATFORM_NAME` table.
4. Add a `layout` module with the verified constants and a unit test
   asserting a synthetic dump parses.

### Worked example: command-based fallback

For RTOSes or exotic kernels without a syscall interface, shell out to
the system's CLI from the trait methods:

```rust
impl OsRouteTable for CliRouteTable {
    type Error = OsRouteError;

    fn add_route(&mut self, prefix: Prefix, nh: IpAddr, _idx: u32) -> Result<(), Self::Error> {
        let out = std::process::Command::new("route")
            .args(["add", "-net", &prefix.to_string(), &nh.to_string()])
            .output().map_err(|e| OsRouteError(e.to_string()))?;
        if out.status.success() { Ok(()) } else {
            Err(OsRouteError(String::from_utf8_lossy(&out.stderr).into()))
        }
    }
    // ...
}
```

This is slower than a native interface (one fork per route) but perfectly
acceptable for control-plane convergence rates; it is also how early
Quagga ports worked on several proprietary platforms.

## Testing backends

- **Unit tests** build synthetic messages and assert they parse, and verify
  platform-specific row construction and route resolution.
- **Cross-compile checks** catch cfg/layout mistakes even without access
  to the target OS — the CI `cross` job builds the full workspace for
  `aarch64-unknown-linux-gnu` and `x86_64-pc-windows-gnu`; run locally
  with `cargo check -p lr-osroute --target x86_64-unknown-freebsd`.
- **E2E**: `lr-daemon --install-kernel-routes` against any peers, then
  verify with the platform's own tooling (`ip route`, `netstat -rn`,
  `route print`, `Get-NetRoute`).

## Troubleshooting

| Symptom                                    | Cause                         | Fix                                                                       |
| ------------------------------------------ | ----------------------------- | ------------------------------------------------------------------------- |
| `socket(AF_NETLINK): Permission denied`    | sandboxed container           | run privileged or keep `install: false`                                   |
| `RTM_ADD …: Operation not permitted` (BSD) | non-root                      | route changes need root on stock BSDs                                     |
| `CreateIpForwardEntry2 failed: error 5`    | Windows without elevation     | run elevated                                                              |
| `cannot find Scrt1.o` (cross build)        | missing target libc dev files | `apt install libc6-dev-arm64-cross`                                       |
| Duplicate/`EEXIST` errors on add           | reconciler re-adds            | treat `EEXIST` as success in your embedder (the daemon logs and moves on) |
