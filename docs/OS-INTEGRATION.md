# OS route-table integration

How `lr-osroute` puts a computed route into the host kernel, and how to
add a backend for a system it does not cover. Read this if you are
embedding the library on your own transport, or porting the dataplane to
a new OS. The protocol codecs do not read this document.

```text
+-----------------------------------------------------+
|  your embedder (lr-daemon, or your own supervisor)  |
+----------------------------+------------------------+
                             | OsRouteTable::{add,delete,list}_route
                             v
+-----------------------------------------------------+
|  lr-osroute                                         |
|  OsRouteTable (portable contract)                   |
|    linux::RtNetlink   bsd::RouteSocket              |
|    windows::IpHelper  stub::StubRouteTable          |
+----------------------------+------------------------+
                             | syscalls / FFI
                             v
+-----------------------------------------------------+
|  kernel FIB: rtnetlink / route(4) / IP Helper API   |
+-----------------------------------------------------+
```

## The contract

The unified entry point is the type alias `lr_osroute::SystemRouteTable`,
which resolves to the backend of the compilation target. The historical
name `lr_osroute::RtNetlink` still resolves on every platform, so older
embedders compile unchanged.

```rust
use lr_osroute::{OsRouteTable, SystemRouteTable};

let mut rt = SystemRouteTable::connect()?;   // rtnetlink on Linux
rt.add_route(prefix, next_hop, 0)?;          // if_index 0 = OS resolves it
let routes = rt.list_routes()?;
```

## Backend matrix

| Platform | Backend | How it is verified |
| --- | --- | --- |
| Linux | `lr-osroute::linux::RtNetlink` | end-to-end in CI: `tests/interop/bgp_kernel_install.sh`, plus the kernel-gated `route_kernel` tests in a rootless network namespace |
| macOS | `lr-osroute::bsd::RouteSocket` | end-to-end in CI: the `macos-interop` job runs `bgp_kernel_install.sh` against the real FIB |
| Windows | `lr-osroute::windows::IpHelper` | end-to-end in CI: the `windows-interop` job runs `bgp_kernel_install.sh` and the kernel-gated `windows_route_table` suite; `windows-fib-probe.yml` re-runs those tests one job per test |
| FreeBSD, NetBSD, OpenBSD | `lr-osroute::bsd::RouteSocket` | compile-time layout constants pinned against each system's `sys/net/route.h`; no CI target builds them |
| anything else | `lr-osroute::stub::StubRouteTable` | compile-only: `connect()` and every mutation return an error, `list_routes()` returns an empty table |

## Linux — rtnetlink (`linux.rs`)

A `NETLINK_ROUTE` socket speaks the rtnetlink message set (RFC 3549):
an add is `RTM_NEWROUTE` carrying a `struct rtmsg` header plus the
`RTA_DST`, `RTA_GATEWAY`, `RTA_OIF` and `RTA_PRIORITY` attributes, and a
dump is `RTM_GETROUTE` with `NLM_F_DUMP`. The backend declares the five C
entry points it needs (`socket`, `bind`, `sendmsg`, `recv`, `close`)
instead of taking a dependency on a netlink crate.

Adds carry `NLM_F_CREATE | NLM_F_REPLACE`, so a missing route is created
and an existing best route for the prefix is replaced atomically. When
`if_index` is zero the backend omits `RTA_OIF` (the kernel rejects a
zero index with `EINVAL`) and the kernel resolves the egress interface
from the gateway, the way `ip route add ... via GW` does. A blackhole add
sends `RTN_BLACKHOLE` with neither gateway nor output interface; the
delete path sends `RTN_UNSPEC`, because a delete naming `RTN_UNICAST`
never matches a blackhole row.

`add_route` delegates to `add_route_tagged` with `Protocol::Bgp`. The tag
becomes the kernel's `RTPROT_*` value (`RTPROT_BGP`, `RTPROT_OSPF`,
`RTPROT_BABEL`, `RTPROT_STATIC`), which is what `ip route show` prints as
the route's origin. Dumps map that field back to `lr_core::rib::Protocol`
so administrative-distance comparison works.

## BSD and macOS — `route(4)` socket (`bsd.rs`)

All four BSDs expose the FIB through a `PF_ROUTE` socket: messages are a
versioned `struct rt_msghdr` followed by the sockaddrs selected by the
`rtm_addrs` bitmask, and a table dump is
`sysctl(CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0)`.

`struct rt_msghdr` drifted between the systems, so compile-time constants
pin the header size, the version byte, the family number and the field
offsets, each against that system's `sys/net/route.h`:

| OS | header size | `RTM_VERSION` | `AF_INET6` | quirk |
| --- | ---: | ---: | ---: | --- |
| FreeBSD | 152 | 5 | 28 | `_rtm_spare1`, `rtm_fmask` |
| OpenBSD | 96 | 5 | 24 | `rtm_hdrlen` must be filled in |
| NetBSD | 120 | 4 | 24 | `__align64` members |
| macOS | 92 | 5 | 30 | classic 4.4BSD layout |

Sockaddrs inside a message are padded to a multiple of `sizeof(long)`,
so `sockaddr_in` stays 16 bytes and `sockaddr_in6` grows from 28 to 32.
Replies are matched on `rtm_seq`, which skips unrelated asynchronous
route-change notifications, and `SO_RCVTIMEO` bounds every read.

Installs carry `RTF_STATIC` so an operator can tell a librouting route
from a kernel, RA or DHCP one; the blackhole form carries
`RTF_BLACKHOLE`. The backend ignores `if_index` — the routing socket
derives the interface from the gateway — and treats `EEXIST` on add and
`ESRCH` on delete as success, so a reconciliation loop is idempotent. A
`route(4)` dump exposes no per-route protocol origin, so `list_routes`
reports `Protocol::Other(0)` and the backend keeps the trait's default
`add_route_tagged`.

## Windows — IP Helper API (`windows.rs`)

Windows' FIB lives behind `iphlpapi.dll`, reached through `windows-sys`:

- `CreateIpForwardEntry2` and `DeleteIpForwardEntry2` modify rows
  described by `MIB_IPFORWARD_ROW2`; `GetIpForwardTable2` snapshots the
  table and `FreeMibTable` releases the buffer.
- `InitializeIpForwardEntry` zeroes a row. It also leaves the
  undocumented `Loopback` flag set on audited builds, so the backend
  clears it explicitly: a row delivered through the loopback interface is
  local delivery under the weak host model, and a daemon listening on
  `0.0.0.0` would answer traffic for the covered prefix.
- `MIB_IPFORWARD_ROW2.Protocol` carries the origin tag — `RouteProtocolBgp`
  for BGP, `RouteProtocolOspf` for OSPFv2 and OSPFv3, `RouteProtocolRip`
  for Babel, `RouteProtocolNetMgmt` for static and connected — which is
  what `route print` shows.
- When `if_index` is zero, `GetBestRoute2` resolves the interface for
  that next hop using the stack's own policy and interface metrics. Pass
  the egress interface when you know it: the resolution is a
  longest-prefix lookup over the current FIB, so a next hop that is
  on-link only on the protocol's own interface can resolve to an
  unrelated adapter.
- Deletes consult an install ledger of `(prefix, next hop, if index)`
  rows this instance created and remove exactly those. Only for a prefix
  the ledger has never seen — a fresh process cleaning up a predecessor's
  routes — do they fall back to removing every protocol-tagged row for
  the prefix. Rows this library did not create are never touched.
- Windows has no discard route type. A loopback gateway is rejected with
  `ERROR_INVALID_PARAMETER`, and every loopback-delivery form is the
  weak-host trap above. The backend installs the platform's null-route
  convention instead: an on-link row on a real egress interface, so the
  stack fails to resolve the covered destination as a neighbour and the
  traffic dies as host-unreachable. Nothing is forwarded and nothing
  loops, which is what an aggregate anchor needs; the difference from
  Linux's silent `RTN_BLACKHOLE` is invisible to routing correctness.

Routes installed this way are not boot-persistent, and modifying the
table needs elevation. `lr-daemon` re-installs its best paths whenever
the RIB converges.

## Writing a backend for another system

Implement `OsRouteTable`. That is the whole contract:

```rust
pub trait OsRouteTable {
    type Error: std::error::Error;

    fn add_route(
        &mut self,
        prefix: Prefix,
        next_hop: IpAddr,
        if_index: u32,
    ) -> Result<(), Self::Error>;

    fn add_route_tagged(
        &mut self,
        prefix: Prefix,
        next_hop: IpAddr,
        if_index: u32,
        protocol: Protocol,
    ) -> Result<(), Self::Error>;

    fn add_blackhole_route(&mut self, prefix: Prefix) -> Result<(), Self::Error>;

    fn delete_route(&mut self, prefix: Prefix) -> Result<(), Self::Error>;

    fn list_routes(&mut self) -> Result<Vec<KernelRoute>, Self::Error>;

    fn has_route(&mut self, prefix: Prefix) -> Result<bool, Self::Error>;
}
```

The default `add_route_tagged` drops `protocol` and calls `add_route`;
override it only if the system can carry a route origin. `has_route` has
a default implementation over `list_routes`.

Guidelines distilled from the three in-tree backends:

1. Use authoritative layouts. A direct syscall surface is reasonable
   where the ABI is stable and unit-testable from synthetic messages;
   for SDK-defined structures prefer generated vendor bindings so the
   layouts cannot drift.
2. Make both mutations idempotent. Route daemons reconcile in loops:
   re-adding an installed route and deleting a missing one must both
   succeed. Linux gets this from `NLM_F_CREATE | NLM_F_REPLACE`, the
   BSDs from treating `EEXIST` and `ESRCH` as success, Windows from its
   already-exists branch.
3. Scope your deletes. Remove only rows your implementation created —
   Linux `RTPROT_*`, Windows protocol-tagged rows, BSD `RTF_STATIC` —
   and never a kernel, RA or DHCP-learned row.
4. Report provenance. Map the OS route-origin field to
   `lr_core::rib::Protocol` in `list_routes()` so cross-protocol
   administrative-distance comparison works. If the system carries no
   such field, say so in a doc comment and return `Protocol::Other`.
5. Bound every syscall. A blocking read needs a timeout; the BSD backend
   sets `SO_RCVTIMEO` for exactly this reason.
6. Pin the layout. Cite the authoritative header in the doc comment,
   keep the observed size and field offsets in named constants, and
   assert them from a unit test (`assert_eq!(size_of::<T>(), N)`), the
   way `lr-osroute::tcp_auth` pins its socket-option structs.

Register the backend in `lib.rs`: add the module, the `RtNetlink` and
`SystemRouteTable` aliases for the new target, and a `PLATFORM_NAME`
constant.

## Testing a backend

- **Unit tests** in the module build synthetic messages and assert they
  parse, and check row construction and interface resolution.
- **Kernel-gated tests** under `crates/lr-osroute/tests/` exercise a real
  kernel table and are `#[ignore]`d so an unprivileged host skips them:
  `route_kernel.rs` (netlink round trips), `srv6_kernel.rs`,
  `ospf6_kernel.rs` and `windows_route_table.rs`. CI runs them in a
  rootless user and network namespace on Linux, and natively on the
  Windows runner.
- **Interop**: `lr-daemon --install-kernel-routes` against any peer, then
  read the table back with the platform's own tool — `ip route`,
  `netstat -rn`, `route -n get`, `route.exe print` or `Find-NetRoute`.
  `tests/interop/bgp_kernel_install.sh` is the shared script and the
  shape both the macOS and Windows CI jobs follow.
- **Cross-compile check** for a target you cannot run: `cargo check -p
  lr-osroute --target x86_64-unknown-freebsd`. It catches cfg and layout
  mistakes, not behaviour.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `socket(AF_NETLINK): Permission denied` | sandboxed container | run privileged, or keep `install = false` |
| `RTM_ADD ...: Operation not permitted` | not root on a stock BSD | elevate the daemon |
| `CreateIpForwardEntry2 failed: error 5` | Windows without elevation | run elevated |
| add reports "file exists" | the reconciler re-added a row | treat the already-exists code as success |
