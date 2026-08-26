# librouting Architecture

This document describes the layering, data flow, and extension points of
`librouting`. It is the canonical reference for new contributors and
embedders.

## High-level layout

```
+----------------+    +----------------+    +----------------+
|   lr-bgp       |    |   lr-ospf      |    |   lr-babel     |
| (RFC 4271 +    |    | (RFC 2328 /    |    | (RFC 8966 +    |
|  extensions)   |    |  RFC 5340)     |    |  RFC 9079)     |
+-------+--------+    +-------+--------+    +-------+--------+
        |                     |                     |
        +---------------------+---------------------+
                              |
                              v
                    +---------------------+
                    |   lr-router         |    <- orchestrator
                    |   (DefaultRouter)   |
                    +----------+----------+
                               |
            +------------------+------------------+
            |                  |                  |
            v                  v                  v
    +---------------+   +---------------+   +----------------+
    |   lr-rib      |   |   lr-policy  |   |   lr-bfd       |
    | (Adj-RIB-In, |   | (route-maps, |   | (peer failure  |
    |  Loc-RIB,    |   |  prefix lists,|  |  detection)    |
    |  Adj-RIB-Out)|   |  AS filters,  |   +----------------+
    +-------+------+   |  safety net)  |
            |          +-------+-------+
            |                  |
            v                  v
            +------------------+
            |   lr-osroute    |  <- optional OS kernel interface
            | (Linux rtnetlink)
            +------------------+
```

All crates depend on `lr-core` for shared primitives (`IpAddr`, `Prefix`,
`Asn`, `RouterId`, `Route`, `Attributes`, codec traits, FSM/timer traits).
`lr-ffi` exposes a C ABI; Go/Python/C++ bindings sit on top.

## Three-layer API

Every protocol crate is structured so embedders can stop at the right level
of abstraction:

| Layer | Description                                    | Example API           |
|-------|------------------------------------------------|------------------------|
|   1   | Pure codec — encode/decode wire bytes         | `BgpCodec`, `BfdCodec` |
|   2   | Protocol FSM — state machine driving actions  | `BgpPeer::step`        |
|   3   | Orchestrator — wires sessions + RIB + timers  | `DefaultRouter`       |

Layer 1 is for analyzers (pcap processors, route collectors).
Layer 2 is for embedders that own their event loop but want protocol logic.
Layer 3 is for embedders that just want "run BGP for me" and get Loc-RIB
deltas back.

## RIB pipeline

```
inbound bytes  →  decode  →  SafetyNet.check  →  ImportHooks  →  AdjRibIn
                                                                ↓
                                              BestPath.select  ← (per-protocol)
                                                                ↓
                                                              LocRib
                                                                ↓
                                            ExportHooks  ←  AdjRibOut  →  outbound bytes
                                                                ↓
                                              OsRouteTable.add_route  (optional)
```

Each stage is replaceable via traits:
- `ImportHook` / `ExportHook` — arbitrary Rust code that may drop or mutate
  routes.
- `SelectionHook` — override the comparator (e.g. prefer routes from a
  specific peer).
- `OsRouteTable` — platform abstraction for the kernel FIB.

## Extension points

| Hook trait            | Stage             | Crate      |
|-----------------------|-------------------|------------|
| `ImportHook`          | post-decode       | lr-policy  |
| `SelectionHook`       | best-path         | lr-policy  |
| `ExportHook`          | pre-encode        | lr-policy  |
| `SafetyNet`           | post-decode       | lr-policy  |
| `OsRouteTable`         | kernel install    | lr-osroute |

## BGP topology

A `PeerTopology` carries the relationship of the local speaker to the peer:

- `role`: `Ebgp` / `Ibgp` / `ConfederationExternal` / `ConfederationInternal`
- `rr_client`: true if this peer is a route-reflector client (RFC 4456)
- `rs_client`: true if this peer is a route-server client (RFC 7947)
- `otc`: RFC 9234 role (`Provider` / `Customer` / `Peer` / `RouteServer` /
  `RsClient`)

The topology drives AS_PATH mutation, NEXT_HOP rewriting, and reachability
checks (`can_advertise()` enforces iBGP full-mesh + RR rules + OTC
valley-free).

## Best-path comparator

`lr-bgp::best_path::BestPath` implements RFC 4271 §9.1.2 with extensions:

1. Weight (vendor-specific; set via policy).
2. LOCAL_PREF (iBGP only; eBGP approximated as 100).
3. AS_PATH length (counting AS_CONFED_SEQUENCE per RFC 6793).
4. ORIGIN (IGP < EGP < INCOMPLETE).
5. MED (only when same neighboring AS, unless `always_compare_med`).
6. eBGP over iBGP (unless `prefer_externals=false`).
7. Lowest IGP metric to NEXT_HOP (caller-supplied).
8. NEXT_HOP equal to peer address.
9. Oldest route (only when `deterministic_router_id=false`).
10. Lowest ORIGINATOR_ID (RFC 5004 deterministic).
11. Shortest CLUSTER_LIST (RFC 4456).
12. Lowest peer IP / peer-id (last resort).

Multipath (`multipath()`) collects all routes that tie on steps 1–11 (the
final peer-id tiebreaker is by definition different for different peers).
`multipath_relax=true` allows mixing neighbors.

## OS routing table reference

`lr-osroute` provides:

- **Trait**: `OsRouteTable` — `add_route()`, `delete_route()`, `list_routes()`.
- **Reference impl**: `linux::RtNetlink` — speaks raw rtnetlink over
  `AF_NETLINK` sockets. Builds `RTM_NEWROUTE` / `RTM_DELROUTE` messages with
  `RTA_DST` / `RTA_GATEWAY` / `RTA_OIF` / `RTA_PRIORITY` attributes.
- **Stub**: `StubRouteTable` — for platforms without rtnetlink or for tests.

The crate is **opt-in** because it performs FFI and requires privileges.
Embedders running inside a sandbox can omit it entirely.

## BFD integration

`lr-bfd` is fully independent — it doesn't depend on `lr-bgp` or any other
protocol crate. BGP can register a BFD session per peer; when BFD signals
"Down", BGP tears down the peer without waiting for the hold timer (typical
sub-second detection vs. 90s for BGP-only keepalives).

## Damping integration

`lr-damping` implements RFC 2439 route flap damping. It is *opt-in* and
**deprecated by RFC 8326** for BGP. Use it for OSPF / Babel where there is
no AS_PATH loop detection to absorb transient flaps, or as a
defensive-safety mechanism during incidents.

## FFI and bindings

- `lr-ffi` exposes a C ABI. `cbindgen` generates `include/lr_ffi.h`.
- `bindings/lr-go` — cgo wrapper with `runtime.SetFinalizer` cleanup.
- `bindings/lr-python` — cffi loader with `Router` context manager.
- `include/librouting.hpp` — header-only C++ wrapper (RAII, throwing
  wrappers).

The C ABI surface is intentionally minimal: opaque handle (`lr_router_t`),
`lr_router_*` lifecycle functions, `lr_bytes_t` for byte buffers,
thread-local `lr_last_error()` for error strings.

## Feature flags

Each crate exposes `default` features that are sensible for typical
embedders. Notable toggles:

- `lr-core` — `std` (default) / `no_std` (for embedded analyzers).
- `lr-bgp` — `asn4` / `mp_bgp` / `addpath` / `graceful_restart` /
  `enhanced_rr` / `extended_communities` / `long_lived`.
- `lr-bfd` — `std` / `no_std`.

## Testing

- Unit tests live alongside the source (`#[cfg(test)]` modules).
- End-to-end tests live in `crates/lr-tests`:
  - `tcp_smoke.rs` — two librouting BGP peers exchange OPEN+KEEPALIVE over
    real TCP.
  - `bird/` — Dockerfile + bird.conf for interop with the BIRD reference
    router (CI runs when Docker is available).
- Total: 130+ tests across 11 crates.

## CI/CD

`.github/workflows/`:
- `ci.yml` — fmt + clippy + tests + C harness + Go + Python + MSRV + cross
- `nightly.yml` — miri for unsafe audit
- `release.yml` — cross-compiled binaries + cargo publish

## License

`MIT OR Apache-2.0` per crate. No GPL/AGPL components.
