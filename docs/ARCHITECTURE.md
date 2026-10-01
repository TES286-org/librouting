# librouting architecture

This page describes how the crates under `crates/` fit together, how a
route travels through the pipeline, and where an embedder can intervene.
Read it if you are adding a protocol, registering a policy hook, or
deciding how much of the library to use.

The code is the source of truth. Every section below names the file or
type that settles a disagreement.

## Crate layering

```
        lr-bgp    lr-ospf   lr-babel   lr-ldp    lr-bfd   lr-bmp
           \         |         |         /          |        /
            \        |         |        /           |       /
             +-------+---------+-------+            |      /
                     |                              |     /
                     v                              v    v
              +---------------+              +---------------+
              |  lr-router    |              |   lr-ffi      |
              | DefaultRouter |              |  (C ABI)      |
              +-------+-------+              +---------------+
                      |
        +-------------+-------------+----------------+
        |             |             |                |
        v             v             v                v
   +---------+  +-----------+  +---------+   +--------------+
   | lr-rib  |  | lr-policy |  | lr-mrt  |   | lr-osroute   |
   | RIBs    |  | hooks,    |  | dumps   |   | kernel FIB,  |
   |         |  | filter DSL|  | (RFC    |   | MPLS, SRv6,  |
   |         |  |           |  |  6396)  |   | transport    |
   +---------+  +-----------+  +---------+   +--------------+
        \             |             /               |
         \            |            /                |
          +-----------+-----------+-----------------+
                              |
                              v
                          +--------+
                          |lr-core |
                          +--------+
```

`lr-core` is the base and depends on no other workspace crate. Every
arrow is a real `[dependencies]` edge in the crate's `Cargo.toml`; the
list below is the per-crate expansion of the picture, including the
optional edges the diagram omits.

| Crate | Depends on |
| --- | --- |
| `lr-core` | — |
| `lr-mpls` | `lr-core` |
| `lr-srv6` | `lr-core` |
| `lr-damping` | `lr-core` |
| `lr-bfd` | `lr-core` |
| `lr-ldp` | `lr-core` |
| `lr-rib` | `lr-core` |
| `lr-bgp` | `lr-core`, `lr-mpls` (`labeled_unicast`) |
| `lr-babel` | `lr-core` |
| `lr-ospf` | `lr-core` |
| `lr-mrt` | `lr-core`, `lr-bgp` (`bgp`) |
| `lr-bmp` | `lr-core`, `lr-bgp` |
| `lr-policy` | `lr-core`, `lr-bgp` (`bgp`), `lr-damping` (`damping`) |
| `lr-router` | `lr-core`, `lr-bgp`, `lr-ospf`, `lr-babel`, `lr-rib`, `lr-policy`, `lr-bmp`, `lr-mpls` |
| `lr-osroute` | `lr-core`, `lr-mpls`, `lr-srv6` |
| `lr-ffi` | `lr-core`, `lr-bgp`, `lr-ospf`, `lr-babel`, `lr-rib`, `lr-policy`, `lr-damping`, `lr-router`, `lr-mpls`, `lr-srv6` |
| `lr-cli` | all of the above except `lr-srv6`, plus `lr-bfd`, `lr-ldp`, `lr-mrt` |
| `lr-tests` | `lr-core`, `lr-bgp`, `lr-ospf`, `lr-babel`, `lr-rib`, `lr-policy`, `lr-router`, `lr-osroute`, `lr-bmp`, `lr-mpls` |

Where a crate's role is not obvious from its name: `lr-bgp` carries the
RFC 8277 labelled-unicast codec that consumes `lr-mpls`
(`crates/lr-bgp/src/path/labeled_nlri.rs`), and `lr-osroute` consumes
`lr-mpls` and `lr-srv6` for its kernel MPLS and seg6 backends
(`crates/lr-osroute/src/mpls_route.rs`,
`crates/lr-osroute/src/seg6_route.rs`). `lr-ldp` defines its own
`GenericLabel` in `crates/lr-ldp/src/tlv.rs` and does not depend on
`lr-mpls`.

### Which crates stand alone

Everything except `lr-cli` is a library, and the codec crates carry no
I/O and no runtime.

- `lr-core` — addresses, codec/FSM/timer traits, the error model. An
  analyzer that wants only those primitives takes this crate and
  nothing else. It is the one crate with a working `no_std` mode
  (`#![cfg_attr(not(feature = "std"), no_std)]`), and the timer queue
  needs `alloc` (`crates/lr-core/src/lib.rs`).
- `lr-bgp`, `lr-ospf`, `lr-babel` — codec plus FSM, on `lr-core` only.
  Use them if you own the event loop, the sockets and the RIB.
  `lr-bgp`'s `labeled_unicast` feature is the one addition, and it
  pulls in `lr-mpls`.
- `lr-mpls`, `lr-srv6`, `lr-damping`, `lr-bfd`, `lr-ldp` — single
  concern, `lr-core` only. `lr-mpls`, `lr-srv6` and `lr-ldp` declare a
  `no_std` feature; `lr-bfd` and `lr-damping` declare `std` only, and
  every one of them also forwards `std` to `lr-core`.
- `lr-rib`, `lr-policy` — usable without `lr-router`. `lr-policy`
  gates its BGP-aware evaluation behind its `bgp` feature and the
  RFC 2439 damping hook behind `damping`.
- `lr-osroute` — opt-in. It performs FFI, needs privileges for the
  kernel backends, and offers `StubRouteTable` for platforms without
  one.
- `lr-router` — the whole pipeline. Everything below it also works
  without it.

## Three-layer API

Every protocol crate is built so an embedder can stop at the right
level of abstraction:

| Layer | What it is | Example |
| --- | --- | --- |
| 1 | Stateless wire codec — bytes in, message out | `lr_bgp::BgpCodec`, `lr_bfd::BfdCodec` |
| 2 | Peer FSM over a transport abstraction | `lr_bgp::BgpPeer::step` |
| 3 | Orchestrator that owns sessions, timers and the RIB | `lr_router::DefaultRouter` |

Layer 1 suits analyzers such as pcap processors and route collectors.
Layer 2 suits embedders that own the event loop but want the protocol
logic. Layer 3 suits embedders that want the router to run and report
Loc-RIB deltas.

## RIB pipeline

`lr_router::DefaultRouter` (`crates/lr-router/src/instance.rs`)
implements the pipeline end to end:

```text
inbound bytes
  -> BgpPeer::feed_bytes -> InstallRoute / WithdrawRoute actions
  -> SafetyNet::check            (AS loop, martian, next-hop sanity)
  -> HookChain::run_import       (import hooks)
  -> AdjRibIn
  -> reselect
       BGP-only candidates -> BestPath::rank  (RFC 4271 §9.1.2)
       mixed candidates    -> RouteSelector::select
  -> LocRib -> RouterEvent::RouteInstalled / RouteWithdrawn
  -> export_selection
       egress rules -> HookChain::run_export_to -> AdjRibOut
  -> BgpPeer::advertise -> outbound bytes
  -> OsRouteTable::add_route     (optional, lr-daemon)
```

Withdrawals run the same pipeline in reverse: the session reports
`WithdrawRoute`, the Adj-RIB-In entry goes away, `reselect` re-runs for
that key, and peers that previously received the route get a wire
withdrawal.

## Router instance internals

`DefaultRouter` is the Layer 3 orchestrator. Every cross-protocol
concern lives on one struct that the embedder drives through the
poll-based `RouterInstance` trait (`crates/lr-router/src/instance.rs`):
sessions, Adj-RIBs, Loc-RIB, policy hooks, redistribution, aggregates,
MRAI, Graceful Restart, maximum-prefix, OSPF areas and virtual links,
and the Babel runtime. The doc comment on each field is the
authoritative reference.

### `DefaultRouter` shape

The struct holds four kinds of state:

| Kind | Fields |
| --- | --- |
| Per-session runtime | `sessions: BTreeMap<u64, SessionState>`, `mrai`, `graceful_restart`, `llgr_caps`, `max_prefix_state`, `collision_meta`, `session_policy` |
| Loc-RIB and Adj-RIBs | `adj_rib_in`, `pre_policy_adj_rib_in`, `adj_rib_out`, `loc_rib`, `originated`, `static_routes`, `direct_rib`, `redistributed_bgp` |
| Cross-protocol OSPF | `ospf_areas`, `ospf_published`, `ospf_externals`, `ospf_v3_externals`, `ospf_v3_external_lsids`, `ospf_v3_summary_lsids`, `ospf_translations`, `ospf_vlinks`, `ospf_grace_seen`, `ospf_grace_events` |
| Cross-protocol misc | `pipes`, `aggregates`, `bmp_sink` |

`pre_policy_adj_rib_in` backs soft reconfiguration inbound: it keeps the
pre-policy copy of each path so an import-policy change can be replayed
without a route refresh.

`add_session` mints a monotonic `u64` handle. Every per-session
`BTreeMap` is keyed on that handle, so a session teardown removes its
slot from all of them in one sweep.

`SessionState` is an `enum` with one variant per protocol — `Bgp`,
`Ospf`, `Babel` — each holding the per-session FSM, a `MemoryConn` (the
output buffer the embedder drains with `drain_output`), and a
protocol-specific runtime.

### Per-protocol runtime structs

- **`OspfRuntime`** — one OSPF adjacency: the neighbor FSM, a streaming
  `OspfCodec`, the `DbExchange` driver (RFC 2328 §7.2 DD/LSR
  sequencing), the segment identity pair (`our_ip` / `neighbor_ip` /
  `dr` / `bdr`, the §10.4 adjacency gate), and the interface
  `network_type` plus `iface_mtu` needed to rebuild the exchange after a
  §10.4 demotion resets the adjacency.

- **`OspfAreaState`** — the per-area LSDB, the area type policy
  (`OspfAreaType`: stub, NSSA or totally stubby, which drives the §3.6
  and RFC 3101 LSA acceptance gate), and a monotonic `topology_version`
  bumped on every _content_ topology change (RFC 3623 §3.2 (3)).
  Embedders use `topology_version` to terminate Graceful-Restart helper
  mode when the topology actually moves; periodic refreshes that only
  bump age or sequence do not increment it.

- **`BabelRuntime`** — one Babel adjacency: the neighbor table, the
  route table, a streaming `BabelCodec`, the current `next_hop` learned
  from NextHop TLVs (RFC 8966 §4.6.4), the peer's 8-byte `router_id`,
  and a `published` snapshot of what the runtime has already pushed to
  Loc-RIB. `diff()` is the bridge to Loc-RIB: every Hello, IHU or
  Update TLV mutates the route table, and `diff()` computes the
  installed and withdrawn delta against `published` so the router emits
  one `RouterEvent` per actual route change.

- **`RuntimeDelta`** — the return shape of one protocol-runtime step:

  ```rust
  struct RuntimeDelta {
      installed: Vec<Route>,
      withdrawn: Vec<RouteKey>,
      withdraw_reason: String,
  }
  ```

  `withdraw_reason` is human-readable and empty when the delta carries
  installs only; `apply_runtime_delta` surfaces it as one
  `RouterEvent::Log` so an operator can tell an expiry from a
  retraction. `apply_runtime_delta` installs the delta directly into
  Loc-RIB without the Adj-RIB-In pipeline: OSPF and Babel are trusted
  sources, and their routes are kept in `direct_rib` so a BGP
  re-ranking of a shared key never evicts them.

The Babel runtime state is session-scoped, so there is no top-level
`babel_*` field on `DefaultRouter`. The OSPF surface is area-scoped and
therefore top-level.

### Loc-RIB contributions

Loc-RIB itself lives in `lr_rib::loc_rib::LocRib`. Four sibling maps in
`DefaultRouter` carry the contributions the decision process must
consult alongside `adj_rib_in`:

1. **`originated: BTreeMap<RouteKey, Route>`** — locally originated
   routes (BIRD `protocol direct`, FRR `network` statements). Kept so
   `unoriginate` can remove them and a config reload can diff old
   against new.
2. **`static_routes: BTreeMap<RouteKey, Route>`** — operator-configured
   static routes. Same reload-diff contract as `originated`.
3. **`direct_rib: BTreeMap<RouteKey, Route>`** — protocol-direct
   contributions from the OSPF and Babel runtimes. These never enter
   BGP advertisements; cross-protocol export stays opt-in through
   `pipes` (FRR `redistribute`, BIRD `pipe`).
4. **`redistributed_bgp: BTreeMap<RouteKey, Route>`** — routes this
   router has redistributed into BGP through a pipe. The re-originated
   copy keeps the source route's peer so the export split horizon
   (RFC 4271 §9.1.3 Phase 3) never re-advertises it to the session it
   came from. The copy competes with the peer's Adj-RIB-In paths for
   the Loc-RIB slot through the decision process.

`reselect(key)` merges those sources and picks the Loc-RIB best for one
prefix:

1. Collect every candidate for `key` from `adj_rib_in`, `originated`
   and `direct_rib`. The redistributed BGP copy is already in
   `adj_rib_in`-compatible form, because the pipe arm of
   `redistribute_route` produced it.
2. If every candidate is BGP, run `BestPath::rank` (RFC 4271 §9.1.2)
   and take `add_path_max_paths` of the result (RFC 7911). Otherwise
   run `RouteSelector::select`, the admin-distance plus metric
   comparator for non-BGP protocols.
3. Hand the ranking to `apply_selection`, which installs the new set
   into `loc_rib`, emits `RouteInstalled` and `RouteWithdrawn`, recurses
   into `redistribute_route` so a new best propagates through pipes, and
   calls `export_selection` so the ranking reaches every BGP session.

### Export hook ordering

`export_selection(key, ranked)` walks every established BGP session and
computes a per-session advertise/withdraw delta. Every later stage sees
only the routes that survived the earlier ones:

1. **iBGP split horizon, route reflection, OTC** (RFC 4271 §9.1.3
   Phase 3, RFC 4456, RFC 9234 §5): a path learned from a session is
   never re-advertised to that same session, and the role, RR and RS
   topology gates which sessions a path may reach at all.
2. **Protocol gate**: `direct_rib` routes from OSPF and Babel never
   enter BGP advertisements. Only BGP routes are eligible for the BGP
   Adj-RIB-Out.
3. **RFC 8212 §3**: an external session with no explicit export policy
   must not carry routes in its Adj-RIB-Out. The desired set stays
   empty, so the diff against Adj-RIB-Out withdraws anything the
   session still advertises.
4. **Export hook chain** (`HookChain::run_export_to`): the surviving
   candidates pass through every registered `ExportHook`, which may
   drop a route, modify it, or set attributes on it.
5. **Add-Path against single-path** (RFC 7911): Add-Path TX peers
   receive each path under a transmit identifier of `rank slot + 1`;
   single-path peers receive only the best path.
6. **Diff against Adj-RIB-Out**: the desired set is diffed against the
   session's `adj_rib_out` view. Paths that fell out of the ranking, or
   that are no longer exported, become withdrawals; new and changed
   paths become UPDATEs.

The hook chain borrows `&self` while session enumeration needs
`&mut self`, so the export pipeline runs in two phases: collect the
policy-approved work per session with `export_work_for` (a `&self`
method), then transmit. `export_selection` restores the hook chain
between the passes.

### MRAI and the per-prefix advertisement queue

The MRAI timer (RFC 4271 §9.2.1.1) is per destination, not per session:
`MraiState.last_sent` and `MraiState.pending` are keyed by `RouteKey`,
so a busy peer never delays unrelated routes. A pending set supersedes
any older pending set, so route churn collapses to the final state at
MRAI expiry. Withdrawals bypass MRAI and are transmitted immediately
(RFC 4271 §9.2.2).

### Redistribution tracking

`redistribute_route(route)` runs from `apply_selection` after every
Loc-RIB best change:

1. **Terminate the feedback loop.** If a stored copy already exists
   with identical protocol, origin, preference, attributes and
   `next_hop`, the function returns. This equality check is the
   fixpoint that ends the `apply_selection` → `redistribute_route`
   cycle when the re-originated copy is itself the Loc-RIB best and
   matches its own pipe. Without it, an additive metric policy
   (`MetricPolicy::Add(N)`) produces a copy that never compares equal to
   the stored one and the recursion does not terminate.
2. **Collect matching pipes.** A pipe matches when
   `pipe.source == route.protocol` and `pipe.matches(prefix)`. OSPF
   pipes call `ospf_redistribute`; BGP pipes re-originate the route as
   a BGP path and run the decision process to install it.
3. **Re-originate the BGP copy** with `origin.proto` set to the locally
   re-originated value (2), keeping the source route's `origin.peer` so
   the export split horizon never re-advertises it to the session it
   came from.
4. **Run the decision process** rather than a wholesale `install_set`:
   the best path by admin distance or the BGP decision process wins the
   Loc-RIB slot, and a beaten peer path stays in Adj-RIB-In to be
   restored when the winner disappears (RFC 4271 §9.1.2).

When the source route disappears, `unredistribute_route(key)` drops the
copy and `reselect(key)` runs again, restoring the next-best candidate.

### OSPF top-level state

The OSPF surface in `DefaultRouter` is the largest cross-protocol block
because OSPF is area-scoped, not session-scoped:

| Field | Purpose |
| --- | --- |
| `ospf_areas: BTreeMap<u32, OspfAreaState>` | per-area LSDB, type policy, `topology_version` |
| `ospf_published: BTreeMap<RouteKey, Route>` | routes currently published to Loc-RIB, diffed on every recompute |
| `ospf_externals: BTreeMap<u32, ExternalDestination>` | redistributed IPv4 destinations (RFC 2328 §12.4.3), keyed by LS ID |
| `ospf_v3_externals: BTreeMap<Prefix, V3ExternalDestination>` | redistributed IPv6 destinations (RFC 5340 §4.4.3.6) |
| `ospf_v3_external_lsids: BTreeMap<Prefix, u32>` | stable 0x4005 LS IDs, one per external prefix |
| `ospf_v3_summary_lsids: BTreeMap<u32, BTreeMap<Prefix, u32>>` | stable 0x2003 inter-area-prefix LS IDs per (area, prefix) |
| `ospf_translations: BTreeSet<(u32, u32, u32)>` | type-7 to type-5 translations this router maintains as an elected NSSA border router (RFC 3101 §3.2) |
| `ospf_vlinks: BTreeMap<(u32, u32), OspfVirtualLink>` | configured virtual links (RFC 2328 §15), keyed by transit area and endpoint router ID |
| `ospf_grace_seen: BTreeMap<(u32, u32), (u32, u16, u16, u16)>` | last seen Grace-LSA instance per (area, advertising router) |
| `ospf_grace_events: Vec<OspfGraceEvent>` | received Grace-LSA instances awaiting the embedder's helper-mode policy |

The LSDB is per area, not per session. LSAs flooded within an area
belong to the area, and every session attached to that area shares
them.

The stable-LS-ID maps exist because the OSPFv3 LS ID carries no
addressing semantics (RFC 5340 §4.4.3.4 and §4.4.3.6), so an ABR or
ASBR must keep a stable prefix-to-LS-ID mapping across re-origination.
FRR reuses the previous instance's LS ID, and so does lr.

The Grace-LSA dedup map keys on the RFC 2328 §13 instance identity
tuple `(sequence, age, checksum, length)` rather than on sequence alone:
a flush (MaxAge, empty body) and a fresh announcement can share a
sequence number at second boundaries of the wallclock-derived lineage
while being different LSAs.

## Extension points

| Trait | Stage | Crate |
| --- | --- | --- |
| `ImportHook` | after decode, before Adj-RIB-In | `lr-policy` |
| `SelectionHook` | during best-path selection | `lr-policy` |
| `ExportHook` | before Adj-RIB-Out encode | `lr-policy` |
| `SafetyNet` | after decode, before the import hooks | `lr-policy` |
| `OsRouteTable` | kernel install | `lr-osroute` |

The pipeline-stage doc comments in `crates/lr-policy/src/hooks.rs` are
the contract for the three hook traits. All of them require
`Send + Sync` and are synchronous: long-running work belongs on a
background task and reaches the route as a flag attribute.

### Registering a hook

`DefaultRouter::hooks_mut()` hands out the `HookChain`, whose `import`,
`selection` and `export` fields are public `Vec<Box<dyn …>>`
(`crates/lr-policy/src/hooks.rs`). Registration is a push:

```rust
use std::sync::{Arc, Mutex};
use lr_damping::DampingTable;
use lr_policy::hooks::DampingImportHook;
use lr_router::DefaultRouter;

let table = Arc::new(Mutex::new(DampingTable::new()));
let mut router = DefaultRouter::new();

// lr-policy's `damping` feature exposes DampingImportHook.
router
    .hooks_mut()
    .import
    .push(Box::new(DampingImportHook::new(Arc::clone(&table))));
```

The daemon does exactly this in `crates/lr-cli/src/daemon.rs`, keeping
its own `Arc` clone of the table so it can answer operational queries
about the same state the hook mutates.

Ordering rules worth knowing before writing a hook:

- Import hooks run in insertion order and a `HookVerdict::Drop`
  short-circuits the rest of the chain.
- `SelectionHook::compare` returns `Option<Ordering>`. The first hook
  that returns `Some` wins; returning `None` defers to the router's own
  comparator.
- Export hooks run in insertion order. `ExportHook::on_export_to`
  receives the destination session id, which is what per-peer export
  policy dispatches on; the default implementation ignores it and
  delegates to `on_export`.
- `ImportHook::on_withdraw` is a notification, not a filter. Fires
  after the route has left Adj-RIB-In, and the return value is ignored.
  The RFC 2439 damping table is fed from here.

## Thread model and mutability

`DefaultRouter` has no interior mutability: no `Cell`, `RefCell`,
`Mutex` or atomics among its fields. That is what makes the read/write
split meaningful.

- `&self` methods are genuinely read-only, so any number of threads may
  hold them at once. `rib_snapshot`, `session_peer_state` and the
  status views used by the runtime API are in this class.
- `&mut self` methods own every state transition: `add_session`,
  `feed_input`, `tick`, `reselect`, `apply_selection`,
  `apply_runtime_delta`, `redistribute_route`, and config reload.
- The daemon wraps the router in `Arc<RwLock<DefaultRouter>>`
  (`crates/lr-cli/src/daemon.rs`, `crates/lr-cli/src/api.rs`). Read
  locks serve API dumps and status; a write lock covers session setup,
  import, reselection, redistribution and reload. One writer at a time
  is the ceiling the lock imposes.

Hook traits carry `Send + Sync` because the daemon moves the router
across threads. A hook that needs shared state behind an `Arc` must
therefore make that state `Send + Sync` too.

## Error model

`lr_core::error` defines the whole surface
(`crates/lr-core/src/error.rs`):

- **Wire codecs** return `ParseError` or `EncodeError`, not the
  top-level type. `ParseError` carries an `ErrorKind`, the byte
  `offset` where parsing stopped, and a static `context` label such as
  `"bgp.open.capability[3].value"`. `ErrorKind::Truncated` is distinct
  from the other kinds on purpose: a decoder that returns `Truncated`
  is asking for more bytes, not rejecting the frame.
- **Library operations** return `lr_core::error::Result<T>`, whose
  error is `Error`. `Error` is one variant per subsystem — `Parse`,
  `Encode`, `Fsm`, `Config`, `Policy`, `Ffi`, `Other` — with `From`
  conversions from each, so a caller can use `?` across layers.
  `Other` exists only under `std`.
- **Sub-errors** are typed: `FsmError` names the state and event of a
  rejected transition, `ConfigError` distinguishes a missing key from a
  conflicting one, `PolicyError` a bad reference from a bad regex,
  `FfiError` a null pointer from a caught panic.
- **The `RouterInstance` trait returns `Result<_, String>`** for
  session-level operations, because the messages are meant for an
  operator and travel unchanged out to the FFI and the runtime API.

The C ABI never returns a Rust `Error`. `lr-ffi` wraps every entry
point in `catch_unwind`, converts a panic into `FfiError::PanicCaught`,
and records the message for `lr_last_error()`.

## Platform and protocol boundaries

`lr-bgp`, `lr-ospf`, `lr-babel`, `lr-ldp` and `lr-bfd` contain no
sockets and no OS calls. Everything platform-specific lives in
`lr-osroute`, which is opt-in:

- **Trait**: `lr_osroute::OsRouteTable` — `add_route`, `delete_route`,
  `list_routes`.
- **Linux**: `linux::RtNetlink` speaks raw rtnetlink over `AF_NETLINK`
  sockets and builds `RTM_NEWROUTE` / `RTM_DELROUTE` messages with
  `RTA_DST`, `RTA_GATEWAY`, `RTA_OIF` and `RTA_PRIORITY`.
- **BSD**: the `route(4)` socket backend.
- **Windows**: the IP Helper API backend.
- **Stub**: `StubRouteTable` for platforms without a backend and for
  tests.

The transport abstractions live there too — `lr-osroute::gtsm`,
`lr-osroute::tcp_auth`, `lr-osroute::bfd_transport`, and the raw-socket
OSPF transport. Embedders inside a sandbox can omit `lr-osroute`
entirely and drive the router directly.

BGPsec is deliberately out of scope. `docs/RELEASE-PLAN.md` §4.4 lists
the out-of-scope protocol items and `docs/STATUS.md` tracks the
capability gap.

## BFD integration

`lr-bfd` depends only on `lr-core`. It implements the RFC 5880 §6.8
state machine and its timing exactly: peer-multiplier detection time,
the negotiated transmit interval with jitter, and Poll/Final parameter
confirmation.

The sockets live in `lr-osroute::bfd_transport` — one shared receive
socket per (address, mode) on the well-known port (3784 single-hop per
RFC 5881, 4784 multihop per RFC 5883) with the single-hop TTL 255
filter, plus one transmit socket per session with an RFC 5881 §4
ephemeral source port.

`crates/lr-cli/src/daemon_bfd.rs` wires the two: one BFD session per
`bfd = true` peer. A BFD Up-to-Down transition tears the BGP session
down with a CEASE NOTIFICATION and a route purge, without waiting for
the BGP hold timer, and the connector holds off reconnecting while BFD
is down.

## Damping integration

`lr-damping` implements RFC 2439 route flap damping. It is opt-in and
off by default, because RFC 7196 documents that RFD with the RFC 2439
default parameters penalizes well-connected networks: each alternate
path explored during convergence re-triggers the penalty. The
configuration knobs include the RFC 7196 conservative settings.

Its router integration point is `DampingImportHook`, an `ImportHook`
(`crates/lr-policy/src/hooks.rs`) — not a selection-stage hook. It is
gated behind `lr-policy`'s `damping` feature.

## FFI and bindings

- `lr-ffi` exposes the C ABI. `cbindgen` generates `include/lr_ffi.h`
  from `build.rs`.
- `bindings/lr-go` — cgo wrapper with `runtime.SetFinalizer` cleanup.
- `bindings/lr-python` — cffi loader with a `Router` context manager.
- `include/librouting.hpp` — header-only C++ wrapper.

The C surface is deliberately small: an opaque `lr_router_t` handle, the
`lr_router_*` lifecycle functions, `lr_bytes_t` for byte buffers, and a
thread-local `lr_last_error()` string. `docs/ffi_design.md` covers the
panic barrier and the handle model.

## Feature flags

Each crate declares its own features in its `Cargo.toml` under
`[features]`; that file is the only current list, and
`cargo metadata` is the machine-readable view. The gates that change
which code compiles in a meaningful way are `lr-policy`'s `bgp` and
`damping` features, `lr-bgp`'s `labeled_unicast` and `exchange-plane`,
and `lr-mrt`'s `bgp`.

## Tests

The layers, and where each one lives:

- **Unit tests** sit next to the code in `#[cfg(test)] mod tests`.
- **Integration tests** sit in `crates/<crate>/tests/`. Cross-crate
  scenarios live in `crates/lr-tests/tests/`; daemon-level scenarios
  spawn the real `lr-daemon` from `crates/lr-cli/tests/`.
- **Interop labs** are the bash scripts in `tests/interop/`. They run
  against BIRD or FRR where the reference daemon is installed and
  against a second `lr-daemon` otherwise, and they skip cleanly when a
  reference daemon is absent. `docs/INTEROP.md` is the matrix and
  `tests/lint_interop_doc.sh` keeps the two in step.
- **Kernel-gated tests** need root and specific kernel modules. They are
  `#[ignore]`d by default and run under `tests/vm/run_vm.sh`.

`cargo nextest list --workspace --all-features` prints the live case
list. `.github/workflows/ci.yml` is the canonical list of which job runs
which layer, including the `abi-freeze` job that enforces the C ABI
half of the 1.0 freeze.

## CI and release

`.github/workflows/`:

- `ci.yml` — format, clippy, nextest, doc-tests, the C, C++, Go and
  Python binding harnesses, the interop labs, MSRV, cross builds, the
  native macOS and Windows runners, coverage, and `abi-freeze`. The
  interop steps are listed in the workflow itself; do not copy the list
  into a document.
- `nightly.yml` — `miri` (an undefined-behaviour audit over the FFI
  unsafe surface), `supply-chain` (`cargo audit` plus `cargo deny`),
  `vm-kernel-gated` (a QEMU VM with `CAP_NET_ADMIN` for TCP-AO, MPLS
  and SRv6), `fuzz` (the `cargo-fuzz` targets under `fuzz/`), and
  `bench-smoke` (a criterion smoke run).
- `docker.yml` — multi-stage Dockerfile build verification.
- `release.yml` — tag-driven cross-compiled binaries staging a GitHub
  Release. Publication to crates.io is a manual step.

## Best-path comparator

`lr_bgp::best_path::BestPath` implements RFC 4271 §9.1.2 with
extensions:

1. Weight (vendor-specific; set through policy).
2. LOCAL_PREF (iBGP only; eBGP is approximated as 100).
3. AS_PATH length. An AS_SET counts as 1 (RFC 4271 §9.1.2.2(a)) and
   confederation segments are not counted (RFC 5065 §5.3(3)) unless
   `count_confed_in_path_len`.
4. ORIGIN (IGP < EGP < INCOMPLETE).
5. MED, only when the routes share a neighboring AS, unless
   `always_compare_med`.
6. eBGP over iBGP, unless `prefer_externals = false`.
7. Lowest IGP metric to NEXT_HOP (caller-supplied).
8. NEXT_HOP equal to the peer address.
9. Oldest route, only when `deterministic_router_id = false`.
10. Lowest ORIGINATOR_ID (RFC 5004).
11. Shortest CLUSTER_LIST (RFC 4456).
12. Lowest peer IP or peer id.

`multipath()` collects every route that ties on steps 1 to 11, since the
final peer-id tiebreaker is by definition different for different peers.
`multipath_relax = true` allows mixing neighbors.

## BGP topology

A `PeerTopology` carries the relationship of the local speaker to the
peer:

- `role` — `Ebgp`, `Ibgp`, `ConfederationExternal`,
  `ConfederationInternal`.
- `rr_client` — true when the peer is a route-reflector client
  (RFC 4456).
- `rs_client` — true when the peer is a route-server client
  (RFC 7947).
- `otc` — the RFC 9234 role: `Provider`, `Customer`, `Peer`,
  `RouteServer` or `RsClient`.

The topology drives AS_PATH mutation, NEXT_HOP rewriting, and the
reachability check. `can_advertise()` enforces the iBGP full-mesh and
route-reflection rules plus OTC valley-free: a route carrying OTC may
only be advertised to Customers and RS-clients (RFC 9234 §5 egress
rule 2).

## Filter DSL

`lr_policy::filter` is a self-contained BIRD-style filter language. The
daemon refers to a filter by name from a peer's `import_filter` or
`export_filter` table, the FFI exposes `lr_filter_compile` and
`lr_filter_evaluate`, and an embedder can call `lr_policy::filter::compile`
directly. The subsystem is eight files under
`crates/lr-policy/src/filter/` — `lexer`, `parser`, `ast`, `eval`,
`bytecode`, `peephole`, `span` and `mod` — with a typed AST as the
contract between the parser and the two evaluators:

```
   source text
        |
        v
   lexer.rs         hand-rolled scanner: 1-char, 2-char and keyword
   (Token, Span)    tokens, each carrying its byte Span
        |
        v
   parser.rs        Pratt parser for expressions (parse_binary with
   (Filter)         operator precedence and a right-assoc fixpoint)
        |           plus recursive descent for statements; validates
        |           call targets up front
        |
        +----------------------+
        v                      v
   eval.rs                 bytecode.rs + peephole.rs
   tree-walking            flat Instr stream + peephole passes
   interpreter             (constant propagation, literal folding,
   (semantic oracle)       dead-branch elimination, jump threading,
                           BranchFieldIntCmp fusion)
        |                      |
        +----------+-----------+
                   v
         EvalResult (Accept / Reject(reason) / Fallthrough)
```

### AST

The AST root is
`Filter { name, body: FilterBody, functions: Vec<FunctionDecl>, line_index }`
with `FilterBody { stmts: Vec<Stmt> }`. `Stmt` carries the imperative
side (`If`, `Case`, `Let`, `Assign`, `AssignRouteField`,
`AppendRouteField`, `Expr`, `Block`, `Return`, `Accept`, `Reject`);
`Expr` carries the functional side (`Lit`, `Var`, `RouteField`, `Call`,
`Defined`, `Method`, `Binary`, `Unary`, `Set`, `PrefixSet`).

Every node owns its byte `Span`, but structural equality is span-blind:
the hand-written `PartialEq` ignores spans so the peephole golden tables
and the proptest oracles do not shift when the source is reformatted.

`RouteFieldKind` enumerates the settable attributes
(`bgp.local_pref`, `med`, `next_hop`, `communities`, `ext_communities`,
`large_communities`) and the read-only ones (`net`, `proto`, `source`,
`bgp.as_path`, `bgp.origin`, `roa.state`). The parser rejects
assignment to a non-settable field at compile time.

### Pratt parser

`parse_binary(min_prec)` is the precedence-climbing loop. It peeks the
next operator (`TokenKind::Plus` to `BinaryOp::Add`, and so on, plus
`Tilde` and `BangTilde` for `~` and `!~` membership), compares the
operator's `precedence()` against `min_prec`, advances, recurses with
the right-associative fixpoint (`prec` for right-associative operators,
`prec + 1` otherwise), and folds the result into an `Expr::Binary`.

Unary (`!x`, `-x`) and postfix (`.method(...)`) sit above the binary
loop; primaries (`Lit`, `Var`, `RouteField`, a parenthesized
expression, set literals, prefix-set literals) sit at the bottom.

A `validate_calls` pass runs after the body so every `Expr::Call` name
resolves either to a user-declared function or to a known built-in
(`len`, `bgp.first_as`, `bgp.contains`, …). The bytecode compiler relies
on that totality to resolve user calls to indices.

### Tree-walking evaluator

`eval::Evaluator<'a, C: FilterContext + ?Sized>` holds the scope stack
(`Vec<Scope>` of `BTreeMap<String, Value>`), the user functions, and a
call-depth counter capped at `MAX_CALL_DEPTH = 64`, so runaway recursion
surfaces as `CallDepthExceeded` rather than a thread-stack overflow.

The evaluator walks the AST statement by statement. The first `accept`
or `reject` short-circuits the whole filter, and `return` exits the
enclosing user function; an `accept` inside a function terminates the
whole filter, matching BIRD. `EvalResult::Fallthrough` is the
no-terminal-hit case the daemon falls back from, leaving the route to
the next route-map entry.

### FilterContext trait

The evaluator never touches a `Route` directly. It goes through
`FilterContext`, an interface of typed accessors
(`bgp_local_pref(&Route) -> Option<u32>`, …) plus mutators
(`set_bgp_local_pref(&mut Route, u32)`, …). Three consequences:

1. The DSL never collapses an absent attribute to its default.
   `Option<u32>` preserves "unset" against "set to zero", which is what
   BIRD's `defined()` semantics depend on. The `Defined` AST node is an
   unevaluated probe that goes through the typed presence check rather
   than a value read.
2. `DaemonFilterContext` and the FFI's C-callback context
   (`lr_filter_context_t`, 18 optional function pointers in
   `include/lr_ffi.h`, where NULL selects the built-in route-backed
   default) share one evaluator, so a C embedder's `bgp.local_pref`
   reads the same path the daemon does.
3. The in-place integer fast paths (`Attributes::get_u32_be`,
   `Attributes::get_u8`) live behind the trait, so the evaluator reads
   LOCAL_PREF, MED and ORIGIN without cloning the `Vec<u8>` attribute
   payload.

### Bytecode VM

`bytecode::compile` lowers the whole AST to a flat `Vec<Instr>` plus one
`Vec<Instr>` per user function. The daemon's `daemon_policy` module
precompiles every `[[filter]]` at startup so the import and export hot
loops run the VM.

The instruction set is small and flat: `Push`, `LoadVar`, `LoadField`,
`StoreVar`, `AssignVar`, `StoreTmp`, `LoadTmp`, `Bin`, `Not`, `Neg`,
`JumpIfFalse`, `JumpIfTrue`, `Jump`, `Truthy`, `Match`,
`BranchFieldIntCmp`, `Defined`, `Call`, `CallFn`, `Method`,
`AssignField`, `AppendField`, `Pop`, `PushScope`, `PopScope`, `Accept`,
`Reject`, `Return`, `EvalTree`. `EvalTree(Expr)` is the tree-walking
fallback for dynamic subtrees such as `defined()` on an arbitrary
expression, so the VM and the interpreter cannot diverge semantically.

An equivalence table holds both engines to the same verdict and the
same post-evaluation route state on every case it lists.
`vm_matches_interpreter_on_policy_table` covers the policy corpus and
`vm_matches_interpreter_on_bench_shapes` the bench-sized shapes; the
table is in `crates/lr-policy/src/filter/eval.rs`.

`peephole::optimize_with_spans` runs three passes inside `compile`:
constant propagation plus literal folding (tracks `let` constants, folds
`Push; Push; Bin` triples and `Push; Not/Neg` pairs, refuses division by
zero, overflow and bad shifts), dead-branch elimination
(`Push(Bool(c)); JumpIfFalse/JumpIfTrue` becomes a drop or a `Jump`,
only when the conditional is not a jump target, which preserves `&&` and
`||` short-circuit semantics), and jump threading (`Jump(X)` to
`Jump(Y)` chains).

A fourth fused pass collapses the canonical
`LoadField(int); Push(Int(c)); Bin(op); JumpIf*(t)` pattern into one
`BranchFieldIntCmp` instruction, which removes the stack traffic, for
the int-typed fields and the comparison operators.

### Comparison to BIRD `f_line`

BIRD compiles its filter AST to an `f_line` (a flat instruction array
with embedded constant pools) and runs it through `f_run`. lr's design
is structurally similar: a flat `Vec<Instr>`, per-function instruction
arrays, a small constant pool embedded in the `Push` and `Match`
operands, and the same `accept`/`reject` short-circuit semantics. Two
differences are deliberate.

- lr keeps the tree-walking interpreter as the semantic oracle and uses
  `EvalTree` as the dynamic-subtree fallback. BIRD removed its
  tree-walker when `f_line` landed; lr kept it so the bytecode VM has a
  differential oracle.
- lr does not intern strings or attributes inside the VM. Names
  (`LoadVar`, `AssignVar`, `Call`, `Method`) are still `String` clones.
  A side-table design with a compact instruction and `consts`, `matches`
  and `trees` side tables was slower than the fat-enum form, because the
  fat enum's fetch loop is branch-predicted and cache-line-aligned.

## Performance

`crates/*/benches/` holds the criterion benches. Run them with
`cargo bench -p <crate>`. The two hot paths worth knowing about:

- **ROA validation** — `lr_bgp::roa::RoaTable::validate` walks a
  path-compressed (Patricia) prefix trie. The covering ROAs of a route
  are exactly the trie nodes on the root-to-route bit path, so a query
  costs `O(prefix_len)`, bounded by 32 or 128 bit visits, whatever the
  table size. Entries stay in a canonical sorted `Vec<RoaEntry>` for
  dumps, equality and snapshot determinism, with the trie as a pure
  lookup index built once at construction
  (`crates/lr-bgp/benches/roa_validate.rs`).
- **Filter DSL evaluation** — filters compile once at startup and each
  route evaluation is a flat opcode loop with no AST re-walking and no
  per-route allocation on the match path. Nine shapes are measured
  under both engines
  (`crates/lr-policy/benches/filter_eval.rs`), and
  `crates/lr-policy/benches/import_pipeline.rs` measures the daemon's
  per-UPDATE cost.

## License

`MIT OR Apache-2.0` per crate. No GPL or AGPL components.
