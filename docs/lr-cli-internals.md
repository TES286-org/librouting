# lr-cli — Internals

This document explains how `crates/lr-cli` is laid out, why it looks
the way it does, and where the natural extension points are. The
user-facing reference is [`lr-cli.md`](lr-cli.md); this page is for
contributors extending the protocol surface or porting the daemon to
a new platform.

The crate ships **two binaries**:

| Binary | Entry point | Role |
| --- | --- | --- |
| `lr` | `src/main.rs` | Stateless wire-byte and MRT inspector. No I/O threads, no transport, no FSM — just `Decoder` calls. |
| `lr-daemon` | `src/daemon.rs` | Reference daemon. Real TCP transports, poll-driven router, ticker thread, signal handling, optional kernel FIB mirror. |

Both binaries deliberately have no `clap` dependency — argument
parsing lives in `daemon_config::parse_args` for the daemon and a
hand-rolled `match args[1]` in `lr`. A stripped container can run
either binary without dragging in a parser framework.

## Module map

```text
crates/lr-cli/src/
├── main.rs              `lr` binary entry point
├── daemon.rs            `lr-daemon` binary entry point + BGP run path
├── daemon_bfd.rs        BFD liveness wiring (RFC 5880/5881/5883)
├── daemon_config.rs     DaemonConfig model + argv + TOML parsing
├── daemon_ldp.rs       LDP run path (RFC 5036 UDP discovery + TCP session)
├── daemon_ospf.rs      OSPFv2 run path (raw IPPROTO_OSPF transport)
├── daemon_ospf3.rs     OSPFv3 run path (raw IPv6 IPPROTO_OSPF transport)
├── daemon_policy.rs    prefix-list / AS-path list / community-list /
│                       route-map model — the config-side of lr-policy
├── translate.rs        `lr-daemon translate bird|frr FILE` (W5.1)
├── parity.rs           `lr parity-replay` + `lr mrt diff` (W5.3)
├── yang.rs             `lr-daemon yang render` (RFC 9647 / RFC 8177)
├── api.rs              Runtime API on the --api-socket Unix socket
├── signal.rs           Cross-platform SIGHUP / SIGINT / SIGTERM handling
├── privdrop.rs         Privilege drop (setuid / setgid)
└── compat.rs           BIRD / FRR dialect detection for --config
```

Each protocol sub-daemon (`run_bgp_daemon`, `run_ospf_daemon`,
`run_ospf3_daemon`, `run_ldp_daemon`, `run_babel_daemon`,
`run_bmp_collector`) follows the same shape:

1. Build a `DefaultRouter` (from `lr-router`) under an `Arc<Mutex<…>>`.
2. Install protocol-wide knobs from the config (RFC 8212 policy,
   enforce-first-as, deterministic router-id, Add-Path max, etc.).
3. Per-peer / per-interface: install one `SessionConfig` + `SessionHandle`
   via `router.add_session(...)`. The handle is the routing key for
   transport threads.
4. Spawn transport threads (one connector per outbound BGP peer, one
   OSPF/Babel/LDP receiver thread per protocol). Each thread holds
   the session handle, owns its `TcpStream` / raw socket, and feeds
   bytes through `router.feed_input(handle, bytes)` and drains
   `router.drain_output(handle)`.
5. Run the poll loop at the daemon's ticker cadence (100–200 ms):
   `router.poll_events(...)` → process `RouterEvent`s → mirror Loc-RIB
   best routes into the kernel via `lr-osroute` (when
   `--install-kernel-routes`).
6. Signal handling: `signal::init()` installs BSD-semantics handlers
   on Unix (a single relaxed atomic store, async-signal-safe). The
   poll loop calls `signal::take_pending()` and acts on `SIGHUP`
   (reload `networks` only) or `SIGTERM` / `SIGINT` (graceful:
   NOTIFICATION CEASE per session, tear down, exit 0).

## The BGP run path — `daemon.rs::run_bgp_daemon`

This is the most complex run path; the other protocols reuse its
patterns at smaller scale. The interesting pieces:

### Multi-peer + collision resolution (RFC 4271 §6.8)

A `[[peer]]` table can carry `remote` (outbound), `address`
(inbound-only), or both. The "both" case is a bidirectional peer:
the daemon connects out AND accepts inbound on the same peer entry.
The two transports run on **separate sessions** (the `handle` /
`handle_in` pair on `PeerEntry`), so an inbound connection can
coexist with the outbound one while the router resolves the
collision.

The collision resolver lives in `lr-router`; the daemon's job is to
feed both transports into their own sessions and let the router
issue the Cease NOTIFICATION to the loser. The
`outbound_lost_collision` atomic latches once the outbound transport
loses — holding off further dial retries into an Established winner
prevents the "higher ID wins" rule from devolving into "first dial
wins" churn.

### GTSM, MD5, TCP-AO

`lr-osroute::gtsm::Gtsm` and `lr-osroute::tcp_auth::TcpAuth` are the
abstractions the daemon arms before bind/connect. Linux implements
both outbound TTL arming and the min-TTL receive filter; other
platforms set outbound TTL only. The daemon's listener arms MD5 /
TCP-AO on the listening socket via the `TcpAuth` trait; inbound
connections with mismatched auth are rejected fail-closed before
the BGP FSM sees them.

TCP-AO needs Linux ≥ 6.7 (`CONFIG_TCP_AO`). Older kernels return
`Protocol not available` — there is no workaround; MD5 or plain TCP
with BFD is the fallback. The nightly CI matrix exercises this on
`ubuntu-24.04` (6.8 kernel) via the `tcp_ao.sh` interop script.

### BFD fast-fail

`daemon_bfd::BfdFlags` carries the per-peer BFD state. When BFD
declares a session Down (3 consecutive missed exchanges), the
router's BGP session is torn immediately — the BGP FSM does not
wait for its own hold-time. `daemon_bfd.rs` is the bridge: it owns
the `BfdSession` (from `lr-bfd`) and signals the BGP peer thread.

### BMP mirroring

`spawn_bmp_sender` connects to the `--bmp-target` station and runs
a dedicated sender thread. The router's BMP sink is called from
inside the router lock, so the daemon pushes BMP bytes over a
channel to the sender thread — the network I/O never blocks the
router's poll loop.

### Kernel mirror

`KernelMirror` (`daemon.rs`) mirrors Loc-RIB best routes into the
kernel FIB via `lr-osroute::SystemRouteTable`. On Linux, the
mirror also drives the **MPLS dataplane** (`mpls_route::MplsNetlink`)
for RFC 8277 BGP-LU: locally originated labelled routes install an
AF_MPLS pop route (the LSP tail), peer-advertised labelled routes
install an encap route pushing the label stack (the LSP head). The
classification is pure (`lsp_decision`) so off-Linux builds compile
and the kernel-table half simply has no work to do.

## The OSPF run paths — `daemon_ospf.rs` / `daemon_ospf3.rs`

OSPF needs raw sockets (`IPPROTO_OSPF` v2 / IPv6-raw v3). The
transport lives in `lr-osroute::ospf_transport` (Linux only; other
platforms return `Unsupported`). The daemon's job is to:

1. Build one `OspfInterface` per `[[ospf.interface]]` table, each
   with its own raw socket and `InterfaceId`.
2. Run a per-interface poll loop: hello / dead timers, DBD / LSR
   exchange (RFC 2328 §7.2 / RFC 5340 §A.5), LSA flooding. The
   codec layer (`lr-ospf::OspfCodec`) is shared; the daemon adds the
   I/O.
3. Originate the LSAs the daemon is responsible for: Router-LSA per
   area, Network-LSA on broadcast segments, type-3 / type-4 summaries
   (ABR), type-5 / type-7 externals (ASBR / NSSA translator),
   SR-Router-LSA + SR-Adj-LSA (RFC 8665), SRv6 RI / Locator LSAs
   (RFC 9513).
4. Run SPF when the LSDB changes (`lr-ospf::spf::run_spf` for v2,
   `run_spf_v3` for v3). The result becomes Loc-RIB entries via
   `lr-rib` merging.
5. For OSPFv3 SRv6 (RFC 9513), install supported-algorithm locators
   into the kernel IPv6 FIB with the IAP-beats-locator preference
   (§5).

The daemon's interface model is **point-to-point** by default
(RFC 2328 §9.1) and **broadcast** when `network_type = "broadcast"`.
The §9.4 DR/BDR election runs only on broadcast segments; the
§10.4 adjacency gating prevents DBD exchange below the 2-WAY state
on broadcast segments (a real bug found during the W3-extra OSPFv3
broadcast slice — see the OSPFv3 broadcast landing log in ROADMAP.md).

The OSPF daemon needs `CAP_NET_RAW`. CI and containers use
`unshare -Urn` (rootless network namespace) to grant it without
host root. OSPFv3 also needs `seg6_enabled=1` for SRv6 — the kernel
interop tests in `crates/lr-osroute/tests/srv6_kernel.rs` skip
cleanly when it is off.

## The Babel run path — `daemon.rs::run_babel_daemon`

Babel is UDP (RFC 8966 port 6696); the daemon binds the well-known
multicast group (`ff02::1:6` v6, `224.0.0.111` v4) and runs a
per-interface send / receive loop. MAC auth (RFC 8967) and the
PC-window (RFC 9467) live in `lr-babel`; the daemon's job is to wire
the configured keys to the `BabelNeighbor` instances.

The interesting daemon-specific piece is the **§5 incremental
deployment** toggle (`--babel-accept-unauthenticated`): the daemon
signs outgoing packets with all configured MAC keys but accepts
unsigned inbound from neighbours that have not yet migrated. This is
the only knob that lets an operator move a network from
unauthenticated to authenticated Babel without a flag day.

## The LDP run path — `daemon_ldp.rs`

LDP (RFC 5036) is two transports: UDP multicast discovery (port
646) + TCP session (port 646). The daemon runs both:

1. Per `--ldp-interface` (or `[[ldp.interface]]`), a UDP multicast
   Hello sender / receiver thread.
2. Per `--ldp-targeted` (or `[[ldp.targeted]]`), an extended-discovery
   UDP targeted-Hello sender / receiver (RFC 5036 §6.2).
3. On Hello adjacency up, dial / accept a TCP session and hand it to
   `lr-ldp::LdpEngine`, which runs the session FSM, the label
   binding advertisements, and the FEC-to-label mapping.

On Linux the daemon also installs the resulting MPLS LSPs via the
same `mpls_route::MplsNetlink` that the BGP-LU mirror uses (kernel
MPLS needs `mpls_router` + `mpls_iptunnel` modules loaded on the
host).

## The BMP collector run path — `daemon.rs::run_bmp_collector`

`--protocol bmp` flips the daemon into BMP collector mode: it
accepts TCP connections on `--listen`, parses the RFC 7854 header +
common preamble + per-message body, and stores the resulting
`BmpMessage`s. This is the reverse of the BGP run path's BMP sender
— the same `lr-bmp` crate covers both sides.

## `translate.rs` — the W5.1 config converter

`lr-daemon translate bird|frr FILE` is a **line-based and shallow**
converter. It deliberately does not try to build a BIRD / FRR AST
(those are full languages with their own parsers); instead it maps
the shapes operators actually deploy — peers, route-maps,
prefix-lists, the import/export `none`/`all` idioms — onto the
daemon's TOML schema. Anything it cannot map faithfully is preserved
as an explicit `# UNMAPPED:` comment so the operator sees what was
lost. The output is always loadable by `lr-daemon --config` (verified
by a round-trip test through the real parser in every `cargo test`
run).

The `lr:` extension directives (e.g. `# lr: import "my-map"` in a
BIRD `protocol bgp` block, `# lr: neighbor 192.0.2.2 import "my-map"`
in FRR) are the lr-specific extension channel — invisible to BIRD /
FRR but understood by the daemon's BIRD / FRR dialect loader. The
two loaders share `translate.rs`'s `LrDirective` parser.

## `parity.rs` — the W5.3 wire-level parity harness

Three pieces:

1. **Capture files** — line-oriented JSON, one BGP message per line.
   The interop proxy `tests/parity/capture_proxy.py` records them
   off the wire (it is a TCP relay that hex-dumps every message in
   both directions); in-process tests write them via
   `parity::write_capture`.
2. **Replay** (`lr parity-replay`) — feeds the captured stream
   into a fresh `DefaultRouter` exactly as the wire delivered it,
   then dumps the resulting Loc-RIB as an MRT `TABLE_DUMP_V2` file
   in the same shape the daemon's runtime API produces.
3. **Diff** (`lr mrt diff A B`) — compares two MRT RIB dumps on
   route **content** (per prefix: AS path, next hop, local-pref,
   MED, communities) and ignores dump-specific noise (timestamps,
   peer indexes, view names).

The reference implementation's RIB at capture time is the ground
truth: replaying the same wire stream into lr must reproduce it, or
the difference is a real interoperability defect (or a documented
normalization — those belong in [`PARITY.md`](PARITY.md)).

## `yang.rs` — RFC 9647 / RFC 8177 XML instance data

`lr-daemon yang render FILE` reads a daemon TOML and emits XML
instance data for the Babel subset of the standards-track YANG
models shipped in `yang/`:

- `ietf-babel` (RFC 9647) — the Babel protocol configuration.
- `ietf-key-chain` (RFC 8177) — the same symmetric keys expressed in
  the generic key-chain model.

`--model all` (default) wraps both in a NETCONF `<config>` element.
The mapping is config → instance data only — `lr` does not implement
a YANG validator, and `config false` nodes are not rendered. The
[`yang.sh`](../tests/interop/yang.sh) interop lab exercises the
output against `libyang` for syntactic + schema validity.

## `api.rs` — the runtime management socket

`--api-socket PATH` opens a Unix-domain socket (Linux / BSD / macOS)
or a named pipe (Windows) and dispatches a line-based command
protocol. The commands are: `status`, `sessions`, `routes`,
`mrt PATH`, `reload`, `shutdown`, `help`, `quit`. See
[`RUNBOOK.md`](RUNBOOK.md) for the protocol reference and the
operational patterns.

The `mrt PATH` command writes the current Loc-RIB as a
`TABLE_DUMP_V2` dump (the same shape `lr parity-replay` produces),
which is what `tests/interop/mrt.sh` uses to assert round-trip
parity with BIRD's own dump.

## `signal.rs` — cross-platform signal handling

Unix design:

- `SIGHUP` / `SIGINT` / `SIGTERM` handlers installed via `signal(2)`
  with BSD semantics (no System-V handler reset).
- The handler body is async-signal-safe: a single relaxed atomic
  store, nothing else.
- The poll loop calls `signal::take_pending()` at its existing
  100–200 ms cadence, so no `EINTR` plumbing is required.

Installing a `SIGHUP` handler is itself hardening: without one a
stray `SIGHUP` (e.g. a hung-up terminal) would terminate the daemon
with the default disposition. Signal numbers are identical across
every Unix target the workspace compiles for (Linux, FreeBSD,
NetBSD, macOS).

On non-Unix platforms the API compiles to inert stubs: no signals
exist there and the daemon falls back to platform conventions
(Ctrl-C console events on Windows, see `SetConsoleCtrlHandler`).
The `signal::init` and `take_pending` calls are the same on both
paths, so the rest of the daemon does not need `#[cfg(unix)]` gates.

## `privdrop.rs` — privilege drop

`--user NAME` / `--group NAME` drop privileges after the listening
sockets are bound, so the daemon can hold port 179 and still run
unprivileged. The drop is a single `setgid` + `setuid` sequence (or
`setegid` + `seteuid` on BSDs); the daemon never escalates back.
On Windows this is a no-op (Windows services run under the service
account's identity from the start; privilege drop is a Unix
convention).

## Cross-platform compilation

The crate builds on every target the workspace supports: Linux,
FreeBSD / NetBSD / OpenBSD / macOS, Windows, and any other Unix
via the stub backend. The platform-specific modules under
`lr-osroute` carry the actual platform calls; `lr-cli` only touches
them through the portable `OsRouteTable` trait and the
`#[cfg(target_os = "linux")]`-gated MPLS / SRv6 mirrors.

Kernel-gated tests (`crates/lr-osroute/tests/{ospf6_kernel,srv6_kernel}.rs`)
use `#![cfg(target_os = "linux")]` at the file level — the
compiler skips them on other platforms, not the test runner. The
daemon e2e tests in `crates/lr-cli/tests/daemon_*.rs` use
`std::net` primitives that work cross-platform (loopback TCP),
so they run on every desktop OS.

## Extension patterns

**Adding a new top-level CLI flag to `lr-daemon`**:

1. Add the field to `DaemonConfig` in `daemon_config.rs`.
2. Add the `--flag-name` argv parser branch in
   `daemon_config::parse_args` (mirror an existing flag's shape;
   be careful with the `repeatable` flag for repeatable arguments).
3. Add the TOML counterpart under `[bgp]` (or `[[peer]]`) in
   `daemon_config::parse_toml_subset`, plus the per-peer override
   if applicable.
4. Consume the value in the right `run_*_daemon` function in
   `daemon.rs` / `daemon_*.rs`.
5. Document the flag in `print_usage()` (in `daemon.rs`) and in
   `templates/daemon.toml` (the per-key comments there are the
   canonical user-facing reference).
6. Add a daemon e2e test in `crates/lr-cli/tests/` covering the
   new flag (one of the existing `daemon_*.rs` tests is a good
   template).
7. Update [`lr-cli.md`](lr-cli.md) (the user guide) and
   [`STATUS.md`](STATUS.md) if the flag is a feature-parity item.

**Adding a new subcommand to `lr`** (the inspector):

1. Add a `mod` and the function in `main.rs` (mirror `decode` /
   `mrt` / `parity_replay`).
2. Wire the dispatch in `main()`'s `match cmd { ... }`.
3. Add the subcommand to `print_usage()`.
4. Add a `crates/lr-tests/tests/` test exercising the subcommand
   end-to-end.

**Adding a new protocol sub-daemon**:

1. Add `daemon_<proto>.rs` mirroring `daemon_ospf.rs`'s shape.
2. Add the protocol name to the `matches!(cfg.protocol.as_str(), …)`
   fail-closed check at the top of `daemon::main()`.
3. Add the `--<proto>-*` flags + TOML tables in `daemon_config.rs`.
4. Add a `run_<proto>_daemon` function in `daemon.rs` that builds
   the router, spawns the transport threads, and runs the poll loop.
5. Add at least one e2e test in `crates/lr-tests/tests/` and one
   interop script in `tests/interop/` against the reference
   implementation.
6. Update [`lr-cli.md`](lr-cli.md), [`STATUS.md`](STATUS.md),
   [`RFC_MAP.md`](RFC_MAP.md), [`ROADMAP.md`](ROADMAP.md) and
   `templates/daemon.toml`.

## Where the tests live

| Layer | Path | What it covers |
| --- | --- | --- |
| Unit, per-crate | `crates/<crate>/src/*.rs` (`#[cfg(test)]` modules) | Wire codec + FSM + SPF |
| Integration, per-crate | `crates/<crate>/tests/*.rs` | Cross-module behaviour inside one crate |
| Daemon e2e | `crates/lr-cli/tests/daemon_*.rs` | Real `lr-daemon` binary spawned on loopback TCP |
| Workspace e2e | `crates/lr-tests/tests/*.rs` | Cross-crate scenarios (redistribution, add-path, GTSM, etc.) |
| Cross-vendor interop | `tests/interop/*.sh` | lr x BIRD, lr x FRR, lr x lr — the wire-level parity gate |
| Kernel-gated interop | `crates/lr-osroute/tests/*_kernel.rs` | Real netlink / seg6 calls; `#[ignore]` by default |
| VM kernel-gated interop | `tests/vm/run_vm.sh` | The above inside a QEMU initramfs VM |

See [`ARCHITECTURE.md`](ARCHITECTURE.md) §Testing layout for the
full picture and [`INTEROP.md`](INTEROP.md) for the interop matrix.
