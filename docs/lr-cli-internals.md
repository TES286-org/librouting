# lr-cli internals

This page explains how `crates/lr-cli` is organised, how a daemon run
path works, and where to add a flag, a subcommand or a protocol. Read it
if you are extending the daemon or porting it to a new platform. The
user-facing reference is [`lr-cli.md`](lr-cli.md).

The code is the source of truth. Each module's `//!` header documents
that module; this page covers the shape they share.

## Binaries

The crate ships three binaries, declared in `crates/lr-cli/Cargo.toml`:

| Binary | Entry point | Role |
| --- | --- | --- |
| `lr` | `src/main.rs` | Stateless wire-byte and MRT inspector |
| `lr-daemon` | `src/daemon.rs` | Reference daemon with real transports |
| `lrctl` | `src/lrctl.rs` | Operational client for a running daemon |

`lr` has no I/O threads, no transport and no FSM; it drives `Decoder`
and `MrtRecord` calls. `lrctl` connects to a running `lr-daemon` over
its API socket and proxies the line-oriented command protocol; a few of
its subcommands, such as `filter compile`, are client-side and need no
daemon.

None of the three depends on `clap`. Argument parsing lives in
`daemon_config::parse_args` for the daemon and in hand-rolled
`match args[1]` dispatch in `lr` and `lrctl`, so a stripped container
can run any of them without a parser framework.

## Module map

| Module | Responsibility |
| --- | --- |
| `main.rs` | `lr` entry point and subcommand dispatch |
| `daemon.rs` | `lr-daemon` entry point, BGP run path, Babel run path, BMP collector, kernel mirror |
| `daemon_multi.rs` | Multi-protocol supervisor for `--protocol bgp,ospf,babel` |
| `daemon_config.rs` | `DaemonConfig` model, argv parser, TOML loader, shared key dispatch |
| `daemon_policy.rs` | TOML policy tables compiled into an `lr_policy::PolicySet` |
| `daemon_ospf.rs` | OSPFv2 run path over raw sockets |
| `daemon_ospf3.rs` | OSPFv3 run path over raw IPv6 sockets |
| `daemon_ldp.rs` | LDP run path: UDP discovery plus TCP session |
| `daemon_bfd.rs` | Per-peer BFD liveness wired into the BGP session |
| `daemon_rpki.rs` | RPKI-RTR cache client thread |
| `daemon_logger.rs` | Process-wide console logger |
| `config_dsl/mod.rs` | Native `.lr` configuration DSL |
| `config_dsl/lexer.rs` | Tokens for the `.lr` grammar |
| `config_dsl/parser.rs` | `.lr` parser and IR lowering |
| `config_dsl/emit.rs` | Deterministic `DaemonConfig` to `.lr` renderer |
| `config_check.rs` | `config check` and `config to-dsl` subcommands |
| `compat.rs` | Native BIRD 2 and FRR 10 configuration loading |
| `translate.rs` | `translate bird\|frr` shallow config converter |
| `translate_bird_filter.rs` | BIRD filter language to the lr filter DSL |
| `parity.rs` | Capture, replay and `mrt diff` parity harness |
| `yang.rs` | `yang render` XML instance data |
| `metrics.rs` | Prometheus `/metrics` HTTP endpoint |
| `api.rs` | Runtime API command dispatcher |
| `api_imp_windows.rs` | Windows named-pipe transport for the same API |
| `signal.rs` | Cross-platform `SIGHUP` / `SIGINT` / `SIGTERM` handling |
| `privdrop.rs` | Privilege drop after the listening sockets are bound |
| `lrctl.rs` | `lrctl` entry point and API client |

## The shape every protocol run path shares

`run_bgp_daemon`, `run_ospf_daemon`, `run_ospf3_daemon`,
`run_ldp_daemon`, `run_babel_daemon` and `run_bmp_collector` all follow
the same six steps:

1. Build a `DefaultRouter` from `lr-router` behind an
   `Arc<RwLock<…>>`.
2. Install the protocol-wide knobs from the config: RFC 8212 policy,
   enforce-first-as, deterministic router-id, Add-Path maximum, and so
   on.
3. Per peer or per interface, install one `SessionConfig` and take the
   `SessionHandle` from `router.add_session(...)`. The handle is the
   routing key for the transport threads.
4. Spawn the transport threads: one connector per outbound BGP peer,
   one receiver per OSPF, Babel or LDP interface. Each thread owns its
   `TcpStream` or raw socket and the handle, and moves bytes with
   `router.feed_input(handle, bytes)` and
   `router.drain_output(handle)`.
5. Run the poll loop at the ticker cadence: `router.poll_events(...)`,
   process the `RouterEvent`s, and mirror Loc-RIB best routes into the
   kernel through `lr-osroute` when `--install-kernel-routes` is set.
6. Handle signals. `signal::init()` installs the handlers; the poll loop
   calls `signal::take_pending()` and acts on `SIGHUP` (reload the
   `networks` set) or `SIGTERM` / `SIGINT` (graceful shutdown: one
   NOTIFICATION CEASE per session, teardown, exit 0).

## The BGP run path

`run_bgp_daemon` in `daemon.rs` is the most complex run path; the other
protocols reuse its patterns at smaller scale.

### Multi-peer and collision resolution

A `[[peer]]` table can carry `remote` (outbound), `address`
(inbound-only), or both. The "both" case is a bidirectional peer: the
daemon dials out and accepts inbound on the same entry. The two
transports run on separate sessions — the `handle` and `handle_in`
fields on `PeerEntry` — so an inbound connection can coexist with the
outbound one while the router resolves the RFC 4271 §6.8 collision.

The collision resolver lives in `lr-router`. The daemon feeds both
transports into their own sessions and lets the router send the Cease
NOTIFICATION to the loser. The `outbound_lost_collision` atomic latches
once the outbound transport loses, which holds off further dial retries
into an Established winner: without it, the "higher router ID wins"
rule degenerates into "first dial wins" churn.

### GTSM, MD5 and TCP-AO

`lr_osroute::gtsm::Gtsm` and `lr_osroute::tcp_auth::TcpAuth` are the
abstractions the daemon arms before bind and connect. Linux implements
both the outbound TTL arming and the min-TTL receive filter; other
platforms set the outbound TTL only. The listener arms MD5 or TCP-AO on
the listening socket through `TcpAuth`, and an inbound connection with
mismatched auth is rejected fail-closed before the BGP FSM sees it.

TCP-AO needs a Linux kernel with `CONFIG_TCP_AO`. Older kernels return
`Protocol not available`; there is no workaround, and MD5 or plain TCP
with BFD is the fallback.

### BFD fast-fail

`daemon_bfd::BfdFlags` carries the per-peer BFD state. When BFD
declares a session Down after three consecutive missed exchanges, the
router tears the BGP session down immediately; the BGP FSM does not
wait for its own hold time. `daemon_bfd.rs` owns the `BfdSession` and
signals the BGP peer thread.

### BMP mirroring

`spawn_bmp_sender` connects to the `--bmp-target` station and runs a
dedicated sender thread. The router calls its BMP sink while holding the
router lock, so the daemon pushes the BMP bytes over a channel to the
sender thread; the network I/O never blocks the poll loop.

### Kernel mirror

`KernelMirror` in `daemon.rs` mirrors Loc-RIB best routes into the
kernel FIB through `lr_osroute::SystemRouteTable`. On Linux the mirror
also drives the MPLS dataplane (`mpls_route::MplsNetlink`) for RFC 8277
BGP-LU: a locally originated labelled route installs an AF_MPLS pop
route, the LSP tail, and a peer-advertised labelled route installs an
encap route pushing the label stack, the LSP head. The classification
function `lsp_decision` is pure, so off-Linux builds compile and the
kernel-table half simply has no work to do.

## The OSPF run paths

OSPF needs raw sockets: `IPPROTO_OSPF` for v2 and a raw IPv6 socket for
v3. The transport lives in `lr_osroute::ospf_transport`, which is Linux
only and returns `Unsupported` elsewhere. The daemon then:

1. Builds one `OspfInterface` per `[[ospf.interface]]` table, each with
   its own raw socket and `InterfaceId`.
2. Runs a per-interface poll loop: hello and dead timers, the DBD and
   LSR exchange (RFC 2328 §7.2, RFC 5340 §A.5), LSA flooding.
   `lr_ospf::OspfCodec` handles the wire; the daemon adds the I/O.
3. Originates the LSAs it is responsible for: the Router-LSA per area,
   the Network-LSA on broadcast segments, type-3 and type-4 summaries as
   an ABR, type-5 and type-7 externals as an ASBR or NSSA translator,
   the SR-Router-LSA and SR-Adj-LSA (RFC 8665), and the SRv6 RI and
   Locator LSAs (RFC 9513).
4. Runs SPF when the per-area LSDB changes (`lr_ospf::spf::run_spf` for
   v2, `run_spf_v3` for v3). The result reaches Loc-RIB through the
   router's runtime delta.
5. For OSPFv3 SRv6 (RFC 9513), installs supported-algorithm locators
   into the kernel IPv6 FIB, preferring the IAP over the locator per
   §5.

An interface is point-to-point by default (RFC 2328 §9.1) and broadcast
when `network_type = "broadcast"`. The §9.4 DR and BDR election runs
only on broadcast segments, and §10.4 adjacency gating prevents a DBD
exchange below 2-WAY.

The OSPF daemon needs `CAP_NET_RAW`. CI and containers grant it with
`unshare -Urn`, a rootless network namespace, rather than host root.
OSPFv3 SRv6 additionally needs `seg6_enabled=1`; the kernel tests in
`crates/lr-osroute/tests/srv6_kernel.rs` skip cleanly when it is off.

## The Babel run path

Babel is UDP on RFC 8966 port 6696. The daemon binds the well-known
multicast groups (`ff02::1:6` for v6, `224.0.0.111` for v4) and runs a
per-interface send and receive loop. MAC authentication (RFC 8967) and
the PC window (RFC 9467) live in `lr-babel`; the daemon wires the
configured keys to the `BabelNeighbor` instances.

The daemon-specific piece is the §5 incremental deployment toggle,
`--babel-accept-unauthenticated`: the daemon signs outgoing packets
with every configured MAC key but accepts unsigned inbound packets from
neighbours that have not migrated yet. It is the knob that lets an
operator move a network from unauthenticated to authenticated Babel
without a flag day.

## The LDP run path

LDP (RFC 5036) uses two transports. The daemon runs both:

1. Per `--ldp-interface` or `[[ldp.interface]]`, a UDP multicast Hello
   sender and receiver thread.
2. Per `--ldp-targeted` or `[[ldp.targeted]]`, an extended-discovery
   targeted-Hello sender and receiver (RFC 5036 §6.2).
3. When a Hello adjacency comes up, dial or accept a TCP session and
   hand it to `lr_ldp::LdpEngine`, which runs the session FSM, the label
   binding advertisements, and the FEC-to-label mapping.

On Linux the daemon installs the resulting MPLS LSPs through the same
`mpls_route::MplsNetlink` the BGP-LU mirror uses. Kernel MPLS needs the
`mpls_router` and `mpls_iptunnel` modules loaded on the host.

## The BMP collector run path

`--protocol bmp` flips the daemon into BMP collector mode. It accepts
TCP connections on `--listen`, parses the RFC 7854 header, common
preamble and per-message body, and stores the resulting `BmpMessage`s.
It is the reverse of the BGP run path's BMP sender, and `lr-bmp` covers
both sides.

## The parity harness

`parity.rs` has three pieces:

1. **Capture files** — line-oriented JSON, one BGP message per line.
   `tests/parity/capture_proxy.py` records them off the wire; it is a
   TCP relay that hex-dumps every message in both directions.
   In-process callers read them with `parity::read_capture` and append
   with `parity::append_capture`.
2. **Replay** (`lr parity-replay`) — feeds the captured stream into a
   fresh `DefaultRouter` in wire order, then dumps the resulting Loc-RIB
   as an MRT `TABLE_DUMP_V2` file in the shape the daemon's runtime API
   produces.
3. **Diff** (`lr mrt diff A B`) — compares two MRT RIB dumps on route
   content: AS path, next hop, MED and communities.

`mrt diff` deliberately does not fingerprint LOCAL_PREF
(`crates/lr-cli/src/parity.rs`, `RouteFingerprint`). LOCAL_PREF is
iBGP-only on the wire (RFC 4271 §4.3 forbids advertising it to eBGP
peers), and implementations attach their own internal default on
import, so BIRD and FRR both show 100 for an eBGP-learned route. A
dump-side LOCAL_PREF reflects the viewer's policy, not the sender's;
including it would report a parity violation for a difference no
speaker can observe on the wire.

The reference implementation's RIB at capture time is the ground truth:
replaying the same wire stream into lr must reproduce it, or the
difference is an interoperability defect or a documented normalization.
The normalizations belong in [`PARITY.md`](PARITY.md).

## Cross-platform compilation

The crate builds on every target the workspace supports: Linux,
FreeBSD, NetBSD, OpenBSD, macOS, and Windows. The platform-specific
calls live in `lr-osroute`; `lr-cli` reaches them only through the
portable `OsRouteTable` trait and the `#[cfg(target_os = "linux")]`
gated MPLS and SRv6 mirrors. The runtime API switches transport per
platform — a Unix domain socket on Unix, a named pipe on Windows — with
the same line protocol on top.

The kernel-gated tests in `crates/lr-osroute/tests/` carry
`#![cfg(target_os = "linux")]` at the file level, so the compiler skips
them on other platforms rather than the test runner. The daemon tests in
`crates/lr-cli/tests/` use `std::net` primitives over loopback TCP, so
they run on every desktop OS.

## Extension patterns

**Adding a top-level CLI flag to `lr-daemon`**:

1. Add the field to `DaemonConfig` in `daemon_config.rs`.
2. Add the `--flag-name` branch to `daemon_config::parse_args`, mirroring
   an existing flag's shape. Repeatable arguments need the repeatable
   flag handled explicitly.
3. Add the config key to the shared `apply_config_key` dispatch in
   `daemon_config.rs`. Both frontends — the native `.lr` DSL and the
   TOML subset — fail closed through it, so a key registered there works
   in both dialects and cannot drift. Register a per-peer override in the
   same match when the key has one.
4. Consume the value in the right `run_*_daemon` function.
5. Document the flag in `print_usage()` and in `templates/daemon.lr` and
   `templates/daemon.toml`, keeping the DSL and TOML twins in step.
6. Add a daemon e2e test under `crates/lr-cli/tests/`; one of the
   existing `daemon_*.rs` files is a good template.
7. Update [`lr-cli.md`](lr-cli.md), and [`STATUS.md`](STATUS.md) when
   the flag is a feature-parity item.

**Adding a subcommand to `lr`**:

1. Add the module and the function in `main.rs`, mirroring `decode`,
   `mrt` or `parity_replay`.
2. Wire the dispatch in `main()`'s `match cmd { ... }`.
3. Add the subcommand to `print_usage()`.
4. Add a test under `crates/lr-tests/tests/` that exercises the
   subcommand end to end.

**Adding a protocol sub-daemon**:

1. Add `daemon_<proto>.rs` mirroring the shape of `daemon_ospf.rs`.
2. Add the protocol name to the fail-closed validation in
   `daemon::main()`. That check loops over `cfg.protocol_set()` and
   rejects any name outside `bgp`, `babel`, `ospf`, `bmp` and `ldp`; a
   value that combines protocols is rejected unless every name is
   `bgp`, `ospf` or `babel`.
3. Add the `--<proto>-*` flags and their config keys through the shared
   `apply_config_key` dispatch in `daemon_config.rs`.
4. Add a `run_<proto>_daemon` function that builds the router, spawns
   the transport threads, and runs the poll loop.
5. Add at least one e2e test under `crates/lr-tests/tests/` and one
   interop script under `tests/interop/` against a reference
   implementation. The interop documentation guard
   (`tests/lint_interop_doc.sh`) requires the script to appear in
   [`INTEROP.md`](INTEROP.md).
6. Update [`lr-cli.md`](lr-cli.md), [`STATUS.md`](STATUS.md),
   [`RFC_MAP.md`](RFC_MAP.md), [`ROADMAP.md`](ROADMAP.md) and the
   `templates/daemon.lr` and `templates/daemon.toml` twins.

## Test layers

| Layer | Path | What it covers |
| --- | --- | --- |
| Unit | `crates/<crate>/src/*.rs` | Wire codec, FSM, SPF |
| Integration | `crates/<crate>/tests/*.rs` | Cross-module behaviour in one crate |
| Daemon e2e | `crates/lr-cli/tests/*.rs` | The real `lr-daemon` binary on loopback TCP |
| Workspace e2e | `crates/lr-tests/tests/*.rs` | Cross-crate scenarios |
| Interop | `tests/interop/*.sh` | lr against BIRD, FRR, or a second lr |
| Kernel-gated | `crates/lr-osroute/tests/*_kernel.rs` | Real netlink and seg6 calls |
| VM kernel-gated | `tests/vm/run_vm.sh` | The kernel-gated set inside a QEMU VM |

[`ARCHITECTURE.md`](ARCHITECTURE.md) has the general picture and
[`INTEROP.md`](INTEROP.md) the interop matrix.
