# Roadmap

This page is the open-work list for librouting. It names the work that
has not landed and what "done" means for each item. Read it if you are
picking up a block of work or deciding whether a gap matters for a
deployment.

Work that has landed is not recorded here.
[`../CHANGELOG.md`](../CHANGELOG.md) and `git log` are the record, and
[`STATUS.md`](STATUS.md) and [`RFC_MAP.md`](RFC_MAP.md) describe what
the code does today. Open issues are the canonical task list and live
on the project's issue tracker. Each item names the crate, module or
RFC that defines it; the code wins over any sentence here.

## Protocol coverage

**BGP SR Policy (RFC 9256) with the SRv6 binding (RFC 9430).** Not
started. Nothing consumes SR policy. The work is the SR Policy address
family and the tunnel-encapsulations attribute: parse the candidate
and dynamic policies, resolve each segment list against `lr-srv6` and
the SR databases, and steer the matching Loc-RIB entries into `seg6`
encap routes through the kernel mirror
(`lr-osroute::seg6_route`). A policy that will not resolve installs
nothing. Done when a controller's policy steers traffic through an lr
daemon, and withdrawal removes both the route and the kernel entry.

**Egress Peer Engineering (RFC 9086).** The codec half — the BGP-LS
Attribute TLVs for the SR-MPLS BGP Peering SID TLVs (PeerNode SID
type 1101, PeerAdj SID type 1102, PeerSet SID type 1103, RFC 9086 §5)
and the matching Node Descriptor sub-TLVs (BGP Router-ID TLV 516,
Member-AS Number TLV 517, §3.1/§3.2) — and the daemon-side EPE
projection (`lr-router::instance::epe`, `DefaultRouter::bgpls_republish_epe`)
have landed.

What remains is the receiver-side (controller-mode) follow-up: a
controller-mode daemon receives EPE NLRIs from its BGP-LS peers and
surfaces them through its Loc-RIB. That touches the daemon's Loc-RIB
model (`RouteKey { prefix, family }` does not fit a BGP-LS NLRI) and
is independent of the projection. Done when a controller learns those
segments from lr, the data plane can push traffic onto them, and a
controller-mode lr daemon can ingest the same NLRIs another daemon
advertises.

## Scaling

The three items below are the daemon-refactoring block of the 2.x
release plan (issue #101). They are sequenced — async I/O lands first
because it is the substrate the RIB concurrency work builds on;
per-AFI RIB sharding landed second (the storage half — `LocRib`'s
internal map is sharded by `NlriFamily` with family-aware accessors,
preserving the frozen public API); the multi-threaded RIB and the
lock-free event bus land together third because the bus is what lets
the API thread read without the writer's lock.

The 1.x stability window freezes the public Rust API and the C ABI
(see [`RELEASE-PLAN.md`](RELEASE-PLAN.md) §4). Each landing must
preserve that surface: `LocRib`'s public methods and the
`RouterInstance` trait stay shape-compatible, with new family-aware
methods added alongside the existing cross-family ones (the
`abi-freeze` CI job enforces the C half mechanically). A breaking
change ships as the 2.0 major bump and lands in one PR after the
three below have stabilised on a release window.

**Async I/O.** The BGP session layer has landed on the event loop:
[`lr-cli::bgp_reactor`](../crates/lr-cli/src/bgp_reactor.rs) drives
every established BGP session from a single `mio` thread — the
listener and the connectors submit connected sockets, readable
events run the exact pump order the per-session threads used
(read → `feed_input` → `drain_output` → write), a partial write parks
its remainder in the slot under WRITABLE interest, and a maintenance
sweep every 50 ms flushes timer-generated output (KEEPALIVEs,
retransmissions) and watches the BFD and router-side close paths.
The per-session thread pool — one thread per socket whose 200 ms
read timeout was the poll cadence — is gone, together with the
`run_peer_session` / `pump_session` functions and the connector's
string-matched backoff classification (now the structured
`bgp_reactor::SessionEnd` enum).

What remains is the rest of the daemon's I/O surfaces: the OSPF raw
sockets ([`lr-osroute::ospf_transport`](../crates/lr-osroute/src/ospf_transport/mod.rs)),
Babel's UDP-plus-multicast pair and BFD's datagram loop
([`lr-osroute::bfd_transport`](../crates/lr-osroute/src/bfd_transport.rs)),
the BGP listener's accept poll and the runtime API / metrics accept
loops. Each wraps differently (raw IP, multicast membership,
connection-less datagrams), so each is its own slice of work.
`mio` is the smaller dependency and the daemon already avoids
`tokio` for the API and metrics threads; `tokio` is the alternative
if the rest of the daemon's I/O surfaces converge on it.

Done when the poll-and-sleep loops are gone across every transport,
an idle session wakes only on an event, and the session, timer and
interop tests still pass.

**Multi-threaded RIB and a lock-free event bus.** The whole router
sits behind `Arc<RwLock<DefaultRouter>>`
(`crates/lr-cli/src/daemon.rs`, `crates/lr-cli/src/api.rs`), so one
writer at a time is the ceiling and an API read waits behind it. The
work is interior concurrency in the RIB (per-shard locks or atomic
structures) plus an event bus that consumers subscribe to in place of
the shared lock. Done when import, reselection and export proceed
concurrently, the best-path result is unchanged, and the API reads
without taking the writer's lock.

The event bus data structure has landed
(`lr-router::event_bus::EventBus`): a bounded MPMC broadcast where
each subscriber gets its own `std::sync::mpsc::Receiver`, `publish`
writes to every active subscriber with `try_send` (a full subscriber
drops the event rather than blocking the publisher), and disconnected
subscribers are pruned on the next publish. The wiring — the daemon's
read-side consumers (ticker, API socket, metrics endpoint, BMP mirror,
kernel mirror) subscribing to the bus in place of the
`Arc<RwLock<DefaultRouter>>` read, plus per-shard locks on the
`LocRib` shards — is the remaining work. The `abi-freeze` CI job
gates the C ABI half.

## Compatibility

**RISC-V targeted compatibility improvements.** The CI matrix covers
the RISC-V architecture in two ways as of
[issue #65](https://github.com/TES286-org/librouting/issues/65): the
`cross` matrix job cross-builds `riscv64gc-unknown-linux-gnu` on
every push, and a native `riscv-native` job runs `cargo nextest`,
doctests and per-arch clippy on real RISC-V hardware via the RISE
Project's `ubuntu-24.04-riscv` runner. The workspace is target-OS-
aware rather than target-arch-aware, so the Linux rtnetlink backend,
the GTSM/TCP-AO socket constants and every protocol codec compile and
run on riscv64 unchanged. What remains is to act on what the CI
surfaces: if a kernel-gated test regresses on riscv64 (a `setsockopt`
constant that does vary by arch, a struct layout quirk), file the
finding against this entry and fix the per-arch path. Done when the
`riscv-native` job has been green on `main` for a release window
without an arch-specific patch landing.

**IBM Power (ppc64le) and IBM Z (s390x) targeted compatibility
improvements.** The CI matrix covers the IBM Power and IBM Z
architectures in two ways as of
[issue #95](https://github.com/TES286-org/librouting/issues/95): the
`cross` matrix job cross-builds
`powerpc64le-unknown-linux-gnu` and `s390x-unknown-linux-gnu` on
every push, and a native `s390x-native` job runs `cargo nextest`,
doctests and per-arch clippy on a self-hosted s390x runner registered
with the labels `[self-hosted, Linux, s390x]`. The IBM-provided
`ubuntu-26.04-ppc64le`, `ubuntu-26.04-ppc64le-p10` and
`ubuntu-26.04-s390x` runners from the IBM Power-Z GitHub App
(<https://github.com/marketplace/power-z-gha-runner>) are pending
review and not yet available; once they clear review, the
`s390x-native` job can switch to (or matrix-add) the IBM-provided
`ubuntu-26.04-s390x` label and ppc64le native jobs can land
(issue #95 stays open to track that follow-up).

The workspace is target-OS-aware rather than target-arch-aware, so
the Linux rtnetlink backend, the GTSM/TCP-AO socket constants and
every protocol codec compile and run on ppc64le and s390x unchanged.
s390x is the only big-endian target in the matrix, so the wire-codec
byte-order discipline (`to_be_bytes` / `from_be_bytes` everywhere,
never native endianness) is mechanically verified on every push. What
remains is to act on what the CI surfaces: if a kernel-gated test
regresses on ppc64le or s390x (a `setsockopt` constant that varies by
arch, a struct layout quirk, a byte-order slip on a wire path), file
the finding against this entry and fix the per-arch path. Done when
the `s390x-native` job has been green on `main` for a release window
without an arch-specific patch landing, and the ppc64le native job
lands once the IBM-provided runner clears review or a self-hosted
ppc64le runner is registered.

## Tooling and supply chain

**IDE integration.** The `.lr` configuration DSL and the filter DSL
have grammar references
([`config_dsl_grammar.md`](config_dsl_grammar.md),
[`filter_dsl_grammar.md`](filter_dsl_grammar.md)) but no editor
support. The work is a tree-sitter grammar covering both, plus a
language server that serves diagnostics from the same parser the
daemon runs at startup, completion for keys and built-ins, and
go-to-definition for policy objects and list references. Done when an
editor shows the daemon's own diagnostic for a broken file before the
daemon starts, and the grammar parses `templates/daemon.lr`.

## Deployment

**A Helm chart.** Deliberately kept out of this repository. A chart
versions independently of the image and of the crate releases, so it
lives in its own repository and references the published container
image. Nothing here blocks on it; this entry exists so its absence is
a decision, not an oversight.

## Non-goals

BGPsec, NBMA and point-to-multipoint OSPF interface types, and OSPFv3
virtual links stay out of scope. They are recorded in
[`STATUS.md`](STATUS.md) and [`RELEASE-PLAN.md`](RELEASE-PLAN.md)
§4.4. Reopening one needs a concrete deployment scenario first.
