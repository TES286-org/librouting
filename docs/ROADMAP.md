# Roadmap

This page is the open-work list for librouting. It names the work that has
not landed and what "done" means for each item. Read it if you are picking
up a block of work or deciding whether a gap matters for a deployment.

Work that has landed is not recorded here.
[`../CHANGELOG.md`](../CHANGELOG.md) and `git log` are the record, and
[`STATUS.md`](STATUS.md) and [`RFC_MAP.md`](RFC_MAP.md) describe what the
code does today. Open issues are the canonical task list and live on the
project's issue tracker. Each item names the crate, module or RFC that
defines it; the code wins over any sentence here.

## Protocol coverage

**BGP-LS (RFC 7752) with the SRv6 extensions (RFC 9552).** Not started.
The daemon does not export IGP topology to a controller. The work is the
MP-BGP Link-State address family: Node, Link and Prefix NLRI with their
descriptor TLVs, the attribute TLVs, and a projection from the OSPF LSDBs
and the SRv6 database onto those shapes in `lr-bgp`. The projection belongs
beside the codec, and the daemon publishes it on a BGP session as a new
family. Done when a third-party collector builds the same graph from our
session that the OSPF daemon holds, and republishing is incremental rather
than a full resend.

**BGP SR Policy (RFC 9256) with the SRv6 binding (RFC 9430).** Not started.
Nothing consumes SR policy. The work is the SR Policy address family and the
tunnel-encapsulation attribute: parse the candidate and dynamic policies,
resolve each segment list against `lr-srv6` and the SR databases, and steer
the matching Loc-RIB entries into `seg6` encap routes through the kernel
mirror (`lr-osroute::seg6_route`). A policy that will not resolve installs
nothing. Done when a controller's policy steers traffic through an lr
daemon, and withdrawal removes both the route and the kernel entry.

**Egress Peer Engineering (RFC 9085).** Partial.
The BGP-LS codec above is the prerequisite. What remains is the EPE-specific
NLRI and attributes: peer node and peer adjacency segments with their SIDs,
advertised so a controller can steer across a chosen inter-AS link or toward
a chosen peer. Done when a controller learns those segments from lr and the
data plane can push traffic onto them.

## Scaling

**Async I/O.** The daemon runs a thread per socket, and its transports poll
with a short `sleep` between reads (`crates/lr-cli/src/daemon.rs`,
[`lr-osroute::ospf_transport`](../crates/lr-osroute/src/ospf_transport/mod.rs),
[`lr-osroute::bfd_transport`](../crates/lr-osroute/src/bfd_transport.rs)).
That costs a wakeup per idle tick and bounds how many sessions one process
holds. The work is to move the session and transport layer onto an event
loop — `mio` or `tokio` — with readiness driving the FSM instead of a timer.
Done when the poll-and-sleep loops are gone, an idle session wakes only on
an event, and the session, timer and interop tests still pass.

**Per-AFI RIB sharding.** [`ARCHITECTURE.md`](ARCHITECTURE.md) describes one
Loc-RIB for every family.
[`lr-rib::loc_rib::LocRib`](../crates/lr-rib/src/loc_rib.rs) is one map keyed
by `RouteKey`, so a full IPv6 table contends with IPv4 on one structure and a
reselect walks it. The work is one RIB per address family behind the
`RouterInstance` API, with selection, merging and the kernel mirror reading
the right shard. Done when the family is part of the RIB's identity, an
update in one family never blocks selection in another, and the selection
and Add-Path tests still hold.

**Multi-threaded RIB and a lock-free event bus.** The whole router sits
behind `Arc<RwLock<DefaultRouter>>` (`crates/lr-cli/src/daemon.rs`,
`crates/lr-cli/src/api.rs`), so one writer at a time is the ceiling and an
API read waits behind it. The work is interior concurrency in the RIB
(per-shard locks or atomic structures) plus an event bus that consumers
subscribe to in place of the shared lock. Done when import, reselection and
export proceed concurrently, the best-path result is unchanged, and the API
reads without taking the writer's lock.

## Compatibility

**Per-protocol route attributes and an external conversion corpus.**
`lr-daemon translate bird|frr` and the native compat loader handle the BGP
subset; attributes that belong to another protocol are dropped with an
`UNMAPPED` note (`crates/lr-cli/src/translate.rs`). The work is to carry the
per-protocol attributes through the translation — OSPF and Babel metrics,
BIRD's route attributes, FRR's address-family state — and to build a corpus
of real configurations from both daemons with the expected output beside
them. Done when a real configuration converts with no unmapped line that
changes its behaviour, the corpus runs in the interop gate, and a new
dialect quirk adds a corpus case instead of a bespoke assertion.

## Tooling and supply chain

**Supply-chain follow-ups.** `cargo audit` and `cargo deny check` run
nightly (`.github/workflows/nightly.yml`, `deny.toml`). Three gaps remain: a
CycloneDX SBOM per release, `cosign` signatures over the release archives
(`.github/workflows/release.yml`), and a static-analysis scan of the Rust
sources. Done when a release publishes a signed SBOM beside its archives, a
consumer can verify an artifact against the signing identity, and the scan
runs on every change with its findings triaged.

**IDE integration.** The `.lr` configuration DSL and the filter DSL have
grammar references ([`config_dsl_grammar.md`](config_dsl_grammar.md),
[`filter_dsl_grammar.md`](filter_dsl_grammar.md)) but no editor support. The
work is a tree-sitter grammar covering both, plus a language server that
serves diagnostics from the same parser the daemon runs at startup,
completion for keys and built-ins, and go-to-definition for policy objects
and list references. Done when an editor shows the daemon's own diagnostic
for a broken file before the daemon starts, and the grammar parses
`templates/daemon.lr`.

**`lrctl roa list`.** Done. The runtime API exposes `show roa` over the
Unix socket / Windows named pipe; `lrctl roa list` and `lrctl roa count`
proxy it. The renderer lives in `crates/lr-cli/src/roa_view.rs` and
walks the live `Arc<RoaStore>` snapshot (the same one the metrics
endpoint already reads), reporting per-layer counts plus one line per
entry. Per-entry provenance is exact (`static` / `rtr` / `both`) via
`RoaStore::provenance_of`, which queries each layer's `HashSet`.

## Deployment

**A Helm chart.** Deliberately kept out of this repository. A chart versions
independently of the image and of the crate releases, so it lives in its own
repository and references the published container image. Nothing here blocks
on it; this entry exists so its absence is a decision, not an oversight.

## Non-goals

BGPsec, NBMA and point-to-multipoint OSPF interface types, and OSPFv3
virtual links stay out of scope. They are recorded in
[`STATUS.md`](STATUS.md) and [`RELEASE-PLAN.md`](RELEASE-PLAN.md) §4.4.
Reopening one needs a concrete deployment scenario first.
