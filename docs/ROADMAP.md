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

**BGP-LS (RFC 7752) with the SRv6 extensions (RFC 9552).** Done —
the wire codec, the OSPF LSDB → BGP-LS projection, the daemon
wiring (`--bgp-ls` flag + `[bgp_ls]` config block + incremental
republish driver), the BIRD interop lab, and the BGP-LS
Attribute TLV codec (RFC 7752 §3.3 + RFC 9514 §7-§8) have all
landed. The STATUS rows for the codec, projection, egress,
republish driver and daemon config are all `yes`; the
`bgpls_bird.sh` lab is the "done" gate from this section.

`lr-bgp::path::bgp_ls` parses and serialises the Node, Link, IPv4
Prefix and IPv6 Prefix NLRI shapes from RFC 7752 §3.3, the Local
Node Descriptor / Remote Node Descriptor / Link Descriptor / Prefix
Descriptor TLVs (§3.2), and the Node Descriptor sub-TLVs (§3.2.1.4:
AS, BGP-LS Identifier, OSPF Area-ID, IGP Router-ID). Unknown TLVs and
sub-TLVs are preserved verbatim so the codec round-trips byte-for-byte
on any well-formed input — the cargo-fuzz target `bgp_ls_decode` ran
62M iterations without crashes. The SRv6 SID NLRI (RFC 9514 §6,
NLRI Type 6) is modelled in full at the NLRI level: the inner SRv6
SID Descriptor TLV stream carries the mandatory SRv6 SID Information
TLV (§6.1, type 518, 16-byte SID) and any optional Multi-Topology
ID TLV (§3.2.1.5, type 263), with strict structural enforcement on
decode.

`lr-bgp::path::bgp_ls_attr` parses and serialises the BGP-LS
Attribute (path attribute type 29, RFC 7752 §3.3) — the TLV
stream that rides alongside a BGP-LS NLRI carrying the
link-state metadata a controller needs. The codec models the
RFC 9514 §7-§8 SRv6 SID Attribute TLVs the projection will
attach to a projected SRv6 SID NLRI — the SRv6 Endpoint Behavior
TLV (§7.1, type 1250), the SRv6 BGP PeerNode SID TLV (§7.2,
type 1251), and the SRv6 SID Structure TLV (§8, type 1252) —
plus the RFC 9514 §3.1 SRv6 Capabilities TLV, the §4.1/§4.2
SRv6 End.X / LAN End.X SID TLVs, and the §5.1 SRv6 Locator TLV,
and a representative subset of the RFC 7752 §3.3.1-§3.3.3
Node/Link/Prefix Attribute TLVs (Node Flag Bits, Opaque Node,
Node Name, IS-IS Area Identifier, IPv4/IPv6 Router-ID, Admin
Group, Max Link / Max Reservable / Unreserved Bandwidth, TE
Default Metric, MPLS Metric, Shared Risk Link Group, IGP
Metric, IGP Flags, IGP Route Tag, Prefix Metric, Forwarding
Address Prefix, Opaque Prefix Attribute, Prefix Attribute
Flags). Unknown TLVs are preserved verbatim so any well-formed
attribute round-trips byte-for-byte. The cargo-fuzz target
`bgp_ls_attr_decode` covers the same contract. The End.X / LAN
End.X SID *projection* update (attaching the §7 attribute to
a projected End.X NLRI through `BgpPeer::advertise_bgpls_with_attr`)
has landed.

`lr-router::instance::lsdb_to_bgpls` projects one OSPF area's LSDB
onto the Node / Link / Prefix NLRI set: OSPFv2 emits Node NLRIs
(Router-LSA, Network-LSA pseudonode), Link NLRIs (transit + P2P)
with IPv4 Interface/Neighbor Address TLVs, and IPv4 Topology Prefix
NLRIs (stub links = `IntraArea`, type-3 Summary-LSAs = `InterArea`,
type-5 AS-External-LSAs = `External1` / `External2` with the OSPF
Area-ID sub-TLV set to 0 per RFC 7752 §3.2.1.4). OSPFv3 emits the
IPv6 equivalents and handles RFC 8362 Extended LSAs, and additionally
walks the OSPFv3 SRv6 database (`lr-ospf::srv6db`, RFC 9513
reception) to emit one RFC 9514 §6 SRv6 SID NLRI per End SID the
database holds — the Local Node Descriptor is the advertising
router's 4-byte IGP Router-ID, and the SRv6 SID Descriptor stream
carries the mandatory SRv6 SID Information TLV (§6.1, type 518,
16-byte SID) plus a Multi-Topology ID TLV (type 263, value 0) for
consistency with the prefix-NLRI projection. End.X / LAN End.X SIDs
are projected by the sibling function
`lsdb_to_bgpls::project_v3_srv6_end_x_nlris`: it walks the same
Srv6Database's per-node `end_x_sids` set (RFC 9513 §9.1 p2p form
and §9.2 LAN form, gated on §9 locator containment and §9.2 neighbor
match) and emits one `(BgpLsNlri, BgpLsAttr)` pair per End.X SID.
The NLRI shape is identical to the End SID projection (RFC 9514 §6
carries the 16-byte SID value; the End.X behavior lives in the
attribute, not in the NLRI); the attribute carries the mandatory
RFC 9514 §7.1 SRv6 Endpoint Behavior TLV (type 1250) and the optional
§8 SRv6 SID Structure TLV (type 1252) when the OSPFv3 §10 sub-TLV
provided the SID-structure split. `diff_bgpls_with_attrs` returns
the added / removed / updated / unchanged pair sets so the daemon
drives incremental MP-BGP UPDATE messages per pair — one UPDATE
per End.X NLRI since each carries its own attribute (RFC 7752 §3.3
does not key the BGP-LS Attribute on individual NLRIs in one
UPDATE). The projection is a pure function on the LSDB;
`DefaultRouter::ospf_area_bgpls_nlris` wraps the plain NLRI projection
with the router's per-area context; `DefaultRouter::bgpls_republish`
drives the plain NLRI projection's incremental republish and
`DefaultRouter::bgpls_republish_end_x` drives the End.X pair
projection's incremental republish. `diff_bgpls` returns the
added / removed / unchanged NLRI sets so a daemon can drive
incremental MP-BGP UPDATE messages by canonical wire form.

`lr-bgp::advertise::BgpPeer::advertise_bgpls` and
`withdraw_bgpls` are the egress primitives: opaque BGP-LS NLRI
bytes ride MP_REACH_NLRI / MP_UNREACH_NLRI attributes built
directly from `BgpLsNlri::encode` (the existing IP-prefix
`MpReach`/`MpUnreach` encoders assume AFI=1/2 — BGP-LS needs the
opaque path). The next-hop field is set to zero (BGP-LS does not
define a next-hop; matches BIRD's `bgp_ls` channel and FRR's
`bgp_bgp_ls.c`). `BgpPeer::advertise_bgpls_with_attr` attaches a
BGP-LS Attribute (type 29, optional + non-transitive) alongside
the MP_REACH_NLRI so the receiver learns the link-state
metadata — the path the End.X projection uses to attach the
§7 SRv6 Endpoint Behavior TLV to a projected End.X NLRI.

`lr-router::instance::DefaultRouter::bgpls_republish` is the
republish driver: projects the area LSDB, computes the diff against
the caller's previous projection, walks every BGP-LS session and
pushes the added NLRIs via `advertise_bgpls`, the removed via
`withdraw_bgpls`. The daemon's ticker thread drives it once per
50 ms tick: `BgplsDriver` (in `lr-cli::daemon`) polls each
configured OSPF area's `topology_version` and calls
`bgpls_republish` on change. The daemon flag is `--bgp-ls` and the
config block is `[bgp_ls]` (with `enabled`, `as_number`,
`bgp_ls_id`, `areas`); both forms fail closed (typo protection).
The same `BgplsDriver` also calls `bgpls_republish_end_x` per tick
to push the End.X / LAN End.X projection's `added` pairs through
`advertise_bgpls_with_attr`, `removed` NLRIs through `withdraw_bgpls`,
and `updated` pairs (NLRI unchanged, attribute changed) through
`advertise_bgpls_with_attr` again — RFC 4271 §9.2.1.2 permits
attribute updates without MP_UNREACH_NLRI. The per-area cache
holds the plain NLRI baseline and the End.X pair baseline side by
side so a topology bump that touches only one projection does not
double-send the other.

The interop lab `tests/interop/bgpls_bird.sh` starts an
OSPF+BGP lr-daemon with `--bgp-ls` against a BIRD 2.17+ peer
configured for the BGP-LS address family. BIRD 2.17+ has the
`bgp_ls` channel (older BIRD SKIPs cleanly); the lab verifies the
BIRD peer builds a Node NLRI for the lr-daemon's router-id from
our BGP-LS session — the same IGP graph the OSPF daemon holds in
its LSDB. The lab runs inside `unshare -Urn` for CAP_NET_RAW, like
the other OSPF interop labs.

**BGP SR Policy (RFC 9256) with the SRv6 binding (RFC 9430).** Not started.
Nothing consumes SR policy. The work is the SR Policy address family and the
tunnel-encapsulation attribute: parse the candidate and dynamic policies,
resolve each segment list against `lr-srv6` and the SR databases, and steer
the matching Loc-RIB entries into `seg6` encap routes through the kernel
mirror (`lr-osroute::seg6_route`). A policy that will not resolve installs
nothing. Done when a controller's policy steers traffic through an lr
daemon, and withdrawal removes both the route and the kernel entry.

**Egress Peer Engineering (RFC 9086).** Partial.
The BGP-LS codec above is the prerequisite, and the codec half of this
work has now landed: the BGP-LS Attribute codec in
`lr-bgp::path::bgp_ls_attr` models the three SR-MPLS BGP Peering SID
TLVs from RFC 9086 §5 — PeerNode SID (type 1101), PeerAdj SID (type
1102), PeerSet SID (type 1103) — sharing a single `BgpPeeringSid`
shape (V/L/B/P flag bits, weight, reserved, and a variable
SID/Index/Label that carries either a 3-byte local MPLS label with
the V flag set or a 4-byte SRGB index with the V flag clear). The
matching Node Descriptor sub-TLVs from RFC 9086 §3.1 / §3.2 — BGP
Router-ID (TLV 516) and Member-AS Number (TLV 517) — are modelled in
`lr-bgp::path::bgp_ls::NodeDescriptorSubTlv` so a BGP-LS Link NLRI
whose Protocol-ID is `Bgp` can round-trip byte-for-byte. The codec
preserves every byte (including the 2-byte reserved field on the
Peering SID) so the round-trip is byte-exact even when an originator
violates the "MUST be zero on originate" constraint; an inconsistent
V-flag/length combination falls through to `Unknown` and still
round-trips.

The daemon-side EPE projection has landed alongside the codec: a new
`lr-router::instance::epe` module walks a snapshot of the daemon's
BGP peer sessions and emits one BGP-LS Link NLRI per Established
session, paired with a BGP-LS Attribute carrying the PeerNode SID
(and any optional PeerAdj / PeerSet SIDs). `DefaultRouter::bgpls_republish_epe`
mirrors `bgpls_republish_end_x` — projects the live session set,
diffs against `prev` via `lsdb_to_bgpls::diff_bgpls_with_attrs`,
and pushes UPDATEs to every BGP-LS session. The `BgplsDriver` ticker
polls `DefaultRouter::bgp_session_identity_hash` and re-projects
on change, so the per-tick cost is negligible when the session
table is stable. The PeerNode SID value the projection emits is a
deterministic per-session placeholder (V flag clear, 4-byte SRGB
index derived from the session handle); operator-configurable SID
values are the next follow-up and do not change the projection
shape.

What remains is the receiver-side (controller-mode) follow-up the
codec PR's scope-boundary section also names: a controller-mode
daemon receives EPE NLRIs from its BGP-LS peers and surfaces them
through its Loc-RIB. That touches the daemon's Loc-RIB model
(`RouteKey { prefix, family }` does not fit a BGP-LS NLRI) and is
independent of this projection. Done when a controller learns those
segments from lr, the data plane can push traffic onto them, and a
controller-mode lr daemon can ingest the same NLRIs another daemon
advertises.

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

**RISC-V targeted compatibility improvements.** The CI matrix covers
the RISC-V architecture in two ways as of [issue #65](https://github.com/TES286-org/librouting/issues/65):
the `cross` matrix job cross-builds `riscv64gc-unknown-linux-gnu` on
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

**Per-protocol route attributes and an external conversion corpus.**
`lr-daemon translate bird|frr` and the native compat loader handle the BGP
subset; BIRD `protocol babel` interface blocks (RFC 8966 §A.2) and BIRD
`protocol ospf` area/interface blocks (RFC 2328 §C / RFC 5340 §A.4)
now carry through to `[[babel.interface]]`, `[[ospf.area]]` and
`[[ospf.interface]]` tables. FRR `router ospf` area policy and
`interface IFNAME` `ip ospf …` directives translate the same way
(`crates/lr-cli/src/translate.rs`). FRR `router ospfv3` area policy
and the `ospfv3 …` interface directives (RFC 5340 §A.4, FRR `ospf6d`)
have landed alongside the v2 path: `ospfv3 router-id A.B.C.D` maps
onto `router_id`, `ospfv3 area N stub|nssa|default-cost M` routes
through the same handler as the bare v2 `area N …` form,
`ospfv3 cost|hello-interval|dead-interval|priority|network …|area N`
inside an `interface IFNAME` block routes through the same
`apply_frr_ospf_iface` helper as the v2 `ip ospf …` directives, and
`ospfv3 instance-id N` / `ospfv3 authentication …` /
`ospfv3 abr-type …` / `ospfv3 log-adjacency-changes` etc. are noted
as unmapped with the v3 directive stem so the operator sees the
version-specific gap. FRR `address-family` state inside `router bgp`
has landed alongside the v3 path: `aggregate-address A.B.C.D/M
[summary-only] [as-set] [route-map NAME]` (RFC 4271 §9.2.2.2) maps
onto `[[aggregate]]` rows (the `summary-only`/`as-set`/`route-map`
qualifiers carry unmapped notes — lr's `[[aggregate]]` models only
the prefix today); `redistribute <proto> [metric M] [route-map
NAME]` (inside `router bgp`/`router ospf`/`router ospfv3`) maps onto
`[[redistribute]]` rows — `bgp`/`ospf`/`ospf3`/`babel` sources map
(the daemon's injection surface), `connected`/`static`/`kernel`/
`rip`/`isis` carry unmapped notes (lr models kernel/static routes
via `networks`, not via a redistribute pipe), and `route-map NAME`
is noted (lr's `[[redistribute]]` has no per-pipe filter hook). A
pipe whose source engine is not `bgp` triggers a top-level
`protocols = ["bgp", "<engine>", …]` emission so the generated
config is loadable as-is (the daemon's `finalize` rejects a
`[[redistribute]]` whose source engine it does not run). `no bgp
ebgp-requires-policy` is consumed silently (the converter always
emits `ebgp_policy = "accept-all"`, which is the same intent), and
`network PREFIX route-map NAME` keeps the prefix while noting the
route-map (lr's `networks` is a plain prefix list). The
route-reflector loop-detection attributes the per-route filter
context rides on have landed: `lr-policy::filter::ast::RouteFieldKind`
gains `BgpAtomicAggregate` (RFC 4271 §5.1.6), `BgpOriginatorId` and
`BgpClusterList` (RFC 4456 §8), exposed through the filter DSL as
`bgp.atomic_aggregate` (Bool), `bgp.originator_id` (IpAddr::V4) and
`bgp.cluster_list` (Set of IpAddr::V4) — `lr-policy::bgp` carries
the matching `atomic_aggregate`, `originator_id`, `cluster_list` and
`has_cluster_list` helpers that read by tag from `Route.attributes`,
and `lr-bgp::path::PathAttributes` gains `originator_id()` and
`cluster_list()` typed accessors alongside the existing
`atomic_aggregate()` and `aggregator()`. The BIRD translator renames
`bgp_atomic_aggregate` / `bgp_originator_id` / `bgp_cluster_list`
to the lr dotted spellings, and the corpus case
`tests/corpus/bird/bgp-rr-loop-filter.conf` exercises all three in
the canonical RR loop-detection idiom (`defined(bgp.cluster_list) &&
local_cluster ~ bgp.cluster_list`, `bgp.originator_id == local_id`,
`bgp.atomic_aggregate`). What remains is the rest of the
per-protocol attribute surface — BIRD's route attributes that ride
the per-route filter context — beyond the RR loop-detection subset
that just landed.
The conversion corpus has landed: `tests/corpus/{bird,frr}/` pairs
every representative BIRD and FRR config with the exact
`.expected.toml` the converter emits, covering the BGP/Babel/OSPF
shapes the converter maps today. Two harnesses share the same data
files — the in-crate `translate::corpus_tests` unit test
(`crates/lr-cli/src/corpus_tests.rs`, drives the converter functions
directly, runs on every platform in `cargo test`) and the
`tests/interop/translate_corpus.sh` end-to-end gate (drives the real
`lr-daemon translate` CLI binary, runs in the Linux interop CI job).
Both honour `LR_CORPUS_UPDATE=1` to regenerate the golden files after
an intentional converter change; every `.expected.toml` round-trips
through the daemon loader so the "generated TOML is always loadable"
contract is machine-checked. A new dialect quirk now adds a corpus
case (input + expected) instead of a bespoke assertion. What remains
is the per-protocol attribute surface named above; the corpus grows
as each new shape lands.

## Tooling and supply chain

**Supply-chain follow-ups.** `cargo audit` and `cargo deny check` run
nightly (`.github/workflows/nightly.yml`, `deny.toml`). The
CycloneDX SBOM per release has landed: the `generate-sbom` job in
`.github/workflows/release.yml` runs `cargo cyclonedx --describe
binaries --all-features --spec-version 1.5` on every `v*` tag push
and attaches one CycloneDX 1.5 JSON SBOM per shipped binary target
(`lr`, `lr-daemon`, `lrctl`, `lr-ffi`) plus a combined
`librouting-sbom-<tag>.tar.gz` to the GitHub release. Each SBOM
carries the binary's transitive crate closure under
`--all-features`, so a consumer pairing an archive with its SBOM
sees the exact dependency set shipped. The workflow stages the
SBOMs into clean `librouting-<binary>-<tag>.cdx.json` filenames
and runs an inline JSON validation pass before upload, so a
malformed SBOM fails the release early instead of shipping
silently. Cosign keyless signing has landed alongside the SBOM:
the `sign-artifacts` job in `release.yml` signs every release
artifact (platform archives, SBOMs, standalone headers) with
cosign keyless signing via GitHub Actions OIDC, anchored at the
Sigstore Fulcio certificate authority and recorded in the Rekor
transparency log. Each artifact gets a single DSSE `.bundle`
file (cosign 2.x's recommended shape — the signature, the
Fulcio certificate and the Rekor entry in one file), and the
job runs an inline `cosign verify-blob` pass against the
workflow's own OIDC identity before upload, so a broken bundle
never reaches the GitHub Release. A consumer verifies with
`cosign verify-blob --bundle <file>.bundle
--certificate-identity-regexp 'https://github.com/TES286-org/librouting/.github/workflows/release.yml@refs/tags/.*'
--certificate-oidc-issuer https://token.actions.githubusercontent.com <file>`;
no project-held key is needed. The static-analysis scan has
landed: an `api-surface` job in `.github/workflows/ci.yml` runs
on every push and every PR, and an `api-surface` job in
`.github/workflows/nightly.yml` runs on the nightly cron, both
running `cargo semver-checks --workspace --all-features
--baseline-rev <latest-tag>` (the gate — a violation fails the
job) and `cargo public-api -p <crate> diff <latest-tag>..HEAD
--simplified` per library crate (the report — the per-crate
Added/Changed/Removed breakdown is uploaded as an
`api-surface-diff` artifact for review). The pre-1.0 freeze
criteria in `docs/RELEASE-PLAN.md` §1 already imply a breaking
change ships as a minor bump; `cargo semver-checks` catches the
accidental kind that slips past review. All three gaps in this
ROADMAP entry are now closed. The `cargo semver-checks` gate
became blocking at the release cut that cleared the pre-existing
semver debt the scan first surfaced (a new variant in
`lr-bgp::path::AttrType` added since the previous release
without a matching version bump). The workspace version lives
in `[workspace.package] version` in `Cargo.toml`.

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
