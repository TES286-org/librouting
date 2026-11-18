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

**Egress Peer Engineering (RFC 9086), controller mode.** The codec and
the daemon-side projection (`lr-router::instance::epe`,
`DefaultRouter::bgpls_republish_epe`) are implemented. What remains is
the receiver-side follow-up: a controller-mode daemon receives EPE NLRIs
from its BGP-LS peers and surfaces them through its Loc-RIB. That
touches the daemon's Loc-RIB model (`RouteKey { prefix, family }` does
not fit a BGP-LS NLRI) and is independent of the projection. Done when
a controller learns those segments from lr, the data plane can push
traffic onto them, and a controller-mode lr daemon can ingest the same
NLRIs another daemon advertises.

## Compatibility

**RISC-V targeted compatibility improvements.** The CI matrix covers
the RISC-V architecture in two ways: the
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
architectures in two ways: the
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
`ubuntu-26.04-s390x` label and ppc64le native jobs can land. The
follow-up is tracked on the issue tracker.

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
