# Changelog

All notable changes to librouting are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 release candidates (`1.0.0-rc.N`) freeze the public API;
breaking changes after a `-rc` lands are recorded under the next
`-rc` heading with a `BREAKING CHANGE:` marker.

The complete narrative for each landed workstream lives in
[`docs/ROADMAP.md`](docs/ROADMAP.md) (the v2 landing log) and
[`docs/ROADMAP-v3.md`](docs/ROADMAP-v3.md) (forward directions).
This file is the consumer-facing summary — protocol features that
ship, breaking changes that affect embedders, dependency bumps.

## [Unreleased]

### Added

- `Protocol::bird_name()` returns the canonical BIRD-style
  lowercase protocol name used by the Filter DSL `proto` field.
  `Bgp -> "bgp"`, `Ospfv2 -> "ospf"`, `Ospfv3 -> "ospf3"`,
  `Babel -> "babel"`, `Static -> "static"`, `Connected -> "direct"`,
  `Other(_) -> "unknown"`. `lr-core::rib::Protocol` gained the new
  method; `lr-policy::filter::eval` uses it instead of the Rust
  `Debug` form, so `proto == "bgp"` now matches a BGP route.
- RFC 8326 Graceful BGP Session Shutdown (sender side):
  `Community::GRACEFUL_SHUTDOWN` (`0xFFFF:0000`) is now the
  canonical alias for the legacy `PLANNED_SHUTDOWN` constant at
  the same wire value; `CommunityKind::GracefulShutdown` is added
  to the classification enum; the export hook
  `lr_policy::hooks::GracefulShutdownExportHook` zeroes
  `LOCAL_PREF` on any route carrying the community while preserving
  the community itself so downstream peers see the signal. The
  daemon installs the hook always-on for BGP. `PathAttributes`
  gained a `set_local_pref(u32)` helper. Six regression tests
  cover the new behaviour.
- `docs/ROADMAP-v3.md` captures the 15 post-rc.3 maturity
  directions, grouped into four priority tiers (T1 immediate value,
  T2 high practical value, T3 engineering maturity, T4 long-term
  protocol breadth).
- Supply-chain hardening:
  - `deny.toml` for `cargo-deny` (advisories, licenses, bans,
    sources).
  - `.github/dependabot.yml` for weekly Cargo + GitHub Actions
    dependency bumps.
  - New `supply-chain` job in `.github/workflows/nightly.yml`
    running `cargo audit` and `cargo deny check`.
- Governance documents at the repo root: `CONTRIBUTING.md`
  (PR checklist, commit message format, test layers, RFC pinning
  procedure), `SECURITY.md` (vulnerability reporting, 90-day
  embargo, threat model), `CODE_OF_CONDUCT.md` (Contributor
  Covenant 2.0).

### Changed

- The Filter DSL `proto` field no longer returns the Rust `Debug`
  string form (`"Bgp"`, `"Ospfv2"`, …). Existing filter bodies that
  matched against the Rust `Debug` form will no longer match — the
  BIRD-style lowercase form documented in the `RouteFieldKind::Proto`
  docstring has always been the intended surface, and is now what
  the evaluator produces.

### Deprecated

Nothing yet.

### Removed

Nothing yet.

### Fixed

- `lr-policy::filter::eval::read_route_field` no longer leaks the
  Rust `Debug` form of `Protocol` into the string surface of the
  Filter DSL `proto` field.

### Security

Nothing yet. Vulnerability disclosures follow the embargo in
[`SECURITY.md`](SECURITY.md); security-relevant fixes land here under
a dedicated `### Security` subsection when they ship.

## [1.0.0-rc.3] — multi-protocol daemon

### Added

- Multi-protocol supervisor — `lr-daemon` can run BGP, OSPF and
  Babel sessions in one process, with cross-protocol Loc-RIB
  merging for shared routers.
- `[[babel.interface]]` TOML table with full RFC 8966 §A.2
  parameter parsing.
- `[[roa]]` TOML table for static ROA loading.
- `[[filter]]` TOML table for BIRD-like filter DSL.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full v2 workstream
narrative that landed in this release candidate.

## [1.0.0-rc.2] — CLI binaries in the release

### Added

- `lr` and `lr-daemon` CLI binaries included in per-OS release
  archives.

## [1.0.0-rc.1] — the API-freeze pre-release

### Added

- Public API freeze. Every crate ships under the dual `MIT OR
  Apache-2.0` license. See [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md)
  for the freeze criteria that gate 1.0.
