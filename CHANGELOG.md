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

- ROADMAP-v3 D2.3 — `lr_bgp::roa_store::RoaStore`, a thread-safe
  two-layer ROA database with atomic snapshot swaps:
  - **Static + RTR provenance layers.** Static entries
    (`[[roa]]` config, FFI) survive cache expiry and are replaced only
    by `replace_static` (config reload); RTR entries follow the RFC
    8210 lifecycle (`apply_rtr_deltas` per sync, `clear_rtr` on §6
    data expiry or cache change).
  - **Atomic whole-table swaps.** Every mutation rebuilds the merged
    entry set and swaps one `Arc<RoaTable>` under a `RwLock`; readers
    clone the Arc under a read lock and validate lock-free — a reader
    never sees a half-applied sync (arc-swap semantics without the new
    dependency). Sort + dedup keeps the table deterministic; §5.6
    duplicates coalesce and §12 code-6 withdrawals no-op naturally.
  - `RoaTable::from_entries` and the `RoaEntry` `Ord` derive are new
    (non-breaking); 11 unit tests including a concurrent-reader
    smoke test.
- ROADMAP-v3 D2.4 — `[bgp.rpki]` configuration + daemon RTR thread:
  - `[bgp.rpki] cache / refresh_interval / retry_interval /
    expire_interval` (fail-closed parsing, syntax-checked cache
    address, non-zero intervals) plus `--rpki-cache`, `--rpki-refresh`,
    `--rpki-retry`, `--rpki-expire` flags. The configured intervals
    are the *initial* §6 timers — a v1+ cache overrides them from
    every End-of-Data PDU. `RtrClient::set_intervals` (new,
    non-breaking) injects them.
  - `lr-cli::daemon_rpki`: one thread per configured cache —
    connect/reconnect with the §6 retry backoff, framing-aware decode
    + `on_pdu`, `poll` driving refresh and expiry, atomic delta
    application into the shared `RoaStore`, §6 expiry withdrawing the
    cache-sourced records. The filter DSL's `roa.state` and the
    `roa_validate` import hook read the live store (cache updates
    apply without recompilation). A grep-friendly `rpki:` line
    (cache/state/version/phase/session/serial/roas/intervals/
    last-sync) joins the runtime API `status` output.
  - Daemon e2e against the mock cache:
    `tests/interop/rtr_lr.sh` (API-verified sync + reconnect) and 3
    cargo e2e tests (`crates/lr-cli/tests/daemon_rpki.rs`).
- ROADMAP-v3 D2.5 — SIGHUP / API `reload` hot reload for RPKI:
  - The fresh config's `[[roa]]` tables replace the store's static
    layer wholesale (malformed reload-time ROAs keep the current
    entries — reload never half-applies); an rpki cache address change
    drops the transport, resets the session memory (§8.2) and
    withdraws the old cache's records; a same-address reload forces a
    fresh incremental query. E2E: SIGHUP re-points a running daemon
    from cache A to cache B (API-verified `roas=4 (static=2 rtr=2)`).
- FFI — `lr_roa_store_*` for C/C++/Go/Python embedders:
  `lr_roa_store_new/free/replace_static/apply_deltas/clear_rtr/len/
  validate` with the `LR_ROA_VALID/_NOT_FOUND/_INVALID` outcomes.
  cbindgen header regenerated; C harness + C++ `librouting.hpp`
  RAII (`make_roa_store`, `roa_store_replace_static/apply_deltas/
  validate`) covered by `tests/ffi/harness.{c,cpp}`; Go `RoaStore`
  type (`bindings/lr-go`) and Python `RoaStore` (`bindings/lr-python`,
  new `roa.py` module) with tests.

- ROADMAP-v3 D2.2 — RTR client state machine,
  `lr_bgp::rtr::client::RtrClient` (RFC 8210 §6-§8):
  - **Transport-agnostic client.** The embedder owns the socket, the
    clock and the live `RoaTable`; `RtrClient` owns the protocol.
    `on_connect()` emits the §8.1 query (Serial Query with the
    remembered `(session_id, serial)`, else Reset Query), `on_pdu()`
    consumes one decoded PDU (now carrying its wire version for §7
    negotiation) and returns the next step, `poll()` applies the §6
    refresh/retry/expire timing rules.
  - **Atomic ROA deltas per sync.** Prefix PDUs accumulate in a
    per-sync batch; the End-of-Data step carries the diff of the
    authoritative record sets — one sync = one atomic delta batch
    (or a `snapshot()` swap), never a half-applied database.
    Duplicates (§5.6) coalesce and unknown withdrawals (§12 code 6)
    no-op, both logged — BIRD's lenient channel semantics.
  - **Full client rule coverage:** §7 version downgrade on the first
    lower-version PDU (Serial Notifies ignored during startup),
    §5.2 immediate Serial Query on notify, session-ID change
    re-issuing a Reset Query, §8.3 Cache-Reset re-query, §12
    No-Data-Available vs. fatal error reports, v0 End-of-Data
    default intervals, and expire-window reporting.
  - 19 unit tests, one per protocol rule. The codec module moved to
    `rtr/pdu.rs` with `rtr/client.rs` alongside; `rtr::decode` now
    returns the PDU's wire version (needed by the negotiation).
- ROADMAP-v3 D2.1 — RPKI-Router (RTR) protocol PDU codec,
  `lr_bgp::rtr` (RFC 8210 versions 0-2):
  - **11-variant PDU enum + framing codec.** Serial Notify, Serial
    Query, Reset Query, Cache Response, IPv4/IPv6 Prefix,
    End-of-Data (v0 12-byte and v1 24-byte forms), Cache Reset,
    Router Key, Error Report, and the ASPA PDU (type 11, version 2 —
    SIDROPS ASPA profile, the shape BIRD's `proto/rpki` implements;
    the roadmap previously mis-cited RFC 8281, which is PCEP).
    `rtr::decode` is framing-aware (`Ok(None)` while a PDU is
    partially buffered) and `rtr::encode` writes exact wire lengths.
  - **BIRD-parity validation on decode.** Version-gated PDU types
    (Router Key ≥ 1, ASPA ≥ 2), the 64 KiB PDU ceiling, per-type
    minimum/exact lengths, prefix invariants (`prefix_len ≤ family
    width`, `max_len ≥ prefix_len`, `max_len ≤ family width`), host
    bit masking, reserved flag-bit normalization, and internal
    length consistency for Error Report and ASPA bodies. The nine
    RFC 8210 §12 error codes are a closed enum with the
    fatal/no-data distinction.
  - **29 unit tests** pin byte-exact wire forms from the RFC 8210 §5
    figures, framing behavior, and the malformed-input paths.
  - **Live interop with BIRD 2.** The new `rtr_cache_mock` example
    (`cargo build -p lr-bgp --example rtr_cache_mock`) serves a
    fixed two-ROA dataset through the codec, and
    `tests/interop/rtr_bird.sh` runs BIRD's RPKI client against it:
    BIRD's Reset Query decodes through `lr_bgp::rtr`, the §7
    version downgrade to v1 works, and our Cache Response + Prefix
    + End-of-Data encodings install `192.0.2.0/24-24 AS64512` and
    `2001:db8::/48-64 AS64512` into BIRD's roa4/roa6 tables
    (birdc-verified). Wired into the CI interop job.
- ROADMAP-v3 D6 — fuzzing, property tests, performance benchmarks
  and RFC wire conformance vectors:
  - **`Prefix::network` IPv6 bug fix.** The previous
    implementation zeroed byte `full_bytes` *before* applying
    the partial-byte mask when `rem_bits > 0`, so the mask
    operated on `0x00` and the partial-byte network bits were
    dropped. For a `/31` prefix, byte 3 holds 7 network bits +
    1 host bit; the old code zeroed all of byte 3 and only then
    AND-ed with `0xfe`, leaving byte 3 at `0x00` regardless of
    the original. OSPFv3 LSA origination, BGP-LS export and
    LDP transit-prefix installation all call `.network()` and
    would silently install wrong addresses for any non-byte-aligned
    IPv6 prefix. Fix: skip byte `full_bytes` in the zeroing loop
    when `rem_bits > 0`, then mask in place — symmetric to the
    v4 path. Two regression tests pin the fix.
  - **proptest suite.** `crates/lr-policy/tests/proptest.rs`
    adds 9 property tests covering prefix-lattice invariants
    (reflexivity, antisymmetry, transitivity), `Prefix::network`
    idempotence and containment, `PrefixList::evaluate`
    first-match semantics, and filter-DSL parser robustness
    (never panics, pure compilation).
  - **RFC conformance vectors.** `crates/lr-bgp/tests/rfc_vectors.rs`
    pins 15 byte-exact wire forms from RFC 4271 (header / OPEN /
    UPDATE / KEEPALIVE / NOTIFICATION), RFC 4486 (Cease /
    Administrative Shutdown), RFC 5492 (capability TLV) and
    RFC 6793 (4-byte AS capability via AS_TRANS).
  - **Criterion benchmarks.** Four bench harnesses under
    `crates/{lr-bgp,lr-policy,lr-rib}/benches/` pin the codec /
    ROA / filter / RIB hot paths. The numbers are the immutable
    baseline the future optimisation work (D8.4 radix trie,
    D3.7 bytecode VM, D15 sharded RIB) will be measured against.
  - **cargo-fuzz targets.** Standalone `fuzz/` workspace with
    three targets — `bgp_decode`, `filter_parser`, `roa_validate`
    — asserting the security contract: never panic / abort / UB
    on arbitrary input. Each ships with a hand-picked seed
    corpus under `fuzz/seeds/<target>/`.
  - **Nightly CI** gained a `fuzz` job (5 min per target,
    non-blocking, uploads crash artifacts) and a `bench-smoke`
    job (workspace criterion run, reduced sample size, uploads
    reports as artifacts).
- ROADMAP-v3 D7 — nightly `cargo deny check` CI step fixed. The
  job had been failing on every run since cargo-deny 0.20 because
  it invoked `cargo deny check --all-features`, but cargo-deny
  0.20+ rejects `--all-features` (it operates on `Cargo.lock`,
  not on the build manifest). Separately, `cbindgen v0.27.0`
  ships under MPL-2.0 which was not on the license allow-list —
  MPL-2.0 is OSI-approved, FSF-libre, file-level copyleft that
  only affects `cbindgen` (a build-time-only dependency of
  `lr-ffi`'s `build.rs`). Added to `deny.toml` with rationale.
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
- RFC 2439 route flap damping wired into the daemon (D4.3). The
  `lr-damping` crate shipped in rc.3 as dead code; the daemon now
  exposes it via a `[damping]` TOML table with eight tunables
  (`additive_incr`, `suppress_threshold`, `reuse_threshold`,
  `upper_limit`, `decay_interval_s`, `decay_factor_active`,
  `decay_factor_withdrawn`, plus `enabled`). When `enabled = true`,
  the daemon installs `lr_policy::hooks::DampingImportHook` on the
  import chain and spawns a `lr-damping-decay` thread that drives
  `DampingTable::decay_all` every `decay_interval_s`. The
  `ImportHook` trait gained an `on_withdraw` default no-op
  notification so the damping hook can also track the
  unreachable-transition FoM increment (router's
  `withdraw_from_session` now notifies the chain). Off by default
  (RFC 7196 §3: RFC 2439 defaults are harmful on Internet-facing
  eBGP). Four unit tests + five TOML parsing tests cover the new
  behaviour.
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
- RustCrypto family bumped to the 2025 releases (issue #12):
  `hmac` 0.12 → 0.13, `sha1`/`sha2`/`blake2` 0.10 → 0.11, all on
  `digest` 0.11 / `crypto-common` 0.2. The four crates move as one
  atomic change — bumping any of them alone splits the tree across
  two incompatible `digest` versions and cannot compile
  (`Hmac<Sha256>` would implement traits from both). Call-site
  migration: MAC key setup resolves through `KeyInit` now (it moved
  off `Mac`), so `<Hmac<Sha1> as Mac>::new_from_slice` UFCS became
  `Hmac::<Sha1>::new_from_slice` with `KeyInit` in scope. Behavior
  is unchanged: the RFC 5709 HMAC-SHA-1/SHA-256 vectors, the RFC
  8967 Babel MAC vectors (HMAC-SHA256 + keyed BLAKE2s-128) and the
  exchange-plane tag tests all pass byte-identically, and the
  `babel_auth.sh` interop lab (challenge resync, wrong-key fail
  closed, incremental deployment) passes against BIRD. All new
  transitive dependencies (`hybrid-array`, `ctutils`, `cmov`,
  `const-oid`, `cpufeatures` 0.3) are `MIT OR Apache-2.0` and
  require Rust ≥ 1.85 — below the workspace MSRV 1.88.
- Dependabot now groups the RustCrypto family (`hmac`, `sha1`,
  `sha2`, `blake2`) into one PR covering major/minor/patch updates.
  Dependabot reads 0.x minor-position bumps as major, which the
  production-dependencies group (minor+patch only) excluded, so the
  0.10 → 0.11 generation landed as four independent PRs (#7-#10)
  that each broke the dependency tree on their own. The dedicated
  group keeps the family on a single `digest` version per PR.

### Deprecated

Nothing yet.

### Removed

Nothing yet.

### Fixed

- `lr-ospf::exchange::DbExchange::poll` retransmits the pending
  initial DBD in ExStart (issue #11). The periodic retransmission
  only fired in Phase::Exchange, so the initial Database Description
  (I|M|MS) sent on entering ExStart was never repeated: one lost
  initial DBD — or one dropped by a peer whose §10.4 DR/BDR gate had
  not opened yet (the runtime drops DBDs below ExStart until the
  election makes `adjacency_viable()` true) — deadlocked the
  adjacency with both sides waiting in ExStart for the other's
  initial while Hellos kept the neighbor alive, and the
  `ospf_broadcast.sh` interop lab hung until its 60 s timeout
  (~10 % of CI runs). RFC 2328 §10.3/§10.8 have the master repeat
  Database Descriptions at RxmtInterval, and BIRD's
  `dbdes_timer_hook` resends in NEIGHBOR_EXSTART for both roles; the
  fix mirrors that. Verified: 20/20 consecutive lab runs green after
  the fix (1 failure in 10 before), two regression tests model the
  deadlock conversation.
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
