# Changelog

All notable changes to librouting are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 release candidates (`1.0.0-rc.N`) freeze the public API;
breaking changes after a `-rc` lands are recorded under the next
`-rc` heading with a `BREAKING CHANGE:` marker.

The narrative for each landed workstream is the commit history; this file
is the consumer-facing summary — protocol features that ship, breaking
changes that affect embedders, dependency bumps. Forward-looking work
lives in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## [Unreleased] — minor: PMSI Tunnel, OSPF + Babel filter DSL, peer-health

The next minor release exposes the RFC 6514 §5 PMSI Tunnel attribute
in the filter DSL as `bgp.pmsi_tunnel` (read-only `bool` — `true`
when the attribute is present, `false` when absent), the RFC 2328
§16 / RFC 5340 §4.1 primary OSPF metric as `ospf.metric1` (read-only
`int` — `0` when the route is not OSPF, mirroring BIRD's eattr
default for an unattached `ospf_metric1` reference), the RFC 2328
§16.4 / RFC 5340 §4.8.5 type-2 external OSPF metric as `ospf.metric2`
(read-only `int` — `0` when the route is not a type-2 external,
mirroring BIRD's eattr default for an unattached `ospf_metric2`
reference), the RFC 2328 §A.4.5 bullet h / RFC 3101 §2.3 /
RFC 5340 §A.4.7 T bit / RFC 8362 §3.6 External-Prefix sub-TLV 3
external route tag as `ospf.tag` (read-only `int` — `0` when the
route carries no tag, mirroring BIRD's eattr default for an
unattached `ospf_tag` reference), the RFC 2328 §A.4 /
RFC 5340 §A.4 OSPF `Advertising Router` field as `ospf.router_id`
(read-only `int` — `0` when the route carries no OSPF router-id
attribute, mirroring BIRD's eattr default for an unattached
`ospf_router_id` reference), the RFC 8966 §3.2 + §3.4.3 primary
Babel metric as `babel.metric` (read-only `int` — `0` when the
route is not Babel, mirroring BIRD's eattr default for an
unattached `babel_metric` reference), the RFC 8966 §3.2 + §4.6.9
Babel sequence number as `babel.seqno` (read-only `int` — `0`
when the route is not Babel, mirroring BIRD's eattr default for
an unattached `babel_seqno` reference — RFC 8966 §3.1 treats 0 as
a valid sequence number, so `defined(babel.seqno)` distinguishes
"non-Babel route" from "Babel route with seqno 0"), and the RFC
8966 §3.2 + §4.6.8 Babel Router-ID as `babel.router_id`
(read-only `int` — `0` when the route is not Babel, mirroring
BIRD's eattr default for an unattached `babel_router_id`
reference — though BIRD stores the value as an opaque 8-byte
bytestring under `EAF_TYPE_OPAQUE`, lr's DSL exposes it as a
64-bit `Int` for the canonical `defined(babel.router_id)` idiom
and for direct equality against the route's i64-form literal;
`defined(babel.router_id)` distinguishes "no attribute" from
"attribute present but zero" — RFC 8966 §3.1 does not forbid
Router-ID 0, the EUI-64 form discourages it but the protocol
accepts any 64-bit value). Per `docs/RELEASE-PLAN.md` §1, the
public Rust API gains new surface (`RouteFieldKind::BgpPmsiTunnel`,
`RouteFieldKind::OspfMetric1`, `RouteFieldKind::OspfMetric2`,
`RouteFieldKind::OspfTag`, `RouteFieldKind::OspfRouterId`,
`RouteFieldKind::BabelMetric`, `RouteFieldKind::BabelSeqno`,
`RouteFieldKind::BabelRouterId`,
`AttrType::LrOspfMetric2`, `AttrType::LrOspfRouterId`,
`AttrType::LrBabelSeqno`, `AttrType::LrBabelRouterId`, sixteen new
`FilterContext` trait methods with default impls, the
`lr-policy::bgp::{pmsi_tunnel, has_pmsi_tunnel}` helpers, the
`lr-policy::ospf::{metric1, has_metric1}` helpers, the
`lr-policy::ospf::{metric2, has_metric2}` helpers, the
`lr-policy::ospf::{tag, has_tag}` helpers and the new
`lr-policy::ospf::{router_id, has_router_id}` helpers, the new
`lr-policy::babel::{metric, has_metric}` / `{seqno, has_seqno}` /
`{router_id, has_router_id}` helpers, the
`lr-bgp::path::well_known::PmsiTunnel` typed view, the
`lr-bgp::path::PathAttributes::pmsi_tunnel` / `has_pmsi_tunnel`
accessors, the `lr-bgp::path::PathAttributes::set_ospf_metric2`
/ `ospf_metric2` / `has_ospf_metric2` accessors, the new
`lr-bgp::path::PathAttributes::set_ospf_router_id` /
`ospf_router_id` / `has_ospf_router_id` accessors, the new
`lr-bgp::path::PathAttributes::set_babel_seqno` / `babel_seqno`
/ `has_babel_seqno` accessors, the new
`lr-bgp::path::PathAttributes::set_babel_router_id` /
`babel_router_id` / `has_babel_router_id` accessors, the new
`Attributes::get_u64_be` helper on `lr-core::attr`, the new
`router_id: Option<u32>` field on `lr-ospf::spf::SpfRoute`, and two
new public fields on `lr-ospf::external::ExternalRoute` and
`ExternalRouteV3` carrying the LSA's external route tag); the new
`RouteFieldKind`, `AttrType` and `SpfRoute` / `ExternalRoute` /
`ExternalRouteV3` variants are a breaking change for downstream
`match` exhaustiveness and struct-literal construction, which the
`api-surface` CI gate will catch when the version cuts. The C ABI
surface is unchanged (no new `lr_*` symbols, `ABI_VERSION` stays
at 2); the FFI callback table `lr_filter_context_t` is untouched —
the new `FilterContext` methods carry default implementations that
delegate to `lr_policy::bgp` and `lr_policy::ospf`, so every
existing embedder inherits the correct behaviour without
recompiling.

### Changed (CI)

**s390x native CI switches to a self-hosted runner; ppc64le native
gated on runner availability** (`ci`,
[issue #95](https://github.com/TES286-org/librouting/issues/95)).
The `ibm-pz-native` matrix job (introduced in the previous round
above, running on the three IBM-provided `ubuntu-26.04-ppc64le`,
`ubuntu-26.04-ppc64le-p10` and `ubuntu-26.04-s390x` labels from
the IBM Power-Z GitHub App) is replaced by a single
`s390x-native` job that runs on a self-hosted s390x runner
registered with the labels `[self-hosted, Linux, s390x]`. The
IBM-provided labels are pending review and not yet available, so
the s390x gate rides on the self-hosted runner in the meantime.

The ppc64le native entries are removed from the matrix until a
runner lands: there is no self-hosted ppc64le runner registered
yet, and the IBM-provided `ubuntu-26.04-ppc64le` /
`ubuntu-26.04-ppc64le-p10` labels are pending the same review.
ppc64le coverage therefore stays limited to the `cross` matrix
(cross-build only, no test) until the IBM-provided runner clears
review or a self-hosted ppc64le runner is registered. The open
work is tracked on [issue #95](https://github.com/TES286-org/librouting/issues/95)
— reopened for this follow-up.

Job shape is otherwise unchanged: `cargo clippy --workspace
--all-features --all-targets -- -D warnings`, `cargo build
--workspace --all-features`, `cargo nextest run --workspace
--all-features`, `cargo test --doc --workspace --all-features`,
plus the two lr-vs-lr loopback interop smoke labs
(`two_daemon.sh` + `labeled_unicast.sh`) the `windows-interop`,
`macos-interop` and `riscv-native` jobs run. clippy runs per-arch
for the same reason the `cross-platform` matrix runs it per-OS:
arch-conditional code (the `c_char` signed/unsigned cast pattern
in `lr-ffi::core` and `lr-ffi::srv6`) only compiles on its own
architecture, so a per-arch lint pass catches future regressions
the x86_64-only `lint` job would miss. fmt is NOT re-run;
rustfmt is deterministic and platform-independent, and the `lint`
job already gates it on every push.

`s390x-unknown-linux-gnu` is Rust Tier 2 with host tools on stable
(<https://forge.rust-lang.org/release/platform-support.html>), so
the workspace's pinned stable toolchain (`rust-toolchain.toml`)
installs a working `rustc` + `cargo` natively on the runner. No
nightly-only codegen or stdlib feature is needed for the project's
hot paths; `RUSTFLAGS` is left at its default. s390x is the only
big-endian target in the matrix, so the wire-codec byte-order
discipline (`to_be_bytes` / `from_be_bytes` everywhere, never
native endianness) is mechanically verified on every push on
that architecture.

`cargo-nextest` does not ship prebuilt binaries for s390x
(<https://github.com/nextest-rs/nextest/releases>), so
`taiki-e/install-action@v2` falls back to a `cargo install` from
source on this architecture; the cold-cache install is ~3-5 min
on the s390x hardware and reuses the cached cargo registry on
subsequent runs.

If no self-hosted s390x runner is registered on the repository,
GitHub marks the `s390x-native` job "no runner found" after the
timeout — it never blocks merge. The `cross` matrix entry covers
the gap until a runner is registered. Once the IBM-provided
`ubuntu-26.04-s390x` runner clears review, the `s390x-native` job
can switch to (or matrix-add) that label and ppc64le native jobs
can land.

`docs/INTEROP.md` (Where the labs run) replaces the `ibm-pz-native`
row with an `s390x-native` row and adds a paragraph explaining the
ppc64le gap. `docs/ROADMAP.md` and `docs/STATUS.md` update the
"IBM Power (ppc64le) and IBM Z (s390x)" entry to reflect the
self-hosted s390x runner and the ppc64le native follow-up.
`docs/RELEASE-PLAN.md` §2.4 mirrors the change and §2.8's
verification table renames `ibm-pz-native` to `s390x-native`.

### Added

**IBM Power (ppc64le) and IBM Z (s390x) CI matrix** (`ci`,
[issue #95](https://github.com/TES286-org/librouting/issues/95)).
The CI workflow in `.github/workflows/ci.yml` now covers the IBM
Power (`ppc64le`) and IBM Z (`s390x`) architectures in two ways,
mirroring the RISC-V (issue #65) split. The existing `cross` matrix
job gains `powerpc64le-unknown-linux-gnu` and
`s390x-unknown-linux-gnu` alongside `aarch64-unknown-linux-gnu`,
`x86_64-pc-windows-gnu` and `riscv64gc-unknown-linux-gnu`: the apt
install step pulls in `gcc-powerpc64le-linux-gnu` +
`libc6-dev-ppc64el-cross` and `gcc-s390x-linux-gnu` +
`libc6-dev-s390x-cross`, the per-target linker env block gains
`CARGO_TARGET_POWERPC64LE_UNKNOWN_LINUX_GNU_LINKER=powerpc64le-linux-gnu-gcc`
and
`CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER=s390x-linux-gnu-gcc`,
and `cargo build --workspace --target <target> --all-features` runs
on every push. This is the safety net: even on a fork where the IBM
Power-Z GitHub App is not installed, the cross-build still produces
a linkable artifact on a plain `ubuntu-latest` runner.

A new `ibm-pz-native` matrix job runs on the three IBM Power-Z
runner labels — `ubuntu-26.04-ppc64le` (IBM POWER9),
`ubuntu-26.04-ppc64le-p10` (IBM POWER10), `ubuntu-26.04-s390x`
(IBM Z), provided by the IBM Power-Z GitHub App
(<https://github.com/marketplace/power-z-gha-runner>,
<https://github.com/IBM/actionspz>). Each matrix entry mirrors the
existing `riscv-native` job: `cargo clippy --workspace --all-features
--all-targets -- -D warnings`, `cargo build --workspace --all-features`,
`cargo nextest run --workspace --all-features`, `cargo test --doc
--workspace --all-features`, plus the two lr-vs-lr loopback interop
smoke labs (`two_daemon.sh` + `labeled_unicast.sh`) the Windows,
macOS and RISC-V native jobs already run, keeping the non-x86_64
coverage shape consistent. clippy runs per-arch for the same reason
the `cross-platform` matrix runs it per-OS: arch-conditional code
(the `c_char` signed/unsigned cast pattern in `lr-ffi::core` and
`lr-ffi::srv6`) only compiles on its own architecture, so a
per-arch lint pass catches future regressions the x86_64-only
`lint` job would miss. fmt is NOT re-run; rustfmt is deterministic
and platform-independent, and the `lint` job already gates it on
every push.

Toolchain choice: both `powerpc64le-unknown-linux-gnu` and
`s390x-unknown-linux-gnu` are Rust Tier 2 with host tools on stable
(<https://forge.rust-lang.org/release/platform-support.html>), so
the workspace's pinned stable toolchain (`rust-toolchain.toml`)
installs a working `rustc` + `cargo` natively on each runner. No
nightly-only codegen or stdlib feature is needed for the project's
hot paths: the BGP/OSPF/Babel wire codecs use `to_be_bytes` /
`from_be_bytes` (which the LLVM backend lowers to native loads +
byte-swap instructions on every target), and the filter DSL
bytecode VM is straight-line Rust that auto-vectorizes on ppc64le
VSX and s390x vx without target-specific intrinsics. `RUSTFLAGS`
is therefore left at its default; downstream users who want to
specialise a release build for a specific CPU generation can set
`RUSTFLAGS="-C target-cpu=native"` (POWER9 / POWER10 / z14 / z15)
in their own build, but the CI jobs stay portable across runner
generations.

The workspace is target-OS-aware, not target-arch-aware: the
socket constants, struct layouts and syscall numbers are identical
across every Linux architecture librouting targets (x86_64,
aarch64, riscv64, ppc64le, s390x). The kernel-gated `#[ignore]d`
tests (`route_kernel`, `srv6_kernel`) self-skip when they lack
`CAP_NET_ADMIN`, so the same `nextest` command runs unchanged on
each IBM runner. s390x is the only big-endian target in the matrix,
so the byte-order discipline the wire codecs already follow (every
multi-byte wire field uses `to_be_bytes` / `from_be_bytes`, never
native endianness) is mechanically verified on every push — a
regression that accidentally slipped in a `to_ne_bytes` on a wire
path would fail its assertion on s390x where native is big-endian
but the wire format is also big-endian, so the symptom differs
from the little-endian targets. This was verified locally with
`cargo check --workspace --target powerpc64le-unknown-linux-gnu
--all-features` and `cargo check --workspace --target
s390x-unknown-linux-gnu --all-features` — both clean.

If the IBM Power-Z GitHub App is not installed on the repository,
GitHub marks the `ibm-pz-native` job "no runner found" after the
timeout — it never blocks merge. The `cross` matrix entries cover
the gap until the App is installed. `cargo-nextest` does not ship
prebuilt binaries for ppc64le or s390x
(<https://github.com/nextest-rs/nextest/releases>), so
`taiki-e/install-action@v2` falls back to a `cargo install` from
source on these architectures; the cold-cache install is ~3-5 min
on the IBM hardware and reuses the cached cargo registry on
subsequent runs.

`docs/INTEROP.md` (Where the labs run) gains an `ibm-pz-native`
row and the surrounding paragraph is updated to explain the
deliberately small subset (mirrors the RISC-V note).

**`lr-ospf` / `lr-cli` OSPFv2 SimplePassword authentication wiring
(`SimplePassword::new`, `[ospf.auth]` TOML keys, `--ospf-auth-type` /
`--ospf-auth-password` CLI flags)** (issue #92 — `defects.txt`
`crates/lr-cli/src/daemon_ospf.rs:L42-L47` DOC-MISMATCH "Authentication
is not wired into the v2 daemon yet"). The `lr_ospf::auth` module
already implemented the wire codec for the three RFC 2328 §D
strategies (NullAuth, SimplePassword, CryptoAuth) and RFC 5709
HMAC-SHA, but the daemon's `daemon_ospf.rs` documentation explicitly
noted "Authentication is not wired into the v2 daemon yet" — a
configuration that set the au_type and auth_data fields had no effect
on outgoing packets, and a peer sending a credential the daemon did
not verify was silently admitted into the LSDB.

This round wires the two stateless strategies end-to-end:

- `lr_ospf::auth::SimplePassword::new(secret: &[u8])` constructor that
  pads short secrets to 8 bytes (RFC 2328 §D.2 fixes the auth_data
  field at 8 bytes) and truncates long ones — the previous shape
  required callers to build the `[u8; 8]` array by hand.
- `[ospf.auth]` TOML table with `type = "null" | "simple"` and
  `password = "..."` (for `simple`). Crypto auth (`type = "md5"`) is
  rejected at parse time with a clear "not wired into the daemon yet"
  message — the wire codec and `CryptoAuth` helper already exist in
  `lr_ospf::auth::crypto`; the per-packet trailer append and anti-replay
  state needed for daemon wiring is the next slice.
- `--ospf-auth-type` and `--ospf-auth-password` CLI flags (with the
  `--ospf-authentication-*` aliases for the long form), rejected at
  `parse_args` time on the same fail-closed rules as the TOML parser.
- `daemon_ospf.rs`'s `OspfDaemon` carries an
  `auth: Option<SimplePassword>` field built from the config. The send
  path applies auth to every outgoing packet (Hello, DD, LSR, LSU,
  LSAck, Grace-LSA): `apply_ospf_auth` sets au_type = 1, writes the
  password into the auth_data field, and zeroes the checksum so the
  subsequent `finalize_v2_packet` recomputes from the modified header.
  The receive path verifies auth on every received packet before the
  LSDB sees it: `verify_ospf_auth` drops a packet whose au_type or
  auth_data do not match (RFC 2328 §D.1 "If the authentication proves
  unsuccessful, the packet is dropped"), logging a single warning per
  drop so the operator can correlate a misconfigured peer with the
  silent adjacency.
- Startup log line surfaces the resolved strategy (`ospf auth: null`
  / `ospf auth: simple-password (AuType 1, 8-byte credential)`); an
  all-zero password (the wire-valid but weak `password = ""` case)
  logs a warning.
- The daemon's documentation header (`daemon_ospf.rs` module doc) no
  longer claims auth is not wired — it now describes the landed
  NullAuth + SimplePassword surface and names CryptoAuth as the
  follow-up.

The default is `null` (NullAuth, AuType 0) — every existing
configuration is unchanged; the new surface is purely additive.
`SimplePassword` is `Send + Sync` (a 9-byte Clone), so the auth
state is cloned out of `self` before the `&mut self.interfaces` send
loops — the borrow checker split the helper into a free-function
`apply_ospf_auth` / `verify_ospf_auth` pair the loops can call without
re-borrowing `self`. 21 new unit tests in
`crates/lr-cli/src/daemon_ospf_tests.rs` cover the codec default
(NullAuth au_type / all-zero auth_data), the apply/verify round-trip
(accept on match, reject on wrong password / wrong au_type /
truncated header), the build-from-config mapping (default → NullAuth,
explicit null → NullAuth, simple → SimplePassword, empty password →
all-zero credential), the config-parse coverage (simple, md5
rejection, unknown type rejection, unknown key rejection), and the
finalize-time validation (simple without password fails closed, long
password warns). 8 new unit tests in `crates/lr-ospf/src/auth/mod.rs`
cover the new `SimplePassword::new` constructor (pad, truncate, empty,
eight-byte round-trip) and the `Auth` trait surface (sign writes the
password, verify accepts signed / rejects mismatched, verify rejects
short header, au_type is SimplePassword).

**`lr-ospf` / `lr-cli` OSPFv2 CryptoAuth daemon wiring
(`[ospf.auth]` `crypto` keys, `--ospf-auth-key` /
`--ospf-auth-key-id` / `--ospf-auth-algorithm` CLI flags, anti-replay
state)** (issue #92 — `defects.txt`
`crates/lr-cli/src/daemon_ospf.rs:L42-L47` DOC-MISMATCH follow-up to
the SimplePassword round above). The `lr_ospf::auth::crypto` module
already implemented the RFC 2328 §D.3 / RFC 5709 wire codec and the
`CryptoAuth` helper (`sign_trailer` / `verify` with HMAC-SHA-1 and
HMAC-SHA-256 and the §D.3.3 anti-replay check), but the daemon still
rejected `type = "md5"` at parse time and the per-packet trailer
append / anti-replay state needed to flow through the daemon's send
and receive paths was the open follow-up.

This round wires the third strategy end-to-end:

- `[ospf.auth]` accepts `type = "crypto"` (alias `"md5"`,
  `"message-digest"`) with `key`, `key_id` (0..=255, RFC 2328
  §D.3.1) and `algorithm = "hmac-sha256" | "hmac-sha1"` (default
  `hmac-sha256`, RFC 5709 §2.2). Finalize-time validation: crypto
  requires `key` and `key_id`; a stale `password` key under crypto
  warns that it is ignored; SHA-1 warns that RFC 5709 §2.2 recommends
  SHA-256.
- `--ospf-auth-key`, `--ospf-auth-key-id`, `--ospf-auth-algorithm` CLI
  flags (with `--ospf-authentication-*` aliases) on the same fail-closed
  rules as the TOML parser.
- `OspfAuthState` enum replaces the prior `Option<SimplePassword>`:
  `None` = NullAuth, `Simple(SimplePassword)` = AuType 1, `Crypto(Arc<Mutex<CryptoAuth>>)`
  = AuType 2. The `Arc<Mutex<_>>` lets the send path advance the
  crypto_seq (RFC 2328 §D.3.2 "non-decreasing") and the receive path
  update the anti-replay `last_peer_seq` (§D.3.3 — strictly greater than
  the last-seen value) without re-borrowing `self`.
- `apply_ospf_auth` for Crypto: sets au_type = 2, writes the
  `(key_id | auth_data_len | crypto_seq | 0x0000)` auth_data field,
  finalizes the OSPF §A.1 checksum over the modified header + body
  (excluding the trailer per RFC 5709 §3 — the trailer is NOT counted
  in the OSPF length), then computes the RFC 5709 §3.3 HMAC over the
  finalized header + body and appends the trailer (Key ID + Auth Data
  Len + Crypto Seq + HMAC-SHA digest).
- `verify_ospf_auth` for Crypto: checks au_type = 2, extracts the
  trailer (length 6 + Auth Data Len from the header), and calls
  `CryptoAuth::verify(packet, trailer)` which compares the Key ID,
  Auth Data Len, MAC and the anti-replay crypto_seq.
- `v2_packet_checksum` now respects the OSPF length field (so an
  appended RFC 5709 trailer is excluded) and excludes the checksum
  field from the sum, making `finalize_v2_packet` idempotent — the
  send path can call `finalize_v2_packet` after `apply_ospf_auth`
  without overwriting the already-finalized checksum the MAC was
  computed over.
- Startup log line surfaces the resolved strategy (`ospf auth: crypto
  (AuType 2, RFC 2328 §D.3 + RFC 5709) — key_id=…, algorithm=…,
  crypto_seq=…`).
- The `daemon_ospf.rs` module doc no longer names CryptoAuth as a
  follow-up — the strategy table in `docs/lr-daemon-reference.md`
  lists all three strategies as wired.

The default is `null` (NullAuth, AuType 0) — every existing
configuration is unchanged; the new surface is purely additive. 16
new unit tests in `crates/lr-cli/src/daemon_ospf_tests.rs` cover the
apply path (writes au_type=2, the auth_data field, appends the
trailer; advances crypto_seq monotonically across packets; HMAC-SHA-1
trailer is 26 bytes vs 38 for SHA-256), the verify path (round-trip
against the same key; rejects tampered digest, wrong Key ID, wrong
key, wrong au_type, truncated trailer; anti-replay rejects a stale
crypto_seq), the config-parse coverage (crypto aliases `md5` /
`message-digest` / `crypto`, algorithm aliases `sha256` /
`hmac-sha-256` / `hmac-sha1` / `sha1`, unknown algorithm rejected),
the finalize-time validation (crypto without `key` fails closed,
crypto without `key_id` fails closed, SHA-1 warns, stale `password`
under crypto warns).

**`lr-ospf` / `lr-cli` OSPFv3 RFC 7166 authentication trailer wiring
(`[ospf.auth] type = "crypto"` under `[ospf] version = "v3"`, the
`OspfV3AuthState` daemon state, `apply_ospf_v3_auth` /
`verify_ospf_v3_auth` per-packet helpers)** (issue #92 — the v3
counterpart of the v2 CryptoAuth round above; the `lr_ospf::auth::v3_auth`
module already implemented the RFC 7166 wire codec and the FFI
surface already exposed it through `lr_ffi::ospf_auth::V3Auth`
constructors/accessors, but the daemon_ospf3 module ignored auth
entirely: a config that set `[ospf.auth] type = "crypto"` under
`[ospf] version = "v3"` had no effect on outgoing packets, and a peer
sending a credential the daemon did not verify was silently admitted
into the LSDB).

This round wires the v3 trailer end-to-end, mirroring the v2
CryptoAuth pattern:

- `OspfV3AuthState` enum: `None` = NullAuth (the default), `Crypto(Arc<Mutex<V3Auth>>)`
  = RFC 7166 trailer. The `Arc<Mutex<_>>` lets the send path advance
  `crypto_seq` (RFC 7166 §4.6) and the receive path update the
  anti-replay `last_peer_seq` without re-borrowing `self`.
- `build_ospf_v3_auth(cfg)` constructs the state from the existing
  `OspfAuthSpec` config: `type = "crypto"` (alias `"md5"`,
  `"message-digest"`) maps to `Crypto`, `key_id` widens to the v3
  16-bit `sa_id` (0..=255 fits in `u16`, the wire field stays 16 bits
  for a future `u16` SA ID without widening `OspfAuthSpec`), the
  algorithm defaults to HMAC-SHA-256 with `algorithm = "hmac-sha1"`
  override.
- `[ospf.auth] type = "simple"` under `[ospf] version = "v3"` is
  rejected at `finalize_ospf` time — RFC 5340 §A.3.1 removed the
  auth_data field from the header, so SimplePassword is not a v3
  strategy. The error message names RFC 7166 as the v3 alternative.
- `apply_ospf_v3_auth(&mut auth, &mut bytes, source_v6)` appends the
  trailer to an outgoing packet, zeroes the OSPFv3 header checksum
  (RFC 7166 §4.2 omits it from the MAC input when the AT is used),
  advances the `crypto_seq` and signs with the explicit `source_v6`
  (the interface's link-local). The OSPF length field stays at the
  body length (the trailer is NOT counted).
- `verify_ospf_v3_auth(&mut auth, &bytes, source_v6)` splits the
  datagram into packet + trailer at the OSPF length boundary and
  verifies the trailer (MAC, SA ID, anti-replay) with the received
  packet's source IPv6 (the peer's link-local, embedded in Apad per
  RFC 7166 §2.3/§4.5).
- `pump_inbound` drops a packet whose trailer is missing, malformed,
  fails the MAC check or fails the anti-replay check before any
  further processing (Hello tracking, router `feed_input`) — the
  LSDB never sees it.
- `pump_outbound` / `send_grace_lsas` / `pump_hellos`: every
  outgoing packet either applies the trailer (Crypto) or finalizes
  the checksum (NullAuth) — an active config that fails to apply
  (defensive case) skips the send rather than emit a trailer-less
  packet the peer would reject.
- Two additive `V3Auth` methods (`sign_trailer_with_source` /
  `verify_with_source`) take the IPv6 source explicitly so a daemon
  can share one `V3Auth` across interfaces (each with its own
  link-local) and peers (each with its own received source). The
  existing `sign_trailer` / `verify` methods (using `self.source_v6`)
  are unchanged for ABI-stable embedders.

The default is `null` (NullAuth) — every existing v3 configuration is
unchanged; the new surface is purely additive. The shared
`last_peer_seq` mirrors the v2 CryptoAuth shape: anti-replay across
multiple peers with a single key is approximate (the strongest seen
sequence sticks; a peer whose seq regresses is rejected). RFC 7166
§4.6 specifies the check as "less than or equal to the value last
received from the same router", so a strict per-peer table is the
long-term shape; a single-peer deployment (the common p2p lab) is
exact today — the same limitation the v2 daemon documents.

12 new unit tests in `crates/lr-cli/src/daemon_ospf3_tests.rs` cover
the state-enum default, the config → state mapping (default null,
explicit null, crypto with HMAC-SHA-256 default, HMAC-SHA-1
override), the apply path (appends the 48-byte SHA-256 trailer,
zeroes the checksum, advances `crypto_seq` monotonically), the
verify path (round-trip, wrong key rejected, wrong source rejected,
replay rejected, NullAuth accepts no trailer, Crypto rejects no
trailer, HMAC-SHA-1 trailer is 36 bytes), and the finalize-time
rejection of `[ospf.auth] type = "simple"` under v3 with the RFC
7166 hint (v2 still accepts it). 4 new `V3Auth` tests in
`crates/lr-ospf/src/auth/v3_auth.rs` cover the explicit-source
variants' round-trip and the distinct-sources-produce-distinct-
trailers contract.

**`lr-router` / `lr-cli` per-session OSPF `RxmtInterval` (`SessionConfig::with_ospf_rxmt_interval`,
`[ospf] rxmt_interval`, `[[ospf.interface]] rxmt_interval`,
`--ospf-rxmt-interval`, FRR `ip ospf retransmit-interval` + BIRD `retransmit` translation)**
(issue #92 — `defects.txt` `crates/lr-ospf/src/exchange.rs:L54`
INCOMPLETE-IMPL). RFC 2328 Appendix B `RxmtInterval` is a per-interface
constant — the gap at which an unacknowledged Database Description,
LS-Request or LSA-Update is retransmitted to a neighbour. The BIRD/FRR
default is 5 s, and the OSPF daemon's `DbExchange` driver hardcoded
the same 5 s through a module-level `RXMT_INTERVAL_MS` constant. The
prior `feat(ospf): DbExchange exposes per-neighbor RxmtInterval`
commit (`93f3406`) added the lower-level `DbExchange::with_rxmt_interval`
builder so a daemon could override the gap per neighbour — but the
daemon's `[[ospf.interface]]` schema, the TOML / CLI parser, and the
BIRD / FRR translation surface did not expose the knob, so every
operator that needed a non-5 s retransmit (a noisy satellite link
wants 30 s; a lab link wants 500 ms) had to fork the daemon.

This round wires the knob end-to-end:

- `SessionConfig::ospf_rxmt_interval_ms: u64` field (default
  `RXMT_INTERVAL_MS`) + `with_ospf_rxmt_interval(ms)` builder; the
  builder clamps 0 ms to 1 ms so the poll loop never busy-spins on
  `saturating_sub(now, last) >= 0` (matches `DbExchange::with_rxmt_interval`).
- `OspfRuntime::new` accepts `rxmt_interval_ms` and applies
  `.with_rxmt_interval(ms)` to the underlying `DbExchange` at
  construction; both `mod.rs` call sites (the per-neighbor session
  builder and the virtual-link session builder) pass
  `cfg.ospf_rxmt_interval_ms` through.
- `[ospf] rxmt_interval = S` (global default, seconds) and
  `[[ospf.interface]] rxmt_interval = S` (per-interface override,
  seconds) TOML keys. The parser accepts the alias
  `retransmit_interval` so a config that came in through `lr translate
  frr` keeps the field name the source operator recognizes. A 0 s
  value is rejected at parse time (the daemon would otherwise clamp
  it to 1 ms, but a 0 in the operator's config is almost certainly a
  typo). `--ospf-rxmt-interval S` (alias
  `--ospf-retransmit-interval`) wires the same knob on the CLI side.
- BIRD `retransmit N;` (RFC 2328 §C.1) and FRR `ip ospf
  retransmit-interval N` / `ipv6 ospf retransmit-interval N` map onto
  the new field; the previous `# UNMAPPED: retransmit … — no lr
  equivalent (BIRD OSPF timer)` / `ip ospf retransmit-interval … — no
  lr equivalent (FRR OSPF interface option)` notes are gone. A 0 s
  or non-numeric value carries an unmapped note so the typo stays
  visible instead of silently becoming a config the daemon would
  reject at parse time.
- The OSPF and OSPFv3 daemons multiply the operator's seconds-grained
  value by 1_000 at session-build time so the millisecond-grained
  `DbExchange::poll` clock reads the right gap. The startup log line
  surfaces the resolved value: `ospf interface eth0 area 0.0.0.0 …
  hello 10s dead 40s rxmt 5s, point-to-point (priority 1, state …)`.

The default 5 s (BIRD/FRR parity) is unchanged for configurations that
do not name the key; the new knob is purely additive. Per-session
overrides do not leak across sessions on the same router (each
`OspfRuntime` owns its own `DbExchange`), so a noisy satellite link
and a LAN link on the same daemon can sit at different retransmit
gaps. Three new unit tests in `lr-router/src/instance/tests.rs`
exercise the override path end-to-end through the real router (a 30 s
session does not retransmit at the 5 s default; a default-5 s session
still retransmits at 5 s; `with_ospf_rxmt_interval(0)` clamps to 1 ms).
Five new daemon-config / translate tests cover the TOML / CLI parser
and the BIRD / FRR translation arms, including the 0 s rejection and
the `retransmit_interval` alias.

**`lr-bgp` / `lr-router` / `lr-cli` per-peer administrative-down
(`PeerConfig::admin_down`, `SessionConfig::admin_down`,
`[[peer]] shutdown`, FRR `neighbor X shutdown` + BIRD `disabled`
translation)** (issue #92 — `defects.txt` L93-L101 INCOMPLETE-IMPL
subset). A peer that the operator has administratively shut down
keeps the daemon's outbound connector passive (no dial), refuses
inbound SYNs from that peer's address, and tears down any already-
Established session with a Cease NOTIFICATION carrying subcode 2
"Administrative Shutdown" (RFC 4486 §3, RFC 8203 §2). The previous
shape noted FRR `neighbor X shutdown` as `# UNMAPPED:` and silently
dialled the peer anyway; BIRD `disabled` was not handled at all.

`lr-bgp::PeerConfig` gains a public `admin_down: bool` field
(default `false`). `lr_router::SessionConfig` gains the same field
plus a `with_admin_down(bool)` builder; `DefaultRouter::add_session`
propagates it through to `PeerConfig::admin_down`. The daemon's
`PeerSpec` gains a `shutdown: Option<bool>` field with a TOML key
(`shutdown = true|false`) in `[[peer]]` blocks; `build_session_config`
propagates the resolved value through `with_admin_down`. The
daemon's `PeerEntry` carries a resolved `admin_down: bool` so the
connector and listener do not re-evaluate the Option on every
iteration. Toggling `shutdown` live via SIGHUP is a follow-up —
the operator restarts the daemon to flip the flag (the connector
and listener read it at startup).

`lr translate frr` maps `neighbor X shutdown` to `shutdown = true`
and `no neighbor X shutdown` to `shutdown = false` (the explicit
un-shutdown — preserves the operator's re-enable statement so a
reload that flips the source back to `shutdown` lands as `true`
rather than the implicit `None`). `neighbor X shutdown message
MSG...` (RFC 8203 §2 shutdown communication) is accepted but the
message is silently stripped (a follow-up can surface it as a
`lr:` directive). `lr translate bird` maps `disabled;` / `disabled
yes;` / `disabled "reason";` to `shutdown = true` and `disabled
no;` to `shutdown = false`.

Test coverage: 2 `lr-bgp` unit tests, 3 `lr-cli` TOML parser unit
tests, 11 `lr-cli` translate unit tests (FRR shutdown / no shutdown
/ shutdown message / no-key default, BIRD disabled / disabled yes /
disabled no / disabled "reason" / no-key default), and 3 `lr-cli`
e2e integration tests against the real `lr-daemon` binary
(`tests/daemon_peer_shutdown.rs`: shutdown = true keeps the
connector passive, shutdown = true on an inbound-only peer refuses
SYNs, shutdown = false is the explicit un-shutdown). The
top-of-file doc in `translate.rs` drops `shutdown` from the
not-mapped list (BIRD `multihop`, FRR `ebgp-multihop` and VRFs
stay).

**`lr-bgp` RFC 4893 / RFC 6793 4-byte AS extension orchestration
helpers** (`bgp`, issue #92 — `defects.txt`
`crates/lr-bgp/src/extensions/asn4.rs:L1-L5` PLACEHOLDER). The
`extensions/asn4.rs` module was a placeholder: a 5-line file whose
only body was `#![allow(dead_code)]` and a doc note saying the
wire-level support lives in `path` / `capabilities` and "this module
will hold high-level orchestration helpers in future revisions". The
FSM inlined the negotiation logic at every call site (the OPEN
builder inlined `if self.cfg.asn4 { caps.push(Capability::four_octet_as(...)) }`,
the OPEN handler inlined
`peer_offered_as4 = caps.iter().any(|c| c.code == FourOctetAs)` and
a separate `caps.iter().find(...).as_four_octet()` chain), so a
future change to the negotiation posture landed in three places at
once.

This round replaces the placeholder with the actual orchestration
helpers, mirroring the `enhanced_rr` / `long_lived` pattern:

- `asn4::advertised(cfg)` — whether the local config opts the session
  into the 4-byte AS capability. Thin wrapper around `cfg.asn4`;
  exists so every extension's `advertised` / `negotiated` /
  `open_capability` triple has the same shape.
- `asn4::peer_offered_as4(peer_caps)` — whether the peer advertised
  the capability in its OPEN, regardless of value well-formedness
  (preserves the historical negotiation posture so the helper
  refactor does not change which OPENs the FSM accepts).
- `asn4::negotiated(cfg, peer_caps)` — whether *both* speakers
  advertised the capability, so the 4-byte AS_PATH encoding can be
  used in both directions (RFC 6793 §4.2.2).
- `asn4::open_capability(cfg)` — the capability to put in the OPEN,
  or `None` when the knob is off.
- `asn4::peer_as4(peer_caps)` — extracts the 4-byte AS the peer
  advertised; returns `None` when absent or malformed, follows the
  RFC 6793 §4 "first occurrence wins" rule on a duplicate.

The FSM's `enqueue_open` now calls `asn4::open_capability`, the
`handle_open_in_opensent` AS4 negotiation block calls
`asn4::negotiated` and `asn4::peer_as4`, and the inline
`peer_offered_as4 = caps.iter().any(...)` /
`caps.iter().find(...).as_four_octet()` chains are gone. The
negotiation posture is byte-for-byte unchanged — the same OPENs
are accepted, the same codecs flip to 4-byte, the same peer AS
values land on `peer_as`.

Sixteen new unit tests in `extensions/asn4.rs` pin every helper:
`advertised_tracks_knob`, `open_capability_off_when_knob_on` /
`_off_when_knob_off` / `_carries_local_as_value`,
`peer_offered_when_capability_present` / `_when_capability_value_is_malformed`,
`peer_not_offered_when_capability_absent`,
`negotiated_requires_local_knob` / `_requires_peer_cap` /
`_when_both_sides_advertise` / `_when_peer_cap_is_malformed`,
`peer_as4_returns_none_when_absent` /
`_returns_value_when_present` / `_returns_none_when_value_is_malformed`
/ `_uses_first_occurrence_on_duplicate` /
`_skips_unrelated_capabilities`.

No public Rust API change (the helpers are additive; the existing
`Capability::four_octet_as` / `as_four_octet` surface is unchanged),
no C ABI change (no `lr_*` symbol touched), no wire-format change
(the codec's `with_asn4` / `set_asn4` calls consume the same boolean
the helpers produce), no version bump.

**`lr-cli` `aggregate-address … summary-only` / `… as-set`
translation onto the `[[aggregate]]` row's `summary_only` /
`as_set` keys** (`compat`, issue #92). The FRR `aggregate-address
A.B.C.D/M [summary-only] [as-set] [route-map NAME]` line previously
dropped the `summary-only` and `as-set` qualifiers with unmapped
notes claiming "lr's `[[aggregate]]` models only the prefix"
(`defects.txt` L62-L65, `crates/lr-cli/src/translate.rs:L55`).
`route-map NAME` (the per-aggregate attribute hook) still carries
an unmapped note — the daemon's `[[aggregate]]` schema has no
per-aggregate route-map surface today; that follow-up is tracked
separately.

`summary-only` (RFC 4271 §9.2.2.2 c) suppresses every more-specific
route that falls inside the aggregate from the Adj-RIB-Out toward
every BGP peer — only the aggregate is advertised. The Loc-RIB is
unchanged (the specifics stay reachable inside the daemon and
feed the aggregate's presence/withdraw decision); the suppression
is purely an egress filter so a downstream router that learns the
aggregate does not also install a more-specific path that would
shadow it. The router's `export_work_for` consults a new
`summary_only_suppresses` predicate that returns true when a
prefix key is more-specific than a registered `summary_only`
aggregate, and the `desired` vector stays empty so the Adj-RIB-Out
diff withdraws any previously-advertised more-specific. Re-registering
the aggregate with `summary_only = false` re-flushes the export
pipeline for every affected prefix so the more-specific routes are
re-advertised.

`as-set` (RFC 4271 §9.2.2.2 d) builds an `AS_SET` segment in the
aggregate's AS_PATH enumerating every AS that contributed a
more-specific route (collected from the contributing routes'
AS_PATH attributes on every recompute, deduplicated and sorted
into stable ascending order for a deterministic wire encoding).
`ATOMIC_AGGREGATE` is omitted in this mode (RFC 4271 §5.1.4:
the AS_SET itself is the "path may be incomplete" signal;
ATOMIC_AGGREGATE is the alternative signal for the empty-AS_PATH
shape). The aggregate is re-originated when the contributing-AS
set changes (a new peer's AS enters the set when its route
arrives; a withdrawing peer's AS leaves when the last specific
from that AS goes), so the wire AS_SET tracks the live Loc-RIB.

The public Rust API gains a new `AggregateOptions` struct in
`lr_router` (carrying `summary_only: bool` and `as_set: bool`,
`#[derive(Default, Copy)]` — both default to `false`, matching
FRR's `aggregate-address` defaults) and a new
`DefaultRouter::add_aggregate_with_options(prefix, options)`
method. The existing `DefaultRouter::add_aggregate(prefix)` is
unchanged (it uses the default options); the existing
`DefaultRouter::remove_aggregate` and
`DefaultRouter::aggregate_prefixes` are unchanged. The internal
representation changed from `BTreeSet<Prefix>` to
`BTreeMap<Prefix, AggregateOptions>` (the public API's stability
guarantee covers `add_aggregate` / `remove_aggregate` /
`aggregate_prefixes`; the field's type was private). The C ABI
surface is unchanged (`lr_router_add_aggregate` still takes a
prefix only; a future `lr_router_add_aggregate_with_options`
that takes an options struct is a follow-up).

The TOML parser accepts the new `summary_only = true|false` and
`as_set = true|false` keys on the `[[aggregate]]` table
(fail-closed on unknown keys, matching the existing
`apply_aggregate_key` posture). The `.lr` DSL parser inherits
the keys via the shared `apply_config_key` dispatch. The FRR
`aggregate-address` parser in `translate.rs` populates the new
fields from the `summary-only` / `as-set` qualifiers; the
rendered TOML emits the keys when set.

Tests: four new e2e tests in
`crates/lr-tests/tests/route_aggregation.rs`
(`aggregate_summary_only_suppresses_specifics_from_export`,
`aggregate_summary_only_release_re_advertises_specifics`,
`aggregate_as_set_builds_as_set_segment_in_as_path`,
`aggregate_as_set_tracks_live_loc_rib`); three new unit tests
in `crates/lr-cli/src/daemon_config_tests.rs`
(`aggregate_unknown_key_fails_closed` updated to use a
genuinely-unknown key, `aggregate_summary_only_and_as_set_parse`
for the TOML round-trip, and
`aggregate_summary_only_and_as_set_default_false` for the
default); four new translate tests in
`crates/lr-cli/src/translate_tests.rs`
(`frr_aggregate_address_summary_only_carries_through`,
`frr_aggregate_address_as_set_carries_through`,
`frr_aggregate_address_summary_only_and_as_set_combine`,
`frr_aggregate_address_route_map_carries_unmapped_note`); the
`tests/corpus/frr/bgp-aggregate.conf` golden file regenerates
with `summary_only = true` in place of the prior `# UNMAPPED:`
note.

**`lr-cli` `redistribute … route-map NAME` translation onto the
pipe's `allow` list** (`compat`, issue #92). The FRR `redistribute
<proto> [metric M] [route-map NAME]` line previously dropped the
`route-map NAME` qualifier with an unmapped note claiming "lr's
`[[redistribute]]` has no per-pipe filter hook" (`defects.txt` L74,
`crates/lr-cli/src/translate.rs:L62`) — but the daemon-side pipe
already carried the per-pipe `allow` field (a CIDR list passed to
`RedistributionPipe::with_allow_prefixes` whose `matches` runs
bit-level containment), the daemon's TOML parser already accepted
the `allow` key, and the FFI's `lr_router_add_redistribution_pipe`
already exposed the same surface to C / C++ / Go / Python
embedders. The gap was on the converter side only: it never
populated the field from a route-map.

The converter now resolves `redistribute … route-map NAME` against
the already-parsed `route_maps` and `prefix_lists` tables in a
post-pass that runs once the whole source file has been scanned
(FRR allows the route-map and prefix-list definitions to appear
*after* the `redistribute` line — forward references). A route-map
lands on the pipe's `allow` list when its shape is a *pure
prefix-list allow*:

- every entry is `permit` (a `deny` entry would need an exclusion
  mechanism `allow` does not have);
- every entry's only match is `match ip address prefix-list NAME`
  (no `match as-path`, `match community`, no `set` clause, no
  other unmapped clause — those carry attribute-rewrite or
  richer-match semantics `allow` cannot express);
- every referenced prefix-list contains only `permit` rows (a
  prefix-list `deny` row would also need an exclusion mechanism);
- every prefix-list row carries `le 32` (v4) / `le 128` (v6) with
  no `ge` qualifier — that is the only shape whose FRR semantics
  ("any prefix inside this network") matches
  `RedistributionPipe::matches`'s bit-level containment. FRR's
  bare `permit PREFIX` (no `le`) is *exact-match* (ge=plen, le=plen),
  which `allow` would silently widen; `ge G` ranges are also
  stricter than containment.

Any richer shape carries an unmapped note describing what was lost
(e.g. "route-map RM cannot be translated to `[[redistribute]]` allow
list (route-map has set clauses); route-map dropped", or
"route-map RM references prefix-lists that cannot be translated
(prefix-list PL has ge/le qualifier (only `le 32` is supported));
route-map dropped") so the operator sees the gap and can either
simplify the route-map or accept the wider `allow` semantics
manually. An undefined route-map name carries "route-map NAME not
defined; route-map dropped".

The converter now also accepts `ipv6 prefix-list NAME permit|deny
PREFIX [ge G] [le L]` — the IPv6 equivalent of `ip prefix-list` —
which it previously ignored (the v6 form shares the same name slot
and shape as the v4 form, so the existing `parse_frr_prefix_list`
handles both; only the dispatch was missing).

No public Rust API change, no C ABI change, no protocol-on-the-wire
change, no version bump. The `RedistributionPipe::with_allow_prefixes`
surface, the daemon's TOML `allow` key, and the FFI's
`lr_router_add_redistribution_pipe` `allow` / `allow_count`
parameters are all unchanged — the converter now feeds them. Twelve
new tests in `crates/lr-cli/src/translate_tests.rs` cover the
happy paths (v4 / v6 / OSPF target / metric + route-map / multiple
permit entries / deduplicated prefix-list rows) and every rejection
shape (undefined route-map, deny entries, set clauses, `ge`
qualifier, exact-match rows, prefix-list deny entries, undefined
prefix-list); the existing `frr_redistribute_route_map_is_unmapped`
test was updated to assert the more specific "not defined" note.

**`lr-ospf` per-area SRv6 database cache for the v3 SPF** (`ospf`,
issue #92). The v3 SPF consumes the per-area SRv6 database projection
(RFC 9513 §2/§5 — `Srv6Database::from_lsdb`) to install the §5 locator
routes; the projection walks the entire area LSDB on every SPF run,
re-deriving the same per-node locator / End-SID view from the same
LSA bodies every time. `Lsdb` now carries a `version: u64` content
revision counter — bumped on every `install` whose outcome is `New`,
`Replaced` or `Purged` and on every `remove` / `age_out` that drops
an entry, but not on the `refresh_due` path (RFC 2328 §14.1) which
re-writes the same LSA body under a new sequence number with reset
age (a pure refresh tick leaves the body content the projection
depends on unchanged). The OSPFv3 recompute path in `lr-router`
caches the SRv6 database per area, keyed by `Lsdb::version`; an SPF
run that lands on a cache hit reuses the projection without
re-walking the LSDB, paying zero `from_lsdb` cost on the common
case (refresh ticks, periodic SPF re-runs against the same LSDB,
consecutive LSDB-change recomputes that did not move any LSA body).

The new public API is additive:

- `lr_ospf::lsdb::Lsdb::version() -> u64` — the monotonic content
  revision counter, the cache invalidation token.
- `lr_ospf::spf::run_spf_v3_with_srv6(lsdb, root, srv6)` and
  `lr_ospf::spf::run_spf_v3_extended_with_srv6(lsdb, root, srv6)` —
  variants of `run_spf_v3` / `run_spf_v3_extended` that take a
  pre-projected `&Srv6Database`. The legacy entry points stay and
  internally call the new variants after computing the projection.

The cache is owned by `lr_router::DefaultRouter` (private field
`ospf_v3_srv6_db_cache: BTreeMap<u32, (u64, Srv6Database)>`) and is
populated by `ospf_v3_refresh_srv6_db_cache`, called at the top of
both `ospf_summarize_areas_v3` and `ospf_recompute`. Detached areas
are pruned; the cached version tracks `area.lsdb.version()` after
every refresh.

`lr-ospf` test count: 374 / 374 ✅ (six new `Lsdb::version` tests);
`lr-router`: 210 / 210 ✅ (five new SRv6 database cache tests pin
the empty-state, populated-after-recompute, cache-hit,
body-change-invalidation and sequence-only-reinstall contracts).

**`lr-ospf` SRv6 locator reachability for every route type**
(`ospf`, issue #92). The SRv6 Locator TLV (RFC 9513 §7.1) carries a
`Route Type` field that selects the reachability calculation per
§5: intra-area (1), inter-area (2), AS-external type 1 / 2 (3 / 4)
and NSSA type 1 / 2 (5 / 6). Until this release the v3 SPF
locator-attachment loop computed *only* intra-area locators — every
inter-area, external, and NSSA locator TLV the SRv6 database
projection kept was silently dropped, and a test
(`v3_non_intra_area_locator_not_computed`) explicitly codified the
gap as the expected behaviour. A receiver that wanted the FIB entry
for a locator advertised by an ABR (or an ASBR, or an NSSA ASBR)
got nothing, even though the upstream LSA was accepted, projected
and deduplicated per §7.1. This release closes the gap by
implementing the per-route-type reachability calculation per §5 +
RFC 5340 §4.8.3 (inter-area shape) + RFC 2328 §16.4 (type-1 /
type-2 external shape) + RFC 3101 §2.5 (NSSA shape):

- **Intra-area (1)**: `metric = dist(advertising router)` (the
  locator's owner is the advertising router; the TLV metric is
  informational — the owner reports 0 for its own locator). This
  is the previously-implemented shape and stays byte-for-byte
  unchanged.
- **Inter-area (2)**: `metric = dist(advertising router) +
  TLV.metric` (saturating at `u64::MAX`), where the advertising
  router is the ABR and the TLV metric is the ABR's reported
  distance to the locator in the remote area — the same shape as a
  v3 inter-area-prefix route derived from a 0x2003 LSA (RFC 5340
  §4.8.3).
- **AS-external type 1 (3) / NSSA type 1 (5)**: `metric =
  dist(advertising router) + TLV.metric` (saturating), mirroring
  the type-1 external route shape (`internal_cost +
  external_metric`, RFC 2328 §16.4 / RFC 3101 §2.5).
- **AS-external type 2 (4) / NSSA type 2 (6)**: `metric =
  TLV.metric` (the external metric dominates); the SPF distance
  to the ASBR / NSSA ASBR is recorded as `internal_cost` so an
  embedder that compares locators covering the same prefix can
  apply the §16.4 (6) tie-break ("smaller external metric wins;
  tie-break by smaller internal cost") without recomputing the SPF
  distance.

This is a breaking change to the Rust pub API of `lr-ospf` — two
new `pub` fields on `SpfLocatorRoute` (`internal_cost: u64` and
`route_type: u8`), plus a `#[non_exhaustive]` annotation that
mirrors `SpfRoute` / `ExternalRouteV3` so future additions (e.g. a
forwarding-address field per RFC 9513 §7.2 sub-TLV 1) land without
forcing every literal construction site to add the new field at
every minor. The C ABI surface does not surface `SpfLocatorRoute`
directly — the FFI's `lr_ospf_spf_v3_locator_at` projects through
`SpfRoute::from_locator` (which keeps its existing signature), so
`lr_ffi.h`, `librouting.hpp` and the Python / Go bindings are
unchanged. The previously-codifying test was renamed to
`v3_inter_area_locator_computed_at_root_with_locator_metric` and
now asserts the locator IS computed; six new tests pin each route
type's metric shape (inter-area, external type 1 / 2, NSSA type 1
/ 2, plus two parametric tests covering unreachable TLV metric and
unreachable advertising router for every route type).

**`lr-cli` complementary test for the exchange-plane feature gate**
(`tests`, issue #92). The existing `daemon_exchange_plane.rs`
integration test is gated with `#![cfg(all(unix, feature =
"exchange-plane"))]` and exercises the daemon's opt-in path when the
W6.3 prototype is compiled in (the session establishes, records
flow, the key-mismatch drops records while keeping the route, a
one-sided opt-in stays inert). The opposite side of the gate — what
the daemon does when `exchange_plane = true` is configured but the
binary was built WITHOUT the `exchange-plane` feature — had no test
coverage: the `defects.txt` `crates/lr-cli/tests/daemon_exchange_plane.rs:L21
| TEST-GAP` entry called out the gap. The new companion file
`crates/lr-cli/tests/daemon_exchange_plane_off.rs` is gated with
`#![cfg(all(unix, not(feature = "exchange-plane")))]` and asserts the
daemon's fail-closed contract: spawning `lr-daemon --exchange-plane`
(or with `--exchange-plane-key`) on a feature-less binary exits with
code 2 and logs `peer {label}: exchange_plane requested but this
binary was built without the exchange-plane feature`. A third test
pins the negative case — a plain BGP daemon config that asks for
neither flag nor key must NOT trip the gate (the regression guard).
The existing `daemon_exchange_plane.rs` header now points at the
companion file so a reader landing on either side of the gate finds
the other. `cargo test` (default features) runs the `_off` file and
skips the feature-on file; `cargo test --features exchange-plane`
runs the converse. The CI matrix exercises both shapes; no public
Rust API change, no C ABI change, no version bump.

**`lr-ospf` SRv6 Locator LSA RFC 9084 Prefix Source sub-TLVs** (`ospf`,
issue #92). The SRv6 Locator TLV (`Srv6LocatorTlv`) now parses and emits
the RFC 9084 §2.1 Prefix Source OSPF Router-ID sub-TLV (Locator LSA
registry type 4) and the RFC 9084 §2.2 Prefix Source Router Address
sub-TLV (type 5). The two constants
`LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ID` and
`LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ADDR` were already declared but the
codec skipped the sub-TLVs as unknown; a receiver that wanted the
originator attribution that RFC 9084 §1 introduces — the OSPF Router-ID
and a reachable IP address of the router that originated an externally
propagated locator — had no surface to read it from. The TLV now carries
`prefix_src_router_id: Option<u32>` and `prefix_src_router_addr:
Option<IpAddr>` (Length 4 = IPv4, Length 16 = IPv6, matching RFC 9084
§2.2's both-AF form); the decoder rejects the parent TLV on a
wrong-length sub-TLV — the same invalidates-parent policy the existing
`IPv6-Forwarding-Address` and `Route-Tag` sub-TLVs use, and a §1
invariant the codec should not silently mask. 6 new unit tests pin the
wire shape byte-for-byte (v4 and v6 round-trip, combined with the
existing sub-TLVs, malformed-length rejection for both, and
arbitrary-order decoding).

This is a breaking change to the Rust pub API of `lr-ospf` — two new
`pub` fields on `Srv6LocatorTlv`, plus a `Default` derive so existing
literal constructors pick up the new fields with `..Default::default()`.
The C ABI does not surface `Srv6LocatorTlv` (the C ABI's `Srv6Locator`
handle wraps `lr_srv6::Locator`, a different type), so the FFI header
and the Python / Go / C++ bindings are unaffected. Within the workspace,
the daemon's `Srv6Origination` builder adds `..Default::default()` to
its single literal; the in-tree test literals follow the same pattern.

**`lr-router` `RedistributionPipe::allow_prefixes` typed as
`Vec<Prefix>`** (`router`, issue #92). The pipe's allow-list was
stored as `Vec<(IpAddr, u8)>` — the unstructured-tuple shape the
previous implementation used. Every caller already had a `Prefix` in
hand and then deconstructed it for the pipe (the daemon parses a
`Prefix` and immediately splits it into `(addr, prefix_len)`; the
FFI builds a `Prefix` from `lr_prefix_t` and then splits it; the
test harness constructs a `(IpAddr, u8)` by hand). The intermediate
existed only at this seam; the typed `Prefix` is the natural API
shape.

This is a breaking change to the Rust pub API of `lr-router`. The C
ABI surface (`lr_router_add_redistribution_pipe` takes `lr_prefix_t*`
+ `allow_count`) is unchanged, so the FFI header (`lr_ffi.h`) and the
Go / Python / C++ bindings that already pass `PrefixSpec` /
`lr_prefix_t` / `'A.B.C.D/M'` across the seam are unaffected.

The matching predicate in `matches()` is unchanged behaviour — it
still delegates to `Prefix::contains_prefix` for bit-level
containment. The old `(addr, plen)` loop that rebuilt a `Prefix` for
each entry collapses into one
`.any(|allow| allow.contains_prefix(route_prefix))` call, which
short-circuits on the first match like the previous early return.

**OSPF ECMP — `lr-ospf::spf` records equal-cost next-hops** (`ospf`,
`ffi`, issue #92). The intra-area SPF relaxation used a strict `<`
comparison on the distance, so the second parent at the same
shortest distance silently dropped its next hop. RFC 2328 §16.1 (4)
requires every equal-cost parent's next hop to be installed — that
is what ECMP is. The fix moves the relaxation to a
strict-better-or-equal shape: a strictly-better path replaces the
distance, parent and next-hop set wholesale; an equal-distance path
keeps the first parent (so the SPF tree shape stays deterministic)
but appends its next hop to the set, de-duplicated.

API shape changes (break changes, permitted by the task constraint):

- `SpfResult::next_hops` is now `BTreeMap<VertexId, Vec<IpAddr>>`
  (was `BTreeMap<VertexId, IpAddr>`).
- `SpfRoute::next_hop` is now `Vec<IpAddr>` (was `Option<IpAddr>`,
  empty = no next hop).
- `SpfResultV3::next_hops` follows the same shape on the v3 side:
  `BTreeMap<V3VertexId, Vec<V3NextHop>>`.
- `SpfLocatorRoute::next_hop` follows the same shape: `Vec<IpAddr>`.

Inter-area `summary_routes` / `summary_routes_v3` follow the same
ECMP contract: when several ABRs advertise the same prefix at the
same total metric, every ABR's first hop lands in the route's
`next_hop` set, de-duplicated; the lowest border router ID stays in
`border_router` / `router_id` for the `ospf.router_id` accessor's
determinism.

The C ABI mirrors the Rust API: `lr_ospf_spf_route_t` replaces its
single-next-hop fields (`next_hop[16]`, `next_hop_is_ipv6`,
`has_next_hop`) with a `next_hop_count: u32` and an inline
`next_hops[LR_OSPF_MAX_NEXTHOPS]` array (16 entries — mirrors BIRD's
default `ospf_ecmp_max` and the Linux kernel's typical
`IP_ROUTE_MULTIPATH` ceiling). The four entry points that return
the struct keep their signatures, so embedders that recompile pick
up the new shape with no source changes beyond the struct fields
they read.

The Go / Python / C++ bindings do NOT wrap the OSPF SPF route C ABI
today (their higher-level OSPF surface is the daemon's
router-instance API, not the raw SPF run), so no binding update is
required for this round. The C and C++ FFI harnesses still pass after
the struct shape change because they do not exercise the OSPF SPF
route C ABI directly.

The `OspfTableEntry` / `Route` next-hop fields stay `Option<IpAddr>`
— the RIB and the kernel FIB mirror keep the single-hop install path
they always had. The ECMP set propagates through the C ABI surface
so an embedder that wants ECMP at the FIB level can read it. RIB /
kernel-level ECMP is a follow-up that does not change the
protocol-level shape this round introduces.

Tests: 3 new ECMP tests in `spf_tests.rs`
(`ecmp_records_distinct_first_hops_for_equal_cost_paths`,
`ecmp_summary_collects_next_hops_from_equal_cost_abrs`,
`ecmp_dedupes_identical_next_hops_from_equal_cost_parents`); 1 new
FFI test `ffi_spf_route_carries_ecmp_next_hop_set` in `ospf_spf.rs`.
`lr-ospf` test count: 341 / 341 ✅, `lr-ffi`: 978 / 978 ✅.

**`lr-srv6` `Behavior` enum — RFC 9800 NEXT-CSID + RFC 10018 End.DTMC
family** (`srv6`, issue #92). The `Behavior` enum now models the full
RFC 9800 NEXT-CSID family (27 new variants) plus the three RFC 10018
`End.DTMC` variants — the "Behavior enum 40+ modelling" gap the
previous round noted. Wire values match the IANA registry verbatim
(https://www.iana.org/assignments/segment-routing/srv6-endpoint-behaviors.csv):

- RFC 9800 §4.1.1 `End with NEXT-CSID` (8 variants at 43–50; common
  short name `uN` for value 48).
- RFC 9800 §4.2.1 `End.X with NEXT-CSID` (8 variants at 52–59; common
  short name `uA` for value 57).
- RFC 10018 §4.1-§4.3 `End.DTMC4` / `End.DTMC6` / `End.DTMC46` (decap
  to MPLS table) at 76–78.
- RFC 9800 §4.3.1 `End.T with NEXT-CSID` (8 variants at 85–92).
- RFC 9800 §4.14-§4.15 `End.B6.Encaps` / `End.B6.Encaps.Red` / `End.BM`
  with NEXT-CSID at 93–95.
- RFC 9800 §4.4-§4.5 `End.LBS` / `End.XLBS` with NEXT-CSID at 96–97
  (locator-block swap).

The classifier methods `is_psp` / `is_usp` / `is_usd` / `is_decap` /
`is_cross_connect` / `is_table_lookup` now cover the new variants —
NEXT-CSID reuses the same flavor bits (RFC 9800 §4.16), and
`End.DTMC4/6/46` share the decap and table-lookup classifications with
the `End.DT*` family.

Deliberately NOT modelled (left for follow-ups): the pre-RFC 9800 draft
assignments at 42 / 51 / 60-68 (NEXT-ONLY-CSID and uDX/uDT — RFC 9800
obsoleted the draft with fresh codepoints; no RFC references the old
values); the RFC 9433 GTP family at 69-72 (needs a GTP-specific
argument layout the crate does not model); the draft assignments at
73-75 / 79-84 / 98-100 (End.DTM, End.M Mirror, End.Replicate, End.BXC,
End.NSH, End.PSID); the RFC 9800 REPLACE-CSID family at 101-141 (the
second flavor RFC 9800 introduces — same structure as NEXT-CSID but a
separate container layout); the RFC 9801 `End.DX1` family at 158-160.

The C ABI surface is unchanged — `Behavior` is exposed through the
runtime lookup `lr_srv6_behavior_from_wire(wire, out_value, out_name,
name_cap)`, which simply gains more entries in its `match`. No header
regeneration needed. `lr-srv6` test count grows from 56 to 61 (the
four new tests `behavior_rfc_9800_next_csid_assignments` /
`behavior_rfc_10018_dtmc_assignments` /
`behavior_next_csid_flavor_classification` /
`behavior_dtmc_classification`, plus the existing
`behavior_from_wire_unassigned` gains stricter assertions for the
now-bounded unmodelled ranges).

**Structured BGP message inspection surface** (`ffi`, issue #92). The
C ABI gained a structured BGP-message inspection surface mirroring
the `lr_bgp::BgpMessage` enum and its variants, so an embedder can
decode a BGP message once and walk its variant fields field-by-field
across the ABI — the same shape a Rust embedder gets from
`match msg { ... }`. The pre-existing `lr_bgp_decode` round-trip path
returned the canonical re-encoded bytes (useful for differential
checks) but exposed none of the parsed structure, forcing C/Go/Python
embedders who wanted to read a message's fields to write their own
BGP parser outside the library — defeating the point of the FFI.

The new surface adds an opaque handle `lr_bgp_message_t` (boxes a
`BgpMessage`) plus a decode entry point and per-variant readers:

- `lr_bgp_decode_message(data, len) -> lr_bgp_message_t` — decodes one
  BGP message and returns an owned handle (NULL on failure; the
  thread-local last-error string is set).
- `lr_bgp_message_free(m)` — releases the handle. Safe on NULL.
- `lr_bgp_message_type(m, *out) -> int32_t` — writes the message type
  code (1..5, see `LR_BGP_MSG_OPEN` etc.) to `*out`.

OPEN readers (RFC 4271 §4.2):

- `lr_bgp_message_open_version` / `_my_as` / `_hold_time` /
  `_bgp_id` — basic OPEN fields. `_my_as` unwraps AS_TRANS (23456)
  when the RFC 6793 four-octet-AS capability is present, surfacing
  the real 32-bit AS.
- `lr_bgp_message_open_param_count` / `_param_at(idx, *out_type,
  *out_value)` — walks the OPEN optional parameters (RFC 5492
  capabilities). The param value is the raw capability payload —
  a sequence of `(code:1, length:1, value:length)` triples an
  embedder can crack open with `Capability::decode_set` on the Rust
  side or by hand from C.

NOTIFICATION readers (RFC 4271 §4.5):

- `lr_bgp_message_notification_code` / `_subcode` / `_data(*out)` —
  error code, subcode and the variable-length diagnostic data
  payload (often empty for compact Cease/Administrative-Reset
  NOTIFICATIONs BIRD/FRR emit).

ROUTE-REFRESH readers (RFC 2918 + RFC 7313):

- `lr_bgp_message_route_refresh_afi` / `_safi` / `_subtype` —
  address-family, sub-address-family and the RFC 7313 subtype
  (0 = Normal, 1 = BoRR, 2 = EoRR, 0xff = unknown — RFC 7313 §3.2
  requires the message be silently ignored, so the decoder maps
  unrecognized values here).

UPDATE readers (RFC 4271 §4.3):

- `lr_bgp_message_update_withdrawn_count` /
  `_nlri_count` / `_attr_count` — section sizes.
- `lr_bgp_message_update_withdrawn_at(idx, *out_prefix)` /
  `_nlri_at(idx, *out_prefix)` — IPv4 withdrawn routes and NLRI
  entries as `lr_prefix_t` (16-byte zero-padded `addr`,
  `is_ipv6` discriminator, `prefix_len`). MP-BGP NLRI (RFC 4760)
  carried inside the MpReach/MpUnreach path attributes is reachable
  through the attribute reader at index 14/15 — typed readers for
  those are a follow-up.
- `lr_bgp_message_update_attr_at(idx, *out_type, *out_flags,
  *out_value)` — path attribute at `idx`. The flags byte layout is
  RFC 4271 §5.1 + RFC 9072 §2 (bit 7 optional, bit 6 transitive,
  bit 5 partial, bit 4 extended-length).

Reader contract: every reader returns `LR_ERR_NULL` (-1) on a null
handle, `LR_ERR_INVALID_HANDLE` (-2) when the message is not the
variant the reader expects (e.g. calling `lr_bgp_message_open_*` on
a NOTIFICATION), and `LR_ERR_OTHER` (-6) on out-of-range indices.

Constants added to `include/lr_ffi.h` (cbindgen-generated):
`LR_BGP_MSG_OPEN`/`_UPDATE`/`_NOTIFICATION`/`_KEEPALIVE`/`_ROUTE_REFRESH`
and `LR_BGP_RR_SUBTYPE_NORMAL`/`_BORR`/`_EORR`.

Per-protocol-binding parity:
- **C++** (`include/librouting.hpp`): new RAII type
  `librouting::BgpMessage` (with custom deleter), `decode_bgp_message`,
  `message_kind`, `open_*`, `notification_*`, `route_refresh_*`,
  `update_*` accessors. Throws `librouting::Error` on FFI failures.
- **Python** (`bindings/lr-python`): new `librouting.codec.BgpMessage`
  class with `decode`, `close`, `kind`, `open_*`, `notification_*`,
  `route_refresh_*`, `update_*` methods, plus the
  `BGP_MSG_*`/`BGP_RR_SUBTYPE_*` constants exported from the
  top-level package. `__del__`/`__enter__`/`__exit__` keep the
  handle single-owner.
- **Go** (`bindings/lr-go`): new `BgpMessage` type with
  `DecodeBgpMessage`, `Close`, `Kind`, `Open*`, `Notification*`,
  `RouteRefresh*`, `Update*` methods, plus the `BGPMsg*` /
  `BGPRRSubtype*` constants. `runtime.SetFinalizer` frees the
  handle when the wrapper leaves scope.

Test coverage: 16 new Rust unit tests in
`crates/lr-ffi/src/codec.rs` cover every variant (OPEN/UPDATE/
NOTIFICATION/KEEPALIVE/ROUTE-REFRESH), the AS_TRANS unwrap path,
the variant-mismatch error path, the null-handle / null-output
rejection paths, the out-of-range index path, the panic barrier
contract (decode-then-free in a loop), and the box/unbox lifecycle
for a hand-built message. New tests in `tests/ffi/harness.c` and
`tests/ffi/harness.cpp` exercise the same surface from C and C++.
New Python tests in `bindings/lr-python/tests/test_librouting.py`
and Go tests in `bindings/lr-go/librouting_test.go` cover the same
shapes. Full workspace test suite, clippy, fmt and the docs linters
are green.

The new surface is the template for the OSPF (`lr_ospf_message_t`)
and Babel (`lr_babel_message_t`) inspection surfaces — the OSPFv3
NSSA route-computation work landed in this same issue (#92) is the
kind of protocol feature whose structured form embedders will want
to read across the ABI in the same shape, and the BGP surface here
is the established pattern they will follow.

**BGP PMSI Tunnel filter DSL surface** (`policy`, `cli`, ROADMAP
"Per-protocol route attributes and an external conversion corpus").
The filter DSL now exposes the RFC 6514 §5 PMSI Tunnel attribute —
the provider-tunnel binding a BGP UPDATE advertises for an MVPN
auto-discovery route (Intra-AS I-PMSI, Inter-As I-PMSI, S-PMSI, Leaf
A-D). BIRD exposes the attribute in its filter language as
`bgp_pmsi_tunnel` (an opaque bytestring — `EAF_TYPE_OPAQUE` +
`T_ENUM_EMPTY` — where the only meaningful operation is
`defined(bgp_pmsi_tunnel)`); lr's DSL mirrors that surface as a
read-only `bool` so the canonical presence-probe idiom
`if defined(bgp.pmsi_tunnel) then reject;` translates faithfully. The
codec stores the raw attribute bytes verbatim so a peer-sent attribute
with non-zero reserved bits or non-zero EXP/S bits round-trips
byte-exact, and the typed view decodes the Flags byte, Tunnel Type,
20-bit MPLS label and variable-length Tunnel Identifier with the two
RFC 6514 §5 hard rules enforced (Tunnel Type 0 MUST carry no Tunnel
Identifier; Tunnel Type 6 MUST carry a 4-byte IPv4 or 16-byte IPv6
endpoint). The `defined(bgp.pmsi_tunnel)` predicate distinguishes
"absent" from "present but malformed" via `has_pmsi_tunnel`. This
closes the last gap in BIRD's filter-attribute surface — every
`bgp_*` filter attribute the BIRD 2 grammar declares now has a
faithful lr-DSL spelling.

**OSPF metric1 filter DSL surface** (`policy`, `cli`, ROADMAP
"Per-protocol route attributes and an external conversion corpus").
The filter DSL now exposes the RFC 2328 §16 / RFC 5340 §4.1 primary
OSPF metric — the SPF cost for intra-area and inter-area routes,
the cost-plus-external-metric for type-1 external routes, and the
cost alone for type-2 external routes. BIRD exposes the value in
its filter language as `ospf_metric1` (an `int` eattr the OSPF
protocol attaches); lr's DSL spells it `ospf.metric1` (read-only
`int`). The mapping is one `match` on `route.protocol` plus one
field read off `route.preference.metric` — no BTreeMap lookup, no
allocation, no codec — cheaper than any `bgp.*` accessor that
decodes a path attribute. A non-OSPF route reads as `0` (the eattr
default for an unattached `ospf_metric1` reference), so the canonical
BIRD idiom `if defined(ospf_metric1) && ospf_metric1 > 100 then
reject;` translates faithfully to `if defined(ospf.metric1) &&
ospf.metric1 > 100 then reject;` and short-circuits on the
`defined()` arm for a non-OSPF route the same way it does in BIRD.
The `defined(ospf.metric1)` predicate distinguishes "non-OSPF
route" from "OSPF route with metric 0" via `has_metric1` — a
cost-0 OSPF route stays defined (a loopback or other
directly-attached network OSPF originates with cost 0), so the
canonical idiom does not drop it. The BIRD translator renames
`ospf_metric1` to `ospf.metric1`; the remaining OSPF per-route
attributes BIRD exposes (`ospf_metric2`, `ospf_tag`,
`ospf_router_id`) have no lr-DSL spelling yet and the translator
marks a filter that references them unfaithful (the `ospf_` prefix
is no longer in `UNMAPPABLE_PREFIXES`; the three remaining OSPF
attributes are listed in `UNMAPPABLE_WORDS` instead). The peephole
pass's `BranchFieldIntCmp` fast path fuses `ospf.metric1 == N` /
`> N` / etc. comparisons the same way it fuses `bgp.local_pref` /
`bgp.med` / `bgp.otc` — the read is one `match` plus one field
read (no allocation), so the fast path avoids the `Value::Int`
allocation + push the unfused sequence pays.

**OSPF router_id filter DSL surface** (`policy`, `cli`, `ospf`,
`router`, ROADMAP "Per-protocol route attributes and an external
conversion corpus"). The filter DSL now exposes the RFC 2328 §A.4
`Advertising Router` field / RFC 5340 §A.4 the same field on
every v3 LSA — the 32-bit OSPF Router-ID of the router that
originated the LSA the route was computed from (the Router-LSA's
advertising router for intra-area stub routes; the Network-LSA's
advertising router — the DR — for intra-area transit routes; the
summary-LSA's advertising router — the ABR — for inter-area
routes; the AS-external-LSA's advertising router — the ASBR — for
external routes). BIRD exposes the value in its filter language
as `ospf_router_id` (an `int` eattr the OSPF protocol attaches to
every route); lr's DSL spells it `ospf.router_id` (read-only
`int`). The OSPF Router-ID rides the private `LrOspfRouterId`
path-attribute tag (code point 252 — stripped at BGP encode, the
same shape `LrOspfMetric2` at 253, `LrExchangePlaneRecords` at
254 and `LrMplsLabelStack` at 255 use): `lr-bgp::path::AttrType`
gains the `LrOspfRouterId` variant, `lr-bgp::path::PathAttributes`
gains the `set_ospf_router_id` / `ospf_router_id` /
`has_ospf_router_id` accessors (the value layout is a single
4-byte big-endian `u32` holding the 32-bit OSPF Router-ID — the
LSA `Advertising Router` field is a 32-bit dotted-quad per RFC
2328 §A.4, no masking needed; the high byte is meaningful).
The codec half adds the `router_id: Option<u32>` field to
`lr-ospf::spf::SpfRoute` (populated for both v2 and v3
intra-area stub / transit routes, inter-area summary routes and
the v3 Intra-Area-Prefix-LSA walk). The populate-the-RIB half
adds `router_id: Option<u32>` to `OspfTableEntry` (pub(super),
stays inside `lr-router::instance`) and the `with_router_id`
builder; `ospf_area_table` and `ospf_recompute` populate the
field from `SpfRoute::router_id` for intra-area routes, from
`OspfKind::Inter::border_router` for inter-area routes, and
from `OspfKind::External::asbr` for external routes. The
`ospf_recompute` route-construction loop attaches the private
`LrOspfRouterId` path attribute on the resulting RIB `Route` when
`entry.router_id` is `Some`. The accessor half adds the
`lr-policy::ospf::{router_id, has_router_id}` helpers (the latter
distinguishes "no attribute" from "attribute present but zero"
via `defined(ospf.router_id)` — RFC 2328 §3.1.b recommends a
non-zero Router-ID but does not forbid 0.0.0.0). The filter-DSL
half adds `RouteFieldKind::OspfRouterId` (read-only `int`), the
parser dispatch for `ospf.router_id`, the eval dispatch
(`field_present` consults `has_router_id`; `read_route_field`
returns the int), the `FilterContext::ospf_router_id` /
`ospf_has_router_id` default impls that delegate to
`lr_policy::ospf`, and the `OspfRouterId` arm in the peephole
pass's `is_int_field` set so the `BranchFieldIntCmp` fast path
fires on `ospf.router_id == N` / `> N` / etc. — the read is one
protocol-kind `match` plus one BTreeMap lookup plus one 4-byte
read on `route.attributes` (no allocation), the same shape as
`ospf.metric2` (which reads a different private tag). The BIRD
translator renames `ospf_router_id` to `ospf.router_id` (and
removes it from `UNMAPPABLE_WORDS` — with this release every
OSPF per-route attribute BIRD's filter grammar declares has a
faithful lr-DSL spelling; the remaining unmappable per-route
attributes are the Babel triplet `babel_metric` /
`babel_router_id` / `babel_seqno`, still gated by the `babel_`
prefix in `UNMAPPABLE_PREFIXES`). The corpus case
`tests/corpus/bird/ospf-router-id-filter.conf` exercises both
the canonical specific-originator accept idiom and the
zero-router-id accept idiom. The Python and Go binding tests
cover the "absent" path (no `LrOspfRouterId` attribute set —
the default for a synthetic test route; the OSPF daemon is the
only producer and the C ABI does not expose a setter for this
tag, mirroring the `LrOspfMetric2` shape) — the "present" path
is exercised by the `lr-policy::ospf::router_id_*` unit tests
(which synthesize the attribute directly via `Attributes::insert`)
and the `lr-router::instance::tests` integration test (which
populates the attribute via the OSPF route computation, the
only producer).

**OSPF metric2 filter DSL surface** (`policy`, `cli`, `ospf`,
ROADMAP "Per-protocol route attributes and an external conversion
corpus"). The filter DSL now exposes the RFC 2328 §16.4 /
RFC 5340 §4.8.5 type-2 external OSPF metric — the E-bit-set LSA
metric the §16.4 (6) type-2 preference ranks against (alone; the
cost to the ASBR breaks the tie, and that cost lives in
`ospf.metric1` for type-2 externals in lr's `preference.metric`
model). BIRD exposes the value in its filter language as
`ospf_metric2` (an `int` eattr the OSPF protocol attaches to
type-2 external routes); lr's DSL spells it `ospf.metric2`
(read-only `int`). The type-2 external metric rides the private
`LrOspfMetric2` path-attribute tag (code point 253 — stripped at
BGP encode, the same shape `LrMplsLabelStack` at 255 and
`LrExchangePlaneRecords` at 254 use): `lr-bgp::path::AttrType`
gains the `LrOspfMetric2` variant, `lr-bgp::path::PathAttributes`
gains the `set_ospf_metric2` / `ospf_metric2` / `has_ospf_metric2`
accessors (the value layout is a single 4-byte big-endian `u32`
holding the 24-bit external metric, zero-extended), and
`lr-router::instance::ospf_ops::ospf_recompute` attaches the
attribute for type-2 externals (where `OspfKind::External {
metric_type: ExternalMetricType::Type2, .. }` matches) — only
for type-2 externals; intra-area, inter-area and type-1
external OSPF routes carry no `LrOspfMetric2` tag, so its
absence is the marker `has_metric2` consults. The typed
accessors in `lr-policy::ospf` read the attribute via one
protocol-kind `match` plus one BTreeMap lookup plus one 4-byte
read on `route.attributes` (no allocation, no codec — the value
layout is a fixed 4-byte `u32`, read in place via
`Attributes::get_u32_be`). Cheaper than any `bgp.*` accessor
that decodes a multi-byte TLV stream, more expensive than
`ospf.metric1` (which reads a struct field, no lookup). A
non-type-2-external route — non-OSPF, intra-area, inter-area or
type-1 external — reads as `0` (the eattr default for an
unattached `ospf_metric2` reference), so the canonical BIRD idiom
`if defined(ospf_metric2) && ospf_metric2 > 100 then reject;`
translates faithfully to `if defined(ospf.metric2) &&
ospf.metric2 > 100 then reject;` and short-circuits on the
`defined()` arm for a non-type-2-external route the same way it
does in BIRD. The `defined(ospf.metric2)` predicate distinguishes
"not a type-2 external" from "type-2 external with metric 0"
via `has_metric2` — a metric-0 type-2 external (an E-bit-set
type-5 LSA whose 24-bit external metric happens to be zero,
unusual but well-formed per RFC 2328 §2.3) stays defined, so the
canonical idiom does not drop it. The BIRD translator renames
`ospf_metric2` to `ospf.metric2` (and removes it from
`UNMAPPABLE_WORDS`, leaving the remaining OSPF attribute
`ospf_router_id` listed there so a filter that references it is
still marked unfaithful). The peephole
pass's `BranchFieldIntCmp` fast path fuses `ospf.metric2 == N` /
`> N` / etc. comparisons the same way it fuses `ospf.metric1` /
`bgp.local_pref` / `bgp.med` / `bgp.otc` — the read is one
lookup plus one fixed-width read (no allocation), so the fast
path avoids the `Value::Int` allocation + push the unfused
sequence pays. The C ABI does not expose a setter for the
`LrOspfMetric2` tag — embedders read the field but never inject
it; the OSPF daemon is the only producer.

**OSPF tag filter DSL surface** (`policy`, `cli`, `ospf`, ROADMAP
"Per-protocol route attributes and an external conversion corpus").
The filter DSL now exposes the RFC 2328 §A.4.5 bullet h /
RFC 3101 §2.3 / RFC 5340 §A.4.7 T bit / RFC 8362 §3.6
External-Prefix sub-TLV 3 external route tag — the 32-bit tag
carried in type-5 / type-7 AS-external-LSA bodies. BIRD exposes
the value in its filter language as `ospf_tag` (an `int` eattr
the OSPF protocol attaches to external routes); lr's DSL spells
it `ospf.tag` (read-only `int`). Unlike `ospf.metric2` (whose
type-2 external metric rides the private `LrOspfMetric2`
path-attribute tag), `ospf.tag` rides the existing `Route::tag`
field — the same field the `SetTag` policy action writes for
the operator-side override, and the same field the OSPF
external-LSA origination path reads when redistributing a route
into OSPF. The OSPF route computation
(`lr-router::instance::ospf_ops::ospf_recompute`) populates
`Route::tag` from the LSA's tag for type-5 / type-7 externals
(the v2 form always carries a 4-byte tag, zero being
well-formed per RFC 2328 §A.4.5 — `Route::tag = Some(t)` even
when the tag is zero; the v3 form's T bit / External-Prefix
sub-TLV 3 carries a tag only when present, so a missing v3 tag
stays `None`). The codec half adds the `route_tag: u32` field
to `lr-ospf::external::ExternalRoute` (v2) and `route_tag:
Option<u32>` to `ExternalRouteV3` (v3), populated from the
LSA body in `external_routes`, `nssa_routes` and
`external_routes_v3_mode`. The populate-the-RIB half adds
`route_tag: Option<u32>` to `OspfTableEntry` (pub(super), stays
inside `lr-router::instance`) and sets `Route::tag =
entry.route_tag` in `ospf_recompute` (replacing the previous
hard-coded `None`). The accessor half adds the
`lr-policy::ospf::{tag, has_tag}` helpers (the latter
distinguishes "no tag" from "tag of zero" via
`defined(ospf.tag)`). The filter-DSL half adds
`RouteFieldKind::OspfTag` (read-only `int`), the parser
dispatch for `ospf.tag`, the eval dispatch (`field_present`
consults `has_tag`; `read_route_field` returns the int), the
`FilterContext::ospf_tag` / `ospf_has_tag` default impls that
delegate to `lr_policy::ospf`, and the `OspfTag` arm in the
peephole pass's `is_int_field` set so the `BranchFieldIntCmp`
fast path fires on `ospf.tag == N` / `> N` / etc. — the read
is one `match` on `route.protocol` plus one `Option<u32>`
field read off `route.tag`, no allocation, no BTreeMap lookup,
cheaper than `ospf.metric2` (which pays a BTreeMap lookup plus
a 4-byte read) and the same shape as `ospf.metric1` (which
reads a struct field, no lookup). The BIRD translator renames
`ospf_tag` to `ospf.tag` (and removes it from
`UNMAPPABLE_WORDS` — with `ospf_router_id` removed alongside
this release, no OSPF per-route attributes remain in
`UNMAPPABLE_WORDS`; the remaining Babel per-route attributes
`babel_metric` / `babel_router_id` / `babel_seqno` are still
marked unfaithful via the `babel_` prefix in
`UNMAPPABLE_PREFIXES`). The corpus case
`tests/corpus/bird/ospf-tag-filter.conf` exercises both the
canonical tagged-route accept idiom and the zero-tag accept
idiom. The Python and Go binding tests cover both the "absent"
path (no tag set — the default for an intra-area / inter-area
OSPF route) and the "present" path (a tag set via
`set_tag` / `SetTag`, mirroring what `ospf_recompute` attaches
for an external route whose LSA carried a tag) — the C ABI
exposes the existing `lr_route_set_tag` setter, so the binding
can exercise the present path that the metric2 binding test
could not (the `LrOspfMetric2` tag has no C ABI setter).

- OSPFv2 ABR summary-LSA origination now applies RFC 2328 Appendix E
  when two prefixes whose network addresses coincide but the masks
  differ (e.g. `10.0.0.0/8` and `10.0.0.0/16`) are summarized into
  the same area. The less-specific LSA keeps the network address as
  its Link State ID; the more-specific one is remapped to its
  broadcast address (host bits all 1) so the two no longer collide on
  the `(ls_type, ls_id, advertising_router)` LSDB key (RFC 2328
  §12.1.6) — previously the second LSA silently overwrote the first
  and only one of the two routes survived in the area's Loc-RIB.
  `lr_ospf::abr` exposes `summary_lsa_id_for` (single-prefix form)
  and `assign_summary_lsa_ids` (batch form that sorts ascending by
  prefix length so the less-specific prefix wins the network address)
  alongside the existing `originate_summary_lsa`; the daemon's ABR
  driver now routes through `originate_summary_lsa_with_id`. The
  remap returns `None` when both the network and broadcast addresses
  are taken by *different* LSAs — RFC 2328 Appendix E notes this
  case has no automatic resolution and the operator must summarize
  at a single length.

- `lr-osroute::seg6_route` now installs four SRv6 seg6local behaviors
  the Linux kernel's `seg6_action_table` (net/ipv6/seg6_local.c)
  implements but the encoder previously rejected with
  `UnsupportedAction`: `End.DT4` (IANA 19, kernel action 8),
  `End.DT46` (IANA 20, kernel action 16), `End.B6.Insert` (IANA 13,
  kernel action 9) and `End.B6.Encaps` (IANA 14, kernel action 10).
  End.DT4 and End.DT46 are the IPv4-L3VPN and dual-stack L3VPN
  decap behaviors (RFC 8986 §4.8 / §4.9); both require the
  `SEG6_LOCAL_VRFTABLE` parameter (uapi 9), a routing-table id
  bound to a VRF device (Linux `CONFIG_NET_L3_MASTER_DEV`).
  End.B6.Insert and End.B6.Encaps are the binding-SID SRH
  insert / encap behaviors (RFC 8986 §4.14); both require the
  `SEG6_LOCAL_SRH` parameter (uapi 2), the SRv6 Routing Header
  the endpoint pushes onto the packet (RFC 8754 §2 wire form).
  `Seg6LocalRoute` gains two additive fields (`vrf_table:
  Option<u32>` and `srh: Option<Srh>`) and two additive builders
  (`with_vrf_table(table)` and `with_srh(srh)`); the existing
  `with_table` builder stays for `End.T` / legacy `End.DT6`. The
  kernel's parameter contract is enforced BEFORE encoding:
  `End.DT4` / `End.DT46` reject a stray `table` parameter (the
  kernel's `parse_nla_action` answers EINVAL for a `SEG6_LOCAL_TABLE`
  attribute the descriptor does not list); `End.B6.Insert` /
  `End.B6.Encaps` reject every parameter except `srh`. The C ABI is
  unchanged (`include/lr_ffi.h` byte-identical — `Seg6LocalRoute` is
  not in the C ABI; the FFI surface only exposes the SRH codec). 10
  new unit tests pin the wire shape, the action-code translation
  (End.DT4 → 8, End.DT46 → 16, End.B6.Insert → 9, End.B6.Encaps →
  10), the required-parameter rejection paths and the stray-parameter
  rejection paths; one new kernel-gated end-to-end test in
  `tests/srv6_kernel.rs` exercises `End.B6.Insert` against a real
  kernel's `seg6_action_table[SEG6_LOCAL_ACTION_END_B6]` descriptor.
  End.BM (IANA 15), End.DX2V (22), End.DT2U (23), End.DT2M (24) and
  the PSP/USP/USD flavor combinations remain rejected — the kernel
  has no `seg6_action_table` descriptor for them.

**`lr-ospf` / `lr-ffi` `HelloBody::interface_id` /
`lr_ospf_hello_interface_id` v3-named accessor for the v2 network_mask
slot** (issue #92 — `defects.txt` `crates/lr-ospf/src/codec.rs:L138-L143`
+ `L372-L373` DOC-MISMATCH "v3 Hello `network_mask` field reused as
Interface ID; comment 'For v3 the network_mask slot carries the
Interface ID; keep as-is' - field name misleading"). RFC 5340 §A.3.2.1
reuses the v2 Hello `network_mask` wire slot for the 4-byte Interface
ID — v3 has no network mask, but the codec stored the bytes in a
`pub network_mask: u32` field, so every v3 read site read
`body.network_mask` and looked like "the network mask is 7" on its
face. The dual semantics lived in inline `// v3: Interface ID slot`
comments at every call site (the codec, the daemon's v3 Hello receive
path), which a refactor could drop without any compile-time signal.

This round makes the v3 intent self-documenting at the call site,
without renaming the public field (the 1.0+ ABI freeze makes a rename
a major bump):

- `lr_ospf::packet::HelloBody::interface_id(&self) -> u32` — the
  v3-named accessor. Reads the same byte as `network_mask()`; the
  dual semantics live at the accessor, not the field.
- `lr_ospf::packet::HelloBody::with_interface_id(self, id: u32) -> Self`
  — `#[must_use]` builder so the v3 construction site reads
  `.with_interface_id(7)` instead of `network_mask: 7` followed by an
  inline comment explaining what the field is.
- `lr_ospf::packet::HelloBody::network_mask(&self) -> u32` and
  `with_network_mask(self, mask: u32) -> Self` — the v2-named
  counterparts, for symmetry at the v2 call sites.
- The codec's v3 path now reads `h.interface_id()` instead of
  `h.network_mask`; the v2 path uses `h.network_mask()`. The decoder
  names the local `network_mask_or_interface_id` so the wire slot's
  dual semantics are visible at the assignment site.
- The daemon's v3 Hello receive path (`daemon_ospf3.rs`) reads
  `body.interface_id()` instead of `body.network_mask`.
- The v3 codec test constructs the Hello via `.with_interface_id(7)`
  and asserts on `h.interface_id()`, so a regression that drops the
  accessor fails the test.

The FFI surface mirrors the Rust accessors additively (no breaking
ABI change — the C ABI freeze allows new symbols):

- `lr_ospf_hello_interface_id(lr_ospf_packet_t p) -> uint32_t` — the
  v3-named alias of `lr_ospf_hello_network_mask`. The two read the
  same wire slot; embedders processing an OSPFv3 Hello should call
  the v3-named accessor so the call site documents the v3 intent.
- C++ wrapper: `ospf_hello_interface_id(lr_ospf_packet_t)` and
  `ospf_hello_interface_id(OspfPacketHandle const&)` mirror the
  existing `ospf_hello_network_mask` overloads.
- Go binding: `OspfPacket.OspfHelloInterfaceId() (uint32, error)`,
  auto-generated by `scripts/gen_go.py` from `scripts/abi.json`.
- Python `_ffi.py` cdef: `lr_ospf_hello_interface_id` declared
  alongside `lr_ospf_hello_network_mask` (the Python binding does
  not generate higher-level wrappers for the per-field OSPF Hello
  readers, so the cdef declaration is the only Python-side change).

3 new Rust unit tests in `crates/lr-ospf/src/packet/mod.rs` cover
the dual-semantics contract: the v2 and v3 accessors read the same
wire slot; the v2 and v3 builders overwrite the struct-literal
value; `with_interface_id` is `#[must_use]` (a caller that ignores
the return value silently drops the assignment). 2 new FFI tests in
`crates/lr-ffi/src/ospf_body.rs` cover the v3 alias: a v3 Hello
built with `with_interface_id(7)` round-trips through the codec and
the FFI accessor returns 7; the v2-named alias returns the same
byte. The v2 `lr_ospf_hello_network_mask` accessor is unchanged
(existing tests pass) — the new symbol is purely additive.

### `templates/bgp-rr`: working iBGP route-reflector scaffold (issue #92)

`templates/bgp-rr/src/main.rs` was a stub — it parsed `--local-as`,
`--router-id` and `--client` argv flags, printed
`"BGP RR cluster scaffold"` and pointed the reader at
`docs/examples/bgp_route_reflector.md`. `templates/README.md`
advertised the template as an "iBGP route reflector cluster (RFC
4456)" scaffold, so the stub fell short of the advertised behaviour
— a downstream user running `cp -r templates/bgp-rr ~/projects/`
got a binary that did not actually reflect routes.

The template is now a working in-process RR demo:

- Parses `--local-as N`, `--router-id A.B.C.D`,
  `--cluster-id A.B.C.D` and `--client A.B.C.D[:port]` (the first
  `--client` replaces the defaults; subsequent ones append).
- Builds one `BgpPeer` per client with `route_reflector_client =
  true` and `route_reflector.enabled = true` (cluster-id from the
  argv). Each RR-side session has a far-side dummy BgpPeer that
  stands in for the client's actual router.
- Drives the OPEN/KEEPALIVE handshake between each RR-side session
  and its far-side dummy so every session reaches `Established`.
- Advertises a sample iBGP-learned route (origin.proto = 1) to the
  second client, drains the resulting UPDATE bytes and decodes
  them to confirm the `ORIGINATOR_ID` and `CLUSTER_LIST`
  attributes the reflector stamps per RFC 4456 §3 are present on
  the wire.

Six unit tests pin the new helpers: `parse_v4_accepts_quad`,
`parse_v4_rejects_bad`, `parse_client_strips_port`,
`args_default_has_two_clients`,
`rr_cluster_reflects_to_client` (full in-process reflection
round-trip), and `rr_attributes_suppressed_when_not_reflector`
(RFC 4456 §3 gating — a non-reflector with an accidentally set
`rr_client` flag must not stamp `ORIGINATOR_ID` / `CLUSTER_LIST`).

The other three templates (`analyzer`, `bfd-integration`,
`os-integration`) were already working scaffolds; this round
brings `bgp-rr` to parity with them. The new `templates` CI job
(`.github/workflows/ci.yml`) loops through every
`templates/<name>/Cargo.toml` and runs `cargo build && cargo test`
in that directory so a regression in any template's main.rs or
its in-process demo fails CI here, not in a downstream user's
`cp -r` copy. The job runs in parallel with the existing `lint`,
`unit-tests`, `ffi-bindings` and `msrv` jobs and uses the same
`Swatinem/rust-cache@v2` action keyed `templates` for incremental
builds.

No public Rust API change, no C ABI change, no version bump.

**`lr-cli` RFC 9234 §3.1 exchange-plane policy role configuration
(`[bgp] exchange_plane_policy_role` + `[[peer]] exchange_plane_policy_role`
+ `--exchange-plane-policy-role`)** (issue #92 — `defects.txt`
`crates/lr-cli/src/daemon.rs` INCOMPLETE-IMPL "lr's daemon does not
configure RFC 9234 roles yet, so the claim is ROLE_UNSET"). The W6.3
exchange-plane prototype already advertised the LRXP capability and
exchanged record sets, but the RFC 9234 §3.1 *policy role* the local
speaker claims for a session was hardcoded to `ROLE_UNSET` in
`wire_exchange_plane` — an operator who wanted to claim `provider`,
`customer`, `rs`, `rs-client` or `peer` (the five RFC 9234 vocabulary
entries) had no TOML or CLI surface to do so, and the role the peer's
import policy consults was always the "no claim" byte.

This round exposes the role end-to-end:

- `DaemonConfig.exchange_plane_policy_role` (router-wide default,
  default value `"unset"`) and `PeerSpec.exchange_plane_policy_role`
  (per-peer override, `Option<String>`) carry the canonical lowercase
  vocabulary word.
- `parse_exchange_plane_policy_role` validates the input at parse
  time, canonicalising case and surrounding whitespace, so a TOML
  value with stray casing (`"RS-Client"`) round-trips to the same
  byte string the C ABI's `policy_role` field carries. A typo'd
  value (`"providor"`) fails closed with a diagnostic that names
  the bad value and enumerates the accepted vocabulary.
- `finalize_exchange_plane` rewrites the empty string (a
  `DaemonConfig::default()` shape the SIGHUP reload path and the
  `.lr` DSL emitter use) to the canonical `"unset"` so the wire byte
  always carries a valid RFC 9234 vocabulary word; it re-validates
  the global and any per-peer overrides so a directly-constructed
  `DaemonConfig` (programming error — the parser would have caught
  it) still fails closed.
- `DaemonConfig::effective_exchange_plane_policy_role(peer)` resolves
  the per-peer override against the global default.
- `wire_exchange_plane` consults the resolver and stamps the matching
  RFC 9234 role byte (`ROLE_PROVIDER` / `ROLE_CUSTOMER` / `ROLE_RS` /
  `ROLE_RS_CLIENT` / `ROLE_PEER` / `ROLE_UNSET`) onto the
  policy-intent record instead of the hardcoded `ROLE_UNSET`.
- The CLI banner (`--help`) advertises the new flag with its
  vocabulary, the per-peer override key, and the per-peer override
  pointer.

Eight in-process unit tests pin the parser + finalize + resolver
(`toml_global_exchange_plane_policy_role_parses`,
`toml_global_exchange_plane_policy_role_canonicalises_case`,
`toml_global_exchange_plane_policy_role_rejects_typo`,
`toml_peer_exchange_plane_policy_role_override_parses`,
`toml_peer_exchange_plane_policy_role_inherits_global`,
`toml_peer_exchange_plane_policy_role_rejects_typo`,
`finalize_rewrites_empty_global_role_to_unset`,
`finalize_rejects_directly_written_bad_role`,
`finalize_rejects_directly_written_bad_peer_role`,
`parse_exchange_plane_policy_role_accepts_canonical_vocabulary`,
`parse_exchange_plane_policy_role_rejects_unknown`). Seven e2e
tests in `crates/lr-cli/tests/daemon_exchange_plane_role.rs` exercise
the CLI surface (`--help` advertisement, `config check` acceptance
of global + per-peer + explicit `unset`, `config check` rejection of
global + per-peer typos, `--exchange-plane-policy-role` CLI flag
acceptance and rejection) through the real `lr-daemon` binary.

No public Rust API change, no C ABI change, no version bump.

### Fixed

**`lr-cli` / `lr-router` / `lr-policy`: FRR `network PREFIX route-map
NAME` qualifier applied at origination** (`policy`, issue #92 —
defects.txt L75). The FRR `network PREFIX route-map NAME` form (RFC
4271 §9.1.2.1 — "Originate routes from the local routing table into
BGP") is the per-network attribute hook on origination: a route-map
whose `set` actions rewrite the locally originated route before it
enters the Loc-RIB (and from there every Adj-RIB-Out) and whose
`deny` verdict suppresses origination. The previous `lr translate
frr` converter parsed the qualifier, pushed the prefix onto
`networks`, and noted the route-map as unmapped — claiming "lr's
`networks` is a plain prefix list, no per-route attribute hook." The
claim was already stale: `lr_policy::RouteMap::evaluate` (with the
`MatchResolver` trait) is the right hook surface, and
`lr_router::DefaultRouter::originate_family` constructs the route
object the route-map can mutate. The gap was on the converter and
daemon-origination sides only.

This round closes the gap end-to-end:

- **`lr-router`**: `DefaultRouter::originate_family_with_route_map`
  is a new public method that builds the locally-originated route
  (factored out of `originate_family` into `build_originated_route`
  so the two paths do not duplicate attribute construction), runs
  the route-map's `evaluate` against it, and installs the
  (possibly mutated) route via the new shared `install_originated`
  helper. The `deny` verdict returns `None` (no origination); the
  `permit` and fall-through cases return `Some(RouteKey)`. The
  route-map's `set` actions (`SetLocalPref` / `SetMed` / `PrependAs`
  / `AddCommunity` / `SetNextHop` / `SetMetric` / `SetTag`) are
  applied before the route enters the Loc-RIB, so every Adj-RIB-Out
  sees the rewritten attribute. The per-session export policy is
  unchanged — the per-network route-map is the origin-wide
  attribute hook, not a per-peer filter.
- **`lr-policy`**: `PolicyHooks` gains a `route_map(name)` accessor
  and a `MatchResolver` impl that delegates to the underlying
  `PolicySet`. The daemon shares one `PolicyHooks` between the
  import/export hook chain (the existing usage) and the per-network
  origination path (the new usage), so a single
  `lr_policy::PolicySet` build covers both dispatch sites. The
  `MatchResolver` impl mirrors the delegation `PolicySet` already
  provides; the `route_map` accessor returns the named `RouteMap` or
  `None` (the daemon's finalize step already rejects unknown
  route-map names at startup, so a missing lookup at runtime is a
  daemon bug — the origination path falls back to plain
  `originate_family` and logs the inconsistency).
- **`lr-cli` (daemon-config)**: a new `[[bgp.network_route_map]]`
  TOML table (with `prefix` and `route_map` keys) carries the
  per-network route-map qualifier. The finalize step fails closed
  when the entry's prefix is not in `networks` (the route-map is a
  per-network qualifier, not a way to originate a network the
  operator did not list), when the `route_map` name is unknown (a
  typo surfaces at startup instead of silently dropping the
  route-map at first UPDATE), and when the same `(prefix,
  route_map)` pair appears twice. The parser also fails closed on
  unknown keys (`typo protection; the route-map qualifier fails
  closed`) — the same posture as the `[[aggregate]]` handler.
- **`lr-cli` (daemon)**: the BGP daemon's origination path now
  looks up the per-network route-map (if any) for each `networks`
  entry, resolves the named `RouteMap` against the daemon's
  `PolicyHooks`, and calls `originate_family_with_route_map` when a
  route-map is configured (logging `originating <prefix> (route-map
  <name>)` on permit, `network <prefix> suppressed by route-map
  <name> (deny verdict)` on deny). The SIGHUP reload path consults
  the freshly-reloaded `[[bgp.network_route_map]]` table the same
  way for newly-originated networks; the live routes stay unchanged
  on reload (the per-network route-map is applied once per
  origination event, not per reload — a follow-up can re-originate
  the affected network when its route-map changes).
- **`lr-cli` (translate)**: the FRR converter now maps `network
  PREFIX route-map NAME` onto a `[[bgp.network_route_map]]` row
  (instead of an unmapped note), keeping the prefix on `networks`
  the same way the previous shape did. The BIRD converter is
  unchanged — BIRD's `network` (inside `protocol bgp`) does not
  carry a per-route route-map qualifier the way FRR's does (BIRD
  puts the route-map on the protocol's `import` / `export` filter
  instead, which the converter already maps onto the per-peer
  `import` / `export` TOML keys).
- **`lr-cli` (config_dsl)**: the `.lr` DSL parser and emitter
  recognise the `bgp.network_route_map { prefix = "..." ;
  route_map = "..." }` block, so `lr config to-dsl` round-trips a
  config that carries `[[bgp.network_route_map]]` without loss.
  The block is a top-level array table (mirrors the TOML shape —
  flat, no enclosing `bgp { … }`).

Test surface: ten new unit tests in
`crates/lr-cli/src/daemon_config_tests.rs` cover the TOML parser +
finalize (`network_route_map_table_parses_and_finalizes`,
`network_route_map_missing_prefix_fails`,
`network_route_map_missing_route_map_fails`,
`network_route_map_unknown_route_map_fails`,
`network_route_map_prefix_not_in_networks_fails`,
`network_route_map_unknown_key_fails_closed`,
`network_route_map_duplicate_fails`,
`network_route_map_empty_route_map_name_fails`,
`network_route_map_bad_prefix_fails`,
`network_route_map_without_route_maps_block_starts_daemon`). Four
new e2e tests in `crates/lr-cli/tests/daemon_policy.rs` exercise
the daemon's runtime path through the real `lr-daemon` binary
(`network_route_map_permit_originate_and_peer_installs` — the
daemon logs `originating <prefix> (route-map <name>)` and the peer
installs the route; `network_route_map_deny_suppresses_origination`
— the daemon logs `network <prefix> suppressed by route-map <name>
(deny verdict)` and the peer never installs the route;
`network_route_map_unknown_route_map_name_fails_startup` and
`network_route_map_prefix_not_in_networks_fails_startup` — the
daemon's stderr carries the finalize-step diagnostic). Four new
unit tests in `crates/lr-cli/src/translate_tests.rs` cover the FRR
converter
(`frr_network_with_route_map_emits_bgp_network_route_map_table`,
`frr_network_with_route_map_missing_name_notes_unmapped`,
`frr_network_without_route_map_still_emits_just_networks`,
`frr_network_route_map_with_route_map_definition_round_trips`).
Two new unit tests in `crates/lr-cli/src/config_dsl/emit_tests.rs`
cover the DSL round-trip
(`round_trips_bgp_network_route_map_table`,
`round_trips_multiple_bgp_network_route_map_tables`). Eight new
unit tests in `crates/lr-router/src/instance/tests.rs` cover
`DefaultRouter::originate_family_with_route_map`'s contract
(permit, deny, fall-through, set_local_pref, set_med, set_tag,
prepend_as, v6 NEXT_HOP unaffected). Two new unit tests in
`crates/lr-policy/src/set.rs` cover `PolicyHooks::route_map` and
the `MatchResolver` delegation
(`policy_hooks_route_map_looks_up_named_route_map`,
`policy_hooks_match_resolver_delegates_to_inner_set`).

Public Rust API change (additive): one new public method on
`lr_router::DefaultRouter`
(`originate_family_with_route_map`), two new public items on
`lr_policy::PolicyHooks` (the `route_map` accessor and the
`MatchResolver` impl), one new public struct in
`lr_cli::daemon_config` (`NetworkRouteMapSpec`). The two
private helpers `build_originated_route` and `install_originated`
on `DefaultRouter` are non-public refactors of the existing
`originate_family` body; their signatures are stable across the
`lr-router` crate's own consumers. No C ABI change (no `lr_*`
symbol touched — `BgpAction` and `Event` are not exposed through
the C ABI; the new `DefaultRouter::originate_family_with_route_map`
is a Rust-API-only addition that takes `&lr_policy::RouteMap` and
`&dyn lr_policy::action::MatchResolver`, neither of which has a C
ABI counterpart), no protocol-on-the-wire change (the route-map's
`set` actions produce attributes the egress path already knew how
to encode), no version bump.

The defects.txt entry this closes is
`crates/lr-cli/src/translate.rs:L71-L72 | INCOMPLETE-IMPL | "lr's
\`networks\` is a plain prefix list, no per-route attribute hook" -
FRR \`network PREFIX route-map NAME\` not mapped`. The matching
re-stated entries at `crates/lr-cli/src/translate.rs:L268` and
`crates/lr-cli/src/translate.rs:L275` are also closed.

**`lr-cli` clippy regression in `daemon_ospf3_tests.rs`** (`test`,
issue #92 follow-up). The `OSPFv3 RFC 7166 authentication trailer
wiring end-to-end` round (commit `3b0bcb5`) added a test that
constructed an error message via `format!("{err}")`, which the
`clippy::useless_format` lint rejects as "use `.to_string()` instead".
The lint is in the workspace `cargo clippy --workspace --all-targets
--all-features -- -D warnings` gate, so the regression broke the gate
on every CI run after the round landed. Replace with `err.to_string()`
— the `Display` impl behind `err.to_string()` is the same as the
`fmt::Display` impl behind `format!("{err}")`, so the test's
observable behaviour (the assertion that the error message contains
"not valid for OSPFv3" and "RFC 7166") is unchanged.

No public Rust API change, no C ABI change, no version bump.

**`lr-ffi` non-Linux build of the `osroute_helpers` module** (`ffi`,
issue #92). The `non_linux_stubs` module in
`crates/lr-ffi/src/osroute_helpers.rs` was missing the `use super::*`
import that brings the parent module's
`lr_osroute_interface_v4_addr_t` / `lr_osroute_interface_v6_addr_t`
struct types into scope, so the v4 / v6 address-array stubs
referenced undeclared types. The Windows cross-build
(`cargo build --workspace --target x86_64-pc-windows-gnu`), the
macOS cross-build (`x86_64-apple-darwin`), the Windows native clippy
job, and the macOS native clippy job — every CI gate that exercises
a non-Linux target — failed with `error[E0425]: cannot find type
\`lr_osroute_interface_v4_addr_t\` in this scope`. The Linux path
compiled because the `linux_helpers` sibling module already had
`use super::*`; only the non-Linux path was broken, so the bug
silently passed the Linux-only `cargo build` and `cargo test` gates
and only surfaced in CI matrix entries that cross-compile or run on
a non-Linux host. The same fix also pulls the unused `set_last_error`
import out of the parent module's `use crate::error::{...}` line
and into the `linux_helpers` module where it is actually referenced
(the parent only uses `LR_ERR_PANIC` directly); the import triggered
`-D warnings` / `unused_imports` on Windows and macOS. The
`LR_ERR_OTHER` constant was likewise moved into `linux_helpers`
since it is the only consumer — declaring it at the parent scope
produced `-D warnings` / `dead_code` on non-Linux (where the stubs
return `0` / success for every entry point, mirroring
`lr_osroute::stub::StubRouteTable`). No `#[no_mangle]` symbol
was added or removed and no C ABI signature changed — `ABI_VERSION`
stays at 2 and the `lr_ffi.h` header diff is empty.

**`lr-policy` community-list and AS-path filter `evaluate` stubs now
fail-closed when the `bgp` feature is off** (`policy`, issue #92). The
`#[cfg(not(feature = "bgp"))]` stubs in
`crates/lr-policy/src/community_list.rs` and
`crates/lr-policy/src/as_path_filter.rs` previously returned `true`
(permit-all) on every call — a permissive stub that silently admitted
every route past a configured-but-unparseable filter. Without the
typed BGP path-attribute decoder the crate cannot actually evaluate
the configured list, so the safe default for a security-sensitive
control plane is to deny the route (`false`), matching what the
`DenyAllResolver` already does on the FFI side and what
`CommunityListBank::evaluate` already does for unknown list ids. The
previous shape was flagged in `defects.txt` as a FAKE-IMPL with an
unsafe default; this release flips the default. Embedders that build
`lr-policy` without `bgp` for prefix-only deployments should use
`PrefixList` and not configure a `CommunityList` / `AsPathFilter` at
all — the stub now denies instead of silently admitting. New
`#[cfg(not(feature = "bgp"))] #[cfg(test)] mod no_bgp_tests` modules
in both files pin the deny behaviour; the existing `#[cfg(test)] mod
tests` modules are gated `#[cfg(all(test, feature = "bgp"))]` to keep
the two test surfaces disjoint. The default build (with `bgp` on)
is unchanged. The `--no-default-features --features std` build of
`lr-policy` is currently blocked upstream of these stubs — the
`FilterContext` trait's default method bodies in
`crates/lr-policy/src/filter/eval.rs` reference `crate::bgp::*`
unconditionally — so the new no-bgp tests stay dormant until that
upstream follow-up lands; they will then exercise the fail-closed
verdict and catch any regression that re-introduces the permissive
permit-all stub.

**`lr-ospf` SPF walk now merges fragmented Router-LSAs per RFC 5340
§4.4.2** (`ospf`, issue #92). The OSPFv3 LSDB pre-scan in
`V3Topology::from_lsdb` previously kept only the first Router-LSA
instance per advertising router (legacy `0x2001` and Extended
`0xA021` paths both used a `BTreeSet::insert` sentinel / `.or_insert`
shape that silently dropped every fragment after the first). RFC 5340
§4.4.2 lets a router originate multiple Router-LSAs per area,
disambiguated by the Link State ID (the fragment number 0, 1, 2, …),
and a conformant receiver MUST merge all fragments into one virtual
vertex: the bits/options come from the lowest-LS-ID fragment, and the
links lists concatenate. Without the merge, a router with more than
approximately 30 interfaces — the threshold at which the link list
no longer fits inside the IPv6 MTU and the LSA has to be split —
silently lost every adjacency described by fragment 1 and beyond,
and the SPF tree lost every reachable destination beyond the first
fragment's links. The fix lifts both the legacy and the
Extended-LSA reception paths: `V3RouterLsaBody::links` is extended
across fragments via `.entry().and_modify(|merged|
merged.links.extend(body.links.clone())).or_insert(body)`, and the
E-Router-LSA pre-pass appends subsequent fragments' decoded
Router-Link TLVs to the merged body. Two new public self-origination
helpers mirror the new surface for emitters: `originate_v3_router_lsa_fragment`
(in `crates/lr-ospf/src/lsa/v3.rs`) and
`originate_v3_e_router_lsa_fragment` (in `crates/lr-ospf/src/lsa/e_v3.rs`)
take an explicit `ls_id` so a router that needs to split its
Router-LSA can originate fragments 0, 1, … as the spec requires; the
existing `originate_v3_router_lsa` and `originate_v3_e_router_lsa`
delegate to them with `ls_id = 0` (no behaviour change for callers
that originate a single fragment). Four regression tests in
`crates/lr-ospf/src/spf_v3_tests.rs` pin the merge:
`v3_fragmented_router_lsa_merges_links_across_fragments` (r2 splits
its link list across two fragments so r3 is reachable only through
the merge),
`v3_fragmented_router_lsa_first_fragment_seen_supplies_bits_and_options`
(a single fragment with a non-zero Link State ID still produces a
valid vertex),
`v3_fragmented_router_lsa_merge_is_lsdb_order_stable` (the
bits/options come from the lowest-LS-ID fragment regardless of
install order — the LSDB's `BTreeMap` iteration is ascending by
`LsaKey`), and `v3_extended_fragmented_e_router_lsa_merges_links_across_fragments`
(the Extended-LSA reception path merges E-Router-LSA fragments too).
No public Rust API surface move beyond the two additive origination
helpers; no C ABI change (`include/lr_ffi.h` byte-identical).

**`lr-ospf` now computes type-7 NSSA routes for OSPFv3 (RFC 5340
§4.4.3.6 / RFC 3101 §2.5)** (`ospf`, issue #92). The v3 type-7 path
was the asymmetric gap left by `external_routes_v3` (RFC 5340
§4.8.5): the v3 AS-external-LSA route calculation landed without a
type-7 mirror, so 0x2007 NSSA-LSAs (and their 0xA027 E-Type-7
counterparts under Extended-LSA mode) never entered v3 SPF — an
NSSA-area v3 deployment could originate type-7 LSAs but the
calculation side installed nothing. The fix adds
`lr_ospf::nssa::nssa_routes_v3` (legacy 0x2007 reception) and
`lr_ospf::nssa::nssa_routes_v3_extended` (Extended-LSA 0xA027
reception) — both mirror `external_routes_v3` with two protocol-
mandated deviations from the type-5 path: the forwarding address
must be covered by an *intra-area* path of the NSSA itself (RFC
3101 §2.5 step (3) — summary routes do not qualify, since type-7
LSAs never leave the NSSA), and the ASBR must be reachable within
the NSSA (no `0x2004` / `0xA024` inter-area-router-LSA fallback —
type-4 LSAs do not flood into NSSAs). The default-route install
rules from §2.5 step (3) [NSSA] carry over: a border router skips
type-7 defaults whose P-bit is clear, and skips all type-7 defaults
when summary import is suppressed. The v3 P-bit lives in the
prefix-options byte (`PREFIX_OPT_P`, RFC 5340 §A.4.1.1) rather than
the LSA header (v3 LSA headers carry no options byte, RFC 5340
§A.4.2); the prefix-options P-bit is the IANA-registered
"Propagate" bit and carries §2.4's NSSA-translation semantics. The
router pipeline (`lr_router::instance::ospf_ops::ospf_recompute`)
honours the new path for `OspfAreaType::Nssa` v3 areas alongside
the existing type-5 / inter-area / intra-area legs. One new public
self-origination helper `originate_v3_nssa_lsa` (in
`crates/lr-ospf/src/lsa/v3.rs`) emits a 0x2007 LSA from a
`V3ExternalDestination` plus a `p_bit` flag, mirroring the v2
`originate_nssa_lsa` for emitters and tests. Fifteen new unit tests
in `crates/lr-ospf/src/nssa_v3_tests.rs` pin the selection rules:
intra-area ASBR reachability, intra-area FA cover (and rejection of
summary cover), link-local / unspecified FA rejection, no
inter-area-router leg (with a sanity check that the type-5 path
*does* honour the leg), LSInfinity / NU-bit filters, type-1 vs
type-2 preference, route-tag propagation, default-route install
rules for border routers (P-bit set / clear, summaries suppressed /
imported), Extended-LSA (0xA027) reception in extended mode only,
origination-helper `p_bit`-requires-FA invariant, type-5 LSA
invisibility to the type-7 path, the fast-path skip for LSDBs
without any type-7, the unreachable-ASBR drop, and the
prefix-options-byte P-bit read. Public Rust API gains the new
`originate_v3_nssa_lsa` function and the `LS_TYPE_NSSA` constant;
no C ABI change (`include/lr_ffi.h` byte-identical). The v3
type-7 → type-5 translation (RFC 3101 §3.2) remains a v2-only
follow-up — the route computation is the substantive gap the defect
flagged, and the translator election logic stays v2-scoped until a
follow-up adds the v3 origination side of the translation.

**Python and Go `Route` bindings now expose every reader and bulk
replacer the C ABI ships** (`bindings`, issue #92). The Python
`Route` class (`bindings/lr-python/src/librouting/policy.py`) was
missing `next_hop()` / `origin()` / `tag()` readers and
`set_large_communities()` / `set_ext_communities()` /
`ext_communities()` — an operator who set the attribute through the
binding could not read it back, and the bulk-replacer variants the C
ABI exposes (`lr_route_set_large_communities`,
`lr_route_set_ext_communities`) had no Python surface at all. The Go
`Route` type (`bindings/lr-go/librouting.go`) had the same
asymmetry for `NextHop()` / `Origin()` / `Tag()` readers and
`SetLargeCommunities()` / `SetExtCommunities()` / `Metric()`. The
C++ wrapper in `include/librouting.hpp` was already complete for
the reader/replacer set except `set_ext_communities`; the C ABI
itself was unchanged (the underlying `lr_route_*` symbols were all
already exposed by `crates/lr-ffi/src/policy_objects.rs`).

The new Python methods mirror the existing readers' shape — `None`
when the attribute is absent (the C ABI returns 1 in that case), an
`LrError` on any negative rc, and the address length signals the
family for `next_hop()` (4 bytes for IPv4, 16 for IPv6, matching the
C ABI's `out_is_ipv6` discriminator). The Go readers mirror the
`(value, ok, error)` triple used by the existing `LocalPref()` /
`Med()` readers. `set_large_communities` / `SetLargeCommunities`
take a flat `[g1, d1_1, d1_2, g2, ...]` slice that must be a multiple
of three (each triple is one RFC 8092 large community); the C ABI
takes the entry count, not the `u32` count, so the binding divides
the slice length by three before the call (matching the C++ wrapper
in `set_large_communities`). `set_ext_communities` /
`SetExtCommunities` take a list of `(kind, subtype, global, local)`
tuples / `ExtCommunity` structs mirroring `lr_ext_comm_t`; the
Python binding uses `getattr(arr[i], "global")` and `setattr` because
`global` is a Python keyword and cannot appear as an attribute
access expression. `Metric()` mirrors the existing `SetMetric`;
the previous Python `metric()` reader already existed.

One new test per binding covers the round trip:
`test_route_attribute_readers_and_replacers` in
`bindings/lr-python/tests/test_librouting.py` and
`TestRouteAttributeReadersAndReplacers` in
`bindings/lr-go/librouting_test.go`. Each test exercises the
absent-default, the v4/v6 next-hop round trip (IPv6 discriminator
covered), the IGP/EGP/INCOMPLETE origin round trip, the bulk
replace + drop (empty list) + malformed-triples rejection for both
community kinds, the metric round trip, and the tag set/clear/
zero-tag-still-present round trip. The Python suite stays at 34
passing tests (was 33); the Go suite stays green. No Rust change,
no C ABI change, no version bump — additive binding surface only.

### `lr-policy`: fail-closed hardening for BGP `SetAction` variants (issue #92)

`SetAction::SetLocalPref`, `SetAction::SetMed`, `SetAction::PrependAs`
and `SetAction::AddCommunity` are BGP-specific path-attribute mutations
(RFC 4271 §5.1.5 / §5.1.4 / §5.1.2 / RFC 1997). When `lr-policy` was
built without the `bgp` feature, the four variants were silent no-ops:
`apply_set` discarded the action with no signal, so an operator who
configured `set local-preference` against a no-`bgp` build saw the
route pass through unchanged, with no indication the policy had been
silently bypassed.

The fail-closed contract is now exposed through
`lr_policy::action::apply_set_checked`, which returns
`ApplySetError::RequiresBgpFeature` for the four variants when the
`bgp` feature is off. `RouteMap::evaluate` consumes the checked form
and denies the route on `Err` — matching the fail-closed tightening
that landed for `CommunityList` / `AsPathFilter`. The legacy
`apply_set` keeps its infallible signature for ABI-stable embedders
and now logs the dropped action through `tracing::warn!` so the silent
failure is at least observable in the daemon's log stream.

The crate's `--no-default-features --features std` build is currently
blocked upstream of this module (`filter/eval.rs`'s default method
bodies reference `crate::bgp::*` unconditionally), so the no-`bgp`
fail-closed tests in `action.rs` and `route_map.rs` pin the contract
for the future follow-up that lands the no-`bgp` build.

### `lr-policy`: filter VM `unreachable!()` arms hardened to `EvalError` (issue #92)

Six `unreachable!()` arms in `crates/lr-policy/src/filter/eval.rs` —
one in `read_int_route_field`, four in `eval_binary` (the Lt/Le/Gt/Ge,
Add/Sub/Mul/Div/Mod, BitAnd/BitOr/BitXor, Shl/Shr match arms), and one
in the `BranchFieldIntCmp` instruction dispatch — were defended by
peephole-pass invariants that, if violated by a future refactor, would
panic on the production data path.

Each `unreachable!()` is replaced by an
`Err(EvalErrorKind::InternalInvariant(&'static str))`
return. The new `InternalInvariant` variant identifies the violated
invariant for diagnostics; the surrounding span points at the offending
instruction in the filter source. The hot path's success case is
unchanged — the `Err` return only fires on peephole drift, where the
previous behavior was a `panic!`. The `read_int_route_field` signature
gains a `span: Span` parameter so the error carries the source span
of the calling `BranchFieldIntCmp` instruction.

### `lr-bgp` / `lr-core`: trait adapter surfaces RouteRefresh / EndOfRib (issue #92)

`BgpAction::RouteRefreshRequested` (RFC 2918 §2) and
`BgpAction::EndOfRib` (RFC 4724 §4) were silently dropped to
`Action::None` by the `StateMachine for BgpPeer` trait adapter in
`crates/lr-bgp/src/fsm.rs`. A trait-only embedder that drives the BGP
FSM through the generic `lr_core::fsm::StateMachine` trait — instead of
consuming `BgpAction` directly as the daemon does — saw neither signal,
masking both the route-refresh request and the End-of-RIB marker.

The adapter now maps both variants to `Action::EmitEvent(Event::*)`,
where `Event` gains two new variants:

- `Event::RouteRefreshRequested { session, family }`
- `Event::EndOfRib { session, family }`

The `From<Event> for RouterEvent` impl in `crates/lr-router/src/event.rs`
maps the two new variants to `RouterEvent::Log(...)` so the daemon's
event stream keeps a trace of the trait-only path; router-aware
embedders that consume `BgpAction` directly (the daemon's shape) are
unchanged. The session id is `cfg.peer_id` of the receiving peer,
matching what `BgpPeer::step()` populates for `Event::PeerStateChange`.

The two new `Event` variants are a breaking change for downstream
`match` exhaustiveness on `Event`. The project's tolerance for
semver drift on `Event` is documented in `CHANGELOG.md` rc.3 / 1.0.0
(`cargo semver-checks` runs with `continue-on-error: true` until the
next minor); the variants are additive for embedders whose `match`
includes a `_ => ...` arm.

### `lr-ospf` / `lr-router`: OSPF LSA retransmission list (RFC 2328
§13.5 / §13.6 / §13.7, issue #92)

The OSPF flood path (`DefaultRouter::ospf_flood`) and the
`OspfBody::LsAck` handler in `crates/lr-router/src/instance/ospf.rs`
were a no-op stub: `ospf_flood` was documented as
"simplified: no ack/retransmission bookkeeping — the poll-driven
embedder handles transport reliability", and the LS-Ack handler
returned `OspfStep::default()` without consulting any state. A
single dropped LS-Update (or dropped LS-Ack) left the two LSDBs
permanently out of sync and SPF computed against a stale view of
the area — the kind of bug BIRD and FRR have not had since their
initial releases.

This release closes the gap. A new public module
`lr_ospf::retransmit` exposes `LinkStateRetransmissionList` — a
`BTreeMap<LsaKey, (Lsa, last_sent_ms)>` keyed by `(ls_type,
link_state_id, advertising_router)`, matching the LSA identity the
LSDB already uses:

- `record_flood(lsa, now_ms)` adds an LSA to the list before the
  LSU is placed on the wire (§13.5 step 5).
- `apply_acks(&[LsaHeader])` drains acked entries (§13.7), matching
  on LSA identity rather than sequence number per §13.7 step 5
  ("the receiver may acknowledge an older instance").
- `poll(now_ms, rxmt_interval)` returns LSAs that have waited
  `RxmtInterval` without an ack (§13.6) and bumps their
  `last_sent_ms` so the next cycle waits another full interval.
- `remove(&LsaKey)`, `clear()`, `contains(&LsaKey)`, `iter()` round
  out the surface for LSDB-replacement cleanup, neighbor reset, and
  the `show ospf neighbor` renderer.

`OspfRuntime` gains a `retransmit: LinkStateRetransmissionList`
field; `ospf_flood` records each flooded LSA on the receiving
neighbor's list before sending, and `OspfBody::LsAck` now invokes
`OspfRuntime::on_ls_ack` which drains the list per §13.7. The
existing poll loop in `crates/lr-router/src/instance/mod.rs` (which
already drives the DBD/LSR exchange retransmissions) gains a
second pass that walks every OSPF session's retransmit list and
re-floods aged entries as a unicast LS-Update to that neighbor —
matching BIRD's `ospf_ls_upd_queue_lsa` per-neighbor shape.

§13.7 step 5 mandates that stray / duplicate acks are accepted
silently; `on_ls_ack` surfaces a `RouterEvent::Log` action when an
ack does not match any pending entry so the operator can
correlate it with a possible session de-sync.

The change is internal: no public Rust API shape changes, no C ABI
changes, no protocol-on-the-wire changes. Existing OSPF tests
(42 of them in `lr-router`'s `instance::tests`) continue to pass,
and the OSPF + BIRD 2.17.5 interop (`tests/interop/ospf_bird.sh`,
`ospf_gr_bird.sh`, `ospf_broadcast.sh`) remains green.

### `lr-osroute`: Linux `source_check` via `RTM_GETROUTE` (issue #92)

`lr_osroute::source_check::check_source_compatibility` is the
diagnostic the daemon runs *before* the first outbound TCP dial to
warn the operator when the configured `local_address` is not on the
kernel's chosen egress interface — the root cause of the Windows
Strong Host Model "peer sent NOTIFICATION code=6 sub=7" storm. The
Windows implementation already used `GetBestRoute2` + a real
`bind()` test, but the Linux `imp` was a no-op stub that returned
`SourceCheck::Ok` without consulting the kernel — `defects.txt`
flagged it as `INCOMPLETE-IMPL` (`crates/lr-osroute/src/source_check.rs:L343-L365`,
"fall back to Ok on Linux until the rtnetlink helper is factored
out").

The Linux `imp` now opens a `NETLINK_ROUTE` socket, issues a single
`RTM_GETROUTE` request carrying `RTA_DST = peer` (the same shape
`ip route get <addr>` produces), and parses the kernel's reply for
`RTA_PREFSRC` and `RTA_OIF`. The diagnostic then returns:

- `SourceCheck::Ok` when the kernel's preferred source matches the
  configured `local`,
- `SourceCheck::Mismatch { configured, kernel_choice }` when the
  kernel would source the dial from a different address (the daemon
  binds, which overrides the default on Linux — informational, no
  warning),
- `SourceCheck::NoRoute` when the kernel reports no route to the
  peer (`NLMSG_ERROR` carrying a negative `ENETUNREACH` /
  `EHOSTUNREACH`),
- `SourceCheck::Ok` on any failure to consult the kernel
  (unprivileged container without netlink access, transient ENOMEM,
  malformed reply) — the diagnostic is a *hint*, not a gate, so the
  daemon still dials and the operator's "outbound TCP established"
  log line is the source of truth once the connection lands.

The platform-support table in the module doc is updated to mark
Linux as `yes — RTM_GETROUTE with RTA_PREFSRC reports the kernel's
preferred source`. The `lr-cli::daemon` Mismatch / Ok log comments
are updated to reflect that Linux now consults the kernel (the
macOS no-op path is unchanged). The FFI wrapper
`lr_osroute_check_source_compatibility` and its C ABI signature are
unchanged — the same `kind` discriminant (0..3) now reflects the
real Linux verdict instead of always `0`.

Tests:

- `source_check::tests::loopback_v4_matches` /
  `loopback_v6_matches` — the kernel's preferred source for
  `127.0.0.1` and `::1` is the loopback address itself, so a
  `local = 127.0.0.1` peer on `127.0.0.1` returns `Ok`.
- `source_check::tests::loopback_against_routable_peer_is_not_ok` —
  the kernel's preferred source for `1.1.1.1` is the egress
  interface's address (NOT `127.0.0.1`), so a `local = 127.0.0.1`
  peer on `1.1.1.1` returns `Mismatch` (or `NoRoute` in a hermetic
  CI without a default route).
- `source_check::tests::diagnostic_is_total_on_any_peer` — the
  helper never panics on any peer (the contract is "never block the
  daemon on a kernel query that might fail").
- The `ffi_check_source_compatibility_returns_ok_on_non_windows`
  test is renamed to `ffi_check_source_compatibility_loopback_ok`
  and now uses loopback-to-loopback (the previous non-loopback probe
  relied on the Linux no-op returning `Ok` for any address pair).
- New `crates/lr-cli/tests/daemon_source_check.rs` e2e tests pin the
  daemon wiring: `loopback_local_loopback_peer_is_ok` (no mismatch
  info line for `local=127.0.0.1` → `127.0.0.1:<port>`),
  `loopback_local_routable_peer_logs_mismatch` (the
  `kernel default source for` info line appears for
  `local=127.0.0.1` → `1.1.1.1:179`).

No public Rust API change, no C ABI change, no protocol-on-the-wire
change, no version bump.

### `lr-ospf` / `lr-router`: RFC 3101 §3.1 NSSA translator reachability (issue #92)

`lr_ospf::nssa::is_elected_translator` was the simplified form of the
RFC 3101 §3.1 election: among the NSSA's border routers — every router
whose router-LSA in the area carries the B-bit, plus the caller —
the highest router ID performs type-7 → type-5 translation, with a
router advertising the Nt-bit (RFC 3101 Appendix B) beating a merely
higher router ID. The full §3.1 rule additionally requires candidates
to be "reachable as an ASBR over the AS's transit topology"; the
simplified form considered NSSA reachability only, which matches
single-backbone deployments and the common FRR/BIRD configuration
but lets a stale or partitioned NSSA border router visible in the
NSSA's LSDB but unreachable across the regular areas steal the
translator role from a reachable one (`defects.txt` flagged it as
`INCOMPLETE-IMPL` at `crates/lr-ospf/src/nssa.rs:L295-L306`,
"simplified: only considers NSSA reachability, does not verify
ASBR is reachable across the whole AS").

A new `is_elected_translator_with_reachability(lsdb, router_id,
reachable: Option<&HashSet<u32>>)` variant adds the §3.1 qualifier.
When `reachable` is `None` the function keeps the legacy behaviour
(NSSA reachability only) so existing embedders and the
`lr_ospf_is_elected_translator` C ABI symbol are unchanged. When
`reachable` is `Some(set)`, candidates — border routers and Nt-bit
unconditional translators — must additionally appear in `set`, i.e.
they must be reachable from the local router through the AS's
regular (non-stubby, non-NSSA) areas' intra-area SPF. The local
router itself is always a candidate, but when the filter is supplied
it must be in the set, otherwise no candidate is reachable and
translation is disabled (§3.1: "an NSSA border router that is not
reachable as an ASBR over the AS's transit topology cannot be the
translator"). An empty `Some(set)` returns `false`.

The daemon's `ospf_translate_nssa` (the only internal caller of the
election) now uses the reachability-aware variant. The router struct
gains a cached `ospf_as_reachable_routers: HashSet<u32>` field
populated by `ospf_summarize_areas_v2` from the same per-area SPF
run that drives summary origination — the set is the union of every
`VertexId::Router(_)` reachable across the local router's regular
(stubby-excluded) v2 areas. Stubby and NSSA areas are excluded from
the set (RFC 2328 §3.6; RFC 3101 §3.1 — they are not part of the
AS's transit topology). The cache is populated in the same
LSDB-change tick that drives the first translation attempt (the
`ospf_on_lsdb_change` flow runs `ospf_summarize_areas` before
`ospf_translate_nssa`), so the first election sees a populated set
rather than a stale `None` filter. There is no extra SPF cost —
the set is a side-effect of the SPF run `ospf_summarize_areas_v2`
already does.

A new `lr_ospf_is_elected_translator_with_reachability` C ABI
symbol exposes the variant. It takes the reachability set as a
`const uint32_t *reachable` + `uintptr_t reachable_count` pair
(matching the `lr_ospf_retransmit_apply_acks` pattern); a NULL
pointer with zero count selects the legacy form. The C++ wrapper
adds the corresponding `ospf_is_elected_translator_with_reachability`
inline (both the raw-handle and RAII-handle overloads). The Go
binding auto-generates an `OspfIsElectedTranslatorWithReachability`
method on `OspfLsdb`. The Python `_ffi.py` cdef declares the new
symbol; the Python wrapper generator
(`scripts/gen_methods_extras.py`) conservatively skips the symbol
because its `const uint32_t *` + `uintptr_t` signature is too
complex for the safe auto-wrapper, so embedders call
`get_lib().lr_ospf_is_elected_translator_with_reachability(...)`
directly. The `scripts/abi.json` ABI surface catalogue and the
`scripts/abi_coverage.py` audit (C++/Python/Go) are regenerated
and stay green: 1788 / 1788 / 1788 covered, 0 missing.

Tests:

- `crates/lr-ospf/src/nssa_tests.rs` — four new unit tests cover the
  new function directly:
  `translator_election_with_reachability_drops_unreachable_candidate`
  (a higher-ID border router that's excluded from the set is dropped;
  adding it back lets it win again), `translator_election_with_reachability_self_not_in_set_disables_translation`
  (an empty set disables translation, a set with only the local
  router elects the local router), `translator_election_with_reachability_drops_unreachable_nt_bit_candidate`
  (an Nt-bit border router that's excluded from the set is dropped,
  even though the Nt-bit normally wins regardless of ID),
  `translator_election_with_reachability_none_matches_legacy`
  (`None` and the legacy form produce identical results).
- `crates/lr-tests/tests/ospf_stub_nssa.rs` — a new e2e test
  `nssa_translator_election_drops_unreachable_candidate` pins the
  daemon wiring: a topology where X1 (router-id `0x01010101`) is the
  only router reachable through area 0 and X2 (router-id
  `0x05050505`, higher) is in the NSSA's LSDB with the B-bit set
  but NOT in X1's area-0 LSDB. The legacy election would have X2
  win (higher ID); the reachability-aware election drops X2 and
  X1 translates, so the type-5 reaches the backbone through X1.
  The existing `nssa_translator_election_prevents_duplicate_translation`
  test (where both border routers ARE reachable through area 0)
  still passes — the reachability filter is a no-op there.

No public Rust API removal (the legacy `is_elected_translator` is
preserved as a thin wrapper), one new C ABI symbol
(additive — `scripts/abi_freeze_check.py HEAD~1 HEAD` stays green),
no protocol-on-the-wire change, no version bump.

### Source binding + TCP-MD5/AO/GTSM

`crates/lr-cli/src/daemon.rs` previously documented a
`connect_secure` limitation — "Source binding does not yet combine
with TCP auth (connect_auth creates its own socket); that combination
is future work." A peer that configured both `local_address` and
`md5_key` / `tcp_ao_key` / `gtsm` saw the auth-armed SYN depart from
the kernel-chosen source IP rather than the configured one, so a
peer matching inbound by source (`neighbor <ip>`) and the kernel's
per-peer key selection both missed it. The FRR `neighbor A.B.C.D
local-address W.X.Y.Z + password ...` and the BIRD `local W.X.Y.Z +
password ...` shapes had no lr equivalent.

The fix widens the connector surface, not the listener surface:

- `lr_osroute::tcp_auth::connect_auth` gains a fourth argument
  `local: Option<SocketAddr>`. When `Some`, the Linux raw-socket
  connector `bind(2)`s the fd to `local` (port 0 = ephemeral)
  between key installation and `connect(2)` so the SYN carries the
  configured source IP alongside the MAC. The non-Linux stub routes
  the no-auth + `Some(local)` case through `tcp_bind::connect_bound`,
  which already works on every platform the crate compiles for.
- `lr_osroute::gtsm::connect_gtsm` gains the same fourth argument
  with the same semantics: bind after TTL arming so the high
  outbound TTL is already in place when the SYN departs.
- `TcpAuthError::is_addr_not_available()` and
  `GtsmError::is_addr_not_available()` predicate the lab-config
  `192.0.2.x` case (`bind(2)` returns `EADDRNOTAVAIL` because the
  address is not assigned to any interface) so the daemon's
  connector can fall back to the kernel-chosen source by retrying
  without the bind — mirroring the existing `connect_bound` arm.
- `daemon::connect_secure` passes `local` through to both
  connectors and adds the same fallback on
  `is_addr_not_available()`. The no-auth + `local` arm is unchanged;
  the listener side is untouched (the listener's auth keys and
  GTSM min-TTL filter are still armed before any inbound SYN
  arrives).

Tests:

- `crates/lr-osroute/src/tcp_auth_tests.rs` — a new
  `md5_loopback_source_bound_handshake` pins the bind-actually-happened
  contract: an accepted socket's peer address must match the bound
  loopback alias `127.0.0.9`, proving the SYN carried the configured
  source IP alongside the MD5 MAC. Existing call sites updated for
  the new fourth argument.
- `crates/lr-osroute/src/gtsm.rs` — a new
  `single_hop_loopback_connects_bound` mirrors the same contract
  for GTSM. Existing call sites updated.
- `crates/lr-tests/tests/gtsm_max_prefix.rs` — call site updated
  for the new fourth argument.

No public Rust API removal (the new fourth argument is additive:
existing call sites pass `None`), no C ABI change (the daemon's
`connect_secure` is private), no protocol-on-the-wire change, no
version bump. The defects.txt entry this closes is
`crates/lr-cli/src/daemon.rs:L2548-L2549 | INCOMPLETE-IMPL |
"Source binding does not yet combine with TCP auth"`.

### `[bgp.rpki]` cache removal via SIGHUP stops the RTR thread

`crates/lr-cli/src/daemon.rs` previously documented a reload
limitation: "reload: rpki cache removed — RPKI keeps running until a
restart (removing the RTR thread live is not supported)". A SIGHUP
that removed the `[bgp.rpki] cache` block from the live config was
*reported* but not *honoured*: the RTR client thread kept running
against the stale cache address, the RTR-sourced ROAs stayed in the
`RoaStore`, and the import hook kept validating inbound UPDATEs
against the withdrawn-but-still-resident ROAs until the operator
restarted the daemon. The static `[[roa]]` table reload was the
only piece of the RPKI surface that SIGHUP actually re-applied.

The fix adds a `RpkiCommand::Shutdown` variant to the RTR client
thread's control channel and wires the reload path to send it when
the fresh config has no `[bgp.rpki] cache` block:

- `crates/lr-cli/src/daemon_rpki.rs` — `RpkiCommand::Shutdown`
  (with `Reconnect`) and `Control::Stop` (with `Interrupt` /
  `Continue`) carry the new path through the thread. The thread
  latches a `stopped` flag, drops the transport, clears the
  RTR-sourced ROAs from the shared `RoaStore` via
  `RoaStore::clear_rtr` (the static `[[roa]]` layer is untouched),
  resets the client to a cold-start state, and exits the loop.
  `refresh_status` renders `phase=stopped` once latched so the
  runtime API `status` line matches the live state.
  `RpkiHandle::shutdown()` is the control-plane entry point;
  `RpkiHandle::reconnect()` and `RpkiHandle::shutdown()` on a dead
  handle both return the existing "client thread is gone" diagnostic
  (the channel's receiver dies when the thread exits). The
  `read_available` burst loop and `sleep_backoff` retry loop both
  drain the control channel between iterations so a queued
  Shutdown surfaces promptly even mid-burst or mid-backoff.
- `crates/lr-cli/src/daemon.rs` — `reload_config` now calls
  `handle.shutdown()` and reports
  `reload: rpki cache removed — RTR thread stopped, RTR-sourced ROAs
  withdrawn`. The `if let Some(handle) = rpki` block's comment was
  updated to describe the new teardown semantics.

Tests:

- `crates/lr-cli/src/daemon_rpki_tests.rs` — seven new unit tests
  pin the shutdown contract: `drain_control` returns `Control::Stop`
  on `Shutdown`; `handle_shutdown` clears the RTR layer, preserves
  the static layer, drops the transport, clears `last_sync`, resets
  the client, latches `stopped`, and renders `phase=stopped`; the
  burst loop and backoff loop both exit promptly on `Shutdown`;
  repeated `handle_shutdown` calls are idempotent;
  `RpkiHandle::shutdown` enqueues the command and returns the log
  line; `RpkiHandle::shutdown` / `reconnect` on a dead handle both
  return the "thread is gone" diagnostic.
- `crates/lr-cli/tests/daemon_rpki.rs` — a new end-to-end test
  (`rpki_reload_removing_cache_stops_thread_and_withdraws_rtr_roas`)
  spawns a real `lr-daemon` against a mock RTR cache, waits for the
  first sync, rewrites the config to drop the `[bgp.rpki] cache`
  block, sends SIGHUP, and asserts that the runtime API `status`
  line reports `roas=1 (static=1 rtr=0)` and `phase=stopped`, and
  that the daemon log shows no `connected to` line *after* the
  `cache removed via reload` line (the thread is gone, no
  reconnect).

No public Rust API change (the daemon's `RpkiHandle` is
`pub(crate)`), no C ABI change (no `lr_*` symbol touched), no
protocol-on-the-wire change, no version bump. The defects.txt entry
this closes is `crates/lr-cli/src/daemon.rs:L6947-L6951 |
INCOMPLETE-IMPL | "removing the RTR thread live is not supported"`
(`crates/lr-cli/src/daemon_rpki.rs:L65-L79 | INCOMPLETE-IMPL |
"RpkiCommand enum only defines Reconnect variant"` is closed by
the same change — the enum now also carries `Shutdown`).

### OSPF daemon honours `--user` / `--group` (issue #92)

`crates/lr-cli/src/daemon_ospf.rs` previously rejected the
`--user` / `--group` combination outright when `--protocol ospf`
was used, returning exit code 2 before any raw socket work happened:

```
--user/--group are not supported with --protocol ospf yet
(raw sockets are opened before the drop would happen)
```

The OSPFv3 daemon (`crates/lr-cli/src/daemon_ospf3.rs`) had no
early reject, but it also never called `do_privdrop`, so `--user`
was silently accepted and ignored — the daemon kept running as
the invoking user. Both shapes are now closed. Every configured
interface's raw `IPPROTO_OSPF` socket is bound first (in
`resolve_interface`, before the daemon reaches the standalone /
embedded dispatch), so the kernel sees the bind as root (or a
user/network namespace with `CAP_NET_RAW`); the privilege drop then
runs in the standalone arm of the `match &host` block — exactly
mirroring the BGP (`daemon.rs`) and LDP (`daemon_ldp.rs`) standalone
privdrop+spawn sequence.

The fix:

- `crates/lr-cli/src/daemon_ospf.rs` — the early reject that
  returned `ExitCode::from(2)` when `cfg.user.is_some() ||
  cfg.group.is_some()` is removed; a `do_privdrop(cfg)` call is
  inserted in the standalone `None` arm of `match &host`, before
  `spawn_api` / `spawn_metrics` / `spawn_ticker`. The embedded
  `Some(h)` arm is unchanged: the multi-protocol supervisor
  (`daemon_multi.rs`) already calls `do_privdrop(cfg)` before
  releasing each engine's startup gate, so the embedded path
  already dropped privileges correctly — only the standalone path
  was missing the call.
- `crates/lr-cli/src/daemon_ospf3.rs` — same `do_privdrop(cfg)`
  call inserted in the standalone `None` arm. The embedded path
  was already correct via the supervisor; the standalone path
  silently ignored the flag.

The drop is a no-op when `--user` is unset, so unconditional
invocation matches the BGP and LDP shapes — every standalone
engine entry point now calls `do_privdrop(cfg)` even when the
flag is absent, keeping the privileged-work → drop → unprivileged-
work ordering identical across every protocol.

Tests:

- `crates/lr-cli/tests/daemon_ospf_privdrop.rs` — three new
  end-to-end tests spawn the real `lr-daemon` binary:
  `ospf_v2_user_no_longer_rejected_outright` verifies the
  early-reject string is gone and the daemon exits non-zero when
  `--user` names a non-existent user; `ospf_v3_user_no_longer_silently_ignored`
  verifies the v3 daemon now exits non-zero on the same input
  (the pre-fix shape silently kept running as the invoking user);
  `ospf_v2_without_user_still_reaches_socket_bind` guards the
  no-`--user` case against a future regression that makes
  `do_privdrop` non-optional.

No public Rust API change (`run_ospf_daemon` / `run_ospf3_daemon`
are `pub(super)` and unchanged in signature), no C ABI change (no
`lr_*` symbol touched), no protocol-on-the-wire change, no version
bump. The defects.txt entry this closes is
`crates/lr-cli/src/daemon_ospf.rs:L359-L366 | INCOMPLETE-IMPL |
"--user / --group are not supported with --protocol ospf yet
(raw sockets are opened before the drop would happen)"`. The v3
silent-ignore gap had no defects.txt line of its own (the audit
listed only the v2 early-reject); the v3 fix is the same shape
landed in the same commit.

### LDPoIPv6 GTSM receive-side enforcement (RFC 7552 §9)

`crates/lr-cli/src/daemon_ldp.rs` previously armed only the
outbound hop limit (255) on every IPv6 LDP session TCP socket
(listener, accepted sockets, active connectors) but did not arm
the receive-side kernel filter — the listener had no
`IPV6_MINHOPCOUNT = 255` set, so an inbound native IPv6 SYN with a
hop limit below 255 (the kernel default of 64, or any value a
remote attacker's packets would arrive with after routing
decrement) was admitted to the listener's accept queue. The
defects.txt entry characterised this as
`crates/lr-cli/src/daemon_ldp.rs:L698-L700 | INCOMPLETE-IMPL |
"lr does not enforce the receive side (fail-open)" - RFC 7552 §9
GTSM receive side not enforced`. The original
`feat(lr-daemon): LDPoIPv6 GTSM hop limit + FRR dual-stack interop`
commit (`5f07d73`) deliberately kept the receive side fail-open at
the time, matching an FRR deployment without `[no] gtsm`; the
protocol's recommendation (RFC 7552 §9) and FRR ldpd's default
(`nbr_gtsm_enabled` returns true for `AF_INET6`) both expect the
filter to be on, so the gap was a real deficiency rather than a
design choice.

The fix arms the listener with
`lr_osroute::gtsm::arm_listener_gtsm(&listener, &Gtsm::single_hop())`
after `listen(2)`. `arm_listener_gtsm` is the same primitive the
BGP daemon uses on its per-peer listeners; on Linux it sets
`IP_MINTTL` (v4) or `IPV6_MINHOPCOUNT` (v6) on the listener fd, so
the kernel drops any inbound SYN whose TTL/hop limit is below the
configured minimum before the SYN reaches the listener's accept
queue. On the LDP daemon's dual-stack v6 listener (`IPV6_V6ONLY=0`)
the filter applies only to native IPv6 packets — v4-mapped
sessions are routed through the v4 stack and bypass
`IPV6_MINHOPCOUNT`, so they continue to be admitted (RFC 7552 §9
does not mandate GTSM for LDPoIPv4, and the LDP daemon's v4
transport already sends with the default TTL). Accepted sockets
inherit the policy from the listener, so no per-accepted-socket
arming is needed for the receive-side filter; the existing
`set_v6_session_hops` call on accepted sockets stays (it re-arms
the outbound hop limit, which the kernel does not inherit on
`accept(2)`). Active connectors continue to set only the outbound
hop limit via `set_v6_session_hops` — setting `IPV6_MINHOPCOUNT`
on a connector would drop the SYN-ACK from a peer that is more
than one hop away (correct for single-hop GTSM, but lr's LDP
daemon does not yet have a per-peer multihop GTSM knob, so the
connector stays at the no-receive-filter default).

On kernels without `IPV6_MINHOPCOUNT` support (non-Linux targets
where the `lr_osroute::gtsm` fallback returns
`GtsmError::Unsupported`), the daemon logs a warning via
`log_warn!(Component::Ldp, ...)` and continues — the outbound hop
limit 255 is still set, and the receive side stays fail-open (the
historical behaviour). The LDP daemon's module doc and the
`set_v6_session_hops` doc comment are updated to reflect the new
behaviour.

Tests:

- `crates/lr-osroute/src/gtsm.rs` — two new live-socket tests pin
  the v6 receive-side contract: `plain_connect_rejected_by_v6_gtsm_listener`
  arms a v6 listener with `arm_listener_gtsm(&listener, &Gtsm::single_hop())`
  and verifies a plain `TcpStream::connect` (kernel-default hop
  limit 64) is rejected (no `accept` succeeds); `v6_gtsm_listener_accepts_gtsm_connect`
  arms the same listener and verifies `connect_gtsm` with hop
  limit 255 is admitted and the accepted socket round-trips a
  byte. Both are `#[cfg(target_os = "linux")]` (the `IPV6_MINHOPCOUNT`
  filter is Linux-specific) and mirror the existing
  `plain_connect_rejected_by_gtsm_listener` / `single_hop_loopback_connects`
  pair for v4.
- `tests/interop/ldp_v6_gtsm.sh` — a new end-to-end interop script
  that spawns the real `lr-daemon --protocol ldp` in a rootless
  `unshare -Urn` namespace with a non-loopback IPv6 address on
  `lo`, waits for the listener on `[::]:6460`, then asserts (1)
  a plain (default hop-limit 64) IPv6 TCP connect to the daemon's
  listener is rejected (no SYN-ACK is sent; the connect times
  out, and the daemon never logs `accepted connection from`); (2)
  a high-hop-limit (255) IPv6 TCP connect via a GTSM-enforcing
  peer is admitted (the connect succeeds and the daemon logs
  `accepted connection from [fd00:99::1]:...`). Wired into
  `.github/workflows/ci.yml` as
  `LDPoIPv6 GTSM receive-side enforcement (RFC 7552 §9)`.

No public Rust API change (`set_v6_session_hops` is private to
the LDP daemon module; `arm_listener_gtsm` and `Gtsm::single_hop`
are existing public surfaces of `lr-osroute::gtsm`, used here
unchanged), no C ABI change (no `lr_*` symbol touched), no
protocol-on-the-wire change, no version bump.

### `lr-cli`: RTR thread shutdown race on macOS / Windows (issue #92 follow-up)

`crates/lr-cli/src/daemon_rpki.rs`'s `RpkiLoop::run()` loop never
re-checked the latched `stopped` flag at the top of the iteration.
When the SIGHUP-driven `RpkiCommand::Shutdown` was queued while
the RTR thread was inside `read_available()` — the inline
control-drain at the head of the read burst consumed the command
(`handle_shutdown()` latched `stopped = true`, cleared the
transport, returned `false`) — the outer `run()` loop continued
past `drain_control()` (the channel was now empty, so
`drain_control()` returned `Control::Continue`), fell through to
`connect()`, and re-established the transport against the cache
address the operator had just removed from the config. The thread
kept running, the next `status` poll reported `phase=stopped` but
`roas=3 (static=1 rtr=2)` (the RTR-sourced ROAs were re-installed
by the re-sync), and the test
`rpki_reload_removing_cache_stops_thread_and_withdraws_rtr_roas`
timed out waiting for the post-shutdown state.

On Linux the `drain_control()` arm happened to win the race in CI
— the reload command was queued while the thread was idle (between
read bursts), so the loop-head `drain_control()` consumed the
Shutdown first, returned `Control::Stop`, and the loop broke
before `connect()` ran. On macOS / Windows the tighter
read-timeout granularity (the macOS `TcpStream::set_read_timeout`
and the Windows named-pipe transport's overlapped I/O timing)
shifted the race the other way: the inline `read_available()`
drain won, and the bug surfaced.

The fix adds a `self.stopped` check at the top of the `run()` loop
and at the head of the `sleep_backoff()` retry loop. The flag
latches in `handle_shutdown()` and never clears, so a single
check at each entry point is sufficient — the loop breaks before
`connect()` runs, the post-loop `client thread stopping` log line
lands, and the next `status` poll observes `phase=stopped` +
`roas=1 (static=1 rtr=0)` (the static `[[roa]]` layer survives
because `handle_shutdown()` only calls `clear_rtr()`, not
`clear_static()`).

Tests: the existing
`rpki_reload_removing_cache_stops_thread_and_withdraws_rtr_roas`
test (introduced by the previous issue #92 fix that landed the
shutdown path) now passes on macOS / Windows too — the race was
already covered by the test's assertion; the platform difference
was which side of the race the CI runner hit. The Linux CI leg
continues to pass (the fix is a strict superset of the previous
behaviour — the new check only fires when the inline drain won).

Public Rust API change: none (the `RpkiLoop` struct is private to
the `daemon_rpki` module). No C ABI change, no protocol-on-the-wire
change, no version bump.

### `lr-cli`: Windows status test host-tolerant after connected routes (issue #92)

`crates/lr-cli/tests/lrctl_windows.rs`'s
`lrctl_status_round_trips_over_named_pipe` test asserted
`rib-entries 1` against the daemon's `status` reply. The daemon
installs connected routes from the kernel interface enumeration
(`install_connected` — BIRD `protocol direct` / FRR
`redistribute connected` parity, landed earlier in this issue
#92 round), so the Loc-RIB total is `N + 1 + (extra UP
interfaces)`. The GitHub Actions `windows-latest` image carries
several virtual / Hyper-V adapters that contribute `proto=direct`
routes, so the total came out to `3` on that runner and the test
failed with `rib-entries 3` instead of `1`.

The fix mirrors the shape `crates/lr-cli/tests/lrctl.rs` and
`crates/lr-cli/tests/daemon_runtime.rs` already use: assert the
BGP-originated network is present via `show routes count`'s
per-protocol breakdown (`proto=bgp routes=1`) instead of the
exact total. The cross-platform `show routes count` command
exists on every platform the daemon compiles for, so the same
assertion works on Windows as on Linux.

Tests: `lrctl_status_round_trips_over_named_pipe` no longer
depends on the runner's interface inventory. The other Windows
tests in the file (`lrctl_sessions_lists_configured_session`,
`unix_style_socket_path_works_on_windows`) are unaffected.

No public Rust API change, no C ABI change, no version bump.

### `lr-bgp` / `lr-core`: RFC 7313 §3.2 BoRR/EoRR demarcation dispatch (issue #92)

`crates/lr-bgp/src/extensions/enhanced_rr.rs` was a placeholder
module (`#![allow(dead_code)]`, three-line doc-only header) — the
defects.txt entry characterised this as
`crates/lr-bgp/src/extensions/enhanced_rr.rs:L1-L5 | PLACEHOLDER |
"Placeholder for the enhanced_rr extension"; `#![allow(dead_code)]``.
The wire-level pieces lived elsewhere (capability encoding in
`lr-bgp::capabilities::Capability::enhanced_rr`, message subtypes in
`lr-bgp::message::RouteRefreshSubtype`, the FSM send-side methods
`begin_enhanced_route_refresh` / `end_enhanced_route_refresh` in
`lr-bgp::fsm::BgpPeer`), but the high-level orchestration helpers
the placeholder promised were never written. In parallel, the FSM's
receive arm for `BgpMessage::RouteRefresh` dispatched only the
`Normal` subtype (RFC 2918) to `BgpAction::RouteRefreshRequested`;
the `BeginOfRib` (BoRR) and `EndOfRib` (EoRR) demarcation subtypes
(RFC 7313 §3.2) were silently discarded, so an embedder that
negotiated RFC 7313 and relied on the demarcation to coordinate a
route-refresh response saw the markers vanish at the wire boundary.

The fix lands in three pieces:

- **`enhanced_rr.rs` orchestration helpers** — the placeholder
  becomes a real module with `advertised(cfg)`,
  `negotiated(cfg, peer_caps)`, and `open_capability(cfg)`, mirroring
  the shape of `addpath` / `long_lived` so a caller can verify the
  capability posture without constructing a peer. The negotiation
  check requires both the local `enhanced_rr` knob and the base
  `route_refresh` knob (RFC 7313 §1 — enhanced refresh extends
  RFC 2918, so the base capability is the precondition) and a
  peer capability whose value is empty (RFC 7313 §2 mandates an
  empty value; a malformed non-empty value is rejected so a
  malformed OPEN does not turn the demarcation on).
- **`BgpAction::BeginOfRouteRefresh(NlriFamily)`** — new variant
  emitted by the FSM receive arm when a negotiated BoRR is received.
  `Event::BeginOfRouteRefresh { session, family }` is added to
  `lr-core::event::Event` (the enum is `#[non_exhaustive]`); the
  `StateMachine for BgpPeer` trait adapter maps the new action to
  the new event so a trait-only embedder that drives the FSM
  through the generic `StateMachine::step` sees the demarcation
  (previously the adapter mapped it to `Action::None`, masking
  the signal — same shape as the issue #92 fix that surfaced
  `RouteRefreshRequested` / `EndOfRib`).
- **EoRR reuses the existing `BgpAction::EndOfRib`** — RFC 7313
  §3.3 says the EoRR is treated as the End-of-RIB marker (RFC
  4724 §4) for the family, so the same action runs the same helper
  in the router (`on_end_of_rib`): the GR-retention purge for
  the family ends, and stale routes the peer did not refresh are
  removed. The router's dispatch on `BgpAction::BeginOfRouteRefresh`
  logs the demarcation marker so the operator can correlate the
  BoRR with the matching EoRR; the `on_end_of_rib` purge already
  removes any route the peer did not refresh (matching the
  implicit EoR marker shape), so a pre-mark step would only be
  useful for an embedder that wants live visibility into "this
  route is being refreshed" (a follow-up could add a
  `RouteRefreshing` flag to the session stats; not needed for
  correctness).

Both demarcation subtypes are gated by
`enhanced_route_refresh_negotiated()` — a peer that sends a BoRR
or EoRR without negotiating the capability is silently ignored
per RFC 7313 §3.2 ("an implementation that does not recognise a
subtype must silently ignore the message"). The `Normal` subtype
(RFC 2918) continues to dispatch through the existing
`BgpAction::RouteRefreshRequested` path; a session that did not
negotiate the Enhanced Route Refresh capability still surfaces
Normal route-refresh requests exactly as before.

Tests:

- `crates/lr-bgp/src/extensions/enhanced_rr.rs` — eight new unit
  tests pin the helper contract: `advertised_tracks_knob`,
  `open_capability_off_when_knob_off`,
  `open_capability_on_when_knob_on`,
  `negotiated_requires_local_knob_and_peer_cap`,
  `negotiated_requires_peer_cap`,
  `negotiated_when_both_sides_advertise`,
  `negotiated_rejects_malformed_capability`,
  `negotiated_requires_base_route_refresh_too`.
- `crates/lr-bgp/src/fsm_tests.rs` — five new tests pin the FSM
  receive-side dispatch:
  `enhanced_route_refresh_borr_emits_action_when_negotiated`,
  `enhanced_route_refresh_eorr_emits_end_of_rib_action_when_negotiated`,
  `enhanced_route_refresh_demarcation_silently_ignored_when_not_negotiated`,
  `trait_adapter_surfaces_begin_of_route_refresh`,
  `trait_adapter_surfaces_eorr_as_end_of_rib`, and
  `route_refresh_normal_subtype_still_dispatched_without_enhanced_rr`
  (a regression guard: the receive-side fix must not regress the
  RFC 2918 base capability path).

Public Rust API change (additive): one new
`BgpAction::BeginOfRouteRefresh(NlriFamily)` variant, one new
`Event::BeginOfRouteRefresh { session, family }` variant
(`#[non_exhaustive]` so the additions are not breaking); the
`enhanced_rr` module gains three new pub functions
(`advertised`, `negotiated`, `open_capability`). No C ABI change
(no `lr_*` symbol touched; `BgpAction` and `Event` are not exposed
through the C ABI), no protocol-on-the-wire change (the BoRR/EoRR
wire format is unchanged — the FSM already produced and parsed the
demarcation subtypes before this change), no version bump.

### `lr-cli`: SIGHUP re-opens the log file destination (issue #92)

`crates/lr-cli/src/daemon_logger.rs:L272 | FUTURE-WORK | "The file
is opened append-only and never re-opened, so a log rotation tool
must signal the daemon to reopen (future work) - log rotation
unsupported"` — the daemon's file destination was opened once at
startup and never re-opened, so the standard `logrotate` postrotate
contract did not work: the operator's `logrotate` config would move
the live log file aside (the daemon still held the old fd and kept
writing to the rotated inode), and the new file at the original
path stayed empty until the daemon was restarted.

The fix lands in three pieces:

- **`daemon_logger::reopen_log_file()`** — a new public-crate
  helper that re-opens the file destination at the path the live
  `LogConfig` carries, leaving the rest of the configuration
  (severity, format, color, per-component overrides) untouched.
  The old fd is dropped (Rust closes the `File` on drop), so the
  kernel sees the rotation tool's rename + create the way it
  expects: the next record lands in the freshly-created file.
  `Ok(())` is returned when the file was re-opened or when no
  file destination is configured (a no-file config is a clean
  no-op). `Err(message)` keeps the existing fd in place so the
  daemon keeps logging to the old file the rotation tool left
  behind; the caller surfaces the error in its reload report.
- **`reload_config` re-applies the `[logging]` block** — the
  BGP / Babel / multi-protocol daemons' SIGHUP-driven
  `reload_config` re-finalises the fresh `[logging]` block and
  re-calls `init_logger` with it. When the fresh config has a
  `[logging] file` set, the path can change too (an operator who
  edits the file path on SIGHUP sees the new path take effect).
  When the fresh config has no `[logging]` block (the operator
  passed `--log-file` on the command line at startup, and the
  config file does not re-set it), the reload falls back to
  `reopen_log_file()` so the startup `--log-file` path is
  re-opened instead of being closed by an `init_logger` call
  with `file: None`. The reload report carries
  `reload: log destination re-opened (SIGHUP)` on success and
  `reload: log destination rejected (...) — keeping current file`
  on failure.
- **OSPF / OSPFv3 / LDP / BMP standalone daemons re-open the
  file via the no-op reload closure** — these daemons do not
  re-parse the config on SIGHUP (the full reload is a no-op for
  OSPF interface set changes, LDP session table, etc.). The
  reload closure now calls `daemon_logger::reopen_log_file()`
  so the operator's `logrotate` postrotate SIGHUP re-opens the
  file the daemon was started with. The reload report carries
  `<proto>: log file re-opened (SIGHUP)` on success and
  `<proto>: log file reopen failed: ...` on failure.

Test coverage: four new unit tests in
`crates/lr-cli/src/daemon_logger.rs` (`init_logger_replacement_reopens_file_destination`,
`reopen_log_file_drops_old_fd_and_opens_a_fresh_one`,
`reopen_log_file_returns_ok_when_no_file_configured`,
`reopen_log_file_returns_err_when_path_is_unopenable`) plus a
new end-to-end test in
`crates/lr-cli/tests/daemon_runtime.rs`
(`sighup_reopens_log_file_for_rotation`) that spawns the real
`lr-daemon` binary with `--log-file`, simulates `logrotate`
(rename + SIGHUP), and verifies the next log line lands in the
re-opened path (and not in the rotated file).

`docs/lr-daemon.md` and `docs/RUNBOOK.md` SIGHUP reload tables
now list the log file reopen behaviour. No public Rust API
change, no C ABI change, no protocol-on-the-wire change, no
version bump.

### `lr-cli`: LDP daemon SIGHUP re-applies `[[ldp.bind]]` (issue #92)

`crates/lr-cli/src/daemon_ldp.rs:L507-L509 | INCOMPLETE-IMPL | LDP
reload returns `vec!["ldp: configuration reload is not supported
yet; shutdown still works".to_string()]`; SIGHUP is a no-op for
LDP` — the LDP daemon's SIGHUP-driven reload was a no-op (only the
log file was re-opened, mirroring the OSPF / BMP daemons). The
operator had to restart the daemon to change `[[ldp.bind]]` entries
even though `[[ldp.bind]]` is the most-frequently-edited LDP table
(a label change, a new FEC, or a removed FEC all flow through it).

The fix lands in three pieces:

- **`daemon_ldp::RebindOp`** — a small enum carrying one
  FEC-label-pair operation (`Advertise { prefix, label }` or
  `Withdraw { prefix, label }`) the SIGHUP closure queues for the
  main loop to apply. The closure runs synchronously inside
  `dispatch_signals` (on the same thread as `pump`), but the
  engine is exclusively borrowed by `pump` for the iteration's
  duration, so the closure cannot call `engine.advertise_mapping`
  directly. The queue bridges the two: the closure pushes ops,
  `pump` drains them at the top of the next iteration, before any
  packet pump iteration processes them.
- **`daemon_ldp::compute_rebind_diff` + `parse_ldp_binds`** —
  pure functions that compute the diff between two `BTreeMap<Prefix,
  GenericLabel>` sets and parse a `DaemonConfig`'s `[[ldp.bind]]`
  table into that shape. The diff ordering matches RFC 5036
  §3.5.7: all withdraws come before all advertises so a label
  change for an existing FEC reaches the engine as a withdraw of
  the old label followed by an advertise of the new one (a receiver
  that updates its received-bindings table on the advertise alone
  would lose the half-of-the-table keyed by the old label).
- **`daemon_ldp::reload_ldp_binds`** — the new reload closure
  body. Re-parses the config file (the same `load_config_file`
  startup uses, so a BIRD / FRR / TOML-loaded daemon re-parses
  through the same dialect path), finalizes it (which validates
  the `[[ldp.bind]]` prefixes and label range), computes the diff
  against the live `current_binds` set, pushes one `RebindOp` per
  change onto `pending_rebinds`, and updates `current_binds` to
  the new target so a second SIGHUP arriving before the pump
  drains computes its diff against the already-targeted state. A
  parse or finalize failure aborts the reload (the operator's
  existing config keeps running) and surfaces in the daemon log
  and the API `reload` reply. The log file reopen still runs
  unconditionally so the operator's `logrotate` postrotate SIGHUP
  works on the LDP daemon.

The session table, transit bookkeeping and interface set are out
of scope for this slice — those need a real diff/apply pass (a
session-up handler has to re-evaluate the targeted-peer list
against the new config, etc.) and are tracked as a separate
follow-up. The `[[ldp.bind]]` slice is the operator's
highest-frequency reload.

`LdpDaemon::drain_rebinds` applies each `RebindOp` against the
engine, the kernel MPLS mirror (Linux only — `install_tail` /
`uninstall_tail` for the pop routes that deliver locally-bound
labels) and the live `binds` map atomically (a failure in one
leaves the engine state advanced but the kernel mirror behind,
which is the same shape as the startup path). The drainer runs at
the top of every pump iteration so a SIGHUP that lands between
two iterations applies atomically on the next; a session that
comes up in `handle_events` below sees the new binds, not the
stale ones.

15 new unit tests in `crates/lr-cli/src/daemon_ldp_tests.rs`
exercise the diff + queue + log-line shape end-to-end:
`compute_rebind_diff_*` (5 tests for the pure diff contract —
empty, identical, add, remove, label-change, mixed),
`parse_ldp_binds_*` (4 tests — empty, explicit labels, skip
None prefix, reject bad prefix), `reload_ldp_binds_*` (6 tests —
no path, missing file, same config (zero ops), adds new bind,
label change + remove).

`docs/lr-daemon.md` and `docs/RUNBOOK.md` SIGHUP reload tables
now list the LDP `[[ldp.bind]]` re-apply behaviour. No public Rust
API change, no C ABI change, no protocol-on-the-wire change, no
version bump.

### `lr-bgp`: RFC 4724 Graceful Restart orchestration helpers (issue #92)

`crates/lr-bgp/src/extensions/graceful_restart.rs:L1-L20 | PLACEHOLDER |
Module only contains doc tables; all implementation lives in
lr-router; `#![allow(dead_code)]` — gap with RFC 4724 §4.2
description` — the `graceful_restart` extension module held only
a doc table; the actual GR capability construction and the peer's
restart-time / R-bit reads were inlined in the FSM
(`crates/lr-bgp/src/fsm.rs`) at every call site. The
`advertised_families` helper existed in the LLGR module
(`crates/lr-bgp/src/extensions/long_lived.rs`) even though its
doc said "Families a restart-related capability (RFC 4724 §3 GR,
RFC 9494 §3.1 LLGR) should list" — shared between the two
extensions, but hosted on the wrong side of the layering.

The module now exposes the same `advertised` / `peer_offered` /
`negotiated` / `open_capability` triple the other extension
modules already use (`asn4`, `enhanced_rr`, `long_lived`), plus
two GR-specific readers:

- `advertised(cfg)` — whether the local config opts the session
  into the RFC 4724 capability (mirror of `enhanced_rr::advertised`
  / `asn4::advertised`).
- `advertised_families(cfg)` — the address-family list to put in
  the capability. Moved from `long_lived` to `graceful_restart` so
  the GR module owns the shared computation; `long_lived` re-exports
  it via `pub use crate::extensions::graceful_restart::advertised_families`
  so existing callers (the FSM, the LLGR tests) keep working
  without rewriting their imports.
- `peer_offered(peer_caps)` — whether the peer advertised the
  capability in its OPEN (mirror of `asn4::peer_offered_as4`).
- `peer_restart_time(peer_caps)` — the peer's advertised Restart
  Time (RFC 4724 §3) in seconds; returns `None` when the peer did
  not advertise the capability or its value is malformed (length < 2).
  Uses `find_map` so a later malformed duplicate does not
  invalidate an earlier well-formed value (mirrors `asn4::peer_as4`'s
  RFC 6793 §4 first-occurrence rule).
- `peer_restart_state(peer_caps)` — whether the peer's R bit
  (Restart State, §3) is set, so the local helper-of-record knows
  the peer has just restarted its control plane and is in the
  process of restoring its routes (§4.2 step 2).
- `negotiated(cfg, peer_caps)` — whether both speakers advertised
  the capability, so the helper-of-record retention policy (§4.2)
  applies.
- `open_capability(cfg)` — the capability to put in the OPEN, or
  `None` when the knob is off. The R bit is left clear (the local
  speaker is not in the restart state on a fresh OPEN); a restarting
  speaker that needs to set the R bit can post-process the returned
  capability. The F bit per family is set: the library keeps
  Adj-RIB-In across reconnects within the same process.

The FSM's OPEN builder now calls
`crate::extensions::graceful_restart::open_capability(&self.cfg)`
instead of inlining the family-list walk + `Capability::graceful_restart`
construction. `BgpPeer::negotiated_graceful_restart_time` now delegates
the local-knob + peer-capability check to `negotiated` and the
peer-time decode to `peer_restart_time`. `BgpPeer::llgr_negotiated`
now uses `peer_offered` for the GR-half of the negotiation
(the LLGR-half stays inline — adding a `long_lived::peer_offered`
helper is the same low-cost follow-up that landed for asn4 /
enhanced_rr, and is left to a follow-up to keep this slice
focused on the GR module).

The `#![allow(dead_code)]` is removed from both
`crates/lr-bgp/src/extensions/graceful_restart.rs` (the module
now carries real implementations) and
`crates/lr-bgp/src/extensions/long_lived.rs` (the
`advertised_families` move + `pub use` re-export keeps the
`long_lived::advertised_families` call site working, and the
module's `open_capability` / `FLAG_FORWARDING` items were already
referenced from the FSM — the `allow` was stale).

23 new unit tests in `crates/lr-bgp/src/extensions/graceful_restart.rs`
(`advertised_tracks_knob`, `open_capability_*` (5 tests for the
OPEN builder — off when knob off, on when knob on, implicit IPv4
family, MP families listed, FRR `no bgp default ipv4-unicast`
excludes / explicit IPv4 kept), `peer_offered_*` (3 tests — when
present, absent, malformed), `peer_restart_time_*` (5 tests —
none when absent, value when present, none when malformed,
first-occurrence on duplicate, skips unrelated capabilities),
`peer_restart_state_*` (3 tests — clear on fresh OPEN, set when
peer signalled restart, false when absent / malformed),
`negotiated_*` (4 tests — requires local knob, requires peer cap,
when both sides advertise, when peer cap is malformed). They
mirror the `asn4` and `enhanced_rr` test layout one-for-one so a
future contributor scanning the extensions directory can read
the three modules with the same expectations.

The existing `lr-bgp` test suite (the LLGR negotiation tests at
`crates/lr-bgp/src/fsm_tests.rs:L882-1009` and the per-extension
`long_lived::tests::*` at
`crates/lr-bgp/src/extensions/long_lived.rs:64-110`) continues
to pass — the refactor preserves the negotiation posture (the
`peer_offered` check counts a malformed capability as "offered"
so the retention policy still applies; the time / R-bit reads
validate the value separately and return `None` / `false` when
malformed).

No public Rust API shape change beyond the new
`lr_bgp::extensions::graceful_restart` items; no C ABI change
(the new functions are pure-Rust helpers, not `extern "C"`); no
protocol-on-the-wire change; no version bump.

### `lr-cli`: BFD daemon `log_debug!`/`log_trace!` migration (issue #92)

`crates/lr-cli/src/daemon.rs:L109-L135 | TODO | log_debug! /
log_trace! macros annotated #[allow(unused_macros)]; comment:
"Several daemon submodules do not yet route their verbose output
through it; the migration can land one submodule at a time"` —
the `log_debug!` and `log_trace!` macros were defined in
`daemon.rs` and gated by `#[allow(unused_macros)]` because no
submodule used them at definition time. The migration has since
started: `daemon.rs` itself at the `peer {label}: reconnecting`
debug line, `daemon_ospf.rs` at the `dbg-drop demux` / `dbg-send`
debug lines, `daemon_ospf3.rs` at the same patterns. The
`#[allow(unused_macros)]` on `log_debug!` was therefore stale.
`log_trace!` was still genuinely unused — keeping the
`#[allow(unused_macros)]` was technically correct but the
migration-status comment did not explain the asymmetry.

This round closes the gap by migrating `daemon_bfd.rs` to use
both macros for per-packet trace, then dropping the stale
annotations and refreshing the migration-status comment.

What landed:

- `daemon_bfd.rs`'s supervisor receive path now emits one
  `log_trace!` per received datagram (gated by the new
  `bfd_debug_enabled()` cached env-var check `LR_BFD_DEBUG`,
  mirroring `daemon_ospf::ospf_debug_enabled`) and one
  `log_debug!` per drop (short BFD datagram < 12 bytes, or
  unmatched discriminator / source address). The records flow
  through `log_record` and are subject to the per-component
  severity filter (`--log-target bfd=debug` / `=trace`) — the
  env var is the cheap per-packet pre-check, the severity
  filter is the real gate. The BFD supervisor polls at the
  10 ms `POLL_MS` cadence and may drain multiple datagrams per
  iteration, so the cached env-var check keeps the per-packet
  overhead off the hot path when trace is not requested.
- `daemon.rs`'s `log_debug!` and `log_trace!` macro
  definitions drop the stale `#[allow(unused_macros)]`
  annotations now that both macros are exercised (`log_debug!`
  by `daemon.rs`, `daemon_ospf.rs`, `daemon_ospf3.rs` and
  `daemon_bfd.rs`; `log_trace!` by `daemon_bfd.rs`). The
  migration-status comment is updated to reflect the actual
  state: `daemon_bfd`, `daemon_ospf` and `daemon_ospf3` route
  per-packet verbose output through the macros; the remaining
  submodules use only `log_info!` / `log_warn!` / `log_error!`
  for operator-facing diagnostics and have no debug surface
  to migrate.

The BFD e2e test (`bfd_fast_fail_beats_hold_time` in
`crates/lr-cli/tests/daemon_bfd.rs`) continues to pass: the
new log calls are gated by the env var (off by default) and
by the per-component severity (default `Info`), so the test's
log scan for `Up -> Down` and `session ended: bfd session
down` is unaffected.

No public Rust API shape change beyond the new private
`bfd_debug_enabled()` helper in `daemon_bfd.rs`; no C ABI
change; no protocol-on-the-wire change; no version bump.

### `lr-cli`: drop dead Windows `ConnDeps.socket_path` field (issue #92)

`crates/lr-cli/src/api_imp_windows.rs:L384-L385 | DEAD-CODE |
socket_path field never read on Windows; annotated
#[allow(dead_code)]` — the Windows runtime-API server's
`ConnDeps` struct carried a `socket_path: Option<&'a str>` field
that was set on every connection (`socket_path: Some(&path_owned)`)
but never read on Windows. The field existed "for structural parity
with the Unix side's `ConnDeps`", but the Unix side reads it during
the `shutdown` command to `std::fs::remove_file(path)` the Unix
socket file; the Windows side has no equivalent cleanup (Windows
named pipes are kernel-namespace objects that vanish when the last
handle closes — there is no socket file to remove). The field was
therefore dead, and the `#[allow(dead_code)]` annotation was the
only thing keeping it from tripping the workspace
`cargo clippy --workspace --all-targets --all-features -- -D warnings`
gate.

This round removes the field altogether, plus the `path_owned`
local that was constructed solely to populate it. The Windows
`ConnDeps` docstring now explicitly notes the asymmetry: it
mirrors the Unix side minus the `socket_path` field, and explains
why (named-pipe semantics obviate socket-file cleanup).

The Windows build (`cargo check -p lr-cli --target
x86_64-pc-windows-gnu --all-features` and `cargo clippy -p lr-cli
--target x86_64-pc-windows-gnu --all-targets --all-features --
-D warnings`) is clean; the Linux lr-cli test suite (717 tests)
and the lr-ffi test suite (1103 tests) are unchanged.

No public Rust API shape change (the `ConnDeps` is `pub(crate)`);
no C ABI change; no protocol-on-the-wire change; no version bump.

### `docs/PARITY.md`: correct FRR RPKI command surface (issue #92)

`docs/PARITY.md:L240-L241 | DOC-MISMATCH | "Filter access" row FRR
column says extcommunity rt ...` (the defects.txt wording) — the
ROA-prefix-origin validation table (PARITY.md §11) listed three
FRR commands that do not exist in any FRRouting release:

- `bgp rpki on` — there is no such BGP-router-level command. RPKI
  in FRR is loaded by running `bgpd` with the `-M rpki` module
  argument (the daemon then connects to the configured `rpki
  cache` servers), and validated state is consulted automatically
  during BGP import; there is no per-protocol "on" toggle.
- `bgp rpki invalid reject` — there is no such command. Per-neighbor
  strict rejection is `neighbor PEER rpki strict` (the session
  refuses to establish when the cache is unreachable); per-route
  invalid handling is a `route-map NAME in` clause that contains a
  `match rpki invalid` line followed by a deny action.
- `bgp rpki invalid-only` — there is no such command. The
  route-map match is `match rpki notfound|invalid|valid`
  (`frr/doc/user/rpki.rst`), not a `bgp rpki …` directive.

The BIRD column's `rpki reload` was also imprecise: BIRD's
per-protocol reload command is `reload in <bgp_proto>` (the BIRD
client command), and `rpki reload` is not a BIRD client command
on its own. The BIRD configuration surface for an RPKI cache is a
`protocol rpki { ... }` block, not "an RPKI session" — the table
now names the block.

What landed (one commit on `main`):

- `docs/PARITY.md` §11 ROA table's FRR column now cites the
  real FRR 10 surface (verified against `frr/doc/user/rpki.rst`
  at the project's tracked 10.x reference):
  - ROA source — `rpki cache tcp HOST PORT` in `rpki` config mode.
  - Validation trigger — load `-M rpki` module; ROA lookup is
    automatic on session establishment (no explicit "on" command).
  - Invalid action — `neighbor PEER rpki strict` (drops invalid
    routes) plus a `match rpki invalid` route-map deny clause.
  - Filter access — `match rpki invalid` inside a `route-map NAME`.
  - The BIRD column's validation trigger now reads
    `reload in <bgp_proto>` (the actual BIRD client command that
    revalidates a BGP protocol's routes against the ROA table), and
    the ROA source now names `protocol rpki` block (BIRD's
    configuration shape) instead of the unqualified "RPKI session".
  - The BIRD filter-access cell now lists the three concrete
    return values of `roa_check(table)` (`ROA_VALID` / `ROA_INVALID` /
    `ROA_UNKNOWN`) so an operator porting a BIRD filter to lr's
    `roa.state == "invalid"` sees the exact mapping.

No code change; no Rust API change; no C ABI change; no
protocol-on-the-wire change; no version bump. The `tests/lint_docs.sh`
and `tests/lint_interop_doc.sh` doc-lint jobs stay green.

### `lr-cli`: OSPFv2 auth CLI surface — `--help` advertises the
flags + `[ospf.auth]` / `ospf_auth` blocks round-trip (issue #92)

The OSPFv2 authentication wiring landed in commits `47a330e`
(SimplePassword) and `52086d7` (CryptoAuth): the daemon signs every
outgoing packet and verifies every received packet against the
configured strategy (RFC 2328 §D — NullAuth, SimplePassword,
CryptoAuth). The CLI surface, however, was incomplete in three
operator-visible ways this round closes:

1. **`--help` did not advertise the `--ospf-auth-type` /
   `--ospf-auth-password` / `--ospf-auth-key` /
   `--ospf-auth-key-id` / `--ospf-auth-algorithm` flags** (or
   their `--ospf-authentication-*` aliases). The parser accepted
   them, but an operator scanning `--help` had no way to discover
   them without reading the docs — the previous `print_usage()`
   output jumped straight from `--ospf-rxmt-interval` to
   `--ldp-transport`, hiding the entire auth cluster. The new
   `--help` text documents every flag and its alias, names the
   RFC 2328 §D / RFC 5709 references, and surfaces the
   fail-closed rules (which key is required for which strategy).

2. **A single-section `[ospf.auth]` header in a TOML config
   produced a spurious `unknown section [ospf.auth] (ignored)`
   warning at parse time**, even though the keys inside the
   section parsed correctly. The previous shape of
   `parse_toml_subset`'s section-header allowlist did not include
   `ospf.auth`, so a clean config check emitted a warning the
   operator read as "the auth block was silently dropped" — even
   though the daemon would actually honour the auth strategy at
   startup. `ospf.auth` is now on the allowlist, so a clean
   config check reports `warnings: 0`.

3. **`config check` skipped the auth fail-closed validation
   entirely when no other OSPF table was present**, so a typo
   like `[ospf.auth] type = "simple"` without a `password`
   silently passed `config check` (the daemon would still fail
   at startup, but the operator's first signal was a startup
   failure rather than a `config check` rejection). The
   `finalize_ospf` "is the OSPF section populated" predicate
   now counts an explicit `OspfAuthSpec` (any field set) as
   OSPF config, so the auth fail-closed validation runs at
   config-check time too — the missing-`password`,
   missing-`key`, missing-`key_id`, unknown-`type` and
   unknown-`algorithm` rejections all surface in
   `lr-daemon config check` output.

The native `.lr` DSL frontend was missing the auth block
entirely: `ospf_auth { ... }` was rejected as an unknown
top-level block. The DSL parser now dispatches `("", "ospf_auth")`
to the same `ospf.auth` `apply_config_key` arm the TOML frontend
uses, so a config that came in through either path lands on the
same typed `OspfAuthSpec` IR. The DSL emitter (`config to-dsl`)
mirrors the parser: a TOML config carrying `[ospf.auth]`
converts to an `.lr` program with the equivalent
`ospf_auth { ... }` block (the round-trip is idempotent — a
TOML config converted to DSL and re-loaded as DSL produces the
same `OspfAuthSpec`).

`templates/daemon.lr` and `templates/daemon.toml` were updated:
the previous templates said "md5 (crypto auth) is rejected with a
clear 'not wired' message — the next slice" (the SimplePassword
round's follow-up note); the new templates show both the
SimplePassword and CryptoAuth shapes, the CLI mirror flags, and
the RFC 2328 §D / RFC 5709 references (the `shipped_templates_match_across_frontends`
unit test still passes — both templates parse to the same IR).

13 new end-to-end integration tests in
`crates/lr-cli/tests/daemon_ospf_auth.rs` exercise the operator-
visible surface through the real `lr-daemon` binary (no socket
work, no root required):

- `help_advertises_ospf_auth_flags` — every flag and every alias
  on the `--help` output.
- `config_check_toml_ospf_auth_simple_no_warning` and
  `config_check_toml_ospf_auth_crypto_no_warning` — a clean TOML
  config check produces zero warnings.
- `config_check_dsl_ospf_auth_simple_block_parses` and
  `config_check_dsl_ospf_auth_crypto_block_parses` — the DSL
  `ospf_auth { ... }` block parses cleanly.
- `config_check_rejects_simple_without_password`,
  `config_check_rejects_crypto_without_key`,
  `config_check_rejects_crypto_without_key_id`,
  `config_check_rejects_unknown_auth_type`,
  `config_check_rejects_unknown_auth_algorithm` — the
  fail-closed rules fire at `config check` time, not at startup.
- `config_to_dsl_round_trips_ospf_auth_simple`,
  `config_to_dsl_round_trips_ospf_auth_crypto` and
  `config_to_dsl_round_trip_idempotent` — the TOML→DSL
  conversion preserves the auth block, and the round-trip is
  idempotent.

No public Rust API change, no C ABI change, no protocol-on-the-
wire change; no version bump. The unit tests in
`daemon_ospf_tests.rs` (the apply/verify codec round-trip and
the TOML parse coverage) still pass — this round adds the e2e
surface on top of them.

### `lr-cli`: stale static/connected redistribute docstrings (issue #92)

The implementation rounds `557c61c` (accept `static` and `connected`
as `[[redistribute]]` sources), `0740f9c` (enumerate kernel
interfaces and install connected routes), `4dfa744` (FRR
`aggregate-address` `summary-only` / `as-set` translation onto the
`[[aggregate]]` row's `summary_only` / `as_set` keys) and `2f7d5b2`
(FRR `redistribute … route-map NAME` translation onto the pipe's
`allow` list) landed BIRD/FRR parity for these surfaces and updated
the top-level docstrings of the affected types (`RedistributeSpec`
in `daemon_config.rs`, `ConfigOut::aggregates` in `translate.rs`).
Five inline docstrings inside the same files and two paragraphs in
the operator-facing docs were not updated and still claimed the
older, pre-implementation state — a DOC-MISMATCH that contradicted
the in-file tests
(`frr_redistribute_connected_maps_to_connected_source`,
`frr_redistribute_static_maps_to_static_source`,
`redistribute_finalize_accepts_static_source`,
`redistribute_finalize_accepts_connected_source`,
`redistribute_finalize_accepts_direct_alias_for_connected`,
`frr_aggregate_address_summary_only_carries_through`,
`frr_redistribute_route_map_translates_to_allow_list`).

The five inline docstrings now match the implementation:

- the module doc and the `ConfigOut::redistributes` field doc in
  `crates/lr-cli/src/translate.rs` now name
  `bgp`/`ospf`/`ospf3`/`babel`/`static`/`connected` as the mapped
  source vocabulary (with `static`/`connected` riding
  `install_static`/`install_connected`, BIRD `redistribute static`
  / `redistribute direct` and FRR `redistribute static` /
  `redistribute connected` parity), and `kernel`/`rip`/`isis` as
  the unmapped remainder;
- the inline comment at the `redistribute` dispatch arm and the
  `apply_frr_redistribute` function doc carry the same correction;
- the `finalize_redistribution` doc bullet in
  `crates/lr-cli/src/daemon_config.rs` now lists the accepted
  source vocabulary and notes that `static` rides `install_static`
  and `connected` rides `install_connected`.

The two markdown docs now match the implementation:

- `docs/ROADMAP.md`'s FRR `address-family` paragraph no longer
  claims `summary-only`/`as-set` carry unmapped notes (only
  `route-map NAME` does), no longer claims `connected`/`static`
  carry unmapped notes (only `kernel`/`rip`/`isis` do), and no
  longer claims the per-pipe filter hook is missing (the converter
  populates the pipe's `allow` list from a pure prefix-list allow;
  richer shapes carry an unmapped note);
- `docs/COMPAT.md`'s `aggregate-address` and `redistribute` rows
  carry the same corrections in table form.

The released `[1.4.0]` section's "FRR address-family state" entry
that originally described the pre-implementation state is left
unchanged — released CHANGELOG sections are immutable historical
records, and the correction lands under `[Unreleased]` instead.

No public Rust API change (the docstrings describe the existing
surface), no C ABI change (no `lr_*` symbol touched), no
protocol-on-the-wire change, no version bump.

**`lr-ospf` unified OSPFv3 self-origination entry point**
(`ospf`, issue #92). `defects.txt` flagged
`crates/lr-ospf/src/origination.rs` as `INCOMPLETE-IMPL`:
"Only v2 router-LSA + v2 packet checksum finalize; v3 origination
scattered across `lsa/v3.rs` and `lsa/e_v3.rs`; no unified
`origination_v3` module entry". The `finalize_v3_packet` /
`finalize_v3_stream` / `v3_packet_checksum_ok` helpers (RFC 5340
§3.3 packet checksum) had landed in `origination.rs` under a
previous round, but the v3 LSA origination surface stayed
scattered across three sibling modules with no single `lr_ospf::*`
path an embedder could grep:

- the fixed-format RFC 5340 LSAs lived in `lr_ospf::lsa::v3`
  (Router-LSA, Router-LSA fragment, Network-LSA, Link-LSA,
  Intra-Area-Prefix-LSA, Inter-Area-Router-LSA, AS-External-LSA,
  Type-7 NSSA-LSA);
- the TLV-bodied RFC 8362 Extended LSAs lived in `lr_ospf::lsa::e_v3`
  (E-Router-LSA, E-Router-LSA fragment, E-Network-LSA, E-Link-LSA,
  E-Intra-Area-Prefix-LSA, E-Inter-Area-Prefix-LSA,
  E-Inter-Area-Router-LSA, E-AS-External-LSA);
- the v3 type-3 summary-LSA equivalent lived in
  `lr_ospf::abr::originate_v3_inter_area_prefix_lsa` (the ABR owns
  the LS-ID-to-prefix mapping, so the helper lives in `abr` rather
  than `lsa`).

`origination.rs` now re-exports every public v3 origination helper
through `pub use`, so an embedder building an OSPFv3 speaker has one
module to grep — `lr_ospf::origination::originate_v3_*` mirrors the
v2 origination helpers (`originate_router_lsa`,
`originate_network_lsa`) already in this module. The re-exports
are name aliases; they do not change behaviour. A call through the
unified path produces the same LSA as a call through the original
module path — `v3_origination_re_exports_alias_the_originals` in
`origination_v3_tests.rs` anchors that contract with one assertion
per source module (`crate::lsa::v3::originate_v3_router_lsa`,
`crate::lsa::e_v3::originate_v3_e_router_lsa`,
`crate::abr::originate_v3_inter_area_prefix_lsa`). The module doc
now describes both halves (v2 and v3) of the self-origination
surface and cross-references the three source modules so the next
reader does not have to grep for them.

Additive only. The re-exports are new public names on an existing
public function; the original module paths
(`lr_ospf::lsa::v3::originate_v3_router_lsa`,
`lr_ospf::lsa::e_v3::originate_v3_e_router_lsa`,
`lr_ospf::abr::originate_v3_inter_area_prefix_lsa`) still work
unchanged, so an embedder that already imports through those paths
does not need to switch. No public Rust API signature changes
(the re-exported functions keep their original signatures), no
C ABI change (no `lr_*` symbol touched, no FFI surface change),
no protocol-on-the-wire change, no version bump.

### BGP-LS Instance-ID configuration (RFC 9552 §3.2) — issue #92

The BGP-LS NLRI `identifier` field is the RFC 9552 §3.2 *BGP-LS
Instance Identifier* — an 8-octet opaque value that names the *IGP
routing domain* the NLRI belongs to (per-IGP-instance, not per-area
or per-NLRI). Every NLRI from one IGP instance shares the same
value; NLRIs from different IGP domains carry distinct values so a
BGP-LS consumer can segregate a multi-domain topology without
consulting the Node Descriptor sub-TLVs. RFC 9552 §3.2 recommends
`0` for the single-instance case, which the project default keeps.

The previous implementation hardcoded `0` for every emitted NLRI
(the OSPF LSDB projection's 17 emit sites across Node, Link, IPv4
Prefix, IPv6 Prefix and SRv6 SID NLRI variants, plus the EPE
projection's per-session emit site) and left a comment naming "a
per-area monotonic counter to disambiguate re-advertisements" as a
future value. The comment misread the field's purpose — RFC 9552
§3.2 fixes the semantics as per-IGP-instance, and re-advertisement
disambiguation is the BGP-LS Attribute's job (metric / attribute
changes), not the NLRI Identifier's.

The fix threads the daemon's configured Instance-ID through the
projection:

- `OspfAreaBgplsContext` (the per-area projection context) gains
  an `instance_id: u64` field; every emitted NLRI's `identifier`
  reads `ctx.instance_id` instead of the hardcoded 0.
- `EpePeerSession` gains an `instance_id: u64` field with a
  `with_instance_id` builder; the EPE Link NLRI's `identifier`
  reads `s.instance_id`.
- The four public `DefaultRouter` projection entry points
  (`ospf_area_bgpls_nlris`, `bgpls_republish`,
  `bgpls_republish_end_x`, `bgpls_republish_epe`) gain an
  `instance_id: u64` parameter; the internal
  `epe_peer_sessions_snapshot` helper gains it too.
- The daemon's `BgplsDriver` carries the field, reads it from
  `BgpLsSpec::bgp_ls_instance_id`, and threads it through the
  three projection calls in its `tick`.
- The daemon's `[bgp_ls]` config block gains an `instance_id = N`
  TOML key (typo-protected, fail-closed on a non-numeric value)
  and a `--bgp-ls-instance-id N` CLI flag (same fail-closed
  posture as `--bgp-ls-id` / `--bgp-ls-as`).
- The startup banner's `bgp-ls:` line surfaces the Instance-ID
  only when the operator pinned a non-zero value — the default `0`
  (RFC 9552 §3.2's single-instance recommendation) stays out of
  the banner so a default `--bgp-ls` invocation produces
  byte-identical output to the previous form (regression gate for
  the existing e2e tests in `daemon_bgpls.rs`).

Breaking Rust API change: the four `DefaultRouter` projection
methods gain an `instance_id: u64` parameter (added between
`bgp_ls_id` and the `prev` slice). The `OspfAreaBgplsContext`
struct gains a field — not marked `#[non_exhaustive]`, so the
struct-literal construction sites in the test fixtures and the
daemon's two temporary build sites are updated in the same round.
The C ABI surface is unchanged (no `lr_*` symbol touched, no FFI
surface change). The default-0 wire output is byte-identical to
the previous hardcoded-0 behaviour, so an embedder that does not
pass `instance_id` through (or passes 0) sees no protocol-on-the-
wire change. The change lands on `main` ahead of the next release
tag, matching the workspace's existing semver-debt pattern.

### `lr-cli`: wire `JValue::Float` / `JArray::len` through real code paths

[Issue #92](https://github.com/TES286-org/librouting/issues/92) —
`crates/lr-cli/src/lrctl_json.rs:L42 | DEAD-CODE | JValue::Float
annotated #[allow(dead_code)]; comment: "kept for forward
compatibility - no lrctl parser emits a float today"` and
`crates/lr-cli/src/lrctl_json.rs:L109 | DEAD-CODE | JArray::len
annotated #[allow(dead_code)]` — the `lrctl` JSON builder declared
both a `JValue::Float` variant and a `JArray::len` accessor that
no production code ever reached, kept under `#[allow(dead_code)]`
with explanatory comments. The defects were genuine: the previous
`push_typed` (the `lrctl` parser that maps a `key=value` token to
a typed `JValue`) tried `u64` then `i64` then fell back to `Str`,
so a fractional value like `cpu-percent=12.3` reached the wire as
a quoted JSON string (`"cpu-percent":"12.3"`) instead of a JSON
number (`"cpu-percent":12.3`), and `JArray::len` had no production
caller — `is_empty()` covered every check the parsers needed.

The fix wires both through real code paths:

- `push_typed` (in `crates/lr-cli/src/lrctl.rs`) tries `u64`,
  then `i64`, then — when the value carries a `.` or `e`/`E` (a
  new `looks_numeric` helper) and parses as a *finite* `f64` —
  pushes it via the new `JObject::push_float` helper, producing a
  `JValue::Float` on the wire. The `looks_numeric` gate keeps
  `NaN` / `inf` / `-inf` (which `f64::parse` accepts) out of the
  float arm entirely, so the writer never sees a
  `JValue::Float(f64::NAN)`; the `is_finite()` guard inside the
  float arm is a second line of defence for direct `push_float`
  callers.
- The `JValue::Float` writer (in
  `crates/lr-cli/src/lrctl_json.rs::write_compact`) now guards
  non-finite values: a `JValue::Float(f64::NAN)` / `±Infinity`
  (which `push_typed` never constructs but `push_float` might) emits
  `null` instead of `NaN` / `inf` — the JSON grammar (ECMA-404 §9)
  forbids non-finite numbers, and ECMAScript's `JSON.stringify`
  does the same `null` mapping. The previous `write!(out, "{f}")`
  would silently produce invalid JSON for any non-finite input.
- `JArray::len` is now used in `parse_show_status_body` and
  `parse_routes_count_body` to surface a new `protocol_count`
  top-level integer field alongside the per-protocol array — a
  monitoring/alerting consumer can read `protocol_count` to alert
  on a count delta (e.g. "expected 3 protocols, got N") without
  parsing the array. The count is read off the same array the
  serializer iterates, not a hand-maintained counter that could
  drift if the parsing loop ever grows more push sites.
- The `#[allow(dead_code)]` annotations on `JValue::Float` and
  `JArray::len` are removed; the explanatory comments now describe
  the real callers (and the JSON-grammar contract the writer
  enforces) instead of "kept for forward compatibility".

Tests: `crates/lr-cli/src/lrctl_json.rs::tests` gains four new
unit tests (`float_finite_renders_as_json_number`,
`float_non_finite_renders_as_null`, `push_float_round_trips_through_object`,
`push_float_non_finite_emits_null_through_object`) covering the
finite-path rendering, the non-finite `null` mapping, and the
`push_float` helper. `crates/lr-cli/src/lrctl_json.rs::tests` also
gains `array_len_counts_pushed_items` for the previously-dead
`JArray::len` accessor. `crates/lr-cli/src/lrctl.rs` gains a new
`push_typed_tests` module with six tests:
`decimal_fraction_becomes_float_not_string`,
`scientific_notation_becomes_float`,
`negative_fraction_becomes_float`,
`nan_and_infinity_stay_as_strings`,
`integer_values_stay_as_integers` (regression guard for the
existing integer-parsing behaviour, so a future change to the
float arm does not silently widen the integer paths), and
`jarray_len_counts_items`.

The `cargo test -p lr-cli` suite (762 tests across all bins +
integration tests) passes; `cargo clippy -p lr-cli --bins --tests
-- -D warnings` is clean; `cargo fmt -p lr-cli --check` is clean.

No public Rust API shape change (`JValue` / `JObject` / `JArray`
are `pub` inside the `lr-cli` binary crate, not a library; the
`push_float` helper is a new public method on a `pub` type, which
is a non-breaking additive change for the crate's internal API);
no C ABI change (the `lrctl_json` module is not in the FFI surface);
no protocol-on-the-wire change (the daemon's status-line output is
unchanged; only the `lrctl --json` proxy's *interpretation* of that
output is more faithful for fractional values, plus the new
`protocol_count` field which is additive). No version bump.

### CI fixes — green main on macOS / RISC-V / s390x

Three platform-native test jobs had been red on every push to `main`
since commit `7a1dbf4` (and the macOS one since the SIGHUP reopen
test landed in `69fbd02`, 2026-11-07). This entry clears all three.

- **`Native (macos-latest)` — `sighup_reopens_log_file_for_rotation`**:
  The test was failing on every macOS CI run since it landed with
  `new log file should contain the reopen notice; got: ` (empty).
  The diagnostic dump added in this entry revealed the real root
  cause: the test's temp dir name
  `lr-daemon-test-hup-logrotate-{PID}-{NANOS}` (~53 chars) combined
  with macOS's `$TMPDIR` (`/var/folders/<xx>/<rest>/T/`, ~50 chars)
  and `daemon.api` (11 chars) exceeded the Unix-domain-socket
  `SUN_LEN` limit (104 bytes). The daemon died at startup with
  `ERROR [api] runtime API: bind ...: path must be shorter than
  SUN_LEN` — before SIGHUP could be delivered, so the new log file
  stayed empty. The fix: the test's temp dir name is shortened to
  `lr-hup-{PID}-{NANOS}` (~25 chars), keeping the full socket path
  under ~80 chars on macOS. Additional hardening:
  (a) `unique_listen_port()` helper derives a per-test port from a
  process-wide atomic counter (range 20000..=39999) so the parallel
  `static_routes_install_and_reload` test can no longer race for
  the hardcoded port 17987;
  (b) the reopen-wait ceiling widens from 15 s to 30 s (10x slack
  over worst observed macOS SIGHUP dispatch latency);
  (c) the reopen-wait assertion prints a diagnostic dump on failure
  (capture log tail + rotated file tail) so a future remote-CI
  failure is triageable from the panic message alone;
  (d) `Daemon::Drop` preserves the capture log on
  `std::thread::panicking()` so the file is still on disk for a CI
  artifact scrubber;
  (e) `daemon_logger::reopen_log_file` now `flush()`es the prior
  `File` handle before swapping it into `LOG_FILE` — forward-looking
  insurance against a future `BufWriter` refactor that would
  otherwise silently lose buffered bytes on the swap.

- **`Native RISC-V (ubuntu-24.04-riscv)` —
  `static_routes_install_and_reload`**:
  The test hardcoded `listen_addr = "127.0.0.1:17987"` — the same
  port `sighup_reopens_log_file_for_rotation` uses. Under
  `cargo nextest`'s parallel harness the two tests race for the
  port; on the slower RISC-V runner the windows overlapped and
  `static_routes_install_and_reload` died with `bind
  127.0.0.1:17987 failed: Address already in use (os error 98)`.
  The fix: `static_routes_install_and_reload` now uses the same
  `unique_listen_port()` helper as the macOS test.

- **`Native s390x (self-hosted) — bfd_fast_fail_beats_hold_time`**:
  The test's `wait_log_all` helper had a 30 s ceiling (widened to
  60 s, then 90 s in this entry). On the self-hosted s390x runner
  (IBM Z hardware, ~3-6x slower than x86_64), the BFD bring-up
  sequence did not reach `-> Up` within 60 s. The 90 s ceiling
  gives ~3x slack over the worst observed timeout while staying
  within the nextest slow-timeout (5 min) and the job's
  `timeout-minutes: 90` ceiling. The test's bring-up wait now
  uses a `wait_log_all_with_sibling` variant that dumps BOTH
  daemons' log tails on failure, so a BFD packet-exchange issue
  on s390x is triageable from the panic message alone — B's log
  reveals whether B's BFD listener ever started and whether B
  received A's BFD packet. The fast-fail-detection wait reuses
  the same helper; the detection itself is ~0.3 s, so the wait
  returns on the first poll that observes the Down transition.
  The `elapsed < Duration::from_secs(5)` assertion is unchanged.

### `lr-bgp` / `lr-cli`: RFC 8210 §5.10 Router Key + §5.11 ASPA deltas (issue #92)

The RTR client (`lr-bgp::rtr::client::RtrClient`) accepted
BGPsec Router Key (RFC 8210 §5.10) and ASPA (RFC 8210 §5.11,
SIDROPS ASPA profile) PDUs on the wire but silently dropped
them — the previous `on_pdu` arm logged `"rtr: <type> PDU
accepted but unused"` and produced no typed output, matching
BIRD's documented parity ("skip Router Key PDUs it cannot
use"). The defect (`defects.txt` L468-L475) was that an
embedder who wanted to consume the cache's attestation —
BGPsec path validation, ASPA validation, or operational
visibility — saw nothing; the data the cache vouches for
never reached the embedder through `ClientStep`.

This round surfaces the two attestation classes as typed
deltas alongside the existing ROA deltas, mirroring the ROA
pattern that landed in 1.0:

- `RouterKeyEntry { ski: [u8; 20], asn: u32,
  subject_public_key_info: Vec<u8> }` and `AspaEntry {
  customer_asn: u32, providers: BTreeSet<u32> }` are the
  normalised equality shapes the client needs to diff two
  syncs. `PartialEq` / `Hash` cover only the wire identity
  (`(ski, asn)` for Router Key, `customer_asn` for ASPA) so
  two PDUs for the same identity collapse onto one entry in
  the client's `HashSet` (matching §5.10's `(ski, asn)`
  scoping and §5.11's "one ASPA object per customer ASN"
  rule). The SPKI / provider set is carried as data; a
  re-announcement with different data replaces the prior
  attestation in the batch and the diff at End of Data
  surfaces the change as a withdraw + announce pair.
- `RouterKeyDelta` / `AspaDelta` (mirroring `RoaDelta`)
  carry one entry plus an `announce: bool` flag.
- `ClientStep` gains two new fields — `router_key_deltas:
  Vec<RouterKeyDelta>` and `aspa_deltas: Vec<AspaDelta>` —
  populated at End of Data alongside `roa_deltas`. The four
  fields are `Vec<T>` so the existing `#[derive(Default)]` on
  `ClientStep` is unchanged; no breaking change for
  embedders that construct `ClientStep { ..Default::default() }`.
- `RtrClient` gains `router_key_snapshot()` /
  `aspa_snapshot()` accessors mirroring `snapshot()` for
  ROA, returning the authoritative set sorted for
  deterministic snapshots.
- The `on_pdu` arm for `RtrPdu::RouterKey` and
  `RtrPdu::Aspa` now accumulates into per-sync batches (with
  the same phase gate the ROA path applies: a PDU outside a
  sync is logged and ignored). At End of Data the batch is
  swapped into the authoritative set and the diff against
  the prior set is emitted as deltas. An explicit withdrawal
  (Announce=false) removes the entry; an implicit withdrawal
  by omission in a Reset Query response also produces a
  withdraw delta (the batch starts empty for Reset Query
  syncs, so any entry not re-announced is removed).
- The daemon's RPKI thread (`crates/lr-cli/src/daemon_rpki.rs`)
  logs the new delta counts alongside the existing ROA delta
  log so the operator sees the attestation the cache vouches
  for even before the FFI carries the typed deltas through to
  C/Go/Python embedders.

The client does not run BGPsec or ASPA validation — that is
a separate slice (BGPsec path validation needs the RPKI
certification path; ASPA validation needs RFC 8481's
upstream/downstream classification). The deltas surface the
cache's attestation so an embedder that does run validation,
or a future validation hook inside librouting, sees the
atomic update alongside the ROA deltas.

7 new Rust unit tests in `crates/lr-bgp/src/rtr/client_tests.rs`
pin the new contract:

- `router_key_and_aspa_are_surfaced_as_deltas` (renamed from
  `router_key_and_aspa_are_accepted_but_unused`) — mid-batch
  deltas are empty; at EoD the deltas carry the entries.
- `router_key_withdrawal_at_next_sync_surfaces_as_remove_delta`
  — a Serial-Query sync with an explicit withdrawal emits a
  `RouterKeyDelta { announce: false, .. }`.
- `aspa_withdrawal_deletes_whole_customer_record` — RFC 8210
  §5.11's "withdrawal deletes the entire ASPA object" rule.
- `aspa_provider_set_is_canonicalised_for_equality` — same
  providers in different wire order produce no delta.
- `router_key_pdu_outside_a_sync_is_logged_and_ignored` /
  `aspa_pdu_outside_a_sync_is_logged_and_ignored` — the phase
  gate matches the ROA path.
- `router_key_replacement_surfaces_as_withdraw_plus_announce`
  — a re-announcement with a different SPKI surfaces as both
  a withdraw of the old attestation and an announce of the new.
- `aspa_provider_set_change_surfaces_as_withdraw_plus_announce`
  — a re-announcement with a different provider set surfaces as
  both a withdraw and an announce.

Breaking Rust API change: `ClientStep` gains two `Vec<T>`
fields (additive under the existing `#[derive(Default)]`, so
`ClientStep { ..Default::default() }` callers continue to
compile). The C ABI surface for the §5.10 / §5.11 attestation
landed in a follow-up round (see the `lr-ffi`: RFC 8210 §5.10
Router Key + §5.11 ASPA C ABI section below); the previous
release carried the Rust-only surface. No version bump in this
round.

### `lr-ffi`: RFC 8210 §5.10 Router Key + §5.11 ASPA C ABI (issue #92)

The follow-up the previous `lr-bgp` / `lr-cli` round named: the
C `lr_rtr_client_step_t` now carries the §5.10 Router Key and
§5.11 ASPA attestation alongside the ROA deltas, so C / C++ / Go
/ Python embedders see the same typed deltas the Rust API
surfaces. The two new types are additive growth on the existing
struct (the new fields land at the tail, the existing fields'
offsets are unchanged); the freeze gate
(`scripts/abi_freeze_check.py`) treats new fields and new
symbols as silent, so no `ABI_VERSION` bump is required.

What landed:

- Two new C types in `crates/lr-ffi/src/rtr_client.rs`:
  `lr_router_key_entry_t` (the 20-byte `ski`, the `asn`, and a
  heap-allocated `subject_public_key_info` pointer + length
  pair) and `lr_aspa_entry_t` (the `customer_asn` and a
  heap-allocated `providers` ASN array + count pair). The
  variable-length payloads are heap-allocated by the FFI and
  owned by the step — the pointers stay valid until
  `lr_rtr_client_step_free` runs; the embedder must not free
  them per-entry.
- Two new C delta structs wrapping the entry structs with an
  `announce: u8` flag: `lr_router_key_delta_t` and
  `lr_aspa_delta_t`, mirroring the existing `lr_roa_delta_t`
  shape.
- `lr_rtr_client_step_t` gains four new tail fields:
  `router_key_delta_count` / `router_key_deltas` and
  `aspa_delta_count` / `aspa_deltas`. The `Default::default()`
  impl initializes all four to zero / NULL, so existing C
  consumers that stack-allocate the struct and zero-init
  continue to compile; consumers that stack-allocate without
  zero-init (the C++ / Go / Python wrappers go through the
  FFI's `step_to_c`, which zero-initialises before populating)
  are unaffected. `ABI_VERSION` stays at 2.
- Two new accessors: `lr_rtr_client_step_router_key_delta_at`
  and `lr_rtr_client_step_aspa_delta_at`, mirroring the
  existing `lr_rtr_client_step_roa_delta_at` shape. Each
  copies the fixed-size entry fields plus the variable-length
  payload pointer/length pair into `*out`. The payload
  pointers borrow from the step and are invalidated by
  `lr_rtr_client_step_free`; the embedder must not free them
  per-entry.
- `step_to_c` now projects the Rust `Vec<RouterKeyDelta>` /
  `Vec<AspaDelta>` into the C arrays (each entry's SPKI /
  providers buffer is heap-allocated as a separate `Box<[u8]>`
  / `Box<[u32]>` and the C struct owns the raw pointer).
- `lr_rtr_client_step_free` now reclaims every entry's SPKI /
  providers buffer before dropping the delta array itself,
  mirroring the existing `logs` reclaim pattern (each `CString`
  is dropped before the array).

The C++ wrapper (`include/librouting.hpp`) gains four new
RAII value types — `RouterKeyEntry`, `RouterKeyDelta`,
`AspaEntry`, `AspaDelta` — that copy the variable-length
payloads into `std::vector<std::uint8_t>` /
`std::vector<std::uint32_t>` so the returned value is owned
and freed on destruction. `RtrClientStep` gains
`router_key_delta_count` / `router_key_delta_at` /
`router_key_deltas` and `aspa_delta_count` / `aspa_delta_at` /
`aspa_deltas` mirroring the existing `roa_delta_*` shape.

The Go binding (`bindings/lr-go/librouting.go`) gains the
same four types (`RouterKeyEntry`, `RouterKeyDelta`,
`AspaEntry`, `AspaDelta`) and the same six methods on
`RtrClientStep`. The variable-length payloads are copied into
Go-owned `[]byte` / `[]uint32` so the returned values are
garbage-collected independently of the step's lifetime.

The Python binding (`bindings/lr-python/src/librouting/rtr.py`)
gains four frozen dataclasses (`RouterKeyEntry`,
`RouterKeyDelta`, `AspaEntry`, `AspaDelta`) and the same six
properties / methods on `RtrClientStep`. The variable-length
payloads are copied into Python-owned `bytes` / `tuple[int, ...]`
so the returned values are garbage-collected independently of
the step's lifetime. The package re-exports the new types as
`RtrRouterKeyDelta` / `RtrRouterKeyEntry` / `RtrAspaDelta` /
`RtrAspaEntry` to match the existing `RtrRoaDelta` /
`RtrRoaEntry` naming convention.

2 new Rust unit tests in `crates/lr-ffi/src/rtr_client.rs`
pin the new contract end-to-end:

- `ffi_rtr_client_step_router_key_and_aspa_deltas_after_v2_sync`
  — feeds a Cache Response + Router Key + ASPA + End-of-Data
  sequence through `lr_rtr_client_on_pdu_raw`, then walks the
  step's new arrays via the new accessors: SPKI bytes
  round-trip verbatim through the FFI pointer, providers are
  projected in ascending order (the Rust `BTreeSet<u32>`
  canonicalisation), out-of-bounds and NULL inputs return
  `LR_ERR_INVALID_HANDLE` / `LR_ERR_NULL`, and `step_free`
  clears all four new fields.
- `ffi_rtr_client_step_router_key_and_aspa_with_empty_payloads`
  — RFC 8210 §5.11 permits an empty provider set ("the
  customer is not a provider of any AS"); the FFI must
  surface NULL pointers + zero counts for the empty payloads
  without crashing on a NULL dereference. The test feeds a
  Router Key with an empty SPKI and an ASPA with an empty
  provider set, then verifies the accessors return NULL
  pointers + zero lengths.

The C++ harness (`tests/ffi/harness.cpp`) extends the
existing `RtrClientStep` test with five new assertions that
pin the empty-step shape of the new surface so a regression
that drops a method breaks at the wrapper layer.

The Go test (`bindings/lr-go/librouting_test.go`) extends
`TestRtrClientStepRoaDeltasAfterFullSync` with five new
assertions for the empty-step shape and adds
`TestRtrClientStepRouterKeyAndAspaDataclassShape` to pin the
new types' field shape. The Python test
(`bindings/lr-python/tests/test_rtr.py`) adds
`test_rtr_client_step_router_key_and_aspa_counts_on_fresh_poll`
and `test_rtr_client_router_key_and_aspa_dataclass_shape`
mirroring the Go coverage.

`scripts/abi_freeze_check.py v1.0.0 HEAD` reports the new
symbols as additive (586 new `#define`s, 284 new typedefs, 85
new struct / enum / union / class, 1849 new functions); no
symbol removed or modified. `scripts/abi_coverage.py HEAD`
reports 1795 / 1795 / 1795 / 1795 coverage across C / C++ /
Python / Go (was 1791 before this round).

### `lr-bgp` (exchange-plane): HintRecord IGP cost via `EgressInput` (issue #92)

defects.txt flagged `build_record_set` for hard-coding the
`HintRecord`'s `igp_cost` and `damp_fom` fields to 0 ("Damping and
IGP integration are future work — 0 is the documented 'off' value").
The advisory `igp_cost` (design §5.1: "the sender's IGP cost from
its decision point to this path's next hop") is the input the
RFC 4271 §9.1.2.2 step (g) tie-break assumes "all the BGP speakers
within an autonomous system can ascertain" but inter-AS receivers
otherwise cannot see — exactly the use case the exchange-plane
hint exists for. Hard-coding it to 0 meant every LRXP-carrying
UPDATE advertised `igp_cost = 0`, so a receiver's policy that
preferred lower-IGP-cost paths saw every LRXP path tie at 0 and
fell through to the remaining tiebreakers — the hint was a no-op
for the IGP dimension.

This round wires the IGP metric end-to-end through the egress path:

- **`lr-bgp::extensions::exchange_plane::EgressInput`** gains two
  new public fields: `igp_metric: Option<u32>` (the IGP metric to
  the route's NEXT_HOP, RFC 4271 §9.1.2.2 step (g)) and
  `damp_fom: Option<u16>` (the local speaker's route-flap figure
  of merit, RFC 2439 shape, advisory only). Both fall through to 0
  in `build_record_set` when `None` (the documented "off" value),
  so existing callers that do not populate the new fields see
  byte-identical wire output.
- **`build_record_set`** now reads `input.igp_metric.unwrap_or(0)`
  for `HintRecord.igp_cost` and `input.damp_fom.unwrap_or(0)` for
  `HintRecord.damp_fom`. The previous hard-coded zeros are gone;
  the rank stays 1 (the decision process is untouched — every
  route handed to egress is by definition the sender's rank-1 path
  for this peer, design §5.1).
- **`lr-bgp::fsm::BgpPeer::attach_exchange_plane`** populates
  `igp_metric: attrs.igp_metric()` — the private `LrIgpMetric` tag
  the embedder attached when it had access to the IGP RIB (the
  same tag the best-path comparator reads for step 7). The
  exchange-plane path keeps the same "absent → 0" mapping as the
  best-path comparator so the two surfaces agree on what "no IGP
  metric" means. `damp_fom: None` is documented as a follow-up:
  the FSM has no access to the daemon's
  `lr_damping::DampingTable` (the table lives in the daemon, not
  in the per-session FSM), so the FoM field exists on `EgressInput`
  for a follow-up that wires the daemon's
  `lr_policy::hooks::DampingImportHook` through a private
  attribute tag (mirroring `LrIgpMetric`); the field is here so the
  follow-up touches only the FSM call site, not the `EgressInput`
  shape again.

5 new unit tests in
`crates/lr-bgp/src/extensions/exchange_plane_tests.rs` pin the
wiring:

- `build_record_set_hint_igp_cost_zero_when_metric_absent` —
  `None` IGP metric flows through to `igp_cost = 0` (the
  documented "off" value), preserving the byte-identical output
  for callers that do not populate the new field.
- `build_record_set_hint_igp_cost_carries_input_metric` —
  `Some(N)` flows through unchanged: the receiver sees the
  sender's actual IGP cost to the route's NEXT_HOP.
- `build_record_set_hint_damp_fom_carries_input_fom` —
  `Some(N)` FoM flows through unchanged. The follow-up that
  wires the daemon's `DampingTable` to populate this field
  depends on this contract; pinning it here keeps a regression
  that re-zeroes the FoM from silently changing the wire hint.
- `build_record_set_hint_carries_both_metric_and_fom` — both
  fields together; the hint carries the sender's actual IGP
  cost and damping FoM, the receiver's policy can prefer the
  lower-IGP-cost path and avoid a path the sender is actively
  damping.
- `hint_igp_cost_round_trips_through_wire` — encode → decode
  symmetry for the newly-wired field; a regression that changes
  the byte layout (e.g. truncating `igp_cost` to u16) would be
  caught here, not just in the abstract `record_roundtrip`
  test.

No public Rust API surface change beyond the two new fields on
the feature-gated `EgressInput` struct (off by default; the
exchange-plane feature is the W6.3 prototype, not the frozen
post-1.0 surface). No C ABI change — `EgressInput` is internal to
the FSM, never exposed across the FFI. No version bump.

### `lr-ffi`: MP-BGP typed NLRI readers on `lr_bgp_message_t` (issue #92)

The follow-up the FFI module doc named: `lr_bgp_decode_message`
returned a typed `BgpMessage` handle whose UPDATE readers covered
the legacy IPv4 withdrawn-routes + NLRI + path-attribute list, but
the MP-BGP NLRI carried inside `MP_REACH_NLRI` / `MP_UNREACH_NLRI`
was reachable only through `lr_bgp_message_update_attr_at` (raw
attribute bytes) — a C embedder could not walk an MP-BGP UPDATE's
NLRI list without re-decoding the attribute value through the
BgpCodec. The new readers below decode the attribute once via
`PathAttributes::mp_reach` / `mp_unreach` and surface each NLRI
entry as a `(path_id, lr_prefix_t)` tuple, the same shape the
legacy IPv4 NLRI / withdrawn readers use. Family (`AFI`, `SAFI`)
and (for `MP_REACH_NLRI`) the next-hop are exposed via dedicated
readers that mirror the existing `lr_bgp_path_attrs_mp_*` shape
on the path-attributes handle. The new symbols are additive
growth on the existing C ABI surface — `ABI_VERSION` stays at 2.

What landed:

- Nine new C ABI functions in `crates/lr-ffi/src/codec.rs`:
  `lr_bgp_message_update_mp_reach_present` / `_family` /
  `_next_hop` / `_nlri_count` / `_nlri_at` and the five
  `_mp_unreach_*` counterparts. The `present` reader returns
  `1`/`0` so an embedder can distinguish "attribute absent" from
  "present with zero NLRI entries" (the End-of-RIB marker for an
  MP family is `MP_UNREACH_NLRI` with zero NLRI); the `_family`
  reader writes `AFI`/`SAFI`; the `_next_hop` reader (MP_REACH only)
  projects the next-hop into the existing `lr_bgp_next_hop_t`
  shape (`kind` 0 = V4, 1 = V6Global, 2 = V4-over-V6 (RFC 5549),
  3 = V6LinkLocal, 4 = V6GlobalLinkLocal — only the global half
  is exposed in `addr` for `kind = 4`; the link-local half is
  dropped, matching the existing
  `lr_bgp_path_attrs_mp_reach` behaviour); the `_nlri_count` /
  `_nlri_at` readers walk the typed NLRI list. The Add-Path
  (RFC 7911) `path_id` is decoded as `0` when Add-Path was not
  negotiated for the family (the C ABI decoder is non-Add-Path,
  matching the existing path-attrs surface — Add-Path-aware
  decoding is a separate follow-up).
- `include/lr_ffi.h` regenerated by `cargo build -p lr-ffi`
  (cbindgen 0.29 auto-generates the new function declarations).
- The codec.rs section header comment that named this as a
  follow-up is replaced with a description of the landed surface.
- C++ RAII wrappers in `include/librouting.hpp`:
  `update_mp_reach_present` / `_family` / `_nlri_count` /
  `_nlri_at` / `_next_hop` and the `_mp_unreach_*` counterparts
  on `BgpMessage`, plus two new value types (`BgpMpFamily`,
  `BgpMpNlriEntry`). The `BgpNextHopKind` enum gains two new
  variants (`V6LinkLocal = 3`, `V6GlobalLinkLocal = 4`) — the
  enum's underlying type is unchanged (`uint8_t`), so existing
  `switch` statements that don't reference the new names
  continue to compile; the new variants are reachable only
  through `update_mp_reach_next_hop`.
- Go bindings in `bindings/lr-go/librouting.go`: 9 new methods on
  `BgpMessage` mirroring the C ABI surface, plus two new value
  types (`BgpMpFamily`, `BgpMpNlriEntry`) and two new
  `NextHopV6LinkLocal` / `NextHopV6GlobalLinkLocal` constants
  on the existing `NextHop*` block. The `prefixFromC` helper
  also sets the `PrefixSpec.IsIPv6` field from the C struct's
  `is_ipv6` discriminator so the value type's field stays
  consistent with `Addr`'s length — the previous implementation
  left `IsIPv6` zero on every `prefixFromC` result, which meant
  callers could not distinguish IPv4 from IPv6 from the
  `PrefixSpec` value alone.
- Python bindings: cdef declarations for the nine new functions
  in `bindings/lr-python/src/librouting/_ffi.py`, 9 new methods
  on `BgpMessage` in `bindings/lr-python/src/librouting/codec.py`,
  two new `NEXT_HOP_V6_LINK_LOCAL` / `NEXT_HOP_V6_GLOBAL_LINK_LOCAL`
  constants exported from `bindings/lr-python/src/librouting/__init__.py`,
  and `BgpNextHop.ip_address` extended to surface the global
  IPv6 address for the two new kinds (so an embedder reading an
  MP_REACH with a link-local next-hop can still get a stdlib
  `ipaddress.IPv6Address`).

11 new Rust unit tests in `crates/lr-ffi/src/codec.rs` pin the
new contract end-to-end: the IPv6 MP_REACH round-trip, the IPv6
MP_UNREACH round-trip, the RFC 5549 V4-over-V6 next-hop, the
V6GlobalLinkLocal kind-4 next-hop (only the global half in
`addr`), the wire-level collapse of `V6LinkLocal` to `V6Global`
on the receive side (the codec cannot recover the link-local-
ness from the wire — the test pins this), the EoR-marker case
for both attributes (present=1 + count=0), the NULL-output and
non-UPDATE rejection paths, and the absent-attribute case for
plain IPv4 UPDATEs. The C++ harness adds 32 new assertions
pinning the same shape, the Go suite adds 3 new tests (MP_REACH
/ MP_UNREACH / absent-on-plain-IPv4-UPDATE), and the Python
suite adds 3 new tests mirroring the Go coverage.

No public Rust API surface change (the new functions live in
the FFI crate only; no new `lr-*` crate type or trait method).
No version bump — the new C ABI symbols are additive growth,
the freeze gate treats new symbols as silent.

**Peer-level BGP flap suppression (issue #99).** A new
`lr-peer-health` crate implements per-`(peer, AFI/SAFI)` flap
suppression — a softer alternative to RFC 2439 prefix damping.
Instead of suppressing unstable prefixes (which leaves them
unreachable), the mechanism temporarily lowers a peer's path
preference at session granularity. The session stays up, the
prefixes stay reachable, and the blast radius is one peer.

Detection uses an EWMA baseline (`ewma_alpha`, default 0.05;
updated only while the peer is at L0 and frozen on escalation
so a flap cannot inflate its own baseline) plus three sliding
windows (short/mid/long, default 5s/30s/120s) with
baseline-relative budgets. Escalation requires at least two
tripped windows including a mid- or long-window confirmation;
hysteresis separates enter and exit thresholds; an emergency
path bypasses the minimum transition interval for catastrophic
bursts. Tiers L0..=L3 represent normal through severe
degradation; recovery is gradual with per-tier dwell and
exponential backoff. On escalation, every prefix the peer has
advertised is marked stale so ECMP excludes it; a fresh UPDATE
re-admits a prefix (clears its stale marker); stale markers
expire after `max_stale_age_s` via a rate-limited sweep.

Six rollout modes gate how far the mechanism reaches: `off`,
`observe` (accounting only), `shadow` (state machine runs, no
stamping, routing unaffected), `shadow-best-path` (like shadow,
plus a `PeerHealthShadowSelectionHook` records divergence
between standard and tiered orderings — routing still
unaffected), `limited` (L1 cap + stale), `full` (all tiers +
stale). The daemon wires the mechanism via `[bgp.peer_health]`
config, spawns a ticker thread, and installs the shadow
selection hook when `rollout = "shadow-best-path"`. The router's
`reselect` uses a **dynamic** `PeerHealthLookup` trait (set by the
daemon when peer-health is enabled) to query the current
per-`(peer, AFI/SAFI)` tier for each BGP candidate and restrict the
candidate set to the lowest non-empty health tier before the standard
decision process (issue #99 §Hooks 3). This is a dynamic lookup — the
tier reflects the state machine's current view, not a stamp frozen at
import time, so a route imported while the peer was healthy is
correctly deprefed when the peer later escalates. Stale paths are
excluded from the ECMP / add-path tail via `is_stale()` on the same
lookup (issue #99 §Recovery). When no lookup is installed (peer-health
off), the router falls back to the stamp-based
`BestPath::rank_tiered`. A SIGHUP that changes `[bgp.peer_health]
rollout` flips the live mode via `PeerHealthTable::set_rollout_mode`
— session state is preserved across the transition.

`lrctl show peer-health` surfaces per-session state: rollout
mode, degraded count, peak tier, and one line per
`(peer, AFI/SAFI)` with tier, baseline, window counts, stale
count, and escalations/recoveries.

New public Rust API surface: `lr_peer_health::{PeerHealthTable,
PeerHealthConfig, PeerHealthTier, RolloutMode,
PeerHealthTable::internal_tier, PeerHealthTable::observe_prefix,
PeerHealthTable::forget_prefix, PeerHealthTable::set_rollout_mode,
...}`, the
`lr_policy::{PeerHealthImportHook, PeerHealthShadowSelectionHook}`,
`lr_router::PeerHealthLookup` (trait the router queries in `reselect`
for dynamic tiering and stale exclusion),
two BGP-private path attributes (`LrPeerHealthTier` = 244,
`LrPeerHealthStale` = 243), four `BestPath` methods
(`tiered_candidates`, `rank_tiered`, `select_tiered`,
`multipath_tiered`), six `PathAttributes` accessors, and a new
`peer-health` feature on `lr-policy`. A new
`ImportHook::on_withdraw_with_origin` trait method (default impl
delegating to the existing 2-parameter `on_withdraw`) carries the
`RouteOrigin` so per-peer withdrawal accounting works correctly
without breaking existing `ImportHook` implementations — the
peer-health hook overrides the new method; the damping hook keeps
its 2-parameter override. `HookChain::run_import_withdraw_with_origin`
dispatches the per-origin variant; the legacy 2-parameter
`run_import_withdraw` is retained for semver stability. New C ABI:
`lr_peer_health_table_t` handle,
`lr_peer_health_config_t` / `lr_peer_health_session_t`
structs, and 9 entry points, surfaced through the Go, Python,
and C++ binding generators. 45+ unit tests cover the state
machine, hook, shadow selection, dynamic tiering, stale exclusion,
and SIGHUP mode flip; 6 E2E tests cover off/observe/shadow-best-path/full
modes and the dynamic-lookup-vs-stamp-based gap.

## [1.8.0] — minor: BGP AGGREGATOR attribute in the filter DSL (RFC 4271 §5.1.7)

librouting 1.8.0 is a minor release. Per `docs/RELEASE-PLAN.md`
§1, the public Rust API gains new surface (`RouteFieldKind::BgpAggregatorAsn`
and `RouteFieldKind::BgpAggregatorSpeaker`, three new `FilterContext`
trait methods with default impls, the `lr-policy::bgp::{aggregator,
aggregator_asn, aggregator_speaker, has_aggregator}` helpers); the new
`RouteFieldKind` variants are a breaking change for downstream `match`
exhaustiveness, which the `api-surface` CI gate will catch going
forward. The C ABI surface is unchanged (no new `lr_*` symbols,
`ABI_VERSION` stays at 2); the FFI callback table
`lr_filter_context_t` is untouched — the new `FilterContext` methods
carry default implementations that delegate to `lr_policy::bgp`, so
every existing embedder inherits the correct behaviour without
recompiling. The typed `aggregator()` accessor on
`lr-bgp::path::PathAttributes` already existed; this release wires it
into the filter DSL.

### Stability

**Minor version bump 1.7.0 → 1.8.0** for the two new
`RouteFieldKind::{BgpAggregatorAsn, BgpAggregatorSpeaker}` variants.
Per `docs/RELEASE-PLAN.md` §1, adding variants to a public enum is a
breaking change for downstream `match` exhaustiveness; the project's
policy (matching the v1.3.0 through v1.7.0 cuts) is to ship it as a
minor bump. The `api-surface` CI gate skips when the workspace version
is ahead of the latest tag, so the gate will become blocking again at
the next release cut. The C ABI surface is unchanged (no new `lr_*`
symbols, `ABI_VERSION` stays at 2).

### Added

**BGP AGGREGATOR filter DSL surface** (`policy`, `cli`, ROADMAP
"Per-protocol route attributes and an external conversion corpus").
The filter DSL now exposes the RFC 4271 §5.1.7 AGGREGATOR attribute —
the `(AS, IP)` pair a BGP speaker stamps onto a route when it
summarises a less-specific across several more-specifics — so an
operator can write aggregation-aware policy:

- `bgp.aggregator.asn` (Int, read-only) — the aggregator's AS number
  (`0` when absent or set to zero). The canonical aggregation-aware
  idiom is `if defined(bgp.aggregator.asn) && bgp.aggregator.asn ==
  64512 then accept;`.
- `bgp.aggregator.speaker` (Ip, read-only) — the aggregator's speaker
  IPv4 address (`false` when absent, mirroring `bgp.next_hop` /
  `bgp.originator_id`'s absent representation; gate with
  `defined(bgp.aggregator.asn)` before reading).
- `defined(bgp.aggregator.asn)` distinguishes "absent" from "set to
  zero" — a present value of AS 0 (rare but legal) reports `true` on
  `defined` and `0` on read. Both components are present together or
  absent together, so `defined(bgp.aggregator.speaker)` reports the
  same presence; `asn` is the canonical probe.

`lr-policy::bgp::{aggregator, aggregator_asn, aggregator_speaker,
has_aggregator}` are the helper quadruple the filter DSL reads
through. `aggregator()` decodes the `Aggregator` struct (a length
check + two fixed-size copies); `aggregator_asn()` / `aggregator_speaker()`
project the pair; `has_aggregator()` is the presence probe. The typed
`aggregator()` accessor on `lr-bgp::path::PathAttributes` already
existed — it accepts both the 6-byte (2-byte-AS) and 8-byte (4-byte-AS)
wire forms, and ingress reconciles AS4_AGGREGATOR (type 18, RFC 6793)
into the canonical type-7 tag, so a single read sees the resolved value
regardless of the peer's AS-width capability.

AGGREGATOR is deliberately **not** fused by the peephole pass's
`BranchFieldIntCmp` fast path — its read decodes the `Aggregator` struct
(a length check + two fixed-size copies, not a single `get_u32_be`), so
fusing would not save the allocation the fast path exists to avoid (the
same reasoning that keeps `bgp.aigp` and the LRXP int-typed fields out
of `is_int_field`). Both the constant-RHS and constant-LHS comparison
forms run the unfused `read_route_field` path; the fused and unfused
paths agree for every route.

The BIRD translator renames `bgp_aggregator` to `bgp.aggregator.asn`
(the canonical presence probe). The corpus case
`tests/corpus/bird/bgp-aggregator-filter.conf` exercises both arms of
the canonical aggregation-aware idiom (`defined(bgp_aggregator) then
accept` and `bgp_aggregator = 0 then accept`) so the converter
round-trips the filter body through `bgp.aggregator.asn` and the daemon
loader accepts the generated TOML.

### Compatibility

- BIRD `bgp_aggregator` filters translate to `bgp.aggregator.asn` —
  the canonical probe for `defined()` (both components are present
  together or absent together, so the presence check is faithful).
- `defined(bgp_aggregator)` survives verbatim — `defined()` shares
  spelling between BIRD and lr.
- FFI embedders see no ABI change: the `FilterContext` trait methods
  `bgp_aggregator_asn` / `bgp_aggregator_speaker` / `bgp_has_aggregator`
  carry default implementations.

## [1.7.0] — minor: BGP AIGP attribute in the filter DSL (RFC 7311)

librouting 1.7.0 is a minor release. Per `docs/RELEASE-PLAN.md`
§1, the public Rust API gains new surface (`RouteFieldKind::BgpAigp`,
two new `FilterContext` trait methods with default impls, the
`lr-bgp::path::well_known::Aigp` type and `PathAttributes::aigp` /
`has_aigp` accessors, the `lr-policy::bgp::{aigp, has_aigp}` helpers,
and `AttrType::Aigp`); the new `RouteFieldKind` variant is a breaking
change for downstream `match` exhaustiveness, which the `api-surface`
CI gate will catch going forward. The C ABI surface is unchanged (no
new `lr_*` symbols, `ABI_VERSION` stays at 2); the FFI callback table
`lr_filter_context_t` is untouched — the new `FilterContext` methods
carry default implementations that delegate to `lr_policy::bgp`, so
every existing embedder inherits the correct behaviour without
recompiling.

### Stability

**Minor version bump 1.6.0 → 1.7.0** for the new
`RouteFieldKind::BgpAigp` variant and the new `AttrType::Aigp`
discriminant. Per `docs/RELEASE-PLAN.md` §1, adding variants to a
public enum is a breaking change for downstream `match`
exhaustiveness; the project's policy (matching the v1.3.0, v1.4.0,
v1.5.0 and v1.6.0 cuts) is to ship it as a minor bump. The
`api-surface` CI gate skips when the workspace version is ahead of
the latest tag, so the gate will become blocking again at the next
release cut. The C ABI surface is unchanged (no new `lr_*` symbols,
`ABI_VERSION` stays at 2).

### Added

**BGP AIGP filter DSL surface** (`bgp`, `policy`, `cli`, ROADMAP
"Per-protocol route attributes and an external conversion corpus").
The filter DSL now exposes the RFC 7311 "Accumulated IGP Metric"
attribute so an operator can prefer lower-metric paths within an
AIGP administrative domain:

- `bgp.aigp` (Int, read-only) — the accumulated IGP metric (the sum
  of every type-1 TLV's 8-byte value in the attribute's TLV stream).
  `0` when absent or set to zero; the wire value is `u64` and the
  DSL's `int` is `i64`, so a value exceeding `i64::MAX` saturates
  (practical IGP metrics are far below `i64::MAX`). The canonical
  metric-comparison idiom is `if bgp.aigp < 100 then accept;`.
- `defined(bgp.aigp)` distinguishes "absent" from "set to zero" — a
  present value of `0` (or an empty value field) reports `true` on
  `defined` and `0` on read, exactly as BIRD's `bgp_aigp` does.

`lr-bgp::path::well_known::Aigp(pub u64)` is the typed view; its
decoder walks the attribute's TLV stream, sums every type-1 TLV's
8-byte big-endian value (the defensive choice for the malformed
"multiple type-1 TLVs" case, matching the attribute's "accumulated"
semantics per RFC 7311 §3.4.3), skips unknown TLV types (RFC 7311
§3 p5: "an AIGP TLV that is not understood MUST be preserved"), and
returns `None` on a malformed stream. The codec stores the raw
attribute bytes verbatim in `PathAttribute::value`, so unknown TLVs
round-trip byte-for-byte. `AttrType::Aigp = 26` joins the
`AttrType` enum; the attribute is optional non-transitive (not
well-known, not mandatory).

`lr-policy::bgp::{aigp, has_aigp}` are the helper pair the filter
DSL reads through. Reads pay one BTreeMap lookup + one TLV-stream
parse per route; unlike `bgp.local_pref` / `bgp.med` / `bgp.otc`
(which use the in-place `get_u32_be` fast path — GitHub #19 P3),
AIGP's value is a TLV stream so a single `get_u32_be` cannot read
it. The parse is bounded by the attribute length and skips unknown
TLVs in O(n).

AIGP is deliberately **not** fused by the peephole pass's
`BranchFieldIntCmp` fast path — its read parses a TLV stream (not a
single `get_u32_be`), so fusing would not save the allocation the
fast path exists to avoid (the same reasoning that keeps the LRXP
int-typed fields out of `is_int_field`). Both the constant-RHS and
constant-LHS comparison forms run the unfused `read_route_field`
path; the fused and unfused paths agree for every route.

The BIRD translator renames `bgp_aigp` to `bgp.aigp`. The corpus
case `tests/corpus/bird/bgp-aigp-metric-filter.conf` exercises both
arms of the canonical metric-comparison idiom (`defined(bgp_aigp) &&
bgp_aigp < 100 then accept` and `bgp_aigp = 0 then accept`) so the
converter round-trips the filter body through `bgp.aigp` and the
daemon loader accepts the generated TOML.

### Compatibility

- BIRD `bgp_aigp` filters translate to `bgp.aigp` with no semantic
  shim (both are integers, `0` = absent or set to zero).
- `defined(bgp_aigp)` survives verbatim — `defined()` shares spelling
  between BIRD and lr.
- FFI embedders see no ABI change: the `FilterContext` trait methods
  `bgp_aigp` / `bgp_has_aigp` carry default implementations.

## [1.6.0] — minor: LRXP exchange-plane records in the filter DSL (issue #81)

librouting 1.6.0 is a minor release. Per `docs/RELEASE-PLAN.md`
§1, the public Rust API gains new surface (`RouteFieldKind::Lrxp*`
variants, twelve new `FilterContext` trait methods with default
impls, a new `lr-policy::lrxp` module); the new `RouteFieldKind`
variants are a breaking change for downstream `match`
exhaustiveness, which the `api-surface` CI gate will catch going
forward. The C ABI surface is unchanged (no new `lr_*` symbols,
`ABI_VERSION` stays at 2); the FFI callback table
`lr_filter_context_t` is untouched — the new `FilterContext`
methods carry default implementations that delegate to
`lr_policy::lrxp`, so every existing embedder inherits the correct
behaviour without recompiling.

### Stability

**Minor version bump 1.5.0 → 1.6.0** for the new
`RouteFieldKind::{LrxpVerified, LrxpPartialTransit, LrxpHintRank,
LrxpHintDampFom, LrxpHintIgpCost, LrxpPolicyRole,
LrxpPolicyImportDigest, LrxpPolicyExportDigest, LrxpOriginAs,
LrxpOriginMaxValidLen, LrxpOriginExpiry}` variants. Per
`docs/RELEASE-PLAN.md` §1, adding variants to a public enum is a
breaking change for downstream `match` exhaustiveness; the
project's policy (matching the v1.3.0, v1.4.0 and v1.5.0 cuts) is
to ship it as a minor bump. The `api-surface` CI gate skips when
the workspace version is ahead of the latest tag, so the gate will
become blocking again at the next release cut. The C ABI surface
is unchanged (no new `lr_*` symbols, `ABI_VERSION` stays at 2).

### Added

**LRXP exchange-plane filter DSL surface** (`policy`, ROADMAP
"LRXP exchange-plane filter DSL surface (issue #81)"). The filter
DSL now exposes the scope-1 records a route carries under the
private `LrExchangePlaneRecords` attribute, behind the
`exchange-plane` feature (off by default). An operator can adjust
`local-pref` / `MED` based on the sender-reported feasibility
hints, policy intent, and origin attestation:

- `bgp.lrxp.verified` (Bool) — true when the route carries a
  verified LRXP record set. The single bool an operator gates on
  when a policy should apply only to LRXP-carrying routes.
- `bgp.lrxp.partial_transit` (Bool) — true when the store is
  partial-transit forwarding material (design §7).
- `bgp.lrxp.hint.rank` / `damp_fom` / `igp_cost` (Int) — the
  scope-1 feasibility hint (design §5.1). `rank` is the sender's
  best-path rank (1 = sender's best); the canonical idiom is `if
  bgp.lrxp.hint.rank > 1 then { bgp.local_pref = 50; }` to
  deprioritise poor repair candidates.
- `bgp.lrxp.policy.role` / `import_digest` / `export_digest` (Int
  / String / String) — the scope-1 policy intent (design §5.2).
  The digests are lowercase hex so two sessions can compare filter
  fingerprints with `==`.
- `bgp.lrxp.origin.origin_as` / `max_valid_len` / `expiry` (Int)
  — the provenance origin attestation (design §5.3). The canonical
  idiom is boosting local-pref for routes with a verified origin:
  `if bgp.lrxp.verified && bgp.lrxp.origin.origin_as == 64512
  then { bgp.local_pref = 200; }`.

`lr-policy` gains an `exchange-plane = ["bgp",
"lr-bgp/exchange-plane"]` feature so the typed accessors can
decode the private record store. `lr-policy::lrxp` is the accessor
module — all read by tag from `Route.attributes` via the
`lr-bgp::extensions::exchange_plane` codec. The `RouteFieldKind`
variants are always present on the enum (so downstream `match`
exhaustiveness is stable across feature configurations); the
parser dispatch (`parse_lrxp_field`) and the eval dispatch
(`field_present`, `read_route_field`) are
`#[cfg(feature = "exchange-plane")]`-gated, with a `#[cfg(not)] _ =>
` fallback so a feature-less build rejects `bgp.lrxp.*` at parse
time with `UnknownBgpField` and the exhaustive matches stay
compilable.

**Fallback (issue #81 requirement)** — the graceful degradation is
built into the accessors: a route with no `LrExchangePlaneRecords`
attribute (the peer did not advertise the capability) reads every
int field as `0`, every bool as `false`, every string as empty, so
the canonical idiom `if bgp.lrxp.hint.rank > 1 then {
bgp.local_pref = 50; }` evaluates its condition to false and the
local-pref write does not fire — the filter no-ops on peers that
do not run the plane.

**Session-level vs per-route (issue #81 requirement)** — the
discrepancy is resolved by reading the route's carried record set:
policy-intent records are nominally per-session but re-attach to
every NLRI the session advertises, so the per-route read is the
correct granularity for a filter that adjusts `local-pref`. Hints
and provenance are per-route by construction.

**Test coverage** — 8 helper tests in `lr-policy::lrxp::tests`
(absent, verified hint/policy/origin, combined, partial-transit,
malformed, issue #81 fallback) + 17 eval tests in
`lr-policy::filter::eval_tests::lrxp_tests` (verified/partial
predicates, hint/policy/origin round-trips, `defined()` semantics,
read-only enforcement, parse errors, the three canonical idioms).
All feature-gated behind `exchange-plane`.

## [1.5.0] — minor: BGP OTC attribute in the filter DSL

librouting 1.5.0 is a minor release. Per `docs/RELEASE-PLAN.md`
§1, the public Rust API gains new surface (`RouteFieldKind::BgpOtc`,
two new `FilterContext` trait methods with default impls, two new
`PathAttributes` typed accessors); the new `RouteFieldKind` variant
is a breaking change for downstream `match` exhaustiveness, which
the `api-surface` CI gate will catch going forward. The C ABI
surface is unchanged (no new `lr_*` symbols, `ABI_VERSION` stays at
2); the FFI callback table `lr_filter_context_t` is untouched — the
new `FilterContext` methods carry default implementations that
delegate to `lr_policy::bgp`, so every existing embedder inherits
the correct behaviour without recompiling.

### Stability

**Minor version bump 1.4.0 → 1.5.0** for the new
`RouteFieldKind::BgpOtc` variant. Per `docs/RELEASE-PLAN.md` §1,
adding variants to a public enum is a breaking change for
downstream `match` exhaustiveness; the project's policy (matching
the v1.3.0 and v1.4.0 cuts that cleared the previous enum-variant
debt the same way) is to ship it as a minor bump. The `api-surface`
CI gate skips when the workspace version is ahead of the latest tag,
so the gate will become blocking again at the next release cut. The
C ABI surface is unchanged (no new `lr_*` symbols, `ABI_VERSION`
stays at 2); the FFI callback table `lr_filter_context_t` is
untouched — the new `FilterContext` trait methods carry default
implementations that delegate to `lr_policy::bgp`, so every existing
embedder inherits the correct behaviour without recompiling.

### Added

**BGP OTC leak-detection attribute in the filter DSL** (`bgp`,
`policy`, `cli`, ROADMAP "Per-protocol route attributes and an
external conversion corpus"). The filter DSL now exposes the
RFC 9234 §3.1 OTC ("Only To Customer") attribute as `bgp.otc`
(read-only `Int`, `0` when absent or set to zero), so an operator
can write the canonical leak-detection idiom directly:

- `if bgp.otc != 0 then reject;` — RFC 9234 §5 egress rule 2 in
  filter form: a route that already carries OTC is "customer-only"
  and must not transit to a provider or peer.
- `if defined(bgp.otc) && bgp.otc != 0 then reject;` — the
  `defined()` gate distinguishes "absent" from "set to zero" so a
  peer that legitimately set OTC=0 (rare but legal) does not trip
  the leak detector.

`lr-bgp::path::PathAttributes` gains typed `otc()` and `has_otc()`
accessors; the former returns `Option<Otc>` (`None` on absent or
malformed, `Some(Otc(0))` on "set but zero"), the latter reports
physical presence so `defined(bgp.otc)` keeps the two cases
distinct. `lr-policy::bgp` carries matching `otc()` and `has_otc()`
helpers that read by tag from `Route.attributes` via
`Attributes::get_u32_be` (the same in-place u32 fast path
`bgp.local_pref` and `bgp.med` use — no `Vec<u8>` clone). The
filter DSL's peephole pass fuses `bgp.otc` integer comparisons
into `BranchFieldIntCmp` (the same fast path the other int-typed
fields use), so `if bgp.otc != 0 then …` pays no `Value::Int`
allocation. The BIRD filter translator renames `bgp_otc` to
`bgp.otc`. A new corpus case
`tests/corpus/bird/bgp-otc-leak-filter.conf` exercises both the
leak-detection idiom and the `defined()` distinction. A proptest
strategy in `lr-bgp::role::otc` pins the `Otc::decode` contract
for the filter DSL surface (4-byte input accepted, byte-exact
round-trip, no input panics). No FFI ABI change: the
`FilterContext` trait methods carry default implementations that
delegate to `lr_policy::bgp`, so every existing impl — daemon, FFI
built-in, FFI callback-table, benches, test stubs — inherits the
correct behaviour without code changes.

## [1.4.0] — minor: BGP RR loop-detection attributes in the filter DSL

librouting 1.4.0 is a minor release. Per `docs/RELEASE-PLAN.md`
§1, the public Rust API gains new surface (`RouteFieldKind`
variants, `OriginatorId` / `ClusterList` types, four new
`FilterContext` trait methods with default impls); the three new
`RouteFieldKind` variants (`BgpAtomicAggregate`, `BgpOriginatorId`,
`BgpClusterList`) are a breaking change for downstream `match`
exhaustiveness, which the `api-surface` CI gate will catch going
forward. The C ABI surface is unchanged (no new `lr_*` symbols,
`ABI_VERSION` stays at 2); the FFI callback table
`lr_filter_context_t` is untouched — the new `FilterContext`
methods carry default implementations that delegate to
`lr_policy::bgp`, so every existing embedder inherits the correct
behaviour without recompiling.

### Stability

**Minor version bump 1.3.0 → 1.4.0** for the new
`RouteFieldKind::{BgpAtomicAggregate, BgpOriginatorId, BgpClusterList}`
variants and the new `OriginatorId` / `ClusterList` types in
`lr-bgp::path::well_known`. Per `docs/RELEASE-PLAN.md` §1, adding
variants to a public enum is a breaking change for downstream
`match` exhaustiveness; the project's policy (matching the v1.3.0
cut that cleared the previous `AttrType::BgpLsAttribute` debt) is
to ship it as a minor bump. The `api-surface` CI gate skips when
the workspace version is ahead of the latest tag, so the gate will
become blocking again at the next release cut. The C ABI surface
is unchanged (no new `lr_*` symbols, `ABI_VERSION` stays at 2); the
FFI callback table `lr_filter_context_t` is untouched — the new
`FilterContext` trait methods carry default implementations that
delegate to `lr_policy::bgp`, so every existing embedder inherits
the correct behaviour without recompiling.

### Added

**BGP route-reflector loop-detection attributes in the filter DSL**
(`bgp`, `policy`, `cli`, ROADMAP "Per-protocol route attributes and
an external conversion corpus"). The filter DSL now exposes three
read-only BGP path attributes that ride the per-route filter context,
so an operator can write loop-detection and aggregation-aware
policies directly:

- `bgp.atomic_aggregate` (RFC 4271 §5.1.6) — `Bool`, true when the
  length-zero ATOMIC_AGGREGATE marker is present, false when absent.
- `bgp.originator_id` (RFC 4456 §8) — `IpAddr::V4` of the route's
  originator, `Bool(false)` when absent.
- `bgp.cluster_list` (RFC 4456 §8) — `Set` of `IpAddr::V4` in
  reflection order, empty when absent; the existing `~` membership
  test accepts `local_cluster ~ bgp.cluster_list` directly.

`lr-bgp::path::PathAttributes` gains typed `originator_id()` and
`cluster_list()` accessors alongside the existing `atomic_aggregate()`
and `aggregator()`. New `OriginatorId` and `ClusterList` types in
`lr-bgp::path::well_known` carry strict-width decoders (4 bytes for
ORIGINATOR_ID, multiple of 4 for CLUSTER_LIST) and a `has_cluster_list`
presence helper that distinguishes "no attribute" from "present but
empty". `lr-policy::bgp` carries matching `atomic_aggregate`,
`originator_id`, `cluster_list` and `has_cluster_list` helpers that
read by tag from `Route.attributes`. The BIRD filter translator
renames `bgp_atomic_aggregate`, `bgp_originator_id` and
`bgp_cluster_list` to the lr dotted spellings. A new corpus case
`tests/corpus/bird/bgp-rr-loop-filter.conf` exercises all three in
the canonical RR loop-detection idiom. No FFI ABI change: the
`FilterContext` trait methods carry default implementations that
delegate to `lr_policy::bgp`, so every existing impl — daemon, FFI
built-in, FFI callback-table, benches, test stubs — inherits the
correct behaviour without code changes.

**BIRD and FRR OSPF configuration translation** (`cli`, ROADMAP
"Per-protocol route attributes and an external conversion corpus").
The `lr translate bird|frr` converter and the native-run compat
loader now carry OSPF configuration through to `[[ospf.area]]` and
`[[ospf.interface]]` tables instead of dropping the whole stanza
with an `UNMAPPED` note.

BIRD `protocol ospf NAME { area N { interface "eth0" { … } } }`
blocks translate per RFC 2328 §C / RFC 5340 §A.4. The area-level
`stub yes`, `nssa yes`, `summary no`, `default cost N` directives
map onto `OspfAreaSpec` (`kind`, `no_summary`, `stub_metric`). The
interface-level `cost`, `hello`, `dead interval`, `priority`,
`type broadcast|pointopoint` directives map onto `OspfIfSpec`
(`cost`, `hello_interval`, `dead_interval`, `priority`,
`network_type`). Parameters without a direct lr equivalent —
`retransmit`, `transmit delay`, `wait`, `dead count`,
`authentication`, `password`, the protocol-level `rfc1583` /
`stub router` / `ecmp` knobs — surface as visible `# UNMAPPED:`
comments so the operator sees the gap.

FRR `router ospf` blocks translate the area-level `area N stub|
nssa|default-cost M|range PREFIX` directives, and FRR `interface
IFNAME` blocks with `ip ospf cost|hello-interval|dead-interval|
priority|network|area` directives map onto the same `OspfIfSpec`
shape. FRR `network PREFIX area N` cannot map mechanically (lr
keys `[[ospf.interface]]` by interface name, not prefix); the
converter notes the gap with a hint instead of silently dropping.
`router ospfv3` produces a note telling the operator to set
`ospf_version = "v3"`, and the v3 directives under it map the same
way as the v2 forms: `ospfv3 router-id A.B.C.D` fills `router_id`,
`ospfv3 area N stub|nssa|default-cost M` routes through the same
handler as the bare v2 `area N …` form, `ospfv3 cost|hello-interval|
dead-interval|priority|network …|area N` inside an `interface IFNAME`
block routes through the same `apply_frr_ospf_iface` helper as the
v2 `ip ospf …` directives, `ospfv3 network PREFIX area N` produces
the same unmapped hint as the v2 form, and `ospfv3 instance-id N` /
`ospfv3 authentication …` / `ospfv3 abr-type …` / `ospfv3
log-adjacency-changes` etc. are noted as unmapped with the v3
directive stem so the operator sees the version-specific gap.

The BGP side of a mixed BIRD or FRR config still converts
alongside the OSPF tables — the converter handles both protocols
in one pass. Existing tests that asserted OSPF was "ignored" now
use RIP (a protocol the converter does not cover) to verify the
ignored-protocols path.

**BIRD/FRR conversion corpus with a golden-file gate** (`cli`,
ROADMAP "Per-protocol route attributes and an external conversion
corpus"). The corpus half of the ROADMAP entry: a directory of
representative BIRD and FRR configurations (`tests/corpus/{bird,frr}/`)
paired with the exact `.expected.toml` the `lr translate` converter
emits, covering the BGP/Babel/OSPF shapes the converter maps today —
single and dual-channel BGP peers, import/export none, the BIRD
filter DSL, ROA tables, static routes, Babel interface blocks, OSPF
area/interface blocks, FRR policy (prefix-lists, route-maps,
as-path/community lists), IPv6 activation, and the OSPFv3 version
note.

Two harnesses share the same data files. The in-crate
`translate::corpus_tests` unit test
(`crates/lr-cli/src/corpus_tests.rs`) drives the converter functions
directly and runs on every platform in `cargo test`. The
`tests/interop/translate_corpus.sh` end-to-end gate drives the real
`lr-daemon translate` CLI binary and runs in the Linux interop CI
job. Both honour `LR_CORPUS_UPDATE=1` to regenerate the golden files
after an intentional converter change, and every `.expected.toml`
round-trips through the daemon loader so the "generated TOML is
always loadable" contract is machine-checked. A new dialect quirk now
adds a corpus case (input + expected) instead of a bespoke assertion.

**FRR `address-family` state: `aggregate-address` and `redistribute`**
(`cli`, ROADMAP "Per-protocol route attributes and an external
conversion corpus"). The `lr translate frr` converter now maps the
FRR `address-family` directives that ride inside `router bgp` (and
the `redistribute` form inside `router ospf`/`router ospfv3`) onto
the daemon's `[[aggregate]]` and `[[redistribute]]` tables instead
of silently dropping them.

`aggregate-address A.B.C.D/M [summary-only] [as-set] [route-map
NAME]` (RFC 4271 §9.2.2.2) maps onto a `[[aggregate]]` row. The
optional `summary-only`, `as-set` and `route-map NAME` qualifiers
carry unmapped notes — lr's `[[aggregate]]` models only the prefix
today (the daemon originates the aggregate with a zeroed AS_PATH
plus ATOMIC_AGGREGATE and AGGREGATOR while any more-specific route
is present, and withdraws it when the last specific disappears; the
FRR qualifiers that suppress specifics or rewrite the aggregate's
AS-SET have no lr equivalent yet).

`redistribute <proto> [metric M] [route-map NAME]` (inside `router
bgp`/`router ospf`/`router ospfv3`) maps onto a `[[redistribute]]`
row. The target engine follows the active router context: `bgp`
inside `router bgp`, `ospf`/`ospf3` inside `router ospf`/`ospfv3`.
The source protocol maps when it is one of `bgp`/`ospf`/`ospf3`/
`babel` (the daemon's injection surface); `connected`/`static`/
`kernel`/`rip`/`isis` carry unmapped notes — lr models kernel/static
routes via `networks`, not via a redistribute pipe. `m[metric M`
carries through; `route-map NAME` is noted (lr's `[[redistribute]]`
has no per-pipe filter hook today). A pipe whose source engine is
not `bgp` triggers a top-level `protocols = ["bgp", "<engine>", …]`
emission so the generated config is loadable as-is — the daemon's
`finalize` rejects a `[[redistribute]]` whose source engine it does
not run, so the converter emits the protocol set the pipe needs.

Two related FRR directives also landed: `no bgp ebgp-requires-policy`
is consumed silently (the converter always emits `ebgp_policy =
"accept-all"`, which is the same intent), and `network PREFIX
route-map NAME` keeps the prefix in `networks` while noting the
route-map (lr's `networks` is a plain prefix list, no per-route
attribute hook).

Two new corpus cases lock in the contract: `tests/corpus/frr/
bgp-aggregate.conf` (the `summary-only` shape) and
`tests/corpus/frr/bgp-redistribute.conf` (the `redistribute ospf
metric 100` + `redistribute connected` shape, exercising both the
mapped pipe and the unmapped note). Both round-trip through the
daemon loader so the "generated TOML is always loadable" contract
is machine-checked.

## [1.3.0] — minor: supply-chain follow-ups, BFD auth, BGP-LS

librouting 1.3.0 is a minor release. Per `docs/RELEASE-PLAN.md`
§1, the public Rust API gains new surface (BFD keyed-hash auth
in `lr-bfd::keyed_auth`, the BGP-LS Attribute TLV codec in
`lr-bgp::path::bgp_ls_attr`, BGP-LS Node Descriptor sub-TLVs in
`lr-bgp::path::bgp_ls`); the new variant
`lr-bgp::path::AttrType::BgpLsAttribute` (RFC 7752 §3.3) is a
breaking change for downstream `match` exhaustiveness, which
the new `api-surface` CI gate will catch going forward. The C
ABI surface is unchanged (no new `lr_*` symbols, `ABI_VERSION`
stays at 2). The release pipeline gains a CycloneDX SBOM per
binary target, cosign keyless artifact signing, and a
`cargo semver-checks` + `cargo public-api` API surface scan on
every push, PR and nightly.

### Added

**Cosign keyless artifact signing** (`ci`, ROADMAP "Supply-chain
follow-ups"). The supply-chain follow-ups ROADMAP entry's cosign
half: every release artifact (platform archives, CycloneDX
SBOMs, standalone headers) is now signed with cosign keyless
signing via GitHub Actions OIDC, anchored at the Sigstore Fulcio
certificate authority and recorded in the Rekor transparency
log. A consumer can verify any artifact against the public
Sigstore root without a project-held key.

A new `sign-artifacts` job in
`.github/workflows/release.yml` runs on every `v*` tag push,
between the `generate-sbom` and `publish-release` jobs. The job:

- Requests an OIDC token from GitHub Actions (gated on
  `permissions.id-token: write`), which cosign exchanges at
  Fulcio for a short-lived signing certificate. No long-lived
  signing key lives in repository secrets.
- Installs cosign via `sigstore/cosign-installer@v3` (major-pinned
  action; the cosign CLI itself is allowed to move forward inside
  the v2 line).
- Downloads every platform archive from `build-native` and every
  SBOM from `generate-sbom`, plus the standalone headers from the
  repo, into a single staging tree.
- Signs each file with `cosign sign-blob --yes --bundle <out>.bundle
  <file>`. The `--bundle` flag produces a single DSSE-format file
  (cosign 2.x's recommended shape) that carries the signature,
  the Fulcio certificate, and the Rekor transparency log entry
  together — a consumer needs only the bundle + the artifact +
  cosign to verify, no separate `.sig` / `.pem` pair to keep in
  sync.
- Immediately runs `cosign verify-blob --bundle <out>.bundle
  --certificate-identity-regexp
  'https://github.com/TES286-org/librouting/.github/workflows/release.yml@refs/tags/.*'
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
  <file>` against the workflow's own OIDC identity. The inline
  verify catches any signing or transparency-log issue before the
  bundle is uploaded — a broken bundle never reaches the GitHub
  Release.
- Uploads the bundle set as the `librouting-signatures` artifact
  for the `publish-release` job to flatten into the draft GitHub
  Release.

The `publish-release` job now `needs: [build-native,
generate-sbom, sign-artifacts]` and flattens every `*.bundle` into
the draft GitHub Release alongside the platform archives, the
SBOMs and the standalone headers. The release body enumerates the
signature shape and the `cosign verify-blob` invocation a
consumer runs to verify an artifact, including the
`--certificate-identity-regexp` covering any `v*` tag the
workflow is triggered on, so a consumer pairs `<file>` with
`<file>.bundle` once and reuses the same command across releases.

**Rust API surface scan (cargo public-api + semver-checks)** (`ci`,
ROADMAP "Supply-chain follow-ups"). The supply-chain follow-ups
ROADMAP entry's static-analysis half: the public Rust API
surface is now scanned on every change. Two complementary tools
cover the project's Tier 1 stability contract (the public Rust
API is frozen at 1.0, so any breaking change ships as a new
minor — per `docs/RELEASE-PLAN.md` §1):

- `cargo semver-checks` is the gate. It runs rustdoc-JSON-based
  semver lints against the latest published `v*` tag's rustdoc
  and fails the job if any check finds a violation — the
  accidental breaking change a reviewer would otherwise miss.
- `cargo public-api` is the report. It walks `rustdoc
  --output-format json` of every library crate, diffs the
  current tree against the latest tag, and emits an
  Added/Changed/Removed breakdown per crate, uploaded as an
  `api-surface-diff` artifact for review.

The PR-level `api-surface` job in
`.github/workflows/ci.yml` runs on every push and every PR.
The job:

- Installs the nightly toolchain (`cargo public-api` uses
  `rustdoc --output-format json`, which is still nightly-only).
- Installs `cargo-public-api` and `cargo-semver-checks` (both
  `cargo install --locked`, with an `|| true` fallback so a
  future release that slips a lockfile bump past the maintainers
  does not break CI silently).
- Resolves the latest `v*` tag (the semver baseline) via
  `git tag --list 'v*' --sort=-v:refname | head -1`. If no tag
  exists yet (first release not cut), the gate is skipped —
  same shape as the nightly variant.
- Runs `cargo +nightly public-api -p <crate> diff
  <latest-tag>..HEAD --simplified --color=never` per library
  crate, captured to `api-surface/<crate>.public-api.diff`.
  The crate list is filtered by `cargo metadata --no-deps`
  to packages whose `targets` include a `lib`-kind target;
  binary-only crates (e.g. `lr-cli`) are skipped because
  `cargo public-api` walks the `[lib]` target's rustdoc JSON,
  which binary-only crates lack.
- Runs `cargo semver-checks --workspace --all-features
  --baseline-rev <latest-tag>`. `--all-features` mirrors the
  build matrix so feature-flagged public items are in scope.
- Uploads the per-crate diffs as the `api-surface-diff`
  artifact (7-day retention on PR-level, 30-day on nightly).

**Nightly API surface snapshot** (`ci`, same ROADMAP entry).
A second `api-surface` job in
`.github/workflows/nightly.yml` runs the same two-tool scan
on the nightly cron (and on `workflow_dispatch`). The artifact
retention is 30 days there so a maintainer can review the
nightly drift history.

### Stability

No Rust API change. No C ABI change. No daemon flag or config
surface change. The scan is purely a CI/CD artifact; the
library and the daemon binaries are untouched.

### Out of scope

- A `cargo public-api --deny` gate that fails the PR on
  additions or removals of public items. Today the diff is the
  report; the gate is `cargo semver-checks`. A `--deny` gate
  would catch additive changes that `cargo semver-checks`
  permits (an addition is a semver-minor, not a violation).
  Worth a follow-up if the project wants the PR to fail on
  every public-API change, not just breaking ones.

### Pre-existing semver debt the scan surfaced

The first run of `cargo semver-checks --workspace --all-features
--baseline-rev v1.2.0` on this branch surfaced an existing
finding: between `v1.2.0` and `HEAD`, the public Rust API gained
breaking changes that were not paired with a version bump:

- `lr-bgp::path::AttrType` gained a new variant
  `AttrType::BgpLsAttribute` (RFC 7752 §3.3 BGP-LS Attribute,
  commit `d472e66`), which is a breaking change for
  downstream `match` exhaustiveness (the enum is not
  `#[non_exhaustive]`).
- The same enum's variant `AttrType::LrMplsLabelStack` moved
  from position 21 to 22, which is a breaking change for
  `PartialOrd`-derived ordering (the enum derives
  `PartialOrd`).

The project is at workspace version `1.2.0` (post-1.0), so per
`docs/RELEASE-PLAN.md` §1 a breaking Rust API change is a
**major** bump. The two findings together require a `2.0.0`
release cut to clear.

Until the version is bumped, the `cargo semver-checks` step in
both `ci.yml` and `nightly.yml` runs with
`continue-on-error: true` so the scan surfaces the finding
without blocking every PR. Once the debt is cleared by a
release cut, the `continue-on-error: true` line can be removed
so the gate becomes blocking — that is the "Done when" state
the ROADMAP entry names.

**CycloneDX SBOM per release** (`ci`, ROADMAP "Supply-chain
follow-ups"). The supply-chain follow-ups ROADMAP entry named
three gaps: a CycloneDX SBOM per release, `cosign` signatures
over the release archives, and a static-analysis scan of the
Rust sources. The SBOM half: the `generate-sbom` job in
`.github/workflows/release.yml` runs on every `v*` tag push and
attaches a CycloneDX 1.5 JSON SBOM per shipped binary target to
the GitHub release, alongside a combined archive.

A new `generate-sbom` job in
`.github/workflows/release.yml` runs `cargo cyclonedx --describe
binaries --all-features --spec-version 1.5` on every release tag
push and emits one CycloneDX 1.5 JSON SBOM per shipped binary
target:

- `librouting-lr-<tag>.cdx.json` — the `lr` inspection CLI
  (transitive closure of `lr-cli`'s `lr` bin target).
- `librouting-lr-daemon-<tag>.cdx.json` — the `lr-daemon`
  reference daemon (`lr-cli`'s `lr-daemon` bin target).
- `librouting-lrctl-<tag>.cdx.json` — the `lrctl` operational
  CLI (`lr-cli`'s `lrctl` bin target).
- `librouting-lr-ffi-<tag>.cdx.json` — the `lr-ffi` C ABI
  library (the `cdylib`/`staticlib`/`rlib` triple).
- `librouting-sbom-<tag>.tar.gz` — every per-binary SBOM in one
  archive.

`--describe binaries` is the right granularity: each binary's
dependency closure is distinct, and a consumer embedding via the
C ABI or running a CLI binary can pull the SBOM that names exactly
the transitive crate set they ship. `--all-features` mirrors the
release build matrix — every feature-flagged dependency the
release binaries ship with is in the SBOM. The job stages the
SBOMs into clean `librouting-<binary>-<tag>.cdx.json` filenames
and runs an inline JSON validation pass (`bomFormat`,
`serialNumber`, `metadata.component` must all be present) before
upload, so a malformed SBOM fails the release early instead of
shipping silently to consumers. The `publish-release` job now
`needs: [build-native, generate-sbom]` and flattens the SBOM
artifacts into the draft GitHub Release alongside the platform
archives and the standalone headers.

`.gitignore` adds `*.cdx.json` and `*.cdx.xml` so a developer
running `cargo cyclonedx` locally for a pre-release audit cannot
accidentally commit the output. The release workflow owns the
canonical SBOM artifacts; the local output is a working file.

### Stability

No Rust API change. No C ABI change. No daemon flag or config
surface change. The SBOM is purely a release-pipeline artifact;
the library and the daemon binaries are untouched.

**BFD keyed-hash authentication** (`feat`, addresses the `partial`
BFD auth row in [`docs/STATUS.md`](docs/STATUS.md)). The BFD auth
surface completes: the four keyed-hash authentication types from
RFC 5880 §4.3 / §4.4 — Keyed MD5 (type 2), Meticulous Keyed MD5
(type 3), Keyed SHA1 (type 4), Meticulous Keyed SHA1 (type 5) —
now compute and verify their digests in-process behind the
`keyed-auth` feature (on by default), bringing the BFD auth
STATUS row from `partial` to `yes`. The previous release left
the keyed-hash section layouts modelled in the wire codec but
framed the digest computation as "embedder-supplied"; the
embedder no longer has to roll its own MD5/SHA1 path.

A new `lr-bfd::keyed_auth` module owns the digest computation,
the per-session sequence-number state (`bfd.XmitAuthSeq`,
`bfd.RcvAuthSeq`, `bfd.AuthSeqKnown`) and the anti-replay check
the RFC requires on the receive side:

- `BfdKeyedAuth::new(key_id, algorithm, secret)` constructs the
  per-session auth state. The secret length is checked against the
  algorithm's maximum (16 bytes for MD5, 20 for SHA1, RFC 5880 §6.7.3
  / §6.7.4) and rejected with `None` if it is empty or too long.
- `BfdSession::set_keyed_auth(Some(ka))` installs the keyed-hash
  auth; `BfdSession::set_keyed_auth(None)` clears it. Additive over
  the existing `BfdConfig::auth_key` (Simple Password): the keyed
  auth takes precedence when both are configured (RFC 5880 §6.7 — a
  packet carries one auth type per packet).
- `BfdSession::keyed_auth()` exposes the installed state; a new
  `BfdSession::config()` accessor exposes the live `BfdConfig`.
- `BfdKeyedAuth::sign_packet(&mut packet_bytes)` signs an encoded
  outbound packet in place — the last `digest_len` bytes (the
  shared key in the digest field) are replaced with the MD5/SHA1
  digest over the full packet.
- `BfdKeyedAuth::verify_inbound(received_bytes, &section,
  detect_mult)` verifies an inbound packet: it rebuilds the pre-hash
  packet by overwriting the trailing digest with the shared key,
  recomputes the hash, and compares against the received digest;
  on a match the receive sequence state advances and the
  anti-replay window is enforced. Returns `false` (without mutating
  state) on any type/key-id/length mismatch, sequence outside the
  `[last, last + 3*DetectMult]` (non-Meticulous) or `[last+1,
  last + 3*DetectMult]` (Meticulous) circular range, or digest
  mismatch.

The session wires the new module into `check_auth` (raw packet bytes
now plumbed through `feed_bytes` → `on_packet` → `check_auth` so the
hash can be recomputed over the full wire form) and `enqueue_packet`
(signs in place after `BfdCodec::encode` produces the key-bearing
packet). The codec itself is unchanged.

### Performance note

The MD5 path uses the `md5` crate's standalone `compute` function
(no hasher state object); the SHA-1 path uses the `sha1` crate's
`Sha1::digest` through the `Digest` trait. Both are `no_std`-friendly
with `default-features = false`, so the `keyed-auth` feature does
not pull `std` in. The auth section wire framing in `lr-bfd::auth`
is unchanged; only the digest computation is new.

### Tests

8 new unit tests in `keyed_auth.rs` cover the algorithm constants,
the constructor length bounds, MD5 / Meticulous SHA1 sign-and-verify
round-trips, wrong-key-id rejection, wrong-secret rejection, the
circular anti-replay range arithmetic (including the wrap-through-0
case), and the anti-replay window bounded by `Detect Mult`.

9 new session integration tests in `session_tests.rs` cover the
full session path: signed outbound carries the digest (not the key),
two sessions reach Up together under Keyed MD5 and under Meticulous
Keyed SHA1, tampered digest is rejected with `AuthFailed` without
advancing the FSM, wrong secret / wrong key ID / missing section are
all rejected, clearing the keyed auth reverts to no-auth, and the
keyed auth accessor exposes the installed state.

A new `bfd_auth` cargo-fuzz target under `fuzz/fuzz_targets/`
exercises the codec + `verify_inbound` path against arbitrary input
(seeds committed under `fuzz/seeds/bfd_auth/`); the nightly
workflow runs it for 5 minutes alongside the existing three
targets. Initial 18M-iteration smoke run produced no panics.

### Stability

Additive only — no breaking changes.

- **Public Rust API (Tier 1)**: new `keyed_auth::BfdKeyedAuth` struct,
  new `keyed_auth::KeyedAuthAlgorithm` enum, new
  `BfdSession::set_keyed_auth` method, new `BfdSession::keyed_auth`
  accessor, new `BfdSession::config` accessor, new public methods on
  `BfdKeyedAuth` (`auth_section_for_tx`, `advance_xmit_seq`,
  `sign_packet`, `verify_inbound`, and the read accessors
  `key_id` / `algorithm` / `xmit_seq` / `rcv_auth_seq_known` /
  `rcv_auth_seq`). No existing signature changes.
- **C ABI (Tier 2)**: unchanged — the new types are Rust-only; the
  `lr-ffi` C header regenerates byte-identical to the prior release.
- **Daemon / config surface (Tier 3)**: unchanged — keyed-hash auth
  is installed programmatically through `BfdSession::set_keyed_auth`.
  Daemon CLI / TOML surfaces that surface it to operators are an
  additive follow-up that does not change the wire path.

### First-hand references used

- RFC 5880 §4.3 (Keyed MD5 / Meticulous Keyed MD5 section format,
  Auth Len 24, 16-byte digest).
- RFC 5880 §4.4 (Keyed SHA1 / Meticulous Keyed SHA1 section format,
  Auth Len 28, 20-byte digest).
- RFC 5880 §6.7.3 (transmit: shared key placed in Auth Key/Digest
  field, MD5 computed over the full packet, digest replaces the
  key; receive: replace digest with key, recompute, compare;
  anti-replay window `[last, last + 3*DetectMult]` for non-Meticulous,
  `[last+1, last + 3*DetectMult]` for Meticulous, circular 32-bit
  space).
- RFC 5880 §6.7.4 (Keyed SHA1 / Meticulous Keyed SHA1: same
  procedure, SHA1 instead of MD5, 20-byte digest, Auth Len 28).
- BIRD `proto/bfd/bfd.c` — keyed-MD5 / keyed-SHA1 sign and verify
  paths, sequence advancement on every packet for both Meticulous
  and non-Meticulous.

**BGP-LS Attribute TLV codec + earlier BGP-LS work** (`feat`,
[issue #60](https://github.com/TES286-org/librouting/issues/60)).
Progress on issue #60: the wire codec for the BGP-LS Link-State
AFI/SAFI pair (AFI=16388, SAFI=71, plus the VPN variant
SAFI=72), the OSPF LSDB → BGP-LS projection, the daemon wiring
(`--bgp-ls` flag, `[bgp_ls]` config block, the BgpPeer BGP-LS
egress primitives, the incremental republish driver), the
BIRD interop lab, and the BGP-LS Attribute TLV codec (RFC 7752
§3.3 + RFC 9514 §7-§8) have all landed. The done criterion — a
third-party collector builds the same IGP graph from our
session that the OSPF daemon holds, with incremental republish
— is met; the `bgpls_bird.sh` lab is the verification gate.

**BGP-LS NLRI codec** (`feat`, [issue #60](https://github.com/TES286-org/librouting/issues/60)).
A new `lr-bgp::path::bgp_ls` module (feature-gated as
`lr-bgp/bgp_ls`, on by default) parses and serialises the four
RFC 7752 §3.3 NLRI shapes — Node (Type 1), Link (Type 2), IPv4
Topology Prefix (Type 3), IPv6 Topology Prefix (Type 4) — plus
the Local/Remote Node Descriptor wrapper TLVs (256/257), the bare
Link Descriptor TLV stream (258-263), the bare Prefix Descriptor TLV
stream (263-265), and the Node Descriptor sub-TLVs (§3.2.1.4:
Autonomous System 512, BGP-LS Identifier 513, OSPF Area-ID 514,
IGP Router-ID 515). The codec also models the SRv6 SID NLRI
(RFC 9514 §6, NLRI Type 6) in full at the NLRI level: the inner
SRv6 SID Descriptor TLV stream carries the mandatory SRv6 SID
Information TLV (§6.1, type 518, 16-byte SID) and any optional
Multi-Topology ID TLV (§3.2.1.5, type 263). The new
`NlriFamily::BGP_LS` and `NlriFamily::BGP_LS_VPN` constants in
`lr-core::nlri` carry the AFI/SAFI pair.

Round-trip safety: the codec enforces strict RFC 7752 §3.3 figure
structure on decode — Node NLRI has exactly one outer TLV
(LOCAL_NODE_DESCRIPTOR); Link NLRI has LOCAL_NODE_DESCRIPTOR +
REMOTE_NODE_DESCRIPTOR followed by bare Link Descriptor sub-TLVs;
Prefix NLRI has LOCAL_NODE_DESCRIPTOR followed by bare Prefix
Descriptor sub-TLVs; SRv6 SID NLRI has LOCAL_NODE_DESCRIPTOR
followed by a bare SRv6 SID Descriptor stream that MUST contain
exactly one SRv6 SID Information TLV (§6.1). A TLV 518 with any
length other than 16 — the only length RFC 9514 §6.1 permits —
falls through to `Unknown` and is rejected at the NLRI level by
the "exactly one 518" structural check. Unknown sub-TLVs are
preserved verbatim, so any well-formed NLRI round-trips
byte-for-byte. The `cargo +nightly fuzz run bgp_ls_decode` target
(mirroring `bgp_decode.rs`) asserts the round-trip property on any
input that decodes successfully; it ran 62 million iterations
without crashes on the seed corpus committed under
`fuzz/seeds/bgp_ls_decode/`.

The BGP-LS Attribute TLVs that ride alongside the SRv6 SID NLRI
(RFC 9514 §7 SRv6 Endpoint Behavior, §8 SRv6 SID Structure) live
in a separate attribute surface and are out of scope for this
codec entry.

**OSPF LSDB → BGP-LS projection** (`feat`, [issue #60](https://github.com/TES286-org/librouting/issues/60)).
A new `lr-router::instance::lsdb_to_bgpls` module (Layer 2 of the
issue's work breakdown) projects one OSPF area's LSDB onto the
BGP-LS NLRI set a controller needs to rebuild the IGP graph the
OSPF daemon holds. Pure function on the LSDB; does not touch the
daemon loop or transports. A new public accessor
[`DefaultRouter::ospf_area_bgpls_nlris`] wraps the projection with
the router's per-area context (AS number, BGP-LS ID, area ID,
protocol).

OSPFv2 emits Node NLRIs (Router-LSA, Network-LSA pseudonode), Link
NLRIs (transit + P2P links) with IPv4 Interface/Neighbor Address
TLVs, and IPv4 Topology Prefix NLRIs (stub links = `IntraArea`,
type-3 Summary-LSAs = `InterArea`, type-5 AS-External-LSAs =
`External1` / `External2` with the OSPF Area-ID sub-TLV set to 0
per RFC 7752 §3.2.1.4). OSPFv3 emits the IPv6 equivalents, plus
handles RFC 8362 Extended LSAs (E-Router, E-Network,
E-Intra-Area-Prefix, E-Inter-Area-Prefix, E-AS-External) with the
same field semantics. The projection looks the DR Router ID up in
the Network-LSA table to build the transit-link remote pseudonode,
and skips a transit-link Link NLRI when the Network-LSA is not in
the LSDB yet (the next projection run sees it).

OSPFv3 also projects the SRv6 SID NLRI (RFC 9514 §6) from the
OSPFv3 SRv6 database (`lr-ospf::srv6db`, RFC 9513 reception). The
projection builds a `Srv6Database` from the same area LSDB and
emits one SRv6 SID NLRI per End SID the database holds — the Local
Node Descriptor is the advertising router's 4-byte IGP Router-ID,
and the SRv6 SID Descriptor stream carries the mandatory SRv6 SID
Information TLV (§6.1, type 518, 16-byte SID) plus a Multi-Topology
ID TLV (RFC 7752 §3.2.1.5, type 263, value 0). End.X / LAN End.X
SIDs are not projected: the RFC 8986 endpoint behavior that
distinguishes them from End SIDs lives in the BGP-LS Attribute
surface (RFC 9514 §7), which is out of scope for the NLRI codec;
the End.X projection is a follow-up once the attribute surface
lands. `diff_bgpls` handles the SRv6 SID NLRIs transparently —
the codec's strict structural enforcement on the SRv6 SID
Descriptor stream makes the encoded bytes a stable identity for
set membership, so the incremental-republish primitive covers
SRv6 SIDs the same way it covers Node / Link / Prefix NLRIs.

[`diff_bgpls`] computes the added / removed / unchanged NLRI sets
between two projections by canonical wire form (RFC 7752 §3.3:
NLRI comparison is byte-for-byte). A daemon running the projection
once per LSDB change uses `added` for MP_REACH_NLRI and `removed`
for MP_UNREACH_NLRI — the incremental-republish primitive the
ROADMAP "done" criterion calls for.

Thirty-nine unit tests cover the per-LSA projection (Node / Link /
IPv4 Prefix / IPv6 Prefix), the OSPFv2 + v3 paths, the E-LSA
shapes, the AS-External area-ID-zero rule, the SRv6 End-SID
projection (single SID, multiple SIDs, multiple locators, multiple
routers, locator-only node, §8 containment gate, §11 behavior
gate, OSPFv2 guard, E-Router-LSA coexistence), the SRv6 SID diff
helper, and the diff helper for the topology NLRIs. Each test
also asserts every emitted NLRI round-trips byte-for-byte through
the codec.

Public Rust API surface (Tier 1) is additive only — the new
`lsdb_to_bgpls` module and the new `DefaultRouter::ospf_area_bgpls_nlris`
method; no existing signature changes. The C ABI (Tier 2) is
unchanged; the new types are Rust-only. The daemon flag and config
surface (Tier 3) are unchanged — BGP-LS daemon wiring is tracked
as a follow-up in [issue #60](https://github.com/TES286-org/librouting/issues/60).

[`DefaultRouter::ospf_area_bgpls_nlris`]: https://github.com/TES286-org/librouting/blob/main/crates/lr-router/src/instance/mod.rs
[`diff_bgpls`]: https://github.com/TES286-org/librouting/blob/main/crates/lr-router/src/instance/lsdb_to_bgpls.rs

**Daemon BGP-LS wiring** (`feat`, [issue #60](https://github.com/TES286-org/librouting/issues/60)).
The daemon wiring half of BGP-LS: a `--bgp-ls` CLI flag and a
`[bgp_ls]` config block (TOML + native DSL) advertise the BGP-LS
address family (AFI=16388, SAFI=71, RFC 7752 §3.1) on every BGP
session, and a projection-driver thread pushes incremental
MP_REACH_NLRI / MP_UNREACH_NLRI UPDATEs to every Established BGP-LS
session when the OSPF LSDB moves. The configuration surface
mirrors `[safety]` / `[logging]`: a single fail-closed section
(`enabled`, `as_number`, `bgp_ls_id`, `areas`); typo'd keys are
hard errors. The CLI mirror is `--bgp-ls`, `--bgp-ls-as`,
`--bgp-ls-id`, `--bgp-ls-area`; `--bgp-ls-area` is repeatable (mirrors
`--network`). The startup banner gains a `bgp-ls:` line that
prints the speaker identity and the area subset.

The egress primitives `BgpPeer::advertise_bgpls(&[BgpLsNlri])` and
`BgpPeer::withdraw_bgpls(&[BgpLsNlri])` (feature-gated
`lr-bgp/bgp_ls`, on by default) assemble the MP_REACH_NLRI /
MP_UNREACH_NLRI attribute bytes directly from
`BgpLsNlri::encode` — the existing IP-prefix `MpReach`/`MpUnreach`
encoders assume AFI=1/2 and cannot carry the opaque BGP-LS NLRI
stream. The next-hop field is set to zero (BGP-LS does not define a
next-hop; matches BIRD's `bgp_ls` channel and FRR's
`bgp_bgp_ls.c`).

The republish driver lives in `lr-router::instance::DefaultRouter::bgpls_republish`:
projects the area LSDB through
`ospf_area_bgpls_nlris`, computes the diff against the caller's
previous projection via `diff_bgpls`, and pushes the added/removed
NLRIs to every BGP-LS session. The daemon's ticker thread drives
the driver once per 50 ms tick: `BgplsDriver` polls each configured
OSPF area's `topology_version` and calls `bgpls_republish` on
change. Sessions without BGP-LS in their `mp_families` see nothing
— matches the per-peer family gating the FSM already enforces on
the receive side.

The interop lab `tests/interop/bgpls_bird.sh` starts an OSPF+BGP
`lr-daemon` with `--bgp-ls` against a BIRD 2.17+ peer configured
for the `bgp_ls` channel. The lab verifies the BIRD peer builds a
Node NLRI for the lr-daemon's router-id from our BGP-LS session —
the same IGP graph the OSPF daemon holds in its LSDB. BIRD <2.17
lacks the `bgp_ls` channel and SKIPs cleanly. The lab is the "done"
gate from `docs/ROADMAP.md` §1: "Done when a third-party collector
builds the same graph from our session that the OSPF daemon holds,
and republishing is incremental rather than a full resend."

Tests: 4 new unit tests in `lr-bgp/src/advertise_tests.rs` cover
`advertise_bgpls` / `withdraw_bgpls` (positive round-trip through
the BGP UPDATE codec, family-gating for peers without BGP-LS, empty
input). 2 new tests in `lr-router/src/instance/tests.rs` cover
`DefaultRouter::bgpls_republish` (the integration of projection +
diff + egress; a no-op for unknown areas). 3 new e2e tests in
`lr-cli/tests/daemon_bgpls.rs` cover the daemon: the `--bgp-ls`
flag negotiates the BGP-LS family alongside IPv4 unicast without
breaking the latter, the startup banner reports the new knob, and
`--bgp-ls-area` accepts the dotted-quad form. The interop lab
SKIPS cleanly when BIRD is unavailable. `cargo test --workspace
--all-features` green; `cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets --all-features -- -D
warnings` clean; `tests/lint_docs.sh` and
`tests/lint_interop_doc.sh` clean.

Public Rust API surface (Tier 1) is additive only — new
`BgpPeer::advertise_bgpls` / `withdraw_bgpls` methods
(feature-gated), new `DefaultRouter::bgpls_republish` /
`ospf_area_ids` methods. The C ABI (Tier 2) is unchanged; the new
types are Rust-only. The daemon flag and config surface (Tier 3)
gains `--bgp-ls`, `--bgp-ls-as`, `--bgp-ls-id`, `--bgp-ls-area`
flags and a `[bgp_ls]` TOML/DSL block; no existing flag is renamed
or removed.

[`BgpPeer::advertise_bgpls`]: https://github.com/TES286-org/librouting/blob/main/crates/lr-bgp/src/advertise.rs
[`DefaultRouter::bgpls_republish`]: https://github.com/TES286-org/librouting/blob/main/crates/lr-router/src/instance/mod.rs

**BGP-LS Attribute TLV codec** (`feat`, [issue #60](https://github.com/TES286-org/librouting/issues/60)).
A new `lr-bgp::path::bgp_ls_attr` module (feature-gated as
`lr-bgp/bgp_ls`, on by default) parses and serialises the BGP-LS
Attribute (RFC 7752 §3.3, BGP path attribute type 29 per the IANA
"BGP Path Attributes" sub-registry). The attribute value is a TLV
stream sharing the same 4-byte TLV framing as the BGP-LS NLRI codec
(RFC 7752 §3.1: 16-bit Type, 16-bit Length, variable Value). It is
the explicit follow-up the previous comment on issue #60 calls out:
the codec surface the End.X / LAN End.X projection update will
attach the SRv6 Endpoint Behavior TLV to a projected End.X SID
NLRI.

TLVs modelled:

- RFC 7752 §3.3.1 Node Attribute TLVs: Node Flag Bits (1024),
  Opaque Node Attribute (1025), Node Name (1026), IS-IS Area
  Identifier (1027), IPv4/IPv6 Router-ID of Local Node (1028/1029).
- RFC 9514 §3.1: SRv6 Capabilities TLV (1038, 4-byte value).
- RFC 7752 §3.3.2 Link Attribute TLVs (selected): Admin Group
  (1088), Max Link Bandwidth (1089), Max Reservable Bandwidth
  (1090), Unreserved Bandwidth (1091), TE Default Metric (1092),
  Link Protection Type (1093), MPLS Metric (1094), Shared Risk
  Link Group (1095), IGP Metric (1114).
- RFC 9514 §4.1/§4.2: SRv6 End.X SID TLV (1106), IS-IS SRv6 LAN
  End.X SID TLV (1107), OSPFv3 SRv6 LAN End.X SID TLV (1108) —
  variable-length with optional sub-TLVs preserved verbatim.
- RFC 7752 §3.3.3 Prefix Attribute TLVs (selected): IGP Flags
  (1150), IGP Route Tag (1151), Prefix Metric (1152), Forwarding
  Address Prefix (1153), Opaque Prefix Attribute (1154), Prefix
  Attribute Flags (1155).
- RFC 9514 §5.1: SRv6 Locator TLV (1162, variable length).
- RFC 9514 §7.1: SRv6 Endpoint Behavior TLV (1250, 4-byte value —
  2-byte endpoint behavior + 1-byte flags + 1-byte algorithm).
- RFC 9514 §7.2: SRv6 BGP PeerNode SID TLV (1251, 12-byte value).
- RFC 9514 §8: SRv6 SID Structure TLV (1252, 4-byte value — four
  1-byte length fields, sum <= 128 enforced on decode per RFC
  9514 §8).

Unknown TLVs are preserved verbatim via `BgpLsAttrTlv::Unknown` so
any well-formed attribute round-trips byte-for-byte — the same
contract the NLRI codec in `path::bgp_ls` enforces. A
wrong-length well-known TLV falls through to `Unknown` rather
than silently dropping bytes. `Srv6EndpointBehavior` surfaces
the RFC 8986 §10.2 IANA "SRv6 Endpoint Behaviors" values the
projection needs to distinguish End from End.X / End.T /
End.DX* (and the `Unknown(u16)` variant preserves unrecognised
code points).

A new `BgpPeer::advertise_bgpls_with_attr(added, attr)` method
attaches the BGP-LS Attribute (path attribute type 29, optional
+ non-transitive per RFC 7752 §3.3) alongside the MP_REACH_NLRI in
the same UPDATE so the receiver learns the link-state metadata
for each NLRI. This is the path the End.X projection follow-up
will use to attach the RFC 9514 §7 SRv6 Endpoint Behavior TLV to
a projected End.X NLRI.

A new cargo-fuzz target `bgp_ls_attr_decode` mirrors
`bgp_ls_decode`: the target feeds arbitrary bytes to
`BgpLsAttr::decode` and asserts the re-encoded bytes match the
input slice for any input the codec accepts. The seed corpus
under `fuzz/seeds/bgp_ls_attr_decode/` covers every modelled TLV
variant plus the malformed-length and overflow paths that fall
through to the `Unknown` passthrough. A unit-test smoke pass
asserts the seed corpus round-trips through the codec
byte-for-byte in the regular `cargo test --workspace` gate so a
regression on the seed corpus shows up without a cargo-fuzz run.

Tests: 32 unit tests in `path::bgp_ls_attr::tests` cover every
variant's wire bytes, the round-trip property through
`BgpLsAttr::encode`/`decode`, the RFC 9514 §8 sum-of-lengths
boundary, the unknown-TLV and wrong-length passthrough paths, the
helper accessors, and the SRv6 Endpoint Behavior IANA code points.
4 new egress tests in `advertise_tests.rs` cover
`advertise_bgpls_with_attr` (positive round-trip through the BGP
UPDATE codec, family gating for peers without BGP-LS, empty-NLRI
no-op, empty-attribute no-op). `cargo test -p lr-bgp --all-features`
-> 336/336 pass.

Public Rust API surface (Tier 1) is additive only — new
`path::bgp_ls_attr` module, new `AttrType::BgpLsAttribute` enum
variant, new `BgpPeer::advertise_bgpls_with_attr` method. The
existing `AttrType::TrafficEngineering = 24` is left untouched
for API stability (the value predates this change and has no
callers; the BGP-LS Attribute type code per RFC 7752 §13 is 29,
not 24). The C ABI (Tier 2) is unchanged; the new types are
Rust-only. The daemon / config surface (Tier 3) is unchanged.

The End.X / LAN End.X SID *projection* update (attaching the
§7 SRv6 Endpoint Behavior TLV to a projected End.X NLRI through
`BgpPeer::advertise_bgpls_with_attr`) is the next follow-up —
the codec is the foundation, the projection update touches the
`lsdb_to_bgpls` module and is tracked separately.

**OSPFv3 SRv6 End.X / LAN End.X projection with attribute** (`feat`,
[issue #60](https://github.com/TES286-org/librouting/issues/60)).
The follow-up the previous entry called out: a new
`lr-router::instance::lsdb_to_bgpls::project_v3_srv6_end_x_nlris`
function projects the OSPFv3 SRv6 End.X / LAN End.X SID database
(RFC 9513 §9) onto RFC 9514 §6 SRv6 SID NLRIs paired with the
BGP-LS Attribute (RFC 7752 §3.3 + RFC 9514 §7-§8) that carries
the SRv6 Endpoint Behavior TLV a controller needs to distinguish
an End.X SID from an End SID. The projection walks the same
`Srv6Database::nodes` the End SID projection walks; for each
`Srv6Node::end_x_sids` entry (RFC 9513 §9.1 p2p form and §9.2 LAN
form, gated on §9 locator containment and §9.2 neighbor match),
it emits one `(BgpLsNlri, BgpLsAttr)` pair. The NLRI shape is
identical to the End SID projection — RFC 9514 §6 carries the
16-byte SID value; the End.X behavior lives in the attribute, not
in the NLRI. The attribute carries the mandatory RFC 9514 §7.1
SRv6 Endpoint Behavior TLV (type 1250, with the behavior, flags
and algorithm from the OSPFv3 End.X sub-TLV) and the optional §8
SRv6 SID Structure TLV (type 1252, with the four length fields
passed through verbatim when the OSPFv3 §10 sub-TLV provided the
SID-structure split). Unknown behaviors round-trip through
`Srv6EndpointBehavior::Unknown(u16)` so a controller that
recognises a newer RFC 8986 §10.2 code point still learns the
behavior.

A new `diff_bgpls_with_attrs` helper computes the added / removed
/ updated / unchanged pair sets between two projections. Indexes
both projections by the encoded NLRI bytes — the NLRI is the route
identity, the attribute is the metadata. Equal NLRI bytes with
differing attribute bytes surface as `updated` (re-advertise with
the new attribute — RFC 4271 §9.2.1.2 permits attribute updates
without MP_UNREACH_NLRI).

A new `DefaultRouter::bgpls_republish_end_x` method drives the
incremental republish: projects the area LSDB through
`project_v3_srv6_end_x_nlris`, diffs against the caller's previous
projection, and pushes UPDATEs to every BGP session that
negotiated the BGP-LS family — `added` and `updated` pairs ride
an MP_REACH_NLRI + BGP-LS Attribute via
`BgpPeer::advertise_bgpls_with_attr` (one UPDATE per pair since
each End.X NLRI has its own attribute — RFC 7752 §3.3 does not
key the BGP-LS Attribute on individual NLRIs in one UPDATE);
`removed` NLRIs ride a single MP_UNREACH_NLRI via
`BgpPeer::withdraw_bgpls`. The `BgplsDriver` in `lr-cli::daemon`
calls both `bgpls_republish` and `bgpls_republish_end_x` per
tick on every configured OSPF area; the per-area cache holds
the plain NLRI baseline and the End.X pair baseline side by
side so a topology bump that touches only one projection does
not double-send the other.

Additive only — no breaking changes.

- **Public Rust API (Tier 1)**: new
  `lsdb_to_bgpls::project_v3_srv6_end_x_nlris`,
  `lsdb_to_bgpls::diff_bgpls_with_attrs`,
  `lsdb_to_bgpls::BgplsAttrDiff`,
  `DefaultRouter::bgpls_republish_end_x`. No existing signature
  changes.
- **C ABI (Tier 2)**: unchanged; the new types are Rust-only.
- **Daemon / config surface (Tier 3)**: unchanged.

18 new unit tests cover the projection (End.X and LAN End.X shapes,
the §9 locator containment gate, the §7.1 behavior attribute, the
§8 SID Structure TLV, unknown behavior round-trip, multiple routers)
and the diff function (added / removed / unchanged / updated). 3
new integration tests in `lr-router/src/instance/tests.rs` cover
`bgpls_republish_end_x` (positive push to a BGP-LS session, no-op
for an OSPFv2 area, no-op for an unknown area). `cargo test -p
lr-router --all-features` → 171/171 pass. `cargo fmt --all --
--check` and `cargo clippy --workspace --all-targets --all-features
-- -D warnings` clean.

**Egress Peer Engineering codec (RFC 9086)** (`feat`, [issue #60](https://github.com/TES286-org/librouting/issues/60)).
The BGP-LS Attribute codec in `lr-bgp::path::bgp_ls_attr` now models
the three SR-MPLS BGP Peering SID TLVs from RFC 9086 §5 — PeerNode SID
(type 1101), PeerAdj SID (type 1102) and PeerSet SID (type 1103). All
three share a single `BgpPeeringSid` shape: a 1-byte flags field
(`BgpPeeringSidFlags` with the V/L/B/P bit constants from RFC 9086 §5
plus a `from_raw` / `raw` accessor pair that preserves reserved bits
for byte-exact round-trip), a 1-byte weight, a 2-byte reserved field
(preserved verbatim so a re-encode round-trips even when an
originator violates the "MUST be zero on originate" constraint), and
a variable `BgpPeeringSidValue::Label([u8; 3])` / `Index(u32)` that
carries either a 3-byte local MPLS label (V flag set, length 7) or a
4-byte SRGB index (V flag clear, length 8). The codec accepts only
the RFC 9086 §5 length/V-flag combinations; an inconsistent
combination (length 7 with V flag clear, length 8 with V flag set,
or any other length) falls through to `BgpLsAttrTlv::Unknown` so the
stream still round-trips byte-for-byte.

The matching Node Descriptor sub-TLVs from RFC 9086 §3.1 / §3.2 are
modelled in `lr-bgp::path::bgp_ls::NodeDescriptorSubTlv`:
`BgpRouterId(u32)` (TLV 516, the BGP Identifier from RFC 6286 §4) and
`BgpConfederationMember(u32)` (TLV 517, the Member-AS Number from
RFC 5065 §4). Both carry the 4-byte unsigned integer shape the base
RFC 7752 fixed-width descriptors use; both are surfaced on
`NodeDescriptor` via the `bgp_router_id()` and
`bgp_confederation_member()` accessors, alongside the existing
`as_number()`, `bgp_ls_id()`, `ospf_area_id()` and `igp_router_id()`
accessors. A BGP-LS Link NLRI whose Protocol-ID is `Bgp` (RFC 9086
§3, the new BGP-LS Protocol-ID for EPE) now round-trips byte-for-byte
end-to-end.

Tests: 13 new unit tests (5 in `bgp_ls_tests.rs` covering the Node
Descriptor sub-TLVs in isolation and inside a full BGP-LS Link NLRI;
8 in `bgp_ls_attr_tests.rs` covering each Peering SID form, flag bit,
non-zero reserved preservation, the inconsistent-V-flag fall-through,
the wrong-length fall-through, and a BGP-LS Attribute with all three
EPE TLVs at once). 6 new fuzz seed corpus entries under
`fuzz/seeds/bgp_ls_attr_decode/` — `peer_node_sid_label.bin`,
`peer_adj_sid_index.bin`, `peer_set_sid_label.bin`,
`peer_node_sid_inconsistent_v.bin`, `peer_adj_sid_wrong_length.bin`,
`peering_sid_nonzero_reserved.bin` — extend the smoke
`seed_corpus_round_trips` test (the `cargo +nightly fuzz run
bgp_ls_attr_decode` target inherits the new seeds automatically).
`cargo test -p lr-bgp --all-features` → 370/370 pass.

Stability: additive only — no breaking changes. The new types are
Rust-only; the C ABI (`lr-ffi`) is unchanged. Daemon / config
surface is unchanged — this PR lands the *codec* the daemon-side
EPE projection will call; the projection itself (walking the
daemon's BGP peer sessions and emitting BGP-LS Link NLRIs with the
PeerNode/PeerAdj/PeerSet SID attributes attached) is the natural
follow-up and is tracked under the "Egress Peer Engineering
(RFC 9086)" entry in `docs/ROADMAP.md`.

First-hand references used: RFC 9086 §3.1 / §3.2 (Node Descriptor
sub-TLVs), §5 (BGP Peering SID TLV shape), §5.1 / §5.2 / §5.3
(per-TLV semantics); RFC 6286 §4 (BGP Identifier), RFC 5065 §4
(Member-AS Number), RFC 8402 (BGP Peering Segments — PeerNode,
PeerAdj, PeerSet definitions); the IANA BGP-LS NLRI Types and
BGP-LS NLRI/Attribute TLVs registries (Protocol-ID 7 = BGP, TLV
516/517/1101/1102/1103).

**Egress Peer Engineering daemon-side projection (RFC 9086)** (`feat`, [issue #60](https://github.com/TES286-org/librouting/issues/60)).
The natural follow-up the EPE codec PR above names in its
scope-boundary section: a new `lr-router::instance::epe` module
walks a snapshot of the daemon's BGP peer sessions and emits one
BGP-LS Link NLRI per Established session, paired with a BGP-LS
Attribute that carries the PeerNode SID (RFC 9086 §5.1, mandatory)
and any optional PeerAdj / PeerSet SIDs the caller supplied.

Each emitted NLRI is a BGP-LS Link NLRI (RFC 7752 §3.3 NLRI Type 2)
with `ProtocolId::Bgp` (RFC 9086 §3, the BGP-LS Protocol-ID for EPE)
and `identifier = 0`. The Local Node Descriptor carries the
Autonomous System (TLV 512), the daemon's BGP-LS Identifier (TLV
513, from the `[bgp_ls]` config block), the BGP Router-ID (TLV 516,
the local BGP Identifier), and the BGP Confederation Member sub-TLV
(TLV 517) when the local speaker is itself a confederation member.
The Remote Node Descriptor carries the peer's AS and BGP Router-ID
(both learned in OPEN); the remote's BGP-LS ID is opaque to us, so
it rides `0` — matching BIRD's `bgp_ls` channel. The Link Descriptor
always carries `MultiTopologyId(0)` (TLV 263); the IPv4 / IPv6
Interface Address (TLV 259 / 261) and Neighbor Address (TLV 260 /
262) sub-TLVs are added when the caller supplied the corresponding
interface addresses.

`DefaultRouter::bgpls_republish_epe` mirrors
`bgpls_republish_end_x`: it snapshots the live BGP session set
through the new `epe_peer_sessions_snapshot` helper, projects it
through `epe::project_epe_peer_sessions`, diffs against `prev` via
`lsdb_to_bgpls::diff_bgpls_with_attrs`, and pushes UPDATEs to
every BGP session that negotiated the BGP-LS family. `added` pairs
ride MP_REACH_NLRI + BGP-LS Attribute (one UPDATE per pair, since
each EPE NLRI carries its own attribute — same model the End.X
projection uses for SRv6 End.X SIDs); `removed` NLRIs ride a single
MP_UNREACH_NLRI; `updated` pairs ride MP_REACH_NLRI + BGP-LS
Attribute (RFC 4271 §9.2.1.2 permits attribute updates without a
withdraw).

`DefaultRouter::bgp_session_identity_hash` is a cheap FNV-1a hash
of every BGP session's `(handle, established, peer_bgp_id, peer_as)`
tuple, in BTreeMap iteration order. The daemon ticker polls this
once per tick and re-projects the EPE NLRI set only when it
changes — saves a per-tick full projection when the session table
is stable. Non-BGP sessions (OSPF, Babel) contribute nothing to
the hash, so an OSPF adjacency churn does not spuriously re-project.

The `BgplsDriver` ticker in `lr-cli::daemon` now runs the EPE
projection after the existing OSPF area walk. The driver gains
two new fields: `epe_pairs` (the last projected
`(BgpLsNlri, BgpLsAttr)` pair set, mirroring the per-area
`end_x_pairs` cache) and `epe_session_hash` (the last seen
identity hash). A successful republish logs
`bgp-ls epe republish: +N -N ^N ~N` matching the existing
`bgp-ls republish area ...` line shape.

The PeerNode SID value the projection emits is a deterministic
per-session placeholder: `V = 0` (SRGB index form), `L = 0`, `B =
0`, `P = 0`, weight 0, reserved 0, SRGB index = `session_handle as
u32`. The placeholder is chosen over the label form (`V = 1`)
because lr does not yet own an SR-MPLS label allocation surface, so
emitting a label would imply a forwarding-plane contract the daemon
does not yet honour. Operator-configurable SID values are the next
follow-up; they do not change the projection shape or this wiring.

Tests: 14 new unit tests in `epe_tests.rs` cover the projection
(empty input, one session, Local / Remote Node Descriptor sub-TLVs,
confederation member sub-TLVs, MT-ID 0, IPv4 / IPv6 Interface /
Neighbor Address sub-TLVs, attribute carrying PeerNode SID alone or
with PeerAdj / PeerSet, multiple sessions in input order,
byte-for-byte round-trip on the full EPE shape, index-form SID
round-trip). 5 integration tests in `instance::tests` cover the
wiring (republish pushes the projected NLRIs to the BGP-LS session;
non-BGP-LS session sees nothing; no BGP-LS session = empty diff
but baseline still advances; no Established session = empty diff;
`bgp_session_identity_hash` changes on established transition and
ignores non-BGP sessions). `cargo nextest run -p lr-router
--features lr-bgp/bgp_ls` → 716/716 pass (was 700, +16 new tests).
`cargo clippy --workspace --all-features --all-targets -- -D
warnings` clean. `cargo fmt --all -- --check` clean.

Stability: additive only — no breaking changes. The new types are
Rust-only; the C ABI (`lr-ffi`) is unchanged. Daemon / config
surface is unchanged — the EPE projection is on whenever
`[bgp_ls]` is enabled; no new CLI flag or TOML key. The
operator-configurable SID surface is a follow-up.

First-hand references used: RFC 9086 §3 (Link NLRI shape for EPE),
§3.1 (BGP Router-ID sub-TLV type 516), §3.2 (Member-AS sub-TLV type
517), §5 (BGP Peering SID shape), §5.1 (PeerNode SID mandatory),
§5.2 (PeerAdj SID), §5.3 (PeerSet SID); RFC 7752 §3.2.1.4 (Node
Descriptor sub-TLV framing), §3.2.2 (Link Descriptor sub-TLVs),
§3.3 (NLRI Type 2 Link); RFC 5065 §4 (Member-AS Number); RFC 6286
§4 (BGP Identifier); RFC 6119 §4.2 / §4.3 (IPv6 Interface /
Neighbor Address TLVs).

### Changed (CI)

**RISC-V CI matrix** (`ci`, [issue #65](https://github.com/TES286-org/librouting/issues/65)).
The CI workflow in `.github/workflows/ci.yml` now covers the RISC-V
architecture in two ways. The existing `cross` matrix job gains
`riscv64gc-unknown-linux-gnu` alongside `aarch64-unknown-linux-gnu`
and `x86_64-pc-windows-gnu`: the apt install step pulls in
`gcc-riscv64-linux-gnu` + `libc6-dev-riscv64-cross`, the
per-target linker env block gains
`CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc`,
and `cargo build --workspace --target riscv64gc-unknown-linux-gnu
--all-features` runs on every push. This is the safety net: even on
a fork where the RISE GitHub App is not installed, the cross-build
still produces an riscv64 linkable artifact on a plain `ubuntu-latest`
runner.

A new `riscv-native` job runs on `ubuntu-24.04-riscv` — the RISE
Project's Scaleway EM-RV1 pool, free for OSS,
<https://riscv-runners.riseproject.dev/>. It mirrors the existing
`unit-tests` job: `cargo clippy --workspace --all-features
--all-targets -- -D warnings`, `cargo build --workspace --all-features`,
`cargo nextest run --workspace --all-features`, `cargo test --doc
--workspace --all-features`. clippy runs per-arch for the same reason
the `cross-platform` matrix runs it per-OS: arch-conditional code only
compiles on its own architecture, so a per-arch lint pass catches
future regressions the x86_64-only `lint` job would miss. fmt is NOT
re-run; rustfmt is deterministic and platform-independent, and the
`lint` job already gates it on every push.

The workspace is target-OS-aware, not target-arch-aware: `lr-osroute`
selects its Linux rtnetlink backend under `target_os = "linux"`, and
the socket constants, struct layouts and syscall numbers are identical
across x86_64, aarch64 and riscv64 (verified locally by `cargo build
-p lr-osroute --target riscv64gc-unknown-linux-gnu --all-features`).
The kernel-gated `#[ignore]`d tests (`route_kernel`, `srv6_kernel`)
self-skip when they lack `CAP_NET_ADMIN`, so the same `nextest`
command runs unchanged on riscv64.

If the RISE App is not installed on the repository, GitHub marks the
`riscv-native` job "no runner found" after the timeout — it never
blocks merge. The `cross` matrix entry covers the gap until the App
is installed.

A side-effect: the doc comments in `lr-osroute::gtsm` and
`lr-osroute::tcp_auth` previously enumerated only x86_64 and aarch64
when describing the Linux UAPI surface; both now mention riscv64
explicitly. No code change — the constants were already correct on
riscv64.

### Added (release artifacts)

**RISC-V release archive** (`release`, [issue #65](https://github.com/TES286-org/librouting/issues/65)).
The release workflow in `.github/workflows/release.yml` ships a
fifth platform archive — `librouting-linux-riscv64gc.tar.gz` — built
natively on the RISE Project's `ubuntu-24.04-riscv` runner. The
archive carries the same shape as the other Linux entry:
`liblr_ffi.so`, `liblr_ffi.a` (where emitted), `lr`, `lr-daemon`,
`lrctl`, and the `include/lr_ffi.h` + `include/librouting.hpp`
pair. A native build is preferred over a cross-build for release
artifacts because the riscv64 target has no cross-validated
release-link path in this repo yet — the `riscv-native` CI job
proves the native build works end-to-end on every push, so the
release path rides on the same guarantee.

The `build-native` job now carries an explicit `timeout-minutes: 120`
ceiling. The RISC-V native release build (LTO + codegen-units=1 +
opt-level=3) is the slowest matrix entry — RISC-V hardware is
roughly 3-5x slower than x86_64 for compute-heavy compilation, and
the existing x86_64/macOS/Windows entries finish in ~15-20 min
each. 120 min gives the RISC-V entry ~6x slack over the x86_64
baseline; the faster entries are unaffected by a higher ceiling.

If the RISE GitHub App is not installed on the repository, this
matrix entry fails the release workflow with "no runner found";
install the App (<https://github.com/apps/rise-risc-v-runners>)
before tagging. The release body in `release.yml` now enumerates
"Linux (x86_64 and RISC-V), macOS (Intel and Apple Silicon) and
Windows" to match the new matrix.

`docs/RELEASE-PLAN.md` §3.2 (Build matrix) is updated to record
the RISC-V entry and its App-installation requirement.

### Changed (CI)

**RISC-V interop smoke tests** (`ci`, [issue #65](https://github.com/TES286-org/librouting/issues/65)).
The `riscv-native` CI job now runs two lr-vs-lr loopback interop
labs as architecture smoke tests, in addition to the existing
clippy / build / nextest / doctest quartet:

- `tests/interop/two_daemon.sh` — two lr-daemons on loopback TCP,
  BGP OPEN/KEEPALIVE/UPDATE exchange, route install + withdrawal
  on session loss.
- `tests/interop/labeled_unicast.sh` — RFC 8277 labelled-unicast
  (AFI=1, SAFI=4) route exchange between two lr-daemons, exercising
  the MPLS label-stack path end-to-end.

These are the same two scripts the `windows-interop` and
`macos-interop` jobs already run, so the non-x86_64 coverage shape
stays consistent. Both are pure TCP on `127.0.0.1`, need no
privileges and no external daemons — the only system dependency is
`bash`, which Ubuntu 24.04 RISC-V ships by default. Each finishes
in ~30 s on x86_64 (~1-2 min on RISC-V hardware).

The full BIRD/FRR interop suite is deliberately NOT run on the
RISC-V runner: RISC-V hardware is roughly 3-5x slower than x86_64
for compute-heavy work, and installing `bird2` + `frr` from apt
adds minutes of package setup alone. The heavier labs (BIRD, FRR,
kernel-route install, network namespaces) stay on the `interop`
job. The two smoke labs are enough to verify the daemon binary
actually exchanges BGP routes end-to-end on `riscv64gc`, not just
that it compiles — closing the gap between "the build is green"
and "the daemon works on this architecture."

`docs/INTEROP.md` (Where the labs run) gains a `riscv-native` row
and the surrounding paragraph is updated to explain the
deliberately small subset.

## [1.2.0] — minor: operational visibility, ROA listing, session operations

librouting 1.2.0 is a minor release: new public Rust API surface and
new runtime API / `lrctl` commands for operational visibility (issue
#52), ROA table listing (ROADMAP "lrctl roa list"), and fine-grained
session operations (issue #52 follow-up). The C ABI surface is
unchanged — the new types and methods are Rust-only; the `--api-socket`
line protocol additions are additive (new commands, no changes to
existing ones).

### Added

**BIRD-style operational visibility** (`feat`, [issue #52](https://github.com/TES286-org/librouting/issues/52)).
A new `SessionStats` struct carried on every `SessionState` variant
(BGP / OSPF / Babel), surfaced through `SessionSummary.stats`:
`established_at_ms`, `last_transition_at_ms`, `state_transitions`
(monotonic), `last_error` kind + timestamp, and
`last_keepalive_received_ms` (the "peer response speed" health metric).
A new `SessionErrorKind` enum (`None` / `NotificationReceived` /
`TransportClosed` / `HoldTimerExpired` / `ParseError` / `Manual` /
`Other`) classifies the most recent close cause.

The runtime API gains a BIRD-style `show …` family that mirrors the
console operators expect from BIRD/FRR:

  show status               extended summary (per-protocol session
                            counts, memory RSS/vsize)
  show sessions [detail]    per-session stats (transitions=, uptime-ms=,
                            last-error=, last-keepalive-rx-ms=, ...)
  show session <handle>     deep dive for one session
  show routes count         Loc-RIB grouped by protocol
  show memory               process RSS and virtual size

`lrctl` proxies each sub-command; `lrctl show` (no sub) maps to
`show status` (BIRD shortcut). Both Unix and Windows
`serve_connection` paths render identically.

**ROA table listing** (`feat`, ROADMAP "lrctl roa list",
[issue #52](https://github.com/TES286-org/librouting/issues/52)
follow-up).
`lrctl roa list` and `lrctl roa count` dump the merged ROA table
(static `[[roa]]` config layer + live RFC 8210 RTR cache, deduplicated)
with per-entry provenance (`source static` / `source rtr` / `source both`).
A new `RoaProvenance` enum and `RoaStore::provenance_of(&entry)` method
expose per-entry layer membership; the renderer lives in
`crates/lr-cli/src/roa_view.rs` and is shared by the Unix and Windows
API paths.

**Write-side fine-grained session operations** (`feat`,
[issue #52](https://github.com/TES286-org/librouting/issues/52)
follow-up).
`lrctl session <handle> soft-in` (FRR `clear ip bgp * soft in`) and
`lrctl session <handle> refresh-in [family]` (RFC 2918 route-refresh)
expose the router core's `soft_reconfig_inbound(h)` and
`request_route_refresh(h, family)` through the runtime API. Recognised
family names: `ipv4-unicast`, `ipv6-unicast`, `ipv4-multicast`,
`ipv4-mpls-vpn`, `ipv6-mpls-vpn`, `ipv4-labeled-unicast`,
`ipv6-labeled-unicast`.

**Daemon-wide graceful drain shutdown** (`feat`, [issue #53](https://github.com/TES286-org/librouting/issues/53)).
A new shutdown mode that minimises the network-wide update rate
during a maintenance exit: stop accepting new routes, withdraw the
locally-originated routes at a rate-limited pace, then exit when the
queue is empty or the deadline elapses. Configured through a new
`[shutdown]` block (`mode = "immediate"` (default, historical) or
`mode = "drain"`, `drain_rate_per_sec = 50`, `drain_max_wait_secs =
600`) or the equivalent `--shutdown-mode`, `--shutdown-drain-rate`,
`--shutdown-drain-max-wait` CLI flags. Triggered on a live daemon
through `lrctl shutdown drain` (or the runtime API `shutdown drain`
command); `lrctl shutdown status` polls the lifecycle
(`running | draining | drained`); `lrctl shutdown abort` cancels a
drain in progress (best-effort — the worker notices on its next
iteration, mirroring the POSIX signal contract).

The drain is implemented as a state machine (`ShutdownController` in
`crates/lr-cli/src/shutdown.rs`) running on its own thread. A new
`DrainModeImportHook` (`crates/lr-policy/src/hooks.rs`) is installed
at the front of the import chain so every inbound UPDATE is dropped
while the drain is in progress — the "stop accepting new routes"
step. The worker then walks the Loc-RIB's static, originated and
aggregate routes, calling the existing `RouterInstance` withdrawal
APIs at the configured rate, then tears down every session with
`shutdown_session` (RFC 4486 §4.1 Administrative Shutdown) before
flipping `running` to false. Three new methods on `RouterInstance`
expose the queue snapshots the worker needs:
`originated_keys()`, `aggregate_prefixes()` (alongside the existing
`static_routes()`). The C ABI surface is unchanged — the new
methods are Rust-only and the drain controller lives in `lr-cli`
(daemon-level concern, not router-instance level).

The drain is wired into every daemon mode: BGP standalone, the
multi-protocol supervisor, and the standalone OSPF / OSPFv3 / LDP
engines. The runtime API dispatch is identical on Unix and Windows
(named pipes mirror the Unix domain socket path verbatim), so
`lrctl shutdown drain|status|abort` works on both platforms. The
mechanism is orthogonal to the existing RFC 8326 community-based
graceful-shutdown hooks (which de-preference per-peer LOCAL_PREF on
tagged routes): RFC 8326 governs one session's maintenance posture;
the drain governs the whole daemon's exit posture. Five e2e tests in
`crates/lr-cli/tests/daemon_graceful_drain.rs` exercise the
running → draining → drained transition through the real
`lr-daemon` binary, the immediate-mode refusal, the abort path,
and the standalone LDP engine's drain mode.

### Fixed

- **Cross-platform drain fix** (`fix`, [issue #53](https://github.com/TES286-org/librouting/issues/53)):
  Windows `Option<Arc>` clone, macOS `lo0` loopback interface name,
  Windows named-pipe `ERROR_NO_DATA` treated as EOF, drain-worker
  race closed by flipping `running=false` before `state=Drained`.
- **macOS/Windows dead-code fix** (`fix`, [issue #52](https://github.com/TES286-org/librouting/issues/52)):
  `parse_kb` gated on `target_os="linux"` to clear `dead_code` lint
  on macOS and Windows under `RUSTFLAGS=-D warnings`.
- **macOS socket path length** (`fix`): shortened `show roa` test
  temp dirs to fit macOS `SUN_LEN` (104 bytes).

## [1.1.1] — patch: metrics portability fix and source-file modularisation

librouting 1.1.1 is a patch release: a bug fix that makes the metrics
endpoint work on Windows ([issue #47](https://github.com/TES286-org/librouting/issues/47))
and a no-API-change refactor that splits the workspace's largest source
files into per-protocol submodules ([issue #48](https://github.com/TES286-org/librouting/issues/48)).
No public Rust API or C ABI symbol changed shape, so the bump is patch
per [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md) §1.

### Changed

**Source-file modularisation** (`refactor`, [issue #48](https://github.com/TES286-org/librouting/issues/48)).
The largest source files in the workspace had grown to the point where
their inline test modules dwarfed the production code — `instance.rs`
was 12 951 lines with 4 600 of tests, `daemon.rs` was 7 621 lines with
924 of tests, and the same pattern repeated across every protocol
crate. The test modules are now sibling files (`<name>_tests.rs`)
included via `#[cfg(test)] #[path = "..."] mod NAME;`, so the module
hierarchy and every public path — the crate re-exports, the C ABI
header, the FFI surface — are unchanged. A file that needs to be read
for its production logic can now be read without scrolling past four
thousand lines of assertions first. Forty-six source files were split
this way; the largest production file, `instance/mod.rs`, was further
broken into `instance/ospf.rs`, `instance/babel.rs` and
`instance/ospf_ops.rs` using Rust's inherent-impl-in-any-module rule —
no field visibility changes needed. Every one of the 2 047 workspace
tests still passes, and `cargo fmt`, `cargo clippy -- -D warnings`, the
C/C++/Go/Python binding tests, and the documentation linters are
clean.

### Fixed

**Metrics endpoint works on every supported target** (`fix(cli)`,
[issue #47](https://github.com/TES286-org/librouting/issues/47)). The
Prometheus `/metrics` HTTP server is a plain `std::net::TcpListener`
responder, so it never needed the `#[cfg(unix)]` guard that wrapped its
implementation — and the misleading "metrics endpoint requires Unix
domain socket support" error it returned on Windows was a bug, not an
intentional stance. The guard and the refusal module are gone; the
server now compiles and serves identically on Linux, the BSDs, macOS
and Windows. The daemon's process model (signals, privilege drop,
named-pipe API transport) keeps its own per-platform guards; the
metrics endpoint does not. The `daemon_metrics.rs` integration suite
loses its `#![cfg(unix)]` filter for the same reason — its tests use
only `std::net::TcpStream` and `Command`, both portable — and a new
in-crate test exercises `spawn` directly so a target without the
daemon binary still gets the regression signal.

## [1.1.0] — configuration and logging overhaul

librouting 1.1.0 ships the configuration and logging surface asked for
in [issue #46](https://github.com/TES286-org/librouting/issues/46):
categorised diagnostic logging, granular safety-net overrides, and
cross-filter reusable function definitions. All three are additive —
no public Rust API or C ABI symbol changed shape — so the bump is
minor per [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md) §1.

### New features

**Categorised logging** (`feat(cli)`). The daemon's diagnostic output
now carries a severity (`error | warn | info | debug | trace`) and a
component (`bgp | ospf | ospfv3 | babel | ldp | bfd | bmp | rib |
policy | router | daemon | api | metrics | config | rpki | osroute |
interop`). The operator controls what lands where through the new
`[logging]` config section (TOML and DSL) and the `--log-level`,
`--log-target`, `--log-format`, `--log-color`, `--log-file` CLI flags.
Plain and JSON output formats are supported; the file destination
mirrors the console. The filter test is `severity <=
level_for(component)`, so a per-component override (`bgp=debug`) wins
over the global default. Every diagnostic `println!`/`eprintln!` call
in the daemon runtime has been migrated to the categorised `log_*!`
macros; the raw `println!`/`eprintln!` macros remain for operational
output (usage banner, startup summary, `status` reply) and
pre-logger-init error paths.

**Granular safety-net overrides** (`feat(policy)`). The
`lr_policy::SafetyConfig` struct gains four new fields (all
default-preserving):
- `enabled: bool` — global kill switch.
- `as_loop_exceptions: Vec<Asn>` — ASNs exempt from the AS_PATH loop
  checks.
- `martian_exceptions: Vec<Prefix>` — prefixes that bypass the martian
  check (a route is exempt when its prefix is contained in any entry).
- `reject_martian_v4: bool` / `reject_martian_v6: bool` — per-AFI
  martian toggle.
The daemon applies the operator's `[safety]` config section to the
router's `SafetyNet` at startup.

**Cross-filter reusable function definitions** (`feat(policy)`). A new
`[[filter_function]]` config table (TOML) / `filter-function` block
(DSL) declares functions callable from every filter and from every
other shared function — the BIRD top-level `function` analogue. The
daemon prepends the shared functions to each filter body before
compilation, so the existing per-filter `function` keyword and the
DSL parser's duplicate-name / shadow detection handle the validation.

### Fixes

- `fix(babel)`: enable `check-link` on the manual single-socket path
  (carrier-based withdrawal now works on the non-per-interface
  transport).
- `fix(tests)`: update interop script assertions for the categorised
  log format (7 scripts touched).

### Compatibility

**No breaking changes.** The C ABI (`lr_abi_version()`) stays at `2`;
the `abi-freeze` CI job confirms the header is additive-only relative
to the `v1.0.0` baseline. The new `SafetyConfig` fields are additive
(defaults preserve the prior behaviour). The new `[logging]`,
`[safety]`, and `[[filter_function]]` config sections are opt-in — a
1.0.0 config file loads and runs identically under 1.1.0.

## [1.0.0] — first stable release

librouting 1.0.0 is the first stable release. The public Rust API (Tier 1)
and the C ABI (Tier 2) enter their stability window: a breaking change to
either is a major-version bump, per [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md)
§1 and §4.1. The daemon flag and config surface (Tier 3) follows the
documented deprecation policy.

**Protocol coverage at parity with BIRD 2 and FRR 10** for everything in
scope — see [`docs/STATUS.md`](docs/STATUS.md) for the per-capability matrix
and [`docs/RFC_MAP.md`](docs/RFC_MAP.md) for the RFC-by-RFC table. BGP
(RFC 4271 + the extension family), OSPFv2/v3, Babel, LDP, BFD, BMP, MRT,
route flap damping, MPLS, SRv6, the RIB pipeline, the filter DSL, and the
OS integration backends (Linux / BSD / Windows) are all `yes`-status with
a test exercising them.

**Cross-vendor interop verified in CI** against BIRD 2 and FRR 10 in both
directions, plus the `lr parity-replay` wire-level harness — the
[`docs/INTEROP.md`](docs/INTEROP.md) matrix is the live `tests/interop/`
listing.

**Cross-platform CI green** on Linux, macOS (Apple Silicon + Intel
cross-build) and Windows (MSVC + GNU cross-build), at the MSRV (Rust
1.88).

**1.0.0 vs rc.6:** no header or symbol change. `lr_abi_version()` stays at
`2`; the abi-freeze baseline tag moves to `v1.0.0`. The only delta from
rc.6 is the version string (workspace + every crate + the Python
`__version__` + the `lrctl` header comment).

Out-of-scope items (BGPsec, NBMA and point-to-multipoint OSPF interface
types, OSPFv3 virtual links) are enumerated in
[`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md) §4.4; open work is in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## [1.0.0-rc.6] — pre-1.0 conformance cleanup

The sixth release candidate closes the pre-1.0 freeze gaps catalogued in
issue #41: the BGP confederation AS_PATH handling that RFC 5065 mandates,
the `MaxPrefixAction::Restart` cooldown the daemon documented but never
enforced, the `[ospf] area` config-file counterpart of `--ospf-area`, and
the C-ABI error-code surface that overloaded `-5` between a dead
`AbiMismatch` and the SRv6 codec.

**Breaking changes (pre-1.0 minor bumps, allowed within the rc window):**

- **BGP confederation AS_PATH (RFC 5065).** Egress now prepends the local
  sub-AS as an `AS_CONFED_SEQUENCE` to a confederation-external peer
  (§4.1(b)), strips `AS_CONFED_*` segments and substitutes the confederation
  identifier (§4 / §4.1(c)(1)) before the confederation boundary, and the
  ingress path rejects an `AS_PATH` carrying `AS_CONFED_*` from a peer that
  is not a member of the local confederation (§5). `ConfederationConfig`
  gains an explicit `confederation_id` field.
- **`MaxPrefixAction::Restart` cooldown.** `PeerConfig` gains
  `maximum_prefix_restart_time` (seconds); a `Restart` that trips arms a
  re-establishment gate the outbound connector respects
  (`RouterInstance::session_restart_cooldown_remaining`). `0` preserves the
  historical `Teardown`-equivalent behaviour. Plumbed through the daemon
  (`--max-prefix-restart-time`, `[bgp]` / `[[peer]]` keys) and the FFI
  `SessionConfig` builder.
- **FFI error codes.** `LrError::AbiMismatch` (`lr_core::FfiError::AbiMismatch`)
  is repurposed as `Codec` (`-5`); the SRv6 codec entry points return it by
  name and the C header gains `#define LR_ERR_CODEC (-5)`. `lr_abi_version()`
  is documented as the only ABI-compatibility surface. The numeric value is
  unchanged, so the documented C-ABI behaviour of the SRv6 functions is
  identical.

**Additive (non-breaking):**

- `[ospf] area = N` is the config-file counterpart of `--ospf-area`
  (issue #41 §5). Both write `cfg.ospf_area` through the shared
  `apply_ospf_key` dispatch.
- Corrected `RFC 8097` → `RFC 8092` (Large Communities) citations in the
  FFI policy-objects doc comments copied into `include/lr_ffi.h`.

The C ABI surface grows additively (`LR_ERR_CODEC` macro, accessor doc
comment); `lr_abi_version()` stays at `2` (no symbol/signature change).
The `abi-freeze` baseline tag moves to `v1.0.0-rc.6`.

## [1.0.0-rc.5] — production interop hardening + static-route ABI

The fifth release candidate is the production-hardening wave: almost
two hundred fixes and tests landed between rc.4 and this cut, almost
all of them driven by real deployments peering lr with BIRD 2 and
babeld over real tunnels and real Windows hosts. The headline fixes
are a Babel metric model that matches babeld/BIRD exactly (the link
cost is added at reception, never announced), IPv4 routes carried on
the IPv6 multicast transport (the shape every reference peer actually
listens on), RFC 8966 §4.5.2 omitted-octet prefix decompression,
§3.5.5 retraction emission when the last route of a family vanishes,
and a Windows kernel-mirror skip that keeps the BGP listener
reachable when the operator blackholes the host's own IP. The public
surface grows additively: static routes (`Router::install_static_v4/
_v6` + withdrawals) ship through the Rust API, the C ABI (four new
`lr_router_*_static_*` symbols, `lr_abi_version()` 1 → 2 — additive,
no existing symbol changed signature or semantics) and the Go,
Python and C++ bindings, all with lifecycle tests. 1987 tests pass
(was 1891 at rc.4); fmt + clippy `-D warnings` clean; the CI matrix
(Linux, macOS, Windows, BIRD + FRR interop, TCP-AO auth, MSRV,
coverage, cross-builds) and the Nightly (Miri, QEMU VM) are green on
this commit.

**Highlights since rc.4:**

- **Static routes through every embedding surface** —
  `Router::install_static_v4/_v6` / `uninstall_static_v4/_v6`
  (blackhole via NULL next hop, per-route metric + tag for
  redistribution pipes), the four-symbol C ABI addition with
  regenerated headers, and synced Go / Python / C++ bindings.
- **Babel metric parity with babeld + BIRD** — advertised metrics no
  longer double-count the announcing link; received Updates fold in
  the receiving session's cost; originated (redistributed) routes
  announce metric 0; until the peer's first IHU its Updates are not
  accepted (babeld parity).
- **IPv4-over-IPv6 babel transport** — v4 routes ride `ff02::1:6`
  with the interface's IPv4 address in a NextHop TLV (babeld shape),
  or RFC 9229 §2.4 AE 4 on v6-only links with `extended_next_hop`.
- **RFC 8966 wire-correctness** — §4.5.2 omitted-octet prefix
  compression reconstructed (BIRD's compressed Update trains decode
  byte-exactly now), §3.5.5 retraction carried whenever the last
  route of a family vanishes (independently of the announce demand),
  wildcard retractions log their real reason, infeasible updates no
  longer displace feasible routes, and the route hold floor rose to
  30 s (§3.2.5) to stop tunnel flapping.
- **Windows production hardening** — the source-bind suite
  (`IP_UNICAST_IF` pinning + retry), the bind-race fix, the
  Ctrl+C-shutdown FIB cleanup, the adapter-correct route
  installation (rc.4's wrong-adapter defect) and the static-blackhole
  / own-listener-IP skip that keeps the BGP listener reachable.
- **BGP session hygiene** — §6.8 collision loss is a backoff signal
  (not a hammering loop), collision resolution for outbound-only
  peers with a listener, RFC 4724 retention follows silent deaths
  only (BIRD parity), graceful close sends Cease / Admin-Shutdown,
  and the kernel-mirror installs static routes with their true
  protocol origin.
- **Kernel FIB interaction** — connected-route replacements are
  refused (they used to break the link's own gateway resolution),
  every installed route is withdrawn on shutdown, duplicate
  `RouteInstalled` events for identical OSPF/Babel re-installs are
  suppressed, and the SRv6 `seg6local` encap type is 7 (not 6 — the
  kernel dispatched the nested payload to the BPF parser before).

### Fixed (Windows — BGP listener dark when a static blackhole covers the own IP)

- **The kernel mirror now skips the blackhole install for prefixes the
  kernel already holds as connected (local-delivery) routes — typically
  the host's own interface addresses.** The operator idiom
  `static { route <own-ip>/32 next_hop "blackhole" }` exists to keep
  the /32 in BGP's Loc-RIB across interface flaps (so the address
  keeps being announced even when the underlying interface is briefly
  down); it is *not* a request to discard traffic to the host's own
  IP. On Windows the mirror was installing the static as a parallel
  `RouteProtocolNetMgmt` on-link row whose destination equaled an
  assigned interface address. The on-link row shadows the kernel's
  local-delivery route: inbound SYNs to the daemon's own BGP listener
  die as the blackhole's ARP-fail discard, the peer's outbound TCP
  never reaches the listener, and a bidirectional peer churns forever
  (every retry ends with a Cease / Connection Collision Resolution
  notification from the peer because the inbound side never established
  to compete in the §6.8 resolution). The mirror now detects the
  overlap via the FIB scan + interface enumeration and skips the
  kernel-side install with a `mirror: skipping blackhole install for
  <prefix> — kernel connected route covers it (own address)` log line.
  The /32 still enters the Loc-RIB (BGP export unchanged); the
  kernel's connected route already provides local delivery, so the
  parallel blackhole row was both redundant and harmful. Linux was
  unaffected (the local table wins preference over the main-table
  blackhole) but the skip is now also taken there for consistency and
  to keep the kernel FIB free of redundant discard rows. The
  `KernelMirror::connected` set is now seeded with the host's own
  interface addresses (host-scope /32 for v4, /128 for v6) in
  addition to the existing FIB scan, because Linux's `RTM_GETROUTE`
  with `RT_TABLE_MAIN` skips the local table (RTN_LOCAL rows live in
  table 255) — without the interface enumeration the skip would never
  fire on Linux. Reproduces with the new
  `static_blackhole_for_own_listener_ip_skips_kernel_install` test in
  `daemon_collision.rs` and the `bgp_blackhole_own_ip.sh` BIRD
  interop.

### Fixed (Babel — production interop with BIRD/babeld)

- **Wildcard retractions now log "babel peer wildcard retraction"
  instead of the misleading "babel best-path displacement" fallback.**
  When a BIRD peer's BGP upstreams disconnect, BIRD's babel export
  filter (`export where source = RTS_BGP`) no longer has anything to
  export and BIRD sends a wildcard retraction (RFC 8966 §4.6.9 — AE 0,
  metric 0xFFFF). The previous `apply_update` code flushed the route
  table on this signal but returned without setting
  `last_withdraw_reason`, so `handle_frame` fell back to the generic
  "best-path displacement" string. The operator (correctly) concluded
  the message was wrong: with one upstream, no "best-path election"
  can produce zero paths — the actual cause is an explicit peer-side
  retraction, not a local-decision displacement. The fix replaces the
  single `String` field with a structured `LastWithdraw { kind,
  first_prefix }` that distinguishes per-prefix retractions, wildcard
  retractions, and the local best-path displacement fallback. The
  count of affected routes comes from `delta.withdrawn.len()` at
  render time, so a 29-route retraction frame logs the count (not
  just the LAST prefix, as the previous overwrite-on-every-TLV
  behaviour did). Behaviour unchanged: routes still flush on wildcard
  retraction (RFC 8966 §4.6.9 permits "MAY keep"; babeld clears; lr
  matches babeld). Only the diagnostic message changes.
- **Route metrics no longer double-count the link on every hop.**
  The advertised Update metric used to include the announcing
  interface's rxcost + RTT penalty, which every *receiver* then added
  again from its own link cost — the production symptom where BIRD
  displayed `metric 394` for lr-originated routes (192 announced +
  192 re-added) while every BIRD peer's route showed just its link
  cost. Babeld's `neighbour_cost` and BIRD's `babel_compute_metric`
  both add the link cost at *reception* (txcost learned from the
  peer's IHU + the measured-RTT penalty) and never put it in the
  announcement, so lr now does exactly that: Updates received over a
  session fold in that session's link cost, re-advertised Updates
  carry the full local metric unchanged, and originated
  (redistributed) routes are announced with metric 0 — babeld's
  redistribute-filter default and BIRD's `ea_babel_metric` default;
  the static protocol's `metric` stays a kernel/RIB property exactly
  as in BIRD, where the generic `metric` attribute never flows into
  `babel_metric`. Until the peer's first IHU arrives the txcost is
  infinite and its Updates are not accepted (babeld parity).
- **IPv4 routes are now announced on the IPv6 transport.** BIRD and
  babeld listen exclusively on `ff02::1:6` — v4 routes that only rode
  the v4 multicast transport (224.0.0.111) were invisible to every
  reference peer. A dual-stack interface now emits babeld's shape
  (a NextHop TLV with the interface's IPv4 address before the AE 1
  Updates); a v6-only link with `extended_next_hop` uses the
  RFC 9229 §2.4 AE 4 (IPv4-via-IPv6) encoding. The previous
  AE 1-Update-after-AE 2-NextHop pairing made BIRD abort the whole
  datagram at the first Update ("Update must have next hop"),
  poisoning every route behind it in the same packet.
- **RFC 8966 §4.5.2 omitted-octet prefix compression is now
  reconstructed.** BIRD compresses consecutive v6 Updates (Prefix
  flag + omitted count); lr learned corrupted prefixes (the in-band
  tail octets read as the head — `fd10:127:286:6::/64` became
  `1001:2702:8600:6::/64` in reproduction) and dropped
  fully-compressed Updates outright (a /48 with six omitted octets
  carries zero prefix bytes).
- **A Babel-learned route no longer displaces the operator's static
  for the same prefix.** Both tunnel ends originating the same
  aggregate made lr replace its own static in the Loc-RIB, stop
  announcing it, and let the remote copy expire ("babel routes not
  fully propagated"); the kernel mirror also clobbered the operator's
  blackhole. Direct (OSPF/Babel) routes now go through the merged
  preference order (static 1 < BGP 20 < OSPF 110 < Babel 120) with
  fallback when the learned copy retracts.
- Updates echoing our own router-id back (a no-split-horizon peer
  re-advertising our claims) are ignored, matching BIRD's guard.
- The announcement seqno is seeded randomly (babeld parity) instead
  of starting at 0/1 — with a stable configured router-id, a restart
  made every previously-announced route stale at peers; recovery is
  the now-implemented Seqno-Request handshake (RFC 8966 §3.2.6.2),
  and Route Requests get an immediate announcement.
- An Update without a preceding NextHop TLV resolves its next hop to
  the datagram sender (RFC 8966 §3.5.3) instead of the local bind
  address — BIRD omits the v6 NextHop TLV for its own announcements.
- `--protocol babel` / `--protocol ospf` daemons now apply their
  `[[static]]` / `[[aggregate]]` / `[[redistribute]]` config like the
  multi-protocol supervisor; previously a standalone Babel daemon
  announced nothing at all.

### Fixed (SRv6 kernel route installation)

- **`seg6local` routes install again — the encap type is 7, not 6.**
  `LWTUNNEL_ENCAP_SEG6_LOCAL` is the 8th member of the kernel's uapi
  enum (`NONE, MPLS, IP, ILA, IP6, SEG6, BPF, SEG6_LOCAL, …`); the
  constant carried 6, which is `LWTUNNEL_ENCAP_BPF`. The kernel
  therefore dispatched the nested `RTA_ENCAP` payload to the BPF
  parser, whose `LWT_BPF_IN` policy (attr 1 — the same number as
  `SEG6_LOCAL_ACTION`) rejected the 4-byte action payload with
  EINVAL (run 36153545939: every `End` install failed while
  iproute2's byte-identical save for the encap type succeeded). The
  fix is verified byte-for-byte: a new conformance test pins the
  full request against the bytes iproute2 itself sends for
  `ip route add … encap seg6local action End dev lo table local`,
  captured off the wire with an sendmsg dump.
- **The `SEG6_LOCAL_*` parameter attributes ride the kernel's uapi
  numbers, and the ACTION carries the kernel's numbering — not
  IANA's.** Two further numbering conflation bugs surfaced behind
  the encap type: the parameter attributes were shifted three
  places off the kernel enum order (`NH4=2/NH6=3/IIF=4/OIF=5/
  TABLE=6` instead of the uapi's `TABLE=3/NH4=4/NH6=5/IIF=6/OIF=7`),
  and the ACTION payload embedded the *IANA* behavior value where
  the kernel expects its own `SEG6_LOCAL_ACTION_*` code (identical
  only for `End`; `End.X` is IANA 5 but kernel 2). Both are fixed by
  an explicit IANA→kernel translation table modelled on the
  kernel's `seg6_action_table` (net/ipv6/seg6_local.c), which also
  carries each action's required/tolerated parameter set — a route
  violating the contract (e.g. `End` with a stray `oif`, or `End.X`
  without its mandatory `nh6`) now fails locally with
  `Seg6RouteError::UnsupportedAction` naming the parameter, instead
  of a bare kernel `EINVAL` after the round trip. Behaviors the
  kernel's table does not implement (PSP/USP/USD flavors, the .Red
  variants, End.DT46's VRFTABLE contract, …) are rejected the same
  way rather than mis-encoded. The kernel-gated suite gains an
  `End.X` + `nh6` install test, so the parameterised path is proven
  against the real parser, not just the byte pins.
- **`lr_srv6::Behavior` now carries the real IANA registry.** The
  enum's discriminants were a mis-remembered table: everything from
  13 on was shifted (it modelled `End.DX6=13` where the registry
  assigns `End.B6.Insert=13` … `End.DT2M=24`, with the B6 family at
  13-15 and the DX/DT family at 16-24), `End.S`/`End.Un`/
  `End.X.PS`/`End.X.PSU`/`End.T.PS`/`End.T.PSU` were invented
  entries (the registry has no such assignments), and the
  PSP/USP/USD flavors were a flat `2/3/4` scheme where the registry
  assigns distinct values through 39. The rework models the 38
  RFC 8986 assignments exactly (1-24, 26-39; 25 is Reserved) and
  is verified against the live registry table line-by-line in a
  unit test. `from_wire` for unassigned values still returns
  `None` — the RFC 8986 §4.19 "treat as End.Un" policy stays with
  the caller, where it belongs. BREAKING CHANGE for anyone matching
  the removed variants or depending on the wrong discriminants;
  the kernel bridge (`lr-osroute::seg6_route`) is the only in-tree
  consumer and now translates explicitly.
- **The SRH Routing Type is 4, not 43 — every encoded SRH was
  malformed and every decoded one rejected.** RFC 8754 §2 assigns
  Routing Type 4 to Segment Routing (IANA's "IPv6 Routing Types"
  registry); 43 is the Next Header value of the Routing extension
  header *containing* the SRH (IPPROTO_ROUTING) — a different field
  at a different layer. The constant was 43, so `seg6_build_state`'s
  `seg6_validate_srh` (`srh->type != IPV6_SRCRT_TYPE_4`) rejected
  every `ip route add ... encap seg6` install with EINVAL (run
  36144067883 — surfaced only after the ENODEV fix let the request
  reach the SRH parser), and `Srh::decode` refused every SRH of real
  traffic. The SRH flags were at draft-era positions too: the O-flag
  is 0x20 (IANA "SRH Flags" registry, RFC 9259; Linux
  `SR6_FLAG1_OAM`), not 0x80, and the HMAC flag is 0x08 (Linux
  `SR6_FLAG1_HMAC`), not 0x40; the reserved-bit check now accepts the
  Linux uapi's four deployed positions (Protected/OAM/Alert/HMAC).
- **seg6/seg6local routes install into the kernel again — the request
  now carries the egress device.** Linux's `fib6_nh_init`
  (net/ipv6/route.c) refuses every IPv6 route that names neither an
  egress device (`RTA_OIF`) nor a gateway with `ENODEV`; there is no
  implicit device pick, which is why `ip route add ... encap seg6
  ...` always carries a `dev` and why FRR's `zclient_send_localsid`
  pins every local SID to a real interface. The seg6local request
  builder never emitted `RTA_OIF` at all (its `oif` builder only sets
  the End.X *action* parameter inside `RTA_ENCAP`), and the seg6
  encap builder only emitted it when the caller set one — so every
  install from the CI rootless netns died with `netlink error -19
  (unknown error)` (run 36136529031). `Seg6LocalRoute` gains a
  route-level `with_if_index` builder and both builders now document
  the requirement; the kernel-gated tests resolve the namespace's
  loopback via `if_nametoindex` (netns-aware) and bring it up first
  (newer kernels also refuse a down egress with `ENETDOWN`). The
  netlink errno mapping now names `ENODEV`, `EACCES`, `ENETDOWN` and
  `ENETUNREACH` instead of "unknown error".

### Fixed (Windows route-table suite — wedge root cause, back on every-push CI)

- **The sixteen-run Windows CI wedge is root-caused and fixed — the
  trigger was the WMI staging path, not netio.** The per-test job
  matrix of run 36228391549 (windows-fib-probe.yml) delivered the
  split the bundled suite never could: the two tests that staged
  their APIPA environment through PowerShell's `New-NetIPAddress` —
  `probe_next_hop_interface_resolution` and
  `explicit_oif_beats_fib_resolution` — are exactly the two that
  wedged their jobs to the ceiling, while the two tests that talk to
  netio directly (`CreateIpForwardEntry2`, `GetIpForwardTable2`,
  `GetBestRoute2`, `GetAdaptersAddresses` — the same call set as the
  always-green windows-interop job and its 60+ always-green interop
  runs) completed in 66-98 seconds. The WMI/NDIS provider path
  (`New-NetIPAddress` → WmiPrvSE → NDIS) is the one call shape that
  wedges the runner at the kernel level; every other API this suite
  touches was proven safe by that control group. The staging now
  rides netio's own unicast-address API
  (`CreateUnicastIpAddressEntry`/`DeleteUnicastIpAddressEntry`) —
  in-process, no child process, no WMI — replicating the staging
  contract exactly (a non-persistent manual address excluded from
  source selection, i.e. `-SkipAsSource $true` +
  `-PolicyStore ActiveStore` semantics).
- **The probe child runner no longer waits on a killed child
  indefinitely.** `run_bounded` called `child.kill()` followed by
  `child.wait()`; a child marked for death but wedged in an
  uninterruptible kernel call never signals its handle, so the
  `wait()` hung the test binary with it — the amplifier that turned
  one wedged WMI provider into a wedged whole CI step. The kill path
  now polls `try_wait()` within a bounded 3-second grace window and
  then abandons the survivor (its stdio is file-redirected and it
  holds no console, so nothing the harness waits on is shared with
  it), reporting the overrun through the existing budget-failure
  status. With the WMI spawn gone this is defense in depth, not the
  hang defense.
- **The suite is back on the every-push CI** (the windows-interop
  job). The `#[ignore]` gate stays — kernel-gated tests run where
  their environment exists (an elevated shell here; the Linux
  siblings run under `unshare -Urn` in the interop job) — but
  nothing is silently skipped on the runners any more: the
  environment-precondition "skips" (`no usable adapter`, `cannot
  stage`) are now hard failures, and `powershell()` is gone from the
  file entirely. The windows-fib-probe.yml evidence machine stays
  dispatch-only for future kernel-level audits (issue #29 closed).

### Fixed (Windows test harness — the CI infinite wait)

- **The windows_route_table suite no longer wedges whole CI jobs.**
  Two defects in the *test harness* (not the production backend)
  composed into the un-killable hang that stalled runs
  36125163593 / 36132336028 / 36136529031 until someone cancelled
  the job — the "ci reports an infinite wait" symptom:
  1. `powershell()` drained the child through **pipes** while
     polling `try_wait` and killing at a 60 s budget — but a
     grandchild that inherits the write end (the WMI provider host,
     `conhost`, anything `New-NetIPAddress` touches) keeps a pipe
     open after the kill, so the reader threads blocked on EOF
     forever, `join()` never returned, and the test binary never
     exited. Step-level `timeout-minutes` could not reap the tree
     (a known runner limitation), which is what turned a bounded
     watchdog into a 35-minute job wedge. Child output now goes to
     temp **files**: a file always reaches EOF at the current write
     position, so the budget kill is final and whatever the child
     wrote before it is exactly what the caller reads. `ping.exe`
     and `route.exe` ride the same bounded runner.
  2. `tcp_connect_behaviour` moved its listener into a thread
     blocked forever in `accept()` — the probe port stayed bound for
     the process's lifetime, so every measurement after the first
     in a probe run returned `listener-error` (silently degrading
     the whole matrix). The accept thread now polls a non-blocking
     listener under a shared stop flag with a hard self-limit, and
     the caller reaps it — bounded by construction, port freed
     within milliseconds.
  The timeout tower that grew around the wedge (detached payload +
  900 s watch loop + step ceilings raised above the payload's own
  wall) is dismantled: the harness is bounded by construction and
  the remaining per-test `timeout` calls are plain loud backstops,
  not the hang defense.
- **The wedge survived every layered fix — runs 362-365 falsified
  each theory in turn, and the final shape is pure PowerShell with
  detached launches.** The file-IO rework bounded the harness's own
  waits; run 362 (in-binary watchdog, timestamped transcripts,
  file-stdio) still wedged and established that GNU `timeout`'s
  SIGTERM is undeliverable to a native cargo.exe (Cygwin/MSYS signal
  emulation only reaches MSYS processes) — the wrapper waits forever,
  which is why every ceiling stacked around it never fired; run 363
  (bash-level `run_bounded`, file stdio, Windows-native `taskkill
  //F //T`) still wedged, establishing that a bash step spawning
  cargo is itself a hanging shape on these runners (PowerShell cargo
  steps and bash steps spawning leaf daemons are always-green);
  runs 364 and 365 (compile from PowerShell, the test binary run
  DIRECTLY from bash, console-less `CREATE_NO_WINDOW` grandchildren,
  `/dev/null` stdin, the kernel-mode in-binary watchdog and the
  taskkill backstop) STILL wedged — leaving exactly one mechanism
  standing: a process stuck in an UNINTERRUPTIBLE kernel call (wedged
  netio) is marked for death by `TerminateProcess` but never actually
  reaped, and everything that waits on its death — bash's `wait`, the
  runner's step timeout, the runner's step finalisation — hangs with
  it. Even the last workflow shape — pure PowerShell, detached
  launches, bounded `WaitForExit` budgets — wedged (run 366: the pwsh
  loop is provably bounded at 4 x 360 s, yet the step sat
  `in_progress` 37+ minutes; the script had finished, the RUNNER could
  not finalise around the limbo survivor). The conclusion: the
  kernel-level hang cannot be prevented or reaped from the workflow
  layer at all, and an every-push job cannot afford it. The suite
  therefore moved:
  - **Off the every-push job** — the windows-interop job keeps the
    three interop scripts (and its cache save finally happens again:
    the wedge was also starving it); the backend's unit tests keep
    running (and passing) in the Native (windows-2022) job.
  - **Into a wedge-tolerant evidence machine** — windows-fib-probe.yml
    is now a per-test JOB matrix with `fail-fast: false` and an
    `if: always()` transcript-commit step: a wedged test burns only
    its own job to the ceiling while the sibling jobs complete and
    COMMIT their transcripts to the dispatched ref. The last
    timestamped `PROBE|` line of a wedged test names the exact call
    site that hung — the data the kernel-level fix needs, which
    sixteen cancelled jobs never left behind. Each test still runs
    detached with bounded waits, and the binary's own defenses stay:
    the kernel-mode `TerminateProcess(GetCurrentProcess(), 70)`
    watchdog, timestamped `PROBE` lines, console-less
    (`CREATE_NO_WINDOW`) children.

### Fixed (BGP — §6.8 collision loss and RFC 4724 retention scope)

- **Losing a connection collision no longer turns the connector into a
  1-second hammer.** When the peer holds a live session to a *dead*
  instance of us — the restart-during-a-link-flap case behind the
  rc.4 Windows RR loop — every fresh dial bounces off the peer's
  Established-protection rule with `Cease / Connection Collision
  Resolution` (RFC 4271 §6.8, RFC 4486 subcode 7). The connector
  redialed ~1 s after every loss (the reconnect backoff reset on every
  successful TCP connect) and the churn guard required BOTH a latched
  loss AND a sibling session already in Established, which never
  happens while the peer's surviving session is the zombie: the loop
  ran until the peer's hold timer cleaned the corpse. Now the loss is
  latched precisely — both when our resolver closes the transport and
  when a Cease/7 arrives from the peer's resolver (the FSM records
  RFC 4486 subcode 7; embedders read it via
  `Router::take_collision_lost`) — the churn guard engages on the
  sibling being Established alone (FRR stops the doppelganger, BIRD
  idles the sibling dial), and the connector waits out the peer's hold
  window (clamped 10–120 s) before dialing again, resetting the
  exponential ladder only after a transport that actually reached
  Established (`Router::session_was_established`).
- **RFC 4724 retention no longer arms for sessions that were never
  established.** Teardown gated retention on the negotiated GR window
  alone, so every §6.8 collision loser mid-handshake pinned a 120 s
  retention for a session that never had routes — visible in the
  production log as `session 3 entered graceful-restart retention`
  after every collision round, and short-circuiting the next
  teardown's Adj-RIB-In purge (the early-return treats an existing
  entry as "keep the original deadline"). Retention now requires the
  transport to have been Established (RFC 4724 §2: it protects the
  routes a session actually learned).
- **Graceful shutdown sends `Cease / Administrative Shutdown`
  (RFC 4486 §4.1 subcode 2) instead of a bare FIN.** `close_session`
  never queued the NOTIFICATION its own comment promised; peers now
  learn the session is going away deliberately and converge
  immediately instead of waiting out the hold timer.

### Fixed (daemon — Windows Ctrl+C leaves the kernel FIB dirty)

- **Ctrl+C (and console close / logoff / shutdown) now run the full
  graceful-shutdown path.** The non-Unix half of `signal` was an inert
  stub: the default console disposition terminated the process on the
  spot, so the session Cease, the RIB flush, and the kernel-route
  withdrawal never executed — every restart left the previous
  daemon's routes in the Windows table (the rc.4 production report:
  `--install-kernel-routes` routes surviving Ctrl+C, a silent
  blackhole until the next restart re-added only its own set). The
  daemon now installs a `SetConsoleCtrlHandler` handler: CTRL_C /
  CTRL_BREAK map to SIGINT, and CTRL_CLOSE / CTRL_LOGOFF /
  CTRL_SHUTDOWN map to SIGTERM with a bounded in-handler wait —
  Windows tears the process down the moment the handler returns, so
  the handler holds (≤ 4 s) until `main` marks shutdown complete,
  which the ticker's final drain (BIRD `persist off` parity: everything
  this daemon installed is withdrawn) precedes. SIGINT/SIGTERM on Unix
  run the identical graceful path and are covered by the new
  `bgp_shutdown_cleanup.sh` interop test.

### Fixed (BGP — §6.8 collision resolution with a listener)

- **Outbound-only peers no longer loop on `Cease / Connection
  Collision Resolution` when the daemon is also listening.** An
  outbound-only peer (only `remote` configured, no `address`)
  whose daemon had `listen_addr` set still received inbound
  connections from the same neighbour — `match_inbound_peer`
  falls back to the host of `remote` via `expected_peer_ip`. The
  inbound was dispatched onto the SAME `SessionHandle` as the
  outbound connector (no `handle_in` existed because the
  bidirectional gate was `is_outbound() && is_inbound()`), and
  `start_session`'s `peer.reset()` clobbered the outbound FSM
  mid-handshake. The router never saw two sessions in one
  `collision_group`, so it could not resolve the collision
  in-house; the remote's `Cease / Connection Collision Resolution`
  NOTIFICATION looped indefinitely — the production Windows RR-loop
  regression. The bidirectional gate is now `is_outbound() &&
  (is_inbound() || cfg.listen_addr.is_some())`, so any outbound
  peer receives a challenger session sharing the same
  `collision_group` whenever the listener is up. The router
  resolves the collision itself, the outbound connector's churn
  guard (`lost_once && sibling_in Established`) engages, and the
  loop converges to exactly one Established session per peer.
- **`listener_auth` and `listener_gtsm` now arm the listener for
  outbound-only peers too.** Same expanded definition of
  "inbound-capable": an outbound-only peer with TCP-MD5/AO or
  GTSM keyed sessions now has its inbound accepted (otherwise the
  kernel would drop the SYN before the listener could match it).
- **The startup log surfaces the new collision topology.** Peers
  that carry a challenger session are labelled `bidirectional
  (remote + listener)` (vs the historical `bidirectional (remote
  + address)`), and the peer summary shows `bidirectional` instead
  of `outbound` — surfaces the §6.8 resolution in the
  operator-visible state so a misconfigured listener is obvious at
  startup.

### Fixed (kernel FIB interaction)

- **Linux blackhole routes are now actually withdrawn.** RTM_DELROUTE
  named `rtm_type=RTN_UNICAST`, but the kernel's IPv4 fib delete
  matcher compares the requested type against every candidate row — a
  unicast delete never matched an installed `RTN_BLACKHOLE`, failed
  with ESRCH, and the blackhole stayed in the kernel after the
  operator removed the static route (or shut the daemon down), keeping
  the FIB discarding traffic for a prefix that had just been
  un-configured. IPv6's fib6 ignores the type on delete, which is why
  only v4 exhibited it. The delete now sends the `RTN_UNSPEC`
  wildcard (what iproute2's plain `ip route del PREFIX` relies on) and
  maps the kernel's `-ESRCH` ack to success — redundant withdrawals
  are idempotent, matching the Windows backend's ERROR_NOT_FOUND
  handling. A new kernel-gated test suite (`route_kernel.rs`) proves
  the round trip against a live kernel for both families.
- **Windows blackhole routes install again — and discard instead of
  locally accepting.** The rc.4 form (a `127.0.0.1`/`::1` loopback
  *gateway*, the `route add ... 127.0.0.1` advice) is rejected by
  `CreateIpForwardEntry2` with `ERROR_INVALID_PARAMETER` (netio
  refuses loopback next hops), so every static blackhole failed to
  install in production. The form before that (zero next hop on the
  loopback *interface*) installed but was local delivery under the
  weak-host model — a daemon listening on 0.0.0.0 answered SYNs for
  the covered space (the "peer closed connection" retry storm). The
  backend now installs the Windows null-route convention: an on-link
  row on a real egress interface (the default-route owner, cached per
  family) — neighbour resolution for the covered destination fails
  and the traffic dies as host-unreachable. Unreachable-flavoured
  discard rather than Linux's silent `RTN_BLACKHOLE`, but nothing is
  forwarded and nothing loops, which is what an aggregate anchor
  needs. The full empirical matrix (modern + legacy IP Helper forms,
  measured connect/ICMP behaviour per form) is preserved as
  `windows_route_table.rs::fib_semantics_probe_matrix`.
- **Windows route withdrawals no longer delete foreign rows.** The
  backend keeps an install ledger — `(prefix, next hop, if index)`
  triples it created — and a withdrawal removes exactly those; only
  for a prefix the ledger never saw (fresh process cleaning a
  predecessor's routes) does it fall back to the protocol-tag sweep.
  A VPN's on-link route for the same prefix (WireGuard AllowedIPs
  rows are `MIB_IPPROTO_NETMGMT`, the same tag lr's statics use)
  previously died with the daemon's withdrawal.
- **Windows withdrawals match the row the stack actually stored.**
  `CreateIpForwardEntry2` normalises row shapes at create time: a
  next hop equal to the egress interface's own address (the BGP
  next-hop-self shape) is stored as the on-link form — `route print`
  shows "On-link" where a gateway was requested. The install ledger
  recorded the *requested* next hop, so a scoped withdrawal never
  matched the normalised table row and silently no-oped as an
  "idempotent success" while the route stayed live in the FIB (the
  "BGP kernel route survived peer teardown" failure). After every
  successful create the backend now reads the row back with the O(1)
  per-row getter (`GetIpForwardEntry2` — no table scan) and ledgers
  the *effective* next hop the stack holds.
- **Windows rows no longer inherit the initializer's `Loopback` flag.**
  `InitializeIpForwardEntry` leaves `MIB_IPFORWARD_ROW2.Loopback` TRUE
  on audited builds (the SDK documents no such default); a set flag is
  loopback delivery under the weak-host model — the local-accept trap
  the on-link blackhole idiom exists to close, still present on every
  row the backend installed. Both row builders now clear the flag
  explicitly and a unit test pins it for both families.
- **Windows routes learned over Babel egress the right interface.**
  The kernel mirror passed `oif 0` for every non-link-local next hop
  and let the OS resolve it; Windows' `GetBestRoute2` longest-prefix
  matched the v4-over-v6 Babel next hop (the AE 1 NextHop TLV — the
  peer's address on the tunnel) against an APIPA `169.254.0.0/16`
  connected route on an *unrelated* adapter, so every learned route
  egressed the wrong interface and the BGP sessions that depended on
  them looped on connect. The mirror now consults a next-hop egress
  registry fed by the protocol transports (the generalisation of the
  link-local v6 registry that already existed): the Babel transport
  registers the peer's addresses and every NextHop TLV value against
  the session's interface — babeld's `neigh->ifp` rule, exposed to
  embedders as `RouterInstance::babel_egress_nexthops`. Explicit
  egress is also now passed for unregistered v4 next hops only when
  a protocol claimed them; ordinary recursive BGP gateways keep
  kernel resolution.
- Installed routes carry the originating protocol's tag
  (RTPROT_BABEL/OSPF/STATIC on Linux, the NL_ROUTE_PROTOCOL MIB
  values on Windows) instead of every row showing up as `bgp`.
- The kernel mirror refuses to replace a kernel-owned *connected*
  route for the same prefix (NLM_F_REPLACE used to swap the on-link
  row out and break the link's own gateway resolution), and withdraws
  every installed route on daemon shutdown.
- Windows: the babel v6 scope resolves through the adapter's
  Ipv6IfIndex (which can diverge from IfIndex), the unicast socket
  also joins the multicast group (Windows delivers only to joined
  sockets), and receive errors are logged instead of silently
  breaking the read loop. The babel daemon registers learned
  link-local next hops in the v6-nexthop oif registry so routes via
  `fe80::` gateways install on Linux and Windows.
- The BGP "received End-of-RIB — synchronization complete" event now
  fires for every session, not only graceful-restart-retained ones.

### Changed (CI)

- **The full windows_route_table matrix runs on every push — the
  permanently-skipped manual probe is gone.** The ci.yml
  windows-interop step now runs all four `#[ignore]`d tests
  (fib_semantics_probe_matrix, probe_next_hop_interface_resolution,
  and the two assertive regressions), each in its own
  `timeout`-bounded cargo invocation; the transcript lines appear in
  the Actions log. The separate workflow_dispatch probe remains only
  as the on-demand way to commit the transcript to a disposable
  branch — no test is gated behind a manual dispatch anymore.
- **CI now exercises the kernel route-table backends on macOS and
  Windows.** A new `macos-interop` job runs `bgp_kernel_install.sh`
  under sudo against the BSD `route(4)` socket (previously
  cross-compile-only), and the Windows interop job runs the same
  script against the IP-Helper backend in the runner's Administrator
  shell. Both assert the learn → install → decide → teardown chain
  against the real OS FIB.
- **The Windows route-table backend now has its own kernel-gated
  regression suite in CI** (`windows_route_table.rs`, Administrator
  shell): the blackhole install must discard (not locally accept) a
  connect into the covered space, and an explicit egress interface
  must beat `GetBestRoute2`'s longest-prefix resolution of an APIPA
  shape staged with `New-NetIPAddress` — both rc.4 production
  defects, asserted against the real netio.
- **The ip_forward transit phase runs in the regular CI job, not
  only the nightly VM.** `bgp_transit.sh` and `ospf.sh` gained a
  root-aware namespace mode (`unshare -n` as root, `unshare -Urn`
  rootless) and an `LR_REQUIRE_FORWARD=1` gate; the interop job now
  also runs both scripts under `sudo`, where phase 4 genuinely
  executes — and the BGP transit's forwarding is pcap-verified: the
  ICMP echo request is captured on BOTH of the transit router's
  interfaces (`pcap_sniff.py` gained an icmp filter mode;
  `pcap_icmp_check.py` decodes the captures) and the identical
  `(id, seq)` pair on ingress and egress is asserted — "r2 answered
  the ping itself" cannot produce that pair, only real forwarding
  can. A skip remains a failure under the gate, so the rootful job
  cannot silently lose the data plane.
- The interop job installs `libyang-tools`, so `yang.sh` (the RFC
  9647 YANG surface gate) runs instead of SKIPping.
- **The learn → install → forward contract is now verified for BGP on
  Linux in the regular CI job** (`bgp_kernel_install.sh`,
  `bgp_transit.sh`): kernel FIB install with `proto bgp`, OS lookup
  via `ip route get`, ICMP delivery through the installed route, and
  peer-death withdrawal. The transit-forwarding phase (ip_forward)
  runs as root in the nightly QEMU VM harness.
- The nightly VM job installs `linux-modules-extra-$(uname -r)`, so
  the MPLS dataplane phases of `mpls_lsp.sh` / `ldp.sh` actually run
  inside the VM instead of SKIPping (the runner's base azure kernel
  package does not ship `mpls_router`).
- The Windows BIRD-in-WSL2 interop job is now a hard gate (its
  stabilisation period passed).
- **The native cross-platform matrix dropped its ubuntu entry and
  formatting step — both fully duplicated by the `lint` and
  `unit-tests` jobs on the same image.
- The SRv6 kernel interop tests run inside the rootless netns instead
  of bare on the runner: without CAP_NET_ADMIN every install died
  with EPERM and the `#[ignore]`d tests passed as vacuous SKIPs
  ("SKIP: add_seg6local_route returned EPERM"). The step now wraps
  the suite in `unshare -Urn` and enables `seg6_enabled` inside that
  netns (per-netns sysctl, rootless-writable — the same pattern the
  MPLS dataplane phase uses).
- The Windows FIB-semantics probe is a manual `workflow_dispatch`
  workflow (`windows-fib-probe.yml`) instead of a branch-gated job in
  the push pipeline: a job gated off main-line triggers shows up as
  permanently "skipped" on every run. The probe payload also runs
  detached with per-test `timeout` guards and the step prints the
  transcript itself — the runner cannot always reap cargo's process
  tree on Windows, and a wedged test used to carry the job to its
  timeout with the transcript lost.
- The interop resolution-steal shape is staged as 169.254.188.0/24
  instead of the full APIPA /16: making 169.254.169.254 (the cloud
  metadata service) on-link on a runner's primary adapter kills the
  guest agent's health check and GitHub cancels the job. The
  longest-prefix steal mechanism the tests reproduce is identical.
- The FIB-mutating Windows tests run with `--test-threads=1` (they
  mutate the same rows and reuse the same probe port).

### Added (tests)

- `tests/interop/_lib.sh` gained portable (Linux/macOS/Windows-Git-
  Bash) kernel-FIB helpers and an elevated (sudo) daemon spawner with
  pidfile-tracked real pids; `two_daemon.sh` and
  `labeled_unicast.sh` were refactored onto the shared library and
  are now platform-portable.
- `crates/lr-osroute/tests/windows_route_table.rs` — the Windows
  sibling of `route_kernel.rs`: two assertive regressions (blackhole
  discard semantics, explicit-egress installation) plus the
  `fib_semantics_probe_matrix` research transcript (every plausible
  blackhole row form across the modern and legacy IP Helper APIs
  with measured connect/ICMP behaviour — the empirical basis for the
  idiom the backend now uses).
- `tests/interop/pcap_icmp_check.py` + `pcap_sniff.py` icmp mode —
  forwarding-proof packet capture for the transit interop tests.
- Daemon kernel-mirror unit tests pin the v4 egress pinning (a
  registered next hop installs with its interface; an unregistered
  one keeps kernel resolution) and the registry's overwrite/zero
  semantics.

_Embedder impact: the public surface grows one defaulted trait method
(`RouterInstance::babel_egress_nexthops`) — no breakage for existing
implementors; the C ABI, the daemon CLI flags and the config DSL are
untouched, so the Go/Python/C/C++ bindings need no regeneration. The
next release-event is the final `1.0.0` cut — see `docs/RELEASE-PLAN.md`
§2.8 for the freeze criteria._

## [1.0.0-rc.4] — config DSL migration + filter VM hardening

The fourth release candidate ships the full configuration-DSL
migration (GitHub issue #18, Phases 0–4) and the filter-VM
performance + correctness work (GitHub issue #19, P6 + P7). The
public Rust API and the C ABI are unchanged since rc.3 — the
release adds a configuration frontend, positioned diagnostics and
VM internals; embedders need no code changes, but bindings
compiled against rc.4 pick up the filter-VM span fix automatically.

**Highlights since rc.3:**

- **Native `.lr` configuration DSL** — the daemon now accepts a
  declarative DSL alongside TOML, with `lr-daemon config to-dsl`
  converting any accepted config (TOML, BIRD, FRR, `.lr`) into the
  deterministic `.lr` form. Both frontends lower through one
  `apply_config_key` dispatch, so they share the exact fail-closed
  key schema and cannot drift. `templates/daemon.lr` ships as the
  fully-commented reference; TOML stays supported through 1.x
  (deprecated, planned removal in 2.x). See `docs/config_dsl_grammar.md`.
- **`lr-daemon config check`** — validate + report a config file
  without starting the daemon; exit 0 valid / 1 invalid / 2 usage.
- **Positioned filter diagnostics** — every token, AST node and
  error carries a byte `Span`; parse and evaluation errors point
  at the exact source location in both engines (interpreter + VM),
  with a rustc-style caret snippet rendered by the daemon and
  `lrctl filter compile`.
- **Filter VM instruction fusion (#19 P6)** — the canonical
  `if bgp.local_pref > 100` import-policy shape compiles to one
  `BranchFieldIntCmp` instruction; `vm_if_local_pref` ~66 → ~28 ns
  (−57 %), `import_pipeline/realistic/10000` −6.5 %.
- **Filter VM lazy span read (#19 P7)** — the dispatch loop reads
  the source span lazily inside fallible arms; infallible arms pay
  zero span cost. Also fixes a latent bug where VM errors inside a
  user-function body indexed the outer filter's span table instead
  of the function's own.
- **RFC 8326 graceful session shutdown** — the
  `GRACEFUL_SHUTDOWN` community is honoured on receive (best-path
  step + import hook) and send (export hook with per-peer exempt),
  gated by `[bgp] graceful_shutdown` (default on).
- **OSPFv3 Extended-LSA + SRv6 End.X** — RFC 8362 reception +
  origination; RFC 9513 §9.1 End.X + §9.2 LAN End.X SIDs.
- **Multi-protocol daemon** (from rc.3, hardened in rc.4) — one
  `lr-daemon` process runs `bgp,ospf,babel` through a shared-router
  supervisor.
- **Interop** — 7 new BIRD/FRR interop labs (E-LSA, End.X, LAN
  End.X, RFC 8212 BIRD/FRR, multi-protocol, graceful-shutdown
  receive) wired into CI.

**Full changelog:** the Added / Fixed / Deprecated entries below
carry the per-feature detail.

### Added

- **Lazy span read in the filter VM dispatch loop (GitHub #19
  P7)** — the bytecode VM's `run_code` no longer reads the source
  span at the top of every dispatch iteration. The span is now read
  lazily inside the fallible arms (`LoadVar` / `AssignVar` / `Bin` /
  `Neg` / `Call` / `CallFn` / `Method` / `AssignField` /
  `AppendField`); infallible arms (`Push` / `Jump` / `Accept` /
  `Reject` / `Return` / `Pop` / `PushScope` / `PopScope` /
  `StoreTmp`) pay zero span cost. The `spans` slice is threaded as a
  parameter to `run_code` alongside `code`, replacing the defensive
  `cf.span_at(ip)` call (a Vec `.get().copied().unwrap_or_default()`
  per dispatch) with a direct `spans[ip]` load on the fallible path.
  Criterion measures a small but consistent improvement on the
  `vm_large_community_set` shape (−0.60 % hit_last, −0.38 % miss,
  both p = 0.00); the other `filter_eval` shapes stay within noise.

### Fixed

- **VM errors inside a user-function body now carry the function's
  own source span** — a latent indexing bug in the filter VM. When
  `run_code` was called for a user-function body (`code = &f.code`),
  it still read `cf.span_at(ip)` — the *outer filter's* span table
  — instead of the function's own `f.spans[ip]`. The outer table is
  parallel to `cf.code`, not to `f.code`, so an error at
  `f.code[ip]` read the wrong span (or `Span::default()` when `ip`
  exceeded the outer filter's code length). The lazy-span refactor
  threads `&f.spans` through `call_compiled_function` → `run_code`,
  so the VM reads the function's own span at every `ip`. The fix is
  pinned by `vm_error_inside_user_function_carries_function_span`,
  which constructs a filter whose function body is longer than the
  outer filter body — the pre-fix path indexed past the end of
  `cf.spans` and returned `Span::default()`. No behaviour change for
  the happy path; errors now point at the right source.

### Added

- **The daemon runs natively on `.lr` everywhere (issue #18 Phase
  3)** — the DSL-first slice of the configuration migration.
  `templates/daemon.lr` ships as the fully-commented reference
  configuration: the same active configuration as
  `templates/daemon.toml`, documented with commented DSL examples for
  every optional feature, and pinned by golden tests to resolve to
  the identical IR as the TOML twin (both frontends, pre- and
  post-finalize; `config to-dsl` renders both byte-identically and
  the conversion is a fixpoint). SIGHUP / API reload now re-resolves
  the config dialect through the same shared parser the
  `--config-dialect` flag uses — a daemon running a `.lr` file
  previously kept its current configuration on reload with
  `unknown config dialect 'lr'`. README, `docs/lr-cli.md`, the
  recipes and the per-scenario examples show `.lr` syntax first; the
  TOML subset remains fully supported (deprecated through 1.x,
  planned for removal in 2.x — `config to-dsl` migrates). Two
  documentation claims the code disproved were corrected in passing
  (`[[networks]]` array tables are not a schema key; the OSPFv3 SRv6
  locator `behavior` is the RFC 9513 §11 u16 code, End = 1). Also
  fixed: the `.lr` lexer panicked on multi-byte characters inside
  comments (char-boundary slice) — comments accept any UTF-8 text
  now.
- **Native `.lr` configuration DSL + `lr-daemon config to-dsl`
  converter (issue #18 Phase 2)** — the TOML→DSL migration's core
  slice. The daemon now accepts a declarative DSL
  (`docs/config_dsl_grammar.md`): blocks with identity arguments,
  typed key-value statements with whitelisted duration/scale unit
  suffixes (`hold_time 90s;`), verbatim filter bodies between braces
  (no string escaping — `filter in { if roa.state == ROA_UNKNOWN
  then accept; }`), and cycle-checked `include "peers.lr";` with
  per-file diagnostics. Both frontends lower through one
  `apply_config_key` dispatch, so `.lr` and TOML share the exact
  fail-closed key schema and cannot drift; `--config-dialect lr`
  forces the dialect and content detection recognizes lr-exclusive
  block headers. `lr-daemon config to-dsl <file>` converts any
  accepted config (TOML, BIRD, FRR, `.lr`) into a deterministic `.lr`
  program — fixed order, unset fields omitted — refusing rather than
  silently dropping anything unrepresentable (parse warnings, filter
  descriptions). Correctness is pinned by the IR-equality round-trip
  property: a kitchen-sink fixture covering every key of every
  section and the shipped template must survive
  `parse(TOML) → to-dsl → parse(lr)` byte-equal; 7 e2e tests cover
  the CLI. Also fixed: a TOML file whose first line is an assignment
  (`protocol = "bgp"`) was misdetected as BIRD.
- **Typed configuration IR + `lr-daemon config check` (issue #18
  Phase 1)** — the second slice of the TOML→DSL configuration
  migration. `DaemonConfig` is now the single typed IR: it derives
  `PartialEq`, so two parsed configurations are comparable for
  semantic equality — the golden property the DSL frontend will be
  validated against (a TOML config and its DSL translation are
  equivalent iff they produce equal IRs). Daemon startup, SIGHUP/API
  reload and the new validator all load through one
  `daemon_config::load_config_file` entry point, so a config `check`
  accepts is exactly a config a daemon accepts. `lr-daemon config
  check <file>` loads + finalizes the file without starting the
  daemon — template inheritance, cross-section name references and
  every other `finalize` invariant run at config-editing time — and
  prints the resolved view (dialect, protocol set, peers, networks,
  policy bank, babel/ospf/roa/redistribute counts, parse warnings);
  exit 0 valid / 1 invalid / 2 usage. IR-equality golden tests pin
  parse determinism, variant equivalence, the semantic peer ordering
  and the shipped template; 8 e2e tests cover the check paths.
- **Filter DSL source spans + positioned diagnostics (issue #18
  Phase 0)** — the foundation for the TOML→DSL configuration
  migration. Every token, AST node and error produced by the filter
  front end now carries a byte `Span` into the filter source, and the
  evaluator, bytecode VM, daemon and `lrctl` all surface it:
  - `lr_policy::filter::span` — `Span` (half-open byte range),
    `LineIndex` (offset → 1-indexed line/col) and `render_snippet`
    (rustc-style caret diagnostic renderer).
  - Parse errors point at the exact offending token, including
    `UnknownFunctionCall`, which now names the unknown call's position
    instead of a generic `1:1`.
  - Evaluation errors (`UndefinedVar`, `AssignToUndefined`,
    `TypeMismatch`, ...) carry real positions in **both** engines —
    the tree-walking interpreter and the bytecode VM report identical
    kind + span + line/col, pinned by an engine-parity test. The VM
    reads a span side table parallel to the instruction stream; the
    peephole passes (fold / fuse / dead-branch / jump-thread) preserve
    the table's alignment, so positions survive optimisation.
  - The daemon (`[[filter]]` startup compilation) and `lrctl filter
    compile` render positioned errors with a caret snippet under the
    offending source line.
  - `MAX_EXPR_DEPTH` tightened from 128 to 108: the AST's span fields
    grow debug-build stack frames, and the recursion guard's margin
    was recalibrated against the worst-case per-level frame chain
    (nested set literals). Real filters nest a handful of levels; the
    positive corpus boundary test pins depth 100 still parsing.
  - `BREAKING CHANGE:` `Token`, `LexerError`, `ParseError` and
    `EvalError` gained fields (`span`); `Stmt` and `Expr` variants
    carry a `span` field (tuple variants grew a second element);
    `Filter` gained `line_index`; `CompiledFilter` / `CompiledFunction`
    gained `spans` (+ `CompiledFilter::line_index`). Code that
    constructs or exhaustively matches these types must add the new
    fields/patterns; `Expr` equality is now span-blind.
- **RFC 8326 Graceful Session Shutdown — receive side and knobs**
  (ROADMAP-v3 D10.1 follow-up). The `GRACEFUL_SHUTDOWN` community
  (`0xFFFF:0000`) is now honoured on all three surfaces, gated by the
  global `[bgp] graceful_shutdown` knob (default on):
  - **§4 best-path step** —
    `BestPathConfig::graceful_shutdown_least_preferred` (default
    true) adds a step
    right after the RFC 9494 LLGR_STALE check in `BestPath::compare`
    and `compare_multipath`: a route carrying the community loses to
    any untagged candidate; between two tagged candidates the normal
    tiebreakers apply. The step sits ahead of LOCAL_PREF because the
    comparator pins eBGP LOCAL_PREF at 100, so the §4.1
    low-LOCAL_PREF policy alone could not de-preference an eBGP path
    against another eBGP path — FRR closes the same gap by forcing
    LOCAL_PREF to 0 on GS-tagged eBGP routes and comparing
    LOCAL_PREF unconditionally (`BGP_GSHUT_LOCAL_PREF`).
  - **§4.1 receiver hook** —
    `lr_policy::hooks::GracefulShutdownImportHook` is the RFC's
    inbound policy as an
    `ImportHook`: an imported route carrying the community has its
    LOCAL_PREF lowered to the RECOMMENDED 0 (configurable via
    `with_low_local_pref`, default mirrors FRR's
    `BGP_GSHUT_LOCAL_PREF`), the community retained, so the
    de-preference also propagates to downstream iBGP speakers that
    do not implement §4.
  - **Per-peer sender-side override** — `[[peer]] graceful_shutdown
    = false` exempts that neighbor's sessions from the §3.1 export
    rewrite (`GracefulShutdownExportHook::with_exempt_sessions`).
    The receive-side honouring stays unconditional, mirroring FRR.
    `[bgp] graceful_shutdown = false` opts out of all three
    surfaces — the plain RFC 4271 decision process, with the
    community inert for selection.
  - The daemon's startup banner reports which hooks are installed
    (and the exempt session count when the per-peer override fires)
    or the explicit opt-out. Four e2e tests
    (`crates/lr-cli/tests/daemon_graceful_shutdown.rs`) cover the
    receiver step, the knob-off restore and both per-peer override
    variants on the real daemon; unit tests pin the comparator
    step, both hooks and the config keys.

- **Filter DSL instruction fusion** (GitHub #19 P6, ROADMAP-v3 D6
  follow-up). The peephole compiler gained a new pass
  `pass_fuse_branches` that collapses the four-instruction pattern
  `LoadField(int); Push(Int(c)); Bin(Cmp); JumpIf*(t)` into a single
  `Instr::BranchFieldIntCmp { .. }`. The fused instruction reads the
  integer route field directly, compares against the constant, and
  branches with zero stack traffic — one cache-line fetch and zero
  `Vec::push`/`pop` instead of the unfused four-fetch/three-push/
  two-pop sequence. The pattern is the canonical import-policy shape
  (`if bgp.local_pref > 100 then accept; reject;`) and the
  `#19`-documented VM hotspot: `vm_if_local_pref` drops from ~66 ns
  to ~28 ns (−57 %, 2.3×) on the bench machine; the
  `import_pipeline/realistic/10000` end-to-end pipeline drops from
  ~12.27 ms to ~11.47 ms (−6.5 %). The fusion pass is conservative
  — it only fires for the four integer-typed fields
  (`BgpLocalPref`/`BgpMed`/`BgpOrigin`/`Source`), only for the six
  comparison ops (`Eq`/`Ne`/`Lt`/`Le`/`Gt`/`Ge`), and refuses to
  fuse when any external jump lands inside the four-instruction
  pattern. The existing equivalence tables in
  `crates/lr-policy/src/filter/eval.rs` pin verdict + route-state
  equality between the fused and unfused VM dispatch.
- OSPFv3 SRv6 LAN End.X SID origination — RFC 9513 §9.2 over RFC 8362
  (ROADMAP-v3 D13 slice 4).
  - **`[[ospf.interface]] srv6_end_x_lan`** — the broadcast form: an
    at-most-/96 IPv6 prefix inside an `[[ospf.srv6_locator]]`
    (broadcast-only, fail-closed). Each Full BDR/DR-Other neighbor `R`
    derives one §9.2 LAN End.X SID as `base | R` — the Router-ID fills
    the low 32 bits, so the mapping is deterministic, collision-free
    and provably inside the locator. On broadcast segments the
    existing `srv6_end_x` knob now covers the §9.1 DR adjacency.
    Both forms ride the transit Router-Link TLV's sub-TLV region of
    the E-Router-LSA (topology carrier under `extended_lsas`,
    sparse-mode companion under legacy mode) and surface on the
    runtime API `status` as `srv6-endx` lines (`lan` marker on the
    §9.2 projections).
  - **`tests/interop/ospf6_e_lsa_endx_lan.sh`** — a three-router
    bridge broadcast segment: the DR projects the plain §9.1 SID, the
    BDR the derived §9.2 LAN SID, the originator self-projects both,
    and all six adjacencies reach Full.

### Deprecated

- **The TOML configuration dialect is deprecated (issue #18 Phase
  4)** — the window the DSL-first migration promised. TOML stays
  fully supported through the 1.x release series and is planned for
  removal in 2.0; `lr-daemon config to-dsl daemon.toml > daemon.lr`
  converts existing files (deterministic, refuses unrepresentable
  input rather than silently dropping it). Every surface that loads
  a config for a running daemon now announces the window when the
  resolved dialect is TOML: daemon startup (`config deprecation: …`
  on stderr), SIGHUP / API `reload` (`reload: config deprecation: …`
  through the same channel as its parse warnings) and `config check`
  (a `deprecation:` line in the resolved-view report). The notice is
  a policy announcement, not a parse warning — it does not join
  `DaemonConfig::warnings` and `config to-dsl` stays silent about it
  (the converter is the migration path itself, and its stderr
  belongs to scripts).

### Fixed

- Inline comments in the daemon TOML subset parser. TOML allows a
  `#` comment after any value, but `parse_toml_subset` only skipped
  whole-line comments, so `entry = 20      # …` — present in the
  shipped `templates/daemon.toml` itself — failed to parse as a bad
  entry and `lr-daemon --config templates/daemon.toml` rejected the
  template. Inline comments are now stripped with a quoted-string
  -aware scanner: hashes inside values (`md5_key = "a#b"`, filter
  bodies) stay data, and a `\` escape does not close the string.
- OSPF DD/LSR packets are now unicast at the peer's address on
  broadcast segments (RFC 2328 §8.1 via RFC 5340 §4.2), in both the
  v2 and v3 daemons. Previously every session packet was multicast to
  AllSPFRouters, which deadlocked the DBD exchange
  nondeterministically on segments with three or more speakers: the
  DR's two independent sequence-numbered conversations interleaved
  inside each DR-Other's single session with it. Two-router segments
  were unaffected (all prior labs are two-router). The v3 OSPFv3
  pseudo-header checksum is finalized for the actual unicast
  destination.
- An OSPF adjacency demoted Full → 2-Way (the §10.4 gate closing on
  an election change) now schedules Router-LSA re-origination
  immediately; previously the stale link lingered until the §14.1
  refresh (30 minutes).

### Added

- OSPFv3 Extended LSAs — RFC 8362 (ROADMAP-v3 D13 slices 1-2).
  - **`lr_ospf::lsa::e_v3`** — the eight TLV-bodied E-LSA codecs:
    E-Router 0xA021 (function code 33), E-Network 0xA022,
    E-Inter-Area-Prefix 0xA023, E-Inter-Area-Router 0xA024,
    E-AS-External 0xC025 (AS flooding scope), E-Type-7 0xA027,
    E-Link 0x8028 (link scope) and E-Intra-Area-Prefix 0xA029
    (function code 38 stays unallocated). RFC 3630 TLV framing
    (4-octet padded, padding not counted in Length), the §3 top-level
    TLV set (Router-Link, Attached-Routers, the prefix TLVs, the
    link-local address TLVs) and the External-Prefix sub-TLVs; the §5
    malformed rules decode to `None` (refused install/ack/flood);
    unknown TLV types skipped; duplicate single-instance TLVs keep the
    first. Origination helpers for all eight shapes.
  - **Extended-LSA reception** — `run_spf_v3_extended`,
    `summary_routes_v3_extended` and `external_routes_v3_extended`:
    a speaker's E-Router/E-Network/E-Link/E-Intra-Area-Prefix LSA
    overrides its legacy counterpart (first E-instance per router
    wins), and the E inter-area/external forms contribute alongside
    the legacy ones. The receiver decides the mode (RFC 8362 §6.1/§6.2
    — no wire capability negotiation exists): the legacy
    `run_spf_v3` path is byte-identical and never uses E-LSAs for the
    calculation, though they are still stored and re-flooded.
  - **`DefaultRouter::set_ospf_v3_extended_lsas`** — the
    `ExtendedLSASupport` knob (RFC 8362 Appendix A) driving the
    extended calculators; daemon surface `[ospf] extended_lsas` /
    `--ospf-extended-lsas`, OSPFv3-only and fail-closed under v2.
  - **Daemon origination** — with the knob on, the v3 daemon
    originates the E-Router/E-Network/E-Link/E-IAP forms instead of
    the legacy shapes (per-LSA sequence floors preserved, MaxAge flush
    paths switched symmetrically). ABR/ASBR origination stays legacy
    (RFC 8362 §6.1 migrates areas individually — every receiver
    interops).
  - No reference implementation originates E-LSAs (verified: FRR
    10.3+ and BIRD 2.17 have none), so acceptance is RFC-figure-pinned
    unit tests plus `tests/interop/ospf6_e_lsa.sh` — the two-daemon
    lab where `extended_lsas = true` makes legacy origination
    impossible, so adjacency + route convergence + link-local next
    hops + MaxAge withdrawal prove the E-LSA path end to end.

- SRv6 adjacency SIDs — RFC 9513 §9 over RFC 8362 (ROADMAP-v3 D13
  slice 3).
  - **`lr_ospf::lsa::srv6`** — the End.X SID sub-TLV (§9.1, registry
    type 31) and LAN End.X SID sub-TLV (§9.2, type 32) codecs riding
    the E-Router-Link TLV's sub-TLV region, with the §10 SID Structure
    as registry type 30 (at most once per parent, lengths summing to
    ≤ 128 bits); `walk_end_x_sub_tlvs` / `walk_lan_end_x_sub_tlvs`.
  - **`lr_ospf::srv6db::Srv6EndXSid`** — the projection from
    E-Router-LSA links, gated on §9 locator containment + algorithm
    match of the same router; multiple instances preserved (the same
    SID may serve several links; a link may carry several SIDs).
  - **`[[ospf.interface]] srv6_end_x`** — per-interface End.X SID
    origination (IPv6, fail-closed inside a configured
    `[[ospf.srv6_locator]]` prefix, p2p-only): under `extended_lsas`
    the sub-TLV rides the topology E-Router-LSA; under legacy mode a
    complete sparse-mode companion E-Router-LSA (RFC 8362 §6.2)
    carries it alongside the legacy topology. The projections surface
    on the daemon runtime API `status` as `srv6-endx` lines.
    `tests/interop/ospf6_e_lsa_endx.sh` pins adjacency + legacy-route
    neutrality + both projections.

- Per-session BGP UPDATE counters + filter-eval latency histograms
  on the Prometheus `/metrics` endpoint (ROADMAP-v3 D12.4).
  - **`lr_bgp::PeerMessageStats`** — FRR `show bgp neighbor`
    "Message statistics" parity on `BgpPeer`: OPEN / UPDATE /
    NOTIFICATION / KEEPALIVE / ROUTE-REFRESH counters per
    direction, counted at the wire boundary (every encoded
    outbound message books as sent through the new single
    `send_msg()` choke point; every decoded inbound message books
    as received in `feed_bytes`). Monotonic across session
    re-establishment — `reset()` leaves the counters untouched
    (per-neighbor semantics, surviving flaps like FRR). Exposed
    via `BgpPeer::message_stats()`.
  - **`SessionSummary::updates_received` / `updates_sent`** —
    the UPDATE counters surfaced through
    `DefaultRouter::session_summaries()` (0 for OSPF/Babel), the
    daemon runtime API `sessions` command (new `updates-rx=` /
    `updates-tx=` fields) and the FFI
    `lr_router_sessions_dump` text — additive `key=value` fields,
    existing parsers keep working.
  - **`lr_bgp_updates_total{session,peer,direction}`** — new
    Prometheus counter: per-session UPDATE counters labelled with
    the configured peer name/address (bidirectional peers get an
    `(inbound)` suffix on the RFC 4271 §6.8 collision challenger).
  - **`lr_filter_eval_duration_seconds{direction,filter}`** — new
    Prometheus histogram: import/export filter DSL evaluation
    latency, one series per (direction, filter name) including the
    internal `__roa_validate` filter (ROA-validation cost is
    separable from user policy). Fixed 16 buckets (100 ns … 10 ms
    + implicit `+Inf`), recorded through relaxed atomics — no
    locks on the per-route path. Recording and rendering are gated
    on the metrics endpoint being configured, so the filter hot
    path pays the two `Instant::now()` calls only while someone
    can scrape.

- Attribute fast paths for the filter DSL hot path (GitHub #19 P3):
  two new `Attributes` methods (`get_u32_be`, `get_u8`) read
  fixed-width integer attributes in place — no `Vec<u8>` clone, no
  intermediate `&[u8]` slice beyond the `BTreeMap` lookup. The
  production `FilterContext` accessors (`lr_policy::bgp::local_pref`,
  `med`, new `origin`) now use these methods, and the `vm_if_local_pref`
  bench's `BenchCtx` updated to match so the bench reflects the
  production fast path (the previous bench `attr()` helper cloned the
  `Vec<u8>` for every attribute read — a bench artifact that hid the
  real production cost).
  - **`Attributes::get_u32_be(tag) -> Option<u32>`** — reads a 4-byte
    big-endian u32 directly off the stored slice. Returns `None` when
    the tag is absent or the value is not exactly 4 bytes (a length
    mismatch indicates a malformed attribute; the caller's
    `unwrap_or(0)` default applies).
  - **`Attributes::get_u8(tag) -> Option<u8>`** — reads a 1-byte u8.
    Returns `None` when the tag is absent or the value is empty.
  - **`lr_policy::bgp::origin(route) -> Option<u8>`** — new function
    surfacing the route's ORIGIN attribute (RFC 4271 §4.2.1: 0=IGP,
    1=EGP, 2=INCOMPLETE). `DaemonFilterContext::bgp_origin` now reads
    the attribute from the route (previously hardcoded `Some(0)` —
    IGP, the BIRD `f_new` default for locally originated routes). The
    default is preserved: `origin(route).unwrap_or(0)`.
  - **`lr_policy::bgp::local_pref` / `med`** — updated to use
    `get_u32_be` (the previous `attr_bytes(route, TAG).and_then(|b|
    b.try_into().ok().map(u32::from_be_bytes))` was already
    zero-clone, but `get_u32_be` fuses the lookup + conversion into
    one call so the compiler can inline the whole read).
  - **Bench delta** (criterion, `--baseline p2`, `--quick`):
    - `vm_if_local_pref`: 83.5 → 66.4 ns (**−21 %**) — the headline
      P3 target. `if bgp.local_pref > 100` is the canonical import
      policy shape; the win is the BTreeMap lookup + `Vec` clone the
      bench's `attr()` helper paid (the production path was already
      zero-clone, but the bench now matches production).
    - `vm_complex_chain`: 224 → 207 ns (**−8 %**) — reads LOCAL_PREF
      and MED.
    - `vm_user_functions`: 437 → 409 ns (**−8 %**) — the `tag_customer`
      function writes LOCAL_PREF.
    - `import_pipeline/realistic/1000`: −5.4 %; `trivial/1000`:
      −4.2 % (statistically significant). No bench regresses.
  - **2 new tests** in `crates/lr-policy/src/bgp.rs` pin the
    `get_u32_be`/`get_u8` round-trips (LOCAL_PREF/MED/ORIGIN) and the
    edge cases (absent attribute, wrong-length value). 1703 tests
    pass total (was 1701, +2).
  - **No API break** — `get_u32_be`/`get_u8` are additive methods on
    `Attributes`; `origin` is a new public function. No FFI/binding
    updates needed.
- User-function call index resolution for the filter DSL bytecode
  (GitHub #19 P2): `Expr::Call { name, .. }` resolves to a new
  `Instr::CallFn { idx, argc }` instruction at compile time when
  `name` is a user-defined function, eliminating the `BTreeMap`
  lookup per call that `Instr::Call { name, .. }` previously paid.
  Built-in calls (`len`, `count`, `delete`, `filter`, `empty`,
  `first`, `last`) keep `Instr::Call { name, argc }` — the parser's
  `validate_calls` pass already guarantees every call name is a user
  function or a built-in, so the resolution is total.
  - **`CompiledFilter`** — `functions` changed from
    `BTreeMap<String, CompiledFunction>` to `Vec<CompiledFunction>`
    (indexed by `CallFn`), plus a new `function_index:
    BTreeMap<String, usize>` map (name → index). The VM's `CallFn`
    handler does `cf.functions[idx]` — a direct `Vec` index, no
    hash + string comparison. **BREAKING CHANGE** for embedders that
    access `CompiledFilter.functions` directly (the field type
    changed from a map to a vec); use `function_index` for name-based
    lookup. No FFI/binding updates needed — `CompiledFilter` is
    opaque across the FFI boundary.
  - **Bench delta** (criterion, `--baseline p5`, `--quick`):
    `vm_user_functions` improved **−1.25 %** (437 → 430 ns,
    p = 0.05). The `user_functions` bench calls 2 user functions
    per eval; the win is the 2 BTreeMap lookups eliminated. No
    other bench regresses — all existing shapes are within ±1 % of
    P5 (noise). The `import_pipeline` bench is also unchanged.
  - **Equivalence preserved** — the 27×4 policy table, the
    bench-shapes table, and the prefix-trie differential table in
    `crates/lr-policy/src/filter/eval.rs` all pass unchanged. 2 new
    tests pin the P2 contract: `p2_user_function_calls_resolve_to_callfn`
    (verifies `CallFn` is emitted for user functions, `Call` for
    built-ins) and `p2_callfn_matches_interpreter_on_user_functions`
    (verifies `CallFn` produces identical verdicts + route state
    vs the tree-walking interpreter across 4 filter sources × 3
    routes).
  - **What is NOT in P2.** Variable slot resolution (`LoadSlot`/
    `StoreSlot`/`AssignSlot` + frame-based scope management) was
    prototyped and benchmarked but not landed — the frame/scope
    double-write and the `Evaluator` allocation overhead regressed
    `vm_simple_accept` by +10 % and `vm_const_fold` by +29 %. The
    slot-resolution work is deferred until a bench with a hot
    variable-intensive filter (100+ `let`/`LoadVar` per eval) exists
    to amortise the fixed overhead, or until P3 (attribute fast
    paths) makes the frame pay for itself by eliminating the
    `Value` clone on attribute reads. P3 remains the highest-
    leverage remaining lever — it would eliminate the `Value` clone
    the `if_local_pref` bench (81.5 ns) pays on every attribute
    read.
- Peephole optimisation pass for the filter DSL bytecode (GitHub
  #19 P5): a new `crates/lr-policy/src/filter/peephole.rs` module
  runs three passes inside `bytecode::compile` after the
  AST-to-bytecode compiler emits the instruction stream.
  - **Constant propagation + literal folding** — a forward pass
    tracks `let`-bound constants in a `HashMap<String, Value>` and
    rewrites `LoadVar(name)` to `Push(v)` when `name` is a known
    constant. `Push(L1); Push(L2); Bin(Op)` triples fold to a
    single `Push(folded)` when both are literals and the fold
    cannot error (the pass refuses to fold division by zero,
    arithmetic overflow, and bad shift amounts — those errors must
    surface at runtime exactly as the unoptimised code surfaces
    them). `Push(Bool(b)); Not` and `Push(Int(n)); Neg` fold the
    same way. The constant map is invalidated at every control-flow
    join (`Jump`, `JumpIfFalse`, `JumpIfTrue`, `PushScope`,
    `PopScope`) and every side-effecting instruction (`Call`,
    `Method`, `EvalTree`, `AssignField`, `AppendField`, `Defined`,
    `AssignVar`) so the analysis is a single forward walk, not a
    full data-flow fixpoint.
  - **Dead-branch elimination** — after folding produces
    `Push(Bool(c)); JumpIfFalse(X)` or `Push(Bool(c));
    JumpIfTrue(X)`, the branch direction is known at compile time.
    `Push(Bool(true)); JumpIfFalse(X)` always falls through (drop
    both); `Push(Bool(false)); JumpIfFalse(X)` always jumps
    (replace with `Jump(X)`). The pass is only applied when the
    `JumpIfFalse`/`JumpIfTrue` is NOT a jump target from elsewhere
    — the `&&`/`||` short-circuit compilation emits `Jump(Le)`
    that targets the `JumpIfFalse` directly, so eliminating the
    branch in that case would change the stack state seen by the
    jump.
  - **Jump threading** — `Jump(X)` where `code[X]` is `Jump(Y)`
    is rewritten to `Jump(Y)`; same for `JumpIfFalse(X)` and
    `JumpIfTrue(X)` when `code[X]` is an unconditional `Jump`.
    Conditional-jump-to-conditional-jump is NOT threaded (the
    target conditional pops a stack value). Threads through chains
    of unconditional jumps until a fixed point per instruction.
  - **Jump-target safety** — both the fold and dead-branch passes
    compute the set of jump targets upfront and skip any
    optimisation that would consume an instruction that is a jump
    target. This is the key correctness invariant: collapsing a
    jump target would change the stack state seen by the jump
    source.
  - The passes iterate to a fixed point (constant propagation can
    expose new fold patterns), then run dead-branch elimination
    once, then jump threading once. The order is intentional:
    folding exposes dead branches, dead-branch elimination exposes
    new jump chains (a `Jump(X)` replacing a `JumpIfFalse(X)` may
    now target another `Jump`).
  - **Bench delta** (criterion, `--quick`): the new `const_fold`
    bench shape (`let a = 6; let b = 7; if a * b == 42 then accept;
    reject;`) measures the win — the tree-walk interpreter runs
    the unoptimised 12-instruction stream at 160 ns, the bytecode
    VM runs the peephole-optimised 6-instruction stream at
    119.5 ns, a **-25 % (1.34×)** speedup. The existing six bench
    shapes are all within ±2 % of P4 (noise) — the pass is a
    no-op on filters without foldable constants.
  - **Equivalence preserved** — the 27×4 policy table, the
    bench-shapes table, and the prefix-trie differential table in
    `crates/lr-policy/src/filter/eval.rs` all pass unchanged. 14
    new unit tests in `peephole.rs` pin the pass's golden output
    (folds, no-fold error cases, jump threading, self-loop safety,
    jump-target invalidation, no-op on dynamic filters).
  - **API additions** — `Instr`, `MatchItem`, `MatchRhs`,
    `DefinedTarget`, `Expr` derive `PartialEq, Eq` (the fold tests
    compare instruction streams for equality; the derives are
    additive and do not affect existing code). `Value` gains `Eq`
    (it was already `PartialEq`; all variants are integer/bool
    based). No public function signatures change; no FFI/binding
    updates needed.
- Prefix-trie set matching for the filter DSL (GitHub #19 P4):
  `PrefixSetTrie` in `crates/lr-policy/src/filter/bytecode.rs`
  replaces the O(n) linear scan over `MatchRhs::Set` prefix items
  with an O(prefix_len) covering walk. The trie is a
  path-compressed Patricia trie that borrows its structure from
  `lr-bgp::roa_trie` (ROADMAP-v3 D8.4) — the same flat-arena node
  layout, the same high-aligned `u128` key encoding, the same
  two-family root layout, the same covering-walk divergence
  rule — but stores `(ge, le)` range constraints instead of ROA
  entry indices. A new `MatchRhs::PrefixSet { trie, others }`
  variant is emitted by the compiler when the set contains at
  least one `MatchItem::PrefixSet`; non-prefix items (values,
  dynamic exprs) stay in `others` for a linear scan. Pure value
  sets keep `MatchRhs::Set` — no regression for sets the trie
  cannot help. Single-prefix patterns (`net ~ 10.0.0.0/8`) now
  also go through the trie (a one-node trie is cheaper than the
  one-element `Vec`).
  - Bench delta (criterion, `--baseline p0`): `vm_large_prefix_set`
    goes from 291 ns to 87.6 ns on `hit_last` (−70 %, 3.3× faster)
    and from 191 ns to 58.3 ns on `miss` (−69 %, 3.3× faster) —
    the biggest actionable win the P0 baseline surfaced. The
    import-pipeline bench shows the win compounding at scale:
    `realistic/10000` −8.8 %, `trivial/10000` −10.4 %,
    `realistic/1000` −5.3 %, `trivial/1000` −5.9 %. No shape
    regresses; the other VM shapes (`simple_accept`,
    `if_local_pref`, `complex_chain`, `large_community_set`,
    `user_functions`) are all within ±1 % of P0 (noise).
  - Engine equivalence: a new test
    `prefix_trie_matches_linear_scan_across_set_shapes` in
    `crates/lr-policy/src/filter/eval.rs` pins the trie ==
    linear-scan contract across five set shapes (plain /32s,
    `ge`/`le` ranges, IPv6, mixed prefix + value, overlapping
    ranges) and a hit/miss/longer/shorter/wrong-family query
    matrix. The existing 27×4 equivalence table and the
    bench-shapes table run verbatim against both `MatchRhs::Set`
    and `MatchRhs::PrefixSet`.
  - P1 (compact instruction encoding, `Instr { op, a: u32, b: u32 }`
    = 12 bytes) was attempted and reverted. The A/B bench showed
    a 2–10 % regression across every VM shape: the side-table
    indirection (one `Vec` lookup per dispatch) exceeded the
    cache-density win on the bench sizes (the existing benches
    exercise filters with ≤ 10 instructions, where the whole
    instruction stream fits in 1–2 cache lines either way). The
    process guardrail ("every optimisation lands with a bench
    delta attached, not an argument") was honoured — the P1
    regression was measured, not argued, and the change was not
    landed. The instruction-encoding work is deferred until a
    bench with a 1000+ instruction filter exists, or until P2/P5
    work makes the compact encoding pay for itself.
- DSL performance baseline benches (GitHub #19 P0): two new
  criterion benches in `crates/lr-policy/benches/` give the filter
  DSL and the daemon import pipeline a measurable perf baseline
  before the P1–P5 optimisation work begins.
  - `filter_eval.rs` grows from three shapes to six: the original
    `simple_accept` / `if_local_pref` / `complex_chain` are
    preserved verbatim (historical regression baselines keep
    working), and three new shapes exercise the realistic-load
    surface the issue comment calls out — `large_prefix_set`
    (100-entry `net ~ [...]`, measured on `hit_last` and `miss`
    positions), `large_community_set` (10-entry
    `bgp.communities ~ [...]`, same two positions) and
    `user_functions` (a two-call chain — classify + tag — that
    exercises the VM's call-dispatch overhead). Every shape runs
    under both engines: the tree-walking interpreter (`evaluate`)
    stays the semantic oracle; the bytecode VM
    (`bytecode::execute`) is the hot path the daemon runs per
    route after `daemon_policy::build_filters` precompiles every
    `[[filter]]` at startup.
  - `import_pipeline.rs` is the new daemon-level bench. For each
    route it runs the import path the daemon actually runs —
    bytecode eval → Adj-RIB-In install → Loc-RIB install — at
    three scales (100 / 1 000 / 10 000 routes) and under two
    filter shapes (`trivial` and `realistic`). The bench lives in
    `lr-policy` (DSL eval is the dominant component) and pulls
    `lr-rib` as a dev-dependency (no cycle — `lr-rib` does not
    depend on `lr-policy`). The bench is shaped to outlive the
    #18 config-format migration: the filter body is a string
    literal, not a config fragment, so the bench can be reused
    unchanged after the TOML→DSL migration lands.
  - Baseline numbers (criterion, `--quick`): the VM is at parity
    with the interpreter on the original three shapes — `if_local_pref`
    is where the VM still loses (+19 %), confirming the P1
    instruction-encoding hypothesis. The new shapes expose where
    the VM wins and loses today: `large_prefix_set` VM is 22–35 %
    *slower* than the tree walk (the linear `MatchRhs::Set` scan
    that P4 prefix-trie targets), `large_community_set` VM is
    43–45 % faster, `user_functions` VM is 64 % faster (the P2
    slot-resolution lever — call dispatch is the tree walker's
    worst case). The import-pipeline bench shows the per-route
    cost the daemon pays: ~570 ns / route at 100 routes,
    ~1.18 µs / route at 10 000 routes (BTreeMap log factor). These
    numbers are the P1–P5 deltas will be measured against.
  - Engine equivalence is load-bearing: a new test
    `vm_matches_interpreter_on_bench_shapes` in
    `crates/lr-policy/src/filter/eval.rs` pins the VM ==
    interpreter contract on the bench-sized shapes (100-entry
    prefix set, 10-entry community set, two-call user-function
    chain) across a six-route matrix. The 27×4 equivalence
    table is preserved unchanged; the new test is additive.
- RFC 8212 interop tests (ROADMAP-v3 D10.6): two end-to-end
  interop scripts verify lr-daemon's default RFC 8212 eBGP policy
  against real BIRD 2 and FRR bgpd. `tests/interop/rfc8212_bird.sh`
  and `tests/interop/rfc8212_frr.sh` each run two phases: Phase 1
  (default mode, no explicit policy) asserts the session reaches
  Established but BIRD/FRR does NOT learn lr-daemon's route and
  lr-daemon does NOT install BIRD/FRR's route — the RFC 8212
  import-deny and export-deny are both exercised; Phase 2 (explicit
  permit-all route-maps) asserts the route flows both directions,
  confirming the RFC-intended escape hatch. The startup warnings
  (`no export route-map; announcing nothing (RFC 8212)` and `no
  import route-map; discarding received routes (RFC 8212)`) are
  pinned as Phase 1 assertions. Both scripts are wired into the CI
  interop job. The scripts gracefully SKIP when `bird`/`birdc` or
  `bgpd` are not on `$PATH` (same pattern as every other interop
  script). The in-process `daemon_rfc8212.rs` tests remain — the
  interop scripts are additive, not replacement.
- FFI design document (ROADMAP-v3 D9.6): `docs/ffi_design.md` is
  the canonical reference for the librouting C ABI design — the
  panic-barrier contract, the `lr_bytes_t` ownership model, the
  cbindgen pipeline, the opaque-handle pattern, the non-reentrant
  lock hazard, what is NOT exposed and why (OSPF/Babel engines are
  daemon-driven, LDP has no router session model, BMP/MRT/BFD are
  codec-only), the error model, and the three-level testing
  strategy. Cross-references every section to the source file that
  implements it.
- Container image (ROADMAP-v3 D12.3): a multi-stage `Dockerfile` at
  the repo root builds the whole workspace in release mode with all
  features and ships the three CLI binaries (`lr`, `lr-daemon`,
  `lrctl`), `liblr_ffi.so` and the C / C++ headers into a
  `debian:bookworm-slim` runtime image. The builder stage pins
  `rust:1.88-slim-bookworm` (the workspace MSRV) and uses BuildKit
  mount caches on the cargo registry + target dir so a no-op rebuild
  is seconds. The runtime stage creates a non-root `lr` user,
  `EXPOSE`s `179/tcp` (BGP) + `9119/tcp` (metrics), declares
  `VOLUME /etc/lr-daemon` + `VOLUME /run/lr-daemon` (for config
  mount + `lrctl` sidecar pattern), and uses
  `ENTRYPOINT ["lr-daemon"]` with `CMD ["--help"]`. The image does
  NOT ship a default config and does NOT push to a registry from CI.
  The `.dockerignore` keeps the build context lean. The
  `docker/README.md` deployment guide covers quick start, production
  config-file mount, sidecar `lrctl`, image layout, exposed ports,
  volumes, the ~100 MB size target, and what the image does NOT
  include. The `.github/workflows/docker.yml` CI workflow builds the
  image on every push / PR / nightly, runs the three CLI binaries,
  verifies `liblr_ffi.so` is loadable via `ldconfig -p`, and reports
  the image size. Helm chart deferred — a Helm chart conventionally
  lives in its own repository so it can version independently of the
  image; the Dockerfile here is the foundation a chart would
  reference.
- Prometheus `/metrics` HTTP endpoint (ROADMAP-v3 D12.2): the daemon
  gains an opt-in HTTP endpoint that serves the Prometheus text
  exposition format on `GET /metrics` (`crates/lr-cli/src/metrics.rs`).
  Hand-rolled HTTP/1.0 responder — no `hyper` / `tokio` dependency,
  matching the project's stance on `api.rs`. Configuration:
  `--metrics-addr ADDR` CLI flag / `[bgp] metrics_addr = "…"` TOML
  key (default off, like `api_socket`); a bind failure is fatal
  (same stance as `spawn_api`). The exposition covers `lr_info`
  (gauge=1 with `version` / `local_as` / `router_id` labels, for join
  queries), `lr_uptime_seconds`, `lr_sessions_total{kind,state}`,
  `lr_established_sessions{kind}` (with explicit-zero for kinds that
  have sessions but none established), `lr_adj_rib_in_entries{kind}`,
  `lr_rib_entries`, and `lr_roa_entries` (omitted entirely when no
  ROA store is configured). `GET /` returns a one-line pointer to
  `/metrics`, `GET /nonexistent` returns `404`, non-GET methods
  return `404`. The `Runtime` struct gained an optional
  `roa_len: Option<Arc<dyn Fn() -> usize + Send + Sync>>` field so
  the BGP daemon can expose the live ROA count without holding a
  lock; OSPF/Babel/LDP/BMP/multi pass `None`. Wired into every
  daemon entry point via `spawn_metrics()`. 7 e2e tests in
  `crates/lr-cli/tests/daemon_metrics.rs`. Documented in
  `docs/RUNBOOK.md`, `docs/lr-cli.md` and `templates/daemon.toml`.
  Filter-eval latency histograms and UPDATE tx/rx counters landed
  later in this release (D12.4) — see the
  "Per-session BGP UPDATE counters + filter-eval latency histograms"
  bullet below.
- `lrctl` operational CLI (ROADMAP-v3 D12.1): a third `lr-cli` binary
  alongside `lr` and `lr-daemon`. Connects to a running `lr-daemon`
  over its Unix API socket and proxies the line-oriented command
  protocol: `lrctl status`, `lrctl sessions [list]`,
  `lrctl routes show [prefix]` (client-side prefix filter),
  `lrctl routes dump <path>` (MRT export via the daemon's `mrt PATH`
  command), `lrctl reload`, `lrctl shutdown`. Adds a client-side
  `lrctl filter compile <body>` that reuses
  `lr-policy::filter::compile` directly so operators can validate a
  filter body before deploying — the same parser path the daemon
  runs at startup. Default socket path `/run/lr-daemon.api` (matches
  `templates/daemon.toml`); `--socket PATH` overrides on any
  subcommand. Non-Unix targets refuse with a clear error. The
  release workflow stages `lrctl` in every platform archive. 10 e2e
  tests in `crates/lr-cli/tests/lrctl.rs`. Documented in
  `docs/lr-cli.md` (new `lrctl` section) and `docs/RUNBOOK.md`.
  `roa list` is deferred — exposing it requires threading the
  `RoaStore` through the daemon's `Runtime` struct (a follow-up
  commit).
- Filter DSL formal grammar reference (ROADMAP-v3 D9.2): the new
  `docs/filter_dsl_grammar.md` is the canonical EBNF reference for
  the BIRD-like filter DSL, derived directly from the lexer + Pratt
  parser source in `crates/lr-policy/src/filter/`. Covers the
  lexical structure, the full statement + expression grammar, the
  operator precedence table (mirroring `BinaryOp::precedence`), the
  route field reference, the `MAX_EXPR_DEPTH` / `MAX_CALL_DEPTH`
  limits, a worked-examples section and a BIRD-comparison table.
  The companion `crates/lr-policy/tests/grammar_corpus.rs` pins
  every example through `lr_policy::filter::compile` — 30 tests
  across positive, negative and boundary cases. The grammar
  captured two real divergences from the older in-tree BIRD
  example doc: the function return-type annotation uses `=>`
  (the same `TokenKind::Arrow` as `case` arms), not BIRD's `->`;
  and AS-path `~` is currently flat set-membership, not BIRD regex
  (the `_` wildcard token is parsed but does not yet carry
  meaning inside `~` patterns). Both are now documented as
  current behaviour with a follow-up pointer.
- BIRD `!~` (not-match) operator in the filter DSL (ROADMAP-v3 D14.5):
  the lr DSL AST has carried `BinaryOp::NotMatch` since the parser was
  first written — the evaluator and bytecode VM already lowered it to
  `Match { negated: true }` — but the lexer never produced a `!~`
  token, so no source program could exercise the path. The fix adds
  `TokenKind::BangTilde` to the lexer's multi-char set (alongside
  `!=` / `==` / …) and maps it to `BinaryOp::NotMatch` in the parser.
  The BIRD filter compat translator (D14.1) now passes `!~` through
  verbatim instead of fail-closing on it; BIRD and lr spell the
  operator identically.
- BIRD `case` statement translation (ROADMAP-v3 D14.6): a new
  structural pre-pass `rewrite_cases` in the BIRD filter compat
  translator walks the token stream and rewrites every BIRD
  `case … { … }` block into lr DSL syntax. The mapping was verified
  against BIRD's `filter/config.Y` §`switch_body` and `conf/cf-lex.l`
  (the `else:` ELSECOL token): arm separator `:` (at depth 1) → `=>`;
  `else :` → `default =>`; non-block arm bodies are wrapped in
  `{ … }` (lr DSL case arm bodies parse a single statement, which
  may be a `Block`); block arm bodies are left as-is; nested cases
  are handled recursively. Range arms (`a .. b:`) remain
  unfaithful — lr case arms match exact values only. `case` is
  removed from the translator's `UNMAPPABLE_WORDS` list.
- FFI expansion, third wave — D5 direction complete (ROADMAP-v3
  D5.1–D5.3): OSPFv2/OSPFv3/Babel session management
  (`lr_router_add_ospf_session` / `lr_router_add_ospfv3_session` /
  `lr_router_add_ospf_session_ext` with stub/NSSA area kinds, network
  type and the RFC 2328 §10.4 segment identities;
  `lr_router_add_babel_session` per RFC 8966 §4.2.1 — LDP sessions
  stay daemon-side by design); policy objects (`lr_route_new_v4/_v6`
  boxing a real `Route` with typed attribute setters/getters,
  `lr_prefix_list_*` with FRR ge/le semantics, `lr_route_map_*` +
  `lr_resolver_*` running the FRR route-map flow with fail-closed
  NULL-resolver semantics); and the Filter DSL over the C ABI
  (`lr_filter_compile` to the D3.7 stack VM, `lr_filter_evaluate`,
  `lr_filter_context_t` — the C callback variant of `FilterContext`
  where every NULL field keeps the built-in route-backed behaviour).
  C/C++/Go/Python bindings synced with tests; the C++ wrapper gains
  RAII `Route` / `PrefixListHandle` / `RouteMapHandle` /
  `ResolverHandle` / `Filter` types.
- FFI expansion, second wave (ROADMAP-v3 D5.4–D5.7): BGP message
  encoders (`lr_bgp_encode_open` with the RFC 6793 four-octet-AS
  capability, `lr_bgp_encode_notification`,
  `lr_bgp_encode_update_withdraw_v4` / `..._announce_v4`), event
  polling (`lr_router_poll_events` serializing `lr_event_t` batches
  with lossless requeue of the overflow), and the local route
  lifecycle (`lr_router_originate_v6`, `lr_router_withdraw_v4` /
  `_v6` — FRR `no network` semantics, idempotent on absent
  statements). `RouterInstance::unoriginate` now reports whether a
  route was actually removed (bool, non-breaking). The C/C++/Go/
  Python surfaces are all synced with tests.
- Cross-protocol interop labs (ROADMAP-v3 D4.5) closing the D4
  direction: `tests/interop/redistribute_bird.sh` (BIRD 2 speaks both
  ends of a BGP↔OSPF pipe over a veth pair — flushed out the
  Router-LSA V/E/B body-bits bug and the protocol-direct export
  missing ORIGIN/AS_PATH), `tests/interop/aggregate_bird.sh` (BIRD
  originates covering specifics, lr aggregates, BIRD verifies
  ATOMIC_AGGREGATE + AGGREGATOR + AS_PATH on the wire and the
  retraction after a SIGHUP route swap) and
  `tests/interop/damping_frr.sh` (FRR bgpd drives withdraw flaps
  into the `[damping]` table — three flaps suppress, the decay ticker
  reactivates below reuse, a post-reuse flap re-installs). All three
  wired into the CI interop job.
- FFI surface for the cross-protocol daemon features (ROADMAP-v3
  D4.4): `lr_router_add_redistribution_pipe` (BIRD `pipe` / FRR
  `redistribute` with metric policy, tag and allow-list),
  `lr_router_add_aggregate` / `lr_router_remove_aggregate` (RFC 4271
  section 9.2.2.2), and `lr_router_set_damping` + `lr_damping_decay` /
  `lr_damping_destroy` (RFC 2439 with an embedder-driven decay
  handle). C constants (`LR_PROTO_*`, `LR_METRIC_*`) ship in the
  generated header; the C++ RAII wrapper, Go and Python bindings all
  expose the new surface with tests, and the C/C++ harnesses exercise
  it in CI.
- Filter DSL bytecode VM (ROADMAP-v3 D3.7): the filter AST compiles
  to a flat instruction stream (jumps for short-circuits and
  branches, lifted constant patterns for `~`, presence instructions
  for `defined()`) executed by a stack VM sharing the interpreter's
  scope/function state, so the two engines are equivalent by
  construction (a 27-source equivalence table pins verdict + route
  state). The daemon's import/export filter hooks compile once at
  start-up and execute bytecode per route. Measured: 23.8 ns vs
  27.9 ns on bare accept, ~2% on complex chains.
- Filter DSL user-defined functions (ROADMAP-v3 D3.1): BIRD-style
  `function name(a, b) -> ret { ... }` declarations ahead of the
  filter body. Bodies run against the caller's route (mutations
  stick), arguments bind positionally in a fresh scope, `return` /
  bare-return / fall-off-the-end yield the call value (default
  `false`), and `accept` / `reject` inside a function terminate the
  whole filter. Runaway recursion is bounded (`MAX_CALL_DEPTH = 64`)
  and compile-time validation rejects undeclared calls, duplicates
  and built-in shadowing — typos fail at startup, not at route time.
- Filter DSL large communities (ROADMAP-v3 D3.2, RFC 8092):
  `LargeCommunity` struct + 12-byte codec in `lr-bgp` (byte-exact
  wire test), typed `PathAttributes` accessors, `lr_policy::bgp`
  helpers and the `bgp.large_communities` filter surface — `+=`, `=`,
  `.add/.delete/.filter`, `~` membership; 4-octet ASNs work natively
  (`4200000000:7:9`).
- Filter DSL extended communities (ROADMAP-v3 D3.3, RFC 4360): BIRD
  tuple literals `(rt, <asn|ip>, <local>)` / `(ro, ...)` / `(soo,
  ...)` mapped to the canonical transitive types (0x42 / 0x41),
  exposed as `bgp.ext_communities` with the same read/write/method
  surface. Note: the pre-existing `ExtendedCommunity` struct cannot
  represent the 2-octet-AS administrator form (type 0x00); the DSL
  steers literals to the canonical 4-octet form and wire bytes from
  peers still pass through opaquely.
- Filter DSL set operations (ROADMAP-v3 D3.4): BIRD `delete` /
  `filter` / `empty` / `count`, with wildcard community patterns
  (`asn:val`, `asn:*`, `*:val`, `*:*`) in set literals. Works
  value-level (`delete(cs, [64512:*])` on a local) and directly on
  route attributes (`bgp.communities.delete([...])`,
  `bgp.as_path.delete([...])`, `bgp.communities.filter([...])`).
  Assignment accepts the canonical BIRD idiom
  `bgp.communities = delete(bgp.communities, [64512:*]);` and
  `bgp.as_path = <sequence>`; `~` matches wildcard patterns. Two new
  `FilterContext` mutators (`set_bgp_communities`, `set_bgp_as_path`)
  — empty results drop the attribute.
- Filter DSL `defined()` / `exists()` (ROADMAP-v3 D3.5): presence
  checks for route attributes and scope variables, parsed structurally
  (`Expr::Defined`) so the argument is never evaluated and an absent
  attribute stays distinguishable from "set to the default". Optional
  attributes (`bgp.local_pref`, `bgp.med`, `bgp.next_hop`,
  `bgp.origin`) report presence from the typed accessors; list-valued
  attributes (`bgp.as_path`, `bgp.communities`) report presence as
  non-empty; `net` / `proto` / `source` / `roa.state` and literals are
  always defined. Any other expression probes against a route copy, so
  `defined()` can never write through. Seven regression tests cover
  the absent-vs-zero-MED distinction, the `exists` alias, list fields,
  variables and the one-argument arity error.
- ROADMAP-v3 D4.1 / D4.2 — daemon surfaces for the cross-protocol
  engines (`[[redistribute]]` and `[[aggregate]]` TOML tables):
  - `[[redistribute]]` (BIRD `pipe` / FRR `redistribute`): routes from
    `source` (`bgp` | `ospf` | `ospf3` | `babel`) are re-originated
    into `target` (`bgp` | `ospf` | `ospf3`) with an optional fixed
    `metric`, OSPF route `tag`, and prefix `allow` list. Fail-closed
    validation: unknown keys, unknown protocol names, unsupported
    targets, sources without a daemon injection surface, pipes into a
    non-running engine (protocol set + `[ospf] version` cross-check)
    and duplicate `(source, target)` pairs are all start-up errors.
    Installed once per process (supervisor or standalone BGP engine);
    the banner lists every pipe and the router logs each
    re-origination as `daemon: redistribute: <prefix> -> <TARGET>`.
  - `[[aggregate]]` (RFC 4271 §9.2.2.2): registers a BGP aggregate
    (zeroed AS_PATH + ATOMIC_AGGREGATE + AGGREGATOR) that is
    originated while a more-specific exists and withdrawn when the
    last one disappears. `summary_only` is refused on purpose — the
    router has no specific-suppression knob yet.
  - Router fix surfaced by the aggregate e2e: `recompute_aggregates`
    now flushes `export_selection` at origination, so an aggregate
    born after the session-up full sync reaches Adj-RIB-Out (with a
    `lr-tests` regression test).
  - E2E: `crates/lr-cli/tests/daemon_redistribute.rs` — the pipe's
    allow-list gates exactly the covered prefix (asserted through the
    router's own log events) and the aggregate traverses an A–B–C
    daemon chain end to end.
- Filter parser recursion limit (nightly fuzz fix): the recursive-
  descent parser now bails out with
  `ParseErrorKind::RecursionLimitExceeded` at `MAX_EXPR_DEPTH = 128`
  nesting levels instead of overflowing the stack on inputs like
  thousands of nested `[` set opens or `!` chains — the nightly
  `filter_parser` cargo-fuzz target found the crash (AddressSanitizer
  stack-overflow, 3 911-byte input). The limit also bounds the AST
  height, keeping recursive `Drop` glue and the tree-walking
  evaluator safe. The crashing input ships as a fuzz seed and a
  corpus-driven regression test
  (`crates/lr-policy/tests/filter_corpus.rs`) runs the whole committed
  seed corpus through `filter::compile`.


- BIRD 2 filter translation into the lr filter DSL (ROADMAP-v3 D14.1):
  `filter`/`function`/`define`/`roa table` blocks become `[[filter]]`
  bodies; `import|export filter NAME` and `import where EXPR` wire the
  filters to peers. Fail-closed per filter — constructs without a
  faithful lr mapping (BIRD-only route attributes, `case`, `print`,
  `!~`, `proto` comparisons, multi-table `roa_check`, …) leave the
  filter unemitted and reported. Operator mapping verified against
  BIRD's grammar and lexer: no `and`/`or`/`not` keywords exist in
  BIRD 2; BIRD equality `=` becomes `==` and assignment `:=` becomes
  `=`. Every emitted body must compile and reference only introduced
  variables. Inline channel bodies (`ipv4 { import all; };`) now
  split into statements instead of one UNMAPPED line, and `roa table`
  entries carry over as `[[roa]]` rows.
- BIRD `protocol babel` translation (ROADMAP-v3 D14.2): interface
  blocks map the RFC 8966 §A.2 parameters onto `[[babel.interface]]`
  tables (type/kind, rxcost, rtt cost/min/max with BIRD's time
  grammar, check link, extended next hop, port); protocol-level
  `next hop` statements backfill interfaces that lack their own.

### Changed

- **BREAKING** `lr-policy::hooks`: `ImportHook`, `SelectionHook` and
  `ExportHook` now require `Send + Sync` (previously `Send` only).
  Hooks are invoked on whichever thread owns the router guard, so
  shared-reference access is the real contract; the `Sync` bound lets
  read guards share `DefaultRouter` across threads (ROADMAP-v3 D8.1).
  Embedders with non-`Sync` hook state must wrap it in `Arc`/`Mutex` —
  a compile-time change, not a behavioural one.
- **BREAKING** `lr-cli` daemon surface: the shared router handle is
  `Arc<RwLock<DefaultRouter>>` (was `Arc<Mutex<...>>`). Read-only
  paths (API `routes`/`status`/`sessions` dumps, session summaries,
  Babel RTT probes, OSPF/LSDB status views) take the read lock and run
  concurrently with each other; mutating paths (session setup,
  `feed_input`, event polling, reselection, redistribution, Babel GC,
  config reload) take the write lock. All 81 call sites are classified
  and the classification is enforced by the borrow checker
  (`DefaultRouter` has no interior mutability) (ROADMAP-v3 D8.1).
- `lr-bgp::roa`: `RoaTable::validate` now walks a path-compressed
  (Patricia) prefix trie — `O(prefix_len)` per query instead of the
  `O(n)` entry scan. Entries keep their canonical sorted `Vec`
  (dumps, equality, snapshot determinism unchanged); the trie is a
  pure lookup index built once at construction.
  `RoaTableBuilder::build` now sorts and deduplicates like
  `from_entries`, so every construction path is byte-deterministic
  (ROADMAP-v3 D8.4). Criterion: ~5 ns uncovered / 75-182 ns covered
  across 1k/10k/100k tables.
- Performance documented in the new "Performance characteristics"
  section of `docs/ARCHITECTURE.md` — ROA lookup costs, the filter
  bytecode hot path, the daemon thread model, the RwLock read/write
  split and the scalability ceiling (ROADMAP-v3 D8.6).

### Fixed

- RFC 8212: DSL filter bindings now count as explicit policy. A
  peer configured with `import_filter`/`export_filter` but no
  route-map was treated as policy-less under the default
  `rfc8212` enforcement — its received routes were silently
  discarded even though the operator wrote an explicit filter.
  `set_session_policy` now considers both binding kinds (RFC 8212
  §3 speaks of "policy" broadly; FRR counts distribute-lists and
  route-maps alike). The startup warning text says "route-map or
  filter" accordingly.

- Route flap damping decay used the UNIX epoch as its time base while
  the import hook derives `now` from the router's monotonic
  milliseconds-since-daemon-start — every decay tick saw an
  astronomically large elapsed time, zeroed the figure-of-merit and
  instantly "reactivated" every suppressed prefix, so damping could
  never hold. The `lr-damping-decay` thread now ticks on the same
  monotonic base the router stamps `route.age_ms` with (caught live by
  the new `tests/interop/damping_frr.sh` FRR lab).
- `cargo bench --workspace -- <criterion args>` no longer dies on the
  first libtest target ("Unrecognized option: 'sample-size'"): every
  `[lib]` target and the `lr-cli` binaries now carry `bench = false`,
  so the bench-smoke nightly job exercises exactly the four criterion
  harnesses.
- ROADMAP-v3 D1 — Babel multi-session concurrency + per-interface
  parameters (RFC 8966 §3.3/§3.7.5/§A.2):
  - `[[babel.interface]]` glob patterns now resolve to one Babel
    session per matching system interface (first matching pattern wins,
    BIRD semantics), each with its own router-id, socket pair and
    per-interface `hello_interval_ms` / `update_interval_ms` /
    `rxcost` / `rtt_cost` / `rtt_min_us` / `rtt_max_us` /
    `next_hop_ipv4` / `next_hop_ipv6` / `extended_next_hop` / `port` /
    `group` / `check_link`. Dual-stack interfaces announce on both
    the IPv6 and IPv4 transports (§4.1).
  - Route re-advertisement between interfaces (§3.7.5): the origin's
    (router-id, seqno) is preserved with the interface cost added to
    the metric, split-horizoned per session; a claim that vanishes is
    retracted with an infinity-metric Update under the origin's
    Router-Id (§3.5.5). `check link` (BIRD `check link yes`, default
    on) withdraws a dead segment's routes within one second and
    resumes when it returns.
  - RFC 8966 §A.2.4 BABEL-RTT delay metric: Timestamp sub-TLV on
    Hellos, Timestamp Echo sub-TLV on IHUs, EWMA-smoothed RTT
    (babeld's decay 42/256, 1 s echo freshness, 600 s sanity, 180 s
    validity) and the linear `rtt_penalty` added to every advertised
    metric when `rtt_cost > 0`.
  - RFC 8966 §3.2.5 route expiry: every Update refreshes its claim's
    hold deadline (babeld's `hold_time = MAX(4·I/100 + I/50, 15)` s);
    `RouterInstance::babel_gc` (new) sweeps expiry once a second and
    retracts everything a dead neighbour taught us.
  - `RouterInstance::babel_rtt_echo` (new) exposes the IHU echo pair;
    `feed_input_at` now takes the transport's wall-clock milliseconds
    beside the 32-bit BABEL-RTT microsecond clock (the method ships
    for the first time in this release, so the signature is final
    rather than broken).
  - `[[babel.key]]` gained the `interface` pattern: keys apply only to
    matching interfaces (unscoped keys apply everywhere); each
    interface authenticates with its own RFC 8967 state.
  - E2E: `tests/interop/babel_multihop.sh` — three speakers in three
    namespaces chained over veth pairs (transit both ways through the
    multi-session middle box, `check link` withdrawal end-to-end,
    reconvergence), wired into CI.
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
