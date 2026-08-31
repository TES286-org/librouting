# Behaviour parity flags — lr vs. BIRD 2 vs. FRR 10

Where the BGP/Babel RFCs leave implementation latitude, mature
implementations diverge — and interoperability depends on knowing
which side of each latitude every speaker is on. This document lists
every behaviour-compatibility knob in librouting side by side with the
semantics of BIRD 2 and FRR 10, taken from their own documentation
(BIRD `doc/bird.sgml` at v2.17.5, FRR `doc/user/bgp.rst` at frr-10.3)
rather than from folklore.

Standing rule (from `STATUS.md` W2): support a reference
implementation's behaviour behind an explicit flag and never break
standards compliance by default. When lr's default differs from FRR's,
the difference is intentional and listed below.

## 1. Route acceptance without policy (RFC 8212)

| Speaker | Knob | Default |
|---------|------|---------|
| lr | `[bgp] ebgp_policy = "rfc8212" \| "accept-all"`, CLI `--ebgp-policy` | `rfc8212` |
| FRR | `bgp ebgp-requires-policy` | enabled (traditional), disabled (datacenter profile) |
| BIRD | no knob — eBGP requires explicit `import`/`export` | enforced |

* FRR: without the incoming filter no routes are accepted, without the
  outgoing filter none are announced; enabling/disabling requires a
  session clear.
* BIRD: "Due to RFC 8212, external BGP protocol requires explicit
  configuration of import and export policies" — other protocols keep
  the `import all`/`export none` defaults.
* lr: `rfc8212` denies both directions for external peers without an
  explicit policy (iBGP and confederation-internal sessions exempt);
  `accept-all` is the RFC 4271 default the RFC itself calls out as the
  insecure deviation (§3 / Appendix A). The interop scripts pin
  `--ebgp-policy accept-all` on the lr side so the labs exercise route
  exchange without policy boilerplate.

## 2. Enforce first AS (RFC 4271 §6.3)

| Speaker | Knob | Default |
|---------|------|---------|
| lr | `[bgp] enforce_first_as`, CLI `--enforce-first-as` / `--no-enforce-first-as` | off |
| FRR | `bgp enforce-first-as` (global) + `no neighbor NAME enforce-first-as` | **on** |
| BIRD | `enforce first as <switch>` (per protocol) | off |

* Semantics are aligned: an eBGP UPDATE whose AS_PATH leftmost sequence
  segment does not start with the peer's AS is rejected before
  Adj-RIB-In (BIRD additionally treats it as a withdraw; FRR logs and
  drops — lr surfaces the rejection as a `RouterEvent::Log` once per
  session).
* Defaults deliberately differ: FRR enforces by default, BIRD and lr do
  not. RFC 4271 §6.3 says a speaker "MAY" enforce, and route-server
  sessions legitimately break the assumption (FRR's own docs warn the
  peering to a route server "MUST disable" it). lr follows the
  permissive RFC latitude; turn the flag on to get FRR's default.
* Scope: lr applies it to eBGP and confederation boundaries; iBGP is
  exempt everywhere. FRR allows a per-neighbor override; the lr knob is
  router-wide.

## 3. Best-path tie-break: router-ID vs. older route (RFC 5004)

| Speaker | Knob | Default |
|---------|------|---------|
| lr | `[bgp] bestpath_compare_routerid`, CLI `--bestpath-compare-routerid` / `--no-…` | on |
| FRR | `bgp bestpath compare-routerid` | off |
| BIRD | `prefer older <switch>` (inverted polarity) | off |

All three express the same pair of alternatives, with different
polarities:

* **router-ID tie-break (RFC 5004 deterministic mode)** — when equal on
  local-pref, AS_PATH length, MED etc., prefer the lowest BGP
  Identifier (ORIGINATOR_ID if present, else the peer's router-ID).
  This is lr's default (`bestpath_compare_routerid = on`), BIRD's
  default (its `prefer older` is off, so ties "break by comparing
  router IDs"), and FRR's non-default (`compare-routerid`).
* **prefer the older route** — the RFC 5004 §4 "already-selected
  external check": prefer the route that is already selected, which
  reduces churn but is the oscillation-sensitive non-deterministic
  form. This is FRR's default, BIRD's `prefer older on`, and lr's
  `--no-bestpath-compare-routerid`.

## 4. Implicit IPv4 unicast activation

| Speaker | Knob | Default |
|---------|------|---------|
| lr | `[bgp] default_ipv4_unicast`, CLI `--default-ipv4-unicast` / `--no-…`, per-peer `[peer] default_ipv4_unicast` | on |
| FRR | `bgp default ipv4-unicast` (AF-scoped) | on |
| BIRD | no knob — channels are explicit | n/a (explicit) |

* FRR: "By default, only the IPv4 unicast address family is announced
  to all neighbors"; `no bgp default ipv4-unicast` makes activation
  fully explicit per address family.
* BIRD has no implicit family: a session exchanges only the families of
  its configured channels, and BIRD refuses a session whose
  capabilities match none of them (`Required capability missing`).
* lr's `default_ipv4_unicast = on` mirrors FRR's default and gates the
  RFC 4271 legacy section (withdrawals, NLRI, EoR) plus the implicit
  IPv4 unicast family. Because BIRD requires the capability to be
  advertised explicitly, the daemon's mp_families builder *adds* IPv4
  unicast to the advertised capability list when the flag is on (the
  two dialects need different wire behaviour from the same flag);
  with the flag off, the configured `mp_families` is used verbatim.

## 5. Local AS in AS_PATH (RFC 4271 §9.1.2.15)

| Speaker | Knob | Default |
|---------|------|---------|
| lr | `[bgp] allow_local_as = N \| "any"`, CLI `--allow-local-as [N]` / `--allowas-any`, per-peer `[peer] allow_local_as` | `0` |
| FRR | `neighbor PEER allowas-in [<(1-10)\|origin>]` | off (reject) |
| BIRD | `allow local as [<number>]` | off (reject) |

* All three reject a received AS_PATH containing the local AS by
  default and scope the relaxation to eBGP (iBGP is exempt everywhere —
  the route would be a loop anyway).
* `N` admits up to N occurrences (lr: any `u32`; FRR: 1..10; BIRD:
  any number). `"any"` / `allowas-any` / BIRD's argument-less form
  disable the check entirely.
* Not modelled in lr: FRR's `allowas-in origin` variant (accept only
  routes *originated* with the local AS — a different predicate from
  occurrence counting).

## 6. Soft reconfiguration inbound

| Speaker | Knob | Default |
|---------|------|---------|
| lr | `[bgp] soft_reconfig_inbound`, CLI `--soft-reconfig-inbound` / `--no-…`, per-peer `[peer] soft_reconfig_inbound` | off |
| FRR | `neighbor PEER soft-reconfiguration inbound` | off |
| BIRD | no knob | always retains |

* FRR: without the knob, received routes that an import filter rejects
  are forgotten and the only recovery is a route refresh or session
  clear; with it, the pre-policy routes are retained so policy can be
  re-applied with `clear ip bgp * soft in` without re-fetching.
* BIRD does not need the knob — every received route lives in a table
  and filters re-run on configuration changes by design.
* lr uses the router pipeline (post-policy Adj-RIB-In), so it needs an
  explicit second store like FRR: when enabled, the raw pre-policy
  routes are kept per session and `soft_reconfig_inbound(h)` re-runs
  the import hooks without touching the session. Default off matches
  FRR (the cost is duplicate RIB memory per peer); RFC 2918/7313 route
  refresh is the always-available alternative, exactly as in FRR.

## 7. Babel MAC incremental deployment (RFC 8967 §5)

| Speaker | Knob | Default |
|---------|------|---------|
| lr | `[[babel.key]]` + `[babel] accept_unauthenticated`, CLI `--babel-key` / `--babel-accept-unauthenticated` | strict |
| BIRD | babel `key …` per interface | strict |
| babeld | `key …` / `auth` | strict |

* With keys configured, all three sign every datagram and drop
  unauthenticated ones. lr's `--babel-accept-unauthenticated` enables
  exactly the RFC 8967 §5 migration mode: send authenticated, accept
  unauthenticated — used to roll out MAC auth across a running network
  and to interoperate with speakers that cannot be upgraded.
* The verification side is full RFC 8967 §4.3 either way (per-neighbour
  PC state, challenge/resync with rate limits, RFC 9467 §3.1 PC split
  and §3.2 windows on top); the flag only relaxes the *acceptance* of
  unauthenticated packets, never the signing.

## 8. Transport & session hardening (reference map)

Not "deviation knobs" — every entry is a standard feature — but the
config surface differs per implementation, so the mapping is listed
once:

| Feature | lr | FRR 10 | BIRD 2.17 |
|---------|----|--------|-----------|
| GTSM (RFC 5082) | `[peer] gtsm` / `--gtsm` | `neighbor PEER ttl-security hops N` | `ttl security` |
| TCP MD5 (RFC 2385) | `[peer] md5_key` / `--md5-key` | `neighbor PEER password …` | `password "…"` |
| TCP-AO (RFC 5925) | `[peer] tcp_ao_keys` (+ `tcp_ao_algorithm`, `tcp_ao_maclen`; kernel ≥ 6.7) | not in 10.3 | `key … algorithm tcp-ao …` |
| BFD single-hop (RFC 5881) | `--bfd` / `[peer] bfd` | `bfd` + bfdd profile | `protocol bfd` + `bfd on` |
| BFD multihop (RFC 5883) | `--bfd-multihop` / `bfd_multihop` | bfdd `multihop` | bfd `multihop` |
| Maximum-prefix | `[peer] max_prefixes` + `max_prefix_action` (warn\|teardown) + `max_prefix_threshold` | `neighbor PEER maximum-prefix N [warn-only]` | `max prefix N [restart\|warn]` |
| Route refresh (RFC 2918/7313) | always available, BoRR/EoRR when negotiated | always available | `enable/require (enhanced) route refresh` |

Notes: lr's maximum-prefix defaults to the Warn action with a 75%
early-warning threshold (the BIRD/FRR convention); the TearDown action
reproduces FRR's default hard-reset behaviour. TCP-AO parity is uneven
in the ecosystem — lr and BIRD 2.16+ speak it on Linux, FRR 10.3 does
not; the kernel must be ≥ 6.7 (`tests/interop/tcp_ao.sh` probes and
skips gracefully elsewhere).

## Deliberate non-parities

Recorded so nobody "fixes" them by accident:

1. **lr defaults are RFC-first.** enforce-first-as off (BIRD, RFC
   latitude) even though FRR defaults it on; deterministic router-ID
   tie-break on (BIRD, RFC 5004) even though FRR defaults the older
   route. The knobs let an operator pick FRR's defaults per deployment.
2. **`ebgp_policy = "accept-all"` exists at all** because real-world
   lab and route-server deployments need the RFC 8212 Appendix-A
   insecure mode; the daemon still warns per policy-less external peer.
3. **BIRD needs the IPv4 unicast capability advertised, FRR does not**
   — the same `default_ipv4_unicast` flag therefore produces
   capability-list differences per peer dialect (see §4). This is a
   wire-level necessity, not a policy difference.
