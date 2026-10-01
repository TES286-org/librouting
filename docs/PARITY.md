# Behaviour parity: lr against BIRD 2 and FRR

Where a routing RFC leaves an implementation latitude, mature
implementations take different sides of it, and interoperability depends
on knowing which side each speaker is on. This page is the single home
for every place lr differs from BIRD 2 (any 2.x) or FRR (8 and later),
taken from their own documentation and source rather than folklore. Read
it when you are migrating a configuration, or when you want to know
whether an lr default is deliberate before you "fix" it.

Each section states a divergence, what BIRD does, what FRR does, what lr
does, and how to change it. Sections that are pure reference mapping say
so. Where lr's default is the standard-conforming one, the section also
names the knob that selects the reference implementation's default.

The reference for dialect-level defaults when lr runs a BIRD or FRR
configuration file is [`COMPAT.md`](COMPAT.md); this page is about the
knobs themselves.

## 1. Route acceptance without policy (RFC 8212)

| Speaker | Knob | Default |
| --- | --- | --- |
| lr | `[bgp] ebgp_policy = "rfc8212" \| "accept-all"`, CLI `--ebgp-policy` | `rfc8212` |
| FRR | `bgp ebgp-requires-policy` | enabled in the traditional profile, disabled in the datacenter profile |
| BIRD | no knob — eBGP requires an explicit `import`/`export` | enforced |

- RFC 8212 §3: a route from an external peer is not eligible for the
  decision process without an import policy, and must not enter that
  peer's Adj-RIB-Out without an export policy.
- FRR: without the incoming filter no route is accepted, without the
  outgoing filter none is announced, and changing the setting requires a
  session clear. The datacenter profile relaxes it.
- BIRD: "Due to RFC 8212, external BGP protocol requires explicit
  configuration of import and export policies." Other protocols keep the
  `import all` / `export none` defaults.
- lr: `rfc8212` denies both directions for an external peer without an
  explicit policy; iBGP and confederation-internal sessions are exempt.
  `accept-all` is the RFC 4271 §9.1.3 default that RFC 8212 Appendix A
  calls out as the insecure deviation, and lr warns per policy-less
  external peer when it is selected.
- Change it with `--ebgp-policy accept-all` (or the `[bgp]` key, or the
  `lr: ebgp-policy` directive in a BIRD/FRR file). The interop labs pin
  `accept-all` on the lr side so that they exercise wire behaviour, not
  policy; `tests/interop/rfc8212_bird.sh` and `rfc8212_frr.sh` cover the
  default itself.

## 2. Enforce first AS (RFC 4271 §6.3)

| Speaker | Knob | Default |
| --- | --- | --- |
| lr | `[bgp] enforce_first_as`, CLI `--enforce-first-as` / `--no-enforce-first-as` | off |
| FRR | `bgp enforce-first-as`, per-neighbour `no neighbor NAME enforce-first-as` | on |
| BIRD | `enforce first as <switch>` per protocol | off |

- Semantics agree: an eBGP UPDATE whose leftmost AS_PATH sequence segment
  does not start with the peer's AS is rejected before Adj-RIB-In. BIRD
  additionally treats it as a withdrawal, FRR logs and drops, and lr
  surfaces the rejection as one `RouterEvent::Log` per session.
- The defaults deliberately differ. RFC 4271 §6.3 says a speaker MAY
  enforce, and a route-server session legitimately breaks the assumption
  — FRR's own documentation says peering with a route server MUST disable
  the check. lr follows the permissive latitude.
- Scope: lr applies the check at eBGP and confederation boundaries and
  exempts iBGP, like the other two. FRR allows a per-neighbour override;
  the lr knob is router-wide.
- Change it with `--enforce-first-as` to get FRR's default.

## 3. Best-path tie-break: router ID or older route (RFC 5004)

| Speaker | Knob | Default |
| --- | --- | --- |
| lr | `[bgp] bestpath_compare_routerid`, CLI `--bestpath-compare-routerid` / `--no-bestpath-compare-routerid` | on |
| FRR | `bgp bestpath compare-routerid` | off |
| BIRD | `prefer older <switch>`, inverted polarity | off |

All three express the same pair of alternatives:

- **Deterministic router-ID tie-break (RFC 5004 §3).** When local
  preference, AS_PATH length and MED are equal, prefer the lowest BGP
  identifier (ORIGINATOR_ID when present, else the peer's router ID).
  This is lr's default with `bestpath_compare_routerid = on`, BIRD's
  default (`prefer older` off), and FRR's non-default.
- **Prefer the older route (RFC 5004 §4).** Prefer the route already
  selected. This reduces churn and is the oscillation-sensitive
  non-deterministic form. It is FRR's default, BIRD's `prefer older on`,
  and lr's `--no-bestpath-compare-routerid`.

## 4. Implicit IPv4 unicast activation

| Speaker | Knob | Default |
| --- | --- | --- |
| lr | `[bgp] default_ipv4_unicast`, CLI `--default-ipv4-unicast` / `--no-…`, per-peer `[peer] default_ipv4_unicast` | on |
| FRR | `bgp default ipv4-unicast` | on |
| BIRD | no knob — channels are explicit | n/a |

- FRR: "By default, only the IPv4 unicast address family is announced to
  all neighbors." `no bgp default ipv4-unicast` makes activation explicit
  per address family.
- BIRD has no implicit family: a session exchanges only the families of
  its configured channels and refuses a session whose capabilities match
  none of them (`Required capability missing`).
- lr's flag gates the RFC 4271 legacy section — withdrawals, NLRI,
  end-of-RIB — plus the implicit IPv4 unicast family. Because BIRD
  insists that the capability be advertised explicitly, the daemon adds
  IPv4 unicast to the advertised capability list when the flag is on,
  while FRR needs no such capability. The one flag therefore produces a
  different wire shape per peer dialect; that is a necessity, not a
  policy choice. With the flag off, the configured `mp_families` is used
  verbatim.
- Change it with `--no-default-ipv4-unicast`.

## 5. Local AS in a received AS_PATH (RFC 4271 §9.1.2.15)

| Speaker | Knob | Default |
| --- | --- | --- |
| lr | `[bgp] allow_local_as = N \| "any"`, CLI `--allow-local-as [N]` / `--allowas-any`, per-peer `[peer] allow_local_as` | `0` |
| FRR | `neighbor PEER allowas-in [<1-10>\|origin]` | off |
| BIRD | `allow local as [<number>]` | off |

- All three reject a received AS_PATH containing the local AS by default
  and scope the relaxation to eBGP; iBGP is exempt everywhere, because
  the route would be a loop.
- `N` admits up to N occurrences: any `u32` in lr, 1 to 10 in FRR, any
  number in BIRD. `"any"`, `allowas-any` and BIRD's argument-less form
  disable the check entirely.
- Not modelled: FRR's `allowas-in origin`, which accepts only routes
  originated with the local AS — a different predicate from occurrence
  counting.

## 6. Soft reconfiguration inbound

| Speaker | Knob | Default |
| --- | --- | --- |
| lr | `[bgp] soft_reconfig_inbound`, CLI `--soft-reconfig-inbound` / `--no-…`, per-peer `[peer] soft_reconfig_inbound` | off |
| FRR | `neighbor PEER soft-reconfiguration inbound` | off |
| BIRD | no knob | always retains |

- FRR: without the knob, a route an import filter rejects is forgotten
  and the only recovery is a route refresh or a session clear. With it,
  the pre-policy routes are retained so policy can be re-applied with
  `clear ip bgp * soft in` without re-fetching.
- BIRD does not need the knob: every received route lives in a table and
  the filters re-run on a configuration change by design.
- lr uses the router pipeline and therefore stores post-policy
  Adj-RIB-In, so it needs an explicit second store like FRR. When the
  flag is on, the raw pre-policy routes are kept per session and
  `soft_reconfig_inbound(h)` re-runs the import hooks without touching
  the session. The default is off, matching FRR and avoiding duplicate
  RIB memory per peer; RFC 2918 and RFC 7313 route refresh is the
  always-available alternative, exactly as in FRR.

## 7. Babel MAC incremental deployment (RFC 8967 §5)

| Speaker | Knob | Default |
| --- | --- | --- |
| lr | `[[babel.key]]` plus `[babel] accept_unauthenticated`, CLI `--babel-key` / `--babel-accept-unauthenticated` | strict |
| BIRD | babel `key …` per interface | strict |
| babeld | `key …` / `auth` | strict |

- With keys configured, all three sign every datagram and drop
  unauthenticated ones. lr's `--babel-accept-unauthenticated` is exactly
  the RFC 8967 §5 migration mode: send authenticated, accept
  unauthenticated. It is for rolling MAC authentication out across a
  running network and for interoperating with a speaker that cannot be
  upgraded.
- The verification side is full RFC 8967 §4.3 either way — per-neighbour
  PC state, challenge and resync with rate limits, with the RFC 9467
  §3.1 PC split and §3.2 windows on top. The flag relaxes the acceptance
  of unauthenticated packets and never the signing.

## 8. Transport and session hardening (reference map)

These are standard features, not deviation knobs, but the configuration
surface differs per implementation, so the mapping is listed once.
TCP-AO availability differs as well: lr and BIRD speak it where the
Linux kernel supports it, and FRR's bgpd has no TCP-AO neighbour knob.

| Feature | lr | FRR | BIRD |
| --- | --- | --- | --- |
| GTSM (RFC 5082) | `[peer] gtsm`, `--gtsm` | `neighbor PEER ttl-security hops N` | `ttl security` |
| TCP MD5 (RFC 2385) | `[peer] md5_key`, `--md5-key` | `neighbor PEER password …` | `password "…"` |
| TCP-AO (RFC 5925) | `[peer] tcp_ao_keys` plus `tcp_ao_algorithm` and `tcp_ao_maclen` | no bgpd knob | `key … algorithm tcp-ao …` |
| BFD single-hop (RFC 5881) | `--bfd`, `[peer] bfd` | `bfd` plus a bfdd profile | `protocol bfd` plus `bfd on` |
| BFD multihop (RFC 5883) | `--bfd-multihop`, `bfd_multihop` | bfdd `multihop` | bfd `multihop` |
| Maximum-prefix | `[peer] max_prefixes`, `max_prefix_action`, `max_prefix_threshold` | `neighbor PEER maximum-prefix N [warn-only]` | `max prefix N [restart\|warn]` |
| Route refresh (RFC 2918, RFC 7313) | always available, BoRR and EoRR when negotiated | always available | `enable/require (enhanced) route refresh` |

Notes:

- **Maximum-prefix.** lr defaults to the Warn action with a 75 % early
  warning (the BIRD and FRR convention). `max_prefix_action` also takes
  `teardown`, which reproduces FRR's hard reset: teardown sends a CEASE
  NOTIFICATION and purges the routes the peer installed (RFC 4271
  §8.2.2). lr's third value, `restart`, behaves like `teardown`; neither
  implements BIRD's re-establishment cooldown.
- **TCP-AO.** lr's keys are installed on the socket through
  `lr-osroute::tcp_auth`, which needs a kernel built with `CONFIG_TCP_AO`
  (Linux 6.7 and later). On an older kernel the key install fails with
  `Protocol not available` and there is no fallback; use TCP MD5 or plain
  TCP with BFD. `tests/interop/tcp_ao.sh` probes this and skips cleanly
  elsewhere.

## 9. OSPF network type and DR election (RFC 2328 §9.4, §10.4)

| Speaker | Broadcast knob | Default network type | DR election |
| --- | --- | --- | --- |
| lr | `[[ospf.interface]] network_type = "broadcast"` | point-to-point | full §9.4: Waiting window, BackupSeen and WaitTimer, the §9.4 step-4 re-election, the §10.4 adjacency gate, the §12.4.2 Network-LSA |
| BIRD 2 | interface `type broadcast`, or auto-classified | auto: broadcast on multiaccess plus multicast media, ptp otherwise | full §9.4 (`ospf_dr_election`) |
| FRR 10 | `ip ospf network broadcast` | auto: broadcast on ethernet-classed media | full §9.4 (`ospf_dr_election`) |

- lr's daemon behaves p2p everywhere until a per-interface
  `network_type = "broadcast"` opts in, so existing labs keep their
  adjacency behaviour. The election follows the RFC step order and was
  cross-checked against BIRD's `elect_bdr` and `elect_dr` and FRR's
  `ospf_dr_election`: the identity is the IP interface address
  (§A.3.2) with a router-ID tie-break.
- While an lr broadcast interface is Waiting — one RouterDeadInterval
  after the interface comes up (§9.3) — no adjacency forms, the same as
  BIRD's `can_do_adj` in `OSPF_IS_WAITING`.
- A secondary address on a broadcast interface stays a type-3 stub link
  when the primary address is described by a transit link. BIRD models
  each address as its own OSPF interface and FRR keeps one interface
  structure per connected prefix; in all three the extra prefix stays
  routed.

## 10. Dialect defaults when lr runs a BIRD or FRR file

A compat-loaded configuration follows its source dialect's defaults
rather than lr's own. The table lives in [`COMPAT.md`](COMPAT.md) §Dialect
defaults, next to the surface it describes; an `lr:` directive overrides
any single default explicitly.

## 11. ROA prefix-origin validation (RFC 6811)

| Feature | lr | BIRD | FRR |
| --- | --- | --- | --- |
| ROA source | `[[roa]] prefix, max_length, asn` | `roa table` plus an RPKI session | `rpki` cache |
| Validation trigger | `[bgp] roa_validate = true` | `rpki reload` | `bgp rpki on` |
| Invalid action | `roa_invalid_action = "reject"` | `reject` | `bgp rpki invalid reject` |
| Filter access | `roa.state == "invalid"` | `roa_check()` | `extcommunity rt …` |
| Malformed ROA | fail closed | strict | strict |

## 12. BIRD-like filter DSL

lr's `[[filter]]` tables target a subset of BIRD's filter grammar. The
compiler in `lr-policy::filter` lowers a body to a flat instruction stream
executed by a stack-machine bytecode VM, with the tree-walking interpreter
kept as the semantic oracle. An equivalence table pins verdict and
attribute-state equality between the two engines so they cannot drift,
and the daemon precompiles every `[[filter]]` at startup so each
import/export evaluation takes the bytecode path.

| Feature | lr | BIRD |
| --- | --- | --- |
| `if`/`then`/`else` | yes | yes |
| `let` bindings | yes | yes (`int x = …`) |
| Arithmetic `+ - * / %` | yes | yes |
| Comparison `== != < <= > >=` | yes | yes |
| Boolean `&& \|\| !` | yes | yes (`and or not`) |
| Bitwise `& \| ^ << >>` | yes | yes |
| Prefix-set `net ~ [ p{ge,le} ]` | yes | yes |
| `bgp.local_pref = N` | yes | yes |
| `bgp.communities += [ asn:val ]` | yes | yes |
| `bgp.as_path.prepend(N)` | yes | yes |
| `accept` / `reject` | yes | yes |
| `case` | yes | yes |
| `len(bgp.as_path)` | yes | yes |
| `roa.state == "invalid"` | yes | `roa_check()` |
| Bytecode compilation | yes, stack VM | yes, `f_line` |

Implementation and harnesses: `crates/lr-policy/src/filter/` for the
compiler, VM and peephole pass, and
`crates/lr-policy/benches/` for the criterion benches.

## 13. Babel multi-NIC with glob patterns

| Feature | lr | BIRD |
| --- | --- | --- |
| Per-interface parameters | `[[babel.interface]]` | `interface "eth0" { … }` |
| Glob patterns | `name = "eth*"`, with `*`, `?` and `\` | `interface "eth*" { … }` |
| Wired, wireless, tunnel | `type = "wired"` | `type wired` |
| RTT-based cost | `rtt_cost`, `rtt_min_us`, `rtt_max_us` | `rtt cost`, `rtt min`, `rtt max` |
| Per-interface keys | `[[babel.key]]`, global | `passwords`, per interface |
| First match wins | yes, in file order | yes, in file order |

## 14. Kernel FIB mirroring

Not a protocol knob, but a visible divergence in what an operator sees in
the routing table.

- **BIRD** installs routes through `protocol kernel` (or `protocol
  static`), whose `import`/`export` filters and preference decide what
  reaches the kernel.
- **FRR** routes between bgpd and the kernel through zebra, which
  arbitrates every protocol's contribution by administrative distance.
- **lr** installs kernel routes only when asked: `--install-kernel-routes`
  (or `install_kernel`, or the `lr: install-kernel` directive). The
  router pipeline owns the Loc-RIB, so the kernel mirror is opt-in and
  off by default. `tests/interop/bgp_kernel_install.sh` pins the
  learn, install, decide, forward and teardown contract on the real FIB
  of each platform.

## 15. Route aggregation

- **BIRD** aggregates through a `protocol aggregate` stanza that has its
  own table and filters.
- **FRR** aggregates with `aggregate-address`, which also takes
  `summary-only` and an `as-set` form.
- **lr** takes `[[aggregate]]` entries, originates the aggregate when at
  least one specific is present, zeroes the AS_PATH and sets
  ATOMIC_AGGREGATE and AGGREGATOR (RFC 4271 §9.2.2.2). There is no
  `as-set` form and no per-aggregate filter; use a `[[filter]]` for the
  policy part. `tests/interop/aggregate_bird.sh` checks the shape against
  BIRD.

## Deliberate non-parities

Recorded so that nobody "fixes" them by accident:

1. **lr's defaults are RFC-first.** Enforce-first-as is off, matching
   BIRD and the RFC latitude, although FRR defaults it on. The
   deterministic router-ID tie-break is on, matching BIRD and RFC 5004,
   although FRR defaults to the older route. The knobs let an operator
   select FRR's defaults per deployment.
2. **`ebgp_policy = "accept-all"` exists at all** because lab and
   route-server deployments need the RFC 8212 Appendix-A insecure mode.
   The daemon still warns per policy-less external peer.
3. **BIRD needs the IPv4 unicast capability advertised and FRR does
   not**, so the one `default_ipv4_unicast` flag produces per-dialect
   capability lists (§4). This is a wire-level necessity.
4. **The `restart` maximum-prefix action has no cooldown yet.** It tears
   the session down like `teardown`, where BIRD refuses to re-establish
   for the configured period. Treat `restart` as an alias until the
   cooldown lands.
