# Roadmap v2 — workstream landing log

The full narrative record for the six roadmap-v2 workstreams: what
each item delivered, the design decisions taken, the interoperability
evidence, and the bugs flushed out along the way. Items are struck
through as they land; the strike-through text stays as the audit
trail.

The *current* implemented-vs-missing snapshot lives in
[`STATUS.md`](STATUS.md) — the capability tables there are kept
synchronized with the code and supersede anything stale here. Rule of
thumb: STATUS.md answers "what can it do today", this file answers
"how did it get there and why".

## Roadmap v2 — toward a complete routing stack

Six workstreams, ordered by expected user value. Work top-down inside
each workstream; cross-workstream ordering is a judgement call, but
protocol-correctness items (W3) always beat convenience items when in
doubt. Items get checked off here as they land.

### W1 — A complete daemon (`lr-daemon`)

The reference daemon must be able to run a real router on its own,
BIRD/FRR-style, without an embedder writing code.

1. ~~**Multi-peer daemon**~~ — done: `[[peer]]` array-of-tables in the
   TOML config with per-peer settings (AS, transport, auth, GTSM,
   maximum-prefix, Add-Path, MP families) inherited from the `[bgp]`
   globals when omitted; repeatable `--peer` CLI flag; one connector
   thread per outbound peer (independent reconnect/backoff); the
   listener accepts concurrent sessions and matches inbound
   connections to configured peers by source address (fail-closed);
   centralized event consumption so Loc-RIB ordering is preserved;
   the previously-ignored TOML keys (`graceful_restart_time`,
   `llgr_stale_time`, `llgr_max_stale_time`, `install_kernel`) now
   parse. Verified by 6 parser unit tests + 4 daemon E2E tests
   (fan-out/transit, inbound matching, unmatched rejection, per-peer
   hold time). Bidirectional peers (`remote` + `address` on one peer)
   landed on top: the daemon runs the two transports on separate
   sessions in one collision group and resolves a connection collision
   per RFC 4271 §6.8 — the connection initiated by the speaker with
   the higher BGP Identifier survives, the loser gets a Cease /
   Connection Collision Resolution NOTIFICATION (see the BGP
   capability table and `crates/lr-cli/tests/daemon_collision.rs`).
   Heterogeneous listener auth keys are still future work.
2. ~~**Config completeness**~~ — done: the previously-ignored documented
   keys (`graceful_restart_time`, `llgr_stale_time`,
   `llgr_max_stale_time`, `install_kernel`) parse, and unknown keys /
   sections / tables now produce line-numbered warnings (kept
   non-fatal for forward compatibility) surfaced at startup
   (`config warning: …`) and on reload.
3. ~~**BFD in the daemon**~~ — done: `--bfd` (or per-peer `bfd =
   true`) starts one BFD session per peer via
   `lr-osroute::bfd_transport` (shared rx socket on 3784 single-hop /
   4784 multihop with the RFC 5881 §5 TTL filter, per-session
   ephemeral source ports) and fast-fails BGP: a BFD Up→Down
   transition tears the session down with a CEASE NOTIFICATION and a
   route purge instead of waiting out the hold timer; the connector
   holds off reconnecting while BFD is down (after first Up — BIRD
   `bgp_bfd_notify` parity). Timing: `[bgp] bfd_min_tx_ms /
   bfd_min_rx_ms / bfd_multiplier` globals with per-peer overrides
   and CLI flags; `bfd_multihop = true` switches to RFC 5883. Verified
   by `crates/lr-cli/tests/daemon_bfd.rs` (SIGSTOP freeze: BGP down
   in ~0.5s at 100ms×3 vs a 60s hold time) and
   `tests/interop/bfd_bird.sh` (BIRD `protocol bfd` + `bfd on`, both
   single-hop and multihop). Landing this drove an lr-bfd
   wire-correctness overhaul: RFC 5880 §4.1 flag bits (the old code
   had a phantom ECHO flag on the Final bit and no Poll/Final), the
   IANA auth type codes, §4.2-§4.4 auth section layouts, and the
   §6.8.6 state machine (Down+Init→Up / Init+Init→Up — the old
   mapping deadlocked two conforming peers in Init forever).
4. ~~**Policy in config + reuse** (external request)~~ — done, three
   slices, in order:
   a. ~~**Policy engine completion**~~ — done: new `lr-policy::bgp`
      module decodes/encodes AS_PATH, COMMUNITIES and MED straight
      on the raw attribute bag (no whole-bag conversion); community
      lists do first-match/implicit-deny against real communities;
      AS-path filters get an FRR-parity pattern matcher (`^ $ _`,
      documented substring semantics); `set med`, `as-path prepend`
      and `add community` now write real attributes. Feature-gated
      `lr-policy → lr-bgp` (default on, no cycle). 14 new unit tests
      against real attribute bytes.
   b. ~~**Policy objects in TOML**~~ — done: `[[prefix-list]]`,
      `[[as-path-list]]`, `[[community-list]]`, `[[route-map]]`
      tables with per-peer `import`/`export` attachment; entries in
      ascending `entry` order; unknown keys inside policy tables and
      unknown references are startup errors (fail closed). Router
      export hooks gained a destination-aware variant
      (`ExportHook::on_export_to`) so per-peer export policy
      dispatches on the egress session — backward compatible via a
      default method. `lr_policy::PolicySet` + `PolicyHooks` are the
      reusable bridge; the daemon wires them in one block. E2E:
      export filter, import filter, set-actions keep-route,
      unknown-reference startup failure (4 tests).
   c. ~~**Peer templates**~~ — done: `[peer-template.<name>]` tables
      holding any `[[peer]]` key (incl. policy attachments); peers
      pull them in via `extends = "<name>"`, per-peer keys override,
      template chains resolve least-specific-first, cycles and
      unknown names are startup errors. Resolves the copy-paste
      burden of multi-peer configs without inventing a new language
      (TOML has no anchors). 3 parser unit tests + template e2e.
5. ~~**OSPF daemon mode**~~ — done: `--protocol ospf` with
   area/interface configuration (`[[ospf.area]]` +
   `[[ospf.interface]]` TOML tables, `--ospf-interface` /
   `--ospf-area` / `--ospf-hello-interval` / `--ospf-dead-interval`
   CLI flags, fail-closed key schemas). Transport: one raw
   `IPPROTO_OSPF` socket per interface (`lr-osroute::ospf_transport`,
   Linux) with `SO_BINDTODEVICE` + `ip_mreqn` multicast scoping; the
   daemon originates Hellos (with the heard-router list), discovers
   neighbors dynamically — one session per `(area, router-id)`, one
   anchor session per area registering the area type — originates
   and re-originates the Router-LSA per area (stub links from
   interface addresses, p2p links per Full adjacency), verifies
   inbound packet checksums and finalizes them on egress. Verified by
   `tests/interop/ospf.sh`: two daemons over a veth pair (one network
   namespace each, rootless via `unshare -Urn`) reach Full adjacency,
   exchange stub nets both directions (10.99.2.0/24 ↔ 10.99.3.0/24)
   and tear the session down on the dead timer. Broadcast segments
   (`network_type = "broadcast"`) run the RFC 2328 §9.4 DR/BDR
   election end-to-end — see the OSPF capability table. Scope notes:
   OSPFv2 only (v3 needs Link-LSAs); auth and reload are not wired
   into the daemon yet.
6. ~~**Operational tooling**~~ — done: the `lr-mrt` crate (RFC 6396)
   reads and writes TABLE_DUMP_V2 dumps (peer index tables,
   RIB_IPV4/IPv6_UNICAST incl. the ADDPATH variants; BGP4MP decode for
   stream tools) and `lr mrt parse|rib` inspects them; the daemon's
   runtime API `mrt <path>` dumps the Loc-RIB in the exact shape
   BIRD's `protocol mrt` produces (byte-verified in the interop suite,
   BIRD dump -> lr parse and back). BMP grew both directions: egress
   `--bmp-target` (channel + reconnecting sender thread wiring the
   router sink) and collector mode `--protocol bmp --listen` (accepts
   stations, decodes Peer Up/Down + Route Monitoring with the split
   feed/next_message codec API, mirrors monitored prefixes into the
   Loc-RIB via `originate_with_attributes` so routes/status/mrt serve
   them). Route Monitoring now carries the full UPDATE (real path
   attributes, MP_REACH for IPv6) and Peer Up mirrors before it even
   under TCP coalescing. RIB *restore* is `originate_with_attributes`
   + `parse_file` — an offline router fed from a dump (the MRT
   round-trip e2e covers the encode side; a full restore CLI remains
   future work). Known limitation: Debian's bird2 package ships
   without the BMP protocol, so the BMP e2e uses two lr-daemons; a
   BIRD-side BMP test waits on a BMP-enabled build.

### W2 — BIRD / FRR non-standard compatibility (selective)

Where BIRD or FRR deviate from (or extend) the RFCs in ways that
matter for interoperation, support the behaviour behind explicit
flags; never break standards compliance by default.

1. ~~**FRR `bgp default ipv4-unicast`**~~ — done: `PeerConfig`
   gained a `default_ipv4_unicast: bool` field (default `true` —
   matches FRR's default and the RFC 4271 implicit IPv4 unicast
   family) plus a helper `ipv4_unicast_active()` returning
   `default_ipv4_unicast || mp_families.contains(IPV4_UNICAST)`. The
   FSM gates legacy-section IPv4 NLRI (withdrawals, NLRI, EoR) on it
   in `lr-bgp::fsm::handle_update_in_established`; `advertise.rs`
   gates `advertise()`, `withdraw_paths()` and `send_end_of_rib()`;
   Add-Path / LLGR `advertised_families()` drop the implicit IPv4
   unicast when the flag is off. The router gained
   `set_session_default_ipv4_unicast(h, on)`; `SessionConfig`
   carries the field through `add_session` to PeerConfig. The daemon
   wires the router-level `[bgp] default_ipv4_unicast = bool` (default
   `true`) + CLI `--default-ipv4-unicast` / `--no-default-ipv4-unicast`
   + per-peer override `[peer] default_ipv4_unicast = bool`. The
   daemon's mp_families builder now always overrides the
   `SessionConfig::bgp()` default (which keeps IPv4 unicast for BIRD
   capability interop): when `default_ipv4_unicast=true` it ensures
   `IPV4_UNICAST` is in the family list (BIRD requires the
   capability to match one of their channels), when `false` it leaves
   the list as configured so the user's explicit `mp_families`
   determines what's active. FFI:
   `lr_router_set_default_ipv4_unicast(r, session, enabled)`, with
   Go (`Router.SetDefaultIPv4Unicast`) and Python
   (`Router.set_default_ipv4_unicast`) mirrors; the C harness
   smoke-tests the on/off round-trip + unknown-handle fail-closed.
   Verified by 4 PeerConfig unit tests, 3 FSM tests (EoR, NLRI,
   withdrawals all suppressed when the flag is off), 1 daemon_config
   unit test, 3 daemon e2e tests (default-on propagates routes,
   `--no-default-ipv4-unicast` suppresses them, explicit
   `--mp-family ipv4-unicast` reactivates), and the C/Go/Python
   binding smoke tests.
2. ~~**FRR `bgp enforce-first-as` + `bgp bestpath compare-routerid`**~~
   — done: the router gained `set_enforce_first_as(bool)` (default
   off — matches FRR `no bgp enforce-first-as` and the RFC 4271 §6.3
   "MAY reject" latitude). With it on, an UPDATE from an external
   peer (eBGP or a confederation boundary, mirroring the W2.1
   scope) whose leftmost AS_PATH sequence segment's first AS is not
   the peer's negotiated AS is dropped before Adj-RIB-In and the
   rejection is surfaced once per session as a `RouterEvent::Log`;
   iBGP and confederation-internal sessions are exempt. The decoder
   uses the FSM-normalized canonical AS_PATH (always 4-byte after the
   `lr-bgp` codec's AS4_PATH merge) — no wire-width guessing. FRR
   `bgp bestpath compare-routerid` is exposed through the existing
   `BestPathConfig::deterministic_router_id` knob: the daemon wires
   it via `[bgp] bestpath_compare_routerid = bool` (default true —
   RFC 5004 deterministic, the inverse of FRR's default). Daemon
   surfaces both as `--enforce-first-as` / `--no-enforce-first-as`
   and `--bestpath-compare-routerid` / `--no-bestpath-compare-routerid`
   CLI flags plus the `[bgp] enforce_first_as` /
   `[bgp] bestpath_compare_routerid` TOML keys; the startup status
   printout names both. FFI: `lr_router_set_enforce_first_as` mirrors
   the C ABI; Go (`Router.SetEnforceFirstAs`) and Python
   (`Router.set_enforce_first_as`) bindings round-trip; the C harness
   smoke-tests the new entry point. Verified by 4 router unit tests
   (default-off accepts, accepts the well-formed case, rejects a
   forged AS_PATH via a hand-rewritten wire UPDATE, iBGP exemption)
   and 2 daemon e2e tests (the flag parses, legit traffic still
   flows, the status printout names the new knobs).
3. ~~**BIRD `bgp allow local as`**~~ — done: `PeerConfig` gained a
   `local_as_tolerance: u32` field (default `0` = reject any
   occurrence of the local AS in a received AS_PATH — RFC 4271
   §9.1.2.15). The router's `import_route` now consults the per-peer
   tolerance when the safety net's `reject_as_loop` fires: on an
   eBGP peer with `tolerance > 0`, the route is admitted when the
   local AS count is ≤ tolerance (FRR `allowas-in N`); `u32::MAX` is
   the `allowas-any` sentinel. iBGP is exempt (FRR/BIRD scope the
   relaxation to eBGP). The new `count_local_as` helper reads the
   FSM-normalized canonical AS_PATH via `PathAttributes::as_path()`,
   fixing a latent width-guessing bug in the safety net's
   `local_as_count` that silently broke `reject_as_loop` for routes
   from any modern peer sending 4-byte AS_PATH (the FSM rewrites
   tag-2 AS_PATH to 4-byte, but the old counter treated tag-2 as
   2-byte when AS4_PATH was absent — undercounting local AS
   occurrences). The router gained
   `set_session_local_as_tolerance(h, N)`; `SessionConfig` carries
   the field through `add_session`. The daemon wires the router-wide
   `[bgp] allow_local_as = N|any|true|false` (default `0`) + CLI
   `--allow-local-as [N]` / `--allowas-any` + per-peer override
   `[peer] allow_local_as`. FFI:
   `lr_router_set_local_as_tolerance`, with Go
   (`Router.SetLocalAsTolerance`) and Python
   (`Router.set_local_as_tolerance`) mirrors. Verified by 6 router
   unit tests (default-0 rejects, tolerance=1 admits 1 / rejects 2,
   allowas-any admits arbitrary, unknown-handle fail-closed,
   post-start fail-closed), the C/Go/Python binding smoke tests,
   and the safety-net fix is exercised by the existing
   `rejects_as_loop` test (2-byte path) plus the new router tests
   (4-byte path). The extended-community syntax sugar
   (`rt:`/`ro:` literals) already parses; no further action needed.
4. ~~**Soft reconfiguration inbound**~~ — done: the router gained a
   `pre_policy_adj_rib_in` storage (a second `AdjRibIn` instance)
   that retains the **raw** received routes before the safety net
   or import hook chain runs, for peers with `soft_reconfig_inbound`
   enabled. `PeerConfig` gained `soft_reconfig_inbound: bool` (default
   off — FRR's default; the cost is duplicate RIB memory per peer);
   `SessionConfig` carries the field through `add_session`;
   `DefaultRouter::set_session_soft_reconfig_inbound(h, on)` is the
   post-`add_session` mutator. `import_route` populates the pre-policy
   RIB before any safety net or import hook runs; `withdraw_from_session`
   and `session_down_cleanup` purge it in lockstep with the post-policy
   RIB. `DefaultRouter::soft_reconfig_inbound(h)` is the FRR `clear ip
   bgp * soft in` op: it re-runs the import hooks against the stored
   pre-policy routes, replaces the session's entries in the post-policy
   `adj_rib_in`, and re-selects every affected prefix — without
   re-fetching from the peer. `DefaultRouter::adj_rib_in_snapshot(h)`
   exposes the pre-policy view to embedders / the runtime API. The
   daemon wires the router-wide `[bgp] soft_reconfig_inbound = bool`
   (default off) + CLI `--soft-reconfig-inbound` /
   `--no-soft-reconfig-inbound` + per-peer override
   `[peer] soft_reconfig_inbound`. FFI:
   `lr_router_set_soft_reconfig_inbound` +
   `lr_router_soft_reconfig_inbound`, with Go
   (`Router.SetSoftReconfigInbound` / `Router.SoftReconfigInbound`) and
   Python (`Router.set_soft_reconfig_inbound` /
   `Router.soft_reconfig_inbound`) mirrors. Verified by 7 router unit
   tests (retains-pre-policy-view, off-does-not-retain,
   re-evaluates-after-policy-change, noop-when-flag-off,
   unknown-handle-noop, mutator-unknown-handle-fail-closed,
   mutator-post-start-fail-closed) and the C/Go/Python binding smokes.
5. Maintain the interop scripts (`tests/interop/*`) as the acceptance
   gate for every compatibility item.


### W3 — RFC coverage gaps (from `RFC_MAP.md`)

Highest-value missing/partial standards, in rough order:

1. ~~**BFD multihop**~~ — done, as RFC 5883 (the roadmap previously
   mis-cited this as "RFC 8562/5881": 8562 is *Multipoint* BFD, and
   5881 is *single-hop*). Multihop sessions ride UDP 4784 with no
   TTL 255 requirement (RFC 5883 §5/§3), demultiplexed by Your
   Discriminator with the source-address fallback for discovery
   packets (§4.1). The daemon exposes it as `--bfd-multihop` /
   `bfd_multihop = true`. BIRD-verified end-to-end
   (`tests/interop/bfd_bird.sh` phase 2: multihop BFD + multihop eBGP
   against `neighbor ... multihop` + `bfd on`). Landing this also
   fixed lr-bfd's core RFC 5880 wire bugs (see W1.3) — without them
   no BFD interop worked at all. Keyed-hash auth over multihop
   (RFC 5883 §6 SHOULD) remains future work (Simple Password is
   supported).
2. ~~**RFC 8212** default eBGP route behaviors~~ — done: the router
   gained `set_ebgp_requires_policy` + per-session
   `set_session_policy(import, export)`; with the mode on, an external
   session (eBGP or a confederation boundary — §1 counts both) without
   an explicit import policy drops received routes before Adj-RIB-In,
   and without an export policy advertises nothing at any of the three
   egress paths (per-prefix export, RFC 2918/7313 reannounce, initial
   dump — EoR still flows so peer GR logic converges). Removing an
   export policy re-evaluates every prefix and withdraws what the
   session carried; iBGP and confederation-internal sessions are
   exempt. The daemon enables the mode by default
   (`[bgp] ebgp_policy = "rfc8212"`; `accept-all` is the §3/Appendix-A
   "insecure-mode" deviation), warns per policy-less external peer at
   startup, and unknown modes fail closed. Verified by 8 router unit
   tests + 5 daemon e2e tests (deny both directions, permit-all
   route-maps restoring flow, accept-all deviation, iBGP exemption,
   unknown mode rejected); the protocol-subject interop scripts pin
   `--ebgp-policy accept-all` on their lr sides. Landing this also
   fixed daemon-level iBGP propagation: locally originated routes
   carried no NEXT_HOP and iBGP egress preserved the gap, so peers
   discarded the UPDATEs (RFC 4271 §6.3) — egress now synthesizes the
   local address (§5.1.3) and the daemon originates `network`s with
   their local address, which also un-breaks kernel FIB installs.
3. ~~**OSPF DBD/LSR exchange**~~ — done: the router runs the full
   RFC 2328 §7.2 synchronization per session (`lr-ospf::exchange`):
   master/slave election per §10.3, MTU-bounded LSA-header paging,
   request-list loading to Full, duplicate DBD handling and
   RxmtInterval retransmissions from tick(). The neighbor FSM now
   restarts to ExStart on sequence mismatch (§10.9/Fig. 12) instead
   of tearing the neighbor down. Landing this against BIRD 2.17.5
   flushed out four latent wire bugs (10-byte LS-Request encoding,
   wrong DBD I-bit value, big-endian MTU ioctl parse, multi-packet
   IP datagrams) and required MinLSArrival-paced Router-LSA
   re-origination (§14). Verified by `tests/interop/ospf_bird.sh`:
   Full adjacency with BIRD over a veth pair and stub nets
   propagated in both directions — OSPF interop is unlocked. FRR
   interop landed later as `tests/interop/ospf_frr.sh` (zebra + ospfd
   10.3 in a netns, ptp network type, Full adjacency, bidirectional
   stub-net propagation, dead-timer teardown observed by ospfd).
   OSPFv3 exchange remains open.
   Broadcast-segment DR
   election landed on top (see the OSPF capability table and
   `tests/interop/ospf_broadcast.sh` — BIRD's default broadcast type
   included).
4. ~~**RFC 5187 / RFC 3623** OSPF graceful restart~~ — done, in
   three slices (wire codec → state machines → daemon + interop):
   * `lr-ospf::lsa::grace` — the Grace-LSA body codec (TLV
     encode/decode for Grace Period, Reason, IPv4/IPv6 Interface
     Address, Address Family), the Opaque LSA ID packing (RFC 5250
     §3.1 — 8-bit Opaque Type `3` + 24-bit Opaque ID), and
     `originate_grace_lsa_v2()` (a finalized link-local Opaque-LSA
     with the §C.4 checksum). O-bit doc audit: the earlier claim
     that RFC 3623 §1 / RFC 5187 §1 define a GR capability O-bit was
     **wrong** — neither RFC mentions any O-bit; the options-field
     O-bit is RFC 5250's *Opaque-LSA capability* (DBD scope only,
     "SHOULD NOT be set and MUST be ignored when received in packets
     other than Database Description packets"; FRR flags Hello
     O-bits as "abuse"). The Grace-LSA itself is the only GR signal;
     the helpers now carry the corrected RFC 5250 semantics.
   * `lr-ospf::gr` — the RFC 3623 state machines: `HelperEntry`
     (§3.1 entry checks 1-5 + the already-helping refresh exception,
     §3.2 exits on flush / grace timeout / topology change, FRR
     `supported_grace_time` clamping) and `RestartTracker` (§2.2
     exit conditions with a latched §2.3 outcome). 15 unit tests.
   * `lr-router` — Grace-LSAs are link-scoped (RFC 5250 §3.1): at
     LSU ingest they never enter the area LSDB and are never
     re-flooded; each *changed instance* (RFC 2328 §13 identity:
     sequence + age + checksum + length — not sequence alone)
     surfaces as a `RouterEvent::OspfGraceLsa` with the decoded
     period/reason/address and a `purged` flag for MaxAge flushes.
     Per-area `topology_version` counters bump on content changes
     of topology LSAs (types 1-5, 7; periodic refreshes excluded)
     — the §3.2 (3) helper-exit signal, polled via
     `ospf_area_topology_version()`. `ospf_area_lsa()` reads the
     LSDB for the §2.2 (1) pre-restart router-LSA walk.
   * Daemon (`--protocol ospf`): the restarting side
     (`[ospf] graceful_restart` + `grace_period`, 1..=1800 per
     §2.1; BIRD/FRR default 120) — on SIGTERM, persist the grace
     deadline to a state file (`gr_state_file`, default
     `<api-socket>.gr`), originate Grace-LSAs per interface
     (repeated with a fresh instance per round, ~1 s apart —
     comfortably above the receivers' MinLSArrival) with a
     wallclock-derived sequence lineage that survives the restart,
     and exit *without* the session-close teardown so the kernel
     FIB persists. The flood window keeps servicing the protocol
     between rounds (inbound + Hellos + outbound; no re-origination,
     election or teardown — §2.1 freezes the pre-restart state):
     a helper whose post-Full Router-LSA refresh is still on its
     LS retransmission list for us refuses helper mode (§3.1 (2)),
     and only our LSAck drains the list — the next round's fresh
     Grace-LSA instance then re-runs the checks while our Hellos
     keep the neighbour Full (§3.1 (1)). This was a real CI-red
     race against BIRD 2.0.8 (jammy's bird2, 7 consecutive
     failures): the shutdown previously stopped reading input, so
     the helper's check never passed. On restart, resume recovery
     from the state file (topology-LSA origination suppressed per
     §2 (1), adjacency back-link verification per §2.2 (2)), and on
     exit flush the Grace-LSAs (§2.3 (6)) with re-origination
     sequenced above the retained pre-restart instances. The
     helper side (default on — BIRD `AWARE`/FRR helper parity;
     `--ospf-no-gr-helper`, `--ospf-helper-grace-cap`): dead-timer
     retention of helping neighbours, Router-LSA keeps advertising
     the adjacency as if Full, §3.2 exits re-run the election +
     re-origination and reap sessions that stayed silent. Runtime
     API `status` reports recovery + active helpers.
   * Verified by `tests/interop/ospf_gr.sh` (two daemons: planned
     restart with retention across the dead interval, recovery
     exit, flush release, and the grace-timeout teardown with route
     withdrawal) and `tests/interop/ospf_gr_bird.sh` (lr restart ×
     BIRD 2 as the helper — CI runs jammy's 2.0.8, locally verified
     against 2.17.x: "started/finished graceful restart" in BIRD's
     log, 10.99.2.0/24 retained through the whole restart).
   * Follow-up audit fixes: the DD options byte now carries the
     RFC 5250 §3 O-bit (see the OSPF capability table's
     "RFC 5250 Opaque-LSA capability signalling" row) — the bit
     previously existed only inside lr's own Grace-LSA headers, so
     BIRD (which captures a neighbour's options from DD packets
     and gates opaque flooding on it) never sent opaque LSAs
     toward lr.
5. ~~**RFC 7684** OSPFv3 prefix link-local attribute LSA types~~
   — done: `LsaTypeV3` gained `PrefixLinkLocalAsLsa = 0x4004`
   (AS-scope, function 4 — RFC 7684 §2.1) with `from_u16`,
   `function_code`, and `Display` support. The `v3_prefix_options`
   module documents all RFC 5340 §A.4.1.1 bits (P, MC, LA, NU) and
   the two RFC 7684 §3 additions (Af-bit `0x80`, R-bit `0x10`). New
   `V3PrefixLinkLocalEntry` struct + `encode_v3_prefix_link_local_entry`
   / `decode_v3_prefix_link_local_entry` / `encode_v3_prefix_link_local_body`
   / `decode_v3_prefix_link_local_body` codec handles the
   variable-length prefix body with the optional one-byte Address
   Family ID (present only when the Af-bit is set). 8 unit tests:
   prefix-options bit values, single-entry roundtrip (basic + with
   Af-bit + without Af-bit), multi-entry body roundtrip, truncated
   body failure (prefix-options byte, prefix bytes, Af-bit af_id),
   empty body, new LSA type parse + display.
6. ~~**Babel-MAC completion**~~ — done (the item previously cited
   "RFC 9289", which is an ONC-RPC/TLS document — a wrong citation;
   the DTLS-less MAC variant is RFC 8967, and RFC 9467 updates it).
   New `BabelAuthInterface` in `lr-babel::auth` implements the full
   RFC 8967 §4.3 reception algorithm: per-neighbour (Index, PC) state
   keyed by source address (created only after the MAC test passes),
   §4.3.1 Challenge Request/Reply resynchronization with a 30 s
   challenge expiry and 300 ms request/reply rate limits, §4.4
   neighbour-state expiry (lazy + explicit gc), and §5 incremental
   deployment (send authenticated, accept unauthenticated). MAC
   algorithms: the mandatory HMAC-SHA256 plus keyed BLAKE2s-128
   (§4.1 SHOULD). §4.2 PC overflow now rotates to a fresh index.
   RFC 9467 landed on top: §3.1 unicast/multicast PC split
   (RECOMMENDED, default on), §3.2 window verification (OPTIONAL,
   configurable size), §3.3 combined mode. The daemon transport signs
   and verifies every datagram (`--babel-key`/`[[babel.key]]`,
   `--babel-accept-unauthenticated`, `--babel-no-pc-split`,
   `--babel-pc-window`), and gained the two-socket unicast/multicast
   transport, periodic Hello/Router-Id/Next-Hop/Update announcements
   with boot-unique router-ids, and `--network` origination.
   Verified by 27 new unit tests plus the two-daemon e2e
   (`tests/interop/babel_auth.sh`: propagation, restart challenge
   resynchronization, wrong-key fail-closed, incremental deployment).
7. ~~**RFC 8277** BGP labeled prefixes (BGP-LU)~~ — done: new `lr-mpls`
   crate (RFC 3032 label + label-stack codec, 4- and 3-octet wire
   forms); `lr-bgp::path::labeled_nlri` (RFC 8277 §3 NLRI codec with
   MP_REACH/MP_UNREACH helpers); `lr-router::originate_labeled`
   injects labelled routes into Loc-RIB; egress encodes the stack into
   labelled MP_REACH (BGP peer FSM dispatches on family for both
   directions); `lr-osroute::mpls_route` (Linux `AF_MPLS` netlink
   route push/swap/pop with `RTA_DST`/`RTA_VIA`/`RTA_NEWDST` and
   `/proc/sys/net/mpls/platform_labels` capability detection);
   `lr-ffi` + Go/Python bindings (`lr_router_originate_labeled_v4/v6`,
   `lr_mpls_platform_labels`); daemon `--labeled-network` /
   `labeled_networks` TOML + `--mp-family ipv4-labeled-unicast` /
   `ipv6-labeled-unicast`; 4 e2e tests + a two-daemon interop script
   (`tests/interop/labeled_unicast.sh`). RFC 5666 EPE remains future
   work.
8. ~~**YANG models (RFC 9647 Babel, key chains RFC 8177)**~~ — done:
   the verbatim `ietf-babel@2024-10-10.yang` (RFC 9647) and
   `ietf-key-chain@2017-06-15.yang` (RFC 8177) modules ship in `yang/`
   (libyang-validated), and `lr-daemon yang render <config.toml>
   [--model babel|keychain|all]` renders the Babel config subset as XML
   instance data conforming to them: the NMDA
   `/routing/control-plane-protocols/control-plane-protocol` envelope
   with `babel:babel` as the protocol type, `constants` (UDP port,
   multicast group), one `mac-key-set` with a `keys` entry per
   `[[babel.key]]` (base64 key bytes, `babel:hmac-sha256` /
   `babel:blake2s` identities), and the same keys as an RFC 8177 key
   chain (`key-chain:hmac-sha-256`, always-valid send-accept lifetime);
   BLAKE2s keys fail closed in the key-chain view (RFC 8177 defines no
   identity for them). The full mapping is documented in
   `yang/README.md`; unit tests pin the wire shapes and
   `tests/interop/yang.sh` validates the output with libyang
   `yanglint` when the tool is present.

### W3-extra — Comprehensive MPLS support (new)

Standalone workstream tracking the comprehensive MPLS goal. Builds on
the RFC 8277 BGP-LU foundation above; each item ships independently.

1. ~~**RFC 3032 label + label-stack codec**~~ — done (lr-mpls crate).
2. ~~**RFC 8277 BGP-LU end-to-end**~~ — done (codec → router → daemon →
   FFI + bindings → interop).
3. ~~**Linux `AF_MPLS` LSP installation**~~ — done
   (`lr-osroute::mpls_route`, push/swap/pop via netlink), including the
   router-level integration: when a BGP-LU route lands in the Loc-RIB
   the daemon mirrors it into the kernel dataplane — an `AF_MPLS` pop
   route for locally originated labels (in-label → `lo`, local
   delivery, the kernel's own explicit-null shape) and an encap route
   (`ip route add … encap mpls <stack>`) for peer-advertised stacks,
   with implicit-null left to PHP and withdrawals reversing both
   halves. Landing this against the v5.10 netlink sources flushed out
   two latent wire bugs the unit tests could never catch: `RTA_VIA`'s
   family field is host byte order (the old big-endian encoding was
   rejected by `nla_get_via` on little-endian kernels), and netlink
   label attributes must carry TTL/TC zeroed (`nla_get_labels`
   rejects data-plane TTL 64). Verified by `tests/interop/mpls_lsp.sh`:
   two rootless netns over a veth pair, kernel-state assertions on
   both sides, and an ICMP echo pushed through the LSP (kernel-gated,
   the tcp_ao.sh skip pattern). Router-level LSP *withdrawal*
   bookkeeping lives in the daemon's mirror (prefix → in-label side
   table). Per-prefix label *allocation* for transit LSR roles landed
   afterwards through the LDP workstream's §3.5.7.1.1 slice (the
   `lr-ldp` engine allocates one local label per learned FEC and the
   daemon mirrors the swap into the kernel — see the LDP capability
   table); the BGP-LU mirror itself keeps its tail-pop / head-encap
   shape.
4. ~~**LDP (RFC 5036)**~~ — done: label distribution protocol for
   non-BGP MPLS LSPs. Foundation slice landed in the new `lr-ldp`
   crate: the
   RFC 5036 codec (PDU/TLV/message), the §2.5.4 session FSM with
   §3.5.3 negotiation, §3.5.2 discovery (link + targeted) with the
   §2.5.2 role decision, a per-peer label information base with DU
   bookkeeping (§3.5.8.1 / §3.5.10.1), §3.5.3 Max PDU Length
   enforcement in both directions, and the `LdpEngine` glue — all
   no-std and covered by a two-speaker loopback e2e. Daemon
   transport done: `--protocol ldp` runs the reference daemon as an
   LSR — a wildcard UDP socket on port 646 joined to 224.0.0.2 per
   configured `[[ldp.interface]]`, link Hellos originated every
   hold-time third with TTL 1 and per-interface egress, targeted
   Hellos (`[[ldp.targeted]]`, `ADDR` or `ADDR:PORT`) as unicast,
   TCP 646 sessions (listener + `EstablishTransport`-driven active
   connects with retry-on-Hello after a failed connect), and
   `[[ldp.bind]]` FEC-label pairs (16..=1048575, 0 = auto-allocate)
   advertised downstream-unsolicited and re-advertised to every
   freshly operational session. Interop verified both ways against
   FRR 10 ldpd (`tests/interop/ldp_frr.sh`: lr learns FRR's
   implicit-null connected-FEC binding, FRR's LIB carries lr's
   explicit 24000 binding) and two-daemon over a veth pair
   (`tests/interop/ldp.sh`). Four follow-up slices landed: RFC 7552
   IPv6 dual-stack procedures (library + daemon transport, see the
   LDP capability table), the `[ldp] install_kernel` AF_MPLS mirror
   of learned bindings, automatic label allocation from the
   `[ldp] label_min/label_max` range, and §3.5.7.1.1 transit-LSR
   label allocation (one local label per learned FEC,
   re-advertised upstream with propagated Hop Count / Path Vector,
   reflected-binding-safe next-hop fallback, kernel swap mirror —
   see the LDP capability table). RFC 5036 §3.5.4 loop detection
   landed on top: `[ldp] loop_detection` (+ `loop_hop_count_limit` /
   `loop_path_vector_limit`, CLI `--ldp-loop-detection`) proposes the
   D bit with PVLim and enforces the §3.4.4.1/A.2.6 checks — a looping
   Mapping is rejected with a Label Release carrying the Loop Detected
   Status TLV, a looping Request
   answered with the non-fatal Loop Detected Notification. RFC 3478
   graceful restart landed on top of that (FT Session TLV + §3.3
   binding retention — see the LDP capability table). The remaining
   open item — external dual-stack interop verification — landed as
   `tests/interop/ldp_frr_v6.sh` (FRR 10 ldpd, RFC 7552): the fix
   series also makes LDPoIPv6 session TCPs send with hop limit 255
   (FRR's default AF_INET6 GTSM was dropping the 64-hops SYN-ACKs)
   and repairs the IPv6 discovery socket bind (IPV6_V6ONLY must be
   set before the bind; the post-bind change died with EINVAL on
   current kernels, silently degrading the daemon to IPv4-only
   discovery).
5. **SR-MPLS (RFC 8660 / 8667)** — Segment Routing MPLS data plane.
   In progress; slice 1 (control-plane codecs + origination) and slice
   2 (reception → SRDB → SPF label attach → kernel mirror) landed:

   - **Codec** (`lr-ospf::lsa::sr`): the RFC 7684 §6 Extended Prefix
     Opaque LSA (area-scoped, Opaque Type 7) with the RFC 8667 §5
     Prefix-SID sub-TLV (NP/M/E/V/L flags, MT-ID, algorithm, 3-octet
     SID), the RFC 4970 Router Information LSA's SR-Algorithm (type 8)
     and SRGB Descriptor (type 9) TLVs, and the remote-label mapping
     (SRGB base + index with the V/L and out-of-range guards from
     RFC 8667 §6/§8.1). Twelve unit tests pin the wire shapes byte for
     byte. One bug was flushed out by the reference implementation
     itself: the first encoder left the *last* TLV/sub-TLV unpadded,
     so the LSA length was not a multiple of 4 — FRR silently rejected
     the whole DBD carrying it and the adjacency hung in ExStart (all
     standard OSPFv2 LSA lengths are 4-aligned; the fix emits the
     trailing alignment padding).
   - **Origination** (daemon): `[ospf] srgb_base/srgb_range` +
     `[[ospf.prefix_sid]]` (prefix/sid/node, `no_php` for the §5 NP
     flag — FRR `no-php-flag` parity) config with the FRR
     default SRGB (16000/8000) when SIDs are configured without an
     explicit block; the daemon originates the area-scoped RI LSA plus
     one Extended Prefix LSA per configured SID through the same
     anchor-LSU path as the Router-LSA (LSDB sequence floor,
     adjacency-driven re-origination). SR-less configs originate
     nothing.
   - **Interop, origination** (`tests/interop/ospf_sr_frr.sh` phase 1):
     lr x FRR 10.3 ospfd over a rootless netns veth pair. FRR requires
     `capability opaque` (its O-bit clearing in `ospf_db_desc`
     otherwise poisons the exchange — flushed out by this lab); with
     it, FRR's LSDB holds both of lr's SR LSAs. The SRDB
     label-mapping assertion is gated on kernel MPLS (FRR reserves the
     SRGB through zebra's label manager; same gate as mpls_lsp.sh
     phase 2).
   - **Reception** (slice 2, `lr-ospf::srdb`): the per-node SR
     database is a pure projection of the area LSDB — SRGBs from RI
     opaque LSAs (Opaque Type 4), Prefix-SID mappings from Extended
     Prefix LSAs (Opaque Type 7). `SrDatabase::label_for` resolves the
     head-end label against the SPF result: among the SPF-algorithm
     mappings whose originator is reachable with a resolvable next
     hop, the closest originator wins (lowest router ID on ties). The
     RFC 8667 §5 PHP rule is a direct consequence of the adjacency
     set: an NP-clear SID whose originator is one hop away means this
     router is the penultimate hop and pops, so no label is produced.
     The underlying SPF gained RFC 2328 §16.1.1 next-hop resolution
     (back-link Link Data for direct p2p neighbours §16.1.1 (5),
     transit-network member addresses §16.1.1 (4), parent inheritance
     §16.1.1 (2)-(3)) plus the adjacent-router set — a pre-scan of the
     LSDB into per-type link maps also replaced the per-vertex
     database re-walk.
   - **Label attach** (`lr-router`): `set_ospf_sr_receive` (off by
     default, fail closed) makes every area recompute attach the
     resolved label to intra/inter-area routes behind
     `[ospf] sr_receive` — via the same private `LrMplsLabelStack`
     attribute the RFC 8277 mirror already consumes — and set the
     route's next hop to the first hop toward the originator, so the
     daemon's existing kernel mirror installs the RFC 8660 encap
     routes with zero extra plumbing. Route selection (kind, metric)
     is untouched; externally-forwarded routes are never labelled.
     Locally originated SIDs additionally get AF_MPLS pop routes (the
     LSP tail) with `install_kernel`.
   - **Interop, reception**: `tests/interop/ospf_sr.sh` (two
     lr-daemons, raw multicast, no kernel MPLS needed) asserts both
     directions of label resolution through the runtime API —
     `10.99.2.0/24 … label=16100 via 10.99.1.1` — including the NP
     rule. `tests/interop/ospf_sr_frr.sh` phase 2 (kernel-MPLS gated,
     FRR `segment-routing on` + `global-block` + `prefix … index 200
     no-php-flag`) asserts lr's Loc-RIB maps FRR's SID to label=16200
     and the kernel FIB carries the encap route.
   - **Next slice**: Adj-SIDs (RFC 8667 §7), then the mapping-server
     (M-flag) shapes. RFC 9256 (Segment Routing Policy) builds on the
     data plane.

### W4 — Documentation, guides, tutorials

1. ~~**A book-style tutorial (`docs/tutorial.md`)**~~ — done: three
   chapters from raw bytes to the router pipeline — wire decode (the
   codec, a hand-built UPDATE read back through the attribute bag),
   two peer FSMs (in-memory session establishment to Established),
   and the router pipeline (sessions, originate → propagate →
   install → withdraw with RIB snapshots and events). Every snippet
   is pinned by `crates/lr-tests/tests/tutorial_snippets.rs`, which
   runs the tutorial's code verbatim — the tutorial cannot drift
   from the API without breaking a test. Indexed at the top of
   `docs/README.md`.
2. ~~**Per-protocol deep dives extending `docs/examples/`**~~ — done:
   `bgp_roles_otc.md` (RFC 9234 role configuration + the OTC
   lifecycle table — egress enforcement live in `lr-bgp::advertise`,
   the §5 ingress helper shipped with FSM enforcement noted as
   future work), `ospf_abr_nssa.md` (type-3 summary origination and
   flush with the backbone-only rule, the stub/NSSA filter map),
   and `babel_source_specific.md` (RFC 9079 source-keyed route
   table with the wire form — Source Prefix sub-TLV 128 — verified
   against `lr-router`'s babel `apply_update`, plus the kernel
   `from`-route caveat).
3. ~~**Binding guides per language (Go / Python / C / C++)**~~ — done:
   `docs/bindings/{go,python,c,cpp}.md`, one page each with a
   complete program (router + eBGP session + originate + wire-byte
   dump) and its exact build/run commands. All four programs were
   compiled and executed against the real `lr-ffi` release build
   during the docs work — each prints the same OPEN wire bytes and
   the guides match the shipped binding APIs (Go's
   finalizer-based cleanup, Python's context-manager Router, C's
   owned `lr_bytes_t` discipline and link-order caveat, C++'s RAII
   wrapper with the raw-ABI escape hatch). Indexed under
   `docs/README.md` §Embedding the library.
4. ~~**Operations runbook**~~ — done: `docs/RUNBOOK.md` — daemon
   lifecycle (signals, privilege drop, the fatal-by-design API
   socket), the runtime API command reference (`status`/`sessions`/
   `routes`/`mrt`/`reload`/`shutdown`, verified against `api.rs`'s
   dispatch), and a troubleshooting FAQ covering the failure modes
   operators hit first: RFC 8212's deny-by-default eBGP, unknown-key
   config warnings, Connect/Active hangs (GTSM TTL, auth arming),
   TCP-AO kernel requirements, rootless-netns raw sockets, the
   host-level `mpls_router` load, kernel-FIB installation being
   opt-in, and reload's networks-only scope. Config reference stays
   in `templates/daemon.toml`, interop lab in `docs/INTEROP.md` —
   the runbook links instead of duplicating. Indexed under
   `docs/README.md` §Running the daemon.
5. Keep `STATUS.md` / `RFC_MAP.md` / `API.md` synchronized with
   every landed feature (standing rule, enforced at review).

### W5 — Compatibility layer

1. ~~**`lr-daemon translate bird|frr <config>`**~~ — done (commit
   `ed37db6`, landed 2026-08-31 but the strike-through was never
   applied here — caught by a docs audit): best-effort
   conversion of BIRD 2 / FRR BGP configs into lr daemon TOML, riding
   the daemon binary so the output is round-trip-tested against the
   real config parser in every test run (16 unit tests in
   `crates/lr-cli/src/translate.rs`). Mapped: router id / local AS,
   peers (`neighbor … as`, `remote-as`, non-default ports →
   `remote` ADDR:PORT), MD5 auth (FRR type-0 passwords; type-7 is
   noted), local address / update-source, hold time, BFD, the
   `import|export none|all` idioms (`none` → generated deny-all
   route-map, `all` → nothing because the emitted
   `ebgp_policy = "accept-all"` already means exactly that — the
   daemon's rfc8212 default would otherwise silently drop routes the
   source config accepted), prefix-lists, as-path access-lists,
   standard community-lists, route-map `match`/`set` clauses
   (prefix-list / as-path / community matches; next-hop,
   local-pref, MED, as-path prepend, add-community), FRR `network`
   and BIRD static-protocol `route` prefixes → `networks`, BIRD
   `ipv4`/`ipv6` channels → `mp_families` (an ipv6-only channel also
   sets `default_ipv4_unicast = false`), and FRR
   `address-family ipv6 unicast` activation. Anything unmappable is
   kept as an explicit `# UNMAPPED:` comment (per-line, per-entry, or
   global) instead of being dropped silently; FRR peers without a
   `remote-as` and dangling policy references are dropped with notes
   because the daemon would refuse to start them (fail-closed policy
   resolution).
2. ~~**Behaviour parity flags documented side-by-side**~~ — done:
   `docs/PARITY.md` catalogs every behaviour-compatibility knob
   (RFC 8212 mode, enforce-first-as, deterministic router-ID
   tie-break, implicit IPv4 unicast, local-AS tolerance, soft
   reconfiguration, Babel §5 incremental deployment) against the
   BIRD 2.17.5 and FRR 10.3 documented semantics — including the
   default differences (FRR defaults enforce-first-as on, BIRD/lr
   off; FRR defaults the RFC 5004 older-route tie-break, BIRD/lr the
   deterministic router-ID) and the transport-knob mapping (GTSM,
   MD5, TCP-AO, BFD, maximum-prefix). Sources are the upstream docs
   themselves, not folklore.
3. ~~**Wire-level parity harness**~~ — done: `lr parity-replay`
   replays a captured BGP message stream (JSONL, one hex message per
   line) into an offline `DefaultRouter` and dumps the resulting
   Loc-RIB as MRT TABLE_DUMP_V2; `lr mrt diff A B` content-compares
   two dumps (per prefix: AS path, next hop, MED, communities —
   LOCAL_PREF excluded: it is iBGP-only on the wire and dump-side
   values are the viewer's internal default, not the sender's).
   `tests/parity/capture_proxy.py` records per-direction BGP messages
   off a live TCP session (RFC 4271 reassembly, TCP-coalescing safe)
   and `tests/interop/parity.sh` runs the full loop against BIRD 2:
   lr-daemon originates two prefixes through the proxy, BIRD's own
   `protocol mrt` view (filtered to the lr protocol) is the ground
   truth, and the replay must come out IDENTICAL. In-process parity
   (capture → replay → diff against the original receiver) is covered
   by unit tests in `crates/lr-cli/src/parity.rs`.
4. ~~**Native BIRD/FRR config run — the compat surface**~~ — done:
   `lr-daemon --config bird.conf|frr.conf` parses the source dialect
   and runs the daemon directly in the *compatible form* (W5.1's
   converter remains for operators who want a reviewable TOML):
   * Dialect auto-detection from the file content (lr TOML / BIRD 2 /
     FRR keyed on lines only the respective dialect uses), fail-closed
     on unknown content, `--config-dialect bird|frr|toml` to force.
   * One mapping, no drift: the native load runs the W5.1
     parse → render pipeline and feeds the rendered TOML through the
     daemon's regular loader, so compat mode and `lr translate`
     produce byte-identical semantics by construction.
   * Dialect-correct defaults, the "compatible form" core: both
     dialects get the accept-all eBGP policy (BIRD/FRR natively admit
     every route without filters — the daemon's RFC 8212 deny-by-default
     would silently drop routes the source config accepts), and FRR
     keeps its documented `bgp enforce-first-as` default (on); the
     converter now emits that too. BIRD channel families and FRR
     address-family activation carry over as before.
   * lr-specific extensions ride `lr:` comment directives — invisible
     to real BIRD and FRR, so a config carrying them still loads in
     the reference implementations. Globals: `listen`, `install-kernel`,
     `api-socket`, `user`/`group`, `bmp-target`, `graceful-restart`,
     `llgr`, `llgr-max-stale`, `add-path`, `add-path-max`,
     `max-prefixes`, `max-prefix-action`, `gtsm`, `ebgp-policy`
     (override the dialect default), `soft-reconfig-inbound`. Per-peer
     (BIRD stanza scope / FRR `lr: neighbor ADDR` form): `add-path`,
     `add-path-max`, `max-prefixes`, `max-prefix-action`,
     `max-prefix-threshold`, `gtsm`, `mp-family` (repeatable),
     `tcp-ao-key` (repeatable), `extended-next-hop`, `allow-local-as`,
     `local-address`, `soft-reconfig-inbound`. Unknown keys and bad
     values surface as warnings — never silently dropped.
   * Honesty channel: in native-run mode there is no TOML file to
     review, so every UNMAPPED note and every non-BGP routing stanza
     (BIRD `protocol ospf …`, FRR `router ospf …`) becomes a startup
     warning; `protocol device` is skipped silently as BIRD
     housekeeping.
   * SIGHUP / runtime-API reload re-parses through the same dialect
     path (the daemon remembers its config dialect), so compat-mode
     daemons reload like TOML ones.
   * Tests: 16 unit tests in `compat.rs` (detection, directives,
     defaults, drift-guard) + converter unit tests; `daemon_compat.rs`
     e2e (BIRD config runs and exchanges routes with a flag-spawned
     peer, FRR config ditto with per-peer directives, non-BGP stanzas
     warn without blocking); `tests/interop/compat_bird.sh` and
     `compat_frr.sh` run compat-mode lr-daemons against real
     BIRD 2.17.5 / FRR 10 bgpd (both directions of route flow, the
     dialect-defaults warnings, the `api-socket` side effect), wired
     into the CI interop job. The e2e flushed out a latent FRR-parser
     gap — a combined `neighbor A port P remote-as N` line never set
     the peer AS (first-token dispatch only handled the
     dedicated-line shape) — fixed and pinned.

### W6 — Research: BGP defects and a private exchange plane

1. ~~**`docs/research/BGP-DEFECTS.md`**~~ — done: catalogues BGP's
   inherent weaknesses with verified references (RFC sections checked
   against the published text; the paper citations taken from the RFCs'
   own reference lists): slow convergence/path-vector latency
   (Labovitz 2000, Griffin 1999/2002, Gao-Rexford), withdrawal
   propagation storms, route leaks (RFC 7908 taxonomy, RFC 9234 role
   gap), origin/path forgery (RFC 6811/8205/7132), full-mesh/RR
   scaling limits (RFC 4456, RFC 3345), MRAI vs churn trade-offs
   (RFC 4271 §9.2.1.1, RFC 7196 — not RFC 8326, which is Graceful BGP
   Session Shutdown and unimplemented), MED oscillation (RFC 3345
   Type I/II, RFC 5004). Each entry maps the defect to the standard
   mitigation and to lr's current coverage; the summary table flags
   the three unmitigated-in-practice defects the EXCHANGE-PLANE design
   targets. Writing it flushed out four wrong RFC 8326 citations
   (lr-damping doc comment, `lr-bgp::best_path` module doc,
   ARCHITECTURE.md, RFC_MAP.md's 8326 row claimed implemented) — all
   fixed in the same series.
2. ~~**`docs/research/EXCHANGE-PLANE.md`**~~ — done: the design review
   document for a capability-negotiated private exchange plane
   (LRXP). Grounded in verified first-hand facts — RFC 5492 §3
   (unknown capabilities are inert, the transparent-fallback hook),
   RFC 4271 §5 (unknown optional-transitive attributes forward with
   the Partial bit, so records survive non-lr transit), the IANA
   "Capability Codes" registry (239-254 reserved for experimental
   use; the prototype claims 251) and the unassigned path-attribute
   range (prototype type 251, both with an RFC 7120 early-allocation
   path to production). Three record classes: scope-1 feasibility
   hints (best-path rank, damping FoM, IGP cost), scope-1 policy
   intent (RFC 9234 role claim + import/export filter digests), and
   propagated, per-hop re-signed provenance proofs (origin
   attestation + a BGPsec-shaped digest chain over lr hops only).
   Session binding via OPEN nonces, monotonic sequences and HMAC-SHA256
   tags (the primitive lr-babel's RFC 8967 code already ships);
   fail-open for route data, fail-closed for trust assertions;
   aggregation strips provenance. Includes the W6.3 prototype plan
   (module layout, feature flag, config keys, five-phase test plan)
   and the open questions for the design review.
3. ~~**Prototype the plane inside `lr-bgp::extensions`**~~ — done as
   the first slice, behind the `exchange-plane` feature flag (off by
   default; the wire format uses the IANA experimental capability
   range 239-254 — the prototype claims 251 — and path-attribute type
   251, both pending an RFC 7120 early allocation):
   `lr-bgp::extensions::exchange_plane` implements the full codec —
   capability value (version/flags/nonce/key block), the
   optional-transitive attribute body (header + record TLVs), all
   three record classes (scope-1 hints, scope-1 policy intent,
   scope-N provenance with origin attestations and per-hop segment
   signatures), HMAC-SHA256 signing/verification with constant-time
   comparison (the same primitive lr-babel's RFC 8967 code uses), the
   OPEN-nonce replay tracker with per-key monotonic sequences, and
   the §3 activation rule (same version + non-empty key
   intersection). FSM wiring: `BgpPeer::set_exchange_plane`
   advertises the capability in OPEN, `exchange_plane_session()`
   exposes the negotiation result — RFC 5492 §3 keeps a one-sided
   advertisement inert, so sessions with non-participating peers
   (BIRD, FRR) are byte-identical to before. 20 new unit tests
   (codec roundtrips, unknown-TLV skip, truncation/version/duplicate-
   tag errors, sign/verify tamper detection, replay decisions,
   activation rules) plus 2 FSM tests (both-sides activation,
   one-sided fallback) — all behind the feature, 147 lr-bgp tests
   with it on and the default build unchanged. The decision process
   is untouched; the follow-up slice wires daemon config
   (`[peer] exchange_plane` + key block) and the UPDATE
   attach/detach hooks, then the design's interop gate (flag off =
   byte-identical UPDATE streams via the W5.3 parity harness).
4. ~~**Daemon integration: config, attach/detach hooks, interop
   gate**~~ — done (the follow-up slice named above), still behind
   the `exchange-plane` feature (off by default end to end):
   * Egress attach (`BgpPeer::advertise`): plane-active sessions get
     a fresh signed record set per UPDATE — scope-1 hint rebuilt
     (rank 1, the sender's chosen path; damping/IGP integration is
     future work), §5.2 policy intent from embedder-supplied role +
     digests, provenance for locally originated routes (fresh origin
     attestation at the configured scope budget, expiry =
     configured wall clock + TTL) with received chains forwarded
     scope-decremented and re-signed per hop (design §7); headless
     chains and exhausted budgets strip provenance. Withdrawals and
     EoR never carry records. The per-session OPEN nonce mixes an
     OPEN-instance counter, so every session instance is
     replay-distinct without an RNG in the no-std FSM.
   * Ingress detach (`handle_update_in_established`): verified sets
     (nonce echo → sequence → tag, design §6) park in a private
     record store on the route bag; Partial-bit arrivals park as raw
     forwarding material; verification failures log + drop the
     records while the route survives (design §8). Scope-1 records
     are consumed — they never leak into re-advertisements (§7).
   * Router plumbing: `DefaultRouter::set_session_exchange_plane`
     (pre-start, fail-closed), `exchange_plane_records(h)` typed
     accessor (last verified set per prefix), the §7
     `exchange_plane_partial_transit(h)` counter, and store pruning
     on withdrawal/teardown. Records of policy/safety-dropped routes
     die with the route.
   * Daemon: `[bgp] exchange_plane` + `[bgp] exchange_plane_keys`
     (`"id:secret"` HMAC-SHA256 pairs) / `--exchange-plane`
     / `--no-exchange-plane` / repeatable `--exchange-plane-key`,
     per-peer `[peer] exchange_plane` override (template inheritance
     included); enabling on a feature-less binary is a startup error
     (fail closed). The §5.2 policy digests are SipHash-2-4 over the
     canonical description of the peer's bound route-maps (entries +
     referenced list definitions), role claimed ROLE_UNSET while the
     daemon has no role config. The runtime API `sessions` command
     reports per-session record counts + the partial-transit counter
     when non-zero.
   * RFC 4271 §5.3 relay fix (unconditional, not feature-gated):
     unknown optional-transitive attributes forward with the Partial
     bit set; unknown optional NON-transitive attributes are no
     longer propagated. The internal `LrMplsLabelStack` tag moved
     251 → 255 (it collided with the exchange-plane wire attribute),
     and the MRT writer filters the private tags out of dumps.
   * Tests: 8 codec tests (record-set construction across all
     classes, scope exhaustion, headless chains, store roundtrips,
     chain verification + tamper detection), 5 FSM tests (attach /
     detach over a live pair, scope-1 no-leak, one-sided
     byte-identical egress, cross-instance replay drop, tamper
     drop), 4 router tests (records surface, plane-off clean,
     three-speaker chain re-sign with end-to-end chain
     verification, partial-transit counting), 1 parser test, and 3
     daemon e2e tests (all-classes flow, wrong-key fail-open, one
     -sided inert).
   * Interop gate (design §10 exit criteria): the CI interop job
     rebuilds the daemon with the feature and runs the W5.3 parity
     harness (flag off = replayed Loc-RIB IDENTICAL against BIRD
     2.17.5) plus `tests/interop/exchange_plane.sh` — the plane-on
     daemon peers with plain BIRD unchanged (the RFC 5492 §3
     fallback gate), verified locally against BIRD 2.17.5. The
     loopback e2e with the flag on demonstrates all three record
     classes (`crates/lr-cli/tests/daemon_exchange_plane.rs`).
