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
     surfaces through `drain_ospf_grace_events()` with the decoded
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
5. ~~**SR-MPLS (RFC 8660 / 8665)**~~ — Segment Routing MPLS data
   plane. Slices 1 (control-plane codecs + origination), 2 (reception
   → SRDB → SPF label attach → kernel mirror) and 3 (adjacency
   segments + mapping server) landed:

   - **Codec** (`lr-ospf::lsa::sr`): the RFC 7684 §6 Extended Prefix
     Opaque LSA (area-scoped, Opaque Type 7) with the RFC 8665 §5
     Prefix-SID sub-TLV (NP/M/E/V/L flags, MT-ID, algorithm, 3-octet
     SID), the RFC 4970 Router Information LSA's SR-Algorithm (type 8)
     and SRGB Descriptor (type 9) TLVs, and the remote-label mapping
     (SRGB base + index with the V/L and out-of-range guards from
     RFC 8665 §5 / RFC 8402 §3.1.1). Twelve unit tests pin the wire shapes byte for
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
     RFC 8665 §5 PHP rule is a direct consequence of the adjacency
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
   - **Slice 3 — adjacency segments** (RFC 8665 §6): the Extended Link
     Opaque LSA (RFC 7684 §3, Opaque Type 8) codec — Extended Link TLV
     (§3.1: link type, reserved, Link ID, Link Data) with the Adj-SID
     (§6.1, type 2: B/V/L/G/P flags, MT-ID, weight, SID — the length-7
     label shape when V/L are set, length-8 index shape otherwise) and
     LAN Adj-SID (§6.2, type 3: plus the 4-octet neighbour Router ID)
     sub-TLVs, all 4-aligned with the RFC 7684 §2.3 length-excludes-
     padding rule (FRR's TLV walk rounds the body size up, so both
     lengths decode). Origination: `[ospf.interface] adj_sid = <label>`
     — one Extended Link LSA per interface (stable ifindex-derived
     Opaque ID) with one Extended Link TLV per Full adjacency,
     originated on the Router-LSA re-origination cadence: p2p links get
     the V/L/P-shaped Adj-SID (Link ID = the neighbour Router ID, Link
     Data = our address, §7.4.1); broadcast segments shape the TLV as
     transit (Link ID = the DR's address) with an Adj-SID toward the DR
     and LAN Adj-SIDs (neighbour Router ID filled) toward the others,
     §7.4.2. When the last Full adjacency drops, the LSA is
     MaxAge-flushed (§7.4.1 "MUST be withdrawn") with the sequence
     record retained so a later re-origination stays above the
     neighbours' floor. With `install_kernel` each advertised
     adjacency mirrors a tail pop (in-label → pop, via the neighbour's
     Hello address on that interface — the adjacency segment's
     forwarding instruction is "out that link") and the flush removes
     it.
   - **Slice 3 — mapping server** (RFC 8665 §4 / RFC 8661 §3.2): the
     Extended Prefix Range TLV codec (type 2 of the Extended Prefix
     LSA: prefix length, AF, Range Size, IA flag, prefix) with the
     M-flagged Prefix-SID assigning to the range's *first* prefix;
     `[[ospf.mapping_server]]` (prefix + sid + `range_size` + `no_php`)
     originates one such LSA per range. Reception:
     `SrRangeMapping::index_for` computes `sid + offset` for every
     prefix inside the span (§4's example arithmetic), and
     `SrDatabase::mapping_label_for` resolves the winning range — a
     reachable SR-capable server with an SRGB, closest first, lowest
     router ID on ties — against the server's SRGB (the
     homogeneous-domain arithmetic RFC 8660 §4.2 backs; the index must
     fit the advertised range). Direct Prefix-SID advertisements beat
     server mappings (RFC 8661 §3.2.3), and the mapped route's LSP
     rides the prefix's *own* path: the SPF now resolves the RFC 2328
     §16.1.1 owner next hop onto stub/transit routes (previously
     `None`), which `ospf_attach_sr_labels` pairs with the label
     (inter-area routes resolve through the border router instead).
   - **Slice 3 — visibility**: `DefaultRouter::ospf_sr_databases`
     projects every area's SRDB (SRGBs, prefix mappings, adjacency
     segments, ranges) for embedders; the OSPF daemon's runtime API
     `status` gained `ospf-sr srgb/adj/ms` lines.
   - **Slice 3 — evidence**: `tests/interop/ospf_sr_adj.sh` (two
     lr-daemons, no kernel MPLS) asserts the adjacency segments both
     ways through the status lines, the mapped labels 16500/16501
     (base + offset), direct-beats-mapping on r2's own prefix (16300
     kept despite the server also mapping it), and the §7.4.1
     withdrawal after the neighbour dies (r1's own advertisement gone;
     the killed originator's stale LSA ages out at MaxAge, as
     link-state flooding dictates). `tests/interop/ospf_sr_frr.sh`
     phase 3 adds `adj_sid = 24000` to the lr side: FRR 10.3's LSDB
     stores the Extended Link LSA (Opaque-Type/Id 8.0.0.*) and its
     `show ip ospf database opaque-area 8.0.0.*` decode reads back the
     full shape — Link Type 1, Link ID 2.2.2.2, Link data 10.99.1.1,
     Adj-SID length 7 flags 0x64 label 24000; the FRR SRDB adjacency
     entry and lr learning FRR's SRLB-allocated Adj-SID are
     kernel-MPLS-gated like phase 2. The `set -u` trap on `SR_UP`
     (unbound whenever MPLS=0 short-circuited the first gated block)
     is fixed alongside.
   - ~~**Slice 4 — SRv6 data plane (RFC 8754 / RFC 8402 / RFC 8986)**~~ —
     the IPv6 counterpart to the SR-MPLS slices above. A new
     `lr-srv6` crate (no_std, mirrors `lr-mpls`) ships the wire
     primitives: a 128-bit [`Sid`](crate:lr-srv6::Sid) (RFC 8754 §3,
     structured LOC:FUNCT:ARGS, IPv6 textual form via RFC 5952
     canonical rendering), a [`Locator`](crate:lr-srv6::Locator)
     (RFC 8754 §3.1 — IPv6 prefix + block bits, host-bits masking,
     `from_str`/`Display`, SID-at-index builders for the function
     space), and an [`Srh`](crate:lr-srv6::Srh) codec (RFC 8754 §2 —
     the full header: Next Header / Hdr Ext Len / Routing Type 43 /
     Segments Left / Last Entry / Flags O+H / Tag / Segment List /
     optional TLV bytes; both encode and decode reject the
     RFC 8754 §2.3 reserved flag bits on send but accept them on
     receive per §2.3's MUST-be-ignored rule; the mid-stack
     bottom-of-stack bit, the `Last Entry`/`Segments Left`
     consistency, the max-segments bound of 127 from the `Hdr Ext
     Len` octet, and the RFC 8200 §4.8 length-vs-`Hdr Ext Len`
     invariant are all enforced). The [`Behavior`](crate:lr-srv6::Behavior)
     registry enumerates all 32 IANA-assigned RFC 8986 §4 endpoint
     opcodes (End / End.X / End.T / End.DX6 / End.DX4 / End.DT6 /
     End.DT4 / End.DT46 / End.DX2 / End.DX2V / End.DT2U / End.DT2M /
     End.B6.Encaps / End.B6.Encaps.Red / End.BM / End.S / End.B6.Insert
     / End.B6.Insert.Red / End.Un / End.X.PS / End.X.PSU / End.T.PS
     / End.T.PSU) with their PSP / USP / USD flavor variants
     (RFC 8986 §4.16) and the decap / cross-connect / table-lookup
     classifiers operators use to drive their own pipelines.
     `lr-osroute::seg6_route` is the kernel mirror:
     [`Seg6Netlink`](crate:lr-osroute::seg6_route::Seg6Netlink) installs
     and deletes `seg6` encap routes (`LWTUNNEL_ENCAP_SEG6` + the
     nested `SEG6_IPTUNNEL_SRH` attribute with the inline/encap mode
     word, `ip route add <prefix> encap seg6 mode encap segs ...
     dev ...`) and `seg6local` endpoint routes
     (`LWTUNNEL_ENCAP_SEG6_LOCAL` + the nested `SEG6_LOCAL_ACTION`
     attribute with its 4-byte u32 action code and the per-behavior
     parameter set — `SEG6_LOCAL_NH4` for End.DX4, `SEG6_LOCAL_NH6`
     for End.DX6, `SEG6_LOCAL_OIF` for End.X, `SEG6_LOCAL_TABLE`
     for End.DT6/End.DT4/End.DT46). Capability detection via
     `/proc/sys/net/ipv6/conf/all/seg6_enabled`. The wire shapes
     match the kernel's `seg6_iptunnel.c` / `seg6_local.c` parser
     byte for byte — verified by 52 `lr-srv6` unit tests, 17
     `lr-osroute::seg6_route` wire-shape tests, and 2 kernel-gated
     interop tests in `crates/lr-osroute/tests/srv6_kernel.rs`
     (install a `seg6` encap route + a `seg6local` End route,
     verify with `ip -6 route show`; gated on `seg6_enabled=1` +
     `CAP_NET_ADMIN`). FFI: `lr_srv6_encode_srh` /
     `lr_srv6_decode_srh` exposed via C ABI, Python
     (`encode_srv6_srh` / `decode_srv6_srh`) and Go
     (`EncodeSRv6SRH` / `DecodeSRv6SRH`) bindings.
   - ~~**Slice 5 — OSPFv3 SRv6 control plane (RFC 9513)**~~ — done: the
     locator + End SID reachability core, sliced into independently
     verified commits. A first-hand audit corrected the roadmap's own
     citation: the OSPFv3 SRv6 extensions are **RFC 9513** (Li et al.,
     December 2023) — RFC 9352, which every doc here had cited, is the
     IS-IS SRv6 sibling (Psenak et al., February 2023). The wire
     codecs (`lr-ospf::lsa::srv6`) pin every shape byte-for-byte
     against the RFC figures: the SRv6 Capabilities TLV (§2, type 20,
     O-flag bit 1) on the OSPFv3 Router Information LSA (RFC 7770
     §2.2, function code 12 — 0xA00C area-scoped, LS ID = Instance
     ID), with the SR-Algorithm TLV (type 8, the RFC 8665 one) and
     the Node MSD TLV (RFC 8476 §2 type 12; the SRv6 MSD types 41 /
     42 / 44 / 45 come from the shared IGP MSD-Types registry RFC
     9513 §4 reuses from RFC 9352 §4 — verified against both texts);
     the SRv6 Locator LSA (§7, function code 42 — 0xA02A area-scoped,
     U-bit set) carrying the Locator TLV (§7.1: route types 1-6,
     anything else ignores the TLV; locator length 1-128; metric
     0xFFFFFFFF = unreachable; the §A.4.1 prefix-word encoding); the
     End SID sub-TLV (§8, type 1 of the Locator LSA sub-TLV registry)
     with the RFC 8986 behavior code points gated per §11 Table 1
     (End 1-4/28-31 and End.DT6/DT4/DT64 18-20 — End.X-family values
     are invalid inside an End SID); the SID Structure sub-TLV (§10,
     type 10 — length MUST be 4, the four bit-lengths sum ≤ 128, at
     most once per parent, violations ignore the parent); and the §6
     AC prefix option (0x80). Origination helpers follow the crate
     sequence convention. The receiving half is `lr-ospf::srv6db`, a
     pure LSDB projection applying the §2/§7.1 duplicate preference
     (area scope beats link/AS across flooding scopes, then the
     numerically smallest LS ID, then the first occurrence within an
     LSA) and the §5/§8 gates (SIDs are never directly routable; an
     End SID outside its covering locator — computed on the masked
     prefix — is ignored). `run_spf_v3` grew a locator phase: an
     intra-area locator's route metric is the advertising router's
     SPF distance and its first hop the router's resolved link-local
     (the root's own locator is connected). `DefaultRouter` gates
     publication behind `set_ospf_srv6_receive` (off by default,
     fail-closed): supported algorithms only (algorithm 0 — flexible
     algorithms are future work), and §5's rule that a prefix
     reachability advertisement beats the locator advertisement for
     the same prefix (an e2e pins a metric-20 IAP route beating a
     metric-10 locator). No reference implementation exists — FRR
     ospf6d has no SRv6 files — so the acceptance is the RFC-figure-
     pinned unit tests (29 in lr-ospf) plus 4 router-level e2e tests
     over live v3 exchanges. End.X / LAN End.X SIDs (§9.1/§9.2, types
     31/32) ride the RFC 8362 E-Router-Link TLV and are a later
     slice, mirroring how the v2 Adj-SID slice followed the Prefix-
     SID one; the daemon `[ospf] srv6` config + origination is slice
     3 of the SRv6 workstream (RFC 9256 / 9430 SR Policy remains the
     long-term BGP-side target).
   - ~~**Slice 6 — OSPFv3 SRv6 daemon surface (slice 3 of the
     SRv6 workstream)**~~ — done: the configuration and origination layer on
     top of slice 2's codec, mirroring the v2 SR-MPLS daemon slices
     (`[[ospf.prefix_sid]]` → `[[ospf.srv6_locator]]`). Config
     surface: `[[ospf.srv6_locator]]` tables (IPv6 `prefix`;
     `algorithm` default 0; `metric`; `anycast` = the §6 AC-bit;
     `sid` defaulting to the locator prefix itself — the RFC 8986 End
     behavior on the locator; `behavior` default 1 = End; and the
     all-or-none §10 SID Structure lengths `block_len`/`node_len`/
     `function_len`/`argument_len`) plus the `[ospf]` globals
     `srv6_receive` (the §5 reception gate on the daemon path — the
     `sr_receive` counterpart), `srv6_o_flag` (§2/RFC 9259), and the
     Node MSD limits `srv6_max_sl`/`srv6_max_end_pop`/
     `srv6_max_h_encaps`/`srv6_max_end_d` (RFC 8476 carrier, RFC 9352
     §4 MSD types); CLI flags `--ospf-srv6-locator` (repeatable),
     `--ospf-srv6-receive`, `--ospf-srv6-o-flag`. Fail-closed
     validation: SRv6 config is OSPFv3-only (rejected under v2 — the
     mirror of the v2-only rejection of the SR-MPLS keys under v3),
     finalize_ospf() now runs for SRv6-only configuration, and the
     per-locator checks reject IPv4 prefixes, End-SID-invalid
     behaviors (§11 Table 1), partial §10 structures, §10 sums above
     128 bits and duplicate locator prefixes. Origination: with
     locators configured the v3 daemon resolves them once into wire
     TLVs and `reoriginate_area` emits, per area and into the same
     LSU as the topology LSAs, the Router Information LSA (instance
     ID 0; Capabilities with the optional O-flag, the SR-Algorithm
     TLV derived from the distinct locator algorithms, the Node MSD
     TLV from the configured limits) and the Locator LSA (Link State
     ID 1; one §7.1 TLV per locator with its §8 End SID and optional
     §10 structure) — sequence floors per area riding the existing
     adjacency-driven re-origination and §14.1 refresh cadences, so
     an SRv6 router looks exactly like a slice-1 daemon otherwise.
     The acceptance gate is the 3-node interop lab
     `tests/interop/ospf6_frr_srv6.sh`: lr1 originates,
     FRR 10.3 ospf6d (which has no SRv6 support at all) must store
     and re-flood the U-bit-set unknown LSAs (RFC 5340 §4.5.2
     transparency — all five of lr1's LSAs appear in its LSDB), and
     lr2 with `srv6_receive` installs lr1's locator as an Ospfv3
     route with a link-local next hop purely through the FRR relay —
     RFC 9513 §5 route computation against a foreign relay. The lab
     also flushed out a config-truth detail: a locator written as
     `2001:db8:a:1::/48` normalizes to `2001:db8:a::/48` (the fourth
     hextet is host bits at /48) — the lab uses a clean /64.

  - **Slice 7 — OSPFv3 inter-area + AS-externals (RFC 5340
    §4.4.3.4/§4.4.3.5/§4.4.3.6, §4.8.3, §4.8.5)** — done: the biggest
    remaining parity gap versus the v2 plane closed. Codecs: the
    Inter-Area-Router-LSA (0x2004 — `0|options(3)|0|metric(3)|dest
    router ID`, 12 bytes, the destination travels in the body per
    §4.4.3.5) and the AS-External-LSA (0x4005 — the E/F/T flags ride
    byte 0 of the metric word at 0x04/0x02/0x01, FRR
    `ospf6_asbr.h` parity and *unlike* the v2 top-bit E form, the
    Referenced LS Type occupies the prefix's trailing §A.4.1 word, and
    the forwarding address is a 16-byte global address gated by the F
    bit). Route calculation: `summary_routes_v3` (§4.8.3 — the §16.2
    form with body prefixes, NU-bit exclusion and the border router's
    link-local first hop on each candidate) and `external_routes_v3`
    (§4.8.5 — the §16.4 form: ASBR legs intra-area from the tree or
    inter-area via 0x2004 *bodies*, FAs validated against the
    intra+summary covering table with the illegal forms refused,
    type-1/2 semantics, the §16.4 (6) preference). Router install: the
    v3 recompute merges intra > inter > external, `OspfKind::External`
    generalizes the forwarding address to `Option<IpAddr>` (a v6 FA
    publishes as the next hop), 0x4005s re-flood across attached v3
    areas, and the `no_summary` acceptance gate now decodes the v3
    default (a zero-length body prefix — the v2 LS-ID heuristic is
    meaningless in v3). Origination: a v3 ABR (all areas v3,
    backbone-attached — mixed v2/v3 routers act as an ABR for neither
    version, fail-closed) originates 0x2003s under the v2 type-3
    source rules with stable per-(area, prefix) LS IDs (previous
    instance reuse, then lowest free ID — FRR `ospf6_new_ls_id`
    parity) and 0x2004s with LS ID = destination router ID and the
    destination's Router-LSA options mirrored (§4.4.3.5, FRR parity);
    `ospf_redistribute_v3`/`ospf_unredistribute_v3` cover the ASBR
    side (stable per-prefix LS ID across areas, illegal FAs refused at
    the API, MaxAge withdrawal, `refresh_due` covers the periodic
    re-origination), and redistribution pipes targeting `Ospfv3`
    bridge v6 routes.

  - **Slice 8 — OSPFv3 broadcast segments (RFC 5340 §4.1.2, §4.4.3.2,
    §4.4.3.3, §4.4.3.5, §A.4.3/A.4.4)** — done: the last v2-parity gap
    in the v3 daemon's data path. `lr-ospf::interface::elect_v3` runs
    the RFC 2328 §9.4 election core on Router-ID identity (RFC 5340
    §4.1.2 keeps the v2 algorithm and interface FSM; §A.3.2's v3 Hello
    carries Router IDs in its DR/BDR fields, so the segment identity
    switches from the v2 IP interface address to the Router ID). The
    daemon drives the §9.3 interface FSM (Waiting/BackupSeen/WaitTimer,
    NeighborChange dirtying from received Hellos) and pushes the
    elected pair through `set_ospf_dr_state`, whose §10.4 adjacency
    gate and §9.4 step-7 AdjOK? handling are identity-agnostic.
    Origination follows FRR ospf6d parity: the Router-LSA describes a
    broadcast interface only as a transit link (§A.4.3 type 2 — the DR
    self-referential, others pointing at the elected DR and only while
    fully adjacent with it); the DR originates the Network-LSA
    (§4.4.3.3 — LS ID = its Interface ID, Options OR'd from the fully
    adjacent neighbors' Link-LSAs, attached routers = itself plus every
    Full neighbor) and flushes it on role loss (§14.1 MaxAge reflood);
    the §4.4.3.5 prefix split — transit-reported interfaces drop their
    prefixes from the router-referenced Intra-Area-Prefix-LSA, the DR
    originates the network-referenced one (the Link-LSA prefix union,
    NU/LA and link-locals excluded, duplicate prefixes merged with
    their options OR'd). One real wire bug the lab flushed out on the
    router side: a peer that is already DR fires its initial DBD the
    moment it sees us bidirectional, and absorbing it while our segment
    was still Waiting left the exchange half-negotiated — DBDs now
    return unprocessed below ExStart (§10.6), and the adjacency
    re-opens through the election's set_ospf_dr_state push. Evidence:
    `tests/interop/ospf6_broadcast.sh` (lr x lr — election convergence,
    Network-LSA-vertex routing both ways, the non-DR carrying the
    shared-segment prefix only via the DR's network IAP, dead-timer
    retraction) and `tests/interop/ospf6_frr_broadcast.sh` (lr x FRR
    10.3 ospf6d on its default broadcast type — two independent §9.4
    implementations converge on the same DR/BDR pair, FRR parses lr's
    transit links + Network-LSA + network IAP, lr resolves FRR's
    loopback through the network vertex onto a link-local next hop).

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

### W3 extra — OSPFv3 daemon mode (RFC 5340)

5. **OSPFv3 daemon mode** — the v2 daemon ran, but the v3 codec
   surfaces that predated it had never touched a real peer (STATUS
   open item 2, and the named prerequisite of the RFC 9513 SRv6
   slice). Landed as a wire audit + codec repair + a purpose-built
   daemon module, sliced into independently verified commits:

   - **Wire audit against RFC 5340 + FRR 10.3 `ospf6d` master**
     found the v3 codec self-consistent but wrong on four counts,
     each invisible to round-trip tests: the packet header must be
     16 bytes (§A.3.1 — the codec emitted v2's 24-byte shape with 8
     junk bytes before every body); the Hello body is
     interface-ID | priority | options(3) | hello | **16-bit** dead |
     DR | BDR (§A.3.2 — the encoder used v2's field order and a
     32-bit dead interval, which FRR's `ospf6_packet_examin`
     alignment check rejects outright); the DBD body is 12 bytes —
     0 | options(3) | MTU | 0 | flags | seq (§A.3.3 — the encoder
     used v2's MTU-first order, FRR parsed MTU 0 and stalled the
     exchange in ExStart); the LS-Request entry's reserved word
     *leads* the 16-bit type (§A.3.4 — the encoder put it second, so
     FRR read type-0 requests and never answered, deadlocking
     Loading). The first two were fixed before any daemon existed
     (self-tests could only pin the *new* shapes); the last two were
     flushed out by the FRR interop lab itself — the DBD fix needed
     FRR's ExStart hang reproduced, the LSR fix needed FRR's
     silent LSR-drop observed. Every shape is pinned against the
     RFC diagram and the FRR struct/encoder (`ospf6_make_hello`,
     `ospf6_make_dbdesc`, `ospf6_lsa.h`), and the exchange gained a
     version parameter (v3 advertises the §A.2 V6|R|E option set
     0x13, not v2's E|O).
   - **LSA bodies (`lr-ospf::lsa::v3`)**: Router-LSA (0x2001) with
     16-byte link descriptors running to the end of the LSA (no
     count field — a v2 habit that does not exist on the v3 wire),
     Network-LSA (0x2002, LS ID = the DR's Interface ID), Link-LSA
     (0x0008 — the §4.4.3.4 MUST that carries each router's
     link-local, the datum every v3 next hop resolves from), and
     Intra-Area-Prefix-LSA (0x2009) with the §A.4.1 prefix encoding
     (addresses rounded to 32-bit words, FRR
     `OSPF6_PREFIX_SPACE` parity). Origination helpers mirror the
     v2 shapes: sequence floors per §12.1.2, finalized LSAs.
   - **SPF (`run_spf_v3`)**: the same Dijkstra tree over the v3
     LSDB, with Network vertices keyed (DR Router ID, DR Interface
     ID). Next hops are (link-local, outgoing Interface ID) pairs: a
     direct p2p neighbor's link-local comes from its Link-LSA whose
     Link State ID is the Neighbor Interface ID of our p2p link (the
     v3 form of RFC 2328 §16.1.1 (5)), and routers on a directly
     attached transit network resolve through the back-link — their
     own Router-LSA transit entry pointing at the network carries
     the Interface ID they use there, which indexes their Link-LSA
     (the unambiguous pure-LSDB route where FRR consults the
     per-link LSDB in `ospf6_nexthop_calc`). Prefixes arrive via
     Intra-Area-Prefix-LSAs; NU- and LA-marked prefixes are excluded
     (§A.4.1). The FRR `ospf6_lsdesc_backlink` bidirectional check
     gates p2p edges. Routes publish as `Protocol::Ospfv3` in the
     v6-unicast family.
   - **Transport (`OspfV6Transport`)**: raw IPv6 protocol-89 sockets
     per interface, ff02::5/ff02::6 membership, hop limit 1,
     `sin6_scope_id` unicast — and no header stripping (unlike IPv4
     raw sockets, the Linux IPv6 raw layer delivers the OSPF packet
     bare). Kernel-gated test: bind on `lo`, multicast a real v3
     Hello, receive it back byte-identical.
   - **Daemon (`daemon_ospf3`)**: `[ospf] version = "v3"` (one
     version per process, FRR's ospfd/ospf6d split). Interface ID =
     kernel ifindex (FRR convention); the neighbor's Interface ID
     rides its Hello into our Router-LSA's p2p descriptions.
     Self-origination: Router-LSA per area (p2p link per Full
     adjacency, MinLSArrival-spaced re-origination + §14.1 refresh),
     a Link-LSA per interface (originated unconditionally — the
     RFC MUST), and one Intra-Area-Prefix-LSA attaching the global
     prefixes. Every egress datagram's IPv6 pseudo-header checksum
     is finalized for the actual (link-local, ff02::5) pair. The
     link-local → interface mapping learned from Hello sources feeds
     a process-wide table the kernel mirror consults, so v3 routes
     install with the RTA_OIF a link-local gateway requires (netlink
     EINVAL without it). Slice-1 scope is p2p-only; the config
     finalizer rejects broadcast/GR/SR combinations outright instead
     of ignoring them. One real bug the lab flushed out on the
     daemon side: the daemon's pumps raced the shared ticker thread
     for `poll_events()` and could steal RouteInstalled events
     before the kernel mirror saw them — the ticker is now the sole
     event consumer.
   - **Evidence**: `tests/interop/ospf6.sh` (two lr daemons over a
     veth pair: Full adjacency, `proto=Ospfv3` routes via link-local
     next hops both directions, kernel FIB install with `dev veth0`,
     dead-timer withdrawal removing the API route *and* the kernel
     route) and `tests/interop/ospf6_frr.sh` (lr × FRR 10.3
     ospf6d, p2p network type: Full adjacency on both, lr learns
     FRR's prefix through a link-local, FRR's route table carries
     lr's prefixes — proving FRR parses lr's Router/Link/
     Intra-Area-Prefix LSAs — and SIGKILL teardown within the dead
     interval).

## Phase 3 — landings

### OSPFv3 graceful restart (RFC 5187)

The Phase 3 plan's item 1 — the last v2-only daemon feature —
landed as four slices:

- **The v3 Grace-LSA (`lr-ospf::lsa::grace`)**: the dedicated
  link-scoped LS type 0x000b (LSA function code 11, S2/S1 = 0,
  U-bit 0) with the originating **Interface ID as the Link State
  ID** — no opaque-type packing, OSPFv3 has no RFC 5250. The TLVs
  are RFC 3623's unchanged; RFC 5187 §1 drops the router-address
  TLV requirement (v3 neighbours are Router-ID identified), so the
  interoperable default body is TLV 1 + TLV 2 only — exactly FRR
  `ospf6_gr_lsa_originate`'s shape. One correction to this file's
  own plan text: RFC 5187 defines **no** GR capability bit in v3
  Hellos/DBDs — the Grace-LSA itself is the signal (v2's O-bit
  belongs to RFC 5250 opaque capability and stays v2-only).
- **A dedicated grace-event channel (`lr-router`)**: received
  Grace-LSAs surface through `drain_ospf_grace_events()` instead of
  `RouterEvent::OspfGraceLsa`. The v2 daemon raced its own ticker
  thread for grace events (whoever polled first got them; the
  ticker drops unknown variants), and the v3 daemon cannot call
  `poll_events()` at all — its ticker is the sole consumer by
  design (the kernel-mirror race the slice-1 CI-red fixed). A
  channel of its own delivers every grace instance to the
  embedder's helper policy deterministically; the v2 daemon's
  helper flow is otherwise unchanged (`ospf_gr.sh` re-verified).
- **The daemon surface (`daemon_ospf3`)**: helper mode with
  dead-timer retention (FRR ospf6d resets the neighbour's inactivity
  timer while helping — so does the v3 `pump_dead_timer` via the
  helper retention set), the graceful-shutdown Grace-LSA flood
  (multicast + unicast copies to bidirectional link-locals, bounded
  retransmission with protocol servicing between rounds, the
  state-file deadline + sequence floor persisted after the flood),
  recovery (origination suppressed, the pre-restart adjacency set
  seeded from the retained v3 Router-LSA p2p descriptors, back-link
  verification, the §2.3 flush + re-origination above the retained
  sequence floors). RFC 5187 §3.2's Interface-ID preservation holds
  structurally: the daemon's Interface IDs are kernel ifindexes,
  which do not change across a process restart while the interface
  stays up.
- **A self-review fix — LSDB sequence floors for every
  self-originated LSA**: only the Router-LSA consulted the area LSDB
  for its previous sequence; the Link/IAP/Network/SRv6 shapes used
  in-memory state alone, so after a recovery a fresh 0x80000001
  instance would be older than every neighbour's retained copy and
  silently ignored (RFC 2328 §12.1.2) — the LSA would never refresh
  and age out an hour after the restart, taking the v3 Link-LSA's
  next-hop resolution with it. `lsa_seq_floor()` generalizes the
  floor to every v3 shape; the v2 Network-LSA gets the same
  treatment.
- **One interop-driven fix, applied to both versions**: the MaxAge
  flush now carries a valid body (period ≥ 1, reason ≤ 3). FRR's
  grace-LSA extraction (`ospf6_extract_grace_lsa_fields` in ospf6d,
  `ospf_extract_grace_lsa_fields` in ospfd) rejects a period-0
  flush as "Wrong Grace LSA packet" and drops it — the helper then
  exits only on grace timeout. FRR's own purge keeps the
  announcement's TLVs; BIRD and lr ignore the flush body, so the
  valid-body flush passes all three receivers (re-verified:
  `ospf_gr.sh`, `ospf_gr_bird.sh`).

Evidence: `tests/interop/ospf6_gr.sh` (two lr daemons — planned
restart with retention + recovery + flush exit, then the
grace-period timeout with teardown and withdrawal) and
`tests/interop/ospf6_gr_frr.sh` (lr restarter × FRR 10.3 ospf6d
with `graceful-restart helper enable` — helper entry on the 0x000b
Grace-LSA, `activeRestarterCnt: 1` retention across the dead
interval, `lastExitReason: "Successful graceful restart"` on the
flush, routes never withdrawn).

## Phase 3 — plan (post roadmap-v2)

Where the project stands: every roadmap-v2 workstream (W1-W6) is
complete, and the W3-extra MPLS extension has landed through SRv6
slice 3 (data plane + RFC 9513 OSPFv3 control plane + daemon
origination). The OSPF planes are now at feature parity with each
other for intra-area, inter-area, external and broadcast-segment
behavior; both daemon modes interoperate live with FRR 10.3 (ospfd,
ospf6d, ldpd, bgpd) and BIRD 2. The honest remaining gaps are narrow
and enumerable - the list below is the next phase.

Ordered by expected user value (protocol-correctness parity first,
control-plane extension second, policy surface third):

1. ~~**OSPFv3 graceful restart (RFC 5187)**~~ — done (the landing
   record lives in "Phase 3 — landings" above). The v2 daemon's last
   exclusive feature is gone: both versions now carry the full GR
   surface, and a v3 restarter recovers from a live FRR 10.3 ospf6d
   helper. The plan text's "O-bit signaling in v3 Hellos/DBDs" was a
   misreading — RFC 5187 defines no capability bit at all; the
   Grace-LSA itself is the signal (the audit correction is recorded
   in `RFC_MAP.md`).
2. **RFC 8362 extended-LSA machinery + SRv6 End.X / LAN End.X SIDs
   (RFC 9513 §9)** - the SRv6 control plane's missing adjacency
   segments. RFC 8362 is the prerequisite: the E-Router / E-Network /
   E-Link / E-Intra-Area-Prefix / E-Inter-Area / E-AS-External LSA
   set with TLV bodies and the U-bit-2 flooding rules, an E-LSA SPF
   path, and then the E-Router-Link TLV carrying the End.X and LAN
   End.X SID sub-TLVs (RFC 9513 §9) originated per interface on Full
   adjacency, projected into `srv6db`, and installed as seg6local
   routes by the kernel mirror (mirroring the v2 Adj-SID slice's
   shape). Interop gate: lr x lr at the library level plus FRR
   transparency (FRR ospf6d stores and re-floods the unknown E-LSAs).
3. **BGP-LS (RFC 7752 base + RFC 9552 SRv6 extensions)** - export
   the routing domain to an SDN controller: node/prefix/link NLRI
   from the OSPF LSDBs, the SRv6 Node (Capabilities, MSDs), Locater
   and End.X SID TLVs projected from `srv6db`, with the daemon as a
   BGP-LS producer (a new address family on the existing BGP
   sessions). Acceptance: a BGP-LS collector (FRR bfdd-style bgpd or
   a lab consumer) receives the full SRv6 view of an lr OSPF domain.
4. **BGP SR Policy (RFC 9256 / RFC 9430)** - the consumer side of
   the SRv6 fabric: receive candidate/dynamic SR policies as VPN
   routes, resolve them to `lr-srv6` segment lists, and steer
   matching Loc-RIB entries into seg6 encap routes in the kernel
   mirror (the BGP-LU LSP-mirror slice's shape, extended to SRv6
   policies).

Non-goals carried forward: BGPsec (documented out of scope), NBMA
and point-to-multipoint interface types (broadcast + p2p cover the
interoperable field surface both references implement; the two types
differ mainly in neighbor discovery, which the daemon's dynamic
session model already handles), and OSPFv3 virtual links (v2-only
today - revisit if a multi-area v3 deployment asks for them).

## Phase 4 — pre-1.0 hardening

Where the project stands: every roadmap-v2 workstream (W1-W6) is
complete, the W3-extra MPLS extension has landed through SRv6 slice 3
(RFC 9513 OSPFv3 control plane + daemon origination), the OSPFv3
graceful-restart slice (RFC 5187) closed the v2-exclusive feature
gap, and the project is at feature parity with BIRD 2 and FRR 10
for every protocol it implements (only BGPsec is ❌ and deliberately
out of scope). The honest remaining work to a 1.0 cut is
engineering hygiene — CI on the desktop platforms, the lr-cli
documentation surface, and an explicit release flow — not protocol
coverage. Phase 4 lands that work.

Ordered by user-visible impact (CI first, documentation second,
release governance third):

1. **CI on Windows + macOS** — done: the `cross-platform` job in
   `.github/workflows/ci.yml` runs a matrix of `ubuntu-22.04`,
   `macos-13` (Intel), `macos-14` (Apple Silicon) and `windows-2022`,
   each running `cargo fmt --check`, `cargo clippy -D warnings`,
   `cargo build --workspace --all-features` and
   `cargo test --workspace --all-features`. The workspace's
   cross-platform surface was already in place (lr-osroute carries
   Windows IP-Helper, BSD/macOS route-socket, and Linux rtnetlink
   backends; `lr-cli::signal` splits along `#[cfg(unix)]` /
   `#[cfg(not(unix))]`; the Linux-only kernel-gated tests
   (`ospf6_kernel.rs`, `srv6_kernel.rs`) are gated at the file level
   with `#![cfg(target_os = "linux")]` so the Windows/macOS runners
   skip them at compile time). The BIRD/FRR interop suite stays on
   the Linux-only `interop` job — it is not portable to runners
   without those packages.

2. **`lr-cli` user guide + internals doc** — done:
   `docs/lr-cli.md` is the user-facing reference for every `lr` and
   `lr-daemon` subcommand (decode, routes, mrt, parity-replay,
   translate, yang render, run, plus the full daemon flag surface
   for BGP, Babel, OSPF, LDP, BMP, and the OSPFv3 SRv6 RFC 9513
   knobs), and `docs/lr-cli-internals.md` is the contributor-facing
   module map and extension-pattern doc. Both link to the existing
   `RUNBOOK.md` (runtime API), `templates/daemon.toml` (every key
   explained), and `INTEROP.md` (interop matrix) instead of
   duplicating them.

3. **`RELEASE-PLAN.md`** — done: `docs/RELEASE-PLAN.md` is the
   canonical reference for the semver policy, the three-tier public
   API stability contract (Rust library API, C ABI, daemon flag +
   config surface), the 1.0 freeze criteria (RFC coverage, CI
   matrix, wire-level parity, ABI version pin, documentation set
   complete), the release flow (pre-release checks, tagging, the
   `release.yml` build matrix on Linux + macOS Intel + macOS Apple
   Silicon + Windows, draft release with auto-generated notes), and
   the post-1.0 governance rules (stability window, deprecation
   policy, new-protocol-crate checklist, compatibility matrix
   against BIRD 2 + FRR 10 + libyang + Linux kernel versions).
   Items 2.4 (cross-platform CI) and 2.6 (documentation set) in the
   freeze criteria are checked off by this Phase; 2.7 (the 1.0 cut
   PR) is the next release-event after one clean week of CI on all
   three platforms.

4. **Extended release workflow** — done: `.github/workflows/release.yml`
   now builds `lr-ffi` on a matrix of four native targets (Linux
   x86_64, macOS x86_64, macOS aarch64, Windows x86_64-MSVC),
   stages the platform's shared library (`liblr_ffi.so` /
   `liblr_ffi.dylib` / `lr_ffi.dll`), the static archive where the
   toolchain emits one, and the C / C++ headers into a tarball
   (or `.zip` on Windows), uploads each as a build artifact, and a
   final `publish-release` job flattens them with the standalone
   headers into a single draft GitHub Release with auto-generated
   commit-diff release notes. The release body links back to
   `docs/RELEASE-PLAN.md` and to the per-language binding guides in
   `docs/bindings/`.

5. Keep `STATUS.md` / `RFC_MAP.md` / `API.md` synchronized with
   every landed feature (standing rule, enforced at review — and
   applied here for the Phase 4 landings).

The Phase 3 protocol work (RFC 8362 E-LSA machinery + SRv6 End.X /
LAN End.X SIDs, BGP-LS, BGP SR Policy) is post-1.0 work: it extends
the surface but does not block the freeze, because the surface it
extends is already at parity with BIRD and FRR for the protocols it
touches.

## Phase 5 — CI matrix hardening + documentation expansion

Where the project stands: Phase 4 landed the cross-platform CI
matrix (Ubuntu + macOS Apple Silicon + Windows) plus the lr-cli
documentation surface and the RELEASE-PLAN. The first week of CI
on the new matrix flushed five real cross-platform bugs (gtsm
test imports, api.rs idle-spin, daemon_bfd Linux-specific
assumptions, lr-ldp 127.0.0.2 send/bind, daemon_runtime API
timing) — all fixed. The remaining work is hygiene, not protocol
coverage: retire the macos-13 (Intel) native job (its runner was
queued-for-hours every CI run since Phase 4 landed, blocking the
signal while the same code paths ran green on macos-14), and fill
the example-doc gaps that surfaced during the Phase 4 docs work
(LDP, BGP-LU + MPLS, OSPFv3 SRv6 had no walkthrough docs).

Ordered by user-visible impact:

1. **Drop `macos-13` from the cross-platform matrix** — done:
   GitHub Actions retired the Intel `macos-13` runner pool
   during 2025. The runner was queued-for-hours (sometimes days)
   on every CI run since the Phase 4 matrix landed, blocking the
   cross-platform signal while the same code paths ran green on
   `macos-14` (Apple Silicon). Dropped from the cross-platform
   job. Intel macOS compilation is still covered by the new
   `cross-macos-intel` job that cross-compiles
   `x86_64-apple-darwin` from a `macos-14` (Apple Silicon)
   runner — the universal Apple clang on `macos-14` targets both
   arches natively. The `lr-osroute` BSD backend has no
   Intel/Apple-Silicon conditional code (the route(4) socket
   ABI is the same), so a build check is sufficient coverage for
   the Intel macOS path. Native test execution on Intel macOS is
   dropped (the kernel-gated tests were already Linux-only at
   the file level).

2. **Three new example docs filling the doc-set gaps** — done:
   - `docs/examples/ldp_basic.md` — LDP label distribution
     (RFC 5036): the byte-pump pattern over UDP discovery + TCP
     session, the FEC/label advertise + withdraw lifecycle, and
     the kernel MPLS dataplane mirror on Linux. Cross-links to
     the daemon's `daemon_ldp.rs` and the `ldp_frr*.sh` interop
     labs.
   - `docs/examples/bgp_labeled_unicast.md` — RFC 8277 BGP-LU →
     MPLS dataplane: the `LrMplsLabelStack` private attribute,
     the LSP tail (locally originated, install pop) and LSP head
     (peer-advertised, install encap) classification, and the
     `KernelMirror` decision table. Cross-links to the
     `labeled_unicast.sh` and `mpls_lsp.sh` interop labs.
   - `docs/examples/ospfv3_srv6.md` — RFC 9513 OSPFv3 SRv6: the
     LOC:FUNCT:ARGS model, the RI LSA + Locator LSA origination
     at the library level (using the real
     `originate_v3_srv6_ri_lsa` + `originate_v3_srv6_locator_lsa`
     signatures), the `srv6db` reception path, and the
     `--ospf-srv6-*` CLI surface. Cross-links to the
     `ospf6_frr_srv6.sh` 3-node interop lab and the next-slice
     roadmap (RFC 8362 E-LSA + End.X SIDs).

3. Keep `STATUS.md` / `RFC_MAP.md` / `API.md` synchronized (the
   standing rule — applied here for the Phase 5 landings: the new
   example docs are indexed in `docs/README.md` and the macOS CI
   change is recorded here).

The Phase 3 protocol work (RFC 8362 E-LSA machinery + SRv6 End.X /
LAN End.X SIDs, BGP-LS, BGP SR Policy) remains post-1.0 work; the
documentation surface it needs (the `ospfv3_srv6.md` example plus
the existing `OS-INTEGRATION.md` SRv6 section + the
`docs/research/EXCHANGE-PLANE.md` design notes) is now in place
for the next implementer to pick up.

## Phase 6 — E-LSA design doc + RUNBOOK expansion + code audit

Where the project stands: Phase 5 landed the CI matrix hardening
(dropping `macos-13`, adding `cross-macos-intel`) and three new
example docs (LDP, BGP-LU, OSPFv3 SRv6). CI is green on all
desktop platforms. The next protocol-correctness slice is Phase 3
item 2 — RFC 8362 Extended-LSA machinery + SRv6 End.X SIDs (RFC
9513 §9). That slice is large enough (seven E-LSA bodies with TLV
framing, the U-bit-2 flooding rules, an E-LSA SPF path, and the
End.X SID sub-TLV) that landing it requires a design doc first:
the codec shapes, the database projection rules, the SPF
integration and the interop verification all need to be enumerated
before any code lands so the implementation does not drift from
the RFC. Phase 6 lands that design doc plus a RUNBOOK expansion
and a small code audit — the protocol implementation itself is
the next Phase.

Ordered by user-visible impact:

1. **RFC 8362 E-LSA implementation design doc** — done:
   `docs/research/E-LSA-DESIGN.md` is the implementation plan for
   the next contributor. Covers: the seven E-LSA function codes
   (0xA020–0xA026) and their LS Type / scope mapping; the shared
   TLV framing (RFC 3630 convention, already used by
   `lr-ospf::lsa::srv6`); the E-Router-LSA body + Router-Link TLV
   shape (the carrier for the End.X SID sub-TLV); the other six
   E-LSA bodies and their TLV type registry; the U-bit-2 flooding
   rules (store + re-flood unchanged through non-participating
   routers — already proven by the SRv6 interop lab); the SPF
   integration plan (E-bit detection + E-LSA → SPF-input
   extractors, additive to the legacy path so a deployment that
   does not configure E-LSAs sees byte-identical output); the
   End.X / LAN End.X SID sub-TLV design (RFC 9513 §9.1/§9.2,
   types 31/32); the interop verification plan (lr x lr + FRR
   transparency, same shape as the SRv6 slice); the three-slice
   breakdown (codecs → SPF → End.X origination + dataplane);
   risk and mitigation table.

2. **RUNBOOK deep-troubleshooting expansion** — done: added a
   "Deeper troubleshooting" section to `docs/RUNBOOK.md` covering
   seven operational failure modes the original FAQ did not reach:
   BGP session flapping (hold-timer / auth / collision diagnosis),
   OSPF adjacency stuck in ExStart (MTU / Router-ID / interface
   type), OSPF adjacency stuck in Exchange (dead-interval / area
   mismatch), LDP label binding not propagating (Hello / session /
   kernel MPLS), route flap damping over-aggressive (modern
   recommendations vs RFC 2439 defaults), memory growth on
   full-table peers (soft-reconfig / import route-map /
   maximum-prefix), CPU spike during full-table reconvergence
   (GR / LLGR / BFD), and MRT dump disk growth (rotation / tmpfs).

3. **Code audit** — done: replaced two `unwrap()` calls in
   `lr-core` production code with explicit patterns that document
   the safety invariant for the reader. The IPv6-address
   dotted-quad parser (`addr.rs`) gained a `match` that removes
   the `last.unwrap()` after the `has_quad` check; the timer heap
   (`timer.rs`) gained an `expect("peek confirmed non-empty")`
   after the `peek()` → `pop()` pair. Both were provably safe by
   construction; the change is readability + lint cleanliness, not
   a bug fix.

4. Keep `STATUS.md` / `RFC_MAP.md` / `API.md` synchronized (the
   standing rule — applied here for the Phase 6 landings).

The Phase 3 protocol work (RFC 8362 E-LSA machinery + SRv6 End.X /
LAN End.X SIDs, BGP-LS, BGP SR Policy) remains post-1.0 work; the
design doc landed in this Phase gives the next implementer the
codec shapes, the SPF integration plan and the interop verification
plan to pick up slice 1 (codecs) without re-deriving the RFC 8362
mapping from scratch.

## Phase 7 — v1.0.0-rc.1 pre-release

Where the project stands: Phase 6 landed the E-LSA design doc, the
RUNBOOK deep-troubleshooting expansion, and a small lr-core code
audit. CI is green on all desktop platforms (11/11 jobs), and
nightly is green (2/2 jobs — Miri UB check + QEMU VM harness for
kernel-gated interop). The user instructed a full judgment of
whether the 1.0.0 release conditions (RELEASE-PLAN.md §2) are
met, and if functionality is complete with no large code changes
expected before 1.0.0, to skip the 1-week clean-CI wait or
publish a pre-release.

The assessment against §2 freeze criteria (verified on commit
`1cc6f5d`):

- ✅ §2.1 — RFC coverage at parity with BIRD 2 + FRR 10 for every
  protocol in scope; only BGPsec is ❌ (documented out of scope).
- ✅ §2.2 — Cross-vendor interop in CI (BIRD 2 + FRR 10): BGP,
  OSPFv2/v3, Babel, LDP, BFD, BMP, MRT, parity — all green.
- ✅ §2.3 — Wire-level parity harness (`lr parity-replay` +
  `parity.sh`) green.
- ✅ §2.4 — Cross-platform CI green: 11/11 jobs (Ubuntu, macOS
  Apple Silicon, Windows, 3 cross-builds, MSRV, Coverage,
  interop BIRD+FRR, interop-auth TCP-AO). macOS Intel is
  cross-compiled from macos-14 (macos-13 retired by GitHub
  Actions).
- ✅ §2.5 — ABI version pinned (`ABI_VERSION = 1` in lr-core;
  cbindgen regenerates the header on every build).
- ✅ §2.6 — Documentation set complete (all listed docs exist and
  reference live code; Phase 4-6 added lr-cli.md,
  lr-cli-internals.md, RELEASE-PLAN.md, E-LSA-DESIGN.md, 3 new
  example docs, RUNBOOK deep-troubleshooting expansion).
- ✅ §2.7 — The 1.0 cut PR is this Phase.
- ✅ Nightly — Miri (UB check for unsafe FFI) green; VM harness
  (kernel-gated interop, QEMU) green.

Ordered by user-visible impact:

1. **Workspace version bump** — done: bumped the workspace
   `version` from `0.1.0` to `1.0.0-rc.1` (and all the
   `[workspace.dependencies]` version lines, the lr-python
   `__version__` + `pyproject.toml`). The Go binding uses git
   tags for versioning (no version string in go.mod). The C/C++
   headers carry no version string (cbindgen does not emit one).
   The `ABI_VERSION` constant in lr-core stays at `1` — the
   pre-release does not change the ABI; the 1.0.0 final will
   carry the same value.

2. **Tag and push** — done: tagged `v1.0.0-rc.1` on commit
   `1cc6f5d`, pushed the tag, triggered the `release.yml`
   workflow.

3. **Release workflow** — done: the `release.yml` build matrix
   (4 native targets: Linux x86_64, macOS Intel + Apple Silicon,
   Windows x86_64-MSVC) all built successfully; the
   `publish-release` job assembled them with the standalone
   headers into a single GitHub Release with 6 assets. Published
   as a pre-release (`draft: false`, `prerelease: true`) with
   detailed release notes covering protocol coverage, interop
   verification, cross-platform CI, out-of-scope items, and the
   "what this pre-release is for" explanation.

4. **release.yml fix** — done: the release.yml build matrix used
   `macos-13` (Intel) for the x86_64-apple-darwin artifact. The
   runner was stuck queued on the first release run (GitHub
   Actions retired the macos-13 runner pool during 2025; Phase 5
   dropped it from the CI matrix for the same reason). Switched
   to `macos-14` (Apple Silicon) and cross-compile to
   x86_64-apple-darwin from there — the universal Apple clang
   on macos-14 targets both arches natively. This matches the
   `cross-macos-intel` job in ci.yml.

5. **1-week clean-CI wait skipped** — done: per the user's
   instruction, the 1-week wait (RELEASE-PLAN.md §2.8 target
   window) was skipped because (a) functionality is complete
   (at parity with BIRD 2 + FRR 10, only BGPsec out of scope)
   and (b) the recent commit history (Phase 4-6) is docs + CI +
   small fixes + one refactor — no protocol code changes. The
   next planned protocol work (RFC 8362 E-LSA + End.X SIDs,
   BGP-LS, BGP SR Policy) is explicitly post-1.0 work.

6. **Pre-release rather than final 1.0.0** — done: released as
   `rc.1` rather than the final `1.0.0` to (a) test the
   never-exercised release.yml workflow end-to-end (this is the
   first time it has run), (b) signal API freeze to the
   community, and (c) not commit to 1.0.0 irrevocably — if the
   release artifacts or the workflow surface issues, we can fix
   and re-tag rc.2 before the final 1.0.0.

The Phase 3 protocol work (RFC 8362 E-LSA machinery + SRv6 End.X /
LAN End.X SIDs, BGP-LS, BGP SR Policy) remains post-1.0 work; the
v1.0.0-rc.1 pre-release freezes the API surface so the next
implementer can land the E-LSA codecs (slice 1 of the design doc)
as a minor version bump (1.1.0) without breaking existing
embedders.

## Phase 8 — v1.0.0-rc.3 multi-protocol daemon

**Goal:** one `lr-daemon` process runs a combination of BGP, OSPF
(v2/v3) and Babel (`--protocol bgp,ospf,babel`).

**Design — shared-router supervisor.** The supervisor
(`crates/lr-cli/src/daemon_multi.rs`) owns the process-wide plumbing
exactly once: one `DefaultRouter` (the shared Loc-RIB), one running
flag, one ticker, one runtime API socket, one signal consumer. Each
engine (the same `run_bgp_daemon` / `run_ospf_daemon` /
`run_ospf3_daemon` / `run_babel_daemon` code paths) takes an
`Option<EngineHost>`: `None` is the classic standalone daemon
(unchanged behaviour), `Some(host)` plugs it into the supervisor —
router, running flag and live-session counter come from the host, and
the engine skips its own runtime, API socket, ticker and privilege
drop. Startup is gated: every engine binds its sockets (OSPF raw
sockets, the BGP :179 listener, the Babel UDP pair), reports `Started`
through its channel and blocks on a `StartGate` (Mutex + Condvar, so
a failing engine cannot wedge its siblings); the supervisor waits for
all reports, then drops privileges and creates the management socket
as the reduced user, then releases the gates. A startup failure in
any engine aborts the combination with that engine's exit code; an
engine dying at runtime stops the remaining engines gracefully (a
combination that silently lost one protocol is not a running
combination).

**Signal ownership.** `take_pending` is a single-consumer atomic
swap, and the BGP engine's connector threads and session pumps all
call `dispatch_signals`. The supervisor marks dispatch supervised
(`signal::set_supervised`); engine-side dispatch becomes a no-op, so
no thread can steal SIGTERM/SIGHUP from the supervisor.

**Cross-protocol RIB semantics** (in `lr-router`): the shared Loc-RIB
merges contributions by the FRR admin-distance order (BGP 20 < OSPF
110 < Babel 120) with withdrawal fallback — protocol-direct routes
(OSPF/Babel runtime deltas, tracked in a `direct_rib` map) are chained
into `reselect`, so a BGP re-ranking never evicts them and a
withdrawal from either side falls back to the other's contribution.
Cross-protocol advertisement into BGP is opt-in only: OSPF/Babel
routes never enter BGP advertisements without a redistribution pipe
(FRR `redistribute` / BIRD `pipe` semantics). `bmp` and `ldp` stay
standalone-only (fail closed at dispatch).

**Coverage:**
- unit: `daemon_config` protocol-set parsing (5 tests), `lr-router`
  cross-protocol merge / no-leak / pipe-for-direct-routes (3 tests)
- e2e: `crates/lr-cli/tests/daemon_multi_protocol.rs` (4 tests —
  bgp,babel combination with a real peer, startup-failure abort,
  fail-closed combos, TOML array selection)
- interop: `tests/interop/multi_protocol.sh` — lr `--protocol
  bgp,ospf` versus one BIRD 2 process running ospf + bgp over a veth
  pair (Full adjacency + established BGP in both processes, the
  shared prefix prefers the BGP path, no OSPF route leaks into BGP
  advertisements, graceful shutdown)
- also fixed the pre-existing Babel main-loop busy-spin (10 ms idle
  sleep)

**Landed:** workspace version bumped to `1.0.0-rc.3`; README,
`docs/lr-cli.md`, `docs/STATUS.md`, `templates/daemon.toml` and the
CI interop matrix updated. Bindings (go/python/c/c++) wrap the
library API, which is unchanged in rc.3 (all changes are daemon-layer
or `lr-router` internals) — no binding regeneration needed.
