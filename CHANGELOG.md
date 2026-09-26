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

### Fixed (Babel — production interop with BIRD/babeld)

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
  Filter-eval latency histograms and UPDATE tx/rx counters remain
  open — they require per-session counters the daemon does not track
  today.
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
- Filter DSL large communities (ROADMAP-v3 D3.2, RFC 8097):
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
