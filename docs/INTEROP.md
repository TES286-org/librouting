# Interop testing against BIRD, FRR and a second daemon

This page is the lab inventory: one row per script under
`tests/interop/`, saying who it talks to and what it proves. Read it when
you want to know whether a behaviour is verified against a reference
implementation, or when you are adding a lab. Running instructions live
in [`RUNBOOK.md`](RUNBOOK.md) and the kernel-gated VM harness in
[`../tests/vm/README.md`](../tests/vm/README.md).

`tests/lint_interop_doc.sh` fails the build when a script under
`tests/interop/` has no row here, or when a row names a script that no
longer exists. The CI `lint` job runs it.

## Where the labs run

Five CI jobs run lab scripts:

| Job | Runner | Labs |
| --- | --- | --- |
| `interop` | Ubuntu, BIRD and FRR installed | every reference-daemon lab |
| `interop-auth` | Ubuntu | `md5.sh`, `tcp_ao.sh` |
| `windows-interop` | Windows | `two_daemon.sh`, `labeled_unicast.sh`, `bgp_kernel_install.sh` |
| `macos-interop` | macOS | `two_daemon.sh`, `labeled_unicast.sh`, `bgp_kernel_install.sh` |
| `windows-bird-interop` | Windows | `bird_wsl.sh` |

The nightly `vm-kernel-gated` job boots
[`tests/vm/run_vm.sh`](../tests/vm/run_vm.sh) — a minimal initramfs QEMU
VM, no disk image and no system installation. The tests whose dataplane
phases need kernel features or root therefore run: `tcp_ao.sh`,
`mpls_lsp.sh`, `ldp.sh`, `ospf.sh`, `bgp_kernel_install.sh` and
`bgp_transit.sh`. The VM boots the kernel under test, so the host's
kernel does not need the features in question.

The `windows-interop` job's `bgp_kernel_install.sh` step is the one that
exercises the `lr-osroute` Windows IP-Helper backend for the route
install. The separate `windows-fib-probe` workflow is
`workflow_dispatch`-only, runs the `lr-osroute` Windows FIB integration
tests rather than a lab, and exists as an on-demand evidence machine.

Every lab auto-detects its reference daemon and prints `SKIP: …` with
exit status 0 when it is absent, so the suite degrades on a restricted
runner.

## Baseline labs (librouting against itself)

These need no reference daemon and no root, which is why they are the
portable ones.

| Script | Peers | What it proves |
| --- | --- | --- |
| `two_daemon.sh` | two lr-daemons over TCP | the session FSM and codec work in both roles: route propagation and session-loss withdrawal |
| `labeled_unicast.sh` | two lr-daemons over TCP | RFC 8277 BGP-LU: an AFI=1/SAFI=4 UPDATE carries label 100 and the stack arrives at the peer |
| `addpath.sh` | two lr-daemons over TCP | RFC 7911 Add-Path: the capability negotiates and the NLRI carries the transmitter's path identifier |
| `bmp.sh` | lr-daemon `--bmp-target` to an lr-daemon collector | RFC 7854: station connect, Peer Up ordering, Route Monitoring carrying the full UPDATE |
| `bgp_kernel_install.sh` | two lr-daemons on one host, `--install-kernel-routes` | learn, install, decide, forward, teardown against the real OS FIB: `ip route show` and `ip route get` on Linux, `netstat -rn` and `route -n get` on macOS, `route.exe print` and `Find-NetRoute` on Windows |
| `bgp_transit.sh` | three lr-daemons, one network namespace each | a route learned on one edge survives re-advertisement by the middle router and stays forwardable on the far edge |
| `mpls_lsp.sh` | two lr-daemons, kernel MPLS enabled | BGP-LU reaches the dataplane: each daemon mirrors its half of the LSP (tail pop, head encap) and a ping crosses it |
| `multi_protocol.sh` | one lr-daemon running BGP and OSPF against one BIRD | the multi-protocol supervisor serves both protocols from one process |
| `exchange_plane.sh` | lr-daemon `--exchange-plane` against plain BIRD | the prototype capability stays inert against a peer that does not advertise it (RFC 5492 §3) |
| `parity.sh` | lr-daemon to BIRD through a recording proxy | replaying the captured UPDATE stream reproduces BIRD's own view of the learned routes (`lr parity-replay`, `lr mrt diff`) |

## BGP against BIRD and FRR

| Script | Peers | What it proves |
| --- | --- | --- |
| `bird.sh` | lr-daemon and BIRD 2, eBGP multihop | OPEN and capability negotiation, UPDATE encoding, route exchange in both directions |
| `frr.sh` | lr-daemon and FRR bgpd, eBGP multihop | the same against bgpd, including its stricter next-hop validation |
| `bird_ipv6.sh` | lr-daemon and BIRD over `[::1]` | IPv6 transport and IPv6 NLRI in both directions |
| `bird_enh.sh` | lr-daemon and BIRD over `[::1]` | RFC 5549 Extended Next-Hop: IPv4 NLRI rides an IPv6 next hop, and the capability tuple is the 6-byte `AFI:2, SAFI:2, NH-AFI:2` form both stacks encode |
| `bird_gtsm.sh` | lr-daemon and BIRD with `ttl security` | RFC 5082 GTSM: TTL 255 in both directions |
| `bird_llgr.sh` | lr-daemon and BIRD 2 | RFC 9494 in both helper roles: negotiation, retention, `LLGR_STALE` marking, stale-time purge |
| `bird_wsl.sh` | lr-daemon on Windows and BIRD inside WSL2 | cross-OS BGP: the Windows TCP stack reaches BIRD's Linux stack through WSL2 localhost forwarding |
| `aggregate_bird.sh` | lr-daemon `[[aggregate]]` and BIRD | RFC 4271 §9.2.2.2: BIRD ships the specifics, lr originates the aggregate with zeroed AS_PATH and ATOMIC_AGGREGATE, and withdraws it when the specifics vanish |
| `redistribute_bird.sh` | multi-protocol lr-daemon and BIRD on both sides | `[[redistribute]]` pipes: BGP routes re-originate as OSPF AS-externals and back |
| `mrt.sh` | BIRD `protocol mrt` to `lr mrt rib`, and lr-daemon to `lr mrt rib` | RFC 6396: BIRD's dump decodes (peer table plus prefixes), and the daemon's Loc-RIB export round-trips AS path and next hop |

## Session hygiene, policy and kernel interaction

| Script | Peers | What it proves |
| --- | --- | --- |
| `bgp_collision_backoff.sh` | lr-daemon against a fake speaker answering RFC 4486 subcode 7 | §6.8 collision loss is a backoff signal: the connector waits out the peer's hold window instead of redialing on every TCP connect |
| `bgp_collision_zombie.sh` | restarted lr-daemon against a peer holding a live session to the dead instance | §6.8 zombie resolution: fresh dials bounce off the peer's Established-protection rule and the daemon backs off |
| `bgp_shutdown_cleanup.sh` | lr-daemon under SIGINT | Cease is sent and every installed route withdrawn, leaving the host FIB as it was found |
| `bgp_blackhole_own_ip.sh` | lr-daemon with a static blackhole for its own listener IP, BIRD as peer | the kernel-mirror skip: the blackhole never shadows local delivery, so the session establishes |
| `rfc8212_bird.sh` | lr-daemon and BIRD 2 | RFC 8212 §3 default deny-in/deny-out for a policy-less eBGP peer, and the explicit-policy escape hatch |
| `rfc8212_frr.sh` | lr-daemon and FRR bgpd | the same against FRR |
| `md5.sh` | lr to lr, lr to BIRD 2, lr to FRR | RFC 2385: the right key establishes with all three stacks and a wrong key does not |
| `tcp_ao.sh` | two lr-daemons | RFC 5925 TCP-AO: a matching key chain establishes, and the same KeyID with a different secret fails closed |
| `bfd_bird.sh` | lr-daemon and BIRD over a veth pair, one netns each | RFC 5880: both sessions reach Up, BGP rides `bfd on`, and a frozen peer (SIGSTOP, TCP still open) is torn down by BFD rather than by the 60 s hold timer |

## Babel

| Script | Peers | What it proves |
| --- | --- | --- |
| `babel_auth.sh` | two lr babel speakers in one netns | RFC 8967 MAC and PC transport auth: the same key establishes, a restart re-keys with a fresh Index, a wrong key is rejected |
| `babel_dualstack_bird.sh` | lr and BIRD across two user namespaces | the production dual-stack shape: v4 and v6 routes over one link with BIRD as peer |
| `babel_multihop.sh` | three speakers in three namespaces | multi-session transit: routes transit the middle speaker, the dead segment's routes withdraw end to end (§3.5.5 retraction plus check link), the link returning reconverges |
| `babel_manual_check_link.sh` | two manual-path lr speakers in two namespaces | issue #39: the manual single-socket path polls its own interface carrier (BIRD `check link` parity) — a carrier loss withdraws the learned route within 3 s, not the 30 s §3.2.5 hold floor; reconvergence on carrier return |
| `babel_infeasible_no_displace.sh` | lr speakers over a tunnel shape | regression: an infeasible update never displaces a feasible route |
| `babel_reinstall_churn.sh` | two lr speakers | regression: a byte-identical re-install does not re-emit `RouteInstalled` or re-touch the kernel mirror |
| `babel_withdraw_reason.sh` | lr and BIRD | a wildcard retraction (§4.6.9) logs its real reason instead of the best-path-displacement fallback |
| `babel_multi_nic.sh` | lr with `[[babel.interface]]` globs on a veth pair | interface enumeration and glob matching resolve each block to the right socket |
| `babel_router_id_e2e.sh` | two lr speakers with configured `--router-id` | the configured router id rides the wire as the 8-byte Router-Id TLV |
| `babel_v6only_extended.sh` | lr over a v6-only tunnel | RFC 9229 extended next hop: v4 routes ride the v6 transport, inferred and explicit, and v4 blackhole statics survive |

## OSPFv2 (RFC 2328) and Segment Routing (RFC 8665)

| Script | Peers | What it proves |
| --- | --- | --- |
| `ospf.sh` | two lr-daemons over raw sockets | daemon mode end to end: Hello exchange, DBD and LSR loading to Full, Router-LSA origination and flooding, stub-net routes in both directions, dead-timer teardown |
| `ospf_bird.sh` | lr-daemon and BIRD 2, ptp over a veth pair | wire compatibility with BIRD's OSPF: master/slave negotiation, LSR loading to Full on both sides, stub nets propagated both ways |
| `ospf_frr.sh` | lr-daemon and FRR ospfd, ptp over a veth pair | the same against ospfd, with dead-timer teardown observed there |
| `ospf_broadcast.sh` | two lr-daemons, `network_type = "broadcast"` | §9.4 election (higher router id wins DR), §10.4 DR-to-BDR adjacency, the Network-LSA and the network-referenced intra-area prefix set |
| `ospf_gr.sh` | two lr-daemons, one restarting gracefully | RFC 3623 planned restart: Grace-LSA flood, helper retention across the dead interval, re-sync, Grace-LSA flush, and the grace-timeout teardown |
| `ospf_gr_bird.sh` | restarting lr-daemon and a BIRD 2 helper | lr's Grace-LSA engages BIRD's helper mode and BIRD retains the route through the whole restart window |
| `ospf_sr.sh` | two lr-daemons, both `sr_receive` | RFC 8665 reception: Router Information and Extended Prefix opaque LSAs populate the per-node SRDB, and the Loc-RIB resolves the peer's prefix-SID to a label |
| `ospf_sr_adj.sh` | two lr-daemons with `adj_sid` and a mapping server | Extended Link opaque LSAs populate the SRDB with the peer's adjacency segment, and the mapping-server range resolves |
| `ospf_sr_frr.sh` | lr-daemon and FRR ospfd with `capability opaque` | origination to FRR (its LSDB holds lr's Router Information and Extended Prefix LSAs), FRR-originated prefix-SIDs mapped back into lr's Loc-RIB, and lr's Extended Link LSA decoded by FRR |

## OSPFv3 (RFC 5340)

| Script | Peers | What it proves |
| --- | --- | --- |
| `ospf6.sh` | two lr-daemons over raw IPv6 multicast | v3 daemon mode: Hello, DBD and LSR exchange to Full, Router, Link and Intra-Area-Prefix LSAs, IPv6 routes both ways with link-local next hops |
| `ospf6_frr.sh` | lr-daemon and FRR ospf6d, ptp | FRR parses lr's v3 wire shapes (16-byte header, 16-bit dead interval, interface-ID semantics) to Full, and lr learns FRR's prefix over a link-local |
| `ospf6_broadcast.sh` | two lr-daemons, v3 broadcast | §4.1.2 with the §9.4 election on router-id identity: the DR originates the Network-LSA and the network-referenced prefix LSA, and transit links replace p2p descriptions |
| `ospf6_frr_broadcast.sh` | lr-daemon and FRR ospf6d on its default broadcast type | both run the election independently, agree on the elected pair, then exchange the broadcast LSA set |
| `ospf6_e_lsa.sh` | two lr-daemons with `extended_lsas = true` | RFC 8362: both daemons originate only the E-Router, E-Link and E-Intra-Area-Prefix forms, so convergence proves the E-LSA exchange and extended-mode SPF |
| `ospf6_e_lsa_endx.sh` | lr-daemon with a locator and `srv6_end_x`, and a plain legacy peer | RFC 9513 §9.1: the sparse-mode companion E-Router-LSA breaks nothing and the peer projects the End.X SID through its srv6db |
| `ospf6_e_lsa_endx_lan.sh` | three lr-daemons on one bridge broadcast segment | RFC 9513 §9.2: the election lands DR, BDR and DR-Other, all adjacencies reach Full, and the LAN End.X SID set projects |
| `ospf6_gr.sh` | two lr-daemons, one restarting gracefully | RFC 5187 planned restart: Grace-LSA flood, helper entry, dead-interval retention, and §2.2 adjacency re-establishment |
| `ospf6_gr_frr.sh` | restarting lr-daemon and an FRR ospf6d helper | ospf6d enters helper mode on lr's Grace-LSAs, retains the adjacency and route across the dead interval, and exits on lr's flush |
| `ospf6_frr_srv6.sh` | lr originator, FRR ospf6d relay, lr receiver | RFC 9513 through a daemon with no SRv6 of its own: ospf6d stores and re-floods lr's Router Information and Locator LSAs, and the far end projects the SIDs |

## Compatibility surface and route policy

| Script | Peers | What it proves |
| --- | --- | --- |
| `compat_bird.sh` | lr-daemon loaded from a native `bird.conf`, and BIRD itself | the BIRD compat layer: lr consumes BIRD's configuration directly and peers with BIRD |
| `compat_frr.sh` | lr-daemon loaded from a native `frr.conf`, and FRR bgpd | the FRR compat layer, same shape; see [`COMPAT.md`](COMPAT.md) |
| `filter_dsl_bird.sh` | lr-daemon with `[[filter]]` tables and BIRD | BIRD-shaped filter bodies (prefix-set membership, arithmetic, attribute assignment, if/then/else) evaluate against real BIRD-advertised routes |
| `damping_frr.sh` | lr `[damping]` and FRR bgpd as the flap generator | RFC 2439: FRR-driven flaps suppress at the threshold, decay reactivates, and a post-reuse flap re-installs (BIRD ships no RFD, so FRR is the reference) |

## LDP, RPKI-RTR and YANG

| Script | Peers | What it proves |
| --- | --- | --- |
| `ldp.sh` | two lr LSRs in namespaces, multicast discovery | LDP end to end: Hello discovery, TCP 646 session, label bindings, and the kernel dataplane phase |
| `ldp_frr.sh` | lr-daemon and FRR zebra plus ldpd | RFC 5036 wire compatibility with ldpd over a veth pair |
| `ldp_frr_v6.sh` | lr-daemon and FRR zebra plus ldpd, both address families | RFC 7552: the session runs over the IPv6 transport, IPv4 bindings exchange both ways, and the IPv6 FEC is learned from FRR's address family |
| `rtr_bird.sh` | BIRD's RPKI client and lr's mock RTR cache | RFC 8210 codec interop: BIRD's Reset and Serial Query decode through `lr_bgp::rtr` and BIRD installs the served ROAs |
| `rtr_lr.sh` | lr-daemon `[bgp.rpki]` client and lr's mock RTR cache | the daemon client end to end: sync, delta application, expiry withdrawal while disconnected, and `SIGHUP` re-point |
| `yang.sh` | `lr-daemon yang render` and yanglint | the shipped `yang/` modules parse with imports resolved and the RFC 9647 instance data validates as config |

## Shared helpers

`_lib.sh` (rootless namespace and veth topology harness) and
`_lr_daemon.sh` (daemon build, spawn and log capture) are infrastructure
the labs source; they are not labs and have no row. A new shared helper
must be added to this note, because the guard checks that every file in
`tests/interop/` is mentioned somewhere on this page.

## Extension notes from running the labs

Each of these was pinned down by a lab, usually after a defect; they are
the reason the code has the shape it has.

- **MP-BGP is mandatory in practice.** BIRD refuses a session that does
  not announce Multiprotocol Extensions for a matching family, so the
  daemon advertises IPv4 unicast by default.
- **The ENH capability value is 6 bytes per tuple.** RFC 5549 §4 and
  RFC 8950 §4 define repeated `<AFI:2, SAFI:2, NH-AFI:2>`; BIRD and FRR
  both reject a value whose length is not a multiple of six, so the
  5-byte form is not an option.
- **A wildcard Babel retraction must set the withdraw reason.** Without
  it the log falls back to a best-path displacement that never happened.
- **BFD has two state-machine fast paths that are easy to get wrong.**
  RFC 5880 §6.8.6 maps Down-plus-Init and Init-plus-Init straight to Up;
  mapping either to Init deadlocks two Active peers in Init. The
  detection time is the peer's multiplier times the negotiated interval,
  and the single-hop TTL filter (RFC 5881 §5) accepts exactly 255.
- **A next hop equal to the peer address is not always exported.** BIRD
  will not export one, and FRR treats a loopback next hop as martian, so
  the labs advertise RFC 5737 documentation addresses.
- **FRR's vty port range is contended.** Every FRR daemon owns a
  well-known port near 2600 and a packaged install starts some of them,
  so a squatted vty port silently makes bgpd skip its own listener. The
  labs therefore take a port outside that range and verify the prompt
  belongs to the instance they started.

## Extending the suite

Add a reference daemon by following the existing pattern:

1. Write a generator for its config: a unique AS number, high ports, a
   static export prefix.
2. Start it with output redirected under `/tmp/lr_<name>_interop/`.
3. Poll its own table (CLI socket, vty, HTTP API — whatever it exposes)
   for `203.0.113.0/24`, and the daemon's log for `198.51.100.0/24`.
4. Print both logs and explicit `PASS`/`FAIL` lines; exit non-zero on
   failure and zero on skip.
5. Add the row to the matching table above.
