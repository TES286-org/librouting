# Interoperability Testing Guide

librouting is verified against real-world routing stacks, not just against
itself. Three layers of interop testing run in CI (`.github/workflows/ci.yml`,
job `interop`) and can all be reproduced locally:

| Test            | Script                        | Peers                                                                    | What it proves                                                                                                                                                                                                                                                   |
| --------------- | ----------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Two-daemon      | `tests/interop/two_daemon.sh` | lr-daemon ↔ lr-daemon over real TCP                                      | FSM + codec consistency in both roles, route propagation + session-loss withdrawal; portable (Linux, macOS, Windows/Git-Bash) — the macOS/Windows interop CI jobs run it natively |
| BGP kernel-install | `tests/interop/bgp_kernel_install.sh` | lr-daemon ↔ lr-daemon, `--install-kernel-routes` | The learn → install → decide → forward → teardown contract on the **real OS FIB**: Loc-RIB convergence, kernel route install (`proto bgp` on Linux), the OS lookup picking the BGP gateway (`ip route get` / `route -n get` / `Find-NetRoute`), ICMP delivery through the installed route, and peer-death withdrawal from the FIB. Linux netns form runs all five steps rootlessly; the macOS loopback form (sudo + BSD route(4) backend) and the Windows loopback form (admin + IP-Helper backend) run steps 1-3 + 5 against their native route-table backends |
| BGP transit     | `tests/interop/bgp_transit.sh` | r1 ↔ r2 (transit, `[[peer]]` multi-peer config) ↔ r3 over two veth pairs | Three-router re-advertisement: the edge route transits r2 into r3's Loc-RIB **and** kernel FIB with r2's egress as next hop, the far-edge lookup uses it, and the announcer's death withdraws it through r2. The ip_forward transit-forwarding phase runs as root in the QEMU VM harness (nightly) |
| OSPF two-daemon | `tests/interop/ospf.sh`       | lr-daemon ↔ lr-daemon over real raw sockets (multicast 224.0.0.5)        | OSPF daemon mode end-to-end: Hello exchange, real DBD/LSR exchange to Full adjacency, Router-LSA origination + flooding, stub-net route propagation **in both directions**, dead-timer teardown                                                                  |
| OSPF x BIRD     | `tests/interop/ospf_bird.sh`  | lr-daemon ↔ BIRD 2 (ospf v2, ptp) over a veth pair                       | Wire compatibility with BIRD's OSPF: DBD master/slave negotiation, header exchange, LSR loading to **Full on both sides**, stub nets propagated in both directions (birdc-verified)                                                                              |
| OSPF x FRR      | `tests/interop/ospf_frr.sh`   | lr-daemon ↔ FRR 10 (zebra + ospfd, ptp) over a veth pair                 | Wire compatibility with FRR's OSPF: DBD master/slave negotiation, LSR loading to **Full on both sides**, stub nets propagated in both directions (vty-verified), dead-timer teardown observed by ospfd                                                            |
| OSPF graceful restart (RFC 3623) | `tests/interop/ospf_gr.sh` | two lr-daemons over a veth pair | Planned restart cycle: Grace-LSA flood on shutdown, helper retention across the peer's dead interval, recovery + re-sync + Grace-LSA flush, and the grace-timeout teardown with route withdrawal |
| OSPF graceful restart x BIRD helper (RFC 3623) | `tests/interop/ospf_gr_bird.sh` | lr-daemon restarts × BIRD 2 helper over a veth pair (CI: jammy's 2.0.8; also verified against 2.17.x locally) | lr's Grace-LSA engages BIRD's helper mode ("started/finished graceful restart" in BIRD's log), BIRD retains 10.99.2.0/24 through the whole restart window — the graceful-shutdown flood services the protocol between rounds (ACKs the helper's in-flight LSA refreshes, keeps Hellos flowing), which a BIRD 2.0.8 helper's RFC 3623 §3.1 (2) check requires |
| OSPF Segment Routing (RFC 8665, slice 1) | `tests/interop/ospf_sr_frr.sh` | lr-daemon (SRGB 16000/8000, prefix-SID 10.99.2.0/24=100) ↔ FRR 10 (zebra + ospfd, `capability opaque`) over a veth pair | lr's Router Information LSA + Extended Prefix Opaque LSA flood to and are stored by FRR (Opaque-Type/Id 4.0.0.0 + 7.0.0.1 in its LSDB); FRR's SRDB label-mapping assertion is kernel-MPLS-gated (FRR reserves the SRGB through zebra's label manager), same gate as mpls_lsp.sh phase 2 |
| OSPF Segment Routing reception (RFC 8665, slice 2) | `tests/interop/ospf_sr.sh` | two lr-daemons (both `sr_receive`, SRGB 16000/8000, no-php prefix-SIDs 10.99.2.0/24=100 and 10.99.3.0/24=300) over raw multicast | the receiver half end-to-end: RI + Extended Prefix opaque LSAs flood and populate the per-node SRDB, and each router's Loc-RIB resolves the peer's prefix-SID into `label=16100`/`label=16300` via the originator's address (RFC 2328 §16.1.1 next hops + the §5 PHP rule; the adjacent no-php originator still pushes). Needs no kernel MPLS — labels assert through the runtime API |
| OSPF SR x FRR reception (RFC 8665 slice 2) | `tests/interop/ospf_sr_frr.sh` phase 2 | same lab, FRR originates (`segment-routing on` + `global-block 16000 8000` + `prefix 10.99.3.0/24 index 200 no-php-flag`) | lr maps FRR's prefix-SID to `label=16200` in its Loc-RIB and — with `--install-kernel-routes` — the kernel FIB carries the RFC 8660 `encap mpls` route; entirely kernel-MPLS-gated (same gate as the SRDB phase) |
| OSPF SR adjacency + mapping server (RFC 8665 slice 3) | `tests/interop/ospf_sr_adj.sh` | two lr-daemons (SRGB 16000/8000, `adj_sid` 24000/24001 on the interfaces, r1 doubling as SR Mapping Server for `10.77.0.0/24 +3` and a precedence probe on r2's own prefix) over raw multicast | Extended Link opaque LSAs (Opaque-Type/Id 8.0.0.*) flood and populate the SRDB — both `status` views show the peer's adjacency segment (`ospf-sr adj … label=24001/24000`); the mapping-server ranges resolve into Loc-RIB labels `16500`/`16501` (base + index offset per RFC 8665 §4); a direct Prefix-SID beats the server's mapping for the same prefix (RFC 8661 §3.2.3); r1's own advertisement is withdrawn when the neighbour dies (§7.4.1) |
| OSPF SR adjacency x FRR (RFC 8665 slice 3) | `tests/interop/ospf_sr_frr.sh` phase 3 | same lab, lr advertises `adj_sid = 24000` on veth0 | FRR's LSDB holds lr's Extended Link LSA (Opaque-Type/Id 8.0.0.*) and decodes the Adj-SID sub-TLV (label 24000, V/L flags, length-7 shape — verified in the `show ip ospf database opaque-area 8.0.0.*` dump); FRR's SRDB adjacency entry + lr learning FRR's own SRLB-allocated Adj-SID are kernel-MPLS-gated |
| OSPFv3 two-daemon (RFC 5340) | `tests/interop/ospf6.sh` | two lr-daemons (`--ospf-version 3`) over raw IPv6 multicast (ff02::5) | OSPFv3 daemon mode end-to-end: v3 Hello/DBD/LSR exchange to Full, Router/Link/Intra-Area-Prefix LSAs, IPv6 route propagation **both directions** (proto=Ospfv3, link-local next hops), dead-timer withdrawal |
| OSPFv3 Extended LSAs (RFC 8362) | `tests/interop/ospf6_e_lsa.sh` | two lr-daemons with `[ospf] extended_lsas = true` | the full Extended-LSA mode end to end: both daemons originate ONLY the E-Router (0xA021)/E-Link (0x8028)/E-Intra-Area-Prefix (0xA029) forms, so adjacency + route convergence + link-local next hops + MaxAge withdrawal prove the E-LSA exchange and the extended-mode SPF |
| OSPFv3 SRv6 End.X (RFC 9513 §9.1 over RFC 8362) | `tests/interop/ospf6_e_lsa_endx.sh` | two lr-daemons: r1 with `[[ospf.srv6_locator]]` + `[[ospf.interface]] srv6_end_x` (sparse mode), r2 plain legacy | End.X SID origination + reception: the sparse-mode companion E-Router-LSA breaks nothing (Full adjacency, legacy routes still converge), r2 projects r1's End.X SID through the srv6db (`status` `srv6-endx` lines, behavior=5, neighbor recorded) and r1 self-projects |
| OSPFv3 SRv6 LAN End.X (RFC 9513 §9.2 over RFC 8362) | `tests/interop/ospf6_e_lsa_endx_lan.sh` | three lr-daemons on one bridge broadcast segment (`extended_lsas = true`): r1 (DR-Other) with `srv6_end_x` + `srv6_end_x_lan`, r2 (BDR) and r3 (DR) plain | the broadcast adjacency-SID set: the §9.4 election lands r3/r2/r1 as DR/BDR/DR-Other, all six adjacencies reach Full over unicast DD/LSR, routes converge through the E-Network vertex, r3 projects r1's plain §9.1 End.X (DR adjacency, no `lan` marker), r2 projects the derived §9.2 LAN End.X `base \| Router-ID` (with the `lan` marker) and r1 self-projects both |
| OSPFv3 x FRR ospf6d (RFC 5340) | `tests/interop/ospf6_frr.sh` | lr-daemon ↔ FRR 10 (zebra + ospf6d, ptp) over a veth pair | FRR parses lr's v3 wire shapes (16-byte header, 16-bit dead interval, Interface-ID semantics) to Full; lr learns FRR's prefix over a link-local; ospf6d learns lr's prefix and drops the neighbor on the dead timer |
| OSPFv3 graceful restart (RFC 5187) | `tests/interop/ospf6_gr.sh` | two lr-daemons (`--ospf-version 3`) over a veth pair; one restarts gracefully | the planned-restart cycle: Grace-LSA flood (LS type 0x000b, LS ID = the Interface ID) → helper entry → dead-interval retention → recovery (re-sync through the helper, §2.2 adjacency re-establishment) → flush exit (§3.2 (1)); then the grace-period timeout path (helper exit, teardown, withdrawal) |
| OSPFv3 GR x FRR ospf6d helper (RFC 5187) | `tests/interop/ospf6_gr_frr.sh` | lr-daemon (restarting router) ↔ FRR 10 ospf6d (`graceful-restart helper enable`, ptp) over a veth pair | FRR enters helper mode on lr's 0x000b Grace-LSAs (`activeRestarterCnt: 1`), retains lr's adjacency + route across the dead interval, and exits on lr's post-recovery flush (`lastExitReason: "Successful graceful restart"`) — lr's recovery re-syncs its LSDB from the live helper |
| OSPFv3 SRv6 (RFC 9513 slice 3) | `tests/interop/ospf6_frr_srv6.sh` | 3-node lab: lr1 (SRv6 originator, `[[ospf.srv6_locator]]`) ↔ FRR 10 ospf6d ↔ lr2 (`srv6_receive`) over two veth pairs | the unknown-LSA transparency gate: ospf6d has no SRv6, yet it stores and re-floods lr1's Router-Information (0xA00C) + Locator (0xA02A) LSAs (all 5 of lr1's LSAs in its LSDB); lr2 installs lr1's locator 2001:db8:a:1::/64 as an Ospfv3 route with a link-local next hop **through the FRR relay** — RFC 9513 §5 route computation over a foreign relay |
| MRT             | `tests/interop/mrt.sh`        | BIRD 2 `protocol mrt` → `lr mrt rib`; lr-daemon → `lr mrt rib`           | RFC 6396 compatibility: BIRD's dump decoded (peer table + prefixes); the daemon's Loc-RIB export round-trips with AS path + next hop                                                                                                                             |
| Wire parity     | `tests/interop/parity.sh`     | lr-daemon → BIRD 2 through a recording proxy (`tests/parity/capture_proxy.py`) | W5.3: the captured lr→BIRD UPDATE stream replayed into an offline router reproduces BIRD's own `protocol mrt` view of the learned routes exactly (`lr parity-replay` + `lr mrt diff` → IDENTICAL)                                                                |
| BMP             | `tests/interop/bmp.sh`        | lr-daemon `--bmp-target` → lr-daemon `--protocol bmp` collector          | BMP end-to-end: station connect, Peer Up ordering, Route Monitoring carrying the full UPDATE, collector serving routes + MRT dump via the runtime API                                                                                                            |
| BIRD            | `tests/interop/bird.sh`       | lr-daemon ↔ BIRD 2 (eBGP, multihop)                                      | Wire compatibility with BIRD: OPEN/capability negotiation, UPDATE encoding, route exchange **in both directions**                                                                                                                                                |
| BIRD LLGR       | `tests/interop/bird_llgr.sh`  | lr-daemon ↔ BIRD 2 (RFC 9494)                                            | Full Long-Lived Graceful Restart lifecycle in **both helper roles**: capability negotiation, retention, `LLGR_STALE` marking and stale-time expiry purge                                                                                                         |
| BFD x BIRD      | `tests/interop/bfd_bird.sh`   | lr-daemon ↔ BIRD 2 (`protocol bfd` + `bfd on`) over a veth pair in netns | BFD wire compatibility (RFC 5880): both sessions reach Up, BGP rides `bfd on`, and a frozen peer (SIGSTOP — TCP still open) is torn down in ~0.5s by BFD at 100ms×3 vs a 60s hold timer; phase 2 proves RFC 5883 multihop mode (UDP 4784, off-link address pair) |
| FRR             | `tests/interop/frr.sh`        | lr-daemon ↔ FRR bgpd (eBGP, multihop)                                    | Wire compatibility with FRR bgpd incl. its stricter next-hop validation                                                                                                                                                                                          |
| LDP x FRR dual-stack | `tests/interop/ldp_frr_v6.sh` | lr-daemon ↔ FRR 10 (zebra + ldpd, ipv4 + ipv6 AFs) over a veth pair   | RFC 7552: session established over the IPv6 transport (TR=6 both sides), IPv4 bindings exchanged both ways (imp-null ↔ 24000), IPv6 FEC learned from FRR's ipv6 address-family; proves the LDPoIPv6 GTSM hop-limit-255 session transport against a real implementation |
| Exchange plane  | `tests/interop/exchange_plane.sh` | lr-daemon (`--exchange-plane`) ↔ BIRD 2 (plain)                      | W6.3 fallback gate: the plane-enabled daemon peers with a non-lr speaker unchanged — the capability stays inert (RFC 5492 §3), routes flow both directions, and no records surface. Needs the `exchange-plane` feature build (or skips)                          |

> **RFC 8212 note.** The daemon's default eBGP route behavior is
> deny-in/deny-out for peers without explicit import/export route-maps
> (`[bgp] ebgp_policy = "rfc8212"`). These scripts test protocol
> behavior (FSM, wire format, GR, auth, BFD — not policy), so their
> lr sides pin `--ebgp-policy accept-all` to keep the tested feature
> isolated; the RFC 8212 behavior itself is covered end-to-end by
> `crates/lr-cli/tests/daemon_rfc8212.rs`.

## What the tests actually verify

For every peer pair, all of the following must hold:

1. **Session establishment** — TCP connect, OPEN exchange, capability
   negotiation (MP-BGP for IPv4 unicast, 4-octet AS), KEEPALIVE cadence
   within the negotiated hold time.
2. **lr → peer propagation** — a locally originated prefix
   (`203.0.113.0/24`) appears in the _peer's_ table:
   `birdc show route` / bgpd's `show ip bgp`.
3. **peer → lr propagation** — a prefix originated by the peer
   (`198.51.100.0/24`, static in BIRD / `network` statement in FRR)
   shows up in lr-daemon's Loc-RIB log with the correct next hop.
4. **Route refresh** — an RFC 2918 ROUTE-REFRESH request triggers a fresh
   family-scoped table dump that is evaluated through the current export policy.
5. **Clean teardown** — End-of-RIB markers are sent after the initial
   dump; no protocol error logs on either side.

The RTR suite is separate (no BGP session involved):

* `rtr_bird.sh` — BIRD 2's RPKI client as the transport consumer: it
  connects to librouting's mock cache (`lr-bgp` `rtr_cache_mock`
  example), sends its Reset Query, downgrades to the negotiated
  version (RFC 8210 §7) and installs the two served ROAs into its
  `roa4` / `roa6` tables (birdc-verified).
* `rtr_lr.sh` — librouting's own daemon as the RTR client: `lr-daemon`
  with `[bgp.rpki]` connects to the same mock cache, the runtime API
  `status` line reports the live store (`roas=3 (static=1 rtr=2)`,
  session/serial from the cache's End of Data), and the daemon's
  reconnect path is exercised by killing the cache mid-run.

## Running locally

```bash
cargo build -p lr-cli                       # builds target/debug/lr-daemon
./tests/interop/two_daemon.sh               # no external dependencies
./tests/interop/bgp_kernel_install.sh       # needs iproute2 + user namespaces (Linux); sudo (macOS); admin shell (Windows)
./tests/interop/bgp_transit.sh              # needs iproute2 + user namespaces; the transit-forward phase needs root (VM harness)
./tests/interop/ospf.sh                     # needs iproute2 + user namespaces
./tests/interop/ospf_sr_frr.sh              # needs FRR (or skips) — RFC 8665 slice 1; SRDB + phase-2 reception kernel-MPLS-gated
./tests/interop/ospf_sr.sh                  # RFC 8665 slice 2 — SR reception, lr x lr (no kernel MPLS needed)
./tests/interop/ospf_sr_adj.sh              # RFC 8665 slice 3 — Adj-SIDs + mapping server, lr x lr (no kernel MPLS needed)
./tests/interop/ospf6.sh                    # RFC 5340 — OSPFv3 two-daemon, raw IPv6 multicast
./tests/interop/ospf6_e_lsa.sh              # RFC 8362 — Extended-LSA mode, two daemons
./tests/interop/ospf6_e_lsa_endx.sh         # RFC 9513 §9.1 End.X over RFC 8362, sparse mode
./tests/interop/ospf6_frr.sh                # needs FRR (or skips) — OSPFv3 x ospf6d, RFC 5340
./tests/interop/ospf6_gr.sh                 # RFC 5187 — OSPFv3 graceful restart, two daemons
./tests/interop/ospf6_gr_frr.sh             # needs FRR (or skips) — OSPFv3 GR x ospf6d helper
./tests/interop/ospf6_frr_srv6.sh           # needs FRR (or skips) — RFC 9513 SRv6 through an FRR relay
./tests/interop/mrt.sh                      # BIRD phase needs bird2 (or skips)
./tests/interop/bmp.sh                      # no external dependencies
./tests/interop/bird.sh                     # needs bird2 (or skips)
./tests/interop/compat_bird.sh              # needs bird2 (or skips) — compat surface: lr runs a BIRD config natively
./tests/interop/compat_frr.sh               # needs FRR bgpd (or skips) — compat surface: lr runs an FRR config natively
./tests/interop/bird_enh.sh                 # needs bird2 (or skips) — RFC 5549 ENH
./tests/interop/bfd_bird.sh                 # needs bird2 + user namespaces (or skips) — BFD RFC 5880/5881/5883
./tests/interop/exchange_plane.sh           # needs bird2 + the exchange-plane feature build (or skips)
./tests/interop/frr.sh                      # needs FRR bgpd (or skips)
./tests/interop/mpls_lsp.sh                 # needs iproute2 + user namespaces; dataplane phase needs the mpls_router module
```

The scripts auto-detect the reference daemons:

- If `bird`/`birdc`/`bgpd` are on `PATH` (CI installs them via apt), they
  are used directly.
- Otherwise a user-space extraction under `/home/z/opt/{bird,frr}` is
  used when present (see below).
- If neither is found the script prints `SKIP: ...` and exits 0, so the
  suite degrades gracefully on restricted runners.

### OSPF lab specifics

`ospf.sh` needs no reference daemon — it runs two lr-daemons — but
raw OSPF sockets require `CAP_NET_RAW`. The script builds a
completely rootless lab when unprivileged user namespaces are
available: `unshare -Urn` grants `CAP_NET_RAW` + `CAP_NET_ADMIN`, the
veth pair plus one network namespace per router is created inside
it, and each daemon runs via `nsenter` in its own namespace (the
two-router model — no loopback shortcuts). Environments that forbid
user namespaces SKIP gracefully. OSPF x BIRD interop runs the same
rootless lab shape (`ospf_bird.sh`): the DBD/LSR exchange (RFC 2328
§7.2) brings both sides to Full and routes flow in both directions.

### BMP lab specifics

`bmp.sh` is pure librouting — a BGP speaker with `--bmp-target`
mirrors into a `--protocol bmp` collector — but the reference-sender
variant (BIRD's `protocol bmp` connecting to our collector) cannot run
yet: Debian's bird2 package is built **without** the BMP protocol
(verified on 2.17.5 — the binary contains no BMP symbols). Revisit
when a BMP-enabled BIRD is packaged or built from source.

### Rootless operation

Both scripts deliberately avoid privileged ports:

- **BIRD** uses the per-protocol `local port 17992` (its own listener) and
  `neighbor 127.0.0.1 port 17993` (lr-daemon's listener). This syntax
  works on every BIRD 2.x from 2.0.8 to 2.17+.
- **bgpd** is started with `-p 17995` (BGP listen port), `-P 2615` (vty
  TCP port), `--vty_socket` (unix socket path), `-Z` (no zebra), `-n`
  (no kernel), `-S` (skip runas) — so it runs as any user.
- lr-daemon always listens on a high port and never installs kernel
  routes unless `--install-kernel-routes` is passed.

### User-space reference daemons (no root, no system install)

On a machine without sudo, Debian packages can be extracted to a prefix
and run from there:

```bash
apt-get download bird2 && dpkg-deb -x bird2_*.deb /tmp/birdroot
/tmp/birdroot/usr/sbin/bird --version

# FRR needs its library path:
apt-get download frr libyang3 librtr0 libjson-c5 ...   # or resolve via apt-cache
for f in *.deb; do dpkg-deb -x "$f" /tmp/frrroot; done
LD_LIBRARY_PATH=/tmp/frrroot/usr/lib/x86_64-linux-gnu/frr:/tmp/frrroot/usr/lib/x86_64-linux-gnu \
  /tmp/frrroot/usr/lib/frr/bgpd --version
```

`tests/interop/bird.sh` and `frr.sh` already look in
`/home/z/opt/{bird,frr}/root` for such extractions.

### Kernel-gated tests in a QEMU VM (no root, no suitable host kernel)

Three scripts additionally need kernel features: `tcp_ao.sh` (TCP-AO,
Linux >= 6.7), and the dataplane phases of `mpls_lsp.sh` / `ldp.sh`
(the `mpls_router` / `mpls_iptunnel` modules). When the host kernel
lacks them (or you cannot `modprobe`), `tests/vm/run_vm.sh` boots a
minimal initramfs QEMU VM — no disk image, no system installation —
where the three scripts run as real root against a kernel that has
everything enabled, and reports a single aggregate pass/fail:

```bash
# one-time: extract a kernel with TCP-AO + MPLS (Ubuntu 24.04's 6.8 works;
# Debian 13's 6.12 ships without TCP-AO)
mkdir -p /opt/lr-kernel
for d in linux-image-6.8.0-139-generic linux-modules-6.8.0-139-generic \
         linux-modules-extra-6.8.0-139-generic; do
    apt-get download "$d" && dpkg-deb -x "${d}"_*.deb /opt/lr-kernel/
done

LR_VM_KERNEL=/opt/lr-kernel tests/vm/run_vm.sh
```

See `tests/vm/README.md` for requirements and knobs. CI self-tests the
harness on `ubuntu-24.04` (nightly `vm-kernel-gated` job, which boots
the runner's own kernel; the job installs
`linux-modules-extra-$(uname -r)` first so the MPLS dataplane phases
actually run instead of SKIPping).

## Platform coverage of the learn → install → forward contract

The interop suite is not Linux-only anymore. CI verifies the
"routes learned, routes installable, data forwardable" contract on
every primary platform, each with the strongest check that platform
can honestly support:

| Platform | Job | LEARNED | INSTALLED | DECISION | FORWARD | TEARDOWN |
| -------- | --- | ------- | --------- | -------- | ------- | -------- |
| Linux (rootless netns) | `interop` | `bgp_kernel_install.sh` | `ip route show` (`proto bgp`) | `ip route get` | ICMP delivered via the route | `bgp_kernel_install.sh` phase 5 |
| Linux (root, QEMU VM) | nightly `vm-kernel-gated` | idem | idem | idem | idem **+ transit hop through an ip_forward router** (`bgp_transit.sh` phase 4) | idem |
| macOS (BSD route(4)) | `macos-interop` | `bgp_kernel_install.sh` (loopback) | `netstat -rn` | `route -n get` | — (single stack; proven on Linux + VM) | kernel-route absence after peer death |
| Windows (IP Helper) | `windows-interop` | `bgp_kernel_install.sh` (loopback) | `route.exe print -4` | `Find-NetRoute` | — (single stack; proven on Linux + VM) | idem |

The macOS and Windows rows are the first CI runs that execute the
`lr-osroute` BSD and IP-Helper backends end-to-end (previously they
were cross-compile-only). Their FORWARD cell is deliberately empty:
a single-host runner has one network stack, so a "via 127.0.0.x"
gateway cannot demonstrate transit forwarding — pretending otherwise
would test the loopback interface, not the FIB. The Linux netns +
QEMU VM rows cover that cell with real two-stack forwarding.

## Configuration used

### The BGP-LU → MPLS dataplane lab (`mpls_lsp.sh`)

Two rootless network namespaces joined by a veth pair, one daemon each:

- `r1` (LSP tail) originates `198.51.100.0/24` with label 100 and mirrors
  it to an `AF_MPLS` pop route (in-label 100 → `lo`, local delivery).
- `r2` (LSP head) receives the labelled route and mirrors it to an
  encap route (`198.51.100.0/24 encap mpls 100 via 10.99.1.1`).

With the kernel `mpls_router` module loaded (CI does `sudo modprobe`
before the lab starts; the per-netns `platform_labels`/`input` sysctls
are writable inside the user namespace), the script asserts the kernel
state on both sides and pushes a real ICMP echo through the LSP.
Without the module it degrades to the control-plane phase and SKIPs the
rest, like `tcp_ao.sh`.

### BIRD side (`bird.sh` generates this)

```
router id 10.0.0.2;
protocol static static_routes {
    ipv4;
    route 198.51.100.0/24 blackhole;
}
protocol bgp lr {
    local port 17992 as 64513;
    neighbor 127.0.0.1 port 17993 as 64512;
    multihop 2;
    ipv4 {
        import all;
        export filter export_to_lr;
        # BIRD refuses to export a next hop equal to the neighbor address
        # (both ends are 127.0.0.1 here), so pin a distinct one.
        next hop address 192.0.2.10;
    };
}
```

### FRR side (`frr.sh` generates this)

```
router bgp 64514
 bgp router-id 10.0.0.3
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor 127.0.0.1 remote-as 64512
 neighbor 127.0.0.1 port 17996
 neighbor 127.0.0.1 ebgp-multihop 2
 neighbor 127.0.0.1 route-map lr-out out
 address-family ipv4 unicast
  network 198.51.100.0/24
 exit-address-family
!
route-map lr-out permit 10
 set ip next-hop 192.0.2.20
```

### Why the synthetic next hops (192.0.2.x)

Both stacks apply next-hop sanity checks on loopback-only test beds:
BIRD refuses to _export_ a next hop equal to the neighbor address, and
FRR rejects loopback next hops as _martian_ on receipt. The scripts
therefore advertise RFC 5737 documentation addresses, which carry fine
over eBGP — the next hop is reachability _information_, it does not have
to be resolvable in the test environment for the control plane to
converge. In a production deployment the daemon's `--local-address`
should be the real interface address (which it is, by default, when
connecting over that interface).

### Compat-surface labs (`compat_bird.sh`, `compat_frr.sh`)

These run the W5.4 compat surface end to end against the real
reference daemons: `lr-daemon --config` loads a **BIRD-shaped** (or
FRR-shaped) configuration file directly — no conversion step — and the
session must establish with real BIRD 2 / bgpd, exchange routes in
both directions, apply the dialect defaults (the startup warning
`bird dialect defaults applied` / `frr dialect defaults applied` is
asserted) and honour an `lr:` comment directive (`api-socket`, whose
socket file must appear). The FRR lab reuses frr.sh's vty harness and
its martian-next-hop pinning (`update-source 192.0.2.1` on the lr
side, the `lr-out` route-map on the bgpd side). See `docs/COMPAT.md`
for the full compat surface documentation.

## Compatibility notes learned from these tests

These are real behaviours the interop suite pinned down; keep them in
mind when embedding librouting or extending the BGP code:

1. **MP-BGP capability is mandatory in practice.** BIRD refuses sessions
   that do not announce Multiprotocol Extensions for a matching family
   (`Required capability missing`). `SessionConfig::bgp` therefore
   advertises IPv4 unicast MP-BGP by default.
2. **Well-known attribute flag bits are validated.** LOCAL_PREF must be
   advertised as well-known discretionary (flags `0x40`), not optional —
   strict implementations drop such UPDATEs or reset the session.
   ORIGINATOR_ID and CLUSTER_LIST are optional non-transitive (`0x80`).
3. **AS4 must be negotiated, not assumed.** The FSM downgrades both
   encode and decode to 2-byte AS_PATH when the peer's OPEN lacks the
   4-octet-AS capability (RFC 6793 §4.2.2).
4. **End-of-RIB matters.** BIRD and FRR both log convergence markers;
   lr-daemon sends an empty UPDATE after its initial table dump
   (RFC 4724 §4).
5. **NOTIFICATION is fatal.** A peer-initiated NOTIFICATION (hold time
   expiry, ceasing, malformed UPDATE) must drive the FSM to Idle and
   purge that peer's Adj-RIB-In — otherwise stale routes survive a
   session reset.
6. **Route refresh is capability-gated.** `RouterInstance::request_route_refresh`
   sends a request only after both OPEN messages advertised RFC 2918. An
   inbound request replaces the peer's family-scoped Adj-RIB-Out entries with
   a fresh export-policy evaluation and finishes with End-of-RIB. When RFC
   7313 is also negotiated, the refreshed dump is bracketed by BoRR and EoRR
   ROUTE-REFRESH messages, which BIRD reports as `Enhanced refresh`.
7. **The RFC 5549 Extended Next-Hop capability uses 6-byte tuples.** RFC
   5549 §4 (and its successor RFC 8950 §4) encodes the capability value as
   repeated `<AFI:2, SAFI:2, NH-AFI:2>` tuples — the SAFI is two octets.
   BIRD 2.x writes the same bytes with a reserved zero byte between AFI and
   SAFI (wire-identical for every real SAFI) and FRR writes the literal
   16-bit SAFI; both reject any value whose length is not a multiple of 6
   with an OPEN error. librouting encodes and decodes exactly this form
   (`tests/interop/bird_enh.sh` verifies the full ENH session against
   BIRD). An earlier revision shipped a non-standard 5-byte tuple
   (`AFI:2, SAFI:1, NH-AFI:2`) and documented BIRD as the deviant — the
   skip note was wrong, the bug was local.
8. **BFD's state machine has two fast paths that are easy to get wrong.**
   RFC 5880 §6.8.6 maps Down+received-Init and Init+received-Init both
   straight to Up; mapping either to Init (an intuitive-looking
   simplification) deadlocks two Active peers in Init forever. The
   detection time is the _peer's_ detect multiplier × the negotiated
   interval — not min(local, peer) — and the single-hop TTL filter
   (RFC 5881 §5) must accept exactly 255, while multihop (RFC 5883)
   accepts anything on UDP 4784. BIRD drops Poll+Final set together
   and packets with a zero My Discriminator; the interop
   (`tests/interop/bfd_bird.sh`) pins all of this against
   `protocol bfd` + `bfd on`.

## Extending the suite

Add a new reference daemon by following the existing pattern:

1. Write a generator for its config (unique AS number, high ports,
   static export prefix).
2. Start it with output redirected under `/tmp/lr_<name>_interop/`.
3. Poll _its_ table (CLI socket, vty, HTTP API — whatever it exposes)
   for `203.0.113.0/24` and lr-daemon's log for `198.51.100.0/24`.
4. Print both logs and `PASS`/`FAIL` lines with distinct failure
   reasons; exit non-zero on failure, zero on skip.

Good next candidates: OpenBGPD (`bgpd` from OpenBSD, has a portable
build), GoBGP (`gobgpd` with YAML config), and Juniper's open-source
`bgpd` conformance harness.
