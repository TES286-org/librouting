# Interoperability Testing Guide

librouting is verified against real-world routing stacks, not just against
itself. Three layers of interop testing run in CI (`.github/workflows/ci.yml`,
job `interop`) and can all be reproduced locally:

| Test | Script | Peers | What it proves |
|------|--------|-------|----------------|
| Two-daemon | `tests/interop/two_daemon.sh` | lr-daemon ↔ lr-daemon over real TCP | FSM + codec consistency in both roles |
| OSPF two-daemon | `tests/interop/ospf.sh` | lr-daemon ↔ lr-daemon over real raw sockets (multicast 224.0.0.5) | OSPF daemon mode end-to-end: Hello exchange, real DBD/LSR exchange to Full adjacency, Router-LSA origination + flooding, stub-net route propagation **in both directions**, dead-timer teardown |
| OSPF x BIRD | `tests/interop/ospf_bird.sh` | lr-daemon ↔ BIRD 2 (ospf v2, ptp) over a veth pair | Wire compatibility with BIRD's OSPF: DBD master/slave negotiation, header exchange, LSR loading to **Full on both sides**, stub nets propagated in both directions (birdc-verified) |
| MRT | `tests/interop/mrt.sh` | BIRD 2 `protocol mrt` → `lr mrt rib`; lr-daemon → `lr mrt rib` | RFC 6396 compatibility: BIRD's dump decoded (peer table + prefixes); the daemon's Loc-RIB export round-trips with AS path + next hop |
| BMP | `tests/interop/bmp.sh` | lr-daemon `--bmp-target` → lr-daemon `--protocol bmp` collector | BMP end-to-end: station connect, Peer Up ordering, Route Monitoring carrying the full UPDATE, collector serving routes + MRT dump via the runtime API |
| BIRD | `tests/interop/bird.sh` | lr-daemon ↔ BIRD 2 (eBGP, multihop) | Wire compatibility with BIRD: OPEN/capability negotiation, UPDATE encoding, route exchange **in both directions** |
| BIRD LLGR | `tests/interop/bird_llgr.sh` | lr-daemon ↔ BIRD 2 (RFC 9494) | Full Long-Lived Graceful Restart lifecycle in **both helper roles**: capability negotiation, retention, `LLGR_STALE` marking and stale-time expiry purge |
| FRR | `tests/interop/frr.sh` | lr-daemon ↔ FRR bgpd (eBGP, multihop) | Wire compatibility with FRR bgpd incl. its stricter next-hop validation |

## What the tests actually verify

For every peer pair, all of the following must hold:

1. **Session establishment** — TCP connect, OPEN exchange, capability
   negotiation (MP-BGP for IPv4 unicast, 4-octet AS), KEEPALIVE cadence
   within the negotiated hold time.
2. **lr → peer propagation** — a locally originated prefix
   (`203.0.113.0/24`) appears in the *peer's* table:
   `birdc show route` / bgpd's `show ip bgp`.
3. **peer → lr propagation** — a prefix originated by the peer
   (`198.51.100.0/24`, static in BIRD / `network` statement in FRR)
   shows up in lr-daemon's Loc-RIB log with the correct next hop.
4. **Route refresh** — an RFC 2918 ROUTE-REFRESH request triggers a fresh
   family-scoped table dump that is evaluated through the current export policy.
5. **Clean teardown** — End-of-RIB markers are sent after the initial
   dump; no protocol error logs on either side.

## Running locally

```bash
cargo build -p lr-cli                       # builds target/debug/lr-daemon
./tests/interop/two_daemon.sh               # no external dependencies
./tests/interop/ospf.sh                     # needs iproute2 + user namespaces
./tests/interop/mrt.sh                      # BIRD phase needs bird2 (or skips)
./tests/interop/bmp.sh                      # no external dependencies
./tests/interop/bird.sh                     # needs bird2 (or skips)
./tests/interop/frr.sh                      # needs FRR bgpd (or skips)
```

The scripts auto-detect the reference daemons:

* If `bird`/`birdc`/`bgpd` are on `PATH` (CI installs them via apt), they
  are used directly.
* Otherwise a user-space extraction under `/home/z/opt/{bird,frr}` is
  used when present (see below).
* If neither is found the script prints `SKIP: ...` and exits 0, so the
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

* **BIRD** uses the per-protocol `local port 17992` (its own listener) and
  `neighbor 127.0.0.1 port 17993` (lr-daemon's listener). This syntax
  works on every BIRD 2.x from 2.0.8 to 2.17+.
* **bgpd** is started with `-p 17995` (BGP listen port), `-P 2615` (vty
  TCP port), `--vty_socket` (unix socket path), `-Z` (no zebra), `-n`
  (no kernel), `-S` (skip runas) — so it runs as any user.
* lr-daemon always listens on a high port and never installs kernel
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

## Configuration used

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
BIRD refuses to *export* a next hop equal to the neighbor address, and
FRR rejects loopback next hops as *martian* on receipt. The scripts
therefore advertise RFC 5737 documentation addresses, which carry fine
over eBGP — the next hop is reachability *information*, it does not have
to be resolvable in the test environment for the control plane to
converge. In a production deployment the daemon's `--local-address`
should be the real interface address (which it is, by default, when
connecting over that interface).

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

## Extending the suite

Add a new reference daemon by following the existing pattern:

1. Write a generator for its config (unique AS number, high ports,
   static export prefix).
2. Start it with output redirected under `/tmp/lr_<name>_interop/`.
3. Poll *its* table (CLI socket, vty, HTTP API — whatever it exposes)
   for `203.0.113.0/24` and lr-daemon's log for `198.51.100.0/24`.
4. Print both logs and `PASS`/`FAIL` lines with distinct failure
   reasons; exit non-zero on failure, zero on skip.

Good next candidates: OpenBGPD (`bgpd` from OpenBSD, has a portable
build), GoBGP (`gobgpd` with YAML config), and Juniper's open-source
`bgpd` conformance harness.
