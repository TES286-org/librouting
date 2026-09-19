# librouting

Platform-independent routing protocol library implemented in Rust. Provides
BGP (RFC 4271 and extensions), OSPFv2/v3 (RFC 2328/5340 and extensions),
Babel (RFC 8966 and extensions), LDP (RFC 5036 and extensions), and the
MPLS label codec (RFC 3032) — each with parsing, finite-state machine
interaction and route/label calculation. BFD (RFC 5880) drives fast peer
failure detection, route flap damping (RFC 2439) is available, and an OS
route-table reference implementation (Linux rtnetlink, BSD route(4),
Windows IP Helper) plus a Linux MPLS dataplane mirror are provided as
opt-in crates. The library is verified bidirectionally against BIRD 2 and
FRR 10 in CI on Linux, macOS (Intel + Apple Silicon) and Windows.

## Design

Three-layer API:

| Layer | Crate                                                                       | Purpose                                                     |
| ----- | --------------------------------------------------------------------------- | ----------------------------------------------------------- |
| 1     | `lr-core::codec` + per-protocol codec modules                               | Stateless wire codec                                        |
| 2     | `lr-bgp::fsm`, `lr-ospf::neighbor`, `lr-babel::neighbor`, `lr-bfd::session` | Peer FSM + transport abstraction                            |
| 3     | `lr-router::instance`                                                       | High-level router instance tying sessions, RIB and policies |

The four-tier RIB model (Adj-RIB-In, Adj-RIB-Out, Loc-RIB, with cross-protocol
merging via admin distance) is captured in `lr-rib`. Policy framework (route
maps, prefix lists, AS-path filters, community lists, hooks + safety net)
lives in `lr-policy`.

The full data plane is wired end-to-end: UPDATEs received by a BGP session
are extracted into routes, pass the safety net and import hooks, enter
Adj-RIB-In, win (or lose) the decision process, land in Loc-RIB, and are
re-advertised to other peers with the correct egress rules (AS prepend,
next-hop-self, LOCAL_PREF stripping/injection, iBGP split-horizon, RR
reflection with ORIGINATOR_ID/CLUSTER_LIST, OTC valley-free enforcement).
Withdrawals propagate back through the same pipeline. See
`docs/ARCHITECTURE.md` for the pipeline diagram.

C ABI bindings (`lr-ffi`) let Go, Python, C and C++ embedders call into the
library without depending on the Rust toolchain at runtime.

## Crates

| Crate        | Path                | Purpose                                                                                                                                                                                                                                                                                                                     |
| ------------ | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lr-core`    | `crates/lr-core`    | Shared foundation: types, codec traits, generic FSM, RIB traits, timers, wire utilities                                                                                                                                                                                                                                     |
| `lr-bgp`     | `crates/lr-bgp`     | BGP-4 codec, path attributes, peer FSM, capabilities, MP-BGP, AddPath, 4-byte ASN, iBGP/eBGP roles, Route Reflector (RFC 4456), Confederations (RFC 6793), Route Server (RFC 7947), OTC (RFC 9234), Extended Next-Hop (RFC 5549), RFC 8277 labelled unicast (BGP-LU), best-path with multipath (RFC 4271 §9.1.2 / RFC 4784) |
| `lr-ospf`    | `crates/lr-ospf`    | OSPFv2/v3 codec, LSAs, link-state DB, neighbor FSM, SPF, areas, auth                                                                                                                                                                                                                                                        |
| `lr-babel`   | `crates/lr-babel`   | Babel codec, TLVs, neighbor FSM, route table, source-specific routing, RFC 8967/9467 MAC authentication                                                                                                                                                                                                                     |
| `lr-rib`     | `crates/lr-rib`     | Adj-RIB-In, Adj-RIB-Out, Loc-RIB, route selection, cross-protocol merging                                                                                                                                                                                                                                                   |
| `lr-policy`  | `crates/lr-policy`  | Route maps, prefix lists, AS-path filters, community lists, import/export/selection hooks, safety net                                                                                                                                                                                                                       |
| `lr-router`  | `crates/lr-router`  | Layer-3 router instance, sessions, scheduler, event dispatch                                                                                                                                                                                                                                                                |
| `lr-bfd`     | `crates/lr-bfd`     | BFD Control packet codec (RFC 5880 §4), session FSM with negotiated timing + Poll/Final (§6.8), auth sections (§4.2-§4.4)                                                                                                                                                                                                   |
| `lr-mpls`    | `crates/lr-mpls`    | MPLS label + label-stack codec (RFC 3032): 4-octet wire form, 3-octet NLRI form (RFC 8277 §3.2), reserved-label constants                                                                                                                                                                                                   |
| `lr-ldp`     | `crates/lr-ldp`     | LDP codec + state machines (RFC 5036): PDU/TLV/message framing, §2.5.4 session FSM with negotiation, §3.5.2 discovery (link + targeted), per-peer label information base (DU), `LdpEngine` glue                                                                                                                              |
| `lr-osroute` | `crates/lr-osroute` | OS route integration + protocol transports: rtnetlink/route(4)/IPHelper, TCP MD5/TCP-AO (`tcp_auth`), GTSM (`gtsm`), BFD UDP (`bfd_transport`, RFC 5881/5883), OSPF raw sockets (`ospf_transport`), Linux AF_MPLS LSP install (`mpls_route`)                                                                                |
| `lr-mrt`     | `crates/lr-mrt`     | MRT dump format (RFC 6396): TABLE_DUMP_V2 read/write, BGP4MP decode                                                                                                                                                                                                                                                         |
| `lr-bmp`     | `crates/lr-bmp`     | BGP Monitoring Protocol (RFC 7854): BMP message codec + router sink                                                                                                                                                                                                                                                         |
| `lr-damping` | `crates/lr-damping` | Route flap damping (RFC 2439)                                                                                                                                                                                                                                                                                               |
| `lr-cli`     | `crates/lr-cli`     | `lr` CLI tool (decode/routes) + `lr-daemon` reference wiring                                                                                                                                                                                                                                                                |
| `lr-ffi`     | `crates/lr-ffi`     | C ABI bindings (cbindgen-generated header)                                                                                                                                                                                                                                                                                  |
| `lr-tests`   | `crates/lr-tests`   | Cross-crate integration tests                                                                                                                                                                                                                                                                                               |

## The daemon

`lr-daemon` is a complete reference embedder: TCP transport (connect or
listen), poll-driven router, ticker thread, reconnect with backoff, RFC
4724 graceful restart and RFC 9494 long-lived graceful restart
(`--graceful-restart SECS`, `--llgr SECS`), RFC 2385 MD5 / RFC 5925
TCP-AO session authentication (`--md5-key SECRET`, `--tcp-ao-key
ID:SECRET`), and optional kernel route installation via rtnetlink.

Migrating from BIRD 2 or FRR? Point `lr-daemon` at your existing
configuration file directly — `lr-daemon --config bird.conf` or
`lr-daemon --config frr.conf` — and it runs in the compatible form
(the source implementation's defaults apply, and lr-specific extras
ride in as `lr:` comment directives; see [docs/COMPAT.md](docs/COMPAT.md)).
Prefer a reviewable conversion? `lr-daemon translate bird|frr <config>`
converts the same BGP configuration into lr daemon TOML — peers, auth,
ports, policies and originated prefixes map over; anything without an
lr equivalent is kept as an explicit `# UNMAPPED:` comment for review
instead of being dropped silently.

```bash
# Terminal 1 — speaker A (listens, originates a prefix)
lr-daemon --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
          --listen 127.0.0.1:1179 --local-address 192.0.2.1 \
          --network 203.0.113.0/24

# Terminal 2 — speaker B (connects, receives the route)
lr-daemon --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
          --peer 127.0.0.1:1179 --local-address 192.0.2.2
# → daemon: session #1 → Established
# → daemon: route installed 203.0.113.0/24 via 192.0.2.1
```

**Multi-peer.** The daemon runs any number of BGP sessions at once.
`--peer` is repeatable (all such peers share `--peer-as`); full
per-peer configuration uses `peer` blocks in the native `.lr` config
(see `templates/daemon.lr`): per-peer AS, hold time, graceful
restart, auth, GTSM, maximum-prefix, Add-Path, MP families and
next-hop source, each inheriting the `bgp` block globals when
omitted. Reusable defaults live in `peer-template` blocks that peers
pull in via `extends "name"` (per-peer keys override template
keys; chains supported). Outbound peers get one connector thread each
(independent reconnect backoff); the listener accepts concurrent
inbound sessions and matches them to configured peers by source
address (`address` key), rejecting connections that match none. Event consumption (logging, kernel route
installation) is centralised on the ticker thread, preserving Loc-RIB
ordering across sessions.

```lr
bgp {
    local_as 64512;
    router_id "10.0.0.1";
    local_address "192.0.2.1";
    listen_addr "0.0.0.0:1179";
    networks ["203.0.113.0/24"];
}

peer "transit-a" {
    remote "192.0.2.2:179";     # outbound: dial this peer
    peer_as 64513;
    md5_key "alpha";
}

peer "customer-b" {
    address "198.51.100.2";     # inbound: accept from this source
    peer_as 64514;
    max_prefixes 1000;
}
```

The native `.lr` DSL (grammar: `docs/config_dsl_grammar.md`) carries
the structure *and* the policy: `prefix-list` / `as-path-list` /
`community-list` / `route-map` blocks attached per peer with
`import "route-map"` / `export "route-map"` (FRR-style first-match /
implicit-deny semantics; set actions include `set_local_pref`,
`set_med`, `set_next_hop`, `prepend` and `add_community`), and
`filter` blocks embed the BIRD-like filter language verbatim — no
string escaping. Unknown references fail at startup — policy never
silently passes traffic. The TOML subset (`templates/daemon.toml`)
stays fully supported as the compatibility spelling — deprecated
through 1.x, planned for removal in 2.x — and
`lr-daemon config to-dsl` converts existing files.

**OSPF mode.** `--protocol ospf` runs the OSPFv2 daemon instead of
BGP: one raw socket (IP protocol 89) per configured interface,
multicast Hellos to 224.0.0.5, dynamic neighbor discovery, the full
RFC 2328 §7.2 DBD/LSR database exchange to Full adjacency
(interop-verified against BIRD 2), per-area Router-LSA origination
and dead-timer teardown. Interfaces and areas
are configured with `ospf { interface "eth0" { } }` /
`ospf { area 1 { type "stub"; } }` blocks in the native `.lr` config
(stub/NSSA area types supported) or the `--ospf-interface` /
`--ospf-area` CLI flags; BGP blocks in the same file are ignored in
OSPF mode. Raw sockets need root or a user/network namespace — the
interop lab runs the whole thing rootless via `unshare -Urn` (see
`tests/interop/ospf.sh`). Current scope: OSPFv2; segments behave
point-to-point by default, and `network_type = "broadcast"` per
interface runs the RFC 2328 §9.4 DR/BDR election (§10.4 adjacency,
§12.4.2 Network-LSA, BIRD-default-broadcast interop verified — see
`tests/interop/ospf_broadcast.sh`); full details in
`docs/ROADMAP.md` (W1.5/W3.3).

```bash
# Two routers on a veth pair, each in its own network namespace:
unshare -Urn lr-daemon --protocol ospf --router-id 1.1.1.1 \
                       --ospf-interface veth0
# → daemon: ospf neighbor 2.2.2.2 Full (area 0.0.0.0)
# → daemon: route installed 10.99.3.0/24 via (none)
```

**Multi-protocol mode (rc.3).** `--protocol` accepts a set: BGP, OSPF
(v2 or v3) and Babel run together in one process through the
multi-protocol supervisor — one shared Loc-RIB, one running flag, one
ticker, one runtime API socket, one thread per engine. The flag is
repeatable and comma-separated (`--protocol bgp,ospf` ==
`--protocol bgp --protocol ospf`); the TOML equivalents are
`protocol = "bgp,ospf"` and `protocols = ["bgp", "ospf"]`. Routes
learned by any engine are visible to all of them (and to `status` /
`routes` / `sessions` on the API socket) with the full preference
order — a prefix learned by both BGP and OSPF prefers BGP (admin
distance 20 < 110), and a withdrawal from one side falls back to the
other. Cross-protocol *advertisement* is never implicit: OSPF and
Babel routes do not leak into BGP advertisements (FRR `redistribute` /
BIRD `pipe` semantics — redistribution stays opt-in through the
router's redistribution pipes). `bmp` and `ldp` cannot combine (fail
closed). Startup is gated: every engine binds its sockets first, then
the supervisor drops privileges and creates the API socket, then the
engines run; a startup failure in any engine aborts the whole
combination. Verified against BIRD 2 running ospf + bgp in one
process: `tests/interop/multi_protocol.sh`.

```bash
unshare -Urn lr-daemon --protocol bgp,ospf --router-id 1.1.1.1 \
                       --local-as 64512 --peer-as 64513 \
                       --listen 10.99.1.1:179 --local-address 10.99.1.1 \
                       --ospf-interface veth0 --network 198.51.100.0/24
# → daemon: 2 engine(s) running
# → daemon: ospf neighbor 2.2.2.2 Full (area 0.0.0.0)
# → daemon: session #3 → Established
```

**LDP mode.** `--protocol ldp` runs the reference daemon as an MPLS
LSR (RFC 5036): a UDP socket on port 646 joined to the all-routers
group (224.0.0.2) per configured interface originates link Hellos
every hold-time third with TTL 1, targeted Hellos reach peers without
a shared link, and the TCP session transport carries Initialization,
Address and Label Mapping messages (§2.5.4 negotiation, downstream
unsolicited). Configured FEC-label bindings (`ldp { bind … }` blocks, label
16..=1048575 with `0` auto-allocating from 16) are advertised to every
operational peer; learned bindings surface as events and in the
runtime API status. Verified against FRR 10 ldpd (see
`tests/interop/ldp_frr.sh`) and two-daemon over a veth pair
(`tests/interop/ldp.sh`). RFC 7552 IPv6 discovery is implemented —
ff02::2 link Hellos with the §5.1 hop-limit-255 check, the §6.1.1
Dual-Stack capability with transport-preference enforcement, and
dual-stack UDP/TCP daemon transports (`--ldp-transport-v6`,
`--ldp-prefer-ipv4`). With `[ldp] install_kernel` the daemon mirrors
learned bindings into the Linux MPLS dataplane (pop route per local
label, encap route per learned FEC) and allocates automatic labels
from a configurable range (`[ldp] label_min`/`label_max`) — full
details in `docs/ROADMAP.md` (W3-extra.4).

```bash
# Two LSRs on a veth pair, each in its own network namespace:
unshare -Urn lr-daemon --protocol ldp --router-id 1.1.1.1 \
                       --ldp-interface veth0 \
                       --ldp-bind 203.0.113.0/24=24000
# → ldp: session up peer 10.99.1.2:0 keepalive 15s max-pdu 4096
# → ldp: mapping learned 10.99.1.0/24 label 3 from 10.99.1.2:0
```

**Operational tooling.** The daemon dumps its Loc-RIB as an MRT file
(RFC 6396 — the format BIRD's `protocol mrt` and every route-analysis
tool speaks) through the runtime API, and mirrors BMP (RFC 7854) to a
monitoring station or _acts as one_:

```bash
echo "mrt /tmp/rib.mrt" | socat - UNIX-CONNECT:/run/lr-daemon.api
lr mrt rib /tmp/rib.mrt          # parse any MRT dump (BIRD, FRR, ours)
lr mrt diff bird.mrt ours.mrt    # content-diff two dumps (exit 1 = differ)
lr-daemon --local-as ... --bmp-target 10.0.0.9:1170   # BMP egress
lr-daemon --protocol bmp --listen 0.0.0.0:1170        # BMP collector
```

**Wire-level parity harness.** `tests/parity/capture_proxy.py` records
the BGP messages of a live session per direction; `lr parity-replay`
replays a capture into an offline router and dumps its Loc-RIB as MRT,
so `lr mrt diff` can prove the replay reproduces the reference
implementation's own RIB view (`tests/interop/parity.sh`, W5.3).

## Workspace Layout

```
librouting/
├── Cargo.toml
├── crates/{lr-core, lr-bgp, lr-ospf, lr-babel, lr-rib, lr-policy,
│           lr-router, lr-bfd, lr-bmp, lr-mrt, lr-damping, lr-osroute,
│           lr-mpls, lr-ldp, lr-cli, lr-ffi, lr-tests}/
├── bindings/{lr-go, lr-python}/        # Go (cgo) and Python (cffi) wrappers
├── docs/
│   ├── README.md                        # documentation index — start here
│   ├── ARCHITECTURE.md                  # layering, RIB pipeline, extension points
│   ├── RFC_MAP.md                       # RFC-by-RFC coverage table
│   ├── API.md                           # public API tour with code snippets
│   ├── STATUS.md                        # implemented-vs-missing gap analysis + roadmap state
│   ├── ROADMAP.md                       # roadmap v2 workstream landing log
│   ├── INTEROP.md                       # BIRD/FRR interop lab guide
│   ├── PARITY.md                        # behaviour knobs vs BIRD 2 / FRR 10
│   ├── RUNBOOK.md                       # operations: lifecycle, runtime API, FAQ
│   ├── OS-INTEGRATION.md                # kernel backends + porting guide
│   ├── tutorial.md                      # book-style tutorial (compile-anchored)
│   ├── bindings/{c,go,python,cpp}.md    # per-language binding guides
│   ├── examples/*.md                    # per-scenario deep dives
│   ├── research/{BGP-DEFECTS,EXCHANGE-PLANE}.md
│   └── scaffolding/README.md            # starter project generator
├── templates/                            # scaffolding templates + daemon.lr/daemon.toml
├── tests/                                # FFI harness + interop scripts (BIRD/FRR)
├── include/{lr_ffi.h, librouting.hpp}   # C ABI header + C++ RAII wrapper
└── .github/workflows/                    # ci.yml + nightly miri + release.yml
```

## Documentation

The documentation index at [`docs/README.md`](docs/README.md) orients new
readers by audience. The canonical references:

| Document                                                       | Path                                       | Audience      |
| -------------------------------------------------------------- | ------------------------------------------ | ------------- |
| Documentation index                                            | [`docs/README.md`](docs/README.md)         | everyone      |
| Architecture (layering, RIB pipeline, extension points)        | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | contributors  |
| RFC reference map (per-RFC coverage)                           | [`docs/RFC_MAP.md`](docs/RFC_MAP.md)       | contributors  |
| Public API tour (per-crate, with snippets)                     | [`docs/API.md`](docs/API.md)               | embedders     |
| Implemented-vs-missing gap analysis + roadmap state           | [`docs/STATUS.md`](docs/STATUS.md)         | everyone      |
| Roadmap v2 landing log (design decisions, evidence)          | [`docs/ROADMAP.md`](docs/ROADMAP.md)       | contributors   |
| OS route-table integration guide (Linux/BSD/Windows + porting) | [`docs/OS-INTEGRATION.md`](docs/OS-INTEGRATION.md) | embedders      |
| Interop testing guide (BIRD/FRR lab)                           | [`docs/INTEROP.md`](docs/INTEROP.md)       | contributors  |
| Behaviour parity flags vs BIRD 2 / FRR 10                     | [`docs/PARITY.md`](docs/PARITY.md)         | operators     |
| Operations runbook (lifecycle, runtime API, FAQ)               | [`docs/RUNBOOK.md`](docs/RUNBOOK.md)       | operators     |
| Book-style tutorial                                            | [`docs/tutorial.md`](docs/tutorial.md)     | newcomers     |
| Per-language binding guides (Go / Python / C / C++)            | [`docs/bindings/`](docs/bindings/)         | embedders     |
| Per-scenario example walkthroughs                              | [`docs/examples/`](docs/examples/)         | operators     |
| BGP defects catalogue + exchange-plane design                 | [`docs/research/`](docs/research/)         | contributors  |
| Scaffolding guide (starter projects)                           | [`docs/scaffolding/README.md`](docs/scaffolding/README.md) | contributors  |
| Templates (incl. fully-commented `daemon.lr`/`daemon.toml`)     | [`templates/`](templates/)                 | operators     |

## BGP topology support

`librouting` ships full support for the most common BGP deployments:

- **iBGP vs eBGP** (RFC 4271 §10): automatic role detection from local/peer
  AS + confederation configuration. Drives AS_PATH prepending, NEXT_HOP
  rewriting, LOCAL_PREF propagation, and reflection rules.
- **Route Reflector** (RFC 4456): `ClusterId`, `ORIGINATOR_ID` insertion,
  `CLUSTER_LIST` prepend + loop detection.
- **Confederations** (RFC 6793): sub-AS membership, `AS_CONFED_SEQUENCE` /
  `AS_CONFED_SET` segment types, external AS announcement.
- **Route Server / IX** (RFC 7947): transparent mode (no AS_PATH prepend,
  NEXT_HOP preserved) + per-client filter chains.
- **BGP Role / OTC** (RFC 9234): `OtcRole` (Provider/Customer/Peer/RS/RsClient)
  - valley-free advertisement enforcement.
- **Graceful Restart** (RFC 4724): per-family capability advertisement,
  stale-route retention for the negotiated restart window and End-of-RIB
  driven resynchronization.
- **Long-Lived Graceful Restart** (RFC 9494): capability 71 negotiation,
  `LLGR_STALE`/`NO_LLGR` communities, least-preferred stale-route
  selection, egress gating to non-LLGR neighbors and per-family stale-time
  retention with a locally configurable cap.
- **Extended Next-Hop** (RFC 5549 / RFC 8950): capability 5 with
  `(NLRI AFI, NLRI SAFI, Nexthop AFI)` tuples (canonical `(1,1,2)`) in
  the standard 6-byte wire form (AFI:2, SAFI:2, NH-AFI:2 — the form
  BIRD 2.x and FRR both encode and require), OPEN-negotiated as the
  intersection of local and peer tuples; IPv4 NLRI
  carried over an IPv6 next-hop (16-byte well-known NEXT_HOP or
  MP_REACH `(AFI=1, 16B)`). Daemon `--extended-next-hop`,
  `--mp-family ipv6-unicast`, `--local-address-v6`; e2e coverage of all
  eight dual-stack / MP-BGP / ENH / pure-IPv6 session modes plus real
  BIRD interop (`tests/interop/bird_enh.sh`).
- **GTSM / TTL security** (RFC 5082): `lr-osroute::gtsm` arms the
  listener with `IP_MINTTL` / `IPV6_MINHOPCOUNT` (kernel drops low-TTL
  SYNs) and sets outbound TTL=255 (single-hop) or N (multihop) on the
  connector. Daemon `--gtsm` / `--gtsm N`.
- **Per-peer maximum-prefix** (BIRD `maximum prefix`, FRR
  `maximum-prefix`): `with_maximum_prefix(N, action)` with warn /
  teardown / restart actions and a configurable early-warning threshold
  (default 75%). Teardown sends a CEASE NOTIFICATION (subcode 1,
  RFC 4486). Daemon `--max-prefixes` / `--max-prefix-action` /
  `--max-prefix-threshold`.

## Best-path selection

Full RFC 4271 §9.1.2 decision process (12 steps) + RFC 5004 deterministic
router-id tiebreak + RFC 4784 multipath. Tunable via `BestPathConfig`:

- `always_compare_med`
- `missing_med_as_infinity`
- `deterministic_router_id`
- `prefer_externals`
- `count_confed_in_path_len`
- `multipath` (N-way equal-cost)
- `multipath_relax` (cross-neighbor multipath)

## Policy hooks

The router ships three trait-based hook points:

- `ImportHook` — invoked after decode, before Adj-RIB-In insertion.
- `SelectionHook` — overrides the comparator during best-path selection.
- `ExportHook` — invoked after Loc-RIB selection, before Adj-RIB-Out encode.

All hooks may drop, keep, or replace routes. They are pure Rust code, so
any operator policy (e.g. "prefer routes from peer X over Y regardless of
attributes") can be implemented without forking.

### RFC 8212 default eBGP route behaviors

`DefaultRouter::set_ebgp_requires_policy(true)` arms the RFC 8212 §3
defaults: an external BGP session (eBGP or a confederation boundary)
whose embedder declared no explicit import policy discards every
received route, and one without an export policy advertises nothing —
stale Adj-RIB-Out entries are withdrawn. Policy presence is declared per
session with `set_session_policy(handle, import, export)`; iBGP is
exempt. The shipped daemon enables the mode by default
(`ebgp_policy "rfc8212";` in the bgp block; `accept-all` restores the RFC 4271
default-accept the RFC permits as a deviation).

### FRR `bgp enforce-first-as` + `bgp bestpath compare-routerid`

`DefaultRouter::set_enforce_first_as(true)` (off by default — FRR `no
bgp enforce-first-as`) drops eBGP UPDATEs whose leftmost AS_PATH
sequence segment's first AS is not the peer's negotiated AS, surfacing
the rejection as a `RouterEvent::Log`. iBGP and confederation-internal
sessions are exempt. The shipped daemon exposes it as
`bgp { enforce_first_as true; }` (CLI `--enforce-first-as` /
`--no-enforce-first-as`); FFI/Go/Python bindings mirror the call. FRR
`bgp bestpath compare-routerid` is exposed via the bgp block's
`bestpath_compare_routerid` key (default `true` — RFC 5004 deterministic; the
inverse of FRR's default).

### FRR `bgp default ipv4-unicast`

`PeerConfig::default_ipv4_unicast` (default `true` — FRR's default and
the RFC 4271 implicit IPv4 unicast family) controls whether IPv4
unicast is implicitly active for a peer even when `mp_families` does
not list it. The FSM gates legacy-section IPv4 NLRI (withdrawals,
NLRI, EoR) on `PeerConfig::ipv4_unicast_active()`; egress in
`advertise.rs` and the families listed by Add-Path / LLGR capabilities
follow. The shipped daemon exposes it as the bgp block key
`default_ipv4_unicast`
(default `true`) with per-peer override; CLI `--no-default-ipv4-unicast`
matches FRR `no bgp default ipv4-unicast`.

### FRR `allowas-in N` / BIRD `allow local as`

`PeerConfig::local_as_tolerance` (default `0` = reject any occurrence
of the local AS in a received AS_PATH — RFC 4271 §9.1.2.15) controls
the per-peer AS-loop tolerance. `N > 0` admits up to N occurrences
(FRR `allowas-in N`); `u32::MAX` admits any number (FRR `allowas-any`).
iBGP is exempt. The shipped daemon exposes it as the bgp block key
`allow_local_as`
(default `0`) with per-peer override; CLI `--allow-local-as [N]` /
`--allowas-any`. Landing this also fixed a latent bug in the safety
net's `local_as_count` that silently broke `reject_as_loop` for routes
from any modern peer sending 4-byte AS_PATH.

### FRR `soft-reconfiguration inbound`

`PeerConfig::soft_reconfig_inbound` (default `false` — FRR's default)
controls whether the router retains the **pre-policy** Adj-RIB-In for
this peer — the raw received routes before the import hook chain
runs — so a policy reconfiguration can be applied without re-fetching
from the peer (`clear ip bgp * soft in`). The cost is duplicate RIB
memory per peer, which is why it is opt-in.
`DefaultRouter::soft_reconfig_inbound(h)` is the op that re-evaluates
the import policy against the stored pre-policy routes. The shipped
daemon exposes it as the bgp block key `soft_reconfig_inbound` (default `false`)
with per-peer override; CLI `--soft-reconfig-inbound` /
`--no-soft-reconfig-inbound`.

### ROA prefix-origin validation (RFC 6811)

`roa_validate true;` in the bgp block arms RFC 6811 §2 prefix-origin validation.
`roa` blocks load ROA entries at startup; every received BGP
UPDATE is validated against the router-wide `RoaTable` at import
time. `roa_invalid_action` controls the `Invalid` outcome:
`"reject"` (default, drop), `"warn"` (accept with log), or
`"accept"` (silent). The filter DSL's `roa.state` accessor reads the
same table regardless of `roa_validate` — so
`if roa.state == "invalid" then { reject; }` always works. See
`docs/examples/filter_dsl_roa.md`.

### BIRD-like filter DSL

`filter` blocks capture a BIRD-like filter body verbatim and attach
it to peers via `import_filter "name"` / `export_filter "name"`. The
DSL supports `if/then/else`, `let` bindings, arithmetic, comparison,
boolean and bitwise operators, prefix-set membership
(`net ~ [ 10.0.0.0/8{16,24} ]`), route attribute access and mutation
(`bgp.local_pref = 200`, `bgp.communities += [ 64512:100 ]`,
`bgp.as_path.prepend(65001)`), `accept`/`reject` (with optional
reason), `case`/switch, and function calls (`len(bgp.as_path)`).
See `docs/examples/filter_dsl_roa.md` for the full grammar and
`docs/PARITY.md` §12 for the BIRD feature-comparison table.

### Babel multi-NIC with glob patterns

`babel { interface "eth*" { } }` blocks configure per-interface Babel parameters
(RFC 8966 §A.2) with shell-like glob patterns (`*`, `?`, `\`). The
daemon enumerates system interfaces via `getifaddrs(3)`, matches
each name against the patterns in file order, and uses the first
match's parameters for the Babel session. When `--local-address` is
unset, the daemon picks the first matched interface's primary address
as the bind source. See `docs/examples/babel_multi_nic.md`.

## Safety net

Protocol-level invariants (RFC compliance requirements) are enforced by
`lr-policy::SafetyNet`:

- AS path loop rejection (RFC 4271 §9.1.2.15)
- NEXT_HOP sanity (unspecified, loopback, or self)
- Martian prefix rejection (RFC 1918 + link-local + loopback + multicast)
- Empty AS_PATH on eBGP (RFC 4271 §6.5 UPDATE error condition)
- Excessive AS loops (> N appearances of own AS)
- Oversized AS_PATH (> N segments)
- Oversized LOCAL_PREF

Each check can be **individually disabled** via `SafetyConfig`. The
defaults match common operator expectations (strict, but not overly
restrictive).

## Status

Implemented and missing features are tracked in detail in
[`docs/STATUS.md`](docs/STATUS.md). Highlights:

- BGP data plane verified bidirectionally against **BIRD 2** and **FRR
  bgpd** over real TCP sessions (`tests/interop/{bird,frr}.sh`, wired into
  CI), including an **RFC 9494 LLGR** lifecycle test
  (`tests/interop/bird_llgr.sh`): both sides negotiate the Long-Lived
  Graceful Restart capability, retain routes across a restart, mark them
  `LLGR_STALE` and purge at the negotiated stale-time expiry. An
  **RFC 7911 Add-Path** suite (`tests/interop/addpath.sh`) negotiates the
  capability over real TCP and verifies the path identifier survives the
  whole pipeline (wire → Adj-RIB-In → Loc-RIB → runtime API).
- OS route-table integration for **Linux (rtnetlink)**, the **BSD family
  (route(4) socket)** and **Windows (IP Helper API)**, plus a porting guide
  for other systems (`docs/OS-INTEGRATION.md`).
- OSPFv3 (RFC 5340) runs the full daemon surface — intra/inter-area
  and external routing, broadcast segments with DR election, SRv6
  (RFC 9513) and graceful restart (RFC 5187, helper + restarting
  router, interop-verified against FRR ospf6d).
- Not yet production-ready: see the open items in `docs/ROADMAP.md`
  (RFC 8362 extended LSAs / SRv6 adjacency SIDs, BGP-LS and SR
  Policy are the next planned slices; SR-MPLS remains v2-only). The
  C ABI is **unstable** until v0.5.

## CI/CD

GitHub Actions workflows live in `.github/workflows/` and run on push to
`main` and on PRs: fmt + clippy + workspace tests + C harness + Go bindings +
Python bindings + MSRV + cross-build (aarch64 Linux, Windows) + **interop
jobs against BIRD and FRR** + a **cross-platform matrix** that runs
`cargo build` and `cargo test` natively on Ubuntu, macOS (Intel + Apple
Silicon) and Windows. The tag-driven `release.yml` produces a per-OS
tarball (`liblr_ffi.{so,dylib,dll}` + the static archive + the C / C++
headers) on each of the four targets and assembles them into a single
draft GitHub Release. Nightly runs `miri` for the unsafe audit on
`lr-osroute` FFI.

## Documentation

The documentation set lives under `docs/`. Start at
[`docs/README.md`](docs/README.md) for the per-audience index:

- User-facing: [`docs/lr-cli.md`](docs/lr-cli.md) (CLI user guide),
  [`docs/RUNBOOK.md`](docs/RUNBOOK.md) (operations),
  [`docs/tutorial.md`](docs/tutorial.md) (book-style tutorial),
  `templates/daemon.lr` (fully-commented reference config, native
  DSL) and its TOML twin `templates/daemon.toml`.
- Embedder-facing: [`docs/API.md`](docs/API.md) (public Rust API tour),
  [`docs/bindings/{c,cpp,go,python}.md`](docs/bindings) (per-language
  embedding guides), [`docs/examples/`](docs/examples) (worked scenarios).
- Contributor-facing: [`docs/lr-cli-internals.md`](docs/lr-cli-internals.md)
  (CLI internals + extension patterns),
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (layering + RIB pipeline),
  [`docs/STATUS.md`](docs/STATUS.md) (implemented-vs-missing),
  [`docs/ROADMAP.md`](docs/ROADMAP.md) (workstream landing log),
  [`docs/RFC_MAP.md`](docs/RFC_MAP.md) (RFC coverage table).
- Maintainer-facing: [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md)
  (semver policy, 1.0 freeze criteria, release flow, post-1.0 governance).

## License

Dual-licensed under MIT OR Apache-2.0.
