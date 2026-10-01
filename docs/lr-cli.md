# The `lr` inspection CLI and the `lrctl` operational CLI

`lr-cli` builds three binaries from `crates/lr-cli`. This page covers
two of them: `lr`, which decodes wire messages and MRT dumps with no
daemon running, and `lrctl`, which drives a running `lr-daemon` over its
runtime API socket. The daemon itself — flags, config keys, lifecycle —
is in [lr-daemon.md](lr-daemon.md), with the exhaustive lists in
[lr-daemon-reference.md](lr-daemon-reference.md). The module layout
behind these binaries is in [lr-cli-internals.md](lr-cli-internals.md).

```sh
cargo build --release -p lr-cli
# target/release/lr, lr-daemon, lrctl
```

## `lr` — the inspection CLI

The subcommands are `version`, `decode <kind> <hex>`, `routes
<list|add|del>`, `mrt <parse|rib|diff>` and `parity-replay`; bare `lr`
or `lr help` prints the banner. Exit codes:

| Code | When |
| --- | --- |
| 0 | Success, or `help` |
| 1 | Runtime failure: decode error, file I/O, kernel error, odd hex |
| 2 | Usage error: unknown command, wrong argument count, unknown `kind` |

`lr` with **no argument at all** prints the banner and exits **1**; an
unrecognised command prints `error: unknown command '<name>'` before
the banner and exits 2.

### `lr version`

Prints the library version from `Cargo.toml`, then a crate list:

```text
librouting <version>
crates: <comma-separated crate names>
```

The crate list is a fixed string literal in `crates/lr-cli/src/main.rs`.
It is not derived from the workspace and it names fewer crates than
`crates/` holds — `lr-srv6`, `lr-cli` and `lr-tests` are missing from
it. Read it as a build label, not as an inventory.

### `lr decode <kind> <hex>`

Decodes one message and pretty-prints it with `{:#?}`. `<hex>` includes
the framing: BGP's 16-octet marker plus the 2-byte length and 1-byte
type, BFD's fixed header. A `0x` prefix is accepted; an odd-length
string is an error and exits 1.

| `<kind>` | Codec | Wire shape |
| --- | --- | --- |
| `bgp-open` | `lr_bgp::BgpCodec` | marker + length + type 1 |
| `bgp-keepalive` | `lr_bgp::BgpCodec` | marker + length + type 4 |
| `bfd` | `lr_bfd::BfdCodec` | 24-byte header, optional auth section |

A BFD control packet is 24 bytes. When the A flag is set an
authentication section follows, and the shortest legal one is 3 bytes:
`Simple Password` is 3 + password length, while the keyed digests are
24 (MD5) and 28 (SHA1) bytes. The decode minimum in
`crates/lr-bfd/src/packet.rs` is therefore 26 for an A-flagged packet,
not a 26-byte frame.

```sh
# KEEPALIVE: marker + length 19 + type 4.
$ lr decode bgp-keepalive \
    ffffffffffffffffffffffffffffffff001304
BgpMessage::Keepalive(...)
```

### `lr routes list|add|del`

Kernel routing-table access through `lr-osroute`, using the platform
backend (Linux `rtnetlink`, BSD/macOS `route(4)`, Windows `IP Helper`).
`routes list` prints a fixed-width table of `prefix`, `next_hop`, `if`,
`metric` and `proto`. `routes add <prefix> <gw> <if_index>` prints
`added: <prefix> via <gw> dev <if_index>`; `routes del <prefix>` (alias
`delete`) prints `deleted: <prefix>`. Both mutating forms need
privilege — `CAP_NET_ADMIN` on Linux, Administrator on Windows — and
where only the `stub` backend exists the connect fails and the command
exits 1.

### `lr mrt parse|rib|diff`

MRT (RFC 6396) tooling on top of `lr-mrt`.

- `mrt parse <file>` — one summary line per record (peer index tables,
  RIB sequence and prefix, BGP4MP state changes and messages), then
  `<n> record(s)`.
- `mrt rib <file>` — the peer index table and one line per (prefix,
  entry) with AS path, next hop, peer and the RFC 7911 Add-Path
  `PATH-ID`, then `<n> rib record(s)`. A dump with no RIB record exits
  1 with `no RIB records found in dump`.
- `mrt diff <a> <b>` — content-diff two RIB dumps. Per prefix it
  compares AS path, next hop, MED and communities, each as a set. It
  prints `IDENTICAL (<n> prefixes)` and exits 0, or `DIFFER (<a> vs
  <b>):` with one line per difference and exits 1.

`mrt diff` deliberately does **not** compare LOCAL_PREF.
`RouteFingerprint` in `crates/lr-cli/src/parity.rs` leaves it out:
LOCAL_PREF is iBGP-only on the wire (RFC 4271 §4.3), so a dump shows
the viewer's own default rather than anything the sender advertised.

### `lr parity-replay`

Replays a captured BGP message stream into an offline `lr-router`
pipeline and writes the resulting Loc-RIB as an MRT `TABLE_DUMP_V2`
file, ready to diff against the reference implementation's own dump.

| Flag | Meaning |
| --- | --- |
| `--capture FILE` | Capture file to read (required) |
| `--direction up\|down` | Stream to replay; default `down` |
| `--local-as N` | Local AS for the replay session |
| `--peer-as N` | Peer AS for the replay session |
| `--router-id A.B.C.D` | Local BGP identifier (required) |
| `--output FILE.mrt` | Loc-RIB dump destination (required) |

`up` is client-to-upstream (lr to the reference), `down` is
upstream-to-client. The default replays `down`, the stream the reference
sent. The capture is line-oriented JSON, one message per line, as
`{"dir":"down","hex":"…"}` with the whole message hex-encoded; blank
lines and `#` comments are skipped. The interop proxy
[`tests/parity/capture_proxy.py`](../tests/parity/capture_proxy.py)
writes that format off the wire.

On success it prints `parity-replay: <n> message(s) replayed, <n> RIB
record(s) -> <path>` and exits 0. An unknown option, a bad `--local-as`
or a missing required flag exits 2; a replay whose session never
reaches Established exits 1. There is no `--help` — an unknown option
prints the usage line and exits 2. `lr-cli` declares no library target,
so there is no in-process capture writer to call from another crate;
outside the crate's own tests the wire proxy is the only writer.

## `lrctl` — the operational CLI

`lrctl` connects to a running daemon's runtime API socket, sends one
command and prints the reply verbatim. `filter compile` runs entirely
client-side through `lr-policy`.

The socket comes from `--socket PATH`, `-s PATH` or `--socket=PATH`, in
any position; the first occurrence wins. Without one, `lrctl` uses
`/run/lr-daemon.api` — the path `templates/daemon.lr` shows. On a
non-Unix target the transport refuses with `runtime API requires Unix
domain sockets (not supported here)`.

| Command | Daemon command | Effect |
| --- | --- | --- |
| `lrctl status` | `status` | Daemon summary |
| `lrctl sessions [list]` | `sessions` | One line per session |
| `lrctl routes show [prefix]` | `routes` | Loc-RIB dump |
| `lrctl routes dump <path>` | `mrt <path>` | Write the Loc-RIB as MRT |
| `lrctl reload` | `reload` | Re-apply the configuration |
| `lrctl shutdown` | `shutdown` | Graceful shutdown |
| `lrctl filter compile <body>` | (none) | Validate a filter body |
| `lrctl version`, `lrctl help` | (none) | Version or banner |

`routes show <prefix>` fetches the whole `routes` reply and filters it
client-side, matching the leading token exactly so `203.0.113.0/24`
does not also match `203.0.113.0/25`. No match is not an error: it
prints `no route for <prefix>` on stderr and exits 0, matching FRR's
`show ip route`.

`filter compile <body>` compiles the body through
`lr_policy::filter::compile`, the same path the daemon runs at startup.
Arguments after `compile` are joined with spaces, so extra shell quoting
is optional. Success prints `ok (<n> statement(s))` — with
`, <n> function(s)` appended when the body defines functions — and
exits 0. A parse error prints a caret snippet ending in
`parse error at <line>:<col>: <kind>` on stderr and exits 1.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Success, including `routes show <prefix>` with no match |
| 1 | Transport failure, or a reply containing an `error:` line |
| 2 | Argument error: unknown command or subcommand, missing argument |

`lrctl` exits 1 when any line of the reply starts with `error:`, but it
still prints the reply first. The daemon's reply strings are in
[RUNBOOK.md](RUNBOOK.md).
