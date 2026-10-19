# `lrctl` JSON output shape

`lrctl --json` produces machine-readable JSON for the supported
commands. This document is the canonical shape contract for consumers
scripts.

## Global flags

```
--json            Compact JSON (default).
--json=compact    Compact JSON (explicit).
--json=pretty     Pretty-printed JSON (2-space indent).
-j                Alias for --json.
```

The flag may appear anywhere in the args (before, after, or in
between the command's own args). It applies to the commands listed
below; other commands (`reload`, `shutdown`, `routes show`,
`routes dump`, `filter compile`, `session <h> soft-in`,
`session <h> refresh-in`, `show session <h>`, `show sessions
detail`, `roa list`, `roa count`) ignore it and emit their
line-oriented form.

## Success replies

Each command's JSON shape mirrors its line-oriented form. Keys
are normalised to `snake_case` (the daemon's `local-as` becomes
`local_as`) so a JSON consumer never has to deal with hyphens as
key characters. Numeric values render as JSON numbers; `true` /
`false` render as JSON booleans; the sentinel `unknown` (BIRD
parity for "no value available") becomes a JSON `null`.

### `lrctl --json status`

The `version` field carries the workspace version from
`[workspace.package] version` in `Cargo.toml` — shown here as
`<version>` so the example does not go stale on the next release.

```json
{
  "version": "<version>",
  "local_as": 64512,
  "peer_as": 64513,
  "router_id": "10.0.0.1",
  "config": "(none)",
  "uptime_secs": 42,
  "sessions": 1,
  "rib_entries": 1
}
```

### `lrctl --json sessions`

```json
[
  {
    "handle": "1",
    "kind": "bgp",
    "local_as": 64512,
    "peer_as": 64513,
    "state": "Idle",
    "established": false,
    "peer_id": "-",
    "hold_time": 0,
    "adj_rib_in": 0,
    "updates_rx": 0,
    "updates_tx": 0
  }
]
```

### `lrctl --json show status`

The same shape as `status` plus a `by_protocol` array (one entry
per protocol kind present in the daemon's session table) and a
`memory` object:

```json
{
  "version": "<version>",
  "local_as": 64512,
  "peer_as": 64513,
  "router_id": "10.0.0.1",
  "config": "(none)",
  "uptime_secs": 42,
  "sessions": 1,
  "established": 0,
  "rib_entries": 1,
  "by_protocol": [
    {
      "kind": "bgp",
      "total": 1,
      "established": 0
    }
  ],
  "memory": {
    "rss_bytes": 9932800,
    "vsize_bytes": 225419264
  }
}
```

### `lrctl --json show routes count`

```json
{
  "total": 1,
  "by_protocol": [
    {
      "protocol": "bgp",
      "routes": 1
    }
  ]
}
```

### `lrctl --json show memory`

```json
{
  "uptime_secs": 42,
  "rss_bytes": 9932800,
  "vsize_bytes": 225419264
}
```

### `lrctl --json ping`

```json
{
  "ok": true,
  "round_trip_ms": 1
}
```

On failure, the `ok` field is `false` and a `detail` string
carries the transport error:

```json
{
  "ok": false,
  "round_trip_ms": 0,
  "detail": "connect /run/lr-daemon.api: No such file or directory"
}
```

## Error replies

Every command's error path renders as a JSON object under
`--json`, so a JSON-consuming script never has to special-case a
non-JSON line:

```json
{
  "ok": false,
  "error": "no session with handle 99"
}
```

Transport failures use the same shape — the `error` field carries
the transport-layer error string.

## Stability contract

The shapes above are part of the `lrctl` operator surface. A
backwards-incompatible change (renaming a key, removing a field,
changing a value's type from number to string) is a major
version bump. Additive changes (new keys) are allowed in minor
releases.

The line-oriented form (i.e. without `--json`) is documented in
`docs/lr-daemon.md` and is the primary operator surface; the JSON
form is a machine-readable view of the same data, kept in
lockstep by the per-command parsers in `crates/lr-cli/src/lrctl.rs`.
