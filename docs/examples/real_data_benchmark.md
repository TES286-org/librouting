# Real-data benchmark

Replay a public MRT RIB dump through librouting's Loc-RIB and collect
the metrics the 2.x plan's "Benchmark Based on Real Data" item names:
processing efficiency, convergence time, memory usage, path-selection
correctness, peak resource usage during soft reload, and static
resource occupation when routing is maintained.

Read this page if you are running the bench locally, wiring it into a
continuous-benchmark pipeline, or triaging a regression the criterion
harness flagged.

## What the bench measures

`lr bench replay --mrt <file>` reads a TABLE_DUMP_V2 RIB dump
(`lr-mrt::parse_file`, RFC 6396), builds a `Route` for every
`(prefix, entry)` pair, installs each one into a fresh
`lr-rib::LocRib`, and reports:

- `parse_ms` — wall time spent in `lr_mrt::parse_file`.
- `install_ms` — wall time spent in `LocRib::install`.
- `routes_per_sec` — `routes_installed / install_ms * 1000`.
- `rss_peak_kb`, `rss_final_kb` — `/proc/self/status` `VmHWM` and
  `VmRSS` on Linux; `unsupported` elsewhere.
- `soft_reload_ms`, `soft_reload_peak_rss_kb` — re-install every
  route (byte-identical) into the same Loc-RIB, exercising the
  `install` no-op path. The peak RSS during this pass is the
  "peak resource usage during soft reload" metric.
- `steady_state_drift_kb` — `VmRSS` drift over a 100 ms hold after
  convergence.
- `correctness.{matched, mismatched, missing, extra}` — per-prefix
  comparison of lr's best path against the dump's candidate set,
  using `lr-mrt::walk_attributes` for the AS_PATH and next hop.

`--json` emits the same fields as one JSON object for scraper
consumption; the default is human-readable.

## Running the bench

The harness lives at
[`tests/bench/real_data.sh`](../../tests/bench/real_data.sh). It
downloads a public RIB dump (RouteViews route-views2 by default),
runs `lr bench replay` against it, and optionally feeds the same
routes to BIRD via `lr-daemon --mrt-feed` for cross-implementation
comparison.

```sh
cargo build --release -p lr-cli --bin lr --bin lr-daemon
bash tests/bench/real_data.sh
```

Env overrides:

- `LR_BENCH_MRT` — path to a local `.mrt` file. When set, the
  harness skips the download.
- `LR_BENCH_MRT_URL` — the dump URL (default: the RouteViews
  route-views2 `bview-latest.gz`).
- `LR_BENCH_NO_BIRD` — when non-empty, skip the BIRD comparison leg.
- `LR_BENCH_BIRD_CAP` — cap on routes fed to BIRD (default 10000).
  A full public RIB (~1M routes) takes hours to replay over a BGP
  session; the cap keeps the BIRD leg within a CI budget.
- `LR_BENCH_OUT` — working directory (default `/tmp/lr_bench`).

The harness SKIPs cleanly (exit 0) when the network egress is
unavailable, when no local MRT is provided, or when BIRD is not
installed and `LR_BENCH_NO_BIRD` is unset.

## Running the bench directly

The CLI subcommand is the bench itself; the harness only acquires
the dump and wires up BIRD:

```sh
target/release/lr bench replay --mrt /tmp/bview.mrt
```

Output:

```text
bench replay: /tmp/bview.mrt
  parse:        412 ms
  install:      1830 ms (950123 routes in, 950123 installed)
  throughput:   519195 routes/sec
  loc-rib:      950123 prefixes, 950123 paths
  rss (linux/proc):    peak 318215 KB, final 318215 KB
  soft reload:  425 ms, peak RSS 318215 KB
  steady state: drift +0 KB over 100 ms hold
  correctness:  950123 matched, 0 mismatched, 0 missing, 0 extra
```

`--json` emits the same fields as a JSON object.

## The criterion regression bench

`cargo bench -p lr-mrt --bench mrt_replay` measures the
`LocRib::install` throughput against either a real dump (when
`LR_BENCH_MRT` is set) or a synthetic 1000-prefix fallback. The
nightly job uploads the criterion report as an artifact; a future
commit can wire the report into a regression-detection bot that
diffs the latest run against the committed baseline.

```sh
LR_BENCH_MRT=/tmp/bview.mrt \
  cargo bench -p lr-mrt --bench mrt_replay -- \
    --sample-size 10 --warm-up-time 1 --measurement-time 3 --noplot
```

## Feeding the dump to a reference implementation

`lr-daemon --mrt-feed <file>` loads an MRT RIB dump into the
daemon's Loc-RIB at startup. The daemon's existing BGP export path
advertises the routes to peers as if learned from a session; a
reference implementation (BIRD, FRR) learns them over a normal BGP
session.

```sh
target/release/lr-daemon \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --ebgp-policy accept-all --listen 127.0.0.1:18080 \
    --local-address 127.0.0.1 \
    --mrt-feed /tmp/bview.mrt --mrt-feed-cap 10000
```

`--mrt-feed-cap N` truncates the feed to the first `N` routes — the
BIRD comparison leg uses a non-zero cap to keep the session within a
CI job's budget. The full uncapped feed is the storage bench's job.

## What the BIRD leg checks

The harness's BIRD leg confirms interoperability: BIRD learns the
routes lr-daemon advertises from the MRT feed, BIRD's MRT dump
writer produces a dump of the lr-learned routes, and the
`lr mrt diff` against lr's own Loc-RIB dump surfaces any
path-selection divergence for triage.

A full prefix-by-prefix diff against lr's Loc-RIB dump is the
follow-up the harness prints counts for today; the
`lr-daemon --mrt-feed` flag and the `--mrt-feed-cap` knob are the
plumbing that follow-up consumes.

## Reference data sources

The default dump URL points at RouteViews route-views2's
`bview-latest.gz`. Other RouteViews collectors
(<https://archive.routeviews.org/>) and the RIPE RIS project
(<https://data.ris.ripe.net/>) carry the same format; point
`LR_BENCH_MRT_URL` at any of them.

A full IPv4 RIB dump is ~300 MB compressed, ~1.5 GB uncompressed,
and carries ~1M routes. The bench's memory and throughput numbers
against a full dump are the ones to track for regression; the
criterion bench's synthetic fallback is the smoke test.
