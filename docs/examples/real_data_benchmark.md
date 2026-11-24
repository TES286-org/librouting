# Real-data benchmark

Import a public MRT RIB dump into multiple BGP speakers via real BGP
sessions, measure each speaker's route count and RSS during the feed,
and compare the results. This is the issue #101 "Benchmark Based on
Real Data" bench: a system that feeds the same routes to lr-daemon,
BIRD and FRR over BGP, not just a self-test of lr.

Read this page if you are running the bench locally, wiring it into a
continuous-benchmark pipeline, or triaging a regression the criterion
harness flagged.

## Architecture

```
                ┌─────────────────┐
                │  Source speaker │
                │  (lr-daemon     │
                │   --mrt-feed)   │
                │   (listener)    │
                └──────┬──────────┘
                       │ BGP sessions (targets connect)
          ┌────────────┼────────────┐
          ▼            ▼            ▼
    ┌─────────┐  ┌─────────┐  ┌─────────┐
    │ lr-     │  │  BIRD   │  │  FRR    │
    │ daemon  │  │         │  │ bgpd    │
    │ (target)│  │ (target)│  │ (target)│
    └─────────┘  └─────────┘  └─────────┘
          │            │            │
          ▼            ▼            ▼
    [sampled     [sampled     [sampled
     every 1s]   every 1s]   every 1s]
          │            │            │
          └────────────┼────────────┘
                       ▼
                ┌─────────────────┐
                │  Comparison     │
                │  report         │
                └─────────────────┘
```

The source lr-daemon loads the MRT dump into its Loc-RIB through the
`--mrt-feed` flag; the daemon's BGP export path advertises the
routes to every connected peer over a real BGP session. Each target
connects to the source and learns the routes via the normal BGP
UPDATE path — the same path a production deployment uses.

## What the bench measures

Each target is sampled every second during the feed. The comparison
report computes, per target:

- **routes_final** — the last non-null route count.
- **convergence_s** — time from the first sample to the last sample
  whose route count changed.
- **routes_per_sec** — `routes_final / convergence_s`.
- **rss_peak_kb** — the maximum RSS across the series.
- **rss_final_kb** — the last RSS sample.

The comparison table prints one row per target and a summary with
the fastest convergence and the highest throughput.

## Running the bench

```sh
cargo build --release -p lr-cli --bin lr --bin lr-daemon --bin lrctl
bash tests/bench/real_data.sh
```

Env overrides:

- `LR_BENCH_MRT` — path to a local `.mrt` file. When set, the
  harness skips the download.
- `LR_BENCH_MRT_URL` — the dump URL (default: RouteViews
  route-views2 `bview-latest.gz`).
- `LR_BENCH_NO_BIRD` — when non-empty, skip the BIRD target.
- `LR_BENCH_NO_FRR` — when non-empty, skip the FRR target.
- `LR_BENCH_CAP` — cap on routes fed to each target (default 1000).
  A full public RIB (~1M routes) takes hours to replay over a BGP
  session; the cap keeps each target within a CI budget.
- `LR_BENCH_OUT` — working directory (default `/tmp/lr_bench`).
- `LR_BENCH_DEADLINE` — per-target convergence deadline in seconds
  (default 120).

The harness SKIPs cleanly (exit 0) when the network egress is
unavailable, when no local MRT is provided, or when BIRD and FRR are
not installed (only the lr-vs-lr leg runs).

## The source speaker

`lr-daemon --mrt-feed <file> [--mrt-feed-cap N]` loads the MRT dump
into the daemon's Loc-RIB at startup, preserving the dump's path
attributes. The daemon's existing BGP export path advertises the
routes to peers.

```sh
target/release/lr-daemon \
    --local-as 64520 --peer-as 64512 --router-id 10.0.0.1 \
    --ebgp-policy accept-all --listen 127.0.0.1:18080 \
    --local-address 192.0.2.1 \
    --mrt-feed /tmp/bview.mrt --mrt-feed-cap 1000
```

`--mrt-feed-cap N` truncates the feed to the first `N` routes — the
harness uses a non-zero cap to keep the BGP session within a CI
budget.

## The Loc-RIB storage bench

`lr bench replay --mrt <file>` measures the Loc-RIB install
throughput directly (no BGP session). It is the criterion regression
surface — the storage layer the BGP-session-driven bench builds on.
The harness runs it at the end as a baseline.

```sh
target/release/lr bench replay --mrt /tmp/bview.mrt
```

The criterion bench `cargo bench -p lr-mrt --bench mrt_replay`
tracks the install throughput against either a real dump
(`LR_BENCH_MRT` env) or a synthetic 1000-prefix fallback.

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
