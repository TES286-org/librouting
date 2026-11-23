#!/usr/bin/env python3
"""Comparison report generator for the real-data benchmark (issue #101).

Reads one time-series file per BGP speaker and prints a comparison
table. Each input file is the JSONL output of `sample_metrics.sh`:

    {"t": <seconds>, "routes": <n>, "rss_kb": <n>}
    ...

The report computes, per speaker:

- **routes_final** — the last non-null route count.
- **convergence_s** — time from the first sample to the last sample
  whose route count changed (the "settled" point).
- **routes_per_sec** — `routes_final / convergence_s` when
  `convergence_s > 0`, else `null`.
- **rss_peak_kb** — the maximum non-null `rss_kb` across the series.
- **rss_final_kb** — the last non-null `rss_kb`.

The comparison table prints one row per speaker and one summary row
with the fastest convergence and the highest throughput.

Usage:
    compare_report.py <label1>:<file1> [<label2>:<file2> ...]

Example:
    compare_report.py lr:/tmp/lr_bench/lr.jsonl \\
        bird:/tmp/lr_bench/bird.jsonl \\
        frr:/tmp/lr_bench/frr.jsonl
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load_series(path: str) -> list[dict]:
    """Load a JSONL time-series file. Malformed lines are skipped."""
    out: list[dict] = []
    p = Path(path)
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def metrics(series: list[dict]) -> dict:
    """Compute the comparison metrics from a time-series."""
    if not series:
        return {
            "routes_final": None,
            "convergence_s": None,
            "routes_per_sec": None,
            "rss_peak_kb": None,
            "rss_final_kb": None,
            "samples": 0,
        }

    # Filter to samples with a non-null route count.
    route_samples = [s for s in series if s.get("routes") is not None]
    rss_samples = [s for s in series if s.get("rss_kb") is not None]

    routes_final = route_samples[-1]["routes"] if route_samples else None

    # Convergence: the timestamp of the last sample whose route count
    # differs from the previous sample's. The first sample's t is the
    # start of the feed (t=0 or close to it).
    convergence_s = None
    if len(route_samples) >= 2:
        first_t = route_samples[0]["t"]
        last_change_t = first_t
        for prev, cur in zip(route_samples, route_samples[1:]):
            if cur["routes"] != prev["routes"]:
                last_change_t = cur["t"]
        convergence_s = last_change_t - first_t
    elif len(route_samples) == 1:
        convergence_s = 0

    routes_per_sec = None
    if routes_final and convergence_s is not None and convergence_s > 0:
        routes_per_sec = routes_final / convergence_s

    rss_peak_kb = max(
        (s["rss_kb"] for s in rss_samples if s.get("rss_kb") is not None),
        default=None,
    )
    rss_final_kb = rss_samples[-1]["rss_kb"] if rss_samples else None

    return {
        "routes_final": routes_final,
        "convergence_s": convergence_s,
        "routes_per_sec": routes_per_sec,
        "rss_peak_kb": rss_peak_kb,
        "rss_final_kb": rss_final_kb,
        "samples": len(series),
    }


def fmt(v, suffix: str = "") -> str:
    """Format a metric value for the table."""
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.1f}{suffix}"
    return f"{v}{suffix}"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    targets: list[tuple[str, dict]] = []
    for arg in argv[1:]:
        if ":" not in arg:
            print(f"error: bad target spec '{arg}' (want label:file)", file=sys.stderr)
            return 2
        label, _, path = arg.partition(":")
        series = load_series(path)
        targets.append((label, metrics(series)))

    if not targets:
        print("error: no target files to compare", file=sys.stderr)
        return 2

    # ---- table ----
    headers = ["target", "routes", "convergence", "routes/sec", "rss peak", "rss final", "samples"]
    rows = []
    for label, m in targets:
        rows.append([
            label,
            fmt(m["routes_final"]),
            fmt(m["convergence_s"], "s"),
            fmt(m["routes_per_sec"]),
            fmt(m["rss_peak_kb"], " KB"),
            fmt(m["rss_final_kb"], " KB"),
            str(m["samples"]),
        ])

    # Column widths.
    widths = [max(len(h), max((len(r[i]) for r in rows), default=0))
              for i, h in enumerate(headers)]

    def print_row(cells: list[str]) -> None:
        print("  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)))

    print_row(headers)
    print_row(["-" * w for w in widths])
    for row in rows:
        print_row(row)

    # ---- summary ----
    print()
    print("summary:")
    converged = [(label, m) for label, m in targets if m["convergence_s"] is not None and m["routes_final"]]
    if converged:
        fastest = min(converged, key=lambda lm: lm[1]["convergence_s"])
        print(f"  fastest convergence: {fastest[0]} ({fmt(fastest[1]['convergence_s'], 's')})")
        highest_throughput = max(
            (lm for lm in converged if lm[1]["routes_per_sec"] is not None),
            key=lambda lm: lm[1]["routes_per_sec"],
            default=None,
        )
        if highest_throughput:
            print(f"  highest throughput:  {highest_throughput[0]} ({fmt(highest_throughput[1]['routes_per_sec'])} routes/sec)")
    else:
        print("  no target converged (all route counts stayed at 0 or null)")

    # ---- JSON output for the harness to upload ----
    print()
    print("json:")
    print(json.dumps({
        "targets": [
            {"label": label, **m} for label, m in targets
        ]
    }))

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
