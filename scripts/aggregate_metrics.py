#!/usr/bin/env python3
"""Aggregate per-run benchmark metrics into a master CSV + per-CVE summary.

Reads the durable per-run files  <raw_dir>/<CVE>_<target>_<fuzzer>_run<id>.csv
(one row each; written live by the orchestrator so partial runs are included),
emits:
  <out>/<fuzzer>_runs.csv      one row per run (+ derived total/per-hour tokens)
  <out>/<fuzzer>_summary.csv   per-CVE mean/median/stdev for the key metrics

Usage:
  python3 scripts/aggregate_metrics.py <raw_dir> --fuzzer <name> --out <dir>
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
from pathlib import Path

# Metrics the report focuses on (per the BENCHMARK.md requirements).
FOCUS = [
    "ttr_s",                # time-to-reach
    "tte_s",                # time-to-exposure
    "unique_crashes",
    "edges_found",
    "bitmap_cvg",
    "total_prep_time_s",
    "fuzzing_loop_time_s",
    "overhead_pct",
    "llm_requests",
    "llm_input_tokens",
    "llm_output_tokens",
    "total_tokens",
    "input_tokens_per_hour",
    "output_tokens_per_hour",
    "total_tokens_per_hour",
    "llm_estimated_calls",   # >0 ⇒ token totals approximate (API omitted usage)
]


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def load_run(csv_path: Path) -> dict | None:
    try:
        rows = list(csv.DictReader(open(csv_path)))
    except OSError:
        return None
    if not rows:
        return None
    row = dict(rows[-1])
    # The orchestrator already writes total_tokens + per-hour rates; derive them
    # here only as a fallback for older/partial files.
    in_tok, out_tok = _f(row.get("llm_input_tokens")), _f(row.get("llm_output_tokens"))
    if in_tok is not None and out_tok is not None and not row.get("total_tokens"):
        row["total_tokens"] = in_tok + out_tok
    dur = _f(row.get("fuzzing_loop_time_s")) or _f(row.get("fuzzing_elapsed_s"))
    hours = dur / 3600.0 if dur and dur > 0 else None
    if hours:
        for src, dst in (("llm_input_tokens", "input_tokens_per_hour"),
                         ("llm_output_tokens", "output_tokens_per_hour"),
                         ("total_tokens", "total_tokens_per_hour")):
            if not row.get(dst):
                tok = _f(row.get(src))
                row[dst] = round(tok / hours, 2) if tok is not None else ""
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results_root")
    ap.add_argument("--fuzzer", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.results_root)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Collect one row per run from the flat named files:
    #   <CVE>_<target>_<fuzzer>_run<id>.csv
    # CVE ids contain '-' (not '_'), and the last two underscore-fields are
    # always <fuzzer> and run<id>, so parsing is unambiguous even when the
    # target_function itself contains underscores.
    runs: list[dict] = []
    for csv_path in sorted(root.glob("*.csv")):
        parts = csv_path.stem.split("_")
        if len(parts) < 3:
            continue
        cve = parts[0]
        run_id = parts[-1].replace("run", "")
        row = load_run(csv_path)
        if row is None:
            continue
        row["fuzzer"] = args.fuzzer
        row["cve"] = cve
        row["run"] = run_id
        runs.append(row)

    if not runs:
        print(f"[aggregate] No completed runs found under {root}")
        return 1

    # ── master per-run CSV ───────────────────────────────────────────────────
    lead = ["fuzzer", "cve", "run"]
    rest = sorted({k for r in runs for k in r} - set(lead))
    runs_csv = out / f"{args.fuzzer}_runs.csv"
    with open(runs_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=lead + rest, extrasaction="ignore")
        w.writeheader()
        w.writerows(runs)
    print(f"[aggregate] {len(runs)} runs → {runs_csv}")

    # ── per-CVE summary (mean/median/stdev) ──────────────────────────────────
    by_cve: dict[str, list[dict]] = {}
    for r in runs:
        by_cve.setdefault(r["cve"], []).append(r)

    summary_csv = out / f"{args.fuzzer}_summary.csv"
    with open(summary_csv, "w", newline="") as f:
        cols = ["fuzzer", "cve", "n_runs", "metric", "mean", "median", "stdev", "min", "max"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for cve in sorted(by_cve):
            group = by_cve[cve]
            for metric in FOCUS:
                vals = [v for v in (_f(r.get(metric)) for r in group) if v is not None]
                if not vals:
                    continue
                w.writerow({
                    "fuzzer": args.fuzzer, "cve": cve, "n_runs": len(group),
                    "metric": metric,
                    "mean": round(statistics.mean(vals), 3),
                    "median": round(statistics.median(vals), 3),
                    "stdev": round(statistics.stdev(vals), 3) if len(vals) >= 2 else "",
                    "min": round(min(vals), 3), "max": round(max(vals), 3),
                })
    print(f"[aggregate] per-CVE summary → {summary_csv}")

    # Console snapshot of TTR/TTE coverage.
    print(f"\n{'CVE':<22}{'runs':>5}{'TTE med':>12}{'TTR med':>12}{'crashes':>10}")
    for cve in sorted(by_cve):
        g = by_cve[cve]
        tte = [v for v in (_f(r.get('tte_s')) for r in g) if v is not None]
        ttr = [v for v in (_f(r.get('ttr_s')) for r in g) if v is not None]
        cr = [v for v in (_f(r.get('unique_crashes')) for r in g) if v is not None]
        print(f"{cve:<22}{len(g):>5}"
              f"{(f'{statistics.median(tte):.0f}s' if tte else '-'):>12}"
              f"{(f'{statistics.median(ttr):.0f}s' if ttr else '-'):>12}"
              f"{(f'{statistics.median(cr):.0f}' if cr else '-'):>10}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
