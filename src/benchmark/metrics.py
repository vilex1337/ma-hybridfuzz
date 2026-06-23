"""
BenchmarkMetrics — timing and event recorder for MA-HybridFuzz benchmarks.

Usage in orchestrator (or any pipeline stage):

    from benchmark.metrics import BenchmarkMetrics

    metrics = BenchmarkMetrics(config)
    metrics.start_phase("static_analysis")
    # ... FCC, attention, coverage build, AFL++ instrumentation ...
    metrics.end_phase("static_analysis")

    metrics.start_phase("llm_prephase")
    # ... seed gen, mutator gen ...
    metrics.end_phase("llm_prephase")

    metrics.set("cached", True)
    metrics.finish()          # logs + writes CSV row

Tracked phases (all optional — unrecorded phases get None in CSV):
    static_analysis   FCC extraction + attention SA + coverage binary + AFL++ instrumentation
    llm_prephase      bug info + function summary + seed generation + mutator generation
    fuzzing_loop      total active fuzzing time

Ad-hoc scalar metrics can be added with metrics.set(key, value).
"""

from __future__ import annotations

import csv
import logging
import os
import re
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from config import AppConfig

logger = logging.getLogger("benchmark.metrics")


class _CoverageChecker(Protocol):
    def check_reached_functions(
        self, binary: str, seed_file: str, candidate_functions: list[str]
    ) -> set[str]: ...


# Columns always present in every CSV row (in order)
_BASE_COLUMNS = [
    "timestamp",
    "session_id",
    "target",
    "target_function",
    "run_id",
    "static_analysis_time_s",
    "llm_prephase_time_s",
    "total_prep_time_s",
    "fuzzing_loop_time_s",
    "overhead_pct",
    "ttr_s",
    "tte_s",
    "unique_crashes",
    "edges_found",
    "bitmap_cvg",
    "fcc_coverage_pct",
    "llm_requests",
    "llm_input_tokens",
    "llm_output_tokens",
    "cached",
    "status",
]


class BenchmarkMetrics:
    """Records preparation overhead and other benchmark metrics, flushes to CSV."""

    def __init__(self, config: AppConfig, csv_path: str | Path | None = None):
        self._config = config
        self._phase_starts: dict[str, float] = {}
        self._phase_durations: dict[str, float] = {}
        self._extras: dict[str, Any] = {}
        self._timing: dict[str, float] = {}        # ttr_s, tte_s
        self._wall_phase_starts: dict[str, float] = {}
        self._total_start: float = time.monotonic()
        self._wall_total_start: float = time.time()
        self._status = "ok"

        # Output location & naming.
        #   - If MA_METRICS_DIR is set (benchmark mode), write a single-row file
        #     named  <cve>_<target>_<fuzzer>_run<id>.csv  into that (mounted)
        #     directory. The file is rewritten on every snapshot() so partial
        #     results survive an interrupted run, and finalised by finish().
        #   - Otherwise keep the legacy append-mode logs/overhead_metrics.csv.
        self._single_row = False
        metrics_dir = os.getenv("MA_METRICS_DIR")
        if csv_path:
            self._csv_path = Path(csv_path)
        elif metrics_dir:
            cve = os.getenv("MA_CVE_ID", "").strip()
            fuzzer = os.getenv("MA_FUZZER_LABEL", "").strip()
            run_id = os.getenv("MA_BENCHMARK_RUN_ID", "").strip()
            target = config.target.target_function or Path(config.target.binary).stem
            parts = [p for p in (cve, target, fuzzer, f"run{run_id}" if run_id else "") if p]
            self._csv_path = Path(metrics_dir) / f"{'_'.join(parts) or 'metrics'}.csv"
            self._single_row = True
        else:
            self._csv_path = Path(config.paths.logs) / "overhead_metrics.csv"
        self._csv_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Phase timing ──────────────────────────────────────────────────────────

    def start_phase(self, phase: str) -> None:
        self._phase_starts[phase] = time.monotonic()
        self._wall_phase_starts[phase] = time.time()
        logger.debug("[Metrics] start_phase: %s", phase)

    def end_phase(self, phase: str) -> float:
        """Stop timing *phase* and return elapsed seconds."""
        start = self._phase_starts.pop(phase, None)
        if start is None:
            logger.warning("[Metrics] end_phase called without matching start_phase: %s", phase)
            return 0.0
        elapsed = time.monotonic() - start
        self._phase_durations[phase] = elapsed
        logger.info("[Metrics] %s completed in %.2fs", phase, elapsed)
        return elapsed

    # ── Ad-hoc scalar values ─────────────────────────────────────────────────

    def set(self, key: str, value: Any) -> None:
        self._extras[key] = value

    def mark_error(self, msg: str = "") -> None:
        self._status = f"error: {msg}" if msg else "error"

    def mark_cached(self) -> None:
        self._extras["cached"] = True

    # ── Effectiveness metrics ─────────────────────────────────────────────────

    @property
    def has_ttr(self) -> bool:
        return "ttr_s" in self._timing

    @property
    def has_tte(self) -> bool:
        return "tte_s" in self._timing

    def poll_canary(self, storage_path: str | Path, bug_id: str, elapsed_s: float) -> None:
        """
        Record TTR/TTE from Magma's canary shared-memory file (reach/trigger
        counters written synchronously by MAGMA_LOG, see canary_reader.py).
        Unlike poll_ttr/poll_tte's queue-scan, this survives the bug-triggering
        input crashing the process, since the write happens before the fault.
        No-op once both are recorded, or if the bug isn't found yet.
        """
        if self.has_ttr and self.has_tte:
            return
        from benchmark.canary_reader import read_canary
        result = read_canary(storage_path, bug_id)
        if result is None:
            return
        reached, triggered = result
        if reached > 0 and not self.has_ttr:
            self._timing["ttr_s"] = round(elapsed_s, 3)
            logger.info("[Metrics] TTR recorded via canary: %.2fs", elapsed_s)
        if triggered > 0 and not self.has_tte:
            self._timing["tte_s"] = round(elapsed_s, 3)
            logger.info("[Metrics] TTE recorded via canary: %.2fs", elapsed_s)

    def poll_tte(self, crashes_dir: str | Path) -> None:
        """Scan AFL++ crash files; record TTE from the earliest crash filename's time: field.

        AFL++ names crashes: id:NNNNNN,sig:NN,...,time:MMMMMM,... where time is ms
        since fuzzing started. Falls back to the file's mtime relative to the
        fuzzing_loop phase start when the field is absent.
        No-op once TTE has been recorded.
        """
        if self.has_tte:
            return
        output_dir = Path(crashes_dir)
        crash_files = list(output_dir.rglob("crashes/id:*")) if output_dir.exists() else []
        if not crash_files:
            return
        earliest_ms: int | None = None
        for f in crash_files:
            m = re.search(r",time:(\d+)", f.name)
            if m:
                ms = int(m.group(1))
                if earliest_ms is None or ms < earliest_ms:
                    earliest_ms = ms
        if earliest_ms is not None:
            self._timing["tte_s"] = round(earliest_ms / 1000.0, 3)
        else:
            fuzz_wall_start = self._wall_phase_starts.get("fuzzing_loop") or self._wall_total_start
            oldest = min(crash_files, key=lambda f: f.stat().st_mtime)
            self._timing["tte_s"] = round(max(oldest.stat().st_mtime - fuzz_wall_start, 0.0), 3)
        logger.info("[Metrics] TTE recorded: %.2fs", self._timing["tte_s"])

    def compute_imr(
        self,
        coverage_checker: _CoverageChecker,
        binary: str,
        fcc: list[str],
        output_dir: str,
    ) -> float | None:
        """Scan all final AFL++ queue entries and compute Ineffective Mutation Rate.

        IMR = 1 - (queue entries reaching any FCC function) / total queue entries

        Runs the LLVM coverage binary once per queue entry (post-hoc, after fuzzing).
        Records the result as "imr" via self.set().
        """
        queue_files = list(Path(output_dir).rglob("queue/id:*"))
        if not queue_files:
            logger.warning("[Metrics] IMR: no queue entries found in %s", output_dir)
            return None

        total = len(queue_files)
        reaching = 0
        covered_fcc_fns: set[str] = set()
        for entry in queue_files:
            try:
                reached = coverage_checker.check_reached_functions(
                    binary=binary,
                    seed_file=str(entry),
                    candidate_functions=fcc,
                )
                if reached:
                    reaching += 1
                covered_fcc_fns.update(reached & set(fcc))
            except Exception as exc:
                logger.debug("[Metrics] IMR coverage check failed for %s: %s", entry.name, exc)

        imr = round(1.0 - reaching / total, 4)
        logger.info(
            "[Metrics] IMR: %.4f (%d/%d queue entries reached toward target)",
            imr, reaching, total,
        )
        self.set("imr", imr)
        self.set("imr_queue_total", total)
        self.set("imr_reaching", reaching)

        if fcc:
            fcc_cov = round(len(covered_fcc_fns) / len(fcc), 4)
            logger.info(
                "[Metrics] FCC coverage: %.4f (%d/%d functions covered)",
                fcc_cov, len(covered_fcc_fns), len(fcc),
            )
            self.set("fcc_coverage_pct", fcc_cov)

        return imr

    def poll_ttr(
        self,
        coverage_checker: _CoverageChecker,
        binary: str,
        target_fn: str,
        fcc: list[str],
        crashes_dir: str | Path,
        elapsed_s: float,
    ) -> None:
        """Check if the target function was reached by the latest queue entry; record TTR.

        Finds the most-recently-modified AFL++ queue entry under *crashes_dir*,
        runs a coverage check, and records TTR if *target_fn* is in the reached set.
        No-op once TTR has been recorded or when no queue entries exist yet.
        """
        if self.has_ttr:
            return
        if not target_fn or not fcc:
            return
        latest = _latest_queue_entry(crashes_dir)
        if latest is None:
            return
        try:
            reached = coverage_checker.check_reached_functions(
                binary=binary,
                seed_file=str(latest),
                candidate_functions=fcc,
            )
        except Exception as exc:
            logger.debug("[Metrics] TTR coverage check failed: %s", exc)
            return
        if target_fn in reached:
            self._timing["ttr_s"] = round(elapsed_s, 3)
            logger.info("[Metrics] TTR recorded: %.2fs", elapsed_s)

    # ── Derived metrics ───────────────────────────────────────────────────────

    @property
    def total_prep_time_s(self) -> float | None:
        sa  = self._phase_durations.get("static_analysis")
        llm = self._phase_durations.get("llm_prephase")
        if sa is None and llm is None:
            return None
        return (sa or 0.0) + (llm or 0.0)

    @property
    def overhead_pct(self) -> float | None:
        prep = self.total_prep_time_s
        fuzz = self._phase_durations.get("fuzzing_loop")
        if prep is None or fuzz is None:
            return None
        total = prep + fuzz
        return round(prep / total * 100, 2) if total > 0 else None

    # ── Finalise and write ────────────────────────────────────────────────────

    def finish(self) -> None:
        """Log a summary and append one row to the CSV."""
        sa   = self._phase_durations.get("static_analysis")
        llm  = self._phase_durations.get("llm_prephase")
        fuzz = self._phase_durations.get("fuzzing_loop")
        total_prep = self.total_prep_time_s

        logger.info("=== Preparation Overhead ===")
        logger.info("  Static analysis + CG:       %s", _fmt(sa))
        logger.info("  Pre-phase LLM seed/mutator: %s", _fmt(llm))
        logger.info("  Total preparation:          %s", _fmt(total_prep))
        if fuzz is not None:
            logger.info("  Fuzzing loop duration:      %s", _fmt(fuzz))
        if self.overhead_pct is not None:
            logger.info("  Overhead %%:                 %.2f%%", self.overhead_pct)
        logger.info("  Time-to-Reach (TTR):        %s", _fmt(self._timing.get("ttr_s")))
        logger.info("  Time-to-Exposure (TTE):     %s", _fmt(self._timing.get("tte_s")))

        row = self._build_row(sa, llm, total_prep, fuzz)
        self._append_csv(row)
        logger.info("[Metrics] Row written to %s", self._csv_path)

    def snapshot(self, extras: dict[str, Any] | None = None) -> None:
        """Rewrite the metrics file with the current in-progress state.

        Lets partial results (TTR/TTE/coverage/crashes/tokens so far) survive a
        run that is killed before finish(). Active only in single-row benchmark
        mode (MA_METRICS_DIR set); a no-op otherwise.
        """
        if not self._single_row:
            return
        if extras:
            self._extras.update(extras)
        fz_start = self._phase_starts.get("fuzzing_loop")
        if fz_start is not None:
            self._extras["fuzzing_elapsed_s"] = round(time.monotonic() - fz_start, 1)
        row = self._build_row(
            self._phase_durations.get("static_analysis"),
            self._phase_durations.get("llm_prephase"),
            self.total_prep_time_s,
            None,                       # fuzzing not finished yet
            complete=False,
        )
        self._write_row(row, overwrite=True)

    def _build_row(
        self,
        sa: float | None,
        llm: float | None,
        total_prep: float | None,
        fuzz: float | None,
        complete: bool = True,
    ) -> dict[str, Any]:
        row: dict[str, Any] = {
            "timestamp":              datetime.now(timezone.utc).isoformat(),
            "session_id":             self._config.inference_session_id,
            "target":                 Path(self._config.target.binary).stem,
            "target_function":        self._config.target.target_function,
            "run_id":                 os.getenv("MA_BENCHMARK_RUN_ID", ""),
            "static_analysis_time_s": _round(sa),
            "llm_prephase_time_s":    _round(llm),
            "total_prep_time_s":      _round(total_prep),
            "fuzzing_loop_time_s":    _round(fuzz),
            "overhead_pct":           _round(self.overhead_pct),
            "ttr_s":                  _round(self._timing.get("ttr_s")),
            "tte_s":                  _round(self._timing.get("tte_s")),
            "cached":                 self._extras.get("cached", False),
            "status":                 self._status,
        }
        # append any extra keys set via .set() (do NOT mutate self._extras —
        # snapshot() may be called many times over the run)
        row.update(self._extras)

        # Derived token metrics: total + per-hour rates (using final fuzzing
        # duration when complete, else the live elapsed time).
        in_tok = _num(row.get("llm_input_tokens"))
        out_tok = _num(row.get("llm_output_tokens"))
        if in_tok is not None and out_tok is not None:
            total = in_tok + out_tok
            row["total_tokens"] = total
            dur = fuzz if fuzz is not None else _num(self._extras.get("fuzzing_elapsed_s"))
            hours = dur / 3600.0 if dur and dur > 0 else None
            if hours:
                row["input_tokens_per_hour"] = round(in_tok / hours, 2)
                row["output_tokens_per_hour"] = round(out_tok / hours, 2)
                row["total_tokens_per_hour"] = round(total / hours, 2)
        row["complete"] = complete
        return row

    def _append_csv(self, row: dict[str, Any]) -> None:
        self._write_row(row, overwrite=self._single_row)

    def _write_row(self, row: dict[str, Any], overwrite: bool = False) -> None:
        # Column order: base columns first, then any extras in sorted order.
        extra_keys = sorted(k for k in row if k not in _BASE_COLUMNS)
        fieldnames = _BASE_COLUMNS + extra_keys
        mode = "w" if overwrite else "a"
        write_header = overwrite or not self._csv_path.exists() or self._csv_path.stat().st_size == 0
        with open(self._csv_path, mode, newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            if write_header:
                writer.writeheader()
            writer.writerow(row)


# ── helpers ───────────────────────────────────────────────────────────────────

def _fmt(seconds: float | None) -> str:
    if seconds is None:
        return "N/A"
    return f"{seconds:.2f}s"


def _round(value: float | None) -> float | str:
    if value is None:
        return ""
    return round(value, 3)


def _num(value: Any) -> float | None:
    """Coerce a value to float, or None if not numeric/empty."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def aggregate_runs(csv_paths: list[str | Path]) -> dict[str, Any]:
    """Read one CSV per run and return mean/median/stddev for numeric fields.

    Returns a dict keyed by field name, each value a dict with:
        mean, median, stdev, min, max, n  (stdev is None when n < 2)

    Non-numeric fields and rows with missing values are skipped per field.

    Example::

        stats = aggregate_runs(["run1/overhead_metrics.csv", "run2/overhead_metrics.csv"])
        print(stats["ttr_s"])   # {"mean": 42.1, "median": 41.5, "stdev": 1.3, ...}
    """
    # Collect the last row from each CSV (most recent measurement per run)
    rows: list[dict[str, str]] = []
    for path in csv_paths:
        p = Path(path)
        if not p.exists():
            continue
        with open(p, newline="") as f:
            all_rows = list(csv.DictReader(f))
        if all_rows:
            rows.append(all_rows[-1])

    if not rows:
        return {}

    # Gather all numeric column names
    numeric_fields: set[str] = set()
    for row in rows:
        for k, v in row.items():
            if v not in ("", None):
                try:
                    float(v)
                    numeric_fields.add(k)
                except ValueError:
                    pass

    result: dict[str, Any] = {}
    for field in sorted(numeric_fields):
        values = []
        for row in rows:
            raw = row.get(field, "")
            if raw not in ("", None):
                try:
                    values.append(float(raw))
                except ValueError:
                    pass
        if not values:
            continue
        result[field] = {
            "mean":   round(statistics.mean(values), 3),
            "median": round(statistics.median(values), 3),
            "stdev":  round(statistics.stdev(values), 3) if len(values) >= 2 else None,
            "min":    round(min(values), 3),
            "max":    round(max(values), 3),
            "n":      len(values),
        }
    return result


def print_aggregate_summary(csv_paths: list[str | Path]) -> None:
    """Print a human-readable aggregate summary across runs to stdout."""
    stats = aggregate_runs(csv_paths)
    if not stats:
        print("  [!] No data to aggregate")
        return

    focus = ["ttr_s", "tte_s", "total_prep_time_s", "fuzzing_loop_time_s", "overhead_pct"]
    labels = {
        "ttr_s":               "TTR",
        "tte_s":               "TTE",
        "total_prep_time_s":   "Total prep time",
        "fuzzing_loop_time_s": "Fuzzing loop time",
        "overhead_pct":        "Overhead %",
    }

    print(f"  {'Metric':<24} {'Mean':>10} {'Median':>10} {'Stdev':>10} {'Min':>10} {'Max':>10}  n")
    print("  " + "-" * 80)
    for field in focus:
        if field not in stats:
            continue
        s = stats[field]
        unit = "%" if field == "overhead_pct" else "s"
        stdev_str = f"{s['stdev']:.2f}{unit}" if s["stdev"] is not None else "  N/A"
        print(
            f"  {labels[field]:<24}"
            f" {s['mean']:>9.2f}{unit}"
            f" {s['median']:>9.2f}{unit}"
            f" {stdev_str:>10}"
            f" {s['min']:>9.2f}{unit}"
            f" {s['max']:>9.2f}{unit}"
            f"  {s['n']}"
        )


def _latest_queue_entry(crashes_dir: str | Path) -> Path | None:
    """Return the most-recently-modified AFL++ queue entry, or None."""
    output_dir = Path(crashes_dir)
    if not output_dir.exists():
        return None
    queue_files = list(output_dir.rglob("queue/id:*"))
    if not queue_files:
        return None
    return max(queue_files, key=lambda f: f.stat().st_mtime)
