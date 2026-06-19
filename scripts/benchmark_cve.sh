#!/bin/bash
# Preparation Overhead benchmark for a specific CVE target.
# Usage: ./scripts/benchmark_cve.sh <CVE-ID> <num_runs>
# Example: ./scripts/benchmark_cve.sh CVE-2019-7317 5

set -eo pipefail

CVE="${1:?Usage: $0 <CVE-ID> <num_runs>}"
NUM_RUNS="${2:?Usage: $0 <CVE-ID> <num_runs>}"

declare -A CVE_LIBRARY=(
  [CVE-2019-7317]=libpng
  [CVE-2015-0973]=libpng
  [CVE-2015-8472]=libpng
  [CVE-2013-6954]=libpng
  [CVE-2016-9535]=libtiff
  [CVE-2016-5314]=libtiff
  [CVE-2019-7663]=libtiff
  [CVE-2016-10269]=libtiff
  [CVE-2018-7456]=libtiff
  [CVE-2018-18557]=libtiff
  [CVE-2017-9047]=libxml2
  [CVE-2017-0663]=libxml2
  [CVE-2017-7375]=libxml2
  [CVE-2016-1836]=libxml2
  [CVE-2016-2108]=openssl
  [CVE-2016-2109]=openssl
  [CVE-2016-0797]=openssl
  [CVE-2016-7052]=openssl
  [CVE-2019-9936]=sqlite3
  [CVE-2019-19244]=sqlite3
  [CVE-2013-7443]=sqlite3
  [CVE-2019-19959]=sqlite3
  [CVE-2019-14494]=poppler
  [CVE-2019-9200]=poppler
  [CVE-2018-20650]=poppler
  [CVE-2017-9776]=poppler
  [CVE-2019-11034]=php
  [CVE-2019-9641]=php
  [CVE-2017-11362]=php
  [CVE-2018-7584]=php
)

LIBRARY="${CVE_LIBRARY[$CVE]}"
if [ -z "$LIBRARY" ]; then
  echo "Unknown CVE '$CVE'. Available:"
  printf '  %s\n' "${!CVE_LIBRARY[@]}" | sort
  exit 1
fi

if ! [[ "$NUM_RUNS" =~ ^[1-9][0-9]*$ ]]; then
  echo "num_runs must be a positive integer, got: $NUM_RUNS"
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIG="configs/magma/cve/$LIBRARY/$CVE.yml"
[ -f "$CONFIG" ] || { echo "Config not found: $CONFIG"; exit 1; }

RESULTS_DIR="$ROOT/workspace/$CVE/bench_overhead_$(date +%Y%m%d_%H%M%S)"
METRICS_DIR="$ROOT/logs/metric"

[ -f .env ] && { set -a; source .env; set +a; }

echo "=== MA-HybridFuzz Preparation Overhead Benchmark ==="
echo "CVE:     $CVE"
echo "Library: $LIBRARY"
echo "Runs:    $NUM_RUNS (concurrent, independent)"
echo "Results: $RESULTS_DIR"
echo ""

mkdir -p "$RESULTS_DIR" "$METRICS_DIR"
PIDS=()
RUN_DIRS=()

copy_metrics() {
  for i in "${!RUN_DIRS[@]}"; do
    run_num=$((i + 1))
    src="${RUN_DIRS[$i]}/logs/overhead_metrics.csv"
    if [ -f "$src" ]; then
      dest="$METRICS_DIR/${CVE}_run_${run_num}_overhead_metrics.csv"
      cp "$src" "$dest"
      echo "[bench] Metrics copied: $dest"
    else
      echo "[bench] No metrics CSV found for run $run_num (${src})"
    fi
  done
}

cleanup() {
  echo ""
  echo "[bench] Interrupted — killing background containers..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  copy_metrics
  exit 130
}
trap cleanup INT TERM

for i in $(seq 1 "$NUM_RUNS"); do
  RUN_DIR="$RESULTS_DIR/run_$i"
  mkdir -p "$RUN_DIR"
  RUN_DIRS+=("$RUN_DIR")

  echo "[bench] Starting run $i → $RUN_DIR"
  docker compose run --rm \
    -e MA_BENCHMARK_RUN_ID="$i" \
    --volume "$RUN_DIR:/workspace" \
    "magma-$LIBRARY" \
    python3 /opt/mahybridfuzz/src/orchestrator.py \
    -c "$CONFIG" \
    > "$RUN_DIR/orchestrator.log" 2>&1 &
  PIDS+=($!)
done

echo "[bench] All $NUM_RUNS instances running. Waiting for completion..."
echo ""

FAILED=0
for i in "${!PIDS[@]}"; do
  run_num=$((i + 1))
  if wait "${PIDS[$i]}"; then
    echo "[bench] Run $run_num finished (ok)"
  else
    echo "[bench] Run $run_num finished (FAILED)"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "=== Preparation Overhead Results ==="
echo ""

python3 - "${RUN_DIRS[@]}" <<'PYEOF'
import sys, csv
from pathlib import Path

run_dirs = sys.argv[1:]
for idx, run_dir in enumerate(run_dirs, 1):
    csv_path = Path(run_dir) / "logs" / "overhead_metrics.csv"
    print(f"Run {idx}  ({run_dir})")
    if not csv_path.exists():
        print(f"  [!] No metrics CSV found: {csv_path}")
        print()
        continue
    with open(csv_path) as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("  [!] Metrics CSV is empty")
        print()
        continue
    row = rows[-1]
    def fmt(val):
        return f"{float(val):.1f}s" if val not in ("", None) else "N/A"
    print(f"  Static analysis + CG time:       {fmt(row.get('static_analysis_time_s'))}")
    print(f"  Pre-phase LLM seed/mutator time: {fmt(row.get('llm_prephase_time_s'))}")
    print(f"  Total preparation time:          {fmt(row.get('total_prep_time_s'))}")
    print(f"  Cached:                          {row.get('cached', 'false')}")
    print(f"  Status:                          {row.get('status', '?')}")
    print()
PYEOF

copy_metrics

if [ "$FAILED" -gt 0 ]; then
  echo "=== Done ($FAILED run(s) failed) ==="
  exit 1
fi
echo "=== Done ==="
