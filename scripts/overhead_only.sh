#!/bin/bash
# Preparation Overhead benchmark for a magma target.
# Usage: ./scripts/benchmark.sh <target> <num_runs>
#   target    one of: libpng libtiff libxml2 openssl sqlite3 poppler php
#   num_runs  number of independent concurrent instances to run
# Example: ./scripts/benchmark.sh libxml2 2
#
# Metrics reported per run (written by BenchmarkMetrics to overhead_metrics.csv):
#   - Static analysis + CG construction time
#   - Pre-phase LLM seed/mutator generation time
#   - Total preparation time

set -eo pipefail

VALID_TARGETS="libpng libtiff libxml2 openssl sqlite3 poppler php"
TARGET="${1:?Usage: $0 <target> <num_runs>}"
NUM_RUNS="${2:?Usage: $0 <target> <num_runs>}"

valid=0
for t in $VALID_TARGETS; do [ "$t" = "$TARGET" ] && valid=1 && break; done
[ "$valid" -eq 1 ] || { echo "Unknown target '$TARGET'. Valid: $VALID_TARGETS"; exit 1; }

if ! [[ "$NUM_RUNS" =~ ^[1-9][0-9]*$ ]]; then
    echo "num_runs must be a positive integer, got: $NUM_RUNS"
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="$ROOT/workspace/$TARGET/bench_overhead_$(date +%Y%m%d_%H%M%S)"
METRICS_DIR="$ROOT/logs/metric"

[ -f .env ] && { set -a; source .env; set +a; }

echo "=== MA-HybridFuzz Preparation Overhead Benchmark ==="
echo "Target:  magma/$TARGET"
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
            dest="$METRICS_DIR/${TARGET}_run_${run_num}_overhead_metrics.csv"
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

# Launch each run in background with its own isolated workspace
for i in $(seq 1 "$NUM_RUNS"); do
    RUN_DIR="$RESULTS_DIR/run_$i"
    mkdir -p "$RUN_DIR"
    RUN_DIRS+=("$RUN_DIR")

    echo "[bench] Starting run $i → $RUN_DIR"
    docker compose run --rm \
        -e MA_BENCHMARK_RUN_ID="$i" \
        --volume "$RUN_DIR:/workspace" \
        "magma-$TARGET" \
        python3 /opt/mahybridfuzz/src/orchestrator.py \
        -c "configs/magma/$TARGET.yml" \
        --overhead-only \
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

# Print metrics from the CSV written by BenchmarkMetrics
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
