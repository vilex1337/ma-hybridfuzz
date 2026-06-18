#!/bin/bash
# MA-HybridFuzz benchmark driver.
#
# Runs the full benchmark matrix for ONE fuzzer over selected Magma CVE targets,
# N replicate runs each, ~6h per run, with bounded parallelism and resume.
#
# Usage:
#   ./scripts/run_benchmark.sh --fuzzer <deepseek|chatgpt|baseline> \
#       [--cve <CVE-ID|all>] [--runs 5] [--parallel 3] \
#       [--timeout 21600] [--build] [--no-resume] [--list]
#
# Examples:
#   ./scripts/run_benchmark.sh --fuzzer baseline --cve all --runs 5 --parallel 3
#   ./scripts/run_benchmark.sh --fuzzer deepseek --cve CVE-2019-7317 --runs 5
#   ./scripts/run_benchmark.sh --fuzzer chatgpt  --cve all --parallel 2
#
# Resume is ON by default: completed (cve,run) jobs are skipped; crashed/partial
# jobs are re-run cleanly from scratch (each completed run is a clean 6h sample).
#
# Provider wiring (set keys in .env):
#   deepseek : cliproxy → DEEPSEEK_BASE_URL (default https://api.deepseek.com),
#              DEEPSEEK_MODEL (default deepseek-reasoner), DEEPSEEK_API_KEY
#   chatgpt  : cliproxy → CLIPROXY_BASE_URL (default http://host.docker.internal:8317/v1),
#              CHATGPT_MODEL (default gpt-5.5), CLIPROXY_API_KEY,
#              host-side health check at CLIPROXY_HEALTH_URL (default http://127.0.0.1:8317/v1/models)
#   baseline : plain AFL++ (orchestrator --baseline), seeded from the Magma corpus.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── defaults ─────────────────────────────────────────────────────────────────
FUZZER=""
CVE="all"
RUNS=5
RUN_START=1            # first replicate id; lets you shard ids across launches/VMs
PARALLEL=3
TIMEOUT=21600          # 6h per run; orchestrator reads fuzzer.timeout from config,
                       # this is only used to pass MA override if you lower it.
BUILD=0
RESUME=1
LIST_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fuzzer)   FUZZER="${2:?}"; shift 2 ;;
        --cve)      CVE="${2:?}"; shift 2 ;;
        --runs)     RUNS="${2:?}"; shift 2 ;;
        --run-start) RUN_START="${2:?}"; shift 2 ;;
        --parallel) PARALLEL="${2:?}"; shift 2 ;;
        --timeout)  TIMEOUT="${2:?}"; shift 2 ;;
        --build)    BUILD=1; shift ;;
        --no-resume) RESUME=0; shift ;;
        --list)     LIST_ONLY=1; shift ;;
        -h|--help)  sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

case "$FUZZER" in
    deepseek|chatgpt|openai|baseline) ;;
    *) echo "Error: --fuzzer must be one of deepseek|chatgpt|openai|baseline"; exit 1 ;;
esac
[[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || { echo "--runs must be a positive integer"; exit 1; }
[[ "$RUN_START" =~ ^[1-9][0-9]*$ ]] || { echo "--run-start must be a positive integer"; exit 1; }
[[ "$PARALLEL" =~ ^[1-9][0-9]*$ ]] || { echo "--parallel must be a positive integer"; exit 1; }
RUN_END=$((RUN_START + RUNS - 1))

[ -f .env ] && { set -a; source .env; set +a; }

# ── discover CVE configs ─────────────────────────────────────────────────────
declare -a CONFIGS
if [ "$CVE" = "all" ]; then
    while IFS= read -r -d '' f; do CONFIGS+=("$f"); done \
        < <(find configs/magma/cve -name 'CVE-*.yml' -print0 | sort -z)
else
    f="$(find configs/magma/cve -name "$CVE.yml" | head -1)"
    [ -n "$f" ] || { echo "CVE config not found for $CVE under configs/magma/cve/"; exit 1; }
    CONFIGS+=("$f")
fi
[ "${#CONFIGS[@]}" -gt 0 ] || { echo "No CVE configs found."; exit 1; }

# Helpers to derive metadata from a config path/contents.
lib_of()    { basename "$(dirname "$1")"; }              # configs/magma/cve/<lib>/CVE.yml
cve_of()    { basename "$1" .yml; }
binstem_of(){ grep -E '^\s*binary:' "$1" | head -1 | sed -E 's/.*"(.*)".*/\1/' | xargs basename; }

if [ "$LIST_ONLY" -eq 1 ]; then
    echo "Fuzzer: $FUZZER | runs: $RUNS | parallel: $PARALLEL"
    echo "Targets (${#CONFIGS[@]}):"
    for c in "${CONFIGS[@]}"; do echo "  $(cve_of "$c")  [$(lib_of "$c")]"; done
    exit 0
fi

# ── provider preflight + env wiring ──────────────────────────────────────────
PROVIDER_ENV=()
case "$FUZZER" in
    deepseek)
        : "${DEEPSEEK_API_KEY:?Set DEEPSEEK_API_KEY in .env}"
        PROVIDER_ENV=(
            -e "MA_LLM_PROVIDER=cliproxy"
            -e "MA_LLM_BASE_URL=${DEEPSEEK_BASE_URL:-https://api.deepseek.com}"
            -e "MA_LLM_MODEL=${DEEPSEEK_MODEL:-deepseek-reasoner}"
            -e "MA_LLM_API_KEY=${DEEPSEEK_API_KEY}"
            -e "MA_LLM_MAX_TOKENS=${DEEPSEEK_MAX_TOKENS:-0}"   # 0 = no cap (R1 needs room)
        )
        ;;
    chatgpt|openai)
        # Direct OpenAI API (teacher-provided key). The openai provider reads
        # OPENAI_API_KEY from the environment. Default model is a reasoning model
        # (o4-mini); set OPENAI_MODEL to the exact id your key supports.
        : "${OPENAI_API_KEY:?Set OPENAI_API_KEY in .env}"
        PROVIDER_ENV=(
            -e "MA_LLM_PROVIDER=openai"
            -e "MA_LLM_MODEL=${OPENAI_MODEL:-o4-mini}"
            -e "OPENAI_API_KEY=${OPENAI_API_KEY}"
        )
        # Default to no output cap (0) so reasoning tokens aren't truncated and
        # you can measure real consumption. Set OPENAI_MAX_TOKENS to a number to cap.
        PROVIDER_ENV+=( -e "MA_LLM_MAX_TOKENS=${OPENAI_MAX_TOKENS:-0}" )
        ;;
    baseline)
        PROVIDER_ENV=()   # no LLM
        ;;
esac

RESULTS_ROOT="$ROOT/workspace/bench/$FUZZER"   # raw AFL output + logs per run
METRICS_DIR="$ROOT/results/$FUZZER"            # aggregated outputs
RAW_DIR="$METRICS_DIR/raw"                      # one named CSV per run (durable)
mkdir -p "$RESULTS_ROOT" "$RAW_DIR" "$ROOT/models/hf"

echo "=== MA-HybridFuzz Benchmark ==="
echo "Fuzzer:   $FUZZER"
echo "Targets:  ${#CONFIGS[@]} CVE(s)  ×  $RUNS run(s) (ids $RUN_START-$RUN_END)  = $(( ${#CONFIGS[@]} * RUNS )) jobs"
echo "Parallel: $PARALLEL   Resume: $([ $RESUME -eq 1 ] && echo on || echo off)"
echo "Per-run:  $RAW_DIR"
echo ""

# ── job completion check ─────────────────────────────────────────────────────
# A run counts as done only when its named metrics CSV shows it fuzzed ~the full
# budget (>= 95% of TIMEOUT). This rejects runs cut short by reboot/Ctrl-C/OOM
# (which leave a partial snapshot) and skips genuinely-complete ones on resume.
# Args: <cve> <run_id>.  The named file is <cve>_<target>_<fuzzer>_run<id>.csv
# (target unknown here, so glob it).
metrics_file_for() {
    ls "$RAW_DIR/${1}_"*"_${FUZZER}_run${2}.csv" 2>/dev/null | head -1
}
job_is_done() {
    local f; f="$(metrics_file_for "$1" "$2")"
    [ -n "$f" ] && [ -f "$f" ] || return 1
    MA_MIN_FUZZ="$TIMEOUT" python3 - "$f" <<'PY'
import csv, os, sys
need = float(os.environ.get("MA_MIN_FUZZ", "0")) * 0.95
try:
    rows = list(csv.DictReader(open(sys.argv[1])))
except Exception:
    sys.exit(1)
if not rows:
    sys.exit(1)
v = (rows[-1].get("fuzzing_loop_time_s") or "").strip()
try:
    sys.exit(0 if float(v) >= need else 1)
except ValueError:
    sys.exit(1)
PY
}

# ── one job ──────────────────────────────────────────────────────────────────
run_one() {
    local config="$1" run_i="$2"
    local lib cve run_dir cname seed_mount=()
    lib="$(lib_of "$config")"
    cve="$(cve_of "$config")"
    run_dir="$RESULTS_ROOT/$cve/run_$run_i"
    cname="bench_${FUZZER}_${cve}_run${run_i}"

    if [ "$RESUME" -eq 1 ] && job_is_done "$cve" "$run_i"; then
        echo "[bench] SKIP (done): $cve run $run_i"
        return 0
    fi

    # Clean restart for a clean 6h sample.
    rm -rf "$run_dir"
    mkdir -p "$run_dir/logs"
    echo "running" > "$run_dir/STATUS"

    # Per-fuzzer extra mounts/env.
    local extra=()
    if [ "$FUZZER" = "baseline" ]; then
        local binstem corpus
        binstem="$(binstem_of "$config")"
        corpus="$ROOT/magma/targets/$lib/corpus/$binstem"
        if [ -d "$corpus" ]; then
            extra+=( --volume "$corpus:/magma_seeds:ro" -e "MA_BASELINE_SEED_DIR=/magma_seeds" )
        else
            echo "[bench] WARNING: baseline seed corpus not found: $corpus (will use minimal seed)"
        fi
    else
        # LLM fuzzers run local LineVul → mount the model cache, point HF + weights there.
        # Cap CPU threads (model + BLAS) so parallel pre-phases don't thrash 4 cores;
        # the model is freed after pre-phase so the 6h loop is light.
        extra+=(
            --volume "$ROOT/models:/models"
            -e "HF_HOME=/models/hf"
            -e "LINEVUL_WEIGHTS=/models/12heads_linevul_model.bin"
            -e "LINEVUL_THREADS=${LINEVUL_THREADS:-2}"
            -e "OMP_NUM_THREADS=${OMP_NUM_THREADS:-2}"
        )
        # Optional hard RAM cap per container (e.g. BENCH_MEM_LIMIT=2.5g).
        [ -n "${BENCH_MEM_LIMIT:-}" ] && extra+=( --memory "$BENCH_MEM_LIMIT" )
    fi

    local orch_args=( -c "$config" --verbosity 1 --force-restart )
    [ "$FUZZER" = "baseline" ] && orch_args+=( --baseline )

    echo "[bench] START: $cve run $run_i  (lib=$lib)"
    docker compose run --rm --name "$cname" \
        -e "MA_BENCHMARK_RUN_ID=$run_i" \
        -e "MA_FUZZER_LABEL=$FUZZER" \
        -e "MA_FUZZER_TIMEOUT=$TIMEOUT" \
        -e "MA_CVE_ID=$cve" \
        -e "MA_METRICS_DIR=/metrics" \
        --volume "$RAW_DIR:/metrics" \
        "${PROVIDER_ENV[@]}" "${extra[@]}" \
        --volume "$run_dir:/workspace" \
        "magma-$lib" \
        python3 /opt/mahybridfuzz/src/orchestrator.py "${orch_args[@]}" \
        > "$run_dir/orchestrator.log" 2>&1

    if job_is_done "$cve" "$run_i"; then
        echo "done" > "$run_dir/STATUS"
        echo "[bench] DONE:  $cve run $run_i"
    else
        echo "failed" > "$run_dir/STATUS"
        echo "[bench] FAIL:  $cve run $run_i (see $run_dir/orchestrator.log)"
    fi
}

# ── graceful shutdown: TERM running containers so orchestrator writes metrics ─
RUNNING_NAMES=()
cleanup() {
    echo ""
    echo "[bench] Interrupted — sending TERM to running containers (metrics will flush)..."
    docker ps --filter "name=bench_${FUZZER}_" --format '{{.Names}}' \
        | while read -r n; do docker kill --signal=TERM "$n" 2>/dev/null || true; done
    wait 2>/dev/null || true
    exit 130
}
trap cleanup INT TERM

# ── scheduler: bounded parallelism over (cve × run) ──────────────────────────
if [ "$BUILD" -eq 1 ]; then
    for lib in $(printf '%s\n' "${CONFIGS[@]}" | while read -r c; do lib_of "$c"; done | sort -u); do
        echo "[bench] Building magma-$lib ..."
        docker compose build "magma-$lib"
    done
fi

active=0
for config in "${CONFIGS[@]}"; do
    for i in $(seq "$RUN_START" "$RUN_END"); do
        run_one "$config" "$i" &
        active=$((active + 1))
        if [ "$active" -ge "$PARALLEL" ]; then
            wait -n 2>/dev/null || wait    # bash<4.3 fallback: drain all
            active=$((active - 1))
        fi
    done
done
wait

echo ""
echo "[bench] All jobs finished. Aggregating metrics..."
python3 scripts/aggregate_metrics.py "$RAW_DIR" --fuzzer "$FUZZER" --out "$METRICS_DIR"
echo "[bench] Per-run CSVs: $RAW_DIR"
echo "[bench] Master CSV + summary in: $METRICS_DIR"
