#!/bin/bash
# Entrypoint for AFLGo baseline containers. Mirrors the fuzzer.* settings
# from the corresponding configs/magma/cve/<lib>/<CVE>.yml so the baseline
# runs under the same budget as MA-HybridFuzz.
set -euo pipefail

: "${BINARY:?BINARY env var (path to instrumented harness) is required}"
: "${SEED_DIR:?SEED_DIR env var (initial corpus dir) is required}"

OUT_DIR="${OUT_DIR:-/aflgo-out}"
MEMORY_LIMIT="${MEMORY_LIMIT:-256}"
EXEC_TIMEOUT="${EXEC_TIMEOUT:-1000}"
CUTOFF="${CUTOFF:-30m}"
RUN_TIMEOUT="${RUN_TIMEOUT:-21600}"

mkdir -p "$OUT_DIR"
echo "[aflgo] binary=$BINARY seeds=$SEED_DIR out=$OUT_DIR mem=${MEMORY_LIMIT}MB exec_timeout=${EXEC_TIMEOUT}ms cutoff=$CUTOFF run_timeout=${RUN_TIMEOUT}s"

# Containers can't reliably control the host's cpufreq governor even when
# privileged, so skip AFL's (non-fatal but otherwise fuzzing-blocking) check.
export AFL_SKIP_CPUFREQ=1

# Magma seed corpora intentionally include historical PoCs for the target
# CVE; under ASAN these crash on calibration, which afl-fuzz otherwise
# treats as fatal. Skip them instead of aborting the whole run.
export AFL_SKIP_CRASHES=1

exec timeout --signal=INT "${RUN_TIMEOUT}" \
    "$AFLGO/afl-fuzz" -m "$MEMORY_LIMIT" -t "$EXEC_TIMEOUT" -z exp -c "$CUTOFF" \
    -i "$SEED_DIR" -o "$OUT_DIR" -- "$BINARY" @@
