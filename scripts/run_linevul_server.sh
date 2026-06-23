#!/bin/bash
# Start the LineVul attention-distance server on the VM HOST (outside Docker).
#
# The fuzzer containers no longer ship torch/transformers — the LLM fuzzers
# (deepseek/chatgpt) call this server during their pre-phase via
# host.docker.internal:<port>. run_benchmark.sh sets MA_LINEVUL_SERVER_URL for
# them automatically and health-checks this server before launching.
#
# One-time host setup:
#   python3 -m venv .venv-linevul && source .venv-linevul/bin/activate
#   pip install -r requirements-linevul.txt
#
# Usage:
#   ./scripts/run_linevul_server.sh            # foreground (use tmux/nohup to persist)
#   LINEVUL_PORT=8600 ./scripts/run_linevul_server.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${LINEVUL_PORT:-8501}"
# Weights + HF cache live under ./models on the host (same location setup_vm.sh
# prepares). The model auto-downloads here on first run via gdown.
export LINEVUL_WEIGHTS="${LINEVUL_WEIGHTS:-$ROOT/models/12heads_linevul_model.bin}"
export HF_HOME="${HF_HOME:-$ROOT/models/hf}"
# Cap CPU threads so the server doesn't thrash all cores while the fuzzers run.
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-2}"
mkdir -p "$ROOT/models/hf"

echo "[linevul] weights=$LINEVUL_WEIGHTS"
echo "[linevul] HF_HOME=$HF_HOME  OMP_NUM_THREADS=$OMP_NUM_THREADS"
echo "[linevul] starting server on 0.0.0.0:$PORT (Ctrl-C to stop)"
exec python3 inference/linevul_server.py --host 0.0.0.0 --port "$PORT"
