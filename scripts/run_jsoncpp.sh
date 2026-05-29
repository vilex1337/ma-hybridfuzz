#!/bin/bash
# Run MA-HybridFuzz against the jsoncpp_jsoncpp_fuzzer target.
# Usage: ./scripts/run_jsoncpp.sh [--build] [orchestrator_args...]
#   --build   rebuild the Docker image before running (useful after code changes)
# Example: ./scripts/run_jsoncpp.sh --verbosity 2

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT"

# Load .env if present
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

if [ "${1:-}" = "--build" ]; then
    echo "[jsoncpp] Building Docker image..."
    docker compose build jsoncpp
    shift
fi

echo "[jsoncpp] Starting MA-HybridFuzz (target: jsoncpp_jsoncpp_fuzzer)..."
docker compose run --rm jsoncpp python3 /opt/mahybridfuzz/src/orchestrator.py -c configs/jsoncpp.yml "$@"
