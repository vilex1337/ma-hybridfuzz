#!/bin/bash
# Run MA-HybridFuzz against the jsoncpp_jsoncpp_fuzzer target.
# Usage: ./scripts/run_jsoncpp.sh [--build]
#   --build   rebuild the Docker image before running (useful after code changes)

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

if [ "$1" = "--build" ]; then
    echo "[jsoncpp] Building Docker image..."
    docker compose build jsoncpp
fi

echo "[jsoncpp] Starting MA-HybridFuzz (target: jsoncpp_jsoncpp_fuzzer)..."
docker compose run --rm jsoncpp
