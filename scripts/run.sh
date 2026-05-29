#!/bin/bash
# MA-HybridFuzz Run Script
# Usage: ./scripts/run.sh [config_file] [orchestrator_args...]
# Example: ./scripts/run.sh configs/default.yml --verbosity 2

set -e

CONFIG=${1:-configs/default.yml}
EXTRA_ARGS=()
if [[ "${1:-}" == -* ]]; then
    CONFIG=configs/default.yml
    EXTRA_ARGS=("$@")
elif [[ $# -gt 0 ]]; then
    shift
    EXTRA_ARGS=("$@")
fi

echo "=== MA-HybridFuzz ==="
echo "Config: $CONFIG"

# Load .env if exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Run with docker compose
docker compose run --rm fuzzer python3 src/orchestrator.py -c "$CONFIG" "${EXTRA_ARGS[@]}"
