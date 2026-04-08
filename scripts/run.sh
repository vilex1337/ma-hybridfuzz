#!/bin/bash
# MA-HybridFuzz Run Script
# Usage: ./scripts/run.sh [config_file]

set -e

CONFIG=${1:-configs/default.yml}

echo "=== MA-HybridFuzz ==="
echo "Config: $CONFIG"

# Load .env if exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Run with docker compose
docker compose run --rm fuzzer python3 src/orchestrator.py -c "$CONFIG"
