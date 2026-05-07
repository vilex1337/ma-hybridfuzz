#!/bin/bash
# MA-HybridFuzz Setup Script
# Usage: ./scripts/setup.sh

set -e

echo "=== MA-HybridFuzz Setup ==="

# Check dependencies
command -v docker >/dev/null 2>&1 || { echo "Error: docker is required but not installed."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || command -v docker compose >/dev/null 2>&1 || { echo "Error: docker-compose is required but not installed."; exit 1; }

# Create workspace directories
echo "[1/3] Creating workspace directories..."
mkdir -p workspace/{corpus,crashes,mutators,distance_cache,coverage,logs,memory,instrumented}

# Check for API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    if [ -f .env ]; then
        echo "[INFO] Loading .env file..."
        export $(grep -v '^#' .env | xargs)
    else
        echo "[WARN] ANTHROPIC_API_KEY not set. Create a .env file:"
        echo '  echo "ANTHROPIC_API_KEY=your-key-here" > .env'
    fi
fi

# Build Docker image
echo "[2/3] Building Docker image..."
docker compose build

echo "[3/3] Setup complete!"
echo ""
echo "Usage:"
echo "  1. Set your API key:  echo 'ANTHROPIC_API_KEY=sk-...' > .env"
echo "  2. Edit config:       configs/default.yml"
echo "  3. Run fuzzer:        docker compose up"
echo "  4. View results:      ls workspace/crashes/"
echo ""
echo "Quick start with a target:"
echo "  docker compose run fuzzer python3 src/orchestrator.py -c configs/default.yml"
