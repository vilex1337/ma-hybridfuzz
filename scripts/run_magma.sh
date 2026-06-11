#!/bin/bash
# Run MA-HybridFuzz against a magma benchmark target.
# Usage: ./scripts/run_magma.sh <target> [--build] [orchestrator_args...]
#   target   one of: libpng libtiff libxml2 openssl sqlite3 poppler php
#   --build  rebuild the Docker image before running
# Example: ./scripts/run_magma.sh libpng --verbosity 2

set -e

VALID_TARGETS="libpng libtiff libxml2 openssl sqlite3 poppler php"
TARGET="${1:?Usage: $0 <target> [--build] [orchestrator_args...]}"
shift

valid=0
for t in $VALID_TARGETS; do [ "$t" = "$TARGET" ] && valid=1 && break; done
[ "$valid" -eq 1 ] || { echo "Unknown target '$TARGET'. Valid: $VALID_TARGETS"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

if [ "${1:-}" = "--build" ]; then
    echo "[$TARGET] Building Docker image..."
    docker compose build "magma-$TARGET"
    shift
fi

echo "[$TARGET] Starting MA-HybridFuzz (magma benchmark)..."
docker compose run --rm "magma-$TARGET" \
    python3 /opt/mahybridfuzz/src/orchestrator.py \
    -c "configs/magma/$TARGET.yml" "$@"
