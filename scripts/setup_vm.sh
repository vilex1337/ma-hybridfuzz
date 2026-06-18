#!/bin/bash
# One-time VM bootstrap for the MA-HybridFuzz benchmark.
#
# Run this once after `git clone` on a fresh VM. It:
#   1. Populates ./magma (the Magma benchmark — patches + seed corpora) which is
#      NOT committed in this repo (it was a broken git submodule). Without it,
#      every Docker build fails on `COPY magma/targets/...`.
#   2. Sanity-checks Docker + Docker Compose.
#   3. Creates .env from .env.example if missing.
#   4. Builds the per-library Docker images.
#
# Usage: ./scripts/setup_vm.sh [--no-build]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The Dockerfiles pin source commits (e.g. libpng a37d4836...) that match the
# upstream Magma bug patches, so the default branch normally applies cleanly.
# Set MAGMA_COMMIT to pin a specific tag/commit for reproducibility.
MAGMA_REPO="${MAGMA_REPO:-https://github.com/HexHive/magma.git}"
MAGMA_COMMIT="${MAGMA_COMMIT:-}"

BUILD=1
[ "${1:-}" = "--no-build" ] && BUILD=0

echo "=== MA-HybridFuzz VM setup ==="

# ── 1. Docker checks ─────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "[setup] Docker not found. Install Docker first."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "[setup] 'docker compose' v2 not found."; exit 1; }
echo "[setup] Docker OK: $(docker --version)"

# ── 2. Populate ./magma ──────────────────────────────────────────────────────
# The Dockerfiles need ./magma/targets/<lib>/{patches,corpus}. The HexHive/magma
# layout provides exactly that.
if [ -f "magma/targets/libpng/patches/setup/0001-setup.patch" ] || \
   ls magma/targets/libpng/patches/*/*.patch >/dev/null 2>&1; then
    echo "[setup] ./magma already populated — skipping clone."
else
    echo "[setup] ./magma is empty. Cloning Magma ($MAGMA_REPO @ ${MAGMA_COMMIT:-default branch})..."
    rm -rf magma .magma_tmp
    git clone "$MAGMA_REPO" .magma_tmp
    [ -n "$MAGMA_COMMIT" ] && ( cd .magma_tmp && git checkout "$MAGMA_COMMIT" )
    # Keep the whole tree; Dockerfiles reference magma/targets/<lib>/...
    rm -rf magma
    mv .magma_tmp magma
    echo "[setup] Magma populated at ./magma"
fi

# Verify the libs we benchmark have patches + corpus.
for lib in libpng libtiff libxml2; do
    [ -d "magma/targets/$lib/patches" ] || echo "[setup] WARNING: magma/targets/$lib/patches missing"
    [ -d "magma/targets/$lib/corpus" ]  || echo "[setup] WARNING: magma/targets/$lib/corpus missing (baseline seeds)"
done

# ── 3. .env ──────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    cp .env.example .env
    chmod 600 .env
    echo "[setup] Created .env from .env.example — fill in your keys (see docs/BENCHMARK_VM.md)."
fi

# ── 4. Models cache dir (LineVul weights + HuggingFace cache) ────────────────
mkdir -p models/hf workspace
echo "[setup] models/ cache dir ready (LineVul weights download here on first run)."

# ── 5. Build images ──────────────────────────────────────────────────────────
if [ "$BUILD" -eq 1 ]; then
    echo "[setup] Building Docker images (this is slow the first time)..."
    for lib in libpng libtiff libxml2 openssl sqlite3 poppler php; do
        echo "[setup] Building magma-$lib ..."
        docker compose build "magma-$lib" || echo "[setup] WARNING: build failed for magma-$lib"
    done
fi

echo ""
echo "=== Setup complete ==="
echo "Next: edit .env, then run e.g."
echo "  ./scripts/run_benchmark.sh --fuzzer baseline --cve all --runs 5 --parallel 3"
