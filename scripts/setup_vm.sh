#!/bin/bash
# Per-target VM bootstrap for the MA-HybridFuzz benchmark.
#
# Run once after `git clone` on a fresh VM, then again per target you want to
# benchmark. On a resource-limited VM the workflow is:
#   setup one target → benchmark all its CVEs → release it → next target.
# It:
#   1. Populates ./magma (the Magma benchmark — patches + seed corpora) which is
#      NOT committed in this repo (it was a broken git submodule). Without it,
#      every Docker build fails on `COPY magma/targets/...`.
#   2. Sanity-checks Docker + Docker Compose.
#   3. Creates .env from .env.example if missing.
#   4. Builds the Docker image(s) for the SELECTED target only (not all libs).
#
# Usage:
#   ./scripts/setup_vm.sh <target> [--no-build]   # build one library's image
#   ./scripts/setup_vm.sh all     [--no-build]    # build every library (old behaviour)
#   ./scripts/setup_vm.sh --list                  # list available targets
#
# Examples:
#   ./scripts/setup_vm.sh libpng
#   ./scripts/setup_vm.sh poppler --no-build
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The Dockerfiles pin source commits (e.g. libpng a37d4836...) that match the
# upstream Magma bug patches, so the default branch normally applies cleanly.
# Set MAGMA_COMMIT to pin a specific tag/commit for reproducibility.
MAGMA_REPO="${MAGMA_REPO:-https://github.com/HexHive/magma.git}"
MAGMA_COMMIT="${MAGMA_COMMIT:-}"

# All benchmarkable libraries (one magma-<lib> compose service + CVE configs each).
ALL_TARGETS=(libpng libtiff libxml2 openssl sqlite3 poppler php)

# ── parse args ─────────────────────────────────────────────────────────────
TARGET=""
BUILD=1
for arg in "$@"; do
    case "$arg" in
        --no-build) BUILD=0 ;;
        --list)
            echo "Available targets:"
            printf '  %s\n' "${ALL_TARGETS[@]}"
            exit 0
            ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        -*) echo "Unknown option: $arg"; exit 1 ;;
        *)  [ -z "$TARGET" ] || { echo "Only one target may be given (got '$TARGET' and '$arg')."; exit 1; }
            TARGET="$arg" ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Error: a target is required. Pick one of: ${ALL_TARGETS[*]} (or 'all')."
    echo "Usage: ./scripts/setup_vm.sh <target> [--no-build]   (see --help)"
    exit 1
fi

# Resolve the list of libraries to build.
if [ "$TARGET" = "all" ]; then
    BUILD_TARGETS=("${ALL_TARGETS[@]}")
else
    valid=0
    for t in "${ALL_TARGETS[@]}"; do [ "$t" = "$TARGET" ] && valid=1; done
    [ "$valid" -eq 1 ] || { echo "Unknown target '$TARGET'. Valid: ${ALL_TARGETS[*]} (or 'all')."; exit 1; }
    BUILD_TARGETS=("$TARGET")
fi

echo "=== MA-HybridFuzz VM setup (target: $TARGET) ==="

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

# Verify the target(s) we're about to build have patches + corpus.
for lib in "${BUILD_TARGETS[@]}"; do
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

# ── 5. Build image(s) for the selected target ────────────────────────────────
if [ "$BUILD" -eq 1 ]; then
    echo "[setup] Building Docker image(s) for: ${BUILD_TARGETS[*]} (slow the first time)..."
    for lib in "${BUILD_TARGETS[@]}"; do
        echo "[setup] Building magma-$lib ..."
        docker compose build "magma-$lib" || echo "[setup] WARNING: build failed for magma-$lib"
    done
fi

echo ""
echo "=== Setup complete ==="
echo "Next: edit .env, then benchmark every CVE of this target, e.g."
if [ "$TARGET" != "all" ]; then
    echo "  ./scripts/run_benchmark.sh --fuzzer baseline --target $TARGET --runs 5 --parallel 3"
    echo ""
    echo "When done, free the image before setting up the next target:"
    echo "  docker rmi \$(docker images -q 'ma-hybridfuzz*magma-$TARGET*') 2>/dev/null; docker image prune -f"
else
    echo "  ./scripts/run_benchmark.sh --fuzzer baseline --cve all --runs 5 --parallel 3"
fi
