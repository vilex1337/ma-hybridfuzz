#!/bin/bash
# Run the AFLGo baseline fuzzer against a specific CVE target, using the
# same target_function and fuzzer.* budget as configs/magma/cve/<lib>/<CVE>.yml.
# Usage: ./scripts/run_baseline.sh <CVE-ID> [--build]
# Example: ./scripts/run_baseline.sh CVE-2019-7317 --build

set -e

CVE="${1:?Usage: $0 <CVE-ID> [--build]}"
shift

declare -A CVE_LIBRARY=(
  [CVE-2019-7317]=libpng
  [CVE-2015-0973]=libpng
  [CVE-2015-8472]=libpng
  [CVE-2013-6954]=libpng
  [CVE-2016-9535]=libtiff
  [CVE-2016-5314]=libtiff
  [CVE-2019-7663]=libtiff
  [CVE-2016-10269]=libtiff
  [CVE-2018-7456]=libtiff
  [CVE-2018-18557]=libtiff
  [CVE-2017-9047]=libxml2
  [CVE-2017-0663]=libxml2
  [CVE-2017-7375]=libxml2
  [CVE-2016-1836]=libxml2
)

LIBRARY="${CVE_LIBRARY[$CVE]}"
if [ -z "$LIBRARY" ]; then
  echo "Unknown CVE '$CVE'. Available:"
  printf '  %s\n' "${!CVE_LIBRARY[@]}" | sort
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

CONFIG="configs/magma/cve/$LIBRARY/$CVE.yml"
[ -f "$CONFIG" ] || { echo "Config not found: $CONFIG"; exit 1; }

[ -f .env ] && { set -a; source .env; set +a; }

read -r TARGET_FUNCTION RUN_TIMEOUT EXEC_TIMEOUT MEMORY_LIMIT <<EOF
$(python3 -c "
import yaml
cfg = yaml.safe_load(open('$CONFIG'))
f = cfg['fuzzer']
print(cfg['target']['target_function'], f['timeout'], f['exec_timeout'], f['memory_limit'])
")
EOF

# Time-to-exploitation cutoff: AFLGo's documented convention is roughly 2/3
# of the total budget, after which it falls back to undirected exploration.
CUTOFF_MIN=$(( (RUN_TIMEOUT * 2 / 3) / 60 ))
CUTOFF="${CUTOFF_MIN}m"

export AFLGO_TARGET_FUNCTION="$TARGET_FUNCTION"
export AFLGO_CVE_ID="$CVE"
export AFLGO_RUN_TIMEOUT="$RUN_TIMEOUT"
export AFLGO_EXEC_TIMEOUT="$EXEC_TIMEOUT"
export AFLGO_MEMORY_LIMIT="$MEMORY_LIMIT"
export AFLGO_CUTOFF="$CUTOFF"

BUILD=0
if [ "${1:-}" = "--build" ]; then
  BUILD=1
  shift
fi

if [ "$BUILD" -eq 1 ] || ! docker image inspect ma-hybridfuzz-aflgo-base:latest >/dev/null 2>&1; then
  echo "[$CVE] Building AFLGo base toolchain image (one-time, builds LLVM 4.0 + AFLGo)..."
  docker compose build magma-aflgo-base
fi

if [ "$BUILD" -eq 1 ]; then
  echo "[$CVE] Building AFLGo image for $LIBRARY (target_function=$TARGET_FUNCTION)..."
  docker compose build "magma-aflgo-$LIBRARY"
fi

RUN_DIR="$ROOT/workspace/$CVE/baseline_aflgo/run_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RUN_DIR"

echo "[$CVE] Starting AFLGo baseline (library: $LIBRARY, target_function: $TARGET_FUNCTION)..."
echo "[$CVE] timeout=${RUN_TIMEOUT}s exec_timeout=${EXEC_TIMEOUT}ms memory_limit=${MEMORY_LIMIT}MB cutoff=$CUTOFF"
echo "[$CVE] Output: $RUN_DIR"

docker compose run --rm \
  --user "$(id -u):$(id -g)" \
  --volume "$RUN_DIR:/aflgo-out" \
  "magma-aflgo-$LIBRARY" "$@"
