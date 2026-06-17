#!/bin/bash
# Run MA-HybridFuzz against a specific CVE target.
# Usage: ./scripts/run_cve.sh <CVE-ID> [--build] [orchestrator_args...]
# Example: ./scripts/run_cve.sh CVE-2019-7317 --verbosity 2

set -e

CVE="${1:?Usage: $0 <CVE-ID> [--build] [orchestrator_args...]}"
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

if [ "${1:-}" = "--build" ]; then
  echo "[$CVE] Building Docker image for $LIBRARY..."
  docker compose build "magma-$LIBRARY"
  shift
fi

echo "[$CVE] Starting MA-HybridFuzz (library: $LIBRARY)..."
docker compose run --rm "magma-$LIBRARY" \
  python3 /opt/mahybridfuzz/src/orchestrator.py \
  -c "$CONFIG" "$@"
