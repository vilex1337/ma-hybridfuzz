#!/bin/bash
# Update LLM and/or LineVul server URLs in all Magma target configs.
# Usage: ./scripts/update_url.sh [--llm <url>] [--linevul <url>]
# At least one of --llm or --linevul must be provided.
# Example: ./scripts/update_url.sh --llm https://abc.ngrok-free.app/ --linevul https://xyz.ngrok-free.app/

set -euo pipefail

LLM_URL=""
LINEVUL_URL=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --llm)      LLM_URL="${2:?--llm requires a URL}";     shift 2 ;;
        --linevul)  LINEVUL_URL="${2:?--linevul requires a URL}"; shift 2 ;;
        *) echo "Unknown argument: $1"; echo "Usage: $0 [--llm <url>] [--linevul <url>]"; exit 1 ;;
    esac
done

if [[ -z "$LLM_URL" && -z "$LINEVUL_URL" ]]; then
    echo "Error: at least one of --llm or --linevul must be provided."
    echo "Usage: $0 [--llm <url>] [--linevul <url>]"
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGS_DIR="$ROOT/configs/magma"

while IFS= read -r -d '' cfg; do
    changed=0
    if [[ -n "$LLM_URL" ]]; then
        sed -i "s|^\( *base_url: *\)\".*\"|\1\"$LLM_URL\"|" "$cfg"
        changed=1
    fi
    if [[ -n "$LINEVUL_URL" ]]; then
        sed -i "s|^\( *server_url: *\)\".*\"|\1\"$LINEVUL_URL\"|" "$cfg"
        changed=1
    fi
    [[ "$changed" -eq 1 ]] && echo "Updated: ${cfg#$ROOT/}"
done < <(find "$CONFIGS_DIR" -name "*.yml" -print0)

echo ""
[[ -n "$LLM_URL" ]]     && echo "LLM URL:     $LLM_URL"
[[ -n "$LINEVUL_URL" ]] && echo "LineVul URL: $LINEVUL_URL"
