"""Stand-alone LineVul attention-distance server (runs on the VM HOST, OUTSIDE Docker).

Keeps the heavy torch/transformers stack off the fuzzer image. The in-container
orchestrator reaches it via MA_LINEVUL_SERVER_URL=http://host.docker.internal:<port>
and the existing *remote* path in src/pre_phase/linevul_scorer.py — so the scoring
math is identical whether it runs in-process or here, because this server reuses
the very same LineVulScorer class in local mode.

Endpoints (must match LineVulScorer._score_remote):
    GET  /health        -> 200 when the model is loaded, 503 otherwise
    POST /score_blocks   {"sid": str, "blocks": {bb_id: source}}  -> {"normalized_scores": {...}}

Run:
    pip install -r requirements-linevul.txt
    ./scripts/run_linevul_server.sh                # convenience wrapper
    # or directly:
    LINEVUL_WEIGHTS=./models/12heads_linevul_model.bin \
        python3 inference/linevul_server.py --host 0.0.0.0 --port 8501
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
from pathlib import Path

# Make the project's src/ importable so we reuse the exact scoring code.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from flask import Flask, jsonify, request  # noqa: E402

from pre_phase.linevul_scorer import LineVulScorer  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("linevul_server")

app = Flask(__name__)

# Empty server_url => the scorer runs the in-process (local) CPU model. One
# shared instance; a lock serialises inference so concurrent benchmark runs
# (--parallel N) don't drive the same torch model from multiple threads at once.
_scorer = LineVulScorer("")
_lock = threading.Lock()


@app.get("/health")
def health():
    return ("ok", 200) if _scorer.is_available() else ("model unavailable", 503)


@app.post("/score_blocks")
def score_blocks():
    data = request.get_json(force=True, silent=True) or {}
    blocks = data.get("blocks", {})
    if not isinstance(blocks, dict):
        return jsonify({"error": "blocks must be an object {bb_id: source}"}), 400
    with _lock:
        scores = _scorer.score_blocks(blocks)
    return jsonify({"normalized_scores": scores})


def main():
    ap = argparse.ArgumentParser(description="LineVul attention-distance server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.getenv("LINEVUL_PORT", "8501")))
    args = ap.parse_args()

    log.info("Warming LineVul model (first load can take a minute)...")
    if _scorer.is_available():
        log.info("LineVul model ready.")
    else:
        log.warning(
            "LineVul model NOT available (missing torch/transformers or weights). "
            "Clients will fall back to uniform attention scores."
        )
    log.info("Serving on %s:%d", args.host, args.port)
    # threaded=True so /health stays responsive while a score request holds _lock.
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
