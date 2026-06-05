"""
LineVul Scorer — HTTP client for the LineVul attention distance server.
Falls back to uniform scores (0.5) if the server is unreachable or unconfigured.
"""
import logging

import requests

logger = logging.getLogger("pre_phase.linevul_scorer")

_TIMEOUT = 300  # seconds — scoring many blocks can take a while


class LineVulScorer:
    """Client for the Kaggle-hosted LineVul inference server."""

    def __init__(self, server_url: str, sid: str = "default"):
        self._url = server_url.rstrip("/") if server_url else ""
        self._sid = sid or "default"

    def is_available(self) -> bool:
        if not self._url:
            return False
        try:
            r = requests.get(f"{self._url}/health", timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    def score_blocks(self, blocks: dict[str, str]) -> dict[str, float]:
        """Return normalized attention scores w(m) ∈ [0, 0.5] per block.

        Falls back to 0.5 (neutral) for all blocks if server unreachable.
        """
        if not blocks:
            return {}
        if not self._url:
            logger.warning("LineVul server URL not configured; using uniform scores")
            return {bb_id: 0.5 for bb_id in blocks}
        try:
            resp = requests.post(
                f"{self._url}/score_blocks",
                json={"sid": self._sid, "blocks": blocks},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()["normalized_scores"]
        except Exception as e:
            logger.warning("LineVul server error (%s); using uniform scores", e)
            return {bb_id: 0.5 for bb_id in blocks}
