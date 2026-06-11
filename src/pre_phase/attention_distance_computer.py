"""
Attention Distance Computer — replaces AttentionComputer.

Pipeline per the paper (Wang Bin et al., 2025):
  1. Extract basic blocks + call graph from source (CFGExtractor)
  2. Score each block with LineVul attention weights (LineVulScorer)
  3. Compute physical distances from call graph (BFS, formula 5)
  4. Compute attention distances: db_att = db_phys × (1.5 - w(m))  (formula 9)
  5. Write distance.cfg.txt in AFLGo format + pickle cache

Preserves the AttentionComputer interface used by the orchestrator:
  compute(), load_cached(), get_distance(), get_neighbors()
"""

import json
import logging
import pickle
from collections import deque
from pathlib import Path

import numpy as np

from config import AppConfig
from logging_utils import VERBOSE_LEVEL
from pre_phase.cfg_extractor import CFGExtractor
from pre_phase.linevul_scorer import LineVulScorer

logger = logging.getLogger("pre_phase.attention_distance")

SA = 1.5        # paper's scaling constant (formula 9)
INF_DIST = 20.0  # distance assigned to unreachable functions


class AttentionDistanceComputer:
    """Compute attention-adjusted basic-block distances for directed fuzzing."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.cache_dir = Path(config.paths.distance_cache)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        sid = (
            config.inference_session_id
            or config.attention.sid
            or config.llm.sid
            or "default"
        )
        self._scorer = LineVulScorer(config.attention.server_url, sid=sid)
        self._extractor = CFGExtractor(config)

        # State loaded by load_cached() or set by compute()
        self._functions: list[str] = []
        self._matrix: np.ndarray | None = None
        self._target: str = ""
        self._block_distances: dict[str, float] = {}  # bb_id -> att dist

    # ── Public interface (same as old AttentionComputer) ─────────────────────

    def compute(self, source_dir: str, target_function: str) -> None:
        """Run the full pipeline and write cache + distance.cfg.txt."""
        logger.info("Extracting CFG from %s ...", source_dir)
        blocks, call_graph = self._extractor.extract(source_dir)
        if not blocks:
            logger.warning("No blocks extracted; skipping attention distance")
            return

        logger.info("Extracted %d blocks from %d functions", len(blocks), len(call_graph))
        logger.log(
            VERBOSE_LEVEL,
            "[Attention] CFG stats: blocks=%d functions=%d call_edges=%d target=%s",
            len(blocks),
            len(call_graph),
            sum(len(v) for v in call_graph.values()),
            target_function,
        )

        # Physical distances: BFS on call graph (function level)
        phys_dist = self._bfs_distances(call_graph, target_function)
        reachable_funcs = [fn for fn, dist in phys_dist.items() if dist < INF_DIST]
        logger.log(
            VERBOSE_LEVEL,
            "[Attention] Physical distance BFS: reachable_functions=%d target_present=%s",
            len(reachable_funcs),
            target_function in phys_dist,
        )

        # Score blocks via LineVul server
        if self._scorer.is_available():
            logger.info("Scoring %d blocks via LineVul server ...", len(blocks))
            w_scores = self._scorer.score_blocks(
                {bb_id: b["source"] for bb_id, b in blocks.items() if b["source"]}
            )
            logger.log(
                VERBOSE_LEVEL,
                "[Attention] LineVul scores received: scored_blocks=%d",
                len(w_scores),
            )
        else:
            logger.warning("LineVul server not available; using uniform attention scores")
            w_scores = {bb_id: 0.5 for bb_id in blocks}
            logger.log(
                VERBOSE_LEVEL,
                "[Attention] Uniform attention scores applied: blocks=%d score=0.5",
                len(w_scores),
            )

        # Compute attention distances per block (formula 9)
        self._block_distances = {}
        for bb_id, block in blocks.items():
            func = block["func"]
            db_phys = phys_dist.get(func, INF_DIST)
            wm = w_scores.get(bb_id, 0.5)
            self._block_distances[bb_id] = db_phys * (SA - wm)

        # Aggregate to function level (min over blocks) for scheduler matrix
        func_dist = self._aggregate_to_functions(blocks, self._block_distances)
        self._target = target_function
        self._functions, self._matrix = self._build_matrix(func_dist, target_function)
        finite_block_distances = [
            dist for dist in self._block_distances.values() if np.isfinite(dist)
        ]
        logger.log(
            VERBOSE_LEVEL,
            "[Attention] Distance computation complete: block_distances=%d finite=%d function_distances=%d matrix_shape=%s",
            len(self._block_distances),
            len(finite_block_distances),
            len(func_dist),
            self._matrix.shape if self._matrix is not None else None,
        )

        # Persist
        self._write_distance_cfg_txt(blocks, self._block_distances)
        self._write_cache()
        logger.info("Attention distances cached at %s", self.cache_dir)

    def load_cached(self) -> dict:
        """Load pre-computed distances. Returns dict usable by AttentionScheduler."""
        cache_path = self.cache_dir / "attention_distances.pkl"
        if not cache_path.exists():
            logger.warning("No cached attention distances found")
            return {}
        with open(cache_path, "rb") as f:
            data = pickle.load(f)
        self._functions = data.get("functions", [])
        self._target = data.get("target", "")
        self._block_distances = data.get("block_distances", {})
        matrix = data.get("matrix")
        if matrix is not None:
            self._matrix = np.array(matrix)
        return data

    def get_distance(self, func_name: str, target: str) -> float:
        """Attention distance between func_name and target (function level)."""
        if self._matrix is None or not self._functions:
            return float("inf")
        try:
            src_idx = self._functions.index(func_name)
            dst_idx = self._functions.index(target)
            return float(self._matrix[src_idx][dst_idx])
        except ValueError:
            return float("inf")

    def get_neighbors(self, target_function: str, top_k: int = 3) -> list[str]:
        """Return top-k functions closest to target by attention distance."""
        if self._matrix is None or not self._functions:
            logger.warning("get_neighbors called before distance matrix is computed")
            return []
        if target_function not in self._functions:
            logger.warning("Target '%s' not in distance matrix", target_function)
            return []
        target_idx = self._functions.index(target_function)
        distances = self._matrix[:, target_idx]
        scored = [
            (self._functions[i], float(distances[i]))
            for i in range(len(self._functions))
            if i != target_idx and np.isfinite(distances[i])
        ]
        scored.sort(key=lambda p: p[1])
        neighbors = [name for name, _ in scored[:top_k]]
        logger.info("Nearest neighbors for '%s': %s", target_function,
                    [(n, f"{d:.3f}") for n, d in scored[:top_k]])
        return neighbors

    # ── Internal ─────────────────────────────────────────────────────────────

    def _bfs_distances(self, call_graph: dict, target: str) -> dict[str, float]:
        """BFS on reversed call graph: distance = hops from function to target."""
        # Reverse: callee -> list of callers
        reverse: dict[str, list] = {}
        for caller, callees in call_graph.items():
            for callee in callees:
                reverse.setdefault(callee, []).append(caller)

        dist: dict[str, float] = {target: 0.0}
        queue: deque = deque([target])
        while queue:
            node = queue.popleft()
            for caller in reverse.get(node, []):
                if caller not in dist:
                    dist[caller] = dist[node] + 1.0
                    queue.append(caller)
        return dist

    def _aggregate_to_functions(
        self, blocks: dict, block_dist: dict[str, float]
    ) -> dict[str, float]:
        """Min attention distance per function over all its blocks."""
        func_min: dict[str, float] = {}
        for bb_id, block in blocks.items():
            func = block["func"]
            d = block_dist.get(bb_id, INF_DIST * SA)
            if func not in func_min or d < func_min[func]:
                func_min[func] = d
        return func_min

    def _build_matrix(
        self, func_dist: dict[str, float], target: str
    ) -> tuple[list[str], np.ndarray]:
        """Build symmetric distance matrix (function × function) for the scheduler."""
        functions = sorted(func_dist.keys())
        if target not in functions:
            functions.append(target)

        n = len(functions)
        matrix = np.full((n, n), float("inf"))
        np.fill_diagonal(matrix, 0.0)

        target_idx = functions.index(target)
        for i, func in enumerate(functions):
            d = func_dist.get(func, float("inf"))
            matrix[i][target_idx] = d
            matrix[target_idx][i] = d

        return functions, matrix

    def _write_distance_cfg_txt(self, blocks: dict, block_dist: dict[str, float]) -> None:
        """Write AFLGo-compatible distance.cfg.txt: func_name,bb_id:distance."""
        out = self.cache_dir / "distance.cfg.txt"
        lines = []
        for bb_id, dist in sorted(block_dist.items()):
            func = blocks[bb_id]["func"] if bb_id in blocks else bb_id.rsplit("_bb", 1)[0]
            lines.append(f"{func},{bb_id}:{dist:.6f}")
        out.write_text("\n".join(lines))
        logger.info("Wrote %s (%d entries)", out, len(lines))

    def _write_cache(self) -> None:
        cache_data = {
            "target": self._target,
            "functions": self._functions,
            "matrix": self._matrix.tolist() if self._matrix is not None else [],
            "block_distances": self._block_distances,
        }
        with open(self.cache_dir / "attention_distances.pkl", "wb") as f:
            pickle.dump(cache_data, f)
        func_dists: dict[str, float] = {}
        if self._matrix is not None and self._target in self._functions:
            t_idx = self._functions.index(self._target)
            for i, fn in enumerate(self._functions):
                d = float(self._matrix[i][t_idx])
                if np.isfinite(d):
                    func_dists[fn] = d
        with open(self.cache_dir / "attention_distances.json", "w") as f:
            json.dump(
                {"target": self._target, "function_distances": func_dists},
                f,
                indent=2,
            )
