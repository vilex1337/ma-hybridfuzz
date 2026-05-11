"""
Attention-Guided Seed Scheduler
Uses pre-computed attention distance matrix to prioritize seeds
that are semantically closer to the target. (Gap 1)
"""

import json
import logging
from pathlib import Path

import numpy as np

logger = logging.getLogger("fuzzing.scheduler")


class AttentionScheduler:
    def __init__(self, config: dict):
        self.config = config
        self._distance_matrix = None
        self._functions = None
        self._target = None
        self._weights = {
            "attention": config["scheduler"]["attention_weight"],
            "coverage": config["scheduler"]["coverage_weight"],
            "speed": config["scheduler"]["speed_weight"],
        }

    def set_distance_matrix(self, data: dict):
        """Load the pre-computed attention distance matrix."""
        if not data:
            return
        self._functions = data.get("functions", [])
        self._target = data.get("target", "")
        matrix = data.get("matrix")
        if matrix is not None:
            self._distance_matrix = np.array(matrix)
            logger.info(
                "Loaded distance matrix: %d functions, target=%s",
                len(self._functions),
                self._target,
            )

    def has_distance_matrix(self) -> bool:
        return self._distance_matrix is not None

    def compute_priority(
        self,
        _seed_path: str,
        reached_functions: list[str],
        coverage_bitmap: bytes | None = None,
        exec_time_us: int = 0,
    ) -> float:
        """Compute scheduling priority for a seed.

        Lower score = higher priority (closer to target).
        """
        # Attention distance component
        attention_score = self._compute_attention_score(reached_functions)

        # Coverage novelty component (normalized)
        coverage_score = self._compute_coverage_score(coverage_bitmap)

        # Speed component (faster = better, normalized)
        speed_score = self._compute_speed_score(exec_time_us)

        # Weighted combination
        priority = (
            self._weights["attention"] * attention_score
            + self._weights["coverage"] * (1.0 - coverage_score)
            + self._weights["speed"] * speed_score
        )

        return priority

    def _compute_attention_score(self, reached_functions: list[str]) -> float:
        """Get minimum attention distance from reached functions to target."""
        if self._distance_matrix is None or self._functions is None or not self._target:
            return 1.0

        if self._target not in self._functions:
            return 1.0

        target_idx = self._functions.index(self._target)
        min_distance = float("inf")

        for func in reached_functions:
            if func in self._functions:
                func_idx = self._functions.index(func)
                dist = float(self._distance_matrix[func_idx][target_idx])
                min_distance = min(min_distance, dist)

        return min(min_distance, 1.0)

    def _compute_coverage_score(self, coverage_bitmap: bytes | None) -> float:
        """Estimate coverage novelty. Higher = more novel edges."""
        if coverage_bitmap is None:
            return 0.5
        # Count non-zero entries as proxy for coverage
        nonzero = sum(1 for b in coverage_bitmap if b != 0)
        total = len(coverage_bitmap) if coverage_bitmap else 1
        return nonzero / total

    def _compute_speed_score(self, exec_time_us: int) -> float:
        """Normalize execution time. Lower time = lower score = higher priority."""
        if exec_time_us <= 0:
            return 0.5
        # Normalize: <1ms = 0.0, >100ms = 1.0
        normalized = min(exec_time_us / 100_000, 1.0)
        return normalized

    def export_afl_distance_file(self) -> str | None:
        """Export distance data in a format AFL++ can consume.

        Creates a file mapping basic block IDs to distances.
        This integrates with AFL++'s -L flag for MOpt or custom scheduling.
        """
        matrix = self._distance_matrix
        functions = self._functions
        target = self._target
        if matrix is None or functions is None or not target:
            return None

        if target not in functions:
            return None

        target_idx = functions.index(target)
        distances = {}
        for i, func in enumerate(functions):
            distances[func] = float(matrix[i][target_idx])

        output_path = Path(self.config["paths"]["distance_cache"]) / "afl_distances.json"
        with open(output_path, "w") as f:
            json.dump(distances, f, indent=2)

        logger.info("Exported AFL distance file: %s", output_path)
        return str(output_path)
